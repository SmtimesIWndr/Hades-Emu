pub mod interp;
mod interp_seg;
mod interp_vec;
pub mod region;
pub mod state;
mod trampolines;
pub mod veh;
mod xstate;

use crate::hooks::HookCb;
use crate::jit::asm::{Asm, AsmError, patch_rel32};
use crate::jit::{Jit, TxCfg, TxError};
use crate::memory::{Fault, FaultKind, Memory, PAGE, PERM_READ, PERM_WRITE};
use crate::{Emu, EmuError, MemAccess};
use iced_x86::{Decoder, DecoderOptions};
use region::{CODE_OFF, CodeRegion, JC_OFF, TLB_OFF};
use state::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use trampolines::{cpu_supports_xsave, dispatch_entry, emit_globals};

impl Emu {
    pub(crate) fn new() -> Result<Box<Emu>, EmuError> {
        if !cpu_supports_xsave() {
            return Err(EmuError::Init("CPU/OS without XSAVE support".into()));
        }
        let region = Arc::new(CodeRegion::new().ok_or_else(|| EmuError::Init("VirtualAlloc failed".into()))?);
        let state = region.state();
        let mut jit = Jit::new(
            region.addr(0),
            region.addr(TLB_OFF),
            region.addr(JC_OFF),
            region.addr(CODE_OFF),
            region.addr(region.size),
        );
        emit_globals(&mut jit).map_err(|e| EmuError::Init(e.to_string()))?;
        let mut emu = Box::new(Emu {
            region,
            state,
            mem: Memory::default(),
            jit,
            hooks: Vec::new(),
            running: false,
            stop_requested: Arc::new(AtomicBool::new(false)),
            pending_flush: false,
            pending_error: None,
            counted: false,
            until: None,
            panic: None,
        });
        let emu_ptr = &mut *emu as *mut Emu as u64;
        let (tlb, jc) = (emu.jit.tlb, emu.jit.jc);
        let st = emu.st_mut();
        st.tlb_ptr = tlb;
        st.jc_ptr = jc;
        st.emu = emu_ptr;
        st.dispatch_fn = dispatch_entry as *const () as u64;
        st.rflags = 0x202;
        st.run_flag = 1;
        st.seg = [0x2B, 0x33, 0x2B, 0x2B, 0x53, 0x2B];
        let x = &mut st.xsave.0;
        x[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        x[28..32].copy_from_slice(&crate::cpu::cpu().mxcsr_mask.to_le_bytes());
        x[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        emu.tlb_flush();
        emu.jit.jc_clear();
        veh::install();
        Ok(emu)
    }

    fn tlb_entry(&self, idx: usize) -> *mut u64 {
        unsafe { (self.jit.tlb as *mut u64).add(idx * 4) }
    }

    pub(crate) fn tlb_flush(&mut self) {
        for i in 0..TLB_ENTRIES {
            let e = self.tlb_entry(i);
            let inv = tlb_invalid_tag(i);
            unsafe {
                *e = inv;
                *e.add(1) = inv;
                *e.add(2) = inv;
                *e.add(3) = 0;
            }
        }
    }

    fn tlb_drop_write(&mut self, page: u64) {
        let i = ((page >> 12) as usize) & (TLB_ENTRIES - 1);
        let e = self.tlb_entry(i);
        let inv = tlb_invalid_tag(i);
        unsafe {
            if *e.add(1) == page {
                *e.add(1) = inv;
            }
            if *e.add(2) == page {
                *e.add(2) = inv;
            }
        }
    }

    pub(crate) fn flush_all(&mut self) {
        self.jit.flush();
        self.tlb_flush();
        self.pending_flush = false;
    }

    pub(crate) fn access(&mut self, ea: u64, size: u64, acc: u64) -> Result<*mut u8, Fault> {
        let need = match acc {
            ACC_R => PERM_READ,
            ACC_W => PERM_WRITE,
            _ => PERM_READ | PERM_WRITE,
        };
        let host = self.mem.resolve(ea, size, need)?;
        if acc & ACC_W != 0 {
            let mut p = ea & !(PAGE - 1);
            while p < ea + size {
                if self.jit.has_code(p) {
                    self.jit.invalidate_range(ea, ea + size);
                    break;
                }
                p += PAGE;
            }
        }
        Ok(host)
    }

    fn tlb_fill(&mut self, ea: u64, size: u64, acc: u64) -> Result<*mut u8, Fault> {
        let host = self.access(ea, size, acc)?;
        let page = ea & !(PAGE - 1);
        let perm = self.mem.find(page).map(|r| r.perm_at(page)).unwrap_or(0);
        let code = self.jit.has_code(page);
        let i = ((page >> 12) as usize) & (TLB_ENTRIES - 1);
        let inv = tlb_invalid_tag(i);
        let e = self.tlb_entry(i);
        let rw = PERM_READ | PERM_WRITE;
        unsafe {
            *e = if perm & PERM_READ != 0 { page } else { inv };
            *e.add(1) = if perm & PERM_WRITE != 0 && !code { page } else { inv };
            *e.add(2) = if perm & rw == rw && !code { page } else { inv };
            *e.add(3) = host as u64 - (ea - page);
        }
        Ok(host)
    }

    pub(crate) fn invalid_hooks(&mut self, access: MemAccess, addr: u64, size: usize, value: u64) -> bool {
        let mut retry = false;
        self.each_hook(
            |s| matches!(s.cb, Some(HookCb::Invalid(_))),
            |emu, cb| {
                if let HookCb::Invalid(f) = cb {
                    retry |= f(emu, access, addr, size, value);
                }
            },
        );
        retry
    }

    pub(crate) fn mem_hooks(&mut self, access: MemAccess, addr: u64, size: usize, value: u64) {
        let bitm = if access == MemAccess::Read { crate::HOOK_MEM_READ } else { crate::HOOK_MEM_WRITE };
        self.each_hook(
            |s| matches!(&s.cb, Some(HookCb::Mem(m, _)) if m & bitm != 0) && s.covers(addr),
            |emu, cb| {
                if let HookCb::Mem(_, f) = cb {
                    f(emu, access, addr, size, value);
                }
            },
        );
    }

    pub(crate) fn peek_value(&self, addr: u64, size: usize) -> u64 {
        let mut b = [0u8; 8];
        let n = size.min(8);
        let _ = self.mem.read(addr, &mut b[..n]);
        u64::from_le_bytes(b)
    }

    pub(crate) fn access_or_fault(&mut self, ea: u64, size: u64, acc: u64) -> Option<*mut u8> {
        let mut retried = false;
        loop {
            match self.access(ea, size, acc) {
                Ok(p) => return Some(p),
                Err(f) => {
                    let access = Emu::fault_access(acc, f.kind);
                    if !retried && self.invalid_hooks(access, ea, size as usize, 0) {
                        retried = true;
                        continue;
                    }
                    self.pending_error = Some(EmuError::Memory { access, addr: ea, size: size as usize, rip: self.st_mut().rip });
                    return None;
                }
            }
        }
    }

    fn smc_cut(&mut self, id: u32, rip: u64) {
        let Some(b) = self.jit.blocks.get(id as usize) else { return };
        let Some(pos) = b.insn_starts.iter().position(|&(g, _)| g == rip) else { return };
        let Some(&(next_rip, host_at)) = b.insn_starts.get(pos + 1) else { return };
        if self.jit.code_end - self.jit.code_pos < 256 {
            return;
        }
        let mut a = Asm::new(self.jit.code_pos, self.jit.code_end, self.jit.state);
        let stub = a.here();
        let ok = a.store_imm64(OFF_RIP, next_rip).is_ok()
            && a.mov_mi(a.st(OFF_EXIT_REASON), EXIT_REDIRECT as i32).is_ok()
            && a.jmp_to(self.jit.g.exit_sync).is_ok();
        if !ok {
            return;
        }
        self.jit.code_pos = (a.here() + 15) & !15;
        unsafe { *(host_at as *mut u8) = 0xE9 };
        patch_rel32(host_at + 1, stub);
    }

    fn after_callback(&mut self, block: u32, rip_before: u64) -> u64 {
        if self.stop_requested.load(Ordering::SeqCst) {
            self.st_mut().exit_reason = EXIT_STOP;
            return 1;
        }
        if self.st().rip != rip_before || self.jit.block(block).is_none() {
            self.st_mut().exit_reason = EXIT_REDIRECT;
            return 1;
        }
        if self.pending_flush {
            self.region.run_flag().store(0, Ordering::SeqCst);
        }
        0
    }

    fn dispatch(&mut self) -> u64 {
        let st = self.st();
        let kind = st.arg_kind & 0xff;
        let acc = (st.arg_kind >> 8) & 0xff;
        let size = st.arg_kind >> 16;
        let block = st.arg_block as u32;
        let ea = st.arg_ea;
        let rip = st.rip;
        match kind {
            KIND_MEM => {
                let mut retried = false;
                loop {
                    let was_valid = self.jit.block(block).is_some();
                    match self.tlb_fill(ea, size, acc) {
                        Ok(host) => {
                            self.st_mut().arg_ret = host as u64;
                            if was_valid && self.jit.block(block).is_none() {
                                self.smc_cut(block, rip);
                            }
                            if self.pending_flush {
                                self.region.run_flag().store(0, Ordering::SeqCst);
                            }
                            return 0;
                        }
                        Err(f) => {
                            let access = Emu::fault_access(acc, f.kind);
                            if !retried && self.invalid_hooks(access, ea, size as usize, 0) {
                                retried = true;
                                continue;
                            }
                            self.pending_error = Some(EmuError::Memory { access, addr: ea, size: size as usize, rip });
                            self.st_mut().exit_reason = EXIT_HELPER;
                            return 1;
                        }
                    }
                }
            }
            KIND_CODE | KIND_BLOCK => {
                let want_block = kind == KIND_BLOCK;
                self.each_hook(
                    |s| match s.cb {
                        Some(HookCb::Code(_)) => !want_block && s.covers(ea),
                        Some(HookCb::Block(_)) => want_block && s.covers(ea),
                        _ => false,
                    },
                    |emu, cb| match cb {
                        HookCb::Code(f) | HookCb::Block(f) => f(emu, ea, size as u32),
                        _ => {}
                    },
                );
                self.after_callback(block, rip)
            }
            KIND_MEMR | KIND_MEMW => {
                let value = self.peek_value(ea, size as usize);
                let access = if kind == KIND_MEMR { MemAccess::Read } else { MemAccess::Write };
                self.mem_hooks(access, ea, size as usize, value);
                self.after_callback(block, rip)
            }
            KIND_INTERP => {
                let insn = self.jit.interp[ea as usize];
                let next = match interp::exec(self, &insn) {
                    Ok(interp::Done::Next) => insn.next_ip(),
                    Ok(interp::Done::Jump(t)) => t,
                    Err(e) => {
                        let st = self.st_mut();
                        st.rip = insn.ip();
                        st.exit_reason = match e {
                            interp::IErr::Fault => EXIT_HELPER,
                            interp::IErr::Exc(v) => {
                                st.exit_aux = v as u64;
                                EXIT_EXCEPTION
                            }
                            interp::IErr::Unsupported => EXIT_UNSUPPORTED,
                        };
                        return 1;
                    }
                };
                let st = self.st_mut();
                st.rip = next;
                if st.rflags & 0x100 != 0 {
                    st.rflags &= !0x100;
                    st.exit_reason = EXIT_TRAP_PENDING;
                    return 1;
                }
                self.after_callback(block, insn.next_ip())
            }
            _ => unreachable!("bad dispatch kind {kind}"),
        }
    }

    fn block_for(&mut self, rip: u64, single: bool) -> Result<u32, EmuError> {
        let map = if single { &self.jit.single_rip } else { &self.jit.by_rip };
        if let Some(&id) = map.get(&rip) {
            if !single {
                let host = self.jit.blocks[id as usize].host;
                self.jit.jc_set(rip, host);
            }
            return Ok(id);
        }
        let mut retried_fetch = false;
        let mut flushed = false;
        loop {
            let code_hook = |a: u64| self.hooks.iter().flatten().any(|s| matches!(s.cb, Some(HookCb::Code(_)) | None) && s.covers(a));
            let block_hook = |a: u64| self.hooks.iter().flatten().any(|s| matches!(s.cb, Some(HookCb::Block(_))) && s.covers(a));
            let mem_r = self.has_hook(|s| matches!(&s.cb, Some(HookCb::Mem(m, _)) if m & crate::HOOK_MEM_READ != 0));
            let mem_w = self.has_hook(|s| matches!(&s.cb, Some(HookCb::Mem(m, _)) if m & crate::HOOK_MEM_WRITE != 0));
            let cfg = TxCfg {
                counted: self.counted,
                single,
                until: self.until,
                code_hook: &code_hook,
                block_hook: &block_hook,
                mem_read_hooks: mem_r,
                mem_write_hooks: mem_w,
            };
            match self.jit.translate(&self.mem, rip, &cfg) {
                Ok(id) => {
                    let (start, end, host) = {
                        let b = &self.jit.blocks[id as usize];
                        (b.start, b.end, b.host)
                    };
                    let mut p = start & !(PAGE - 1);
                    while p < end.max(start + 1) {
                        self.tlb_drop_write(p);
                        p += PAGE;
                    }
                    self.jit.jc_set(rip, host);
                    return Ok(id);
                }
                Err(TxError::Asm(AsmError::OutOfSpace)) if !flushed => {
                    flushed = true;
                    self.flush_all();
                }
                Err(TxError::Asm(e)) => return Err(EmuError::Translate { rip, msg: e.to_string() }),
                Err(TxError::Fetch(Fault { kind, addr })) => {
                    let access = if kind == FaultKind::Unmapped { MemAccess::FetchUnmapped } else { MemAccess::FetchProt };
                    if !retried_fetch && self.invalid_hooks(access, addr, 1, 0) {
                        retried_fetch = true;
                        continue;
                    }
                    return Err(EmuError::Memory { access, addr, size: 1, rip });
                }
            }
        }
    }

    fn enter(&mut self, host: u64) {
        let f: unsafe extern "win64" fn(u64) = unsafe { core::mem::transmute(self.jit.g.entry as usize) };
        unsafe { f(host) };
    }

    fn intr_hooks(&mut self, n: u32) -> bool {
        if !self.has_hook(|s| matches!(s.cb, Some(HookCb::Intr(_)))) {
            return false;
        }
        self.each_hook(
            |s| matches!(s.cb, Some(HookCb::Intr(_))),
            |emu, cb| {
                if let HookCb::Intr(f) = cb {
                    f(emu, n)
                }
            },
        );
        true
    }

    fn describe(&self, rip: u64) -> String {
        let bytes = self.mem_read_vec(rip, 15).or_else(|_| self.mem_read_vec(rip, 1)).unwrap_or_default();
        let insn = Decoder::with_ip(64, &bytes, rip, DecoderOptions::NONE).decode();
        format!("{:?}", insn.code())
    }

    pub fn emu_start(&mut self, begin: u64, until: u64, timeout: Option<Duration>, count: u64) -> Result<(), EmuError> {
        if self.running {
            return Err(EmuError::Busy);
        }
        let counted = count > 0;
        if counted != self.counted {
            self.counted = counted;
            self.flush_all();
        }
        if self.pending_flush {
            self.flush_all();
        }
        if self.until != Some(until) {
            if let Some(old) = self.until {
                self.jit.invalidate_range(old, old.saturating_add(1));
            }
            self.jit.invalidate_range(until, until.saturating_add(1));
            self.until = Some(until);
        }
        let st = self.st_mut();
        st.rip = begin;
        st.icount_left = count;
        self.stop_requested.store(false, Ordering::SeqCst);
        self.region.run_flag().store(1, Ordering::SeqCst);
        self.pending_error = None;
        self.running = true;

        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog = timeout.map(|t| {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let region = self.region.clone();
            let flag = timed_out.clone();
            let h = std::thread::spawn(move || {
                if rx.recv_timeout(t).is_err() {
                    flag.store(true, Ordering::SeqCst);
                    region.run_flag().store(0, Ordering::SeqCst);
                }
            });
            (tx, h)
        });

        veh::CURRENT.with(|c| c.set(self as *mut Emu));
        let result = self.run_loop(&timed_out);
        veh::CURRENT.with(|c| c.set(core::ptr::null_mut()));
        self.running = false;
        if let Some((tx, h)) = watchdog {
            let _ = tx.send(());
            let _ = h.join();
        }
        if let Some(p) = self.panic.take() {
            std::panic::resume_unwind(p);
        }
        result
    }

    fn run_loop(&mut self, timed_out: &AtomicBool) -> Result<(), EmuError> {
        let mut chain: Option<(u32, u32)> = None;
        let mut trap_after = false;
        loop {
            if self.pending_flush {
                self.flush_all();
                chain = None;
            }
            if self.stop_requested.load(Ordering::SeqCst) || timed_out.load(Ordering::SeqCst) {
                return Ok(());
            }
            if self.counted && self.st_mut().icount_left == 0 {
                return Ok(());
            }
            let rip = self.st_mut().rip;
            let single = std::mem::take(&mut trap_after);
            let id = self.block_for(rip, single)?;
            if let Some((src, site)) = chain.take()
                && !single
                && self.jit.block(src).is_some_and(|b| b.sites.get(site as usize).is_some_and(|s| s.target == rip))
            {
                self.jit.link(src, site, id);
            }
            let host = self.jit.blocks[id as usize].host;
            if single {
                self.region.run_flag().store(0, Ordering::SeqCst);
            }
            self.enter(host);
            if single && !self.stop_requested.load(Ordering::SeqCst) && !timed_out.load(Ordering::SeqCst) {
                self.region.run_flag().store(1, Ordering::SeqCst);
            }
            if self.panic.is_some() {
                return Ok(());
            }
            let st = self.st();
            let reason = st.exit_reason;
            match reason {
                EXIT_CHAIN if !single => {
                    let cs = st.chain_site;
                    chain = Some(((cs >> 32) as u32, cs as u32));
                }
                EXIT_CHAIN | EXIT_INDIRECT | EXIT_REDIRECT => {}
                EXIT_TRAP_PENDING => trap_after = true,
                EXIT_STOP => {
                    if self.stop_requested.load(Ordering::SeqCst) || timed_out.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    self.region.run_flag().store(1, Ordering::SeqCst);
                }
                EXIT_COUNT | EXIT_UNTIL => return Ok(()),
                EXIT_HELPER => {
                    if let Some(e) = self.pending_error.take() {
                        return Err(e);
                    }
                }
                EXIT_EXCEPTION => {
                    let (vector, rip) = (st.exit_aux as u32, st.rip);
                    if !self.intr_hooks(vector) {
                        return Err(EmuError::Exception { vector, rip });
                    }
                    continue;
                }
                EXIT_INTERRUPT => {
                    let (intno, rip) = (st.exit_aux as u32, st.rip);
                    if !self.intr_hooks(intno) {
                        return Err(EmuError::Interrupt { intno, rip });
                    }
                }
                EXIT_SYSCALL => {
                    if !self.has_hook(|s| matches!(s.cb, Some(HookCb::Syscall(_)))) {
                        return Err(EmuError::Syscall { rip: st.rip });
                    }
                    self.each_hook(
                        |s| matches!(s.cb, Some(HookCb::Syscall(_))),
                        |emu, cb| {
                            if let HookCb::Syscall(f) = cb {
                                f(emu)
                            }
                        },
                    );
                }
                EXIT_UNSUPPORTED => {
                    let rip = st.rip;
                    return Err(EmuError::Unsupported { rip, text: self.describe(rip) });
                }
                r => unreachable!("bad exit reason {r}"),
            }
            if single && reason != EXIT_TRAP_PENDING {
                let rip = self.st_mut().rip;
                if !self.intr_hooks(crate::EXC_DEBUG) {
                    return Err(EmuError::Exception { vector: crate::EXC_DEBUG, rip });
                }
            }
        }
    }
}
