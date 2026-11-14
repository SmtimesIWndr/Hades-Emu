use super::classify::{flags_effect, insn_hook_bit, mem_op_index};
use super::*;
use crate::jit::asm::{AResult, Asm, mem};
use crate::jit::regs::*;
use crate::memory::{FaultKind, Memory};
use iced_x86::{
    Code, ConditionCode, Decoder, DecoderError, DecoderOptions, Instruction, InstructionInfoFactory, MemoryOperand,
    Mnemonic, OpAccess, OpKind, Register,
};

fn acc_of(a: OpAccess) -> Option<u64> {
    match a {
        OpAccess::Read | OpAccess::CondRead => Some(ACC_R),
        OpAccess::Write | OpAccess::CondWrite => Some(ACC_W),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => Some(ACC_RW),
        _ => None,
    }
}

fn tag_off(acc: u64) -> i64 {
    match acc {
        ACC_R => TLB_TAG_R,
        ACC_W => TLB_TAG_W,
        _ => TLB_TAG_RW,
    }
}

fn remap(r: Register, s: Option<usize>) -> Register {
    match gpr_idx(r) {
        Some(RSP) if !is_high8(r) => with_family(r, R15),
        Some(R15) => with_family(r, s.expect("r15 holder")),
        _ => r,
    }
}

fn pick(excluded: u16, norex: bool) -> usize {
    pick_scratch(excluded, norex).expect("scratch register available")
}

enum Stub {
    Chain { site: usize },
    Stop { patch: u64, rip: u64, reason: u64 },
    MemSlow { patch: u64, back: u64, m: MemDesc, size: u32, acc: u64, fl: bool, t1: usize, t2: usize, rip: u64 },
    PopfTrap { patch: u64, v: usize, next: u64 },
}

enum EaSrc {
    Imm(u64),
    Mem(MemDesc),
    LastEa,
}

enum Resume {
    Imm(u64),
    IndTarget,
}

struct Tx<'a> {
    a: Asm,
    id: u32,
    g: Globals,
    stubs: Vec<Stub>,
    sites: Vec<ChainSite>,
    meta: Vec<NativeMeta>,
    starts: Vec<(u64, u64)>,
    interp: &'a mut Vec<Instruction>,
    mem_hooks: bool,
    mem_r: bool,
    mem_w: bool,
    info: InstructionInfoFactory,
}

impl Tx<'_> {
    fn r(i: usize) -> Register {
        GPR64[i]
    }

    fn exit_now(&mut self, reason: u64, rip: u64, aux: u64) -> AResult {
        self.a.store_imm64(OFF_RIP, rip)?;
        self.a.store_imm64(OFF_EXIT_AUX, aux)?;
        self.a.mov_mi(self.a.st(OFF_EXIT_REASON), reason as i32)?;
        self.a.jmp_to(self.g.exit_sync)
    }

    fn chain(&mut self, target: u64, backward: bool) -> AResult {
        if backward {
            self.a.mov_mr(self.a.spill_slot(RCX), Register::RCX)?;
            self.a.mov_rm(Register::RCX, self.a.st(OFF_RUN_FLAG))?;
            let p = self.a.jrcxz_far()?;
            self.a.mov_rm(Register::RCX, self.a.spill_slot(RCX))?;
            self.stubs.push(Stub::Stop { patch: p, rip: target, reason: EXIT_STOP });
        }
        let patch = self.a.jmp_rel32()?;
        self.sites.push(ChainSite { patch, stub: 0, target, linked: None });
        self.stubs.push(Stub::Chain { site: self.sites.len() - 1 });
        Ok(())
    }

    fn compute_ea(&mut self, dst: usize, tmp: usize, m: &MemDesc) -> AResult {
        let d = Self::r(dst);
        if let Some(abs) = m.absolute {
            self.a.mov_ri(d, abs)?;
        } else {
            let uses15 = [m.base, m.index].iter().any(|&r| gpr_idx(r) == Some(R15));
            if uses15 {
                self.a.mov_rm(d, self.a.gpr(R15))?;
            }
            let fam = |r: Register| match gpr_idx(r) {
                Some(RSP) => with_family(r, R15),
                Some(R15) => with_family(r, dst),
                _ => r,
            };
            let mo = MemoryOperand::with_base_index_scale_displ_size(
                fam(m.base),
                fam(m.index),
                m.scale,
                m.disp,
                if m.disp != 0 { 1 } else { 0 },
            );
            self.a.lea(d, mo)?;
        }
        if let Some(seg) = m.seg {
            let t = Self::r(tmp);
            self.a.mov_rm(t, self.a.st(seg))?;
            self.a.lea(d, MemoryOperand::with_base_index(d, t))?;
        }
        Ok(())
    }

    fn hook_call(&mut self, kind: u64, acc: u64, size: u64, ea: EaSrc, resume: Resume) -> AResult {
        match ea {
            EaSrc::Imm(v) => self.a.store_imm64(OFF_ARG_EA, v)?,
            EaSrc::LastEa => {
                self.a.mov_mr(self.a.spill_slot(TMP_SLOT), Register::RAX)?;
                self.a.mov_rm(Register::RAX, self.a.st(OFF_LAST_EA))?;
                self.a.mov_mr(self.a.st(OFF_ARG_EA), Register::RAX)?;
                self.a.mov_rm(Register::RAX, self.a.spill_slot(TMP_SLOT))?;
            }
            EaSrc::Mem(m) => {
                let x = pick(m.regs(), false);
                let y = pick(m.regs() | bit(x), false);
                self.a.mov_mr(self.a.spill_slot(x), Self::r(x))?;
                self.a.mov_mr(self.a.spill_slot(y), Self::r(y))?;
                self.compute_ea(x, y, &m)?;
                self.a.mov_mr(self.a.st(OFF_ARG_EA), Self::r(x))?;
                self.a.mov_rm(Self::r(x), self.a.spill_slot(x))?;
                self.a.mov_rm(Self::r(y), self.a.spill_slot(y))?;
            }
        }
        match resume {
            Resume::Imm(v) => self.a.store_imm64(OFF_RIP, v)?,
            Resume::IndTarget => {
                self.a.mov_mr(self.a.spill_slot(TMP_SLOT), Register::RAX)?;
                self.a.mov_rm(Register::RAX, self.a.st(OFF_IND_TARGET))?;
                self.a.mov_mr(self.a.st(OFF_RIP), Register::RAX)?;
                self.a.mov_rm(Register::RAX, self.a.spill_slot(TMP_SLOT))?;
            }
        }
        self.a.mov_mi(self.a.st(OFF_ARG_KIND), (kind | acc << 8 | size << 16) as i32)?;
        self.a.mov_mi(self.a.st(OFF_ARG_BLOCK), self.id as i32)?;
        self.a.call_to(self.g.tramp)
    }

    fn read_hook(&mut self, m: MemDesc, size: u32, rip: u64) -> AResult {
        if self.mem_r { self.hook_call(KIND_MEMR, ACC_R, size as u64, EaSrc::Mem(m), Resume::Imm(rip)) } else { Ok(()) }
    }

    fn write_hook(&mut self, size: u32, resume: Resume) -> AResult {
        if self.mem_w { self.hook_call(KIND_MEMW, ACC_W, size as u64, EaSrc::LastEa, resume) } else { Ok(()) }
    }

    #[allow(clippy::too_many_arguments)]
    fn lookup(&mut self, m: &MemDesc, size: u32, acc: u64, fl: bool, t1: usize, t2: usize, rip: u64) -> AResult {
        let (r1, r2) = (Self::r(t1), Self::r(t2));
        if fl {
            self.a.save_flags()?;
        }
        self.a.mov_mr(self.a.spill_slot(t1), r1)?;
        self.a.mov_mr(self.a.spill_slot(t2), r2)?;
        self.compute_ea(t1, t2, m)?;
        if self.mem_hooks {
            self.a.mov_mr(self.a.st(OFF_LAST_EA), r1)?;
        }
        self.a.mov_rr(r2, r1)?;
        self.a.op_ri(Code::Shr_rm64_imm8, r2, 7)?;
        self.a.op_ri(Code::And_rm64_imm32, r2, ((TLB_ENTRIES - 1) << 5) as i64)?;
        self.a.op_rm(Code::Add_r64_rm64, r2, self.a.st(OFF_TLB_PTR))?;
        self.a.op_rm(Code::Sub_r64_rm64, r1, mem(r2, tag_off(acc)))?;
        self.a.op_ri(Code::Cmp_rm64_imm32, r1, (4096 - size + 1) as i64)?;
        let patch = self.a.jcc_rel32(0x3)?;
        self.a.op_rm(Code::Add_r64_rm64, r1, mem(r2, TLB_HOST))?;
        let back = self.a.here();
        self.a.mov_rm(r2, self.a.spill_slot(t2))?;
        if fl {
            self.a.restore_flags()?;
        }
        self.stubs.push(Stub::MemSlow { patch, back, m: *m, size, acc, fl, t1, t2, rip });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn mem_insn(&mut self, host: &Instruction, m: &MemDesc, size: u32, acc: u64, fl: bool, excl: u16, extra: u16, norex: bool, rip: u64) -> AResult {
        let mut ex = excl | m.regs() | bit(RSP) | bit(R15);
        if fl {
            ex |= bit(RAX);
        }
        let t1 = pick(ex, norex);
        let t2 = pick(ex | bit(t1), false);
        self.lookup(m, size, acc, fl, t1, t2, rip)?;
        let mut h = *host;
        h.set_memory_base(Self::r(t1));
        h.set_memory_index(Register::None);
        h.set_memory_index_scale(1);
        h.set_memory_displacement64(0);
        h.set_memory_displ_size(0);
        h.set_segment_prefix(Register::None);
        let lo = self.a.here();
        self.a.ins(&h)?;
        self.meta.push(NativeMeta { lo, hi: self.a.here(), rip, spilled: extra | bit(t1) });
        self.a.mov_rm(Self::r(t1), self.a.spill_slot(t1))
    }

    fn native(&mut self, h: &Instruction, rip: u64, spilled: u16) -> AResult {
        let lo = self.a.here();
        self.a.ins(h)?;
        self.meta.push(NativeMeta { lo, hi: self.a.here(), rip, spilled });
        Ok(())
    }

    fn generic(&mut self, insn: &Instruction, bytes: &[u8], fl_live: bool) -> AResult {
        let info = self.info.info(insn).clone();
        let mut used = 0u16;
        let mut high8 = false;
        for ur in info.used_registers() {
            if let Some(i) = gpr_idx(ur.register()) {
                used |= bit(i);
                high8 |= is_high8(ur.register());
            }
        }
        let mem_op = mem_op_index(insn);
        let is_lea = insn.mnemonic() == Mnemonic::Lea;
        if used & (bit(RSP) | bit(R15)) == 0 && mem_op.is_none() {
            let lo = self.a.here();
            self.a.raw(bytes)?;
            self.meta.push(NativeMeta { lo, hi: self.a.here(), rip: insn.ip(), spilled: 0 });
            return Ok(());
        }
        let acc = if is_lea { None } else { mem_op.and_then(|op| acc_of(info.op_access(op))) };
        let m = MemDesc::of(insn);
        let mut r15_reg = false;
        let mut r15_write = false;
        for op in 0..insn.op_count() {
            if insn.op_kind(op) == OpKind::Register && gpr_idx(insn.op_register(op)) == Some(R15) {
                r15_reg = true;
                r15_write |= matches!(
                    info.op_access(op),
                    OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                );
            }
        }
        let lea_abs = is_lea && m.absolute.is_some();
        let needs_s = r15_reg || (is_lea && !lea_abs && m.regs() & bit(R15) != 0);
        let may_fault = matches!(insn.mnemonic(), Mnemonic::Div | Mnemonic::Idiv);
        let fl = (fl_live || may_fault) && acc.is_some();
        let mut excl = used | bit(RSP) | bit(R15);
        let s = if needs_s {
            let s = pick(excl | m.regs() | if fl { bit(RAX) } else { 0 }, false);
            excl |= bit(s);
            Some(s)
        } else {
            None
        };
        let mut h = *insn;
        let rm_code = match insn.code() {
            Code::Mov_AL_moffs8 => Some(Code::Mov_r8_rm8),
            Code::Mov_AX_moffs16 => Some(Code::Mov_r16_rm16),
            Code::Mov_EAX_moffs32 => Some(Code::Mov_r32_rm32),
            Code::Mov_RAX_moffs64 => Some(Code::Mov_r64_rm64),
            Code::Mov_moffs8_AL => Some(Code::Mov_rm8_r8),
            Code::Mov_moffs16_AX => Some(Code::Mov_rm16_r16),
            Code::Mov_moffs32_EAX => Some(Code::Mov_rm32_r32),
            Code::Mov_moffs64_RAX => Some(Code::Mov_rm64_r64),
            _ => None,
        };
        if let Some(c) = rm_code {
            h.set_code(c);
        }
        if lea_abs {
            let d = remap(insn.op0_register(), s);
            let v = m.absolute.unwrap();
            h = match d.size() {
                8 => Instruction::with2(Code::Mov_r64_imm64, d, v),
                4 => Instruction::with2(Code::Mov_r32_imm32, d, v as u32),
                _ => Instruction::with2(Code::Mov_r16_imm16, d, v as u16 as u32),
            }
            .expect("mov imm form");
        } else {
            for op in 0..insn.op_count() {
                if insn.op_kind(op) == OpKind::Register {
                    h.set_op_register(op, remap(insn.op_register(op), s));
                }
            }
            if is_lea {
                h.set_memory_base(remap(insn.memory_base(), s));
                h.set_memory_index(remap(insn.memory_index(), s));
            }
        }
        let size = insn.memory_size().size() as u32;
        if let Some(acc) = acc
            && acc & ACC_R != 0
        {
            self.read_hook(m, size, insn.ip())?;
        }
        if let Some(s) = s {
            self.a.mov_mr(self.a.spill_slot(s), Self::r(s))?;
            self.a.mov_rm(Self::r(s), self.a.gpr(R15))?;
        }
        let sbit = s.map(bit).unwrap_or(0);
        match acc {
            Some(acc) => self.mem_insn(&h, &m, size, acc, fl, excl, sbit, high8, insn.ip())?,
            None => self.native(&h, insn.ip(), sbit)?,
        }
        if let Some(s) = s {
            if r15_write {
                self.a.mov_mr(self.a.gpr(R15), Self::r(s))?;
            }
            self.a.mov_rm(Self::r(s), self.a.spill_slot(s))?;
        }
        if let Some(acc) = acc
            && acc & ACC_W != 0
        {
            self.write_hook(size, Resume::Imm(insn.next_ip()))?;
        }
        Ok(())
    }

    fn mov_store(size: u32, src: Register) -> Instruction {
        let code = if size == 8 { Code::Mov_rm64_r64 } else { Code::Mov_rm16_r16 };
        let src = if size == 8 { src } else { GPR16[gpr_idx(src).unwrap()] };
        Instruction::with2(code, MemoryOperand::with_base(Register::RAX), src).unwrap()
    }
    fn mov_load(size: u32, dst: Register) -> Instruction {
        let code = if size == 8 { Code::Mov_r64_rm64 } else { Code::Mov_r16_rm16 };
        let dst = if size == 8 { dst } else { GPR16[gpr_idx(dst).unwrap()] };
        Instruction::with2(code, dst, MemoryOperand::with_base(Register::RAX)).unwrap()
    }

    fn adjust_rsp(&mut self, delta: i64) -> AResult {
        self.a.lea(Register::R15, mem(Register::R15, delta))
    }

    fn push_reg(&mut self, v: usize, size: u32, fl: bool, rip: u64) -> AResult {
        let h = Self::mov_store(size, Self::r(v));
        self.mem_insn(&h, &MemDesc::stack(-(size as i64)), size, ACC_W, fl, bit(v), bit(v), false, rip)?;
        self.adjust_rsp(-(size as i64))
    }

    fn push(&mut self, insn: &Instruction, fl: bool) -> AResult {
        let size = (-insn.stack_pointer_increment()) as u32;
        let rip = insn.ip();
        match insn.op_kind(0) {
            OpKind::Register => {
                let r = insn.op0_register();
                let idx = gpr_idx(r).unwrap();
                if idx == R15 {
                    let v = pick(0, false);
                    self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
                    self.a.mov_rm(Self::r(v), self.a.gpr(R15))?;
                    self.push_reg(v, size, fl, rip)?;
                    self.a.mov_rm(Self::r(v), self.a.spill_slot(v))?;
                } else {
                    let src = if idx == RSP { Register::R15 } else { GPR64[idx] };
                    let h = Self::mov_store(size, src);
                    self.mem_insn(&h, &MemDesc::stack(-(size as i64)), size, ACC_W, fl, bit(gpr_idx(src).unwrap()), 0, false, rip)?;
                    self.adjust_rsp(-(size as i64))?;
                }
            }
            OpKind::Memory => {
                let m = MemDesc::of(insn);
                self.read_hook(m, size, rip)?;
                let v = pick(m.regs(), false);
                self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
                let ld = Self::mov_load(size, Self::r(v));
                self.mem_insn(&ld, &m, size, ACC_R, fl, bit(v), bit(v), false, rip)?;
                self.push_reg(v, size, fl, rip)?;
                self.a.mov_rm(Self::r(v), self.a.spill_slot(v))?;
            }
            _ => {
                let h = if size == 8 {
                    Instruction::with2(Code::Mov_rm64_imm32, MemoryOperand::with_base(Register::RAX), insn.immediate(0) as i64 as i32).unwrap()
                } else {
                    Instruction::with2(Code::Mov_rm16_imm16, MemoryOperand::with_base(Register::RAX), insn.immediate(0) as u16 as u32).unwrap()
                };
                self.mem_insn(&h, &MemDesc::stack(-(size as i64)), size, ACC_W, fl, 0, 0, false, rip)?;
                self.adjust_rsp(-(size as i64))?;
            }
        }
        self.write_hook(size, Resume::Imm(insn.next_ip()))
    }

    fn pop(&mut self, insn: &Instruction, fl: bool) -> AResult {
        let size = insn.stack_pointer_increment() as u32;
        let rip = insn.ip();
        let top = MemDesc::stack(0);
        self.read_hook(top, size, rip)?;
        match insn.op_kind(0) {
            OpKind::Register => {
                let idx = gpr_idx(insn.op0_register()).unwrap();
                if idx == RSP {
                    let h = Self::mov_load(size, Register::R15);
                    self.mem_insn(&h, &top, size, ACC_R, fl, 0, 0, false, rip)?;
                } else if idx == R15 {
                    let v = pick(0, false);
                    self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
                    let h = Self::mov_load(size, Self::r(v));
                    self.mem_insn(&h, &top, size, ACC_R, fl, bit(v), bit(v), false, rip)?;
                    let src = if size == 8 { Self::r(v) } else { GPR16[v] };
                    self.a.mov_mr(self.a.gpr(R15), src)?;
                    self.a.mov_rm(Self::r(v), self.a.spill_slot(v))?;
                    self.adjust_rsp(size as i64)?;
                } else {
                    let h = Self::mov_load(size, GPR64[idx]);
                    self.mem_insn(&h, &top, size, ACC_R, fl, bit(idx), 0, false, rip)?;
                    self.adjust_rsp(size as i64)?;
                }
            }
            _ => {
                let m = MemDesc::of(insn);
                let v = pick(m.regs(), false);
                self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
                let ld = Self::mov_load(size, Self::r(v));
                self.mem_insn(&ld, &top, size, ACC_R, fl, bit(v), bit(v), false, rip)?;
                self.adjust_rsp(size as i64)?;
                let st = Self::mov_store(size, Self::r(v));
                self.mem_insn(&st, &m, size, ACC_W, fl, bit(v), bit(v), false, rip)?;
                self.a.mov_rm(Self::r(v), self.a.spill_slot(v))?;
                self.write_hook(size, Resume::Imm(insn.next_ip()))?;
            }
        }
        Ok(())
    }

    fn pushfq(&mut self, insn: &Instruction, fl: bool) -> AResult {
        let v = pick(0, false);
        self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
        self.a.op0(Code::Pushfq)?;
        self.a.op_r(Code::Pop_r64, Self::r(v))?;
        self.push_reg(v, 8, fl, insn.ip())?;
        self.a.mov_rm(Self::r(v), self.a.spill_slot(v))?;
        self.write_hook(8, Resume::Imm(insn.next_ip()))
    }

    fn popfq(&mut self, insn: &Instruction) -> AResult {
        let top = MemDesc::stack(0);
        self.read_hook(top, 8, insn.ip())?;
        let v = pick(0, false);
        self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
        let h = Self::mov_load(8, Self::r(v));
        self.mem_insn(&h, &top, 8, ACC_R, false, bit(v), bit(v), false, insn.ip())?;
        self.adjust_rsp(8)?;
        self.a.op_ri(Code::Test_rm64_imm32, Self::r(v), 0x100)?;
        let trap = self.a.jcc_rel32(0x5)?;
        self.finish_popfq(v)?;
        self.stubs.push(Stub::PopfTrap { patch: trap, v, next: insn.next_ip() });
        Ok(())
    }

    fn finish_popfq(&mut self, v: usize) -> AResult {
        self.a.op_ri(Code::And_rm64_imm32, Self::r(v), 0x200CD5)?;
        self.a.op_ri(Code::Or_rm64_imm32, Self::r(v), 0x202)?;
        self.a.op_r(Code::Push_r64, Self::r(v))?;
        self.a.op0(Code::Popfq)?;
        self.a.mov_rm(Self::r(v), self.a.spill_slot(v))
    }

    fn leave(&mut self, insn: &Instruction, fl: bool) -> AResult {
        self.a.mov_rr(Register::R15, Register::RBP)?;
        let top = MemDesc::stack(0);
        self.read_hook(top, 8, insn.ip())?;
        let h = Self::mov_load(8, Register::RBP);
        self.mem_insn(&h, &top, 8, ACC_R, fl, bit(5), 0, false, insn.ip())?;
        self.adjust_rsp(8)
    }

    fn load_target(&mut self, insn: &Instruction, fl: bool) -> AResult {
        match insn.op_kind(0) {
            OpKind::Register => {
                let idx = gpr_idx(insn.op0_register()).unwrap();
                if idx == R15 {
                    self.a.mov_mr(self.a.spill_slot(TMP_SLOT), Register::RAX)?;
                    self.a.mov_rm(Register::RAX, self.a.gpr(R15))?;
                    self.a.mov_mr(self.a.st(OFF_IND_TARGET), Register::RAX)?;
                    self.a.mov_rm(Register::RAX, self.a.spill_slot(TMP_SLOT))
                } else {
                    let r = if idx == RSP { Register::R15 } else { GPR64[idx] };
                    self.a.mov_mr(self.a.st(OFF_IND_TARGET), r)
                }
            }
            _ => {
                let m = MemDesc::of(insn);
                self.read_hook(m, 8, insn.ip())?;
                let v = pick(m.regs(), false);
                self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
                let ld = Self::mov_load(8, Self::r(v));
                self.mem_insn(&ld, &m, 8, ACC_R, fl, bit(v), bit(v), false, insn.ip())?;
                self.a.mov_mr(self.a.st(OFF_IND_TARGET), Self::r(v))?;
                self.a.mov_rm(Self::r(v), self.a.spill_slot(v))
            }
        }
    }

    fn push_imm64(&mut self, value: u64, rip: u64) -> AResult {
        let v = pick(0, false);
        self.a.mov_mr(self.a.spill_slot(v), Self::r(v))?;
        self.a.mov_ri(Self::r(v), value)?;
        self.push_reg(v, 8, true, rip)?;
        self.a.mov_rm(Self::r(v), self.a.spill_slot(v))
    }

    fn rd_base(&mut self, insn: &Instruction, off: usize) -> AResult {
        let d = insn.op0_register();
        let idx = gpr_idx(d).unwrap();
        if idx == R15 {
            self.a.mov_mr(self.a.spill_slot(TMP_SLOT), Register::RAX)?;
            self.a.mov_rm(if d.size() == 8 { Register::RAX } else { Register::EAX }, self.a.st(off))?;
            self.a.mov_mr(self.a.gpr(R15), Register::RAX)?;
            self.a.mov_rm(Register::RAX, self.a.spill_slot(TMP_SLOT))
        } else {
            self.a.mov_rm(remap(d, None), self.a.st(off))
        }
    }

    fn wr_base(&mut self, insn: &Instruction, off: usize) -> AResult {
        let s = insn.op0_register();
        let idx = gpr_idx(s).unwrap();
        let tmp = idx == R15;
        let src = if tmp {
            self.a.mov_mr(self.a.spill_slot(TMP_SLOT), Register::RAX)?;
            self.a.mov_rm(Register::RAX, self.a.gpr(R15))?;
            with_family(s, RAX)
        } else {
            remap(s, None)
        };
        self.a.mov_mr(self.a.st(off), src)?;
        if src.size() == 4 {
            self.a.mov_mi32(self.a.st(off + 4), 0)?;
        }
        if tmp {
            self.a.mov_rm(Register::RAX, self.a.spill_slot(TMP_SLOT))?;
        }
        Ok(())
    }

    fn emit_stubs(&mut self) -> AResult {
        let stubs = std::mem::take(&mut self.stubs);
        for s in stubs {
            match s {
                Stub::Chain { site } => {
                    let here = self.a.here();
                    let target = self.sites[site].target;
                    self.sites[site].stub = here;
                    patch_rel32(self.sites[site].patch, here);
                    self.a.store_imm64(OFF_RIP, target)?;
                    self.a.store_imm64(OFF_CHAIN_SITE, (self.id as u64) << 32 | site as u64)?;
                    self.a.mov_mi(self.a.st(OFF_EXIT_REASON), EXIT_CHAIN as i32)?;
                    self.a.jmp_to(self.g.exit_sync)?;
                }
                Stub::Stop { patch, rip, reason } => {
                    patch_rel32(patch, self.a.here());
                    self.a.mov_rm(Register::RCX, self.a.spill_slot(RCX))?;
                    self.exit_now(reason, rip, 0)?;
                }
                Stub::PopfTrap { patch, v, next } => {
                    patch_rel32(patch, self.a.here());
                    self.finish_popfq(v)?;
                    self.exit_now(EXIT_TRAP_PENDING, next, 0)?;
                }
                Stub::MemSlow { patch, back, m, size, acc, fl, t1, t2, rip } => {
                    let (r1, r2) = (Self::r(t1), Self::r(t2));
                    patch_rel32(patch, self.a.here());
                    self.compute_ea(t1, t2, &m)?;
                    self.a.mov_mr(self.a.st(OFF_ARG_EA), r1)?;
                    self.a.mov_ri(r1, rip)?;
                    self.a.mov_mr(self.a.st(OFF_RIP), r1)?;
                    self.a.mov_rm(r1, self.a.spill_slot(t1))?;
                    self.a.mov_rm(r2, self.a.spill_slot(t2))?;
                    if fl {
                        self.a.restore_flags()?;
                    }
                    self.a.mov_mi(self.a.st(OFF_ARG_KIND), (KIND_MEM | acc << 8 | (size as u64) << 16) as i32)?;
                    self.a.mov_mi(self.a.st(OFF_ARG_BLOCK), self.id as i32)?;
                    self.a.call_to(self.g.tramp)?;
                    if fl {
                        self.a.save_flags()?;
                    }
                    self.a.mov_mr(self.a.spill_slot(t1), r1)?;
                    self.a.mov_mr(self.a.spill_slot(t2), r2)?;
                    self.a.mov_rm(r1, self.a.st(OFF_ARG_RET))?;
                    self.a.jmp_to(back)?;
                }
            }
        }
        Ok(())
    }
}

impl Jit {
    pub fn translate(&mut self, memory: &Memory, rip: u64, cfg: &TxCfg) -> Result<u32, TxError> {
        if self.needs_flush() {
            return Err(TxError::Asm(AsmError::OutOfSpace));
        }
        let id = self.blocks.len() as u32;
        let mut insns: Vec<(Instruction, Kind, &[u8])> = Vec::new();
        let mut info = InstructionInfoFactory::new();
        if cfg.until != Some(rip) {
            let win = memory.fetch_window(rip, 4096 + 16).map_err(TxError::Fetch)?;
            let mut d = Decoder::with_ip(64, win, rip, DecoderOptions::NONE);
            let max = if cfg.counted || cfg.single { 1 } else { MAX_INSNS };
            while insns.len() < max {
                let ip = d.ip();
                if !insns.is_empty() && (Some(ip) == cfg.until || ip - rip >= 4096) {
                    break;
                }
                let insn = d.decode();
                if insn.is_invalid() {
                    if d.last_error() == DecoderError::NoMoreBytes {
                        if insns.is_empty() {
                            let next = rip + win.len() as u64;
                            let f = memory.fetch_window(next, 1).err().unwrap_or(Fault { kind: FaultKind::Unmapped, addr: next });
                            return Err(TxError::Fetch(f));
                        }
                        break;
                    }
                    let off = (ip - rip) as usize;
                    insns.push((insn, Kind::Exception(crate::EXC_INVALID_OPCODE), &win[off..off]));
                    break;
                }
                let mut k = classify(&insn, &mut info);
                if cfg.insn_hooks & insn_hook_bit(&insn) != 0 && matches!(k, Kind::Generic) {
                    k = Kind::Interp;
                }
                let off = (ip - rip) as usize;
                insns.push((insn, k, &win[off..off + insn.len()]));
                if k.terminates() {
                    break;
                }
            }
        }

        let mut live = vec![0u32; insns.len() + 1];
        live[insns.len()] = ARITH;
        for (n, (insn, k, _)) in insns.iter().enumerate().rev() {
            let (r, kill) = match k {
                Kind::Skip | Kind::Exception(_) | Kind::Unsupported => (0, 0),
                _ => flags_effect(insn),
            };
            live[n] = r | (live[n + 1] & !kill);
        }

        let mut tx = Tx {
            a: Asm::new(self.code_pos, self.code_end, self.state),
            id,
            g: self.g,
            stubs: Vec::new(),
            sites: Vec::new(),
            meta: Vec::new(),
            starts: Vec::new(),
            interp: &mut self.interp,
            mem_hooks: cfg.mem_read_hooks || cfg.mem_write_hooks,
            mem_r: cfg.mem_read_hooks,
            mem_w: cfg.mem_write_hooks,
            info,
        };
        let host = tx.a.here();
        let end = insns.last().map(|(i, _, _)| i.next_ip()).unwrap_or(rip);

        if insns.is_empty() {
            tx.exit_now(EXIT_UNTIL, rip, 0)?;
        } else {
            if cfg.counted {
                tx.a.mov_mr(tx.a.spill_slot(RCX), Register::RCX)?;
                tx.a.mov_rm(Register::RCX, tx.a.st(OFF_ICOUNT))?;
                let p = tx.a.jrcxz_far()?;
                tx.a.lea(Register::RCX, mem(Register::RCX, -1))?;
                tx.a.mov_mr(tx.a.st(OFF_ICOUNT), Register::RCX)?;
                tx.a.mov_rm(Register::RCX, tx.a.spill_slot(RCX))?;
                tx.stubs.push(Stub::Stop { patch: p, rip, reason: EXIT_COUNT });
            }
            if (cfg.block_hook)(rip) {
                tx.hook_call(KIND_BLOCK, 0, end - rip, EaSrc::Imm(rip), Resume::Imm(rip))?;
            }
            let mut terminated = false;
            for (n, (insn, k, bytes)) in insns.iter().enumerate() {
                let ip = insn.ip();
                let next = insn.next_ip();
                tx.starts.push((ip, tx.a.here()));
                if (cfg.code_hook)(ip) {
                    tx.hook_call(KIND_CODE, 0, insn.len() as u64, EaSrc::Imm(ip), Resume::Imm(ip))?;
                }
                let fl = live[n] != 0;
                match *k {
                    Kind::Generic => tx.generic(insn, bytes, fl)?,
                    Kind::Skip => {}
                    Kind::Push => tx.push(insn, fl)?,
                    Kind::Pop => tx.pop(insn, fl)?,
                    Kind::Pushfq => tx.pushfq(insn, fl)?,
                    Kind::Popfq => tx.popfq(insn)?,
                    Kind::Leave => tx.leave(insn, fl)?,
                    Kind::RdBase(off) => tx.rd_base(insn, off)?,
                    Kind::WrBase(off) => tx.wr_base(insn, off)?,
                    Kind::Interp | Kind::InterpEnd => {
                        let idx = tx.interp.len() as u64;
                        tx.interp.push(*insn);
                        tx.hook_call(KIND_INTERP, 0, 0, EaSrc::Imm(idx), Resume::Imm(ip))?;
                        if matches!(k, Kind::InterpEnd) {
                            tx.chain(next, false)?;
                        }
                    }
                    Kind::TxAbort(t) => {
                        tx.a.mov_ri(Register::RAX, 0)?;
                        tx.chain(t, t <= ip)?;
                    }
                    Kind::Jmp(t) => tx.chain(t, t <= ip)?,
                    Kind::Jcc(t) => {
                        let cc = insn.condition_code() as u8 - ConditionCode::o as u8;
                        let p = tx.a.jcc_rel32(cc)?;
                        tx.chain(next, false)?;
                        patch_rel32(p, tx.a.here());
                        tx.chain(t, t <= ip)?;
                    }
                    Kind::LoopLike(t) => {
                        let op = match insn.mnemonic() {
                            Mnemonic::Loopne => 0xE0,
                            Mnemonic::Loope => 0xE1,
                            Mnemonic::Loop => 0xE2,
                            _ => 0xE3,
                        };
                        let addr32 = matches!(
                            insn.code(),
                            Code::Loop_rel8_64_ECX | Code::Loope_rel8_64_ECX | Code::Loopne_rel8_64_ECX | Code::Jecxz_rel8_64
                        );
                        if addr32 {
                            tx.a.raw(&[0x67])?;
                        }
                        let lo = tx.a.here();
                        tx.a.raw(&[op, 0x02, 0xEB, 0x05])?;
                        tx.meta.push(NativeMeta { lo, hi: lo + 2, rip: ip, spilled: 0 });
                        let p = tx.a.jmp_rel32()?;
                        tx.chain(next, false)?;
                        patch_rel32(p, tx.a.here());
                        tx.chain(t, t <= ip)?;
                    }
                    Kind::CallDirect(t) => {
                        tx.push_imm64(next, ip)?;
                        tx.write_hook(8, Resume::Imm(t))?;
                        tx.chain(t, t <= ip)?;
                    }
                    Kind::CallIndirect => {
                        tx.load_target(insn, true)?;
                        tx.push_imm64(next, ip)?;
                        tx.write_hook(8, Resume::IndTarget)?;
                        tx.a.jmp_to(tx.g.indirect)?;
                    }
                    Kind::JmpIndirect => {
                        tx.load_target(insn, true)?;
                        tx.a.jmp_to(tx.g.indirect)?;
                    }
                    Kind::Ret(imm) => {
                        let top = MemDesc::stack(0);
                        tx.read_hook(top, 8, ip)?;
                        let v = pick(0, false);
                        tx.a.mov_mr(tx.a.spill_slot(v), Tx::r(v))?;
                        let h = Tx::mov_load(8, Tx::r(v));
                        tx.mem_insn(&h, &top, 8, ACC_R, true, bit(v), bit(v), false, ip)?;
                        tx.a.mov_mr(tx.a.st(OFF_IND_TARGET), Tx::r(v))?;
                        tx.a.mov_rm(Tx::r(v), tx.a.spill_slot(v))?;
                        tx.adjust_rsp(8 + imm as i64)?;
                        tx.a.jmp_to(tx.g.indirect)?;
                    }
                    Kind::Syscall => tx.exit_now(EXIT_SYSCALL, next, 0)?,
                    Kind::Interrupt(n) => tx.exit_now(EXIT_INTERRUPT, next, n as u64)?,
                    Kind::Exception(v) => tx.exit_now(EXIT_EXCEPTION, ip, v as u64)?,
                    Kind::Unsupported => tx.exit_now(EXIT_UNSUPPORTED, ip, 0)?,
                }
                terminated = k.terminates();
            }
            if !terminated {
                tx.chain(end, false)?;
            }
        }
        tx.emit_stubs()?;
        let host_end = tx.a.here();
        let block = Block {
            start: rip,
            end,
            host,
            host_end,
            sites: tx.sites,
            incoming: Vec::new(),
            meta: tx.meta,
            insn_starts: tx.starts,
            valid: true,
        };
        self.code_pos = (host_end + 15) & !15;
        self.blocks.push(block);
        if cfg.single {
            self.single_rip.insert(rip, id);
        } else {
            self.by_rip.insert(rip, id);
        }
        self.by_host.insert(host, id);
        let mut p = rip & !(PAGE - 1);
        while p < end.max(rip + 1) {
            self.pages.entry(p).or_default().push(id);
            p += PAGE;
        }
        Ok(id)
    }
}
