use crate::jit::MemDesc;
use crate::jit::regs::{RCX, RSP, gpr_idx, is_high8};
use crate::runtime::state::*;
use crate::hooks::{HOOK_MEM_READ, HOOK_MEM_WRITE, HookCb};
use crate::{Emu, MemAccess};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

const RSI: usize = 6;
const RDI: usize = 7;
const RBP: usize = 5;
const RAX: usize = 0;

const F_CF: u64 = 0x1;
const F_PF: u64 = 0x4;
const F_AF: u64 = 0x10;
const F_ZF: u64 = 0x40;
const F_SF: u64 = 0x80;
const F_DF: u64 = 0x400;
const F_OF: u64 = 0x800;

fn mask(size: u64) -> u64 {
    if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 }
}

fn reg(emu: &Emu, r: Register) -> u64 {
    let Some(i) = gpr_idx(r) else { return 0 };
    let v = emu.st().gpr[i];
    if is_high8(r) { (v >> 8) & 0xff } else { v & mask(r.size() as u64) }
}

fn seg_base(emu: &Emu, i: &Instruction) -> u64 {
    match i.segment_prefix() {
        Register::FS => emu.st().fs_base,
        Register::GS => emu.st().gs_base,
        _ => 0,
    }
}

fn ea(emu: &Emu, i: &Instruction) -> u64 {
    let m = MemDesc::of(i);
    let mut a = match m.absolute {
        Some(abs) => abs,
        None => reg(emu, m.base)
            .wrapping_add(reg(emu, m.index).wrapping_mul(m.scale as u64))
            .wrapping_add(m.disp as u64),
    };
    if m.addr32 {
        a &= 0xffff_ffff;
    }
    a.wrapping_add(seg_base(emu, i))
}

struct Mem {
    r_hooks: bool,
    w_hooks: bool,
}

impl Mem {
    fn new(emu: &Emu) -> Self {
        Self {
            r_hooks: emu.has_hook(|s| matches!(&s.cb, Some(HookCb::Mem(m, _)) if m & HOOK_MEM_READ != 0)),
            w_hooks: emu.has_hook(|s| matches!(&s.cb, Some(HookCb::Mem(m, _)) if m & HOOK_MEM_WRITE != 0)),
        }
    }

    fn read(&self, emu: &mut Emu, addr: u64, size: u64, acc: u64) -> Result<u64, ()> {
        let p = emu.access_or_fault(addr, size, acc).ok_or(())?;
        let mut b = [0u8; 8];
        unsafe { core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), size as usize) };
        let v = u64::from_le_bytes(b);
        if self.r_hooks {
            emu.mem_hooks(MemAccess::Read, addr, size as usize, v);
        }
        Ok(v)
    }

    fn write(&self, emu: &mut Emu, addr: u64, size: u64, v: u64) -> Result<(), ()> {
        let p = emu.access_or_fault(addr, size, ACC_W).ok_or(())?;
        unsafe { core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), p, size as usize) };
        if self.w_hooks {
            emu.mem_hooks(MemAccess::Write, addr, size as usize, v);
        }
        Ok(())
    }
}

fn set_sub_flags(emu: &mut Emu, a: u64, b: u64, size: u64) {
    let m = mask(size);
    let (a, b) = (a & m, b & m);
    let res = a.wrapping_sub(b) & m;
    let top = size * 8 - 1;
    let mut f = 0;
    if a < b {
        f |= F_CF;
    }
    if (res as u8).count_ones().is_multiple_of(2) {
        f |= F_PF;
    }
    if (a ^ b ^ res) & 0x10 != 0 {
        f |= F_AF;
    }
    if res == 0 {
        f |= F_ZF;
    }
    if (res >> top) & 1 != 0 {
        f |= F_SF;
    }
    if (((a ^ b) & (a ^ res)) >> top) & 1 != 0 {
        f |= F_OF;
    }
    let st = emu.st_mut();
    st.rflags = (st.rflags & !(F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)) | f;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SOp {
    Movs,
    Stos,
    Lods,
    Cmps,
    Scas,
}

fn string_op(i: &Instruction) -> Option<(SOp, u64)> {
    use Mnemonic as M;
    Some(match i.mnemonic() {
        M::Movsb => (SOp::Movs, 1),
        M::Movsw => (SOp::Movs, 2),
        M::Movsd => (SOp::Movs, 4),
        M::Movsq => (SOp::Movs, 8),
        M::Stosb => (SOp::Stos, 1),
        M::Stosw => (SOp::Stos, 2),
        M::Stosd => (SOp::Stos, 4),
        M::Stosq => (SOp::Stos, 8),
        M::Lodsb => (SOp::Lods, 1),
        M::Lodsw => (SOp::Lods, 2),
        M::Lodsd => (SOp::Lods, 4),
        M::Lodsq => (SOp::Lods, 8),
        M::Cmpsb => (SOp::Cmps, 1),
        M::Cmpsw => (SOp::Cmps, 2),
        M::Cmpsd => (SOp::Cmps, 4),
        M::Cmpsq => (SOp::Cmps, 8),
        M::Scasb => (SOp::Scas, 1),
        M::Scasw => (SOp::Scas, 2),
        M::Scasd => (SOp::Scas, 4),
        M::Scasq => (SOp::Scas, 8),
        _ => return None,
    })
}

fn bulk(emu: &mut Emu, op: SOp, sz: u64, seg: u64) -> Result<bool, ()> {
    let st = emu.st_mut();
    let (count, rsi, rdi) = (st.gpr[RCX], st.gpr[RSI], st.gpr[RDI]);
    let src = seg.wrapping_add(rsi);
    let mut chunk = count.min((4096 - (rdi & 0xfff)) / sz);
    if op == SOp::Movs {
        chunk = chunk.min((4096 - (src & 0xfff)) / sz);
    }
    if chunk == 0 {
        return Ok(false);
    }
    let bytes = chunk * sz;
    let ps = if op == SOp::Movs { Some(emu.access_or_fault(src, bytes, ACC_R).ok_or(())?) } else { None };
    let pd = emu.access_or_fault(rdi, bytes, ACC_W).ok_or(())?;
    unsafe {
        match ps {
            Some(ps) if rdi > src && rdi < src + bytes => {
                for k in 0..chunk as usize {
                    let off = k * sz as usize;
                    let mut e = [0u8; 8];
                    core::ptr::copy_nonoverlapping(ps.add(off), e.as_mut_ptr(), sz as usize);
                    core::ptr::copy_nonoverlapping(e.as_ptr(), pd.add(off), sz as usize);
                }
            }
            Some(ps) => core::ptr::copy(ps, pd, bytes as usize),
            None => {
                let v = (emu.st_mut().gpr[RAX] & mask(sz)).to_le_bytes();
                if sz == 1 {
                    core::ptr::write_bytes(pd, v[0], bytes as usize);
                } else {
                    for k in 0..chunk as usize {
                        core::ptr::copy_nonoverlapping(v.as_ptr(), pd.add(k * sz as usize), sz as usize);
                    }
                }
            }
        }
    }
    let st = emu.st_mut();
    if op == SOp::Movs {
        st.gpr[RSI] = rsi.wrapping_add(bytes);
    }
    st.gpr[RDI] = rdi.wrapping_add(bytes);
    st.gpr[RCX] = count - chunk;
    Ok(true)
}

fn string(emu: &mut Emu, i: &Instruction, op: SOp, sz: u64) -> Result<(), ()> {
    let mm = Mem::new(emu);
    let addr32 = (0..i.op_count()).any(|k| matches!(i.op_kind(k), OpKind::MemorySegESI | OpKind::MemoryESEDI));
    let amask = if addr32 { 0xffff_ffff } else { u64::MAX };
    let seg = seg_base(emu, i);
    let rep = i.has_rep_prefix() || i.has_repne_prefix();
    let cond = matches!(op, SOp::Cmps | SOp::Scas);
    loop {
        let st = emu.st_mut();
        let df = st.rflags & F_DF != 0;
        let step = if df { sz.wrapping_neg() } else { sz };
        if rep && st.gpr[RCX] & amask == 0 {
            break;
        }
        if rep && !df && !addr32 && !cond && op != SOp::Lods && !mm.r_hooks && !mm.w_hooks && bulk(emu, op, sz, seg)? {
            continue;
        }
        let st = emu.st_mut();
        let (rsi, rdi) = (st.gpr[RSI] & amask, st.gpr[RDI] & amask);
        let (mut nsi, mut ndi) = (rsi, rdi);
        match op {
            SOp::Movs => {
                let v = mm.read(emu, seg.wrapping_add(rsi), sz, ACC_R)?;
                mm.write(emu, rdi, sz, v)?;
                nsi = rsi.wrapping_add(step);
                ndi = rdi.wrapping_add(step);
            }
            SOp::Stos => {
                let v = emu.st_mut().gpr[RAX] & mask(sz);
                mm.write(emu, rdi, sz, v)?;
                ndi = rdi.wrapping_add(step);
            }
            SOp::Lods => {
                let v = mm.read(emu, seg.wrapping_add(rsi), sz, ACC_R)?;
                let st = emu.st_mut();
                st.gpr[RAX] = match sz {
                    4 => v,
                    8 => v,
                    _ => (st.gpr[RAX] & !mask(sz)) | v,
                };
                nsi = rsi.wrapping_add(step);
            }
            SOp::Cmps => {
                let a = mm.read(emu, seg.wrapping_add(rsi), sz, ACC_R)?;
                let b = mm.read(emu, rdi, sz, ACC_R)?;
                set_sub_flags(emu, a, b, sz);
                nsi = rsi.wrapping_add(step);
                ndi = rdi.wrapping_add(step);
            }
            SOp::Scas => {
                let b = mm.read(emu, rdi, sz, ACC_R)?;
                let a = emu.st_mut().gpr[RAX];
                set_sub_flags(emu, a, b, sz);
                ndi = rdi.wrapping_add(step);
            }
        }
        let st = emu.st_mut();
        st.gpr[RSI] = nsi & amask;
        st.gpr[RDI] = ndi & amask;
        if !rep {
            break;
        }
        st.gpr[RCX] = (st.gpr[RCX] & amask).wrapping_sub(1) & amask;
        if cond {
            let zf = st.rflags & F_ZF != 0;
            if (i.has_repe_prefix() && !zf) || (i.has_repne_prefix() && zf) {
                break;
            }
        }
    }
    Ok(())
}

fn enter(emu: &mut Emu, i: &Instruction) -> Result<(), ()> {
    let mm = Mem::new(emu);
    let size = i.immediate16() as u64;
    let level = (i.immediate8_2nd() & 31) as u64;
    let st = emu.st_mut();
    let (mut rsp, mut rbp) = (st.gpr[RSP], st.gpr[RBP]);
    rsp = rsp.wrapping_sub(8);
    mm.write(emu, rsp, 8, rbp)?;
    let frame = rsp;
    if level > 0 {
        for _ in 1..level {
            rbp = rbp.wrapping_sub(8);
            let v = mm.read(emu, rbp, 8, ACC_R)?;
            rsp = rsp.wrapping_sub(8);
            mm.write(emu, rsp, 8, v)?;
        }
        rsp = rsp.wrapping_sub(8);
        mm.write(emu, rsp, 8, frame)?;
    }
    let st = emu.st_mut();
    st.gpr[RBP] = frame;
    st.gpr[RSP] = rsp.wrapping_sub(size);
    Ok(())
}

fn bit_test(emu: &mut Emu, i: &Instruction) -> Result<(), ()> {
    let mm = Mem::new(emu);
    let opsize = i.memory_size().size() as u64;
    let bits = opsize * 8;
    let raw = reg(emu, i.op1_register());
    let off = match opsize {
        2 => raw as u16 as i16 as i64,
        4 => raw as u32 as i32 as i64,
        _ => raw as i64,
    };
    let addr = ea(emu, i).wrapping_add(((off >> bits.trailing_zeros()) * opsize as i64) as u64);
    let bitno = (off as u64) & (bits - 1);
    let acc = if i.mnemonic() == Mnemonic::Bt { ACC_R } else { ACC_RW };
    let v = mm.read(emu, addr, opsize, acc)?;
    let nv = match i.mnemonic() {
        Mnemonic::Bts => v | (1 << bitno),
        Mnemonic::Btr => v & !(1 << bitno),
        Mnemonic::Btc => v ^ (1 << bitno),
        _ => v,
    };
    if i.mnemonic() != Mnemonic::Bt {
        mm.write(emu, addr, opsize, nv)?;
    }
    let st = emu.st_mut();
    st.rflags = (st.rflags & !F_CF) | ((v >> bitno) & 1);
    Ok(())
}

fn xlat(emu: &mut Emu, i: &Instruction) -> Result<(), ()> {
    let mm = Mem::new(emu);
    let addr = ea(emu, i);
    let v = mm.read(emu, addr, 1, ACC_R)?;
    let st = emu.st_mut();
    st.gpr[RAX] = (st.gpr[RAX] & !0xff) | v;
    Ok(())
}

pub(crate) fn exec(emu: &mut Emu, i: &Instruction) -> Result<(), ()> {
    if let Some((op, sz)) = string_op(i)
        && i.is_string_instruction()
    {
        return string(emu, i, op, sz);
    }
    match i.mnemonic() {
        Mnemonic::Enter => enter(emu, i),
        Mnemonic::Xlatb => xlat(emu, i),
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => bit_test(emu, i),
        m => unreachable!("interp: {m:?}"),
    }
}
