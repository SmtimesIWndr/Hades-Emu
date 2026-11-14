use super::interp::{Done, IErr, Mem, R, ea, reg};
use crate::cpu::{Vendor, cpu};
use crate::jit::regs::{RSP, gpr_idx};
use crate::runtime::state::*;
use crate::{EXC_GENERAL_PROTECTION, EXC_INVALID_OPCODE, Emu};
use iced_x86::{Code, Instruction, MemorySize, Mnemonic, OpKind, Register};

const CPL: u16 = 3;
const GDT_LIMIT: u16 = 0x6F;
const POPF16_MASK: u64 = 0x0DD5;
const IRET_MASK: u64 = 0x20_0DD5;

#[derive(Clone, Copy)]
enum Desc {
    Code64(u16),
    Code32(u16),
    Data(u16),
    System,
}

fn gp() -> IErr {
    IErr::Exc(EXC_GENERAL_PROTECTION)
}

fn is_null(sel: u16) -> bool {
    sel & !3 == 0
}

fn gdt(sel: u16) -> R<Desc> {
    if sel & 4 != 0 || sel > GDT_LIMIT {
        return Err(gp());
    }
    Ok(match sel >> 3 {
        2 => Desc::Code64(0),
        3 => Desc::Data(0),
        4 => Desc::Code32(3),
        5 | 10 => Desc::Data(3),
        6 => Desc::Code64(3),
        _ => Desc::System,
    })
}

pub(crate) fn canonical(a: u64) -> bool {
    ((a << 16) as i64 >> 16) as u64 == a
}

fn seg_index(r: Register) -> usize {
    match r {
        Register::ES => SEG_ES,
        Register::CS => SEG_CS,
        Register::SS => SEG_SS,
        Register::DS => SEG_DS,
        Register::FS => SEG_FS,
        _ => SEG_GS,
    }
}

fn check_data_seg(seg: usize, sel: u16) -> R {
    let rpl = sel & 3;
    if seg == SEG_SS {
        if is_null(sel) || rpl != CPL {
            return Err(gp());
        }
        return match gdt(sel)? {
            Desc::Data(dpl) if dpl == CPL => Ok(()),
            _ => Err(gp()),
        };
    }
    if is_null(sel) {
        return Ok(());
    }
    match gdt(sel)? {
        Desc::Data(dpl) | Desc::Code32(dpl) | Desc::Code64(dpl) if dpl >= CPL.max(rpl) => Ok(()),
        _ => Err(gp()),
    }
}

fn commit_seg(emu: &mut Emu, seg: usize, sel: u16) {
    let clears = cpu().vendor != Vendor::Amd || cpu().null_sel_clears_base;
    let st = emu.st_mut();
    st.seg[seg] = sel as u64;
    let base = match seg {
        SEG_FS => &mut st.fs_base,
        SEG_GS => &mut st.gs_base,
        _ => return,
    };
    if !is_null(sel) || clears {
        *base = 0;
    }
}

fn load_seg(emu: &mut Emu, seg: usize, sel: u16) -> R {
    check_data_seg(seg, sel)?;
    commit_seg(emu, seg, sel);
    Ok(())
}

pub(super) fn set_reg(emu: &mut Emu, r: Register, v: u64) {
    let Some(idx) = gpr_idx(r) else { return };
    let st = emu.st_mut();
    st.gpr[idx] = match r.size() {
        8 | 4 => v & if r.size() == 4 { 0xffff_ffff } else { u64::MAX },
        2 => (st.gpr[idx] & !0xffff) | (v & 0xffff),
        _ => (st.gpr[idx] & !0xff) | (v & 0xff),
    };
}

fn push_bytes(emu: &mut Emu, mm: &Mem, data: &[u8]) -> R {
    let rsp = emu.st().gpr[RSP].wrapping_sub(data.len() as u64);
    mm.write_bytes(emu, rsp, data)?;
    emu.st_mut().gpr[RSP] = rsp;
    Ok(())
}

pub(super) fn seg_op(emu: &mut Emu, i: &Instruction) -> R {
    let mm = Mem::new(emu);
    match i.mnemonic() {
        Mnemonic::Mov if i.op0_kind() == OpKind::Register && i.op0_register().is_segment_register() => {
            let s = i.op0_register();
            if s == Register::CS {
                return Err(IErr::Exc(EXC_INVALID_OPCODE));
            }
            let sel = if i.op1_kind() == OpKind::Register {
                reg(emu, i.op1_register())
            } else {
                let a = ea(emu, i);
                mm.read(emu, a, 2, ACC_R)?
            } as u16;
            load_seg(emu, seg_index(s), sel)
        }
        Mnemonic::Mov => {
            let sel = emu.st().seg[seg_index(i.op1_register())] & 0xffff;
            if i.op0_kind() == OpKind::Register {
                set_reg(emu, i.op0_register(), sel);
                Ok(())
            } else {
                let a = ea(emu, i);
                mm.write(emu, a, 2, sel)
            }
        }
        Mnemonic::Push => {
            let sel = emu.st().seg[seg_index(i.op0_register())] & 0xffff;
            let osz = i.stack_pointer_increment().unsigned_abs() as u64;
            if osz == 2 || cpu().vendor == Vendor::Amd {
                let bytes = sel.to_le_bytes();
                push_bytes(emu, &mm, &bytes[..osz as usize])
            } else {
                let rsp = emu.st().gpr[RSP].wrapping_sub(osz);
                mm.write(emu, rsp, 2, sel)?;
                emu.st_mut().gpr[RSP] = rsp;
                Ok(())
            }
        }
        Mnemonic::Pop => {
            let osz = i.stack_pointer_increment() as u64;
            let rsp = emu.st().gpr[RSP];
            let sel = mm.read(emu, rsp, osz, ACC_R)? as u16;
            load_seg(emu, seg_index(i.op0_register()), sel)?;
            emu.st_mut().gpr[RSP] = rsp.wrapping_add(osz);
            Ok(())
        }
        m => {
            let seg = match m {
                Mnemonic::Lfs => SEG_FS,
                Mnemonic::Lgs => SEG_GS,
                _ => SEG_SS,
            };
            let d = i.op0_register();
            let osz = if d.size() == 8 && cpu().vendor == Vendor::Amd { 4 } else { d.size() as u64 };
            let a = ea(emu, i);
            let off = mm.read(emu, a, osz, ACC_R)?;
            let sel = mm.read(emu, a.wrapping_add(osz), 2, ACC_R)? as u16;
            load_seg(emu, seg, sel)?;
            set_reg(emu, d, off);
            Ok(())
        }
    }
}

pub(super) fn flags16(emu: &mut Emu, i: &Instruction) -> R {
    let mm = Mem::new(emu);
    let rsp = emu.st().gpr[RSP];
    if i.mnemonic() == Mnemonic::Pushf {
        let v = emu.st().rflags & 0xffff;
        let nsp = rsp.wrapping_sub(2);
        mm.write(emu, nsp, 2, v)?;
        emu.st_mut().gpr[RSP] = nsp;
    } else {
        let v = mm.read(emu, rsp, 2, ACC_R)?;
        let st = emu.st_mut();
        st.rflags = (st.rflags & !POPF16_MASK) | (v & POPF16_MASK);
        st.gpr[RSP] = rsp.wrapping_add(2);
    }
    Ok(())
}

fn check_code_target(sel: u16) -> R {
    if is_null(sel) {
        return Err(gp());
    }
    match gdt(sel)? {
        Desc::Code64(dpl) if dpl == CPL => Ok(()),
        Desc::Code32(dpl) if dpl == CPL => Err(IErr::Unsupported),
        _ => Err(gp()),
    }
}

fn check_return_cs(sel: u16) -> R {
    if is_null(sel) {
        return Err(gp());
    }
    let rpl = sel & 3;
    if rpl < CPL {
        return Err(gp());
    }
    match gdt(sel)? {
        Desc::Code64(dpl) if dpl == rpl => Ok(()),
        Desc::Code32(dpl) if dpl == rpl => Err(IErr::Unsupported),
        _ => Err(gp()),
    }
}

fn le(v: u64, n: u64) -> impl Iterator<Item = u8> {
    v.to_le_bytes().into_iter().take(n as usize)
}

pub(super) fn far_jmp_call(emu: &mut Emu, i: &Instruction) -> R<Done> {
    let mm = Mem::new(emu);
    let osz = match i.memory_size() {
        MemorySize::SegPtr16 => 2,
        MemorySize::SegPtr64 if cpu().vendor != Vendor::Amd => 8,
        _ => 4,
    };
    let a = ea(emu, i);
    let off = mm.read(emu, a, osz, ACC_R)?;
    let sel = mm.read(emu, a.wrapping_add(osz), 2, ACC_R)? as u16;
    check_code_target(sel)?;
    if !canonical(off) {
        return Err(gp());
    }
    if i.mnemonic() == Mnemonic::Call {
        let cs = emu.st().seg[SEG_CS];
        let buf: Vec<u8> = le(i.next_ip(), osz).chain(le(cs, osz)).collect();
        push_bytes(emu, &mm, &buf)?;
    }
    emu.st_mut().seg[SEG_CS] = ((sel & !3) | CPL) as u64;
    Ok(Done::Jump(off))
}

pub(super) fn far_return(emu: &mut Emu, i: &Instruction) -> R<Done> {
    use Code as C;
    let mm = Mem::new(emu);
    let (osz, imm, iret) = match i.code() {
        C::Retfw => (2, 0, false),
        C::Retfd => (4, 0, false),
        C::Retfq => (8, 0, false),
        C::Retfw_imm16 => (2, i.immediate16() as u64, false),
        C::Retfd_imm16 => (4, i.immediate16() as u64, false),
        C::Retfq_imm16 => (8, i.immediate16() as u64, false),
        C::Iretw => (2, 0, true),
        C::Iretd => (4, 0, true),
        _ => (8, 0, true),
    };
    let rsp = emu.st().gpr[RSP];
    let n = if iret { 5 } else { 2 };
    let mut v = [0u64; 5];
    for (k, slot) in v.iter_mut().enumerate().take(n) {
        *slot = mm.read(emu, rsp.wrapping_add(k as u64 * osz), osz, ACC_R)?;
    }
    let cs = v[1] as u16;
    check_return_cs(cs)?;
    if iret {
        let ss = v[4] as u16;
        if is_null(ss) || ss & 3 != cs & 3 {
            return Err(gp());
        }
        match gdt(ss)? {
            Desc::Data(dpl) if dpl == ss & 3 => {}
            _ => return Err(gp()),
        }
    }
    if !canonical(v[0]) {
        return Err(gp());
    }
    let st = emu.st_mut();
    st.seg[SEG_CS] = cs as u64;
    if iret {
        let m = if osz == 2 { IRET_MASK & 0xffff } else { IRET_MASK };
        st.rflags = (st.rflags & !m) | (v[2] & m);
        st.gpr[RSP] = v[3];
        st.seg[SEG_SS] = v[4] & 0xffff;
    } else {
        st.gpr[RSP] = rsp.wrapping_add(2 * osz + imm);
    }
    Ok(Done::Jump(v[0]))
}
