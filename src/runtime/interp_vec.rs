use super::interp::{IErr, Mem, R, ea, reg, seg_base};
use super::xstate::{HEADER, LEGACY_ST, LEGACY_XMM, MANAGED, MXCSR, sync};
use crate::cpu::cpu;
use crate::runtime::state::*;
use crate::{EXC_GENERAL_PROTECTION, EXC_INVALID_OPCODE, Emu};
use iced_x86::{Code, EncodingKind, Instruction, Mnemonic, OpKind, Register};

const RAX: usize = 0;
const RDX: usize = 2;
const RDI: usize = 7;

fn ud() -> IErr {
    IErr::Exc(EXC_INVALID_OPCODE)
}

fn gp() -> IErr {
    IErr::Exc(EXC_GENERAL_PROTECTION)
}

fn rfbm(emu: &Emu) -> u64 {
    let st = emu.st();
    ((st.gpr[RDX] & 0xffff_ffff) << 32 | (st.gpr[RAX] & 0xffff_ffff)) & cpu().xcr0
}

fn comp_size(k: usize) -> usize {
    cpu().xcomp[k].size as usize
}

fn compact_offsets(xcomp: u64) -> [usize; 64] {
    let mut off = [0usize; 64];
    let mut at = 576usize;
    for (k, o) in off.iter_mut().enumerate().skip(2) {
        if xcomp >> k & 1 == 0 {
            continue;
        }
        if cpu().xcomp[k].align64 {
            at = (at + 63) & !63;
        }
        *o = at;
        at += comp_size(k);
    }
    off
}

fn x87_format(raw: &[u8], w64: bool) -> Vec<u8> {
    let mut v = raw[0..24].to_vec();
    if !w64 {
        v[12..16].fill(0);
        v[20..24].fill(0);
    }
    v
}

fn x87_init() -> Vec<u8> {
    let mut v = vec![0u8; 24];
    v[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
    v
}

pub(super) fn xsave(emu: &mut Emu, i: &Instruction) -> R {
    use Mnemonic as M;
    let m = i.mnemonic();
    let c = cpu();
    if (matches!(m, M::Xsaveopt | M::Xsaveopt64) && !c.xsaveopt) || (matches!(m, M::Xsavec | M::Xsavec64) && !c.xsavec) {
        return Err(ud());
    }
    let w64 = matches!(m, M::Xsave64 | M::Xsaveopt64 | M::Xsavec64);
    let compact = matches!(m, M::Xsavec | M::Xsavec64);
    let a = ea(emu, i);
    if a & 63 != 0 {
        return Err(gp());
    }
    let rfbm = rfbm(emu);
    let x = sync(emu);
    let xinuse = x.bv() & MANAGED;
    let img = x.a.to_vec();
    let mut writes: Vec<(usize, Vec<u8>)> = Vec::new();
    let saved = |k: usize| rfbm >> k & 1 != 0 && (!compact || xinuse >> k & 1 != 0);
    if saved(0) {
        if xinuse & 1 != 0 {
            writes.push((0, x87_format(&img, w64)));
            writes.push((LEGACY_ST, img[LEGACY_ST..LEGACY_XMM].to_vec()));
        } else {
            writes.push((0, x87_init()));
            writes.push((LEGACY_ST, vec![0; LEGACY_XMM - LEGACY_ST]));
        }
    }
    if rfbm & 6 != 0 {
        writes.push((MXCSR, img[MXCSR..MXCSR + 8].to_vec()));
    }
    if saved(1) {
        let v = if xinuse & 2 != 0 { img[LEGACY_XMM..LEGACY_XMM + 256].to_vec() } else { vec![0; 256] };
        writes.push((LEGACY_XMM, v));
    }
    let coff = compact_offsets(rfbm);
    for (k, &co) in coff.iter().enumerate().take(63).skip(2) {
        if !saved(k) {
            continue;
        }
        let comp = c.xcomp[k];
        let size = comp.size as usize;
        let src = comp.offset as usize;
        let data = if xinuse >> k & 1 != 0 { img[src..src + size].to_vec() } else { vec![0; size] };
        writes.push((if compact { co } else { src }, data));
    }
    let mm = Mem::new(emu);
    let header = if compact {
        let mut h = vec![0u8; 64];
        h[0..8].copy_from_slice(&(xinuse & rfbm).to_le_bytes());
        h[8..16].copy_from_slice(&(rfbm | 1 << 63).to_le_bytes());
        h
    } else {
        let old = mm.read(emu, a + HEADER as u64, 8, ACC_RW)?;
        ((old & !rfbm) | (xinuse & rfbm)).to_le_bytes().to_vec()
    };
    writes.push((HEADER, header));
    for (off, d) in &writes {
        mm.probe_w(emu, a + *off as u64, d.len())?;
    }
    for (off, d) in &writes {
        mm.write_bytes(emu, a + *off as u64, d)?;
    }
    Ok(())
}

pub(super) fn xrstor(emu: &mut Emu, i: &Instruction) -> R {
    let w64 = i.mnemonic() == Mnemonic::Xrstor64;
    let c = cpu();
    let a = ea(emu, i);
    if a & 63 != 0 {
        return Err(gp());
    }
    let mm = Mem::new(emu);
    let hdr = mm.read_bytes(emu, a + HEADER as u64, 64, ACC_R)?;
    let bv = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let xcomp = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
    let compact = xcomp >> 63 != 0;
    if compact {
        if !c.xsavec || xcomp & !(c.xcr0 | 1 << 63) != 0 || bv & !xcomp != 0 || hdr[16..64].iter().any(|&b| b != 0) {
            return Err(gp());
        }
    } else if hdr[8..24].iter().any(|&b| b != 0) || bv & !c.xcr0 != 0 {
        return Err(gp());
    }
    let rfbm = rfbm(emu);
    let load = |k: usize| rfbm >> k & 1 != 0 && bv >> k & 1 != 0;
    let mut x87 = None;
    if load(0) {
        let head = mm.read_bytes(emu, a, 24, ACC_R)?;
        let regs = mm.read_bytes(emu, a + LEGACY_ST as u64, LEGACY_XMM - LEGACY_ST, ACC_R)?;
        x87 = Some((x87_format(&head, w64), regs));
    }
    let mut mxcsr = None;
    if rfbm & 6 != 0 {
        let v = if !compact || bv & 2 != 0 { mm.read(emu, a + MXCSR as u64, 4, ACC_R)? as u32 } else { 0x1F80 };
        if v & !c.mxcsr_mask != 0 {
            return Err(gp());
        }
        mxcsr = Some(v);
    }
    let sse = if load(1) { Some(mm.read_bytes(emu, a + LEGACY_XMM as u64, 256, ACC_R)?) } else { None };
    let coff = compact_offsets(xcomp);
    let mut comps: Vec<(usize, Option<Vec<u8>>)> = Vec::new();
    for (k, &co) in coff.iter().enumerate().take(63).skip(2) {
        if rfbm >> k & 1 == 0 {
            continue;
        }
        let data = if load(k) {
            let off = if compact { co } else { c.xcomp[k].offset as usize };
            Some(mm.read_bytes(emu, a + off as u64, comp_size(k), ACC_R)?)
        } else {
            None
        };
        if MANAGED >> k & 1 == 0 {
            if data.is_some_and(|d| d.iter().any(|&b| b != 0)) {
                return Err(IErr::Unsupported);
            }
            continue;
        }
        comps.push((k, data));
    }
    let mut x = sync(emu);
    let mut nbv = x.bv();
    if rfbm & 1 != 0 {
        match x87 {
            Some((head, regs)) => {
                x.a[0..24].copy_from_slice(&head);
                x.a[LEGACY_ST..LEGACY_XMM].copy_from_slice(&regs);
                nbv |= 1;
            }
            None => nbv &= !1,
        }
    }
    if let Some(v) = mxcsr {
        x.a[MXCSR..MXCSR + 4].copy_from_slice(&v.to_le_bytes());
    }
    if rfbm & 2 != 0 {
        match sse {
            Some(d) => {
                x.a[LEGACY_XMM..LEGACY_XMM + 256].copy_from_slice(&d);
                nbv |= 2;
            }
            None => nbv &= !2,
        }
    }
    for (k, data) in comps {
        let off = c.xcomp[k].offset as usize;
        match data {
            Some(d) => {
                x.a[off..off + d.len()].copy_from_slice(&d);
                nbv |= 1 << k;
            }
            None => nbv &= !(1 << k),
        }
    }
    x.set_bv(nbv);
    Ok(())
}

fn vreg_bytes(r: Register) -> usize {
    r.size()
}

fn implicit_di(emu: &Emu, i: &Instruction) -> u64 {
    let rdi = emu.st().gpr[RDI];
    let a = if (0..i.op_count()).any(|k| i.op_kind(k) == OpKind::MemorySegEDI) { rdi & 0xffff_ffff } else { rdi };
    a.wrapping_add(seg_base(emu, i))
}

pub(super) fn maskmov(emu: &mut Emu, i: &Instruction) -> R {
    let mmx = i.mnemonic() == Mnemonic::Maskmovq;
    if i.mnemonic() == Mnemonic::Vmaskmovdqu && cpu().xcr0 & 4 == 0 {
        return Err(ud());
    }
    let regs: Vec<Register> = (0..i.op_count()).filter(|&k| i.op_kind(k) == OpKind::Register).map(|k| i.op_register(k)).collect();
    let (src, msk) = (regs[0], regs[1]);
    let (data, mask, len) = {
        let x = sync(emu);
        if mmx {
            let mut d = [0u8; 64];
            let mut m = [0u8; 64];
            d[..8].copy_from_slice(&x.mm_read(src.number()).to_le_bytes());
            m[..8].copy_from_slice(&x.mm_read(msk.number()).to_le_bytes());
            (d, m, 8)
        } else {
            (x.vec_read(src.number()), x.vec_read(msk.number()), 16)
        }
    };
    let addr = implicit_di(emu, i);
    let mm = Mem::new(emu);
    for b in 0..len {
        if mask[b] & 0x80 != 0 {
            mm.write(emu, addr.wrapping_add(b as u64), 1, data[b] as u64)?;
        }
    }
    if mmx {
        sync(emu).mmx_enter();
    }
    Ok(())
}

pub(super) fn movdir64b(emu: &mut Emu, i: &Instruction) -> R {
    if !cpu().movdir64b {
        return Err(ud());
    }
    let dst = reg(emu, i.op0_register());
    if dst & 63 != 0 {
        return Err(gp());
    }
    let src = ea(emu, i);
    let mm = Mem::new(emu);
    let data = mm.read_bytes(emu, src, 64, ACC_R)?;
    mm.write_bytes(emu, dst, &data)
}

pub(super) fn clzero(emu: &mut Emu, i: &Instruction) -> R {
    if !cpu().clzero {
        return Err(ud());
    }
    let line = cpu().cache_line;
    let rax = emu.st().gpr[RAX];
    let rax = if i.code() == Code::Clzerod { rax & 0xffff_ffff } else { rax };
    let a = (rax & !(line - 1)).wrapping_add(seg_base(emu, i));
    let mm = Mem::new(emu);
    mm.write_bytes(emu, a, &vec![0u8; line as usize])
}

pub(super) fn monitor_probe(emu: &mut Emu, i: &Instruction) -> R {
    let a = if i.mnemonic() == Mnemonic::Umonitor {
        if !cpu().waitpkg {
            return Err(ud());
        }
        reg(emu, i.op0_register())
    } else {
        if !cpu().monitorx {
            return Err(ud());
        }
        if emu.st().gpr[1] & 0xffff_ffff != 0 {
            return Err(gp());
        }
        let rax = emu.st().gpr[RAX];
        if i.code() == Code::Monitorxd { rax & 0xffff_ffff } else { rax }
    };
    let a = a.wrapping_add(seg_base(emu, i));
    emu.access_or_fault(a, 1, ACC_R).ok_or(IErr::Fault)?;
    Ok(())
}

enum Vs {
    Gather,
    Scatter,
    Prefetch,
}

pub(super) fn gather_scatter(emu: &mut Emu, i: &Instruction) -> R {
    use Mnemonic as M;
    let (op, elem) = match i.mnemonic() {
        M::Vgatherdps | M::Vgatherqps | M::Vpgatherdd | M::Vpgatherqd => (Vs::Gather, 4),
        M::Vgatherdpd | M::Vgatherqpd | M::Vpgatherdq | M::Vpgatherqq => (Vs::Gather, 8),
        M::Vscatterdps | M::Vscatterqps | M::Vpscatterdd | M::Vpscatterqd => (Vs::Scatter, 4),
        M::Vscatterdpd | M::Vscatterqpd | M::Vpscatterdq | M::Vpscatterqq => (Vs::Scatter, 8),
        M::Vgatherpf0dps | M::Vgatherpf0qps | M::Vgatherpf0dpd | M::Vgatherpf0qpd | M::Vgatherpf1dps
        | M::Vgatherpf1qps | M::Vgatherpf1dpd | M::Vgatherpf1qpd | M::Vscatterpf0dps | M::Vscatterpf0qps
        | M::Vscatterpf0dpd | M::Vscatterpf0qpd | M::Vscatterpf1dps | M::Vscatterpf1qps | M::Vscatterpf1dpd
        | M::Vscatterpf1qpd => (Vs::Prefetch, 4),
        _ => return Err(IErr::Unsupported),
    };
    let c = cpu();
    let evex = i.encoding() == EncodingKind::EVEX;
    let index = i.memory_index();
    let data = match op {
        Vs::Gather => i.op0_register(),
        Vs::Scatter => i.op1_register(),
        Vs::Prefetch => index,
    };
    let vl = vreg_bytes(data).max(vreg_bytes(index));
    let feature = match op {
        Vs::Prefetch => c.avx512pf,
        _ if evex => c.avx512f && (vl == 64 || c.avx512vl),
        _ => c.avx2,
    };
    if !feature {
        return Err(ud());
    }
    let isz = if i.is_vsib32() { 4 } else { 8 };
    let n = vl / elem.max(isz);
    let k = i.op_mask();
    let (dn, xn) = (data.number(), index.number());
    if evex {
        if k == Register::None || i.zeroing_masking() || (matches!(op, Vs::Gather) && dn == xn) {
            return Err(ud());
        }
    } else {
        let mn = i.op2_register().number();
        if dn == xn || dn == mn || xn == mn {
            return Err(ud());
        }
    }
    let base_reg = i.memory_base();
    let addr32 = base_reg.is_gpr32();
    let base = if base_reg == Register::None { 0 } else { reg(emu, base_reg) };
    let disp = i.memory_displacement64();
    let scale = i.memory_index_scale() as u64;
    let seg = seg_base(emu, i);
    let (mut dv, xv, mut mv, mut kv) = {
        let x = sync(emu);
        let mv = if evex { [0u8; 64] } else { x.vec_read(i.op2_register().number()) };
        let kv = if evex { x.k_read(k.number()) } else { 0 };
        (x.vec_read(dn), x.vec_read(xn), mv, kv)
    };
    let active = |j: usize, mv: &[u8; 64], kv: u64| {
        if evex { kv >> j & 1 != 0 } else { mv[j * elem + elem - 1] & 0x80 != 0 }
    };
    let mm = Mem::new(emu);
    let mut err = None;
    if !matches!(op, Vs::Prefetch) {
        for j in 0..n {
            if !active(j, &mv, kv) {
                continue;
            }
            let ix = if isz == 4 {
                i32::from_le_bytes(xv[j * 4..j * 4 + 4].try_into().unwrap()) as i64 as u64
            } else {
                u64::from_le_bytes(xv[j * 8..j * 8 + 8].try_into().unwrap())
            };
            let mut ad = base.wrapping_add(ix.wrapping_mul(scale)).wrapping_add(disp);
            if addr32 {
                ad &= 0xffff_ffff;
            }
            ad = ad.wrapping_add(seg);
            let r = match op {
                Vs::Gather => mm.read(emu, ad, elem as u64, ACC_R).map(|v| {
                    dv[j * elem..j * elem + elem].copy_from_slice(&v.to_le_bytes()[..elem]);
                }),
                _ => {
                    let mut b = [0u8; 8];
                    b[..elem].copy_from_slice(&dv[j * elem..j * elem + elem]);
                    mm.write(emu, ad, elem as u64, u64::from_le_bytes(b))
                }
            };
            if let Err(e) = r {
                err = Some(e);
                break;
            }
            if evex {
                kv &= !(1 << j);
            } else {
                mv[j * elem..j * elem + elem].fill(0);
            }
        }
    }
    let done = err.is_none();
    let mut x = sync(emu);
    if evex {
        x.k_write(k.number(), if done { 0 } else { kv });
    } else {
        let mw = vreg_bytes(i.op2_register());
        if done {
            mv = [0; 64];
        }
        mv[mw..].fill(0);
        x.vec_write(i.op2_register().number(), &mv);
    }
    if matches!(op, Vs::Gather) {
        dv[vreg_bytes(data)..].fill(0);
        x.vec_write(dn, &dv);
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
