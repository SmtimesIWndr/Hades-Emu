use super::interp::{IErr, R};
use super::interp_seg::set_reg;
use crate::cpu::cpu;
use crate::hooks::HookCb;
use crate::{EXC_INVALID_OPCODE, Emu};
use core::arch::asm;
use core::arch::x86_64::__cpuid_count;
use iced_x86::{Instruction, Mnemonic};

const RAX: usize = 0;
const RCX: usize = 1;
const RDX: usize = 2;
const RBX: usize = 3;
const STATUS_FLAGS: u64 = 0x8D5;

pub(super) fn cpuid(emu: &mut Emu) -> R {
    let st = emu.st();
    let (leaf, sub) = (st.gpr[RAX] as u32, st.gpr[RCX] as u32);
    let r = emu
        .first_hook(|e, cb| match cb {
            HookCb::Cpuid(f) => f(e, leaf, sub),
            _ => None,
        })
        .unwrap_or_else(|| {
            let c = __cpuid_count(leaf, sub);
            [c.eax, c.ebx, c.ecx, c.edx]
        });
    let st = emu.st_mut();
    st.gpr[RAX] = r[0] as u64;
    st.gpr[RBX] = r[1] as u64;
    st.gpr[RCX] = r[2] as u64;
    st.gpr[RDX] = r[3] as u64;
    Ok(())
}

fn host_tsc(with_aux: bool) -> (u64, u32) {
    let (lo, hi, aux): (u32, u32, u32);
    unsafe {
        if with_aux {
            asm!("rdtscp", out("eax") lo, out("edx") hi, out("ecx") aux, options(nomem, nostack, preserves_flags));
        } else {
            asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
            aux = 0;
        }
    }
    ((hi as u64) << 32 | lo as u64, aux)
}

pub(super) fn rdtsc(emu: &mut Emu, i: &Instruction) -> R {
    let with_aux = i.mnemonic() == Mnemonic::Rdtscp;
    if with_aux && !cpu().rdtscp {
        return Err(IErr::Exc(EXC_INVALID_OPCODE));
    }
    let hooked = emu.first_hook(|e, cb| match cb {
        HookCb::Rdtsc(f) => f(e),
        _ => None,
    });
    let (host, aux) = host_tsc(with_aux);
    let tsc = hooked.unwrap_or(host);
    let st = emu.st_mut();
    st.gpr[RAX] = tsc & 0xffff_ffff;
    st.gpr[RDX] = tsc >> 32;
    if with_aux {
        st.gpr[RCX] = aux as u64;
    }
    Ok(())
}

fn host_rand(seed: bool) -> (u64, bool) {
    let (v, ok): (u64, u8);
    unsafe {
        if seed {
            asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack));
        } else {
            asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack));
        }
    }
    (v, ok != 0)
}

pub(super) fn rand(emu: &mut Emu, i: &Instruction) -> R {
    let seed = i.mnemonic() == Mnemonic::Rdseed;
    let dst = i.op0_register();
    let bytes = dst.size() as u32;
    let hooked = emu.first_hook(|e, cb| match cb {
        HookCb::Rand(f) => f(e, seed, bytes),
        _ => None,
    });
    let (v, ok) = match hooked {
        Some(v) => (v, true),
        None if (seed && cpu().rdseed) || (!seed && cpu().rdrand) => host_rand(seed),
        None => return Err(IErr::Exc(EXC_INVALID_OPCODE)),
    };
    set_reg(emu, dst, if ok { v } else { 0 });
    let st = emu.st_mut();
    st.rflags = (st.rflags & !STATUS_FLAGS) | ok as u64;
    Ok(())
}
