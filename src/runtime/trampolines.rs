use crate::Emu;
use crate::jit::Jit;
use crate::jit::asm::{AResult, Asm, mem, patch_rel32};
use crate::jit::regs::*;
use crate::runtime::state::*;
use iced_x86::{Code, Register};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn xsave_code() -> Code {
    let r = core::arch::x86_64::__cpuid_count(0xD, 1);
    if r.eax & 1 != 0 { Code::Xsaveopt64_mem } else { Code::Xsave64_mem }
}

fn save_ext(a: &mut Asm) -> AResult {
    a.op_ri(Code::Mov_r32_imm32, Register::EAX, XSAVE_MASK as i64)?;
    a.op_rr(Code::Xor_r32_rm32, Register::EDX, Register::EDX)?;
    a.op_m(xsave_code(), a.st(OFF_XSAVE))
}

fn save_gprs(a: &mut Asm) -> AResult {
    for (i, &r) in GPR64.iter().enumerate() {
        if i != RSP && i != R15 {
            a.mov_mr(a.gpr(i), r)?;
        }
    }
    a.mov_mr(a.gpr(RSP), Register::R15)?;
    a.op0(Code::Pushfq)?;
    a.op_m(Code::Pop_rm64, a.st(OFF_RFLAGS))
}

fn save_guest(a: &mut Asm) -> AResult {
    save_gprs(a)?;
    save_ext(a)
}

fn load_ext(a: &mut Asm) -> AResult {
    a.op_ri(Code::Mov_r32_imm32, Register::EAX, XSAVE_MASK as i64)?;
    a.op_rr(Code::Xor_r32_rm32, Register::EDX, Register::EDX)?;
    a.op_m(Code::Xrstor64_mem, a.st(OFF_XSAVE))
}

fn load_gprs(a: &mut Asm) -> AResult {
    a.op_m(Code::Push_rm64, a.st(OFF_RFLAGS))?;
    a.op0(Code::Popfq)?;
    for (i, &r) in GPR64.iter().enumerate() {
        if i != RSP && i != R15 {
            a.mov_rm(r, a.gpr(i))?;
        }
    }
    a.mov_rm(Register::R15, a.gpr(RSP))
}

fn load_guest(a: &mut Asm) -> AResult {
    load_ext(a)?;
    load_gprs(a)
}

const XMM: [Register; 16] = [
    Register::XMM0, Register::XMM1, Register::XMM2, Register::XMM3, Register::XMM4, Register::XMM5,
    Register::XMM6, Register::XMM7, Register::XMM8, Register::XMM9, Register::XMM10, Register::XMM11,
    Register::XMM12, Register::XMM13, Register::XMM14, Register::XMM15,
];
const XSAVE_XMM: usize = 160;
const XSAVE_MXCSR: usize = 24;
const XSAVE_BV: usize = 512;

fn xgetbv1_supported() -> bool {
    core::arch::x86_64::__cpuid_count(0xD, 1).eax & (1 << 2) != 0
}

fn light_save(a: &mut Asm) -> AResult {
    for (i, x) in XMM.iter().enumerate() {
        a.ins(&iced_x86::Instruction::with2(Code::Movdqu_xmmm128_xmm, a.st(OFF_XSAVE + XSAVE_XMM + 16 * i), *x).unwrap())?;
    }
    a.op_m(Code::Stmxcsr_m32, a.st(OFF_XSAVE + XSAVE_MXCSR))?;
    a.ins(&iced_x86::Instruction::with2(Code::Or_rm64_imm8, a.st(OFF_XSAVE + XSAVE_BV), 2i32).unwrap())?;
    a.ins(&iced_x86::Instruction::with2(Code::And_rm64_imm32, a.st(OFF_XSAVE + XSAVE_BV), !0xE4i32).unwrap())
}

fn light_restore(a: &mut Asm) -> AResult {
    for (i, x) in XMM.iter().enumerate() {
        a.op_rm(Code::Movdqu_xmm_xmmm128, *x, a.st(OFF_XSAVE + XSAVE_XMM + 16 * i))?;
    }
    a.op_m(Code::Ldmxcsr_m32, a.st(OFF_XSAVE + XSAVE_MXCSR))
}

const CALLEE_SAVED: [Register; 8] = [
    Register::RBX, Register::RBP, Register::RDI, Register::RSI,
    Register::R12, Register::R13, Register::R14, Register::R15,
];
const XMM_SAVED: [Register; 10] = [
    Register::XMM6, Register::XMM7, Register::XMM8, Register::XMM9, Register::XMM10,
    Register::XMM11, Register::XMM12, Register::XMM13, Register::XMM14, Register::XMM15,
];

pub(super) fn emit_globals(jit: &mut Jit) -> AResult {
    let mut a = Asm::new(jit.code_pos, jit.code_end, jit.state);
    let mut g = jit.g;

    g.exit_common = a.here();
    a.mov_rm(Register::RSP, a.st(OFF_HOST_RSP))?;
    a.op0(Code::Fninit)?;
    a.op_m(Code::Fldcw_m2byte, a.st(OFF_HOST_FCW))?;
    a.op_m(Code::Ldmxcsr_m32, a.st(OFF_HOST_MXCSR))?;
    a.op0(Code::Cld)?;
    for (k, x) in XMM_SAVED.iter().enumerate() {
        a.op_rm(Code::Movdqu_xmm_xmmm128, *x, mem(Register::RSP, 16 * k as i64))?;
    }
    a.op_ri(Code::Add_rm64_imm32, Register::RSP, 168)?;
    for r in CALLEE_SAVED.iter().rev() {
        a.op_r(Code::Pop_r64, *r)?;
    }
    a.op0(Code::Retnq)?;

    g.exit_sync = a.here();
    save_guest(&mut a)?;
    a.jmp_to(g.exit_common)?;

    g.exit_fault = a.here();
    a.op_ri(Code::Mov_r32_imm32, Register::EAX, XSAVE_MASK as i64)?;
    a.op_rr(Code::Xor_r32_rm32, Register::EDX, Register::EDX)?;
    a.op_m(Code::Xsave64_mem, a.st(OFF_XSAVE))?;
    a.jmp_to(g.exit_common)?;

    g.entry = a.here();
    for r in CALLEE_SAVED {
        a.op_r(Code::Push_r64, r)?;
    }
    a.op_ri(Code::Sub_rm64_imm32, Register::RSP, 168)?;
    for (k, x) in XMM_SAVED.iter().enumerate() {
        a.ins(&iced_x86::Instruction::with2(Code::Movdqu_xmmm128_xmm, mem(Register::RSP, 16 * k as i64), *x).unwrap())?;
    }
    a.op_m(Code::Stmxcsr_m32, a.st(OFF_HOST_MXCSR))?;
    a.op_m(Code::Fnstcw_m2byte, a.st(OFF_HOST_FCW))?;
    a.mov_mr(a.st(OFF_HOST_RSP), Register::RSP)?;
    a.mov_mr(a.st(OFF_JUMP_SLOT), Register::RCX)?;
    load_guest(&mut a)?;
    a.op_m(Code::Jmp_rm64, a.st(OFF_JUMP_SLOT))?;

    g.tramp = a.here();
    save_gprs(&mut a)?;
    let light = xgetbv1_supported();
    if light {
        a.op_ri(Code::Mov_r32_imm32, Register::ECX, 1)?;
        a.op0(Code::Xgetbv)?;
        a.op_ri(Code::Test_rm32_imm32, Register::EAX, 0xE4)?;
        let to_full = a.jcc_rel32(0x5)?;
        light_save(&mut a)?;
        a.mov_mi(a.st(OFF_EXT_LIGHT), 1)?;
        let to_common = a.jmp_rel32()?;
        patch_rel32(to_full, a.here());
        save_ext(&mut a)?;
        a.mov_mi(a.st(OFF_EXT_LIGHT), 0)?;
        patch_rel32(to_common, a.here());
    } else {
        save_ext(&mut a)?;
    }
    a.op0(Code::Cld)?;
    a.op_m(Code::Ldmxcsr_m32, a.st(OFF_HOST_MXCSR))?;
    a.mov_rr(Register::RBX, Register::RSP)?;
    a.op_ri(Code::And_rm64_imm8, Register::RSP, -16)?;
    a.op_ri(Code::Sub_rm64_imm8, Register::RSP, 32)?;
    a.lea(Register::RCX, a.st(0))?;
    a.op_m(Code::Call_rm64, a.st(OFF_DISPATCH))?;
    a.mov_rr(Register::RSP, Register::RBX)?;
    a.op_rr(Code::Test_rm64_r64, Register::RAX, Register::RAX)?;
    let to_exit = a.jcc_rel32(0x5)?;
    if light {
        a.ins(&iced_x86::Instruction::with2(Code::Cmp_rm64_imm8, a.st(OFF_EXT_LIGHT), 0i32).unwrap())?;
        let to_full = a.jcc_rel32(0x4)?;
        light_restore(&mut a)?;
        let to_gprs = a.jmp_rel32()?;
        patch_rel32(to_full, a.here());
        load_ext(&mut a)?;
        patch_rel32(to_gprs, a.here());
    } else {
        load_ext(&mut a)?;
    }
    load_gprs(&mut a)?;
    a.op0(Code::Retnq)?;
    patch_rel32(to_exit, a.here());
    if light {
        a.ins(&iced_x86::Instruction::with2(Code::Cmp_rm64_imm8, a.st(OFF_EXT_LIGHT), 0i32).unwrap())?;
        let done = a.jcc_rel32(0x4)?;
        patch_rel32(done, g.exit_common);
        light_restore(&mut a)?;
        a.op_ri(Code::Mov_r32_imm32, Register::EAX, XSAVE_MASK as i64)?;
        a.op_rr(Code::Xor_r32_rm32, Register::EDX, Register::EDX)?;
        a.op_m(Code::Xsave64_mem, a.st(OFF_XSAVE))?;
    }
    a.jmp_to(g.exit_common)?;

    g.ind_clean = a.here();
    a.mov_mr(a.spill_slot(TMP_SLOT), Register::RAX)?;
    a.mov_rm(Register::RAX, a.st(OFF_IND_TARGET))?;
    a.mov_mr(a.st(OFF_RIP), Register::RAX)?;
    a.mov_rm(Register::RAX, a.spill_slot(TMP_SLOT))?;
    a.mov_mi(a.st(OFF_EXIT_REASON), EXIT_INDIRECT as i32)?;
    a.jmp_to(g.exit_sync)?;

    g.indirect = a.here();
    a.save_flags()?;
    a.mov_mr(a.spill_slot(RCX), Register::RCX)?;
    a.mov_mr(a.spill_slot(RDX), Register::RDX)?;
    a.mov_rm(Register::RDX, a.st(OFF_IND_TARGET))?;
    a.mov_rm(Register::RCX, a.st(OFF_RUN_FLAG))?;
    let stop = a.jrcxz_far()?;
    a.mov_rr(Register::RCX, Register::RDX)?;
    a.op_ri(Code::Shl_rm64_imm8, Register::RCX, 4)?;
    a.op_ri(Code::And_rm64_imm32, Register::RCX, ((JC_ENTRIES - 1) << 4) as i64)?;
    a.op_rm(Code::Add_r64_rm64, Register::RCX, a.st(OFF_JC_PTR))?;
    a.op_rm(Code::Cmp_r64_rm64, Register::RDX, mem(Register::RCX, 0))?;
    let miss = a.jcc_rel32(0x5)?;
    a.mov_rm(Register::RCX, mem(Register::RCX, 8))?;
    a.mov_mr(a.st(OFF_JUMP_SLOT), Register::RCX)?;
    a.mov_rm(Register::RDX, a.spill_slot(RDX))?;
    a.mov_rm(Register::RCX, a.spill_slot(RCX))?;
    a.restore_flags()?;
    a.op_m(Code::Jmp_rm64, a.st(OFF_JUMP_SLOT))?;
    for (patch, reason) in [(stop, EXIT_STOP), (miss, EXIT_INDIRECT)] {
        patch_rel32(patch, a.here());
        a.mov_mr(a.st(OFF_RIP), Register::RDX)?;
        a.mov_rm(Register::RDX, a.spill_slot(RDX))?;
        a.mov_rm(Register::RCX, a.spill_slot(RCX))?;
        a.restore_flags()?;
        a.mov_mi(a.st(OFF_EXIT_REASON), reason as i32)?;
        a.jmp_to(g.exit_sync)?;
    }

    jit.g = g;
    jit.code_start = (a.here() + 63) & !63;
    jit.code_pos = jit.code_start;
    Ok(())
}

pub(super) fn cpu_supports_xsave() -> bool {
    let r = core::arch::x86_64::__cpuid(1);
    r.ecx & (1 << 27) != 0 && r.ecx & (1 << 26) != 0
}

pub(super) unsafe extern "win64" fn dispatch_entry(state: *mut CpuState) -> u64 {
    let emu = unsafe { &mut *((*state).emu as *mut Emu) };
    match catch_unwind(AssertUnwindSafe(|| emu.dispatch())) {
        Ok(r) => r,
        Err(p) => {
            emu.panic = Some(p);
            emu.st_mut().exit_reason = EXIT_HELPER;
            1
        }
    }
}
