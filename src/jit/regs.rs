use iced_x86::Register;

pub const RAX: usize = 0;
pub const RCX: usize = 1;
pub const RDX: usize = 2;
pub const RSP: usize = 4;
pub const R15: usize = 15;

pub const GPR64: [Register; 16] = [
    Register::RAX, Register::RCX, Register::RDX, Register::RBX,
    Register::RSP, Register::RBP, Register::RSI, Register::RDI,
    Register::R8, Register::R9, Register::R10, Register::R11,
    Register::R12, Register::R13, Register::R14, Register::R15,
];
pub const GPR32: [Register; 16] = [
    Register::EAX, Register::ECX, Register::EDX, Register::EBX,
    Register::ESP, Register::EBP, Register::ESI, Register::EDI,
    Register::R8D, Register::R9D, Register::R10D, Register::R11D,
    Register::R12D, Register::R13D, Register::R14D, Register::R15D,
];
pub const GPR16: [Register; 16] = [
    Register::AX, Register::CX, Register::DX, Register::BX,
    Register::SP, Register::BP, Register::SI, Register::DI,
    Register::R8W, Register::R9W, Register::R10W, Register::R11W,
    Register::R12W, Register::R13W, Register::R14W, Register::R15W,
];
pub const GPR8: [Register; 16] = [
    Register::AL, Register::CL, Register::DL, Register::BL,
    Register::SPL, Register::BPL, Register::SIL, Register::DIL,
    Register::R8L, Register::R9L, Register::R10L, Register::R11L,
    Register::R12L, Register::R13L, Register::R14L, Register::R15L,
];

pub fn gpr_idx(r: Register) -> Option<usize> {
    if r == Register::None || !r.is_gpr() {
        return None;
    }
    Some(r.full_register() as usize - Register::RAX as usize)
}

pub fn is_high8(r: Register) -> bool {
    matches!(r, Register::AH | Register::CH | Register::DH | Register::BH)
}

pub fn with_family(r: Register, idx: usize) -> Register {
    match r.size() {
        8 => GPR64[idx],
        4 => GPR32[idx],
        2 => GPR16[idx],
        _ => GPR8[idx],
    }
}

pub fn bit(idx: usize) -> u16 {
    1u16 << idx
}

pub const SCRATCH_ORDER: [usize; 14] = [14, 13, 12, 11, 10, 9, 8, 6, 7, 5, 3, 1, 2, 0];
pub const SCRATCH_ORDER_NOREX: [usize; 7] = [6, 7, 5, 3, 1, 2, 0];

pub fn pick_scratch(excluded: u16, norex: bool) -> Option<usize> {
    let order: &[usize] = if norex { &SCRATCH_ORDER_NOREX } else { &SCRATCH_ORDER };
    order.iter().copied().find(|&i| excluded & bit(i) == 0 && i != RSP && i != R15)
}
