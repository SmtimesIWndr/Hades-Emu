use super::ARITH;
use crate::{EXC_GENERAL_PROTECTION, EXC_INVALID_OPCODE};
use crate::jit::regs::*;
use crate::runtime::state::*;
use iced_x86::{Code, FlowControl, Instruction, InstructionInfoFactory, MemorySize, Mnemonic, OpAccess, OpKind, Register};

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Generic,
    Skip,
    Push,
    Pop,
    Pushfq,
    Popfq,
    Leave,
    Interp,
    RdBase(usize),
    WrBase(usize),
    Jmp(u64),
    Jcc(u64),
    LoopLike(u64),
    CallDirect(u64),
    CallIndirect,
    JmpIndirect,
    Ret(u16),
    Syscall,
    Interrupt(u32),
    Exception(u32),
    Unsupported,
}

impl Kind {
    pub(super) fn terminates(self) -> bool {
        matches!(
            self,
            Kind::Jmp(_)
                | Kind::Jcc(_)
                | Kind::LoopLike(_)
                | Kind::CallDirect(_)
                | Kind::CallIndirect
                | Kind::JmpIndirect
                | Kind::Ret(_)
                | Kind::Syscall
                | Kind::Interrupt(_)
                | Kind::Exception(_)
                | Kind::Unsupported
        )
    }
}

fn is_far_mem(i: &Instruction) -> bool {
    matches!(i.memory_size(), MemorySize::SegPtr16 | MemorySize::SegPtr32 | MemorySize::SegPtr64)
}

fn has_special_mem(i: &Instruction) -> bool {
    (0..i.op_count()).any(|op| {
        matches!(
            i.op_kind(op),
            OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI
        )
    })
}

pub(super) fn mem_op_index(i: &Instruction) -> Option<u32> {
    (0..i.op_count()).find(|&op| i.op_kind(op) == OpKind::Memory)
}

pub fn classify(i: &Instruction, f: &mut InstructionInfoFactory) -> Kind {
    use Mnemonic as M;
    if i.code().is_privileged() {
        return Kind::Exception(EXC_GENERAL_PROTECTION);
    }
    let k0 = i.op_kind(0);
    match i.mnemonic() {
        M::Syscall => Kind::Syscall,
        M::Int3 => Kind::Interrupt(3),
        M::Int1 => Kind::Interrupt(1),
        M::Int => Kind::Interrupt(i.immediate8() as u32),
        M::Ud0 | M::Ud1 | M::Ud2 => Kind::Exception(EXC_INVALID_OPCODE),
        M::Insb | M::Insw | M::Insd | M::Outsb | M::Outsw | M::Outsd => Kind::Exception(EXC_GENERAL_PROTECTION),
        M::Jmp => match k0 {
            OpKind::NearBranch64 => Kind::Jmp(i.near_branch_target()),
            OpKind::Register if i.op0_register().is_gpr64() => Kind::JmpIndirect,
            OpKind::Memory if !is_far_mem(i) && i.memory_size().size() == 8 => Kind::JmpIndirect,
            _ => Kind::Unsupported,
        },
        M::Call => match k0 {
            OpKind::NearBranch64 => Kind::CallDirect(i.near_branch_target()),
            OpKind::Register if i.op0_register().is_gpr64() => Kind::CallIndirect,
            OpKind::Memory if !is_far_mem(i) && i.memory_size().size() == 8 => Kind::CallIndirect,
            _ => Kind::Unsupported,
        },
        M::Ret => match i.code() {
            Code::Retnq => Kind::Ret(0),
            Code::Retnq_imm16 => Kind::Ret(i.immediate16()),
            _ => Kind::Unsupported,
        },
        M::Loop | M::Loope | M::Loopne | M::Jrcxz | M::Jecxz if k0 == OpKind::NearBranch64 => {
            Kind::LoopLike(i.near_branch_target())
        }
        _ if i.is_jcc_short_or_near() && k0 == OpKind::NearBranch64 => Kind::Jcc(i.near_branch_target()),
        M::Push => match k0 {
            OpKind::Register if i.op0_register().is_gpr() => Kind::Push,
            OpKind::Memory | OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate8to16 | OpKind::Immediate16 => Kind::Push,
            _ => Kind::Unsupported,
        },
        M::Pop => match k0 {
            OpKind::Register if i.op0_register().is_gpr() => Kind::Pop,
            OpKind::Memory => Kind::Pop,
            _ => Kind::Unsupported,
        },
        M::Pushfq => Kind::Pushfq,
        M::Popfq => Kind::Popfq,
        M::Leave if i.code() == Code::Leaveq => Kind::Leave,
        M::Enter if i.code() == Code::Enterq_imm16_imm8 => Kind::Interp,
        M::Xlatb => Kind::Interp,
        M::Bt | M::Bts | M::Btr | M::Btc if k0 == OpKind::Memory && i.op_kind(1) == OpKind::Register => Kind::Interp,
        M::Rdfsbase => Kind::RdBase(OFF_FS),
        M::Rdgsbase => Kind::RdBase(OFF_GS),
        M::Wrfsbase => Kind::WrBase(OFF_FS),
        M::Wrgsbase => Kind::WrBase(OFF_GS),
        M::Incsspd | M::Incsspq | M::Rdsspd | M::Rdsspq | M::Saveprevssp | M::Rstorssp | M::Wrssd | M::Wrssq
        | M::Wrussd | M::Wrussq | M::Setssbsy | M::Clrssbsy | M::Wrpkru | M::Xsave | M::Xsave64 | M::Xsaveopt
        | M::Xsaveopt64 | M::Xsavec | M::Xsavec64 | M::Xsaves | M::Xsaves64 | M::Xrstor | M::Xrstor64 | M::Xrstors
        | M::Xrstors64 | M::Lfs | M::Lgs | M::Lss | M::Monitor | M::Monitorx | M::Sysenter | M::Sysexit
        | M::Sysret | M::Iret | M::Iretd | M::Iretq | M::Retf | M::Into | M::Jmpe | M::Xbegin | M::Xabort
        | M::Xend => Kind::Unsupported,
        M::Mov if k0 == OpKind::Register && i.op0_register().is_segment_register() => Kind::Unsupported,
        _ if i.is_string_instruction() => Kind::Interp,
        _ => {
            if i.is_stack_instruction() || i.flow_control() != FlowControl::Next || i.is_vsib() || has_special_mem(i) {
                Kind::Unsupported
            } else if let Some(op) = mem_op_index(i) {
                let acc = f.info(i).op_access(op);
                let size = i.memory_size().size();
                if matches!(acc, OpAccess::NoMemAccess | OpAccess::None) {
                    if i.mnemonic() == M::Lea { Kind::Generic } else { Kind::Skip }
                } else if size == 0 || size > 4096 {
                    Kind::Unsupported
                } else {
                    Kind::Generic
                }
            } else {
                Kind::Generic
            }
        }
    }
}

pub(super) fn flags_effect(i: &Instruction) -> (u32, u32) {
    use Mnemonic as M;
    let read = i.rflags_read() & ARITH;
    let mut kill = i.rflags_modified() & ARITH;
    if matches!(i.mnemonic(), M::Shl | M::Shr | M::Sar | M::Sal | M::Rol | M::Ror | M::Rcl | M::Rcr | M::Shld | M::Shrd) {
        let cnt_op = i.op_count() - 1;
        let zero_possible = match i.op_kind(cnt_op) {
            OpKind::Register => true,
            OpKind::Immediate8 => i.immediate8() & 0x3f == 0 || (i.op0_register().size() != 8 && i.immediate8() & 0x1f == 0),
            _ => false,
        };
        if zero_possible {
            kill = 0;
        }
    }
    (read, kill)
}

#[derive(Clone, Copy)]
pub struct MemDesc {
    pub base: Register,
    pub index: Register,
    pub scale: u32,
    pub disp: i64,
    pub absolute: Option<u64>,
    pub addr32: bool,
    pub seg: Option<usize>,
}

impl MemDesc {
    pub fn of(i: &Instruction) -> Self {
        let base = i.memory_base();
        let index = i.memory_index();
        let seg = match i.segment_prefix() {
            Register::FS => Some(OFF_FS),
            Register::GS => Some(OFF_GS),
            _ => None,
        };
        let addr32 = base.is_gpr32() || index.is_gpr32() || base == Register::EIP;
        let raw = i.memory_displacement64();
        let absolute = if base == Register::RIP || base == Register::EIP || (base == Register::None && index == Register::None) {
            Some(if addr32 { raw as u32 as u64 } else { raw })
        } else {
            None
        };
        let disp = if addr32 { raw as u32 as i32 as i64 } else { raw as i64 };
        Self { base, index, scale: i.memory_index_scale(), disp, absolute, addr32, seg }
    }
    pub fn stack(disp: i64) -> Self {
        Self { base: Register::RSP, index: Register::None, scale: 1, disp, absolute: None, addr32: false, seg: None }
    }
    pub(super) fn regs(&self) -> u16 {
        let mut m = 0;
        for r in [self.base, self.index] {
            if let Some(i) = gpr_idx(r) {
                m |= bit(i);
            }
        }
        m
    }
}
