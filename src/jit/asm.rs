use crate::runtime::state::*;
use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Register};

#[derive(Debug)]
pub enum AsmError {
    OutOfSpace,
    Encode(String),
}

impl std::fmt::Display for AsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsmError::OutOfSpace => write!(f, "code cache full"),
            AsmError::Encode(m) => write!(f, "encode failed: {m}"),
        }
    }
}

pub struct Asm {
    pub pos: u64,
    pub end: u64,
    pub state: u64,
    enc: Encoder,
}

pub type AResult<T = ()> = Result<T, AsmError>;

fn i2(code: Code, a: impl Into<Op>, b: impl Into<Op>) -> Instruction {
    let (a, b) = (a.into(), b.into());
    match (a, b) {
        (Op::R(a), Op::R(b)) => Instruction::with2(code, a, b),
        (Op::R(a), Op::M(b)) => Instruction::with2(code, a, b),
        (Op::M(a), Op::R(b)) => Instruction::with2(code, a, b),
        (Op::R(a), Op::I(b)) => Instruction::with2(code, a, b),
        (Op::M(a), Op::I(b)) => Instruction::with2(code, a, b as i32),
        _ => unreachable!(),
    }
    .expect("static instruction form")
}

pub enum Op {
    R(Register),
    M(MemoryOperand),
    I(i64),
}
impl From<Register> for Op {
    fn from(r: Register) -> Self {
        Op::R(r)
    }
}
impl From<MemoryOperand> for Op {
    fn from(m: MemoryOperand) -> Self {
        Op::M(m)
    }
}
impl From<i64> for Op {
    fn from(i: i64) -> Self {
        Op::I(i)
    }
}

pub fn mem(base: Register, disp: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(base, disp)
}

impl Asm {
    pub fn new(pos: u64, end: u64, state: u64) -> Self {
        Self { pos, end, state, enc: Encoder::new(64) }
    }

    pub fn here(&self) -> u64 {
        self.pos
    }

    pub fn raw(&mut self, b: &[u8]) -> AResult {
        if self.pos + b.len() as u64 > self.end {
            return Err(AsmError::OutOfSpace);
        }
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), self.pos as *mut u8, b.len()) };
        self.pos += b.len() as u64;
        Ok(())
    }

    pub fn ins(&mut self, i: &Instruction) -> AResult {
        self.enc
            .encode(i, self.pos)
            .map_err(|e| AsmError::Encode(format!("{e} ({:?})", i.code())))?;
        let mut buf = self.enc.take_buffer();
        let r = self.raw(&buf);
        buf.clear();
        self.enc.set_buffer(buf);
        r
    }

    pub fn st(&self, off: usize) -> MemoryOperand {
        MemoryOperand::with_base_displ(Register::RIP, (self.state + off as u64) as i64)
    }
    pub fn gpr(&self, i: usize) -> MemoryOperand {
        self.st(gpr_off(i))
    }
    pub fn spill_slot(&self, i: usize) -> MemoryOperand {
        self.st(spill_off(i))
    }

    pub fn mov_rm(&mut self, r: Register, m: MemoryOperand) -> AResult {
        let code = match r.size() {
            8 => Code::Mov_r64_rm64,
            4 => Code::Mov_r32_rm32,
            2 => Code::Mov_r16_rm16,
            _ => Code::Mov_r8_rm8,
        };
        self.ins(&i2(code, r, m))
    }
    pub fn mov_mr(&mut self, m: MemoryOperand, r: Register) -> AResult {
        let code = match r.size() {
            8 => Code::Mov_rm64_r64,
            4 => Code::Mov_rm32_r32,
            2 => Code::Mov_rm16_r16,
            _ => Code::Mov_rm8_r8,
        };
        self.ins(&i2(code, m, r))
    }
    pub fn mov_rr(&mut self, d: Register, s: Register) -> AResult {
        self.ins(&i2(Code::Mov_r64_rm64, d, s))
    }
    pub fn mov_ri(&mut self, r: Register, imm: u64) -> AResult {
        self.ins(&i2(Code::Mov_r64_imm64, r, imm as i64))
    }
    pub fn mov_mi(&mut self, m: MemoryOperand, imm: i32) -> AResult {
        self.ins(&i2(Code::Mov_rm64_imm32, m, imm as i64))
    }
    pub fn mov_mi32(&mut self, m: MemoryOperand, imm: u32) -> AResult {
        self.ins(&i2(Code::Mov_rm32_imm32, m, imm as i64))
    }
    pub fn lea(&mut self, r: Register, m: MemoryOperand) -> AResult {
        self.ins(&i2(Code::Lea_r64_m, r, m))
    }
    pub fn op_rm(&mut self, code: Code, r: Register, m: MemoryOperand) -> AResult {
        self.ins(&i2(code, r, m))
    }
    pub fn op_ri(&mut self, code: Code, r: Register, imm: i64) -> AResult {
        self.ins(&i2(code, r, imm))
    }
    pub fn op_rr(&mut self, code: Code, a: Register, b: Register) -> AResult {
        self.ins(&i2(code, a, b))
    }
    pub fn op_m(&mut self, code: Code, m: MemoryOperand) -> AResult {
        self.ins(&Instruction::with1(code, m).expect("static form"))
    }
    pub fn op_r(&mut self, code: Code, r: Register) -> AResult {
        self.ins(&Instruction::with1(code, r).expect("static form"))
    }
    pub fn op0(&mut self, code: Code) -> AResult {
        self.ins(&Instruction::with(code))
    }

    pub fn store_imm64(&mut self, off: usize, imm: u64) -> AResult {
        if imm as i64 == imm as i32 as i64 {
            return self.mov_mi(self.st(off), imm as i32);
        }
        self.mov_mr(self.spill_slot(TMP_SLOT), Register::RAX)?;
        self.mov_ri(Register::RAX, imm)?;
        self.mov_mr(self.st(off), Register::RAX)?;
        self.mov_rm(Register::RAX, self.spill_slot(TMP_SLOT))
    }

    pub fn save_flags(&mut self) -> AResult {
        self.mov_mr(self.spill_slot(0), Register::RAX)?;
        self.op0(Code::Lahf)?;
        self.op_r(Code::Seto_rm8, Register::AL)?;
        self.mov_mr(self.st(OFF_FLAGSAVE), Register::AX)?;
        self.mov_rm(Register::RAX, self.spill_slot(0))
    }
    pub fn restore_flags(&mut self) -> AResult {
        self.mov_mr(self.spill_slot(0), Register::RAX)?;
        self.mov_rm(Register::AX, self.st(OFF_FLAGSAVE))?;
        self.op_ri(Code::Add_rm8_imm8, Register::AL, 0x7f)?;
        self.op0(Code::Sahf)?;
        self.mov_rm(Register::RAX, self.spill_slot(0))
    }

    pub fn jmp_rel32(&mut self) -> AResult<u64> {
        self.raw(&[0xE9, 0, 0, 0, 0])?;
        Ok(self.pos - 4)
    }
    pub fn jcc_rel32(&mut self, cc: u8) -> AResult<u64> {
        self.raw(&[0x0F, 0x80 | cc, 0, 0, 0, 0])?;
        Ok(self.pos - 4)
    }
    pub fn jmp_to(&mut self, target: u64) -> AResult {
        let p = self.jmp_rel32()?;
        patch_rel32(p, target);
        Ok(())
    }
    pub fn call_to(&mut self, target: u64) -> AResult {
        self.raw(&[0xE8, 0, 0, 0, 0])?;
        patch_rel32(self.pos - 4, target);
        Ok(())
    }
    pub fn jrcxz_far(&mut self) -> AResult<u64> {
        self.raw(&[0xE3, 0x02, 0xEB, 0x05, 0xE9, 0, 0, 0, 0])?;
        Ok(self.pos - 4)
    }
}

pub fn patch_rel32(at: u64, target: u64) {
    let rel = target.wrapping_sub(at + 4) as i64;
    debug_assert!(rel == rel as i32 as i64);
    unsafe { core::ptr::write_unaligned(at as *mut i32, rel as i32) };
}
