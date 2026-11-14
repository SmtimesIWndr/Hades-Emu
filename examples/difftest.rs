use hades_emu::*;
use iced_x86::{Code, ConditionCode, Encoder, Instruction, MemoryOperand, Register};
use std::collections::HashMap;
use std::fmt::Write as _;

pub const CODE: u64 = 0x400000;
pub const DATA: u64 = 0x600000;
pub const DATA_SIZE: u64 = 0x2000;
pub const STACK: u64 = 0x700000;
pub const STACK_SIZE: u64 = 0x10000;
pub const FS_BASE: u64 = 0x800;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

enum Item {
    I(Instruction),
    Jcc(ConditionCode, Vec<Item>),
    Call(Vec<Item>),
}

const OF: u32 = 1;
const SF: u32 = 2;
const ZF: u32 = 4;
const AF: u32 = 8;
const CF: u32 = 16;
const PF: u32 = 32;
const ALL: u32 = OF | SF | ZF | AF | CF | PF;

const WRITABLE: [usize; 14] = [0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn reg_of(idx: usize, size: u32) -> Register {
    let base = match size {
        64 => Register::RAX,
        32 => Register::EAX,
        16 => Register::AX,
        _ => {
            return [
                Register::AL, Register::CL, Register::DL, Register::BL, Register::SPL, Register::BPL, Register::SIL, Register::DIL,
                Register::R8L, Register::R9L, Register::R10L, Register::R11L, Register::R12L, Register::R13L, Register::R14L, Register::R15L,
            ][idx];
        }
    };
    let all: Vec<Register> = Register::values().collect();
    all[base as usize + idx]
}

struct Gen {
    rng: Rng,
    codes: HashMap<String, Code>,
    defined: u32,
    enc: Encoder,
}

impl Gen {
    fn code(&self, name: &str) -> Code {
        *self.codes.get(name).unwrap_or_else(|| panic!("no code {name}"))
    }

    fn mem(&mut self, size_hint: u64) -> MemoryOperand {
        let disp_max = 0x1f00 - size_hint;
        match self.rng.below(10) {
            0..=3 => MemoryOperand::with_base_displ(Register::RBP, self.rng.below(disp_max) as i64),
            4 => MemoryOperand::with_base_displ(Register::RSP, self.rng.below(0x400) as i64),
            5 => MemoryOperand::new(Register::RBP, Register::R13, self.rng.pick(&[1, 2, 4, 8]), self.rng.below(0x700) as i64, 4, false, Register::None),
            6 => MemoryOperand::with_base_displ(Register::RIP, (DATA + self.rng.below(disp_max)) as i64),
            7 => MemoryOperand::new(Register::RBP, Register::None, 1, self.rng.below(0x700) as i64, 4, false, Register::FS),
            8 => MemoryOperand::with_base_displ(Register::EBP, self.rng.below(disp_max) as i64),
            _ => MemoryOperand::new(Register::RSP, Register::R13, 1, self.rng.below(0x200) as i64, 4, false, Register::None),
        }
    }

    fn wreg(&mut self) -> usize {
        self.rng.pick(&WRITABLE)
    }
    fn rreg(&mut self) -> usize {
        if self.rng.chance(8) { 4 } else { self.rng.below(16) as usize }
    }

    fn size(&mut self) -> u32 {
        self.rng.pick(&[8, 16, 32, 64, 64, 64, 32])
    }

    fn imm_name(size: u32) -> &'static str {
        match size {
            64 | 32 => "imm32",
            16 => "imm16",
            _ => "imm8",
        }
    }

    fn cond(&mut self) -> Option<ConditionCode> {
        use ConditionCode as C;
        let all = [
            (C::o, OF), (C::no, OF), (C::b, CF), (C::ae, CF), (C::e, ZF), (C::ne, ZF), (C::be, CF | ZF), (C::a, CF | ZF),
            (C::s, SF), (C::ns, SF), (C::p, PF), (C::np, PF), (C::l, SF | OF), (C::ge, SF | OF), (C::le, ZF | SF | OF), (C::g, ZF | SF | OF),
        ];
        let ok: Vec<_> = all.iter().filter(|(_, f)| self.defined & f == *f).map(|(c, _)| *c).collect();
        if ok.is_empty() { None } else { Some(self.rng.pick(&ok)) }
    }

    fn cc_name(c: ConditionCode) -> &'static str {
        use ConditionCode as C;
        match c {
            C::o => "o", C::no => "no", C::b => "b", C::ae => "ae", C::e => "e", C::ne => "ne", C::be => "be", C::a => "a",
            C::s => "s", C::ns => "ns", C::p => "p", C::np => "np", C::l => "l", C::ge => "ge", C::le => "le", _ => "g",
        }
    }

    fn accept(&mut self, i: Instruction, out: &mut Vec<Item>) -> bool {
        let read = i.rflags_read() & ALL;
        if read & !self.defined != 0 {
            return false;
        }
        let ok = self.enc.encode(&i, CODE).is_ok();
        let _ = self.enc.take_buffer();
        if !ok {
            return false;
        }
        let def = (i.rflags_written() | i.rflags_cleared() | i.rflags_set()) & ALL;
        self.defined = (self.defined | def) & !(i.rflags_undefined() & ALL);
        out.push(Item::I(i));
        true
    }

    fn uses_index(m: &MemoryOperand) -> bool {
        m.index == Register::R13
    }

    fn emit_mem_prep(&mut self, m: &MemoryOperand, out: &mut Vec<Item>) {
        if Self::uses_index(m) {
            out.push(Item::I(Instruction::with2(Code::Movzx_r32_rm8, Register::R13D, Register::R13L).unwrap()));
        }
    }

    fn one(&mut self, out: &mut Vec<Item>, depth: u32) {
        let r = self.rng.below(100);
        let size = self.size();
        let s = size.to_string();
        let res: Option<Instruction> = match r {
            0..=17 => {
                let op = self.rng.pick(&["Add", "Or", "Adc", "Sbb", "And", "Sub", "Xor", "Cmp"]);
                let form = self.rng.below(5);
                let dst = self.wreg();
                match form {
                    0 => Instruction::with2(self.code(&format!("{op}_rm{s}_r{s}")), reg_of(dst, size), reg_of(self.rreg(), size)).ok(),
                    1 => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(self.code(&format!("{op}_r{s}_rm{s}")), reg_of(dst, size), m).ok()
                    }
                    2 => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(self.code(&format!("{op}_rm{s}_r{s}")), m, reg_of(self.rreg(), size)).ok()
                    }
                    3 => {
                        let imm = self.rng.next() as i32 >> self.rng.below(31);
                        let imm = match size { 8 => imm as i8 as i32, 16 => imm as i16 as i32, _ => imm };
                        let c = self.code(&format!("{op}_rm{s}_{}", Self::imm_name(size)));
                        if size == 16 || size == 8 {
                            Instruction::with2(c, reg_of(dst, size), imm as u32 & if size == 8 { 0xff } else { 0xffff }).ok()
                        } else {
                            Instruction::with2(c, reg_of(dst, size), imm).ok()
                        }
                    }
                    _ => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        let c = self.code(&format!("{op}_rm{s}_imm8"));
                        Instruction::with2(c, m, self.rng.below(256) as i32 as i8 as i32).ok()
                    }
                }
            }
            18..=21 => {
                let op = self.rng.pick(&["Inc", "Dec", "Neg", "Not"]);
                if self.rng.chance(50) {
                    Instruction::with1(self.code(&format!("{op}_rm{s}")), reg_of(self.wreg(), size)).ok()
                } else {
                    let m = self.mem(8);
                    self.emit_mem_prep(&m, out);
                    Instruction::with1(self.code(&format!("{op}_rm{s}")), m).ok()
                }
            }
            22..=27 => {
                let op = self.rng.pick(&["Rol", "Ror", "Rcl", "Rcr", "Shl", "Shr", "Sar"]);
                let dst = self.wreg();
                match self.rng.below(3) {
                    0 => Instruction::with2(self.code(&format!("{op}_rm{s}_imm8")), reg_of(dst, size), 1 + self.rng.below(size as u64 - 1) as u32).ok(),
                    1 => Instruction::with2(self.code(&format!("{op}_rm{s}_1")), reg_of(dst, size), 1u32).ok(),
                    _ => {
                        let i = Instruction::with2(self.code(&format!("{op}_rm{s}_CL")), reg_of(dst, size), Register::CL).ok();
                        if let Some(i) = i
                            && self.accept(i, out)
                        {
                            self.defined = 0;
                        }
                        None
                    }
                }
            }
            28..=37 => {
                let dst = self.wreg();
                match self.rng.below(6) {
                    0 => Instruction::with2(self.code(&format!("Mov_rm{s}_r{s}")), reg_of(dst, size), reg_of(self.rreg(), size)).ok(),
                    1 => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(self.code(&format!("Mov_r{s}_rm{s}")), reg_of(dst, size), m).ok()
                    }
                    2 => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(self.code(&format!("Mov_rm{s}_r{s}")), m, reg_of(self.rreg(), size)).ok()
                    }
                    3 => Instruction::with2(Code::Mov_r64_imm64, reg_of(dst, 64), self.rng.next()).ok(),
                    4 => {
                        let hi = self.rng.pick(&[Register::AH, Register::CH, Register::DH, Register::BH]);
                        let lo = self.rng.pick(&[Register::AL, Register::CL, Register::DL, Register::BL, Register::AH, Register::BH]);
                        match self.rng.below(3) {
                            0 => Instruction::with2(Code::Mov_r8_rm8, hi, lo).ok(),
                            1 => Instruction::with2(Code::Add_r8_rm8, hi, MemoryOperand::with_base_displ(Register::RBP, self.rng.below(0x100) as i64)).ok(),
                            _ => Instruction::with2(Code::Mov_rm8_r8, MemoryOperand::with_base_displ(Register::RBP, self.rng.below(0x100) as i64), hi).ok(),
                        }
                    }
                    _ => {
                        let name = self.rng.pick(&["Movzx_r32_rm8", "Movzx_r64_rm16", "Movsx_r64_rm8", "Movsxd_r64_rm32", "Movsx_r32_rm16"]);
                        let (ds, ss) = match name {
                            "Movzx_r32_rm8" => (32, 8),
                            "Movzx_r64_rm16" => (64, 16),
                            "Movsx_r64_rm8" => (64, 8),
                            "Movsxd_r64_rm32" => (64, 32),
                            _ => (32, 16),
                        };
                        if self.rng.chance(50) {
                            Instruction::with2(self.code(name), reg_of(dst, ds), reg_of(self.rreg(), ss)).ok()
                        } else {
                            let m = self.mem(8);
                            self.emit_mem_prep(&m, out);
                            Instruction::with2(self.code(name), reg_of(dst, ds), m).ok()
                        }
                    }
                }
            }
            38..=42 => {
                let base = self.rng.pick(&[Register::RSP, Register::R15, Register::RAX, Register::RBP, Register::R12, Register::None]);
                let index = self.rng.pick(&[Register::R15, Register::RCX, Register::None, Register::R14]);
                let m = MemoryOperand::new(base, index, self.rng.pick(&[1, 2, 4, 8]), self.rng.next() as i32 as i64 >> 8, 4, false, Register::None);
                let dsz = self.rng.pick(&[64, 32, 16]);
                let c = self.code(&format!("Lea_r{dsz}_m"));
                if base == Register::None && index == Register::None {
                    None
                } else {
                    Instruction::with2(c, reg_of(self.wreg(), dsz), m).ok()
                }
            }
            43..=46 => {
                let a = self.wreg();
                let b = self.wreg();
                match self.rng.below(5) {
                    0 => Instruction::with2(Code::Xchg_rm64_r64, reg_of(a, 64), reg_of(b, 64)).ok(),
                    1 => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(Code::Xchg_rm64_r64, m, reg_of(b, 64)).ok()
                    }
                    2 => Instruction::with2(Code::Xadd_rm64_r64, reg_of(a, 64), reg_of(b, 64)).ok(),
                    3 => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(Code::Cmpxchg_rm64_r64, m, reg_of(b, 64)).ok()
                    }
                    _ => Instruction::with1(Code::Bswap_r64, reg_of(a, 64)).ok(),
                }
            }
            47..=51 => match self.rng.below(4) {
                0 => Instruction::with2(Code::Imul_r64_rm64, reg_of(self.wreg(), 64), reg_of(self.rreg(), 64)).ok(),
                1 => Instruction::with3(Code::Imul_r32_rm32_imm32, reg_of(self.wreg(), 32), reg_of(self.rreg(), 32), self.rng.next() as i32).ok(),
                2 => Instruction::with1(Code::Mul_rm64, reg_of(self.rreg(), 64)).ok(),
                _ => {
                    let m = self.mem(8);
                    self.emit_mem_prep(&m, out);
                    Instruction::with1(Code::Imul_rm32, m).ok()
                }
            },
            52..=56 => {
                let c = self.cond();
                c.and_then(|c| {
                    let n = Self::cc_name(c);
                    if self.rng.chance(50) {
                        Instruction::with1(self.code(&format!("Set{n}_rm8")), reg_of(self.wreg(), 8)).ok()
                    } else {
                        Instruction::with2(self.code(&format!("Cmov{n}_r64_rm64")), reg_of(self.wreg(), 64), reg_of(self.rreg(), 64)).ok()
                    }
                })
            }
            57..=60 => {
                let op = self.rng.pick(&["Bt", "Bts", "Btr", "Btc"]);
                match self.rng.below(3) {
                    0 => Instruction::with2(self.code(&format!("{op}_rm64_imm8")), reg_of(self.wreg(), 64), self.rng.below(64) as u32).ok(),
                    1 => {
                        let m = self.mem(8);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(self.code(&format!("{op}_rm32_imm8")), m, self.rng.below(32) as u32).ok()
                    }
                    _ => {
                        out.push(Item::I(Instruction::with2(Code::Mov_r32_imm32, Register::R11D, self.rng.below(2000) as u32).unwrap()));
                        let disp = self.rng.below(0x1000) as i64;
                        Instruction::with2(self.code(&format!("{op}_rm64_r64")), MemoryOperand::with_base_displ(Register::RBP, disp), Register::R11).ok()
                    }
                }
            }
            61..=64 => {
                let a = self.wreg();
                let b = self.wreg();
                if self.rng.chance(60) {
                    out.push(Item::I(Instruction::with1(Code::Push_r64, reg_of(self.rreg(), 64)).unwrap()));
                    Instruction::with1(Code::Pop_r64, reg_of(a, 64)).ok()
                } else if self.rng.chance(50) {
                    let m = MemoryOperand::with_base_displ(Register::RBP, self.rng.below(0x1000) as i64);
                    out.push(Item::I(Instruction::with1(Code::Push_rm64, m).unwrap()));
                    let m2 = MemoryOperand::with_base_displ(Register::RBP, self.rng.below(0x1000) as i64);
                    Instruction::with1(Code::Pop_rm64, m2).ok()
                } else {
                    out.push(Item::I(Instruction::with1(Code::Pushq_imm32, self.rng.next() as i32).unwrap()));
                    Instruction::with1(Code::Pop_r64, reg_of(b, 64)).ok()
                }
            }
            65..=67 => {
                if self.defined & (CF | PF | AF | ZF | SF | OF) == ALL && self.rng.chance(50) {
                    out.push(Item::I(Instruction::with(Code::Pushfq)));
                    out.push(Item::I(Instruction::with2(Code::And_rm64_imm32, MemoryOperand::with_base(Register::RSP), 0x8D5).unwrap()));
                    let r = self.wreg();
                    Instruction::with1(Code::Pop_r64, reg_of(r, 64)).ok()
                } else if self.rng.chance(50) {
                    let r = self.wreg();
                    out.push(Item::I(Instruction::with2(Code::And_rm64_imm32, reg_of(r, 64), 0x8D5).unwrap()));
                    out.push(Item::I(Instruction::with1(Code::Push_r64, reg_of(r, 64)).unwrap()));
                    let i = Instruction::with(Code::Popfq);
                    out.push(Item::I(i));
                    self.defined = ALL;
                    None
                } else if self.defined & (CF | PF | AF | ZF | SF) == (CF | PF | AF | ZF | SF) {
                    Some(Instruction::with(Code::Lahf))
                } else {
                    Some(Instruction::with(Code::Sahf))
                }
            }
            68..=70 => Some(Instruction::with(self.rng.pick(&[Code::Cqo, Code::Cdqe, Code::Cwde, Code::Cdq, Code::Stc, Code::Clc, Code::Cmc]))),
            71..=74 => {
                let x = self.rng.pick(&[Register::XMM0, Register::XMM1, Register::XMM2, Register::XMM3]);
                let y = self.rng.pick(&[Register::XMM0, Register::XMM1, Register::XMM2, Register::XMM3]);
                match self.rng.below(5) {
                    0 => {
                        let m = self.mem(16);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(Code::Movdqu_xmm_xmmm128, x, m).ok()
                    }
                    1 => {
                        let m = self.mem(16);
                        self.emit_mem_prep(&m, out);
                        Instruction::with2(Code::Movdqu_xmmm128_xmm, m, x).ok()
                    }
                    2 => Instruction::with2(self.rng.pick(&[Code::Paddd_xmm_xmmm128, Code::Pxor_xmm_xmmm128, Code::Pmullw_xmm_xmmm128, Code::Punpcklbw_xmm_xmmm128]), x, y).ok(),
                    3 => Instruction::with3(Code::Pshufd_xmm_xmmm128_imm8, x, y, self.rng.below(256) as u32).ok(),
                    _ => Instruction::with2(Code::Movq_rm64_xmm, reg_of(self.wreg(), 64), x).ok(),
                }
            }
            75..=79 => {
                let n = 1 + self.rng.below(40);
                let down = self.rng.chance(25);
                let (src, dst) = if down { (0x400 + self.rng.below(0x800), 0x1400 + self.rng.below(0x800)) } else { (self.rng.below(0x800), 0x800 + self.rng.below(0x1000)) };
                let dst = if self.rng.chance(20) { src + self.rng.below(4) } else { dst };
                out.push(Item::I(Instruction::with2(Code::Lea_r64_m, Register::RSI, MemoryOperand::with_base_displ(Register::RBP, src as i64)).unwrap()));
                out.push(Item::I(Instruction::with2(Code::Lea_r64_m, Register::RDI, MemoryOperand::with_base_displ(Register::RBP, dst as i64)).unwrap()));
                out.push(Item::I(Instruction::with2(Code::Mov_r32_imm32, Register::ECX, n as u32).unwrap()));
                if down {
                    out.push(Item::I(Instruction::with(Code::Std)));
                }
                let (code, rep) = self.rng.pick(&[
                    (Code::Movsb_m8_m8, 0), (Code::Movsq_m64_m64, 0), (Code::Stosb_m8_AL, 0), (Code::Stosq_m64_RAX, 0),
                    (Code::Lodsb_AL_m8, 0), (Code::Cmpsb_m8_m8, 1), (Code::Scasb_AL_m8, 2), (Code::Movsd_m32_m32, 0),
                ]);
                let mut i = Instruction::with(code);
                match rep {
                    0 => i.set_has_rep_prefix(true),
                    1 => i.set_has_repe_prefix(true),
                    _ => i.set_has_repne_prefix(true),
                }
                if self.accept(i, out) && down {
                    out.push(Item::I(Instruction::with(Code::Cld)));
                }
                None
            }
            80..=84 if depth < 2 => {
                if let Some(c) = self.cond() {
                    let before = self.defined;
                    let mut inner = Vec::new();
                    for _ in 0..1 + self.rng.below(3) {
                        self.one(&mut inner, depth + 1);
                    }
                    self.defined &= before;
                    out.push(Item::Jcc(c, inner));
                }
                None
            }
            85..=87 if depth < 2 => {
                let mut inner = Vec::new();
                for _ in 0..1 + self.rng.below(4) {
                    self.one(&mut inner, depth + 1);
                }
                out.push(Item::Call(inner));
                None
            }
            88..=90 => {
                let op = self.rng.pick(&["Test_rm64_r64", "Test_rm32_r32", "Cmp_rm64_r64"]);
                Instruction::with2(self.code(op), reg_of(self.rreg(), if op.contains("32") { 32 } else { 64 }), reg_of(self.rreg(), if op.contains("32") { 32 } else { 64 })).ok()
            }
            91..=94 => {
                let dst = self.wreg();
                let m = MemoryOperand::new(Register::RBP, Register::None, 1, self.rng.below(0x700) as i64, 4, false, Register::FS);
                if self.rng.chance(50) {
                    Instruction::with2(Code::Mov_r64_rm64, reg_of(dst, 64), m).ok()
                } else {
                    Instruction::with2(Code::Add_rm32_r32, m, reg_of(dst, 32)).ok()
                }
            }
            _ => {
                let dst = self.wreg();
                if self.rng.chance(50) {
                    Instruction::with2(Code::Mov_rm64_r64, reg_of(dst, 64), Register::RSP).ok()
                } else {
                    Instruction::with2(Code::Lea_r64_m, reg_of(dst, 64), MemoryOperand::with_base_displ(Register::RSP, self.rng.below(0x80) as i64 - 0x40)).ok()
                }
            }
        };
        if let Some(i) = res {
            self.accept(i, out);
        }
    }
}

fn encode(items: &[Item], ip: u64, enc: &mut Encoder, out: &mut Vec<u8>) {
    for it in items {
        let here = ip + out.len() as u64;
        match it {
            Item::I(i) => {
                let ok = enc.encode(i, here).is_ok();
                let bytes = enc.take_buffer();
                if ok {
                    out.extend(bytes);
                }
            }
            Item::Jcc(c, inner) => {
                let mut body = Vec::new();
                encode(inner, here + 6, enc, &mut body);
                let code = match c {
                    ConditionCode::o => Code::Jo_rel32_64, ConditionCode::no => Code::Jno_rel32_64,
                    ConditionCode::b => Code::Jb_rel32_64, ConditionCode::ae => Code::Jae_rel32_64,
                    ConditionCode::e => Code::Je_rel32_64, ConditionCode::ne => Code::Jne_rel32_64,
                    ConditionCode::be => Code::Jbe_rel32_64, ConditionCode::a => Code::Ja_rel32_64,
                    ConditionCode::s => Code::Js_rel32_64, ConditionCode::ns => Code::Jns_rel32_64,
                    ConditionCode::p => Code::Jp_rel32_64, ConditionCode::np => Code::Jnp_rel32_64,
                    ConditionCode::l => Code::Jl_rel32_64, ConditionCode::ge => Code::Jge_rel32_64,
                    ConditionCode::le => Code::Jle_rel32_64, _ => Code::Jg_rel32_64,
                };
                let j = Instruction::with_branch(code, here + 6 + body.len() as u64).unwrap();
                enc.encode(&j, here).unwrap();
                out.extend(enc.take_buffer());
                out.extend(body);
            }
            Item::Call(inner) => {
                let mut body = Vec::new();
                encode(inner, here + 10, enc, &mut body);
                let call = Instruction::with_branch(Code::Call_rel32_64, here + 10).unwrap();
                enc.encode(&call, here).unwrap();
                out.extend(enc.take_buffer());
                let jmp = Instruction::with_branch(Code::Jmp_rel32_64, here + 10 + body.len() as u64 + 1).unwrap();
                enc.encode(&jmp, here + 5).unwrap();
                out.extend(enc.take_buffer());
                out.extend(body);
                out.push(0xC3);
            }
        }
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

pub fn fnv(data: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn dump(hex_code: &str) {
    let hex_code = hex_code.trim();
    use iced_x86::{Decoder, Formatter, IntelFormatter};
    let bytes: Vec<u8> = (0..hex_code.len()).step_by(2).map(|i| u8::from_str_radix(&hex_code[i..i + 2], 16).unwrap()).collect();
    let mut f = IntelFormatter::new();
    for i in Decoder::with_ip(64, &bytes, CODE, 0) {
        let mut s = String::new();
        f.format(&i, &mut s);
        println!("{:#x}: {s}", i.ip());
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let start = line.find(&format!("\"{key}\":\"")).unwrap() + key.len() + 4;
    let rest = &line[start..];
    &rest[..rest.find('"').unwrap()]
}

fn list(line: &str, key: &str) -> Vec<u128> {
    let start = line.find(&format!("\"{key}\":[")).unwrap() + key.len() + 4;
    let rest = &line[start..];
    rest[..rest.find(']').unwrap()].split(',').map(|v| v.parse().unwrap()).collect()
}

fn trace(path: &str, case: usize) {
    let text = std::fs::read_to_string(path).unwrap();
    let line = text.lines().nth(case).unwrap();
    let code = unhex(field(line, "code"));
    let data = unhex(field(line, "data"));
    let regs = list(line, "regs");
    let xmm = list(line, "xmm");
    let mut emu = Hades::new().unwrap();
    emu.mem_map(CODE, 0x10000, PERM_ALL).unwrap();
    emu.mem_map(DATA, DATA_SIZE, PERM_READ | PERM_WRITE).unwrap();
    emu.mem_map(STACK, STACK_SIZE, PERM_READ | PERM_WRITE).unwrap();
    emu.mem_write(CODE, &code).unwrap();
    emu.mem_write(DATA, &data).unwrap();
    for (i, r) in Reg::GPRS.iter().enumerate() {
        emu.reg_write(*r, regs[i] as u64);
    }
    emu.reg_write(Reg::RFLAGS, 0x202);
    emu.reg_write(Reg::FsBase, FS_BASE);
    for (i, x) in xmm.iter().enumerate() {
        emu.xmm_write(i, *x);
    }
    emu.add_code_hook(1, 0, |e, addr, _| {
        let r: Vec<String> = Reg::GPRS.iter().map(|r| e.reg_read(*r).to_string()).collect();
        println!("[{addr},{},{}]", r.join(","), e.reg_read(Reg::RFLAGS));
    });
    let r = emu.emu_start(CODE, CODE + code.len() as u64, None, 0);
    let fr: Vec<String> = Reg::GPRS.iter().map(|r| emu.reg_read(*r).to_string()).collect();
    println!("[{},{},{}]", emu.reg_read(Reg::RIP), fr.join(","), emu.reg_read(Reg::RFLAGS));
    eprintln!("{r:?}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("dump") {
        dump(&args[2]);
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("trace") {
        trace(&args[2], args[3].parse().unwrap());
        return;
    }
    let cases: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let seed: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let out_path = args.get(3).cloned().unwrap_or_else(|| "cases.jsonl".into());
    let codes: HashMap<String, Code> = Code::values().map(|c| (format!("{c:?}"), c)).collect();
    let mut g = Gen { rng: Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1), codes, defined: 0, enc: Encoder::new(64) };
    let mut out = String::new();
    let mut emu = Hades::new().unwrap();
    emu.mem_map(CODE, 0x10000, PERM_ALL).unwrap();
    emu.mem_map(DATA, DATA_SIZE, PERM_READ | PERM_WRITE).unwrap();
    emu.mem_map(STACK, STACK_SIZE, PERM_READ | PERM_WRITE).unwrap();
    let mut errors = 0;
    let mode = std::env::var("DIFF_MODE").unwrap_or_default();
    if mode == "hooks" {
        emu.add_mem_hook(HOOK_MEM_READ | HOOK_MEM_WRITE, 1, 0, |_, _, _, _, _| {});
        emu.add_block_hook(1, 0, |_, _, _| {});
        emu.add_code_hook(CODE + 0x20, CODE + 0x80, |_, _, _| {});
    }
    let budget = if mode == "count" { 1_000_000 } else { 0 };
    for case in 0..cases {
        g.defined = 0;
        let mut items = Vec::new();
        let n = 20 + g.rng.below(40);
        for _ in 0..n {
            g.one(&mut items, 0);
        }
        items.push(Item::I(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap()));
        let mut enc = Encoder::new(64);
        let mut code = Vec::new();
        encode(&items, CODE, &mut enc, &mut code);

        let mut regs = [0u64; 16];
        for r in regs.iter_mut() {
            *r = g.rng.next() >> g.rng.below(64);
        }
        regs[4] = STACK + 0x8000;
        regs[5] = DATA;
        let data: Vec<u8> = (0..DATA_SIZE).map(|_| g.rng.next() as u8).collect();
        let stack = vec![0u8; STACK_SIZE as usize];
        let xmm: Vec<u128> = (0..4).map(|_| (g.rng.next() as u128) << 64 | g.rng.next() as u128).collect();

        emu.mem_write(CODE, &code).unwrap();
        emu.mem_write(DATA, &data).unwrap();
        emu.mem_write(STACK, &stack).unwrap();
        for (i, r) in Reg::GPRS.iter().enumerate() {
            emu.reg_write(*r, regs[i]);
        }
        emu.reg_write(Reg::RFLAGS, 0x202);
        emu.reg_write(Reg::FsBase, FS_BASE);
        emu.reg_write(Reg::GsBase, 0);
        for (i, x) in xmm.iter().enumerate() {
            emu.xmm_write(i, *x);
        }
        let r = emu.emu_start(CODE, CODE + code.len() as u64, None, budget);
        let mut line = format!(
            "{{\"case\":{case},\"code\":\"{}\",\"regs\":[{}],\"data\":\"{}\",\"xmm\":[{}],",
            hex(&code),
            regs.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","),
            hex(&data),
            xmm.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","),
        );
        match r {
            Ok(()) => {
                let fr: Vec<String> = Reg::GPRS.iter().map(|r| emu.reg_read(*r).to_string()).collect();
                let mut mem = emu.mem_read_vec(DATA, DATA_SIZE as usize).unwrap();
                mem.extend(emu.mem_read_vec(STACK, STACK_SIZE as usize).unwrap());
                let fx: Vec<String> = (0..4).map(|i| emu.xmm_read(i).to_string()).collect();
                let _ = write!(
                    line,
                    "\"out\":{{\"regs\":[{}],\"rflags\":{},\"rip\":{},\"memhash\":{},\"xmm\":[{}]}}}}",
                    fr.join(","),
                    emu.reg_read(Reg::RFLAGS),
                    emu.reg_read(Reg::RIP),
                    fnv(&mem),
                    fx.join(",")
                );
            }
            Err(e) => {
                errors += 1;
                let _ = write!(line, "\"error\":\"{e}\"}}");
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    std::fs::write(&out_path, out).unwrap();
    eprintln!("wrote {cases} cases to {out_path} ({errors} hades errors), {} cached blocks", emu.cached_blocks());
}
