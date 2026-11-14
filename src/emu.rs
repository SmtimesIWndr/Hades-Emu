use crate::error::{EmuError, MemAccess};
use crate::hooks::HookSlot;
use crate::jit::Jit;
use crate::memory::{FaultKind, Memory, PERM_EXEC, PERM_READ, PERM_WRITE};
use crate::runtime::region::CodeRegion;
use crate::runtime::state::{self, CpuState};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const PERM_ALL: u8 = PERM_READ | PERM_WRITE | PERM_EXEC;

pub const EXC_DIVIDE: u32 = 0;
pub const EXC_DEBUG: u32 = 1;
pub const EXC_BREAKPOINT: u32 = 3;
pub const EXC_INVALID_OPCODE: u32 = 6;
pub const EXC_GENERAL_PROTECTION: u32 = 13;
pub const EXC_X87: u32 = 16;
pub const EXC_SIMD: u32 = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum Reg {
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP, RFLAGS, FsBase, GsBase,
}

impl Reg {
    pub const GPRS: [Reg; 16] = [
        Reg::RAX, Reg::RCX, Reg::RDX, Reg::RBX, Reg::RSP, Reg::RBP, Reg::RSI, Reg::RDI,
        Reg::R8, Reg::R9, Reg::R10, Reg::R11, Reg::R12, Reg::R13, Reg::R14, Reg::R15,
    ];
}

#[derive(Clone)]
pub struct StopHandle {
    region: Arc<CodeRegion>,
    requested: Arc<AtomicBool>,
}

impl StopHandle {
    pub fn stop(&self) {
        self.requested.store(true, Ordering::SeqCst);
        self.region.run_flag().store(0, Ordering::SeqCst);
    }
}

pub struct Emu {
    pub(crate) region: Arc<CodeRegion>,
    pub(crate) state: *mut CpuState,
    pub(crate) mem: Memory,
    pub(crate) jit: Jit,
    pub(crate) hooks: Vec<Option<HookSlot>>,
    pub(crate) running: bool,
    pub(crate) stop_requested: Arc<AtomicBool>,
    pub(crate) pending_flush: bool,
    pub(crate) pending_error: Option<EmuError>,
    pub(crate) counted: bool,
    pub(crate) until: Option<u64>,
    pub(crate) panic: Option<Box<dyn std::any::Any + Send>>,
}

pub struct Hades {
    emu: Box<Emu>,
}

impl std::ops::Deref for Hades {
    type Target = Emu;
    fn deref(&self) -> &Emu {
        &self.emu
    }
}
impl std::ops::DerefMut for Hades {
    fn deref_mut(&mut self) -> &mut Emu {
        &mut self.emu
    }
}

impl Hades {
    pub fn new() -> Result<Self, EmuError> {
        Ok(Self { emu: Emu::new()? })
    }
}

impl Emu {
    pub(crate) fn st(&self) -> &CpuState {
        unsafe { &*self.state }
    }

    pub(crate) fn st_mut(&mut self) -> &mut CpuState {
        unsafe { &mut *self.state }
    }

    pub fn mem_map(&mut self, addr: u64, size: u64, perms: u8) -> Result<(), EmuError> {
        self.mem.map(addr, size, perms)?;
        self.tlb_flush();
        Ok(())
    }

    pub fn mem_unmap(&mut self, addr: u64, size: u64) -> Result<(), EmuError> {
        self.mem.unmap(addr, size)?;
        self.jit.invalidate_range(addr, addr + size);
        self.tlb_flush();
        Ok(())
    }

    pub fn mem_protect(&mut self, addr: u64, size: u64, perms: u8) -> Result<(), EmuError> {
        self.mem.protect(addr, size, perms)?;
        if perms & PERM_EXEC == 0 {
            self.jit.invalidate_range(addr, addr + size);
        }
        self.tlb_flush();
        Ok(())
    }

    pub fn mem_regions(&self) -> Vec<(u64, u64, u8)> {
        self.mem.regions().collect()
    }

    pub fn mem_read(&self, addr: u64, out: &mut [u8]) -> Result<(), EmuError> {
        self.mem.read(addr, out).map_err(|f| EmuError::Memory {
            access: MemAccess::ReadUnmapped,
            addr: f.addr,
            size: out.len(),
            rip: self.st().rip,
        })
    }

    pub fn mem_read_vec(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmuError> {
        let mut v = vec![0; len];
        self.mem_read(addr, &mut v)?;
        Ok(v)
    }

    pub fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<(), EmuError> {
        self.mem.write(addr, data).map_err(|f| EmuError::Memory {
            access: MemAccess::WriteUnmapped,
            addr: f.addr,
            size: data.len(),
            rip: self.st().rip,
        })?;
        self.jit.invalidate_range(addr, addr + data.len() as u64);
        Ok(())
    }

    pub fn reg_read(&self, r: Reg) -> u64 {
        let st = self.st();
        match r {
            Reg::RIP => st.rip,
            Reg::RFLAGS => st.rflags,
            Reg::FsBase => st.fs_base,
            Reg::GsBase => st.gs_base,
            _ => st.gpr[r as usize],
        }
    }

    pub fn reg_write(&mut self, r: Reg, v: u64) {
        let st = self.st_mut();
        match r {
            Reg::RIP => st.rip = v,
            Reg::RFLAGS => st.rflags = (v & 0x200CD5) | 0x202,
            Reg::FsBase => st.fs_base = v,
            Reg::GsBase => st.gs_base = v,
            _ => st.gpr[r as usize] = v,
        }
    }

    pub fn xmm_read(&self, i: usize) -> u128 {
        let x = &self.st().xsave.0;
        let bv = u64::from_le_bytes(x[512..520].try_into().unwrap());
        if bv & 2 == 0 {
            return 0;
        }
        u128::from_le_bytes(x[160 + i * 16..176 + i * 16].try_into().unwrap())
    }

    pub fn xmm_write(&mut self, i: usize, v: u128) {
        let x = &mut self.st_mut().xsave.0;
        let mut bv = u64::from_le_bytes(x[512..520].try_into().unwrap());
        if bv & 2 == 0 {
            x[160..416].fill(0);
            bv |= 2;
        }
        x[512..520].copy_from_slice(&bv.to_le_bytes());
        x[160 + i * 16..176 + i * 16].copy_from_slice(&v.to_le_bytes());
    }

    pub fn emu_stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        self.region.run_flag().store(0, Ordering::SeqCst);
    }

    pub fn stop_handle(&self) -> StopHandle {
        StopHandle { region: self.region.clone(), requested: self.stop_requested.clone() }
    }

    pub fn flush_cache(&mut self) {
        self.request_flush();
    }

    pub fn cached_blocks(&self) -> usize {
        self.jit.by_rip.len()
    }

    pub(crate) fn fault_access(acc: u64, kind: FaultKind) -> MemAccess {
        match (acc, kind) {
            (state::ACC_R, FaultKind::Unmapped) => MemAccess::ReadUnmapped,
            (state::ACC_R, FaultKind::Protected) => MemAccess::ReadProt,
            (_, FaultKind::Unmapped) => MemAccess::WriteUnmapped,
            (_, FaultKind::Protected) => MemAccess::WriteProt,
        }
    }
}
