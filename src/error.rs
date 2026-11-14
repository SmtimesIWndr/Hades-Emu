use crate::memory::MapError;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemAccess {
    Read,
    Write,
    Fetch,
    ReadUnmapped,
    WriteUnmapped,
    FetchUnmapped,
    ReadProt,
    WriteProt,
    FetchProt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmuError {
    Memory { access: MemAccess, addr: u64, size: usize, rip: u64 },
    Exception { vector: u32, rip: u64 },
    Interrupt { intno: u32, rip: u64 },
    Syscall { rip: u64 },
    Unsupported { rip: u64, text: String },
    Translate { rip: u64, msg: String },
    Map(String),
    Busy,
    Init(String),
}

impl fmt::Display for EmuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmuError::Memory { access, addr, size, rip } => {
                write!(f, "memory fault {access:?} at {addr:#x} (size {size}) rip={rip:#x}")
            }
            EmuError::Exception { vector, rip } => write!(f, "cpu exception {vector} at {rip:#x}"),
            EmuError::Interrupt { intno, rip } => write!(f, "unhandled interrupt {intno} (next rip {rip:#x})"),
            EmuError::Syscall { rip } => write!(f, "unhandled syscall (next rip {rip:#x})"),
            EmuError::Unsupported { rip, text } => write!(f, "unsupported instruction {text} at {rip:#x}"),
            EmuError::Translate { rip, msg } => write!(f, "translation failed at {rip:#x}: {msg}"),
            EmuError::Map(m) => write!(f, "mapping error: {m}"),
            EmuError::Busy => write!(f, "emulator is already running"),
            EmuError::Init(m) => write!(f, "initialization failed: {m}"),
        }
    }
}

impl std::error::Error for EmuError {}

impl From<MapError> for EmuError {
    fn from(e: MapError) -> Self {
        EmuError::Map(format!("{e:?}"))
    }
}
