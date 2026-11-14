#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("hades-emu requires a Windows x86-64 host");

mod cpu;
mod emu;
mod error;
mod hooks;
mod jit;
mod memory;
mod runtime;

pub use emu::*;
pub use error::{EmuError, MemAccess};
pub use hooks::{HOOK_MEM_READ, HOOK_MEM_WRITE, HookId};
pub use memory::{PERM_EXEC, PERM_READ, PERM_WRITE};
