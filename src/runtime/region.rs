use crate::runtime::state::{CpuState, JC_ENTRIES, JC_ENTRY_SIZE, TLB_ENTRIES, TLB_ENTRY_SIZE};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
};

pub const REGION_SIZE: usize = 128 << 20;

pub struct CodeRegion {
    pub base: *mut u8,
    pub size: usize,
}

unsafe impl Send for CodeRegion {}
unsafe impl Sync for CodeRegion {}

const fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

pub const TLB_OFF: usize = align_up(core::mem::size_of::<CpuState>(), 4096);
pub const JC_OFF: usize = TLB_OFF + TLB_ENTRIES * TLB_ENTRY_SIZE;
pub const CODE_OFF: usize = align_up(JC_OFF + JC_ENTRIES * JC_ENTRY_SIZE, 4096);

impl CodeRegion {
    pub fn new() -> Option<Self> {
        let base = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                REGION_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut u8;
        if base.is_null() {
            return None;
        }
        Some(Self { base, size: REGION_SIZE })
    }

    pub fn addr(&self, off: usize) -> u64 {
        self.base as u64 + off as u64
    }

    pub fn state(&self) -> *mut CpuState {
        self.base as *mut CpuState
    }

    pub fn run_flag(&self) -> &core::sync::atomic::AtomicU64 {
        unsafe {
            core::sync::atomic::AtomicU64::from_ptr(core::ptr::addr_of_mut!((*self.state()).run_flag))
        }
    }
}

impl Drop for CodeRegion {
    fn drop(&mut self) {
        unsafe {
            VirtualFree(self.base as *mut _, 0, MEM_RELEASE);
        }
    }
}
