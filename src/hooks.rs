use crate::emu::Emu;
use crate::error::MemAccess;
use std::sync::atomic::Ordering;

pub const HOOK_MEM_READ: u8 = 1;
pub const HOOK_MEM_WRITE: u8 = 2;

pub type HookId = usize;

pub(crate) type CodeCb = Box<dyn FnMut(&mut Emu, u64, u32)>;
pub(crate) type MemCb = Box<dyn FnMut(&mut Emu, MemAccess, u64, usize, u64)>;
pub(crate) type InvalidCb = Box<dyn FnMut(&mut Emu, MemAccess, u64, usize, u64) -> bool>;
pub(crate) type IntrCb = Box<dyn FnMut(&mut Emu, u32)>;
pub(crate) type SyscallCb = Box<dyn FnMut(&mut Emu)>;

pub(crate) enum HookCb {
    Code(CodeCb),
    Block(CodeCb),
    Mem(u8, MemCb),
    Invalid(InvalidCb),
    Intr(IntrCb),
    Syscall(SyscallCb),
}

pub(crate) struct HookSlot {
    pub(crate) begin: u64,
    pub(crate) end: u64,
    pub(crate) cb: Option<HookCb>,
}

impl HookSlot {
    pub(crate) fn covers(&self, addr: u64) -> bool {
        self.begin > self.end || (self.begin <= addr && addr <= self.end)
    }
}

impl Emu {
    fn add_hook(&mut self, begin: u64, end: u64, cb: HookCb) -> HookId {
        let affects_code = matches!(cb, HookCb::Code(_) | HookCb::Block(_) | HookCb::Mem(..));
        let id = self.hooks.len();
        self.hooks.push(Some(HookSlot { begin, end, cb: Some(cb) }));
        if affects_code {
            self.request_flush();
        }
        id
    }

    pub fn add_code_hook(&mut self, begin: u64, end: u64, cb: impl FnMut(&mut Emu, u64, u32) + 'static) -> HookId {
        self.add_hook(begin, end, HookCb::Code(Box::new(cb)))
    }

    pub fn add_block_hook(&mut self, begin: u64, end: u64, cb: impl FnMut(&mut Emu, u64, u32) + 'static) -> HookId {
        self.add_hook(begin, end, HookCb::Block(Box::new(cb)))
    }

    pub fn add_mem_hook(
        &mut self,
        mask: u8,
        begin: u64,
        end: u64,
        cb: impl FnMut(&mut Emu, MemAccess, u64, usize, u64) + 'static,
    ) -> HookId {
        self.add_hook(begin, end, HookCb::Mem(mask, Box::new(cb)))
    }

    pub fn add_invalid_mem_hook(&mut self, cb: impl FnMut(&mut Emu, MemAccess, u64, usize, u64) -> bool + 'static) -> HookId {
        self.add_hook(1, 0, HookCb::Invalid(Box::new(cb)))
    }

    pub fn add_intr_hook(&mut self, cb: impl FnMut(&mut Emu, u32) + 'static) -> HookId {
        self.add_hook(1, 0, HookCb::Intr(Box::new(cb)))
    }

    pub fn add_syscall_hook(&mut self, cb: impl FnMut(&mut Emu) + 'static) -> HookId {
        self.add_hook(1, 0, HookCb::Syscall(Box::new(cb)))
    }

    pub fn hook_del(&mut self, id: HookId) {
        if let Some(slot) = self.hooks.get_mut(id).and_then(|s| s.take())
            && matches!(slot.cb, Some(HookCb::Code(_) | HookCb::Block(_) | HookCb::Mem(..)) | None)
        {
            self.request_flush();
        }
    }

    pub(crate) fn request_flush(&mut self) {
        if self.running {
            self.pending_flush = true;
            self.region.run_flag().store(0, Ordering::SeqCst);
        } else {
            self.flush_all();
        }
    }

    pub(crate) fn has_hook(&self, f: impl Fn(&HookSlot) -> bool) -> bool {
        self.hooks.iter().flatten().any(f)
    }

    pub(crate) fn each_hook(&mut self, mut select: impl FnMut(&HookSlot) -> bool, mut call: impl FnMut(&mut Emu, &mut HookCb)) {
        for id in 0..self.hooks.len() {
            let Some(slot) = self.hooks[id].as_mut() else { continue };
            if !select(slot) {
                continue;
            }
            let Some(mut cb) = slot.cb.take() else { continue };
            call(self, &mut cb);
            if let Some(slot) = self.hooks.get_mut(id).and_then(|s| s.as_mut()) {
                slot.cb = Some(cb);
            }
        }
    }
}
