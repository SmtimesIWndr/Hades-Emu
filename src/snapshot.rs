use crate::cpu::cpu;
use crate::memory::{PAGE, RegionImage};
use crate::runtime::xstate;
use crate::{Emu, EmuError};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct Context {
    gpr: [u64; 16],
    rip: u64,
    rflags: u64,
    fs_base: u64,
    gs_base: u64,
    seg: [u64; 6],
    xsave: Box<[u8]>,
}

pub struct Snapshot {
    id: u64,
    ctx: Context,
    mem: Vec<RegionImage>,
}

impl Snapshot {
    pub fn context(&self) -> &Context {
        &self.ctx
    }
}

pub(crate) struct Track {
    id: u64,
    layout: u64,
    pub(crate) dirty: HashSet<u64>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl Emu {
    pub fn context_save(&mut self) -> Context {
        let size = cpu().xsave_size;
        let xsave = xstate::sync(self).a[..size].into();
        let st = self.st();
        Context { gpr: st.gpr, rip: st.rip, rflags: st.rflags, fs_base: st.fs_base, gs_base: st.gs_base, seg: st.seg, xsave }
    }

    pub fn context_restore(&mut self, c: &Context) {
        let st = self.st_mut();
        st.gpr = c.gpr;
        st.rip = c.rip;
        st.rflags = c.rflags;
        st.fs_base = c.fs_base;
        st.gs_base = c.gs_base;
        st.seg = c.seg;
        st.ext_light = 0;
        st.xsave.0[..c.xsave.len()].copy_from_slice(&c.xsave);
    }

    pub fn snapshot(&mut self) -> Snapshot {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let ctx = self.context_save();
        let mem = self.mem.capture();
        self.snap = Some(Track { id, layout: self.layout_gen, dirty: HashSet::new() });
        self.tlb_flush();
        Snapshot { id, ctx, mem }
    }

    pub fn snapshot_restore(&mut self, s: &Snapshot) -> Result<(), EmuError> {
        let fast = self.snap.as_ref().is_some_and(|t| t.id == s.id && t.layout == self.layout_gen);
        if fast {
            let dirty = self.snap.as_mut().map(|t| std::mem::take(&mut t.dirty)).unwrap_or_default();
            for page in dirty {
                let img = &s.mem[s.mem.partition_point(|r| r.base <= page) - 1];
                let off = (page - img.base) as usize;
                if let Ok(host) = self.mem.resolve(page, PAGE, 0) {
                    unsafe { core::ptr::copy_nonoverlapping(img.data[off..].as_ptr(), host, PAGE as usize) };
                }
                self.tlb_drop_write(page);
                if self.jit.has_code(page) {
                    self.jit.invalidate_range(page, page + PAGE);
                }
            }
        } else {
            let old: Vec<(u64, u64)> = self.mem.regions().map(|(lo, hi, _)| (lo, hi + 1)).collect();
            self.mem.restore(&s.mem)?;
            for (lo, hi) in old.into_iter().chain(s.mem.iter().map(|r| (r.base, r.base + r.data.len() as u64))) {
                self.jit.invalidate_range(lo, hi);
            }
            self.layout_gen += 1;
            self.tlb_flush();
        }
        self.snap = Some(Track { id: s.id, layout: self.layout_gen, dirty: HashSet::new() });
        self.context_restore(&s.ctx);
        Ok(())
    }
}
