use crate::jit::asm::{AsmError, patch_rel32};
use crate::memory::{Fault, PAGE};
use crate::runtime::state::*;
use iced_x86::Instruction;
use std::collections::{BTreeMap, HashMap};

pub mod asm;
mod classify;
pub mod regs;
mod translate;

pub use classify::{Kind, MemDesc, classify};


const MAX_INSNS: usize = 128;
const ARITH: u32 = 0x3F;

pub struct ChainSite {
    pub patch: u64,
    pub stub: u64,
    pub target: u64,
    pub linked: Option<u32>,
}

pub struct NativeMeta {
    pub lo: u64,
    pub hi: u64,
    pub rip: u64,
    pub spilled: u16,
}

pub struct Block {
    pub start: u64,
    pub end: u64,
    pub host: u64,
    pub host_end: u64,
    pub sites: Vec<ChainSite>,
    pub incoming: Vec<(u32, u32)>,
    pub meta: Vec<NativeMeta>,
    pub insn_starts: Vec<(u64, u64)>,
    pub valid: bool,
}

#[derive(Default, Clone, Copy)]
pub struct Globals {
    pub entry: u64,
    pub exit_sync: u64,
    pub exit_common: u64,
    pub exit_fault: u64,
    pub tramp: u64,
    pub indirect: u64,
    pub ind_clean: u64,
}

pub enum TxError {
    Fetch(Fault),
    Asm(AsmError),
}

impl From<AsmError> for TxError {
    fn from(e: AsmError) -> Self {
        TxError::Asm(e)
    }
}

pub struct TxCfg<'a> {
    pub counted: bool,
    pub single: bool,
    pub until: Option<u64>,
    pub code_hook: &'a dyn Fn(u64) -> bool,
    pub block_hook: &'a dyn Fn(u64) -> bool,
    pub mem_read_hooks: bool,
    pub mem_write_hooks: bool,
}

pub struct Jit {
    pub state: u64,
    pub tlb: u64,
    pub jc: u64,
    pub g: Globals,
    pub code_start: u64,
    pub code_pos: u64,
    pub code_end: u64,
    pub blocks: Vec<Block>,
    pub by_rip: HashMap<u64, u32>,
    pub single_rip: HashMap<u64, u32>,
    pub by_host: BTreeMap<u64, u32>,
    pub pages: HashMap<u64, Vec<u32>>,
    pub interp: Vec<Instruction>,
}

impl Jit {
    pub fn new(state: u64, tlb: u64, jc: u64, code_start: u64, code_end: u64) -> Self {
        Self {
            state,
            tlb,
            jc,
            g: Globals::default(),
            code_start,
            code_pos: code_start,
            code_end,
            blocks: Vec::new(),
            by_rip: HashMap::new(),
            single_rip: HashMap::new(),
            by_host: BTreeMap::new(),
            pages: HashMap::new(),
            interp: Vec::new(),
        }
    }

    pub fn needs_flush(&self) -> bool {
        self.code_end - self.code_pos < (1 << 20)
    }

    pub fn flush(&mut self) {
        self.blocks.clear();
        self.by_rip.clear();
        self.single_rip.clear();
        self.by_host.clear();
        self.pages.clear();
        self.interp.clear();
        self.code_pos = self.code_start;
        self.jc_clear();
    }

    pub fn jc_clear(&mut self) {
        let jc = self.jc as *mut u64;
        for i in 0..JC_ENTRIES {
            unsafe {
                *jc.add(i * 2) = u64::MAX;
                *jc.add(i * 2 + 1) = self.g.ind_clean;
            }
        }
    }

    fn jc_entry(&self, pc: u64) -> *mut u64 {
        unsafe { (self.jc as *mut u64).add(((pc as usize) & (JC_ENTRIES - 1)) * 2) }
    }

    pub fn jc_set(&mut self, pc: u64, host: u64) {
        let e = self.jc_entry(pc);
        unsafe {
            *e = pc;
            *e.add(1) = host;
        }
    }

    fn jc_remove(&mut self, pc: u64) {
        let e = self.jc_entry(pc);
        unsafe {
            if *e == pc {
                *e = u64::MAX;
                *e.add(1) = self.g.ind_clean;
            }
        }
    }

    pub fn block(&self, id: u32) -> Option<&Block> {
        self.blocks.get(id as usize).filter(|b| b.valid)
    }

    fn block_mut(&mut self, id: u32) -> Option<&mut Block> {
        self.blocks.get_mut(id as usize).filter(|b| b.valid)
    }

    pub fn has_code(&self, page: u64) -> bool {
        self.pages.get(&page).is_some_and(|v| !v.is_empty())
    }

    pub fn link(&mut self, src: u32, site: u32, dst: u32) {
        let Some(host) = self.block(dst).map(|b| b.host) else { return };
        let Some(sb) = self.block_mut(src) else { return };
        let Some(s) = sb.sites.get_mut(site as usize) else { return };
        if s.linked.is_some() {
            return;
        }
        patch_rel32(s.patch, host);
        s.linked = Some(dst);
        self.blocks[dst as usize].incoming.push((src, site));
    }

    pub fn invalidate(&mut self, id: u32) {
        let Some(b) = self.block_mut(id) else { return };
        b.valid = false;
        let incoming = std::mem::take(&mut b.incoming);
        let outgoing: Vec<(usize, u32)> =
            b.sites.iter_mut().enumerate().filter_map(|(i, s)| s.linked.take().map(|t| (i, t))).collect();
        let (start, end) = (b.start, b.end);
        for (src, idx) in incoming {
            if let Some(sb) = self.block_mut(src) {
                let s = &mut sb.sites[idx as usize];
                if s.linked == Some(id) {
                    patch_rel32(s.patch, s.stub);
                    s.linked = None;
                }
            }
        }
        for (idx, t) in outgoing {
            if let Some(tb) = self.block_mut(t) {
                tb.incoming.retain(|&(x, y)| !(x == id && y == idx as u32));
            }
        }
        if self.by_rip.get(&start) == Some(&id) {
            self.by_rip.remove(&start);
        }
        if self.single_rip.get(&start) == Some(&id) {
            self.single_rip.remove(&start);
        }
        let mut p = start & !(PAGE - 1);
        while p < end.max(start + 1) {
            if let Some(v) = self.pages.get_mut(&p) {
                v.retain(|&x| x != id);
            }
            p += PAGE;
        }
        self.jc_remove(start);
    }

    pub fn invalidate_range(&mut self, lo: u64, hi: u64) -> Vec<u32> {
        let mut out = Vec::new();
        let mut p = lo & !(PAGE - 1);
        while p < hi {
            if let Some(list) = self.pages.get(&p).cloned() {
                for id in list {
                    if let Some(b) = self.block(id)
                        && b.start < hi
                        && b.end.max(b.start + 1) > lo
                    {
                        self.invalidate(id);
                        out.push(id);
                    }
                }
            }
            p = match p.checked_add(PAGE) {
                Some(n) => n,
                None => break,
            };
        }
        out
    }

    pub fn native_at(&self, pc: u64) -> Option<&NativeMeta> {
        let (_, &id) = self.by_host.range(..=pc).next_back()?;
        let b = self.blocks.get(id as usize)?;
        if pc >= b.host_end {
            return None;
        }
        b.meta.iter().find(|m| pc >= m.lo && pc < m.hi)
    }
}
