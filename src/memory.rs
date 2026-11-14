use std::collections::BTreeMap;
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree};

pub const PAGE: u64 = 0x1000;

pub const PERM_READ: u8 = 1;
pub const PERM_WRITE: u8 = 2;
pub const PERM_EXEC: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    Unmapped,
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub addr: u64,
}

struct HostBuf {
    ptr: *mut u8,
}

impl HostBuf {
    fn new(len: usize) -> Option<Self> {
        let ptr = unsafe { VirtualAlloc(core::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) } as *mut u8;
        if ptr.is_null() { None } else { Some(Self { ptr }) }
    }
}

impl Drop for HostBuf {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.ptr as *mut _, 0, MEM_RELEASE) };
    }
}

pub struct Region {
    pub base: u64,
    pub size: u64,
    host: HostBuf,
    perms: Vec<u8>,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.base + self.size
    }
    pub fn perm_at(&self, addr: u64) -> u8 {
        self.perms[((addr - self.base) / PAGE) as usize]
    }
}

#[derive(Debug)]
pub enum MapError {
    Unaligned,
    Overlap,
    NoMemory,
    NotMapped,
}

pub(crate) struct RegionImage {
    pub(crate) base: u64,
    perms: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

#[derive(Default)]
pub struct Memory {
    regions: BTreeMap<u64, Region>,
}

impl Memory {
    pub fn find(&self, addr: u64) -> Option<&Region> {
        let (_, r) = self.regions.range(..=addr).next_back()?;
        (addr < r.end()).then_some(r)
    }

    pub fn regions(&self) -> impl Iterator<Item = (u64, u64, u8)> + '_ {
        self.regions.values().flat_map(|r| {
            let mut out = Vec::new();
            let mut start = 0usize;
            for i in 1..=r.perms.len() {
                if i == r.perms.len() || r.perms[i] != r.perms[start] {
                    out.push((r.base + start as u64 * PAGE, r.base + i as u64 * PAGE - 1, r.perms[start]));
                    start = i;
                }
            }
            out
        })
    }

    pub(crate) fn capture(&self) -> Vec<RegionImage> {
        self.regions
            .values()
            .map(|r| RegionImage {
                base: r.base,
                perms: r.perms.clone(),
                data: unsafe { core::slice::from_raw_parts(r.host.ptr, r.size as usize) }.to_vec(),
            })
            .collect()
    }

    pub(crate) fn restore(&mut self, images: &[RegionImage]) -> Result<(), MapError> {
        let mut regions = BTreeMap::new();
        for img in images {
            let host = HostBuf::new(img.data.len()).ok_or(MapError::NoMemory)?;
            unsafe { core::ptr::copy_nonoverlapping(img.data.as_ptr(), host.ptr, img.data.len()) };
            let size = img.data.len() as u64;
            regions.insert(img.base, Region { base: img.base, size, host, perms: img.perms.clone() });
        }
        self.regions = regions;
        Ok(())
    }

    pub fn map(&mut self, addr: u64, size: u64, perms: u8) -> Result<(), MapError> {
        if !addr.is_multiple_of(PAGE) || !size.is_multiple_of(PAGE) || size == 0 || addr.checked_add(size).is_none() {
            return Err(MapError::Unaligned);
        }
        let end = addr + size;
        if self.regions.range(..end).next_back().is_some_and(|(_, r)| r.end() > addr) {
            return Err(MapError::Overlap);
        }
        let left = self.regions.range(..addr).next_back().filter(|(_, r)| r.end() == addr).map(|(&b, _)| b);
        let right = self.regions.contains_key(&end).then_some(end);
        let new_base = left.unwrap_or(addr);
        let new_end = right.map(|b| self.regions[&b].end()).unwrap_or(end);
        let buf = HostBuf::new((new_end - new_base) as usize).ok_or(MapError::NoMemory)?;
        let mut perm_vec = vec![0u8; ((new_end - new_base) / PAGE) as usize];
        for b in left.into_iter().chain(right) {
            let r = self.regions.remove(&b).unwrap();
            let off = (r.base - new_base) as usize;
            unsafe { core::ptr::copy_nonoverlapping(r.host.ptr, buf.ptr.add(off), r.size as usize) };
            perm_vec[off / PAGE as usize..off / PAGE as usize + r.perms.len()].copy_from_slice(&r.perms);
        }
        let off = ((addr - new_base) / PAGE) as usize;
        perm_vec[off..off + (size / PAGE) as usize].fill(perms);
        self.regions.insert(new_base, Region { base: new_base, size: new_end - new_base, host: buf, perms: perm_vec });
        Ok(())
    }

    fn require_mapped(&self, addr: u64, size: u64) -> Result<(), MapError> {
        if !addr.is_multiple_of(PAGE) || !size.is_multiple_of(PAGE) || addr.checked_add(size).is_none() {
            return Err(MapError::Unaligned);
        }
        let mut a = addr;
        while a < addr + size {
            let r = self.find(a).ok_or(MapError::NotMapped)?;
            a = r.end();
        }
        Ok(())
    }

    pub fn unmap(&mut self, addr: u64, size: u64) -> Result<(), MapError> {
        self.require_mapped(addr, size)?;
        let end = addr + size;
        let bases: Vec<u64> = self.regions.range(..end).filter(|(_, r)| r.end() > addr).map(|(&b, _)| b).collect();
        for b in bases {
            let r = self.regions.remove(&b).unwrap();
            for (lo, hi) in [(r.base, addr.max(r.base)), (end.min(r.end()), r.end())] {
                if hi <= lo || (lo >= addr && hi <= end) {
                    continue;
                }
                let buf = HostBuf::new((hi - lo) as usize).ok_or(MapError::NoMemory)?;
                let off = (lo - r.base) as usize;
                unsafe { core::ptr::copy_nonoverlapping(r.host.ptr.add(off), buf.ptr, (hi - lo) as usize) };
                let p = r.perms[off / PAGE as usize..(hi - r.base) as usize / PAGE as usize].to_vec();
                self.regions.insert(lo, Region { base: lo, size: hi - lo, host: buf, perms: p });
            }
        }
        Ok(())
    }

    pub fn protect(&mut self, addr: u64, size: u64, perms: u8) -> Result<(), MapError> {
        self.require_mapped(addr, size)?;
        let end = addr + size;
        for r in self.regions.values_mut().filter(|r| r.base < end && r.end() > addr) {
            let lo = (addr.max(r.base) - r.base) / PAGE;
            let hi = (end.min(r.end()) - r.base) / PAGE;
            r.perms[lo as usize..hi as usize].fill(perms);
        }
        Ok(())
    }

    pub fn resolve(&self, addr: u64, size: u64, need: u8) -> Result<*mut u8, Fault> {
        let r = self.find(addr).ok_or(Fault { kind: FaultKind::Unmapped, addr })?;
        let last = addr.checked_add(size.max(1) - 1).ok_or(Fault { kind: FaultKind::Unmapped, addr })?;
        if last >= r.end() {
            return Err(Fault { kind: FaultKind::Unmapped, addr: r.end() });
        }
        let mut p = addr & !(PAGE - 1);
        while p <= last {
            if r.perm_at(p) & need != need {
                return Err(Fault { kind: FaultKind::Protected, addr: p.max(addr) });
            }
            p += PAGE;
        }
        Ok(unsafe { r.host.ptr.add((addr - r.base) as usize) })
    }

    pub fn read(&self, mut addr: u64, out: &mut [u8]) -> Result<(), Fault> {
        let mut done = 0;
        while done < out.len() {
            let r = self.find(addr).ok_or(Fault { kind: FaultKind::Unmapped, addr })?;
            let n = ((r.end() - addr) as usize).min(out.len() - done);
            unsafe { core::ptr::copy_nonoverlapping(r.host.ptr.add((addr - r.base) as usize), out[done..].as_mut_ptr(), n) };
            done += n;
            addr += n as u64;
        }
        Ok(())
    }

    pub fn write(&mut self, mut addr: u64, data: &[u8]) -> Result<(), Fault> {
        let mut done = 0;
        while done < data.len() {
            let r = self.find(addr).ok_or(Fault { kind: FaultKind::Unmapped, addr })?;
            let n = ((r.end() - addr) as usize).min(data.len() - done);
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), r.host.ptr.add((addr - r.base) as usize), n) };
            done += n;
            addr += n as u64;
        }
        Ok(())
    }

    pub fn fetch_window(&self, addr: u64, max: usize) -> Result<&[u8], Fault> {
        let r = self.find(addr).ok_or(Fault { kind: FaultKind::Unmapped, addr })?;
        if r.perm_at(addr) & PERM_EXEC == 0 {
            return Err(Fault { kind: FaultKind::Protected, addr });
        }
        let mut end = (addr & !(PAGE - 1)) + PAGE;
        while end < r.end() && end - addr < max as u64 && r.perm_at(end) & PERM_EXEC != 0 {
            end += PAGE;
        }
        let end = end.min(r.end()).min(addr + max as u64);
        Ok(unsafe { core::slice::from_raw_parts(r.host.ptr.add((addr - r.base) as usize), (end - addr) as usize) })
    }
}
