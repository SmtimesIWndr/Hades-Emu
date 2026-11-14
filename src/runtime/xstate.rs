use crate::Emu;
use crate::cpu::cpu;

pub const LEGACY_XMM: usize = 160;
pub const LEGACY_ST: usize = 32;
pub const MXCSR: usize = 24;
pub const HEADER: usize = 512;
pub const MANAGED: u64 = 0xE7;

pub struct XState<'a> {
    pub a: &'a mut [u8],
}

pub fn sync(emu: &mut Emu) -> XState<'_> {
    let st = emu.st_mut();
    if st.ext_light != 0 {
        unsafe {
            core::arch::asm!(
                "xsave64 [{0}]",
                in(reg) st.xsave.0.as_mut_ptr(),
                in("eax") 1u32,
                in("edx") 0u32,
                options(nostack),
            );
        }
        st.ext_light = 0;
    }
    XState { a: &mut st.xsave.0 }
}

impl XState<'_> {
    pub fn bv(&self) -> u64 {
        u64::from_le_bytes(self.a[HEADER..HEADER + 8].try_into().unwrap())
    }

    pub fn set_bv(&mut self, v: u64) {
        self.a[HEADER..HEADER + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn comp_range(i: usize) -> Option<(usize, usize)> {
        if cpu().xcr0 >> i & 1 == 0 {
            return None;
        }
        let c = cpu().xcomp[i];
        Some((c.offset as usize, c.size as usize))
    }

    fn ensure(&mut self, i: usize) {
        if self.bv() >> i & 1 != 0 {
            return;
        }
        match i {
            0 => {
                self.a[0..24].fill(0);
                self.a[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
                self.a[LEGACY_ST..LEGACY_XMM].fill(0);
            }
            1 => self.a[LEGACY_XMM..LEGACY_XMM + 256].fill(0),
            _ => {
                if let Some((o, s)) = Self::comp_range(i) {
                    self.a[o..o + s].fill(0);
                }
            }
        }
        let bv = self.bv() | 1 << i;
        self.set_bv(bv);
    }

    fn get(&self, comp: usize, off: usize, out: &mut [u8]) {
        if self.bv() >> comp & 1 == 0 {
            out.fill(0);
            return;
        }
        out.copy_from_slice(&self.a[off..off + out.len()]);
    }

    pub fn vec_read(&self, r: usize) -> [u8; 64] {
        let mut v = [0u8; 64];
        if r < 16 {
            self.get(1, LEGACY_XMM + 16 * r, &mut v[0..16]);
            if let Some((o, _)) = Self::comp_range(2) {
                self.get(2, o + 16 * r, &mut v[16..32]);
            }
            if let Some((o, _)) = Self::comp_range(6) {
                self.get(6, o + 32 * r, &mut v[32..64]);
            }
        } else if let Some((o, _)) = Self::comp_range(7) {
            self.get(7, o + 64 * (r - 16), &mut v);
        }
        v
    }

    pub fn vec_write(&mut self, r: usize, v: &[u8; 64]) {
        if r < 16 {
            self.ensure(1);
            self.a[LEGACY_XMM + 16 * r..LEGACY_XMM + 16 * r + 16].copy_from_slice(&v[0..16]);
            if let Some((o, _)) = Self::comp_range(2) {
                self.ensure(2);
                self.a[o + 16 * r..o + 16 * r + 16].copy_from_slice(&v[16..32]);
            }
            if let Some((o, _)) = Self::comp_range(6) {
                self.ensure(6);
                self.a[o + 32 * r..o + 32 * r + 32].copy_from_slice(&v[32..64]);
            }
        } else if let Some((o, _)) = Self::comp_range(7) {
            self.ensure(7);
            self.a[o + 64 * (r - 16)..o + 64 * (r - 16) + 64].copy_from_slice(v);
        }
    }

    pub fn k_read(&self, k: usize) -> u64 {
        let Some((o, _)) = Self::comp_range(5) else { return 0 };
        let mut b = [0u8; 8];
        self.get(5, o + 8 * k, &mut b);
        u64::from_le_bytes(b)
    }

    pub fn k_write(&mut self, k: usize, v: u64) {
        let Some((o, _)) = Self::comp_range(5) else { return };
        self.ensure(5);
        self.a[o + 8 * k..o + 8 * k + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn top(&self) -> usize {
        if self.bv() & 1 == 0 {
            return 0;
        }
        (u16::from_le_bytes([self.a[2], self.a[3]]) >> 11 & 7) as usize
    }

    pub fn mm_read(&self, i: usize) -> u64 {
        let slot = (i + 8 - self.top()) & 7;
        let mut b = [0u8; 8];
        self.get(0, LEGACY_ST + 16 * slot, &mut b);
        u64::from_le_bytes(b)
    }

    pub fn mmx_enter(&mut self) {
        self.ensure(0);
        let top = self.top();
        if top != 0 {
            let mut st = [0u8; 128];
            st.copy_from_slice(&self.a[LEGACY_ST..LEGACY_XMM]);
            for k in 0..8 {
                let from = (k + 8 - top) & 7;
                self.a[LEGACY_ST + 16 * k..LEGACY_ST + 16 * k + 16].copy_from_slice(&st[16 * from..16 * from + 16]);
            }
        }
        let fsw = u16::from_le_bytes([self.a[2], self.a[3]]) & !0x3800;
        self.a[2..4].copy_from_slice(&fsw.to_le_bytes());
        self.a[4] = 0xFF;
    }
}
