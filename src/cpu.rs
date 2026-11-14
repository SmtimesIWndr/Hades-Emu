use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};
use std::sync::LazyLock;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Intel,
    Amd,
    Other,
}

#[derive(Clone, Copy, Default)]
pub struct XComponent {
    pub size: u32,
    pub offset: u32,
    pub align64: bool,
}

pub struct Cpu {
    pub vendor: Vendor,
    pub xcr0: u64,
    pub rtm: bool,
    pub ospke: bool,
    pub amx_tile: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub avx512vl: bool,
    pub avx512pf: bool,
    pub movdir64b: bool,
    pub enqcmd: bool,
    pub waitpkg: bool,
    pub monitorx: bool,
    pub clzero: bool,
    pub xsaveopt: bool,
    pub xsavec: bool,
    pub null_sel_clears_base: bool,
    pub cache_line: u64,
    pub rdrand: bool,
    pub rdseed: bool,
    pub rdtscp: bool,
    pub xsave_size: usize,
    pub mxcsr_mask: u32,
    pub xcomp: [XComponent; 64],
}

#[repr(C, align(16))]
struct Fx([u8; 512]);

fn mxcsr_mask() -> u32 {
    let mut fx = Fx([0; 512]);
    unsafe { core::arch::asm!("fxsave64 [{0}]", in(reg) fx.0.as_mut_ptr(), options(nostack)) };
    match u32::from_le_bytes(fx.0[28..32].try_into().unwrap()) {
        0 => 0xFFBF,
        m => m,
    }
}

fn bit(v: u32, b: u32) -> bool {
    v >> b & 1 != 0
}

impl Cpu {
    fn detect() -> Cpu {
        let v0 = __cpuid(0);
        let vendor = match (v0.ebx, v0.edx, v0.ecx) {
            (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => Vendor::Intel,
            (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Vendor::Amd,
            _ => Vendor::Other,
        };
        let max = v0.eax;
        let l1 = __cpuid(1);
        let l7 = if max >= 7 { __cpuid_count(7, 0) } else { __cpuid_count(0, 0) };
        let has7 = max >= 7;
        let ext_max = __cpuid(0x8000_0000).eax;
        let (e1, e1d) = if ext_max >= 0x8000_0001 { (__cpuid(0x8000_0001).ecx, __cpuid(0x8000_0001).edx) } else { (0, 0) };
        let e8 = if ext_max >= 0x8000_0008 { __cpuid(0x8000_0008).ebx } else { 0 };
        let e21 = if ext_max >= 0x8000_0021 { __cpuid(0x8000_0021).eax } else { 0 };
        let osxsave = bit(l1.ecx, 27);
        let xcr0 = if osxsave { unsafe { _xgetbv(0) } } else { 0 };
        let d1 = if max >= 0xD { __cpuid_count(0xD, 1).eax } else { 0 };
        let mut xcomp = [XComponent::default(); 64];
        if max >= 0xD {
            for (i, c) in xcomp.iter_mut().enumerate().skip(2) {
                if xcr0 >> i & 1 != 0 {
                    let r = __cpuid_count(0xD, i as u32);
                    *c = XComponent { size: r.eax, offset: r.ebx, align64: bit(r.ecx, 1) };
                }
            }
        }
        Cpu {
            vendor,
            xcr0,
            rtm: has7 && bit(l7.ebx, 11),
            ospke: has7 && bit(l7.ecx, 4),
            amx_tile: has7 && bit(l7.edx, 24),
            avx2: has7 && bit(l7.ebx, 5) && xcr0 & 6 == 6,
            avx512f: has7 && bit(l7.ebx, 16) && xcr0 & 0xE6 == 0xE6,
            avx512vl: has7 && bit(l7.ebx, 31) && xcr0 & 0xE6 == 0xE6,
            avx512pf: has7 && bit(l7.ebx, 26) && xcr0 & 0xE6 == 0xE6,
            movdir64b: has7 && bit(l7.ecx, 28),
            enqcmd: has7 && bit(l7.ecx, 29),
            waitpkg: has7 && bit(l7.ecx, 5),
            monitorx: bit(e1, 29),
            clzero: bit(e8, 0),
            xsaveopt: bit(d1, 0),
            xsavec: bit(d1, 1),
            null_sel_clears_base: vendor == Vendor::Amd && bit(e21, 6),
            cache_line: (((l1.ebx >> 8) & 0xff) as u64 * 8).max(64),
            mxcsr_mask: mxcsr_mask(),
            rdrand: bit(l1.ecx, 30),
            rdseed: has7 && bit(l7.ebx, 18),
            rdtscp: bit(e1d, 27),
            xsave_size: if max >= 0xD { __cpuid_count(0xD, 0).ebx as usize } else { 576 },
            xcomp,
        }
    }
}

static CPU: LazyLock<Cpu> = LazyLock::new(Cpu::detect);

pub fn cpu() -> &'static Cpu {
    &CPU
}
