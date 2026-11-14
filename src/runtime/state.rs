use core::mem::offset_of;

pub const XSAVE_AREA: usize = 16384;
pub const XSAVE_MASK: u32 = 0xE7;

pub const TLB_BITS: u32 = 12;
pub const TLB_ENTRIES: usize = 1 << TLB_BITS;
pub const TLB_ENTRY_SIZE: usize = 32;
pub const TLB_TAG_R: i64 = 0;
pub const TLB_TAG_W: i64 = 8;
pub const TLB_TAG_RW: i64 = 16;
pub const TLB_HOST: i64 = 24;

pub const JC_BITS: u32 = 16;
pub const JC_ENTRIES: usize = 1 << JC_BITS;
pub const JC_ENTRY_SIZE: usize = 16;

pub const EXIT_CHAIN: u64 = 1;
pub const EXIT_INDIRECT: u64 = 2;
pub const EXIT_STOP: u64 = 3;
pub const EXIT_UNTIL: u64 = 4;
pub const EXIT_HELPER: u64 = 5;
pub const EXIT_EXCEPTION: u64 = 6;
pub const EXIT_INTERRUPT: u64 = 7;
pub const EXIT_SYSCALL: u64 = 8;
pub const EXIT_UNSUPPORTED: u64 = 9;
pub const EXIT_COUNT: u64 = 10;
pub const EXIT_REDIRECT: u64 = 11;
pub const EXIT_TRAP_PENDING: u64 = 12;

pub const KIND_MEM: u64 = 1;
pub const KIND_CODE: u64 = 2;
pub const KIND_BLOCK: u64 = 3;
pub const KIND_MEMR: u64 = 4;
pub const KIND_MEMW: u64 = 5;
pub const KIND_INTERP: u64 = 6;

pub const SEG_ES: usize = 0;
pub const SEG_CS: usize = 1;
pub const SEG_SS: usize = 2;
pub const SEG_DS: usize = 3;
pub const SEG_FS: usize = 4;
pub const SEG_GS: usize = 5;

pub const ACC_R: u64 = 1;
pub const ACC_W: u64 = 2;
pub const ACC_RW: u64 = 3;

#[repr(C, align(64))]
pub struct XsaveArea(pub [u8; XSAVE_AREA]);

#[repr(C, align(64))]
pub struct CpuState {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub spill: [u64; 16],
    pub flagsave: u64,
    pub host_rsp: u64,
    pub jump_slot: u64,
    pub run_flag: u64,
    pub icount_left: u64,
    pub exit_reason: u64,
    pub exit_aux: u64,
    pub chain_site: u64,
    pub arg_kind: u64,
    pub arg_ea: u64,
    pub arg_block: u64,
    pub arg_ret: u64,
    pub last_ea: u64,
    pub tlb_ptr: u64,
    pub jc_ptr: u64,
    pub emu: u64,
    pub dispatch_fn: u64,
    pub host_mxcsr: u64,
    pub ind_target: u64,
    pub host_fcw: u64,
    pub ext_light: u64,
    pub seg: [u64; 6],
    pub xsave: XsaveArea,
}

pub const OFF_GPR: usize = offset_of!(CpuState, gpr);
pub const OFF_RIP: usize = offset_of!(CpuState, rip);
pub const OFF_RFLAGS: usize = offset_of!(CpuState, rflags);
pub const OFF_FS: usize = offset_of!(CpuState, fs_base);
pub const OFF_GS: usize = offset_of!(CpuState, gs_base);
pub const OFF_SPILL: usize = offset_of!(CpuState, spill);
pub const OFF_FLAGSAVE: usize = offset_of!(CpuState, flagsave);
pub const OFF_HOST_RSP: usize = offset_of!(CpuState, host_rsp);
pub const OFF_JUMP_SLOT: usize = offset_of!(CpuState, jump_slot);
pub const OFF_RUN_FLAG: usize = offset_of!(CpuState, run_flag);
pub const OFF_ICOUNT: usize = offset_of!(CpuState, icount_left);
pub const OFF_EXIT_REASON: usize = offset_of!(CpuState, exit_reason);
pub const OFF_EXIT_AUX: usize = offset_of!(CpuState, exit_aux);
pub const OFF_CHAIN_SITE: usize = offset_of!(CpuState, chain_site);
pub const OFF_ARG_KIND: usize = offset_of!(CpuState, arg_kind);
pub const OFF_ARG_EA: usize = offset_of!(CpuState, arg_ea);
pub const OFF_ARG_BLOCK: usize = offset_of!(CpuState, arg_block);
pub const OFF_ARG_RET: usize = offset_of!(CpuState, arg_ret);
pub const OFF_LAST_EA: usize = offset_of!(CpuState, last_ea);
pub const OFF_TLB_PTR: usize = offset_of!(CpuState, tlb_ptr);
pub const OFF_JC_PTR: usize = offset_of!(CpuState, jc_ptr);
pub const OFF_IND_TARGET: usize = offset_of!(CpuState, ind_target);
pub const OFF_DISPATCH: usize = offset_of!(CpuState, dispatch_fn);
pub const OFF_HOST_MXCSR: usize = offset_of!(CpuState, host_mxcsr);
pub const OFF_HOST_FCW: usize = offset_of!(CpuState, host_fcw);
pub const OFF_EXT_LIGHT: usize = offset_of!(CpuState, ext_light);
pub const OFF_XSAVE: usize = offset_of!(CpuState, xsave);

pub const TMP_SLOT: usize = 4;

pub const fn gpr_off(i: usize) -> usize {
    OFF_GPR + i * 8
}
pub const fn spill_off(i: usize) -> usize {
    OFF_SPILL + i * 8
}

pub fn tlb_invalid_tag(i: usize) -> u64 {
    (((i + 1) & (TLB_ENTRIES - 1)) as u64) << 12
}
