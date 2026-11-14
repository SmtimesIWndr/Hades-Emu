use crate::Emu;
use crate::jit::regs::{R15, RSP};
use crate::runtime::state::{EXIT_EXCEPTION, CpuState};
use std::cell::Cell;
use std::sync::Once;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};

thread_local! {
    pub static CURRENT: Cell<*mut Emu> = const { Cell::new(core::ptr::null_mut()) };
}

static INSTALL: Once = Once::new();

pub fn install() {
    INSTALL.call_once(|| unsafe {
        AddVectoredExceptionHandler(1, Some(handler));
    });
}

fn vector_of(code: NTSTATUS) -> Option<u64> {
    Some(match code {
        EXCEPTION_INT_DIVIDE_BY_ZERO | EXCEPTION_INT_OVERFLOW => 0,
        EXCEPTION_SINGLE_STEP => 1,
        EXCEPTION_BREAKPOINT => 3,
        EXCEPTION_ILLEGAL_INSTRUCTION => 6,
        EXCEPTION_PRIV_INSTRUCTION | EXCEPTION_ACCESS_VIOLATION | EXCEPTION_DATATYPE_MISALIGNMENT => 13,
        EXCEPTION_FLT_DENORMAL_OPERAND | EXCEPTION_FLT_DIVIDE_BY_ZERO | EXCEPTION_FLT_INEXACT_RESULT
        | EXCEPTION_FLT_INVALID_OPERATION | EXCEPTION_FLT_OVERFLOW | EXCEPTION_FLT_STACK_CHECK
        | EXCEPTION_FLT_UNDERFLOW => 16,
        STATUS_FLOAT_MULTIPLE_TRAPS | STATUS_FLOAT_MULTIPLE_FAULTS => 19,
        _ => return None,
    })
}

unsafe extern "system" fn handler(ep: *mut EXCEPTION_POINTERS) -> i32 {
    let emu = CURRENT.with(|c| c.get());
    if emu.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    unsafe {
        let emu = &mut *emu;
        let ctx = &mut *(*ep).ContextRecord;
        let rec = &*(*ep).ExceptionRecord;
        let Some(meta) = emu.jit.native_at(ctx.Rip) else { return EXCEPTION_CONTINUE_SEARCH };
        let Some(vector) = vector_of(rec.ExceptionCode) else { return EXCEPTION_CONTINUE_SEARCH };
        let (guest_rip, spilled) = (meta.rip, meta.spilled);
        let st: &mut CpuState = &mut *emu.state;
        let host = [
            ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.R15, ctx.Rbp, ctx.Rsi, ctx.Rdi,
            ctx.R8, ctx.R9, ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14,
        ];
        for (i, &v) in host.iter().enumerate() {
            st.gpr[i] = v;
        }
        let _ = RSP;
        for i in 0..R15 {
            if spilled & (1 << i) != 0 {
                st.gpr[i] = st.spill[i];
            }
        }
        st.rflags = ctx.EFlags as u64;
        st.rip = guest_rip;
        st.exit_reason = EXIT_EXCEPTION;
        st.exit_aux = vector;
        ctx.Rip = emu.jit.g.exit_fault;
        ctx.Rsp = st.host_rsp;
        EXCEPTION_CONTINUE_EXECUTION
    }
}
