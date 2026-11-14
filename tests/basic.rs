use hades_emu::*;
use iced_x86::code_asm::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

const CODE: u64 = 0x140000000;
const DATA: u64 = 0x10000000;
const STACK: u64 = 0x7ff00000;
const STACK_SIZE: u64 = 0x100000;

fn assemble(f: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    f(&mut a).unwrap();
    a.nop().unwrap();
    a.assemble(CODE).unwrap()
}

fn find(code: &[u8], m: iced_x86::Mnemonic, n: usize) -> u64 {
    iced_x86::Decoder::with_ip(64, code, CODE, 0).into_iter().filter(|i| i.mnemonic() == m).nth(n).unwrap().ip()
}

fn setup(code: &[u8]) -> Hades {
    let mut h = Hades::new().unwrap();
    h.mem_map(CODE, 0x10000, PERM_ALL).unwrap();
    h.mem_map(DATA, 0x10000, PERM_READ | PERM_WRITE).unwrap();
    h.mem_map(STACK, STACK_SIZE, PERM_READ | PERM_WRITE).unwrap();
    h.mem_write(CODE, code).unwrap();
    h.reg_write(Reg::RSP, STACK + STACK_SIZE - 0x1000);
    h
}

fn run(code: &[u8]) -> Hades {
    let mut h = setup(code);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    h
}

#[test]
fn alu_and_loop() {
    let code = assemble(|a| {
        let mut l = a.create_label();
        a.mov(rcx, 1000u64)?;
        a.xor(eax, eax)?;
        a.set_label(&mut l)?;
        a.add(rax, rcx)?;
        a.dec(rcx)?;
        a.jnz(l)?;
        a.imul_3(rbx, rax, 3)?;
        Ok(())
    });
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RAX), 500500);
    assert_eq!(h.reg_read(Reg::RBX), 1501500);
    assert_eq!(h.reg_read(Reg::RCX), 0);
    assert_eq!(h.reg_read(Reg::RIP), CODE + code.len() as u64);
}

#[test]
fn memory_and_rip_relative() {
    let code = assemble(|a| {
        let mut slot = a.create_label();
        let mut end = a.create_label();
        a.mov(rbx, DATA)?;
        a.mov(rax, 0x1122334455667788u64)?;
        a.mov(qword_ptr(rbx + 8), rax)?;
        a.mov(ecx, dword_ptr(rbx + 12))?;
        a.mov(qword_ptr(slot), rax)?;
        a.mov(rdx, qword_ptr(slot))?;
        a.add(qword_ptr(rbx + 8), 1)?;
        a.mov(rsi, qword_ptr(rbx + 8))?;
        a.jmp(end)?;
        a.set_label(&mut slot)?;
        a.dq(&[0])?;
        a.set_label(&mut end)?;
        Ok(())
    });
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RCX), 0x11223344);
    assert_eq!(h.reg_read(Reg::RDX), 0x1122334455667788);
    assert_eq!(h.reg_read(Reg::RSI), 0x1122334455667789);
}

#[test]
fn flags_live_across_memory_access() {
    let code = assemble(|a| {
        let mut below = a.create_label();
        let mut done = a.create_label();
        a.mov(rbx, DATA)?;
        a.mov(qword_ptr(rbx), 77)?;
        a.mov(eax, 1)?;
        a.cmp(eax, 2)?;
        a.mov(rcx, qword_ptr(rbx))?;
        a.mov(qword_ptr(rbx + 16), rcx)?;
        a.jb(below)?;
        a.mov(edx, 0xbad)?;
        a.jmp(done)?;
        a.set_label(&mut below)?;
        a.mov(edx, 0x600d)?;
        a.set_label(&mut done)?;
        Ok(())
    });
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RDX), 0x600d);
    assert_eq!(h.reg_read(Reg::RCX), 77);
}

#[test]
fn recursion_call_ret() {
    let code = assemble(|a| {
        let mut fib = a.create_label();
        let mut base = a.create_label();
        let mut end = a.create_label();
        a.mov(ecx, 20)?;
        a.call(fib)?;
        a.jmp(end)?;
        a.set_label(&mut fib)?;
        a.cmp(rcx, 2)?;
        a.jb(base)?;
        a.push(rcx)?;
        a.dec(rcx)?;
        a.call(fib)?;
        a.pop(rcx)?;
        a.push(rax)?;
        a.sub(rcx, 2)?;
        a.call(fib)?;
        a.pop(rdx)?;
        a.add(rax, rdx)?;
        a.ret()?;
        a.set_label(&mut base)?;
        a.mov(rax, rcx)?;
        a.ret()?;
        a.set_label(&mut end)?;
        Ok(())
    });
    let mut h = setup(&code);
    let sp0 = h.reg_read(Reg::RSP);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 6765);
    assert_eq!(h.reg_read(Reg::RSP), sp0);
}

#[test]
fn rsp_and_r15_remapping() {
    let code = assemble(|a| {
        a.mov(r15, rsp)?;
        a.sub(rsp, 0x40)?;
        a.mov(qword_ptr(rsp + 8), r15)?;
        a.mov(r14, qword_ptr(rsp + 8))?;
        a.lea(r13, qword_ptr(rsp + r15 * 2 + 8))?;
        a.mov(qword_ptr(r15 - 8), 5)?;
        a.add(r15, qword_ptr(r15 - 8))?;
        a.push(r15)?;
        a.pop(r12)?;
        a.mov(r11d, esp)?;
        a.add(rsp, 0x40)?;
        a.xchg(r15, rsp)?;
        a.xchg(r15, rsp)?;
        Ok(())
    });
    let mut h = setup(&code);
    let sp0 = h.reg_read(Reg::RSP);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::R14), sp0);
    assert_eq!(h.reg_read(Reg::R13), (sp0 - 0x40).wrapping_add(sp0 * 2 + 8));
    assert_eq!(h.reg_read(Reg::R15), sp0 + 5);
    assert_eq!(h.reg_read(Reg::R12), sp0 + 5);
    assert_eq!(h.reg_read(Reg::R11), (sp0 - 0x40) & 0xffff_ffff);
    assert_eq!(h.reg_read(Reg::RSP), sp0);
}

#[test]
fn high_byte_registers_with_memory() {
    let code = assemble(|a| {
        a.mov(rsi, DATA)?;
        a.mov(byte_ptr(rsi + 3), 0x5a)?;
        a.mov(eax, 0x11223344)?;
        a.mov(ah, byte_ptr(rsi + 3))?;
        a.mov(byte_ptr(rsi + 4), bh)?;
        Ok(())
    });
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RAX), 0x11225a44);
}

#[test]
fn pushfq_popfq_and_cmov() {
    let code = assemble(|a| {
        a.stc()?;
        a.pushfq()?;
        a.clc()?;
        a.popfq()?;
        a.mov(eax, 0)?;
        a.adc(eax, 0)?;
        a.mov(r15, 9u64)?;
        a.mov(ecx, 1)?;
        a.test(ecx, ecx)?;
        a.cmovnz(r15, rcx)?;
        Ok(())
    });
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RAX), 1);
    assert_eq!(h.reg_read(Reg::R15), 1);
}

#[test]
fn string_ops() {
    let code = assemble(|a| {
        a.mov(rdi, DATA)?;
        a.mov(rax, 0x4141414141414141u64)?;
        a.mov(ecx, 4)?;
        a.rep().stosq()?;
        a.mov(byte_ptr(rdi), 0)?;
        a.mov(rsi, DATA)?;
        a.mov(rdi, DATA + 0x100)?;
        a.mov(ecx, 33)?;
        a.rep().movsb()?;
        a.mov(rdi, DATA + 0x100)?;
        a.mov(rcx, -1i64)?;
        a.xor(eax, eax)?;
        a.repne().scasb()?;
        a.not(rcx)?;
        a.dec(rcx)?;
        Ok(())
    });
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RCX), 32);
    assert_eq!(h.mem_read_vec(DATA + 0x100, 33).unwrap(), [vec![0x41; 32], vec![0]].concat());
}

#[test]
fn segment_bases() {
    let code = assemble(|a| {
        a.mov(rax, qword_ptr(0x30).gs())?;
        a.mov(rcx, 0x60u64)?;
        a.mov(rdx, qword_ptr(rcx).gs())?;
        a.rdgsbase(rbx)?;
        Ok(())
    });
    let mut h = setup(&code);
    h.reg_write(Reg::GsBase, DATA);
    h.mem_write(DATA + 0x30, &0xdeadbeefu64.to_le_bytes()).unwrap();
    h.mem_write(DATA + 0x60, &0xcafeu64.to_le_bytes()).unwrap();
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 0xdeadbeef);
    assert_eq!(h.reg_read(Reg::RDX), 0xcafe);
    assert_eq!(h.reg_read(Reg::RBX), DATA);
}

#[test]
fn syscall_and_code_hooks() {
    let code = assemble(|a| {
        a.mov(eax, 0x55)?;
        a.syscall()?;
        a.add(rax, 1)?;
        Ok(())
    });
    let mut h = setup(&code);
    let count = Rc::new(RefCell::new(Vec::new()));
    let c2 = count.clone();
    h.add_code_hook(1, 0, move |_, addr, size| c2.borrow_mut().push((addr, size)));
    h.add_syscall_hook(|emu| {
        assert_eq!(emu.reg_read(Reg::RAX), 0x55);
        emu.reg_write(Reg::RAX, 0x1000);
    });
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 0x1001);
    let c = count.borrow();
    let add = find(&code, iced_x86::Mnemonic::Add, 0);
    assert_eq!(c[..3], [(CODE, 5), (CODE + 5, 2), (add, (code.len() as u64 - 1 - (add - CODE)) as u32)]);
}

#[test]
fn mem_hooks_report_accesses() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.mov(qword_ptr(rbx + 0x20), 0x77)?;
        a.mov(rax, qword_ptr(rbx + 0x20))?;
        a.push(rax)?;
        a.pop(rcx)?;
        Ok(())
    });
    let mut h = setup(&code);
    let log = Rc::new(RefCell::new(Vec::new()));
    let l2 = log.clone();
    h.add_mem_hook(HOOK_MEM_READ | HOOK_MEM_WRITE, 1, 0, move |_, acc, addr, size, val| {
        l2.borrow_mut().push((acc, addr, size, val))
    });
    let sp0 = h.reg_read(Reg::RSP);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(
        *log.borrow(),
        vec![
            (MemAccess::Write, DATA + 0x20, 8, 0x77),
            (MemAccess::Read, DATA + 0x20, 8, 0x77),
            (MemAccess::Write, sp0 - 8, 8, 0x77),
            (MemAccess::Read, sp0 - 8, 8, 0x77),
        ]
    );
}

#[test]
fn unmapped_read_is_precise_and_hook_can_map() {
    let code = assemble(|a| {
        a.mov(eax, 1)?;
        a.mov(rbx, 0x50000000u64)?;
        a.mov(rcx, qword_ptr(rbx + 8))?;
        a.mov(eax, 2)?;
        Ok(())
    });
    let mut h = setup(&code);
    let err = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
    assert_eq!(err, EmuError::Memory { access: MemAccess::ReadUnmapped, addr: 0x50000008, size: 8, rip: CODE + 15 });
    assert_eq!(h.reg_read(Reg::RAX), 1);

    let mut h = setup(&code);
    h.add_invalid_mem_hook(|emu, _, addr, _, _| {
        emu.mem_map(addr & !0xfff, 0x1000, PERM_READ).unwrap();
        emu.mem_write(addr, &42u64.to_le_bytes()).unwrap();
        true
    });
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RCX), 42);
    assert_eq!(h.reg_read(Reg::RAX), 2);
}

#[test]
fn write_to_readonly_faults() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.mov(qword_ptr(rbx), rbx)?;
        Ok(())
    });
    let mut h = setup(&code);
    h.mem_protect(DATA, 0x1000, PERM_READ).unwrap();
    let err = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
    assert!(matches!(err, EmuError::Memory { access: MemAccess::WriteProt, addr: DATA, .. }), "{err:?}");
}

#[test]
fn divide_error_is_precise() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.mov(r9, 0x99u64)?;
        a.xor(ecx, ecx)?;
        a.mov(eax, 10)?;
        a.cmp(eax, 30)?;
        a.div(dword_ptr(rbx + rcx))?;
        a.mov(eax, 3)?;
        Ok(())
    });
    let mut h = setup(&code);
    let err = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
    let div_rip = find(&code, iced_x86::Mnemonic::Div, 0);
    assert_eq!(err, EmuError::Exception { vector: EXC_DIVIDE, rip: div_rip });
    assert_eq!(h.reg_read(Reg::RAX), 10);
    assert_eq!(h.reg_read(Reg::RBX), DATA);
    assert_eq!(h.reg_read(Reg::R9), 0x99);
    assert_eq!(h.reg_read(Reg::RCX), 0);
    assert_ne!(h.reg_read(Reg::RFLAGS) & 0x80, 0, "SF from cmp survives");

    let mut h = setup(&code);
    h.add_intr_hook(|emu, v| {
        assert_eq!(v, EXC_DIVIDE);
        let rip = emu.reg_read(Reg::RIP);
        emu.reg_write(Reg::RIP, rip + 3);
    });
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 3);
}

#[test]
fn self_modifying_code_in_same_block() {
    let code = assemble(|a| {
        a.mov(eax, 1)?;
        a.mov(rbx, CODE + 19)?;
        a.mov(byte_ptr(rbx), 7)?;
        a.mov(ecx, 0x100)?;
        a.add(eax, ecx)?;
        Ok(())
    });
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RCX), 0x107);
    assert_eq!(h.reg_read(Reg::RAX), 0x108);
}

#[test]
fn code_rewritten_between_runs() {
    let code = assemble(|a| {
        a.mov(eax, 1)?;
        Ok(())
    });
    let mut h = run(&code);
    assert_eq!(h.reg_read(Reg::RAX), 1);
    h.mem_write(CODE + 1, &5u32.to_le_bytes()).unwrap();
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 5);
}

#[test]
fn count_until_and_timeout() {
    let code = assemble(|a| {
        let mut l = a.create_label();
        a.mov(eax, 1)?;
        a.mov(ecx, 2)?;
        a.mov(edx, 3)?;
        a.mov(ebx, 4)?;
        a.set_label(&mut l)?;
        a.jmp(l)?;
        Ok(())
    });
    let mut h = setup(&code);
    h.emu_start(CODE, u64::MAX, None, 2).unwrap();
    assert_eq!((h.reg_read(Reg::RAX), h.reg_read(Reg::RCX), h.reg_read(Reg::RDX)), (1, 2, 0));
    assert_eq!(h.reg_read(Reg::RIP), CODE + 10);

    let mut h = setup(&code);
    h.emu_start(CODE, CODE + 15, None, 0).unwrap();
    assert_eq!((h.reg_read(Reg::RDX), h.reg_read(Reg::RBX)), (3, 0));
    assert_eq!(h.reg_read(Reg::RIP), CODE + 15);

    let mut h = setup(&code);
    let t = std::time::Instant::now();
    h.emu_start(CODE, u64::MAX, Some(Duration::from_millis(100)), 0).unwrap();
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(h.reg_read(Reg::RBX), 4);
    assert_eq!(h.reg_read(Reg::RIP), CODE + 20);
}

#[test]
fn stop_from_hook() {
    let code = assemble(|a| {
        let mut l = a.create_label();
        a.set_label(&mut l)?;
        a.inc(rax)?;
        a.jmp(l)?;
        Ok(())
    });
    let mut h = setup(&code);
    h.add_code_hook(CODE, CODE, |emu, _, _| {
        if emu.reg_read(Reg::RAX) == 100 {
            emu.emu_stop();
        }
    });
    h.emu_start(CODE, u64::MAX, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 100);
    assert_eq!(h.reg_read(Reg::RIP), CODE);
}

#[test]
fn sse_state_round_trips() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.movdqu(xmm0, xmmword_ptr(rbx))?;
        a.paddd(xmm0, xmm0)?;
        a.movdqu(xmmword_ptr(rbx + 16), xmm0)?;
        a.movq(rax, xmm0)?;
        Ok(())
    });
    let mut h = setup(&code);
    h.mem_write(DATA, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0]).unwrap();
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 0x0000000400000002);
    assert_eq!(h.mem_read_vec(DATA + 16, 16).unwrap(), vec![2, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0]);
    assert_eq!(h.xmm_read(0), 0x00000008_00000006_00000004_00000002);
}

#[test]
fn indirect_jumps_and_tables() {
    let code = assemble(|a| {
        let mut table = a.create_label();
        let mut t0 = a.create_label();
        let mut t1 = a.create_label();
        let mut lp = a.create_label();
        let mut next = a.create_label();
        let mut end = a.create_label();
        a.lea(rdx, qword_ptr(table))?;
        a.lea(rax, qword_ptr(t0))?;
        a.mov(qword_ptr(rdx), rax)?;
        a.lea(rax, qword_ptr(t1))?;
        a.mov(qword_ptr(rdx + 8), rax)?;
        a.xor(esi, esi)?;
        a.xor(edi, edi)?;
        a.set_label(&mut lp)?;
        a.mov(eax, esi)?;
        a.and(eax, 1)?;
        a.lea(rdx, qword_ptr(table))?;
        a.jmp(qword_ptr(rdx + rax * 8))?;
        a.set_label(&mut t0)?;
        a.add(edi, 1)?;
        a.jmp(next)?;
        a.set_label(&mut t1)?;
        a.add(edi, 100)?;
        a.set_label(&mut next)?;
        a.inc(esi)?;
        a.cmp(esi, 10)?;
        a.jne(lp)?;
        a.jmp(end)?;
        a.set_label(&mut table)?;
        a.dq(&[0, 0])?;
        a.set_label(&mut end)?;
        Ok(())
    });
    let mut h = setup(&code);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RDI), 505);
}

#[test]
fn enter_leave_xlat_bt() {
    let code = assemble(|a| {
        a.mov(rbp, 0x1234u64)?;
        a.enter(0x20u32, 0u32)?;
        a.mov(r8, rbp)?;
        a.leave()?;
        a.mov(rbx, DATA)?;
        a.mov(byte_ptr(rbx + 5), 0x99)?;
        a.mov(eax, 5)?;
        a.xlatb()?;
        a.mov(rcx, 67u64)?;
        a.bts(qword_ptr(rbx + 0x100), rcx)?;
        a.mov(rdx, qword_ptr(rbx + 0x108))?;
        Ok(())
    });
    let mut h = setup(&code);
    let sp0 = h.reg_read(Reg::RSP);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::R8), sp0 - 8);
    assert_eq!(h.reg_read(Reg::RBP), 0x1234);
    assert_eq!(h.reg_read(Reg::RSP), sp0);
    assert_eq!(h.reg_read(Reg::RAX), 0x99);
    assert_eq!(h.reg_read(Reg::RDX), 8);
}

#[test]
fn unsupported_and_invalid_instructions() {
    let mut h = setup(&[0x90, 0x0f, 0x0b]);
    let err = h.emu_start(CODE, CODE + 3, None, 0).unwrap_err();
    assert_eq!(err, EmuError::Exception { vector: EXC_INVALID_OPCODE, rip: CODE + 1 });
    let mut h = setup(&[0xcc]);
    let err = h.emu_start(CODE, CODE + 1, None, 0).unwrap_err();
    assert_eq!(err, EmuError::Interrupt { intno: 3, rip: CODE + 1 });
}

#[test]
fn hooks_preserve_and_edit_vector_state() {
    let code = assemble(|a| {
        a.mov(eax, 5)?;
        a.movq(xmm3, rax)?;
        a.nop()?;
        a.movq(rbx, xmm4)?;
        a.movq(rcx, xmm3)?;
        Ok(())
    });
    let mut h = setup(&code);
    let probe = find(&code, iced_x86::Mnemonic::Nop, 0);
    h.add_code_hook(probe, probe, |emu, _, _| {
        assert_eq!(emu.xmm_read(3), 5);
        emu.xmm_write(4, 7);
    });
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RBX), 7);
    assert_eq!(h.reg_read(Reg::RCX), 5);
}

#[test]
fn avx_upper_halves_survive_hooks() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.vmovdqu(ymm1, ymmword_ptr(rbx))?;
        a.vpaddd(ymm1, ymm1, ymm1)?;
        a.mov(rcx, rbx)?;
        a.vmovdqu(ymmword_ptr(rbx + 32), ymm1)?;
        a.vzeroupper()?;
        Ok(())
    });
    let mut h = setup(&code);
    let input: Vec<u8> = (1..=32).collect();
    h.mem_write(DATA, &input).unwrap();
    h.add_code_hook(1, 0, |_, _, _| {});
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    let out = h.mem_read_vec(DATA + 32, 32).unwrap();
    let want: Vec<u8> = input
        .chunks(4)
        .flat_map(|c| (u32::from_le_bytes(c.try_into().unwrap()) * 2).to_le_bytes())
        .collect();
    assert_eq!(out, want);
}

#[test]
fn x87_state_survives_stop_and_resume() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.fld1()?;
        a.fld1()?;
        a.faddp(st1, st0)?;
        a.nop()?;
        a.fstp(qword_ptr(rbx))?;
        Ok(())
    });
    let mut h = setup(&code);
    let probe = find(&code, iced_x86::Mnemonic::Nop, 0);
    h.add_code_hook(probe, probe, |emu, _, _| emu.emu_stop());
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RIP), probe);
    h.emu_start(probe + 1, CODE + code.len() as u64, None, 0).unwrap();
    let v = f64::from_le_bytes(h.mem_read_vec(DATA, 8).unwrap().try_into().unwrap());
    assert_eq!(v, 2.0);
}

#[test]
fn popf_trap_flag_single_steps_one_instruction() {
    let code = assemble(|a| {
        a.pushfq()?;
        a.or(qword_ptr(rsp), 0x100)?;
        a.popfq()?;
        a.mov(ecx, 7)?;
        a.mov(edx, 9)?;
        Ok(())
    });
    let after_mov_ecx = find(&code, iced_x86::Mnemonic::Mov, 1);
    let mut h = setup(&code);
    let err = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
    assert_eq!(err, EmuError::Exception { vector: EXC_DEBUG, rip: after_mov_ecx });
    assert_eq!(h.reg_read(Reg::RCX), 7);
    assert_eq!(h.reg_read(Reg::RDX), 0);

    let mut h = setup(&code);
    let hits = Rc::new(RefCell::new(Vec::new()));
    let h2 = hits.clone();
    h.add_intr_hook(move |e, v| h2.borrow_mut().push((v, e.reg_read(Reg::RIP))));
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(*hits.borrow(), vec![(EXC_DEBUG, after_mov_ecx)]);
    assert_eq!(h.reg_read(Reg::RDX), 9);
}


fn cpuid(leaf: u32, sub: u32) -> core::arch::x86_64::CpuidResult {
    core::arch::x86_64::__cpuid_count(leaf, sub)
}

fn host_is_amd() -> bool {
    cpuid(0, 0).ebx == 0x6874_7541
}

fn run_err(code: &[u8]) -> (Hades, EmuError) {
    let mut h = setup(code);
    let e = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
    (h, e)
}

fn exc(vector: u32, rip: u64) -> EmuError {
    EmuError::Exception { vector, rip }
}

fn ymm_mem(h: &Hades, addr: u64) -> Vec<u32> {
    h.mem_read_vec(addr, 32).unwrap().chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}

#[test]
fn far_call_and_far_return_stay_in_64bit_code() {
    let code = assemble(|a| {
        let mut target = a.create_label();
        let mut end = a.create_label();
        a.mov(rbx, DATA)?;
        a.mov(rsi, rsp)?;
        a.db(&[0xFF, 0x1B])?;
        a.mov(ecx, 1)?;
        a.jmp(end)?;
        a.set_label(&mut target)?;
        a.mov(rdx, rsp)?;
        a.db(&[0xCB])?;
        a.set_label(&mut end)?;
        Ok(())
    });
    const LOW: u64 = 0x0040_0000;
    let low = |a: u64| a - CODE + LOW;
    let ret_ip = low(find(&code, iced_x86::Mnemonic::Mov, 2));
    let target = low(find(&code, iced_x86::Mnemonic::Mov, 3));
    let mut h = setup(&[]);
    h.mem_map(LOW, 0x1000, PERM_ALL).unwrap();
    h.mem_write(LOW, &code).unwrap();
    let mut ptr = (target as u32).to_le_bytes().to_vec();
    ptr.extend(0x33u16.to_le_bytes());
    h.mem_write(DATA, &ptr).unwrap();
    h.emu_start(LOW, LOW + code.len() as u64, None, 0).unwrap();
    let sp0 = h.reg_read(Reg::RSI);
    assert_eq!(h.reg_read(Reg::RCX), 1);
    assert_eq!(h.reg_read(Reg::RDX), sp0 - 8);
    assert_eq!(h.reg_read(Reg::RSP), sp0);
    assert_eq!(h.reg_read(Reg::CS), 0x33);
    let frame = h.mem_read_vec(sp0 - 8, 8).unwrap();
    assert_eq!(u32::from_le_bytes(frame[0..4].try_into().unwrap()) as u64, ret_ip);
    assert_eq!(u32::from_le_bytes(frame[4..8].try_into().unwrap()), 0x33);
}

#[test]
fn far_jump_selector_checks() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.db(&[0xFF, 0x2B])?;
        Ok(())
    });
    let jmp = find(&code, iced_x86::Mnemonic::Jmp, 0);
    for sel in [0x00u16, 0x10, 0x13, 0x2B, 0x40, 0x48, 0x70, 0x37, 0x23] {
        let mut h = setup(&code);
        let mut ptr = (CODE as u32).to_le_bytes().to_vec();
        ptr.extend(sel.to_le_bytes());
        h.mem_write(DATA, &ptr).unwrap();
        let e = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
        match sel {
            0x23 => assert!(matches!(e, EmuError::Unsupported { rip: at, .. } if at == jmp), "{sel:#x}: {e:?}"),
            _ => assert_eq!(e, exc(EXC_GENERAL_PROTECTION, jmp), "{sel:#x}"),
        }
        assert_eq!(h.reg_read(Reg::CS), 0x33);
    }
}

fn iret_code(code_sel: i32, stack_sel: i32) -> Vec<u8> {
    assemble(|a| {
        let mut target = a.create_label();
        a.mov(rsi, rsp)?;
        a.push(stack_sel)?;
        a.push(rsi)?;
        a.pushfq()?;
        a.or(qword_ptr(rsp), 0x801)?;
        a.push(code_sel)?;
        a.lea(rax, ptr(target))?;
        a.push(rax)?;
        a.iretq()?;
        a.ud2()?;
        a.set_label(&mut target)?;
        a.setc(cl)?;
        a.seto(dl)?;
        Ok(())
    })
}

#[test]
fn iretq_restores_rip_flags_and_stack() {
    let h = run(&iret_code(0x33, 0x2B));
    assert_eq!(h.reg_read(Reg::RCX) & 0xff, 1);
    assert_eq!(h.reg_read(Reg::RDX) & 0xff, 1);
    assert_eq!(h.reg_read(Reg::RSP), h.reg_read(Reg::RSI));
    assert_eq!(h.reg_read(Reg::SS), 0x2B);

    for (code_sel, stack_sel) in [(0x33, 0), (0x33, 0x28), (0x30, 0x2B), (0x2B, 0x2B), (0x23, 0x2B)] {
        let code = iret_code(code_sel, stack_sel);
        let iret = find(&code, iced_x86::Mnemonic::Iretq, 0);
        let (h, e) = run_err(&code);
        match code_sel {
            0x23 => assert!(matches!(e, EmuError::Unsupported { rip: at, .. } if at == iret)),
            _ => assert_eq!(e, exc(EXC_GENERAL_PROTECTION, iret), "{code_sel:#x}:{stack_sel:#x}"),
        }
        assert_eq!(h.reg_read(Reg::RSP), h.reg_read(Reg::RSI) - 40);
    }
}

#[test]
fn segment_register_loads_and_stores() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.db(&[0x66, 0x8C, 0xE8])?;
        a.mov(ecx, 0x53)?;
        a.db(&[0x8E, 0xE9])?;
        a.db(&[0x0F, 0xA0])?;
        a.pop(rdx)?;
        a.mov(dword_ptr(rbx), 0x11223344)?;
        a.mov(word_ptr(rbx + 4), 0x2B)?;
        a.db(&[0x0F, 0xB2, 0x33])?;
        a.xor(edi, edi)?;
        a.db(&[0x8E, 0xDF])?;
        Ok(())
    });
    let mut h = setup(&code);
    h.reg_write(Reg::GsBase, 0x5000);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX) & 0xffff, 0x2B);
    assert_eq!(h.reg_read(Reg::GS), 0x53);
    assert_eq!(h.reg_read(Reg::GsBase), 0);
    assert_eq!(h.reg_read(Reg::RDX) & 0xffff, 0x53);
    assert_eq!(h.reg_read(Reg::RSI), 0x11223344);
    assert_eq!(h.reg_read(Reg::SS), 0x2B);
    assert_eq!(h.reg_read(Reg::DS), 0);

    for (bytes, vector) in [
        (vec![0xB8, 0x10, 0, 0, 0, 0x8E, 0xD8], EXC_GENERAL_PROTECTION),
        (vec![0xB8, 0x40, 0, 0, 0, 0x8E, 0xE0], EXC_GENERAL_PROTECTION),
        (vec![0x31, 0xC0, 0x90, 0x90, 0x90, 0x8E, 0xD0], EXC_GENERAL_PROTECTION),
        (vec![0xB8, 0x23, 0, 0, 0, 0x8E, 0xD0], EXC_GENERAL_PROTECTION),
        (vec![0xB8, 0x2B, 0, 0, 0, 0x8E, 0xC8], EXC_INVALID_OPCODE),
    ] {
        let (h, e) = run_err(&bytes);
        assert_eq!(e, exc(vector, CODE + 5), "{bytes:x?}");
        assert_eq!(h.reg_read(Reg::DS), 0x2B);
        assert_eq!(h.reg_read(Reg::SS), 0x2B);
    }
}

#[test]
fn sixteen_bit_pushf_popf() {
    let code = assemble(|a| {
        a.mov(rsi, rsp)?;
        a.stc()?;
        a.db(&[0x66, 0x9C])?;
        a.mov(rdi, rsp)?;
        a.movzx(eax, word_ptr(rsp))?;
        a.clc()?;
        a.db(&[0x66, 0x9D])?;
        a.setc(cl)?;
        Ok(())
    });
    let h = run(&code);
    let sp0 = h.reg_read(Reg::RSI);
    assert_eq!(h.reg_read(Reg::RDI), sp0 - 2);
    assert_eq!(h.reg_read(Reg::RSP), sp0);
    assert_eq!(h.reg_read(Reg::RAX) & 0x0001, 1);
    assert_eq!(h.reg_read(Reg::RCX) & 0xff, 1);

    let code = assemble(|a| {
        a.sub(rsp, 2)?;
        a.mov(word_ptr(rsp), 0x0102)?;
        a.db(&[0x66, 0x9D])?;
        a.mov(ecx, 7)?;
        a.mov(edx, 9)?;
        Ok(())
    });
    let after = find(&code, iced_x86::Mnemonic::Mov, 2);
    let (h, e) = run_err(&code);
    assert_eq!(e, exc(EXC_DEBUG, after));
    assert_eq!(h.reg_read(Reg::RCX), 7);
    assert_eq!(h.reg_read(Reg::RDX), 0);
}

#[test]
fn tsx_transactions_always_abort() {
    let rtm = cpuid(7, 0).ebx >> 11 & 1 != 0;
    let code = assemble(|a| {
        let mut fallback = a.create_label();
        a.mov(rax, -1i64)?;
        a.xbegin(fallback)?;
        a.mov(ecx, 1)?;
        a.xend()?;
        a.set_label(&mut fallback)?;
        a.mov(edx, 2)?;
        Ok(())
    });
    let xbegin = find(&code, iced_x86::Mnemonic::Xbegin, 0);
    let mut h = setup(&code);
    let r = h.emu_start(CODE, CODE + code.len() as u64, None, 0);
    if rtm {
        r.unwrap();
        assert_eq!(h.reg_read(Reg::RAX), 0);
        assert_eq!(h.reg_read(Reg::RCX), 0);
        assert_eq!(h.reg_read(Reg::RDX), 2);
    } else {
        assert_eq!(r.unwrap_err(), exc(EXC_INVALID_OPCODE, xbegin));
    }
    let (_, e) = run_err(&[0x0F, 0x01, 0xD5]);
    assert_eq!(e, exc(if rtm { EXC_GENERAL_PROTECTION } else { EXC_INVALID_OPCODE }, CODE));
}

#[test]
fn system_instructions_fault_like_user_mode() {
    let sysenter = if host_is_amd() { EXC_INVALID_OPCODE } else { EXC_GENERAL_PROTECTION };
    for (bytes, vector) in [
        (&[0x0F, 0x34][..], sysenter),
        (&[0x0F, 0x35][..], EXC_GENERAL_PROTECTION),
        (&[0x48, 0x0F, 0x07][..], EXC_GENERAL_PROTECTION),
        (&[0x0F, 0x01, 0xC8][..], EXC_INVALID_OPCODE),
        (&[0x0F, 0x01, 0xC9][..], EXC_INVALID_OPCODE),
        (&[0x0F, 0x01, 0xEF][..], EXC_INVALID_OPCODE),
        (&[0x0F, 0x01, 0xEE][..], EXC_INVALID_OPCODE),
        (&[0xF3, 0x48, 0x0F, 0xAE, 0xE8][..], EXC_INVALID_OPCODE),
        (&[0xF3, 0x0F, 0x01, 0xEA][..], EXC_INVALID_OPCODE),
        (&[0xF3, 0x0F, 0x01, 0xE8][..], EXC_INVALID_OPCODE),
        (&[0x66, 0x48, 0x0F, 0x38, 0xF5, 0x03][..], EXC_GENERAL_PROTECTION),
        (&[0x48, 0x0F, 0xC7, 0x1B][..], EXC_GENERAL_PROTECTION),
    ] {
        let (_, e) = run_err(bytes);
        assert_eq!(e, exc(vector, CODE), "{bytes:x?}");
    }
    let code = [0x48, 0xC7, 0xC0, 0x34, 0x12, 0, 0, 0xF3, 0x48, 0x0F, 0x1E, 0xC8, 0xF3, 0x0F, 0x1A, 0x00];
    let h = run(&code);
    assert_eq!(h.reg_read(Reg::RAX), 0x1234);
}

#[test]
fn guest_xsave_and_xrstor_use_guest_memory() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.mov(rax, 0x1122_3344_5566_7788u64)?;
        a.movq(xmm1, rax)?;
        a.vmovdqu(ymm2, ymmword_ptr(rbx + 0x1000))?;
        a.mov(eax, -1)?;
        a.mov(edx, -1)?;
        a.xsave64(ptr(rbx))?;
        a.pxor(xmm1, xmm1)?;
        a.vpxor(ymm2, ymm2, ymm2)?;
        a.xrstor64(ptr(rbx))?;
        a.movq(rcx, xmm1)?;
        a.vmovdqu(ymmword_ptr(rbx + 0x1100), ymm2)?;
        Ok(())
    });
    let mut h = setup(&code);
    let pattern: Vec<u8> = (1..=32).collect();
    h.mem_write(DATA + 0x1000, &pattern).unwrap();
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RCX), 0x1122_3344_5566_7788);
    assert_eq!(h.mem_read_vec(DATA + 0x1100, 32).unwrap(), pattern);
    let img = h.mem_read_vec(DATA, 1024).unwrap();
    assert_eq!(u32::from_le_bytes(img[24..28].try_into().unwrap()), 0x1F80);
    assert_eq!(img[160 + 16..160 + 24], 0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(img[160 + 32..160 + 48], pattern[..16]);
    assert_eq!(img[576 + 32..576 + 48], pattern[16..]);
    assert_eq!(u64::from_le_bytes(img[512..520].try_into().unwrap()) & 6, 6);
    assert_eq!(img[520..536], [0u8; 16]);

    let misaligned = assemble(|a| {
        a.mov(rbx, DATA + 8)?;
        a.xsave64(ptr(rbx))?;
        Ok(())
    });
    let (_, e) = run_err(&misaligned);
    assert_eq!(e, exc(EXC_GENERAL_PROTECTION, find(&misaligned, iced_x86::Mnemonic::Xsave64, 0)));

    let bad_header = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.mov(eax, -1)?;
        a.mov(edx, -1)?;
        a.xrstor64(ptr(rbx))?;
        Ok(())
    });
    let mut h = setup(&bad_header);
    h.mem_write(DATA + 520, &[1]).unwrap();
    let e = h.emu_start(CODE, CODE + bad_header.len() as u64, None, 0).unwrap_err();
    assert_eq!(e, exc(EXC_GENERAL_PROTECTION, find(&bad_header, iced_x86::Mnemonic::Xrstor64, 0)));
}

#[test]
fn guest_xsavec_round_trips_in_compacted_form() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.mov(rax, 0x0102_0304_0506_0708u64)?;
        a.movq(xmm5, rax)?;
        a.mov(eax, 7)?;
        a.xor(edx, edx)?;
        a.xsavec64(ptr(rbx))?;
        a.pxor(xmm5, xmm5)?;
        a.xrstor64(ptr(rbx))?;
        a.movq(rcx, xmm5)?;
        Ok(())
    });
    let mut h = setup(&code);
    let r = h.emu_start(CODE, CODE + code.len() as u64, None, 0);
    if cpuid(0xD, 1).eax >> 1 & 1 == 0 {
        assert_eq!(r.unwrap_err(), exc(EXC_INVALID_OPCODE, find(&code, iced_x86::Mnemonic::Xsavec64, 0)));
        return;
    }
    r.unwrap();
    assert_eq!(h.reg_read(Reg::RCX), 0x0102_0304_0506_0708);
    let hdr = h.mem_read_vec(DATA + 512, 16).unwrap();
    assert_eq!(u64::from_le_bytes(hdr[8..16].try_into().unwrap()), 7 | 1 << 63);
}

fn gather_code() -> Vec<u8> {
    assemble(|a| {
        a.mov(rbx, DATA)?;
        a.vmovdqu(ymm1, ymmword_ptr(rbx + 0x100))?;
        a.vmovdqu(ymm2, ymmword_ptr(rbx + 0x120))?;
        a.vmovdqu(ymm0, ymmword_ptr(rbx + 0x140))?;
        a.vpgatherdd_3(ymm0, ptr(rbx + ymm1 * 4), ymm2)?;
        a.vmovdqu(ymmword_ptr(rbx + 0x200), ymm0)?;
        a.vmovdqu(ymmword_ptr(rbx + 0x220), ymm2)?;
        Ok(())
    })
}

fn gather_setup(code: &[u8], idx: [u32; 8]) -> Hades {
    let mut h = setup(code);
    let table: Vec<u8> = (0..8u32).flat_map(|k| (100 + k).to_le_bytes()).collect();
    h.mem_write(DATA, &table).unwrap();
    h.mem_write(DATA + 0x100, &idx.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()).unwrap();
    let mask: Vec<u8> = (0..8).flat_map(|k: u32| if k == 3 { 0u32 } else { 0x8000_0000u32 }.to_le_bytes()).collect();
    h.mem_write(DATA + 0x120, &mask).unwrap();
    h.mem_write(DATA + 0x140, &[0xEE; 32]).unwrap();
    h
}

#[test]
fn avx2_gather_merges_masked_lanes_and_faults_precisely() {
    let code = gather_code();
    let mut h = gather_setup(&code, [0, 2, 4, 6, 1, 3, 5, 7]);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(ymm_mem(&h, DATA + 0x200), vec![100, 102, 104, 0xEEEE_EEEE, 101, 103, 105, 107]);
    assert_eq!(ymm_mem(&h, DATA + 0x220), vec![0; 8]);

    let gather = find(&code, iced_x86::Mnemonic::Vpgatherdd, 0);
    let mut h = gather_setup(&code, [0, 2, 0x4000, 6, 1, 3, 5, 7]);
    let e = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
    assert!(matches!(e, EmuError::Memory { addr, rip: at, .. } if addr == DATA + 0x10000 && at == gather), "{e:?}");
    let lanes = |v: u128| (0..4).map(|k| (v >> (32 * k)) as u32).collect::<Vec<_>>();
    assert_eq!(lanes(h.xmm_read(0)), vec![100, 102, 0xEEEE_EEEE, 0xEEEE_EEEE]);
    assert_eq!(lanes(h.xmm_read(2)), vec![0, 0, 0x8000_0000, 0]);
}

#[test]
fn avx512_gather_and_scatter_follow_opmask() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.vmovdqu32(zmm1, zmmword_ptr(rbx + 0x100))?;
        a.vmovdqu32(zmm2, zmmword_ptr(rbx + 0x140))?;
        a.mov(eax, 0xFFF7)?;
        a.kmovw(k1, eax)?;
        a.vpgatherdd(zmm2.k1(), ptr(rbx + zmm1 * 4))?;
        a.kmovw(ecx, k1)?;
        a.vmovdqu32(zmmword_ptr(rbx + 0x200), zmm2)?;
        a.mov(eax, 0x0005)?;
        a.kmovw(k2, eax)?;
        a.vpscatterdd(ptr(rbx + 0x400 + zmm1 * 4).k2(), zmm2)?;
        Ok(())
    });
    let mut h = setup(&code);
    let table: Vec<u8> = (0..16u32).flat_map(|k| (100 + k).to_le_bytes()).collect();
    h.mem_write(DATA, &table).unwrap();
    let idx: Vec<u8> = (0..16u32).flat_map(|k| (15 - k).to_le_bytes()).collect();
    h.mem_write(DATA + 0x100, &idx).unwrap();
    h.mem_write(DATA + 0x140, &[0xEE; 64]).unwrap();
    let r = h.emu_start(CODE, CODE + code.len() as u64, None, 0);
    if cpuid(7, 0).ebx >> 16 & 1 == 0 {
        assert_eq!(r.unwrap_err(), exc(EXC_INVALID_OPCODE, find(&code, iced_x86::Mnemonic::Vmovdqu32, 0)));
        return;
    }
    r.unwrap();
    let out: Vec<u32> = h.mem_read_vec(DATA + 0x200, 64).unwrap().chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    let want: Vec<u32> = (0..16u32).map(|k| if k == 3 { 0xEEEE_EEEE } else { 115 - k }).collect();
    assert_eq!(out, want);
    assert_eq!(h.reg_read(Reg::RCX), 0);
    let sc = h.mem_read_vec(DATA + 0x400, 64).unwrap();
    assert_eq!(u32::from_le_bytes(sc[60..64].try_into().unwrap()), 115);
    assert_eq!(u32::from_le_bytes(sc[52..56].try_into().unwrap()), 113);
    assert_eq!(sc[0..52], [0u8; 52]);
}

#[test]
fn maskmov_stores_selected_bytes_at_rdi() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.lea(rdi, ptr(rbx + 0x300))?;
        a.movdqu(xmm0, xmmword_ptr(rbx))?;
        a.movdqu(xmm1, xmmword_ptr(rbx + 0x10))?;
        a.maskmovdqu(xmm0, xmm1)?;
        a.lea(rdi, ptr(rbx + 0x380))?;
        a.movq(mm0, qword_ptr(rbx))?;
        a.movq(mm1, qword_ptr(rbx + 0x18))?;
        a.maskmovq(mm0, mm1)?;
        a.emms()?;
        Ok(())
    });
    let mut h = setup(&code);
    let data: Vec<u8> = (0x10..0x20).collect();
    let mask: Vec<u8> = (0..16).map(|k| if k % 2 == 0 { 0x80 } else { 0x7F }).collect();
    h.mem_write(DATA, &data).unwrap();
    h.mem_write(DATA + 0x10, &mask).unwrap();
    h.mem_write(DATA + 0x300, &[0xAA; 16]).unwrap();
    h.mem_write(DATA + 0x380, &[0xAA; 8]).unwrap();
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    let want: Vec<u8> = (0..16).map(|k| if k % 2 == 0 { 0x10 + k as u8 } else { 0xAA }).collect();
    assert_eq!(h.mem_read_vec(DATA + 0x300, 16).unwrap(), want);
    assert_eq!(h.mem_read_vec(DATA + 0x380, 8).unwrap(), want[..8]);
}

#[test]
fn register_addressed_stores_use_guest_memory() {
    let movdir64b = cpuid(7, 0).ecx >> 28 & 1 != 0;
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.lea(rcx, ptr(rbx + 0x500))?;
        a.movdir64b(rcx, ptr(rbx))?;
        a.lea(rcx, ptr(rbx + 0x5C8))?;
        a.movdir64b(rcx, ptr(rbx))?;
        Ok(())
    });
    let mut h = setup(&code);
    let src: Vec<u8> = (0..64).collect();
    h.mem_write(DATA, &src).unwrap();
    let e = h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap_err();
    if movdir64b {
        assert_eq!(h.mem_read_vec(DATA + 0x500, 64).unwrap(), src);
        assert_eq!(e, exc(EXC_GENERAL_PROTECTION, find(&code, iced_x86::Mnemonic::Movdir64b, 1)));
    } else {
        assert_eq!(e, exc(EXC_INVALID_OPCODE, find(&code, iced_x86::Mnemonic::Movdir64b, 0)));
    }

    let clzero = cpuid(0x8000_0008, 0).ebx & 1 != 0;
    let code = assemble(|a| {
        a.mov(rax, DATA + 0x610)?;
        a.clzero()?;
        Ok(())
    });
    let mut h = setup(&code);
    h.mem_write(DATA + 0x5C0, &[0xAA; 0x100]).unwrap();
    let r = h.emu_start(CODE, CODE + code.len() as u64, None, 0);
    if clzero {
        r.unwrap();
        let m = h.mem_read_vec(DATA + 0x5C0, 0x100).unwrap();
        assert_eq!(m[..0x40], [0xAA; 0x40]);
        assert_eq!(m[0x40..0x80], [0; 0x40]);
        assert_eq!(m[0x80..], [0xAA; 0x80]);
    } else {
        assert_eq!(r.unwrap_err(), exc(EXC_INVALID_OPCODE, find(&code, iced_x86::Mnemonic::Clzero, 0)));
    }
}


#[test]
fn cpuid_rdtsc_rdrand_hooks_override_host_values() {
    let code = assemble(|a| {
        a.xor(eax, eax)?;
        a.xor(ecx, ecx)?;
        a.cpuid()?;
        a.mov(r8, rbx)?;
        a.mov(r9, rdx)?;
        a.mov(r10, rcx)?;
        a.mov(eax, 1)?;
        a.cpuid()?;
        a.mov(r11, rax)?;
        a.rdtsc()?;
        a.shl(rdx, 32)?;
        a.or(rax, rdx)?;
        a.mov(r12, rax)?;
        a.mov(rsi, -1i64)?;
        a.rdrand(si)?;
        a.setc(bl)?;
        a.rdseed(edi)?;
        a.setc(bh)?;
        Ok(())
    });
    let mut h = setup(&code);
    let leaves = Rc::new(RefCell::new(Vec::new()));
    let l2 = leaves.clone();
    h.add_cpuid_hook(move |_, leaf, sub| {
        l2.borrow_mut().push((leaf, sub));
        (leaf == 0).then_some([0xD, u32::from_le_bytes(*b"Genu"), u32::from_le_bytes(*b"ntel"), u32::from_le_bytes(*b"ineI")])
    });
    h.add_rdtsc_hook(|_| Some(0x1122_3344_5566_7788));
    h.add_rdrand_hook(|_, seed, bytes| Some(if seed { 0xAAAA_BBBB_CCCC_DDDD } else { 0x1234 + bytes as u64 }));
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(*leaves.borrow(), vec![(0, 0), (1, u32::from_le_bytes(*b"ntel"))]);
    let vendor: Vec<u8> = [Reg::R8, Reg::R9, Reg::R10].iter().flat_map(|&r| (h.reg_read(r) as u32).to_le_bytes()).collect();
    assert_eq!(vendor, b"GenuineIntel");
    assert_eq!(h.reg_read(Reg::R11) as u32, cpuid(1, 0).eax);
    assert_eq!(h.reg_read(Reg::R12), 0x1122_3344_5566_7788);
    assert_eq!(h.reg_read(Reg::RSI), 0xFFFF_FFFF_FFFF_1236);
    assert_eq!(h.reg_read(Reg::RDI), 0xCCCC_DDDD);
    assert_eq!(h.reg_read(Reg::RBX) & 0xFFFF, 0x0101);
}

#[test]
fn deleting_cpuid_hook_restores_host_values() {
    let code = assemble(|a| {
        a.xor(eax, eax)?;
        a.cpuid()?;
        Ok(())
    });
    let mut h = setup(&code);
    let id = h.add_cpuid_hook(|_, _, _| Some([1, 2, 3, 4]));
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RBX), 2);
    h.hook_del(id);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RBX) as u32, cpuid(0, 0).ebx);
}

#[test]
fn context_save_restore_covers_gprs_flags_and_vector_state() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.add(rax, 1)?;
        a.vmovdqu(ymm3, ymmword_ptr(rbx))?;
        a.vpaddd(ymm3, ymm3, ymm3)?;
        a.vmovdqu(ymmword_ptr(rbx), ymm3)?;
        a.stc()?;
        Ok(())
    });
    let mut h = setup(&code);
    h.mem_write(DATA, &[1; 32]).unwrap();
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    let ctx = h.context_save();
    let rflags = h.reg_read(Reg::RFLAGS);
    h.emu_start(CODE + 10, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.reg_read(Reg::RAX), 2);
    h.reg_write(Reg::RFLAGS, 0x202);
    h.context_restore(&ctx);
    assert_eq!(h.reg_read(Reg::RAX), 1);
    assert_eq!(h.reg_read(Reg::RFLAGS), rflags);
    let probe = assemble(|a| {
        a.mov(rbx, DATA + 0x100)?;
        a.vmovdqu(ymmword_ptr(rbx), ymm3)?;
        Ok(())
    });
    h.mem_write(CODE + 0x1000, &probe).unwrap();
    h.emu_start(CODE + 0x1000, CODE + 0x1000 + probe.len() as u64, None, 0).unwrap();
    assert_eq!(h.mem_read_vec(DATA + 0x100, 32).unwrap(), vec![2; 32]);
}

fn snapshot_code() -> Vec<u8> {
    assemble(|a| {
        a.mov(rbx, DATA)?;
        a.add(qword_ptr(rbx), 1)?;
        a.lea(rdi, ptr(rbx + 0x2000))?;
        a.mov(ecx, 0x1800)?;
        a.mov(al, 0x5A)?;
        a.rep().stosb()?;
        a.mov(rdx, CODE)?;
        a.mov(byte_ptr(rdx + 0x800), 0xC3)?;
        a.inc(r12)?;
        Ok(())
    })
}

#[test]
fn snapshot_restore_rewinds_memory_registers_and_code() {
    let code = snapshot_code();
    let mut h = setup(&code);
    h.mem_write(CODE + 0x800, &[0x90]).unwrap();
    h.reg_write(Reg::R12, 7);
    let snap = h.snapshot();
    let before = h.mem_read_vec(DATA, 0x4000).unwrap();
    for _ in 0..3 {
        h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
        h.mem_write(DATA + 0x8000, &[9; 16]).unwrap();
        assert_eq!(h.reg_read(Reg::R12), 8);
        assert_eq!(h.mem_read_vec(DATA, 1).unwrap(), [1]);
        h.snapshot_restore(&snap).unwrap();
        assert_eq!(h.reg_read(Reg::R12), 7);
        assert_eq!(h.mem_read_vec(DATA, 0x4000).unwrap(), before);
        assert_eq!(h.mem_read_vec(DATA + 0x8000, 16).unwrap(), [0; 16]);
        assert_eq!(h.mem_read_vec(CODE + 0x800, 1).unwrap(), [0x90]);
    }
}

#[test]
fn snapshot_restore_undoes_mappings_and_older_snapshots_still_work() {
    let code = snapshot_code();
    let mut h = setup(&code);
    let first = h.snapshot();
    let regions = h.mem_regions();
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    let second = h.snapshot();
    h.mem_map(0x5000_0000, 0x1000, PERM_READ).unwrap();
    h.mem_protect(DATA, 0x1000, PERM_READ).unwrap();
    h.snapshot_restore(&first).unwrap();
    assert_eq!(h.mem_regions(), regions);
    assert_eq!(h.mem_read_vec(DATA, 1).unwrap(), [0]);
    h.snapshot_restore(&second).unwrap();
    assert_eq!(h.mem_read_vec(DATA, 1).unwrap(), [1]);
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(h.mem_read_vec(DATA, 1).unwrap(), [2]);
}

#[test]
fn snapshot_restore_from_hook_rewinds_running_guest() {
    let code = assemble(|a| {
        a.mov(rbx, DATA)?;
        a.nop()?;
        a.add(qword_ptr(rbx), 1)?;
        a.inc(rsi)?;
        a.nop()?;
        Ok(())
    });
    let mut h = setup(&code);
    let start = find(&code, iced_x86::Mnemonic::Nop, 0);
    let end = find(&code, iced_x86::Mnemonic::Nop, 1);
    let snap: Rc<RefCell<Option<Snapshot>>> = Rc::new(RefCell::new(None));
    let rewinds = Rc::new(RefCell::new(0));
    let (s1, s2, r2) = (snap.clone(), snap.clone(), rewinds.clone());
    h.add_code_hook(start, start, move |e, _, _| {
        if s1.borrow().is_none() {
            *s1.borrow_mut() = Some(e.snapshot());
        }
    });
    h.add_code_hook(end, end, move |e, _, _| {
        if *r2.borrow() < 5 {
            *r2.borrow_mut() += 1;
            e.snapshot_restore(s2.borrow().as_ref().unwrap()).unwrap();
            e.reg_write(Reg::RCX, e.reg_read(Reg::RCX) + 1);
        }
    });
    h.emu_start(CODE, CODE + code.len() as u64, None, 0).unwrap();
    assert_eq!(*rewinds.borrow(), 5);
    assert_eq!(h.mem_read_vec(DATA, 1).unwrap(), [1]);
    assert_eq!(h.reg_read(Reg::RSI), 1);
    assert_eq!(h.reg_read(Reg::RCX), 1);
}
