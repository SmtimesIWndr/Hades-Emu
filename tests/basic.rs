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
