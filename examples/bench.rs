use hades_emu::*;
use iced_x86::code_asm::*;
use std::fmt::Write as _;
use std::time::Instant;

const CODE: u64 = 0x140000000;
const DATA: u64 = 0x10000000;
const DATA_SIZE: u64 = 0x200000;
const STACK: u64 = 0x7ff00000;
const STACK_SIZE: u64 = 0x100000;

struct Workload {
    name: &'static str,
    code: Vec<u8>,
}

fn asm(f: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    f(&mut a).unwrap();
    a.nop().unwrap();
    a.assemble(CODE).unwrap()
}

fn workloads() -> Vec<Workload> {
    let mut w = Vec::new();
    w.push(Workload {
        name: "alu_xorshift",
        code: asm(|a| {
            let mut l = a.create_label();
            a.mov(rcx, 30_000_000u64)?;
            a.mov(rax, 0x9E3779B97F4A7C15u64)?;
            a.set_label(&mut l)?;
            a.mov(rdx, rax)?;
            a.shl(rdx, 13)?;
            a.xor(rax, rdx)?;
            a.mov(rdx, rax)?;
            a.shr(rdx, 7)?;
            a.xor(rax, rdx)?;
            a.mov(rdx, rax)?;
            a.shl(rdx, 17)?;
            a.xor(rax, rdx)?;
            a.dec(rcx)?;
            a.jnz(l)?;
            Ok(())
        }),
    });
    w.push(Workload {
        name: "mem_rmw",
        code: asm(|a| {
            let mut outer = a.create_label();
            let mut inner = a.create_label();
            a.mov(r8, 400u64)?;
            a.xor(edx, edx)?;
            a.set_label(&mut outer)?;
            a.mov(rsi, DATA)?;
            a.mov(ecx, 8192)?;
            a.set_label(&mut inner)?;
            a.mov(rax, qword_ptr(rsi))?;
            a.add(rax, rdx)?;
            a.mov(qword_ptr(rsi), rax)?;
            a.add(rdx, rax)?;
            a.add(rsi, 8)?;
            a.dec(ecx)?;
            a.jnz(inner)?;
            a.dec(r8)?;
            a.jnz(outer)?;
            Ok(())
        }),
    });
    w.push(Workload {
        name: "call_fib30",
        code: asm(|a| {
            let mut fib = a.create_label();
            let mut base = a.create_label();
            let mut end = a.create_label();
            a.mov(ecx, 30)?;
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
        }),
    });
    w.push(Workload {
        name: "insertion_sort",
        code: asm(|a| {
            let mut fill = a.create_label();
            let mut outer = a.create_label();
            let mut inner = a.create_label();
            let mut place = a.create_label();
            let mut next = a.create_label();
            let n = 6000u32;
            a.mov(rdi, DATA)?;
            a.mov(ecx, n)?;
            a.mov(eax, 12345)?;
            a.set_label(&mut fill)?;
            a.imul_3(eax, eax, 1103515245)?;
            a.add(eax, 12345)?;
            a.mov(dword_ptr(rdi + rcx * 4 - 4), eax)?;
            a.dec(ecx)?;
            a.jnz(fill)?;
            a.mov(esi, 1)?;
            a.set_label(&mut outer)?;
            a.mov(eax, dword_ptr(rdi + rsi * 4))?;
            a.mov(edx, esi)?;
            a.set_label(&mut inner)?;
            a.test(edx, edx)?;
            a.jz(place)?;
            a.mov(ebx, dword_ptr(rdi + rdx * 4 - 4))?;
            a.cmp(ebx, eax)?;
            a.jle(place)?;
            a.mov(dword_ptr(rdi + rdx * 4), ebx)?;
            a.dec(edx)?;
            a.jmp(inner)?;
            a.set_label(&mut place)?;
            a.mov(dword_ptr(rdi + rdx * 4), eax)?;
            a.set_label(&mut next)?;
            a.inc(esi)?;
            a.cmp(esi, n)?;
            a.jb(outer)?;
            Ok(())
        }),
    });
    w.push(Workload {
        name: "rep_movsb",
        code: asm(|a| {
            let mut l = a.create_label();
            a.mov(r8, 30u64)?;
            a.set_label(&mut l)?;
            a.mov(rsi, DATA)?;
            a.mov(rdi, DATA + 0x100000)?;
            a.mov(ecx, 0x100000)?;
            a.rep().movsb()?;
            a.dec(r8)?;
            a.jnz(l)?;
            Ok(())
        }),
    });
    w.push(Workload {
        name: "push_pop",
        code: asm(|a| {
            let mut l = a.create_label();
            a.mov(rcx, 10_000_000u64)?;
            a.set_label(&mut l)?;
            a.push(rax)?;
            a.push(rbx)?;
            a.push(rcx)?;
            a.pop(rdx)?;
            a.pop(rsi)?;
            a.pop(rdi)?;
            a.add(rax, rdx)?;
            a.dec(rcx)?;
            a.jnz(l)?;
            Ok(())
        }),
    });
    w
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn setup(code: &[u8]) -> Hades {
    let mut h = Hades::new().unwrap();
    h.mem_map(CODE, 0x10000, PERM_ALL).unwrap();
    h.mem_map(DATA, DATA_SIZE, PERM_READ | PERM_WRITE).unwrap();
    h.mem_map(STACK, STACK_SIZE, PERM_READ | PERM_WRITE).unwrap();
    h.mem_write(CODE, code).unwrap();
    h.reg_write(Reg::RSP, STACK + STACK_SIZE - 0x1000);
    h
}

fn main() {
    let mut json = String::from("{\"code_base\":");
    let _ = write!(json, "{CODE},\"data\":{DATA},\"data_size\":{DATA_SIZE},\"stack\":{STACK},\"stack_size\":{STACK_SIZE},\"workloads\":[");
    println!("{:16} {:>10} {:>12} {:>14}", "workload", "hades ms", "insns", "Minsn/s");
    for (k, w) in workloads().iter().enumerate() {
        let end = CODE + w.code.len() as u64;
        let mut hades = f64::MAX;
        let mut result = 0;
        for _ in 0..5 {
            let mut h = setup(&w.code);
            let t = Instant::now();
            h.emu_start(CODE, end, None, 0).unwrap();
            hades = hades.min(t.elapsed().as_secs_f64());
            result = h.reg_read(Reg::RAX);
        }

        let mut hc = setup(&w.code);
        let counter = std::rc::Rc::new(std::cell::Cell::new(0u64));
        let sizes = std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::<u64, u64>::new()));
        let code_copy = w.code.clone();
        let (c2, s2) = (counter.clone(), sizes.clone());
        hc.add_block_hook(1, 0, move |_, addr, size| {
            let n = *s2.borrow_mut().entry(addr).or_insert_with(|| {
                let off = (addr - CODE) as usize;
                iced_x86::Decoder::with_ip(64, &code_copy[off..off + size as usize], addr, 0).into_iter().count() as u64
            });
            c2.set(c2.get() + n);
        });
        hc.emu_start(CODE, end, None, 0).unwrap();
        assert_eq!(hc.reg_read(Reg::RAX), result, "hooked run diverged");
        let insns = counter.get();
        println!("{:16} {:>10.1} {:>12} {:>14.0}", w.name, hades * 1e3, insns, insns as f64 / hades / 1e6);
        if k > 0 {
            json.push(',');
        }
        let _ = write!(json, "{{\"name\":\"{}\",\"code\":\"{}\",\"hades_s\":{hades},\"insns\":{insns},\"rax\":{result}}}", w.name, hex(&w.code));
    }
    json.push_str("]}");
    std::fs::write("target/bench.json", json).unwrap();

    let w = &workloads()[0];
    let mut h = setup(&w.code);
    let n = std::rc::Rc::new(std::cell::Cell::new(0u64));
    let n2 = n.clone();
    h.add_code_hook(1, 0, move |_, _, _| n2.set(n2.get() + 1));
    let t = Instant::now();
    h.emu_start(CODE, CODE + w.code.len() as u64, None, 0).unwrap();
    let s = t.elapsed().as_secs_f64();
    println!("code hook on every insn: {} hooks in {:.1} ms = {:.1} ns/hook", n.get(), s * 1e3, s * 1e9 / n.get() as f64);
}
