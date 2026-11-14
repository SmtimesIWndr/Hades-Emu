# Hades-Emu

A fast x86-64 user-mode CPU emulator for Windows x64 hosts.

## Performance (vs Unicorn 2.1.4)

Best of N fresh runs

| workload | guest insns | Unicorn ms | Hades ms | speedup |
|---|---:|---:|---:|---:|
| alu_xorshift (register ALU loop) | 330 M | 77.6 | 38.0 | 2.0× |
| mem_rmw (load/add/store over 64 KiB) | 22.9 M | 152.1 | 7.3 | 20.8× |
| call_fib30 (recursive call/ret) | 21.5 M | 293.5 | 29.7 | 9.9× |
| insertion_sort (6000 × i32) | 72.2 M | 489.0 | 27.9 | 17.5× |
| rep_movsb (30 × 1 MiB) | 182 | 3541.0 | 1.1 | 3182× |
| push_pop | 90 M | 1592.5 | 69.2 | 23.0× |

### Real world example: VMProtect 3.9 virtualized binary

`vmp-usermode-3-9-virtualized.exe` runs from its PE entry point through VMProtect's obfuscated, virtualized loader in an identical guest env on both engines. The same image/DLL mappings, PEB/TEB/loader list, and API/syscall semantics. The Hades harness is `examples/pe_run.rs` , `tools/pe_run_unicorn.py` is a Unicorn port of it. Along the way the loader:

- walks the loader list and resolves exports by itself
- maps a fresh ntdll from `\KnownDlls` and makes direct syscalls
- runs the debugger checks, debug port/object queries with aliased and misaligned buffers, debug object counting, thread hiding, the kernel debugger query, the TitanHide probe and the invalid handle `NtClose`
- reads and maps its own file, changes page protections and fills the import table.

Both runs stop at VMProtect's single step check, `popfq` with TF set followed by `rdtsc`. A real OS would deliver that `#DB` to VMP's handler, neither harness models exception delivery (Soon 👀).

| run (entry -> stop) | guest insns | Unicorn ms | Hades ms | speedup |
| --- | ---: | ---: | ---: | ---: |
| VMP virtualized loader -> single step trap | 948 M | 23 160 | 1 091 | **21.2×** |
| plain MSVC CRT start up -> end of `main` | 18 K | 15.8 | 7.9 | 2.0× |

Timings are best of 5 runs for Hades and best of 3 for Unicorn, measured around the emulation call with translation included (`python tools/bench_vmp.py <exe> 1400011a3`). That is about 870 M guest instructions/s for Hades vs 41 M/s for Unicorn on VMP's handler code. The instruction count comes from `HADES_COUNT=1`. 

Equivalence (`python tools/compare_runs.py`, run with `HADES_VERBOSE=1`):

- **VMP build:** both engines produce the identical 34 call API/syscall sequence (names and return values) and stop at the same RIP with the same RSP, flags and GPRs, except RAX:RDX, which hold the single stepped `rdtsc` result. Memory differs in 5 stack bytes, an earlier stored `rdtsc` value. Those same bytes also differ between two Hades runs.
- **Plain build:** identical 231 call sequence and final RIP/RSP/flags. The only differing state is written by MSVC's `__isa_available_init` from `cpuid`/`xgetbv` (Hades exposes the host CPU, Unicorn its QEMU model), plus the R11 scratch register left behind by the CPU-dependent paths.

```
HADES_VERBOSE=1 cargo run --release --example pe_run -- <exe> <stop_rip> <dump_lo> <dump_hi> h.bin > h.log
HADES_VERBOSE=1 python tools/pe_run_unicorn.py      <exe> <stop_rip> <dump_lo> <dump_hi> u.bin > u.log
python tools/compare_runs.py h.log u.log h.bin u.bin
```

`HADES_VERBOSE=1` prints every API and syscall with arguments and result. `HADES_COUNT=1` counts executed guest instructions. `HADES_MODE=count|hooks` reruns with single instruction blocks or memory hook call sites everywhere, as a codegen cross check

## Usage

```rust
use hades_emu::*;

let mut emu = Hades::new()?;
emu.mem_map(0x140000000, 0x10000, PERM_ALL)?;
emu.mem_map(0x7ff00000, 0x100000, PERM_READ | PERM_WRITE)?;
emu.mem_write(0x140000000, &code)?;
emu.reg_write(Reg::RSP, 0x7fff0000);
emu.reg_write(Reg::GsBase, teb_address);

emu.add_code_hook(1, 0, |e, addr, size| println!("{addr:#x} {size}"));        // begin > end: everywhere
emu.add_mem_hook(HOOK_MEM_WRITE, 0x10000000, 0x1000ffff, |_, acc, addr, size, value| {});
emu.add_syscall_hook(|e| { let nr = e.reg_read(Reg::RAX); e.reg_write(Reg::RAX, 0); });
emu.add_intr_hook(|e, vector| { /* int3, int n, #DE/#UD/#GP from guest code */ });
emu.add_invalid_mem_hook(|e, access, addr, size, _| {
    e.mem_map(addr & !0xfff, 0x1000, PERM_READ | PERM_WRITE).is_ok() // true = retry the access
});

emu.emu_start(0x140000000, until, Some(Duration::from_secs(5)), 0)?;
```

Hooks receive `&mut Emu` and can read and write registers (`reg_*`, `xmm_*`), memory and mappings, change RIP (execution resumes there), or call `emu_stop()`. `stop_handle()` returns a `Send + Sync` handle that stops emulation from another thread.

Errors are explicit: `EmuError::Memory { access, addr, size, rip }`, `Exception { vector, rip }`, `Interrupt`, `Syscall`, `Unsupported { rip, text }`.

## Project layout

```
src/
  lib.rs              public re-exports
  emu.rs              Hades / Emu API: memory, registers, control
  error.rs            EmuError, MemAccess
  hooks.rs            hook registry and add_*_hook API
  memory.rs           guest memory regions and permissions
  jit/
    mod.rs            block cache, chaining, invalidation, jump cache
    classify.rs       instruction classification, flag liveness, memory operands
    translate.rs      guest -> host translation
    asm.rs            host code emitter
    regs.rs           register mapping and scratch allocation
  runtime/
    mod.rs            run loop, dispatcher, soft-TLB fill
    trampolines.rs    entry/exit/helper/indirect branch stubs
    state.rs          CpuState layout shared with generated code
    region.rs         executable region allocation
    interp.rs         string ops, xlat, enter, bt* with memory
    veh.rs            host fault -> guest exception
tests/                integration tests
examples/             bench (vs Unicorn), difftest (fuzzer), pe_run (Windows PE harness)
tools/                Unicorn counterparts and comparison scripts (Python, needs `unicorn`)
```

## Design

- **Registers stay in host registers.** Guest GPRs map 1:1 onto host GPRs, except that guest `rsp` lives in host `r15` and guest `r15` lives in memory. The host keeps its own `rsp`. Guest RFLAGS stay in host RFLAGS, and XMM/YMM/ZMM and x87 state stay live. Most instructions (`ALU`, `SSE/AVX`, `cpuid`, `rdtsc`, `lock` prefixed operations) run natively. They are only re encoded when they touch `rsp`/`r15` or memory.
- **Soft TLB.** Every memory operand goes through an inline, 4096-entry, direct mapped TLB with separate R/W/RW tags. One compare covers both the permission check and page crossing. The guest address is rewritten to `[host_ptr]`, so the original instruction (`add [m], r`, `cmpxchg16b`, `movdqu`, `fxsave` …) still executes natively on host memory. Guest regions are host contiguous because adjacent mappings are merged.
- **Flag liveness.** The lookup clobbers arithmetic flags. A backward liveness pass inserts a cheap `lahf`/`seto` save/restore only where guest flags are live.
- **Control flow.** Direct branches are patched into chained `jmp rel32`s. `ret` and indirect `jmp`/`call` use an inline 64K entry jump cache. Stop and timeout checks are flag free (`jrcxz`) and sit only on backward edges and indirect branches.
- **Hooks are compiled in.** Code, block and memory hooks generate calls only where they apply. Callbacks run through one trampoline. While the guest's AVX/AVX-512 state is still in init state, it saves XMM0–15 and MXCSR directly, otherwise it uses XSAVEOPT.
- **Self modifying code.** Pages holding translated code never get a write TLB entry. A write to them invalidates the overlapping blocks. If the current block is invalidated, its code is cut right after the current instruction.
- **Precise exceptions.** Host faults raised by natively executed guest instructions go through a vectored exception handler. It rebuilds exact guest state (including scratch registers spilled at that point) and returns `Exception { vector, rip }` or calls interrupt hooks.
- **Interpreter fallback.** String instructions (with page chunked fast paths for `rep movs`/`rep stos`), `xlat`, `enter`, and `bt*` with a memory operand and register bit offset run in Rust.

## Verification

- `cargo test`: 26 integration tests covering semantics, hooks, faults, SMC, `until`/count/timeout, TF single stepping and vector-state preservation.

- Differential fuzzing against Unicorn, random programs exercising ALU ops, shifts, mul, `lea` with RSP/R15, high byte registers, `xchg`/`xadd`/`cmpxchg`, `setcc`/`cmovcc`, `bt*`, push/pop (including memory forms), `pushfq`/`popfq`, `lahf`/`sahf`, string ops with `std`, forward `jcc`, `call`/`ret`, RIP relative, FS relative and 32 bit addressing, and SSE. The generator tracks architecturally defined flags so it never compares undefined bits. 26,000 programs matched across three codegen modes

  ```
  DIFF_MODE=plain|hooks|count cargo run --release --example difftest -- 2000 <seed> target/c.jsonl
  python tools/difftest.py target/c.jsonl
  python tools/difftrace.py target/c.jsonl <case>   # first diverging instruction
  ```

## Limitations

- Host must be Windows x64 with XSAVE. The guest is 64 bit user mode only.
- `cpuid`, `rdtsc` and `rdrand` return host values, and guest AVX 512 works only if the host has it.
- Not emulated (yet) these return `EmuError::Unsupported`:
  - far `jmp`/`call`/`ret`, `iret`, `sysenter`/`sysexit`/`sysret`
  - segment register loads, and `pushf`/`popf` with 16 bit operand size
  - the guest XSAVE family
  - CET shadow stack instructions, `wrpkru`, TSX `xbegin`/`xabort`/`xend`, `monitor`/`mwait`
  - VSIB gathers scatters, and instructions with implicit `[rdi]`-style operands other than string ops (`maskmovdqu`, `movdir64b`)
- Privileged instructions raise `#GP`. TF and AC are never loaded into the host. A `popfq` that sets TF single steps like hardware. The next instruction executes, then `#DB` (vector 1, `EXC_DEBUG`) is raised with RIP after it.
- When a memory access faults while the guest's arithmetic flags are dead (overwritten before being read), the flag bits in the reported state are unspecified. Resuming is unaffected. `div`/`idiv` always keep precise flags.
- Hooks added or removed from inside a callback take effect at the next backward branch or indirect jump. `emu_stop()` from a code hook stops before the hooked instruction.
- Memory read hooks fire before the access and receive the current memory value. Write hooks fire after the access and receive the written value.
- The code cache is 128 MiB and is flushed when full.
