import json
import sys

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import *

CODE, DATA, DATA_SIZE, STACK, STACK_SIZE, FS_BASE = 0x400000, 0x600000, 0x2000, 0x700000, 0x10000, 0x800
GPRS = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
XMMS = [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3]
FLAG_MASK = 0x8D5


def fnv(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def run_unicorn(case):
    code = bytes.fromhex(case["code"])
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x10000)
    uc.mem_map(DATA, DATA_SIZE)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_write(CODE, code)
    uc.mem_write(DATA, bytes.fromhex(case["data"]))
    for r, v in zip(GPRS, case["regs"]):
        uc.reg_write(r, v)
    uc.reg_write(UC_X86_REG_RFLAGS, 0x202)
    uc.reg_write(UC_X86_REG_FS_BASE, FS_BASE)
    for r, v in zip(XMMS, case["xmm"]):
        uc.reg_write(r, v)
    uc.emu_start(CODE, CODE + len(code))
    mem = bytes(uc.mem_read(DATA, DATA_SIZE)) + bytes(uc.mem_read(STACK, STACK_SIZE))
    return {
        "regs": [uc.reg_read(r) for r in GPRS],
        "rflags": uc.reg_read(UC_X86_REG_RFLAGS),
        "rip": uc.reg_read(UC_X86_REG_RIP),
        "memhash": fnv(mem),
        "xmm": [uc.reg_read(r) for r in XMMS],
    }


def main():
    path = sys.argv[1]
    total = ok = 0
    failures = []
    for line in open(path):
        case = json.loads(line)
        total += 1
        try:
            u = run_unicorn(case)
        except UcError as e:
            u = {"error": str(e)}
        h = case.get("out")
        diffs = []
        if h is None or "error" in u:
            if not (h is None and "error" in u):
                diffs.append(f"hades={case.get('error')} unicorn={u.get('error')}")
        else:
            for i, (a, b) in enumerate(zip(h["regs"], u["regs"])):
                if a != b:
                    diffs.append(f"{NAMES[i]}: hades={a:#x} unicorn={b:#x}")
            if (h["rflags"] ^ u["rflags"]) & FLAG_MASK:
                diffs.append(f"rflags: hades={h['rflags']:#x} unicorn={u['rflags']:#x}")
            if h["rip"] != u["rip"]:
                diffs.append(f"rip: hades={h['rip']:#x} unicorn={u['rip']:#x}")
            if h["memhash"] != u["memhash"]:
                diffs.append("memory differs")
            for i, (a, b) in enumerate(zip(h["xmm"], u["xmm"])):
                if a != b:
                    diffs.append(f"xmm{i}: hades={a:#x} unicorn={b:#x}")
        if diffs:
            failures.append((case["case"], diffs))
        else:
            ok += 1
    print(f"{ok}/{total} cases match")
    for c, d in failures[:15]:
        print(f"case {c}: " + "; ".join(d))
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
