import json
import subprocess
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from difftest import CODE, DATA, DATA_SIZE, STACK, STACK_SIZE, FS_BASE, GPRS, NAMES, XMMS


def unicorn_trace(case):
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
    out = []
    uc.hook_add(UC_HOOK_CODE, lambda u, a, s, _: out.append([a] + [u.reg_read(r) for r in GPRS] + [u.reg_read(UC_X86_REG_RFLAGS)]))
    uc.emu_start(CODE, CODE + len(code))
    out.append([uc.reg_read(UC_X86_REG_RIP)] + [uc.reg_read(r) for r in GPRS] + [uc.reg_read(UC_X86_REG_RFLAGS)])
    return out


def main():
    path, n = sys.argv[1], int(sys.argv[2])
    case = json.loads(open(path).readlines()[n])
    exe = "target/release/examples/difftest.exe"
    h = [json.loads(l) for l in subprocess.run([exe, "trace", path, str(n)], capture_output=True, text=True).stdout.splitlines()]
    u = unicorn_trace(case)
    listing = subprocess.run([exe, "dump", case["code"]], capture_output=True, text=True).stdout.splitlines()
    dis = {int(l.split(":")[0], 16): l for l in listing}
    for i, (a, b) in enumerate(zip(h, u)):
        diffs = [f"{NAMES[k]} h={a[k + 1]:#x} u={b[k + 1]:#x}" for k in range(16) if a[k + 1] != b[k + 1]]
        if a[0] != b[0]:
            diffs.append(f"rip h={a[0]:#x} u={b[0]:#x}")
        if diffs:
            prev = h[i - 1][0] if i else None
            print(f"diverged before step {i}; previous insn: {dis.get(prev, prev)}")
            print("  " + "; ".join(diffs))
            for j in range(max(0, i - 8), i + 1):
                print(f"    {dis.get(h[j][0], hex(h[j][0]))[:60]:60}  flags h={h[j][17] & 0x8d5:#05x} u={u[j][17] & 0x8d5:#05x}")
            print(f"  flags before prev: h={h[i - 1][17]:#x} u={u[i - 1][17]:#x}" if i else "")
            return
    print(f"no divergence in {min(len(h), len(u))} steps (lens {len(h)} {len(u)})")


if __name__ == "__main__":
    main()
