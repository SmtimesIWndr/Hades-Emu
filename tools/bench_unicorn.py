import json
import sys
import time

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, __version__
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RSP

b = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "target/bench.json"))
print(f"unicorn {__version__}")
print(f"{'workload':16} {'unicorn ms':>11} {'hades ms':>10} {'speedup':>8}")
for w in b["workloads"]:
    code = bytes.fromhex(w["code"])
    s = float("inf")
    for _ in range(3):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(b["code_base"], 0x10000)
        uc.mem_map(b["data"], b["data_size"])
        uc.mem_map(b["stack"], b["stack_size"])
        uc.mem_write(b["code_base"], code)
        uc.reg_write(UC_X86_REG_RSP, b["stack"] + b["stack_size"] - 0x1000)
        t = time.perf_counter()
        uc.emu_start(b["code_base"], b["code_base"] + len(code))
        s = min(s, time.perf_counter() - t)
        assert uc.reg_read(UC_X86_REG_RAX) == w["rax"], f"{w['name']}: result mismatch"
    print(f"{w['name']:16} {s * 1e3:>11.1f} {w['hades_s'] * 1e3:>10.1f} {s / w['hades_s']:>7.1f}x")

w = b["workloads"][0]
code = bytes.fromhex(w["code"])
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(b["code_base"], 0x10000)
uc.mem_map(b["stack"], b["stack_size"])
uc.mem_write(b["code_base"], code)
n = [0]


def hook(u, a, s, d):
    n[0] += 1


uc.hook_add(UC_HOOK_CODE, hook)
t = time.perf_counter()
uc.emu_start(b["code_base"], b["code_base"] + len(code), count=3_000_000)
s = time.perf_counter() - t
print(f"unicorn python code hook: {n[0]} hooks in {s * 1e3:.1f} ms = {s * 1e9 / n[0]:.1f} ns/hook")
