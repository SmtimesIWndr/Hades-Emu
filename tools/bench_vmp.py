import re
import subprocess
import sys

exe, stop = sys.argv[1], sys.argv[2]
hn = int(sys.argv[3]) if len(sys.argv) > 3 else 5
un = int(sys.argv[4]) if len(sys.argv) > 4 else 3


def run(cmd):
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    ms = float(re.search(r"after ([0-9.]+) ms", out).group(1))
    rip = re.search(r"^FINAL rip=(0x[0-9a-f]+)", out, re.M).group(1)
    return ms, rip


h = [run(["target/release/examples/pe_run.exe", exe, stop]) for _ in range(hn)]
u = [run([sys.executable, "tools/pe_run_unicorn.py", exe, stop]) for _ in range(un)]
rips = {r for _, r in h + u}
hb, ub = min(m for m, _ in h), min(m for m, _ in u)
print(f"hades   best {hb:9.1f} ms  runs {[round(m, 1) for m, _ in h]}")
print(f"unicorn best {ub:9.1f} ms  runs {[round(m, 1) for m, _ in u]}")
print(f"final rip: {sorted(rips)} ({'same for all runs' if len(rips) == 1 else 'DIFFERS'})")
print(f"speedup: {ub / hb:.1f}x")
