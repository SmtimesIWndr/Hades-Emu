import re
import sys


def calls(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s+call (\S+)\(.*\) = (0x[0-9a-f]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def final(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("FINAL"):
            return dict(kv.split("=") for kv in line.split()[1:])
    return {}


def main():
    hl, ul, hb, ub = sys.argv[1:5]
    hc, uc = calls(hl), calls(ul)
    n = min(len(hc), len(uc))
    first = next((i for i in range(n) if hc[i] != uc[i]), None)
    print(f"call sequence: hades {len(hc)}, unicorn {len(uc)}; " +
          ("identical" if first is None and len(hc) == len(uc) else f"first difference at #{first if first is not None else n}"))
    if first is not None:
        print(f"  hades:   {hc[first]}\n  unicorn: {uc[first]}")
    hf, uf = final(hl), final(ul)
    for k in ("rip", "rsp", "rflags"):
        print(f"final {k}: hades {hf.get(k)} unicorn {uf.get(k)}{'' if hf.get(k) == uf.get(k) else '  <-- differs'}")
    other = [k for k in hf if k not in ("rip", "rsp", "rflags") and hf[k] != uf.get(k)]
    print(f"other GPRs differing: {other or 'none'}")
    a, b = open(hb, "rb").read(), open(ub, "rb").read()
    diffs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    print(f"memory dump: {len(a)} bytes, {len(diffs)} differing" + (f" (first at offset {diffs[0]:#x})" if diffs else ""))


if __name__ == "__main__":
    main()
