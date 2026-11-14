import ctypes
import os
import struct
import sys
import time

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INTR
from unicorn import UC_PROT_READ as R, UC_PROT_WRITE as W, UC_PROT_EXEC as X, UC_PROT_ALL as RWX
from unicorn.x86_const import *

STACK, STACK_SIZE = 0x0000_0010_0000_0000, 0x10_0000
TEB = 0x0000_0020_0000_0000
PEB, LDR, STRINGS = TEB + 0x1000, TEB + 0x2000, TEB + 0x8000
KUSER = 0x7FFE_0000
HEAP, HEAP_SIZE = 0x0000_0030_0000_0000, 0x400_0000
STUBS, STUB_SIZE = 0x0000_7FF7_0000_0000, 0x10000
RETURN_SENTINEL = STUBS + STUB_SIZE - 16
HEAP_HANDLE = 0x0000_0030_DEAD_0000
SYSTEM_DLLS = [("ntdll.dll", 0x7FFA_0000_0000), ("kernel32.dll", 0x7FFA_1000_0000), ("kernelbase.dll", 0x7FFA_2000_0000)]
M64 = (1 << 64) - 1
VERBOSE = bool(os.environ.get("HADES_VERBOSE"))

GPRS = [("rax", UC_X86_REG_RAX), ("rcx", UC_X86_REG_RCX), ("rdx", UC_X86_REG_RDX), ("rbx", UC_X86_REG_RBX),
        ("rsp", UC_X86_REG_RSP), ("rbp", UC_X86_REG_RBP), ("rsi", UC_X86_REG_RSI), ("rdi", UC_X86_REG_RDI),
        ("r8", UC_X86_REG_R8), ("r9", UC_X86_REG_R9), ("r10", UC_X86_REG_R10), ("r11", UC_X86_REG_R11),
        ("r12", UC_X86_REG_R12), ("r13", UC_X86_REG_R13), ("r14", UC_X86_REG_R14), ("r15", UC_X86_REG_R15)]


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


class Module:
    pass


def r64(uc, a): return u64(uc.mem_read(a, 8), 0)


def w64(uc, a, v):
    if a:
        try: uc.mem_write(a, struct.pack("<Q", v & M64))
        except UcError: pass


def w32(uc, a, v):
    if a:
        try: uc.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))
        except UcError: pass


def write(uc, a, data):
    try: uc.mem_write(a, bytes(data))
    except UcError: pass


def readable(uc, a, n):
    try:
        uc.mem_read(a, n)
        return True
    except UcError:
        return False


def read_cstr(uc, a):
    s = bytearray()
    while len(s) <= 512:
        try: c = uc.mem_read(a, 1)[0]
        except UcError: break
        if c == 0: break
        s.append(c); a += 1
    return s.decode("latin-1")


def read_wstr(uc, a):
    s = []
    while len(s) <= 512:
        try: c = u16(uc.mem_read(a, 2), 0)
        except UcError: break
        if c == 0: break
        s.append(c); a += 2
    return struct.pack(f"<{len(s)}H", *s).decode("utf-16-le", "replace")


def wstr(s): return s.encode("utf-16-le") + b"\0\0"


def map_image(uc, file, name, base, perms):
    pe = u32(file, 0x3c); opt = pe + 24
    nsec, opt_size = u16(file, pe + 6), u16(file, pe + 20)
    entry = u32(file, opt + 16)
    size = (u32(file, opt + 56) + 0xfff) & ~0xfff
    headers = u32(file, opt + 60)
    uc.mem_map(base, size, perms)
    uc.mem_write(base, file[:headers])
    sections = []
    for s in range(nsec):
        h = opt + opt_size + s * 40
        va, raw_size, raw_ptr = u32(file, h + 12), u32(file, h + 16), u32(file, h + 20)
        sections.append((va, u32(file, h + 8), u32(file, h + 36)))
        if raw_size > 0 and raw_ptr < len(file):
            uc.mem_write(base + va, file[raw_ptr:raw_ptr + raw_size])
    pref = u64(file, opt + 24)
    delta = (base - pref) & M64
    rrva, rsize = u32(file, opt + 152), u32(file, opt + 156)
    if delta and rrva:
        relocs = bytes(uc.mem_read(base + rrva, rsize))
        off = 0
        while off + 8 <= len(relocs):
            page, bsize = u32(relocs, off), u32(relocs, off + 4)
            if bsize < 8: break
            for k in range(off + 8, off + bsize, 2):
                ent = u16(relocs, k)
                at = base + page + (ent & 0xfff)
                if ent >> 12 == 10:
                    uc.mem_write(at, struct.pack("<Q", (r64(uc, at) + delta) & M64))
                elif ent >> 12 == 3:
                    v = u32(uc.mem_read(at, 4), 0)
                    uc.mem_write(at, struct.pack("<I", (v + delta) & 0xFFFFFFFF))
            off += bsize
    uc.mem_write(base + pe + 24 + 24, struct.pack("<Q", base))
    erva, esize = u32(file, opt + 112), u32(file, opt + 116)
    m = Module()
    m.name, m.base, m.size = name.lower(), base, size
    m.entry = base + entry if entry else 0
    m.exports, m.ordinals, m.by_addr, m.export_dir, m.sections = {}, {}, {}, (erva, esize), sections
    if erva:
        ed = bytes(uc.mem_read(base + erva, 40))
        obase, nfun, nnames = u32(ed, 16), u32(ed, 20), u32(ed, 24)
        afun, anames, aords = u32(ed, 28), u32(ed, 32), u32(ed, 36)
        funcs = bytes(uc.mem_read(base + afun, nfun * 4))
        names = bytes(uc.mem_read(base + anames, nnames * 4))
        ords = bytes(uc.mem_read(base + aords, nnames * 2))
        for k in range(nfun):
            m.ordinals[obase + k] = u32(funcs, k * 4)
        for k in range(nnames):
            n = read_cstr(uc, base + u32(names, k * 4))
            rva = u32(funcs, u16(ords, k * 2) * 4)
            if not (erva <= rva < erva + esize):
                m.by_addr[base + rva] = f"{m.name}!{n}"
            m.exports[n] = rva
    return m


class Env:
    def __init__(self, exe_path, image_base, modules):
        self.modules = modules
        self.stubs, self.by_name, self.next_stub = {}, {}, STUBS
        self.heap_top, self.heap_sizes, self.fls = HEAP, {}, []
        self.image_base, self.exe_path = image_base, exe_path
        self.calls, self.unknown, self.syscalls = [], {}, []
        self.exited = self.stray = None
        self.sections, self.next_map, self.sysnames = {}, 0x7FFB_0000_0000, {}
        self.vm_top, self.hidden = 0x0000_0040_0000_0000, False
        self.files, self.file_sections, self.next_handle = {}, {}, 0x700
        self.prot, self.instr_cb, self.sys_stubs = {}, 0, set()

    def stub_for(self, name):
        if name in self.by_name: return self.by_name[name]
        a = self.next_stub; self.next_stub += 16
        self.stubs[a] = name; self.by_name[name] = a
        return a

    def module(self, name):
        n = name.lower()
        if n.startswith("api-ms-win-") or n.startswith("ext-ms-"): n = "kernelbase.dll"
        if not n.endswith(".dll") and not n.endswith(".exe"): n += ".dll"
        return next((m for m in self.modules if m.name == n), None)

    def alloc(self, size):
        p = (self.heap_top + 15) & ~15
        self.heap_top = p + max(size, 1)
        assert self.heap_top < HEAP + HEAP_SIZE
        self.heap_sizes[p] = size
        return p


def resolve(uc, env, dll, func, depth):
    m = env.module(dll)
    if m is None: return None
    if func.startswith("#"):
        rva = m.ordinals.get(int(func[1:]))
    else:
        rva = m.exports.get(func)
    if rva is None: return None
    erva, esize = m.export_dir
    if erva <= rva < erva + esize:
        if depth >= 4: return None
        fwd = read_cstr(uc, m.base + rva)
        if "." not in fwd: return None
        d, f = fwd.split(".", 1)
        return resolve(uc, env, d, f, depth + 1)
    return m.base + rva


def arg(uc, n):
    regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    if n < 4: return uc.reg_read(regs[n])
    return r64(uc, uc.reg_read(UC_X86_REG_RSP) + 8 * (n + 1))


def win_perm(p):
    return {0x02: R, 0x04: R | W, 0x08: R | W, 0x10: X, 0x20: R | X, 0x40: RWX, 0x80: RWX}.get(p & 0xFF, 0)


def set_prot(uc, env, lo, size, new):
    old = env.prot.get(lo, 0x40)
    for p in range(lo, lo + size, 0x1000):
        env.prot[p] = new
    try: uc.mem_protect(lo, size, win_perm(new))
    except UcError: pass
    return old


def oa_name(uc, oa):
    try:
        us = r64(uc, oa + 0x10)
        if not us: return ""
        return read_wstr(uc, r64(uc, us + 8))
    except UcError:
        return ""


def api(uc, env, name):
    a = [arg(uc, i) for i in range(6)]
    ret = api_impl(uc, env, name)
    if VERBOSE:
        print(f"  call {name}({', '.join(hex(x) for x in a)}) = {hex(ret & M64)}")
    return ret & M64


def api_impl(uc, env, name):
    short = name.rsplit("!", 1)[-1]
    A = lambda n: arg(uc, n)
    if short in ("GetSystemTimeAsFileTime", "GetSystemTimePreciseAsFileTime"):
        w64(uc, A(0), 0x01DB_0000_0000_0000); return 0
    if short in ("QueryPerformanceCounter", "RtlQueryPerformanceCounter"):
        w64(uc, A(0), 123_456_789); return 1
    if short in ("QueryPerformanceFrequency", "RtlQueryPerformanceFrequency"):
        w64(uc, A(0), 10_000_000); return 1
    if short in ("GetTickCount64", "GetTickCount"): return 1_000_000
    if short == "GetCurrentProcessId": return 0x1000
    if short == "GetCurrentThreadId": return 0x1004
    if short == "GetCurrentProcess": return M64
    if short == "GetCurrentThread": return M64 - 1
    if short in ("IsProcessorFeaturePresent", "RtlIsProcessorFeaturePresent"): return int(A(0) in (10, 17, 23))
    if short in ("InitializeSListHead", "RtlInitializeSListHead"):
        write(uc, A(0), bytes(16)); return 0
    if short in ("InterlockedFlushSList", "RtlInterlockedFlushSList", "IsDebuggerPresent",
                 "SetUnhandledExceptionFilter", "UnhandledExceptionFilter", "SetConsoleCtrlHandler"): return 0
    if short in ("GetModuleHandleW", "GetModuleHandleA", "LoadLibraryExW", "LoadLibraryW", "LoadLibraryA", "LoadLibraryExA"):
        p = A(0)
        if p == 0: return env.image_base
        n = read_cstr(uc, p) if short.endswith("A") else read_wstr(uc, p)
        m = env.module(n.rsplit("\\", 1)[-1])
        return m.base if m else 0
    if short == "GetModuleHandleExW":
        w64(uc, A(2), env.image_base); return 1
    if short == "FreeLibrary": return 1
    if short == "GetProcAddress":
        h, p = A(0), A(1)
        f = f"#{p}" if p < 0x10000 else read_cstr(uc, p)
        m = next((m for m in env.modules if m.base == h), None)
        return (resolve(uc, env, m.name, f, 0) or 0) if m else 0
    if short == "GetModuleFileNameW":
        path = wstr("C:\\guest\\app.exe"); write(uc, A(1), path); return len(path) // 2 - 1
    if short == "GetStartupInfoW":
        s = bytearray(0x68); s[0] = 0x68; write(uc, A(0), s); return 0
    if short == "GetCommandLineA": return STRINGS
    if short == "GetCommandLineW": return STRINGS + 0x100
    if short == "GetEnvironmentStringsW": return STRINGS + 0x200
    if short == "FreeEnvironmentStringsW": return 1
    if short == "GetStdHandle": return 0x100 + ((-A(0)) & 0xFFFFFFFF)
    if short == "GetFileType": return 1
    if short == "GetConsoleMode": return 0
    if short in ("GetConsoleOutputCP", "GetACP"): return 1252
    if short == "GetOEMCP": return 437
    if short in ("IsValidCodePage", "IsValidLocale", "AreFileApisANSI"): return 1
    if short == "GetCPInfo":
        s = bytearray(20); s[0] = 1; s[4] = ord("?"); write(uc, A(1), s); return 1
    if short == "GetUserDefaultLCID": return 0x409
    if short == "MultiByteToWideChar":
        src, n, dst, cap = A(2), A(3) & 0xFFFFFFFF, A(4), A(5)
        n = n - (1 << 32) if n & 0x80000000 else n
        data = (read_cstr(uc, src).encode("latin-1") + b"\0") if n < 0 else bytes(uc.mem_read(src, n)) if n else b""
        if cap and dst: write(uc, dst, b"".join(struct.pack("<H", c) for c in data[:cap]))
        return len(data)
    if short == "WideCharToMultiByte":
        src, n, dst, cap = A(2), A(3) & 0xFFFFFFFF, A(4), A(5)
        n = n - (1 << 32) if n & 0x80000000 else n
        if n < 0:
            s = read_wstr(uc, src).encode("utf-16-le")
            chars = list(struct.unpack(f"<{len(s) // 2}H", s)) + [0]
        else:
            raw = bytes(uc.mem_read(src, n * 2)) if n else b""
            chars = list(struct.unpack(f"<{n}H", raw))
        if cap and dst: write(uc, dst, bytes(c if c < 0x80 else ord("?") for c in chars[:cap]))
        return len(chars)
    if short == "GetStringTypeW":
        src, n, out = A(1), A(2) & 0xFFFFFFFF, A(3)
        n = len(read_wstr(uc, src)) + 1 if n & 0x80000000 else n
        types = bytearray()
        for i in range(n):
            try: c = u16(uc.mem_read(src + 2 * i, 2), 0)
            except UcError: c = 0
            ch = chr(c) if c < 0x80 else "\0"
            t = 0
            if ch.isupper(): t |= 1
            if ch.islower(): t |= 2
            if ch.isdigit(): t |= 4
            if ch in " \t\n\x0b\x0c\r": t |= 8
            if 0x21 <= c <= 0x7e and not ch.isalnum(): t |= 0x10
            if c < 0x20 or c == 0x7f: t |= 0x20
            if ch == " ": t |= 0x40
            if ch in "0123456789abcdefABCDEF": t |= 0x80
            if ch.isalpha(): t |= 0x100
            types += struct.pack("<H", t)
        write(uc, out, types); return 1
    if short in ("LCMapStringW", "LCMapStringEx"):
        src, n, dst, cap = A(2), A(3) & 0xFFFFFFFF, A(4), A(5)
        n = len(read_wstr(uc, src)) + 1 if n & 0x80000000 else n
        if cap and dst: write(uc, dst, uc.mem_read(src, n * 2))
        return n
    if short == "CompareStringW": return 2
    if short in ("GetProcessHeap",): return HEAP_HANDLE
    if short in ("HeapAlloc", "RtlAllocateHeap"):
        flags, size = A(1), A(2)
        p = env.alloc(size)
        if flags & 8: write(uc, p, bytes(size))
        return p
    if short in ("HeapFree", "RtlFreeHeap"): return 1
    if short in ("HeapSize", "RtlSizeHeap"): return env.heap_sizes.get(A(2), M64)
    if short in ("HeapReAlloc", "RtlReAllocateHeap"):
        old, size = A(2), A(3)
        p = env.alloc(size)
        n = min(env.heap_sizes.get(old, 0), size)
        if n: write(uc, p, uc.mem_read(old, n))
        return p
    if short == "FlsAlloc":
        env.fls.append(0); return len(env.fls) - 1
    if short == "FlsFree": return 1
    if short == "FlsGetValue":
        i = A(0); return env.fls[i] if i < len(env.fls) else 0
    if short == "FlsSetValue":
        i = A(0)
        if i < len(env.fls): env.fls[i] = A(1)
        return 1
    if short in ("InitializeCriticalSectionEx", "InitializeCriticalSectionAndSpinCount", "RtlInitializeCriticalSectionEx"):
        write(uc, A(0), bytes(40)); return 1
    if short in ("EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection", "RtlEnterCriticalSection",
                 "RtlLeaveCriticalSection", "RtlDeleteCriticalSection"): return 0
    if short in ("EncodePointer", "DecodePointer", "RtlEncodePointer", "RtlDecodePointer"): return A(0)
    if short in ("GetLastError", "RtlGetLastWin32Error"): return u32(uc.mem_read(TEB + 0x68, 4), 0)
    if short in ("SetLastError", "RtlSetLastWin32Error"):
        w32(uc, TEB + 0x68, A(0)); return 0
    if short == "VirtualProtect":
        addr, size, new = A(0), A(1), A(2) & 0xFFFFFFFF
        lo = addr & ~0xFFF
        old = set_prot(uc, env, lo, ((addr + size + 0xFFF) & ~0xFFF) - lo, new)
        w32(uc, A(3), old); return 1
    if short in ("VMProtectBeginVirtualization", "VMProtectBeginUltra", "VMProtectBeginMutation", "VMProtectEnd"): return 0
    if short in ("ZwOpenSection", "NtOpenSection"):
        us = r64(uc, A(2) + 0x10)
        n = read_wstr(uc, r64(uc, us + 8))
        h = 0x500 + 4 * len(env.sections)
        env.sections[h] = n.rsplit("\\", 1)[-1].lower()
        w64(uc, A(0), h); return 0
    if short in ("ZwMapViewOfSection", "NtMapViewOfSection"):
        h, base = A(0), env.next_map
        if h in env.file_sections:
            fh, image = env.file_sections[h]
            data = env.files[fh][0]
            if image:
                size = map_image(uc, data, "view", base, R | X).size
            else:
                size = (len(data) + 0xFFF) & ~0xFFF
                uc.mem_map(base, size, R); uc.mem_write(base, data)
        else:
            if h not in env.sections: return 0xC000_0008
            try: f = open(f"C:\\Windows\\System32\\{env.sections[h]}", "rb").read()
            except OSError: return 0xC000_0034
            size = map_image(uc, f, env.sections[h], base, R | X).size
        env.next_map += (size + 0xFFFF) & ~0xFFFF
        w64(uc, A(2), base); w64(uc, A(6), size); return 0
    if short in ("ZwUnmapViewOfSection", "NtUnmapViewOfSection"): return 0
    if short in ("ZwClose", "NtClose", "CloseHandle"):
        h = A(0)
        known = (env.sections.pop(h, None) is not None) | (env.files.pop(h, None) is not None) | (env.file_sections.pop(h, None) is not None)
        return 0 if known else 0xC000_0008
    if short in ("ZwOpenFile", "NtOpenFile", "ZwCreateFile", "NtCreateFile"):
        n = oa_name(uc, A(2)).lower()
        if not n.endswith("\\app.exe"): return 0xC000_0034
        h = env.next_handle; env.next_handle += 4
        env.files[h] = [open(env.exe_path, "rb").read(), 0]
        w64(uc, A(0), h); w64(uc, A(3), 0); w64(uc, A(3) + 8, 1); return 0
    if short in ("ZwQueryInformationFile", "NtQueryInformationFile"):
        h, iosb, buf, ln, cls = A(0), A(1), A(2), A(3), A(4)
        if h not in env.files: return 0xC000_0008
        data, pos = env.files[h]
        write(uc, buf, bytes(ln))
        if cls == 5:
            w64(uc, buf, (len(data) + 0xFFF) & ~0xFFF); w64(uc, buf + 8, len(data)); w32(uc, buf + 16, 1)
        elif cls == 14:
            w64(uc, buf, pos)
        w64(uc, iosb, 0); w64(uc, iosb + 8, ln); return 0
    if short in ("ZwReadFile", "NtReadFile"):
        h, iosb, buf, ln, offp = A(0), A(4), A(5), A(6), A(7)
        off = r64(uc, offp) if offp else None
        if h not in env.files: return 0xC000_0008
        f = env.files[h]
        start = f[1] if off is None else off
        if start >= len(f[0]): return 0xC000_0011
        n = min(ln, len(f[0]) - start)
        f[1] = start + n
        write(uc, buf, f[0][start:start + n]); w64(uc, iosb, 0); w64(uc, iosb + 8, n); return 0
    if short in ("ZwCreateSection", "NtCreateSection"):
        out, attrs, fh = A(0), A(5), A(6)
        if fh not in env.files: return 0xC000_0008
        h = env.next_handle; env.next_handle += 4
        env.file_sections[h] = (fh, attrs & 0x0100_0000 != 0)
        w64(uc, out, h); return 0
    if short in ("ZwQueryInformationProcess", "NtQueryInformationProcess"):
        cls, buf, ln, retlen = A(1), A(2), A(3), A(4)
        if (ln and buf % 4) or (retlen and retlen % 4): return 0x8000_0002
        if (ln and not readable(uc, buf, ln)) or (retlen and not readable(uc, retlen, 4)): return 0xC000_0005
        need = {0: 0x30, 0x7: 8, 0x1E: 8, 0x1F: 4}.get(cls, ln)
        if ln != need: return 0xC000_0004
        write(uc, buf, bytes(ln))
        status = 0
        if cls == 0: w64(uc, buf + 8, PEB)
        elif cls == 0x1E: status = 0xC000_0353
        elif cls == 0x1F: w32(uc, buf, 1)
        if retlen: w32(uc, retlen, need)
        return status
    if short in ("ZwCreateDebugObject", "NtCreateDebugObject"):
        w64(uc, A(0), 0x600); env.sections[0x600] = "<debug object>"; return 0
    if short in ("ZwQueryObject", "NtQueryObject") and A(1) == 2:
        buf, ln, retlen = A(2), A(3), A(4)
        nm = wstr("DebugObject")
        need = 0x68 + len(nm)
        if ln < need:
            w32(uc, retlen, need); return 0xC000_0004
        info = bytearray(need)
        struct.pack_into("<HH", info, 0, len(nm) - 2, len(nm))
        struct.pack_into("<Q", info, 8, buf + 0x68)
        struct.pack_into("<II", info, 0x10, 1, 1)
        info[0x68:] = nm
        write(uc, buf, info)
        w32(uc, retlen, need); return 0
    if short in ("ZwSetInformationThread", "NtSetInformationThread") and A(1) == 0x11:
        if A(3) != 0: return 0xC000_0004
        env.hidden = True; return 0
    if short in ("ZwQueryInformationThread", "NtQueryInformationThread") and A(1) == 0x11:
        if A(3) != 1: return 0xC000_0004
        write(uc, A(2), bytes([int(env.hidden)])); w32(uc, A(4), 1); return 0
    if short in ("ZwQuerySystemInformation", "NtQuerySystemInformation"):
        cls, buf, ln = A(0), A(1), A(2)
        write(uc, buf, bytes(ln))
        if cls == 0x23: write(uc, buf, bytes([0, 1]))
        return 0
    if short in ("ZwSetInformationProcess", "NtSetInformationProcess") and A(1) == 0x28:
        env.instr_cb = r64(uc, A(2) + 8); return 0
    if short in ("ZwSetInformationThread", "NtSetInformationThread", "ZwSetInformationProcess", "NtSetInformationProcess"): return 0
    if short in ("ZwProtectVirtualMemory", "NtProtectVirtualMemory"):
        pbase, psize, new = A(1), A(2), A(3) & 0xFFFFFFFF
        addr, size = r64(uc, pbase), r64(uc, psize)
        lo = addr & ~0xFFF
        hi = (addr + max(size, 1) + 0xFFF) & ~0xFFF
        if lo not in env.prot: return 0xC000_0045
        old = set_prot(uc, env, lo, hi - lo, new)
        w64(uc, pbase, lo); w64(uc, psize, hi - lo); w32(uc, A(4), old); return 0
    if short in ("ZwFreeVirtualMemory", "NtFreeVirtualMemory", "VirtualFree"): return 0
    if short in ("ExitProcess", "TerminateProcess", "RtlExitUserProcess"):
        env.exited = A(1 if short == "TerminateProcess" else 0); uc.emu_stop(); return 0
    if short in ("CreateFileW", "CreateFileA"): return M64
    env.unknown[name] = env.unknown.get(name, 0) + 1
    return 0


def build_ldr(uc, mods):
    entry = lambda k: LDR + 0x100 + k * 0x300
    w32(uc, LDR, 0x58); w32(uc, LDR + 4, 1)
    for k, (name, base, size, ep) in enumerate(mods):
        en = entry(k)
        w64(uc, en + 0x30, base); w64(uc, en + 0x38, ep); w32(uc, en + 0x40, size)
        for off, s, at in ((0x48, f"C:\\Windows\\System32\\{name}", en + 0x100), (0x58, name, en + 0x200)):
            w = wstr(s); uc.mem_write(at, w)
            ln = len(w) - 2
            uc.mem_write(en + off, struct.pack("<HH", ln, ln + 2)); w64(uc, en + off + 8, at)
    for lst, skip_exe in ((0x10, False), (0x20, False), (0x30, True)):
        nodes = [entry(k) + lst - 0x10 for k in range(len(mods)) if not (skip_exe and k == 0)]
        allp = [LDR + lst] + nodes
        for i, n in enumerate(allp):
            w64(uc, n, allp[(i + 1) % len(allp)]); w64(uc, n + 8, allp[(i - 1) % len(allp)])


def main():
    path = sys.argv[1]
    stop = int(sys.argv[2], 16) if len(sys.argv) > 2 else M64
    file = open(path, "rb").read()
    opt = u32(file, 0x3c) + 24
    image_base = u64(file, opt + 24)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    exe = map_image(uc, file, "app.exe", image_base, RWX)
    modules = [exe] + [map_image(uc, open(f"C:\\Windows\\System32\\{n}", "rb").read(), n, b, R | X) for n, b in SYSTEM_DLLS]
    uc.mem_map(STACK, STACK_SIZE, R | W)
    uc.mem_map(TEB, 0x10000, R | W)
    uc.mem_map(HEAP, HEAP_SIZE, R | W)
    uc.mem_map(STUBS, STUB_SIZE, R | X)
    uc.mem_write(STUBS, b"\xCC" * STUB_SIZE)
    uc.mem_map(KUSER, 0x1000, R)
    kuser = bytes((ctypes.c_ubyte * 0x1000).from_address(KUSER))
    uc.mem_write(KUSER, kuser)
    for a, v in ((TEB + 0x08, STACK + STACK_SIZE), (TEB + 0x10, STACK), (TEB + 0x30, TEB), (TEB + 0x40, 0x1000),
                 (TEB + 0x48, 0x1004), (TEB + 0x60, PEB), (PEB + 0x10, image_base), (PEB + 0x18, LDR), (PEB + 0x30, HEAP_HANDLE)):
        w64(uc, a, v)
    w32(uc, PEB + 0x118, 10); w32(uc, PEB + 0x11C, 0); w32(uc, PEB + 0x120, u32(kuser, 0x260))
    build_ldr(uc, [(m.name, m.base, m.size, m.entry) for m in modules])
    uc.mem_write(STRINGS, b"app.exe\0"); uc.mem_write(STRINGS + 0x100, wstr("app.exe")); uc.mem_write(STRINGS + 0x200, bytes(4))
    uc.reg_write(UC_X86_REG_GS_BASE, TEB)
    uc.reg_write(UC_X86_REG_RFLAGS, 0x202)
    env = Env(path, image_base, modules)

    imp_rva = u32(file, opt + 120)
    d = image_base + imp_rva
    while imp_rva:
        desc = bytes(uc.mem_read(d, 20))
        ilt, name_rva, iat = u32(desc, 0), u32(desc, 12), u32(desc, 16)
        if name_rva == 0: break
        dll = read_cstr(uc, image_base + name_rva)
        lookup = ilt or iat
        k = 0
        while True:
            ent = r64(uc, image_base + lookup + 8 * k)
            if ent == 0: break
            f = f"#{ent & 0xffff}" if ent >> 63 else read_cstr(uc, image_base + (ent & 0x7fff_ffff) + 2)
            addr = resolve(uc, env, dll, f, 0) or env.stub_for(f"{dll}!{f}")
            w64(uc, image_base + iat + 8 * k, addr)
            k += 1
        d += 20

    set_prot(uc, env, exe.base, exe.size, 0x02)
    for va, vsize, ch in exe.sections:
        r, w, x = ch & 0x4000_0000, ch & 0x8000_0000, ch & 0x2000_0000
        p = 0x40 if x and w else 0x20 if x else 0x04 if w else 0x02 if r else 0x01
        set_prot(uc, env, exe.base + va, (vsize + 0xFFF) & ~0xFFF, p)
    sp = STACK + STACK_SIZE - 0x1000
    uc.reg_write(UC_X86_REG_RSP, sp)
    w64(uc, sp, RETURN_SENTINEL)

    ntdll = env.module("ntdll.dll")
    for a, n in ntdll.by_addr.items():
        b = bytes(uc.mem_read(a, 8))
        if b[:4] == b"\x4C\x8B\xD1\xB8":
            env.sysnames.setdefault(u32(b, 4), n.replace("!Nt", "!Zw"))
            env.sys_stubs.add(a)
    by_addr = {}
    for m in modules[1:]:
        by_addr.update(m.by_addr)

    def on_code(uc, addr, size, _):
        if addr == RETURN_SENTINEL:
            env.exited = uc.reg_read(UC_X86_REG_RAX); uc.emu_stop(); return
        if any((addr - k) in env.sys_stubs for k in range(0x20)):
            return
        name = env.stubs.get(addr) or by_addr.get(addr)
        if name is None:
            env.stray = addr; uc.emu_stop(); return
        caller = r64(uc, uc.reg_read(UC_X86_REG_RSP))
        env.calls.append((name, caller))
        ret = api(uc, env, name)
        if env.exited is not None: return
        uc.reg_write(UC_X86_REG_RAX, ret)
        uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
        uc.reg_write(UC_X86_REG_RIP, caller)

    for m in modules[1:]:
        uc.hook_add(UC_HOOK_CODE, on_code, None, m.base, m.base + m.size - 1)
    uc.hook_add(UC_HOOK_CODE, on_code, None, STUBS, STUBS + STUB_SIZE - 1)

    def on_syscall(uc, _):
        rip = uc.reg_read(UC_X86_REG_RIP)
        nxt = rip + 2 if bytes(uc.mem_read(rip, 2)) == b"\x0f\x05" else rip
        nr = uc.reg_read(UC_X86_REG_RAX)
        env.syscalls.append((nr, nxt))
        name = env.sysnames.get(nr, f"syscall#{nr:x}")
        uc.reg_write(UC_X86_REG_RCX, uc.reg_read(UC_X86_REG_R10))
        env.calls.append((f"[syscall] {name}", nxt))
        ret = api(uc, env, name)
        uc.reg_write(UC_X86_REG_RAX, ret)
        uc.reg_write(UC_X86_REG_RCX, nxt)
        uc.reg_write(UC_X86_REG_R11, uc.reg_read(UC_X86_REG_RFLAGS))
        if env.instr_cb:
            uc.reg_write(UC_X86_REG_R10, nxt)
            uc.reg_write(UC_X86_REG_RIP, env.instr_cb - (nxt - rip))

    uc.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    def on_intr(uc, intno, _):
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"guest interrupt/exception {intno} at rip={rip:#x}")
        env.stray = rip; uc.emu_stop()

    uc.hook_add(UC_HOOK_INTR, on_intr)

    entry = exe.entry
    print(f"image {image_base:#x}, entry {entry:#x}")
    t = time.perf_counter()
    err = None
    try:
        uc.emu_start(entry, stop)
    except UcError as e:
        err = e
    el = time.perf_counter() - t
    print(f"result: {err} (errno {getattr(err, 'errno', None)}) after {el * 1e3:.1f} ms; rip={uc.reg_read(UC_X86_REG_RIP):#x}")
    print(f"exit: {env.exited}; stray execution: {env.stray}")
    print(f"{len(env.calls)} API calls, {len(env.syscalls)} direct syscalls")
    if env.unknown: print(f"unimplemented (returned 0): {env.unknown}")
    regs = " ".join(f"{n}={uc.reg_read(r):#x}" for n, r in GPRS)
    print(f"FINAL rip={uc.reg_read(UC_X86_REG_RIP):#x} rflags={uc.reg_read(UC_X86_REG_RFLAGS) & 0x8D5:#x} {regs}")
    if len(sys.argv) >= 6:
        lo, hi = int(sys.argv[3], 16), int(sys.argv[4], 16)
        dump = bytes(uc.mem_read(lo, hi - lo)) + bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 0x100))
        open(sys.argv[5], "wb").write(dump)
        print(f"dumped [{lo:#x},{hi:#x}) + 0x100 bytes at rsp to {sys.argv[5]}")


if __name__ == "__main__":
    main()
