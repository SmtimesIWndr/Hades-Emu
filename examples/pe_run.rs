use hades_emu::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

const STACK: u64 = 0x0000_0010_0000_0000;
const STACK_SIZE: u64 = 0x10_0000;
const TEB: u64 = 0x0000_0020_0000_0000;
const PEB: u64 = TEB + 0x1000;
const LDR: u64 = TEB + 0x2000;
const STRINGS: u64 = TEB + 0x8000;
const KUSER: u64 = 0x7FFE_0000;
const HEAP: u64 = 0x0000_0030_0000_0000;
const HEAP_SIZE: u64 = 0x400_0000;
const STUBS: u64 = 0x0000_7FF7_0000_0000;
const STUB_SIZE: u64 = 0x10000;
const RETURN_SENTINEL: u64 = STUBS + STUB_SIZE - 16;
const HEAP_HANDLE: u64 = 0x0000_0030_DEAD_0000;
const SYSTEM_DLLS: [(&str, u64); 3] =
    [("ntdll.dll", 0x7FFA_0000_0000), ("kernel32.dll", 0x7FFA_1000_0000), ("kernelbase.dll", 0x7FFA_2000_0000)];

fn rd<T: Copy>(b: &[u8], off: usize) -> T {
    unsafe { core::ptr::read_unaligned(b[off..].as_ptr() as *const T) }
}

struct Module {
    name: String,
    base: u64,
    size: u64,
    entry: u64,
    exports: HashMap<String, u32>,
    ordinals: HashMap<u32, u32>,
    export_dir: (u32, u32),
    by_addr: HashMap<u64, String>,
    sections: Vec<(u64, u64, u32)>,
}

fn map_image(emu: &mut Emu, file: &[u8], name: &str, base: u64, perms: u8) -> Module {
    let pe = rd::<u32>(file, 0x3c) as usize;
    let opt = pe + 24;
    let nsec = rd::<u16>(file, pe + 6) as usize;
    let opt_size = rd::<u16>(file, pe + 20) as usize;
    let entry = rd::<u32>(file, opt + 16) as u64;
    let size = (rd::<u32>(file, opt + 56) as u64 + 0xfff) & !0xfff;
    let headers = rd::<u32>(file, opt + 60) as usize;
    emu.mem_map(base, size, perms).unwrap();
    emu.mem_write(base, &file[..headers.min(file.len())]).unwrap();
    let mut sections = Vec::new();
    for s in 0..nsec {
        let h = opt + opt_size + s * 40;
        let (va, raw_size, raw_ptr) = (rd::<u32>(file, h + 12) as u64, rd::<u32>(file, h + 16) as usize, rd::<u32>(file, h + 20) as usize);
        sections.push((va, rd::<u32>(file, h + 8) as u64, rd::<u32>(file, h + 36)));
        if raw_size > 0 && raw_ptr < file.len() {
            emu.mem_write(base + va, &file[raw_ptr..(raw_ptr + raw_size).min(file.len())]).unwrap();
        }
    }
    let pref = rd::<u64>(file, opt + 24);
    let delta = base.wrapping_sub(pref);
    let (rrva, rsize) = (rd::<u32>(file, opt + 152) as u64, rd::<u32>(file, opt + 156) as u64);
    if delta != 0 && rrva != 0 {
        let relocs = emu.mem_read_vec(base + rrva, rsize as usize).unwrap();
        let mut off = 0usize;
        while off + 8 <= relocs.len() {
            let (page, bsize) = (rd::<u32>(&relocs, off) as u64, rd::<u32>(&relocs, off + 4) as usize);
            if bsize < 8 {
                break;
            }
            for k in (off + 8..off + bsize).step_by(2) {
                let ent = rd::<u16>(&relocs, k);
                let at = base + page + (ent & 0xfff) as u64;
                match ent >> 12 {
                    10 => {
                        let v = u64::from_le_bytes(emu.mem_read_vec(at, 8).unwrap().try_into().unwrap());
                        emu.mem_write(at, &v.wrapping_add(delta).to_le_bytes()).unwrap();
                    }
                    3 => {
                        let v = u32::from_le_bytes(emu.mem_read_vec(at, 4).unwrap().try_into().unwrap());
                        emu.mem_write(at, &v.wrapping_add(delta as u32).to_le_bytes()).unwrap();
                    }
                    _ => {}
                }
            }
            off += bsize;
        }
    }
    emu.mem_write(base + pe as u64 + 24 + 24, &base.to_le_bytes()).unwrap();
    let (erva, esize) = (rd::<u32>(file, opt + 112), rd::<u32>(file, opt + 116));
    let mut m = Module {
        name: name.to_ascii_lowercase(),
        base,
        size,
        entry: if entry != 0 { base + entry } else { 0 },
        exports: HashMap::new(),
        ordinals: HashMap::new(),
        export_dir: (erva, esize),
        by_addr: HashMap::new(),
        sections,
    };
    if erva != 0 {
        let ed = emu.mem_read_vec(base + erva as u64, 40).unwrap();
        let (obase, nfun, nnames) = (rd::<u32>(&ed, 16), rd::<u32>(&ed, 20), rd::<u32>(&ed, 24));
        let (afun, anames, aords) = (rd::<u32>(&ed, 28) as u64, rd::<u32>(&ed, 32) as u64, rd::<u32>(&ed, 36) as u64);
        let funcs = emu.mem_read_vec(base + afun, nfun as usize * 4).unwrap();
        let names = emu.mem_read_vec(base + anames, nnames as usize * 4).unwrap();
        let ords = emu.mem_read_vec(base + aords, nnames as usize * 2).unwrap();
        for k in 0..nfun as usize {
            m.ordinals.insert(obase + k as u32, rd::<u32>(&funcs, k * 4));
        }
        for k in 0..nnames as usize {
            let n = read_cstr(emu, base + rd::<u32>(&names, k * 4) as u64);
            let rva = rd::<u32>(&funcs, rd::<u16>(&ords, k * 2) as usize * 4);
            if !(erva..erva + esize).contains(&rva) {
                m.by_addr.insert(base + rva as u64, format!("{}!{n}", m.name));
            }
            m.exports.insert(n, rva);
        }
    }
    m
}

struct Env {
    modules: Vec<Module>,
    stubs: HashMap<u64, String>,
    by_name: HashMap<String, u64>,
    next_stub: u64,
    heap_top: u64,
    heap_sizes: HashMap<u64, u64>,
    fls: Vec<u64>,
    image_base: u64,
    out: Vec<u8>,
    calls: Vec<(String, u64)>,
    unknown: HashMap<String, u64>,
    syscalls: Vec<(u64, u64)>,
    exited: Option<u64>,
    stray: Option<u64>,
    sections: HashMap<u64, String>,
    next_map: u64,
    sysnames: HashMap<u64, String>,
    vm_top: u64,
    hidden: bool,
    exe_path: String,
    files: HashMap<u64, (Vec<u8>, u64)>,
    file_sections: HashMap<u64, (u64, bool)>,
    next_handle: u64,
    prot: HashMap<u64, u32>,
    instr_cb: u64,
    sys_stubs: std::collections::HashSet<u64>,
}

impl Env {
    fn stub_for(&mut self, name: &str) -> u64 {
        if let Some(&a) = self.by_name.get(name) {
            return a;
        }
        let a = self.next_stub;
        self.next_stub += 16;
        self.stubs.insert(a, name.to_string());
        self.by_name.insert(name.to_string(), a);
        a
    }

    fn module(&self, name: &str) -> Option<&Module> {
        let mut n = name.to_ascii_lowercase();
        if n.starts_with("api-ms-win-") || n.starts_with("ext-ms-") {
            n = "kernelbase.dll".into();
        }
        if !n.ends_with(".dll") && !n.ends_with(".exe") {
            n.push_str(".dll");
        }
        self.modules.iter().find(|m| m.name == n)
    }

    fn alloc(&mut self, size: u64) -> u64 {
        let p = (self.heap_top + 15) & !15;
        self.heap_top = p + size.max(1);
        assert!(self.heap_top < HEAP + HEAP_SIZE, "guest heap exhausted");
        self.heap_sizes.insert(p, size);
        p
    }
}

fn resolve(e: &Emu, env: &Env, dll: &str, func: &str, depth: u32) -> Option<u64> {
    let m = env.module(dll)?;
    let rva = if let Some(o) = func.strip_prefix('#') { *m.ordinals.get(&o.parse().ok()?)? } else { *m.exports.get(func)? };
    let (erva, esize) = m.export_dir;
    if (erva..erva + esize).contains(&rva) {
        if depth >= 4 {
            return None;
        }
        let fwd = read_cstr(e, m.base + rva as u64);
        let (d, f) = fwd.split_once('.')?;
        return resolve(e, env, d, f, depth + 1);
    }
    Some(m.base + rva as u64)
}

fn read_cstr(e: &Emu, mut a: u64) -> String {
    let mut s = Vec::new();
    while let Ok(b) = e.mem_read_vec(a, 1) {
        if b[0] == 0 || s.len() > 512 {
            break;
        }
        s.push(b[0]);
        a += 1;
    }
    String::from_utf8_lossy(&s).into_owned()
}

fn read_wstr(e: &Emu, mut a: u64) -> String {
    let mut s = Vec::new();
    while let Ok(b) = e.mem_read_vec(a, 2) {
        let c = u16::from_le_bytes([b[0], b[1]]);
        if c == 0 || s.len() > 512 {
            break;
        }
        s.push(c);
        a += 2;
    }
    String::from_utf16_lossy(&s)
}

fn wstr(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(|c| c.to_le_bytes()).collect()
}
fn w64(e: &mut Emu, a: u64, v: u64) {
    if a != 0 {
        let _ = e.mem_write(a, &v.to_le_bytes());
    }
}
fn w32(e: &mut Emu, a: u64, v: u32) {
    if a != 0 {
        let _ = e.mem_write(a, &v.to_le_bytes());
    }
}
fn r64(e: &Emu, a: u64) -> u64 {
    u64::from_le_bytes(e.mem_read_vec(a, 8).unwrap().try_into().unwrap())
}
fn arg(e: &Emu, n: u64) -> u64 {
    match n {
        0 => e.reg_read(Reg::RCX),
        1 => e.reg_read(Reg::RDX),
        2 => e.reg_read(Reg::R8),
        3 => e.reg_read(Reg::R9),
        _ => r64(e, e.reg_read(Reg::RSP) + 8 * (n + 1)),
    }
}

fn win_perm(p: u32) -> u8 {
    match p & 0xFF {
        0x02 => PERM_READ,
        0x04 | 0x08 => PERM_READ | PERM_WRITE,
        0x10 => PERM_EXEC,
        0x20 => PERM_READ | PERM_EXEC,
        0x40 | 0x80 => PERM_ALL,
        _ => 0,
    }
}

fn set_prot(e: &mut Emu, env: &mut Env, lo: u64, size: u64, new: u32) -> u32 {
    let old = env.prot.get(&lo).copied().unwrap_or(0x40);
    let mut p = lo;
    while p < lo + size {
        env.prot.insert(p, new);
        p += 0x1000;
    }
    let _ = e.mem_protect(lo, size, win_perm(new));
    old
}

fn oa_name(e: &Emu, oa: u64) -> String {
    e.mem_read_vec(oa + 0x10, 8)
        .ok()
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .filter(|&us| us != 0)
        .and_then(|us| e.mem_read_vec(us + 8, 8).ok().map(|b| u64::from_le_bytes(b.try_into().unwrap())))
        .map(|p| read_wstr(e, p))
        .unwrap_or_default()
}

fn api(e: &mut Emu, env: &mut Env, name: &str) -> u64 {
    let a: Vec<u64> = (0..6).map(|i| arg(e, i)).collect();
    let ret = api_impl(e, env, name);
    if std::env::var_os("HADES_VERBOSE").is_some() {
        let short = name.rsplit('!').next().unwrap();
        let extra = match short {
            "ZwOpenFile" | "ZwCreateFile" | "ZwOpenSection" | "ZwOpenKey" | "ZwQueryAttributesFile" => format!(" name={:?}", oa_name(e, a[2])),
            "ZwWriteFile" => format!(" data={:?}", String::from_utf8_lossy(&e.mem_read_vec(a[5], (arg(e, 6) as usize).min(256)).unwrap_or_default())),
            "ZwProtectVirtualMemory" => format!(" range={:#x}+{:#x} old={:#x}", r64(e, a[1]), r64(e, a[2]), e.mem_read_vec(a[4], 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)),
            "ZwRaiseHardError" => {
                let us = |k: u64| e.mem_read_vec(a[3] + 8 * k, 8).ok().map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
                let text = |p: u64| e.mem_read_vec(p + 8, 8).ok().map(|b| read_wstr(e, u64::from_le_bytes(b.try_into().unwrap()))).unwrap_or_default();
                format!(" status={:#x} text={:?} caption={:?}", a[0], text(us(0)), text(us(1)))
            }
            _ => String::new(),
        };
        println!("  call {name}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) = {ret:#x}{extra}", a[0], a[1], a[2], a[3], a[4], a[5]);
    }
    ret
}

fn api_impl(e: &mut Emu, env: &mut Env, name: &str) -> u64 {
    let short = name.rsplit('!').next().unwrap();
    match short {
        "GetSystemTimeAsFileTime" | "GetSystemTimePreciseAsFileTime" => {
            w64(e, arg(e, 0), 0x01DB_0000_0000_0000);
            0
        }
        "QueryPerformanceCounter" | "RtlQueryPerformanceCounter" => {
            w64(e, arg(e, 0), 123_456_789);
            1
        }
        "QueryPerformanceFrequency" | "RtlQueryPerformanceFrequency" => {
            w64(e, arg(e, 0), 10_000_000);
            1
        }
        "GetTickCount64" | "GetTickCount" => 1_000_000,
        "GetCurrentProcessId" => 0x1000,
        "GetCurrentThreadId" => 0x1004,
        "GetCurrentProcess" => u64::MAX,
        "GetCurrentThread" => u64::MAX - 1,
        "IsProcessorFeaturePresent" | "RtlIsProcessorFeaturePresent" => matches!(arg(e, 0), 10 | 17 | 23) as u64,
        "InitializeSListHead" | "RtlInitializeSListHead" => {
            let _ = e.mem_write(arg(e, 0), &[0; 16]);
            0
        }
        "InterlockedFlushSList" | "RtlInterlockedFlushSList" => 0,
        "IsDebuggerPresent" => 0,
        "SetUnhandledExceptionFilter" | "UnhandledExceptionFilter" | "SetConsoleCtrlHandler" => 0,
        "GetModuleHandleW" | "GetModuleHandleA" | "LoadLibraryExW" | "LoadLibraryW" | "LoadLibraryA" | "LoadLibraryExA" => {
            let p = arg(e, 0);
            if p == 0 {
                return env.image_base;
            }
            let n = if short.ends_with('A') { read_cstr(e, p) } else { read_wstr(e, p) };
            let n = n.rsplit('\\').next().unwrap().to_string();
            env.module(&n).map(|m| m.base).unwrap_or(0)
        }
        "GetModuleHandleExW" => {
            w64(e, arg(e, 2), env.image_base);
            1
        }
        "FreeLibrary" => 1,
        "GetProcAddress" => {
            let (h, p) = (arg(e, 0), arg(e, 1));
            let f = if p < 0x10000 { format!("#{p}") } else { read_cstr(e, p) };
            match env.modules.iter().find(|m| m.base == h).map(|m| m.name.clone()) {
                Some(d) => resolve(e, env, &d, &f, 0).unwrap_or(0),
                None => 0,
            }
        }
        "GetModuleFileNameW" => {
            let path = wstr("C:\\guest\\app.exe");
            let _ = e.mem_write(arg(e, 1), &path);
            (path.len() / 2 - 1) as u64
        }
        "GetStartupInfoW" => {
            let mut s = vec![0u8; 0x68];
            s[0] = 0x68;
            let _ = e.mem_write(arg(e, 0), &s);
            0
        }
        "GetCommandLineA" => STRINGS,
        "GetCommandLineW" => STRINGS + 0x100,
        "GetEnvironmentStringsW" => STRINGS + 0x200,
        "FreeEnvironmentStringsW" => 1,
        "GetStdHandle" => 0x100 + (arg(e, 0) as u32).wrapping_neg() as u64,
        "GetFileType" => 1,
        "GetConsoleMode" => 0,
        "GetConsoleOutputCP" | "GetACP" => 1252,
        "GetOEMCP" => 437,
        "IsValidCodePage" | "IsValidLocale" => 1,
        "AreFileApisANSI" => 1,
        "GetCPInfo" => {
            let mut s = vec![0u8; 20];
            s[0] = 1;
            s[4] = b'?';
            let _ = e.mem_write(arg(e, 1), &s);
            1
        }
        "GetUserDefaultLCID" => 0x409,
        "MultiByteToWideChar" => {
            let (src, n, dst, cap) = (arg(e, 2), arg(e, 3) as i32, arg(e, 4), arg(e, 5));
            let bytes = if n < 0 {
                let mut v = read_cstr(e, src).into_bytes();
                v.push(0);
                v
            } else {
                e.mem_read_vec(src, n as usize).unwrap_or_default()
            };
            if cap != 0 && dst != 0 {
                let w: Vec<u8> = bytes.iter().take(cap as usize).flat_map(|&b| (b as u16).to_le_bytes()).collect();
                let _ = e.mem_write(dst, &w);
            }
            bytes.len() as u64
        }
        "WideCharToMultiByte" => {
            let (src, n, dst, cap) = (arg(e, 2), arg(e, 3) as i32, arg(e, 4), arg(e, 5));
            let chars: Vec<u16> = if n < 0 {
                read_wstr(e, src).encode_utf16().chain([0]).collect()
            } else {
                e.mem_read_vec(src, n as usize * 2).unwrap_or_default().chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
            };
            if cap != 0 && dst != 0 {
                let b: Vec<u8> = chars.iter().take(cap as usize).map(|&c| if c < 0x80 { c as u8 } else { b'?' }).collect();
                let _ = e.mem_write(dst, &b);
            }
            chars.len() as u64
        }
        "GetStringTypeW" => {
            let (src, n, out) = (arg(e, 1), arg(e, 2) as i32, arg(e, 3));
            let n = if n < 0 { read_wstr(e, src).len() + 1 } else { n as usize };
            let types: Vec<u8> = (0..n)
                .flat_map(|i| {
                    let c = e.mem_read_vec(src + 2 * i as u64, 2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
                    let ch = char::from_u32(c as u32).unwrap_or('\0');
                    let mut t = 0u16;
                    if ch.is_ascii_uppercase() { t |= 1 }
                    if ch.is_ascii_lowercase() { t |= 2 }
                    if ch.is_ascii_digit() { t |= 4 }
                    if ch.is_ascii_whitespace() { t |= 8 }
                    if ch.is_ascii_punctuation() { t |= 0x10 }
                    if ch.is_ascii_control() { t |= 0x20 }
                    if ch == ' ' { t |= 0x40 }
                    if ch.is_ascii_hexdigit() { t |= 0x80 }
                    if ch.is_ascii_alphabetic() { t |= 0x100 }
                    t.to_le_bytes()
                })
                .collect();
            let _ = e.mem_write(out, &types);
            1
        }
        "LCMapStringW" | "LCMapStringEx" => {
            let (src, n, dst, cap) = (arg(e, 2), arg(e, 3) as i32, arg(e, 4), arg(e, 5));
            let n = if n < 0 { read_wstr(e, src).len() + 1 } else { n as usize };
            if cap != 0 && dst != 0 {
                let b = e.mem_read_vec(src, n * 2).unwrap_or_default();
                let _ = e.mem_write(dst, &b);
            }
            n as u64
        }
        "CompareStringW" => 2,
        "GetProcessHeap" => HEAP_HANDLE,
        "HeapAlloc" | "RtlAllocateHeap" => {
            let (flags, size) = (arg(e, 1), arg(e, 2));
            let p = env.alloc(size);
            if flags & 8 != 0 {
                let _ = e.mem_write(p, &vec![0; size as usize]);
            }
            p
        }
        "HeapFree" | "RtlFreeHeap" => 1,
        "HeapSize" | "RtlSizeHeap" => env.heap_sizes.get(&arg(e, 2)).copied().unwrap_or(u64::MAX),
        "HeapReAlloc" | "RtlReAllocateHeap" => {
            let (old, size) = (arg(e, 2), arg(e, 3));
            let p = env.alloc(size);
            let n = env.heap_sizes.get(&old).copied().unwrap_or(0).min(size);
            if let Ok(b) = e.mem_read_vec(old, n as usize) {
                let _ = e.mem_write(p, &b);
            }
            p
        }
        "FlsAlloc" => {
            env.fls.push(0);
            env.fls.len() as u64 - 1
        }
        "FlsFree" => 1,
        "FlsGetValue" => env.fls.get(arg(e, 0) as usize).copied().unwrap_or(0),
        "FlsSetValue" => {
            let i = arg(e, 0) as usize;
            if i < env.fls.len() {
                env.fls[i] = arg(e, 1);
            }
            1
        }
        "InitializeCriticalSectionEx" | "InitializeCriticalSectionAndSpinCount" | "RtlInitializeCriticalSectionEx" => {
            let _ = e.mem_write(arg(e, 0), &[0; 40]);
            1
        }
        "EnterCriticalSection" | "LeaveCriticalSection" | "DeleteCriticalSection" | "RtlEnterCriticalSection"
        | "RtlLeaveCriticalSection" | "RtlDeleteCriticalSection" => 0,
        "EncodePointer" | "DecodePointer" | "RtlEncodePointer" | "RtlDecodePointer" => arg(e, 0),
        "GetLastError" | "RtlGetLastWin32Error" => u32::from_le_bytes(e.mem_read_vec(TEB + 0x68, 4).unwrap().try_into().unwrap()) as u64,
        "SetLastError" | "RtlSetLastWin32Error" => {
            w32(e, TEB + 0x68, arg(e, 0) as u32);
            0
        }
        "WriteFile" => {
            let (buf, n) = (arg(e, 1), arg(e, 2));
            env.out.extend(e.mem_read_vec(buf, n as usize).unwrap_or_default());
            w32(e, arg(e, 3), n as u32);
            1
        }
        "WriteConsoleW" => {
            let (buf, n) = (arg(e, 1), arg(e, 2));
            let s: Vec<u16> = e.mem_read_vec(buf, n as usize * 2).unwrap_or_default().chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            env.out.extend(String::from_utf16_lossy(&s).into_bytes());
            w32(e, arg(e, 3), n as u32);
            1
        }
        "VirtualProtect" => {
            let (addr, size, new) = (arg(e, 0), arg(e, 1), arg(e, 2) as u32);
            let lo = addr & !0xFFF;
            let old = set_prot(e, env, lo, ((addr + size + 0xFFF) & !0xFFF) - lo, new);
            w32(e, arg(e, 3), old);
            1
        }
        "VMProtectBeginVirtualization" | "VMProtectBeginUltra" | "VMProtectBeginMutation" | "VMProtectEnd" => 0,
        "ZwOpenSection" | "NtOpenSection" => {
            let oa = arg(e, 2);
            let us = r64(e, oa + 0x10);
            let name = read_wstr(e, r64(e, us + 8));
            let h = 0x500 + 4 * env.sections.len() as u64;
            env.sections.insert(h, name.rsplit('\\').next().unwrap().to_ascii_lowercase());
            w64(e, arg(e, 0), h);
            0
        }
        "ZwMapViewOfSection" | "NtMapViewOfSection" => {
            let h = arg(e, 0);
            let base = env.next_map;
            let size = if let Some(&(fh, image)) = env.file_sections.get(&h) {
                let data = env.files[&fh].0.clone();
                if image {
                    map_image(e, &data, "view", base, PERM_READ | PERM_EXEC).size
                } else {
                    let size = (data.len() as u64 + 0xFFF) & !0xFFF;
                    e.mem_map(base, size, PERM_READ).unwrap();
                    e.mem_write(base, &data).unwrap();
                    size
                }
            } else {
                let Some(name) = env.sections.get(&h).cloned() else { return 0xC000_0008 };
                let Ok(file) = std::fs::read(format!("C:\\Windows\\System32\\{name}")) else { return 0xC000_0034 };
                map_image(e, &file, &name, base, PERM_READ | PERM_EXEC).size
            };
            env.next_map += (size + 0xFFFF) & !0xFFFF;
            w64(e, arg(e, 2), base);
            w64(e, arg(e, 6), size);
            0
        }
        "ZwUnmapViewOfSection" | "NtUnmapViewOfSection" => 0,
        "ZwClose" | "NtClose" | "CloseHandle" => {
            let h = arg(e, 0);
            let known = env.sections.remove(&h).is_some() | env.files.remove(&h).is_some() | env.file_sections.remove(&h).is_some();
            if known { 0 } else { 0xC000_0008 }
        }
        "ZwOpenFile" | "NtOpenFile" | "ZwCreateFile" | "NtCreateFile" => {
            let name = oa_name(e, arg(e, 2)).to_ascii_lowercase();
            if !name.ends_with("\\app.exe") {
                return 0xC000_0034;
            }
            let data = std::fs::read(&env.exe_path).unwrap();
            let h = env.next_handle;
            env.next_handle += 4;
            env.files.insert(h, (data, 0));
            w64(e, arg(e, 0), h);
            w64(e, arg(e, 3), 0);
            w64(e, arg(e, 3) + 8, 1);
            0
        }
        "ZwQueryInformationFile" | "NtQueryInformationFile" => {
            let (h, iosb, buf, len, class) = (arg(e, 0), arg(e, 1), arg(e, 2), arg(e, 3), arg(e, 4));
            let Some((data, pos)) = env.files.get(&h) else { return 0xC000_0008 };
            let _ = e.mem_write(buf, &vec![0; len as usize]);
            match class {
                5 => {
                    w64(e, buf, (data.len() as u64 + 0xFFF) & !0xFFF);
                    w64(e, buf + 8, data.len() as u64);
                    w32(e, buf + 16, 1);
                }
                14 => w64(e, buf, *pos),
                _ => {}
            }
            w64(e, iosb, 0);
            w64(e, iosb + 8, len);
            0
        }
        "ZwReadFile" | "NtReadFile" => {
            let (h, iosb, buf, len, off_ptr) = (arg(e, 0), arg(e, 4), arg(e, 5), arg(e, 6), arg(e, 7));
            let off = if off_ptr != 0 { Some(r64(e, off_ptr)) } else { None };
            let Some((data, pos)) = env.files.get_mut(&h) else { return 0xC000_0008 };
            let start = off.unwrap_or(*pos) as usize;
            if start >= data.len() {
                return 0xC000_0011;
            }
            let n = (len as usize).min(data.len() - start);
            let chunk = data[start..start + n].to_vec();
            *pos = (start + n) as u64;
            let _ = e.mem_write(buf, &chunk);
            w64(e, iosb, 0);
            w64(e, iosb + 8, n as u64);
            0
        }
        "ZwCreateSection" | "NtCreateSection" => {
            let (out, attrs, fh) = (arg(e, 0), arg(e, 5), arg(e, 6));
            if !env.files.contains_key(&fh) {
                return 0xC000_0008;
            }
            let h = env.next_handle;
            env.next_handle += 4;
            env.file_sections.insert(h, (fh, attrs & 0x0100_0000 != 0));
            w64(e, out, h);
            0
        }
        "ZwQueryInformationProcess" | "NtQueryInformationProcess" => {
            let (class, buf, len, retlen) = (arg(e, 1), arg(e, 2), arg(e, 3), arg(e, 4));
            if len != 0 && buf % 4 != 0 || retlen != 0 && retlen % 4 != 0 {
                return 0x8000_0002;
            }
            if len != 0 && e.mem_read_vec(buf, len as usize).is_err() || retlen != 0 && e.mem_read_vec(retlen, 4).is_err() {
                return 0xC000_0005;
            }
            let need = match class {
                0 => 0x30,
                0x7 | 0x1E => 8,
                0x1F => 4,
                _ => len,
            };
            if len != need {
                return 0xC000_0004;
            }
            let _ = e.mem_write(buf, &vec![0; len as usize]);
            let status = match class {
                0 => {
                    w64(e, buf + 8, PEB);
                    0
                }
                0x1E => 0xC000_0353,
                0x1F => {
                    w32(e, buf, 1);
                    0
                }
                _ => 0,
            };
            if retlen != 0 {
                w32(e, retlen, need as u32);
            }
            status
        }
        "ZwCreateDebugObject" | "NtCreateDebugObject" => {
            w64(e, arg(e, 0), 0x600);
            env.sections.insert(0x600, "<debug object>".into());
            0
        }
        "ZwQueryObject" | "NtQueryObject" if arg(e, 1) == 2 => {
            let (buf, len, retlen) = (arg(e, 2), arg(e, 3), arg(e, 4));
            let name = wstr("DebugObject");
            let need = 0x68 + name.len() as u64;
            if len < need {
                w32(e, retlen, need as u32);
                return 0xC000_0004;
            }
            let mut info = vec![0u8; need as usize];
            info[0..2].copy_from_slice(&((name.len() - 2) as u16).to_le_bytes());
            info[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            info[8..16].copy_from_slice(&(buf + 0x68).to_le_bytes());
            info[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
            info[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
            info[0x68..].copy_from_slice(&name);
            let _ = e.mem_write(buf, &info);
            w32(e, retlen, need as u32);
            0
        }
        "ZwSetInformationThread" | "NtSetInformationThread" if arg(e, 1) == 0x11 => {
            if arg(e, 3) != 0 {
                return 0xC000_0004;
            }
            env.hidden = true;
            0
        }
        "ZwQueryInformationThread" | "NtQueryInformationThread" if arg(e, 1) == 0x11 => {
            if arg(e, 3) != 1 {
                return 0xC000_0004;
            }
            let _ = e.mem_write(arg(e, 2), &[env.hidden as u8]);
            w32(e, arg(e, 4), 1);
            0
        }
        "ZwQuerySystemInformation" | "NtQuerySystemInformation" => {
            let (class, buf, len) = (arg(e, 0), arg(e, 1), arg(e, 2));
            let _ = e.mem_write(buf, &vec![0; len as usize]);
            if class == 0x23 {
                let _ = e.mem_write(buf, &[0, 1]);
            }
            0
        }
        "ZwSetInformationProcess" | "NtSetInformationProcess" if arg(e, 1) == 0x28 => {
            env.instr_cb = r64(e, arg(e, 2) + 8);
            0
        }
        "ZwSetInformationThread" | "NtSetInformationThread" | "ZwSetInformationProcess" | "NtSetInformationProcess" => 0,
        "ZwProtectVirtualMemory" | "NtProtectVirtualMemory" => {
            let (pbase, psize, new) = (arg(e, 1), arg(e, 2), arg(e, 3) as u32);
            let (addr, size) = (r64(e, pbase), r64(e, psize));
            let lo = addr & !0xFFF;
            let hi = (addr + size.max(1) + 0xFFF) & !0xFFF;
            if !env.prot.contains_key(&lo) {
                return 0xC000_0045;
            }
            let old = set_prot(e, env, lo, hi - lo, new);
            w64(e, pbase, lo);
            w64(e, psize, hi - lo);
            w32(e, arg(e, 4), old);
            0
        }
        "ZwAllocateVirtualMemory" | "NtAllocateVirtualMemory" | "VirtualAlloc" => {
            let (pbase, psize) = if short == "VirtualAlloc" { (0, 0) } else { (arg(e, 1), arg(e, 3)) };
            let size = if short == "VirtualAlloc" { arg(e, 1) } else { r64(e, psize) };
            let want = if short == "VirtualAlloc" { arg(e, 0) } else { r64(e, pbase) };
            let size = (size + 0xFFFF) & !0xFFFF;
            let base = if want != 0 && (e.mem_map(want & !0xFFF, size, PERM_ALL).is_ok() || e.mem_read_vec(want, 1).is_ok()) {
                want & !0xFFF
            } else {
                let b = env.vm_top;
                env.vm_top += size;
                e.mem_map(b, size, PERM_ALL).unwrap();
                b
            };
            if short == "VirtualAlloc" {
                return base;
            }
            w64(e, pbase, base);
            w64(e, psize, size);
            0
        }
        "ZwFreeVirtualMemory" | "NtFreeVirtualMemory" | "VirtualFree" => 0,
        "ExitProcess" | "TerminateProcess" | "RtlExitUserProcess" => {
            env.exited = Some(arg(e, if short == "TerminateProcess" { 1 } else { 0 }));
            e.emu_stop();
            0
        }
        "CreateFileW" | "CreateFileA" => u64::MAX,
        _ => {
            *env.unknown.entry(name.to_string()).or_default() += 1;
            0
        }
    }
}

fn build_ldr(emu: &mut Emu, mods: &[(String, u64, u64, u64)]) {
    let entry = |k: usize| LDR + 0x100 + k as u64 * 0x300;
    w32(emu, LDR, 0x58);
    w32(emu, LDR + 4, 1);
    for (k, (name, base, size, ep)) in mods.iter().enumerate() {
        let en = entry(k);
        w64(emu, en + 0x30, *base);
        w64(emu, en + 0x38, *ep);
        w32(emu, en + 0x40, *size as u32);
        let full = format!("C:\\Windows\\System32\\{name}");
        for (off, s, at) in [(0x48u64, full.as_str(), en + 0x100), (0x58, name.as_str(), en + 0x200)] {
            let w = wstr(s);
            emu.mem_write(at, &w).unwrap();
            let len = (w.len() - 2) as u16;
            emu.mem_write(en + off, &[len.to_le_bytes(), (len + 2).to_le_bytes()].concat()).unwrap();
            w64(emu, en + off + 8, at);
        }
    }
    for (list, skip_exe) in [(0x10u64, false), (0x20, false), (0x30, true)] {
        let link_off = list - 0x10;
        let nodes: Vec<u64> = (0..mods.len()).filter(|&k| !(skip_exe && k == 0)).map(|k| entry(k) + link_off).collect();
        let head = LDR + list;
        let all: Vec<u64> = std::iter::once(head).chain(nodes.iter().copied()).collect();
        for (i, &n) in all.iter().enumerate() {
            w64(emu, n, all[(i + 1) % all.len()]);
            w64(emu, n + 8, all[(i + all.len() - 1) % all.len()]);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = &args[1];
    let stop_rip = args.get(2).map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap());
    let file = std::fs::read(path).unwrap();
    let opt = rd::<u32>(&file, 0x3c) as usize + 24;
    let image_base = rd::<u64>(&file, opt + 24);

    let mut emu = Hades::new().unwrap();
    let exe = map_image(&mut emu, &file, "app.exe", image_base, PERM_ALL);
    let entry = exe.entry;
    let mut modules = vec![exe];
    for (name, base) in SYSTEM_DLLS {
        let f = std::fs::read(format!("C:\\Windows\\System32\\{name}")).unwrap();
        modules.push(map_image(&mut emu, &f, name, base, PERM_READ | PERM_EXEC));
    }
    let ldr: Vec<_> = modules.iter().map(|m| (m.name.clone(), m.base, m.size, m.entry)).collect();

    emu.mem_map(STACK, STACK_SIZE, PERM_READ | PERM_WRITE).unwrap();
    emu.mem_map(TEB, 0x10000, PERM_READ | PERM_WRITE).unwrap();
    emu.mem_map(HEAP, HEAP_SIZE, PERM_READ | PERM_WRITE).unwrap();
    emu.mem_map(STUBS, STUB_SIZE, PERM_READ | PERM_EXEC).unwrap();
    emu.mem_write(STUBS, &vec![0xCC; STUB_SIZE as usize]).unwrap();
    emu.mem_map(KUSER, 0x1000, PERM_READ).unwrap();
    let kuser = unsafe { std::slice::from_raw_parts(KUSER as *const u8, 0x1000) };
    emu.mem_write(KUSER, kuser).unwrap();

    w64(&mut emu, TEB + 0x08, STACK + STACK_SIZE);
    w64(&mut emu, TEB + 0x10, STACK);
    w64(&mut emu, TEB + 0x30, TEB);
    w64(&mut emu, TEB + 0x40, 0x1000);
    w64(&mut emu, TEB + 0x48, 0x1004);
    w64(&mut emu, TEB + 0x60, PEB);
    w64(&mut emu, PEB + 0x10, image_base);
    w64(&mut emu, PEB + 0x18, LDR);
    w64(&mut emu, PEB + 0x30, HEAP_HANDLE);
    w32(&mut emu, PEB + 0x118, 10);
    w32(&mut emu, PEB + 0x11C, 0);
    w32(&mut emu, PEB + 0x120, u32::from_le_bytes(kuser[0x260..0x264].try_into().unwrap()));
    build_ldr(&mut emu, &ldr);
    emu.mem_write(STRINGS, b"app.exe\0").unwrap();
    emu.mem_write(STRINGS + 0x100, &wstr("app.exe")).unwrap();
    emu.mem_write(STRINGS + 0x200, &[0; 4]).unwrap();
    emu.reg_write(Reg::GsBase, TEB);

    let env = Rc::new(RefCell::new(Env {
        modules,
        stubs: HashMap::new(),
        by_name: HashMap::new(),
        next_stub: STUBS,
        heap_top: HEAP,
        heap_sizes: HashMap::new(),
        fls: Vec::new(),
        image_base,
        out: Vec::new(),
        calls: Vec::new(),
        unknown: HashMap::new(),
        syscalls: Vec::new(),
        exited: None,
        stray: None,
        sections: HashMap::new(),
        next_map: 0x7FFB_0000_0000,
        sysnames: HashMap::new(),
        vm_top: 0x0000_0040_0000_0000,
        hidden: false,
        exe_path: path.clone(),
        files: HashMap::new(),
        file_sections: HashMap::new(),
        next_handle: 0x700,
        prot: HashMap::new(),
        instr_cb: 0,
        sys_stubs: Default::default(),
    }));

    let imp_rva = rd::<u32>(&file, opt + 120) as u64;
    let mut nimports = 0;
    let mut d = image_base + imp_rva;
    if imp_rva != 0 {
        loop {
            let desc = emu.mem_read_vec(d, 20).unwrap();
            let (ilt, name_rva, iat) = (rd::<u32>(&desc, 0) as u64, rd::<u32>(&desc, 12) as u64, rd::<u32>(&desc, 16) as u64);
            if name_rva == 0 {
                break;
            }
            let dll = read_cstr(&emu, image_base + name_rva);
            let lookup = if ilt != 0 { ilt } else { iat };
            for k in 0.. {
                let ent = r64(&emu, image_base + lookup + 8 * k);
                if ent == 0 {
                    break;
                }
                let f = if ent >> 63 != 0 { format!("#{}", ent & 0xffff) } else { read_cstr(&emu, image_base + (ent & 0x7fff_ffff) + 2) };
                let found = resolve(&emu, &env.borrow(), &dll, &f, 0);
                let addr = found.unwrap_or_else(|| env.borrow_mut().stub_for(&format!("{dll}!{f}")));
                w64(&mut emu, image_base + iat + 8 * k, addr);
                nimports += 1;
            }
            d += 20;
        }
    }

    {
        let mut env_m = env.borrow_mut();
        let (base, size, secs) = (env_m.modules[0].base, env_m.modules[0].size, env_m.modules[0].sections.clone());
        set_prot(&mut emu, &mut env_m, base, size, 0x02);
        for (va, vsize, ch) in secs {
            let (r, w, x) = (ch & 0x4000_0000 != 0, ch & 0x8000_0000 != 0, ch & 0x2000_0000 != 0);
            let p = match (x, w, r) {
                (true, true, _) => 0x40,
                (true, false, _) => 0x20,
                (false, true, _) => 0x04,
                (false, false, true) => 0x02,
                _ => 0x01,
            };
            set_prot(&mut emu, &mut env_m, base + va, (vsize + 0xFFF) & !0xFFF, p);
        }
    }
    let sp = STACK + STACK_SIZE - 0x1000;
    emu.reg_write(Reg::RSP, sp);
    w64(&mut emu, sp, RETURN_SENTINEL);

    let ranges: Vec<(u64, u64)> = env.borrow().modules.iter().skip(1).map(|m| (m.base, m.base + m.size - 1)).chain([(STUBS, STUBS + STUB_SIZE - 1)]).collect();
    for (lo, hi) in ranges {
        let e2 = env.clone();
        emu.add_code_hook(lo, hi, move |e, addr, _| {
            if addr == RETURN_SENTINEL {
                e2.borrow_mut().exited = Some(e.reg_read(Reg::RAX));
                e.emu_stop();
                return;
            }
            if (0..0x20).any(|k| e2.borrow().sys_stubs.contains(&addr.wrapping_sub(k))) {
                return;
            }
            let name = {
                let env = e2.borrow();
                env.stubs.get(&addr).cloned().or_else(|| env.modules.iter().find_map(|m| m.by_addr.get(&addr).cloned()))
            };
            let Some(name) = name else {
                e2.borrow_mut().stray = Some(addr);
                e.emu_stop();
                return;
            };
            let caller = r64(e, e.reg_read(Reg::RSP));
            e2.borrow_mut().calls.push((name.clone(), caller));
            let ret = api(e, &mut e2.borrow_mut(), &name);
            if e2.borrow().exited.is_some() {
                return;
            }
            e.reg_write(Reg::RAX, ret);
            let sp = e.reg_read(Reg::RSP);
            e.reg_write(Reg::RSP, sp + 8);
            e.reg_write(Reg::RIP, caller);
        });
    }
    {
        let mut env_m = env.borrow_mut();
        let stubs: Vec<(u64, String)> =
            env_m.modules.iter().filter(|m| m.name == "ntdll.dll").flat_map(|m| m.by_addr.iter().map(|(a, n)| (*a, n.clone()))).collect();
        for (a, n) in stubs {
            if let Ok(b) = emu.mem_read_vec(a, 8)
                && b[..4] == [0x4C, 0x8B, 0xD1, 0xB8]
            {
                env_m.sysnames.entry(u32::from_le_bytes(b[4..8].try_into().unwrap()) as u64).or_insert(n.replace("!Nt", "!Zw"));
                env_m.sys_stubs.insert(a);
            }
        }
    }
    let e3 = env.clone();
    emu.add_syscall_hook(move |e| {
        let nr = e.reg_read(Reg::RAX);
        let next = e.reg_read(Reg::RIP);
        e3.borrow_mut().syscalls.push((nr, next));
        let name = e3.borrow().sysnames.get(&nr).cloned().unwrap_or_else(|| format!("syscall#{nr:x}"));
        let r10 = e.reg_read(Reg::R10);
        e.reg_write(Reg::RCX, r10);
        e3.borrow_mut().calls.push((format!("[syscall] {name}"), next));
        let ret = api(e, &mut e3.borrow_mut(), &name);
        e.reg_write(Reg::RAX, ret);
        e.reg_write(Reg::RCX, next);
        let fl = e.reg_read(Reg::RFLAGS);
        e.reg_write(Reg::R11, fl);
        let cb = e3.borrow().instr_cb;
        if cb != 0 {
            e.reg_write(Reg::R10, next);
            e.reg_write(Reg::RIP, cb);
        }
    });
    let e4 = env.clone();
    emu.add_intr_hook(move |e, v| {
        println!("guest interrupt/exception {v} at rip={:#x}", e.reg_read(Reg::RIP));
        e4.borrow_mut().stray = Some(e.reg_read(Reg::RIP));
        e.emu_stop();
    });

    println!("image {image_base:#x}, entry {entry:#x}, {nimports} imports");
    let icount = Rc::new(RefCell::new((0u64, HashMap::<(u64, u32), u64>::new())));
    if std::env::var_os("HADES_COUNT").is_some() {
        let ic = icount.clone();
        emu.add_block_hook(1, 0, move |e, addr, size| {
            let mut c = ic.borrow_mut();
            let n = *c.1.entry((addr, size)).or_insert_with(|| {
                let bytes = e.mem_read_vec(addr, size as usize).unwrap_or_default();
                iced_x86::Decoder::with_ip(64, &bytes, addr, 0).into_iter().count() as u64
            });
            c.0 += n;
        });
    }
    let t = Instant::now();
    let mode = std::env::var("HADES_MODE").unwrap_or_default();
    if mode == "hooks" {
        emu.add_mem_hook(HOOK_MEM_READ | HOOK_MEM_WRITE, 1, 0, |_, _, _, _, _| {});
    }
    let budget = if mode == "count" { u64::MAX >> 1 } else { 0 };
    let r = emu.emu_start(entry, stop_rip.unwrap_or(u64::MAX), Some(Duration::from_secs(600)), budget);
    let el = t.elapsed();
    let env = env.borrow();
    println!("result: {r:?} after {:.1} ms; rip={:#x}; cached blocks {}", el.as_secs_f64() * 1e3, emu.reg_read(Reg::RIP), emu.cached_blocks());
    println!("exit: {:?}; stray execution: {:x?}", env.exited, env.stray);
    if std::env::var_os("HADES_COUNT").is_some() {
        println!("executed guest instructions: {}", icount.borrow().0);
    }
    let mut counts: Vec<(&String, usize)> = Vec::new();
    for (n, _) in &env.calls {
        match counts.iter_mut().find(|(k, _)| *k == n) {
            Some(c) => c.1 += 1,
            None => counts.push((n, 1)),
        }
    }
    println!("{} API calls ({} distinct):", env.calls.len(), counts.len());
    for (n, c) in &counts {
        println!("  {c:6}  {n}");
    }
    if !env.unknown.is_empty() {
        println!("unimplemented (returned 0): {:?}", env.unknown);
    }
    if !env.syscalls.is_empty() {
        println!("{} direct syscalls:", env.syscalls.len());
        for (nr, rip) in &env.syscalls {
            println!("  {nr:#5x} {:40} from {rip:#x}", env.sysnames.get(nr).map(|s| s.as_str()).unwrap_or("?"));
        }
    }
    if !env.out.is_empty() {
        println!("guest output:\n{}", String::from_utf8_lossy(&env.out));
    }
    print!("FINAL rip={:#x} rflags={:#x}", emu.reg_read(Reg::RIP), emu.reg_read(Reg::RFLAGS) & 0x8D5);
    for r in Reg::GPRS {
        print!(" {}={:#x}", format!("{r:?}").to_lowercase(), emu.reg_read(r));
    }
    println!();
    if args.len() >= 6 {
        let lo = u64::from_str_radix(args[3].trim_start_matches("0x"), 16).unwrap();
        let hi = u64::from_str_radix(args[4].trim_start_matches("0x"), 16).unwrap();
        let mut dump = emu.mem_read_vec(lo, (hi - lo) as usize).unwrap();
        dump.extend(emu.mem_read_vec(emu.reg_read(Reg::RSP), 0x100).unwrap());
        std::fs::write(&args[5], dump).unwrap();
        println!("dumped [{lo:#x},{hi:#x}) + 0x100 bytes at rsp to {}", args[5]);
    }
}
