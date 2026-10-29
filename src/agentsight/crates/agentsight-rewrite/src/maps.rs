//! Target process address-space inspection: `/proc/<pid>/maps` parsing and
//! minimal ELF64 `.dynsym` lookup used to locate `SSL_write` at runtime.
//!
//! This is a PoC-grade resolver. The full multi-TLS / static-binary resolution
//! (prologue patterns, offset fingerprint tables) lives in the main crate's
//! `probes/sslsniff` subsystem and will be reused in a later stage; for now
//! the engine supports dynamically linked OpenSSL targets.

use std::fs;
use std::io::Read;

use crate::error::{Result, RewriteError};

/// One line of `/proc/<pid>/maps`.
#[derive(Debug, Clone)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub path: String,
}

pub fn parse_maps(pid: i32) -> Result<Vec<MapEntry>> {
    let mut buf = String::new();
    fs::File::open(format!("/proc/{pid}/maps"))
        .and_then(|mut f| f.read_to_string(&mut buf))
        .map_err(|e| RewriteError::ProcMem { pid, source: e })?;
    Ok(buf.lines().filter_map(MapEntry::parse).collect())
}

impl MapEntry {
    fn parse(line: &str) -> Option<MapEntry> {
        let mut parts = line.splitn(6, ' ');
        let range = parts.next()?;
        let perms = parts.next()?.to_string();
        // offset / dev / inode are positional-only here
        parts.next()?;
        parts.next()?;
        parts.next()?;
        let path = parts.next()?.trim().to_string();
        let (start, end) = range.split_once('-')?;
        Some(MapEntry {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
            perms,
            path,
        })
    }
}

/// Lowest-addressed mapping whose path contains `needle`; for a shared
/// library this is its load base (ET_DYN, vaddr space starts at the base).
pub fn module_base(maps: &[MapEntry], needle: &str, pid: i32) -> Result<(u64, String)> {
    maps.iter()
        .filter(|m| m.path.contains(needle))
        .min_by_key(|m| m.start)
        .map(|m| (m.start, m.path.clone()))
        .ok_or_else(|| RewriteError::ModuleNotFound {
            module: needle.to_string(),
            pid,
        })
}

// ---------------------------------------------------------------------------
// Static-binary SSL_write resolution (Tier 2), ported from the observation
// side (probes/sslsniff.rs find_static_ssl_offsets) with one deliberate
// difference: we scan the target's executable mappings in memory instead of
// the ELF file, so pattern hits are already runtime VAs and no PT_LOAD
// offset-to-vaddr conversion is needed for static-pie binaries.
// ---------------------------------------------------------------------------

/// SSL_read prologue (OpenSSL/BoringSSL, x86_64).
pub const READ_PAT: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50, 0x48, 0x83, 0xbf, 0x98, 0x00, 0x00,
    0x00, 0x00, 0x74,
];
/// SSL_write prologue.
pub const WRITE_PAT: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
    0x18, 0x41, 0x89, 0xd7, 0x49, 0x89, 0xf6, 0x48, 0x89, 0xfb,
];
/// SSL_do_handshake prologues, one per toolchain flavor (clang builds vs bun
/// single-file executables); copied from the observation side.
pub const HANDSHAKE_PATS: &[&[u8]] = &[
    &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83,
        0xec, 0x28, 0x49, 0x89, 0xfc, 0x48, 0x8b, 0x47, 0x30,
    ],
    &[
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50, 0x4c, 0x8b, 0x7f, 0x30, 0x49,
        0x83, 0xbf, 0x18, 0x01, 0x00, 0x00, 0x00, 0x74,
    ],
];
/// Max distance between SSL_read and SSL_write in one compilation unit.
const ADJACENCY: u64 = 0x1000;

fn find_all(haystack: &[u8], needle: &[u8], base_va: u64) -> Vec<u64> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| base_va + i as u64)
        .collect()
}

/// Runtime address of `symbol` in the ELF image at `path` as loaded in a
/// process whose lowest mapping is `base`: ET_DYN (PIE) adds the base,
/// ET_EXEC already bakes the link address into st_value.
pub fn symbol_runtime_vaddr(path: &str, symbol: &str, base: u64) -> Result<u64> {
    let data = fs::read(path).map_err(|e| RewriteError::ElfRead {
        path: path.to_string(),
        source: e,
    })?;
    if data.len() < 20 {
        return Err(RewriteError::SymbolNotFound {
            symbol: symbol.to_string(),
            path: path.to_string(),
        });
    }
    let is_dyn = u16::from_le_bytes(data[16..18].try_into().unwrap()) == 3; // ET_DYN
    let val = symbol_vaddr(path, symbol)?;
    Ok(if is_dyn { base + val } else { val })
}

/// Locate the SSL_write runtime VA inside the executable mappings of
/// `image_path` using the observation side's semantics: SSL_read must match
/// exactly once, a handshake variant must exist before it, and SSL_write must
/// be the first write-pattern hit within 4KB after SSL_read. Returns None
/// when any confidence check fails - the caller must not guess, because a
/// rewrite breakpoint at a wrong address corrupts the target instead of
/// merely missing events.
pub fn find_static_write_va(
    mem: &mut super::proc_mem::ProcMem,
    maps: &[MapEntry],
    image_path: &str,
) -> Option<u64> {
    let mut read: Vec<u64> = Vec::new();
    let mut write: Vec<u64> = Vec::new();
    let mut handshake: Vec<u64> = Vec::new();
    for m in maps
        .iter()
        .filter(|m| m.perms.contains('x') && m.path == image_path)
    {
        let len = (m.end - m.start) as usize;
        if len > 256 * 1024 * 1024 {
            continue; // sanity bound
        }
        let mut buf = vec![0u8; len];
        mem.read(m.start, &mut buf).ok()?;
        read.extend(find_all(&buf, READ_PAT, m.start));
        write.extend(find_all(&buf, WRITE_PAT, m.start));
        for pat in HANDSHAKE_PATS {
            handshake.extend(find_all(&buf, pat, m.start));
        }
    }
    if read.len() != 1 {
        log::debug!(
            "[resolve] SSL_read pattern matches = {}, need exactly 1",
            read.len()
        );
        return None;
    }
    let read_va = read[0];
    handshake.retain(|&v| v < read_va);
    handshake.sort_unstable();
    handshake.last()?; // handshake must exist before read
    write
        .iter()
        .copied()
        .filter(|&v| v > read_va && v - read_va < ADJACENCY)
        .min()
}

/// Whether `path` is an ET_DYN (PIE / shared-object) ELF image. ET_DYN
/// symbol/offset values are relative to the load base; ET_EXEC values are
/// absolute.
pub fn is_dyn_elf(path: &str) -> Option<bool> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut hdr = [0u8; 20];
    f.read_exact(&mut hdr).ok()?;
    if &hdr[0..4] != b"\x7fELF" || hdr[4] != 2 {
        return None;
    }
    Some(u16::from_le_bytes(hdr[16..18].try_into().unwrap()) == 3)
}

/// Map a load-relative virtual address to its file offset via PT_LOAD
/// segments. `rel_vaddr` = runtime VA minus the image's lowest mapping.
pub fn vaddr_to_file_offset(path: &str, rel_vaddr: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let mut hdr = [0u8; 64];
    f.read_exact(&mut hdr).ok()?;
    if &hdr[0..4] != b"\x7fELF" || hdr[4] != 2 {
        return None;
    }
    let rd16 = |b: &[u8]| u16::from_le_bytes(b.try_into().unwrap());
    let rd32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let rd64 = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    let phoff = rd64(&hdr[32..40]);
    let phentsize = rd16(&hdr[54..56]) as u64;
    let phnum = rd16(&hdr[56..58]) as u64;
    if phoff == 0 || phentsize < 56 {
        return None;
    }
    for i in 0..phnum {
        let mut ph = [0u8; 56];
        f.seek(SeekFrom::Start(phoff + i * phentsize)).ok()?;
        f.read_exact(&mut ph).ok()?;
        if rd32(&ph[0..4]) != 1 {
            continue; // PT_LOAD
        }
        let p_offset = rd64(&ph[8..16]);
        let p_vaddr = rd64(&ph[16..24]);
        let p_filesz = rd64(&ph[32..40]);
        if rel_vaddr >= p_vaddr && rel_vaddr < p_vaddr.saturating_add(p_filesz) {
            return Some(p_offset + (rel_vaddr - p_vaddr));
        }
    }
    None
}

/// Length in bytes of the first instruction at `bytes`, for the handful of
/// prologues that open SSL functions in the wild (endbr64 variants, classic
/// push-rbp prologues). Returns None for anything unrecognized -- callers
/// must fail closed rather than guess a shift past a live uprobe.
pub fn first_insn_len(bytes: &[u8]) -> Option<u64> {
    if bytes.len() >= 4
        && bytes[0] == 0xF3
        && bytes[1] == 0x0F
        && bytes[2] == 0x1E
        && bytes[3] == 0xFA
    {
        return Some(4); // endbr64
    }
    if bytes[0] == 0x55 {
        return Some(1); // push rbp
    }
    if bytes[0] == 0x41 && (bytes[1] & 0xF0) == 0x50 {
        return Some(1); // push r12..r15
    }
    if bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xE5 {
        return Some(3); // mov rbp, rsp
    }
    if bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC {
        return Some(4); // sub rsp, imm8
    }
    None
}

/// GNU build-id (hex) from the ELF64 PT_NOTE segment of `path`, or None.
/// Ported from the observation side's probes/elf_buildid.rs with the same
/// guards: 64-bit little-endian only, and implausible PT_NOTE sizes are
/// rejected instead of driving a huge allocation.
pub fn read_buildid(path: &str) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let mut ident = [0u8; 16];
    f.read_exact(&mut ident).ok()?;
    if &ident[0..4] != b"\x7fELF" || ident[4] != 2 || ident[5] != 1 {
        return None; // ELF64 little-endian only
    }
    let mut hdr = [0u8; 48];
    f.read_exact(&mut hdr).ok()?;
    let rd16 = |b: &[u8]| u16::from_le_bytes(b.try_into().unwrap());
    let rd32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let rd64 = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    let phoff = rd64(&hdr[16..24]);
    let phentsize = rd16(&hdr[38..40]) as u64;
    let phnum = rd16(&hdr[40..42]) as u64;
    if phoff == 0 || phentsize < 56 {
        return None;
    }
    const MAX_NOTE_BYTES: u64 = 64 * 1024;
    for i in 0..phnum {
        let mut ph = [0u8; 56];
        f.seek(SeekFrom::Start(phoff + i * phentsize)).ok()?;
        f.read_exact(&mut ph).ok()?;
        if rd32(&ph[0..4]) != 4 {
            continue; // PT_NOTE
        }
        let p_offset = rd64(&ph[8..16]);
        let p_filesz = rd64(&ph[32..40]);
        if p_filesz == 0 || p_filesz > MAX_NOTE_BYTES {
            continue;
        }
        let mut notes = vec![0u8; p_filesz as usize];
        f.seek(SeekFrom::Start(p_offset)).ok()?;
        f.read_exact(&mut notes).ok()?;
        let mut o = 0usize;
        while o + 12 <= notes.len() {
            let namesz = u32::from_le_bytes(notes[o..o + 4].try_into().unwrap()) as usize;
            let descsz = u32::from_le_bytes(notes[o + 4..o + 8].try_into().unwrap()) as usize;
            let ntype = u32::from_le_bytes(notes[o + 8..o + 12].try_into().unwrap());
            let desc = o + 12 + namesz;
            let next = desc + descsz;
            if namesz == 0 || next > notes.len() {
                break;
            }
            if ntype == 3 && &notes[o + 12..o + 16] == b"GNU\0" {
                return Some(
                    notes[desc..desc + descsz]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                );
            }
            o = next;
        }
    }
    None
}

/// Find a `syscall` (0F 05) byte pair inside an executable mapping of libc.
/// Executing the pair as an instruction is the standard remote-syscall trick;
/// the byte pair may straddle real instruction boundaries, which is fine.
pub fn find_syscall_gadget(mem: &mut super::proc_mem::ProcMem, maps: &[MapEntry]) -> Result<u64> {
    for m in maps {
        if !m.path.contains("libc") || !m.perms.contains('x') {
            continue;
        }
        let len = (m.end - m.start) as usize;
        let mut buf = vec![0u8; len];
        mem.read(m.start, &mut buf)?;
        for (i, w) in buf.windows(2).enumerate() {
            if w == [0x0F, 0x05] {
                return Ok(m.start + i as u64);
            }
        }
    }
    Err(RewriteError::NoSyscallGadget { pid: mem.pid() })
}

/// Return `st_value` of `symbol` in the ELF64 symbol tables of `path`,
/// trying `.dynsym` first and then the full `.symtab` (unstripped static
/// binaries like uv-Python keep SSL_write as a local symbol there). For an
/// ET_DYN object the value is an offset to add to the load base.
pub fn symbol_vaddr(path: &str, symbol: &str) -> Result<u64> {
    let data = fs::read(path).map_err(|e| RewriteError::ElfRead {
        path: path.to_string(),
        source: e,
    })?;
    parse_sym_vaddr(&data, symbol, /*dynsym_only=*/ true)
        .or_else(|| parse_sym_vaddr(&data, symbol, false))
        .ok_or_else(|| RewriteError::SymbolNotFound {
            symbol: symbol.to_string(),
            path: path.to_string(),
        })
}

fn parse_sym_vaddr(data: &[u8], symbol: &str, dynsym_only: bool) -> Option<u64> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
        return None; // not ELF64 little-endian
    }
    let rd_u16 = |o: usize| -> Option<u16> {
        Some(u16::from_le_bytes(data.get(o..o + 2)?.try_into().ok()?))
    };
    let rd_u32 = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
    };
    let rd_u64 = |o: usize| -> Option<u64> {
        Some(u64::from_le_bytes(data.get(o..o + 8)?.try_into().ok()?))
    };

    let shoff = rd_u64(0x28)? as usize;
    let shentsize = rd_u16(0x3A)? as usize;
    let shnum = rd_u16(0x3C)? as usize;
    if shoff == 0
        || shnum == 0
        || shentsize < 64
        || shoff.saturating_add(shentsize * shnum) > data.len()
    {
        return None;
    }
    let sh = |i: usize| shoff + i * shentsize;

    // Locate the symbol table (SHT_DYNSYM=11, or SHT_SYMTAB=2 for the full
    // table) and its linked string table section.
    let want_type: u32 = if dynsym_only { 11 } else { 2 };
    let mut sym = None;
    for i in 0..shnum {
        let h = sh(i);
        if rd_u32(h + 0x04)? != want_type {
            continue;
        }
        let link = rd_u32(h + 0x28)? as usize;
        if link >= shnum {
            return None;
        }
        sym = Some((
            rd_u64(h + 0x18)? as usize,
            rd_u64(h + 0x20)? as usize,
            rd_u64(sh(link) + 0x18)? as usize,
        ));
        break;
    }
    let (sym_off, sym_size, str_off) = sym?;
    if str_off > data.len() {
        return None;
    }

    const ENT: usize = 24; // Elf64_Sym
    for i in 0..sym_size / ENT {
        let s = sym_off + i * ENT;
        if s + ENT > data.len() {
            break;
        }
        let name_off = rd_u32(s)? as usize;
        if name_off == 0 {
            continue;
        }
        let name_start = str_off + name_off;
        if name_start >= data.len() {
            continue;
        }
        let name_end = data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(data.len());
        if &data[name_start..name_end] == symbol.as_bytes() {
            return rd_u64(s + 0x08); // st_value
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_line() {
        let m = MapEntry::parse(
            "7f0000000000-7f0000100000 r-xp 00000000 08:02 123456   /usr/lib64/libssl.so.1.1.1k",
        )
        .expect("line should parse");
        assert_eq!(m.start, 0x7f0000000000);
        assert_eq!(m.end, 0x7f0000100000);
        assert_eq!(m.perms, "r-xp");
        assert!(m.path.ends_with("libssl.so.1.1.1k"));
    }

    #[test]
    fn rejects_malformed_maps_line() {
        assert!(MapEntry::parse("garbage").is_none());
        assert!(MapEntry::parse("zz-11 r-xp 0 0 0 /x").is_none());
    }

    #[test]
    fn module_base_picks_lowest_mapping() {
        let maps = vec![
            MapEntry {
                start: 0x2000,
                end: 0x3000,
                perms: "r--p".into(),
                path: "/lib/libssl.so".into(),
            },
            MapEntry {
                start: 0x1000,
                end: 0x1fff,
                perms: "r--p".into(),
                path: "/lib/libssl.so".into(),
            },
            MapEntry {
                start: 0x4000,
                end: 0x5000,
                perms: "r--p".into(),
                path: "/lib/libc.so".into(),
            },
        ];
        let (base, _) = module_base(&maps, "libssl", 1).expect("found");
        assert_eq!(base, 0x1000);
        assert!(module_base(&maps, "libcrypto", 1).is_err());
    }

    #[test]
    fn dynsym_lookup_works_on_real_libssl() {
        // Environment-dependent smoke test: exercise the ELF parser against
        // the system libssl when present, verifying SSL_write resolves.
        let candidates = [
            "/usr/lib64/libssl.so.1.1.1k",
            "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        ];
        let path = candidates.iter().find(|p| std::path::Path::new(p).exists());
        let Some(path) = path else {
            return; // no libssl on this machine; nothing to verify
        };
        let v = symbol_vaddr(path, "SSL_write").expect("SSL_write in dynsym");
        assert!(v > 0 && v < 0x1_000_000);
    }

    #[test]
    fn dynsym_lookup_fails_cleanly_on_garbage() {
        let garbage = b"not an elf file at all, definitely".to_vec();
        assert!(parse_sym_vaddr(&garbage, "SSL_write", true).is_none());
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    #[test]
    fn debug_uv_python_symtab() {
        let p = std::env::var("REWRITE_DEBUG_ELF").unwrap_or_default();
        if p.is_empty() {
            return;
        }
        let data = fs::read(&p).unwrap_or_default();
        eprintln!("file len={}", data.len());
        let r1 = parse_sym_vaddr(&data, "SSL_write", true);
        eprintln!("dynsym result={r1:?}");
        let r2 = parse_sym_vaddr(&data, "SSL_write", false);
        eprintln!("symtab result={r2:?}");
    }
}
