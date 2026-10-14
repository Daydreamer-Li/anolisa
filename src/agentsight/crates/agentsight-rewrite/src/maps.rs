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

/// Return `st_value` of `symbol` in the ELF64 dynamic symbol table of `path`.
/// For an ET_DYN shared object this is the offset to add to the load base.
pub fn symbol_vaddr(path: &str, symbol: &str) -> Result<u64> {
    let data = fs::read(path).map_err(|e| RewriteError::ElfRead {
        path: path.to_string(),
        source: e,
    })?;
    parse_dynsym_vaddr(&data, symbol).ok_or_else(|| RewriteError::SymbolNotFound {
        symbol: symbol.to_string(),
        path: path.to_string(),
    })
}

fn parse_dynsym_vaddr(data: &[u8], symbol: &str) -> Option<u64> {
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

    // Locate SHT_DYNSYM and its linked string table section.
    let mut sym = None;
    for i in 0..shnum {
        let h = sh(i);
        if rd_u32(h + 0x04)? != 11 {
            continue; // not SHT_DYNSYM
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
        assert!(parse_dynsym_vaddr(&garbage, "SSL_write").is_none());
    }
}
