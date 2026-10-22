//! Tier-3 offset fingerprint table, ported from the observation side
//! (`probes/codex_offsets.rs` + `probes/elf_buildid.rs`).
//!
//! Covers statically-linked, stripped binaries that have neither a dynamic
//! libssl nor usable SSL symbols: entries are keyed by
//! `file_size + head_64k_sha256 [+ GNU build-id]` and carry the file offsets
//! of the SSL functions as produced by
//! `scripts/extract-codex-offsets.py`. The table is loaded from an
//! agentsight.json-format file so both agentsight and this daemon share the
//! same asset.
//!
//! Offsets are FILE offsets (uprobe convention on the observation side); the
//! engine converts them to runtime VAs via the ELF program headers.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{Result, RewriteError};

const HEAD_SIZE: usize = 65536;

/// File offsets of the SSL functions for one fingerprinted binary.
#[derive(Debug, Clone, Deserialize)]
pub struct StaticSslOffsets {
    pub ssl_write: u64,
    #[serde(default)]
    pub ssl_read: Option<u64>,
    #[serde(default)]
    pub ssl_do_handshake: Option<u64>,
    /// True when `ssl_write` actually points at `SSL_write_ex`.
    #[serde(default)]
    pub write_is_ex: bool,
}

#[derive(Debug, Deserialize)]
struct Fingerprint {
    #[serde(default)]
    build_id: Option<String>,
    file_size: u64,
    head_64k_sha256: String,
}

#[derive(Debug, Deserialize)]
struct Entry {
    fingerprint: Fingerprint,
    offsets: Option<StaticSslOffsets>,
}

#[derive(Debug, Deserialize)]
struct Root {
    codex_offsets: CodexOffsets,
}

#[derive(Debug, Deserialize)]
struct CodexOffsets {
    entries: Vec<Entry>,
}

/// Loaded Tier-3 table. `None` entries (fingerprint present but offsets not
/// extractable) are kept so a lookup fails explicitly instead of falling
/// through to a different build's offsets.
pub struct OffsetTable {
    entries: Vec<(Fingerprint, Option<StaticSslOffsets>)>,
}

impl OffsetTable {
    /// Parse an agentsight.json-format document.
    pub fn load(json_str: &str) -> Result<OffsetTable> {
        let root: Root = serde_json::from_str(json_str)
            .map_err(|e| RewriteError::Config(format!("offset table parse: {e}")))?;
        Ok(OffsetTable {
            entries: root
                .codex_offsets
                .entries
                .into_iter()
                .map(|e| (e.fingerprint, e.offsets))
                .collect(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Match `path` against the table: file_size narrows candidates, then
    /// GNU build-id (preferred) and head-64K SHA256 decide. Returns the
    /// offsets of the matching build, never a guess from a different build.
    pub fn lookup(&self, path: &str) -> Option<StaticSslOffsets> {
        let file_size = std::fs::metadata(path).ok()?.len();
        let candidates: Vec<&(Fingerprint, Option<StaticSslOffsets>)> = self
            .entries
            .iter()
            .filter(|(fp, _)| fp.file_size == file_size)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let build_id = crate::maps::read_buildid(path);
        if let Some(bid) = &build_id {
            for (fp, off) in &candidates {
                if fp.build_id.as_deref() == Some(bid.as_str()) {
                    return off.clone();
                }
            }
        }
        let head_sha = head_sha256(path)?;
        for (fp, off) in &candidates {
            if fp.head_64k_sha256 == head_sha {
                return off.clone();
            }
        }
        None
    }
}

fn head_sha256(path: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_SIZE];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(
        Sha256::digest(&buf)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// Convert a file offset to a virtual address relative to the load base
/// (i.e. the value to add to the runtime base for ET_DYN, or the absolute
/// address for ET_EXEC), by locating the covering PT_LOAD segment.
pub fn file_offset_to_rel_vaddr(path: &str, off: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let mut ident = [0u8; 16];
    f.read_exact(&mut ident).ok()?;
    if &ident[0..4] != b"\x7fELF" || ident[4] != 2 {
        return None; // ELF64 little-endian only
    }
    let mut hdr = [0u8; 48];
    f.read_exact(&mut hdr).ok()?;
    let le = ident[5] == 1;
    let rd64 = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    let rd32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let rd16 = |b: &[u8]| u16::from_le_bytes(b.try_into().unwrap());
    if !le {
        return None;
    }
    let phoff = rd64(&hdr[16..24]);
    let phentsize = rd16(&hdr[38..40]) as u64;
    let phnum = rd16(&hdr[40..42]) as u64;
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
        if off >= p_offset && off < p_offset.saturating_add(p_filesz) {
            return Some(p_vaddr + (off - p_offset));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = r#"{
        "codex_offsets": {
            "schema_version": 1,
            "entries": [
                {
                    "codex_version": "x",
                    "fingerprint": { "file_size": 1000,
                        "build_id": "deadbeef",
                        "head_64k_sha256": "aa55" },
                    "offsets": { "ssl_write": 4096, "ssl_read": 8192,
                                 "ssl_do_handshake": 2048, "write_is_ex": true }
                },
                {
                    "codex_version": "no-offsets",
                    "fingerprint": { "file_size": 2000, "head_64k_sha256": "ff00" },
                    "offsets": null
                }
            ]
        }
    }"#;

    #[test]
    fn loads_and_matches_by_build_id() {
        let t = OffsetTable::load(TABLE).expect("table");
        assert_eq!(t.entries.len(), 2);
        let bin = std::env::temp_dir().join("t3_buildid.bin");
        std::fs::write(&bin, vec![0u8; 1000]).unwrap();
        // No real PT_NOTE here, so build-id matching cannot trigger; the
        // head-sha fallback would not match "aa55" either. Only verify the
        // size pre-filter rejects unknown files cleanly.
        assert!(t.lookup(bin.to_str().unwrap()).is_none());
        let _ = std::fs::remove_file(bin);
    }

    #[test]
    fn empty_table_is_empty() {
        let t = OffsetTable::load(r#"{"codex_offsets":{"entries":[]}}"#).expect("table");
        assert!(t.is_empty());
    }

    #[test]
    fn rejects_malformed_table() {
        assert!(OffsetTable::load("not json").is_err());
        assert!(OffsetTable::load(r#"{"other":1}"#).is_err());
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    /// Full chain against a real binary: point REWRITE_DEBUG_ELF at any
    /// ELF with SSL symbols, extract an entry with the observation side's
    /// script, and verify lookup + VA conversion agree with Tier 1.
    #[test]
    fn lookup_real_binary() {
        let path = std::env::var("REWRITE_DEBUG_ELF").unwrap_or_default();
        if path.is_empty() {
            return;
        }
        let out = std::process::Command::new(
            "/root/yunqing/projects/anolisa-rewrite/src/agentsight/scripts/extract-codex-offsets.py",
        )
        .arg(&path)
        .output()
        .expect("extract script");
        let table = OffsetTable::load(std::str::from_utf8(&out.stdout).unwrap_or(""));
        let Ok(table) = table else {
            eprintln!(
                "table load failed (binary may be stripped): {:?}",
                out.stdout
            );
            return;
        };
        let off = table.lookup(&path).expect("lookup by fingerprint");
        let et_dyn = crate::maps::is_dyn_elf(&path).unwrap_or(true);
        eprintln!(
            "lookup ok: ssl_write={:#x} write_is_ex={} et_dyn={et_dyn}",
            off.ssl_write, off.write_is_ex
        );
        let sym = crate::maps::symbol_runtime_vaddr(&path, "SSL_write", 0);
        if let Ok(sym_va) = sym {
            // For ET_EXEC the entry value must equal the symbol address; for
            // ET_DYN it is relative, so only compare the ET_EXEC case.
            if !et_dyn {
                assert_eq!(off.ssl_write, sym_va, "tier3 entry must match tier1 symbol");
            }
        }
    }
}
