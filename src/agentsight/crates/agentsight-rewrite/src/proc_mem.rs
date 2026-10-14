//! Read/write access to target process memory via `/proc/<pid>/mem`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::error::{Result, RewriteError};

/// Handle to `/proc/<pid>/mem`. Once the target process exits, reads and
/// writes fail — callers treat that as "target gone".
pub struct ProcMem {
    pid: i32,
    file: File,
}

impl ProcMem {
    pub fn open(pid: i32) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
            .map_err(|e| RewriteError::ProcMem { pid, source: e })?;
        Ok(ProcMem { pid, file })
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(addr))
            .and_then(|_| self.file.read_exact(buf))
            .map_err(|e| RewriteError::ProcMem {
                pid: self.pid,
                source: e,
            })
    }

    pub fn write(&mut self, addr: u64, buf: &[u8]) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(addr))
            .and_then(|_| self.file.write_all(buf))
            .map_err(|e| RewriteError::ProcMem {
                pid: self.pid,
                source: e,
            })
    }
}
