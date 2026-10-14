//! Error type for the rewrite engine.

use std::io;

/// Errors produced while attaching to a target and rewriting its traffic.
#[derive(Debug, thiserror::Error)]
pub enum RewriteError {
    #[error("ptrace {op} failed for tid {tid}: {source}")]
    Ptrace {
        op: &'static str,
        tid: i32,
        #[source]
        source: io::Error,
    },

    #[error("memory access on pid {pid} failed: {source}")]
    ProcMem {
        pid: i32,
        #[source]
        source: io::Error,
    },

    #[error("symbol {symbol} not found in {path}")]
    SymbolNotFound { symbol: String, path: String },

    #[error("failed to read ELF file {path}: {source}")]
    ElfRead {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("module {module} not found in pid {pid} maps")]
    ModuleNotFound { module: String, pid: i32 },

    #[error("no `syscall` gadget found in libc of pid {pid}")]
    NoSyscallGadget { pid: i32 },

    #[error("remote {op} syscall returned {ret:#x}")]
    RemoteSyscall { op: &'static str, ret: i64 },

    #[error("invalid rewrite config: {0}")]
    Config(String),

    #[error("fork failed: {0}")]
    Fork(io::Error),

    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, RewriteError>;
