//! Standalone ptrace-based LLM traffic rewrite engine.
//!
//! Runs as an independent privileged daemon (independent-process deployment):
//! it attaches to a target agent process via `PTRACE_SEIZE`, plants an int3
//! at the `SSL_write` entry, and on every hit applies rewrite rules to the
//! plaintext buffer before the real TLS layer encrypts it.
//!
//! Deployment relationship with the rest of agentsight:
//! - depends on the main agentsight service for assets (agent discovery,
//!   identity anchors, cmdline rules) but owns its own process and socket;
//! - crash-isolated from agentsight-enforcer: a rewrite failure must never
//!   affect observation (uprobe pipeline) or the enforcement decision plane.
//!
//! Safety model (validated by the P0 PoC, see `.qoder/ptrace-poc`):
//! - a forked watchdog restores the breakpoint byte via `/proc/<pid>/mem`
//!   when this daemon dies for any reason, including SIGKILL;
//! - the target process is expected to install the SIGTRAP safety-net
//!   handler (or accept the degraded risk) — see `docs` in the design doc.
//!
//! Linux only: the whole crate is gated behind `target_os = "linux"`.
#![cfg(target_os = "linux")]

pub mod engine;
pub mod error;
pub mod maps;
pub mod proc_mem;
pub mod ptrace;
pub mod remote;
pub mod rules;
pub mod watchdog;

pub use engine::RewriteEngine;
pub use error::{Result, RewriteError};
pub use rules::{Mode, RewriteRule, RuleSet};
