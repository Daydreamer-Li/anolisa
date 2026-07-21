//! Agent process discovery endpoint.
//!
//! Uses the cross-platform `sysinfo` crate to enumerate running processes
//! and match them against known AI coding agent signatures. Works on both
//! Linux and macOS without platform-specific code.
//!
//! Ported from agentopt's `crates/server/src/agents.rs`, adapted to actix-web.

use std::collections::HashMap;

use actix_web::{HttpResponse, Responder, get};
use serde::Serialize;
use sysinfo::System;

// ── Known agent signatures ────────────────────────────────────────────────

/// A known agent type with its process matching patterns and display info.
struct AgentSignature {
    /// Display name
    name: &'static str,
    /// Short identifier
    id: &'static str,
    /// Exact process name matches (case-insensitive)
    comm_exact: &'static [&'static str],
    /// Substrings to look for in the full cmdline (word-boundary match)
    cmdline_contains: &'static [&'static str],
    /// Icon emoji
    icon: &'static str,
    /// Category
    category: &'static str,
}

const AGENT_SIGNATURES: &[AgentSignature] = &[
    AgentSignature {
        name: "Claude Code",
        id: "claude-code",
        comm_exact: &["claude"],
        cmdline_contains: &["claude-code", "claude_code"],
        icon: "🟣",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "Codex",
        id: "codex",
        comm_exact: &["codex"],
        cmdline_contains: &["openai-codex", "codex-cli"],
        icon: "🟢",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "Gemini CLI",
        id: "gemini-cli",
        comm_exact: &["gemini"],
        cmdline_contains: &["gemini-cli", "@google/gemini-cli"],
        icon: "🔵",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "Cursor",
        id: "cursor",
        comm_exact: &["cursor", "Cursor", "cursor-agent"],
        cmdline_contains: &["cursor"],
        icon: "⚡",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "GitHub Copilot",
        id: "copilot",
        comm_exact: &["copilot"],
        cmdline_contains: &["github-copilot", "copilot-agent"],
        icon: "🤖",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "Aider",
        id: "aider",
        comm_exact: &["aider"],
        cmdline_contains: &["aider-chat", "aider"],
        icon: "🦊",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "Amp",
        id: "amp",
        comm_exact: &["amp"],
        cmdline_contains: &["ampcode", "amp-cli"],
        icon: "⚙️",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "Windsurf",
        id: "windsurf",
        comm_exact: &["windsurf", "Windsurf"],
        cmdline_contains: &["windsurf"],
        icon: "🏄",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "Zed",
        id: "zed",
        comm_exact: &["zed"],
        cmdline_contains: &["zed-editor"],
        icon: "✏️",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "OpenHands",
        id: "openhands",
        comm_exact: &["openhands"],
        cmdline_contains: &["openhands", "openhands-ai"],
        icon: "👐",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "Cline",
        id: "cline",
        comm_exact: &["cline"],
        cmdline_contains: &["cline-bot", "cline-extension"],
        icon: "📎",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "Qwen Code",
        id: "qwen-code",
        comm_exact: &["qwen", "qwen-code"],
        cmdline_contains: &["qwen-code", "qwen_code"],
        icon: "🔮",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "DeepSeek",
        id: "deepseek",
        comm_exact: &["deepseek"],
        cmdline_contains: &["deepseek-cli", "deepseek-code"],
        icon: "🐋",
        category: "Coding Agent",
    },
    AgentSignature {
        name: "Kilo Code",
        id: "kilo",
        comm_exact: &["kilo", "kilo-code"],
        cmdline_contains: &["kilocode", "kilo-code"],
        icon: "📏",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "Qoder",
        id: "qoder",
        comm_exact: &["qoder", "Qoder"],
        cmdline_contains: &["qoder"],
        icon: "🔧",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "QoderWork",
        id: "qoderwork",
        comm_exact: &["qoderwork", "QoderWork"],
        cmdline_contains: &["qoderwork", "qoder-work"],
        icon: "🏗️",
        category: "IDE Agent",
    },
    AgentSignature {
        name: "Roo Code",
        id: "roo",
        comm_exact: &["roo", "roo-code"],
        cmdline_contains: &["roo-code", "roo_code", "rooveter"],
        icon: "🦘",
        category: "IDE Agent",
    },
];

// ── Data structures ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct AgentInfo {
    id: String,
    name: String,
    icon: String,
    category: String,
    status: String,
    pids: Vec<u32>,
    process_count: usize,
    cpu_percent: f64,
    mem_mb: f64,
    uptime_secs: u64,
    cmdline_preview: String,
    cwd: String,
}

#[derive(Serialize)]
struct AgentsSummary {
    agents: Vec<AgentInfo>,
    total_running: usize,
    scanned_at: u64,
    hostname: String,
}

// ── Process scanning (cross-platform via sysinfo) ────────────────────────

struct ProcessInfo {
    pid: u32,
    comm: String,
    cmdline: String,
    cpu_percent: f64,
    mem_mb: f64,
    uptime_secs: u64,
    cwd: String,
}

/// Check if `haystack` contains `needle` as a whole word.
/// Word boundaries: non-alphanumeric, non-hyphen characters or string boundaries.
/// This prevents "qoder" from matching "qoder-server" or "qoderwork".
fn contains_word(haystack: &str, needle: &str) -> bool {
    let h = haystack.to_lowercase();
    let n = needle.to_lowercase();
    let mut start = 0;
    while let Some(pos) = h[start..].find(&n) {
        let abs_pos = start + pos;
        // Before: must be start-of-string, or preceded by non-alphanumeric non-hyphen
        let before_ok = abs_pos == 0
            || (!h.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                && h.as_bytes()[abs_pos - 1] != b'-'
                && h.as_bytes()[abs_pos - 1] != b'_');
        // After: must be end-of-string, or followed by non-alphanumeric non-hyphen
        let after_pos = abs_pos + n.len();
        let after_ok = after_pos >= h.len()
            || (!h.as_bytes()[after_pos].is_ascii_alphanumeric()
                && h.as_bytes()[after_pos] != b'-'
                && h.as_bytes()[after_pos] != b'_');
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

/// Check if a PID is actually a thread (Tgid != Pid in /proc/[pid]/status).
/// On Linux, threads appear in /proc with their own TID but share memory with
/// the main process. We must skip them to avoid counting the same memory multiple times.
/// On macOS, sysinfo doesn't enumerate threads as separate processes, so this is a no-op.
fn is_thread(pid: u32) -> bool {
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        let mut tgid = None;
        let mut pid_val = None;
        for line in status.lines() {
            if line.starts_with("Tgid:") {
                tgid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u32>().ok());
            } else if line.starts_with("Pid:") {
                pid_val = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u32>().ok());
            }
            if tgid.is_some() && pid_val.is_some() {
                break;
            }
        }
        if let (Some(tgid), Some(pid_val)) = (tgid, pid_val) {
            return tgid != pid_val;
        }
    }
    false
}

fn scan_processes() -> Vec<ProcessInfo> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    // sysinfo needs two CPU snapshots to compute usage %;
    // first call gets baseline, sleep briefly, then second call computes delta
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut processes = Vec::new();

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();
        // Skip PID 1/2 (init/kernel)
        if pid_u32 <= 2 {
            continue;
        }

        let comm = process.name().to_string_lossy().to_string();

        // Skip threads: on Linux, threads have their own /proc/[tid]/ entries
        // with the same comm as the main process, but Tgid != Pid.
        if is_thread(pid_u32) {
            continue;
        }

        let cmdline: String = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");

        let cwd = process
            .cwd()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let cpu_percent = process.cpu_usage() as f64;
        let mem_mb = process.memory() as f64 / (1024.0 * 1024.0);

        let start_time = process.start_time();
        let uptime_secs = if start_time > 0 && start_time <= now {
            now - start_time
        } else {
            0
        };

        processes.push(ProcessInfo {
            pid: pid_u32,
            comm,
            cmdline,
            cpu_percent,
            mem_mb,
            uptime_secs,
            cwd,
        });
    }

    processes
}

fn match_agents(processes: &[ProcessInfo]) -> Vec<AgentInfo> {
    let mut found: HashMap<&str, Vec<&ProcessInfo>> = HashMap::new();

    for proc in processes {
        // Skip our own agentsight-local process
        let comm_lower = proc.comm.to_lowercase();
        let cmdline_lower = proc.cmdline.to_lowercase();
        if comm_lower.contains("agentsight-local") || cmdline_lower.contains("agentsight-local") {
            continue;
        }

        for sig in AGENT_SIGNATURES {
            let mut matched = false;

            // Strategy 1: exact match on process name
            for exact in sig.comm_exact {
                if comm_lower == exact.to_lowercase() {
                    matched = true;
                    break;
                }
            }

            // Strategy 2: word-boundary match on cmdline
            if !matched {
                for pattern in sig.cmdline_contains {
                    if contains_word(&cmdline_lower, pattern) {
                        matched = true;
                        break;
                    }
                }
            }

            if matched {
                found.entry(sig.id).or_default().push(proc);
                break; // one agent per process
            }
        }
    }

    let mut agents: Vec<AgentInfo> = found
        .into_iter()
        .filter_map(|(id, procs)| {
            let sig = AGENT_SIGNATURES.iter().find(|s| s.id == id)?;
            let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
            let cpu: f64 = procs.iter().map(|p| p.cpu_percent).sum();
            let mem_mb: f64 = procs.iter().map(|p| p.mem_mb).sum();
            let max_uptime = procs.iter().map(|p| p.uptime_secs).max().unwrap_or(0);
            let cmdline_preview = procs
                .first()
                .map(|p| {
                    let s = &p.cmdline;
                    if s.chars().count() > 120 {
                        format!("{}...", s.chars().take(120).collect::<String>())
                    } else {
                        s.clone()
                    }
                })
                .unwrap_or_default();
            let cwd = procs.first().map(|p| p.cwd.clone()).unwrap_or_default();

            Some(AgentInfo {
                id: sig.id.to_string(),
                name: sig.name.to_string(),
                icon: sig.icon.to_string(),
                category: sig.category.to_string(),
                status: "running".to_string(),
                pids,
                process_count: procs.len(),
                cpu_percent: (cpu * 10.0).round() / 10.0,
                mem_mb: (mem_mb * 10.0).round() / 10.0,
                uptime_secs: max_uptime,
                cmdline_preview,
                cwd,
            })
        })
        .collect();

    agents.sort_by(|a, b| b.process_count.cmp(&a.process_count));
    agents
}

fn get_hostname() -> String {
    System::host_name().unwrap_or_else(|| "unknown".to_string())
}

// ── Endpoint handler ──────────────────────────────────────────────────────

/// List running AI agent processes detected on this machine.
#[get("/api/agents")]
pub async fn list_agents() -> impl Responder {
    let result = actix_web::web::block(|| {
        let processes = scan_processes();
        let agents = match_agents(&processes);
        let total_running = agents.len();
        let scanned_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        AgentsSummary {
            agents,
            total_running,
            scanned_at,
            hostname: get_hostname(),
        }
    })
    .await;

    match result {
        Ok(summary) => HttpResponse::Ok().json(summary),
        Err(e) => HttpResponse::InternalServerError().body(format!("Process scan failed: {e}")),
    }
}
