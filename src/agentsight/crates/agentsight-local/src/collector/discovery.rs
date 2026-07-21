//! Cross-platform local agent session file discovery
//!
//! Scans well-known directories on the local machine for JSONL session files
//! produced by AI coding agents (Claude Code, Qoder, QoderWork, Codex, Cursor).
//! Uses `dirs::home_dir()` for cross-platform `$HOME` resolution.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Layout type for session file storage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Sessions stored under per-project subdirectories: <root>/<project>/<file>.jsonl
    PerProject,
    /// Sessions stored flat: <root>/<file>.jsonl
    Flat,
}

/// Describes where a particular agent stores its session files
struct SessionSource {
    agent_id: &'static str,
    agent_name: &'static str,
    icon: &'static str,
    dirs: &'static [&'static str],
    layout: Layout,
    /// Subdirectory names to recurse into (e.g. Qoder's "transcript")
    scan_subdirs: &'static [&'static str],
}

/// Well-known session storage locations for supported AI coding agents
static SESSION_SOURCES: &[SessionSource] = &[
    SessionSource {
        agent_id: "claude-code",
        agent_name: "Claude Code",
        icon: "🟣",
        dirs: &[".claude/projects"],
        layout: Layout::PerProject,
        scan_subdirs: &[],
    },
    SessionSource {
        agent_id: "qoder",
        agent_name: "Qoder",
        icon: "🔧",
        dirs: &[".qoder/projects"],
        layout: Layout::PerProject,
        scan_subdirs: &["transcript"],
    },
    SessionSource {
        agent_id: "qoderwork",
        agent_name: "QoderWork",
        icon: "🏗️",
        dirs: &[".qoderwork/projects"],
        layout: Layout::PerProject,
        scan_subdirs: &["transcript"],
    },
    SessionSource {
        agent_id: "codex",
        agent_name: "Codex",
        icon: "🟢",
        dirs: &[".codex/sessions", ".codex/archived_sessions"],
        layout: Layout::Flat,
        scan_subdirs: &[],
    },
    SessionSource {
        agent_id: "cursor",
        agent_name: "Cursor",
        icon: "⚡",
        dirs: &[".cursor/projects"],
        layout: Layout::PerProject,
        scan_subdirs: &[],
    },
];

/// A discovered local agent session file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSession {
    pub session_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub agent_icon: String,
    pub project: String,
    pub message_count: u32,
    pub first_message: String,
    pub file_path: String,
    pub file_size_kb: f64,
    pub modified_ts: u64,
}

/// Response for the local sessions API endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSessionsResponse {
    pub sessions: Vec<LocalSession>,
    pub total: usize,
    pub scanned_at: u64,
}

/// Discover all local agent session files across all configured agents.
pub fn discover_local_sessions() -> Vec<LocalSession> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return vec![],
    };

    let mut sessions = Vec::new();

    for source in SESSION_SOURCES {
        for rel_dir in source.dirs {
            let dir = home.join(rel_dir);
            if !dir.exists() {
                continue;
            }
            scan_source(&dir, source, &mut sessions);
        }
    }

    sessions.sort_by(|a, b| b.modified_ts.cmp(&a.modified_ts));
    sessions
}

fn scan_source(dir: &Path, source: &SessionSource, sessions: &mut Vec<LocalSession>) {
    match source.layout {
        Layout::PerProject => {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let project = decode_project_dir(&path, dir);
                        scan_project_dir(&path, source, &project, sessions);
                    }
                }
            }
        }
        Layout::Flat => {
            scan_project_dir(dir, source, "(default)", sessions);
        }
    }
}

fn scan_project_dir(
    dir: &Path,
    source: &SessionSource,
    project: &str,
    sessions: &mut Vec<LocalSession>,
) {
    // Scan top-level .jsonl files
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && path.extension().is_some_and(|ext| ext == "jsonl")
                && let Some(session) = parse_session_file(&path, source, project)
            {
                sessions.push(session);
            }
        }
    }

    // Recurse into whitelisted subdirectories (e.g. Qoder's "transcript")
    if !source.scan_subdirs.is_empty()
        && let Ok(entries) = fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if source.scan_subdirs.contains(&dir_name) {
                    scan_project_dir(&path, source, project, sessions);
                }
            }
        }
    }
}

/// Parse a JSONL session file to extract metadata for the session list.
fn parse_session_file(path: &Path, source: &SessionSource, project: &str) -> Option<LocalSession> {
    let metadata = fs::metadata(path).ok()?;
    let file_size_kb = metadata.len() as f64 / 1024.0;
    if file_size_kb < 0.05 {
        return None;
    }

    let modified_ts = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let content = fs::read_to_string(path).ok()?;
    let mut session_id = String::new();
    let mut message_count = 0u32;
    let mut first_message = String::new();
    let mut has_human_text = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let event: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");

        // Extract session_id from runtime-config or any event
        if session_id.is_empty()
            && let Some(sid) = event.get("sessionId").and_then(|v| v.as_str())
        {
            session_id = sid.to_string();
        }

        match event_type {
            "runtime-config" | "session_meta" | "progress" | "last-prompt" => continue,
            "user" | "assistant" => {
                message_count += 1;
                if event_type == "user"
                    && let Some(content_arr) =
                        event.pointer("/message/content").and_then(|c| c.as_array())
                {
                    for block in content_arr {
                        let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        if block_type == "text" {
                            let text = block.get("text").and_then(|t| t.as_str()).unwrap_or("");
                            if !text.is_empty() && first_message.is_empty() {
                                first_message = strip_system_context(text);
                                first_message = truncate(&first_message, 200);
                            }
                            has_human_text = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if !has_human_text {
        return None;
    }

    if session_id.is_empty() {
        session_id = path
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
    }

    Some(LocalSession {
        session_id,
        agent_id: source.agent_id.to_string(),
        agent_name: source.agent_name.to_string(),
        agent_icon: source.icon.to_string(),
        project: project.to_string(),
        message_count,
        first_message,
        file_path: path.to_string_lossy().to_string(),
        file_size_kb,
        modified_ts,
    })
}

/// Decode an encoded project directory name to a human-readable project name.
///
/// Qoder/Claude Code encode absolute paths into directory names by replacing
/// `/` with `-` and prefixing with `-`:
///   `-Users-john-projects-myapp` → `myapp`
///   `-data-skillopt` → `skillopt`
fn decode_project_dir(dir: &Path, _root: &Path) -> String {
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Strip leading dash
    let stripped = name.strip_prefix('-').unwrap_or(name);
    let parts: Vec<&str> = stripped.split('-').collect();

    if parts.is_empty() {
        return name.to_string();
    }

    // Look for known parent markers and return the segment after the last match
    const MARKERS: &[&str] = &[
        "code",
        "coding",
        "dev",
        "development",
        "projects",
        "repos",
        "src",
        "work",
        "workspace",
    ];

    let mut last_match_idx: Option<usize> = None;
    for (i, part) in parts.iter().enumerate() {
        if MARKERS.contains(part) {
            last_match_idx = Some(i);
        }
    }

    match last_match_idx {
        Some(idx) if idx + 1 < parts.len() => parts[idx + 1].to_string(),
        _ => parts.last().unwrap_or(&"unknown").to_string(),
    }
}

/// Strip `<system-reminder>...</system-reminder>` blocks from text.
fn strip_system_context(text: &str) -> String {
    let mut result = String::new();
    let mut in_reminder = false;
    for line in text.lines() {
        if line.contains("<system-reminder>") {
            in_reminder = true;
            continue;
        }
        if line.contains("</system-reminder>") {
            in_reminder = false;
            continue;
        }
        if !in_reminder {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(line);
        }
    }
    result.trim().to_string()
}

/// UTF-8 safe string truncation
fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect::<String>()
}
