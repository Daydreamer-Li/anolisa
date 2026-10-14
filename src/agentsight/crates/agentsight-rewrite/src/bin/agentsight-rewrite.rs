//! `agentsight-rewrite` daemon: standalone ptrace-based rewrite service.
//!
//! Attach to one target process and apply rewrite rules from a JSON file.
//! Advise mode counts matches without modifying memory; Enforce mode
//! rewrites the plaintext at the SSL boundary before encryption.
//!
//! ```text
//! agentsight-rewrite --pid 12345 --rules /etc/agentsight/rewrite.json
//! ```

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use log::{LevelFilter, Metadata, Record};

const DEFAULT_RULES_PATH: &str = "/etc/agentsight/rewrite.json";

/// Minimal logger honoring RUST_LOG level keywords (error/warn/info/debug/
/// trace; default info) without pulling env_logger into a privileged daemon.
struct StdLogger;

impl log::Log for StdLogger {
    // The `log` macros already gate calls on the global max level; accept
    // everything that reaches us.
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "{} [rewrite] {}", record.level(), record.args());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

fn init_logging() {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::Info);
    let _ = log::set_boxed_logger(Box::new(StdLogger));
    log::set_max_level(level);
}

fn die(msg: &str) -> ! {
    eprintln!("agentsight-rewrite: {msg}");
    std::process::exit(2);
}

fn parse_args() -> (i32, String, usize) {
    let args: Vec<String> = std::env::args().collect();
    let mut pid: Option<i32> = None;
    let mut rules_path = DEFAULT_RULES_PATH.to_string();
    let mut max_hits = usize::MAX;
    let mut i = 1;
    while i < args.len() {
        let flag = args[i].clone();
        if flag == "--pid" || flag == "--rules" || flag == "--max-hits" {
            i += 1;
            let Some(value) = args.get(i).cloned() else {
                die(&format!("{flag} expects a value"));
            };
            match flag.as_str() {
                "--pid" => {
                    pid = Some(
                        value
                            .parse()
                            .unwrap_or_else(|_| die("--pid expects a numeric pid")),
                    )
                }
                "--rules" => rules_path = value,
                "--max-hits" => {
                    max_hits = value
                        .parse()
                        .unwrap_or_else(|_| die("--max-hits expects a number"))
                }
                _ => unreachable!("flag matched above"),
            }
        } else {
            die(&format!(
                "unknown argument {flag:?}; expected --pid/--rules/--max-hits"
            ));
        }
        i += 1;
    }
    let Some(pid) = pid else {
        die("usage: agentsight-rewrite --pid <pid> [--rules <path>] [--max-hits <n>]");
    };
    (pid, rules_path, max_hits)
}

fn load_rules(path: &str) -> agentsight_rewrite::RuleSet {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(&format!("cannot read rules file {path}: {e}")));
    agentsight_rewrite::RuleSet::from_json(&text)
        .unwrap_or_else(|e| die(&format!("invalid rules file {path}: {e}")))
}

fn main() {
    init_logging();
    let (pid, rules_path, max_hits) = parse_args();
    let rules = load_rules(&rules_path);
    log::info!(
        "rules loaded from {rules_path}: mode={:?} rules={}",
        rules.mode,
        rules.rules.len()
    );

    if let Err(e) = agentsight_rewrite::engine::probe_breakpoint_address(pid) {
        die(&format!("target {pid} is not attachable: {e}"));
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&shutdown);
    if let Err(e) = ctrlc::set_handler(move || {
        log::info!("signal received, shutting down");
        handler_flag.store(true, Ordering::SeqCst);
    }) {
        die(&format!("cannot install signal handler: {e}"));
    }

    let mut engine = match agentsight_rewrite::RewriteEngine::attach(pid, rules) {
        Ok(e) => e,
        Err(e) => die(&format!("attach to {pid} failed: {e}")),
    };
    match engine.run(&shutdown, max_hits) {
        Ok(stats) => log::info!(
            "done: hits={} rewritten={} advise-matches={} elapsed={}ms",
            stats.hits,
            stats.rewritten,
            stats.would_match,
            stats.elapsed_ms
        ),
        Err(e) => die(&format!("engine failed: {e}")),
    }
}
