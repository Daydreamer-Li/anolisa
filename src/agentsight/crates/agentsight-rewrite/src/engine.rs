//! Rewrite engine: the ptrace event loop driving breakpoint hits.
//!
//! Sequence per hit (identical to the validated P0 PoC):
//! 1. a thread traps on the int3 at the `SSL_write` entry;
//! 2. rewind rip, restore the original byte (disarming the breakpoint for
//!    the duration of the hit — the serialization window);
//! 3. read rdi/rsi/rdx (`SSL*`, buf, num) and the payload itself;
//! 4. decide: rules apply → variable-length rewrite via a remote mmap
//!    (buffer reuse when the cached remote buffer is large enough, munmap +
//!    bigger mmap otherwise); no rule → observe-only pass-through;
//! 5. point rsi/rdx at the new buffer (also mirror into the caller's own
//!    buffer when the replacement fits, so calling code sees the rewrite);
//! 6. single-step over the restored first instruction, re-arm the int3,
//!    continue.
//!
//! On shutdown every thread is interrupted, mid-flight register frames are
//! restored, threads are detached, and the breakpoint byte is verified.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{c_int, pid_t, user_regs_struct, waitpid, __WALL};

use crate::error::{Result, RewriteError};
use crate::maps;
use crate::proc_mem::ProcMem;
use crate::ptrace;
use crate::remote::{self, RemoteOp};
use crate::rules::RuleSet;
use crate::watchdog;

/// Cap on the payload bytes we read per hit. Real LLM requests exceed this,
/// but the plaintext header carrying the API key lives in the first bytes;
/// full-payload scanning belongs to the observation pipeline, not the
/// latency-critical rewrite path.
const MAX_PAYLOAD_READ: usize = 4096;

/// Where a thread is in the hit-handling pipeline.
#[derive(Debug)]
enum Phase {
    /// Normal execution; a stop means either a breakpoint hit or a foreign
    /// signal to forward.
    Idle,
    /// Running queued remote syscalls; one singlestep stop per op.
    Remote {
        ops: std::collections::VecDeque<RemoteOp>,
        // Boxed: user_regs_struct is ~200 bytes and Idle/StepOver carry no
        // data, so the unboxed variant trips clippy::large_enum_variant.
        orig: Box<user_regs_struct>,
        payload: Vec<u8>,
    },
    /// Stepped over the first instruction of SSL_write; re-arm + continue.
    StepOver,
}

#[derive(Debug)]
struct Thread {
    phase: Phase,
    remote_buf: u64,
    remote_cap: usize,
}

/// Counters reported back to the daemon after `run` returns.
#[derive(Debug, Default, Clone, Copy)]
pub struct EngineStats {
    pub hits: usize,
    pub rewritten: usize,
    pub would_match: usize,
    pub elapsed_ms: u128,
}

pub struct RewriteEngine {
    pid: pid_t,
    bp_addr: u64,
    orig_byte: [u8; 1],
    gadget: u64,
    mem: ProcMem,
    threads: HashMap<pid_t, Thread>,
    rules: RuleSet,
    stats: EngineStats,
    started: std::time::Instant,
}

impl RewriteEngine {
    /// Resolve the SSL_write address in the target, seize all current
    /// threads, arm the breakpoint and spawn the crash watchdog.
    pub fn attach(pid: pid_t, rules: RuleSet) -> Result<Self> {
        let maps = maps::parse_maps(pid)?;
        let (ssl_base, ssl_path) = maps::module_base(&maps, "libssl", pid)?;
        let sym_off = maps::symbol_vaddr(&ssl_path, "SSL_write")?;
        let bp_addr = ssl_base + sym_off;
        log::info!(
            "libssl base {ssl_base:#x} ({ssl_path}) SSL_write {sym_off:#x} -> bp {bp_addr:#x}"
        );

        let mut mem = ProcMem::open(pid)?;
        let gadget = maps::find_syscall_gadget(&mut mem, &maps)?;
        log::info!("remote syscall gadget at {gadget:#x}");

        let mut engine = RewriteEngine {
            pid,
            bp_addr,
            orig_byte: [0u8; 1],
            gadget,
            mem,
            threads: HashMap::new(),
            rules,
            stats: EngineStats::default(),
            started: std::time::Instant::now(),
        };
        engine.seize_all()?;
        engine.arm_breakpoint()?;
        Ok(engine)
    }

    fn seize_all(&mut self) -> Result<()> {
        let tids: Vec<pid_t> = std::fs::read_dir(format!("/proc/{}/task", self.pid))
            .map_err(RewriteError::Io)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter_map(|s| s.parse().ok())
            .collect();
        let mut seized = 0usize;
        for tid in tids {
            if ptrace::seize(tid) {
                self.threads.insert(
                    tid,
                    Thread {
                        phase: Phase::Idle,
                        remote_buf: 0,
                        remote_cap: 0,
                    },
                );
                seized += 1;
            } else {
                log::debug!("seize skipped for tid {tid} (attach race)");
            }
        }
        log::info!("seized {seized} threads");
        Ok(())
    }

    fn arm_breakpoint(&mut self) -> Result<()> {
        self.mem.read(self.bp_addr, &mut self.orig_byte)?;
        if self.orig_byte[0] == 0xCC {
            return Err(RewriteError::Config(format!(
                "byte at bp {:#x} is already 0xCC; another tracer attached?",
                self.bp_addr
            )));
        }
        self.mem.write(self.bp_addr, &[0xCC])?;
        watchdog::spawn(self.pid, self.bp_addr, self.orig_byte[0])?;
        log::info!(
            "breakpoint armed (orig byte {:#x}), watchdog spawned",
            self.orig_byte[0]
        );
        Ok(())
    }

    /// Drive the event loop until `shutdown` flips, `max_hits` is reached or
    /// the target exits. Always runs the shutdown/detach sequence before
    /// returning.
    pub fn run(&mut self, shutdown: &AtomicBool, max_hits: usize) -> Result<EngineStats> {
        loop {
            if shutdown.load(Ordering::SeqCst) {
                log::info!("shutdown requested");
                break;
            }
            if self.stats.hits >= max_hits {
                log::info!("hit limit {max_hits} reached");
                break;
            }
            if self.threads.is_empty() {
                log::info!("no threads left under control, target finished");
                break;
            }
            let mut status: c_int = 0;
            let tid = unsafe { waitpid(-1, &mut status, __WALL) };
            if tid < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if err.raw_os_error() == Some(libc::ECHILD) {
                    log::info!("all tracees gone");
                    break;
                }
                log::warn!("waitpid failed: {err}");
                break;
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.threads.remove(&tid);
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            let sig = libc::WSTOPSIG(status);
            let event = (status >> 16) as c_int;
            self.handle_stop(tid, sig, event);
        }
        self.stats.elapsed_ms = self.started.elapsed().as_millis();
        self.shutdown();
        Ok(self.stats)
    }

    fn handle_stop(&mut self, tid: pid_t, sig: c_int, event: c_int) {
        // Take the phase out so the helpers below can re-enter
        // `self.threads` without holding a borrow across self calls.
        let phase = match self.threads.get_mut(&tid) {
            Some(th) => std::mem::replace(&mut th.phase, Phase::Idle),
            None => return,
        };
        match phase {
            Phase::Idle => self.handle_idle(tid, sig, event),
            Phase::Remote {
                mut ops,
                orig,
                payload,
            } => self.handle_remote(tid, &mut ops, *orig, payload),
            Phase::StepOver => self.step_over(tid),
        }
    }

    fn handle_idle(&mut self, tid: pid_t, sig: c_int, event: c_int) {
        if event == 0 && sig == libc::SIGTRAP {
            let regs = match ptrace::getregs(tid) {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("hit handling: getregs tid {tid}: {e}; forwarding signal");
                    let _ = ptrace::cont(tid, sig);
                    return;
                }
            };
            let hit_rip = regs.rip - 1;
            if hit_rip != self.bp_addr {
                // A foreign SIGTRAP: deliver it unchanged.
                let _ = ptrace::cont(tid, sig);
                return;
            }
            self.process_hit(tid, regs);
        } else if event == libc::PTRACE_EVENT_STOP && sig == libc::SIGTRAP {
            // group-stop / interrupt-stop: resume without signal injection
            let _ = ptrace::cont(tid, 0);
        } else {
            // Unrelated signal: forward unchanged.
            let _ = ptrace::cont(tid, sig);
        }
    }

    fn process_hit(&mut self, tid: pid_t, mut regs: user_regs_struct) {
        self.stats.hits += 1;
        regs.rip = self.bp_addr; // rewind onto the instruction to re-execute
        let orig = regs;

        if let Err(e) = self.mem.write(self.bp_addr, &self.orig_byte) {
            log::error!("hit {tid}: cannot disarm breakpoint: {e}");
            return;
        }

        let buf_ptr = regs.rsi;
        let num = regs.rdx as usize;
        let mut payload = vec![0u8; num.min(MAX_PAYLOAD_READ)];
        if num > 0 && num <= MAX_PAYLOAD_READ {
            if let Err(e) = self.mem.read(buf_ptr, &mut payload) {
                log::warn!("hit {tid}: payload read failed: {e}; passing through");
            }
        }

        // Preferred mode: equal-length in-place substring patches. They keep
        // the request line, headers and Content-Length framing intact and
        // need no remote allocation (validated against real node/python
        // runtimes; see the P0 field-test notes).
        if let Some(patches) = self.rules.patches_in_place(&payload) {
            self.stats.rewritten += 1;
            let mut after = payload.clone();
            let mut ok = true;
            for (at, bytes) in &patches {
                after[*at..*at + bytes.len()].copy_from_slice(bytes);
                if let Err(e) = self.mem.write(buf_ptr + *at as u64, bytes) {
                    log::error!("hit {tid}: in-place patch write failed: {e}");
                    ok = false;
                }
            }
            if !ok {
                return;
            }
            log::info!(
                "hit#{} tid={tid} len={num} in-place rewrite ({} patches): {:?} => {:?}",
                self.stats.hits,
                patches.len(),
                String::from_utf8_lossy(&payload),
                String::from_utf8_lossy(&after)
            );
            if let Err(e) = ptrace::setregs(tid, &orig).and_then(|_| ptrace::singlestep(tid)) {
                log::error!("hit {tid}: passthrough resume failed: {e}");
            }
            if let Some(th) = self.threads.get_mut(&tid) {
                th.phase = Phase::StepOver;
            }
            return;
        }

        let replacement = self.rules.apply(&payload);
        if replacement.is_none() && self.rules.would_match(&payload) {
            self.stats.would_match += 1;
            log::info!(
                "hit#{} tid={tid} len={num} advise-match (enforce would rewrite)",
                self.stats.hits
            );
        }

        let Some(np) = replacement else {
            // Observe-only pass-through.
            if let Err(e) = ptrace::setregs(tid, &orig).and_then(|_| ptrace::singlestep(tid)) {
                log::error!("hit {tid}: passthrough resume failed: {e}");
            }
            if let Some(th) = self.threads.get_mut(&tid) {
                th.phase = Phase::StepOver;
            }
            return;
        };

        self.stats.rewritten += 1;
        log::info!(
            "hit#{} tid={tid} len={num} rewrite {} bytes: {:?} => {:?}",
            self.stats.hits,
            np.len(),
            String::from_utf8_lossy(&payload),
            String::from_utf8_lossy(&np)
        );

        let need = np.len();
        // Snapshot the thread's remote-buffer state; the borrow must end
        // before the memory/ptrace calls below.
        let (remote_buf, remote_cap) = match self.threads.get_mut(&tid) {
            Some(t) => (t.remote_buf, t.remote_cap),
            None => return,
        };
        if remote_cap >= need {
            // Reuse the cached remote buffer: no remote syscall needed.
            // (An empty op queue here was a silent starve in the PoC: the
            // thread parked forever with the breakpoint disarmed.)
            if self.apply_remote(tid, remote_buf, &orig, &np).is_err() {
                return;
            }
            if let Some(th) = self.threads.get_mut(&tid) {
                singlestep_to_stepover(tid, th);
            }
        } else {
            let mut ops = std::collections::VecDeque::new();
            if remote_buf != 0 {
                ops.push_back(RemoteOp::Munmap {
                    addr: remote_buf,
                    len: remote_cap as u64,
                });
            }
            ops.push_back(RemoteOp::Mmap {
                len: remote::page_round(need),
            });
            // Park on the gadget while we still hold the local op queue;
            // the resulting stop is consumed by the next loop iteration,
            // by which time the phase below is in place.
            self.kick_remote(tid, &ops);
            if let Some(th) = self.threads.get_mut(&tid) {
                th.phase = Phase::Remote {
                    ops,
                    orig: Box::new(orig),
                    payload: np,
                };
            }
        }
    }

    /// Write the replacement into the (cached) remote buffer, mirror it into
    /// the caller's buffer when it fits, point rsi/rdx at the remote copy.
    fn apply_remote(
        &mut self,
        tid: pid_t,
        remote_buf: u64,
        orig: &user_regs_struct,
        np: &[u8],
    ) -> Result<()> {
        self.mem.write(remote_buf, np)?;
        if np.len() <= orig.rdx as usize {
            let _ = self.mem.write(orig.rsi, np);
        }
        let mut r = *orig;
        r.rsi = remote_buf;
        r.rdx = np.len() as u64;
        ptrace::setregs(tid, &r)
    }

    fn handle_remote(
        &mut self,
        tid: pid_t,
        ops: &mut std::collections::VecDeque<RemoteOp>,
        orig: user_regs_struct,
        payload: Vec<u8>,
    ) {
        let Some(op) = ops.front().cloned() else {
            // Cannot happen: Phase::Remote is only entered with a non-empty
            // queue (see process_hit); recover defensively anyway.
            self.recover(tid, &orig);
            return;
        };
        let after = match ptrace::getregs(tid) {
            Ok(r) => r,
            Err(e) => {
                log::error!("remote op: getregs tid {tid}: {e}");
                self.recover(tid, &orig);
                return;
            }
        };
        if let Err(e) = remote::check_result(&op, after.rax) {
            log::error!("remote op failed on tid {tid}: {e}");
            self.recover(tid, &orig);
            return;
        }
        match op {
            RemoteOp::Mmap { len } => {
                if self.apply_remote(tid, after.rax, &orig, &payload).is_err() {
                    return;
                }
                if let Some(th) = self.threads.get_mut(&tid) {
                    th.remote_buf = after.rax;
                    th.remote_cap = len as usize;
                    singlestep_to_stepover(tid, th);
                }
            }
            RemoteOp::Munmap { .. } => {
                ops.pop_front();
                self.kick_remote(tid, ops);
                if let Some(th) = self.threads.get_mut(&tid) {
                    th.phase = Phase::Remote {
                        ops: ops.clone(),
                        orig: Box::new(orig),
                        payload,
                    };
                }
            }
        }
    }

    /// Park the thread on the syscall gadget for the first queued op and
    /// singlestep through it.
    fn kick_remote(&self, tid: pid_t, ops: &std::collections::VecDeque<RemoteOp>) {
        let Some(op) = ops.front() else {
            return;
        };
        let res = ptrace::getregs(tid)
            .and_then(|cur| {
                let frame = remote::regs_for(op, &cur, self.gadget);
                ptrace::setregs(tid, &frame)
            })
            .and_then(|_| ptrace::singlestep(tid));
        if let Err(e) = res {
            log::error!("remote op: park on gadget tid {tid}: {e}");
        }
    }

    /// Re-arm the breakpoint and resume normal execution.
    fn step_over(&mut self, tid: pid_t) {
        if let Err(e) = self.mem.write(self.bp_addr, &[0xCC]) {
            log::error!("re-arm failed on tid {tid}: {e}");
        }
        if let Some(th) = self.threads.get_mut(&tid) {
            th.phase = Phase::Idle;
        }
        let _ = ptrace::cont(tid, 0);
    }

    /// Best-effort recovery for a thread whose mid-pipeline state broke:
    /// restore the original register frame and resume. The breakpoint byte
    /// is already disarmed at that point, so the thread continues normally.
    fn recover(&mut self, tid: pid_t, orig: &user_regs_struct) {
        log::warn!("recovering tid {tid} to pre-hit state");
        if let Err(e) = ptrace::setregs(tid, orig).and_then(|_| ptrace::cont(tid, 0)) {
            log::error!("recover tid {tid} failed: {e}; dropping thread from map");
            self.threads.remove(&tid);
        } else {
            if let Some(th) = self.threads.get_mut(&tid) {
                th.phase = Phase::Idle;
            }
            // The breakpoint byte is disarmed at this point; re-arm now so
            // the engine does not miss hits until the next StepOver.
            let _ = self.mem.write(self.bp_addr, &[0xCC]);
        }
    }

    fn shutdown(&mut self) {
        log::info!(
            "shutting down: hits={} rewritten={} advise-matches={} elapsed={}ms",
            self.stats.hits,
            self.stats.rewritten,
            self.stats.would_match,
            self.stats.elapsed_ms
        );
        // Restore the byte first so resumed threads never see the int3.
        if let Err(e) = self.mem.write(self.bp_addr, &self.orig_byte) {
            log::warn!("bp restore failed: {e}");
        }
        let tids: Vec<pid_t> = self.threads.keys().copied().collect();
        for tid in tids {
            let Some(th) = self.threads.get_mut(&tid) else {
                continue;
            };
            let restore = match &th.phase {
                Phase::Remote { orig, .. } => Some(**orig),
                _ => None,
            };
            ptrace::interrupt(tid);
            let mut status: c_int = 0;
            let w = unsafe { waitpid(tid, &mut status, __WALL) };
            if w < 0 || !libc::WIFSTOPPED(status) {
                log::debug!("tid {tid} exited during shutdown, skipping detach");
                continue;
            }
            if let Some(orig) = restore {
                if let Err(e) = ptrace::setregs(tid, &orig) {
                    log::warn!("mid-flight regs restore failed for tid {tid}: {e}");
                }
            }
            ptrace::detach(tid);
        }
        self.threads.clear();
        // Belt and braces (also covers the watchdog being unable to run).
        let _ = self.mem.write(self.bp_addr, &self.orig_byte);
        if unsafe { libc::kill(self.pid, 0) } != 0 {
            log::info!("target exited after detach");
            return;
        }
        let mut check = [0u8; 1];
        match self.mem.read(self.bp_addr, &mut check) {
            Ok(()) if check == self.orig_byte => {
                log::info!("clean detach, no residual breakpoint");
            }
            Ok(()) => log::error!(
                "bp byte {:#x} != expected {:#x} after detach",
                check[0],
                self.orig_byte[0]
            ),
            Err(e) => log::error!("bp byte verification failed: {e}"),
        }
    }
}

/// After the replacement registers are set, single-step over the first
/// instruction of SSL_write; the resulting stop is handled as StepOver.
fn singlestep_to_stepover(tid: pid_t, th: &mut Thread) {
    match ptrace::singlestep(tid) {
        Ok(()) => th.phase = Phase::StepOver,
        Err(e) => log::error!("singlestep tid {tid}: {e}"),
    }
}

/// Resolve the breakpoint address for `pid` without attaching (used by the
/// daemon for a pre-flight check and logging).
pub fn probe_breakpoint_address(pid: pid_t) -> Result<u64> {
    let maps = maps::parse_maps(pid)?;
    let (base, path) = maps::module_base(&maps, "libssl", pid)?;
    Ok(base + maps::symbol_vaddr(&path, "SSL_write")?)
}
