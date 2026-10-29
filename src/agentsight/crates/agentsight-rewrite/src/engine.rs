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
    /// Per-hit stop duration (breakpoint trap -> resume), microseconds.
    pub lat_p50_us: u64,
    pub lat_p99_us: u64,
    pub lat_max_us: u64,
}

/// One planted int3 and the byte it replaced.
struct Breakpoint {
    addr: u64,
    orig: [u8; 1],
}

pub struct RewriteEngine {
    pid: pid_t,
    bps: Vec<Breakpoint>,
    gadget: u64,
    mem: ProcMem,
    threads: HashMap<pid_t, Thread>,
    rules: RuleSet,
    stats: EngineStats,
    started: std::time::Instant,
    /// Hit currently being serviced (single-threaded event loop, so at most
    /// one at a time); completed on the resume in `step_over`.
    hit_start: Option<std::time::Instant>,
    latencies_us: Vec<u64>,
    last_thread_scan: std::time::Instant,
    /// Address-space snapshot at attach time; used to map VAs back to file
    /// offsets when reading original instruction bytes under a live uprobe.
    maps_snapshot: Vec<maps::MapEntry>,
}

/// How often to rescan /proc/<pid>/task for threads spawned after attach.
/// Untraced threads that hit a planted int3 die with SIGTRAP (they have no
/// tracer and usually no safety-net handler), so the scan interval is a
/// correctness bound, not a performance knob.
const THREAD_SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

extern "C" fn on_alarm(_: c_int) {
    // Empty: its only job is to interrupt the blocking waitpid (EINTR) so
    // the event loop can rescan threads and check the shutdown flag.
}

/// Start the periodic ITIMER_REAL that wakes the blocking waitpid every
/// THREAD_SCAN_INTERVAL. Replaces the PoC's 500µs WNOHANG busy-poll: the
/// loop now sleeps in the kernel between events (idle CPU ~0) and only
/// wakes on real ptrace events or the timer tick.
fn start_scan_timer() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as usize;
        // Deliberately WITHOUT SA_RESTART: the EINTR wake-up is the point.
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: THREAD_SCAN_INTERVAL.as_micros() as libc::suseconds_t,
        };
        let it = libc::itimerval {
            it_interval: tv,
            it_value: tv,
        };
        assert_eq!(
            libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()),
            0
        );
    }
}

impl RewriteEngine {
    /// Resolve the SSL_write address in the target, seize all current
    /// threads, arm the breakpoint and spawn the crash watchdog.
    pub fn attach(
        pid: pid_t,
        rules: RuleSet,
        offsets: Option<crate::offsets::OffsetTable>,
    ) -> Result<Self> {
        let maps = maps::parse_maps(pid)?;
        let mut mem = ProcMem::open(pid)?;

        let resolved = resolve_breakpoints(pid, &maps, &mut mem, offsets.as_ref())?;

        let gadget = maps::find_syscall_gadget(&mut mem, &maps)?;
        log::info!("remote syscall gadget at {gadget:#x}");

        let mut engine = RewriteEngine {
            pid,
            bps: Vec::new(),
            gadget,
            mem,
            threads: HashMap::new(),
            rules,
            stats: EngineStats::default(),
            started: std::time::Instant::now(),
            hit_start: None,
            latencies_us: Vec::new(),
            last_thread_scan: std::time::Instant::now() - THREAD_SCAN_INTERVAL,
            maps_snapshot: maps.clone(),
        };
        engine.seize_all()?;
        engine.arm_breakpoints(&resolved)?;
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

    /// SEIZE threads spawned after attach. A window remains (a thread that
    /// traps between its creation and the next scan is still lost) but it
    /// shrinks the exposure from "all future threads" to "50ms of thread
    /// lifetime"; combined with the target-side SIGTRAP safety net this is
    /// the P0-validated containment.
    fn seize_new_threads(&mut self) {
        let tids: Vec<pid_t> = std::fs::read_dir(format!("/proc/{}/task", self.pid))
            .map_err(RewriteError::Io)
            .ok()
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        for tid in tids {
            if self.threads.contains_key(&tid) {
                continue;
            }
            if ptrace::seize(tid) {
                log::debug!("seized new thread {tid}");
                self.threads.insert(
                    tid,
                    Thread {
                        phase: Phase::Idle,
                        remote_buf: 0,
                        remote_cap: 0,
                    },
                );
            }
        }
    }

    fn arm_breakpoints(&mut self, resolved: &[(u64, String)]) -> Result<()> {
        for (entry, what) in resolved {
            // Agentsight trace runs uprobes on the same entry. A live uprobe
            // shows up as int3 (0xCC) on the first byte; planting there is
            // impossible (the kernel consumes that trap and the ptrace
            // tracer never sees it). Shift our int3 past the first
            // instruction instead: entry fires the uprobe (kernel XOLs the
            // first insn and resumes right after it), and the very next
            // byte is ours. Only the ubiquitous endbr64 prologue is
            // recognized -- anything else fails closed.
            let mut head = [0u8; 8];
            self.mem.read(*entry, &mut head)?;
            let mut addr = *entry;
            let mut shifted = false;
            if head[0] == 0xCC {
                let entry = *entry;
                // A live uprobe owns the entry: its int3 replaced the first
                // byte of the first instruction. Recover the ORIGINAL bytes
                // from the backing file (via PT_LOAD) and decode that
                // instruction's length to place our int3 at the second
                // instruction boundary -- entry still fires the uprobe, and
                // the byte right after it is ours. Anything unrecoverable or
                // unrecognized fails closed.
                let image = self
                    .maps_snapshot
                    .iter()
                    .find(|m| entry >= m.start && entry < m.end)
                    .map(|m| m.path.clone())
                    .ok_or_else(|| {
                        RewriteError::Config(format!(
                            "entry {entry:#x}: no backing image found in maps"
                        ))
                    })?;
                let image_base = self
                    .maps_snapshot
                    .iter()
                    .filter(|m| m.path == image)
                    .map(|m| m.start)
                    .min()
                    .unwrap_or(0);
                let rel = entry - image_base;
                let file_off = maps::vaddr_to_file_offset(&image, rel).ok_or_else(|| {
                    RewriteError::Config(format!(
                        "entry {entry:#x}: cannot map VA to file offset in {image}"
                    ))
                })?;
                let mut orig_head = [0u8; 16];
                std::fs::File::open(&image)
                    .and_then(|mut f| {
                        use std::io::{Read, Seek, SeekFrom};
                        f.seek(SeekFrom::Start(file_off))?;
                        f.read_exact(&mut orig_head)?;
                        Ok(())
                    })
                    .map_err(|e| {
                        RewriteError::Config(format!(
                            "entry {entry:#x}: cannot read original bytes from {image}: {e}"
                        ))
                    })?;
                let len = maps::first_insn_len(&orig_head).ok_or_else(|| {
                    RewriteError::Config(format!(
                        "entry {entry:#x}: first instruction {:02x?} not recognized; \
                         refusing to guess a shift over a live uprobe",
                        &orig_head[..4.min(orig_head.len())]
                    ))
                })?;
                addr = entry + len;
                shifted = true;
                log::info!(
                    "uprobe detected at entry {entry:#x} (orig insn {len}B); \
                     shifting our int3 to {addr:#x}"
                );
            }

            let mut orig = [0u8; 1];
            self.mem.read(addr, &mut orig)?;
            if orig[0] == 0xCC {
                return Err(RewriteError::Config(format!(
                    "byte at {addr:#x} is already 0xCC; another tracer attached?"
                )));
            }
            self.mem.write(addr, &[0xCC])?;
            watchdog::spawn(self.pid, addr, orig[0])?;
            log::info!(
                "breakpoint armed at {addr:#x} ({what}, orig {:#x}{})",
                orig[0],
                if shifted {
                    ", shifted +4 over live uprobe"
                } else {
                    ""
                }
            );
            self.bps.push(Breakpoint { addr, orig });
        }
        Ok(())
    }

    /// Drive the event loop until `shutdown` flips, `max_hits` is reached or
    /// the target exits. Always runs the shutdown/detach sequence before
    /// returning.
    pub fn run(&mut self, shutdown: &AtomicBool, max_hits: usize) -> Result<EngineStats> {
        start_scan_timer();
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
            // Block until the next ptrace event. The ITIMER_REAL tick
            // interrupts us every THREAD_SCAN_INTERVAL (EINTR) so the thread
            // rescan and the shutdown check stay live while idle. Blocking
            // (instead of the PoC's WNOHANG polling) removes the p99 polling
            // tail: a stopped thread is served the moment its stop arrives.
            if self.last_thread_scan.elapsed() >= THREAD_SCAN_INTERVAL {
                self.last_thread_scan = std::time::Instant::now();
                self.seize_new_threads();
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
        let mut lat = std::mem::take(&mut self.latencies_us);
        lat.sort_unstable();
        if !lat.is_empty() {
            self.stats.lat_p50_us = lat[lat.len() / 2];
            self.stats.lat_p99_us = lat[lat.len() * 99 / 100];
            self.stats.lat_max_us = lat[lat.len() - 1];
        }
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
            let Some(bp) = self.bps.iter().find(|b| b.addr == hit_rip) else {
                // A foreign SIGTRAP: deliver it unchanged.
                let _ = ptrace::cont(tid, sig);
                return;
            };
            let (bp_addr, orig_byte) = (bp.addr, bp.orig);
            self.hit_start = Some(std::time::Instant::now());
            self.process_hit(tid, regs, bp_addr, orig_byte);
        } else if event == libc::PTRACE_EVENT_STOP && sig == libc::SIGTRAP {
            // group-stop / interrupt-stop: resume without signal injection
            let _ = ptrace::cont(tid, 0);
        } else {
            // Unrelated signal: forward unchanged.
            let _ = ptrace::cont(tid, sig);
        }
    }

    fn process_hit(
        &mut self,
        tid: pid_t,
        mut regs: user_regs_struct,
        bp_addr: u64,
        orig_byte: [u8; 1],
    ) {
        self.stats.hits += 1;
        regs.rip = bp_addr; // rewind onto the instruction to re-execute
        let orig = regs;

        if let Err(e) = self.mem.write(bp_addr, &orig_byte) {
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
        for b in &self.bps {
            if let Err(e) = self.mem.write(b.addr, &[0xCC]) {
                log::error!("re-arm failed on tid {tid}: {e}");
            }
        }
        if let Some(th) = self.threads.get_mut(&tid) {
            th.phase = Phase::Idle;
        }
        let _ = ptrace::cont(tid, 0);
        if let Some(t0) = self.hit_start.take() {
            self.latencies_us.push(t0.elapsed().as_micros() as u64);
        }
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
            // The breakpoint bytes are disarmed at this point; re-arm now
            // so the engine does not miss hits until the next StepOver.
            for b in &self.bps {
                let _ = self.mem.write(b.addr, &[0xCC]);
            }
        }
    }

    fn shutdown(&mut self) {
        let mut lat = self.latencies_us.clone();
        lat.sort_unstable();
        let (p50, p99) = (
            lat.get(lat.len() / 2).copied().unwrap_or(0),
            lat.get(lat.len() * 99 / 100).copied().unwrap_or(0),
        );
        log::info!(
            "shutting down: hits={} rewritten={} advise-matches={} elapsed={}ms lat_us p50={p50} p99={p99}",
            self.stats.hits,
            self.stats.rewritten,
            self.stats.would_match,
            self.stats.elapsed_ms
        );
        // Restore the bytes first so resumed threads never see the int3.
        for b in &self.bps {
            if let Err(e) = self.mem.write(b.addr, &b.orig) {
                log::warn!("bp restore failed: {e}");
            }
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
        for b in &self.bps {
            let _ = self.mem.write(b.addr, &b.orig);
        }
        if unsafe { libc::kill(self.pid, 0) } != 0 {
            log::info!("target exited after detach");
            return;
        }
        for b in &self.bps {
            let mut check = [0u8; 1];
            match self.mem.read(b.addr, &mut check) {
                Ok(()) if check == b.orig => log::debug!("bp {:#x} restored", b.addr),
                Ok(()) => log::error!(
                    "bp {:#x} byte {:#x} != expected {:#x} after detach",
                    b.addr,
                    check[0],
                    b.orig[0]
                ),
                Err(e) => log::error!("bp byte verification failed: {e}"),
            }
        }
        log::info!("clean detach, no residual breakpoint");
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

/// Resolve the SSL_write breakpoint address for `pid` with the full tier
/// Resolve every SSL-write-family breakpoint for `pid` with the full tier
/// chain, shared by the daemon pre-flight check and `attach`:
///
/// - tier 1: dynamic libssl symbol table;
/// - tier 1.5: main executable symbol table (unstripped static builds such
///   as uv-Python keep SSL_write / SSL_write_ex as local .symtab symbols);
/// - tier 2: prologue-pattern confidence chain.
///
/// SSL_write_ex shares SSL_write's first three arguments, so both entry
/// points run the same rewrite logic; OpenSSL 3 callers may use only the
/// `_ex` variant, so both must be instrumented.
fn resolve_breakpoints(
    pid: pid_t,
    maps: &[maps::MapEntry],
    mem: &mut ProcMem,
    offsets: Option<&crate::offsets::OffsetTable>,
) -> Result<Vec<(u64, String)>> {
    let mut out = Vec::new();
    let symbol_host: Option<(u64, String)> = match maps::module_base(maps, "libssl", pid) {
        Ok((base, path)) => Some((base, path)),
        Err(_) => {
            let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                .map_err(RewriteError::Io)?
                .to_string_lossy()
                .into_owned();
            // ET_DYN (PIE): st_value is relative to the load base.
            let base = maps
                .iter()
                .filter(|m| m.path == exe)
                .map(|m| m.start)
                .min()
                .unwrap_or(0);
            Some((base, exe))
        }
    };
    if let Some((base, path)) = symbol_host {
        for sym in ["SSL_write", "SSL_write_ex"] {
            if let Ok(va) = maps::symbol_runtime_vaddr(&path, sym, base) {
                let tier = if out.is_empty() { "1" } else { "1b" };
                out.push((va, format!("tier{tier}-sym {sym} ({path})")));
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(RewriteError::Io)?
        .to_string_lossy()
        .into_owned();
    let base = maps
        .iter()
        .filter(|m| m.path == exe)
        .map(|m| m.start)
        .min()
        .unwrap_or(0);
    for sym in ["SSL_write", "SSL_write_ex"] {
        if let Ok(va) = maps::symbol_runtime_vaddr(&exe, sym, base) {
            let tier = if out.is_empty() { "1.5" } else { "1.5b" };
            out.push((va, format!("tier{tier}-exe-sym {sym} ({exe})")));
        }
    }
    if out.is_empty() {
        // Tier 3: offset fingerprint table (agentsight.json codex_offsets
        // format) for stripped binaries with no symbols at all. Entry values
        // follow the same convention as symbol values: relative for ET_DYN,
        // absolute for ET_EXEC.
        if let Some(table) = offsets {
            if let Some(off) = table.lookup(&exe) {
                let et_dyn = maps::is_dyn_elf(&exe).unwrap_or(true);
                let va = if et_dyn {
                    base + off.ssl_write
                } else {
                    off.ssl_write
                };
                let variant = if off.write_is_ex {
                    "SSL_write_ex"
                } else {
                    "SSL_write"
                };
                out.push((va, format!("tier3-fingerprint {variant} ({exe})")));
            }
        }
    }
    if out.is_empty() {
        let va = maps::find_static_write_va(mem, maps, &exe).ok_or_else(|| {
            RewriteError::SymbolNotFound {
                symbol: "SSL_write (static pattern)".to_string(),
                path: exe.clone(),
            }
        })?;
        out.push((va, format!("tier2-pattern ({exe})")));
    }
    Ok(out)
}

/// Resolve the breakpoint address for `pid` without attaching (used by the
/// daemon for a pre-flight check and logging).
pub fn probe_breakpoint_address(pid: pid_t) -> Result<u64> {
    probe_breakpoint_address_with_offsets(pid, None)
}

/// Same as `probe_breakpoint_address`, with an offset fingerprint table.
pub fn probe_breakpoint_address_with_offsets(
    pid: pid_t,
    offsets: Option<&crate::offsets::OffsetTable>,
) -> Result<u64> {
    let maps = maps::parse_maps(pid)?;
    let mut mem = ProcMem::open(pid)?;
    let all = resolve_breakpoints(pid, &maps, &mut mem, offsets)?;
    Ok(all[0].0)
}
