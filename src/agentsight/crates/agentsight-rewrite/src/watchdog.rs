//! Crash-safety watchdog.
//!
//! The tracer forks a child holding the read end of a pipe. The parent keeps
//! the write end open for its whole lifetime; the file descriptor is closed
//! by the kernel no matter how the parent dies — clean exit, panic, SIGKILL —
//! at which point the child wakes and restores the original breakpoint byte
//! through `/proc/<pid>/mem` (no ptrace attachment required).
//!
//! The restore is idempotent: on a clean shutdown the engine restores the
//! byte itself and the watchdog writes the identical byte again.
//!
//! Known boundary (see the P0 PoC README): the watchdog cannot rescue a
//! thread that is parked in a ptrace-stop at the breakpoint when the tracer
//! dies — the kernel's auto-detach delivers the pending SIGTRAP to the
//! target. Healing that case requires the target-side SIGTRAP safety-net
//! handler; this module only guarantees the byte itself is never left behind.

use libc::{c_int, c_void, pid_t};

use crate::error::{Result, RewriteError};

extern "C" {
    fn fork() -> i32;
}

/// Fork the watchdog. Must be called after the breakpoint byte has been
/// replaced, so the child knows the value to restore.
pub fn spawn(pid: pid_t, bp_addr: u64, orig_byte: u8) -> Result<()> {
    let mut fds = [0 as c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(RewriteError::Io(std::io::Error::last_os_error()));
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    // SAFETY: fork per man page; the child branch never returns into the
    // parent's Rust runtime state and exits via libc::_exit.
    match unsafe { fork() } {
        0 => child_watch(pid, bp_addr, orig_byte, read_fd, write_fd),
        child if child > 0 => {
            unsafe {
                libc::close(read_fd);
            }
            // Intentionally leave `write_fd` open for the parent's whole
            // lifetime: it keeps the child blocked, and the kernel closes it
            // on any exit path, which is the watchdog trigger.
            Ok(())
        }
        _ => {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            Err(RewriteError::Fork(std::io::Error::last_os_error()))
        }
    }
}

fn child_watch(pid: pid_t, bp_addr: u64, orig_byte: u8, read_fd: c_int, write_fd: c_int) -> ! {
    unsafe {
        libc::close(write_fd);
        let mut sink = [0u8; 1];
        // Block until every write end is gone (i.e. the tracer exited).
        while libc::read(read_fd, sink.as_mut_ptr() as *mut c_void, 1) > 0 {}
        libc::close(read_fd);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/mem"))
        {
            use std::io::{Seek, SeekFrom, Write};
            let _ = f.seek(SeekFrom::Start(bp_addr));
            let _ = f.write_all(&[orig_byte]);
        }
        libc::_exit(0);
    }
}
