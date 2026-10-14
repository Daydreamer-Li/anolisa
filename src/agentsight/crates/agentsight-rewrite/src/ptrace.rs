//! Thin safe wrappers over the ptrace requests used by the engine.
//!
//! Every wrapper maps errno into [`RewriteError::Ptrace`]; no request is
//! retried here — callers decide on recovery (e.g. a dead thread during
//! shutdown is a normal case for the detach loop).

use std::io;

use libc::{c_int, c_long, c_void, pid_t, user_regs_struct};

use crate::error::{Result, RewriteError};

const PTRACE_CONT: c_int = 7;
const PTRACE_SINGLESTEP: c_int = 9;
const PTRACE_GETREGS: c_int = 12;
const PTRACE_SETREGS: c_int = 13;
const PTRACE_DETACH: c_int = 17;
const PTRACE_SEIZE: c_int = 0x4206;
const PTRACE_INTERRUPT: c_int = 0x4207;

extern "C" {
    fn ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;
}

fn call(op: &'static str, tid: pid_t, request: c_int, data: *mut c_void) -> Result<()> {
    // SAFETY: ptrace per man page; request/tid come from our wrappers and
    // `data` is either null or a valid out-pointer provided by the caller.
    let rc = unsafe { ptrace(request, tid, std::ptr::null_mut(), data) };
    if rc == -1 {
        return Err(RewriteError::Ptrace {
            op,
            tid,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// PTRACE_SEIZE the thread. Returns false when the thread exited in the
/// attach race (ESRCH), which is a normal condition when enumerating
/// `/proc/<pid>/task` of a live process.
pub fn seize(tid: pid_t) -> bool {
    matches!(
        unsafe {
            ptrace(
                PTRACE_SEIZE,
                tid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    )
}

pub fn getregs(tid: pid_t) -> Result<user_regs_struct> {
    let mut regs: user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: regs is a valid out-parameter of the right layout.
    let rc = unsafe {
        ptrace(
            PTRACE_GETREGS,
            tid,
            std::ptr::null_mut(),
            &mut regs as *mut user_regs_struct as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(RewriteError::Ptrace {
            op: "GETREGS",
            tid,
            source: io::Error::last_os_error(),
        });
    }
    Ok(regs)
}

pub fn setregs(tid: pid_t, regs: &user_regs_struct) -> Result<()> {
    // SAFETY: regs is a valid in-parameter of the right layout.
    let rc = unsafe {
        ptrace(
            PTRACE_SETREGS,
            tid,
            std::ptr::null_mut(),
            regs as *const user_regs_struct as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(RewriteError::Ptrace {
            op: "SETREGS",
            tid,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

pub fn cont(tid: pid_t, sig: c_int) -> Result<()> {
    call("CONT", tid, PTRACE_CONT, sig as *mut c_void)
}

pub fn singlestep(tid: pid_t) -> Result<()> {
    call("SINGLESTEP", tid, PTRACE_SINGLESTEP, std::ptr::null_mut())
}

/// PTRACE_INTERRUPT; best-effort by design (a thread may have exited).
pub fn interrupt(tid: pid_t) {
    unsafe {
        ptrace(
            PTRACE_INTERRUPT,
            tid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

/// PTRACE_DETACH; best-effort by design.
pub fn detach(tid: pid_t) {
    unsafe {
        ptrace(
            PTRACE_DETACH,
            tid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}
