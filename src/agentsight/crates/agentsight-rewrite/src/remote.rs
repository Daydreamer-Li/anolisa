//! Remote syscall execution inside the target process.
//!
//! While a thread is stopped at a breakpoint we park it on a `syscall`
//! instruction inside libc, load the syscall ABI into registers, single-step
//! through the syscall, and read the return value from rax. This is what
//! makes variable-length rewrites possible: we mmap a fresh buffer in the
//! target's address space and point rsi/rdx at it.
//!
//! Invariants learned in the PoC:
//! - the register frame handed to SETREGS must be derived from the thread's
//!   current frame; a zeroed frame has `cs = 0`, which the kernel rejects
//!   with EIO;
//! - the engine's waitpid loop must consume the singlestep stop before the
//!   result register is read — these helpers therefore only build frames and
//!   validate results, the sequencing lives in `engine`.

use libc::user_regs_struct;

use crate::error::RewriteError;

const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;
const PROT_READ_WRITE: u64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x02 | 0x20;

pub const PAGE_SIZE: u64 = 0x1000;

/// One remote memory-management operation, executed in the target process.
#[derive(Debug, Clone)]
pub enum RemoteOp {
    /// mmap(len) — returns the new buffer address in rax.
    Mmap { len: u64 },
    /// munmap(addr, len) — frees a previously allocated remote buffer.
    Munmap { addr: u64, len: u64 },
}

/// Round `len` up to page granularity with a one-page floor.
pub fn page_round(len: usize) -> u64 {
    let l = len as u64;
    ((l + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)).max(PAGE_SIZE)
}

/// Build the register frame for `op`, parked on the syscall gadget.
/// Everything except the syscall ABI fields and rip is inherited from the
/// thread's current frame (notably cs/ss, which SETREGS validates).
pub fn regs_for(op: &RemoteOp, current: &user_regs_struct, gadget: u64) -> user_regs_struct {
    let mut r = *current;
    match op {
        RemoteOp::Mmap { len } => {
            r.rax = SYS_MMAP;
            r.rdi = 0; // addr: kernel picks
            r.rsi = *len;
            r.rdx = PROT_READ_WRITE;
            r.r10 = MAP_PRIVATE_ANONYMOUS;
            r.r8 = u64::MAX; // fd = -1
            r.r9 = 0; // offset
        }
        RemoteOp::Munmap { addr, len } => {
            r.rax = SYS_MUNMAP;
            r.rdi = *addr;
            r.rsi = *len;
        }
    }
    r.rip = gadget;
    r
}

/// Validate the rax returned by a completed remote syscall.
pub fn check_result(op: &RemoteOp, rax: u64) -> Result<(), RewriteError> {
    let ret = rax as i64;
    let failed = match op {
        RemoteOp::Mmap { .. } => (-4095..=-1).contains(&ret),
        RemoteOp::Munmap { .. } => ret != 0,
    };
    if failed {
        let name = match op {
            RemoteOp::Mmap { .. } => "mmap",
            RemoteOp::Munmap { .. } => "munmap",
        };
        return Err(RewriteError::RemoteSyscall { op: name, ret });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> user_regs_struct {
        let mut r: user_regs_struct = unsafe { std::mem::zeroed() };
        r.cs = 0x33;
        r.rip = 0x1000;
        r
    }

    #[test]
    fn page_round_floors_at_one_page() {
        assert_eq!(page_round(0), PAGE_SIZE);
        assert_eq!(page_round(1), PAGE_SIZE);
        assert_eq!(page_round(PAGE_SIZE as usize), PAGE_SIZE);
        assert_eq!(page_round(PAGE_SIZE as usize + 1), 2 * PAGE_SIZE);
    }

    #[test]
    fn mmap_frame_sets_abi_and_keeps_cs() {
        let cur = frame();
        let r = regs_for(&RemoteOp::Mmap { len: 0x2000 }, &cur, 0xdead);
        assert_eq!(r.rax, SYS_MMAP);
        assert_eq!(r.rsi, 0x2000);
        assert_eq!(r.rdx, PROT_READ_WRITE);
        assert_eq!(r.r10, MAP_PRIVATE_ANONYMOUS);
        assert_eq!(r.r8, u64::MAX);
        assert_eq!(r.rip, 0xdead);
        assert_eq!(r.cs, 0x33, "cs must be inherited, not zeroed");
    }

    #[test]
    fn munmap_frame_sets_args() {
        let cur = frame();
        let r = regs_for(
            &RemoteOp::Munmap {
                addr: 0x7000,
                len: 0x1000,
            },
            &cur,
            0xdead,
        );
        assert_eq!(r.rax, SYS_MUNMAP);
        assert_eq!(r.rdi, 0x7000);
        assert_eq!(r.rsi, 0x1000);
    }

    #[test]
    fn result_validation() {
        let mmap = RemoteOp::Mmap { len: PAGE_SIZE };
        assert!(check_result(&mmap, 0x7f00_0000_0000).is_ok());
        assert!(
            check_result(&mmap, (-12i64) as u64).is_err(),
            "-ENOMEM must fail"
        );
        let munmap = RemoteOp::Munmap { addr: 0, len: 0 };
        assert!(check_result(&munmap, 0).is_ok());
        assert!(check_result(&munmap, (-22i64) as u64).is_err());
    }
}
