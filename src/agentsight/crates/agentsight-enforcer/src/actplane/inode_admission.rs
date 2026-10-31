//! Hold read leases until inode write hooks are active, excluding pre-existing writers.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;

use crate::BackendError;

// Linux UAPI uses 10 on both supported architectures; libc does not expose it on GNU.
const F_SETSIG: i32 = 10;

/// A temporary admission barrier; closing the last descriptor releases the lease.
#[derive(Clone, Debug)]
pub(super) struct InodeAdmission {
    file: Arc<File>,
    path: String,
}

impl InodeAdmission {
    /// Rejects existing writable handles and mappings without trusting a racy procfs scan.
    pub(super) fn acquire(held: &File, path: &str) -> Result<Self, BackendError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", held.as_raw_fd()))
            .map_err(|error| failure(path, error))?;
        // SIGURG is ignored by default. A competing writer must not terminate
        // the daemon via the default SIGIO lease-break notification.
        fcntl(&file, libc::F_SETOWN, std::process::id() as i32)
            .and_then(|_| fcntl(&file, F_SETSIG, libc::SIGURG))
            .and_then(|_| fcntl(&file, libc::F_SETLEASE, libc::F_RDLCK))
            .map_err(|error| failure(path, error))?;
        Ok(Self {
            file: Arc::new(file),
            path: path.into(),
        })
    }

    /// Detects a lease break or expiry before reporting the binding as enforced.
    pub(super) fn validate(&self) -> Result<(), BackendError> {
        let lease =
            fcntl(&self.file, libc::F_GETLEASE, 0).map_err(|error| failure(&self.path, error))?;
        if lease != libc::F_RDLCK {
            return Err(failure(&self.path, "admission lease was broken"));
        }
        Ok(())
    }

    /// Releases the barrier once the kernel hooks cover future writes and mappings.
    pub(super) fn release(&self) -> Result<(), BackendError> {
        fcntl(&self.file, libc::F_SETLEASE, libc::F_UNLCK)
            .map(|_| ())
            .map_err(|error| failure(&self.path, error))
    }
}

fn fcntl(file: &File, operation: i32, value: i32) -> io::Result<i32> {
    // SAFETY: the owned descriptor is valid and these fcntl operations take an integer.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), operation, value) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn failure(path: &str, error: impl std::fmt::Display) -> BackendError {
    BackendError::CompileFailure(format!(
        "cannot admit inode write protection for '{path}': {error}; close existing writable handles and mappings and retry on a filesystem supporting read leases"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn admission_rejects_writers_and_surviving_mappings_but_allows_readers() {
        let path = format!("/tmp/admission-{}", uuid::Uuid::new_v4());
        fs::write(&path, b"mapped fixture").unwrap();
        let reader = File::open(&path).unwrap();
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(InodeAdmission::acquire(&reader, &path).is_err());
        let length = writer.metadata().unwrap().len() as usize;
        // SAFETY: mmap receives a live readable/writable fd and the returned range
        // is only used by munmap below; no Rust references alias the mapping.
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                writer.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        drop(writer);
        assert!(InodeAdmission::acquire(&reader, &path).is_err());
        // SAFETY: this is exactly the mapping returned above and it has no live references.
        assert_eq!(unsafe { libc::munmap(mapped, length) }, 0);
        let barrier = InodeAdmission::acquire(&reader, &path).unwrap();
        barrier.validate().unwrap();
        assert_eq!(
            reader.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
        barrier.release().unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_ok());
        fs::remove_file(path).unwrap();
    }
}
