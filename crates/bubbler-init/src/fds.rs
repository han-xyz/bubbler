//! The descriptors a process was handed but was not given.
//!
//! Every descriptor a parent leaves open without `FD_CLOEXEC` is inherited,
//! and neither bubbler nor its supervisor picks its parent: a shell, a
//! terminal, a service manager or a build system opens what it likes and
//! passes it on without meaning to. bwrap hands every descriptor it holds
//! to the sandbox, so one nobody meant to give reaches the sandbox, its
//! supervisor, every command exec'd in it and every sidecar of the run.
//!
//! A sweep is the answer at both ends: bubbler marks the strays
//! close-on-exec before each spawn, so no child of a run sees them, and
//! the supervisor closes them outright, since inside the sandbox they are
//! the only descriptors of the host session left.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use rustix::fs::{Dir, Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_setfd};

/// Where the kernel lists a process's own open descriptors.
const FD_DIR: &str = "/proc/self/fd";

/// The first descriptor a sweep looks at. Below it is the stdio every
/// process is expected to have, which each spawn sets up for itself.
const FIRST: RawFd = 3;

/// What a sweep does with a descriptor above stdio that was not named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stray {
    /// Close it. For a process that holds nothing above stdio of its own,
    /// so an unasked-for descriptor is gone from it as well as from its
    /// children.
    Close,
    /// Mark it close-on-exec. For a process with descriptors of its own
    /// to keep: they stay open here and reach no child.
    Cloexec,
}

/// Deal with every descriptor above stdio except the ones `keep` names.
///
/// The caller must be the only thread opening or closing descriptors while
/// this runs. It acts on numbers read from `/proc/self/fd` a moment
/// earlier, and under [`Stray::Close`] a number another thread had closed
/// and reopened in between would be that thread's descriptor being closed
/// under it.
///
/// A descriptor that has gone away by itself is not an error: it is not
/// one a child could inherit either.
pub fn sweep(keep: &[RawFd], what: Stray) -> io::Result<()> {
    for fd in strays(keep)? {
        // SAFETY: `fd` is a number this process's own `/proc/self/fd`
        // listed as open, with stdio, the listing's own descriptor and
        // everything `keep` names already taken out of it. Nothing else in
        // this process may open or close descriptors while a sweep runs
        // (the contract above), so the number still names what it named
        // when the kernel reported it. `borrow_raw` closes nothing and the
        // borrow ends with the `fcntl`; `close` takes a number this
        // process owns and nothing else holds a handle to, since a stray
        // is by definition a descriptor no part of bubbler asked for.
        unsafe {
            match what {
                Stray::Close => rustix::io::close(fd),
                Stray::Cloexec => match fcntl_setfd(BorrowedFd::borrow_raw(fd), FdFlags::CLOEXEC) {
                    Ok(()) | Err(Errno::BADF) => {}
                    Err(e) => return Err(e.into()),
                },
            }
        }
    }
    Ok(())
}

/// Every descriptor above stdio this process holds that `keep` does not
/// name. The listing's own descriptor is never among them, and it is
/// closed before the caller acts on the numbers.
fn strays(keep: &[RawFd]) -> io::Result<Vec<RawFd>> {
    let dir = rustix::fs::open(
        FD_DIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let own = dir.as_raw_fd();
    let mut entries = Dir::new(dir)?;
    let mut found = Vec::new();
    while let Some(entry) = entries.read() {
        let entry = entry?;
        // `.` and `..` are the only names here that are not numbers.
        let Some(fd) = entry
            .file_name()
            .to_str()
            .ok()
            .and_then(|n| n.parse::<RawFd>().ok())
        else {
            continue;
        };
        if fd >= FIRST && fd != own && !keep.contains(&fd) {
            found.push(fd);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`Stray::Close`] is never run for real in here. A sweep is
    /// process-wide and these tests are threads of one binary, so closing
    /// what this thread did not open is closing another thread's
    /// descriptors — which is the contract above, not a case to exercise.
    /// What that arm does with a number is what the supervisor's own
    /// integration tests measure, in a process of its own.
    #[test]
    fn a_descriptor_this_process_opened_is_a_stray_unless_it_is_kept() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        assert!(strays(&[]).unwrap().contains(&fd), "fd {fd} was not listed");
        assert!(
            !strays(&[fd]).unwrap().contains(&fd),
            "fd {fd} was listed although it was kept"
        );
    }

    /// Marking is safe to do for real in this binary, where closing is
    /// not: no test here starts a process, so no descriptor of a thread
    /// beside this one is waiting to be inherited by anything.
    #[test]
    fn a_stray_is_marked_close_on_exec_and_a_kept_one_is_left_alone() {
        let kept = std::fs::File::open("/dev/null").unwrap();
        let stray = std::fs::File::open("/dev/null").unwrap();
        fcntl_setfd(&kept, FdFlags::empty()).unwrap();
        fcntl_setfd(&stray, FdFlags::empty()).unwrap();
        sweep(&[kept.as_raw_fd()], Stray::Cloexec).unwrap();
        assert_eq!(rustix::io::fcntl_getfd(&kept).unwrap(), FdFlags::empty());
        assert_eq!(
            rustix::io::fcntl_getfd(&stray).unwrap(),
            FdFlags::CLOEXEC,
            "a descriptor nobody named stayed inheritable"
        );
    }

    #[test]
    fn stdio_is_never_a_stray() {
        let found = strays(&[]).unwrap();
        assert!(
            found.iter().all(|fd| *fd >= FIRST),
            "stdio was listed: {found:?}"
        );
    }
}
