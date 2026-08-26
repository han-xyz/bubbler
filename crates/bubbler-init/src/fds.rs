//! The descriptors a process was handed but was not given.
//!
//! Every descriptor a parent leaves open without `FD_CLOEXEC` is inherited,
//! and neither bubbler nor its supervisor picks its parent: a shell, a
//! terminal, a service manager or a build system opens what it likes and
//! passes it on without meaning to. bwrap hands every descriptor it holds
//! to the sandbox, so one nobody meant to give reaches the sandbox, its
//! supervisor, every command exec'd in it and every sidecar of the run.
//!
//! A sweep is the answer at both ends, and the two halves are not equally
//! safe. [`sweep_cloexec`] only marks, which no owner of a descriptor can
//! be harmed by, so it is a safe function. [`close_strays`] closes numbers
//! outright, which would be a double close and then a stolen descriptor
//! for anything still holding one, so it is `unsafe` and has a contract.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use rustix::fs::{Dir, Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_setfd};

/// Where the kernel lists a process's own open descriptors.
const FD_DIR: &str = "/proc/self/fd";

/// The first descriptor a sweep looks at. Below it is the stdio every
/// process is expected to have, which each spawn sets up for itself.
const FIRST: RawFd = 3;

/// Mark every descriptor above stdio close-on-exec except the ones `keep`
/// names, so the next spawn inherits only what it was built to.
///
/// Nothing is closed and no descriptor changes hands: an owner keeps its
/// own, and a flag that was going to be set on it for the spawn anyway is
/// set a moment earlier. For a process that has descriptors of its own to
/// go on using — bubbler during a run.
///
/// Only one thread may spawn while a sweep's result stands, since the
/// flag is process-wide state, and a descriptor that has gone away by
/// itself is not an error: it is not one a child could inherit either.
pub fn sweep_cloexec(keep: &[RawFd]) -> io::Result<()> {
    for fd in strays(keep)? {
        // SAFETY: `fd` is a number this process's own `/proc/self/fd`
        // listed as open moments ago. `borrow_raw` closes nothing and the
        // borrow ends with the `fcntl`, so nothing that owns that
        // descriptor loses it or sees it change hands; the worst a number
        // reused in between can cost is a close-on-exec flag on a
        // descriptor that was about to be given one. A number that is not
        // open at all answers `EBADF`, which is nothing to report.
        match unsafe { fcntl_setfd(BorrowedFd::borrow_raw(fd), FdFlags::CLOEXEC) } {
            Ok(()) | Err(Errno::BADF) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Close every descriptor above stdio except the ones `keep` names.
///
/// For a process that holds nothing above stdio of its own, so an
/// unasked-for descriptor is gone from it as well as from its children —
/// the supervisor at the top of `main`, where the sandbox's whole
/// descriptor table is whatever bwrap passed through.
///
/// # Safety
///
/// The caller must own every descriptor above stdio that `keep` does not
/// name, and must hold no `OwnedFd`, `File`, socket or other owning handle
/// on any of them: this closes those numbers, and the owner would then
/// close them a second time — onto whatever the kernel had handed the
/// number to by then.
///
/// The caller must also be the only thread opening or closing descriptors
/// while this runs. The numbers come from `/proc/self/fd` a moment
/// earlier, and one that another thread had closed and reopened in between
/// would be that thread's descriptor being closed under it.
pub unsafe fn close_strays(keep: &[RawFd]) -> io::Result<()> {
    for fd in strays(keep)? {
        // SAFETY: the caller has promised that no handle of this process
        // owns `fd` and that no other thread is opening or closing
        // descriptors, so this number still names the stray the kernel
        // reported and closing it is closing nothing anyone holds.
        unsafe { rustix::io::close(fd) };
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

    /// [`close_strays`] is never run in here. A sweep is process-wide and
    /// these tests are threads of one binary, so closing what this thread
    /// did not open is closing another thread's descriptors — which is
    /// that function's contract, not a case to exercise. What it does with
    /// a number is what the supervisor's own integration tests measure, in
    /// a process of its own.
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
        sweep_cloexec(&[kept.as_raw_fd()]).unwrap();
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
