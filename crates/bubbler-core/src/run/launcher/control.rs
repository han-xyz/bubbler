//! The start lock and the control socket that make one live run per instance.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustix::fs::{FlockOperation, Mode, OFlags, flock};
use rustix::io::Errno;
use signal_hook::consts::SIGTERM;

use crate::run::launch_error::LaunchError;
use crate::{exec, run_log};

// What the command gives when the forwarded SIGTERM stops it.
pub(super) const STOPPED_CODE: i32 = 128 + SIGTERM;

const START_LOCK_POLL: Duration = Duration::from_millis(50);

// Follows no link, and no FIFO can park the open.
fn open_start_lock(path: &Path) -> Result<OwnedFd, LaunchError> {
    rustix::fs::open(
        path,
        OFlags::CREATE
            | OFlags::WRONLY
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::NOCTTY
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
}

// The liveness check, the unlink of a dead run's socket and the bind all happen under the lock;
// `log` is told the run started while it is held, so a joining start adds after the emptying.
pub(super) fn bind_control_socket(
    dir: &Path,
    lock_path: &Path,
    name: &str,
    stop: &AtomicBool,
    log: Option<&run_log::Redirect>,
) -> Result<(UnixListener, SocketGuard), LaunchError> {
    let lock_err = |e: Errno| LaunchError::Io(lock_path.to_path_buf(), e.into());
    let lock = open_start_lock(lock_path)?;
    // Polled rather than blocking: the stop signals are installed with
    // SA_RESTART, so a blocking `flock` would sleep through them.
    loop {
        match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(Errno::WOULDBLOCK | Errno::INTR) => {}
            Err(e) => return Err(lock_err(e)),
        }
        if stop.load(Ordering::SeqCst) {
            return Err(LaunchError::Stopped);
        }
        std::thread::sleep(START_LOCK_POLL);
    }
    let sock_path = dir.join(exec::SOCKET_NAME);
    let io_at = |e: io::Error| LaunchError::Io(sock_path.clone(), e);
    if exec::is_live_at(&sock_path) {
        return Err(LaunchError::AlreadyRunning(name.to_owned()));
    }
    match std::fs::remove_file(&sock_path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_at(e)),
        _ => {}
    }
    let listener = UnixListener::bind(&sock_path).map_err(io_at)?;
    let held = rustix::fs::open(
        &sock_path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_at(e.into()))?;
    let bound = rustix::fs::fstat(&held).map_err(|e| io_at(e.into()))?;
    let guard = SocketGuard {
        id: (bound.st_dev as u64, bound.st_ino as u64),
        path: sock_path,
        _held: held,
    };
    if let Some(log) = log {
        log.started();
    }
    Ok((listener, guard))
}

// Only the socket this run bound: a start after this sandbox exited may have bound its own.
// The held descriptor keeps the inode allocated, so a later socket cannot reuse its number.
#[derive(Debug)]
pub(super) struct SocketGuard {
    path: PathBuf,
    id: (u64, u64),
    _held: OwnedFd,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let ours =
            std::fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.id);
        // Nothing to report: a socket left behind is found refused, and
        // cleared, by the next start.
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// Taken once the sandbox has exited, so a start made now waits for this run's teardown.
// Blocking: a stop signal has usually ended the run by now, and another start holds the lock only
// from its liveness check to its bind. A lock that cannot be had costs only that guarantee, so it
// is a warning.
pub(super) fn lock_for_teardown(path: &Path) -> Option<OwnedFd> {
    let locked = open_start_lock(path).and_then(|lock| {
        flock(&lock, FlockOperation::LockExclusive)
            .map(|()| lock)
            .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
    });
    match locked {
        Ok(lock) => Some(lock),
        Err(e) => {
            eprintln!("bubbler: warning: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    /// A socket a dead run left is cleared and bound again; one a run
    /// answers on is that run's, and is left answering.
    #[test]
    fn a_start_binds_over_a_dead_socket_and_not_over_a_live_one() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let lock = tmp.path().join("t@start.lock");
        let path = dir.join(exec::SOCKET_NAME);
        let stop = AtomicBool::new(false);
        exec::close_for_good(UnixListener::bind(&path).unwrap());
        let (live, _guard) =
            bind_control_socket(&dir, &lock, "t", &stop, None).expect("a fresh bind");
        let again = bind_control_socket(&dir, &lock, "t", &stop, None);
        assert!(
            matches!(&again, Err(LaunchError::AlreadyRunning(n)) if n == "t"),
            "{again:?}"
        );
        let _client = UnixStream::connect(&path).unwrap();
        live.accept()
            .expect("the first start's socket still answers");
        assert!(lock.exists(), "the lock file is kept");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "only the socket is in the runtime directory"
        );
    }

    /// A run's guard removes the socket it bound, and leaves one a later
    /// start bound at the same path in its place.
    #[test]
    fn a_run_removes_its_own_socket_and_not_a_later_start_s() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join("t@start.lock");
        let path = tmp.path().join(exec::SOCKET_NAME);
        let stop = AtomicBool::new(false);
        let (listener, guard) = bind_control_socket(tmp.path(), &lock, "t", &stop, None).unwrap();
        exec::close_for_good(listener);
        let (_later, later_guard) =
            bind_control_socket(tmp.path(), &lock, "t", &stop, None).unwrap();
        drop(guard);
        assert!(path.exists(), "the later start's socket was removed");
        drop(later_guard);
        assert!(!path.exists(), "a run's own socket is removed");
    }

    /// A start waiting on another's lock is still ended by a stop signal.
    #[test]
    fn a_start_waiting_on_the_lock_ends_when_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join("t@start.lock");
        let held = std::fs::File::create(&lock).unwrap();
        flock(&held, FlockOperation::LockExclusive).unwrap();
        let stop = AtomicBool::new(true);
        let waited = bind_control_socket(tmp.path(), &lock, "t", &stop, None);
        assert!(matches!(waited, Err(LaunchError::Stopped)), "{waited:?}");
        assert!(!tmp.path().join(exec::SOCKET_NAME).exists());
    }
}
