//! The filtering D-Bus proxy sidecar, and the readiness and liveness checks the other sidecars share.

use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{Access, AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::env::Env;
use crate::host::Host;
use crate::launch_error::LaunchError;
use crate::sidecar_argv::proxy_argv;
use crate::{dbus, dbus_a11y, run_log, service};
use bubbler_plan::plan_error::PlanError;

use super::POLL;
use super::alloc::{RealAlloc, spawning};
use super::identity::FileGuard;
use super::runtime_dir::{
    fresh_sidecar_dir, move_aside, open_dir, open_dir_nofollow, remove_sidecar_dir,
};
use super::spawn::{bwrap_command, on_path, spawn_sidecar};

pub(super) const PROXY_READY: Duration = Duration::from_secs(5);

const PROXY_STOP: Duration = Duration::from_secs(1);

/// A running D-Bus proxy sidecar. Dropping it closes the ready pipe, which is what makes
/// `xdg-dbus-proxy` exit, so it must outlive the sandbox using the socket.
#[derive(Debug)]
pub(crate) struct ProxyHandle {
    pub(super) child: Child,
    pub(super) alloc: RealAlloc,
    pub(super) socket_dir: PathBuf,
    pub(super) _stderr: run_log::Relay,
}

impl Drop for ProxyHandle {
    // The proxy leaves on `POLLHUP` of its write end, which needs our read end gone too; one that
    // ignores it is killed.
    fn drop(&mut self) {
        self.alloc.fds.clear();
        self.alloc.ready_read.take();
        let deadline = Instant::now() + PROXY_STOP;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(POLL);
        }
        // Holds only what the proxy put there; the socket it served was moved out already.
        remove_sidecar_dir(&self.socket_dir);
    }
}

// False on deadline, EOF or a gone child: nothing is listening either way. `Stopped` once
// `stop` is set: a Ctrl-C reaches the sidecar's process group too.
pub(super) fn wait_ready(
    ready: &OwnedFd,
    child: &mut Child,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<bool, LaunchError> {
    let mut byte = [0u8; 1];
    let is_ready = loop {
        let slice = Timespec {
            tv_sec: POLL.as_secs() as Secs,
            tv_nsec: POLL.subsec_nanos() as Nsecs,
        };
        match poll(&mut [PollFd::new(ready, PollFlags::IN)], Some(&slice)) {
            // `Ok(0)` already waited out the slice; a failing poll keeps failing, so sleep.
            Ok(0) => {}
            Err(_) => std::thread::sleep(POLL),
            Ok(_) => match rustix::io::read(ready, &mut byte) {
                Ok(0) => break false,
                Ok(_) => break true,
                Err(Errno::INTR) => {}
                Err(_) => break false,
            },
        }
        if stop.load(Ordering::SeqCst) {
            return Err(LaunchError::Stopped);
        }
        if Instant::now() >= deadline {
            break false;
        }
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            break false;
        }
    };
    if !is_ready && stop.load(Ordering::SeqCst) {
        return Err(LaunchError::Stopped);
    }
    Ok(is_ready)
}

// A reaped sidecar's pid may be a stranger's by now; `try_wait` answers from its cached status,
// so a reaping anywhere in the run is caught here.
pub(super) fn still_running(child: &mut Child) -> bool {
    !matches!(child.try_wait(), Ok(Some(_)))
}

/// Start an instance's filtering D-Bus proxy in its own sandbox and wait until its socket
/// exists. The handle must outlive the sandbox.
pub(crate) fn start_proxy(
    env: &Env,
    dir: &Path,
    plan: &dbus::Plan,
    host: &dyn Host,
    stop: &AtomicBool,
) -> Result<ProxyHandle, LaunchError> {
    // Only the buses the plan grants are resolved: probing the other one
    // would fail a run over a socket it never asked for.
    let session_bus = plan
        .session
        .as_ref()
        .map(|_| {
            let path = dbus::guarded_host_bus(host, env)?;
            service::require_socket(host, dbus::SESSION_NODE, path)
        })
        .transpose()?;
    let system_bus = plan
        .system
        .as_ref()
        .map(|_| {
            let path = dbus::guarded_host_system_bus(host, env)?;
            service::require_socket(host, dbus::SYSTEM_NODE, path)
        })
        .transpose()?;
    // Resolved before the proxy starts: asking after the sandbox is up would be asking for a bus
    // already meant to be serving.
    let a11y_bus = plan
        .a11y
        .as_ref()
        .map(|_| {
            let path = dbus_a11y::guarded_host_a11y_bus(host, env)?;
            Ok::<_, LaunchError>(service::require_socket(host, dbus::A11Y_NODE, path)?)
        })
        .transpose()?;
    // After the bus guards, so a refused address is reported before a missing package; before the
    // spawn, so a missing binary is not bwrap's execvp line after the full PROXY_READY wait.
    let program = dbus::proxy_program(env);
    let found = if program.components().count() > 1 {
        rustix::fs::access(&program, Access::EXEC_OK).is_ok()
    } else {
        on_path(&program.to_string_lossy()).is_some()
    };
    if !found {
        return Err(LaunchError::Plan(PlanError::BadValue {
            service: "dbus",
            reason: format!(
                "`{}` is not on PATH; install the `xdg-dbus-proxy` package, or drop the \
                 `dbus`, `portals`, `a11y` and `system-bus` nodes",
                program.display()
            ),
        }));
    }
    // The proxy gets this directory and nothing else of the instance's
    // runtime state, so it is created here rather than bound from above.
    fresh_sidecar_dir(&dbus::socket_dir(dir))?;
    let mut alloc = RealAlloc::sidecar(dir.to_path_buf());
    let argv = proxy_argv(
        env,
        plan,
        dbus::HostBuses {
            session: session_bus.as_deref(),
            system: system_bus.as_deref(),
            a11y: a11y_bus.as_deref(),
        },
        dir,
        host,
        &mut alloc,
    )?;
    let cmd = bwrap_command(&argv, &mut alloc)?;
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let (child, stderr) = spawn_sidecar(cmd, env.dbus_log)?;
    let mut handle = ProxyHandle {
        child,
        alloc,
        _stderr: stderr,
        socket_dir: dbus::socket_dir(dir),
    };
    handle.alloc.close_options();
    // The instance's own bwrap must not inherit these: a second holder of
    // the ready pipe would keep the proxy alive after the run has ended.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let ProxyHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no ready pipe was allocated")))?;
    if !wait_ready(ready, child, Instant::now() + PROXY_READY, stop)? {
        return Err(LaunchError::ProxyNotReady);
    }
    Ok(handle)
}

// Move first, check second, as in `adopt_socket`. `node` is the config node that granted the
// bus, so a failure names what the user would change.
pub(super) fn adopt_proxy_bus(
    dir: &Path,
    socket: &str,
    node: &'static str,
    uid: u32,
) -> Result<FileGuard, LaunchError> {
    let from_dir = dbus::socket_dir(dir);
    let from = open_dir_nofollow(rustix::fs::CWD, &from_dir, &from_dir, node)?;
    let to = open_dir(dir)?;
    let path = dbus::app_bus_path(dir, socket);
    clear_socket_name(&to, dir, socket).map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    rustix::fs::renameat(&from, socket, &to, socket).map_err(|e| match e {
        Errno::NOENT => LaunchError::Plan(PlanError::MissingResource {
            service: node,
            path: dbus::proxy_bus_path(dir, socket),
        }),
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let guard = FileGuard(path.clone());
    let wrong_type = |expected| {
        LaunchError::Plan(PlanError::WrongType {
            service: node,
            path: path.clone(),
            expected,
        })
    };
    let bus = rustix::fs::openat(
        &to,
        socket,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP => wrong_type("a socket"),
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let stat = rustix::fs::fstat(&bus).map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if kind != rustix::fs::FileType::Socket {
        // A directory cannot be unlinked as a file, and one left at this
        // name would fail the rename of every later start of the instance.
        if kind == rustix::fs::FileType::Directory {
            remove_moved_dir(&to, dir, socket);
        }
        return Err(wrong_type("a socket"));
    }
    if stat.st_uid != uid {
        return Err(wrong_type("a socket owned by this user"));
    }
    Ok(guard)
}

// Cleared so the next start's rename onto this name works; after the move only bubbler reaches it.
pub(super) fn remove_moved_dir(inst: &OwnedFd, dir: &Path, socket: &str) {
    if let Err(e) = move_aside(inst, dir, OsStr::new(socket)) {
        eprintln!(
            "bubbler: warning: {} could not be moved aside ({e}); the next start tries again",
            dir.join(socket).display()
        );
    }
}

// A killed run can leave a directory at the name, and a rename cannot put a socket over one.
pub(super) fn clear_socket_name(
    inst: &OwnedFd,
    dir: &Path,
    socket: &str,
) -> rustix::io::Result<()> {
    match rustix::fs::statat(inst, socket, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat)
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::Directory =>
        {
            move_aside(inst, dir, OsStr::new(socket))
        }
        Ok(_) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{leftovers, own_uid, plant_chain, with_desktop_fd_limit};
    use super::*;

    use std::ffi::OsString;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn a_proxied_socket_is_moved_out_of_the_proxys_reach() {
        // Both buses are adopted by the same rule; only the file name
        // differs.
        for socket in [dbus::SESSION_SOCKET, dbus::SYSTEM_SOCKET] {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
            let listener = UnixListener::bind(dbus::proxy_bus_path(dir, socket)).unwrap();
            let guard = adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()).unwrap();
            let moved = std::fs::symlink_metadata(dbus::app_bus_path(dir, socket)).unwrap();
            assert!(std::os::unix::fs::FileTypeExt::is_socket(
                &moved.file_type()
            ));
            assert!(!dbus::proxy_bus_path(dir, socket).exists());
            // The proxy serves the socket it bound, not the path it bound
            // it at.
            assert!(UnixStream::connect(dbus::app_bus_path(dir, socket)).is_ok());
            drop(listener);
            drop(guard);
            assert!(
                !dbus::app_bus_path(dir, socket).exists(),
                "{socket}: the socket outlived the run"
            );
        }
        // A failure names the node the user would have to look at.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(dbus::socket_dir(tmp.path())).unwrap();
        assert!(matches!(
            adopt_proxy_bus(
                tmp.path(),
                dbus::SYSTEM_SOCKET,
                dbus::SYSTEM_NODE,
                own_uid()
            ),
            Err(LaunchError::Plan(PlanError::MissingResource {
                service: "system-bus",
                ..
            }))
        ));
    }

    #[test]
    fn anything_but_a_socket_in_the_proxys_directory_stops_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let socket = dbus::SESSION_SOCKET;
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::MissingResource {
                service: "dbus",
                ..
            }))
        ));
        // A symlink is the attack: `stat` through it would report the type
        // of its target, and bwrap would bind that target.
        std::os::unix::fs::symlink("/etc", dbus::proxy_bus_path(dir, socket)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            }))
        ));
        // Moved out of the proxy's reach first, so a refused run leaves
        // nothing of it behind either.
        assert!(
            !dbus::app_bus_path(dir, socket).exists(),
            "the symlink was kept"
        );
        assert!(
            !dbus::proxy_bus_path(dir, socket).exists(),
            "the symlink was left in place"
        );
        std::fs::write(dbus::proxy_bus_path(dir, socket), b"").unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            }))
        ));
        assert!(!dbus::app_bus_path(dir, socket).exists());
        // A directory is refused like anything else, and removed with what
        // is in it: `remove_file` cannot take one, and one left at this
        // name would fail the rename of every later start.
        std::fs::create_dir(dbus::proxy_bus_path(dir, socket)).unwrap();
        std::fs::write(dbus::proxy_bus_path(dir, socket).join("x"), b"").unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            }))
        ));
        assert!(
            !dbus::app_bus_path(dir, socket).exists(),
            "the directory was kept"
        );
        // And the next honest start works.
        let listener = UnixListener::bind(dbus::proxy_bus_path(dir, socket)).unwrap();
        adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid())
            .expect("a socket after a refused directory");
        drop(listener);
    }

    /// A proxy can plant a tree no walk finishes where its socket belongs:
    /// deeper than the descriptor limit, with a level no one may open and
    /// links out. It is refused, nothing it links to changes, and nothing
    /// is left at the socket's name to fail the next start.
    #[test]
    fn a_deep_unreadable_tree_at_a_proxy_sockets_name_does_not_block_the_next_start() {
        use std::os::unix::fs::PermissionsExt;
        with_desktop_fd_limit(|| {
            let tmp = tempfile::tempdir().unwrap();
            let elsewhere = tmp.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            let sentinel = elsewhere.join("sentinel");
            std::fs::write(&sentinel, b"sentinel").unwrap();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            let before = (mode(&elsewhere), mode(&sentinel));
            let dir = tmp.path().join("t");
            std::fs::create_dir(&dir).unwrap();
            std::fs::create_dir(dbus::socket_dir(&dir)).unwrap();
            let socket = dbus::SESSION_SOCKET;
            let planted = dbus::proxy_bus_path(&dir, socket);
            let bottom = plant_chain(&planted, 1500);
            rustix::fs::mkdirat(&bottom, "locked", Mode::RWXU).unwrap();
            let locked = rustix::fs::openat(
                &bottom,
                "locked",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            rustix::fs::symlinkat(&sentinel, &locked, "out").unwrap();
            rustix::fs::symlinkat(&elsewhere, &locked, "up").unwrap();
            rustix::fs::chmod(
                format!("/proc/self/fd/{}", locked.as_raw_fd()),
                Mode::empty(),
            )
            .unwrap();

            assert!(matches!(
                adopt_proxy_bus(&dir, socket, dbus::SESSION_NODE, own_uid()),
                Err(LaunchError::Plan(PlanError::WrongType {
                    expected: "a socket",
                    ..
                }))
            ));

            let app_bus = dbus::app_bus_path(&dir, socket);
            assert!(
                std::fs::symlink_metadata(&app_bus).is_err(),
                "the tree was kept"
            );
            assert_eq!(leftovers(&dir, &app_bus), Vec::<OsString>::new());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
            assert_eq!((mode(&elsewhere), mode(&sentinel)), before);
            let listener = UnixListener::bind(&planted).unwrap();
            adopt_proxy_bus(&dir, socket, dbus::SESSION_NODE, own_uid())
                .expect("a socket after a refused tree");
            drop(listener);
        });
    }

    #[test]
    fn a_proxied_socket_of_another_user_stops_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let socket = dbus::SESSION_SOCKET;
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        let _listener = UnixListener::bind(dbus::proxy_bus_path(dir, socket)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid() + 1),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket owned by this user",
                ..
            }))
        ));
        assert!(!dbus::app_bus_path(dir, socket).exists());
    }

    #[test]
    fn a_link_in_place_of_the_proxys_directory_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let socket = dbus::SESSION_SOCKET;
        let _listener = UnixListener::bind(elsewhere.join(socket)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dbus::socket_dir(&dir)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(&dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a directory",
                ..
            }))
        ));
        assert!(elsewhere.join(socket).exists());
    }
}
