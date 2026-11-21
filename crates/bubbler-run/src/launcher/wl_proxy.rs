//! The Wayland proxy sidecar and the security context it connects through.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Child;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{Pid, Signal, kill_process};

use crate::config::WaylandMode;
use crate::env::Env;
use crate::host::Host;
use crate::instance::Instance;
use crate::launch_error::LaunchError;
use crate::sidecar_argv::{wayland_mode, wayland_node, wl_proxy_argv};
use crate::wayland::ProxyPlan;
use crate::wayland_context::{self, WaylandError};
use crate::{dbus, run_log, service, wayland};

use super::POLL;
use super::alloc::{RealAlloc, spawning};
use super::dbus_proxy::{PROXY_READY, still_running, wait_ready};
use super::identity::FileGuard;
use super::spawn::{bwrap_command, spawn_sidecar};

const WL_PROXY_STOP: Duration = Duration::from_secs(5);

/// A run's Wayland sidecar: the proxy, the socket it accepts on and, where the compositor took
/// one, the security context. Dropping it stops the proxy and ends the context, so it must
/// outlive the sandbox.
#[derive(Debug)]
pub struct WaylandHandle {
    child: Child,
    alloc: RealAlloc,
    // The compositor's `close_fd`; `None` where it offers no security context.
    _close: Option<OwnedFd>,
    _socket: FileGuard,
    _context: Option<FileGuard>,
    _stderr: run_log::Relay,
}

impl Drop for WaylandHandle {
    // To bwrap, whose `--die-with-parent` takes the proxy down: the proxy holds no pipe of
    // bubbler's whose hangup it could see.
    fn drop(&mut self) {
        if still_running(&mut self.child) {
            if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
                let _ = kill_process(pid, Signal::TERM);
            }
            let deadline = Instant::now() + WL_PROXY_STOP;
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
        }
        self.alloc.fds.clear();
        self.alloc.ready_read.take();
    }
}

/// Bind the socket this run's application connects to and start `bubbler-wl-proxy` behind it,
/// through a security context where the compositor has one. `Ok(None)` only for `wayland
/// "host"`. The handle must outlive the sandbox.
pub fn start_wayland(
    env: &Env,
    dir: &Path,
    inst: &Instance,
    host: &dyn Host,
    stop: &AtomicBool,
) -> Result<Option<WaylandHandle>, LaunchError> {
    let (Some(WaylandMode::Sandboxed { clipboard }), Some(node)) = (
        wayland_mode(&inst.config.services),
        wayland_node(&inst.config.services),
    ) else {
        return Ok(None);
    };
    // The bind's own check, made before connecting: a display name that is a path would pick the
    // endpoint. wayrs reads the process environment itself, so both values go through it.
    let display = service::wayland_display(env)?;
    service::check_wayland_display(std::env::var_os("WAYLAND_DISPLAY").as_deref())?;
    wayland_context::refuse_inherited(std::env::var_os("WAYLAND_SOCKET").as_deref())?;
    let plan = match wayland_context::probe()? {
        true => ProxyPlan::context(dir, clipboard),
        false => {
            eprintln!(
                "bubbler: note: wayland: no wp_security_context_manager_v1; \
                 the proxy hides the privileged globals instead"
            );
            // Follows symlinks, as the bind does: the name is one component under the user's own
            // 0700 `$XDG_RUNTIME_DIR`, so whatever could plant a link there is already the user.
            let session = service::require_socket(host, "wayland", env.runtime_dir.join(display))?;
            ProxyPlan::fallback(dir, session, clipboard)
        }
    };
    // The context makes the connection behind it a sandboxed client's, so it precedes the dial.
    let (close, context) = match plan.context {
        true => {
            let (close, guard) = bind_context(dir, &inst.name)?;
            (Some(close), Some(guard))
        }
        false => (None, None),
    };
    let listener = bind_listener(&plan.listener)?;
    let socket = FileGuard(plan.listener.clone());
    let mut alloc = RealAlloc::sidecar_listening(listener.into(), dir.to_path_buf());
    let argv = wl_proxy_argv(env, &plan, node, host, &mut alloc)?;
    let cmd = bwrap_command(&argv, &mut alloc)?;
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let (child, stderr) = spawn_sidecar(cmd, false)?;
    let mut handle = WaylandHandle {
        child,
        alloc,
        _stderr: stderr,
        _close: close,
        _socket: socket,
        _context: context,
    };
    // Nothing of bubbler's may accept on the sandbox's display socket, and a second holder would
    // keep connections queueing after the sidecar died instead of refusing them.
    handle.alloc.close_listener();
    handle.alloc.close_options();
    // CLOEXEC again before the instance's own bwrap: the ready pipe belongs to this spawn only.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let WaylandHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no ready pipe was allocated")))?;
    if !wait_ready(ready, child, Instant::now() + PROXY_READY, stop)? {
        let what = match child.try_wait() {
            Ok(Some(status)) => format!("it exited ({status})"),
            _ => format!("it did not report a listening socket within {PROXY_READY:?}"),
        };
        return Err(WaylandError::ProxyNotReady(what).into());
    }
    Ok(Some(handle))
}

// Removes a socket left by a killed run; any error but a missing file is the instance's own
// 0700 directory refusing, which the bind would not survive either.
fn bind_listener(path: &Path) -> Result<UnixListener, LaunchError> {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Err(WaylandError::Listen(path.to_path_buf(), e).into());
    }
    UnixListener::bind(path).map_err(|e| WaylandError::Listen(path.to_path_buf(), e).into())
}

// The context lasts exactly as long as the returned close pipe end and socket guard.
fn bind_context(dir: &Path, instance: &str) -> Result<(OwnedFd, FileGuard), LaunchError> {
    let path = wayland::context_socket_path(dir);
    let listener = bind_listener(&path)?;
    let guard = FileGuard(path);
    // CLOEXEC on both ends: any other holder of the write end would keep the compositor accepting.
    let (close_read, close_write) =
        pipe_with(PipeFlags::CLOEXEC).map_err(|e| WaylandError::Pipe(e.into()))?;
    wayland_context::create_context(
        listener.into(),
        close_read,
        &dbus::app_id(instance),
        &dbus::flatpak_instance_id(instance),
    )?;
    Ok((close_write, guard))
}

#[cfg(test)]
mod tests {
    use super::super::tests::no_data_dir;
    use super::*;
    use crate::host::RealHost;
    use crate::sidecar_argv::test_support::*;
    use bubbler_plan::plan_error::PlanError;

    use std::process::{Command, Stdio};

    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    /// The display name decides what the launcher connects to, so it is
    /// refused before anything is: the case runs on a host with no
    /// compositor at all and must still fail on the name, and on this
    /// host it must fail without leaving a socket behind.
    #[test]
    fn a_display_name_that_is_a_path_is_refused_before_the_compositor() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let mut e = env(tmp.path());
        let app = inst(tmp.path(), "wayland\ncommand \"true\"");
        for bad in ["../wayland-1", "/run/user/1000/wayland-1"] {
            e.wayland_display = Some(bad.into());
            let err =
                start_wayland(&e, &dir, &app, &RealHost, &AtomicBool::new(false)).expect_err(bad);
            assert!(
                matches!(
                    err,
                    LaunchError::Plan(PlanError::BadValue {
                        service: "wayland",
                        ..
                    })
                ),
                "{bad}: {err:?}"
            );
        }
        e.wayland_display = None;
        assert!(matches!(
            start_wayland(&e, &dir, &app, &RealHost, &AtomicBool::new(false)),
            Err(LaunchError::Plan(PlanError::MissingEnv {
                service: "wayland",
                var: "WAYLAND_DISPLAY"
            }))
        ));
        assert!(!wayland::socket_path(&dir).exists());
        assert!(!wayland::context_socket_path(&dir).exists());
    }

    /// Without the grant, and with `wayland "host"`, there is nothing to
    /// start: the compositor is not connected to and no socket is bound.
    #[test]
    fn a_run_without_a_sandboxed_wayland_grant_starts_no_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let mut e = env(tmp.path());
        // A name a bind would refuse, so a run that got as far as the
        // check would fail rather than pass quietly.
        e.wayland_display = Some("../wayland-1".into());
        for kdl in ["command \"true\"", "wayland \"host\"\ncommand \"true\""] {
            let app = inst(tmp.path(), kdl);
            assert!(
                start_wayland(&e, &dir, &app, &RealHost, &AtomicBool::new(false))
                    .unwrap()
                    .is_none(),
                "{kdl}"
            );
        }
        assert!(!wayland::socket_path(&dir).exists());
    }

    /// The proxy is stopped with the run: dropping the handle signals
    /// the sidecar, waits for it and takes the application's socket
    /// with it.
    ///
    /// A stand-in child rather than the proxy itself: what is under test
    /// is the handle, and a run that reaches a real proxy needs a
    /// compositor. The child's stdout is a pipe nothing else holds, so
    /// its read end reports end of file exactly when the child is gone —
    /// which no reused pid can fake.
    #[test]
    fn dropping_the_wayland_handle_stops_the_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("wayland");
        std::fs::write(&socket, b"").unwrap();
        let (read, write) = rustix::pipe::pipe().unwrap();
        let child = Command::new("/usr/bin/sleep")
            .arg("600")
            .stdout(Stdio::from(write))
            .spawn()
            .unwrap();
        let handle = WaylandHandle {
            child,
            alloc: RealAlloc::sidecar(no_data_dir()),
            _close: None,
            _socket: FileGuard(socket.clone()),
            _context: None,
            _stderr: run_log::relay().unwrap().1,
        };
        let started = Instant::now();
        drop(handle);
        assert!(
            started.elapsed() < WL_PROXY_STOP,
            "the drop waited out the kill deadline"
        );
        let slice = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert!(
            poll(&mut [PollFd::new(&read, PollFlags::IN)], Some(&slice)).unwrap() > 0,
            "the stand-in proxy is still running"
        );
        let mut byte = [0u8; 1];
        assert_eq!(rustix::io::read(&read, &mut byte).unwrap(), 0);
        assert!(!socket.exists(), "the socket outlived the run");
    }

    /// A sidecar that failed to start has already been reaped by the
    /// readiness wait, and neither handle may signal that pid: by then
    /// the kernel may have handed it to something else.
    ///
    /// The decision itself is [`still_running`], and that is what this
    /// asserts, because the drop's use of it is invisible from in here:
    /// a `kill` of a reaped pid is an ignored `ESRCH`, so deleting the
    /// guard changes nothing this process can see. A mutation of
    /// `still_running` — a constant either way, or the `try_wait`
    /// without its negation — fails one of the four assertions below.
    #[test]
    fn a_reaped_proxy_is_not_signalled_when_the_handle_drops() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("wayland");
        std::fs::write(&socket, b"").unwrap();
        let mut live = Command::new("/usr/bin/sleep").arg("600").spawn().unwrap();
        assert!(
            still_running(&mut live),
            "a running sidecar is one to signal"
        );
        let _ = live.kill();
        let _ = live.wait();
        assert!(!still_running(&mut live), "and a killed one is not");

        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        // What the readiness wait does to a sidecar that exits instead of
        // reporting: it is reaped here, and the pid stops being its own.
        let deadline = Instant::now() + PROXY_READY;
        while still_running(&mut child) {
            assert!(Instant::now() < deadline, "/usr/bin/true never exited");
            std::thread::sleep(POLL);
        }
        assert!(
            !still_running(&mut child),
            "the cached status answers every later call"
        );
        let handle = WaylandHandle {
            child,
            alloc: RealAlloc::sidecar(no_data_dir()),
            _close: None,
            _socket: FileGuard(socket.clone()),
            _context: None,
            _stderr: run_log::relay().unwrap().1,
        };
        let started = Instant::now();
        drop(handle);
        assert!(started.elapsed() < POLL, "the drop waited on a reaped pid");
        assert!(!socket.exists(), "the socket outlived the run");
    }
}
