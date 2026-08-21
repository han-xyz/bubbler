//! Client side of the exec channel: talk to a running instance's
//! `bubbler-init` through the control socket in the runtime dir.
//!
//! What the exec'd process gets for stdio is the terminal mode's
//! decision: a pty bubbler allocated and relays, or bubbler's own
//! descriptors. Descriptors handed over are reachable through `/proc` by
//! everything else in the sandbox, so the channel is a tooling path, not
//! a hardening boundary.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bubbler_init::{proto, wire};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::pipe::PipeFlags;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};

use crate::env::Env;
use crate::error::LaunchError;
use crate::launcher::{SignalGuard, exit_code};
use crate::tty::{self, RawGuard, RelayEnd, StdioPlan, StdioTarget};

/// Name of the control socket inside an instance's runtime directory.
pub const SOCKET_NAME: &str = "init.sock";

/// `$XDG_RUNTIME_DIR/bubbler/<name>/init.sock`. `name` is an instance
/// name the caller has already validated.
pub fn socket_path(env: &Env, name: &str) -> PathBuf {
    env.runtime_dir.join("bubbler").join(name).join(SOCKET_NAME)
}

/// Connect to a live instance. `Ok(None)` when nothing listens; a refused
/// socket is left over from a dead run and is unlinked so a fresh start
/// can bind the path again.
pub fn connect(env: &Env, name: &str) -> Result<Option<UnixStream>, LaunchError> {
    let path = socket_path(env, name);
    match UnixStream::connect(&path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(&path).map_err(|e| LaunchError::Io(path.clone(), e))?;
            Ok(None)
        }
        Err(e) => Err(LaunchError::Io(path, e)),
    }
}

/// Poll with no wait at all: the relay asks between its own reads and
/// must never park here.
const NOW: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

/// The signals that end a relayed exec, and the code each leaves. Caught
/// rather than fatal because the terminal is bubbler's to give back: a
/// killed relay would leave the user's terminal raw.
const STOP_SIGNALS: [i32; 3] = [SIGINT, SIGTERM, SIGHUP];

fn protocol_error(e: io::Error) -> LaunchError {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => {
            LaunchError::Protocol("the instance stopped while the command was running".into())
        }
        _ => LaunchError::Protocol(e.to_string()),
    }
}

/// Whether the supervisor has sent something: the status is the only
/// thing it ever writes, so anything readable means the command is over.
fn status_ready(stream: &UnixStream) -> bool {
    let mut fds = [PollFd::new(stream, PollFlags::IN)];
    poll(&mut fds, Some(&NOW)).is_ok() && !fds[0].revents().is_empty()
}

/// The descriptor the supervisor is given for one of fds 0, 1 and 2.
/// Everything is duplicated: bubbler drops its copies once the request is
/// on its way, and the ones inside the sandbox live on.
fn fd_for(
    target: StdioTarget,
    index: usize,
    host: &[OwnedFd; 3],
    plan: &StdioPlan,
    pipes: &mut Vec<(OwnedFd, usize)>,
) -> Result<OwnedFd, LaunchError> {
    match target {
        StdioTarget::Slave => match &plan.pty {
            Some(pty) => pty.slave.try_clone().map_err(LaunchError::Pty),
            // A plan naming a pty that was never allocated is a bug;
            // sending bubbler's own terminal instead would hide it.
            None => Err(LaunchError::Pty(io::Error::other(
                "no pty was allocated for this command",
            ))),
        },
        StdioTarget::Inherit => host[index].try_clone().map_err(LaunchError::Pty),
        StdioTarget::Null => tty::null_stdio(),
        StdioTarget::Pipe => {
            // CLOEXEC: only the supervisor's copy of the write end may
            // outlive this call, and it travels by SCM_RIGHTS.
            let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)
                .map_err(|e| LaunchError::Pty(e.into()))?;
            pipes.push((read, index));
            Ok(write)
        }
    }
}

/// Run `argv` inside the live instance and return the exit code to
/// propagate. `mode` decides what the command gets for stdio: in `pty`
/// mode bubbler allocates one, asks the supervisor to make it the
/// command's controlling terminal and relays it, so the sandbox never
/// holds a descriptor for the user's terminal.
///
/// Waits without a deadline: the command may run for as long as it likes.
/// Detaching (`^]` three times) returns 0 and leaves it under the
/// instance's supervisor — with bubbler gone its pty hangs up, so a
/// command that does not ignore `SIGHUP` ends there.
///
/// A `SIGINT`, `SIGTERM` or `SIGHUP` while output is being relayed ends
/// the relay the same way and returns `128 + signal`: the command stays
/// with the supervisor, which is the most an exec can do about it — the
/// channel carries a request and a status, and nothing else.
pub fn run_in(
    stream: &UnixStream,
    argv: &[OsString],
    mode: tty::TtyMode,
) -> Result<i32, LaunchError> {
    let refs: Vec<&OsStr> = argv.iter().map(|a| a.as_os_str()).collect();
    let host = tty::host_stdio()?;
    let is_tty = tty::host_is_tty();
    let mut plan = tty::plan(mode, is_tty);
    // The pty copies the first terminal bubbler has, and is allocated
    // before raw mode: afterwards it would carry raw settings into the
    // sandbox, leaving the command without echo or line editing.
    if let Some(i) = plan
        .needs_pty()
        .then(|| is_tty.iter().position(|t| *t))
        .flatten()
    {
        plan.pty = Some(tty::allocate(host[i].as_fd())?);
    }
    let mut pipes: Vec<(OwnedFd, usize)> = Vec::new();
    let mut send: Vec<OwnedFd> = Vec::with_capacity(3);
    for (i, target) in plan.fds.into_iter().enumerate() {
        send.push(fd_for(target, i, &host, &plan, &mut pipes)?);
    }
    let flags = if plan.ctty() { proto::FLAG_CTTY } else { 0 };
    wire::send_request(
        stream,
        &refs,
        flags,
        [send[0].as_fd(), send[1].as_fd(), send[2].as_fd()],
    )
    .map_err(|e| LaunchError::Protocol(e.to_string()))?;
    // The fds are in the socket's queue and no longer need an owner here.
    // The slave goes with them: one left behind would keep the pty from
    // ever reporting the end of the command's output.
    drop(send);
    let master = plan.pty.take().map(|p| p.master);
    let winch = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicUsize::new(0));
    let mut registered = SignalGuard(Vec::new());
    // Only while something is being relayed. With nothing of ours in
    // between, the terminal is untouched and a signal is the caller's to
    // die of, as it was before the command was sent.
    if master.is_some() || !pipes.is_empty() {
        for sig in STOP_SIGNALS {
            let id = signal_hook::flag::register_usize(sig, Arc::clone(&stop), sig as usize)
                .map_err(LaunchError::Signal)?;
            registered.0.push(id);
        }
    }
    if master.is_some() {
        let id = signal_hook::flag::register(SIGWINCH, Arc::clone(&winch))
            .map_err(LaunchError::Signal)?;
        registered.0.push(id);
    }
    // The guard restores the terminal on every way out from here on.
    let mut raw = match plan.raw_mode() {
        true => Some(RawGuard::new(host[0].as_fd())?),
        false => None,
    };
    // Output the user's own descriptors cannot take goes here instead:
    // when none of them can be written to at all (`bubbler exec x
    // < /dev/tty > out`) and when one stops taking it. Draining somewhere
    // is what keeps the command from blocking on a full pty or pipe.
    let sink = tty::null_stdio()?;
    let mut received: Option<io::Result<i32>> = None;
    let mut signalled: Option<i32> = None;
    // Latched for the relay, which reads it while handing over the last
    // of the output: a signal means the user is waiting for bubbler.
    let stopping = AtomicBool::new(false);
    let caught = tty::Caught {
        winch: &winch,
        stop: &stopping,
    };
    let end = {
        let mut until = || {
            if status_ready(stream) {
                let got = wire::recv_status(stream);
                // Any answer ends the wait; a broken one is reported below.
                let code = got
                    .as_ref()
                    .map_or(1, |raw| exit_code(ExitStatus::from_raw(*raw)));
                received = Some(got);
                return Some(code);
            }
            // A status already in hand wins over a signal arriving with
            // it; what is left here ends the relay with nothing to
            // report but the signal itself.
            match stop.swap(0, Ordering::SeqCst) {
                0 => None,
                sig => {
                    signalled = Some(sig as i32);
                    stopping.store(true, Ordering::SeqCst);
                    Some(128 + sig as i32)
                }
            }
        };
        match &master {
            Some(master) => {
                let out = tty::output_fd(&plan, &host);
                // With nothing of the user's able to take the output it
                // goes to the sink, which never refuses it, so the name
                // is never printed.
                let (host_out, out_name) = match out {
                    Some(i) => (host[i].as_fd(), tty::FD_NAMES[i]),
                    None => (sink.as_fd(), tty::FD_NAMES[1]),
                };
                tty::relay(
                    master.as_fd(),
                    plan.ctty().then(|| host[0].as_fd()),
                    host_out,
                    out_name,
                    sink.as_fd(),
                    &mut until,
                    &caught,
                )?
            }
            None if !pipes.is_empty() => {
                let ends: Vec<_> = pipes
                    .iter()
                    .map(|(read, i)| (read.as_fd(), host[*i].as_fd(), tty::FD_NAMES[*i]))
                    .collect();
                tty::pump(&ends, sink.as_fd(), &mut until, &stopping)?;
                RelayEnd::Exited(0)
            }
            // Nothing of ours to move: the status is all this waits for.
            None => {
                received = Some(wire::recv_status(stream));
                RelayEnd::Exited(0)
            }
        }
    };
    match (end, received, signalled) {
        (RelayEnd::Detached, ..) => {
            // Restored before the note, which would otherwise be printed
            // with the terminal still raw.
            if let Some(guard) = raw.as_mut() {
                guard.restore();
            }
            eprintln!("{}", tty::DETACHED_NOTE);
            Ok(0)
        }
        (_, Some(Ok(raw)), _) => Ok(exit_code(ExitStatus::from_raw(raw))),
        (_, Some(Err(e)), _) => Err(protocol_error(e)),
        // The guard puts the terminal back as this returns, which is the
        // whole reason the signal was caught instead of fatal.
        (_, None, Some(sig)) => Ok(128 + sig),
        (_, None, None) => Err(LaunchError::Protocol(
            "the instance sent no status for the command".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn env(runtime_dir: &Path) -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            config_home: "/home/han/.config".into(),
            runtime_dir: runtime_dir.to_path_buf(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            dbus_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
        }
    }

    fn instance_dir(runtime_dir: &Path, name: &str) -> PathBuf {
        let dir = runtime_dir.join("bubbler").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_socket_is_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        assert_eq!(socket_path(&e, "t"), tmp.path().join("bubbler/t/init.sock"));
        assert!(connect(&e, "t").unwrap().is_none());
    }

    #[test]
    fn a_stale_socket_is_unlinked_so_a_fresh_start_can_bind() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let path = instance_dir(tmp.path(), "t").join(SOCKET_NAME);
        // A socket file with nobody listening is what a killed run leaves.
        drop(UnixListener::bind(&path).unwrap());
        assert!(connect(&e, "t").unwrap().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn a_live_socket_connects_and_round_trips_a_status() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let path = instance_dir(tmp.path(), "t").join(SOCKET_NAME);
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let (request, fds) = wire::recv_request(&stream, deadline).unwrap();
            assert_eq!(request.argv, vec![OsString::from("true")]);
            assert_eq!(fds.len(), 3);
            wire::send_status(&stream, 3 << 8).unwrap();
        });
        let stream = connect(&e, "t").unwrap().expect("the listener is live");
        let mode = tty::TtyMode::Passthrough;
        assert_eq!(run_in(&stream, &[OsString::from("true")], mode).unwrap(), 3);
        server.join().unwrap();
    }

    #[test]
    fn a_hangup_without_a_status_is_a_protocol_error() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let path = instance_dir(tmp.path(), "t").join(SOCKET_NAME);
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || drop(listener.accept().unwrap()));
        let stream = connect(&e, "t").unwrap().expect("the listener is live");
        assert!(matches!(
            run_in(
                &stream,
                &[OsString::from("true")],
                tty::TtyMode::Passthrough
            ),
            Err(LaunchError::Protocol(_))
        ));
        server.join().unwrap();
    }
}
