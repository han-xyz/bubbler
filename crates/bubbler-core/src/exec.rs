//! Client side of the exec channel: talk to a running instance's
//! `bubbler-init` through the control socket in the runtime dir.
//!
//! The exec'd process is handed this process's own stdin, stdout and
//! stderr, so it can reach the host terminal directly. The channel is a
//! debugging and tooling path, not a hardening boundary.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;

use bubbler_init::wire;

use crate::env::Env;
use crate::error::LaunchError;
use crate::launcher::exit_code;

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

/// Run `argv` inside the live instance with this process's stdio and
/// return the exit code to propagate. Waits without a deadline: the
/// command may run for as long as it likes, and interrupting bubbler
/// here leaves it running under the instance's init.
pub fn run_in(stream: &UnixStream, argv: &[OsString]) -> Result<i32, LaunchError> {
    let refs: Vec<&OsStr> = argv.iter().map(|a| a.as_os_str()).collect();
    let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
    wire::send_request(
        stream,
        &refs,
        [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()],
    )
    .map_err(|e| LaunchError::Protocol(e.to_string()))?;
    let raw = wire::recv_status(stream).map_err(|e| LaunchError::Protocol(e.to_string()))?;
    Ok(exit_code(ExitStatus::from_raw(raw)))
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
            runtime_dir: runtime_dir.to_path_buf(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
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
            let (argv, fds) = wire::recv_request(&stream, deadline).unwrap();
            assert_eq!(argv, vec![OsString::from("true")]);
            assert_eq!(fds.len(), 3);
            wire::send_status(&stream, 3 << 8).unwrap();
        });
        let stream = connect(&e, "t").unwrap().expect("the listener is live");
        assert_eq!(run_in(&stream, &[OsString::from("true")]).unwrap(), 3);
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
            run_in(&stream, &[OsString::from("true")]),
            Err(LaunchError::Protocol(_))
        ));
        server.join().unwrap();
    }
}
