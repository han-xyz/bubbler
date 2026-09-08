//! The holder mode of the supervisor binary, started the way
//! `pw-container` starts it: one word of argv, everything else in the
//! environment.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process};

/// How long the holder gets to report, and to leave after SIGTERM. Both
/// are one write and one exit, so this bounds a hang and not the work.
const LIMIT: Duration = Duration::from_secs(5);

/// The holder started as `pw-container` starts it: the socket it made,
/// the descriptor to report on, and no arguments at all. Its stdout is
/// the report descriptor here, which is what `BUBBLER_PW_REPORT_FD`
/// names; a run gives it a pipe of the launcher's instead.
struct Held {
    child: Child,
    socket: PathBuf,
    /// Kept open, as `pw-container` keeps its own: the socket the holder
    /// renames is a bound one.
    _listener: UnixListener,
}

fn start(dir: &Path) -> Held {
    let socket = dir.join("pipewire-Zz90Yx");
    let listener = UnixListener::bind(&socket).expect("a bound socket");
    let child = Command::new(env!("CARGO_BIN_EXE_bubbler-init"))
        .arg0("bubbler-pw-hold")
        .env_clear()
        .env("PIPEWIRE_REMOTE", &socket)
        .env("BUBBLER_PW_REPORT_FD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the supervisor binary");
    Held {
        child,
        socket,
        _listener: listener,
    }
}

/// Everything `fd` holds up to the first newline, within [`LIMIT`].
fn reported(fd: BorrowedFd<'_>) -> String {
    let deadline = Instant::now() + LIMIT;
    let mut line = Vec::new();
    while !line.ends_with(b"\n") {
        assert!(Instant::now() < deadline, "nothing was reported: {line:?}");
        let slice = Timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        if !matches!(poll(&mut [PollFd::new(&fd, PollFlags::IN)], Some(&slice)), Ok(n) if n > 0) {
            continue;
        }
        let mut byte = [0u8; 1];
        match rustix::io::read(fd, &mut byte) {
            Ok(0) => panic!("the report descriptor closed before a line: {line:?}"),
            Ok(_) => line.push(byte[0]),
            Err(Errno::INTR) => {}
            Err(e) => panic!("reading the report: {e}"),
        }
    }
    String::from_utf8(line).expect("a path this test wrote")
}

/// Stop `held` however the test ended, so no holder outlives it.
fn stop(mut held: Held) {
    let _ = held.child.kill();
    let _ = held.child.wait();
}

#[test]
fn the_holder_reports_the_path_it_renamed_the_context_socket_to() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut held = start(dir.path());
    let out: OwnedFd = held.child.stdout.take().expect("a piped stdout").into();

    let line = reported(out.as_fd());

    let renamed = dir.path().join("pipewire-0");
    assert_eq!(line, format!("{}\n", renamed.display()));
    assert!(renamed.exists(), "the socket is at the reported path");
    assert!(!held.socket.exists(), "and no longer at its old one");
    stop(held);
}

#[test]
fn the_holder_exits_zero_on_sigterm() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut held = start(dir.path());
    let out: OwnedFd = held.child.stdout.take().expect("a piped stdout").into();
    // Only once it has reported: before that it is still renaming, and
    // this would be measuring the race rather than the signal.
    reported(out.as_fd());

    kill_process(Pid::from_child(&held.child), Signal::TERM).expect("the holder is running");

    let deadline = Instant::now() + LIMIT;
    let status = loop {
        match held.child.try_wait().expect("waiting for the holder") {
            Some(status) => break status,
            None => assert!(
                Instant::now() < deadline,
                "the holder ignored SIGTERM for {LIMIT:?}"
            ),
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0), "{status}");
}
