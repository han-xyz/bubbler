use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use bubbler_init::{proto, wire};

type Started = (std::process::Child, std::path::PathBuf, tempfile::TempDir);

fn start(cmd: &[&str]) -> Started {
    start_with(cmd, false, None, None)
}

/// Start the supervisor on an inherited listening socket. `ctty` stands
/// for bubbler passing `--ctty`: the terminal on fd 0 is a pty bubbler
/// allocated, so the main command may take it over. `stdio` is what all
/// three of its descriptors become; without one it gets `/dev/null`, so
/// no test ever hands it the terminal it is run from. `helper` is the
/// display helper argv bubbler passes as `--helper <argv...> --`.
fn start_with(
    cmd: &[&str],
    ctty: bool,
    stdio: Option<&OwnedFd>,
    helper: Option<&[&str]>,
) -> Started {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("init.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    // The listener must be inherited: clear CLOEXEC on a dup.
    let inherited = rustix::io::fcntl_dupfd_cloexec(listener.as_fd(), 3).unwrap();
    rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty()).unwrap();
    let mut init = Command::new(env!("CARGO_BIN_EXE_bubbler-init"));
    init.arg("--socket-fd")
        .arg(inherited.as_raw_fd().to_string());
    if ctty {
        init.arg("--ctty");
    }
    if let Some(argv) = helper {
        init.arg("--helper").args(argv).arg("--");
    }
    match stdio {
        Some(fd) => {
            init.stdin(Stdio::from(fd.try_clone().unwrap()))
                .stdout(Stdio::from(fd.try_clone().unwrap()))
                .stderr(Stdio::from(fd.try_clone().unwrap()));
        }
        None => {
            init.stdin(Stdio::null()).stdout(Stdio::null());
        }
    }
    let child = init.arg("--").args(cmd).spawn().unwrap();
    drop(listener);
    drop(inherited);
    (child, sock, tmp)
}

/// A fresh pty pair; the caller keeps the master and hands the slave out.
fn pty_pair() -> (OwnedFd, OwnedFd) {
    let flags = rustix::pty::OpenptFlags::RDWR
        | rustix::pty::OpenptFlags::NOCTTY
        | rustix::pty::OpenptFlags::CLOEXEC;
    let master = rustix::pty::openpt(flags).unwrap();
    rustix::pty::grantpt(&master).unwrap();
    rustix::pty::unlockpt(&master).unwrap();
    let slave = rustix::pty::ioctl_tiocgptpeer(&master, flags).unwrap();
    (master, slave)
}

fn exec(sock: &std::path::Path, argv: &[&str]) -> i32 {
    let null = std::fs::File::open("/dev/null").unwrap();
    exec_with_stdout(sock, argv, null.as_fd())
}

/// Exec a command whose stdout is `out`, so the test can read back what
/// it printed; stdin and stderr are `/dev/null`.
fn exec_with_stdout(
    sock: &std::path::Path,
    argv: &[&str],
    out: std::os::fd::BorrowedFd<'_>,
) -> i32 {
    let s = UnixStream::connect(sock).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let refs: Vec<&std::ffi::OsStr> = argv.iter().map(std::ffi::OsStr::new).collect();
    wire::send_request(&s, &refs, 0, [null.as_fd(), out, null.as_fd()]).unwrap();
    wire::recv_status(&s).unwrap()
}

#[test]
fn exec_returns_status_and_sigterm_stops_everything() {
    let (mut init, sock, _tmp) = start(&["/usr/bin/sleep", "30"]);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        ExitStatus::from_raw(exec(&sock, &["/usr/bin/true"])).code(),
        Some(0)
    );
    let st = exec(&sock, &["/usr/bin/sh", "-c", "exit 3"]);
    assert_eq!(ExitStatus::from_raw(st).code(), Some(3));
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    let t = Instant::now();
    let status = loop {
        if let Some(s) = init.try_wait().unwrap() {
            break s;
        }
        assert!(t.elapsed() < Duration::from_secs(8), "init did not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(143));
}

#[test]
fn main_exit_code_propagates_and_bad_request_is_ignored() {
    let (mut init, sock, _tmp) = start(&["/usr/bin/sh", "-c", "sleep 0.5; exit 7"]);
    std::thread::sleep(Duration::from_millis(100));
    let s = UnixStream::connect(&sock).unwrap();
    (&s).write_all(b"garbage").unwrap();
    drop(s);
    let status = init.wait().unwrap();
    assert_eq!(status.code(), Some(7));
}

#[test]
fn main_exit_terminates_leftover_execs() {
    let (mut init, sock, _tmp) = start(&["/usr/bin/sh", "-c", "sleep 0.3"]);
    let s = UnixStream::connect(&sock).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let argv = [
        std::ffi::OsStr::new("/usr/bin/sleep"),
        std::ffi::OsStr::new("30"),
    ];
    wire::send_request(&s, &argv, 0, [null.as_fd(); 3]).unwrap();
    let st = wire::recv_status(&s).unwrap();
    assert_eq!(ExitStatus::from_raw(st).signal(), Some(15));
    assert_eq!(init.wait().unwrap().code(), Some(0));
}

/// What the sandbox must see when its stdio is a terminal: its own
/// session, and `/dev/tty` resolving to that terminal.
const TTY_PROBE: &str = concat!(
    // Fields 6 and 7 of /proc/<pid>/stat are the session id and the
    // controlling terminal's device number; `ps` is not in a clean
    // chroot (procps-ng is a dependency of base, not base-devel).
    r#"read -r _ _ _ _ _ sid tty _ < /proc/$$/stat; "#,
    r#"test "$sid" = "$$" && echo LEADER; "#,
    // tty_nr packs major/minor the same way `stat -c %t:%T` prints them
    // (minor bits 0-7 and 20-31, major bits 8-19); 0 means none.
    r#"maj=$(( (tty >> 8) & 0xfff )); min=$(( (tty & 0xff) | ((tty >> 12) & 0xfff00) )); "#,
    r#"test "$tty" != 0 && test "$(printf %x:%x $maj $min)" = "$(stat -c %t:%T "$(readlink /proc/self/fd/0)")" && echo CTTY"#
);

/// Read a pty master to the end; the last slave closing reports `EIO`.
fn read_to_end(fd: std::os::fd::BorrowedFd<'_>) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match rustix::io::read(fd, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Exec the probe with a fresh pty as its stdio; returns its status and
/// everything it printed to that pty. `ctty` is the request flag asking
/// for that pty to become the command's controlling terminal.
fn exec_on_a_pty(sock: &std::path::Path, ctty: bool) -> (i32, String) {
    let (master, slave) = pty_pair();
    let s = UnixStream::connect(sock).unwrap();
    let argv = [
        std::ffi::OsStr::new("/usr/bin/sh"),
        std::ffi::OsStr::new("-c"),
        std::ffi::OsStr::new(TTY_PROBE),
    ];
    let flags = if ctty { proto::FLAG_CTTY } else { 0 };
    wire::send_request(&s, &argv, flags, [slave.as_fd(); 3]).unwrap();
    // The supervisor side holds the only slave, so the master reads to
    // EIO once the command has exited.
    drop(slave);
    let status = wire::recv_status(&s).unwrap();
    (status, read_to_end(master.as_fd()))
}

fn stop(init: &mut std::process::Child) {
    rustix::process::kill_process(
        rustix::process::Pid::from_child(init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    init.wait().unwrap();
}

#[test]
fn the_main_command_given_a_terminal_leads_its_own_session_and_owns_it() {
    let (master, slave) = pty_pair();
    let (mut init, _sock, _tmp) =
        start_with(&["/usr/bin/sh", "-c", TTY_PROBE], true, Some(&slave), None);
    // Only the supervisor's copies are left, so the master reads to EIO
    // as soon as the run is over.
    drop(slave);
    assert_eq!(init.wait().unwrap().code(), Some(0));
    let out = read_to_end(master.as_fd());
    assert!(out.contains("LEADER"), "not a session leader: {out:?}");
    assert!(out.contains("CTTY"), "/dev/tty is not its own pty: {out:?}");
}

#[test]
fn an_exec_request_may_ask_for_the_terminal_it_sends() {
    // No `--ctty`: the flag on the request is what decides, because only
    // the client knows the pty on fd 0 is one it allocated.
    let (mut init, sock, _tmp) = start(&["/usr/bin/sleep", "30"]);
    std::thread::sleep(Duration::from_millis(200));
    let (status, out) = exec_on_a_pty(&sock, true);
    assert!(out.contains("LEADER"), "not a session leader: {out:?}");
    assert!(out.contains("CTTY"), "/dev/tty is not its own pty: {out:?}");
    assert_eq!(ExitStatus::from_raw(status).code(), Some(0), "{out:?}");
    stop(&mut init);
}

#[test]
fn without_the_request_flag_a_terminal_is_left_to_whoever_owns_it() {
    // `--ctty` covers the instance's own command only: an exec whose fd 0
    // may be the user's own terminal must not take it over.
    let (mut init, sock, _tmp) = start_with(&["/usr/bin/sleep", "30"], true, None, None);
    std::thread::sleep(Duration::from_millis(200));
    let (_, out) = exec_on_a_pty(&sock, false);
    assert!(!out.contains("LEADER"), "took a session anyway: {out:?}");
    assert!(!out.contains("CTTY"), "took the terminal anyway: {out:?}");
    stop(&mut init);
}

#[test]
fn unexecutable_request_reports_127() {
    let (mut init, sock, _tmp) = start(&["/usr/bin/sleep", "30"]);
    let st = exec(&sock, &["/nonexistent/bubbler-test-command"]);
    assert_eq!(ExitStatus::from_raw(st).code(), Some(127));
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    init.wait().unwrap();
}

/// Promise `len` payload bytes with the three fds attached, then send nothing.
fn send_prefix_and_fds(stream: &UnixStream, len: u32) {
    let null = std::fs::File::open("/dev/null").unwrap();
    let fds = [null.as_fd(); 3];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut anc = rustix::net::SendAncillaryBuffer::new(&mut space);
    assert!(anc.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
    rustix::net::sendmsg(
        stream.as_fd(),
        &[std::io::IoSlice::new(&len.to_le_bytes())],
        &mut anc,
        rustix::net::SendFlags::empty(),
    )
    .unwrap();
}

#[test]
fn a_closed_socket_fd_is_a_usage_error_not_an_abort() {
    let out = Command::new(env!("CARGO_BIN_EXE_bubbler-init"))
        .arg("--socket-fd")
        .arg("99")
        .arg("--")
        .arg("/usr/bin/true")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "aborted instead of exiting 2");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("socket fd"), "stderr was {err:?}");
}

#[test]
fn a_stalled_client_cannot_hold_up_the_supervisor() {
    let (mut init, sock, _tmp) = start(&["/usr/bin/sleep", "30"]);
    std::thread::sleep(Duration::from_millis(200));
    let stalled = UnixStream::connect(&sock).unwrap();
    send_prefix_and_fds(&stalled, 64);
    let t = Instant::now();
    assert_eq!(
        ExitStatus::from_raw(exec(&sock, &["/usr/bin/true"])).code(),
        Some(0)
    );
    assert!(
        t.elapsed() < Duration::from_millis(1000),
        "second exec waited {:?}",
        t.elapsed()
    );
    let t = Instant::now();
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    let status = loop {
        if let Some(s) = init.try_wait().unwrap() {
            break s;
        }
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "init took {:?} to honour SIGTERM",
            t.elapsed()
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(143));
    drop(stalled);
}

#[test]
fn more_stalled_clients_than_the_table_holds_drops_the_oldest() {
    let (mut init, sock, _tmp) = start(&["/usr/bin/sleep", "30"]);
    std::thread::sleep(Duration::from_millis(200));
    // One more than the supervisor keeps: the first connection makes room
    // for the last instead of the table growing without bound.
    let stalled: Vec<UnixStream> = (0..17)
        .map(|_| {
            let s = UnixStream::connect(&sock).unwrap();
            send_prefix_and_fds(&s, 64);
            s
        })
        .collect();
    let oldest = &stalled[0];
    oldest
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0u8; 1];
    // Closed is closed, whichever way it reaches this end: an orderly
    // EOF when the supervisor had already read the prefix this client
    // sent, and ECONNRESET when it had not, since closing a socket with
    // unread bytes in it sends an RST instead. Which of the two the read
    // sees is a race with the supervisor's own poll.
    match std::io::Read::read(&mut &*oldest, &mut byte) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("the oldest stalled connection was kept: {other:?}"),
    }
    assert_eq!(
        ExitStatus::from_raw(exec(&sock, &["/usr/bin/true"])).code(),
        Some(0)
    );
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    init.wait().unwrap();
    drop(stalled);
}

/// Interpreter the fake display helpers are written in; the tests below
/// skip when it is not installed, as the fixtures elsewhere do.
const PYTHON: &str = "/usr/bin/python3";

/// Returns false (after printing why) when the fake helpers cannot run here.
fn require_python() -> bool {
    let ok = std::path::Path::new(PYTHON).is_file();
    if !ok {
        println!("skipping: {PYTHON} is not installed");
    }
    ok
}

/// What every fake helper does before it differs: find `-displayfd N` in
/// its own argv the way Xwayland does, and leave its pid beside the
/// script so the test can tell whether it is still running.
const HELPER_PRELUDE: &str = r#"import os, sys, time
argv = sys.argv[1:]
fd = int(argv[argv.index("-displayfd") + 1])
open(sys.argv[0] + ".pid", "w").write(str(os.getpid()))
"#;

/// A helper that reports display 0 and then stays up, as Xwayland does.
const REPORTS_AND_STAYS: &str = r#"os.write(fd, b"0\n")
time.sleep(30)
"#;
/// A helper that comes up but never reports a display.
const NEVER_REPORTS: &str = "time.sleep(30)\n";
/// A helper that fails before it can report anything.
const DIES_AT_ONCE: &str = "sys.exit(1)\n";
/// A helper that reports a display and then loses it.
const REPORTS_AND_DIES: &str = r#"os.write(fd, b"0\n")
time.sleep(0.5)
"#;

/// Write one fake helper into `dir` and return its path.
fn helper_script(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(HELPER_PRELUDE.as_bytes()).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

/// A file standing in for the supervisor's whole stdio, so its messages
/// are readable and none of them reach the terminal the tests run from.
fn stdio_file(path: &std::path::Path) -> OwnedFd {
    OwnedFd::from(
        std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap(),
    )
}

/// Wait for a file to hold something and return it.
fn wait_for_file(path: &std::path::Path) -> String {
    let t = Instant::now();
    loop {
        if let Ok(s) = std::fs::read_to_string(path)
            && !s.is_empty()
        {
            return s;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The pid a fake helper recorded for itself.
fn helper_pid(script: &std::path::Path) -> i32 {
    let mut pidfile = script.as_os_str().to_owned();
    pidfile.push(".pid");
    wait_for_file(std::path::Path::new(&pidfile))
        .trim()
        .parse()
        .unwrap()
}

/// Fail unless the helper has left the process table. It is the
/// supervisor's own child, so it is reaped there and the entry goes with it.
fn assert_gone(pid: i32) {
    let path = std::path::PathBuf::from(format!("/proc/{pid}"));
    let t = Instant::now();
    while path.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "the helper ({pid}) was left running"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_helper_that_reports_a_display_is_started_first_and_the_command_sees_it() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = helper_script(dir.path(), "reports.py", REPORTS_AND_STAYS);
    let seen = dir.path().join("cmd.env");
    let run = format!("env > {}; exec sleep 30", seen.display());
    let (mut init, sock, _tmp) = start_with(
        &["/usr/bin/sh", "-c", &run],
        false,
        None,
        Some(&[PYTHON, script.to_str().unwrap()]),
    );
    let env = wait_for_file(&seen);
    assert!(
        env.lines().any(|l| l == "DISPLAY=:0"),
        "the command saw no display: {env:?}"
    );
    let out = dir.path().join("exec.env");
    let file = std::fs::File::create(&out).unwrap();
    let st = exec_with_stdout(&sock, &["/usr/bin/env"], file.as_fd());
    assert_eq!(ExitStatus::from_raw(st).code(), Some(0));
    let env = std::fs::read_to_string(&out).unwrap();
    assert!(
        env.lines().any(|l| l == "DISPLAY=:0"),
        "the exec'd child saw no display: {env:?}"
    );
    let pid = helper_pid(&script);
    stop(&mut init);
    assert_gone(pid);
}

#[test]
fn a_helper_that_never_reports_is_a_startup_failure() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = helper_script(dir.path(), "mute.py", NEVER_REPORTS);
    let marker = dir.path().join("the-command-ran");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &["/usr/bin/touch", marker.to_str().unwrap()],
        false,
        Some(&fd),
        Some(&[PYTHON, script.to_str().unwrap()]),
    );
    let pid = helper_pid(&script);
    let t = Instant::now();
    let status = init.wait().unwrap();
    assert!(
        t.elapsed() >= Duration::from_secs(9) && t.elapsed() < Duration::from_secs(25),
        "gave up after {:?}",
        t.elapsed()
    );
    assert_eq!(status.code(), Some(2));
    let err = std::fs::read_to_string(&log).unwrap();
    assert!(err.contains("Xwayland did not start"), "stderr was {err:?}");
    assert!(!marker.exists(), "the command ran without a display");
    assert_gone(pid);
}

#[test]
fn a_helper_that_dies_before_reporting_is_a_startup_failure() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = helper_script(dir.path(), "doomed.py", DIES_AT_ONCE);
    let marker = dir.path().join("the-command-ran");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &["/usr/bin/touch", marker.to_str().unwrap()],
        false,
        Some(&fd),
        Some(&[PYTHON, script.to_str().unwrap()]),
    );
    let pid = helper_pid(&script);
    let t = Instant::now();
    let status = init.wait().unwrap();
    assert!(
        t.elapsed() < Duration::from_secs(9),
        "waited the full timeout"
    );
    assert_eq!(status.code(), Some(2));
    let err = std::fs::read_to_string(&log).unwrap();
    assert!(err.contains("Xwayland did not start"), "stderr was {err:?}");
    assert!(!marker.exists(), "the command ran without a display");
    assert_gone(pid);
}

#[test]
fn a_helper_dying_while_the_command_runs_terminates_the_command() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = helper_script(dir.path(), "quitter.py", REPORTS_AND_DIES);
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &["/usr/bin/sleep", "30"],
        false,
        Some(&fd),
        Some(&[PYTHON, script.to_str().unwrap()]),
    );
    let t = Instant::now();
    let status = init.wait().unwrap();
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "the command outlived the display by {:?}",
        t.elapsed()
    );
    assert_eq!(status.code(), Some(143));
    let err = std::fs::read_to_string(&log).unwrap();
    assert!(
        err.contains("Xwayland exited; stopping the command"),
        "stderr was {err:?}"
    );
}
