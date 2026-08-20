use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use bubbler_init::wire;

type Started = (std::process::Child, std::path::PathBuf, tempfile::TempDir);

fn start(cmd: &[&str]) -> Started {
    start_with(cmd, false)
}

/// `ctty` stands for bubbler passing `--ctty`: the terminal on fd 0 is a
/// pty bubbler allocated, so the command may take it over.
fn start_with(cmd: &[&str], ctty: bool) -> Started {
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
    let child = init
        .arg("--")
        .args(cmd)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    drop(listener);
    drop(inherited);
    (child, sock, tmp)
}

fn exec(sock: &std::path::Path, argv: &[&str]) -> i32 {
    let s = UnixStream::connect(sock).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let refs: Vec<&std::ffi::OsStr> = argv.iter().map(std::ffi::OsStr::new).collect();
    wire::send_request(&s, &refs, [null.as_fd(), null.as_fd(), null.as_fd()]).unwrap();
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
    wire::send_request(&s, &argv, [null.as_fd(); 3]).unwrap();
    let st = wire::recv_status(&s).unwrap();
    assert_eq!(ExitStatus::from_raw(st).signal(), Some(15));
    assert_eq!(init.wait().unwrap().code(), Some(0));
}

/// What the sandbox must see when its stdio is a terminal: its own
/// session, and `/dev/tty` resolving to that terminal.
const TTY_PROBE: &str = concat!(
    r#"test "$(ps -o sid= -p $$ | tr -d ' ')" = "$$" && echo LEADER; "#,
    // `ps -o tty=` names the controlling terminal from the kernel, and
    // prints `?` when there is none; fd 0 is the pty that was handed in.
    r#"test "$(readlink /proc/self/fd/0)" = "/dev/$(ps -o tty= -p $$ | tr -d ' ')" && echo CTTY"#
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
/// everything it printed to that pty.
fn exec_on_a_pty(sock: &std::path::Path) -> (i32, String) {
    let flags = rustix::pty::OpenptFlags::RDWR
        | rustix::pty::OpenptFlags::NOCTTY
        | rustix::pty::OpenptFlags::CLOEXEC;
    let master = rustix::pty::openpt(flags).unwrap();
    rustix::pty::grantpt(&master).unwrap();
    rustix::pty::unlockpt(&master).unwrap();
    let slave = rustix::pty::ioctl_tiocgptpeer(&master, flags).unwrap();
    let s = UnixStream::connect(sock).unwrap();
    let argv = [
        std::ffi::OsStr::new("/usr/bin/sh"),
        std::ffi::OsStr::new("-c"),
        std::ffi::OsStr::new(TTY_PROBE),
    ];
    wire::send_request(&s, &argv, [slave.as_fd(); 3]).unwrap();
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
fn a_command_given_a_terminal_leads_its_own_session_and_owns_it() {
    let (mut init, sock, _tmp) = start_with(&["/usr/bin/sleep", "30"], true);
    std::thread::sleep(Duration::from_millis(200));
    let (status, out) = exec_on_a_pty(&sock);
    assert!(out.contains("LEADER"), "not a session leader: {out:?}");
    assert!(out.contains("CTTY"), "/dev/tty is not its own pty: {out:?}");
    assert_eq!(ExitStatus::from_raw(status).code(), Some(0), "{out:?}");
    stop(&mut init);
}

#[test]
fn without_the_flag_a_terminal_is_left_to_whoever_owns_it() {
    // No `--ctty`: the terminal on fd 0 may be the user's own, and taking
    // it over would move their shell out of its session.
    let (mut init, sock, _tmp) = start(&["/usr/bin/sleep", "30"]);
    std::thread::sleep(Duration::from_millis(200));
    let (_, out) = exec_on_a_pty(&sock);
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
    assert_eq!(
        std::io::Read::read(&mut &*oldest, &mut byte).unwrap(),
        0,
        "the oldest stalled connection was kept"
    );
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
