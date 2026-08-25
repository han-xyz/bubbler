use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use bubbler_init::{proto, wire};

type Started = (std::process::Child, PathBuf, tempfile::TempDir);

/// Everything bubbler may pass the supervisor beyond the command itself.
/// `ctty` stands for `--ctty`: the terminal on fd 0 is a pty bubbler
/// allocated, so the main command may take it over. `stdio` is what all
/// three of its descriptors become; without one it gets `/dev/null`, so
/// no test ever hands it the terminal it is run from. `x11` is the X
/// server argv passed as `--x11 <argv...> --`, `x11_socket` the socket
/// the supervisor binds for it, and `wm` the window manager program.
#[derive(Default)]
struct Opts<'a> {
    ctty: bool,
    stdio: Option<&'a OwnedFd>,
    x11: Option<&'a [&'a str]>,
    x11_socket: Option<&'a Path>,
    wm: Option<&'a Path>,
}

/// One spawn at a time; see `spawn_locked`, which is the only thing that
/// takes it.
static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Spawn a supervisor with the process to ourselves. `listener`, when
/// given, is duplicated with CLOEXEC cleared so the supervisor inherits
/// it, and `build` is handed that descriptor's number to name in the
/// argv it returns. Clearing CLOEXEC is a change to the whole process,
/// and `cargo test` runs these tests as threads of one: any other spawn
/// in flight would inherit the descriptor too, and hand it on to every
/// child of its own. So the lock is held from the duplicate to its
/// close, and every spawn in this file goes through here.
fn spawn_locked(
    listener: Option<&UnixListener>,
    build: impl FnOnce(Option<std::os::fd::RawFd>) -> Command,
) -> std::process::Child {
    // A test that panicked while holding it poisoned nothing: the lock
    // guards a window in this process, not any state worth distrusting.
    let _one_at_a_time = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    let inherited = listener.map(|l| {
        let fd = rustix::io::fcntl_dupfd_cloexec(l.as_fd(), 3).unwrap();
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::empty()).unwrap();
        fd
    });
    let mut command = build(inherited.as_ref().map(AsRawFd::as_raw_fd));
    let child = command.spawn().unwrap();
    // Closed before the lock goes, or the window it guards is still open.
    drop(inherited);
    child
}

fn start(cmd: &[&str]) -> Started {
    start_with(cmd, Opts::default())
}

/// Start the supervisor on an inherited listening socket.
fn start_with(cmd: &[&str], opts: Opts<'_>) -> Started {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("init.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let child = spawn_locked(Some(&listener), |fd| {
        let mut init = Command::new(env!("CARGO_BIN_EXE_bubbler-init"));
        init.arg("--socket-fd").arg(
            fd.expect("a listener was handed over, so it has a number")
                .to_string(),
        );
        if opts.ctty {
            init.arg("--ctty");
        }
        if let Some(argv) = opts.x11 {
            init.arg("--x11").args(argv).arg("--");
        }
        if let Some(path) = opts.x11_socket {
            init.arg("--x11-socket").arg(path);
        }
        if let Some(wm) = opts.wm {
            init.arg("--wm").arg(wm);
        }
        match opts.stdio {
            Some(fd) => {
                init.stdin(Stdio::from(fd.try_clone().unwrap()))
                    .stdout(Stdio::from(fd.try_clone().unwrap()))
                    .stderr(Stdio::from(fd.try_clone().unwrap()));
            }
            None => {
                init.stdin(Stdio::null()).stdout(Stdio::null());
            }
        }
        init.arg("--").args(cmd);
        init
    });
    drop(listener);
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

fn exec(sock: &Path, argv: &[&str]) -> i32 {
    let null = std::fs::File::open("/dev/null").unwrap();
    exec_with(sock, argv, null.as_fd(), null.as_fd())
}

/// Exec a command whose stdout is `out`, so the test can read back what
/// it printed; stdin and stderr are `/dev/null`.
fn exec_with_stdout(sock: &Path, argv: &[&str], out: std::os::fd::BorrowedFd<'_>) -> i32 {
    let null = std::fs::File::open("/dev/null").unwrap();
    exec_with(sock, argv, out, null.as_fd())
}

/// Exec a command with `out` for its stdout and `err` for its stderr —
/// which is where the supervisor writes what it did with the request,
/// and so where a refusal is read back from. Stdin is `/dev/null`.
fn exec_with(
    sock: &Path,
    argv: &[&str],
    out: std::os::fd::BorrowedFd<'_>,
    err: std::os::fd::BorrowedFd<'_>,
) -> i32 {
    let s = UnixStream::connect(sock).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let refs: Vec<&std::ffi::OsStr> = argv.iter().map(std::ffi::OsStr::new).collect();
    wire::send_request(&s, &refs, 0, [null.as_fd(), out, err]).unwrap();
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
    let status = wait_within(&mut init, PATIENT);
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
    assert_eq!(wait_within(&mut init, PATIENT).code(), Some(0));
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
fn exec_on_a_pty(sock: &Path, ctty: bool) -> (i32, String) {
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

/// Wait for the supervisor to exit, but never longer than `limit`. A run
/// that outlives what it was supposed to end with is the regression these
/// tests guard, and a test that hangs on it hides it instead of reporting
/// it. `PATIENT` is for the runs that end on their own, where the bound is
/// only there so a hang is a failure.
const PATIENT: Duration = Duration::from_secs(30);

fn wait_within(init: &mut std::process::Child, limit: Duration) -> ExitStatus {
    let t = Instant::now();
    loop {
        if let Some(status) = init.try_wait().unwrap() {
            return status;
        }
        if t.elapsed() >= limit {
            let _ = init.kill();
            let _ = init.wait();
            panic!("the supervisor was still running after {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stop(init: &mut std::process::Child) {
    rustix::process::kill_process(
        rustix::process::Pid::from_child(init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    wait_within(init, PATIENT);
}

#[test]
fn the_main_command_given_a_terminal_leads_its_own_session_and_owns_it() {
    let (master, slave) = pty_pair();
    let (mut init, _sock, _tmp) = start_with(
        &["/usr/bin/sh", "-c", TTY_PROBE],
        Opts {
            ctty: true,
            stdio: Some(&slave),
            ..Opts::default()
        },
    );
    // Only the supervisor's copies are left, so the master reads to EIO
    // as soon as the run is over.
    drop(slave);
    assert_eq!(wait_within(&mut init, PATIENT).code(), Some(0));
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
    let (mut init, sock, _tmp) = start_with(
        &["/usr/bin/sleep", "30"],
        Opts {
            ctty: true,
            ..Opts::default()
        },
    );
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
    stop(&mut init);
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
    // No listener to inherit: 99 is a number nothing has open.
    let init = spawn_locked(None, |_| {
        let mut init = Command::new(env!("CARGO_BIN_EXE_bubbler-init"));
        init.arg("--socket-fd")
            .arg("99")
            .arg("--")
            .arg("/usr/bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        init
    });
    let out = init.wait_with_output().unwrap();
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
    stop(&mut init);
    drop(stalled);
}

/// Interpreter the fake X servers are written in; the tests below skip
/// when it is not installed, as the fixtures elsewhere do.
const PYTHON: &str = "/usr/bin/python3";

/// Returns false (after printing why) when the fake servers cannot run here.
fn require_python() -> bool {
    let ok = Path::new(PYTHON).is_file();
    if !ok {
        println!("skipping: {PYTHON} is not installed");
    }
    ok
}

/// Lists the descriptors a fixture inherited, minus the one the listing
/// itself opened: `os.listdir` holds a descriptor on the directory while
/// it reads it, and that one is closed again — so its `/proc/self/fd`
/// link is already gone — by the time the entries are looked at.
const FD_LIST: &str = r#"def _fds():
    out = []
    for e in os.listdir("/proc/self/fd"):
        try:
            os.readlink("/proc/self/fd/" + e)
        except OSError:
            continue
        out.append(int(e))
    return " ".join(str(n) for n in sorted(out))
"#;

/// Records when a fixture was asked to stop, so a test can put the
/// supervisor's shutdown steps in order. `time.monotonic_ns` reads
/// CLOCK_MONOTONIC, which every process on the host shares.
const STAMPS_ON_TERM: &str = r#"def _bye(*_):
    open(sys.argv[0] + ".stamp", "w").write(str(time.monotonic_ns()))
    sys.exit(0)
signal.signal(signal.SIGTERM, _bye)
"#;

/// What every fake X server does before it differs: find `-listenfd N` in
/// its own argv the way Xwayland does, and record its pid beside the
/// script so a test can tell whether it was started at all.
const SERVER_HEAD: &str = r#"import os, signal, socket, sys, time
argv = sys.argv[1:]
fd = int(argv[argv.index("-listenfd") + 1])
open(sys.argv[0] + ".pid", "w").write(str(os.getpid()))
"#;
/// Accepting on the inherited socket the connection that woke it, which
/// is the whole point: the supervisor never accepted it.
const SERVER_ACCEPT: &str = r#"listener = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
conn, _ = listener.accept()
conn.sendall(b"X")
"#;
/// A server that serves its first client and stays up, as Xwayland does.
const SERVES_AND_STAYS: &str = "time.sleep(30)\n";
/// A server that serves its first client and then loses the display.
const SERVES_AND_DIES: &str = "sys.exit(0)\n";

/// What every fake window manager records: its pid, the descriptors it
/// inherited and the display it was handed.
const WM_RECORDS: &str = r#"seen = _fds()
open(sys.argv[0] + ".pid", "w").write(str(os.getpid()))
open(sys.argv[0] + ".fds", "w").write(seen)
open(sys.argv[0] + ".display", "w").write(os.environ.get("DISPLAY", "none"))
"#;
/// A window manager that stays up, as one managing windows would.
const WM_STAYS: &str = "time.sleep(30)\n";
/// A window manager that is there but does not stay.
const WM_EXITS: &str = "";

/// A command that runs until the test lets it stop, and records when it did.
const COMMAND_WAITS: &str = r#"#!/usr/bin/python3
import os, sys, time
while not os.path.exists(sys.argv[1]):
    time.sleep(0.02)
open(sys.argv[0] + ".stamp", "w").write(str(time.monotonic_ns()))
"#;
/// A command that will not take SIGTERM for an answer. It gives up after
/// a minute all the same, so a supervisor that fails to escalate does not
/// leave it behind for the rest of the day.
const COMMAND_IGNORES_TERM: &str = r#"#!/usr/bin/python3
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
"#;

/// Write one fixture into `dir` and return its path. Only the ones the
/// supervisor names on their own — the window manager and the command —
/// have to be executable; the X server is run through the interpreter,
/// so `--x11` carries more than one word.
fn write_script(dir: &Path, name: &str, body: &str, executable: bool) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    if executable {
        let mode = std::os::unix::fs::PermissionsExt::from_mode(0o755);
        std::fs::set_permissions(&path, mode).unwrap();
    }
    path
}

/// Write one fake X server into `dir` and return its path.
fn server_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let text = format!("{SERVER_HEAD}{STAMPS_ON_TERM}{SERVER_ACCEPT}{body}");
    write_script(dir, name, &text, false)
}

/// Write one fake window manager into `dir` and return its path.
fn wm_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let text = format!(
        "#!{PYTHON}\nimport os, signal, sys, time\n{FD_LIST}{STAMPS_ON_TERM}{WM_RECORDS}{body}"
    );
    write_script(dir, name, &text, true)
}

/// A file standing in for the supervisor's whole stdio, so its messages
/// are readable and none of them reach the terminal the tests run from.
fn stdio_file(path: &Path) -> OwnedFd {
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
fn wait_for_file(path: &Path) -> String {
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

/// Wait for a path to exist, whatever it holds; the display socket is
/// bound before the command runs, so a client may connect at once.
fn wait_for_path(path: &Path) {
    let t = Instant::now();
    while !path.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait for the supervisor's stderr to carry `needle`, and hand back all
/// of it, so a failing assertion can show what was logged instead.
fn wait_for_log(log: &Path, needle: &str) -> String {
    let t = Instant::now();
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "{needle:?} was never logged; stderr was {text:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A file a fixture wrote beside itself.
fn beside(script: &Path, suffix: &str) -> PathBuf {
    let mut path = script.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
}

/// The pid a fixture recorded for itself.
fn pid_of(script: &Path) -> i32 {
    wait_for_file(&beside(script, ".pid"))
        .trim()
        .parse()
        .unwrap()
}

/// When a fixture was asked to stop, on the clock they all share.
fn stamp_of(script: &Path) -> u128 {
    wait_for_file(&beside(script, ".stamp"))
        .trim()
        .parse()
        .unwrap()
}

/// Fail unless the process has left the process table. It is the
/// supervisor's own child, so it is reaped there and the entry goes with it.
fn assert_gone(pid: i32) {
    let path = PathBuf::from(format!("/proc/{pid}"));
    let t = Instant::now();
    while path.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "the process ({pid}) was left running"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Connect to the socket the supervisor bound for the display. This
/// succeeds while no server exists: the supervisor is listening, so the
/// connection waits in the queue for the server it just woke.
fn x_connect(path: &Path) -> UnixStream {
    let client = UnixStream::connect(path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
}

/// The byte the fake server sends once it has accepted, so a test can
/// tell that the connection was served by the server and not by init.
fn served_byte(client: &UnixStream) -> u8 {
    let mut byte = [0u8; 1];
    std::io::Read::read_exact(&mut &*client, &mut byte).unwrap();
    byte[0]
}

#[test]
fn the_x_server_is_not_started_until_a_client_connects() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_STAYS);
    let xsock = dir.path().join("X0");
    let seen = dir.path().join("cmd.env");
    let run = format!("env > {}; exec sleep 30", seen.display());
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, sock, _tmp) = start_with(
        &["/usr/bin/sh", "-c", &run],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    // The display is in the environment from the command's first line,
    // long before anything has connected to it.
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
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        !beside(&script, ".pid").exists(),
        "the server was started with no client to serve"
    );
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    let pid = pid_of(&script);
    stop(&mut init);
    assert_gone(pid);
}

#[test]
fn the_window_manager_starts_with_the_server_and_the_shutdown_runs_inwards() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_STAYS);
    let wm = wm_script(dir.path(), "fake-wm", WM_STAYS);
    let cmd = write_script(dir.path(), "command", COMMAND_WAITS, true);
    let xsock = dir.path().join("X0");
    let quit = dir.path().join("quit");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &[cmd.to_str().unwrap(), quit.to_str().unwrap()],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            wm: Some(&wm),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let display = beside(&wm, ".display");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !display.exists(),
        "the window manager ran with no server to manage"
    );
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    assert_eq!(
        wait_for_file(&display),
        ":0",
        "the window manager saw the wrong display"
    );
    let server_pid = pid_of(&script);
    let wm_pid = pid_of(&wm);
    std::fs::write(&quit, b"").unwrap();
    let status = wait_within(&mut init, Duration::from_secs(10));
    assert_eq!(status.code(), Some(0));
    assert_gone(wm_pid);
    assert_gone(server_pid);
    // Command, then window manager, then server: nothing is left drawing
    // on a display that has already gone.
    let (command, wm, server) = (stamp_of(&cmd), stamp_of(&wm), stamp_of(&script));
    assert!(
        command < wm,
        "the window manager was stopped first ({command} vs {wm})"
    );
    assert!(
        wm < server,
        "the server was stopped before its window manager ({wm} vs {server})"
    );
}

#[test]
fn no_child_but_the_server_inherits_the_display_socket() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_STAYS);
    let wm = wm_script(dir.path(), "fake-wm", WM_STAYS);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, sock, _tmp) = start_with(
        &["/usr/bin/sleep", "30"],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            wm: Some(&wm),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    // The socket is handed to the server on a duplicate, so the window
    // manager spawned right after it has nothing above its own stdio.
    assert_eq!(
        wait_for_file(&beside(&wm, ".fds")),
        "0 1 2",
        "the window manager inherited more than its stdio"
    );
    let out = dir.path().join("exec.fds");
    let file = std::fs::File::create(&out).unwrap();
    let program = format!("import os\n{FD_LIST}print(_fds())\n");
    let st = exec_with_stdout(&sock, &[PYTHON, "-c", &program], file.as_fd());
    assert_eq!(ExitStatus::from_raw(st).code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap().trim(),
        "0 1 2",
        "an exec'd child inherited more than the stdio it was sent"
    );
    stop(&mut init);
}

#[test]
fn a_window_manager_that_cannot_be_started_is_logged_and_the_command_runs_on() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_STAYS);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, sock, _tmp) = start_with(
        &["/usr/bin/sleep", "30"],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            wm: Some(Path::new("nosuchwm")),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    wait_for_log(&log, "bubbler-init: wm nosuchwm: ");
    // A window manager is a convenience; the display it would have
    // managed is up and the command is still using it.
    assert_eq!(
        ExitStatus::from_raw(exec(&sock, &["/usr/bin/true"])).code(),
        Some(0)
    );
    assert!(init.try_wait().unwrap().is_none(), "the run was abandoned");
    stop(&mut init);
}

#[test]
fn a_window_manager_that_exits_is_reported_once_and_the_command_runs_on() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_STAYS);
    let wm = wm_script(dir.path(), "fake-wm", WM_EXITS);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, sock, _tmp) = start_with(
        &["/usr/bin/sleep", "30"],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            wm: Some(&wm),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    let line = format!("bubbler-init: wm {} exited", wm.display());
    wait_for_log(&log, &line);
    // Reported once and not restarted: the loop would otherwise say it
    // again on every tick.
    std::thread::sleep(Duration::from_millis(300));
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(text.matches(&line).count(), 1, "stderr was {text:?}");
    assert_eq!(
        ExitStatus::from_raw(exec(&sock, &["/usr/bin/true"])).code(),
        Some(0)
    );
    assert!(init.try_wait().unwrap().is_none(), "the run was abandoned");
    stop(&mut init);
}

#[test]
fn a_server_that_exits_after_serving_terminates_the_command() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_DIES);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &["/usr/bin/sleep", "30"],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    let status = wait_within(&mut init, Duration::from_secs(10));
    assert_eq!(status.code(), Some(143));
    let err = std::fs::read_to_string(&log).unwrap();
    assert!(
        err.contains("Xwayland exited; stopping the command"),
        "stderr was {err:?}"
    );
}

#[test]
fn a_command_that_ignores_the_signal_is_killed_when_the_display_goes() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_DIES);
    let cmd = write_script(dir.path(), "deaf", COMMAND_IGNORES_TERM, true);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &[cmd.to_str().unwrap()],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    let t = Instant::now();
    let status = wait_within(&mut init, Duration::from_secs(12));
    // The grace is the whole point: SIGTERM was ignored, so the run ends
    // on the SIGKILL that follows it instead of never ending at all.
    assert!(
        t.elapsed() > Duration::from_secs(4),
        "the escalation took {:?}",
        t.elapsed()
    );
    assert_eq!(status.code(), Some(137), "not the exit of a killed command");
    let err = std::fs::read_to_string(&log).unwrap();
    assert!(
        err.contains("Xwayland exited; stopping the command"),
        "stderr was {err:?}"
    );
}

#[test]
fn a_second_stop_does_not_buy_the_command_another_grace() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_DIES);
    let cmd = write_script(dir.path(), "deaf", COMMAND_IGNORES_TERM, true);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &[cmd.to_str().unwrap()],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    wait_for_log(&log, "Xwayland exited; stopping the command");
    let deadline_set = Instant::now();
    // A second stop event partway through the grace. The command ignores
    // both signals, so what is being measured is the deadline: it belongs
    // to the first event, or every later signal postpones the SIGKILL.
    std::thread::sleep(Duration::from_secs(2));
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    assert_eq!(
        wait_within(&mut init, Duration::from_secs(12)).code(),
        Some(137)
    );
    assert!(
        deadline_set.elapsed() < Duration::from_millis(6500),
        "the second signal bought another grace: {:?}",
        deadline_set.elapsed()
    );
}

#[test]
fn a_client_that_connects_while_stopping_wakes_nothing() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_STAYS);
    let cmd = write_script(dir.path(), "deaf", COMMAND_IGNORES_TERM, true);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &[cmd.to_str().unwrap()],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&init),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    // The command ignores SIGTERM, so this connection arrives with the
    // whole grace still to run. Starting a server and a window manager
    // for those few seconds is work whose only end is killing them again.
    let _client = x_connect(&xsock);
    assert_eq!(
        wait_within(&mut init, Duration::from_secs(12)).code(),
        Some(137)
    );
    assert!(
        !beside(&script, ".pid").exists(),
        "a display was started for a run that was already ending"
    );
}

#[test]
fn an_exec_is_refused_once_the_run_is_stopping() {
    if !require_python() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = server_script(dir.path(), "xserver.py", SERVES_AND_DIES);
    let cmd = write_script(dir.path(), "deaf", COMMAND_IGNORES_TERM, true);
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, sock, _tmp) = start_with(
        &[cmd.to_str().unwrap()],
        Opts {
            stdio: Some(&fd),
            x11: Some(&[PYTHON, script.to_str().unwrap()]),
            x11_socket: Some(&xsock),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    assert_eq!(served_byte(&client), b'X');
    // The command ignores SIGTERM, so the whole grace is still ahead: a
    // request arriving in it must not start a child that the deadline
    // would then SIGKILL without ever having asked it to stop.
    wait_for_log(&log, "Xwayland exited; stopping the command");
    let null = std::fs::File::open("/dev/null").unwrap();
    let seen = dir.path().join("exec.err");
    let file = std::fs::File::create(&seen).unwrap();
    let st = exec_with(&sock, &["/usr/bin/true"], null.as_fd(), file.as_fd());
    assert_eq!(
        ExitStatus::from_raw(st).code(),
        Some(127),
        "the request was served while the run was ending"
    );
    let told = std::fs::read_to_string(&seen).unwrap();
    assert!(told.contains("stopping"), "the client was told {told:?}");
    // And the run still ends exactly as it did without the request.
    assert_eq!(
        wait_within(&mut init, Duration::from_secs(12)).code(),
        Some(137)
    );
}

#[test]
fn a_server_that_cannot_be_spawned_terminates_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let xsock = dir.path().join("X0");
    let log = dir.path().join("init.log");
    let fd = stdio_file(&log);
    let (mut init, _sock, _tmp) = start_with(
        &["/usr/bin/sleep", "30"],
        Opts {
            stdio: Some(&fd),
            x11: Some(&["/nonexistent/bubbler-test-xserver"]),
            x11_socket: Some(&xsock),
            ..Opts::default()
        },
    );
    wait_for_path(&xsock);
    let client = x_connect(&xsock);
    let status = wait_within(&mut init, Duration::from_secs(10));
    assert_eq!(status.code(), Some(143));
    let err = std::fs::read_to_string(&log).unwrap();
    assert!(err.contains("Xwayland did not start"), "stderr was {err:?}");
    // The client that waited for a server that never came is let go when
    // the supervisor closes the socket, either way a closed socket reads.
    let mut byte = [0u8; 1];
    match std::io::Read::read(&mut &client, &mut byte) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("the waiting client was left connected: {other:?}"),
    }
}
