//! In-sandbox supervisor: runs the command, serves exec requests on the
//! inherited socket, forwards SIGTERM, SIGINT, SIGHUP and SIGQUIT, exits
//! with the command's status.
//! With `--x11` it also owns the display socket: the command runs at once with
//! `DISPLAY` set, and the nested X server (plus the `--wm` window manager) is
//! started on the first client that connects and stopped last.

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Timespec, poll};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::process::{
    DumpableBehavior, Pid, Signal, kill_process, set_dumpable_behavior,
    set_parent_process_death_signal,
};
use rustix::thread::{
    CapabilitySet, CapabilitySets, capabilities, capability_is_in_bounding_set,
    clear_ambient_capability_set, remove_capability_from_bounding_set, set_capabilities,
    set_no_new_privs,
};

use bubbler_init::{fds, proto, wire};

mod pw_hold;
mod spawn;

// The `poll` timeout, so `accept`, `wait` and every request read are
// non-blocking and one iteration is bounded by it.
const TICK: Duration = Duration::from_millis(20);
const TICK_TIMESPEC: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: TICK.subsec_nanos() as Nsecs,
};
const GRACE: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
// Raw wait status for a command that could not be executed, as a shell reports it.
const NOT_EXECUTABLE: i32 = 127 << 8;
// Connections whose request has not arrived in full. The oldest is
// dropped to make room, so stalled clients cannot grow the table.
const MAX_PENDING: usize = 16;
// The server is always started as `:0`.
const X11_SOCKET: &str = "/tmp/.X11-unix/X0";
const DISPLAY: &str = ":0";
// Clients the display socket queues before the server has taken it
// over. Only the first one has to wait for a server to start at all.
const X11_BACKLOG: i32 = 16;
// The one usage line, so a grammar error always names the whole grammar.
const USAGE: &str = "bubbler-init: usage: --socket-fd N [--ctty] \
[--x11 argv... --] [--x11-socket path] [--wm program] -- cmd...";

struct Args {
    socket_fd: i32,
    ctty: bool,
    x11: Option<Vec<OsString>>,
    x11_socket: PathBuf,
    wm: Option<OsString>,
    command: Vec<OsString>,
}

struct X11 {
    argv: Vec<OsString>,
    wm: Option<OsString>,
    listener: UnixListener,
    // Set on the first connection and never cleared: the server owns the
    // socket from then on, so init neither polls nor accepts it again,
    // and a server that failed to start is not started a second time.
    started: bool,
    server: Option<Child>,
    wm_child: Option<Child>,
}

struct Exec {
    child: Child,
    stream: UnixStream,
}

#[derive(Default)]
struct Stopping {
    // Set by the first stop event and never cleared. From then on no new
    // exec'd child is started: one spawned now could only be killed
    // moments later, without the SIGTERM every other child was given.
    asked: bool,
    // Set by the first stop event and never moved: whatever is still
    // running at the end is held to it too.
    kill_at: Option<Instant>,
    killed: bool,
}

struct Pending {
    stream: UnixStream,
    incoming: wire::Incoming,
    deadline: Instant,
}

fn parse_args() -> Option<Args> {
    parse_from(std::env::args_os().skip(1))
}

// `--x11-socket` overrides the path init binds for the display; it exists
// for this crate's own tests, and bubbler never passes it.
fn parse_from(mut it: impl Iterator<Item = OsString>) -> Option<Args> {
    let mut socket_fd = None;
    let mut ctty = false;
    let mut x11 = None;
    let mut x11_socket = None;
    let mut wm = None;
    let mut command = Vec::new();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--socket-fd") => socket_fd = it.next()?.to_str()?.parse().ok(),
            Some("--ctty") => ctty = true,
            // A second one would silently replace the first, and a server
            // that is dropped here is a display nothing ever starts.
            Some("--x11") if x11.is_none() => {
                let argv: Vec<OsString> = it.by_ref().take_while(|w| w != "--").collect();
                if argv.is_empty() {
                    return None;
                }
                x11 = Some(argv);
            }
            Some("--x11-socket") if x11_socket.is_none() => {
                x11_socket = Some(PathBuf::from(it.next()?));
            }
            Some("--wm") if wm.is_none() => wm = Some(it.next()?),
            Some("--") => {
                command.extend(it);
                break;
            }
            _ => return None,
        }
    }
    // Both only mean something with a display to serve: without one they
    // are a caller that believes it asked for a nested server and did not.
    if x11.is_none() && (x11_socket.is_some() || wm.is_some()) {
        return None;
    }
    if command.is_empty() {
        return None;
    }
    Some(Args {
        socket_fd: socket_fd?,
        ctty,
        x11,
        x11_socket: x11_socket.unwrap_or_else(|| PathBuf::from(X11_SOCKET)),
        wm,
        command,
    })
}

fn listener_from_fd(fd: i32) -> Option<UnixListener> {
    if fd < 3 {
        return None;
    }
    // SAFETY: the precondition is that `fd` names a descriptor this process
    // owns and that nothing else will close. `fcntl_getfd` is the probe that
    // rules out a number that is not open at all (EBADF) before any owning
    // handle exists, so no closed number is ever adopted or closed twice;
    // this listener is the only descriptor above stdio left by the time
    // `main` gets here, since the sweep there closed every other one, so
    // there is no second owner. A number that is open but not a listening
    // socket is rejected below and closed again on drop.
    let owned = unsafe {
        fcntl_getfd(BorrowedFd::borrow_raw(fd)).ok()?;
        OwnedFd::from_raw_fd(fd)
    };
    // CLOEXEC keeps the control channel out of the command and every exec'd child.
    fcntl_setfd(&owned, FdFlags::CLOEXEC).ok()?;
    if !rustix::net::sockopt::socket_acceptconn(&owned).ok()? {
        return None;
    }
    let listener = UnixListener::from(owned);
    listener.set_nonblocking(true).ok()?;
    Some(listener)
}

// Only ever called for a terminal bubbler allocated: claiming whatever sits
// on fd 0 would take over the user's own terminal in passthrough mode.
fn take_ctty(command: &mut Command) {
    // SAFETY: the closure runs in the forked child between fork and execve,
    // where only async-signal-safe work is allowed: `setsid` and
    // `ioctl(TIOCSCTTY)` are single syscalls that allocate nothing and take
    // no lock. `borrow_raw` only names fd 0 and never closes it, and by the
    // time the closure runs that number is the command's own stdin, since
    // the stdio is installed before these callbacks. Both failures are
    // deliberately ignored: a child that already leads a session keeps it,
    // and a command that cannot claim the terminal still has to run.
    unsafe {
        let stdin = BorrowedFd::borrow_raw(0);
        command.pre_exec(move || {
            let _ = rustix::process::setsid();
            let _ = rustix::process::ioctl_tiocsctty(stdin);
            Ok(())
        });
    }
}

// `PR_SET_NO_NEW_PRIVS` first, so nothing the supervisor `execve`s can
// gain a privilege whatever it finds on the filesystem.
fn harden() -> rustix::io::Result<()> {
    set_no_new_privs(true)?;
    clear_ambient_capability_set()?;
    let empty = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    if capabilities(None)? != empty {
        set_capabilities(None, empty)?;
    }
    // `.iter_names()`, not `.iter()`: rustix marks `CapabilitySet` with
    // bitflags' external-bits escape hatch (`const _ = !0;`) so a future
    // kernel's capability past bit 40 still round-trips through this
    // type, and `.iter()` yields that one unnamed remainder as a single
    // multi-bit flag. `capability_is_in_bounding_set` and
    // `remove_capability_from_bounding_set` both reject anything but a
    // single bit with `EINVAL`; `.iter_names()` yields only the 41
    // capabilities this build of rustix (1.1.4) knows the names of.
    for (_, capability) in CapabilitySet::all().iter_names() {
        if capability_is_in_bounding_set(capability)? {
            // A caller without CAP_SETPCAP gets EPERM here. That leaves the
            // bounding set as this process found it, which
            // `PR_SET_NO_NEW_PRIVS` above already made inert: no `execve`
            // from here can turn a bounding-set entry into a held capability.
            match remove_capability_from_bounding_set(capability) {
                Ok(()) | Err(Errno::PERM) => {}
                Err(e) => return Err(e),
            }
        }
    }
    // A bwrap that is killed leaves this process a `SIGTERM`, which is the
    // one the run already knows how to end on.
    set_parent_process_death_signal(Some(Signal::TERM))?;
    Ok(())
}

// A regular file is written as is, so one on a hung mount can still stall
// the loop.
fn refuse(stream: &UnixStream, report: Option<OwnedFd>, why: &str) {
    if let Some(fd) = report {
        write_unless_blocked(&fd, format!("bubbler-init: {why}\n").as_bytes());
    }
    let _ = wire::send_status(stream, NOT_EXECUTABLE);
}

// Write `line` to `fd` without blocking and without changing the flags
// of the open file description the client shares with it.
fn write_unless_blocked(fd: &OwnedFd, line: &[u8]) {
    let Ok(stat) = rustix::fs::fstat(fd) else {
        return;
    };
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Socket => {
            let flags = rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL;
            let _ = rustix::net::send(fd, line, flags);
        }
        // A reopen would write from offset 0 over the start of the file,
        // and O_NONBLOCK does nothing for a regular file anyway.
        FileType::RegularFile => {
            let _ = rustix::io::write(fd, line);
        }
        _ => {
            // A reopen through /proc can grant write access the client's
            // descriptor never had, so only one it can write through is reopened.
            let Ok(given) = rustix::fs::fcntl_getfl(fd) else {
                return;
            };
            let access = given & OFlags::RWMODE;
            if given.contains(OFlags::PATH) || (access != OFlags::WRONLY && access != OFlags::RDWR)
            {
                return;
            }
            let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let flags = OFlags::WRONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
            if let Ok(own) = rustix::fs::open(path, flags, Mode::empty()) {
                let _ = rustix::io::write(&own, line);
            }
        }
    }
}

// Whether the command takes fd 0 as its controlling terminal is the
// request's own flag, not the instance's `--ctty`: the client knows which
// of the fds it just sent is a pty it allocated.
fn serve(
    stream: UnixStream,
    request: &proto::Request,
    fds: Vec<OwnedFd>,
    execs: &mut Vec<Exec>,
    display: Option<&OsStr>,
    stopping: bool,
) {
    let Some((program, rest)) = request.argv.split_first() else {
        return;
    };
    let mut fds = fds.into_iter();
    let (Some(stdin), Some(stdout), Some(stderr)) = (fds.next(), fds.next(), fds.next()) else {
        return;
    };
    let report = stderr.try_clone().ok();
    if stopping {
        let why = format!("stopping; {} was not run", program.to_string_lossy());
        refuse(&stream, report, &why);
        return;
    }
    let terminal = request.ctty() && rustix::termios::isatty(&stdin);
    // argv[0] is resolved through PATH as seen inside the sandbox.
    let mut command = Command::new(program);
    command
        .args(rest)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // The display is init's to hand out: an exec'd child gets the same
    // one the instance's own command was started with.
    if let Some(d) = display {
        command.env("DISPLAY", d);
    }
    if terminal {
        take_ctty(&mut command);
    }
    match command.spawn() {
        Ok(child) => execs.push(Exec { child, stream }),
        Err(e) => refuse(
            &stream,
            report,
            &format!("{}: {e}", program.to_string_lossy()),
        ),
    }
}

// `ready` is parallel to `pending` and shrinks with it.
fn read_pending(
    pending: &mut Vec<Pending>,
    ready: &mut Vec<bool>,
    execs: &mut Vec<Exec>,
    display: Option<&OsStr>,
    stopping: bool,
) {
    let mut i = 0;
    while i < pending.len() {
        if !ready.get(i).copied().unwrap_or(false) {
            i += 1;
            continue;
        }
        let p = &mut pending[i];
        match p.incoming.read_step(&p.stream) {
            Ok(None) => i += 1,
            Ok(Some((request, fds))) => {
                let p = pending.remove(i);
                ready.remove(i);
                serve(p.stream, &request, fds, execs, display, stopping);
            }
            // A malformed request or a hangup closes the connection.
            Err(_) => {
                pending.remove(i);
                ready.remove(i);
            }
        }
    }
}

fn reap(execs: &mut Vec<Exec>) {
    execs.retain_mut(|e| match e.child.try_wait() {
        Ok(None) => true,
        Ok(Some(status)) => {
            let _ = wire::send_status(&e.stream, status.into_raw());
            false
        }
        Err(_) => false,
    });
}

// A process init can no longer account for is treated as gone: assuming
// it is still up is what would leave the command drawing on a display that
// is not there.
fn has_exited(child: &mut Child, what: &str) -> bool {
    match child.try_wait() {
        Ok(None) => false,
        Ok(Some(_)) => true,
        Err(e) => {
            eprintln!("bubbler-init: cannot wait for {what}: {e}");
            true
        }
    }
}

// Exec'd children are unreaped here, so their pids are still theirs.
fn signal_execs(execs: &[Exec], sig: Signal) {
    for e in execs {
        let _ = kill_process(Pid::from_child(&e.child), sig);
    }
}

// Set the deadline at which whatever ignored SIGTERM is SIGKILLed. The
// deadline is the point: a command that traps SIGTERM would otherwise
// keep the sandbox alive for as long as it liked.
fn begin_stop(command: &Child, execs: &[Exec], stopping: &mut Stopping) {
    // Nothing here is reaped until the loop exits, so every pid is still its own.
    let _ = kill_process(Pid::from_child(command), Signal::TERM);
    signal_execs(execs, Signal::TERM);
    stopping.asked = true;
    // The first deadline is the deadline. A second stop event asking for
    // its own grace is how a command that ignores SIGTERM would earn one
    // more of them for every signal it is sent.
    stopping.kill_at = stopping.kill_at.or(Some(Instant::now() + GRACE));
}

fn shutdown(execs: &mut Vec<Exec>, kill_at: Option<Instant>) {
    if execs.is_empty() {
        return;
    }
    signal_execs(execs, Signal::TERM);
    let deadline = kill_at.unwrap_or_else(|| Instant::now() + GRACE);
    while !execs.is_empty() && Instant::now() < deadline {
        std::thread::sleep(TICK);
        reap(execs);
    }
    signal_execs(execs, Signal::KILL);
    for e in execs.iter_mut() {
        if let Ok(status) = e.child.wait() {
            let _ = wire::send_status(&e.stream, status.into_raw());
        }
    }
    execs.clear();
}

// The socket is listening before the command runs, so the first client
// waits in its queue instead of failing to connect while the server is
// still starting.
fn bind_x11(path: &Path) -> Result<UnixListener, String> {
    if let Some(dir) = path.parent() {
        match rustix::fs::mkdir(dir, Mode::from_raw_mode(0o1777)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(format!("cannot create {}: {e}", dir.display())),
        }
        // umask clears bits from the mode `mkdir` was given, and the
        // socket directory is world-writable with the sticky bit on a
        // host. Only for the real one: a path a test chose is its own.
        if path == Path::new(X11_SOCKET) {
            rustix::fs::chmod(dir, Mode::from_raw_mode(0o1777))
                .map_err(|e| format!("cannot set the mode of {}: {e}", dir.display()))?;
        }
    }
    let addr = SocketAddrUnix::new(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let sock = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| format!("cannot create the socket: {e}"))?;
    rustix::net::bind(&sock, &addr).map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
    rustix::net::listen(&sock, X11_BACKLOG)
        .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
    Ok(UnixListener::from(sock))
}

// The connection that woke init is deliberately left in the queue: the
// server accepts it on the very descriptor it inherits.
fn start_x11(x: &mut X11) -> Result<(), String> {
    let (program, rest) = x.argv.split_first().ok_or("no server to run")?;
    // A duplicate carries the socket across this one exec, so the
    // listener init keeps stays CLOEXEC and no later child inherits it.
    let handed = fcntl_dupfd_cloexec(&x.listener, 3)
        .map_err(|e| format!("cannot duplicate the socket: {e}"))?;
    fcntl_setfd(&handed, FdFlags::empty()).map_err(|e| format!("cannot pass the socket: {e}"))?;
    let child = Command::new(program)
        .args(rest)
        .arg("-listenfd")
        .arg(handed.as_raw_fd().to_string())
        .spawn()
        .map_err(|e| format!("{}: {e}", program.to_string_lossy()))?;
    x.server = Some(child);
    Ok(())
}

// The window manager is a convenience and not a display: one that is
// missing or that exits is reported, and the command keeps running.
fn start_wm(x: &mut X11) {
    let Some(wm) = x.wm.as_ref() else { return };
    match Command::new(wm).env("DISPLAY", DISPLAY).spawn() {
        Ok(child) => x.wm_child = Some(child),
        Err(e) => eprintln!("bubbler-init: wm {}: {e}", wm.to_string_lossy()),
    }
}

fn stop_child(child: &mut Child, kill_at: Option<Instant>) {
    let _ = kill_process(Pid::from_child(child), Signal::TERM);
    let deadline = kill_at.unwrap_or_else(|| Instant::now() + GRACE);
    while Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(TICK);
    }
    let _ = child.kill();
    let _ = child.wait();
}

// Stop the window manager and then the server. Only ever called once
// the command and every exec'd child are gone: nothing may lose its
// display while it is still drawing on it, and the window manager is
// never left managing a server that has already exited.
fn stop_x11(x11: Option<&mut X11>, kill_at: Option<Instant>) {
    let Some(x) = x11 else { return };
    if let Some(wm) = x.wm_child.as_mut() {
        stop_child(wm, kill_at);
    }
    if let Some(server) = x.server.as_mut() {
        stop_child(server, kill_at);
    }
}

fn code_of(status: ExitStatus) -> u8 {
    let code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1);
    u8::try_from(code).unwrap_or(1)
}

// One file is bound at every mode's own path, so the basename of
// `argv[0]` is the whole of what separates the modes.
fn started_as(name: &str) -> bool {
    std::env::args_os()
        .next()
        .is_some_and(|a| Path::new(&a).file_name() == Some(OsStr::new(name)))
}

fn main() -> ExitCode {
    // Before anything the supervisor does to its own process: the shim
    // keeps the descriptors its caller forwarded, which the sweep below
    // exists to close, and it holds no privilege the command should not
    // have.
    if started_as(spawn::NAME) {
        return spawn::run(std::env::args_os().skip(1));
    }
    // Also before the sweep, and for the same reason: the holder reports
    // on a descriptor bubbler passed it, and it is not the sandbox's
    // supervisor but a process of the audio sidecar.
    if started_as(pw_hold::NAME) {
        return pw_hold::run();
    }
    let Some(mut args) = parse_args() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // Before the socket is adopted, the display is bound or anything at
    // all is started. `--socket-fd` is the one descriptor this argv names,
    // so everything else above stdio is something bwrap passed through.
    //
    // SAFETY: nothing above stdio has an owner in this process yet. Only
    // the argv has been read, `parse_from` opens nothing, and every
    // descriptor this program goes on to hold — the control socket, the
    // display socket, a child's stdio — is created after this line. No
    // other thread exists to race it either: init spawns none, and the
    // first child of its own comes later.
    if let Err(e) = unsafe { fds::close_strays(&[args.socket_fd]) } {
        eprintln!("bubbler-init: cannot close the descriptors it was not given: {e}");
        return ExitCode::from(2);
    }
    let Some(listener) = listener_from_fd(args.socket_fd) else {
        eprintln!(
            "bubbler-init: {}: not an open listening socket fd",
            args.socket_fd
        );
        return ExitCode::from(2);
    };
    // A non-dumpable process can only be ptraced, or have fds taken with
    // pidfd_getfd, by a tracer holding CAP_SYS_PTRACE, even where
    // kernel.yama.ptrace_scope is 0; execve resets it, so the command and
    // every exec'd child are unaffected.
    if let Err(e) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        eprintln!("bubbler-init: cannot become non-dumpable: {e}");
        return ExitCode::from(2);
    }
    if let Err(e) = harden() {
        eprintln!("bubbler-init: cannot give up privilege: {e}");
        return ExitCode::from(2);
    }
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGQUIT,
    ] {
        if signal_hook::flag::register(sig, Arc::clone(&stop)).is_err() {
            eprintln!("bubbler-init: cannot install signal handlers");
            return ExitCode::from(2);
        }
    }
    let Some((program, rest)) = args.command.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // Before the command, so the display it is about to be pointed at is
    // one it can connect to from its first line, server or no server.
    let mut x11 = match args.x11.take() {
        Some(argv) => match bind_x11(&args.x11_socket) {
            Ok(listener) => Some(X11 {
                argv,
                wm: args.wm.take(),
                listener,
                started: false,
                server: None,
                wm_child: None,
            }),
            Err(reason) => {
                eprintln!("bubbler-init: cannot bind the display socket: {reason}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let display = x11.as_ref().map(|_| OsStr::new(DISPLAY));
    let mut launch = Command::new(program);
    launch.args(rest);
    if let Some(d) = display {
        launch.env("DISPLAY", d);
    }
    // `--ctty` is bubbler saying the terminal on fd 0 is a pty slave it
    // allocated for this sandbox, and not the user's own terminal.
    if args.ctty && rustix::termios::isatty(std::io::stdin()) {
        take_ctty(&mut launch);
    }
    let mut command = match launch.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("bubbler-init: {}: {e}", program.to_string_lossy());
            stop_x11(x11.as_mut(), None);
            return ExitCode::from(127);
        }
    };

    let mut execs: Vec<Exec> = Vec::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut stopping = Stopping::default();
    loop {
        if let Ok(Some(status)) = command.try_wait() {
            reap(&mut execs);
            shutdown(&mut execs, stopping.kill_at);
            stop_x11(x11.as_mut(), stopping.kill_at);
            return ExitCode::from(code_of(status));
        }
        if let Some(x) = x11.as_mut() {
            // Checked after the command's own exit, so the two going down
            // together is not reported as the server stopping the command.
            if x.server.as_mut().is_some_and(|s| has_exited(s, "Xwayland")) {
                eprintln!("bubbler-init: Xwayland exited; stopping the command");
                begin_stop(&command, &execs, &mut stopping);
                x.server = None;
            }
            // Said once: the child is dropped here and never started
            // again, so the next tick has nothing left to report.
            if x.wm_child
                .as_mut()
                .is_some_and(|w| has_exited(w, "the window manager"))
            {
                if let Some(name) = x.wm.as_ref() {
                    eprintln!("bubbler-init: wm {} exited", name.to_string_lossy());
                }
                x.wm_child = None;
            }
        }
        reap(&mut execs);
        if !stopping.killed && stopping.kill_at.is_some_and(|at| Instant::now() >= at) {
            let _ = kill_process(Pid::from_child(&command), Signal::KILL);
            signal_execs(&execs, Signal::KILL);
            stopping.killed = true;
        }
        // The display socket leaves the poll set once the run is ending, so
        // a client connecting during the grace wakes nothing — and so that
        // the loop does not spin on a connection it has decided not to answer.
        let waking = x11
            .as_ref()
            .filter(|x| !x.started && !stopping.asked)
            .map(|x| &x.listener);
        let mut fds = Vec::with_capacity(2 + pending.len());
        fds.push(PollFd::new(&listener, PollFlags::IN));
        if let Some(l) = waking {
            fds.push(PollFd::new(l, PollFlags::IN));
        }
        fds.extend(
            pending
                .iter()
                .map(|p| PollFd::new(&p.stream, PollFlags::IN)),
        );
        let polled = poll(&mut fds, Some(&TICK_TIMESPEC));
        let accept = fds[0].revents().contains(PollFlags::IN);
        // The display socket takes the slot after the control listener
        // while it is still init's to watch; the pending ones follow both.
        let x_slot = usize::from(waking.is_some());
        let wake_x11 = x_slot == 1 && fds[1].revents().contains(PollFlags::IN);
        let mut ready: Vec<bool> = fds[1 + x_slot..]
            .iter()
            .map(|f| !f.revents().is_empty())
            .collect();
        drop(fds);
        // Taken here and nowhere else, so a stop that arrived while this
        // set was being built or polled is acted on before anything that
        // poll reported. A signal pending before `poll` returns has run its
        // handler by the time this reads the flag, so the two cannot
        // cross: init spawns no threads, so that handler is this thread's
        // own, run on its way out of the syscall.
        if stop.swap(false, Ordering::SeqCst) {
            begin_stop(&command, &execs, &mut stopping);
        }
        match polled {
            Ok(0) => {}
            // Every poll error is retried on purpose: EINTR means a signal
            // was delivered, whose flag the line above has just read, and no
            // other error is a reason to abandon a command that is still
            // running.
            Err(_) => {
                std::thread::sleep(TICK);
                continue;
            }
            Ok(_) => {}
        }
        // The socket leaves the poll set when the run is asked to stop, but
        // a wake already in hand can be older than the asking.
        if wake_x11
            && !stopping.asked
            && let Some(x) = x11.as_mut()
        {
            x.started = true;
            match start_x11(x) {
                Ok(()) => start_wm(x),
                Err(reason) => {
                    eprintln!("bubbler-init: Xwayland did not start: {reason}");
                    begin_stop(&command, &execs, &mut stopping);
                }
            }
        }
        read_pending(
            &mut pending,
            &mut ready,
            &mut execs,
            display,
            stopping.asked,
        );
        // Dropping the connection is the whole answer to a client that
        // ran out of time: nothing was spawned for it.
        let now = Instant::now();
        pending.retain(|p| p.deadline > now);
        if accept {
            while let Ok((stream, _)) = listener.accept() {
                if stream.set_nonblocking(true).is_err() {
                    continue;
                }
                if pending.len() >= MAX_PENDING {
                    pending.remove(0);
                }
                pending.push(Pending {
                    stream,
                    incoming: wire::Incoming::new(),
                    deadline: Instant::now() + REQUEST_TIMEOUT,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(words: &[&str]) -> Option<Args> {
        parse_from(words.iter().map(OsString::from))
    }

    #[test]
    fn the_server_argv_ends_at_its_own_terminator() {
        let a = parse(&[
            "--socket-fd",
            "3",
            "--ctty",
            "--x11",
            "Xwayland",
            ":0",
            "--",
            "--",
            "/usr/bin/true",
            "--x11",
        ])
        .unwrap();
        assert_eq!(a.socket_fd, 3);
        assert!(a.ctty);
        assert_eq!(a.x11.unwrap(), ["Xwayland", ":0"]);
        assert_eq!(a.command, ["/usr/bin/true", "--x11"]);
    }

    #[test]
    fn a_server_without_an_argv_is_a_usage_error() {
        assert!(parse(&["--socket-fd", "3", "--x11", "--", "--", "/usr/bin/true"]).is_none());
    }

    #[test]
    fn a_server_argv_that_is_never_terminated_is_a_usage_error() {
        // The server swallows the words the command would have been.
        assert!(parse(&["--socket-fd", "3", "--x11", "Xwayland", "/usr/bin/true"]).is_none());
        // One `--` short: what follows it is neither a flag nor a command.
        assert!(
            parse(&[
                "--socket-fd",
                "3",
                "--x11",
                "Xwayland",
                "--",
                "/usr/bin/true"
            ])
            .is_none()
        );
    }

    #[test]
    fn a_second_server_is_a_usage_error() {
        let words = [
            "--socket-fd",
            "3",
            "--x11",
            "Xwayland",
            "--",
            "--x11",
            "Xephyr",
            "--",
            "--",
            "/usr/bin/true",
        ];
        assert!(parse(&words).is_none());
    }

    #[test]
    fn no_display_is_the_usual_grammar() {
        let a = parse(&["--socket-fd", "4", "--", "/usr/bin/true"]).unwrap();
        assert!(a.x11.is_none());
        assert!(a.wm.is_none());
        assert!(!a.ctty);
        assert_eq!(a.command, ["/usr/bin/true"]);
    }

    #[test]
    fn the_window_manager_follows_the_server_argv() {
        let a = parse(&[
            "--socket-fd",
            "3",
            "--x11",
            "Xwayland",
            "--",
            "--wm",
            "twm",
            "--",
            "/usr/bin/true",
        ])
        .unwrap();
        assert_eq!(a.x11.unwrap(), ["Xwayland"]);
        assert_eq!(a.wm.unwrap(), "twm");
        assert_eq!(a.command, ["/usr/bin/true"]);
    }

    #[test]
    fn a_window_manager_without_a_server_is_a_usage_error() {
        assert!(parse(&["--socket-fd", "3", "--wm", "twm", "--", "/usr/bin/true"]).is_none());
    }

    #[test]
    fn a_second_window_manager_is_a_usage_error() {
        let words = [
            "--socket-fd",
            "3",
            "--x11",
            "Xwayland",
            "--",
            "--wm",
            "twm",
            "--wm",
            "openbox",
            "--",
            "/usr/bin/true",
        ];
        assert!(parse(&words).is_none());
    }

    #[test]
    fn the_socket_path_is_the_display_zero_socket_unless_a_test_says_otherwise() {
        let a = parse(&[
            "--socket-fd",
            "3",
            "--x11",
            "Xwayland",
            "--",
            "--",
            "/usr/bin/true",
        ])
        .unwrap();
        assert_eq!(a.x11_socket, Path::new(X11_SOCKET));
        let a = parse(&[
            "--socket-fd",
            "3",
            "--x11",
            "Xwayland",
            "--",
            "--x11-socket",
            "/tmp/probe/X0",
            "--",
            "/usr/bin/true",
        ])
        .unwrap();
        assert_eq!(a.x11_socket, Path::new("/tmp/probe/X0"));
    }

    #[test]
    fn a_socket_path_without_a_server_is_a_usage_error() {
        let words = [
            "--socket-fd",
            "3",
            "--x11-socket",
            "/tmp/probe/X0",
            "--",
            "/usr/bin/true",
        ];
        assert!(parse(&words).is_none());
    }

    #[test]
    fn the_helper_flag_the_display_socket_replaced_is_rejected() {
        let words = [
            "--socket-fd",
            "3",
            "--helper",
            "Xwayland",
            "--",
            "--",
            "/usr/bin/true",
        ];
        assert!(parse(&words).is_none());
    }
}
