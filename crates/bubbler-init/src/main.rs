//! In-sandbox supervisor: runs the command, serves exec requests on the
//! inherited socket, forwards SIGTERM/SIGINT, exits with the command's status.
//! With `--x11` it also owns the display socket: the command runs at once with
//! `DISPLAY` set, and the nested X server (plus the `--wm` window manager) is
//! started on the first client that connects and stopped last.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Timespec, poll};
use rustix::fs::Mode;
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::process::{DumpableBehavior, Pid, Signal, kill_process, set_dumpable_behavior};

use bubbler_init::{proto, wire};

/// Supervisor tick: the `poll` timeout, so `accept`, `wait` and every
/// request read are non-blocking and one iteration is bounded by it.
const TICK: Duration = Duration::from_millis(20);
const TICK_TIMESPEC: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: TICK.subsec_nanos() as Nsecs,
};
/// How long a process gets between SIGTERM and SIGKILL.
const GRACE: Duration = Duration::from_secs(5);
/// Deadline for one whole request, counted from the accept.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Raw wait status for a command that could not be executed, as a shell reports it.
const NOT_EXECUTABLE: i32 = 127 << 8;
/// Connections whose request has not arrived in full. The oldest is
/// dropped to make room, so stalled clients cannot grow the table.
const MAX_PENDING: usize = 16;
/// The display socket inside the sandbox, and the display every process
/// there is pointed at. The server is always started as `:0`.
const X11_SOCKET: &str = "/tmp/.X11-unix/X0";
const DISPLAY: &str = ":0";
/// Clients the display socket queues before the server has taken it
/// over. Only the first one has to wait for a server to start at all.
const X11_BACKLOG: i32 = 16;
/// The one usage line, so a grammar error always names the whole grammar.
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

/// The nested X server, the socket bound for it and the window manager
/// that goes with it. The socket listens from before the command starts,
/// so a client may connect while there is no server yet; that connection
/// is what starts one, and the server accepts it itself.
struct X11 {
    argv: Vec<OsString>,
    wm: Option<OsString>,
    listener: UnixListener,
    /// Set on the first connection and never cleared: the server owns the
    /// socket from then on, so init neither polls nor accepts it again,
    /// and a server that failed to start is not started a second time.
    started: bool,
    server: Option<Child>,
    wm_child: Option<Child>,
}

/// A command run for a client, with the connection waiting for its status.
struct Exec {
    child: Child,
    stream: UnixStream,
}

/// The end of the run: whether anything has asked for it, and the moment
/// whatever ignored SIGTERM is SIGKILLed.
#[derive(Default)]
struct Stopping {
    /// Set by the first stop event and never cleared. From then on no new
    /// exec'd child is started: one spawned now could only be killed
    /// moments later, without the SIGTERM every other child was given.
    /// Nor is the X server, which a client connecting during the grace
    /// would otherwise wake for the seconds it has left.
    asked: bool,
    /// Cleared once the SIGKILL has gone out.
    kill_at: Option<Instant>,
}

/// An accepted connection whose request is still arriving.
struct Pending {
    stream: UnixStream,
    incoming: wire::Incoming,
    deadline: Instant,
}

/// Parse `--socket-fd N [--ctty] [--x11 argv... --] [--x11-socket path]
/// [--wm program] -- cmd...`; anything else is a usage error.
fn parse_args() -> Option<Args> {
    parse_from(std::env::args_os().skip(1))
}

/// The grammar itself, over any argv but this process's own. The X server
/// argv ends at its own bare `--`, so it may hold any words, including the
/// command's own. `--x11-socket` overrides the path init binds for the
/// display; it exists for this crate's own tests, which run on a host
/// where `/tmp/.X11-unix/X0` is the session's own display, and bubbler
/// never passes it.
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

/// Adopt the inherited listening socket named by `--socket-fd`, CLOEXEC at once.
fn listener_from_fd(fd: i32) -> Option<UnixListener> {
    if fd < 3 {
        return None;
    }
    // SAFETY: the precondition is that `fd` names a descriptor this process
    // owns and that nothing else will close. `fcntl_getfd` is the probe that
    // rules out a number that is not open at all (EBADF) before any owning
    // handle exists, so no closed number is ever adopted or closed twice;
    // bubbler passes this listener as the only inherited fd above stdio, so
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

/// Give the command its own session with its stdin as the controlling
/// terminal, so job control and `/dev/tty` work inside the sandbox. Only
/// ever called for a terminal bubbler allocated: claiming whatever sits
/// on fd 0 would take over the user's own terminal in passthrough mode.
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

/// Turn a request down: say why on the connection's own stderr, and
/// answer the status a shell reports for a command it could not run.
fn refuse(stream: &UnixStream, report: Option<OwnedFd>, why: &str) {
    if let Some(fd) = report {
        let _ = writeln!(File::from(fd), "bubbler-init: {why}");
    }
    let _ = wire::send_status(stream, NOT_EXECUTABLE);
}

/// Execute one received request; a malformed one closes the connection,
/// spawning nothing. Whether the command takes fd 0 as its controlling
/// terminal is the request's own flag, not the instance's `--ctty`: the
/// client knows which of the fds it just sent is a pty it allocated.
/// Once the run is stopping nothing new is started at all.
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

/// Take one read step on every connection `poll` reported, spawning the
/// commands whose requests are now whole. `ready` is parallel to
/// `pending` and shrinks with it.
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

/// Answer and drop every exec connection whose child has exited.
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

/// Whether a child is gone. `try_wait` fails only where init cannot learn
/// the child's fate at all, and a process it can no longer account for is
/// treated as gone: assuming it is still up is what would leave the
/// command drawing on a display that is not there.
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

/// Signal every exec'd child. They are unreaped here, so their pids are still theirs.
fn signal_execs(execs: &[Exec], sig: Signal) {
    for e in execs {
        let _ = kill_process(Pid::from_child(&e.child), sig);
    }
}

/// Ask the run to end: SIGTERM the command and every exec'd child, and
/// set the deadline at which whatever ignored it is SIGKILLed. The
/// deadline is the point: a command that traps SIGTERM would otherwise
/// keep the sandbox alive for as long as it liked.
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

/// SIGTERM the remaining exec'd children and SIGKILL whatever outlives the grace.
fn shutdown(execs: &mut Vec<Exec>) {
    if execs.is_empty() {
        return;
    }
    signal_execs(execs, Signal::TERM);
    let deadline = Instant::now() + GRACE;
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

/// Bind the socket the nested X server will inherit. It is listening
/// before the command runs, so the first client waits in its queue
/// instead of failing to connect while the server is still starting.
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

/// Hand the listening socket to the X server. The connection that woke
/// init is deliberately left in the queue: the server accepts it on the
/// very descriptor it inherits, so the client that waited is served by
/// the server it woke, on the socket it already connected to.
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

/// Start the window manager beside the server. It is a convenience and
/// not a display: one that is missing or that exits is reported, and the
/// command keeps running on a server that simply manages nothing.
fn start_wm(x: &mut X11) {
    let Some(wm) = x.wm.as_ref() else { return };
    match Command::new(wm).env("DISPLAY", DISPLAY).spawn() {
        Ok(child) => x.wm_child = Some(child),
        Err(e) => eprintln!("bubbler-init: wm {}: {e}", wm.to_string_lossy()),
    }
}

/// SIGTERM one child and SIGKILL whatever outlives the grace, then reap it.
fn stop_child(child: &mut Child) {
    let _ = kill_process(Pid::from_child(child), Signal::TERM);
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(TICK);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Stop the window manager and then the server. Only ever called once
/// the command and every exec'd child are gone: nothing may lose its
/// display while it is still drawing on it, and the window manager is
/// never left managing a server that has already exited.
fn stop_x11(x11: Option<&mut X11>) {
    let Some(x) = x11 else { return };
    if let Some(wm) = x.wm_child.as_mut() {
        stop_child(wm);
    }
    if let Some(server) = x.server.as_mut() {
        stop_child(server);
    }
}

/// The command's exit code, or 128 + signal when a signal killed it.
fn code_of(status: ExitStatus) -> u8 {
    let code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1);
    u8::try_from(code).unwrap_or(1)
}

fn main() -> ExitCode {
    let Some(mut args) = parse_args() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(listener) = listener_from_fd(args.socket_fd) else {
        eprintln!(
            "bubbler-init: {}: not an open listening socket fd",
            args.socket_fd
        );
        return ExitCode::from(2);
    };
    // A non-dumpable process can only be ptraced, or have fds taken with
    // pidfd_getfd, by a tracer holding CAP_SYS_PTRACE, even where
    // kernel.yama.ptrace_scope is 0; execve resets it, so the command and every
    // exec'd child are unaffected.
    if let Err(e) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        eprintln!("bubbler-init: cannot become non-dumpable: {e}");
        return ExitCode::from(2);
    }
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
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
            stop_x11(x11.as_mut());
            return ExitCode::from(127);
        }
    };

    let mut execs: Vec<Exec> = Vec::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut stopping = Stopping::default();
    loop {
        if stop.swap(false, Ordering::SeqCst) {
            begin_stop(&command, &execs, &mut stopping);
        }
        if let Ok(Some(status)) = command.try_wait() {
            reap(&mut execs);
            shutdown(&mut execs);
            stop_x11(x11.as_mut());
            return ExitCode::from(code_of(status));
        }
        if let Some(x) = x11.as_mut() {
            // A server that exits takes the display with it: the command
            // cannot draw any more, so it is stopped instead of left
            // blind. Checked after the command's own exit, so the two
            // going down together is not reported as the server stopping
            // the command.
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
        if stopping.kill_at.is_some_and(|at| Instant::now() >= at) {
            let _ = kill_process(Pid::from_child(&command), Signal::KILL);
            signal_execs(&execs, Signal::KILL);
            stopping.kill_at = None;
        }
        // The listener, the display socket while nothing serves it, and
        // every half-read request in one poll set: a client that stops
        // mid-request delays nothing but itself. The display socket
        // leaves that set once the run is ending, so a client connecting
        // during the grace wakes nothing — and so that the loop does not
        // spin on a connection it has decided not to answer.
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
        match polled {
            Ok(0) => {}
            // Every poll error is retried on purpose: EINTR means a signal was
            // delivered and the next tick acts on it, and no other error is a
            // reason to abandon a command that is still running.
            Err(_) => {
                std::thread::sleep(TICK);
                continue;
            }
            Ok(_) => {}
        }
        // The first client to connect is what starts the server, and the
        // window manager goes up with it: neither exists in a sandbox
        // whose command never speaks X11.
        if wake_x11 && let Some(x) = x11.as_mut() {
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
