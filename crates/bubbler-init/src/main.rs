//! In-sandbox supervisor: runs the command, serves exec requests on the
//! inherited socket, forwards SIGTERM/SIGINT, exits with the command's status.
//! With `--helper` it also runs a display helper (Xwayland) before the
//! command, hands the command and every exec'd child the display it
//! reports, and stops it last.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Timespec, poll};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::pipe::{PipeFlags, pipe_with};
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
/// How long the display helper gets to report its display number. A
/// helper that is slower than this is one the command cannot use anyway.
const HELPER_READY: Duration = Duration::from_secs(10);
/// Longest first line a display helper may write. A helper that streams
/// anything else at the pipe is broken, and its output is not init's to
/// buffer without a bound.
const MAX_DISPLAY_LINE: usize = 64;
/// Connections whose request has not arrived in full. The oldest is
/// dropped to make room, so stalled clients cannot grow the table.
const MAX_PENDING: usize = 16;

struct Args {
    socket_fd: i32,
    ctty: bool,
    helper: Option<Vec<OsString>>,
    command: Vec<OsString>,
}

/// The display helper and the display it reported. It is started before
/// the command and stopped after it, so nothing inside the sandbox is
/// ever pointed at a display that is not there.
struct Helper {
    child: Child,
    display: OsString,
    /// Init's end of the `-displayfd` pipe, held open until the helper is
    /// gone. Xserver(1) documents only the write ("will write the display
    /// number back on this file descriptor as a newline-terminated
    /// string"), not that the server then closes it, so init keeps its end
    /// rather than leave a later write facing EPIPE.
    _display_pipe: OwnedFd,
}

/// A command run for a client, with the connection waiting for its status.
struct Exec {
    child: Child,
    stream: UnixStream,
}

/// An accepted connection whose request is still arriving.
struct Pending {
    stream: UnixStream,
    incoming: wire::Incoming,
    deadline: Instant,
}

/// Parse `--socket-fd N [--ctty] [--helper argv... --] -- cmd...`;
/// anything else is a usage error. The helper argv ends at its own bare
/// `--`, so it may hold any words, including the command's own.
fn parse_args() -> Option<Args> {
    parse_from(std::env::args_os().skip(1))
}

/// The grammar itself, over any argv but this process's own.
fn parse_from(mut it: impl Iterator<Item = OsString>) -> Option<Args> {
    let mut socket_fd = None;
    let mut ctty = false;
    let mut helper = None;
    let mut command = Vec::new();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--socket-fd") => socket_fd = it.next()?.to_str()?.parse().ok(),
            Some("--ctty") => ctty = true,
            // A second one would silently replace the first, and a helper
            // that is dropped here is a display nothing ever starts.
            Some("--helper") if helper.is_none() => {
                let argv: Vec<OsString> = it.by_ref().take_while(|w| w != "--").collect();
                if argv.is_empty() {
                    return None;
                }
                helper = Some(argv);
            }
            Some("--") => {
                command.extend(it);
                break;
            }
            _ => return None,
        }
    }
    if command.is_empty() {
        return None;
    }
    Some(Args {
        socket_fd: socket_fd?,
        ctty,
        helper,
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

/// Execute one received request; a malformed one closes the connection,
/// spawning nothing. Whether the command takes fd 0 as its controlling
/// terminal is the request's own flag, not the instance's `--ctty`: the
/// client knows which of the fds it just sent is a pty it allocated.
fn serve(
    stream: UnixStream,
    request: &proto::Request,
    fds: Vec<OwnedFd>,
    execs: &mut Vec<Exec>,
    display: Option<&OsStr>,
) {
    let Some((program, rest)) = request.argv.split_first() else {
        return;
    };
    let mut fds = fds.into_iter();
    let (Some(stdin), Some(stdout), Some(stderr)) = (fds.next(), fds.next(), fds.next()) else {
        return;
    };
    let report = stderr.try_clone().ok();
    let terminal = request.ctty() && rustix::termios::isatty(&stdin);
    // argv[0] is resolved through PATH as seen inside the sandbox.
    let mut command = Command::new(program);
    command
        .args(rest)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // The helper's display is init's to hand out: an exec'd child gets
    // the same one the instance's own command was started with.
    if let Some(d) = display {
        command.env("DISPLAY", d);
    }
    if terminal {
        take_ctty(&mut command);
    }
    match command.spawn() {
        Ok(child) => execs.push(Exec { child, stream }),
        Err(e) => {
            if let Some(fd) = report {
                let _ = writeln!(
                    File::from(fd),
                    "bubbler-init: {}: {e}",
                    program.to_string_lossy()
                );
            }
            let _ = wire::send_status(&stream, NOT_EXECUTABLE);
        }
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
                serve(p.stream, &request, fds, execs, display);
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

/// Signal every exec'd child. They are unreaped here, so their pids are still theirs.
fn signal_execs(execs: &[Exec], sig: Signal) {
    for e in execs {
        let _ = kill_process(Pid::from_child(&e.child), sig);
    }
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

/// Kill a helper that never became usable and reap it, so a failed
/// startup leaves no process behind, then hand back why it failed.
fn abandon(child: &mut Child, reason: String) -> String {
    let _ = child.kill();
    let _ = child.wait();
    reason
}

/// Start the display helper and wait for the display number it writes to
/// `-displayfd`. That write end is the only descriptor the helper
/// inherits beyond stdio, and init drops its own copy right after the
/// spawn, so the pipe reports EOF as soon as the helper is gone.
fn start_helper(argv: &[OsString], stop: &AtomicBool) -> Result<Helper, String> {
    let (program, rest) = argv.split_first().ok_or("no helper to run")?;
    let (r, w) = pipe_with(PipeFlags::CLOEXEC)
        .map_err(|e| format!("cannot create the display pipe: {e}"))?;
    let mut launch = Command::new(program);
    launch
        .args(rest)
        .arg("-displayfd")
        .arg(w.as_raw_fd().to_string());
    // The helper is the one process that may have this fd, and it is
    // spawned on the next line, so no other child can inherit it.
    fcntl_setfd(&w, FdFlags::empty()).map_err(|e| format!("cannot pass the display pipe: {e}"))?;
    let spawned = launch.spawn();
    drop(w);
    let mut child = spawned.map_err(|e| format!("{}: {e}", program.to_string_lossy()))?;
    let deadline = Instant::now() + HELPER_READY;
    let mut line = Vec::new();
    let mut buf = [0u8; 32];
    loop {
        let mut fds = [PollFd::new(&r, PollFlags::IN)];
        let _ = poll(&mut fds, Some(&TICK_TIMESPEC));
        if !fds[0].revents().is_empty() {
            match rustix::io::read(&r, &mut buf) {
                Ok(0) => {
                    let why = "the display pipe closed with no display number".to_string();
                    return Err(abandon(&mut child, why));
                }
                Ok(n) if line.len() + n <= MAX_DISPLAY_LINE => {
                    line.extend_from_slice(&buf[..n]);
                }
                Ok(_) => {
                    let why = "it wrote more than a display number".to_string();
                    return Err(abandon(&mut child, why));
                }
                Err(e) if e == rustix::io::Errno::INTR || e == rustix::io::Errno::AGAIN => {}
                Err(e) => {
                    return Err(abandon(&mut child, format!("cannot read the display: {e}")));
                }
            }
        }
        if let Some(end) = line.iter().position(|&b| b == b'\n') {
            let text = String::from_utf8_lossy(&line[..end]);
            return match text.trim().parse::<u32>() {
                Ok(n) => Ok(Helper {
                    child,
                    display: OsString::from(format!(":{n}")),
                    _display_pipe: r,
                }),
                Err(_) => Err(abandon(
                    &mut child,
                    format!("it reported {text:?}, not a display number"),
                )),
            };
        }
        // The read above drains the pipe first, so a helper that reported
        // a display and exited at once is still a success.
        if let Ok(Some(status)) = child.try_wait() {
            let why = format!("it exited before reporting a display ({status})");
            return Err(abandon(&mut child, why));
        }
        if Instant::now() >= deadline {
            let why = format!("no display number after {}s", HELPER_READY.as_secs());
            return Err(abandon(&mut child, why));
        }
        // A signal during the wait ends the run here: the command has not
        // been spawned, so there is nothing to stop but the helper.
        if stop.load(Ordering::SeqCst) {
            let why = "it was stopped before it was ready".to_string();
            return Err(abandon(&mut child, why));
        }
    }
}

/// SIGTERM the helper and SIGKILL whatever outlives the grace, then reap
/// it. Only ever called once the command and every exec'd child are
/// gone: nothing may lose its display while it is still drawing on it.
fn stop_helper(helper: Option<&mut Helper>) {
    let Some(h) = helper else { return };
    let _ = kill_process(Pid::from_child(&h.child), Signal::TERM);
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline {
        if !matches!(h.child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(TICK);
    }
    let _ = h.child.kill();
    let _ = h.child.wait();
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
    let Some(args) = parse_args() else {
        eprintln!("bubbler-init: usage: --socket-fd N [--ctty] [--helper argv... --] -- cmd...");
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
        eprintln!("bubbler-init: usage: --socket-fd N [--ctty] [--helper argv... --] -- cmd...");
        return ExitCode::from(2);
    };
    // Before the command, so a display the command needs is listening
    // and its number known by the time the command's first line runs.
    let mut helper = match args.helper.as_deref().map(|a| start_helper(a, &stop)) {
        Some(Ok(h)) => Some(h),
        Some(Err(reason)) => {
            eprintln!("bubbler-init: Xwayland did not start: {reason}");
            return ExitCode::from(2);
        }
        None => None,
    };
    // A copy of the display, so the loop below can drop a helper that
    // died without the command's own environment changing under it.
    let display = helper.as_ref().map(|h| h.display.clone());
    let display = display.as_deref();
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
            stop_helper(helper.as_mut());
            return ExitCode::from(127);
        }
    };

    let mut execs: Vec<Exec> = Vec::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut kill_at: Option<Instant> = None;
    loop {
        if stop.swap(false, Ordering::SeqCst) {
            // The command is unreaped until the loop exits, so its pid is still its own.
            let _ = kill_process(Pid::from_child(&command), Signal::TERM);
            signal_execs(&execs, Signal::TERM);
            kill_at = Some(Instant::now() + GRACE);
        }
        if let Ok(Some(status)) = command.try_wait() {
            reap(&mut execs);
            shutdown(&mut execs);
            stop_helper(helper.as_mut());
            return ExitCode::from(code_of(status));
        }
        // A helper that exits takes the display with it: the command
        // cannot draw any more, so it is stopped instead of left blind.
        // Checked after the command's own exit, so the two going down
        // together is not reported as the helper stopping the command.
        if helper
            .as_mut()
            .is_some_and(|h| matches!(h.child.try_wait(), Ok(Some(_))))
        {
            eprintln!("bubbler-init: Xwayland exited; stopping the command");
            let _ = kill_process(Pid::from_child(&command), Signal::TERM);
            helper = None;
        }
        reap(&mut execs);
        if kill_at.is_some_and(|at| Instant::now() >= at) {
            let _ = kill_process(Pid::from_child(&command), Signal::KILL);
            signal_execs(&execs, Signal::KILL);
            kill_at = None;
        }
        // The listener and every half-read request in one poll set: a
        // client that stops mid-request delays nothing but itself.
        let mut fds = Vec::with_capacity(1 + pending.len());
        fds.push(PollFd::new(&listener, PollFlags::IN));
        fds.extend(
            pending
                .iter()
                .map(|p| PollFd::new(&p.stream, PollFlags::IN)),
        );
        let polled = poll(&mut fds, Some(&TICK_TIMESPEC));
        let accept = fds[0].revents().contains(PollFlags::IN);
        let mut ready: Vec<bool> = fds[1..].iter().map(|f| !f.revents().is_empty()).collect();
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
        read_pending(&mut pending, &mut ready, &mut execs, display);
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
    fn the_helper_argv_ends_at_its_own_terminator() {
        let a = parse(&[
            "--socket-fd",
            "3",
            "--ctty",
            "--helper",
            "Xwayland",
            ":0",
            "--",
            "--",
            "/usr/bin/true",
            "--helper",
        ])
        .unwrap();
        assert_eq!(a.socket_fd, 3);
        assert!(a.ctty);
        assert_eq!(a.helper.unwrap(), ["Xwayland", ":0"]);
        assert_eq!(a.command, ["/usr/bin/true", "--helper"]);
    }

    #[test]
    fn a_helper_without_an_argv_is_a_usage_error() {
        assert!(parse(&["--socket-fd", "3", "--helper", "--", "--", "/usr/bin/true"]).is_none());
    }

    #[test]
    fn a_helper_argv_that_is_never_terminated_is_a_usage_error() {
        // The helper swallows the words the command would have been.
        assert!(parse(&["--socket-fd", "3", "--helper", "Xwayland", "/usr/bin/true"]).is_none());
        // One `--` short: what follows it is neither a flag nor a command.
        assert!(
            parse(&[
                "--socket-fd",
                "3",
                "--helper",
                "Xwayland",
                "--",
                "/usr/bin/true"
            ])
            .is_none()
        );
    }

    #[test]
    fn a_second_helper_is_a_usage_error() {
        let words = [
            "--socket-fd",
            "3",
            "--helper",
            "Xwayland",
            "--",
            "--helper",
            "Xephyr",
            "--",
            "--",
            "/usr/bin/true",
        ];
        assert!(parse(&words).is_none());
    }

    #[test]
    fn no_helper_is_the_usual_grammar() {
        let a = parse(&["--socket-fd", "4", "--", "/usr/bin/true"]).unwrap();
        assert!(a.helper.is_none());
        assert!(!a.ctty);
        assert_eq!(a.command, ["/usr/bin/true"]);
    }
}
