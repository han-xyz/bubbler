//! In-sandbox supervisor: runs the command, serves exec requests on the
//! inherited socket, forwards SIGTERM/SIGINT, exits with the command's status.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Timespec, poll};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::process::{DumpableBehavior, Pid, Signal, kill_process, set_dumpable_behavior};

use bubbler_init::wire;

/// Supervisor tick: the `poll` timeout, so `accept` and `wait` never block.
/// One iteration can still take up to [`REQUEST_TIMEOUT`] while it reads a request.
const TICK: Duration = Duration::from_millis(20);
const TICK_TIMESPEC: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: TICK.subsec_nanos() as Nsecs,
};
/// How long a process gets between SIGTERM and SIGKILL.
const GRACE: Duration = Duration::from_secs(5);
/// Deadline for one whole request; a client sending slowly cannot extend it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Raw wait status for a command that could not be executed, as a shell reports it.
const NOT_EXECUTABLE: i32 = 127 << 8;

struct Args {
    socket_fd: i32,
    command: Vec<OsString>,
}

/// A command run for a client, with the connection waiting for its status.
struct Exec {
    child: Child,
    stream: UnixStream,
}

/// Parse `--socket-fd N -- cmd...`; anything else is a usage error.
fn parse_args() -> Option<Args> {
    let mut it = std::env::args_os().skip(1);
    let mut socket_fd = None;
    let mut command = Vec::new();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--socket-fd") => socket_fd = it.next()?.to_str()?.parse().ok(),
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

/// Execute one request; a malformed one closes the connection, spawning nothing.
fn serve(stream: UnixStream, execs: &mut Vec<Exec>) {
    let Ok((argv, fds)) = wire::recv_request(&stream, Instant::now() + REQUEST_TIMEOUT) else {
        return;
    };
    let Some((program, rest)) = argv.split_first() else {
        return;
    };
    let mut fds = fds.into_iter();
    let (Some(stdin), Some(stdout), Some(stderr)) = (fds.next(), fds.next(), fds.next()) else {
        return;
    };
    let report = stderr.try_clone().ok();
    // argv[0] is resolved through PATH as seen inside the sandbox.
    let spawned = Command::new(program)
        .args(rest)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn();
    match spawned {
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
        eprintln!("bubbler-init: usage: --socket-fd N -- cmd...");
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
        eprintln!("bubbler-init: usage: --socket-fd N -- cmd...");
        return ExitCode::from(2);
    };
    let mut command = match Command::new(program).args(rest).spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("bubbler-init: {}: {e}", program.to_string_lossy());
            return ExitCode::from(127);
        }
    };

    let mut execs: Vec<Exec> = Vec::new();
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
            return ExitCode::from(code_of(status));
        }
        reap(&mut execs);
        if kill_at.is_some_and(|at| Instant::now() >= at) {
            let _ = kill_process(Pid::from_child(&command), Signal::KILL);
            signal_execs(&execs, Signal::KILL);
            kill_at = None;
        }
        let mut fds = [PollFd::new(&listener, PollFlags::IN)];
        match poll(&mut fds, Some(&TICK_TIMESPEC)) {
            Ok(0) => continue,
            // Every poll error is retried on purpose: EINTR means a signal was
            // delivered and the next tick acts on it, and no other error is a
            // reason to abandon a command that is still running.
            Err(_) => {
                std::thread::sleep(TICK);
                continue;
            }
            Ok(_) => {}
        }
        while let Ok((stream, _)) = listener.accept() {
            serve(stream, &mut execs);
        }
    }
}
