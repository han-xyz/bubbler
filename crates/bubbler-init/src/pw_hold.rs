//! The process a PipeWire security context is held open by, as a mode of
//! the supervisor binary: `pw-container` creates the context socket, runs
//! this as its program, and tears the context down when it exits.
//!
//! `pw-container` names its socket itself (`/tmp/pipewire-XXXXXX`, a
//! template it takes from no environment variable), so this mode renames
//! it to the name a PipeWire client looks for and reports the path it
//! ended at. Then it waits: the context lasts exactly as long as this
//! process does.

use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::event::{Nsecs, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{Signal, set_parent_process_death_signal};

/// The file name bwrap binds the supervisor binary at for this mode, and
/// the `argv[0]` basename that selects it.
pub const NAME: &str = "bubbler-pw-hold";

/// Names the descriptor the renamed socket's path is reported on. Not an
/// argument: `pw-container` hands its program to `system()` as one word
/// and drops every further one, so the environment is the only channel
/// this mode has.
pub const REPORT_FD: &str = "BUBBLER_PW_REPORT_FD";

/// What the socket is renamed to: the name every PipeWire client looks
/// for under its runtime directory, which is where bubbler binds it.
pub const SOCKET_NAME: &str = "pipewire-0";

/// Rename the context socket `remote` to [`SOCKET_NAME`] beside itself
/// and report the path it now has on `report`, one line.
///
/// A bound unix socket keeps its identity across `rename(2)` — the
/// listening socket is the inode, not the name — so a client that
/// connects to the new path reaches the same server.
fn hand_over(remote: &Path, report: BorrowedFd<'_>) -> Result<PathBuf, String> {
    let to = remote.with_file_name(SOCKET_NAME);
    rustix::fs::rename(remote, &to)
        .map_err(|e| format!("renaming {} to {}: {e}", remote.display(), to.display()))?;
    let mut line = to.clone().into_os_string();
    line.push("\n");
    write_all(report, line.as_bytes()).map_err(|e| format!("reporting {}: {e}", to.display()))?;
    Ok(to)
}

/// Hand the context socket over and hold the context open until this
/// run ends. Returns only once it has: a `pw-container` whose program
/// has exited tears the security context down with it.
pub fn run() -> ExitCode {
    // Set before anything is renamed: from here on the holder leaves
    // with `pw-container` even if nothing signals it. That is a backstop
    // behind the sidecar's own pid namespace, whose pid 1 is
    // `pw-container` itself.
    if let Err(e) = set_parent_process_death_signal(Some(Signal::TERM)) {
        eprintln!("{NAME}: cannot ask to die with pw-container: {e}");
        return ExitCode::from(2);
    }
    let Some(remote) = std::env::var_os("PIPEWIRE_REMOTE") else {
        eprintln!("{NAME}: PIPEWIRE_REMOTE is not set; pw-container sets it for its program");
        return ExitCode::from(2);
    };
    let Some(fd) = std::env::var(REPORT_FD)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|n| *n >= 0)
    else {
        eprintln!("{NAME}: {REPORT_FD} does not name a descriptor to report on");
        return ExitCode::from(2);
    };
    // SAFETY: the number comes from bubbler's own `--setenv`, naming a
    // pipe it made inheritable for exactly this sidecar. Nothing else in
    // this process holds a handle to it: this mode opens nothing before
    // this line, and the only other descriptors it has are the ones
    // `pw-container` was started with.
    let report = unsafe { OwnedFd::from_raw_fd(fd) };
    let stop = Arc::new(AtomicBool::new(false));
    // The four the supervisor takes, for the same reason: each of them
    // means the run is over, and left on their default dispositions they
    // would kill this process where it stands instead of letting it
    // report the exit `pw-container` reads.
    //
    // Before the report and not after it: the line below is what tells
    // bubbler the context is up, and the run it belongs to can end at
    // any moment from then on. A SIGTERM in the window between the two
    // would find the default disposition and kill the holder, which
    // leaves `pw-container` waiting out the launcher's whole stop
    // deadline instead of exiting with it.
    for sig in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGQUIT,
    ] {
        if signal_hook::flag::register(sig, Arc::clone(&stop)).is_err() {
            eprintln!("{NAME}: cannot install signal handlers");
            return ExitCode::from(2);
        }
    }
    if let Err(why) = hand_over(Path::new(&remote), report.as_fd()) {
        eprintln!("{NAME}: {why}");
        return ExitCode::from(1);
    }
    // Closed as soon as the path is out: bubbler reads one line and then
    // waits on nothing, and a descriptor held open here would keep it
    // from seeing the end of a holder that died before reporting.
    drop(report);
    while !stop.load(Ordering::Relaxed) {
        // A signal that arrived between the check above and this call
        // would not interrupt it, so the wait is bounded rather than
        // endless; a signal during it ends it at once, since `poll` is
        // never restarted after a handler (`signal(7)`).
        match poll(&mut [], Some(&TICK)) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(e) => {
                eprintln!("{NAME}: waiting for the run to end: {e}");
                return ExitCode::from(2);
            }
        }
    }
    ExitCode::SUCCESS
}

/// How long the holder waits between checks of the stop flag.
const TICK: Timespec = Timespec {
    tv_sec: 1,
    tv_nsec: 0 as Nsecs,
};

/// Write every byte of `line` to `fd`, since a pipe may take a short
/// write and the reader on the other side waits for the whole line.
fn write_all(fd: BorrowedFd<'_>, line: &[u8]) -> Result<(), Errno> {
    let mut rest = line;
    while !rest.is_empty() {
        match rustix::io::write(fd, rest) {
            Ok(0) => return Err(Errno::PIPE),
            Ok(n) => rest = &rest[n..],
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn the_socket_is_renamed_beside_itself_and_stays_connectable() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let from = dir.path().join("pipewire-Ab12Cd");
        let listener = UnixListener::bind(&from).expect("a bound socket");
        let (read, write) = rustix::pipe::pipe().expect("a pipe");

        let to = hand_over(&from, write.as_fd()).expect("the rename");

        assert_eq!(to, dir.path().join(SOCKET_NAME));
        assert!(!from.exists(), "the old name is gone");
        drop(write);
        let mut reported = String::new();
        std::fs::File::from(read)
            .read_to_string(&mut reported)
            .expect("the report");
        assert_eq!(reported, format!("{}\n", to.display()));

        let mut client = UnixStream::connect(&to).expect("a client of the renamed socket");
        let (mut server, _) = listener.accept().expect("the server side");
        client.write_all(b"ping").expect("a write");
        let mut got = [0u8; 4];
        server.read_exact(&mut got).expect("a read");
        assert_eq!(&got, b"ping");
    }

    #[test]
    fn a_socket_that_is_not_there_is_refused_by_name() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let from = dir.path().join("pipewire-gone");
        let (_read, write) = rustix::pipe::pipe().expect("a pipe");
        let e = hand_over(&from, write.as_fd()).expect_err("no socket to rename");
        assert!(e.contains("pipewire-gone"), "{e}");
    }
}
