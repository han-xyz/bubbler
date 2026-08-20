//! The sandbox's terminal: pty allocation, the per-fd stdio decision, raw
//! mode on the user's terminal and the relay between the two.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{Mode, OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::{Errno, read, write};
use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
use rustix::termios::{
    LocalModes, OptionalActions, SpecialCodeIndex, Termios, isatty, tcgetattr, tcgetwinsize,
    tcsetattr, tcsetwinsize,
};

use crate::error::{ConfigError, LaunchError};

/// Bytes moved per read. A terminal hands over far less at a time; this
/// only bounds a fast writer inside the sandbox.
const CHUNK: usize = 8192;

/// Relay tick: how often the exit check and the `SIGWINCH` flag are
/// serviced when no fd is ready.
const TICK: Duration = Duration::from_millis(100);
const TICK_TIMESPEC: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: TICK.subsec_nanos() as Nsecs,
};

/// How long output still in the pty is waited for after the command's
/// status arrives.
const DRAIN: Duration = Duration::from_millis(200);

/// `^]`, the detach key.
const ESCAPE: u8 = 0x1d;

/// What the user is told when the detach sequence is typed. The sandbox
/// keeps running either way; what ends is the relay.
pub const DETACHED_NOTE: &str = "bubbler: detached; the sandbox keeps running";

/// How many `ESCAPE` bytes in a row detach, and how long that run may take.
const DETACH_RUN: usize = 3;
const DETACH_WINDOW: Duration = Duration::from_secs(1);

/// How the sandbox's stdio is connected to the user's terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TtyMode {
    /// Every fd that is a terminal gets the slave of a pty bubbler owns;
    /// the sandbox never holds a descriptor for the user's terminal.
    #[default]
    Pty,
    /// bubbler's own fds are handed over: the sandbox can read the user's
    /// keystrokes and write escape sequences to their terminal.
    Passthrough,
    /// No terminal at all: stdin is `/dev/null`, output comes back
    /// through pipes, and bwrap binds nothing at `/dev/console`.
    None,
}

impl FromStr for TtyMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pty" => Ok(Self::Pty),
            "passthrough" => Ok(Self::Passthrough),
            "none" => Ok(Self::None),
            _ => Err(ConfigError::BadArgument {
                node: "tty".to_owned(),
                reason: format!("expected `pty`, `passthrough` or `none`, got `{s}`"),
            }),
        }
    }
}

/// What one of the sandbox's fds 0, 1 and 2 is connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioTarget {
    /// The slave of the pty allocated for this launch.
    Slave,
    /// bubbler's own fd, passed through unchanged.
    Inherit,
    /// `/dev/null`.
    Null,
    /// A pipe bubbler copies to its own output.
    Pipe,
}

/// One pseudoterminal: bubbler keeps the master, the sandbox gets the slave.
#[derive(Debug)]
pub struct Pty {
    /// bubbler's end, which the relay reads and writes.
    pub master: OwnedFd,
    /// The sandbox's end, handed to bwrap or to the supervisor.
    pub slave: OwnedFd,
}

/// Where each of the sandbox's stdio fds goes, and the pty they need.
/// `pty` is filled in by the caller with [`allocate`] when
/// [`StdioPlan::needs_pty`] says one is required.
#[derive(Debug)]
pub struct StdioPlan {
    /// Target for fds 0, 1 and 2, in that order.
    pub fds: [StdioTarget; 3],
    /// The pty the [`StdioTarget::Slave`] entries name.
    pub pty: Option<Pty>,
}

impl StdioPlan {
    /// Whether this plan needs a pty allocated for it.
    pub fn needs_pty(&self) -> bool {
        self.fds.contains(&StdioTarget::Slave)
    }

    /// Whether the user's terminal must go to raw mode: only when the
    /// sandbox reads its input through the pty, so its line discipline is
    /// the one interpreting Ctrl-C and the erase key.
    pub fn raw_mode(&self) -> bool {
        self.ctty()
    }

    /// Whether the sandbox may take its fd 0 as a controlling terminal:
    /// only when that fd is the slave of a pty bubbler allocated, never a
    /// terminal it merely inherited from the user.
    pub fn ctty(&self) -> bool {
        self.fds[0] == StdioTarget::Slave
    }
}

/// Which of bubbler's own fds 0, 1 and 2 are terminals. What the plan is
/// made from: a pty replaces a terminal, never a pipe or a redirect.
pub fn host_is_tty() -> [bool; 3] {
    let (i, o, e) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    [isatty(i), isatty(o), isatty(e)]
}

/// An open `/dev/null`: the stdio slot for something that must exist but
/// carries nothing — a descriptor bubbler was started without, a sandbox
/// asked for no terminal, or a pty whose output no fd of bubbler's can take.
pub fn null_stdio() -> Result<OwnedFd, LaunchError> {
    let path = Path::new("/dev/null");
    rustix::fs::open(path, OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
}

/// bubbler's own fds 0, 1 and 2, duplicated so a plan can index them by
/// number. The copies are `CLOEXEC`: what the sandbox gets is decided by
/// the plan, never inherited by accident. A descriptor bubbler was
/// started without stands in as `/dev/null` — a plan is made of three
/// fds, and one nobody is using is no reason to refuse the launch.
pub fn host_stdio() -> Result<[OwnedFd; 3], LaunchError> {
    let (i, o, e) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    let dup = |fd: BorrowedFd<'_>| match fd.try_clone_to_owned() {
        Ok(fd) => Ok(fd),
        Err(_) => null_stdio(),
    };
    Ok([dup(i.as_fd())?, dup(o.as_fd())?, dup(e.as_fd())?])
}

/// Which of bubbler's fds the pty's output goes back out on: the first of
/// 1, 2 and 0 the pty stands in for, so output still reaches the terminal
/// when stdout alone is redirected. `None` when there is no pty, or when
/// the only candidate cannot be written to: `bubbler run x < /dev/tty` is
/// a terminal opened read-only, and every write to it would fail.
pub fn output_fd(plan: &StdioPlan, host: &[OwnedFd; 3]) -> Option<usize> {
    [1, 2, 0]
        .into_iter()
        .find(|i| plan.fds[*i] == StdioTarget::Slave && writable(host[*i].as_fd()))
}

/// Whether `fd` was opened for writing. An fd whose access mode cannot be
/// read is taken as unusable, which only costs it its turn as the output.
fn writable(fd: BorrowedFd<'_>) -> bool {
    fcntl_getfl(fd).is_ok_and(|f| f & OFlags::ACCMODE != OFlags::RDONLY)
}

/// Decide each of fds 0, 1 and 2 on its own from `mode` and which of
/// bubbler's fds are terminals. Pure: it opens nothing.
pub fn plan(mode: TtyMode, is_tty: [bool; 3]) -> StdioPlan {
    let fds = match mode {
        TtyMode::Pty => is_tty.map(|t| {
            if t {
                StdioTarget::Slave
            } else {
                StdioTarget::Inherit
            }
        }),
        TtyMode::Passthrough => [StdioTarget::Inherit; 3],
        TtyMode::None => [StdioTarget::Null, StdioTarget::Pipe, StdioTarget::Pipe],
    };
    StdioPlan { fds, pty: None }
}

/// Allocate a pty and copy `host_tty`'s settings and size onto its slave,
/// so the erase key, `IUTF8` and the window size the user has apply
/// inside the sandbox. `host_tty` must be a terminal (`ENOTTY` otherwise)
/// and must still be in its normal mode: called after [`RawGuard::new`]
/// this would hand the sandbox a raw pty, with no echo and no line editing.
pub fn allocate(host_tty: BorrowedFd<'_>) -> Result<Pty, LaunchError> {
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
    let master = openpt(flags).map_err(pty_error)?;
    // A documented no-op on Linux, kept because it is the contract of /dev/ptmx.
    grantpt(&master).map_err(pty_error)?;
    // Without this the peer cannot be opened at all.
    unlockpt(&master).map_err(pty_error)?;
    // TIOCGPTPEER opens the slave from the master with no path lookup, so
    // no /dev/pts is consulted and there is nothing to race.
    let slave = ioctl_tiocgptpeer(&master, flags).map_err(pty_error)?;
    let settings = tcgetattr(host_tty).map_err(pty_error)?;
    tcsetattr(&slave, OptionalActions::Now, &settings).map_err(pty_error)?;
    let size = tcgetwinsize(host_tty).map_err(pty_error)?;
    tcsetwinsize(&slave, size).map_err(pty_error)?;
    Ok(Pty { master, slave })
}

/// Raw mode on a terminal for as long as it lives. Restoring is what
/// keeps a killed bubbler from leaving the user without an echo.
pub struct RawGuard<'a> {
    fd: BorrowedFd<'a>,
    saved: Option<Termios>,
}

impl<'a> RawGuard<'a> {
    /// Save `fd`'s settings and put it in raw mode. `fd` must be a
    /// terminal; anything else fails with `ENOTTY`.
    pub fn new(fd: BorrowedFd<'a>) -> Result<Self, LaunchError> {
        let saved = tcgetattr(fd).map_err(pty_error)?;
        let mut raw = saved.clone();
        raw.make_raw();
        tcsetattr(fd, OptionalActions::Now, &raw).map_err(pty_error)?;
        Ok(Self {
            fd,
            saved: Some(saved),
        })
    }

    /// Restore the saved settings now. Idempotent, so the signal path can
    /// call it and the drop still runs.
    pub fn restore(&mut self) {
        if let Some(saved) = self.saved.take() {
            // Flush, not Now: whatever the user typed after the sandbox
            // stopped reading is not fed to their shell.
            let _ = tcsetattr(self.fd, OptionalActions::Flush, &saved);
        }
    }
}

impl Drop for RawGuard<'_> {
    fn drop(&mut self) {
        self.restore();
    }
}

/// How a relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// The command exited with this code, as `until` reported it.
    Exited(i32),
    /// The user typed the detach sequence; the sandbox keeps running.
    Detached,
}

/// The `^]`x3 detach run. Escapes are held back until the run either
/// completes or cannot, so a `^]` the user meant for the app still
/// arrives, just late.
struct Escape {
    held: usize,
    since: Option<Instant>,
}

impl Escape {
    fn new() -> Self {
        Self {
            held: 0,
            since: None,
        }
    }

    /// Append what the sandbox should see of `chunk`; `true` means detach.
    fn feed(&mut self, chunk: &[u8], now: Instant, out: &mut Vec<u8>) -> bool {
        for &byte in chunk {
            if byte != ESCAPE {
                self.release(out);
                out.push(byte);
                continue;
            }
            self.expire(now, out);
            self.held += 1;
            if self.held == 1 {
                self.since = Some(now);
            }
            if self.held == DETACH_RUN {
                self.held = 0;
                self.since = None;
                return true;
            }
        }
        false
    }

    /// Release escapes whose run can no longer finish in time.
    fn expire(&mut self, now: Instant, out: &mut Vec<u8>) {
        if self
            .since
            .is_some_and(|s| now.duration_since(s) > DETACH_WINDOW)
        {
            self.release(out);
        }
    }

    fn release(&mut self, out: &mut Vec<u8>) {
        out.extend(std::iter::repeat_n(ESCAPE, self.held));
        self.held = 0;
        self.since = None;
    }
}

/// Carry bytes between the user's terminal and the sandbox's pty until
/// `until` reports an exit or the user detaches. `master` is never
/// closed: that would tear the pty down under a running command. Every
/// `winch` is answered by copying `host_out`'s size onto the pty, so
/// `host_out` must be the user's terminal; the size it starts with is the
/// one [`allocate`] copied from the terminal it was given.
pub fn relay(
    master: BorrowedFd<'_>,
    host_in: Option<BorrowedFd<'_>>,
    host_out: BorrowedFd<'_>,
    until: &mut dyn FnMut() -> Option<i32>,
    winch: &AtomicBool,
) -> Result<RelayEnd, LaunchError> {
    // Non-blocking, so a command that has stopped reading cannot hold the
    // loop inside write() while its own output waits to be relayed.
    let flags = fcntl_getfl(master).map_err(pty_error)?;
    fcntl_setfl(master, flags | OFlags::NONBLOCK).map_err(pty_error)?;
    let mut stdin = host_in;
    let mut pending: Vec<u8> = Vec::new();
    let mut escape = Escape::new();
    let mut output = true;
    let mut buf = [0u8; CHUNK];
    loop {
        if let Some(code) = until() {
            if output {
                drain(master, host_out)?;
            }
            return Ok(RelayEnd::Exited(code));
        }
        if winch.swap(false, Ordering::SeqCst) {
            resize(master, host_out);
        }
        escape.expire(Instant::now(), &mut pending);

        // Reading the host stops while a chunk waits for the pty, so the
        // bytes stay in the terminal's own buffer instead of ours.
        let read_stdin = stdin.filter(|_| pending.is_empty());
        let mut fds = Vec::with_capacity(2);
        if let Some(fd) = read_stdin {
            fds.push(PollFd::from_borrowed_fd(fd, PollFlags::IN));
        }
        let mut events = PollFlags::empty();
        events.set(PollFlags::IN, output);
        events.set(PollFlags::OUT, !pending.is_empty());
        let master_at = (!events.is_empty()).then(|| {
            fds.push(PollFd::from_borrowed_fd(master, events));
            fds.len() - 1
        });
        let polled = poll(&mut fds, Some(&TICK_TIMESPEC));
        let stdin_ready = read_stdin.is_some() && !fds[0].revents().is_empty();
        let revents = master_at.map_or(PollFlags::empty(), |i| fds[i].revents());
        drop(fds);
        match polled {
            // EINTR means a signal arrived, which the next tick acts on.
            Err(Errno::INTR) => continue,
            Err(e) => return Err(pty_error(e)),
            Ok(_) => {}
        }

        if revents.contains(PollFlags::OUT) && !pending.is_empty() {
            match write(master, &pending) {
                Ok(n) => drop(pending.drain(..n)),
                Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                // The pty is gone; there is nothing left to type into.
                Err(_) => {
                    pending.clear();
                    stdin = None;
                }
            }
        }
        if let Some(fd) = read_stdin.filter(|_| stdin_ready) {
            match read(fd, &mut buf) {
                // Only a host stdin that is not a terminal ends this way,
                // which no plan produces: a pipe or a redirect is handed
                // to the sandbox directly. It serves a caller that relays
                // one anyway, and the tests that drive this with a socket.
                Ok(0) => {
                    stdin = None;
                    if let Some(eof) = eof_char(master) {
                        pending.push(eof);
                    }
                }
                Ok(n) => {
                    if escape.feed(&buf[..n], Instant::now(), &mut pending) {
                        return Ok(RelayEnd::Detached);
                    }
                }
                Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                // A terminal that hung up reads as an error.
                Err(_) => stdin = None,
            }
        }
        if output && revents.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            match read(master, &mut buf) {
                Ok(0) => output = false,
                // A terminal that cannot take the output — closed, gone,
                // or opened read-only — ends the relaying, never the run:
                // the command is still going and its status is still due.
                Ok(n) => output = write_all(host_out, &buf[..n]).is_ok(),
                Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                // EIO is the last slave closing: no more output is coming,
                // but the status may still be on its way.
                Err(_) => output = false,
            }
        }
    }
}

/// Move what the pty still holds to the host, for at most [`DRAIN`]:
/// the status arrives before the last output has been read out.
fn drain(master: BorrowedFd<'_>, host_out: BorrowedFd<'_>) -> Result<(), LaunchError> {
    let deadline = Instant::now() + DRAIN;
    let mut buf = [0u8; CHUNK];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        let mut fds = [PollFd::from_borrowed_fd(master, PollFlags::IN)];
        match poll(&mut fds, Some(&timespec(left))) {
            Err(Errno::INTR) => continue,
            Err(e) => return Err(pty_error(e)),
            Ok(_) => {}
        }
        if fds[0].revents().is_empty() {
            return Ok(());
        }
        match read(master, &mut buf) {
            Ok(0) => return Ok(()),
            // Nowhere to put it is the same as nothing left to take.
            Ok(n) if write_all(host_out, &buf[..n]).is_err() => return Ok(()),
            Ok(_) => {}
            Err(Errno::AGAIN) | Err(Errno::INTR) => {}
            Err(_) => return Ok(()),
        }
    }
}

/// Copy each pipe to the fd next to it until `until` reports an exit and
/// the pipes have run dry, or 200 ms after that at the latest. This is
/// the whole relay for a sandbox with no terminal: same poll loop, no
/// threads, and nothing that can hand the sandbox a terminal fd.
pub fn pump(
    pipes: &[(BorrowedFd<'_>, BorrowedFd<'_>)],
    until: &mut dyn FnMut() -> Option<i32>,
) -> Result<i32, LaunchError> {
    let mut open = vec![true; pipes.len()];
    let mut buf = [0u8; CHUNK];
    let mut exited: Option<(i32, Instant)> = None;
    loop {
        if exited.is_none()
            && let Some(code) = until()
        {
            exited = Some((code, Instant::now() + DRAIN));
        }
        if let Some((code, deadline)) = exited
            && (!open.contains(&true) || Instant::now() >= deadline)
        {
            return Ok(code);
        }
        let mut fds: Vec<PollFd> = Vec::with_capacity(pipes.len());
        let live: Vec<usize> = open
            .iter()
            .enumerate()
            .filter_map(|(i, o)| o.then_some(i))
            .collect();
        for i in &live {
            fds.push(PollFd::from_borrowed_fd(pipes[*i].0, PollFlags::IN));
        }
        let polled = poll(&mut fds, Some(&TICK_TIMESPEC));
        let ready: Vec<bool> = fds.iter().map(|f| !f.revents().is_empty()).collect();
        drop(fds);
        match polled {
            Err(Errno::INTR) => continue,
            Err(e) => return Err(pty_error(e)),
            Ok(_) => {}
        }
        for (slot, i) in live.into_iter().enumerate() {
            if !ready[slot] {
                continue;
            }
            match read(pipes[i].0, &mut buf) {
                // The sandbox closed this end; nothing more will come.
                Ok(0) => open[i] = false,
                // As for the relay: output bubbler cannot pass on is not
                // a reason to end a command that is still running.
                Ok(n) => open[i] = write_all(pipes[i].1, &buf[..n]).is_ok(),
                Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                Err(_) => open[i] = false,
            }
        }
    }
}

/// The pty's end-of-file character, or `None` when its line discipline
/// has no notion of one: `VEOF` is only acted on in canonical mode, so a
/// reader that turned `ICANON` off would just receive a stray byte.
fn eof_char(master: BorrowedFd<'_>) -> Option<u8> {
    let settings = tcgetattr(master).ok()?;
    settings
        .local_modes
        .contains(LocalModes::ICANON)
        .then(|| settings.special_codes[SpecialCodeIndex::VEOF])
}

/// Copy the host terminal's size onto the pty. The kernel then raises
/// `SIGWINCH` for the pty's foreground process group inside the sandbox.
fn resize(master: BorrowedFd<'_>, host: BorrowedFd<'_>) {
    if let Ok(size) = tcgetwinsize(host) {
        // Only the window size is at stake, and a host fd that is not a
        // terminal has none to copy.
        let _ = tcsetwinsize(master, size);
    }
}

/// Write every byte to the user's terminal, waiting for it when it is full.
fn write_all(fd: BorrowedFd<'_>, mut buf: &[u8]) -> Result<(), LaunchError> {
    while !buf.is_empty() {
        match write(fd, buf) {
            Ok(0) => return Err(pty_error(Errno::IO)),
            Ok(n) => buf = &buf[n..],
            Err(Errno::AGAIN) | Err(Errno::INTR) => {
                let mut fds = [PollFd::from_borrowed_fd(fd, PollFlags::OUT)];
                // Waiting is the whole point; a failed wait just retries.
                let _ = poll(&mut fds, Some(&TICK_TIMESPEC));
            }
            Err(e) => return Err(pty_error(e)),
        }
    }
    Ok(())
}

/// `Timespec` for `poll`, which takes no `Duration`.
fn timespec(d: Duration) -> Timespec {
    Timespec {
        tv_sec: d.as_secs() as Secs,
        tv_nsec: d.subsec_nanos() as Nsecs,
    }
}

fn pty_error(e: Errno) -> LaunchError {
    LaunchError::Pty(e.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};

    use rustix::termios::{OutputModes, Winsize};

    /// A pty pair standing in for the sandbox's terminal: canonical, but
    /// without echo or output processing, so a test sees exact bytes.
    fn pty_pair() -> Pty {
        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let master = openpt(flags).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let slave = ioctl_tiocgptpeer(&master, flags).unwrap();
        let mut t = tcgetattr(&slave).unwrap();
        t.local_modes.remove(LocalModes::ECHO);
        t.output_modes.remove(OutputModes::OPOST);
        tcsetattr(&slave, OptionalActions::Now, &t).unwrap();
        Pty { master, slave }
    }

    /// One read once `fd` has something, or `None` after `wait`.
    fn read_soon(fd: BorrowedFd<'_>, wait: Duration) -> Option<Vec<u8>> {
        let mut fds = [PollFd::from_borrowed_fd(fd, PollFlags::IN)];
        poll(&mut fds, Some(&timespec(wait))).unwrap();
        if fds[0].revents().is_empty() {
            return None;
        }
        let mut buf = [0u8; 256];
        let n = read(fd, &mut buf).unwrap();
        Some(buf[..n].to_vec())
    }

    /// Read from `fd` until it has delivered `want`, or fail.
    fn expect(fd: BorrowedFd<'_>, want: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.len() < want.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "timed out with {got:?}, wanted {want:?}");
            match read_soon(fd, left) {
                Some(bytes) if bytes.is_empty() => panic!("closed with {got:?}"),
                Some(bytes) => got.extend_from_slice(&bytes),
                None => {}
            }
        }
        assert_eq!(got, want);
    }

    /// A relay on its own thread, stopped by setting `stop`.
    struct Running {
        stop: Arc<AtomicBool>,
        winch: Arc<AtomicBool>,
        handle: JoinHandle<Result<RelayEnd, LaunchError>>,
    }

    fn spawn_relay(master: OwnedFd, host_in: Option<OwnedFd>, host_out: OwnedFd) -> Running {
        let stop = Arc::new(AtomicBool::new(false));
        let winch = Arc::new(AtomicBool::new(false));
        let (s, w) = (Arc::clone(&stop), Arc::clone(&winch));
        let handle = thread::spawn(move || {
            let mut until = || s.load(Ordering::SeqCst).then_some(0);
            relay(
                master.as_fd(),
                host_in.as_ref().map(|f| f.as_fd()),
                host_out.as_fd(),
                &mut until,
                &w,
            )
        });
        Running {
            stop,
            winch,
            handle,
        }
    }

    fn finish(r: Running) -> RelayEnd {
        r.stop.store(true, Ordering::SeqCst);
        r.handle.join().unwrap().unwrap()
    }

    #[test]
    fn the_plan_decides_each_fd_on_its_own() {
        use StdioTarget::{Inherit, Null, Pipe, Slave};
        let combos = [
            ([false, false, false], [Inherit, Inherit, Inherit]),
            ([true, false, false], [Slave, Inherit, Inherit]),
            ([false, true, false], [Inherit, Slave, Inherit]),
            ([false, false, true], [Inherit, Inherit, Slave]),
            ([true, true, false], [Slave, Slave, Inherit]),
            ([true, false, true], [Slave, Inherit, Slave]),
            ([false, true, true], [Inherit, Slave, Slave]),
            ([true, true, true], [Slave, Slave, Slave]),
        ];
        for (is_tty, want) in combos {
            let p = plan(TtyMode::Pty, is_tty);
            assert_eq!(p.fds, want, "pty mode with {is_tty:?}");
            assert_eq!(p.needs_pty(), is_tty.iter().any(|t| *t));
            assert_eq!(p.raw_mode(), is_tty[0]);
            assert!(p.pty.is_none());

            let p = plan(TtyMode::Passthrough, is_tty);
            assert_eq!(p.fds, [Inherit; 3], "passthrough with {is_tty:?}");
            assert!(!p.needs_pty() && !p.raw_mode());

            let p = plan(TtyMode::None, is_tty);
            assert_eq!(p.fds, [Null, Pipe, Pipe], "none with {is_tty:?}");
            assert!(!p.needs_pty() && !p.raw_mode());
        }
    }

    /// Three fds standing in for bubbler's own, `access` deciding how fd 0
    /// was opened: `RDONLY` is `bubbler run x < /dev/tty`.
    fn host_fds(access: OFlags) -> [OwnedFd; 3] {
        let null = Path::new("/dev/null");
        let open = |flags: OFlags| rustix::fs::open(null, flags, Mode::empty()).unwrap();
        [open(access), open(OFlags::RDWR), open(OFlags::RDWR)]
    }

    #[test]
    fn the_pty_writes_back_to_the_first_terminal_among_stdout_stderr_stdin() {
        use StdioTarget::{Inherit, Slave};
        let host = host_fds(OFlags::RDWR);
        let at = |fds: [StdioTarget; 3]| output_fd(&StdioPlan { fds, pty: None }, &host);
        assert_eq!(at([Slave, Slave, Slave]), Some(1));
        // stdout redirected to a file: the terminal is still stderr's.
        assert_eq!(at([Slave, Inherit, Slave]), Some(2));
        // Only stdin is a terminal, so that is where its echo must go.
        assert_eq!(at([Slave, Inherit, Inherit]), Some(0));
        assert_eq!(at([Inherit; 3]), None);
    }

    #[test]
    fn a_terminal_opened_read_only_is_no_place_to_write_output() {
        use StdioTarget::{Inherit, Slave};
        let host = host_fds(OFlags::RDONLY);
        let at = |fds: [StdioTarget; 3]| output_fd(&StdioPlan { fds, pty: None }, &host);
        // `bubbler run x < /dev/tty > out 2> err`: the one candidate is a
        // terminal that cannot be written to, so the caller must find a
        // sink of its own instead of failing on the first write.
        assert_eq!(at([Slave, Inherit, Inherit]), None);
        assert_eq!(at([Slave, Slave, Inherit]), Some(1));
    }

    #[test]
    fn modes_parse_by_name_only() {
        assert_eq!(TtyMode::from_str("pty").unwrap(), TtyMode::Pty);
        assert_eq!(
            TtyMode::from_str("passthrough").unwrap(),
            TtyMode::Passthrough
        );
        assert_eq!(TtyMode::from_str("none").unwrap(), TtyMode::None);
        assert_eq!(TtyMode::default(), TtyMode::Pty);
        assert!(matches!(
            TtyMode::from_str("PTY"),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn a_new_pty_carries_the_host_size_and_special_characters() {
        let host = pty_pair();
        tcsetwinsize(
            &host.slave,
            Winsize {
                ws_row: 11,
                ws_col: 33,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .unwrap();
        let mut t = tcgetattr(&host.slave).unwrap();
        t.special_codes[SpecialCodeIndex::VERASE] = 0x08;
        tcsetattr(&host.slave, OptionalActions::Now, &t).unwrap();

        let pty = allocate(host.slave.as_fd()).unwrap();
        let size = tcgetwinsize(&pty.slave).unwrap();
        assert_eq!((size.ws_row, size.ws_col), (11, 33));
        assert_eq!(
            tcgetattr(&pty.slave).unwrap().special_codes[SpecialCodeIndex::VERASE],
            0x08
        );
        // The same terminal is seen from bubbler's end.
        assert_eq!(tcgetwinsize(&pty.master).unwrap().ws_col, 33);
    }

    #[test]
    fn the_guard_enters_raw_mode_and_restores_the_terminal() {
        let pty = pty_pair();
        let before = tcgetattr(&pty.slave).unwrap().local_modes;
        {
            let _guard = RawGuard::new(pty.slave.as_fd()).unwrap();
            let raw = tcgetattr(&pty.slave).unwrap().local_modes;
            assert!(!raw.contains(LocalModes::ECHO));
            assert!(!raw.contains(LocalModes::ICANON));
            assert!(!raw.contains(LocalModes::ISIG));
        }
        assert_eq!(tcgetattr(&pty.slave).unwrap().local_modes, before);
    }

    #[test]
    fn restoring_twice_is_the_same_as_restoring_once() {
        let pty = pty_pair();
        let before = tcgetattr(&pty.slave).unwrap().local_modes;
        let mut guard = RawGuard::new(pty.slave.as_fd()).unwrap();
        guard.restore();
        let mut t = tcgetattr(&pty.slave).unwrap();
        t.local_modes.remove(LocalModes::ISIG);
        tcsetattr(&pty.slave, OptionalActions::Now, &t).unwrap();
        // A restored guard owns nothing, so neither this call nor the drop
        // may undo a setting made after it.
        guard.restore();
        drop(guard);
        let after = tcgetattr(&pty.slave).unwrap().local_modes;
        assert_eq!(after, before - LocalModes::ISIG);
    }

    #[test]
    fn the_relay_moves_bytes_in_both_directions() {
        let Pty { master, slave } = pty_pair();
        let (host_in, test_in) = UnixStream::pair().unwrap();
        let (host_out, test_out) = UnixStream::pair().unwrap();
        let r = spawn_relay(master, Some(host_in.into()), host_out.into());
        write(&test_in, b"typed\n").unwrap();
        expect(slave.as_fd(), b"typed\n");
        write(&slave, b"printed\n").unwrap();
        expect(test_out.as_fd(), b"printed\n");
        assert_eq!(finish(r), RelayEnd::Exited(0));
    }

    #[test]
    fn output_the_host_cannot_take_ends_the_relaying_and_not_the_run() {
        let Pty { master, slave } = pty_pair();
        let (host_in, test_in) = UnixStream::pair().unwrap();
        // Every write to a read-only descriptor fails with EBADF, which is
        // what a terminal opened `< /dev/tty` does to the first chunk of
        // output the sandbox produces.
        let read_only = rustix::fs::open(
            Path::new("/dev/null"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let r = spawn_relay(master, Some(host_in.into()), read_only);
        write(&slave, b"output nobody can take\n").unwrap();
        // The relay is still there: what the user types still arrives.
        write(&test_in, b"typed\n").unwrap();
        expect(slave.as_fd(), b"typed\n");
        assert_eq!(finish(r), RelayEnd::Exited(0));
    }

    #[test]
    fn stdin_eof_sends_the_end_of_file_character_and_keeps_the_pty() {
        let Pty { master, slave } = pty_pair();
        let (host_in, test_in) = UnixStream::pair().unwrap();
        let (host_out, _test_out) = UnixStream::pair().unwrap();
        let r = spawn_relay(master, Some(host_in.into()), host_out.into());
        write(&test_in, b"line\n").unwrap();
        expect(slave.as_fd(), b"line\n");
        drop(test_in);
        // In canonical mode the EOF character is a zero-length read, not a byte.
        assert_eq!(
            read_soon(slave.as_fd(), Duration::from_secs(5)),
            Some(Vec::new())
        );
        // The master stayed open, so the pty still works both ways.
        write(&slave, b"still here\n").unwrap();
        assert_eq!(finish(r), RelayEnd::Exited(0));
    }

    #[test]
    fn three_escapes_detach_without_reaching_the_sandbox() {
        let Pty { master, slave } = pty_pair();
        let (host_in, test_in) = UnixStream::pair().unwrap();
        let (host_out, _test_out) = UnixStream::pair().unwrap();
        let r = spawn_relay(
            master.try_clone().unwrap(),
            Some(host_in.into()),
            host_out.into(),
        );
        write(&test_in, &[ESCAPE, ESCAPE, ESCAPE]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !r.handle.is_finished() {
            assert!(Instant::now() < deadline, "the relay did not detach");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(r.handle.join().unwrap().unwrap(), RelayEnd::Detached);
        // What the test writes now is all the pty has ever been given.
        write(&master, b"\n").unwrap();
        expect(slave.as_fd(), b"\n");
    }

    #[test]
    fn escapes_the_user_meant_to_type_reach_the_sandbox() {
        let Pty { master, slave } = pty_pair();
        let (host_in, test_in) = UnixStream::pair().unwrap();
        let (host_out, _test_out) = UnixStream::pair().unwrap();
        let r = spawn_relay(master, Some(host_in.into()), host_out.into());
        write(&test_in, &[ESCAPE, ESCAPE, b'x', b'\n']).unwrap();
        expect(slave.as_fd(), &[ESCAPE, ESCAPE, b'x', b'\n']);
        assert_eq!(finish(r), RelayEnd::Exited(0));
    }

    #[test]
    fn output_written_before_the_exit_is_drained() {
        let Pty { master, slave } = pty_pair();
        let (host_out, test_out) = UnixStream::pair().unwrap();
        let host_out = OwnedFd::from(host_out);
        write(&slave, b"last words\n").unwrap();
        let winch = AtomicBool::new(false);
        let mut until = || Some(7);
        let started = Instant::now();
        let end = relay(master.as_fd(), None, host_out.as_fd(), &mut until, &winch).unwrap();
        assert_eq!(end, RelayEnd::Exited(7));
        // The slave is still open, so the drain ends on its own deadline.
        assert!(started.elapsed() < Duration::from_secs(1));
        expect(test_out.as_fd(), b"last words\n");
    }

    #[test]
    fn a_window_change_is_copied_onto_the_pty() {
        let Pty { master, slave } = pty_pair();
        let host = pty_pair();
        let size = Winsize {
            ws_row: 13,
            ws_col: 71,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        tcsetwinsize(&host.slave, size).unwrap();
        let r = spawn_relay(master, None, host.slave);
        r.winch.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(5);
        while tcgetwinsize(&slave).unwrap().ws_col != 71 {
            assert!(Instant::now() < deadline, "the size never reached the pty");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(tcgetwinsize(&slave).unwrap().ws_row, 13);
        assert_eq!(finish(r), RelayEnd::Exited(0));
        drop(host.master);
    }

    #[test]
    fn the_pump_copies_each_pipe_to_its_own_destination() {
        let (r_out, w_out) = rustix::pipe::pipe().unwrap();
        let (r_err, w_err) = rustix::pipe::pipe().unwrap();
        let (host_out, test_out) = UnixStream::pair().unwrap();
        let (host_err, test_err) = UnixStream::pair().unwrap();
        write(&w_out, b"to stdout\n").unwrap();
        write(&w_err, b"to stderr\n").unwrap();
        // The sandbox is gone: its pipes are at EOF and the status is in.
        drop(w_out);
        drop(w_err);
        let mut until = || Some(5);
        let code = pump(
            &[
                (r_out.as_fd(), host_out.as_fd()),
                (r_err.as_fd(), host_err.as_fd()),
            ],
            &mut until,
        )
        .unwrap();
        assert_eq!(code, 5);
        expect(test_out.as_fd(), b"to stdout\n");
        expect(test_err.as_fd(), b"to stderr\n");
    }

    #[test]
    fn the_pump_stops_on_the_drain_deadline_when_a_pipe_stays_open() {
        let (read_end, write_end) = rustix::pipe::pipe().unwrap();
        let (host_out, test_out) = UnixStream::pair().unwrap();
        write(&write_end, b"last words\n").unwrap();
        let mut until = || Some(0);
        let started = Instant::now();
        // Something inside still holds the write end, so only the deadline
        // ends this; what was already written must still arrive.
        let code = pump(&[(read_end.as_fd(), host_out.as_fd())], &mut until).unwrap();
        assert_eq!(code, 0);
        assert!(started.elapsed() < Duration::from_secs(1));
        expect(test_out.as_fd(), b"last words\n");
        drop(write_end);
    }

    #[test]
    fn an_escape_run_only_detaches_inside_its_window() {
        let start = Instant::now();
        let mut esc = Escape::new();
        let mut out = Vec::new();
        assert!(!esc.feed(&[ESCAPE, ESCAPE], start, &mut out));
        assert!(out.is_empty(), "held escapes were forwarded early");
        // The third one comes too late to be part of the same run, and the
        // two held ones are the user's own bytes.
        assert!(!esc.feed(&[ESCAPE], start + Duration::from_secs(2), &mut out));
        assert_eq!(out, [ESCAPE, ESCAPE]);
    }

    #[test]
    fn held_escapes_are_released_when_the_window_passes() {
        let start = Instant::now();
        let mut esc = Escape::new();
        let mut out = Vec::new();
        assert!(!esc.feed(&[ESCAPE], start, &mut out));
        esc.expire(start + Duration::from_millis(500), &mut out);
        assert!(out.is_empty(), "released before the window passed");
        esc.expire(start + Duration::from_secs(2), &mut out);
        assert_eq!(out, [ESCAPE]);
    }

    #[test]
    fn a_run_of_three_escapes_detaches_and_ordinary_bytes_pass_through() {
        let start = Instant::now();
        let mut esc = Escape::new();
        let mut out = Vec::new();
        assert!(!esc.feed(b"hi", start, &mut out));
        assert_eq!(out, b"hi");
        out.clear();
        assert!(esc.feed(&[ESCAPE, ESCAPE, ESCAPE, b'z'], start, &mut out));
        assert!(out.is_empty(), "the detach sequence was forwarded");
    }
}
