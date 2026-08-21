//! The sandbox's terminal: pty allocation, the per-fd stdio decision, raw
//! mode on the user's terminal and the relay between the two.

use std::collections::VecDeque;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{FileType, Mode, OFlags, fcntl_getfl, fcntl_setfl};
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

/// A poll that only asks and never waits.
const NOW: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

/// How long output still in the pty is waited for after the command's
/// status arrives.
const DRAIN: Duration = Duration::from_millis(200);

/// How long a destination that is taking nothing at all is still waited
/// for before what is left is given up on. A terminal frees its write
/// room a buffer at a time, so a reader taking a little at a time leaves
/// `write` failing for a while without being stuck: readiness counts as
/// movement, and only the two together running out mean a stall.
const STALL: Duration = Duration::from_secs(5);

/// The whole of what handing over one destination's last output may
/// take, however well it is going. The backstop behind [`STALL`].
const FLUSH_MAX: Duration = Duration::from_secs(10);

/// How much longer that output is offered once the user is waiting for
/// bubbler to be gone. What the host will take at once it still gets.
const HURRY: Duration = Duration::from_millis(200);

/// How much output may wait for a host terminal that is not taking it.
/// Once this much is held the sandbox's side is left unread, so its pty
/// or pipe fills and it blocks in its own `write`: output is slowed to
/// the speed of the terminal, never dropped.
const PENDING_MAX: usize = 64 * 1024;

/// How much may wait once the command's status is in hand. Holding back
/// is pointless from then on — nothing can reach the pty or the pipe any
/// more — and what the kernel still buffers there, itself capped, is the
/// end of the output the user asked for.
const DRAIN_MAX: usize = 2 * PENDING_MAX;

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
/// the plan, never inherited by accident.
///
/// A descriptor the process was started without stands in as `/dev/null`,
/// so a plan can assume all three exist. The `bubbler` binary fills such
/// gaps at startup, before anything can take the number; this is the
/// backstop for a library caller that does not.
pub fn host_stdio() -> Result<[OwnedFd; 3], LaunchError> {
    let (i, o, e) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    let dup = |fd: BorrowedFd<'_>| match fd.try_clone_to_owned() {
        Ok(fd) => Ok(fd),
        Err(_) => null_stdio(),
    };
    Ok([dup(i.as_fd())?, dup(o.as_fd())?, dup(e.as_fd())?])
}

/// What to call each of bubbler's own stdio fds in a message: the relay
/// carries the output on dups of them, whose numbers name nothing the
/// user has heard of.
pub const FD_NAMES: [&str; 3] = ["stdin", "stdout", "stderr"];

/// Which of bubbler's fds the pty's output goes back out on: the first of
/// 1, 2 and 0 the pty stands in for, so output still reaches the terminal
/// when stdout alone is redirected. `None` when there is no pty, or when
/// the only candidate is a terminal opened read-only.
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
/// so the erase key, `IUTF8` and the window size the user has apply inside
/// the sandbox. `host_tty` must be a terminal, and not yet in raw mode.
// After `RawGuard::new` this would hand the sandbox a raw pty instead,
// with no echo and no line editing.
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

/// One destination of the sandbox's output, with a way to write to it
/// that cannot block.
///
/// `O_NONBLOCK` is what keeps a terminal that has stopped reading from
/// parking the loop that also services the exit check, the signal flags
/// and the detach sequence — but the flag belongs to the open file
/// description, which every duplicate of the descriptor shares, the
/// user's shell among them. So the destination is [`reopen`]ed where it
/// can be, and not even a `SIGKILL` leaves a flag behind; only where it
/// cannot is the host's own flag changed and put back.
struct Unblocked<'a> {
    host: BorrowedFd<'a>,
    /// A description of `host`'s file that only this relay holds.
    own: Option<OwnedFd>,
    /// What `host`'s own flags were, when they had to be changed.
    saved: Option<OFlags>,
}

/// Whether `fd` has an offset of its own, which a second description of
/// it would not share: it would write from 0 over what is already there.
/// True of the two seekable kinds a descriptor can be open on, and both
/// of them take a write without ever blocking on a reader.
fn seekable(fd: BorrowedFd<'_>) -> bool {
    rustix::fs::fstat(fd).is_ok_and(|stat| {
        matches!(
            FileType::from_raw_mode(stat.st_mode),
            FileType::RegularFile | FileType::BlockDevice
        )
    })
}

/// A second description of what `fd` is open on, non-blocking and held
/// by nobody else, or `None` when there can be none: a socket has no
/// such description, a [`seekable`] one would start over at offset 0,
/// and a descriptor that is not already writable would gain an access it
/// was denied — for the read end of a pipe, its *other* end.
fn reopen(fd: BorrowedFd<'_>) -> Option<OwnedFd> {
    if !writable(fd) || seekable(fd) {
        return None;
    }
    // A magic link: this re-opens the very file the descriptor is on,
    // not a path that could have been replaced in the meantime.
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    rustix::fs::open(
        path,
        // NOCTTY: a terminal opened here must not become bubbler's own.
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .ok()
}

/// Where a relay's warnings go: a description of fd 2 that only the
/// relay holds, non-blocking, opened once when the relay starts.
///
/// A warning about output the host would not take must never be written
/// to a host that would not take it — with the destination re-opened, fd
/// 2 is the user's own blocking terminal, and one `write` to a terminal
/// that has stopped reading parks the loop that answers the exit check
/// and the signals for good. So a warning that will not go through at
/// once is dropped: truncated output is worth a word, never a run that
/// only `SIGKILL` can end.
struct Warn {
    fd: Option<OwnedFd>,
    /// fd 2's own flags, when the duplicate had to change them.
    saved: Option<OFlags>,
}

impl Warn {
    fn new() -> Self {
        let Ok(dup) = std::io::stderr().as_fd().try_clone_to_owned() else {
            return Self {
                fd: None,
                saved: None,
            };
        };
        if let Some(own) = reopen(dup.as_fd()) {
            return Self {
                fd: Some(own),
                saved: None,
            };
        }
        // No second description to be had. A seekable fd takes a write
        // without blocking anyway, so it is left exactly as it is.
        if seekable(dup.as_fd()) {
            return Self {
                fd: Some(dup),
                saved: None,
            };
        }
        // What is left is a socket, or a terminal on a system without
        // `/proc`. The flag has to go on the description fd 2 shares,
        // and comes off again when the relay is done with it.
        let saved = fcntl_getfl(&dup).ok();
        if let Some(flags) = saved {
            // A failed set is the same case as no flag at all: the
            // warning is dropped below rather than written.
            let _ = fcntl_setfl(&dup, flags | OFlags::NONBLOCK);
        }
        Self {
            fd: Some(dup),
            saved,
        }
    }

    /// Say `msg`, or drop it. Never blocks, never fails a run, and never
    /// waits for a terminal that has stopped reading.
    fn say(&self, msg: &str) {
        let Some(fd) = &self.fd else {
            return;
        };
        if self.saved.is_some() {
            // The flag went on a description bubbler does not own alone
            // and may not have taken at all, so this asks first. Not a
            // guarantee — a ready destination can still take only part
            // of a message — but the last resort behind the flag.
            let mut fds = [PollFd::from_borrowed_fd(fd.as_fd(), PollFlags::OUT)];
            if !poll(&mut fds, Some(&NOW)).is_ok_and(|n| n > 0) {
                return;
            }
        }
        let _ = write(fd, msg.as_bytes());
    }
}

impl Drop for Warn {
    fn drop(&mut self) {
        if let (Some(fd), Some(flags)) = (&self.fd, self.saved) {
            // Nothing to report and nothing to do about it, as for the
            // destinations: this is the way out of a run.
            let _ = fcntl_setfl(fd, flags);
        }
    }
}

/// The destinations of one relay, each with a way to write to it that
/// cannot block, for as long as the relay runs.
struct NonBlocking<'a> {
    dests: Vec<Unblocked<'a>>,
}

impl<'a> NonBlocking<'a> {
    fn new(fds: &[BorrowedFd<'a>]) -> Self {
        // Every descriptor that has to have its own flags changed is read
        // before any of them is changed, so two of them sharing one open
        // file description cannot save each other's non-blocking flag.
        let mut dests: Vec<Unblocked<'a>> = fds
            .iter()
            .map(|fd| {
                let own = reopen(*fd);
                // A descriptor whose flags cannot be read is left alone;
                // that costs it its non-blocking writes and nothing else.
                let saved = match own {
                    Some(_) => None,
                    None => fcntl_getfl(fd).ok(),
                };
                Unblocked {
                    host: *fd,
                    own,
                    saved,
                }
            })
            .collect();
        for dest in &mut dests {
            if let Some(flags) = dest.saved {
                // A failed set is the same case: the write blocks as before.
                let _ = fcntl_setfl(dest.host, flags | OFlags::NONBLOCK);
            }
        }
        Self { dests }
    }

    /// Where to write destination `i`'s output.
    fn fd(&self, i: usize) -> BorrowedFd<'_> {
        let dest = &self.dests[i];
        dest.own.as_ref().map_or(dest.host, |fd| fd.as_fd())
    }
}

impl Drop for NonBlocking<'_> {
    fn drop(&mut self) {
        for dest in self.dests.drain(..) {
            if let Some(flags) = dest.saved {
                // Nothing to report and nothing to do about it: what this
                // restores is the user's terminal, on the way out of a run.
                let _ = fcntl_setfl(dest.host, flags);
            }
        }
    }
}

/// Where the sandbox's output goes, and what of it the host has not
/// taken yet. Bounded by [`PENDING_MAX`] while the command runs:
/// back-pressure reaches the sandbox through its own pty, and nothing is
/// ever dropped.
struct Out<'a> {
    fd: BorrowedFd<'a>,
    /// Where the output goes once `fd` refuses it: a descriptor that
    /// always takes it ([`null_stdio`]).
    sink: BorrowedFd<'a>,
    /// What to call `fd` when it stops taking the output.
    name: &'a str,
    /// Where a word about output that had to be dropped goes, without
    /// ever waiting for it to be taken.
    warn: &'a Warn,
    /// A ring: a partial write moves its front, never the rest of it.
    pending: VecDeque<u8>,
    /// How much may wait here before the sandbox's side is left unread.
    limit: usize,
    /// False once even the sink refuses the output: there is nowhere
    /// left to put it, and reading for it stops.
    open: bool,
}

impl<'a> Out<'a> {
    fn new(fd: BorrowedFd<'a>, sink: BorrowedFd<'a>, name: &'a str, warn: &'a Warn) -> Self {
        Self {
            fd,
            sink,
            name,
            warn,
            pending: VecDeque::new(),
            limit: PENDING_MAX,
            open: true,
        }
    }

    /// Stop holding the sandbox back: its status has arrived, so what is
    /// left in its pty or pipe is all there will ever be.
    fn relax(&mut self) {
        self.limit = DRAIN_MAX;
    }

    /// Whether output is waiting for the host to take it.
    fn waiting(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Whether no more may be read for it until the host catches up.
    fn full(&self) -> bool {
        self.pending.len() >= self.limit
    }

    fn push(&mut self, bytes: &[u8]) {
        self.pending.extend(bytes);
    }

    /// Hand the host what it will take right now. Never blocks: what is
    /// left waits for the next `POLLOUT`.
    fn flush(&mut self) {
        while self.open && !self.pending.is_empty() {
            // The front run of the ring; the rest follows next turn.
            let (front, _) = self.pending.as_slices();
            match write(self.fd, front) {
                Ok(0) => self.failed(Errno::IO),
                Ok(n) => drop(self.pending.drain(..n)),
                Err(Errno::AGAIN) | Err(Errno::INTR) => return,
                Err(e) => self.failed(e),
            }
        }
    }

    /// Hand over what is still waiting, for as long as the host keeps
    /// taking it: this is the end of the command's output, and a
    /// deadline is no reason to drop it.
    ///
    /// Bounded three ways, none of which ever blocks: [`FLUSH_MAX`] for
    /// the whole of it, [`STALL`] without either a write getting through
    /// or the host reporting itself writable, and [`HURRY`] from the
    /// moment `stop` says the user is waiting for bubbler to be gone.
    fn finish(&mut self, stop: &AtomicBool) {
        let start = Instant::now();
        let mut moved = start;
        let mut hurried = stop.load(Ordering::SeqCst).then_some(start);
        while self.open && !self.pending.is_empty() {
            let held = self.pending.len();
            self.flush();
            if self.pending.is_empty() {
                return;
            }
            let now = Instant::now();
            if self.pending.len() < held {
                moved = now;
            }
            if hurried.is_none() && stop.load(Ordering::SeqCst) {
                hurried = Some(now);
            }
            if hurried.is_some_and(|t| now.duration_since(t) >= HURRY) {
                self.give_up("bubbler is stopping");
                return;
            }
            if now.duration_since(moved) >= STALL || now.duration_since(start) >= FLUSH_MAX {
                self.give_up("it stopped being taken");
                return;
            }
            // Readiness counts as movement: a terminal frees its write
            // room a buffer at a time, so a reader taking a little at a
            // time leaves `write` failing for longer than a stall would
            // allow while never actually being stuck.
            let mut fds = [PollFd::from_borrowed_fd(self.fd, PollFlags::OUT)];
            if poll(&mut fds, Some(&TICK_TIMESPEC)).is_ok_and(|n| n > 0) {
                moved = Instant::now();
            }
        }
    }

    /// The one place output is dropped, and it is always announced.
    fn give_up(&mut self, why: &str) {
        self.warn.say(&format!(
            "bubbler: {} bytes of output to {} were dropped: {why}\n",
            self.pending.len(),
            self.name
        ));
        self.pending.clear();
    }

    /// Send what `fd` would not take to the sink from now on; when that
    /// already was the sink, the output has nowhere left to go.
    fn failed(&mut self, e: Errno) {
        if redirect(&mut self.fd, self.sink, e, self.name, self.warn) {
            return;
        }
        self.open = false;
        self.pending.clear();
    }
}

/// What this run's signal handlers have caught, as the relay reads it.
pub struct Caught<'a> {
    /// Set on `SIGWINCH` and cleared by the relay, which answers each
    /// one by copying the host terminal's size onto the pty.
    pub winch: &'a AtomicBool,
    /// Latched once a stop signal has been caught: the user is waiting
    /// for bubbler to be gone, so output still in hand is offered
    /// briefly rather than to the end.
    pub stop: &'a AtomicBool,
}

/// Carry bytes between the user's terminal and the sandbox's pty until
/// `until` reports an exit or the user detaches. `master` is never
/// closed: that would tear the pty down under a running command. Every
/// `caught.winch` is answered by copying `host_out`'s size onto the pty,
/// so `host_out` must be the user's terminal; the size it starts with is
/// the one [`allocate`] copied from the terminal it was given. Output
/// `host_out` refuses goes to `sink` instead, which must be a descriptor
/// that always accepts it ([`null_stdio`]).
///
/// Nothing here ever waits on the host: it is written to through a
/// description of bubbler's own that is non-blocking, and so is the one
/// warning that can come of it. A host that stops reading must never
/// park the loop that answers `until` and the signals. Up to 64 KiB of
/// output waits here, and beyond that the pty is left unread, so the
/// sandbox blocks on its own terminal rather than losing a byte; what it
/// still holds when the command's status arrives is read out too, and
/// handed over before this returns unless `caught.stop` says the user is
/// waiting for bubbler to be gone.
pub fn relay(
    master: BorrowedFd<'_>,
    host_in: Option<BorrowedFd<'_>>,
    host_out: BorrowedFd<'_>,
    out_name: &str,
    sink: BorrowedFd<'_>,
    until: &mut dyn FnMut() -> Option<i32>,
    caught: &Caught<'_>,
) -> Result<RelayEnd, LaunchError> {
    // Non-blocking, so a command that has stopped reading cannot hold the
    // loop inside write() while its own output waits to be relayed.
    let flags = fcntl_getfl(master).map_err(pty_error)?;
    fcntl_setfl(master, flags | OFlags::NONBLOCK).map_err(pty_error)?;
    // And a way to write to the host's end that cannot block either,
    // nor to say so afterwards.
    let dests = NonBlocking::new(&[host_out]);
    let warn = Warn::new();
    let mut out = Out::new(dests.fd(0), sink, out_name, &warn);
    let mut stdin = host_in;
    let mut typed: Vec<u8> = Vec::new();
    let mut escape = Escape::new();
    let mut reading = true;
    let mut buf = [0u8; CHUNK];
    loop {
        if let Some(code) = until() {
            drain(master, &mut out, reading, caught.stop);
            return Ok(RelayEnd::Exited(code));
        }
        if caught.winch.swap(false, Ordering::SeqCst) {
            resize(master, host_out);
        }
        escape.expire(Instant::now(), &mut typed);

        // Reading the host stops while a chunk waits for the pty, so the
        // bytes stay in the terminal's own buffer instead of ours.
        let read_stdin = stdin.filter(|_| typed.is_empty());
        let mut fds = Vec::with_capacity(3);
        let stdin_at = read_stdin.map(|fd| {
            fds.push(PollFd::from_borrowed_fd(fd, PollFlags::IN));
            fds.len() - 1
        });
        let mut events = PollFlags::empty();
        events.set(PollFlags::IN, reading && out.open && !out.full());
        events.set(PollFlags::OUT, !typed.is_empty());
        let master_at = (!events.is_empty()).then(|| {
            fds.push(PollFd::from_borrowed_fd(master, events));
            fds.len() - 1
        });
        let out_at = out.waiting().then(|| {
            fds.push(PollFd::from_borrowed_fd(out.fd, PollFlags::OUT));
            fds.len() - 1
        });
        let polled = poll(&mut fds, Some(&TICK_TIMESPEC));
        let stdin_ready = stdin_at.is_some_and(|i| !fds[i].revents().is_empty());
        let out_ready = out_at.is_some_and(|i| !fds[i].revents().is_empty());
        let revents = master_at.map_or(PollFlags::empty(), |i| fds[i].revents());
        drop(fds);
        match polled {
            // EINTR means a signal arrived, which the next tick acts on.
            Err(Errno::INTR) => continue,
            Err(e) => return Err(pty_error(e)),
            Ok(_) => {}
        }

        if out_ready {
            out.flush();
        }
        if revents.contains(PollFlags::OUT) && !typed.is_empty() {
            match write(master, &typed) {
                Ok(n) => drop(typed.drain(..n)),
                Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                // The pty is gone; there is nothing left to type into.
                Err(_) => {
                    typed.clear();
                    stdin = None;
                }
            }
        }
        if let Some(fd) = read_stdin.filter(|_| stdin_ready) {
            match read(fd, &mut buf) {
                // A terminal that hung up, or a stdin that is not one and
                // has run out. No plan produces the latter — a pipe or a
                // redirect goes to the sandbox directly — so in bubbler
                // this is the terminal going away.
                Ok(0) => {
                    stdin = None;
                    if let Some(eof) = eof_char(master) {
                        typed.push(eof);
                    }
                }
                Ok(n) => {
                    if escape.feed(&buf[..n], Instant::now(), &mut typed) {
                        // What the sandbox has already written is the
                        // user's to see, detach or not.
                        out.relax();
                        out.finish(caught.stop);
                        return Ok(RelayEnd::Detached);
                    }
                }
                Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                // A terminal that hung up reads as an error.
                Err(_) => stdin = None,
            }
        }
        if reading && revents.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            match read(master, &mut buf) {
                Ok(0) => reading = false,
                // A terminal that cannot take the output — closed, gone,
                // or opened read-only — costs the output its destination,
                // never the run: the command is still going, its status is
                // still due, and its pty must go on being emptied.
                Ok(n) => {
                    out.push(&buf[..n]);
                    out.flush();
                }
                Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                // EIO is the last slave closing: no more output is coming,
                // but the status may still be on its way.
                Err(_) => reading = false,
            }
        }
    }
}

/// Move what the pty and the output buffer still hold to the host: the
/// status arrives before the last output has been read out, and the host
/// may still be behind. [`DRAIN`] bounds how long more is read out of
/// the pty, with [`DRAIN_MAX`] to hold it in, and what has been read by
/// then is handed over for as long as the host takes it. `reading` says
/// whether the master is worth reading at all. Nothing here is worth
/// failing a finished run over, so every error just ends it.
fn drain(master: BorrowedFd<'_>, out: &mut Out<'_>, mut reading: bool, stop: &AtomicBool) {
    out.relax();
    let deadline = Instant::now() + DRAIN;
    let mut buf = [0u8; CHUNK];
    while reading && out.open {
        out.flush();
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut fds = Vec::with_capacity(2);
        let master_at = (!out.full()).then(|| {
            fds.push(PollFd::from_borrowed_fd(master, PollFlags::IN));
            fds.len() - 1
        });
        if out.waiting() {
            fds.push(PollFd::from_borrowed_fd(out.fd, PollFlags::OUT));
        }
        match poll(&mut fds, Some(&timespec(left))) {
            Err(Errno::INTR) => continue,
            // A timeout is the deadline: no more is read out of the pty.
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let ready = master_at.is_some_and(|i| !fds[i].revents().is_empty());
        drop(fds);
        if !ready {
            continue;
        }
        match read(master, &mut buf) {
            Ok(0) => reading = false,
            Ok(n) => out.push(&buf[..n]),
            Err(Errno::AGAIN) | Err(Errno::INTR) => {}
            Err(_) => reading = false,
        }
    }
    // The deadline bounds how long more is read out of the pty, never
    // what has already been read: that is the end of the command's
    // output, and it is handed over for as long as the host is taking it
    // and the user is not waiting.
    out.finish(stop);
}

/// Copy each pipe to the fd next to it until `until` reports an exit and
/// the pipes have run dry, or 200 ms after that at the latest. This is
/// the whole relay for a sandbox with no terminal: same poll loop, no
/// threads, and nothing that can hand the sandbox a terminal fd. A
/// destination that stops taking output is replaced by `sink`, so a
/// reader that left early (`bubbler run ... | head`) cannot leave the
/// command blocked on a full pipe. What the pipes hold when the status
/// arrives is handed over as in the relay, and `stop` cuts that short
/// the same way.
pub fn pump(
    pipes: &[(BorrowedFd<'_>, BorrowedFd<'_>, &str)],
    sink: BorrowedFd<'_>,
    until: &mut dyn FnMut() -> Option<i32>,
    stop: &AtomicBool,
) -> Result<i32, LaunchError> {
    let host: Vec<BorrowedFd<'_>> = pipes.iter().map(|(_, to, _)| *to).collect();
    // As for the relay: a destination that stops reading may cost the
    // output its place, never the loop that is waiting for the exit.
    let dests = NonBlocking::new(&host);
    let warn = Warn::new();
    let mut outs: Vec<Out<'_>> = pipes
        .iter()
        .enumerate()
        .map(|(i, (_, _, name))| Out::new(dests.fd(i), sink, name, &warn))
        .collect();
    let mut open = vec![true; pipes.len()];
    let mut buf = [0u8; CHUNK];
    let mut exited: Option<(i32, Instant)> = None;
    loop {
        if exited.is_none()
            && let Some(code) = until()
        {
            exited = Some((code, Instant::now() + DRAIN));
            for out in &mut outs {
                out.relax();
            }
        }
        let waiting = outs.iter().any(Out::waiting);
        if let Some((code, deadline)) = exited
            && ((!open.contains(&true) && !waiting) || Instant::now() >= deadline)
        {
            // As in the relay: the deadline ends the reading, and what
            // was read is handed over while the host is taking it.
            for out in &mut outs {
                out.finish(stop);
            }
            return Ok(code);
        }
        let mut fds: Vec<PollFd> = Vec::with_capacity(pipes.len() * 2);
        // Which fd each poll slot belongs to: the pipe of `i` when
        // `read`, the destination of `i` when not.
        let mut slots: Vec<(usize, bool)> = Vec::with_capacity(pipes.len() * 2);
        for (i, out) in outs.iter().enumerate() {
            if open[i] && out.open && !out.full() {
                fds.push(PollFd::from_borrowed_fd(pipes[i].0, PollFlags::IN));
                slots.push((i, true));
            }
            if out.waiting() {
                fds.push(PollFd::from_borrowed_fd(out.fd, PollFlags::OUT));
                slots.push((i, false));
            }
        }
        let polled = poll(&mut fds, Some(&TICK_TIMESPEC));
        let ready: Vec<bool> = fds.iter().map(|f| !f.revents().is_empty()).collect();
        drop(fds);
        match polled {
            Err(Errno::INTR) => continue,
            Err(e) => return Err(pty_error(e)),
            Ok(_) => {}
        }
        for (slot, (i, read_pipe)) in slots.into_iter().enumerate() {
            if !ready[slot] {
                continue;
            }
            if read_pipe {
                match read(pipes[i].0, &mut buf) {
                    // The sandbox closed this end; nothing more will come.
                    Ok(0) => open[i] = false,
                    // As for the relay: output bubbler cannot pass on goes
                    // to the sink, and this pipe keeps being emptied.
                    Ok(n) => {
                        outs[i].push(&buf[..n]);
                        outs[i].flush();
                    }
                    Err(Errno::AGAIN) | Err(Errno::INTR) => {}
                    Err(_) => open[i] = false,
                }
            } else {
                outs[i].flush();
            }
            // With nowhere left to put this pipe's output there is no
            // reason to go on reading it.
            if !outs[i].open {
                open[i] = false;
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

/// Send what `dest` would not take to `sink` from now on, and say so
/// once, calling it `what`. `false` when `dest` already was the sink:
/// there is nowhere left to put the output, and the copy stops.
///
/// Reading the sandbox side has to go on either way — a pty or a pipe
/// nobody empties fills up, and the command blocks in `write` forever.
fn redirect<'a>(
    dest: &mut BorrowedFd<'a>,
    sink: BorrowedFd<'a>,
    e: Errno,
    what: &str,
    warn: &Warn,
) -> bool {
    if dest.as_raw_fd() == sink.as_raw_fd() {
        return false;
    }
    // Truncated output is worth a word, and a warning that cannot be
    // written either (the terminal is what just failed) is nothing to act
    // on.
    warn.say(&format!(
        "bubbler: output to {what} failed: {}; discarding further output\n",
        std::io::Error::from(e)
    ));
    *dest = sink;
    true
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
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
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

    /// A relay on its own thread, stopped by setting `stop`. `hurry`
    /// stands in for a caught signal: the run ends as it would after the
    /// command's own exit unless a test sets it.
    struct Running {
        stop: Arc<AtomicBool>,
        hurry: Arc<AtomicBool>,
        winch: Arc<AtomicBool>,
        handle: JoinHandle<Result<RelayEnd, LaunchError>>,
    }

    fn spawn_relay(master: OwnedFd, host_in: Option<OwnedFd>, host_out: OwnedFd) -> Running {
        let stop = Arc::new(AtomicBool::new(false));
        let hurry = Arc::new(AtomicBool::new(false));
        let winch = Arc::new(AtomicBool::new(false));
        let (s, h, w) = (Arc::clone(&stop), Arc::clone(&hurry), Arc::clone(&winch));
        let handle = thread::spawn(move || {
            let mut until = || s.load(Ordering::SeqCst).then_some(0);
            let sink = null_stdio().unwrap();
            relay(
                master.as_fd(),
                host_in.as_ref().map(|f| f.as_fd()),
                host_out.as_fd(),
                FD_NAMES[1],
                sink.as_fd(),
                &mut until,
                &Caught {
                    winch: &w,
                    stop: &h,
                },
            )
        });
        Running {
            stop,
            hurry,
            winch,
            handle,
        }
    }

    /// Stop the relay and wait for it, but never for longer than `limit`:
    /// a relay parked in a write is the bug several of these tests are
    /// about, and joining one would hang the whole run.
    fn finish_within(r: Running, limit: Duration) -> RelayEnd {
        r.stop.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + limit;
        while !r.handle.is_finished() {
            assert!(
                Instant::now() < deadline,
                "the relay did not end in {limit:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
        r.handle.join().unwrap().unwrap()
    }

    fn finish(r: Running) -> RelayEnd {
        finish_within(r, Duration::from_secs(5))
    }

    /// Held while fd 2 is not what it was, so two tests moving it at once
    /// cannot restore each other's and swallow the rest of the run's
    /// output.
    static QUIET: Mutex<()> = Mutex::new(());

    /// Point fd 2 somewhere else while the guard lives, and put it back
    /// afterwards. Several tests make the relay report a destination that
    /// refuses its output, and that warning is the expected result, not
    /// something to print through a test run; one points fd 2 at the very
    /// destination that refuses it, which is what a real run does.
    struct StderrOn {
        saved: OwnedFd,
        _lock: MutexGuard<'static, ()>,
    }

    impl StderrOn {
        fn at(fd: OwnedFd) -> Self {
            // A poisoned lock only means such a test panicked, and its
            // guard put fd 2 back on the way out.
            let lock = QUIET.lock().unwrap_or_else(PoisonError::into_inner);
            let saved = std::io::stderr()
                .as_fd()
                .try_clone_to_owned()
                .expect("duplicating stderr");
            rustix::stdio::dup2_stderr(fd).expect("moving stderr");
            Self { saved, _lock: lock }
        }

        fn null() -> Self {
            Self::at(null_stdio().unwrap())
        }
    }

    impl Drop for StderrOn {
        fn drop(&mut self) {
            rustix::stdio::dup2_stderr(&self.saved).expect("restoring stderr");
        }
    }

    /// The byte at `i` of the flood one test sends through a pty: a cycle
    /// long enough that output lost anywhere in the middle shows up as a
    /// mismatch rather than as a shorter run of the same byte.
    fn flood_byte(i: usize) -> u8 {
        (i % 251) as u8
    }

    /// Fill a pipe to its capacity, so every further write to it blocks.
    /// The flag is put back: what the code under test does with a full
    /// destination is the point.
    fn fill(fd: BorrowedFd<'_>) {
        let flags = fcntl_getfl(fd).unwrap();
        fcntl_setfl(fd, flags | OFlags::NONBLOCK).unwrap();
        while write(fd, &[b'x'; 4096]).is_ok() {}
        fcntl_setfl(fd, flags).unwrap();
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
    fn output_the_host_cannot_take_is_discarded_and_the_pty_kept_empty() {
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
        let quiet = StderrOn::null();
        let r = spawn_relay(master, Some(host_in.into()), read_only);
        // More than the pty holds: a relay that stopped reading here would
        // leave the writer blocked in the sandbox for good.
        let mut sent = 0;
        while sent < 256 * 1024 {
            sent += write(&slave, &[b'x'; 4096]).unwrap();
        }
        // And it is still a relay: what the user types still arrives.
        write(&test_in, b"typed\n").unwrap();
        expect(slave.as_fd(), b"typed\n");
        assert_eq!(finish(r), RelayEnd::Exited(0));
        drop(quiet);
    }

    #[test]
    fn a_host_that_never_reads_holds_the_sandbox_back_instead_of_the_relay() {
        let Pty { master, slave } = pty_pair();
        // A terminal that has stopped taking anything: the pipe fills and
        // stays full, because nothing ever reads its other end.
        let (reader, host_out) = rustix::pipe::pipe().unwrap();
        // A copy of the host's descriptor, to read its flags back from
        // afterwards: what the relay does to it, the user's shell sees.
        let probe = host_out.try_clone().unwrap();
        let flags = fcntl_getfl(&probe).unwrap();
        let sent = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let (s, d) = (Arc::clone(&sent), Arc::clone(&done));
        // The sandbox floods its pty with far more than anything on the
        // way to the host can hold.
        let feeder = thread::spawn(move || {
            let mut n = 0usize;
            while n < 1024 * 1024 {
                let chunk: Vec<u8> = (n..n + 4096).map(flood_byte).collect();
                match write(&slave, &chunk) {
                    // The relay has ended and taken the master with it.
                    Ok(0) | Err(_) => break,
                    Ok(k) => n += k,
                }
                s.store(n, Ordering::SeqCst);
            }
            d.store(true, Ordering::SeqCst);
        });
        let r = spawn_relay(master, None, host_out);
        // Wait until nothing downstream can take another byte: the pipe is
        // full, the relay holds all it may, and the sandbox is blocked in
        // its own write.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last = usize::MAX;
        while sent.load(Ordering::SeqCst) != last {
            assert!(Instant::now() < deadline, "the flood never stalled");
            last = sent.load(Ordering::SeqCst);
            thread::sleep(Duration::from_millis(100));
        }
        assert!(last > 0, "the relay moved nothing at all");
        assert!(
            !done.load(Ordering::SeqCst),
            "the flood was swallowed instead of held back"
        );
        // The whole point: the exit check is still serviced, so a status
        // ends the relay while the host is stuck. What it still held is
        // offered for [`STALL`] and then given up on, which is one of the
        // two cases where output is dropped, and it says so.
        let quiet = StderrOn::null();
        let end = finish_within(r, DRAIN + STALL + Duration::from_secs(1));
        drop(quiet);
        assert_eq!(end, RelayEnd::Exited(0));
        assert_eq!(
            fcntl_getfl(&probe).unwrap(),
            flags,
            "the relay left the host's own descriptor changed"
        );
        // And nothing was dropped on the way: what the host finally reads
        // is the beginning of the flood, byte for byte.
        let mut got = Vec::new();
        while let Some(bytes) = read_soon(reader.as_fd(), Duration::from_millis(200)) {
            if bytes.is_empty() {
                break;
            }
            got.extend_from_slice(&bytes);
        }
        assert!(got.len() >= 4096, "the host got {} bytes", got.len());
        for (i, byte) in got.iter().enumerate() {
            assert_eq!(*byte, flood_byte(i), "output was lost before byte {i}");
        }
        feeder.join().unwrap();
    }

    #[test]
    fn a_slow_host_gets_every_byte_before_the_relay_leaves() {
        const TOTAL: usize = 100 * 1024;
        let Pty { master, slave } = pty_pair();
        let (reader, host_out) = rustix::pipe::pipe().unwrap();
        // A host taking about 40 KB a second: whatever the relay is still
        // holding when the command ends has to wait for it, and none of
        // it may be dropped because the wait ran long.
        let taker = thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(100));
                let mut fds = [PollFd::from_borrowed_fd(reader.as_fd(), PollFlags::IN)];
                if poll(&mut fds, Some(&timespec(Duration::from_millis(500)))).is_err() {
                    break;
                }
                if fds[0].revents().is_empty() {
                    continue;
                }
                match read(&reader, &mut buf) {
                    // The relay has gone and closed its end.
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            got
        });
        let r = spawn_relay(master, None, host_out);
        let feeder = thread::spawn(move || {
            let mut n = 0usize;
            while n < TOTAL {
                let chunk: Vec<u8> = (n..(n + 4096).min(TOTAL)).map(flood_byte).collect();
                match write(&slave, &chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => n += k,
                }
            }
            n
        });
        assert_eq!(feeder.join().unwrap(), TOTAL);
        // Everything is out of the pty and into the relay before the
        // status arrives, so what is at stake is only what it holds.
        thread::sleep(Duration::from_millis(300));
        assert_eq!(
            finish_within(r, Duration::from_secs(20)),
            RelayEnd::Exited(0)
        );
        let got = taker.join().unwrap();
        assert_eq!(got.len(), TOTAL, "output was dropped on the way out");
        for (i, byte) in got.iter().enumerate() {
            assert_eq!(*byte, flood_byte(i), "output was lost before byte {i}");
        }
    }

    #[test]
    fn everything_written_before_the_exit_reaches_a_slow_host() {
        let Pty { master, slave } = pty_pair();
        let (reader, host_out) = rustix::pipe::pipe().unwrap();
        // Nothing is read until the command has ended, so by then the
        // pipe, the relay and the pty all hold as much as they may.
        let start = Arc::new(AtomicBool::new(false));
        let go = Arc::clone(&start);
        let taker = thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_secs(60);
            while !go.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(20));
            }
            // From here on about 40 KB a second, as a terminal that is
            // slow but never stops.
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(100));
                let mut fds = [PollFd::from_borrowed_fd(reader.as_fd(), PollFlags::IN)];
                if poll(&mut fds, Some(&timespec(Duration::from_millis(500)))).is_err() {
                    break;
                }
                if fds[0].revents().is_empty() {
                    continue;
                }
                match read(&reader, &mut buf) {
                    // The relay has gone and closed its end.
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            got
        });
        let r = spawn_relay(master, None, host_out);
        // Write until the pty itself will take no more: that is every
        // buffer between the sandbox and the host filled to the brim.
        let flags = fcntl_getfl(&slave).unwrap();
        fcntl_setfl(&slave, flags | OFlags::NONBLOCK).unwrap();
        let mut sent = 0usize;
        let mut stuck = 0;
        let deadline = Instant::now() + Duration::from_secs(30);
        // Nothing is read until the stop, so once the pty has refused
        // three times running, nothing downstream is moving either.
        while stuck < 3 {
            assert!(Instant::now() < deadline, "the pty never filled up");
            let chunk: Vec<u8> = (sent..sent + 4096).map(flood_byte).collect();
            match write(&slave, &chunk) {
                Ok(0) => break,
                Ok(n) => {
                    sent += n;
                    stuck = 0;
                }
                Err(Errno::AGAIN) => {
                    stuck += 1;
                    thread::sleep(Duration::from_millis(300));
                }
                Err(_) => break,
            }
        }
        assert!(sent > PENDING_MAX, "only {sent} bytes were ever written");
        // The command ends here, so nothing more can reach the pty and
        // every byte already in one is the user's to see.
        start.store(true, Ordering::SeqCst);
        assert_eq!(
            finish_within(r, Duration::from_secs(30)),
            RelayEnd::Exited(0)
        );
        let got = taker.join().unwrap();
        assert_eq!(got.len(), sent, "output was dropped on the way out");
        for (i, byte) in got.iter().enumerate() {
            assert_eq!(*byte, flood_byte(i), "output was lost before byte {i}");
        }
    }

    #[test]
    fn a_detach_hands_over_the_output_that_is_still_waiting() {
        let Pty { master, slave } = pty_pair();
        let (host_in, test_in) = UnixStream::pair().unwrap();
        let (reader, host_out) = rustix::pipe::pipe().unwrap();
        // Nothing more fits until the host reads, so what the sandbox
        // writes now is still in the relay when the user detaches.
        fill(host_out.as_fd());
        let r = spawn_relay(master, Some(host_in.into()), host_out);
        write(&slave, b"MARKER\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        write(&test_in, &[ESCAPE, ESCAPE, ESCAPE]).unwrap();
        thread::sleep(Duration::from_millis(300));
        assert!(
            !r.handle.is_finished(),
            "the relay left with the sandbox's output still in hand"
        );
        // The host takes its output again; the detach must hand over what
        // it held before it goes.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while !got.ends_with(b"MARKER\n") {
            assert!(Instant::now() < deadline, "the marker never arrived");
            match read_soon(reader.as_fd(), Duration::from_millis(200)) {
                Some(bytes) if bytes.is_empty() => panic!("the host end was closed"),
                Some(bytes) => got.extend_from_slice(&bytes),
                None => {}
            }
        }
        assert_eq!(r.handle.join().unwrap().unwrap(), RelayEnd::Detached);
    }

    #[test]
    fn a_read_only_destination_is_never_reopened_for_writing() {
        let (read_end, write_end) = rustix::pipe::pipe().unwrap();
        // `/proc/self/fd` on the read end of a pipe opens its *other*
        // end: a destination that could not be written to would quietly
        // become one, and the output the sink was there for would go
        // into the pipe instead.
        assert!(reopen(read_end.as_fd()).is_none());
        // What is already open for writing gains nothing it did not have.
        assert!(reopen(write_end.as_fd()).is_some());
    }

    #[test]
    fn a_warning_never_parks_the_relay_on_a_wedged_terminal() {
        let Pty { master, slave } = pty_pair();
        // The destination and fd 2 are one and the same wedged pipe,
        // which is what a real run has: with the destination re-opened,
        // fd 2 is still the user's own blocking terminal. So the relay
        // has output it cannot hand over and nowhere to say so either,
        // and saying so must not be what ends it.
        let (reader, host_out) = rustix::pipe::pipe().unwrap();
        fill(host_out.as_fd());
        let wedged = StderrOn::at(host_out.try_clone().unwrap());
        let r = spawn_relay(master, None, host_out);
        write(&slave, b"nowhere to go\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        // A caught signal, so the last of the output is offered for
        // [`HURRY`] and the warning about dropping it comes right after.
        r.hurry.store(true, Ordering::SeqCst);
        let end = finish_within(r, Duration::from_secs(2));
        drop(wedged);
        assert_eq!(end, RelayEnd::Exited(0));
        drop(reader);
    }

    #[test]
    fn a_caught_signal_cuts_the_last_of_the_output_short() {
        let Pty { master, slave } = pty_pair();
        let (reader, host_out) = rustix::pipe::pipe().unwrap();
        fill(host_out.as_fd());
        let quiet = StderrOn::null();
        let r = spawn_relay(master, None, host_out);
        write(&slave, b"waiting\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        r.hurry.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let end = finish_within(r, Duration::from_secs(2));
        drop(quiet);
        assert_eq!(end, RelayEnd::Exited(0));
        // [`HURRY`], not [`STALL`]: a host that is merely behind would be
        // waited for, but the user is waiting for bubbler.
        assert!(
            started.elapsed() < STALL,
            "the signal waited out the stall in {:?}",
            started.elapsed()
        );
        drop(reader);
    }

    #[test]
    fn a_terminal_taking_a_little_at_a_time_is_not_a_stalled_one() {
        const HELD: usize = 8192;
        let Pty { master, slave } = pty_pair();
        let Pty {
            master: host_master,
            slave: host_slave,
        } = pty_pair();
        // A terminal with no room left, so what the sandbox writes now
        // is still the relay's to hand over when the command ends.
        fill(host_slave.as_fd());
        let done = Arc::new(AtomicBool::new(false));
        let d = Arc::clone(&done);
        let taker = thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                // 256 bytes every 200 ms while the relay hands over what
                // it holds. A pty frees its write room a buffer at a
                // time, so `write` goes on failing for seconds at a
                // stretch with the terminal not stuck in the least; then
                // as fast as it likes, since what is being tested is
                // what the relay handed over, not how long this takes.
                let slow = !d.load(Ordering::SeqCst);
                let want = match slow {
                    true => 256,
                    false => buf.len(),
                };
                if slow {
                    thread::sleep(Duration::from_millis(200));
                }
                let mut fds = [PollFd::from_borrowed_fd(host_master.as_fd(), PollFlags::IN)];
                if poll(&mut fds, Some(&timespec(Duration::from_millis(200)))).is_err() {
                    break;
                }
                if fds[0].revents().is_empty() {
                    if !slow {
                        break;
                    }
                    continue;
                }
                match read(&host_master, &mut buf[..want]) {
                    // The relay has gone and closed its end.
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            got
        });
        let r = spawn_relay(master, None, host_slave);
        let payload: Vec<u8> = (0..HELD).map(flood_byte).collect();
        let mut sent = 0;
        while sent < HELD {
            sent += write(&slave, &payload[sent..]).unwrap();
        }
        thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        assert_eq!(
            finish_within(r, Duration::from_secs(40)),
            RelayEnd::Exited(0)
        );
        let waited = started.elapsed();
        done.store(true, Ordering::SeqCst);
        let got = taker.join().unwrap();
        // What the terminal was filled with first, and then every byte
        // the relay was holding when the command ended.
        assert!(
            got.len() >= HELD && got[got.len() - HELD..] == payload,
            "a slow terminal was taken for a stalled one: {} bytes read",
            got.len()
        );
        // And it really was handed over against a `write` that kept
        // failing: a run that never had to wait proves nothing here.
        assert!(
            waited > Duration::from_secs(2),
            "the terminal took it all at once in {waited:?}"
        );
    }

    #[test]
    fn a_destination_that_never_drains_does_not_park_the_pump() {
        let (read_end, write_end) = rustix::pipe::pipe().unwrap();
        // A destination nobody empties, filled before the pump ever sees
        // it, so every write to it would block.
        let (_stuck, dest) = rustix::pipe::pipe().unwrap();
        fill(dest.as_fd());
        write(&write_end, b"output the host cannot take\n").unwrap();
        let sink = null_stdio().unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut until = || (Instant::now() >= deadline).then_some(9);
        let started = Instant::now();
        // A caught signal: the user is waiting, so that line is offered
        // for [`HURRY`] and then given up on, which is what the warning
        // here is.
        let quiet = StderrOn::null();
        let code = pump(
            &[(read_end.as_fd(), dest.as_fd(), FD_NAMES[1])],
            sink.as_fd(),
            &mut until,
            &AtomicBool::new(true),
        )
        .unwrap();
        drop(quiet);
        assert_eq!(code, 9);
        // Parking would be for good; anything bounded is not that.
        assert!(
            started.elapsed() < DRAIN + HURRY + Duration::from_secs(1),
            "the pump parked in a write"
        );
    }

    #[test]
    fn a_pipe_whose_reader_left_is_drained_into_the_sink() {
        let (read_end, write_end) = rustix::pipe::pipe().unwrap();
        // A destination that is closed: `bubbler run ... | head`, once
        // head has had enough.
        let (gone, reader) = rustix::pipe::pipe().unwrap();
        drop(reader);
        let sink = null_stdio().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let d = Arc::clone(&done);
        let feeder = thread::spawn(move || {
            let mut sent = 0;
            // Far more than a pipe holds; without the sink this blocks.
            while sent < 512 * 1024 {
                sent += write(&write_end, &[b'x'; 4096]).unwrap();
            }
            d.store(true, Ordering::SeqCst);
        });
        let quiet = StderrOn::null();
        let mut until = || done.load(Ordering::SeqCst).then_some(3);
        let code = pump(
            &[(read_end.as_fd(), gone.as_fd(), FD_NAMES[1])],
            sink.as_fd(),
            &mut until,
            &AtomicBool::new(false),
        )
        .unwrap();
        drop(quiet);
        assert_eq!(code, 3);
        feeder.join().unwrap();
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
        let (winch, hurry) = (AtomicBool::new(false), AtomicBool::new(false));
        let mut until = || Some(7);
        let started = Instant::now();
        let sink = null_stdio().unwrap();
        let end = relay(
            master.as_fd(),
            None,
            host_out.as_fd(),
            FD_NAMES[1],
            sink.as_fd(),
            &mut until,
            &Caught {
                winch: &winch,
                stop: &hurry,
            },
        )
        .unwrap();
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
        let sink = null_stdio().unwrap();
        let code = pump(
            &[
                (r_out.as_fd(), host_out.as_fd(), FD_NAMES[1]),
                (r_err.as_fd(), host_err.as_fd(), FD_NAMES[2]),
            ],
            sink.as_fd(),
            &mut until,
            &AtomicBool::new(false),
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
        let sink = null_stdio().unwrap();
        let code = pump(
            &[(read_end.as_fd(), host_out.as_fd(), FD_NAMES[1])],
            sink.as_fd(),
            &mut until,
            &AtomicBool::new(false),
        )
        .unwrap();
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
