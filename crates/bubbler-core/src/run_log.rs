//! What a run started from a desktop entry or a shim has to say, kept in
//! the instance directory instead of thrown away.
//!
//! A launcher gives the process it starts no terminal, so bubbler's own
//! warnings, a sidecar's errors and the application's stderr would all go
//! nowhere. While a [`Redirect`] lives, fd 2 is a pipe a thread copies
//! into `last-run.log`; it stops at [`MAX_BYTES`], measured against the
//! file itself before every write so a second bubbler appending to the
//! same log cannot push it over, and keeps draining afterwards, so an
//! application that never stops writing fills neither the disk nor the
//! pipe.
//!
//! **The copying thread must never spawn a process.** The launcher clears
//! `CLOEXEC` on the descriptors one child is meant to inherit and puts it
//! back once that spawn has happened (`RealAlloc::inheritable` in
//! [`crate::launcher`]), which is only sound while one thread spawns at a
//! time; a command started here could carry the sandbox's control socket
//! into a process that has no business holding it.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{Mode, OFlags};
use rustix::pipe::PipeFlags;

use crate::error::LaunchError;

/// Name of the log inside the instance directory.
pub const LOG_FILE: &str = "last-run.log";

/// Most the log ever holds, the note below included. A cap and not a
/// rotation: what a run said last is what a user is looking for, and one
/// mebibyte of it is more than a launcher failure ever needs. It caps the
/// file, not one writer's share of it.
pub const MAX_BYTES: u64 = 1 << 20;

/// Written once, in place of the output that no longer fits.
const NOTE: &str = "\nbubbler: log full; the rest of this run's output was dropped\n";

/// Tried once when a tee's log fails, so a cut-off record reads as one.
const STOPPED: &str = "\nbubbler: writing the log failed; the record of this run stops here\n";

/// How long a [`Redirect`] or a [`Relay`] waits for its copying thread on
/// the way out. A process that outlived the run still holds the pipe open,
/// and giving up costs the last few lines, never the exit.
const FLUSH: Duration = Duration::from_secs(1);

/// The log of the instance whose directory is `dir`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(LOG_FILE)
}

/// The log's contents, or `None` when the instance has never been started
/// without a terminal. Read without following a symlink: the file is
/// named inside an instance directory, which is the user's to fill.
pub fn read(path: &Path) -> Result<Option<Vec<u8>>, LaunchError> {
    let io_at = |e: io::Error| LaunchError::Io(path.to_path_buf(), e);
    let file = match open(path, OFlags::RDONLY) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_at(e)),
    };
    let mut text = Vec::new();
    std::fs::File::from(file)
        .read_to_end(&mut text)
        .map_err(io_at)?;
    Ok(Some(text))
}

/// Open the log for `flags`, refusing everything that is not a regular
/// file of the user's own: a symlink is not followed (`O_NOFOLLOW`), a
/// fifo cannot park the open (`O_NONBLOCK`, which a regular file ignores)
/// and any other type is refused outright.
fn open(path: &Path, flags: OFlags) -> io::Result<OwnedFd> {
    let file = rustix::fs::open(
        path,
        flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    let stat = rustix::fs::fstat(&file)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

/// fd 2 pointed at an instance's log for as long as this lives. Dropping
/// it puts the caller's own stderr back.
pub struct Redirect {
    /// Where [`Redirect::started`] or [`Redirect::joined`] tells the
    /// copying thread whether the log is emptied first.
    settle: Option<SyncSender<bool>>,
    /// The log, when it is to be emptied, for [`Redirect::started`] to
    /// empty before it returns.
    to_empty: Option<OwnedFd>,
    saved: OwnedFd,
    /// bubbler's end of the pipe. Dropped first on the way out, since the
    /// copying thread ends on the last writer closing it.
    writer: Option<OwnedFd>,
    done: Receiver<()>,
}

/// Point fd 2 at `path` and copy everything written there into it.
/// `truncate` empties the file first, which is what starting a sandbox
/// does; an exec into a live instance appends instead, so a run's log
/// outlives the commands sent into it.
///
/// With `truncate`, nothing is copied until the run says which it turned
/// out to be — [`Redirect::started`], [`Redirect::joined`] or
/// [`Redirect::not_started`] — or the redirect is dropped, which empties
/// the log as asked: a start that loses the race to another start of the
/// instance, or is stopped while it waits on that one, must not empty the
/// log it is writing. Until then what is written
/// waits in the pipe, which holds far more than a start says before
/// its bind.
///
/// The file is opened `O_APPEND` either way, so a second bubbler writing
/// to the same log lands after what is already there rather than over it.
pub fn redirect(path: &Path, truncate: bool) -> Result<Redirect, LaunchError> {
    start(path, truncate, false)
}

/// [`redirect`], with everything also still written to the stderr the
/// caller had: the cap is the file's alone, and a stderr whose reader has
/// gone is given up on while the file goes on.
pub fn tee(path: &Path, truncate: bool) -> Result<Redirect, LaunchError> {
    start(path, truncate, true)
}

fn start(path: &Path, truncate: bool, keep_stderr: bool) -> Result<Redirect, LaunchError> {
    let io_at = |e: io::Error| LaunchError::Io(path.to_path_buf(), e);
    let file = open(path, OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND).map_err(io_at)?;
    // The mode is only applied when the file is created, so a log from an
    // older run, or from a different umask, is narrowed here.
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| io_at(e.into()))?;
    let (settle, settled) = mpsc::sync_channel(1);
    let to_empty = match truncate {
        true => Some(file.try_clone().map_err(LaunchError::Data)?),
        false => None,
    };
    let (reader, writer) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    let saved = io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map_err(LaunchError::Data)?;
    let stderr = match keep_stderr {
        true => Some(saved.try_clone().map_err(LaunchError::Data)?),
        false => None,
    };
    // Not CLOEXEC once it is fd 2: every child bubbler starts writes its
    // own errors into the log too.
    rustix::stdio::dup2_stderr(&writer).map_err(|e| LaunchError::Data(e.into()))?;
    let (tx, done) = mpsc::sync_channel(1);
    // Nothing in here may start a process; see the module comment.
    std::thread::spawn(move || {
        // A sender dropped unused is the redirect dropped before the run
        // said, which keeps what was asked for. A failed truncation costs
        // the old run's lines staying ahead of this one's, nothing more.
        if truncate && settled.recv().unwrap_or(true) {
            let _ = rustix::fs::ftruncate(&file, 0);
        }
        let file = std::fs::File::from(file);
        let mut stderr = stderr.map(|fd| Blocking(std::fs::File::from(fd)));
        let _ = copy_capped(
            std::fs::File::from(reader),
            &file,
            || file.metadata().map(|m| m.len()),
            stderr.as_mut().map(|f| f as &mut dyn Write),
        );
        // A send that finds nobody waiting is the caller having given up
        // on the flush, which is not this thread's failure.
        let _ = tx.send(());
    });
    Ok(Redirect {
        settle: Some(settle),
        to_empty,
        saved,
        writer: Some(writer),
        done,
    })
}

impl Redirect {
    /// This run started the sandbox: a log opened to be emptied is
    /// emptied before this returns, so a start that joins once the start
    /// lock is released adds to it after that, and everything the run
    /// wrote follows.
    pub fn started(&self) {
        // A failed truncation costs the old run's lines staying ahead of
        // this one's, nothing more.
        if let Some(file) = &self.to_empty {
            let _ = rustix::fs::ftruncate(file, 0);
        }
        self.settle_on(false);
    }

    /// This run joined one that is already up: what it writes is added
    /// to that run's log.
    pub fn joined(&self) {
        self.settle_on(false);
    }

    /// This run ended without starting the sandbox: what it wrote is
    /// added to the log, which may be the one a running start is writing.
    pub fn not_started(&self) {
        self.settle_on(false);
    }

    /// The first answer is the one that counts; the channel holds one.
    fn settle_on(&self, truncate: bool) {
        if let Some(settle) = &self.settle {
            let _ = settle.try_send(truncate);
        }
    }

    /// The stderr the caller had before fd 2 was pointed at the log: what
    /// a command that may outlive this run is handed, so nothing it writes
    /// later depends on a copy that ends with the run.
    pub fn original_stderr(&self) -> BorrowedFd<'_> {
        self.saved.as_fd()
    }
}

impl Drop for Redirect {
    fn drop(&mut self) {
        self.settle.take();
        // Both copies of the write end have to go before the reader sees
        // the end of the output: this one, and the one that is fd 2.
        self.writer.take();
        // A failure here leaves fd 2 on a pipe nothing reads any more, so
        // what follows is lost; there is nowhere left to report that, and
        // ending the process over it would lose the exit code as well.
        let _ = rustix::stdio::dup2_stderr(&self.saved);
        match self.done.recv_timeout(FLUSH) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
            // A child of this run still holds the pipe. Waiting longer
            // would hold up an exit that has nothing left to do.
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

/// The write end of a pipe whose every byte a thread copies to the stderr
/// bubbler has now, for a sidecar's stderr: the sidecar parses what the
/// sandbox sends it, so it is handed no terminal of the caller's.
pub fn relay() -> Result<(OwnedFd, Relay), LaunchError> {
    let (reader, writer) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    let stderr = io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map_err(LaunchError::Data)?;
    let (tx, done) = mpsc::sync_channel(1);
    // Nothing in here may start a process; see the module comment.
    std::thread::spawn(move || {
        let mut stderr = Blocking(std::fs::File::from(stderr));
        let _ = copy_capped(
            std::fs::File::from(reader),
            io::sink(),
            || Ok(0),
            Some(&mut stderr),
        );
        let _ = tx.send(());
    });
    Ok((writer, Relay { done }))
}

/// The copying thread of a [`relay`]. Dropped once the sidecar is gone, it
/// waits up to a second for the last of its output.
#[derive(Debug)]
pub struct Relay {
    done: Receiver<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.done.recv_timeout(FLUSH);
    }
}

/// Copy `src` to `dst` while `size` reports room under [`MAX_BYTES`],
/// then say once that the rest was dropped and keep reading. Draining to
/// the end matters: a writer whose pipe fills stops dead, and the writer
/// here is the sandbox.
///
/// `size` is the destination's own size, asked for again before every
/// write rather than counted here, so whatever another writer has
/// appended in the meantime counts against the same cap.
///
/// `stderr`, when given, is sent every byte read, past the cap too, after
/// the file has had its share: a stderr nobody reads blocks the copy, and
/// the record is what matters then. A stderr whose reader has gone is given
/// up on; any other failure there costs that chunk. With a `stderr`, a file
/// that fails is given one try at a note saying so, when it has room for
/// it under the cap, then given up on while the copy goes on, since the
/// caller's own stderr is what the run was promised.
fn copy_capped(
    mut src: impl Read,
    dst: impl Write,
    mut size: impl FnMut() -> io::Result<u64>,
    mut stderr: Option<&mut dyn Write>,
) -> io::Result<()> {
    let teeing = stderr.is_some();
    let mut dst = Some(dst);
    let mut noted = false;
    let mut buf = [0u8; 8192];
    loop {
        let read = match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if let Some(file) = dst.as_mut()
            && let Err(e) = append_capped(&mut *file, &buf[..read], &mut size, &mut noted)
        {
            if !teeing {
                return Err(e);
            }
            // The log just failed, so the note may not land either, and it
            // is only tried where the file says there is room for it.
            if size().is_ok_and(|held| held + STOPPED.len() as u64 <= MAX_BYTES) {
                let _ = file.write_all(STOPPED.as_bytes());
            }
            dst = None;
        }
        if let Some(out) = stderr.as_mut()
            && let Err(e) = out.write_all(&buf[..read])
            && e.kind() == io::ErrorKind::BrokenPipe
        {
            stderr = None;
        }
    }
}

/// The caller's stderr, written to as if it blocked: its file description
/// may be one a parent shares with `O_NONBLOCK` set, where a full pipe
/// answers `WouldBlock`, and a chunk dropped for that is output the
/// caller would have had without bubbler in between.
struct Blocking(std::fs::File);

impl Write for Blocking {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.0.write(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let mut fds = [PollFd::new(&self.0, PollFlags::OUT)];
                    poll(&mut fds, None)?;
                }
                written => return written,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Write what of `chunk` fits under [`MAX_BYTES`] to `dst`, and the note
/// the first time something does not.
fn append_capped(
    mut dst: impl Write,
    chunk: &[u8],
    size: &mut impl FnMut() -> io::Result<u64>,
    noted: &mut bool,
) -> io::Result<()> {
    let note = NOTE.len() as u64;
    // The note is kept out of the room for output, so writing it is
    // never what takes the file over the cap.
    let room = MAX_BYTES.saturating_sub(size()?);
    let take = usize::try_from(room.saturating_sub(note))
        .unwrap_or(usize::MAX)
        .min(chunk.len());
    if take > 0 {
        dst.write_all(&chunk[..take])?;
    }
    if take < chunk.len() && !*noted {
        *noted = true;
        if room >= note {
            dst.write_all(NOTE.as_bytes())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Copy into a buffer that reports its own size the way the file
    /// does, counting `held` bytes another writer put there first.
    fn capped(input: &[u8], held: u64) -> Vec<u8> {
        let out = std::cell::RefCell::new(Vec::new());
        copy_capped(
            input,
            Shared(&out),
            || Ok(held + out.borrow().len() as u64),
            None,
        )
        .unwrap();
        out.into_inner()
    }

    /// A destination every write to fails with this kind: `BrokenPipe` is
    /// a stderr whose reader has gone, `StorageFull` a log on a full disk.
    struct Failing(io::ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A stderr whose first write fails and whose later writes land.
    struct FailsOnce(bool, Vec<u8>);

    impl Write for FailsOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.0 {
                self.0 = true;
                return Err(io::ErrorKind::Other.into());
            }
            self.1.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_tee_gives_stderr_everything_and_the_file_what_fits() {
        let flood = vec![b'x'; 8192];
        let out = std::cell::RefCell::new(Vec::new());
        let mut stderr = Vec::new();
        copy_capped(
            &flood[..],
            Shared(&out),
            || Ok(MAX_BYTES - 100 + out.borrow().len() as u64),
            Some(&mut stderr),
        )
        .unwrap();
        assert_eq!(stderr, flood);
        assert_eq!(out.borrow().len(), 100);
        assert!(out.borrow().ends_with(NOTE.as_bytes()));

        // A reader that left costs its own copy, not the file's.
        let out = std::cell::RefCell::new(Vec::new());
        copy_capped(
            &b"hello"[..],
            Shared(&out),
            || Ok(out.borrow().len() as u64),
            Some(&mut Failing(io::ErrorKind::BrokenPipe)),
        )
        .unwrap();
        assert_eq!(out.into_inner(), b"hello");

        // Any other failure costs that chunk only.
        let out = std::cell::RefCell::new(Vec::new());
        let mut stderr = FailsOnce(false, Vec::new());
        copy_capped(
            (&b"one"[..]).chain(&b"two"[..]),
            Shared(&out),
            || Ok(out.borrow().len() as u64),
            Some(&mut stderr),
        )
        .unwrap();
        assert_eq!(stderr.1, b"two");
        assert_eq!(out.into_inner(), b"onetwo");
    }

    #[test]
    fn a_tee_whose_log_fails_keeps_giving_stderr_everything() {
        let mut stderr = Vec::new();
        copy_capped(
            (&b"one"[..]).chain(&b"two"[..]),
            Failing(io::ErrorKind::StorageFull),
            || Ok(0),
            Some(&mut stderr),
        )
        .unwrap();
        assert_eq!(stderr, b"onetwo");

        let mut stderr = Vec::new();
        copy_capped(
            (&b"one"[..]).chain(&b"two"[..]),
            Vec::new(),
            || Err(io::ErrorKind::Other.into()),
            Some(&mut stderr),
        )
        .unwrap();
        assert_eq!(stderr, b"onetwo");

        // A log that fails after taking some output says where it stopped.
        let out = std::cell::RefCell::new(Vec::new());
        let failed = std::cell::Cell::new(false);
        let mut stderr = Vec::new();
        copy_capped(
            (&b"one"[..]).chain(&b"two"[..]),
            Shared(&out),
            || match out.borrow().len() {
                0 => Ok(0),
                held if failed.replace(true) => Ok(held as u64),
                _ => Err(io::ErrorKind::Other.into()),
            },
            Some(&mut stderr),
        )
        .unwrap();
        assert_eq!(stderr, b"onetwo");
        assert_eq!(out.into_inner(), [b"one", STOPPED.as_bytes()].concat());

        // Never past the cap, the note included.
        let out = std::cell::RefCell::new(Vec::new());
        let asked = std::cell::Cell::new(0);
        copy_capped(
            &b"one"[..],
            Shared(&out),
            || {
                asked.set(asked.get() + 1);
                match asked.get() {
                    1 => Err(io::ErrorKind::Other.into()),
                    _ => Ok(MAX_BYTES - 1),
                }
            },
            Some(&mut Vec::new()),
        )
        .unwrap();
        assert!(out.into_inner().is_empty());
    }

    #[test]
    fn a_non_blocking_stderr_is_waited_for_not_dropped() {
        let (reader, writer) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC).unwrap();
        rustix::fs::fcntl_setfl(&writer, OFlags::NONBLOCK).unwrap();
        let drain = std::thread::spawn(move || {
            // Late, so the pipe fills and the writer is told to wait.
            std::thread::sleep(Duration::from_millis(100));
            let mut all = Vec::new();
            std::fs::File::from(reader).read_to_end(&mut all).unwrap();
            all
        });
        let flood = vec![b'x'; 1 << 20];
        let mut stderr = Blocking(std::fs::File::from(writer));
        copy_capped(&flood[..], io::sink(), || Ok(0), Some(&mut stderr)).unwrap();
        drop(stderr);
        assert_eq!(drain.join().unwrap().len(), flood.len());
    }

    /// A destination the size closure can read the length of, which is
    /// what `fstat` on the log is.
    struct Shared<'a>(&'a std::cell::RefCell<Vec<u8>>);

    impl Write for Shared<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_past_the_cap_is_dropped_and_said_to_be() {
        assert_eq!(capped(b"hello", 0), b"hello");

        let flood = vec![b'x'; 8192];
        // What the file already holds counts, so a log a second bubbler
        // has been appending to is not given a fresh mebibyte.
        let out = capped(&flood, MAX_BYTES - 100);
        assert_eq!(out.len(), 100);
        assert!(out.ends_with(NOTE.as_bytes()), "{out:?}");
        assert_eq!(out.iter().filter(|b| **b == b'x').count(), 100 - NOTE.len());

        // Exactly the room there was: nothing was lost, so nothing is said.
        let out = capped(&flood[..100 - NOTE.len()], MAX_BYTES - 100);
        assert_eq!(out.len(), 100 - NOTE.len());

        // A file already at the cap keeps every byte it has, and one with
        // room for nothing but the note is left alone too.
        assert!(capped(&flood, MAX_BYTES).is_empty());
        assert!(capped(&flood, MAX_BYTES - 1).is_empty());
    }

    #[test]
    fn the_log_is_the_users_own_regular_file_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        let log = path(tmp.path());
        assert_eq!(log, tmp.path().join("last-run.log"));
        assert!(read(&log).unwrap().is_none());

        std::fs::write(&log, b"held").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read(&log).unwrap().unwrap(), b"held");

        // A symlink, whatever it points at, is not this instance's log.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, b"secret").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        assert!(read(&link).is_err());
        assert!(open(&link, OFlags::WRONLY).is_err());

        // Neither is a directory or a fifo, and the fifo does not park
        // the open waiting for a reader.
        assert!(open(tmp.path(), OFlags::RDONLY).is_err());
        let fifo = tmp.path().join("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
        assert!(open(&fifo, OFlags::WRONLY).is_err());
    }
}
