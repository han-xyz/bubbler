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
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

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

/// How long a [`Redirect`] waits for the copying thread on the way out. A
/// sidecar that outlived the run still holds the pipe open, and giving up
/// costs the last few lines, never the exit.
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
/// The file is opened `O_APPEND` either way, so a second bubbler writing
/// to the same log lands after what is already there rather than over it.
pub fn redirect(path: &Path, truncate: bool) -> Result<Redirect, LaunchError> {
    let io_at = |e: io::Error| LaunchError::Io(path.to_path_buf(), e);
    let file = open(path, OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND).map_err(io_at)?;
    // The mode is only applied when the file is created, so a log from an
    // older run, or from a different umask, is narrowed here.
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| io_at(e.into()))?;
    if truncate {
        rustix::fs::ftruncate(&file, 0).map_err(|e| io_at(e.into()))?;
    }
    let (reader, writer) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    let saved = io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map_err(LaunchError::Data)?;
    // Not CLOEXEC once it is fd 2: every child bubbler starts writes its
    // own errors into the log too.
    rustix::stdio::dup2_stderr(&writer).map_err(|e| LaunchError::Data(e.into()))?;
    let (tx, done) = mpsc::sync_channel(1);
    // Nothing in here may start a process; see the module comment.
    std::thread::spawn(move || {
        let file = std::fs::File::from(file);
        let _ = copy_capped(std::fs::File::from(reader), &file, || {
            file.metadata().map(|m| m.len())
        });
        // A send that finds nobody waiting is the caller having given up
        // on the flush, which is not this thread's failure.
        let _ = tx.send(());
    });
    Ok(Redirect {
        saved,
        writer: Some(writer),
        done,
    })
}

impl Drop for Redirect {
    fn drop(&mut self) {
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

/// Copy `src` to `dst` while `size` reports room under [`MAX_BYTES`],
/// then say once that the rest was dropped and keep reading. Draining to
/// the end matters: a writer whose pipe fills stops dead, and the writer
/// here is the sandbox.
///
/// `size` is the destination's own size, asked for again before every
/// write rather than counted here, so whatever another writer has
/// appended in the meantime counts against the same cap.
fn copy_capped(
    mut src: impl Read,
    mut dst: impl Write,
    mut size: impl FnMut() -> io::Result<u64>,
) -> io::Result<()> {
    let note = NOTE.len() as u64;
    let mut noted = false;
    let mut buf = [0u8; 8192];
    loop {
        let read = match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        // The note is kept out of the room for output, so writing it is
        // never what takes the file over the cap.
        let room = MAX_BYTES.saturating_sub(size()?);
        let take = usize::try_from(room.saturating_sub(note))
            .unwrap_or(usize::MAX)
            .min(read);
        if take > 0 {
            dst.write_all(&buf[..take])?;
        }
        if take < read && !noted {
            noted = true;
            if room >= note {
                dst.write_all(NOTE.as_bytes())?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Copy into a buffer that reports its own size the way the file
    /// does, counting `held` bytes another writer put there first.
    fn capped(input: &[u8], held: u64) -> Vec<u8> {
        let out = std::cell::RefCell::new(Vec::new());
        copy_capped(input, Shared(&out), || Ok(held + out.borrow().len() as u64)).unwrap();
        out.into_inner()
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
