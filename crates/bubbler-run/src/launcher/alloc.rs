//! The allocator a real run's argv is built with.

use std::ffi::OsString;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{MemfdFlags, Mode, OFlags, SealFlags};
use rustix::io::{FdFlags, fcntl_setfd};

use bubbler_init::fds;

use crate::bwrap::FdAllocator;
use crate::launch_error::LaunchError;
use crate::sidecar_argv::{SIDECAR_PREFIX, data_name};

/// Allocator for a real run: seccomp memfds, generated files in the run's runtime directory, the
/// bound control socket and a sidecar ready pipe.
///
/// A generated file is the live source of a read-only bind, so its content must not change and it
/// must not be unlinked while any sandbox holds that bind. Each allocator therefore owns the files
/// it wrote and is the only thing that unlinks them, when it drops after its own sandbox has
/// exited; and no two allocators of one run write the same path, which is what
/// [`RealAlloc::sidecar`]'s name prefix is for — `portals` gives the application sandbox and the
/// D-Bus proxy a `/.flatpak-info` each, and the proxy is already running with its own bound when
/// the application's argv is built.
#[derive(Debug)]
pub(crate) struct RealAlloc {
    /// Fds bwrap inherits; they stay open until it has been spawned.
    pub fds: Vec<OwnedFd>,
    /// The listening control socket, already dup'ed without `CLOEXEC`;
    /// `None` for a sidecar, which serves no exec channel.
    pub socket: Option<RawFd>,
    /// The listening socket a sidecar accepts the application on, until
    /// [`FdAllocator::listener`] hands it over. Handed out once: a
    /// number given twice would be closed twice.
    pub listen: Option<OwnedFd>,
    listen_fd: Option<RawFd>,
    options_fd: Option<RawFd>,
    /// Read end of the ready pipe, once [`FdAllocator::ready_pipe`] made one.
    pub ready_read: Option<OwnedFd>,
    /// Read end of the info pipe bwrap reports the sandbox pid on.
    pub info_read: Option<OwnedFd>,
    /// Write end of the info pipe; the caller drops it once bwrap has
    /// started, so the read end reports EOF if bwrap never answers.
    pub info_write: Option<OwnedFd>,
    /// Write end of the pipe the sandbox is blocked on. Writing to it or
    /// dropping it is what lets the sandbox exec its command.
    pub block_write: Option<OwnedFd>,
    dir: PathBuf,
    prefix: &'static str,
    written: Vec<PathBuf>,
}

impl Drop for RealAlloc {
    fn drop(&mut self) {
        for path in self.written.drain(..) {
            // A file left behind is overwritten by the next start of the same instance.
            let _ = std::fs::remove_file(path);
        }
    }
}

impl RealAlloc {
    /// Allocate around an already inherited control socket fd. `dir` is the run's runtime
    /// directory, which the caller has created.
    pub(crate) fn new(socket: RawFd, dir: PathBuf) -> Self {
        let mut a = Self::in_dir(dir, "");
        a.socket = Some(socket);
        a
    }

    /// Allocate for a sidecar sandbox: generated files and a ready pipe, no control socket, and
    /// file names apart from the application sandbox's.
    pub(crate) fn sidecar(dir: PathBuf) -> Self {
        Self::in_dir(dir, SIDECAR_PREFIX)
    }

    fn in_dir(dir: PathBuf, prefix: &'static str) -> Self {
        Self {
            fds: Vec::new(),
            socket: None,
            listen: None,
            listen_fd: None,
            options_fd: None,
            ready_read: None,
            info_read: None,
            info_write: None,
            block_write: None,
            dir,
            prefix,
            written: Vec::new(),
        }
    }

    /// Allocate for a sidecar that accepts on a socket bubbler has
    /// already bound and listened on, which it inherits by number.
    pub(crate) fn sidecar_listening(listener: OwnedFd, dir: PathBuf) -> Self {
        let mut a = Self::sidecar(dir);
        a.listen = Some(listener);
        a
    }

    fn keep(&mut self, fd: OwnedFd) -> OsString {
        let n = fd.as_raw_fd();
        self.fds.push(fd);
        OsString::from(n.to_string())
    }

    pub(super) fn close_listener(&mut self) {
        if let Some(fd) = self.listen_fd.take() {
            self.fds.retain(|held| held.as_raw_fd() != fd);
        }
    }

    // A sealed memfd rather than a pipe, so nothing has to write while bwrap reads, whatever the
    // length.
    pub(super) fn options(&mut self, options: &[OsString]) -> io::Result<OsString> {
        if let Some(option) = options.iter().find(|o| o.as_bytes().contains(&0)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a bwrap option holds a NUL byte: {option:?}"),
            ));
        }
        let fd = rustix::fs::memfd_create(
            "bubbler-args",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?;
        let mut f = std::fs::File::from(fd);
        for option in options {
            f.write_all(option.as_bytes())?;
            f.write_all(b"\0")?;
        }
        f.seek(SeekFrom::Start(0))?;
        rustix::fs::fcntl_add_seals(
            &f,
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
        )?;
        self.options_fd = Some(f.as_raw_fd());
        Ok(self.keep(f.into()))
    }

    pub(super) fn close_options(&mut self) {
        if let Some(fd) = self.options_fd.take() {
            self.fds.retain(|held| held.as_raw_fd() != fd);
        }
    }

    // CLOEXEC at rest, cleared only around the one spawn they were built for. That window is
    // process-wide; bubbler's other threads (run-log copier, KDL parser) open no fd, spawn nothing,
    // and no configuration is parsed while the window is open.
    pub(super) fn inheritable(&self, on: bool) -> io::Result<()> {
        let flags = match on {
            true => FdFlags::empty(),
            false => FdFlags::CLOEXEC,
        };
        for fd in &self.fds {
            fcntl_setfd(fd, flags)?;
        }
        Ok(())
    }

    // The info pipe's write end is never CLOEXEC: the caller closes it by hand after the spawn. A
    // caller closing a fd takes it out here too, or the next sweep would spare a recycled number.
    pub(super) fn intended(&self) -> Vec<RawFd> {
        let mut fds: Vec<RawFd> = self.fds.iter().map(AsRawFd::as_raw_fd).collect();
        fds.extend(self.socket);
        fds.extend(self.info_write.as_ref().map(AsRawFd::as_raw_fd));
        fds
    }
}

// Call immediately before a spawn. Nothing is closed: bubbler's own descriptors only stop
// crossing into children. Process-wide like `RealAlloc::inheritable`.
pub(super) fn spawning(keep: &[RawFd]) -> Result<(), LaunchError> {
    fds::sweep_cloexec(keep).map_err(LaunchError::Descriptors)
}

impl FdAllocator for RealAlloc {
    fn data(&mut self, content: &[u8]) -> io::Result<OsString> {
        // Inheritable only around the spawn this argv was built for: no sidecar needs the sandbox's
        // `/etc/passwd`, `/.flatpak-info` or resolver.
        let fd = rustix::fs::memfd_create("bubbler-data", MemfdFlags::CLOEXEC)?;
        let mut f = std::fs::File::from(fd);
        f.write_all(content)?;
        f.seek(SeekFrom::Start(0))?;
        Ok(self.keep(f.into()))
    }

    // `O_NOFOLLOW` keeps the write in the runtime directory; the mode is set, not left to the
    // umask, since bwrap gives the destination the source's mode.
    fn file(&mut self, dest: &Path, content: &[u8]) -> io::Result<OsString> {
        let path = self.dir.join(data_name(self.prefix, dest));
        let mut f = std::fs::File::from(rustix::fs::open(
            &path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        )?);
        rustix::fs::fchmod(&f, Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH)?;
        f.write_all(content)?;
        self.written.push(path.clone());
        Ok(path.into_os_string())
    }

    fn init_socket(&mut self) -> io::Result<OsString> {
        match self.socket {
            Some(fd) => Ok(OsString::from(fd.to_string())),
            None => Err(io::Error::other("this sandbox has no control socket")),
        }
    }

    // One pipe per run: a second call replaces the first.
    fn ready_pipe(&mut self) -> io::Result<OsString> {
        let (read, write) = rustix::pipe::pipe()?;
        fcntl_setfd(&read, FdFlags::CLOEXEC)?;
        self.ready_read = Some(read);
        Ok(self.keep(write))
    }

    fn listener(&mut self) -> io::Result<OsString> {
        match self.listen.take() {
            Some(fd) => {
                self.listen_fd = Some(fd.as_raw_fd());
                Ok(self.keep(fd))
            }
            None => Err(io::Error::other("this sidecar has no listening socket")),
        }
    }

    // Kept apart from the other fds: the caller drops the write end right after the spawn, so a
    // bwrap that never answers gives EOF instead of a hang.
    fn info_pipe(&mut self) -> io::Result<OsString> {
        let (read, write) = rustix::pipe::pipe()?;
        fcntl_setfd(&read, FdFlags::CLOEXEC)?;
        self.info_read = Some(read);
        let n = write.as_raw_fd();
        self.info_write = Some(write);
        Ok(OsString::from(n.to_string()))
    }

    // The write end stays out of every child, so nothing but bubbler can release the sandbox.
    fn block_pipe(&mut self) -> io::Result<OsString> {
        let (read, write) = rustix::pipe::pipe()?;
        fcntl_setfd(&write, FdFlags::CLOEXEC)?;
        self.block_write = Some(write);
        Ok(self.keep(read))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::no_data_dir;
    use super::*;

    #[test]
    fn what_a_spawn_may_inherit_is_the_fds_the_socket_and_the_info_pipe() {
        // A descriptor this test holds open, so the number below cannot be
        // handed to one of the allocations that follow: a literal would
        // be, whenever the process runs this test alone.
        let socket = std::fs::File::open("/dev/null").unwrap();
        let number = socket.as_raw_fd();
        let mut alloc = RealAlloc::new(number, no_data_dir());
        assert_eq!(alloc.intended(), vec![number]);
        alloc.data(b"a").unwrap();
        alloc.block_pipe().unwrap();
        alloc.info_pipe().unwrap();
        let held: Vec<RawFd> = alloc.fds.iter().map(AsRawFd::as_raw_fd).collect();
        let info = alloc
            .info_write
            .as_ref()
            .expect("the info pipe was allocated")
            .as_raw_fd();
        // The write end of the info pipe is the one bwrap must inherit
        // that `inheritable` never touches, so a sweep that went by
        // `fds` alone would take the sandbox pid with it.
        let mut want = held;
        want.push(number);
        want.push(info);
        assert_eq!(alloc.intended(), want);
        // What `run` does once bwrap holds the socket: the number goes
        // with the descriptor, so a later spawn's sweep is never told to
        // spare a number the kernel has handed on to something else.
        alloc.socket.take();
        assert!(
            !alloc.intended().contains(&number),
            "a closed number is spared"
        );
    }

    #[test]
    fn real_alloc_block_pipe_hands_the_sandbox_the_read_end() {
        use std::io::Read;
        let mut alloc = RealAlloc::new(7, no_data_dir());
        let fd = alloc.block_pipe().unwrap();
        let read = alloc.fds.last().expect("the read end is inherited");
        assert_eq!(fd, OsString::from(read.as_raw_fd().to_string()));
        assert_eq!(rustix::io::fcntl_getfd(read).unwrap(), FdFlags::empty());
        let write = alloc.block_write.take().expect("the write end stays here");
        assert_eq!(rustix::io::fcntl_getfd(&write).unwrap(), FdFlags::CLOEXEC);
        rustix::io::write(&write, b"\n").unwrap();
        let mut got = [0u8; 1];
        std::fs::File::from(read.try_clone().unwrap())
            .read_exact(&mut got)
            .unwrap();
        assert_eq!(&got, b"\n");
    }

    #[test]
    fn real_alloc_data_is_readable_from_the_start_and_inheritable_for_one_spawn() {
        use std::io::Read;
        let mut alloc = RealAlloc::new(7, no_data_dir());
        let fd = alloc.data(b"hello").unwrap();
        assert_eq!(alloc.init_socket().unwrap(), OsString::from("7"));
        assert_eq!(alloc.fds.len(), 1);
        assert_eq!(fd, OsString::from(alloc.fds[0].as_raw_fd().to_string()));
        let flags = || rustix::io::fcntl_getfd(&alloc.fds[0]).unwrap();
        // At rest the file is closed on exec, so the sidecars the run
        // spawns around the sandbox — the proxy before it, pasta after
        // it — never inherit the sandbox's `/etc/passwd` or its resolver.
        assert_eq!(flags(), FdFlags::CLOEXEC);
        alloc.inheritable(true).unwrap();
        assert_eq!(flags(), FdFlags::empty());
        alloc.inheritable(false).unwrap();
        assert_eq!(flags(), FdFlags::CLOEXEC);
        // A dup shares the file offset, so this reads what bwrap would read.
        let mut got = String::new();
        std::fs::File::from(alloc.fds[0].try_clone().unwrap())
            .read_to_string(&mut got)
            .unwrap();
        assert_eq!(got, "hello");
    }

    /// bwrap splits its `--args` data at every NUL, so an option holding
    /// one would arrive as two.
    #[test]
    fn real_alloc_options_refuse_an_option_holding_a_nul() {
        use std::os::unix::ffi::OsStringExt;
        let mut alloc = RealAlloc::sidecar(no_data_dir());
        let options = [
            OsString::from("--setenv"),
            OsString::from_vec(b"A\0--bind".to_vec()),
            OsString::from("x"),
        ];
        let err = alloc.options(&options).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(alloc.fds.is_empty());
    }

    #[test]
    fn real_alloc_ready_pipe_keeps_the_read_end() {
        use std::io::Read;
        let mut alloc = RealAlloc::new(7, no_data_dir());
        let fd = alloc.ready_pipe().unwrap();
        let write = alloc.fds.last().expect("the write end is inherited");
        assert_eq!(fd, OsString::from(write.as_raw_fd().to_string()));
        assert_eq!(rustix::io::fcntl_getfd(write).unwrap(), FdFlags::empty());
        rustix::io::write(write, b"x").unwrap();
        let read = alloc.ready_read.take().expect("the read end stays here");
        assert_eq!(rustix::io::fcntl_getfd(&read).unwrap(), FdFlags::CLOEXEC);
        let mut got = [0u8; 1];
        std::fs::File::from(read).read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
    }

    #[test]
    fn real_alloc_info_pipe_splits_the_ends() {
        use std::io::Read;
        let mut alloc = RealAlloc::new(7, no_data_dir());
        let fd = alloc.info_pipe().unwrap();
        let write = alloc.info_write.take().expect("the write end is inherited");
        assert_eq!(fd, OsString::from(write.as_raw_fd().to_string()));
        assert_eq!(rustix::io::fcntl_getfd(&write).unwrap(), FdFlags::empty());
        assert!(
            alloc.fds.is_empty(),
            "the write end is dropped by the caller"
        );
        rustix::io::write(&write, b"{}").unwrap();
        drop(write);
        let read = alloc.info_read.take().expect("the read end stays here");
        assert_eq!(rustix::io::fcntl_getfd(&read).unwrap(), FdFlags::CLOEXEC);
        let mut got = String::new();
        std::fs::File::from(read).read_to_string(&mut got).unwrap();
        assert_eq!(got, "{}");
    }
}
