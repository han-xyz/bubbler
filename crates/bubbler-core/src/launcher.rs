//! Spawns bubblewrap. The only process-spawning code in the crate; it
//! never goes through a shell.

use std::ffi::OsString;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{MemfdFlags, Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use rustix::process::{Pid, Signal, kill_process};
use signal_hook::SigId;
use signal_hook::consts::{SIGINT, SIGTERM};

use crate::bwrap::{BwrapArgs, FdAllocator};
use crate::env::Env;
use crate::error::{ConfigError, LaunchError};
use crate::host::{Host, RealHost};
use crate::instance::Instance;
use crate::{dbus, exec, init_bin, service};

/// How often a running sandbox is checked for having exited.
const POLL: Duration = Duration::from_millis(100);

/// How long the sandbox has to report its pid before the run continues
/// without being able to shut it down gracefully.
const INFO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the D-Bus proxy has to report that its socket is up.
const PROXY_READY: Duration = Duration::from_secs(5);

/// How long a proxy may take to leave after its ready pipe is closed
/// before it is killed.
const PROXY_STOP: Duration = Duration::from_secs(1);

/// Allocator for `--dry-run`: numbers every fd 3, 4, ... without creating
/// anything.
#[derive(Debug)]
pub struct DryRunAlloc {
    next: u32,
}

impl Default for DryRunAlloc {
    /// Numbering starts above the process's own stdio.
    fn default() -> Self {
        Self { next: 2 }
    }
}

impl DryRunAlloc {
    fn bump(&mut self) -> io::Result<OsString> {
        self.next += 1;
        Ok(OsString::from(self.next.to_string()))
    }
}

impl FdAllocator for DryRunAlloc {
    fn data(&mut self, _content: &[u8]) -> io::Result<OsString> {
        self.bump()
    }
    fn init_socket(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn ready_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn info_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn block_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
}

/// Allocator for a real run: memfds for data files, the control socket
/// bubbler already bound, and a sidecar ready pipe.
#[derive(Debug)]
pub struct RealAlloc {
    /// Fds bwrap inherits; they stay open until it has been spawned.
    pub fds: Vec<OwnedFd>,
    /// The listening control socket, already dup'ed without `CLOEXEC`;
    /// `None` for a sidecar, which serves no exec channel.
    pub socket: Option<RawFd>,
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
}

impl RealAlloc {
    /// Allocate around an already inherited control socket fd.
    pub fn new(socket: RawFd) -> Self {
        Self {
            fds: Vec::new(),
            socket: Some(socket),
            ready_read: None,
            info_read: None,
            info_write: None,
            block_write: None,
        }
    }

    /// Allocate for a sidecar sandbox: data files and a ready pipe, but
    /// no control socket to hand out.
    pub fn sidecar() -> Self {
        Self {
            fds: Vec::new(),
            socket: None,
            ready_read: None,
            info_read: None,
            info_write: None,
            block_write: None,
        }
    }

    /// Keep `fd` open for the child and report the number it will see.
    fn keep(&mut self, fd: OwnedFd) -> OsString {
        let n = fd.as_raw_fd();
        self.fds.push(fd);
        OsString::from(n.to_string())
    }
}

impl FdAllocator for RealAlloc {
    fn data(&mut self, content: &[u8]) -> io::Result<OsString> {
        // No `MFD_CLOEXEC`: bwrap is a child process and must inherit the fd.
        let fd = rustix::fs::memfd_create("bubbler-data", MemfdFlags::empty())?;
        let mut f = std::fs::File::from(fd);
        f.write_all(content)?;
        f.seek(SeekFrom::Start(0))?;
        Ok(self.keep(f.into()))
    }

    fn init_socket(&mut self) -> io::Result<OsString> {
        match self.socket {
            Some(fd) => Ok(OsString::from(fd.to_string())),
            None => Err(io::Error::other("this sandbox has no control socket")),
        }
    }

    /// The sandboxed sidecar writes the ready byte, so it inherits the
    /// write end; the read end stays here and out of every child. One
    /// pipe per run: a second call replaces the first.
    fn ready_pipe(&mut self) -> io::Result<OsString> {
        let (read, write) = rustix::pipe::pipe()?;
        fcntl_setfd(&read, FdFlags::CLOEXEC)?;
        self.ready_read = Some(read);
        Ok(self.keep(write))
    }

    /// bwrap inherits the write end and reports the sandbox pid on it.
    /// The write end is kept apart from the other fds because the caller
    /// drops it right after the spawn to get EOF instead of a hang.
    fn info_pipe(&mut self) -> io::Result<OsString> {
        let (read, write) = rustix::pipe::pipe()?;
        fcntl_setfd(&read, FdFlags::CLOEXEC)?;
        self.info_read = Some(read);
        let n = write.as_raw_fd();
        self.info_write = Some(write);
        Ok(OsString::from(n.to_string()))
    }

    /// bwrap inherits the read end and waits on it; the write end stays
    /// here and out of every child, so nothing but bubbler can release
    /// the sandbox.
    fn block_pipe(&mut self) -> io::Result<OsString> {
        let (read, write) = rustix::pipe::pipe()?;
        fcntl_setfd(&write, FdFlags::CLOEXEC)?;
        self.block_write = Some(write);
        Ok(self.keep(read))
    }
}

/// The command to run: the CLI's if it gave one, else the config's.
pub fn resolve_command<'a>(
    inst: &'a Instance,
    command: Option<&'a [OsString]>,
) -> Result<&'a [OsString], ConfigError> {
    match command {
        Some(c) if !c.is_empty() => Ok(c),
        _ => inst
            .config
            .command
            .as_deref()
            .ok_or(ConfigError::MissingCommand),
    }
}

/// Complete bwrap argv (without the program name) for an instance.
/// `command` from the CLI replaces the config's `command` entirely.
/// `alloc` turns each generated data file and channel into the fd number
/// bwrap reads it from.
pub fn build_argv(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    alloc: &mut dyn FdAllocator,
) -> Result<Vec<OsString>, LaunchError> {
    let command = resolve_command(inst, command)?;
    let host = RealHost;
    let plan = dbus::plan(&inst.config.services, &inst.name);
    let ctx = service::ServiceCtx {
        instance_runtime: instance_runtime_dir(env, &inst.name),
        dbus: plan.as_ref(),
    };
    let mut args = BwrapArgs::baseline(env, &inst.home(), &host);
    // A portal call is answered by the identity bubbler publishes from
    // bwrap's own info document, so the app waits until that file is there.
    if plan.as_ref().is_some_and(|p| p.portals) {
        args.block_until_released();
    }
    service::apply_all(&inst.config.services, env, &mut args, &host, &ctx)?;
    service::apply_env(&inst.config.env, &mut args)?;
    args.bind_init(&init_bin::locate(env, &host)?);
    args.finish(command, alloc)
}

/// Complete bwrap argv (without the program name) for the D-Bus proxy
/// sidecar of one instance. `alloc` keeps the read end of the pipe the
/// proxy reports readiness on.
pub fn proxy_argv(
    env: &Env,
    plan: &dbus::Plan,
    host_bus: &Path,
    dir: &Path,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Vec<OsString>, LaunchError> {
    let ready = alloc.ready_pipe().map_err(LaunchError::Data)?;
    let program = dbus::proxy_program(env);
    let command = dbus::proxy_command(&program, plan, host_bus, dir, env.dbus_log, &ready);
    let mut args = BwrapArgs::proxy_baseline(host_bus, &dbus::socket_dir(dir), host);
    // The proxy reads this to decide it is talking for a sandboxed app;
    // without `portals` it is only the `[Application]` section.
    args.ro_bind_data(
        plan.flatpak_info.clone(),
        Path::new(dbus::FLATPAK_INFO),
        "0644",
    );
    // An overriding binary is not on the sandbox's `PATH`, so it is bound
    // in at its own path; the packaged proxy needs no bind.
    if env.proxy_override.is_some() {
        let program = service::require_file(host, "dbus", program)?;
        args.ro_bind(&program, &program);
    }
    args.finish_plain(&command, alloc)
}

/// A running proxy sidecar. Dropping every end of its `--fd` pipe that
/// bubbler holds is what makes `xdg-dbus-proxy` exit, so the handle must
/// outlive the sandbox that uses the socket.
#[derive(Debug)]
pub struct ProxyHandle {
    child: Child,
    /// Holds both ends of the ready pipe and the `/.flatpak-info` fd.
    alloc: RealAlloc,
    /// The proxy's own directory, removed once it has exited.
    socket_dir: PathBuf,
}

impl Drop for ProxyHandle {
    /// Close the ready pipe so the proxy exits by itself, then reap it;
    /// a proxy that ignores the closed pipe is killed instead of leaking.
    // The proxy polls its own write end and leaves on `POLLHUP`, which
    // needs the last *read* end gone: keeping ours would hold it alive
    // until the kill below.
    fn drop(&mut self) {
        self.alloc.fds.clear();
        self.alloc.ready_read.take();
        let deadline = Instant::now() + PROXY_STOP;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(POLL);
        }
        // The directory is bubbler's own and holds only what the proxy put
        // there; the socket it served has been moved out of it already.
        let _ = std::fs::remove_dir_all(&self.socket_dir);
    }
}

/// Wait for the sidecar's ready byte, which says it has bound its socket
/// and is accepting connections. False when the deadline passes, the pipe
/// reaches EOF or the child is gone: in each case nothing is listening on
/// the socket the sandbox is about to bind.
fn wait_ready(ready: &OwnedFd, child: &mut Child, deadline: Instant) -> bool {
    let mut byte = [0u8; 1];
    loop {
        let slice = Timespec {
            tv_sec: POLL.as_secs() as Secs,
            tv_nsec: POLL.subsec_nanos() as Nsecs,
        };
        match poll(&mut [PollFd::new(ready, PollFlags::IN)], Some(&slice)) {
            // `Ok(0)` already waited out the slice; a failing poll keeps
            // failing, so sleep rather than spin until the deadline.
            Ok(0) => {}
            Err(_) => std::thread::sleep(POLL),
            Ok(_) => match rustix::io::read(ready, &mut byte) {
                Ok(0) => return false,
                Ok(_) => return true,
                Err(Errno::INTR) => {}
                Err(_) => return false,
            },
        }
        if Instant::now() >= deadline {
            return false;
        }
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            return false;
        }
    }
}

/// Start the filtering D-Bus proxy for an instance in its own sandbox and
/// wait for it to report readiness, so the socket exists before the
/// instance's own bwrap binds it. The returned handle must stay alive for
/// as long as the sandbox runs.
pub fn start_proxy(
    env: &Env,
    dir: &Path,
    plan: &dbus::Plan,
    host: &dyn Host,
) -> Result<ProxyHandle, LaunchError> {
    let host_bus = service::require_socket(host, "dbus", dbus::host_bus(env))?;
    // The proxy gets this directory and nothing else of the instance's
    // runtime state, so it is created here rather than bound from above.
    mkdir_private(&dbus::socket_dir(dir))?;
    let mut alloc = RealAlloc::sidecar();
    let argv = proxy_argv(env, plan, &host_bus, dir, host, &mut alloc)?;
    let child = Command::new("bwrap")
        .args(&argv)
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    // From here on every exit path stops the proxy through the handle.
    let mut handle = ProxyHandle {
        child,
        alloc,
        socket_dir: dbus::socket_dir(dir),
    };
    // The instance's own bwrap must not inherit these: a second holder of
    // the ready pipe would keep the proxy alive after the run has ended.
    for fd in &handle.alloc.fds {
        fcntl_setfd(fd, FdFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    }
    let ProxyHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no ready pipe was allocated")))?;
    if !wait_ready(ready, child, Instant::now() + PROXY_READY) {
        return Err(LaunchError::ProxyNotReady);
    }
    Ok(handle)
}

/// Open a directory bubbler itself created under `$XDG_RUNTIME_DIR`,
/// for the `*at` calls that move the proxied socket.
fn open_dir(path: &Path) -> Result<OwnedFd, LaunchError> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
}

/// Prove the proxy really left a socket behind and move it out of the one
/// directory the proxy can write to, so what the sandbox binds cannot be
/// swapped between this check and the bind.
///
/// The proxy keeps serving after the move: it listens on the socket it
/// bound, not on the path, and the sandbox connects through the new one.
// Opened with `O_NOFOLLOW`, so a symlink left in the socket's place fails
// with ELOOP instead of being followed: `stat` through a path reports the
// type of the target, and bwrap would bind that target.
fn adopt_proxy_bus(dir: &Path) -> Result<(), LaunchError> {
    let from = open_dir(&dbus::socket_dir(dir))?;
    let to = open_dir(dir)?;
    let path = dbus::proxy_bus_path(dir);
    let wrong_type = || LaunchError::WrongType {
        service: "dbus",
        path: path.clone(),
        expected: "a socket",
    };
    let bus = rustix::fs::openat(
        &from,
        "bus",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP => wrong_type(),
        Errno::NOENT => LaunchError::MissingResource {
            service: "dbus",
            path: path.clone(),
        },
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let stat = rustix::fs::fstat(&bus).map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Socket {
        return Err(wrong_type());
    }
    drop(bus);
    rustix::fs::renameat(&from, "bus", &to, "bus")
        .map_err(|e| LaunchError::Io(dbus::app_bus_path(dir), e.into()))
}

/// `$XDG_RUNTIME_DIR/bubbler/<name>`: an instance's runtime state on the
/// host. `name` is an instance name the caller has already validated.
pub fn instance_runtime_dir(env: &Env, name: &str) -> PathBuf {
    env.runtime_dir.join("bubbler").join(name)
}

/// Create `dir` with mode 0700, tolerating one that already exists. Only
/// the user can create anything under `$XDG_RUNTIME_DIR`, so a directory
/// left over from an earlier run is reused as is.
fn mkdir_private(dir: &Path) -> Result<(), LaunchError> {
    match rustix::fs::mkdir(dir, Mode::RWXU) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(LaunchError::Io(dir.to_path_buf(), e.into())),
    }
}

/// Create `$XDG_RUNTIME_DIR/bubbler/<name>/` with mode 0700; an existing
/// directory is reused as is. Not a lock: what a second start of the same
/// instance collides with is the control socket in it.
pub fn prepare_runtime_dir(env: &Env, inst: &Instance) -> Result<PathBuf, LaunchError> {
    // Each level is created 0700 outright rather than created wide and
    // narrowed afterwards; a missing $XDG_RUNTIME_DIR is created, but its
    // parent is not, since that would mean the session has no runtime dir.
    mkdir_private(&env.runtime_dir)?;
    mkdir_private(&env.runtime_dir.join("bubbler"))?;
    let dir = instance_runtime_dir(env, &inst.name);
    mkdir_private(&dir)?;
    Ok(dir)
}

/// Process exit code to propagate: the child's code, or `128 + signal`.
pub fn exit_code(status: ExitStatus) -> i32 {
    if let Some(c) = status.code() {
        c
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        1
    }
}

/// Value of `child-pid` in bwrap's `--info-fd` JSON. Scanned rather than
/// parsed: bwrap adds members over time and only this one matters.
fn parse_child_pid(buf: &[u8]) -> Option<i32> {
    const KEY: &[u8] = b"\"child-pid\"";
    let after = buf.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let rest = &buf[after..];
    let colon = rest.iter().position(|b| *b == b':')?;
    let tail = &rest[colon + 1..];
    let start = tail.iter().position(|b| !b.is_ascii_whitespace())?;
    let end = start
        + tail[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    // Digits running to the end of the buffer may still be half read, so
    // they only count once something follows them.
    if end == start || end == tail.len() {
        return None;
    }
    std::str::from_utf8(&tail[start..end]).ok()?.parse().ok()
}

/// End of the first complete JSON object in `buf`: braces counted outside
/// strings. bwrap writes its info as one multi-line document, and a
/// truncated one is no use to the portals that parse it.
fn json_object_end(buf: &[u8]) -> Option<usize> {
    let mut depth = 0u32;
    let mut in_string = false;
    let mut escaped = false;
    for (i, b) in buf.iter().enumerate() {
        match b {
            _ if escaped => escaped = false,
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Read the info pipe until bwrap has reported a whole document with
/// `child-pid` in it, or until the deadline, EOF or the child's own exit
/// says it never will. The bytes come back as bwrap wrote them: portals
/// read that same document out of `bwrapinfo.json`.
fn read_sandbox_info(
    info: &OwnedFd,
    child: &mut Child,
    deadline: Instant,
) -> Option<(i32, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        if let Some(end) = json_object_end(&buf)
            && let Some(pid) = parse_child_pid(&buf[..end])
        {
            buf.truncate(end);
            return Some((pid, buf));
        }
        if Instant::now() >= deadline || child.try_wait().ok()?.is_some() {
            return None;
        }
        let slice = Timespec {
            tv_sec: POLL.as_secs() as Secs,
            tv_nsec: POLL.subsec_nanos() as Nsecs,
        };
        match poll(&mut [PollFd::new(info, PollFlags::IN)], Some(&slice)) {
            // A signal during startup is acted on by the wait loop, so
            // every interruption here is simply retried until the deadline.
            Ok(0) | Err(_) => continue,
            Ok(_) => {}
        }
        match rustix::io::read(info, &mut chunk) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(Errno::INTR) => {}
            Err(_) => return None,
        }
    }
}

/// Host pid of the supervisor in the sandbox, for signalling it directly.
/// `reaper` is the `child-pid` bwrap reported.
///
/// That reaper is pid 1 of the sandbox's pid namespace and ignores every
/// signal from outside it that it has no handler for
/// (`pid_namespaces(7)`); `bubbler-init` is its only child at startup and
/// does handle SIGTERM.
// Only callable once the sandbox has been released: a sandbox still
// waiting on `--block-fd` has not forked the supervisor yet.
fn supervisor_pid(reaper: i32, child: &mut Child, deadline: Instant) -> Option<Pid> {
    let children = PathBuf::from(format!("/proc/{reaper}/task/{reaper}/children"));
    loop {
        // Only an empty list is worth waiting on: the reaper forks the
        // supervisor a moment after it appears. A read that fails means
        // the sandbox is already gone, or this kernel has no `children`
        // file, and neither gets better by asking again.
        let list = std::fs::read_to_string(&children).ok()?;
        if let Some(pid) = list
            .split_ascii_whitespace()
            .next()
            .and_then(|p| p.parse::<i32>().ok())
            .and_then(Pid::from_raw)
        {
            return Some(pid);
        }
        if Instant::now() >= deadline || child.try_wait().ok()?.is_some() {
            return None;
        }
        std::thread::sleep(POLL);
    }
}

/// Removes one of the run's own files when it leaves, on every path: the
/// control socket, and the proxied bus socket once it has been moved.
struct FileGuard(PathBuf);

impl Drop for FileGuard {
    fn drop(&mut self) {
        // Nothing to report: a concurrent start may have replaced the
        // socket, and a stale one is detected by connecting to it anyway.
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Removes this run's `$XDG_RUNTIME_DIR/.flatpak/<instance>` when the run
/// leaves, on every path. Only that entry: the `.flatpak` directory above
/// it is flatpak's own and holds other sandboxes' instances.
struct FlatpakGuard(PathBuf);

impl Drop for FlatpakGuard {
    fn drop(&mut self) {
        // Nothing to report: the directory holds this run's identity and
        // nothing else, and a leftover only names a pid that is gone.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Publish bwrap's own info document as
/// `$XDG_RUNTIME_DIR/.flatpak/<instance>/bwrapinfo.json`, which is how
/// xdg-desktop-portal turns a sandboxed bus peer into a pidfd of the
/// sandbox. The guard removes the directory again when the run ends.
fn publish_bwrapinfo(env: &Env, instance: &str, info: &[u8]) -> Result<FlatpakGuard, LaunchError> {
    mkdir_private(&env.runtime_dir.join(dbus::FLATPAK_DIR))?;
    let dir = dbus::flatpak_instance_dir(env, instance);
    mkdir_private(&dir)?;
    // From here on the directory is removed again however this ends.
    let guard = FlatpakGuard(dir.clone());
    // Written and renamed inside the directory, so a portal reading it
    // never sees half a document.
    let tmp = dir.join(format!("{}.new", dbus::BWRAPINFO));
    std::fs::write(&tmp, info).map_err(|e| LaunchError::Io(tmp.clone(), e))?;
    let dest = dir.join(dbus::BWRAPINFO);
    std::fs::rename(&tmp, &dest).map_err(|e| LaunchError::Io(dest, e))?;
    Ok(guard)
}

/// Give xdg-desktop-portal this run's identity, or say why portals will
/// not work. Never fatal: an app whose portal calls fail still runs.
fn publish_identity(env: &Env, instance: &str, info: Option<&[u8]>) -> Option<FlatpakGuard> {
    let Some(info) = info else {
        eprintln!("bubbler: warning: the sandbox reported no pid, so portal operations will fail");
        return None;
    };
    match publish_bwrapinfo(env, instance, info) {
        Ok(guard) => Some(guard),
        Err(e) => {
            // `LaunchError::Io` shows the path; what went wrong is its source.
            let why = std::error::Error::source(&e).map_or_else(String::new, |s| format!(": {s}"));
            eprintln!("bubbler: warning: {e}{why}, so portal operations will fail");
            None
        }
    }
}

/// Let the sandbox past its `--block-fd`. Closing the pipe releases it
/// just as the byte does, so a failed write still starts the app.
fn release_block(alloc: &mut RealAlloc) {
    if let Some(fd) = alloc.block_write.take() {
        let _ = rustix::io::write(&fd, b"\n");
    }
}

/// Drops this run's SIGINT/SIGTERM actions when it leaves, so a later run
/// never sees a stale flag. `signal-hook` leaves its own handler in place,
/// so both signals stay caught and are ignored until the next run.
struct SignalGuard(Vec<SigId>);

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            // `false` only means the handler was already removed.
            let _ = signal_hook::low_level::unregister(id);
        }
    }
}

/// Start the instance: bind its control socket, run bwrap around
/// `bubbler-init`, forward SIGINT/SIGTERM once as SIGTERM and return the
/// exit code to propagate. `AlreadyRunning` when the instance is live;
/// that is an exec, which the caller decides on.
pub fn run(env: &Env, inst: &Instance, command: Option<&[OsString]>) -> Result<i32, LaunchError> {
    let dir = prepare_runtime_dir(env, inst)?;
    if exec::connect(env, &inst.name)?.is_some() {
        return Err(LaunchError::AlreadyRunning(inst.name.clone()));
    }
    let sock_path = dir.join(exec::SOCKET_NAME);
    let io_at = |e: Errno| LaunchError::Io(sock_path.clone(), e.into());
    let listener =
        UnixListener::bind(&sock_path).map_err(|e| LaunchError::Io(sock_path.clone(), e))?;
    let _socket_guard = FileGuard(sock_path.clone());
    let inherited = fcntl_dupfd_cloexec(listener.as_fd(), 3).map_err(io_at)?;
    // bwrap must inherit exactly this one fd; everything else stays CLOEXEC.
    fcntl_setfd(&inherited, FdFlags::empty()).map_err(io_at)?;
    let mut alloc = RealAlloc::new(inherited.as_raw_fd());
    // A run with nothing to run must fail before a sidecar is started.
    resolve_command(inst, command)?;
    // Before the argv is built, so the proxy's socket is there for bwrap
    // to bind: a missing bind source is a failed start, not a warning.
    let plan = dbus::plan(&inst.config.services, &inst.name);
    let portals = plan.as_ref().is_some_and(|p| p.portals);
    let _proxy = match &plan {
        Some(plan) => Some(start_proxy(env, &dir, plan, &RealHost)?),
        None => None,
    };
    // Between the proxy's ready byte and the sandbox's bind the socket is
    // checked and moved where the proxy cannot reach it.
    let _bus = match &plan {
        Some(_) => {
            adopt_proxy_bus(&dir)?;
            Some(FileGuard(dbus::app_bus_path(&dir)))
        }
        None => None,
    };
    let argv = build_argv(env, inst, command, &mut alloc)?;
    let stop = Arc::new(AtomicBool::new(false));
    let mut registered = SignalGuard(Vec::new());
    for sig in [SIGINT, SIGTERM] {
        let id =
            signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(LaunchError::Signal)?;
        registered.0.push(id);
    }
    let mut child = Command::new("bwrap")
        .args(&argv)
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    // The sandbox holds the listening socket and the info pipe now; bubbler
    // keeping copies would make a dead instance look live and hide the EOF.
    drop(inherited);
    drop(listener);
    drop(alloc.info_write.take());
    let deadline = Instant::now() + INFO_TIMEOUT;
    let info = alloc
        .info_read
        .as_ref()
        .and_then(|fd| read_sandbox_info(fd, &mut child, deadline));
    // Before the supervisor is looked for: a sandbox held at `--block-fd`
    // has not forked it yet, so there would be nothing to find.
    let _identity = if portals {
        let published = publish_identity(env, &inst.name, info.as_ref().map(|(_, raw)| &raw[..]));
        // However that went, the sandbox is let go: an app that cannot
        // reach portals still has to run.
        release_block(&mut alloc);
        published
    } else {
        None
    };
    let supervisor = info
        .as_ref()
        .and_then(|(reaper, _)| supervisor_pid(*reaper, &mut child, deadline));
    let status = loop {
        if let Some(status) = child.try_wait().map_err(LaunchError::Spawn)? {
            break status;
        }
        if stop.swap(false, Ordering::SeqCst) {
            // bubblewrap 0.11.2 exits on SIGTERM instead of forwarding it,
            // so the signal goes to the supervisor, which stops the command
            // within its grace period; without its pid the sandbox can only
            // be brought down through bwrap and --die-with-parent. Racing
            // the child's own exit is normal, so a failed kill is not an
            // error.
            let target = supervisor.unwrap_or_else(|| Pid::from_child(&child));
            let _ = kill_process(target, Signal::TERM);
        }
        std::thread::sleep(POLL);
    };
    // bwrap copies the data files out of the fds while it starts, so they
    // must stay open until it has exited.
    drop(alloc);
    Ok(exit_code(status))
}

/// Run `argv` inside the live instance `name` and return its exit code.
pub fn exec(env: &Env, name: &str, argv: &[OsString]) -> Result<i32, LaunchError> {
    match exec::connect(env, name)? {
        Some(stream) => exec::run_in(&stream, argv),
        None => Err(LaunchError::NotRunning(name.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bwrap::INIT_INSIDE;
    use std::os::unix::net::UnixStream;

    /// An `Env` whose `$BUBBLER_INIT` points at a stand-in binary, so
    /// argv building does not depend on where the test binary lives.
    fn env(tmp: &Path) -> Env {
        let init = tmp.join("bubbler-init");
        std::fs::write(&init, b"").unwrap();
        Env {
            home: tmp.join("home"),
            data_home: tmp.join("data"),
            runtime_dir: tmp.join("run"),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: Some(init),
            dbus_address: None,
            dbus_log: false,
            proxy_override: None,
        }
    }

    fn inst(tmp: &Path, kdl: &str) -> Instance {
        Instance {
            name: "t".into(),
            dir: tmp.join("data/bubbler/instances/t"),
            config: crate::config::parse(kdl).unwrap(),
        }
    }

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn argv_uses_config_command_unless_overridden() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\" \"-e\" \"fish\"");
        let a = build_argv(&e, &i, None, &mut DryRunAlloc::default()).unwrap();
        assert_eq!(
            &a[a.len() - 4..],
            &[
                OsString::from("--"),
                "foot".into(),
                "-e".into(),
                "fish".into()
            ]
        );
        let a = build_argv(
            &e,
            &i,
            Some(&[OsString::from("ls")]),
            &mut DryRunAlloc::default(),
        )
        .unwrap();
        assert_eq!(&a[a.len() - 2..], &[OsString::from("--"), "ls".into()]);
    }

    #[test]
    fn the_init_binary_is_bound_and_wraps_the_command() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default()).unwrap());
        let init = tmp.path().join("bubbler-init").display().to_string();
        assert!(
            a.windows(3)
                .any(|w| w == ["--ro-bind", init.as_str(), INIT_INSIDE])
        );
        assert_eq!(
            &a[a.len() - 6..],
            &["--", INIT_INSIDE, "--socket-fd", "6", "--", "foot"]
        );
    }

    #[test]
    fn a_missing_init_binary_is_a_missing_resource() {
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.init_override = Some(tmp.path().join("gone"));
        let i = inst(tmp.path(), "command \"foot\"");
        assert!(matches!(
            build_argv(&e, &i, None, &mut DryRunAlloc::default()),
            Err(LaunchError::MissingResource {
                service: "init",
                ..
            })
        ));
    }

    #[test]
    fn config_env_pairs_reach_the_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(
            tmp.path(),
            "env MOZ_ENABLE_WAYLAND=\"1\"\ncommand \"firefox\"",
        );
        let a = build_argv(&e, &i, None, &mut DryRunAlloc::default()).unwrap();
        let s = strs(&a);
        assert!(
            s.windows(3)
                .any(|w| w == ["--setenv", "MOZ_ENABLE_WAYLAND", "1"])
        );
    }

    #[test]
    fn no_command_anywhere_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "");
        assert!(matches!(
            build_argv(&e, &i, None, &mut DryRunAlloc::default()),
            Err(LaunchError::Config(ConfigError::MissingCommand))
        ));
        assert!(matches!(
            build_argv(&e, &i, Some(&[]), &mut DryRunAlloc::default()),
            Err(LaunchError::Config(ConfigError::MissingCommand))
        ));
    }

    #[test]
    fn runtime_dir_is_created_private_and_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "");
        let d = prepare_runtime_dir(&e, &i).unwrap();
        assert_eq!(d, tmp.path().join("run/bubbler/t"));
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        prepare_runtime_dir(&e, &i).unwrap();
    }

    #[test]
    fn a_live_instance_is_never_started_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"/usr/bin/true\"");
        let dir = prepare_runtime_dir(&e, &i).unwrap();
        let _listener = UnixListener::bind(dir.join(exec::SOCKET_NAME)).unwrap();
        assert!(matches!(
            run(&e, &i, None),
            Err(LaunchError::AlreadyRunning(n)) if n == "t"
        ));
    }

    #[test]
    fn exec_without_a_live_instance_is_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        assert!(matches!(
            exec(&e, "t", &[OsString::from("/usr/bin/true")]),
            Err(LaunchError::NotRunning(n)) if n == "t"
        ));
    }

    #[test]
    fn proxy_argv_runs_the_proxy_in_its_own_sandbox() {
        use crate::config::Service;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(&[Service::Dbus { rules: vec![] }, Service::Notify], "t")
            .expect("dbus is granted");
        let argv = proxy_argv(
            &e,
            &plan,
            Path::new("/run/user/1000/bus"),
            Path::new("/run/user/1000/bubbler/t"),
            &FakeHost::default(),
            &mut DryRunAlloc::default(),
        )
        .unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/bin",
                "/sbin",
                "--tmpfs",
                "/etc",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/run/user/1000/bus",
                "/run/user/1000/bus",
                "--bind",
                "/run/user/1000/bubbler/t/dbus",
                "/run/user/1000/bubbler/t/dbus",
                "--perms",
                "0644",
                "--ro-bind-data",
                "4",
                "/.flatpak-info",
                "--clearenv",
                "--",
                "xdg-dbus-proxy",
                "--fd=3",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "--talk=org.freedesktop.Notifications",
            ]
        );
    }

    #[test]
    fn the_proxy_never_sees_the_instances_control_socket() {
        use crate::config::Service;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        let dir = Path::new("/run/user/1000/bubbler/t");
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                Path::new("/run/user/1000/bus"),
                dir,
                &FakeHost::default(),
                &mut DryRunAlloc::default(),
            )
            .unwrap(),
        );
        // Compared element-wise: the instance directory is a prefix of the
        // socket directory, so a substring check would prove nothing.
        assert!(
            !argv.iter().any(|a| a == dir.to_str().unwrap()),
            "the instance directory itself is bound: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.contains(exec::SOCKET_NAME)),
            "the control socket is reachable from the proxy: {argv:?}"
        );
        // Where the checked socket is moved to; naming it here would give
        // the proxy the path the sandbox actually binds.
        let app_bus = dbus::app_bus_path(dir).display().to_string();
        assert!(
            !argv.contains(&app_bus),
            "the proxy names the socket the sandbox binds: {argv:?}"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == "--bind").count(),
            1,
            "the socket directory is the only writable bind: {argv:?}"
        );
    }

    #[test]
    fn proxy_argv_logs_only_when_asked() {
        use crate::config::Service;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.dbus_log = true;
        let plan = dbus::plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                Path::new("/run/user/1000/bus"),
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut DryRunAlloc::default(),
            )
            .unwrap(),
        );
        assert_eq!(&argv[argv.len() - 2..], &["--filter", "--log"]);
    }

    #[test]
    fn an_overriding_proxy_binary_is_bound_in_and_run() {
        use crate::config::Service;
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        let fake = tmp.path().join("fake-proxy");
        e.proxy_override = Some(fake.clone());
        let plan = dbus::plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        let (file, _, _) = types();
        let host = FakeHost::default().with(&fake.to_string_lossy(), file);
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                Path::new("/run/user/1000/bus"),
                Path::new("/run/user/1000/bubbler/t"),
                &host,
                &mut DryRunAlloc::default(),
            )
            .unwrap(),
        );
        let fake = fake.display().to_string();
        assert!(
            argv.windows(3)
                .any(|w| w == ["--ro-bind", fake.as_str(), fake.as_str()]),
            "{argv:?}"
        );
        assert_eq!(argv[argv.len() - 6..argv.len() - 4], ["--", fake.as_str()]);
        // Nothing is bound for a binary that is not there to run.
        assert!(matches!(
            proxy_argv(
                &e,
                &plan,
                Path::new("/run/user/1000/bus"),
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut DryRunAlloc::default(),
            ),
            Err(LaunchError::MissingResource {
                service: "dbus",
                ..
            })
        ));
    }

    #[test]
    fn a_dbus_instance_binds_the_proxied_socket_in_a_dry_run() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "dbus\nportals\ncommand \"x\"");
        let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default()).unwrap());
        let bus = tmp.path().join("run/bubbler/t/bus").display().to_string();
        let inside = tmp.path().join("run/bus").display().to_string();
        assert!(
            a.windows(3)
                .any(|w| w == ["--ro-bind", bus.as_str(), inside.as_str()]),
            "{a:?}"
        );
        assert!(
            a.windows(3).any(|w| w
                == [
                    "--setenv",
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={inside}").as_str()
                ]),
            "{a:?}"
        );
        assert!(a.contains(&"/.flatpak-info".to_string()), "{a:?}");
    }

    #[test]
    fn only_a_portals_instance_waits_for_its_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "dbus\nportals\ncommand \"x\"");
        let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default()).unwrap());
        assert!(a.windows(2).any(|w| w == ["--block-fd", "4"]), "{a:?}");
        for kdl in ["dbus\ncommand \"x\"", "command \"x\""] {
            let i = inst(tmp.path(), kdl);
            let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default()).unwrap());
            assert!(!a.contains(&"--block-fd".to_string()), "{kdl}: {a:?}");
        }
    }

    #[test]
    fn a_proxied_socket_is_moved_out_of_the_proxys_reach() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        let listener = UnixListener::bind(dbus::proxy_bus_path(dir)).unwrap();
        adopt_proxy_bus(dir).unwrap();
        let moved = std::fs::symlink_metadata(dbus::app_bus_path(dir)).unwrap();
        assert!(std::os::unix::fs::FileTypeExt::is_socket(
            &moved.file_type()
        ));
        assert!(!dbus::proxy_bus_path(dir).exists());
        // The proxy serves the socket it bound, not the path it bound it at.
        assert!(UnixStream::connect(dbus::app_bus_path(dir)).is_ok());
        drop(listener);
    }

    #[test]
    fn anything_but_a_socket_in_the_proxys_directory_stops_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir),
            Err(LaunchError::MissingResource {
                service: "dbus",
                ..
            })
        ));
        // A symlink is the attack: `stat` through it would report the type
        // of its target, and bwrap would bind that target.
        std::os::unix::fs::symlink("/etc", dbus::proxy_bus_path(dir)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir),
            Err(LaunchError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            })
        ));
        std::fs::remove_file(dbus::proxy_bus_path(dir)).unwrap();
        std::fs::write(dbus::proxy_bus_path(dir), b"").unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir),
            Err(LaunchError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            })
        ));
        assert!(!dbus::app_bus_path(dir).exists());
    }

    #[test]
    fn dry_run_alloc_numbers_every_fd_from_three() {
        let mut alloc = DryRunAlloc::default();
        assert_eq!(alloc.data(b"a").unwrap(), OsString::from("3"));
        assert_eq!(alloc.data(b"b").unwrap(), OsString::from("4"));
        assert_eq!(alloc.init_socket().unwrap(), OsString::from("5"));
        assert_eq!(alloc.ready_pipe().unwrap(), OsString::from("6"));
        assert_eq!(alloc.info_pipe().unwrap(), OsString::from("7"));
        assert_eq!(alloc.block_pipe().unwrap(), OsString::from("8"));
    }

    #[test]
    fn real_alloc_block_pipe_hands_the_sandbox_the_read_end() {
        use std::io::Read;
        let mut alloc = RealAlloc::new(7);
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
    fn a_json_object_ends_at_its_closing_brace() {
        let doc = b"{\n    \"child-pid\": 7\n}\n";
        assert_eq!(json_object_end(doc), Some(doc.len() - 1));
        assert_eq!(json_object_end(b"{\"a\": {\"b\": 1}}"), Some(15));
        // Braces inside a string do not close the object, and a document
        // still being written has no end yet.
        assert_eq!(json_object_end(b"{\"a\": \"}\", \"b\": 1}"), Some(18));
        assert_eq!(json_object_end(b"{\"a\": \"\\\"}\"}"), Some(12));
        assert_eq!(json_object_end(b"{\n    \"child-pid\": 7"), None);
        assert_eq!(json_object_end(b""), None);
    }

    #[test]
    fn real_alloc_data_is_readable_from_the_start_and_inheritable() {
        use std::io::Read;
        let mut alloc = RealAlloc::new(7);
        let fd = alloc.data(b"hello").unwrap();
        assert_eq!(alloc.init_socket().unwrap(), OsString::from("7"));
        assert_eq!(alloc.fds.len(), 1);
        assert_eq!(fd, OsString::from(alloc.fds[0].as_raw_fd().to_string()));
        assert_eq!(
            rustix::io::fcntl_getfd(&alloc.fds[0]).unwrap(),
            FdFlags::empty()
        );
        // A dup shares the file offset, so this reads what bwrap would read.
        let mut got = String::new();
        std::fs::File::from(alloc.fds[0].try_clone().unwrap())
            .read_to_string(&mut got)
            .unwrap();
        assert_eq!(got, "hello");
    }

    #[test]
    fn real_alloc_ready_pipe_keeps_the_read_end() {
        use std::io::Read;
        let mut alloc = RealAlloc::new(7);
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
        let mut alloc = RealAlloc::new(7);
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

    #[test]
    fn child_pid_is_scanned_out_of_bwraps_json() {
        assert_eq!(
            parse_child_pid(b"{\n    \"child-pid\": 4321,\n    \"net-namespace\": 7\n}"),
            Some(4321)
        );
        assert_eq!(parse_child_pid(b"{\"child-pid\":9}"), Some(9));
        // A pid still being written, no pid, and no member at all.
        assert_eq!(parse_child_pid(b"{\n    \"child-pid\": 43"), None);
        assert_eq!(parse_child_pid(b"{\n    \"child-pid\": }"), None);
        assert_eq!(parse_child_pid(b"{\"cgroup-namespace\": 4026533374}"), None);
        assert_eq!(parse_child_pid(b""), None);
    }

    #[test]
    fn exit_code_from_status() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
