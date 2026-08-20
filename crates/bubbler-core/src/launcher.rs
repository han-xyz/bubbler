//! Spawns bubblewrap. The only process-spawning code in the crate; it
//! never goes through a shell.

use std::ffi::OsString;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{AtFlags, MemfdFlags, Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use rustix::process::{Pid, Signal, kill_process, test_kill_process};
use signal_hook::SigId;
use signal_hook::consts::{SIGINT, SIGTERM, SIGWINCH};

use crate::bwrap::{BwrapArgs, FdAllocator};
use crate::env::Env;
use crate::error::{ConfigError, LaunchError};
use crate::host::{Host, RealHost};
use crate::instance::Instance;
use crate::tty::{self, Pty, RawGuard, RelayEnd, StdioTarget, TtyMode};
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

/// How long the supervisor has to appear inside the sandbox before the
/// run goes on without a pid to signal.
const SUPERVISOR_WAIT: Duration = Duration::from_secs(2);

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
/// bwrap reads it from. `ctty` says the sandbox's stdin will be the slave
/// of a pty bubbler allocated, which is the only case in which the
/// supervisor may claim it.
pub fn build_argv(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    alloc: &mut dyn FdAllocator,
    ctty: bool,
) -> Result<Vec<OsString>, LaunchError> {
    let command = resolve_command(inst, command)?;
    let host = RealHost;
    let plan = dbus::plan(&inst.config.services, &inst.name);
    let ctx = service::ServiceCtx {
        instance_runtime: instance_runtime_dir(env, &inst.name),
        dbus: plan.as_ref(),
    };
    let mut args = BwrapArgs::baseline(env, &inst.home(), &host);
    if ctty {
        args.ctty();
    }
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

/// Move the proxy's socket out of the one directory the proxy can write
/// to, then prove that what was moved really is a socket. The returned
/// guard removes the moved entry when the run ends.
///
/// The proxy keeps serving after the move: it listens on the socket it
/// bound, not on the path, and the sandbox connects through the new one.
// The move comes first and the check second: the reverse leaves a window
// in which a proxy that keeps swapping the name can put a symlink in the
// place of the socket that was just checked. Nothing outside the instance
// directory can touch the entry once it is here, so its type cannot
// change after this. `O_NOFOLLOW` then makes a symlink fail with ELOOP
// instead of being followed, since `stat` through a path would report the
// type of the target and bwrap would bind that target.
fn adopt_proxy_bus(dir: &Path) -> Result<FileGuard, LaunchError> {
    let from = open_dir(&dbus::socket_dir(dir))?;
    let to = open_dir(dir)?;
    let path = dbus::app_bus_path(dir);
    rustix::fs::renameat(&from, "bus", &to, "bus").map_err(|e| match e {
        Errno::NOENT => LaunchError::MissingResource {
            service: "dbus",
            path: dbus::proxy_bus_path(dir),
        },
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    // Whatever was moved is bubbler's to remove from here on, socket or not.
    let guard = FileGuard(path.clone());
    let wrong_type = || LaunchError::WrongType {
        service: "dbus",
        path: path.clone(),
        expected: "a socket",
    };
    let bus = rustix::fs::openat(
        &to,
        "bus",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP => wrong_type(),
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let stat = rustix::fs::fstat(&bus).map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if kind != rustix::fs::FileType::Socket {
        // A directory cannot be unlinked as a file, and one left at this
        // name would fail the rename of every later start of the instance.
        if kind == rustix::fs::FileType::Directory {
            remove_moved_dir(&to, &path);
        }
        return Err(wrong_type());
    }
    Ok(guard)
}

/// Remove a directory the proxy planted where its socket belongs. Whatever
/// it holds goes with it: after the move nothing but bubbler can reach it.
fn remove_moved_dir(inst: &OwnedFd, path: &Path) {
    if rustix::fs::unlinkat(inst, "bus", AtFlags::REMOVEDIR).is_err() {
        let _ = std::fs::remove_dir_all(path);
    }
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

/// Whether `pid` is running the supervisor, by the name in
/// `/proc/<pid>/comm`. The reaper's child carries bwrap's name until it
/// execs, and a failed exec leaves something else there entirely.
fn is_supervisor(pid: Pid) -> bool {
    let comm = format!("/proc/{}/comm", pid.as_raw_nonzero());
    std::fs::read_to_string(comm).is_ok_and(|name| name == format!("{}\n", init_bin::NAME))
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
        // An empty list and a child that has not exec'd yet are both worth
        // waiting on: the reaper forks the supervisor a moment after it
        // appears. A read that fails means the sandbox is already gone, or
        // this kernel has no `children` file, and neither gets better by
        // asking again.
        let list = std::fs::read_to_string(&children).ok()?;
        if let Some(pid) = list
            .split_ascii_whitespace()
            .next()
            .and_then(|p| p.parse::<i32>().ok())
            .and_then(Pid::from_raw)
            && is_supervisor(pid)
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

/// Removes this run's `$XDG_RUNTIME_DIR/.flatpak/bubbler-<instance>` when
/// the run leaves, on every path. Only that entry, and only one this run
/// created: the `.flatpak` directory above it is shared with flatpak and
/// holds other sandboxes' instances.
struct FlatpakGuard(PathBuf);

impl Drop for FlatpakGuard {
    fn drop(&mut self) {
        // Nothing to report: the directory holds this run's identity and
        // nothing else, and a leftover only names a pid that is gone.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Remove a `.flatpak` entry a killed run left behind, and only that: a
/// directory holding nothing but a `bwrapinfo.json` whose `child-pid` is
/// no longer a live process. Anything else is someone's to keep.
fn sweep_identity(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let names: Vec<OsString> = entries.flatten().map(|e| e.file_name()).collect();
    if names != [OsString::from(dbus::BWRAPINFO)] {
        return;
    }
    let Ok(info) = std::fs::read(dir.join(dbus::BWRAPINFO)) else {
        return;
    };
    // `kill(pid, 0)` fails with ESRCH only when no process has that pid;
    // EPERM means it is alive and owned by someone else.
    let gone = parse_child_pid(&info)
        .and_then(Pid::from_raw)
        .is_some_and(|pid| test_kill_process(pid) == Err(Errno::SRCH));
    if gone {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Publish bwrap's own info document as
/// `$XDG_RUNTIME_DIR/.flatpak/bubbler-<instance>/bwrapinfo.json`, which is
/// how xdg-desktop-portal turns a sandboxed bus peer into a pidfd of the
/// sandbox. The guard removes the directory again when the run ends.
///
/// The instance directory is created outright, never adopted: a second
/// run of the same instance must not publish over the first one's
/// identity, and a directory that is not a dead run's is an error.
fn publish_bwrapinfo(env: &Env, instance: &str, info: &[u8]) -> Result<FlatpakGuard, LaunchError> {
    mkdir_private(&env.runtime_dir.join(dbus::FLATPAK_DIR))?;
    let dir = dbus::flatpak_instance_dir(env, instance);
    sweep_identity(&dir);
    rustix::fs::mkdir(&dir, Mode::RWXU)
        .map_err(|e| LaunchError::Io(dir.to_path_buf(), e.into()))?;
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

/// Drops this run's signal actions when it leaves, so a later run never
/// sees a stale flag. `signal-hook` leaves its own handler in place, so
/// the signals stay caught and are ignored until the next run.
pub(crate) struct SignalGuard(pub(crate) Vec<SigId>);

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            // `false` only means the handler was already removed.
            let _ = signal_hook::low_level::unregister(id);
        }
    }
}

/// What bwrap is spawned with for one of fds 0, 1 and 2. The slave is
/// duplicated per fd, so closing bubbler's own copy after the spawn
/// leaves the sandbox's three intact.
fn stdio_for(target: StdioTarget, pty: Option<&Pty>) -> Result<Stdio, LaunchError> {
    match (target, pty) {
        (StdioTarget::Slave, Some(p)) => {
            Ok(Stdio::from(p.slave.try_clone().map_err(LaunchError::Pty)?))
        }
        // A plan naming a pty that was never allocated is a bug; handing
        // the sandbox bubbler's own terminal instead would hide it.
        (StdioTarget::Slave, None) => Err(LaunchError::Pty(io::Error::other(
            "no pty was allocated for this sandbox",
        ))),
        (StdioTarget::Inherit, _) => Ok(Stdio::inherit()),
        (StdioTarget::Null, _) => Ok(Stdio::null()),
        (StdioTarget::Pipe, _) => Ok(Stdio::piped()),
    }
}

/// Forward a caught signal to the sandbox and report the exit code once
/// bwrap has one. The single place a run learns that it is over.
fn check_exit(
    child: &mut Child,
    stop: &AtomicBool,
    supervisor: Option<Pid>,
) -> io::Result<Option<i32>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(exit_code(status)));
    }
    if stop.swap(false, Ordering::SeqCst) {
        // bubblewrap 0.11.2 exits on SIGTERM instead of forwarding it,
        // so the signal goes to the supervisor, which stops the command
        // within its grace period; without its pid the sandbox can only
        // be brought down through bwrap and --die-with-parent. Racing
        // the child's own exit is normal, so a failed kill is not an
        // error.
        let target = supervisor.unwrap_or_else(|| Pid::from_child(child));
        let _ = kill_process(target, Signal::TERM);
    }
    Ok(None)
}

/// The exit check as the relay wants it: a closure reporting the code
/// once there is one. A `try_wait` that fails ends the wait too, with the
/// error left in `failed` for the caller to return.
fn until_exit<'a>(
    child: &'a mut Child,
    stop: &'a AtomicBool,
    supervisor: Option<Pid>,
    failed: &'a mut Option<io::Error>,
) -> impl FnMut() -> Option<i32> + 'a {
    move || match check_exit(child, stop, supervisor) {
        Ok(code) => code,
        Err(e) => {
            *failed = Some(e);
            Some(1)
        }
    }
}

/// Wait for a sandbox that has no terminal and no pipes of ours: nothing
/// to move, so the loop only watches for the exit and for signals.
fn wait_plain(
    child: &mut Child,
    stop: &AtomicBool,
    supervisor: Option<Pid>,
) -> Result<i32, LaunchError> {
    loop {
        if let Some(code) = check_exit(child, stop, supervisor).map_err(LaunchError::Spawn)? {
            return Ok(code);
        }
        std::thread::sleep(POLL);
    }
}

/// Wait while copying the sandbox's output pipes to bubbler's own stdout
/// and stderr, which is all `tty "none"` needs.
fn wait_pumping(
    child: &mut Child,
    stop: &AtomicBool,
    supervisor: Option<Pid>,
    pipes: &[(BorrowedFd<'_>, BorrowedFd<'_>)],
    sink: BorrowedFd<'_>,
) -> Result<i32, LaunchError> {
    let mut failed = None;
    let code = {
        let mut until = until_exit(child, stop, supervisor, &mut failed);
        tty::pump(pipes, sink, &mut until)?
    };
    match failed {
        Some(e) => Err(LaunchError::Spawn(e)),
        None => Ok(code),
    }
}

/// The host side of a relayed run: what the user types, which only
/// reaches the pty when the sandbox reads through it; where the pty's
/// output goes; and where it is drained when nothing of bubbler's can
/// take that output, or after a detach.
struct RelayEnds<'a> {
    input: Option<BorrowedFd<'a>>,
    output: BorrowedFd<'a>,
    sink: BorrowedFd<'a>,
}

/// Wait while relaying between the user's terminal and the sandbox's pty.
///
/// Detaching ends the relay, not the run: bubbler holds the master, and
/// closing it would hang up the terminal inside, while leaving would take
/// the sandbox with it through `--die-with-parent`. So it goes on
/// waiting, quietly, with the pty drained into `sink` so a program inside
/// cannot fill it and block.
fn wait_relaying(
    child: &mut Child,
    stop: &AtomicBool,
    supervisor: Option<Pid>,
    winch: &AtomicBool,
    master: BorrowedFd<'_>,
    ends: RelayEnds<'_>,
    raw: &mut Option<RawGuard<'_>>,
) -> Result<i32, LaunchError> {
    let mut failed = None;
    let end = {
        let mut until = until_exit(child, stop, supervisor, &mut failed);
        tty::relay(
            master,
            ends.input,
            ends.output,
            ends.sink,
            &mut until,
            winch,
        )?
    };
    if let Some(e) = failed {
        return Err(LaunchError::Spawn(e));
    }
    let code = match end {
        RelayEnd::Exited(code) => code,
        RelayEnd::Detached => {
            // Restored first: the note would otherwise be printed with the
            // terminal still raw, and its newline would not return the
            // cursor to the first column.
            if let Some(guard) = raw.as_mut() {
                guard.restore();
            }
            eprintln!("{}", tty::DETACHED_NOTE);
            let mut until = until_exit(child, stop, supervisor, &mut failed);
            match tty::relay(master, None, ends.sink, ends.sink, &mut until, winch)? {
                RelayEnd::Exited(code) => code,
                // Nothing is read from the user any more, so there is
                // nothing left that could ask to detach.
                RelayEnd::Detached => 0,
            }
        }
    };
    match failed {
        Some(e) => Err(LaunchError::Spawn(e)),
        None => Ok(code),
    }
}

/// Start the instance: bind its control socket, run bwrap around
/// `bubbler-init`, forward SIGINT/SIGTERM once as SIGTERM and return the
/// exit code to propagate. `mode` decides what the sandbox gets for stdio;
/// in `pty` mode bubbler allocates one and relays, so the sandbox never
/// holds a descriptor for the user's terminal. `AlreadyRunning` when the
/// instance is live; that is an exec, which the caller decides on.
pub fn run(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    mode: TtyMode,
) -> Result<i32, LaunchError> {
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
    // moved where the proxy cannot reach it, and only then checked.
    let _bus = match &plan {
        Some(_) => Some(adopt_proxy_bus(&dir)?),
        None => None,
    };
    let host = tty::host_stdio()?;
    let is_tty = tty::host_is_tty();
    let mut stdio = tty::plan(mode, is_tty);
    // The pty copies the settings of the first terminal bubbler has, and
    // is allocated before raw mode: afterwards it would carry raw
    // settings, leaving the sandbox without echo or line editing.
    if let Some(i) = stdio
        .needs_pty()
        .then(|| is_tty.iter().position(|t| *t))
        .flatten()
    {
        stdio.pty = Some(tty::allocate(host[i].as_fd())?);
    }
    let argv = build_argv(env, inst, command, &mut alloc, stdio.ctty())?;
    let stop = Arc::new(AtomicBool::new(false));
    let winch = Arc::new(AtomicBool::new(false));
    let mut registered = SignalGuard(Vec::new());
    for sig in [SIGINT, SIGTERM] {
        let id =
            signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(LaunchError::Signal)?;
        registered.0.push(id);
    }
    if stdio.needs_pty() {
        let id = signal_hook::flag::register(SIGWINCH, Arc::clone(&winch))
            .map_err(LaunchError::Signal)?;
        registered.0.push(id);
    }
    // Raw from here on: the pty inside has the line discipline now, so
    // Ctrl-C is a byte for it and the guard restores the terminal on
    // every way out of this function.
    let mut raw = match stdio.raw_mode() {
        true => Some(RawGuard::new(host[0].as_fd())?),
        false => None,
    };
    let mut child = Command::new("bwrap")
        .args(&argv)
        .stdin(stdio_for(stdio.fds[0], stdio.pty.as_ref())?)
        .stdout(stdio_for(stdio.fds[1], stdio.pty.as_ref())?)
        .stderr(stdio_for(stdio.fds[2], stdio.pty.as_ref())?)
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
    // The slave goes with it: the sandbox has its own copies, and one left
    // here would keep the pty from ever reporting the end of its output.
    let master = stdio.pty.take().map(|p| p.master);
    let mut pipes: Vec<(OwnedFd, usize)> = Vec::new();
    if let Some(out) = child.stdout.take() {
        pipes.push((out.into(), 1));
    }
    if let Some(err) = child.stderr.take() {
        pipes.push((err.into(), 2));
    }
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
    // Its own deadline: the one above may already have been spent waiting
    // for bwrap's info document.
    let supervisor = info.as_ref().and_then(|(reaper, _)| {
        supervisor_pid(*reaper, &mut child, Instant::now() + SUPERVISOR_WAIT)
    });
    // Output the user's own descriptors cannot take goes here instead:
    // when none of them can be written to at all (`bubbler run x
    // < /dev/tty > out`), when one stops taking it (a reader that left),
    // and after a detach. Draining somewhere is what keeps a command from
    // blocking on a full pty or pipe.
    let sink = tty::null_stdio()?;
    let code = match &master {
        Some(master) => {
            let out = tty::output_fd(&stdio, &host);
            let host_out = out.map_or(sink.as_fd(), |i| host[i].as_fd());
            let ends = RelayEnds {
                input: stdio.ctty().then(|| host[0].as_fd()),
                output: host_out,
                sink: sink.as_fd(),
            };
            wait_relaying(
                &mut child,
                &stop,
                supervisor,
                &winch,
                master.as_fd(),
                ends,
                &mut raw,
            )
        }
        None if !pipes.is_empty() => {
            let ends: Vec<(BorrowedFd<'_>, BorrowedFd<'_>)> = pipes
                .iter()
                .map(|(read, i)| (read.as_fd(), host[*i].as_fd()))
                .collect();
            wait_pumping(&mut child, &stop, supervisor, &ends, sink.as_fd())
        }
        None => wait_plain(&mut child, &stop, supervisor),
    }?;
    // bwrap copies the data files out of the fds while it starts, so they
    // must stay open until it has exited.
    drop(alloc);
    Ok(code)
}

/// Run `argv` inside the live instance `name` and return its exit code.
/// `mode` decides the terminal the command inside gets, exactly as for
/// [`run`].
pub fn exec(env: &Env, name: &str, argv: &[OsString], mode: TtyMode) -> Result<i32, LaunchError> {
    match exec::connect(env, name)? {
        Some(stream) => exec::run_in(&stream, argv, mode),
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
        let a = build_argv(&e, &i, None, &mut DryRunAlloc::default(), false).unwrap();
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
            false,
        )
        .unwrap();
        assert_eq!(&a[a.len() - 2..], &[OsString::from("--"), "ls".into()]);
    }

    #[test]
    fn the_init_binary_is_bound_and_wraps_the_command() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default(), false).unwrap());
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
            build_argv(&e, &i, None, &mut DryRunAlloc::default(), false),
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
        let a = build_argv(&e, &i, None, &mut DryRunAlloc::default(), false).unwrap();
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
            build_argv(&e, &i, None, &mut DryRunAlloc::default(), false),
            Err(LaunchError::Config(ConfigError::MissingCommand))
        ));
        assert!(matches!(
            build_argv(&e, &i, Some(&[]), &mut DryRunAlloc::default(), false),
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
            run(&e, &i, None, TtyMode::Passthrough),
            Err(LaunchError::AlreadyRunning(n)) if n == "t"
        ));
    }

    #[test]
    fn exec_without_a_live_instance_is_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        assert!(matches!(
            exec(&e, "t", &[OsString::from("/usr/bin/true")], TtyMode::Passthrough),
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
        let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default(), false).unwrap());
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
        let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default(), false).unwrap());
        assert!(a.windows(2).any(|w| w == ["--block-fd", "4"]), "{a:?}");
        for kdl in ["dbus\ncommand \"x\"", "command \"x\""] {
            let i = inst(tmp.path(), kdl);
            let a = strs(&build_argv(&e, &i, None, &mut DryRunAlloc::default(), false).unwrap());
            assert!(!a.contains(&"--block-fd".to_string()), "{kdl}: {a:?}");
        }
    }

    #[test]
    fn a_proxied_socket_is_moved_out_of_the_proxys_reach() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        let listener = UnixListener::bind(dbus::proxy_bus_path(dir)).unwrap();
        let guard = adopt_proxy_bus(dir).unwrap();
        let moved = std::fs::symlink_metadata(dbus::app_bus_path(dir)).unwrap();
        assert!(std::os::unix::fs::FileTypeExt::is_socket(
            &moved.file_type()
        ));
        assert!(!dbus::proxy_bus_path(dir).exists());
        // The proxy serves the socket it bound, not the path it bound it at.
        assert!(UnixStream::connect(dbus::app_bus_path(dir)).is_ok());
        drop(listener);
        drop(guard);
        assert!(
            !dbus::app_bus_path(dir).exists(),
            "the socket outlived the run"
        );
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
        // Moved out of the proxy's reach first, so a refused run leaves
        // nothing of it behind either.
        assert!(!dbus::app_bus_path(dir).exists(), "the symlink was kept");
        assert!(
            !dbus::proxy_bus_path(dir).exists(),
            "the symlink was left in place"
        );
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
        // A directory is refused like anything else, and removed with what
        // is in it: `remove_file` cannot take one, and one left at this
        // name would fail the rename of every later start.
        std::fs::create_dir(dbus::proxy_bus_path(dir)).unwrap();
        std::fs::write(dbus::proxy_bus_path(dir).join("x"), b"").unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir),
            Err(LaunchError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            })
        ));
        assert!(!dbus::app_bus_path(dir).exists(), "the directory was kept");
        // And the next honest start works.
        let listener = UnixListener::bind(dbus::proxy_bus_path(dir)).unwrap();
        adopt_proxy_bus(dir).expect("a socket after a refused directory");
        drop(listener);
    }

    /// A pid no process has: a child that has already been reaped.
    fn dead_pid() -> u32 {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    fn bwrapinfo(pid: u32) -> Vec<u8> {
        format!("{{\n    \"child-pid\": {pid},\n    \"x\": 1\n}}\n").into_bytes()
    }

    #[test]
    fn a_dead_runs_identity_directory_is_swept_before_the_new_one_is_made() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = dbus::flatpak_instance_dir(&e, "t");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(dbus::BWRAPINFO), bwrapinfo(dead_pid())).unwrap();
        let guard = publish_bwrapinfo(&e, "t", &bwrapinfo(4321)).unwrap();
        assert_eq!(
            std::fs::read(dir.join(dbus::BWRAPINFO)).unwrap(),
            bwrapinfo(4321)
        );
        drop(guard);
        assert!(!dir.exists(), "the identity outlived the run");
    }

    #[test]
    fn an_identity_directory_that_is_not_a_dead_runs_is_never_adopted() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = dbus::flatpak_instance_dir(&e, "t");
        // A live pid: another bubbler is using this instance's identity.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(dbus::BWRAPINFO), bwrapinfo(std::process::id())).unwrap();
        assert!(matches!(
            publish_bwrapinfo(&e, "t", &bwrapinfo(4321)),
            Err(LaunchError::Io(_, _))
        ));
        // Anything else in it is not something bubbler put there.
        std::fs::write(dir.join(dbus::BWRAPINFO), bwrapinfo(dead_pid())).unwrap();
        std::fs::write(dir.join("other"), b"").unwrap();
        assert!(matches!(
            publish_bwrapinfo(&e, "t", &bwrapinfo(4321)),
            Err(LaunchError::Io(_, _))
        ));
        assert!(dir.join("other").is_file(), "a foreign file was removed");
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
    fn only_a_process_running_the_supervisor_is_signalled() {
        let me = Pid::from_raw(std::process::id() as i32).expect("a live pid");
        assert!(!is_supervisor(me), "this test binary is not the supervisor");
    }

    #[test]
    fn exit_code_from_status() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
