//! Spawns bubblewrap and the sidecars a sandbox needs: the D-Bus, Wayland and
//! egress proxies, the audio sidecars, pasta and `nft`. The only
//! process-spawning code in the crate; it never goes through a shell.
//! Every spawn is preceded by a [`fds::sweep_cloexec`], so a child holds
//! only the descriptors it was meant to: each public function that spawns
//! marks the caller's other descriptors above stdio close-on-exec, closing
//! none. Every sidecar is killed on every way out of a run.

use std::ffi::{OsStr, OsString, c_void};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{Access, AtFlags, FlockOperation, MemfdFlags, Mode, OFlags, SealFlags, flock};
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use rustix::ioctl::{self, Opcode};
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{
    DumpableBehavior, Pid, Signal, kill_process, set_dumpable_behavior,
    set_parent_process_death_signal,
};
use rustix::thread::{
    CapabilitiesSecureBits, CapabilitySet, CapabilitySets, LinkNameSpaceType, capabilities,
    clear_ambient_capability_set, configure_capability_in_ambient_set, move_into_link_name_space,
    set_capabilities, set_capabilities_secure_bits, set_no_new_privs,
};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};

use bubbler_init::fds;

use crate::bwrap::{Argv, Explained, FdAllocator};
use crate::config::{NetworkConfig, Service, WaylandMode};
use crate::env::Env;
use crate::exec::SignalGuard;
pub use crate::exec::exit_code;
use crate::host::{Host, RealHost};
use crate::instance::Instance;
pub use crate::paths::{RUNTIME_SUBDIR, instance_runtime_dir};
pub(crate) use crate::paths::{START_LOCK_SUFFIX, start_lock_path};
use crate::plan::plan_error::PlanError;
use crate::run::launch_error::{LaunchError, NetworkError, PipeWireError};
pub use crate::sidecar_argv::{
    DryRunAlloc, build_argv, explain, explain_net_proxy, explain_wayland_proxy, proxy_argv,
    pw_context_argv, pw_pulse_argv, resolve_command, wl_proxy_argv, wl_proxy_plan,
};
use crate::sidecar_argv::{
    SIDECAR_PREFIX, build_args_on, data_name, network_of, proxy_args, wayland_mode, wayland_node,
};
use crate::tty::{self, Pty, StdioTarget, TtyMode};
use crate::tty_relay::{self, RawGuard, RelayEnd};
use crate::wayland::ProxyPlan;
use crate::wayland_context::{self, WaylandError};
use crate::{
    cgroup, dbus, dbus_a11y, exec, init_bin, network, pipewire, proc, run_log, service, version,
    version_probe, wayland,
};

const POLL: Duration = Duration::from_millis(100);

// Past this the run goes on without a pid to stop the sandbox gracefully.
const INFO_TIMEOUT: Duration = Duration::from_secs(5);

const PROXY_READY: Duration = Duration::from_secs(5);

const PROXY_STOP: Duration = Duration::from_secs(1);

const WL_PROXY_STOP: Duration = Duration::from_secs(5);

pub(crate) const PW_READY: Duration = Duration::from_secs(5);

const PW_STOP: Duration = Duration::from_secs(5);

// The server reports readiness on nothing: this bounds the wait for its socket.
pub(crate) const PULSE_READY: Duration = Duration::from_secs(5);

const PULSE_STOP: Duration = Duration::from_secs(5);

// The holder writes a constant of bubbler's; a longer line is not the holder answering.
const PW_REPORT_MAX: usize = 4096;

const PASTA_READY: Duration = Duration::from_secs(5);

const PASTA_STOP: Duration = Duration::from_secs(1);

// A bound on a hang, not on the work: `nft` took 1.5 ms when measured.
pub(crate) const NFT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the egress proxy has to report that it is listening. It binds one socket after three
/// `setns` calls; this is a bound on a hang and not on the work.
pub(crate) const NET_PROXY_READY: Duration = Duration::from_secs(5);

const NET_PROXY_STOP: Duration = Duration::from_secs(5);

const SUPERVISOR_WAIT: Duration = Duration::from_secs(2);

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
pub struct RealAlloc {
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
    pub fn new(socket: RawFd, dir: PathBuf) -> Self {
        let mut a = Self::in_dir(dir, "");
        a.socket = Some(socket);
        a
    }

    /// Allocate for a sidecar sandbox: generated files and a ready pipe, no control socket, and
    /// file names apart from the application sandbox's.
    pub fn sidecar(dir: PathBuf) -> Self {
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
    pub fn sidecar_listening(listener: OwnedFd, dir: PathBuf) -> Self {
        let mut a = Self::sidecar(dir);
        a.listen = Some(listener);
        a
    }

    fn keep(&mut self, fd: OwnedFd) -> OsString {
        let n = fd.as_raw_fd();
        self.fds.push(fd);
        OsString::from(n.to_string())
    }

    fn close_listener(&mut self) {
        if let Some(fd) = self.listen_fd.take() {
            self.fds.retain(|held| held.as_raw_fd() != fd);
        }
    }

    // A sealed memfd rather than a pipe, so nothing has to write while bwrap reads, whatever the
    // length.
    fn options(&mut self, options: &[OsString]) -> io::Result<OsString> {
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

    fn close_options(&mut self) {
        if let Some(fd) = self.options_fd.take() {
            self.fds.retain(|held| held.as_raw_fd() != fd);
        }
    }

    // CLOEXEC at rest, cleared only around the one spawn they were built for. That window is
    // process-wide; bubbler's other threads (run-log copier, KDL parser) open no fd, spawn nothing,
    // and no configuration is parsed while the window is open.
    fn inheritable(&self, on: bool) -> io::Result<()> {
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
    fn intended(&self) -> Vec<RawFd> {
        let mut fds: Vec<RawFd> = self.fds.iter().map(AsRawFd::as_raw_fd).collect();
        fds.extend(self.socket);
        fds.extend(self.info_write.as_ref().map(AsRawFd::as_raw_fd));
        fds
    }
}

// Call immediately before a spawn. Nothing is closed: bubbler's own descriptors only stop
// crossing into children. Process-wide like `RealAlloc::inheritable`.
fn spawning(keep: &[RawFd]) -> Result<(), LaunchError> {
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

/// The D-Bus sidecar's argv with what produced each argument, or `None` where no bus is
/// granted. Host sockets are not probed, but addresses are resolved as a run would, which for
/// the accessibility bus may ask `org.a11y.Bus`.
pub fn explain_proxy(env: &Env, inst: &Instance) -> Result<Option<Vec<Explained>>, LaunchError> {
    let Some(plan) = dbus::plan(&inst.config.services, &inst.name) else {
        return Ok(None);
    };
    let session = plan
        .session
        .as_ref()
        .map(|_| dbus::guarded_host_bus(&RealHost, env))
        .transpose()?;
    let system = plan
        .system
        .as_ref()
        .map(|_| dbus::guarded_host_system_bus(&RealHost, env))
        .transpose()?;
    let a11y = plan
        .a11y
        .as_ref()
        .map(|_| dbus_a11y::guarded_host_a11y_bus(&RealHost, env))
        .transpose()?;
    let dir = instance_runtime_dir(env, &inst.name);
    let mut alloc = DryRunAlloc::sidecar(dir.clone());
    let (args, command) = proxy_args(
        env,
        &plan,
        dbus::HostBuses {
            session: session.as_deref(),
            system: system.as_deref(),
            a11y: a11y.as_deref(),
        },
        &dir,
        &RealHost,
        &mut alloc,
    )?;
    Ok(Some(args.finish_plain_explained(&command, &mut alloc)?))
}

/// A running D-Bus proxy sidecar. Dropping it closes the ready pipe, which is what makes
/// `xdg-dbus-proxy` exit, so it must outlive the sandbox using the socket.
#[derive(Debug)]
pub struct ProxyHandle {
    child: Child,
    alloc: RealAlloc,
    socket_dir: PathBuf,
    _stderr: run_log::Relay,
}

impl Drop for ProxyHandle {
    // The proxy leaves on `POLLHUP` of its write end, which needs our read end gone too; one that
    // ignores it is killed.
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
        // Holds only what the proxy put there; the socket it served was moved out already.
        remove_sidecar_dir(&self.socket_dir);
    }
}

// False on deadline, EOF or a gone child: nothing is listening either way. `Stopped` once
// `stop` is set: a Ctrl-C reaches the sidecar's process group too.
fn wait_ready(
    ready: &OwnedFd,
    child: &mut Child,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<bool, LaunchError> {
    let mut byte = [0u8; 1];
    let is_ready = loop {
        let slice = Timespec {
            tv_sec: POLL.as_secs() as Secs,
            tv_nsec: POLL.subsec_nanos() as Nsecs,
        };
        match poll(&mut [PollFd::new(ready, PollFlags::IN)], Some(&slice)) {
            // `Ok(0)` already waited out the slice; a failing poll keeps failing, so sleep.
            Ok(0) => {}
            Err(_) => std::thread::sleep(POLL),
            Ok(_) => match rustix::io::read(ready, &mut byte) {
                Ok(0) => break false,
                Ok(_) => break true,
                Err(Errno::INTR) => {}
                Err(_) => break false,
            },
        }
        if stop.load(Ordering::SeqCst) {
            return Err(LaunchError::Stopped);
        }
        if Instant::now() >= deadline {
            break false;
        }
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            break false;
        }
    };
    if !is_ready && stop.load(Ordering::SeqCst) {
        return Err(LaunchError::Stopped);
    }
    Ok(is_ready)
}

// A reaped sidecar's pid may be a stranger's by now; `try_wait` answers from its cached status,
// so a reaping anywhere in the run is caught here.
fn still_running(child: &mut Child) -> bool {
    !matches!(child.try_wait(), Ok(Some(_)))
}

/// A run's Wayland sidecar: the proxy, the socket it accepts on and, where the compositor took
/// one, the security context. Dropping it stops the proxy and ends the context, so it must
/// outlive the sandbox.
#[derive(Debug)]
pub struct WaylandHandle {
    child: Child,
    alloc: RealAlloc,
    // The compositor's `close_fd`; `None` where it offers no security context.
    _close: Option<OwnedFd>,
    _socket: FileGuard,
    _context: Option<FileGuard>,
    _stderr: run_log::Relay,
}

impl Drop for WaylandHandle {
    // To bwrap, whose `--die-with-parent` takes the proxy down: the proxy holds no pipe of
    // bubbler's whose hangup it could see.
    fn drop(&mut self) {
        if still_running(&mut self.child) {
            if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
                let _ = kill_process(pid, Signal::TERM);
            }
            let deadline = Instant::now() + WL_PROXY_STOP;
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
        }
        self.alloc.fds.clear();
        self.alloc.ready_read.take();
    }
}

/// Bind the socket this run's application connects to and start `bubbler-wl-proxy` behind it,
/// through a security context where the compositor has one. `Ok(None)` only for `wayland
/// "host"`. The handle must outlive the sandbox.
pub fn start_wayland(
    env: &Env,
    dir: &Path,
    inst: &Instance,
    host: &dyn Host,
    stop: &AtomicBool,
) -> Result<Option<WaylandHandle>, LaunchError> {
    let (Some(WaylandMode::Sandboxed { clipboard }), Some(node)) = (
        wayland_mode(&inst.config.services),
        wayland_node(&inst.config.services),
    ) else {
        return Ok(None);
    };
    // The bind's own check, made before connecting: a display name that is a path would pick the
    // endpoint. wayrs reads the process environment itself, so both values go through it.
    let display = service::wayland_display(env)?;
    service::check_wayland_display(std::env::var_os("WAYLAND_DISPLAY").as_deref())?;
    wayland_context::refuse_inherited(std::env::var_os("WAYLAND_SOCKET").as_deref())?;
    let plan = match wayland_context::probe()? {
        true => ProxyPlan::context(dir, clipboard),
        false => {
            eprintln!(
                "bubbler: note: wayland: no wp_security_context_manager_v1; \
                 the proxy hides the privileged globals instead"
            );
            // Follows symlinks, as the bind does: the name is one component under the user's own
            // 0700 `$XDG_RUNTIME_DIR`, so whatever could plant a link there is already the user.
            let session = service::require_socket(host, "wayland", env.runtime_dir.join(display))?;
            ProxyPlan::fallback(dir, session, clipboard)
        }
    };
    // The context makes the connection behind it a sandboxed client's, so it precedes the dial.
    let (close, context) = match plan.context {
        true => {
            let (close, guard) = bind_context(dir, &inst.name)?;
            (Some(close), Some(guard))
        }
        false => (None, None),
    };
    let listener = bind_listener(&plan.listener)?;
    let socket = FileGuard(plan.listener.clone());
    let mut alloc = RealAlloc::sidecar_listening(listener.into(), dir.to_path_buf());
    let argv = wl_proxy_argv(env, &plan, node, host, &mut alloc)?;
    let cmd = bwrap_command(&argv, &mut alloc)?;
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let (child, stderr) = spawn_sidecar(cmd, false)?;
    let mut handle = WaylandHandle {
        child,
        alloc,
        _stderr: stderr,
        _close: close,
        _socket: socket,
        _context: context,
    };
    // Nothing of bubbler's may accept on the sandbox's display socket, and a second holder would
    // keep connections queueing after the sidecar died instead of refusing them.
    handle.alloc.close_listener();
    handle.alloc.close_options();
    // CLOEXEC again before the instance's own bwrap: the ready pipe belongs to this spawn only.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let WaylandHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no ready pipe was allocated")))?;
    if !wait_ready(ready, child, Instant::now() + PROXY_READY, stop)? {
        let what = match child.try_wait() {
            Ok(Some(status)) => format!("it exited ({status})"),
            _ => format!("it did not report a listening socket within {PROXY_READY:?}"),
        };
        return Err(WaylandError::ProxyNotReady(what).into());
    }
    Ok(Some(handle))
}

// Removes a socket left by a killed run; any error but a missing file is the instance's own
// 0700 directory refusing, which the bind would not survive either.
fn bind_listener(path: &Path) -> Result<UnixListener, LaunchError> {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Err(WaylandError::Listen(path.to_path_buf(), e).into());
    }
    UnixListener::bind(path).map_err(|e| WaylandError::Listen(path.to_path_buf(), e).into())
}

// The context lasts exactly as long as the returned close pipe end and socket guard.
fn bind_context(dir: &Path, instance: &str) -> Result<(OwnedFd, FileGuard), LaunchError> {
    let path = wayland::context_socket_path(dir);
    let listener = bind_listener(&path)?;
    let guard = FileGuard(path);
    // CLOEXEC on both ends: any other holder of the write end would keep the compositor accepting.
    let (close_read, close_write) =
        pipe_with(PipeFlags::CLOEXEC).map_err(|e| WaylandError::Pipe(e.into()))?;
    wayland_context::create_context(
        listener.into(),
        close_read,
        &dbus::app_id(instance),
        &dbus::flatpak_instance_id(instance),
    )?;
    Ok((close_write, guard))
}

/// A run's PipeWire security context and its sidecar. `pw-container` tears the context down when
/// its program exits, so dropping this ends it; it must outlive the sandbox.
#[derive(Debug)]
pub struct PwHandle {
    child: Child,
    alloc: RealAlloc,
    // `pw-container` unlinks the name it chose, which the holder renamed away, so what is left
    // here is bubbler's.
    dir: PathBuf,
    // `None` until the socket is moved out of `dir`; until then it goes with the directory.
    _socket: Option<FileGuard>,
    _stderr: run_log::Relay,
}

impl Drop for PwHandle {
    // To bwrap, not `pw-container`, which ignores SIGTERM until its program exits (measured on
    // 1.6.8); bwrap dying takes the pid namespace with it.
    fn drop(&mut self) {
        if still_running(&mut self.child) {
            if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
                let _ = kill_process(pid, Signal::TERM);
            }
            let deadline = Instant::now() + PW_STOP;
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
        }
        self.alloc.fds.clear();
        self.alloc.ready_read.take();
        // Holds nothing but the context socket, and the sandbox that bound it has exited.
        remove_sidecar_dir(&self.dir);
    }
}

/// Create this run's PipeWire security context and wait for its socket, which bwrap then binds.
/// `Ok(None)` where no audio is granted. The handle must outlive the sandbox.
pub fn start_pw_context(
    env: &Env,
    dir: &Path,
    inst: &Instance,
    host: &dyn Host,
    stop: &AtomicBool,
) -> Result<Option<PwHandle>, LaunchError> {
    let Some(audio) = inst.config.audio() else {
        return Ok(None);
    };
    // Checked before anything starts: otherwise a missing tool surfaces as a sidecar that never
    // reported its socket.
    service::require_file(host, "pipewire", PathBuf::from(pipewire::PW_CONTAINER))?;
    // Probed here, not with the sandbox's argv: that names only the context's socket, and its
    // explanation describes a host whose daemon may not be up yet.
    service::require_socket(host, "pipewire", pipewire::host_socket(&env.runtime_dir))?;
    let pw = pipewire::dir(dir);
    fresh_sidecar_dir(&pw)?;
    // The pid of this run: two runs of one instance are then two
    // contexts on the daemon's side rather than one name used twice.
    let run_id = std::process::id().to_string();
    let ctx = pipewire::Context {
        instance_runtime: dir,
        instance: &inst.name,
        run_id: &run_id,
        audio,
    };
    let mut alloc = RealAlloc::sidecar(dir.to_path_buf());
    let argv = pw_context_argv(env, &ctx, host, &mut alloc)?;
    let cmd = bwrap_command(&argv, &mut alloc)?;
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let (child, stderr) = spawn_sidecar(cmd, false)?;
    let mut handle = PwHandle {
        child,
        alloc,
        _stderr: stderr,
        dir: pw,
        _socket: None,
    };
    handle.alloc.close_options();
    // A second holder of the report pipe would keep bubbler from seeing it hang up.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let PwHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no report pipe was allocated")))?;
    // The holder reports the name as its own sandbox sees it (that `/tmp` is this directory), so
    // the only answer taken is the planned name.
    if read_report(ready, child, Instant::now() + PW_READY, stop)?.as_deref()
        != Some(pipewire::SOCKET_INSIDE)
    {
        return Err(match child.try_wait() {
            Ok(Some(status)) => PipeWireError::ContextExited(status),
            _ => PipeWireError::ContextSilent,
        }
        .into());
    }
    handle._socket = Some(adopt_socket(
        "pipewire",
        (&pipewire::dir(dir), pipewire::SOCKET_NAME),
        (dir, pipewire::SOCKET_NAME),
        env.uid,
    )?);
    Ok(Some(handle))
}

// A byte at a time: the descriptor stays open afterwards, so a longer read would block on a
// pipe with nothing more coming.
fn read_report(
    ready: &OwnedFd,
    child: &mut Child,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<Option<String>, LaunchError> {
    let mut line = Vec::new();
    let report = loop {
        let slice = Timespec {
            tv_sec: POLL.as_secs() as Secs,
            tv_nsec: POLL.subsec_nanos() as Nsecs,
        };
        match poll(&mut [PollFd::new(ready, PollFlags::IN)], Some(&slice)) {
            // `Ok(0)` already waited out the slice; a failing poll keeps failing, so sleep.
            Ok(0) => {}
            Err(_) => std::thread::sleep(POLL),
            Ok(_) => {
                let mut byte = [0u8; 1];
                match rustix::io::read(ready, &mut byte) {
                    Ok(0) => break None,
                    Ok(_) if byte[0] == b'\n' => break String::from_utf8(line).ok(),
                    Ok(_) if line.len() >= PW_REPORT_MAX => break None,
                    Ok(_) => line.push(byte[0]),
                    Err(Errno::INTR) => {}
                    Err(_) => break None,
                }
            }
        }
        if stop.load(Ordering::SeqCst) {
            return Err(LaunchError::Stopped);
        }
        if Instant::now() >= deadline {
            break None;
        }
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            break None;
        }
    };
    if report.is_none() && stop.load(Ordering::SeqCst) {
        return Err(LaunchError::Stopped);
    }
    Ok(report)
}

// The sidecar keeps serving after the move: it listens on the socket it bound, not on the path,
// and the sandbox connects through the new one.
// Move first, check second: the reverse lets a sidecar swap a symlink in after the check, and
// bwrap resolves bind sources through links. Once moved, only bubbler can touch the entry.
fn adopt_socket(
    service: &'static str,
    from: (&Path, &str),
    to: (&Path, &str),
    uid: u32,
) -> Result<FileGuard, LaunchError> {
    let (from_dir, made) = from;
    let (to_dir, name) = to;
    // `from_dir` may be one the sidecar made or replaced (the pulse
    // server's `pulse`), so a link at its name is refused, not followed.
    let source = open_dir_nofollow(rustix::fs::CWD, from_dir, from_dir, service)?;
    let target = open_dir(to_dir)?;
    let path = to_dir.join(name);
    clear_socket_name(&target, to_dir, name)
        .map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    rustix::fs::renameat(&source, made, &target, name).map_err(|e| match e {
        Errno::NOENT => LaunchError::Plan(PlanError::MissingResource {
            service,
            path: from_dir.join(made),
        }),
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let guard = FileGuard(path.clone());
    let wrong_type = |expected| {
        LaunchError::Plan(PlanError::WrongType {
            service,
            path: path.clone(),
            expected,
        })
    };
    let socket = rustix::fs::openat(
        &target,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP => wrong_type("a socket"),
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let stat = rustix::fs::fstat(&socket).map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if kind != rustix::fs::FileType::Socket {
        // A directory cannot be unlinked as a file, and one left at this
        // name would fail the rename of every later start of the instance.
        if kind == rustix::fs::FileType::Directory {
            remove_moved_dir(&target, to_dir, name);
        }
        return Err(wrong_type("a socket"));
    }
    if stat.st_uid != uid {
        return Err(wrong_type("a socket owned by this user"));
    }
    Ok(guard)
}

/// A run's private PulseAudio server sidecar. Dropping it stops the server, so it must outlive
/// the sandbox, and it drops before [`PwHandle`], whose context it is a client of.
#[derive(Debug)]
pub struct PulseHandle {
    child: Child,
    alloc: RealAlloc,
    dir: PathBuf,
    // `None` until the socket is moved out of `dir`; until then it goes with the directory.
    _socket: Option<FileGuard>,
    _stderr: run_log::Relay,
}

impl Drop for PulseHandle {
    // To bwrap, whose `--die-with-parent` takes the server down with it.
    fn drop(&mut self) {
        if still_running(&mut self.child) {
            if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
                let _ = kill_process(pid, Signal::TERM);
            }
            let deadline = Instant::now() + PULSE_STOP;
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
        }
        self.alloc.fds.clear();
        // Holds only this server's files, and the sandbox that bound its socket has exited.
        remove_sidecar_dir(&self.dir);
    }
}

/// Start this run's private PulseAudio server, a client of [`start_pw_context`]'s context, and
/// wait for its socket. `Ok(None)` without `pulseaudio`. The handle must outlive the sandbox.
pub fn start_pw_pulse(
    env: &Env,
    dir: &Path,
    inst: &Instance,
    host: &dyn Host,
    stop: &AtomicBool,
) -> Result<Option<PulseHandle>, LaunchError> {
    if !inst
        .config
        .services
        .iter()
        .any(|s| matches!(s, Service::Pulseaudio { .. }))
    {
        return Ok(None);
    }
    // Checked first: without the module the server serves no protocol, and the run would fail on
    // the readiness deadline instead of naming the missing package.
    service::require_file(host, "pulseaudio", PathBuf::from(pipewire::PULSE_MODULE))?;
    prepare_pulse_dir(env, host, dir)?;
    let pw = pipewire::pulse_dir(dir);
    let made_in = pipewire::pulse_socket_dir(dir);
    let made = made_in.join(pipewire::PULSE_NATIVE);
    let mut alloc = RealAlloc::sidecar(dir.to_path_buf());
    let argv = pw_pulse_argv(env, dir, host, &mut alloc)?;
    let cmd = bwrap_command(&argv, &mut alloc)?;
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let (child, stderr) = spawn_sidecar(cmd, false)?;
    let mut handle = PulseHandle {
        child,
        alloc,
        _stderr: stderr,
        dir: pw,
        _socket: None,
    };
    handle.alloc.close_options();
    // The instance's own bwrap must not inherit the seccomp descriptor
    // this argv was built with.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let deadline = Instant::now() + PULSE_READY;
    while !made.exists() {
        // Before the exit: a Ctrl-C reaches this server's process group
        // too, and kills it.
        if stop.load(Ordering::SeqCst) {
            return Err(LaunchError::Stopped);
        }
        if let Ok(Some(status)) = handle.child.try_wait() {
            return Err(PipeWireError::PulseExited(status).into());
        }
        if Instant::now() >= deadline {
            return Err(PipeWireError::PulseSilent(made.to_path_buf()).into());
        }
        std::thread::sleep(POLL);
    }
    handle._socket = Some(adopt_socket(
        "pulseaudio",
        (&made_in, pipewire::PULSE_NATIVE),
        (dir, pipewire::PULSE_ADOPTED),
        env.uid,
    )?);
    Ok(Some(handle))
}

fn prepare_pulse_dir(env: &Env, host: &dyn Host, dir: &Path) -> Result<(), LaunchError> {
    // Made afresh, so nothing a dead run left is taken for the new server's socket or written
    // through.
    fresh_sidecar_dir(&pipewire::pulse_dir(dir))?;
    // The server creates no directory for its address (measured on 1.6.8: "bind() to
    // '/tmp/pulse/native' failed: No such file or directory").
    mkdir_private(&pipewire::pulse_socket_dir(dir))?;
    write_pulse_config(env, host, dir)?;
    Ok(())
}

// The host's main file is copied, not pointed at: `PIPEWIRE_CONFIG_DIR` replaces the search
// path whole. User fragments are not: a `server.address` in one would pick the socket.
fn write_pulse_config(env: &Env, host: &dyn Host, dir: &Path) -> Result<PathBuf, LaunchError> {
    let dirs = pipewire::pulse_conf_dirs(&env.config_home);
    let source = pipewire::pulse_conf(host, &env.config_home).ok_or_else(|| {
        // The last directory searched is the one the package ships, so
        // that is the path a report can be acted on.
        LaunchError::Plan(PlanError::MissingResource {
            service: "pulseaudio",
            path: dirs[dirs.len() - 1].join(pipewire::PULSE_CONF),
        })
    })?;
    let text = std::fs::read(&source).map_err(|e| LaunchError::Io(source.clone(), e))?;
    let cfg = pipewire::pulse_config_dir(dir);
    let drop_in = cfg.join(pipewire::PULSE_DROP_IN);
    let drop_in_dir = drop_in
        .parent()
        .expect("PULSE_DROP_IN names a file inside a directory");
    mkdir_private(&cfg)?;
    mkdir_private(drop_in_dir)?;
    write_private(&cfg.join(pipewire::PULSE_CONF), &text)?;
    write_private(&drop_in, pipewire::PULSE_OVERRIDE.as_bytes())?;
    Ok(cfg)
}

// `O_NOFOLLOW` keeps the write in the runtime directory; the mode is set, not left to the
// umask or to an earlier run.
fn write_private(path: &Path, content: &[u8]) -> Result<(), LaunchError> {
    let io_at = |e: Errno| LaunchError::Io(path.to_path_buf(), e.into());
    let file = rustix::fs::open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(io_at)?;
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(io_at)?;
    std::fs::File::from(file)
        .write_all(content)
        .map_err(|e| LaunchError::Io(path.to_path_buf(), e))
}

/// Start an instance's filtering D-Bus proxy in its own sandbox and wait until its socket
/// exists. The handle must outlive the sandbox.
pub fn start_proxy(
    env: &Env,
    dir: &Path,
    plan: &dbus::Plan,
    host: &dyn Host,
    stop: &AtomicBool,
) -> Result<ProxyHandle, LaunchError> {
    // Only the buses the plan grants are resolved: probing the other one
    // would fail a run over a socket it never asked for.
    let session_bus = plan
        .session
        .as_ref()
        .map(|_| {
            let path = dbus::guarded_host_bus(host, env)?;
            service::require_socket(host, dbus::SESSION_NODE, path)
        })
        .transpose()?;
    let system_bus = plan
        .system
        .as_ref()
        .map(|_| {
            let path = dbus::guarded_host_system_bus(host, env)?;
            service::require_socket(host, dbus::SYSTEM_NODE, path)
        })
        .transpose()?;
    // Resolved before the proxy starts: asking after the sandbox is up would be asking for a bus
    // already meant to be serving.
    let a11y_bus = plan
        .a11y
        .as_ref()
        .map(|_| {
            let path = dbus_a11y::guarded_host_a11y_bus(host, env)?;
            Ok::<_, LaunchError>(service::require_socket(host, dbus::A11Y_NODE, path)?)
        })
        .transpose()?;
    // After the bus guards, so a refused address is reported before a missing package; before the
    // spawn, so a missing binary is not bwrap's execvp line after the full PROXY_READY wait.
    let program = dbus::proxy_program(env);
    let found = if program.components().count() > 1 {
        rustix::fs::access(&program, Access::EXEC_OK).is_ok()
    } else {
        on_path(&program.to_string_lossy()).is_some()
    };
    if !found {
        return Err(LaunchError::Plan(PlanError::BadValue {
            service: "dbus",
            reason: format!(
                "`{}` is not on PATH; install the `xdg-dbus-proxy` package, or drop the \
                 `dbus`, `portals`, `a11y` and `system-bus` nodes",
                program.display()
            ),
        }));
    }
    // The proxy gets this directory and nothing else of the instance's
    // runtime state, so it is created here rather than bound from above.
    fresh_sidecar_dir(&dbus::socket_dir(dir))?;
    let mut alloc = RealAlloc::sidecar(dir.to_path_buf());
    let argv = proxy_argv(
        env,
        plan,
        dbus::HostBuses {
            session: session_bus.as_deref(),
            system: system_bus.as_deref(),
            a11y: a11y_bus.as_deref(),
        },
        dir,
        host,
        &mut alloc,
    )?;
    let cmd = bwrap_command(&argv, &mut alloc)?;
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let (child, stderr) = spawn_sidecar(cmd, env.dbus_log)?;
    let mut handle = ProxyHandle {
        child,
        alloc,
        _stderr: stderr,
        socket_dir: dbus::socket_dir(dir),
    };
    handle.alloc.close_options();
    // The instance's own bwrap must not inherit these: a second holder of
    // the ready pipe would keep the proxy alive after the run has ended.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let ProxyHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no ready pipe was allocated")))?;
    if !wait_ready(ready, child, Instant::now() + PROXY_READY, stop)? {
        return Err(LaunchError::ProxyNotReady);
    }
    Ok(handle)
}

// Before the failing run closes the block pipe, by pid: killing bwrap leaves its child. SIGKILL
// from an ancestor pid namespace reaches a pid 1 (`pid_namespaces(7)`).
fn abort_sandbox(child: &mut Child, sandbox: Option<i32>) {
    if let Some(pid) = sandbox.and_then(Pid::from_raw) {
        let _ = kill_process(pid, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

// The sandbox's namespace is connected to the outside exactly as long as this lives.
#[derive(Debug)]
struct PastaHandle {
    child: Child,
    // Set once reaped: the notice appears once and the pid is never signalled after.
    exited: bool,
    _stderr: run_log::Relay,
}

impl PastaHandle {
    // The sandbox keeps running, unconnected. The relay's warning channel, not `eprintln!`: one
    // blocking terminal write would park the loop answering the exit check and the signals.
    fn check(&mut self, warn: &tty_relay::Warn) {
        if self.exited {
            return;
        }
        let Ok(Some(status)) = self.child.try_wait() else {
            return;
        };
        self.exited = true;
        warn.say(&format!(
            "bubbler: warning: pasta exited ({status}); the sandbox has lost its network\n"
        ));
    }
}

impl Drop for PastaHandle {
    // pasta quits with its namespace (`pasta(1)`; no `--no-netns-quit`), but a sidecar with a
    // route out is not left to a condition bubbler does not control.
    fn drop(&mut self) {
        if self.exited || !still_running(&mut self.child) {
            return;
        }
        if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
            let _ = kill_process(pid, Signal::TERM);
        }
        let deadline = Instant::now() + PASTA_STOP;
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
    }
}

// Compared by nsfs device and inode (`namespaces(7)`), on the descriptor already held:
// resolving `/proc/<pid>/ns/net` again could land on a reused pid's namespace.
fn same_namespace(held: BorrowedFd<'_>, path: &Path) -> Result<bool, LaunchError> {
    let theirs =
        rustix::fs::stat(path).map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))?;
    let ours = rustix::fs::fstat(held).map_err(|e| LaunchError::Data(e.into()))?;
    Ok((ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino))
}

// `_IO(0xb7, 0x1)` from `linux/nsfs.h`: returns a descriptor for the owning user namespace
// (`ioctl_ns(2)`).
const NS_GET_USERNS: Opcode = ioctl::opcode::none(0xb7, 0x1);

// Neither `NoArg` nor `Getter` fits: the descriptor is the return value, which `NoArg` drops
// and `Getter` would read from a buffer the kernel never writes.
struct NsGetUserns;

// SAFETY: `NS_GET_USERNS` takes no argument and writes nothing into
// userspace — hence the null pointer and `IS_MUTATING = false` — and on
// success its return value is a newly opened descriptor, which is what
// `output_from_ptr` makes of it.
unsafe impl ioctl::Ioctl for NsGetUserns {
    type Output = OwnedFd;

    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        NS_GET_USERNS
    }

    fn as_ptr(&mut self) -> *mut c_void {
        std::ptr::null_mut()
    }

    unsafe fn output_from_ptr(
        out: ioctl::IoctlOutput,
        _: *mut c_void,
    ) -> rustix::io::Result<Self::Output> {
        // SAFETY: the caller hands over the return value of an `ioctl`
        // that succeeded, which for this opcode is a descriptor the
        // kernel has just opened and nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(out) })
    }
}

// Asked of the netns, not a pid: bwrap moves the sandbox into a nested user namespace after
// reporting `child-pid`, while a netns's owner is fixed at creation (`ioctl_ns(2)`).
fn owning_userns(netns: BorrowedFd<'_>) -> rustix::io::Result<OwnedFd> {
    // SAFETY: `NsGetUserns` describes what `NS_GET_USERNS` does, and it
    // is made on a descriptor of an nsfs file, which is what `netns` is.
    unsafe { ioctl::ioctl(netns, NsGetUserns) }
}

// Held open across the ruleset and pasta spawns, so the pid cannot be reused under them.
struct SandboxNs {
    net: OwnedFd,
    // Where a process holds the capabilities to configure `net`.
    user: OwnedFd,
    // Joined by the egress proxy, so it resolves through the sandbox's `resolv.conf` and sees only
    // its filesystem; owned like `net`, so the join costs no further capability.
    mnt: OwnedFd,
}

// The pid may have been reused since bwrap reported it: one not in a namespace of its own is
// not the sandbox, and `nft` and pasta would act on the host's network.
fn sandbox_namespaces(child_pid: i32) -> Result<SandboxNs, LaunchError> {
    let net_path = PathBuf::from(format!("/proc/{child_pid}/ns/net"));
    let net = rustix::fs::open(&net_path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| LaunchError::Io(net_path.clone(), e.into()))?;
    if same_namespace(net.as_fd(), Path::new("/proc/self/ns/net"))? {
        return Err(NetworkError::PidReusedNet.into());
    }
    let user = owning_userns(net.as_fd()).map_err(|e| LaunchError::Io(net_path, e.into()))?;
    let mnt_path = PathBuf::from(format!("/proc/{child_pid}/ns/mnt"));
    let mnt = rustix::fs::open(&mnt_path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| LaunchError::Io(mnt_path, e.into()))?;
    // Checked apart: a pid reused between the two `open`s would join the proxy to a stranger's
    // mount namespace and the sandbox's network namespace.
    if same_namespace(mnt.as_fd(), Path::new("/proc/self/ns/mnt"))? {
        return Err(NetworkError::PidReusedMnt.into());
    }
    Ok(SandboxNs { net, user, mnt })
}

// `nft` is spawned, not linked: a library means `libnftnl` or `bindgen` for a stable text
// format. `cgroup` must exist already: nftables stores the id the path resolves to, so a
// cgroup made after this would be matched by nothing.
fn install_rules(
    cfg: &NetworkConfig,
    ns: &SandboxNs,
    cgroup: Option<&network::Cgroup>,
    stop: &AtomicBool,
) -> Result<(), LaunchError> {
    let Some(text) = network::ruleset(cfg, cgroup) else {
        // Nothing to install where nothing is filtered; a filtered run whose ruleset could not be
        // written must not get the whole network.
        if cfg.outbound == network::Outbound::Deny && cfg.is_isolated() {
            return Err(LaunchError::Plan(PlanError::BadValue {
                service: "network",
                reason: "the ruleset an `allow-host` needs is written around the \
                         egress proxy's own cgroup, and none was made for this run"
                    .to_owned(),
            }));
        }
        return Ok(());
    };
    let (user, net) = (ns.user.as_raw_fd(), ns.net.as_raw_fd());
    let mut cmd = Command::new(network::NFT_BIN);
    cmd.arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        // `nft`'s own diagnostics go where bubbler's do, never to the
        // caller's stdout: that is the argv audit trail.
        .stderr(Stdio::inherit());
    // SAFETY: the closure runs in the forked child between `fork` and
    // `execve`, where only async-signal-safe calls are allowed. Every
    // call in it is one syscall through rustix and allocates nothing:
    // `setns` twice, `capget`/`capset`, and `prctl` twice. The two
    // descriptors are valid there because `fork` copies the descriptor
    // table and the parent holds `ns` open across the spawn, so
    // `borrow_raw` borrows descriptors nothing has closed.
    //
    // User namespace first: entering the netns takes the capabilities it grants (`setns(2)`).
    // Ambient CAP_NET_ADMIN and a locked `SECBIT_NOROOT` leave `nft` that one capability.
    unsafe {
        cmd.pre_exec(move || {
            let user = BorrowedFd::borrow_raw(user);
            let net = BorrowedFd::borrow_raw(net);
            move_into_link_name_space(user, Some(LinkNameSpaceType::User))?;
            move_into_link_name_space(net, Some(LinkNameSpaceType::Network))?;
            let mut caps = capabilities(None)?;
            caps.inheritable |= CapabilitySet::NET_ADMIN;
            set_capabilities(None, caps)?;
            configure_capability_in_ambient_set(CapabilitySet::NET_ADMIN, true)?;
            set_capabilities_secure_bits(
                CapabilitiesSecureBits::NO_ROOT | CapabilitiesSecureBits::NO_ROOT_LOCKED,
            )?;
            Ok(())
        });
    }
    // Nothing above stdio: the namespaces are entered before the exec and
    // the ruleset arrives on a pipe this spawn makes for itself.
    spawning(&[])?;
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        // Only a really missing `nft` names the package: a failed `pre_exec` is a spawn failure
        // too.
        io::ErrorKind::NotFound if on_path(network::NFT_BIN).is_none() => {
            LaunchError::Plan(PlanError::BadValue {
                service: "network",
                reason: format!(
                    "`{}` is not on PATH; install the `nftables` package, or drop \
                 `outbound \"deny\"` to leave the sandbox network unfiltered",
                    network::NFT_BIN
                ),
            })
        }
        _ => NetworkError::NftStart(e).into(),
    })?;
    let mut stdin = child
        .stdin
        .take()
        .expect("stdin is piped, so the child always has one");
    let written = stdin.write_all(text.as_bytes());
    // Closed before the wait, or `nft` reads forever. The write has no deadline: a hang there
    // leaves the sandbox held at `--block-fd`, never started rather than unfiltered.
    drop(stdin);
    let deadline = Instant::now() + NFT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(e) => return Err(NetworkError::NftWait(e).into()),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(POLL);
    };
    // A sidecar holding CAP_NET_ADMIN over the sandbox's namespaces is
    // not left running because it stopped answering.
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(NetworkError::NftTimeout.into());
    };
    // A Ctrl-C reaches `nft` too, in bubbler's process group: killed by
    // a signal while a stop is pending, it is the stop's doing.
    if status.signal().is_some() && stop.load(Ordering::SeqCst) {
        return Err(LaunchError::Stopped);
    }
    if !status.success() {
        return Err(NetworkError::NftRefused(status).into());
    }
    written.map_err(NetworkError::NftWrite)?;
    Ok(())
}

// `bwrap`, found on bubbler's own `PATH`, to be started with an empty environment: it stays pid 1
// inside the sandbox, where its environ is readable, and `--clearenv` cleans only what it starts
// (https://github.com/containers/bubblewrap/issues/725). Its command line is readable there too,
// so `argv`'s options reach it through `--args` from a descriptor `alloc` holds until the spawn
// has happened ([`RealAlloc::close_options`]).
// The `--` and the command stay on argv: bwrap drops a command it finds in an `--args` file.
// Call before the spawn window opens, so the options descriptor is in it.
fn bwrap_command(argv: &Argv, alloc: &mut RealAlloc) -> Result<Command, LaunchError> {
    let bwrap = on_path("bwrap").ok_or(LaunchError::BwrapMissing)?;
    let options = alloc.options(argv.options()).map_err(LaunchError::Data)?;
    let mut cmd = Command::new(bwrap);
    cmd.env_clear()
        .arg("--args")
        .arg(options)
        .args(argv.command());
    Ok(cmd)
}

// A sidecar parses what the sandbox sends it, so it holds none of the caller's stdio and no
// terminal. `xdg-dbus-proxy --log` writes to stdout, so `log_stdout` sends it to the relay too.
fn spawn_sidecar(
    mut cmd: Command,
    log_stdout: bool,
) -> Result<(Child, run_log::Relay), LaunchError> {
    let (stderr, relay) = run_log::relay()?;
    let stdout = match log_stdout {
        true => Stdio::from(stderr.try_clone().map_err(LaunchError::Data)?),
        false => Stdio::null(),
    };
    cmd.stdin(Stdio::null()).stdout(stdout).stderr(stderr);
    let spawned = cmd.spawn();
    // `cmd` holds bubbler's copy of the relay's write end; the relay only
    // sees the end of the output once that copy is gone.
    drop(cmd);
    let child = spawned.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => LaunchError::BwrapMissing,
        _ => LaunchError::Spawn(e),
    })?;
    Ok((child, relay))
}

// execvp's fallback with `PATH` unset.
const DEFAULT_PATH: &str = "/usr/bin:/bin";

// The library reads the environment only here: for `bwrap`, which starts with none, and to
// tell a missing package from bubbler's own `NotFound` in an error message.
fn on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_else(|| DEFAULT_PATH.into());
    std::env::split_paths(&path).find_map(|dir| {
        if dir.as_os_str().is_empty() {
            return None;
        }
        let candidate = dir.join(bin);
        // A directory passes the access check; execvp would go on past it.
        (candidate.is_file() && rustix::fs::access(&candidate, Access::EXEC_OK).is_ok())
            .then_some(candidate)
    })
}

// The sandbox must still be held at `--block-fd`. pasta goes non-dumpable while starting, so
// its paths name bubbler's `/proc/self/fd`, and both descriptors stay open across the spawn.
fn start_pasta(
    env: &Env,
    cfg: &NetworkConfig,
    child_pid: i32,
    ns: &SandboxNs,
    stop: &AtomicBool,
) -> Result<PastaHandle, LaunchError> {
    let userns = &ns.user;
    let (ready, done) = rustix::pipe::pipe().map_err(|e| LaunchError::Data(e.into()))?;
    for fd in [&ready, &done] {
        fcntl_setfd(fd, FdFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    }
    let me = std::process::id();
    let argv = network::pasta_argv(
        cfg,
        network::Attach {
            userns: &OsString::from(format!("/proc/{me}/fd/{}", userns.as_raw_fd())),
            ready: &OsString::from(format!("/proc/{me}/fd/{}", done.as_raw_fd())),
            child: &OsString::from(child_pid.to_string()),
        },
    );
    // Nothing above stdio: pasta opens both descriptors through bubbler's `/proc` entry.
    spawning(&[])?;
    // pasta's stdout and stderr go where bubbler's messages do: never to the caller's stdout (the
    // argv audit trail), nor as the caller's own descriptor.
    let (log, stderr) = run_log::relay()?;
    let log_too = log.try_clone().map_err(LaunchError::Data)?;
    let missing = || {
        LaunchError::Plan(PlanError::BadValue {
            service: "network",
            reason: format!(
                "`{}` is not on PATH; install the `passt` package, or write \
             `network \"host\"` to use the host network namespace",
                network::PASTA_BIN
            ),
        })
    };
    let program = match &env.pasta_override {
        Some(path) => path.clone(),
        // Looked up here, so the forked child `execve`s a path rather than
        // walking `PATH` after `fork`.
        None => on_path(network::PASTA_BIN).ok_or_else(missing)?,
    };
    let mut cmd = Command::new(program);
    cmd.args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_too));
    // SAFETY: the closure runs in the forked child between `fork` and
    // `execve`; `setsid` is one syscall that allocates nothing, so it is
    // async-signal-safe. In a session of its own pasta has no controlling
    // terminal, so it cannot open `/dev/tty` and reach the caller's.
    unsafe {
        cmd.pre_exec(|| {
            rustix::process::setsid()?;
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => missing(),
        _ => LaunchError::Spawn(e),
    })?;
    let mut handle = PastaHandle {
        child,
        exited: false,
        _stderr: stderr,
    };
    if !wait_ready(
        &ready,
        &mut handle.child,
        Instant::now() + PASTA_READY,
        stop,
    )? {
        return Err(NetworkError::PastaNotReady.into());
    }
    Ok(handle)
}

// Dropped, which stops the proxy, before the run's cgroup guard: a cgroup holding a process
// cannot be removed.
#[derive(Debug)]
struct NetProxyHandle {
    child: Child,
    // Set once reaped: the notice appears once and the pid is never signalled after.
    exited: bool,
    _stderr: run_log::Relay,
}

impl NetProxyHandle {
    // The sandbox keeps running: its filter is unchanged, it only loses its one way out.
    fn check(&mut self, warn: &tty_relay::Warn) {
        if self.exited {
            return;
        }
        let Ok(Some(status)) = self.child.try_wait() else {
            return;
        };
        self.exited = true;
        warn.say(&format!(
            "bubbler: warning: the egress proxy exited ({status}); the sandbox can reach \
             none of its `allow-host` names\n"
        ));
    }
}

impl Drop for NetProxyHandle {
    // `PR_SET_PDEATHSIG` covers only bubbler dying; a normal end must not leave a process in the
    // sandbox's namespaces, and the cgroup cannot be removed while one is there.
    fn drop(&mut self) {
        if self.exited || !still_running(&mut self.child) {
            return;
        }
        if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
            let _ = kill_process(pid, Signal::TERM);
        }
        let deadline = Instant::now() + NET_PROXY_STOP;
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
    }
}

struct NetworkSidecars {
    pasta: PastaHandle,
    proxy: Option<NetProxyHandle>,
}

impl NetworkSidecars {
    fn check(&mut self, warn: &tty_relay::Warn) {
        self.pasta.check(warn);
        if let Some(proxy) = self.proxy.as_mut() {
            proxy.check(warn);
        }
    }
}

// The order is the safety: cgroup before bwrap, ruleset before pasta, proxy listening before
// the release, so the sandbox is never connected and unfiltered, nor reaching a silent proxy.
fn start_network(
    env: &Env,
    cfg: &NetworkConfig,
    child_pid: i32,
    cgroup: Option<&cgroup::SandboxCgroup>,
    stop: &AtomicBool,
) -> Result<NetworkSidecars, LaunchError> {
    let ns = sandbox_namespaces(child_pid)?;
    install_rules(cfg, &ns, cgroup.map(cgroup::SandboxCgroup::spec), stop)?;
    let pasta = start_pasta(env, cfg, child_pid, &ns, stop)?;
    let proxy = cgroup
        .map(|cgroup| start_net_proxy(cfg, &ns, cgroup, env.net_proxy_log, stop))
        .transpose()?;
    Ok(NetworkSidecars { pasta, proxy })
}

// Exec'd from `network::NET_PROXY_INSIDE`: after the mount join a host path resolves to
// nothing. Only refusals are logged unless `log_tunnels`: its lines land on the app's terminal.
fn start_net_proxy(
    cfg: &NetworkConfig,
    ns: &SandboxNs,
    cgroup: &cgroup::SandboxCgroup,
    log_tunnels: bool,
    stop: &AtomicBool,
) -> Result<NetProxyHandle, LaunchError> {
    let (ready, done) = rustix::pipe::pipe().map_err(|e| LaunchError::Data(e.into()))?;
    fcntl_setfd(&ready, FdFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    // The write end is the one descriptor this spawn hands over, so it
    // is the one exception to the sweep below.
    fcntl_setfd(&done, FdFlags::empty()).map_err(|e| LaunchError::Data(e.into()))?;
    let argv = network::net_proxy_argv(
        cfg,
        network::ProxyFds {
            ready: &OsString::from(done.as_raw_fd().to_string()),
            log: OsStr::new("2"),
        },
        log_tunnels,
    );
    let (log, stderr) = run_log::relay()?;
    let mut cmd = Command::new(network::NET_PROXY_INSIDE);
    cmd.args(&argv)
        // The proxy reads none of the host's environment, and every variable would cross into the
        // sandbox's namespaces.
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log);
    let procs = cgroup.procs().as_raw_fd();
    let (user, net, mnt) = (ns.user.as_raw_fd(), ns.net.as_raw_fd(), ns.mnt.as_raw_fd());
    // SAFETY: the closure runs in the forked child between `fork` and
    // `execve`, where only async-signal-safe calls are allowed. Every
    // call in it is one syscall through rustix and allocates nothing —
    // the pid is formatted into a stack buffer and `chdir` is handed a
    // C string literal. The four descriptors are valid there because
    // `fork` copies the descriptor table and the parent holds the
    // cgroup handle and `ns` open across the spawn, so `borrow_raw`
    // borrows descriptors nothing has closed.
    //
    // The order is the manual's ("The proxy process").
    unsafe {
        cmd.pre_exec(move || {
            rustix::process::setsid()?;
            let procs = BorrowedFd::borrow_raw(procs);
            let mut buf = [0u8; 10];
            rustix::io::write(
                procs,
                decimal(rustix::process::getpid().as_raw_nonzero().get(), &mut buf),
            )?;
            let user = BorrowedFd::borrow_raw(user);
            let net = BorrowedFd::borrow_raw(net);
            let mnt = BorrowedFd::borrow_raw(mnt);
            move_into_link_name_space(user, Some(LinkNameSpaceType::User))?;
            move_into_link_name_space(net, Some(LinkNameSpaceType::Network))?;
            move_into_link_name_space(mnt, Some(LinkNameSpaceType::Mount))?;
            rustix::process::chdir(c"/")?;
            set_capabilities_secure_bits(
                CapabilitiesSecureBits::NO_ROOT | CapabilitiesSecureBits::NO_ROOT_LOCKED,
            )?;
            clear_ambient_capability_set()?;
            set_capabilities(
                None,
                CapabilitySets {
                    effective: CapabilitySet::empty(),
                    permitted: CapabilitySet::empty(),
                    inheritable: CapabilitySet::empty(),
                },
            )?;
            set_no_new_privs(true)?;
            set_parent_process_death_signal(Some(Signal::TERM))?;
            set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
            Ok(())
        });
    }
    spawning(&[done.as_raw_fd()])?;
    // Never `LaunchError::Spawn`, which names bwrap: a failed `pre_exec` step arrives as a failed
    // spawn too, and its `NotFound` is not a missing binary.
    let spawned = cmd.spawn();
    // `cmd` holds bubbler's copy of the relay's write end; the relay only
    // sees the end of the output once that copy is gone.
    drop(cmd);
    let child = spawned.map_err(NetworkError::ProxyStart)?;
    let mut handle = NetProxyHandle {
        child,
        exited: false,
        _stderr: stderr,
    };
    // bubbler's own copy of the write end goes now, so a proxy that dies
    // without writing gives the wait below an EOF instead of a deadline.
    drop(done);
    if !wait_ready(
        &ready,
        &mut handle.child,
        Instant::now() + NET_PROXY_READY,
        stop,
    )? {
        return Err(match handle.child.try_wait() {
            Ok(Some(status)) => NetworkError::ProxyExited(status),
            _ => NetworkError::ProxySilent,
        }
        .into());
    }
    Ok(handle)
}

// ENOSYS (no `CONFIG_KEYS`) is not a failure: there is no keyring to inherit either. rustix
// wraps no keyring call, hence `libc`.
fn join_session_keyring() -> io::Result<()> {
    // SAFETY: one syscall taking its arguments by value, allocating
    // nothing and touching no memory of this process — async-signal-safe,
    // which is what a `pre_exec` closure is held to. The null name is
    // what asks for a fresh anonymous keyring rather than a named one.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            u64::from(libc::KEYCTL_JOIN_SESSION_KEYRING),
            0u64,
        )
    };
    if rc >= 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS) => Ok(()),
        _ => Err(err),
    }
}

// For the proxy's `pre_exec`, where `format!` would allocate in a forked child.
fn decimal(value: i32, buf: &mut [u8; 10]) -> &[u8] {
    let mut value = value.unsigned_abs();
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 || at == 0 {
            break;
        }
    }
    &buf[at..]
}

fn open_dir(path: &Path) -> Result<OwnedFd, LaunchError> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
}

// Move first, check second, as in `adopt_socket`. `node` is the config node that granted the
// bus, so a failure names what the user would change.
fn adopt_proxy_bus(
    dir: &Path,
    socket: &str,
    node: &'static str,
    uid: u32,
) -> Result<FileGuard, LaunchError> {
    let from_dir = dbus::socket_dir(dir);
    let from = open_dir_nofollow(rustix::fs::CWD, &from_dir, &from_dir, node)?;
    let to = open_dir(dir)?;
    let path = dbus::app_bus_path(dir, socket);
    clear_socket_name(&to, dir, socket).map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    rustix::fs::renameat(&from, socket, &to, socket).map_err(|e| match e {
        Errno::NOENT => LaunchError::Plan(PlanError::MissingResource {
            service: node,
            path: dbus::proxy_bus_path(dir, socket),
        }),
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let guard = FileGuard(path.clone());
    let wrong_type = |expected| {
        LaunchError::Plan(PlanError::WrongType {
            service: node,
            path: path.clone(),
            expected,
        })
    };
    let bus = rustix::fs::openat(
        &to,
        socket,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP => wrong_type("a socket"),
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    let stat = rustix::fs::fstat(&bus).map_err(|e| LaunchError::Io(path.clone(), e.into()))?;
    let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if kind != rustix::fs::FileType::Socket {
        // A directory cannot be unlinked as a file, and one left at this
        // name would fail the rename of every later start of the instance.
        if kind == rustix::fs::FileType::Directory {
            remove_moved_dir(&to, dir, socket);
        }
        return Err(wrong_type("a socket"));
    }
    if stat.st_uid != uid {
        return Err(wrong_type("a socket owned by this user"));
    }
    Ok(guard)
}

// Cleared so the next start's rename onto this name works; after the move only bubbler reaches it.
fn remove_moved_dir(inst: &OwnedFd, dir: &Path, socket: &str) {
    if let Err(e) = move_aside(inst, dir, OsStr::new(socket)) {
        eprintln!(
            "bubbler: warning: {} could not be moved aside ({e}); the next start tries again",
            dir.join(socket).display()
        );
    }
}

// A killed run can leave a directory at the name, and a rename cannot put a socket over one.
fn clear_socket_name(inst: &OwnedFd, dir: &Path, socket: &str) -> rustix::io::Result<()> {
    match rustix::fs::statat(inst, socket, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat)
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::Directory =>
        {
            move_aside(inst, dir, OsStr::new(socket))
        }
        Ok(_) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

// An existing directory is reused as is: only the user can create under `$XDG_RUNTIME_DIR`.
fn mkdir_private(dir: &Path) -> Result<(), LaunchError> {
    match rustix::fs::mkdir(dir, Mode::RWXU) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(LaunchError::Io(dir.to_path_buf(), e.into())),
    }
}

// Bounds how long clearing dead runs' leftovers delays one start; the next start takes up
// the rest.
const LEFTOVER_BUDGET: usize = 100_000;

// Only after this run's control-socket bind found no live run. Only one start at a time gets
// there, and a run that is ending holds a start back until its teardown is done — except for a
// start that binds in the moment between the sandbox's exit and the ending run taking the lock.
// What is at the name is moved aside and removed best-effort, never followed.
fn fresh_sidecar_dir(dir: &Path) -> Result<(), LaunchError> {
    let io_at = |e: Errno| LaunchError::Io(dir.to_path_buf(), e.into());
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        unreachable!("a sidecar directory is named inside the instance's");
    };
    let at = open_dir(parent)?;
    match rustix::fs::statat(&at, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => clear_leftovers(&at, name),
        Err(e) => return Err(io_at(e)),
        Ok(_) => move_aside(&at, parent, name).map_err(io_at)?,
    }
    rustix::fs::mkdirat(&at, name, Mode::RWXU).map_err(io_at)
}

// A rename within bubbler's own directory: no mode or depth refuses it, and a link moves as
// the link.
fn move_aside(at: &OwnedFd, dir: &Path, name: &OsStr) -> rustix::io::Result<()> {
    let moved = rename_to_free(at, name, at, &mut 0, |seq| leftover_name(name, seq))?;
    clear_leftovers(at, name);
    if rustix::fs::statat(at, &moved, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
        eprintln!(
            "bubbler: warning: {} is what a sidecar left and could not be removed in full; the next start tries again",
            dir.join(moved).display()
        );
    }
    Ok(())
}

// Only once the sidecar has exited. Not `std::fs::remove_dir_all`: it recurses, and a deep
// enough tree overflows the stack.
fn remove_sidecar_dir(dir: &Path) {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        return;
    };
    let Ok(at) = open_dir(parent) else {
        return;
    };
    let _ = remove_tree(&at, name, &mut LEFTOVER_BUDGET.clone());
}

// Only bubbler writes the instance's runtime directory, so the name need not be unguessable.
fn leftover_name(name: &OsStr, seq: u64) -> OsString {
    let mut aside = leftover_prefix(name);
    aside.push(format!("{}.{seq}", std::process::id()));
    aside
}

fn leftover_prefix(name: &OsStr) -> OsString {
    let mut prefix = name.to_owned();
    prefix.push(".leftover.");
    prefix
}

// A failure is left for the next start; the start that moved the tree aside already warned.
fn clear_leftovers(at: &OwnedFd, name: &OsStr) {
    let prefix = leftover_prefix(name);
    let mut budget = LEFTOVER_BUDGET;
    // Only bubbler writes the instance's directory, so its width is not a
    // sidecar's to choose.
    let Ok(names) = entry_names(at, usize::MAX) else {
        return;
    };
    for leftover in names {
        if leftover.as_bytes().starts_with(prefix.as_bytes()) {
            let _ = remove_tree(at, &leftover, &mut budget);
        }
    }
}

// Never replaces an entry; `seq` is left past the name taken.
fn rename_to_free(
    from: &OwnedFd,
    name: &OsStr,
    to: &OwnedFd,
    seq: &mut u64,
    make: impl Fn(u64) -> OsString,
) -> rustix::io::Result<OsString> {
    loop {
        let new = make(*seq);
        *seq += 1;
        match rustix::fs::renameat_with(from, name, to, &new, rustix::fs::RenameFlags::NOREPLACE) {
            Err(Errno::EXIST) => {}
            Err(e) => return Err(e),
            Ok(()) => return Ok(new),
        }
    }
}

// Names read before acting on them, so a directory of any width costs bounded memory.
const READ_BATCH: usize = 1024;

// A fixed number of descriptors at any depth: each pass empties the directories in the top
// one and lifts their contents into it. Work done before `EAGAIN` stays done.
fn remove_tree(at: &OwnedFd, name: &OsStr, budget: &mut usize) -> rustix::io::Result<()> {
    let Some(top) = unlink_or_open(at, name)? else {
        return Ok(());
    };
    let mut lifted = 0;
    loop {
        let names = entry_names(&top, READ_BATCH)?;
        if names.is_empty() {
            break;
        }
        for entry in names {
            spend(budget)?;
            let Some(inner) = unlink_or_open(&top, &entry)? else {
                continue;
            };
            loop {
                let subs = entry_names(&inner, READ_BATCH)?;
                if subs.is_empty() {
                    break;
                }
                for sub in subs {
                    spend(budget)?;
                    if unlink_or_open(&inner, &sub)?.is_some() {
                        rename_to_free(&inner, &sub, &top, &mut lifted, |seq| {
                            OsString::from(seq.to_string())
                        })?;
                    }
                }
            }
            rustix::fs::unlinkat(&top, &entry, AtFlags::REMOVEDIR)?;
        }
    }
    rustix::fs::unlinkat(at, name, AtFlags::REMOVEDIR)
}

fn spend(budget: &mut usize) -> rustix::io::Result<()> {
    *budget = budget.checked_sub(1).ok_or(Errno::AGAIN)?;
    Ok(())
}

// A sidecar can leave a directory no one may read or move; the mode changes on the opened
// directory, never on whatever the path names by then, and no link is followed.
fn unlink_or_open(at: &OwnedFd, name: &OsStr) -> rustix::io::Result<Option<OwnedFd>> {
    let stat = rustix::fs::statat(at, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        rustix::fs::unlinkat(at, name, AtFlags::empty())?;
        return Ok(None);
    }
    let pinned = rustix::fs::openat(
        at,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // `fchmod` refuses an `O_PATH` descriptor, and one opened for reading
    // needs the permission this is restoring.
    rustix::fs::chmod(format!("/proc/self/fd/{}", pinned.as_raw_fd()), Mode::RWXU)?;
    rustix::fs::openat(
        &pinned,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(Some)
}

fn entry_names(dir: &OwnedFd, max: usize) -> rustix::io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir)? {
        if names.len() == max {
            break;
        }
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Create `$XDG_RUNTIME_DIR/bubbler/<name>/` with mode 0700, reusing an existing one. Not a
/// lock: a second start of the instance collides on the control socket in it.
pub fn prepare_runtime_dir(env: &Env, inst: &Instance) -> Result<PathBuf, LaunchError> {
    // Each level is created 0700 outright; a missing `$XDG_RUNTIME_DIR` is created but not its
    // parent, which would mean the session has no runtime dir.
    mkdir_private(&env.runtime_dir)?;
    mkdir_private(&env.runtime_dir.join(RUNTIME_SUBDIR))?;
    let dir = instance_runtime_dir(env, &inst.name);
    mkdir_private(&dir)?;
    Ok(dir)
}

// Only bubbler creates these, never a sandbox: whoever creates `app/<id>` decides what the
// others bind. Why the check-then-bind window is no hole: threat model, app-runtime.
fn prepare_app_runtime(env: &Env, services: &[Service]) -> Result<(), LaunchError> {
    let ids: Vec<&str> = services
        .iter()
        .filter_map(|s| match s {
            Service::AppRuntime { id, .. } => Some(id.as_str()),
            _ => None,
        })
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    // Both levels 0700, the way `prepare_runtime_dir` makes its own: the
    // order in the caller is not what should decide whether they are.
    mkdir_private(&env.runtime_dir)?;
    let app = env.runtime_dir.join("app");
    mkdir_private(&app)?;
    let at = open_dir_nofollow(rustix::fs::CWD, &app, &app, "app-runtime")?;
    for id in ids {
        let dir = service::app_runtime_dir(env, id);
        // `mkdir` reports EEXIST for a symlink too, so the probe below is what catches one.
        match rustix::fs::mkdirat(&at, id, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(LaunchError::Io(dir, e.into())),
        }
        open_dir_nofollow(&at, id, &dir, "app-runtime")?;
    }
    Ok(())
}

fn open_dir_nofollow<P: rustix::path::Arg>(
    at: impl AsFd,
    path: P,
    named: &Path,
    service: &'static str,
) -> Result<OwnedFd, LaunchError> {
    rustix::fs::openat(
        at,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::NOTDIR => LaunchError::Plan(PlanError::WrongType {
            service,
            path: named.to_path_buf(),
            expected: "a directory",
        }),
        e => LaunchError::Io(named.to_path_buf(), e.into()),
    })
}

// Scanned rather than parsed: bwrap adds members over time and only this one matters.
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

// Braces counted outside strings: bwrap writes one multi-line document, and portals cannot
// use a truncated one.
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

// Portals read this same document back out of `bwrapinfo.json`, so it is returned as written.
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

// The reaper's child carries bwrap's name until it execs, and a failed exec leaves another.
fn is_supervisor(pid: Pid) -> bool {
    let comm = format!("/proc/{}/comm", pid.as_raw_nonzero());
    std::fs::read_to_string(comm).is_ok_and(|name| name == format!("{}\n", init_bin::NAME))
}

// The reaper is pid 1 there and ignores outside signals it has no handler for; `bubbler-init`,
// its first child, handles SIGTERM. Only once released: a held sandbox has not forked it.
fn supervisor_pid(reaper: i32, child: &mut Child, deadline: Instant) -> Option<Pid> {
    let children = PathBuf::from(format!("/proc/{reaper}/task/{reaper}/children"));
    loop {
        // An empty list or a child not yet exec'd is worth waiting on; a failed read means the
        // sandbox is gone or the kernel has no `children` file, and neither improves.
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

#[derive(Debug)]
struct FileGuard(PathBuf);

impl Drop for FileGuard {
    fn drop(&mut self) {
        // Nothing to report: a concurrent start may have replaced the
        // socket, and a stale one is detected by connecting to it anyway.
        let _ = std::fs::remove_file(&self.0);
    }
}

// Removes only this run's entry: the `.flatpak` directory above it is shared with flatpak.
struct FlatpakGuard(PathBuf);

impl Drop for FlatpakGuard {
    fn drop(&mut self) {
        // Nothing to report: the directory holds this run's identity and
        // nothing else, and a leftover only names a pid that is gone.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Only a directory holding nothing but a `bwrapinfo.json` whose `child-pid` is dead; anything
// else is someone's to keep.
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
    let gone = parse_child_pid(&info)
        .and_then(Pid::from_raw)
        .is_some_and(|pid| !proc::pid_alive(pid));
    if gone {
        let _ = std::fs::remove_dir_all(dir);
    }
}

// Created outright, never adopted: a second run of the instance must not publish over the
// first one's identity.
fn publish_bwrapinfo(env: &Env, instance: &str, info: &[u8]) -> Result<FlatpakGuard, LaunchError> {
    mkdir_private(&env.runtime_dir.join(dbus::FLATPAK_DIR))?;
    let dir = dbus::flatpak_instance_dir(env, instance);
    sweep_identity(&dir);
    rustix::fs::mkdir(&dir, Mode::RWXU)
        .map_err(|e| LaunchError::Io(dir.to_path_buf(), e.into()))?;
    let guard = FlatpakGuard(dir.clone());
    // Written and renamed inside the directory, so a portal reading it
    // never sees half a document.
    let tmp = dir.join(format!("{}.new", dbus::BWRAPINFO));
    std::fs::write(&tmp, info).map_err(|e| LaunchError::Io(tmp.clone(), e))?;
    let dest = dir.join(dbus::BWRAPINFO);
    std::fs::rename(&tmp, &dest).map_err(|e| LaunchError::Io(dest, e))?;
    Ok(guard)
}

// Never fatal: an app whose portal calls fail still runs.
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

// Closing the pipe releases the sandbox as the byte does, so a failed write still starts it.
fn release_block(alloc: &mut RealAlloc) {
    if let Some(fd) = alloc.block_write.take() {
        let _ = rustix::io::write(&fd, b"\n");
    }
}

// The slave is duplicated per fd, so closing bubbler's copy leaves the sandbox's three intact.
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

struct Watch<'a> {
    stop: &'a AtomicBool,
    supervisor: Option<Pid>,
    stopping: &'a AtomicBool,
    network: &'a mut Option<NetworkSidecars>,
    warn: &'a tty_relay::Warn,
    // Taken into `ending` when the exit is seen, not once the output is drained.
    start_lock: &'a Path,
    ending: Option<OwnedFd>,
}

// The single place a run learns it is over, so the sidecars are checked here too.
fn check_exit(child: &mut Child, w: &mut Watch<'_>) -> io::Result<Option<i32>> {
    if let Some(status) = child.try_wait()? {
        // Once only: a second open of the file would wait on this one.
        if w.ending.is_none() {
            w.ending = lock_for_teardown(w.start_lock);
        }
        return Ok(Some(exit_code(status)));
    }
    if let Some(network) = w.network.as_mut() {
        network.check(w.warn);
    }
    let Watch {
        stop,
        supervisor,
        stopping,
        ..
    } = w;
    if stop.swap(false, Ordering::SeqCst) {
        // Latched, unlike `stop` itself: from here on the user is
        // waiting, and the relay hands over what it holds accordingly.
        stopping.store(true, Ordering::SeqCst);
        // bubblewrap 0.11.2 exits on SIGTERM instead of forwarding it, so the supervisor gets it;
        // bwrap and `--die-with-parent` are the fallback. A failed kill is a race with the exit.
        let target = supervisor.unwrap_or_else(|| Pid::from_child(child));
        let _ = kill_process(target, Signal::TERM);
    }
    Ok(None)
}

// A failing `try_wait` ends the wait too, its error left in `failed`.
fn until_exit<'a>(
    child: &'a mut Child,
    w: &'a mut Watch<'_>,
    failed: &'a mut Option<io::Error>,
) -> impl FnMut() -> Option<i32> + 'a {
    move || match check_exit(child, w) {
        Ok(code) => code,
        Err(e) => {
            *failed = Some(e);
            Some(1)
        }
    }
}

fn wait_plain(child: &mut Child, w: &mut Watch<'_>) -> Result<i32, LaunchError> {
    loop {
        if let Some(code) = check_exit(child, w).map_err(LaunchError::Spawn)? {
            return Ok(code);
        }
        std::thread::sleep(POLL);
    }
}

fn wait_pumping(
    child: &mut Child,
    w: &mut Watch<'_>,
    pipes: &[(BorrowedFd<'_>, BorrowedFd<'_>, &str)],
    sink: BorrowedFd<'_>,
) -> Result<i32, LaunchError> {
    let mut failed = None;
    let stopping = w.stopping;
    let code = {
        let mut until = until_exit(child, w, &mut failed);
        tty_relay::pump(pipes, sink, &mut until, stopping)?
    };
    match failed {
        Some(e) => Err(LaunchError::Spawn(e)),
        None => Ok(code),
    }
}

struct RelayEnds<'a> {
    input: Option<BorrowedFd<'a>>,
    output: BorrowedFd<'a>,
    out_name: &'static str,
    sink: BorrowedFd<'a>,
}

// Detaching ends the relay, not the run: closing the master would hang up the terminal inside
// and leaving would kill the sandbox, so it waits on with the pty drained into `sink`.
fn wait_relaying(
    child: &mut Child,
    w: &mut Watch<'_>,
    caught: &tty_relay::Caught<'_>,
    master: BorrowedFd<'_>,
    ends: RelayEnds<'_>,
    raw: &mut Option<RawGuard<'_>>,
) -> Result<i32, LaunchError> {
    let mut failed = None;
    let end = {
        let mut until = until_exit(child, w, &mut failed);
        tty_relay::relay(
            master,
            ends.input,
            ends.output,
            ends.out_name,
            ends.sink,
            &mut until,
            caught,
        )?
    };
    if let Some(e) = failed {
        return Err(LaunchError::Spawn(e));
    }
    let code = match end {
        RelayEnd::Exited(code) => code,
        RelayEnd::Detached => {
            // Restored first, or the note would print in raw mode without a carriage return.
            if let Some(guard) = raw.as_mut() {
                guard.restore();
            }
            eprintln!("{}", tty_relay::DETACHED_NOTE);
            let mut until = until_exit(child, w, &mut failed);
            match tty_relay::relay(
                master,
                None,
                ends.sink,
                ends.out_name,
                ends.sink,
                &mut until,
                caught,
            )? {
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

/// Start the instance and return the exit code to propagate. `AlreadyRunning` when it is live,
/// for the caller to turn into an exec. A stop signal during startup stops what was started and
/// returns 128+SIGTERM. `log` is told whether this run started the sandbox. On `AlreadyRunning` it
/// is told nothing: the caller either [joins](run_log::Redirect::joined) that run or says it did
/// not start.
pub fn run(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    mode: TtyMode,
    log: Option<&run_log::Redirect>,
) -> Result<i32, LaunchError> {
    let ended = start_run(env, inst, command, mode, log);
    // A no-op after `started`, whose answer is the one that counts.
    if let Some(log) = log
        && !matches!(ended, Err(LaunchError::AlreadyRunning(_)))
    {
        log.not_started();
    }
    ended
}

fn start_run(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    mode: TtyMode,
    log: Option<&run_log::Redirect>,
) -> Result<i32, LaunchError> {
    // Before anything is created: a tool below its floor is reported even if the run then fails
    // for another reason.
    for line in version::warnings(
        version_probe::bwrap(),
        version_probe::proxy(env),
        &inst.config.services,
    ) {
        eprintln!("bubbler: warning: {line}");
    }
    prepare_runtime_dir(env, inst)?;
    let stop = Arc::new(AtomicBool::new(false));
    let mut registered = SignalGuard(Vec::new());
    // Caught from here: a signal's default action while sidecars start would leave them behind.
    // SIGHUP too, so a terminal that goes away leaves through the same path.
    for sig in [SIGINT, SIGTERM, SIGHUP] {
        let id =
            signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(LaunchError::Signal)?;
        registered.0.push(id);
    }
    // Everything the start made is dropped by the time this matches,
    // which is what stops the sidecars and removes what they left.
    match start_and_wait(env, inst, command, mode, &stop, &mut registered, log) {
        Err(LaunchError::Stopped) => Ok(STOPPED_CODE),
        code => code,
    }
}

// What the command gives when the forwarded SIGTERM stops it.
const STOPPED_CODE: i32 = 128 + SIGTERM;

const START_LOCK_POLL: Duration = Duration::from_millis(50);

// Follows no link, and no FIFO can park the open.
fn open_start_lock(path: &Path) -> Result<OwnedFd, LaunchError> {
    rustix::fs::open(
        path,
        OFlags::CREATE
            | OFlags::WRONLY
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::NOCTTY
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
}

// The liveness check, the unlink of a dead run's socket and the bind all happen under the lock;
// `log` is told the run started while it is held, so a joining start adds after the emptying.
fn bind_control_socket(
    dir: &Path,
    lock_path: &Path,
    name: &str,
    stop: &AtomicBool,
    log: Option<&run_log::Redirect>,
) -> Result<(UnixListener, SocketGuard), LaunchError> {
    let lock_err = |e: Errno| LaunchError::Io(lock_path.to_path_buf(), e.into());
    let lock = open_start_lock(lock_path)?;
    // Polled rather than blocking: the stop signals are installed with
    // SA_RESTART, so a blocking `flock` would sleep through them.
    loop {
        match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(Errno::WOULDBLOCK | Errno::INTR) => {}
            Err(e) => return Err(lock_err(e)),
        }
        if stop.load(Ordering::SeqCst) {
            return Err(LaunchError::Stopped);
        }
        std::thread::sleep(START_LOCK_POLL);
    }
    let sock_path = dir.join(exec::SOCKET_NAME);
    let io_at = |e: io::Error| LaunchError::Io(sock_path.clone(), e);
    if exec::is_live_at(&sock_path) {
        return Err(LaunchError::AlreadyRunning(name.to_owned()));
    }
    match std::fs::remove_file(&sock_path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_at(e)),
        _ => {}
    }
    let listener = UnixListener::bind(&sock_path).map_err(io_at)?;
    let held = rustix::fs::open(
        &sock_path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_at(e.into()))?;
    let bound = rustix::fs::fstat(&held).map_err(|e| io_at(e.into()))?;
    let guard = SocketGuard {
        id: (bound.st_dev as u64, bound.st_ino as u64),
        path: sock_path,
        _held: held,
    };
    if let Some(log) = log {
        log.started();
    }
    Ok((listener, guard))
}

// Only the socket this run bound: a start after this sandbox exited may have bound its own.
// The held descriptor keeps the inode allocated, so a later socket cannot reuse its number.
#[derive(Debug)]
struct SocketGuard {
    path: PathBuf,
    id: (u64, u64),
    _held: OwnedFd,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let ours =
            std::fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.id);
        // Nothing to report: a socket left behind is found refused, and
        // cleared, by the next start.
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// Taken once the sandbox has exited, so a start made now waits for this run's teardown.
// Blocking: a stop signal has usually ended the run by now, and another start holds the lock only
// from its liveness check to its bind. A lock that cannot be had costs only that guarantee, so it
// is a warning.
fn lock_for_teardown(path: &Path) -> Option<OwnedFd> {
    let locked = open_start_lock(path).and_then(|lock| {
        flock(&lock, FlockOperation::LockExclusive)
            .map(|()| lock)
            .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
    });
    match locked {
        Ok(lock) => Some(lock),
        Err(e) => {
            eprintln!("bubbler: warning: {e}");
            None
        }
    }
}

fn start_and_wait(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    mode: TtyMode,
    stop: &AtomicBool,
    registered: &mut SignalGuard,
    log: Option<&run_log::Redirect>,
) -> Result<i32, LaunchError> {
    let dir = instance_runtime_dir(env, &inst.name);
    let lock_path = start_lock_path(env, &inst.name);
    // Declared first to drop last: it holds a relaunch back until everything below is torn down.
    let _ending: Option<OwnedFd>;
    let sock_path = dir.join(exec::SOCKET_NAME);
    let io_at = |e: Errno| LaunchError::Io(sock_path.clone(), e.into());
    let (listener, _socket_guard) = bind_control_socket(&dir, &lock_path, &inst.name, stop, log)?;
    let inherited = fcntl_dupfd_cloexec(listener.as_fd(), 3).map_err(io_at)?;
    let mut alloc = RealAlloc::new(inherited.as_raw_fd(), dir.clone());
    // A run with nothing to run must fail before a sidecar is started.
    resolve_command(inst, command)?;
    // Before the argv is built, so the proxy's socket is there for bwrap
    // to bind: a missing bind source is a failed start, not a warning.
    let plan = dbus::plan(&inst.config.services, &inst.name);
    let portals = plan.as_ref().is_some_and(|p| p.portals);
    let isolated = network_of(&inst.config.services).filter(|c| c.is_isolated());
    let _proxy = match &plan {
        Some(plan) => Some(start_proxy(env, &dir, plan, &RealHost, stop)?),
        None => None,
    };
    // Each socket is moved out of the proxy's reach, then checked; each guard removes its socket
    // at the end of the run.
    let mut buses: Vec<FileGuard> = Vec::new();
    if let Some(plan) = &plan {
        for (socket, node) in plan.buses() {
            buses.push(adopt_proxy_bus(&dir, socket, node, env.uid)?);
        }
    }
    if stop.load(Ordering::SeqCst) {
        return Ok(STOPPED_CODE);
    }
    // The sandbox binds the socket this sidecar accepts on, so it too starts before the argv.
    let _wayland = start_wayland(env, &dir, inst, &RealHost, stop)?;
    if stop.load(Ordering::SeqCst) {
        return Ok(STOPPED_CODE);
    }
    // Before the argv: the context socket is the only PipeWire socket the sandbox gets.
    let _pw_context = start_pw_context(env, &dir, inst, &RealHost, stop)?;
    if stop.load(Ordering::SeqCst) {
        return Ok(STOPPED_CODE);
    }
    // After the context it connects to, before the sandbox it serves; dropped before the context.
    let _pw_pulse = start_pw_pulse(env, &dir, inst, &RealHost, stop)?;
    let host = tty_relay::host_stdio()?;
    let is_tty = tty_relay::host_is_tty();
    let mut stdio = tty::plan(mode, is_tty);
    // Allocated before raw mode, whose settings it would otherwise copy, leaving the sandbox
    // without echo or line editing.
    if let Some(i) = stdio
        .needs_pty()
        .then(|| is_tty.iter().position(|t| *t))
        .flatten()
    {
        stdio.pty = Some(tty_relay::allocate(host[i].as_fd())?);
    }
    // Before the argv is built, for the same reason the proxy is: a bind whose source is not there
    // is a failed start, not a warning.
    prepare_app_runtime(env, &inst.config.services)?;
    // Before bwrap, which never changes cgroup: the sandbox inherits the run's `sandbox` leaf, and
    // the proxy's leaf beside it is out of its reach. Dropped after the sidecars below.
    let net_cgroup = match isolated.filter(|c| !c.allow_hosts.is_empty()) {
        Some(_) => Some(cgroup::create(&inst.name, std::process::id())?),
        None => None,
    };
    // The operations, not the flat argv, because the sweep reads their destinations. Flattened
    // again straight after, so what bwrap is handed is what `build_argv` would have produced.
    let (args, resolved) = build_args_on(env, inst, command, stdio.ctty(), &RealHost)?;
    let finished = args.finish_ops(resolved, &mut alloc)?;
    // A destination behind a planted link is a write outside the sandbox on bwrap below 0.12.0,
    // so the run is refused.
    service::sweep_destinations(&finished.ops, env, &RealHost)?;
    let argv = finished.into_argv();
    // What `stop` becomes once a run has seen it: `stop` is cleared as
    // the signal is acted on, this stays set for the rest of the run.
    let stopping = AtomicBool::new(false);
    let winch = Arc::new(AtomicBool::new(false));
    if stdio.needs_pty() {
        let id = signal_hook::flag::register(SIGWINCH, Arc::clone(&winch))
            .map_err(LaunchError::Signal)?;
        registered.0.push(id);
    }
    if stop.load(Ordering::SeqCst) {
        return Ok(STOPPED_CODE);
    }
    // Raw from here: the pty inside has the line discipline, so Ctrl-C is a byte for it.
    let mut raw = match stdio.raw_mode() {
        true => Some(RawGuard::new(host[0].as_fd())?),
        false => None,
    };
    let mut cmd = bwrap_command(&argv, &mut alloc)?;
    // Inheritable for exactly this spawn: the proxy started before it and pasta starts after it.
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    fcntl_setfd(&inherited, FdFlags::empty()).map_err(io_at)?;
    spawning(&alloc.intended())?;
    // SAFETY: the closure runs in the forked child between `fork` and
    // `execve`, where only async-signal-safe calls are allowed. It makes
    // one syscall and allocates nothing.
    unsafe {
        cmd.pre_exec(join_session_keyring);
    }
    let mut child = cmd
        .stdin(stdio_for(stdio.fds[0], stdio.pty.as_ref())?)
        .stdout(stdio_for(stdio.fds[1], stdio.pty.as_ref())?)
        .stderr(stdio_for(stdio.fds[2], stdio.pty.as_ref())?)
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    alloc.close_options();
    alloc.inheritable(false).map_err(LaunchError::Data)?;
    // Copies kept here would make a dead instance look live and hide the EOF; each number goes
    // with its descriptor, so no later sweep spares a recycled number.
    alloc.socket.take();
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
    // However publishing goes, the sandbox is let go below: an app that
    // cannot reach portals still has to run.
    let _identity = match portals {
        true => publish_identity(env, &inst.name, info.as_ref().map(|(_, raw)| &raw[..])),
        false => None,
    };
    // pasta before the release and the supervisor lookup: a held sandbox has not forked it yet,
    // and one released unconnected would start without network. One that cannot is stopped.
    let mut network = match isolated {
        Some(cfg) => {
            let started = match info.as_ref() {
                Some((child_pid, _)) => {
                    start_network(env, cfg, *child_pid, net_cgroup.as_ref(), stop)
                }
                None => Err(NetworkError::NoSandboxPid.into()),
            };
            match started {
                Ok(handle) => Some(handle),
                Err(e) => {
                    // A Ctrl-C kills the held bwrap too, which is the stop's doing; any other
                    // failure is reported.
                    let bwrap_ended = matches!(child.try_wait(), Ok(Some(_)));
                    abort_sandbox(&mut child, info.as_ref().map(|(pid, _)| *pid));
                    if stop.load(Ordering::SeqCst) && bwrap_ended {
                        return Err(LaunchError::Stopped);
                    }
                    return Err(e);
                }
            }
        }
        None => None,
    };
    if portals || isolated.is_some() {
        // Still held, so a stop caught while pasta started ends the start
        // here rather than letting the application begin only to stop it.
        if stop.load(Ordering::SeqCst) {
            abort_sandbox(&mut child, info.as_ref().map(|(pid, _)| *pid));
            return Ok(STOPPED_CODE);
        }
        release_block(&mut alloc);
    }
    // Its own deadline: the one above may already have been spent waiting
    // for bwrap's info document.
    let supervisor = info.as_ref().and_then(|(reaper, _)| {
        supervisor_pid(*reaper, &mut child, Instant::now() + SUPERVISOR_WAIT)
    });
    // Where output goes that the user's descriptors cannot take, and after a detach: draining
    // keeps a command from blocking on a full pty or pipe.
    let sink = tty_relay::null_stdio()?;
    let caught = tty_relay::Caught {
        winch: &winch,
        stop: &stopping,
    };
    let warn = tty_relay::Warn::new();
    let mut watch = Watch {
        stop,
        supervisor,
        stopping: &stopping,
        network: &mut network,
        warn: &warn,
        start_lock: &lock_path,
        ending: None,
    };
    let code = match &master {
        Some(master) => {
            let out = tty_relay::output_fd(&stdio, &host);
            // The sink never refuses output, so this name is never printed.
            let (host_out, out_name) = match out {
                Some(i) => (host[i].as_fd(), tty::FD_NAMES[i]),
                None => (sink.as_fd(), tty::FD_NAMES[1]),
            };
            let ends = RelayEnds {
                input: stdio.ctty().then(|| host[0].as_fd()),
                output: host_out,
                out_name,
                sink: sink.as_fd(),
            };
            wait_relaying(
                &mut child,
                &mut watch,
                &caught,
                master.as_fd(),
                ends,
                &mut raw,
            )
        }
        None if !pipes.is_empty() => {
            let ends: Vec<(BorrowedFd<'_>, BorrowedFd<'_>, &str)> = pipes
                .iter()
                .map(|(read, i)| (read.as_fd(), host[*i].as_fd(), tty::FD_NAMES[*i]))
                .collect();
            wait_pumping(&mut child, &mut watch, &ends, sink.as_fd())
        }
        None => wait_plain(&mut child, &mut watch),
    };
    // A wait that failed before it saw the exit took no lock.
    _ending = watch
        .ending
        .take()
        .or_else(|| lock_for_teardown(&lock_path));
    let code = code?;
    // After the wait: the generated files are the live sources of the sandbox's binds, and
    // dropping the allocator unlinks them.
    drop(alloc);
    Ok(code)
}

/// Run `argv` inside the live instance `name` and return its exit code; `mode` is as for [`run`].
pub fn exec(env: &Env, name: &str, argv: &[OsString], mode: TtyMode) -> Result<i32, LaunchError> {
    match exec::connect(env, name)? {
        Some(stream) => exec::run_in(&stream, argv, mode),
        None => Err(LaunchError::NotRunning(name.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar_argv::test_support::*;

    use crate::bwrap::Origin;

    use crate::config::WaylandMode;

    use std::io::BufRead;

    use std::os::unix::net::UnixStream;

    /// The pid the proxy's `pre_exec` writes into `cgroup.procs`, which
    /// is formatted by hand because a forked child may not allocate. The
    /// ends of the range and the one-digit case, since an off-by-one in
    /// the buffer index would put the wrong process in the one cgroup
    /// the filter accepts.
    #[test]
    fn the_pid_written_into_the_cgroup_is_formatted_exactly() {
        let mut buf = [0u8; 10];
        assert_eq!(decimal(1, &mut buf), b"1");
        assert_eq!(decimal(0, &mut buf), b"0");
        assert_eq!(decimal(4194304, &mut buf), b"4194304");
        // The widest a pid can be, which fills the buffer exactly.
        assert_eq!(decimal(i32::MAX, &mut buf), b"2147483647");
    }

    /// A session keyring is per-thread credentials, so joining one here
    /// changes this thread's keyring and nothing else's. The id before
    /// and after therefore has to differ: that is the whole of what the
    /// sandbox gets — a keyring of its own rather than the login
    /// session's, whatever a profile says about `keyctl`.
    #[test]
    fn joining_a_session_keyring_leaves_the_thread_on_a_new_one() {
        // KEYCTL_GET_KEYRING_ID(KEY_SPEC_SESSION_KEYRING, create=0).
        let id = || -> i64 {
            // SAFETY: `keyctl` takes its arguments by value; this asks
            // for the id of an existing keyring and creates nothing.
            unsafe { libc::syscall(libc::SYS_keyctl, 0u64, -3i64, 0u64) }
        };
        let before = id();
        if before < 0 {
            // A kernel without CONFIG_KEYS has no keyring to inherit, so
            // there is nothing to test rather than something that failed.
            eprintln!("skipping: this host has no session keyring");
            return;
        }
        join_session_keyring().unwrap();
        let after = id();
        assert!(after >= 0, "no keyring after joining one");
        assert_ne!(before, after, "the thread kept the keyring it was given");
    }

    /// A socket a dead run left is cleared and bound again; one a run
    /// answers on is that run's, and is left answering.
    #[test]
    fn a_start_binds_over_a_dead_socket_and_not_over_a_live_one() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let lock = tmp.path().join("t@start.lock");
        let path = dir.join(exec::SOCKET_NAME);
        let stop = AtomicBool::new(false);
        exec::close_for_good(UnixListener::bind(&path).unwrap());
        let (live, _guard) =
            bind_control_socket(&dir, &lock, "t", &stop, None).expect("a fresh bind");
        let again = bind_control_socket(&dir, &lock, "t", &stop, None);
        assert!(
            matches!(&again, Err(LaunchError::AlreadyRunning(n)) if n == "t"),
            "{again:?}"
        );
        let _client = UnixStream::connect(&path).unwrap();
        live.accept()
            .expect("the first start's socket still answers");
        assert!(lock.exists(), "the lock file is kept");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "only the socket is in the runtime directory"
        );
    }

    /// A run's guard removes the socket it bound, and leaves one a later
    /// start bound at the same path in its place.
    #[test]
    fn a_run_removes_its_own_socket_and_not_a_later_start_s() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join("t@start.lock");
        let path = tmp.path().join(exec::SOCKET_NAME);
        let stop = AtomicBool::new(false);
        let (listener, guard) = bind_control_socket(tmp.path(), &lock, "t", &stop, None).unwrap();
        exec::close_for_good(listener);
        let (_later, later_guard) =
            bind_control_socket(tmp.path(), &lock, "t", &stop, None).unwrap();
        drop(guard);
        assert!(path.exists(), "the later start's socket was removed");
        drop(later_guard);
        assert!(!path.exists(), "a run's own socket is removed");
    }

    /// A start waiting on another's lock is still ended by a stop signal.
    #[test]
    fn a_start_waiting_on_the_lock_ends_when_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join("t@start.lock");
        let held = std::fs::File::create(&lock).unwrap();
        flock(&held, FlockOperation::LockExclusive).unwrap();
        let stop = AtomicBool::new(true);
        let waited = bind_control_socket(tmp.path(), &lock, "t", &stop, None);
        assert!(matches!(waited, Err(LaunchError::Stopped)), "{waited:?}");
        assert!(!tmp.path().join(exec::SOCKET_NAME).exists());
    }

    /// The directory a real allocator gets in a test that allocates
    /// descriptors and no generated file: one that is not there, so a
    /// call to [`FdAllocator::file`] would fail rather than write
    /// somewhere real.
    fn no_data_dir() -> PathBuf {
        PathBuf::from("/nonexistent/bubbler")
    }

    /// The display name decides what the launcher connects to, so it is
    /// refused before anything is: the case runs on a host with no
    /// compositor at all and must still fail on the name, and on this
    /// host it must fail without leaving a socket behind.
    #[test]
    fn a_display_name_that_is_a_path_is_refused_before_the_compositor() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let mut e = env(tmp.path());
        let app = inst(tmp.path(), "wayland\ncommand \"true\"");
        for bad in ["../wayland-1", "/run/user/1000/wayland-1"] {
            e.wayland_display = Some(bad.into());
            let err =
                start_wayland(&e, &dir, &app, &RealHost, &AtomicBool::new(false)).expect_err(bad);
            assert!(
                matches!(
                    err,
                    LaunchError::Plan(PlanError::BadValue {
                        service: "wayland",
                        ..
                    })
                ),
                "{bad}: {err:?}"
            );
        }
        e.wayland_display = None;
        assert!(matches!(
            start_wayland(&e, &dir, &app, &RealHost, &AtomicBool::new(false)),
            Err(LaunchError::Plan(PlanError::MissingEnv {
                service: "wayland",
                var: "WAYLAND_DISPLAY"
            }))
        ));
        assert!(!wayland::socket_path(&dir).exists());
        assert!(!wayland::context_socket_path(&dir).exists());
    }

    /// Without the grant, and with `wayland "host"`, there is nothing to
    /// start: the compositor is not connected to and no socket is bound.
    #[test]
    fn a_run_without_a_sandboxed_wayland_grant_starts_no_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let mut e = env(tmp.path());
        // A name a bind would refuse, so a run that got as far as the
        // check would fail rather than pass quietly.
        e.wayland_display = Some("../wayland-1".into());
        for kdl in ["command \"true\"", "wayland \"host\"\ncommand \"true\""] {
            let app = inst(tmp.path(), kdl);
            assert!(
                start_wayland(&e, &dir, &app, &RealHost, &AtomicBool::new(false))
                    .unwrap()
                    .is_none(),
                "{kdl}"
            );
        }
        assert!(!wayland::socket_path(&dir).exists());
    }

    #[test]
    fn the_proxy_and_the_sandbox_bind_flatpak_info_from_two_host_files() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let kdl = "dbus\nportals\ncommand \"true\"\n";
        let source = |items: &[Explained]| {
            items
                .iter()
                .find_map(|i| match i.args.as_slice() {
                    [flag, src, dest]
                        if flag == "--ro-bind" && dest == OsStr::new(dbus::FLATPAK_INFO) =>
                    {
                        Some(src.clone())
                    }
                    _ => None,
                })
                .expect("a `portals` node writes /.flatpak-info")
        };
        let sandbox = source(&explained(tmp.path(), &e, kdl));
        let proxy = source(
            &explain_proxy(&e, &inst(tmp.path(), kdl))
                .unwrap()
                .expect("a `dbus` node starts a proxy"),
        );
        assert_ne!(sandbox, proxy);
    }

    #[test]
    fn the_proxy_argv_is_explained_only_where_there_is_a_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        assert!(
            explain_proxy(&e, &inst(tmp.path(), "wayland\ncommand \"true\""))
                .unwrap()
                .is_none()
        );
        let items = explain_proxy(&e, &inst(tmp.path(), "dbus\nnotify\ncommand \"true\""))
            .unwrap()
            .expect("a `dbus` node starts a proxy");
        assert_eq!(items[0].origin, Origin::Baseline);
        assert_eq!(
            line(&items, Origin::Identity),
            format!(
                "--ro-bind {}/bubbler/t/proxy-.flatpak-info /.flatpak-info",
                tmp.path().join("run").display()
            )
        );
        // One element per line: the sidecar's argv is its rule list, and
        // each rule is grouped under the node that asked for it.
        assert_eq!(
            line(&items, Origin::Service(1)),
            "--talk=org.freedesktop.Notifications"
        );
        // An option of the sidecar applies to the address before it, so
        // the address and the options over it belong to the node that
        // granted that bus, not to the proxy's own invocation.
        let bus = line(&items, Origin::Service(0));
        assert!(bus.contains(" --filter"), "{bus}");
        assert!(bus.starts_with("unix:path="), "{bus}");
        let own: Vec<String> = items
            .iter()
            .filter(|i| i.origin == Origin::Command)
            .map(|i| i.args[0].to_string_lossy().into_owned())
            .collect();
        assert!(own.iter().any(|a| a.starts_with("--fd=")), "{own:?}");
        assert!(
            !own.iter()
                .any(|a| a.starts_with("--talk=") || a == "--filter"),
            "a rule is not the proxy's own argument: {own:?}"
        );
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
    fn app_runtime_dirs_are_created_once_and_reused_whatever_their_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let svcs = vec![
            Service::AppRuntime {
                id: "org.keepassxc.KeePassXC".to_owned(),
                mode: crate::config::ShareMode::ReadWrite,
            },
            Service::AppRuntime {
                id: "org.example.Other".to_owned(),
                mode: crate::config::ShareMode::ReadOnly,
            },
        ];
        prepare_app_runtime(&e, &svcs).unwrap();
        let one = tmp.path().join("run/app/org.keepassxc.KeePassXC");
        assert!(one.is_dir());
        assert!(tmp.path().join("run/app/org.example.Other").is_dir());
        // A native application creates the directory at 0755 (Qt's
        // `mkpath`), and bubbler reuses it rather than fighting over the
        // mode: `$XDG_RUNTIME_DIR` being 0700 is what keeps it private.
        std::fs::set_permissions(&one, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_app_runtime(&e, &svcs).unwrap();
        assert_eq!(
            std::fs::metadata(&one).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn an_app_runtime_id_that_is_not_a_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        std::fs::create_dir_all(tmp.path().join("run/app")).unwrap();
        // A symlink where the directory belongs would bind whatever it
        // points at, resolved on the host's side of the boundary.
        std::os::unix::fs::symlink("/etc", tmp.path().join("run/app/org.example.App")).unwrap();
        let svcs = vec![Service::AppRuntime {
            id: "org.example.App".to_owned(),
            mode: crate::config::ShareMode::ReadOnly,
        }];
        assert!(matches!(
            prepare_app_runtime(&e, &svcs),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
        std::fs::remove_file(tmp.path().join("run/app/org.example.App")).unwrap();
        std::fs::write(tmp.path().join("run/app/org.example.App"), b"").unwrap();
        assert!(matches!(
            prepare_app_runtime(&e, &svcs),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
    }

    #[test]
    fn an_app_parent_that_is_not_a_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        std::fs::create_dir_all(tmp.path().join("run")).unwrap();
        // `mkdir` reports EEXIST for a plain file too, so the probe of
        // the parent is the only thing between this and an `openat` that
        // would fail somewhere less legible.
        std::fs::write(tmp.path().join("run/app"), b"").unwrap();
        assert!(matches!(
            prepare_app_runtime(
                &e,
                &[Service::AppRuntime {
                    id: "org.example.App".to_owned(),
                    mode: crate::config::ShareMode::ReadOnly,
                }]
            ),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
    }

    #[test]
    fn an_app_parent_that_is_a_symlink_is_refused_before_any_id_is_made() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        std::fs::create_dir_all(tmp.path().join("run")).unwrap();
        std::fs::create_dir_all(tmp.path().join("elsewhere")).unwrap();
        // `app` pointing away would make every id resolve outside the
        // runtime directory while the sandbox binds the path the config
        // named.
        std::os::unix::fs::symlink(tmp.path().join("elsewhere"), tmp.path().join("run/app"))
            .unwrap();
        let svcs = vec![Service::AppRuntime {
            id: "org.example.App".to_owned(),
            mode: crate::config::ShareMode::ReadOnly,
        }];
        assert!(matches!(
            prepare_app_runtime(&e, &svcs),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
        assert!(!tmp.path().join("elsewhere/org.example.App").exists());
    }

    #[test]
    fn a_config_without_app_runtime_creates_no_app_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        prepare_app_runtime(&e, &[Service::Wayland(WaylandMode::default())]).unwrap();
        assert!(!tmp.path().join("run/app").exists());
    }

    #[test]
    fn a_live_instance_is_never_started_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"/usr/bin/true\"");
        let dir = prepare_runtime_dir(&e, &i).unwrap();
        let _listener = UnixListener::bind(dir.join(exec::SOCKET_NAME)).unwrap();
        assert!(matches!(
            run(&e, &i, None, TtyMode::Passthrough, None),
            Err(LaunchError::AlreadyRunning(n)) if n == "t"
        ));
    }

    /// A start that lost the race and joined writes like any run, so a
    /// start that fails after it still finds room for its line.
    #[test]
    fn a_start_that_joined_leaves_room_for_a_failed_start_after_it() {
        use std::io::Write;
        let _fd2 = run_log::FD2.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"/usr/bin/true\"");
        let dir = prepare_runtime_dir(&e, &i).unwrap();
        let _listener = UnixListener::bind(dir.join(exec::SOCKET_NAME)).unwrap();
        let log = tmp.path().join(run_log::LOG_FILE);

        let joining = run_log::redirect(&log, true).unwrap();
        let lost = run(&e, &i, None, TtyMode::Passthrough, Some(&joining));
        assert!(
            matches!(lost, Err(LaunchError::AlreadyRunning(_))),
            "{lost:?}"
        );
        joining.joined();
        std::io::stderr().write_all(&vec![b'x'; 2 << 20]).unwrap();
        drop(joining);

        let failed = "bubbler: the start failed before its lock\n";
        let start = run_log::redirect(&log, true).unwrap();
        std::io::stderr().write_all(failed.as_bytes()).unwrap();
        start.not_started();
        drop(start);

        let held = run_log::read(&log).unwrap().unwrap();
        assert!(
            String::from_utf8_lossy(&held).contains(failed),
            "the failure was not recorded"
        );
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

    /// The proxy is stopped with the run: dropping the handle signals
    /// the sidecar, waits for it and takes the application's socket
    /// with it.
    ///
    /// A stand-in child rather than the proxy itself: what is under test
    /// is the handle, and a run that reaches a real proxy needs a
    /// compositor. The child's stdout is a pipe nothing else holds, so
    /// its read end reports end of file exactly when the child is gone —
    /// which no reused pid can fake.
    #[test]
    fn dropping_the_wayland_handle_stops_the_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("wayland");
        std::fs::write(&socket, b"").unwrap();
        let (read, write) = rustix::pipe::pipe().unwrap();
        let child = Command::new("/usr/bin/sleep")
            .arg("600")
            .stdout(Stdio::from(write))
            .spawn()
            .unwrap();
        let handle = WaylandHandle {
            child,
            alloc: RealAlloc::sidecar(no_data_dir()),
            _close: None,
            _socket: FileGuard(socket.clone()),
            _context: None,
            _stderr: run_log::relay().unwrap().1,
        };
        let started = Instant::now();
        drop(handle);
        assert!(
            started.elapsed() < WL_PROXY_STOP,
            "the drop waited out the kill deadline"
        );
        let slice = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert!(
            poll(&mut [PollFd::new(&read, PollFlags::IN)], Some(&slice)).unwrap() > 0,
            "the stand-in proxy is still running"
        );
        let mut byte = [0u8; 1];
        assert_eq!(rustix::io::read(&read, &mut byte).unwrap(), 0);
        assert!(!socket.exists(), "the socket outlived the run");
    }

    /// A sidecar that failed to start has already been reaped by the
    /// readiness wait, and neither handle may signal that pid: by then
    /// the kernel may have handed it to something else.
    ///
    /// The decision itself is [`still_running`], and that is what this
    /// asserts, because the drop's use of it is invisible from in here:
    /// a `kill` of a reaped pid is an ignored `ESRCH`, so deleting the
    /// guard changes nothing this process can see. A mutation of
    /// `still_running` — a constant either way, or the `try_wait`
    /// without its negation — fails one of the four assertions below.
    #[test]
    fn a_reaped_proxy_is_not_signalled_when_the_handle_drops() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("wayland");
        std::fs::write(&socket, b"").unwrap();
        let mut live = Command::new("/usr/bin/sleep").arg("600").spawn().unwrap();
        assert!(
            still_running(&mut live),
            "a running sidecar is one to signal"
        );
        let _ = live.kill();
        let _ = live.wait();
        assert!(!still_running(&mut live), "and a killed one is not");

        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        // What the readiness wait does to a sidecar that exits instead of
        // reporting: it is reaped here, and the pid stops being its own.
        let deadline = Instant::now() + PROXY_READY;
        while still_running(&mut child) {
            assert!(Instant::now() < deadline, "/usr/bin/true never exited");
            std::thread::sleep(POLL);
        }
        assert!(
            !still_running(&mut child),
            "the cached status answers every later call"
        );
        let handle = WaylandHandle {
            child,
            alloc: RealAlloc::sidecar(no_data_dir()),
            _close: None,
            _socket: FileGuard(socket.clone()),
            _context: None,
            _stderr: run_log::relay().unwrap().1,
        };
        let started = Instant::now();
        drop(handle);
        assert!(started.elapsed() < POLL, "the drop waited on a reaped pid");
        assert!(!socket.exists(), "the socket outlived the run");
    }

    /// R13: a live run stops on the missing tool, before a sidecar it
    /// could never create the context with is started. The plan-time
    /// check in `service` is what a `--dry-run` fails on; this is the
    /// path a run takes.
    #[test]
    fn a_run_without_pw_container_starts_no_context_sidecar() {
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "pipewire\ncommand \"true\"\n");
        let dir = instance_runtime_dir(&e, "t");
        // The session's daemon is up: the tool is the one thing missing.
        let (_, _, socket) = types();
        let host = FakeHost::default().with(
            pipewire::host_socket(&e.runtime_dir).to_str().unwrap(),
            socket,
        );
        assert!(matches!(
            start_pw_context(&e, &dir, &i, &host, &AtomicBool::new(false)),
            Err(LaunchError::Plan(PlanError::MissingResource { service: "pipewire", ref path }))
                if path == Path::new(pipewire::PW_CONTAINER)
        ));
        assert!(!pipewire::dir(&dir).exists(), "a context directory is left");
    }

    /// R13, pulse half: the same for the module that makes the sidecar a
    /// PulseAudio server — without it the server would come up without a
    /// socket and the run would fail on a timeout instead.
    #[test]
    fn a_run_without_the_pulse_protocol_module_starts_no_server() {
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "pulseaudio\ncommand \"true\"\n");
        let dir = instance_runtime_dir(&e, "t");
        // Everything the server needs except the module itself.
        let (file, _, _) = types();
        let host = FakeHost::default().with(
            pipewire::pulse_conf_dirs(&e.config_home)[2]
                .join(pipewire::PULSE_CONF)
                .to_str()
                .unwrap(),
            file,
        );
        assert!(matches!(
            start_pw_pulse(&e, &dir, &i, &host, &AtomicBool::new(false)),
            Err(LaunchError::Plan(PlanError::MissingResource { service: "pulseaudio", ref path }))
                if path == Path::new(pipewire::PULSE_MODULE)
        ));
        assert!(
            !pipewire::pulse_dir(&dir).exists(),
            "a server directory is left"
        );
    }

    /// R6: what the private pulse server reads is the host's own
    /// configuration plus bubbler's two settings, in a directory only
    /// this user can open.
    #[test]
    fn the_pulse_config_is_the_hosts_copied_with_bubblers_fragment_beside_it() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let text = "pulse.properties = { server.address = [ \"unix:native\" ] }\n";
        let source = e.config_home.join("pipewire").join(pipewire::PULSE_CONF);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, text).unwrap();
        let dir = instance_runtime_dir(&e, "t");
        std::fs::create_dir_all(pipewire::pulse_dir(&dir)).unwrap();

        let cfg = write_pulse_config(&e, &RealHost, &dir).unwrap();

        assert_eq!(cfg, pipewire::pulse_config_dir(&dir));
        assert_eq!(
            std::fs::read_to_string(cfg.join(pipewire::PULSE_CONF)).unwrap(),
            text
        );
        assert_eq!(
            std::fs::read_to_string(cfg.join(pipewire::PULSE_DROP_IN)).unwrap(),
            pipewire::PULSE_OVERRIDE
        );
        let mode = |p: PathBuf| std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(cfg.clone()), 0o700);
        assert_eq!(mode(cfg.join("pipewire-pulse.conf.d")), 0o700);
        assert_eq!(mode(cfg.join(pipewire::PULSE_CONF)), 0o600);
        assert_eq!(mode(cfg.join(pipewire::PULSE_DROP_IN)), 0o600);
    }

    /// A sidecar can write its own directory, so a dead run can leave a
    /// link there to a host directory the sidecar chose. Planted where a
    /// file bubbler writes or unlinks is: in the pulse directory itself
    /// and in both subdirectories.
    #[test]
    fn a_dead_runs_links_in_the_pulse_directory_are_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let source = e.config_home.join("pipewire").join(pipewire::PULSE_CONF);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, "pulse.properties = {}\n").unwrap();
        let dir = instance_runtime_dir(&e, "t");
        let pw = pipewire::pulse_dir(&dir);
        std::fs::create_dir_all(&pw).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let sentinels = [pipewire::PULSE_NATIVE, pipewire::PULSE_CONF];
        for name in sentinels {
            std::fs::write(elsewhere.join(name), b"sentinel").unwrap();
        }
        std::os::unix::fs::symlink(&elsewhere, pipewire::pulse_socket_dir(&dir)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, pipewire::pulse_config_dir(&dir)).unwrap();

        prepare_pulse_dir(&e, &RealHost, &dir).unwrap();

        for name in sentinels {
            assert_eq!(
                std::fs::read(elsewhere.join(name)).ok().as_deref(),
                Some(&b"sentinel"[..]),
                "{name} outside the runtime directory was touched"
            );
        }
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 2);
        for made in [
            pipewire::pulse_socket_dir(&dir),
            pipewire::pulse_config_dir(&dir),
        ] {
            assert!(
                std::fs::symlink_metadata(&made).unwrap().is_dir(),
                "{} is not a directory of its own",
                made.display()
            );
        }

        // A link in place of the pulse directory itself.
        std::fs::remove_dir_all(&pw).unwrap();
        std::fs::remove_file(elsewhere.join(pipewire::PULSE_CONF)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &pw).unwrap();
        prepare_pulse_dir(&e, &RealHost, &dir).unwrap();
        assert!(std::fs::symlink_metadata(&pw).unwrap().is_dir());
        assert!(!elsewhere.join(pipewire::PULSE_CONF).exists());
        assert!(!elsewhere.join("cfg").exists());
    }

    /// The pulse server can replace the directory its socket is made in
    /// while it runs; the socket is then looked for there, never in the
    /// host directory a link names, and nothing there is moved or removed.
    #[test]
    fn a_link_in_place_of_the_socket_directory_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join(pipewire::PULSE_NATIVE), b"sentinel").unwrap();
        std::fs::create_dir(pipewire::pulse_dir(&dir)).unwrap();
        let made_in = pipewire::pulse_socket_dir(&dir);
        std::os::unix::fs::symlink(&elsewhere, &made_in).unwrap();
        assert!(matches!(
            adopt_socket(
                "pulseaudio",
                (&made_in, pipewire::PULSE_NATIVE),
                (&dir, pipewire::PULSE_ADOPTED),
                rustix::process::getuid().as_raw(),
            ),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "pulseaudio",
                expected: "a directory",
                ..
            }))
        ));
        assert_eq!(
            std::fs::read(elsewhere.join(pipewire::PULSE_NATIVE))
                .ok()
                .as_deref(),
            Some(&b"sentinel"[..])
        );
    }

    /// The same for the two other directories a sidecar writes: whatever
    /// a dead run left at their name is replaced by a fresh directory, a
    /// link included, and what it pointed at is left alone.
    #[test]
    fn a_sidecar_directory_is_made_afresh_whatever_is_at_its_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("sentinel"), b"sentinel").unwrap();
        for sidecar in [pipewire::dir(&dir), dbus::socket_dir(&dir)] {
            std::os::unix::fs::symlink(&elsewhere, &sidecar).unwrap();
            fresh_sidecar_dir(&sidecar).unwrap();
            let made = std::fs::symlink_metadata(&sidecar).unwrap();
            assert!(made.is_dir(), "{} is still a link", sidecar.display());
            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);
            assert!(elsewhere.join("sentinel").exists());

            std::fs::write(sidecar.join("left"), b"").unwrap();
            fresh_sidecar_dir(&sidecar).unwrap();
            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);

            std::fs::remove_dir(&sidecar).unwrap();
            std::fs::write(&sidecar, b"").unwrap();
            fresh_sidecar_dir(&sidecar).unwrap();
            assert!(std::fs::symlink_metadata(&sidecar).unwrap().is_dir());
        }
    }

    /// A sidecar runs as the user, so it can leave a tree no one may open
    /// in the directory it writes. Each real start path clears it before
    /// its sidecar starts, links inside it included, and changes nothing
    /// those links name. The fakes reach no further than a sidecar bwrap
    /// that fails on a bind source the host does not have.
    #[test]
    fn an_unreadable_tree_a_sidecar_left_does_not_block_its_start() {
        use crate::host::fake::{FakeHost, types};
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        let bus = tmp.path().join("bus");
        e.dbus_address = Some(format!("unix:path={}", bus.display()).into());
        e.proxy_override = Some(PathBuf::from("/usr/bin/true"));
        let conf = e.config_home.join("pipewire").join(pipewire::PULSE_CONF);
        std::fs::create_dir_all(conf.parent().unwrap()).unwrap();
        std::fs::write(&conf, "pulse.properties = {}\n").unwrap();
        let (file, _, socket) = types();
        let host = FakeHost::default()
            .with(bus.to_str().unwrap(), socket)
            .with(
                pipewire::host_socket(&e.runtime_dir).to_str().unwrap(),
                socket,
            )
            .with(pipewire::PW_CONTAINER, file)
            .with(pipewire::PULSE_MODULE, file)
            .with(conf.to_str().unwrap(), file);
        let i = inst(tmp.path(), "dbus\npipewire\npulseaudio\ncommand \"true\"\n");
        let dir = prepare_runtime_dir(&e, &i).unwrap();
        let plan = dbus::plan(&i.config.services, "t").expect("dbus is granted");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let sentinel = elsewhere.join("sentinel");
        std::fs::write(&sentinel, b"sentinel").unwrap();
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
        let before = (mode(&elsewhere), mode(&sentinel));
        let stop = AtomicBool::new(false);
        type Start<'a> = Box<dyn Fn() -> Result<(), LaunchError> + 'a>;
        let starts: [(PathBuf, Start); 3] = [
            (
                dbus::socket_dir(&dir),
                Box::new(|| start_proxy(&e, &dir, &plan, &host, &stop).map(|_| ())),
            ),
            (
                pipewire::dir(&dir),
                Box::new(|| start_pw_context(&e, &dir, &i, &host, &stop).map(|_| ())),
            ),
            (
                pipewire::pulse_dir(&dir),
                Box::new(|| start_pw_pulse(&e, &dir, &i, &host, &stop).map(|_| ())),
            ),
        ];
        for (sidecar, start) in starts {
            let locked = sidecar.join("x");
            std::fs::create_dir_all(&locked).unwrap();
            std::fs::write(locked.join("f"), b"").unwrap();
            std::os::unix::fs::symlink(&sentinel, locked.join("out")).unwrap();
            std::os::unix::fs::symlink(&elsewhere, locked.join("up")).unwrap();
            for d in [&locked, &sidecar] {
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o000)).unwrap();
            }

            let got = start();

            assert!(
                !matches!(&got, Err(LaunchError::Io(p, _)) if p.starts_with(&sidecar)),
                "{}: {got:?}",
                sidecar.display()
            );
            if let Ok(m) = std::fs::symlink_metadata(&sidecar) {
                std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o700)).unwrap();
                assert!(m.is_dir(), "{}", sidecar.display());
                assert_eq!(
                    std::fs::read_dir(&sidecar).unwrap().count(),
                    0,
                    "{}: the tree is still there",
                    sidecar.display()
                );
            }
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
            assert_eq!((mode(&elsewhere), mode(&sentinel)), before);
        }
    }

    /// A chain of directories `depth` deep at `top`, made one level at a
    /// time so no path ever gets long; the deepest directory is returned.
    fn plant_chain(top: &Path, depth: usize) -> OwnedFd {
        let pin = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        std::fs::create_dir(top).unwrap();
        let mut at = rustix::fs::open(top, pin, Mode::empty()).unwrap();
        for _ in 0..depth {
            rustix::fs::mkdirat(&at, "d", Mode::RWXU).unwrap();
            at = rustix::fs::openat(&at, "d", pin, Mode::empty()).unwrap();
        }
        at
    }

    /// The descriptor limit most desktops start a process with, so a tree
    /// deeper than half of it is deeper than one descriptor per level of
    /// a walk can reach.
    fn with_desktop_fd_limit(test: impl FnOnce()) {
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
        let was = getrlimit(Resource::Nofile);
        let lowered = Rlimit {
            current: Some(was.current.map_or(1024, |c| c.min(1024))),
            maximum: was.maximum,
        };
        setrlimit(Resource::Nofile, lowered).unwrap();
        test();
        setrlimit(Resource::Nofile, was).unwrap();
    }

    fn leftovers(dir: &Path, sidecar: &Path) -> Vec<OsString> {
        let mut prefix = sidecar.file_name().unwrap().to_owned();
        prefix.push(".");
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.as_bytes().starts_with(prefix.as_bytes()))
            .collect()
    }

    /// A sidecar can build a tree deeper than any walk holding a
    /// descriptor per level can follow. The start still gets a fresh
    /// directory, and the tree is gone rather than left beside it.
    #[test]
    fn a_tree_deeper_than_the_descriptor_limit_does_not_block_its_start() {
        with_desktop_fd_limit(|| {
            let tmp = tempfile::tempdir().unwrap();
            let sidecar = pipewire::dir(tmp.path());
            plant_chain(&sidecar, 1500);

            fresh_sidecar_dir(&sidecar).unwrap();

            assert!(std::fs::symlink_metadata(&sidecar).unwrap().is_dir());
            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);
            assert_eq!(leftovers(tmp.path(), &sidecar), Vec::<OsString>::new());
        });
    }

    /// What the moved tree links to, at its deepest and behind levels no
    /// one may open, is neither followed, removed nor given new modes.
    #[test]
    fn removing_a_moved_tree_changes_nothing_its_links_name() {
        use std::os::unix::fs::PermissionsExt;
        with_desktop_fd_limit(|| {
            let tmp = tempfile::tempdir().unwrap();
            let elsewhere = tmp.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            let sentinel = elsewhere.join("sentinel");
            std::fs::write(&sentinel, b"sentinel").unwrap();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            let before = (mode(&elsewhere), mode(&sentinel));
            let dir = tmp.path().join("t");
            std::fs::create_dir(&dir).unwrap();
            let sidecar = dbus::socket_dir(&dir);
            let bottom = plant_chain(&sidecar, 600);
            rustix::fs::symlinkat(&sentinel, &bottom, "out").unwrap();
            rustix::fs::symlinkat(&elsewhere, &bottom, "up").unwrap();
            rustix::fs::chmod(
                format!("/proc/self/fd/{}", bottom.as_raw_fd()),
                Mode::empty(),
            )
            .unwrap();
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o000)).unwrap();

            fresh_sidecar_dir(&sidecar).unwrap();

            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);
            assert_eq!(leftovers(&dir, &sidecar), Vec::<OsString>::new());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
            assert_eq!((mode(&elsewhere), mode(&sentinel)), before);
        });
    }

    /// `PIPEWIRE_CONFIG_DIR` has no fallback for the main file, so a host
    /// holding none is a run that would fail inside a sidecar; it fails
    /// here instead, naming the file it looked for last.
    #[test]
    fn a_host_with_no_pulse_configuration_is_named_rather_than_started_without_one() {
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = instance_runtime_dir(&e, "t");
        std::fs::create_dir_all(pipewire::pulse_dir(&dir)).unwrap();
        assert!(matches!(
            write_pulse_config(&e, &FakeHost::default(), &dir),
            Err(LaunchError::Plan(PlanError::MissingResource { service: "pulseaudio", ref path }))
                if path == Path::new("/usr/share/pipewire/pipewire-pulse.conf")
        ));
    }

    /// `--explain --proxy` reads the sidecar it would start, so the
    /// third bus is in it. The address comes from the variable at-spi2's
    /// own clients read first, which is why this explanation asks no bus
    /// anything.
    #[test]
    fn the_explained_proxy_argv_holds_the_accessibility_bus() {
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.at_spi_bus_address = Some("unix:path=/run/user/1000/at-spi/bus_0".into());
        let items = explain_proxy(&e, &inst(tmp.path(), "dbus\na11y\ncommand \"true\""))
            .unwrap()
            .expect("a `dbus` node starts a proxy");
        let dir = tmp.path().join("run/bubbler/t/dbus").display().to_string();
        let bus = line(&items, Origin::Service(1));
        assert!(
            bus.starts_with(&format!(
                "unix:path=/run/user/1000/at-spi/bus_0 {dir}/a11y --filter --call="
            )),
            "{bus}"
        );
        assert_eq!(
            bus.split(' ').filter(|a| a.starts_with("--call=")).count()
                + bus
                    .split(' ')
                    .filter(|a| a.starts_with("--broadcast="))
                    .count(),
            dbus::A11Y_RULES.len(),
            "{bus}"
        );
    }

    /// The bus addresses are host environment, so each resolved path is
    /// measured against bubbler's own runtime directory before anything
    /// is bound: a socket under it is an instance's control socket or a
    /// proxy's own output, and proxying one would hand the sandbox the
    /// channel that runs commands inside another.
    #[test]
    fn a_host_bus_address_under_bubblers_runtime_directory_is_refused() {
        use crate::host::fake::{self, FakeHost};
        let tmp = tempfile::tempdir().unwrap();
        // Real directories and a real link, because the explanation
        // resolves through the host it runs on; the fake host used for a
        // run is told about the same link.
        let run = tmp.path().join("run");
        std::fs::create_dir_all(run.join("bubbler/t")).unwrap();
        std::fs::create_dir_all(run.join("systemd")).unwrap();
        std::os::unix::fs::symlink(run.join("bubbler/t"), run.join("link")).unwrap();
        let path = |p: &Path| p.display().to_string();
        // The session bus is resolved and probed before the other two,
        // so it has to be a socket for their guard to be reached at all.
        let (_, _, sock) = fake::types();
        let host = FakeHost::default()
            .with("/run/user/1000/bus", sock)
            .link(&path(&run.join("link")), &path(&run.join("bubbler/t")));
        let inside = OsString::from(format!(
            "unix:path={}",
            path(&run.join("bubbler/t/init.sock"))
        ));
        type Set = fn(&mut Env, OsString);
        let cases: [(&str, &str, Set); 3] = [
            ("dbus\ncommand \"true\"", "dbus", |e, a| {
                e.dbus_address = Some(a)
            }),
            (
                "dbus\nsystem-bus { talk \"org.freedesktop.UPower\" }\ncommand \"true\"",
                "system-bus",
                |e, a| e.dbus_system_address = Some(a),
            ),
            ("dbus\na11y\ncommand \"true\"", dbus::A11Y_NODE, |e, a| {
                e.at_spi_bus_address = Some(a)
            }),
        ];
        for (kdl, node, set) in cases {
            let mut e = env(tmp.path());
            // The other addresses stay outside the directory, so the
            // failure can only be the bus under test.
            e.dbus_address = Some("unix:path=/run/user/1000/bus".into());
            set(&mut e, inside.clone());
            let cfg = inst(tmp.path(), kdl);
            let plan = dbus::plan(&cfg.config.services, "t").expect("a `dbus` node starts a proxy");
            let dir = instance_runtime_dir(&e, "t");
            // Both paths into the proxy, since a run resolves the
            // addresses again rather than reading the explanation.
            for got in [
                start_proxy(&e, &dir, &plan, &host, &AtomicBool::new(false)).map(|_| ()),
                explain_proxy(&e, &cfg).map(|_| ()),
            ] {
                match got {
                    Err(LaunchError::Plan(PlanError::BadValue { service, reason })) => {
                        assert_eq!(service, node);
                        assert_eq!(
                            reason,
                            "the host bus address names a socket under bubbler's own \
                             runtime directory"
                        );
                    }
                    other => panic!("{node}: {other:?}"),
                }
            }
        }
        // Spelling the same directory through a `..` or a link is the
        // same address, so both are resolved before the comparison
        // rather than after it.
        for sneaky in [
            run.join("systemd/../bubbler/t/init.sock"),
            run.join("link/init.sock"),
        ] {
            let mut e = env(tmp.path());
            e.dbus_address = Some(OsString::from(format!("unix:path={}", path(&sneaky))));
            let cfg = inst(tmp.path(), "dbus\ncommand \"true\"");
            let plan = dbus::plan(&cfg.config.services, "t").expect("a `dbus` node starts a proxy");
            let dir = instance_runtime_dir(&e, "t");
            for got in [
                start_proxy(&e, &dir, &plan, &host, &AtomicBool::new(false)).map(|_| ()),
                explain_proxy(&e, &cfg).map(|_| ()),
            ] {
                assert!(
                    matches!(
                        got,
                        Err(LaunchError::Plan(PlanError::BadValue {
                            service: "dbus",
                            ..
                        }))
                    ),
                    "{}: {got:?}",
                    path(&sneaky)
                );
            }
        }
        // The addresses a session normally sets are outside it, and the
        // guard leaves them alone.
        let mut e = env(tmp.path());
        e.dbus_address = Some("unix:path=/run/user/1000/bus".into());
        e.dbus_system_address = Some("unix:path=/run/dbus/system_bus_socket".into());
        e.at_spi_bus_address = Some("unix:path=/run/user/1000/at-spi/bus_0".into());
        assert!(
            explain_proxy(
                &e,
                &inst(
                    tmp.path(),
                    "dbus\nsystem-bus { talk \"org.freedesktop.UPower\" }\na11y\ncommand \"true\"",
                )
            )
            .unwrap()
            .is_some()
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
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: None,
                    a11y: None,
                },
                dir,
                &FakeHost::default(),
                &mut dry(&e),
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
        let app_bus = dbus::app_bus_path(dir, dbus::SESSION_SOCKET)
            .display()
            .to_string();
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
    fn a_proxied_socket_is_moved_out_of_the_proxys_reach() {
        // Both buses are adopted by the same rule; only the file name
        // differs.
        for socket in [dbus::SESSION_SOCKET, dbus::SYSTEM_SOCKET] {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path();
            std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
            let listener = UnixListener::bind(dbus::proxy_bus_path(dir, socket)).unwrap();
            let guard = adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()).unwrap();
            let moved = std::fs::symlink_metadata(dbus::app_bus_path(dir, socket)).unwrap();
            assert!(std::os::unix::fs::FileTypeExt::is_socket(
                &moved.file_type()
            ));
            assert!(!dbus::proxy_bus_path(dir, socket).exists());
            // The proxy serves the socket it bound, not the path it bound
            // it at.
            assert!(UnixStream::connect(dbus::app_bus_path(dir, socket)).is_ok());
            drop(listener);
            drop(guard);
            assert!(
                !dbus::app_bus_path(dir, socket).exists(),
                "{socket}: the socket outlived the run"
            );
        }
        // A failure names the node the user would have to look at.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(dbus::socket_dir(tmp.path())).unwrap();
        assert!(matches!(
            adopt_proxy_bus(
                tmp.path(),
                dbus::SYSTEM_SOCKET,
                dbus::SYSTEM_NODE,
                own_uid()
            ),
            Err(LaunchError::Plan(PlanError::MissingResource {
                service: "system-bus",
                ..
            }))
        ));
    }

    #[test]
    fn anything_but_a_socket_in_the_proxys_directory_stops_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let socket = dbus::SESSION_SOCKET;
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::MissingResource {
                service: "dbus",
                ..
            }))
        ));
        // A symlink is the attack: `stat` through it would report the type
        // of its target, and bwrap would bind that target.
        std::os::unix::fs::symlink("/etc", dbus::proxy_bus_path(dir, socket)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            }))
        ));
        // Moved out of the proxy's reach first, so a refused run leaves
        // nothing of it behind either.
        assert!(
            !dbus::app_bus_path(dir, socket).exists(),
            "the symlink was kept"
        );
        assert!(
            !dbus::proxy_bus_path(dir, socket).exists(),
            "the symlink was left in place"
        );
        std::fs::write(dbus::proxy_bus_path(dir, socket), b"").unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            }))
        ));
        assert!(!dbus::app_bus_path(dir, socket).exists());
        // A directory is refused like anything else, and removed with what
        // is in it: `remove_file` cannot take one, and one left at this
        // name would fail the rename of every later start.
        std::fs::create_dir(dbus::proxy_bus_path(dir, socket)).unwrap();
        std::fs::write(dbus::proxy_bus_path(dir, socket).join("x"), b"").unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            }))
        ));
        assert!(
            !dbus::app_bus_path(dir, socket).exists(),
            "the directory was kept"
        );
        // And the next honest start works.
        let listener = UnixListener::bind(dbus::proxy_bus_path(dir, socket)).unwrap();
        adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid())
            .expect("a socket after a refused directory");
        drop(listener);
    }

    /// A proxy can plant a tree no walk finishes where its socket belongs:
    /// deeper than the descriptor limit, with a level no one may open and
    /// links out. It is refused, nothing it links to changes, and nothing
    /// is left at the socket's name to fail the next start.
    #[test]
    fn a_deep_unreadable_tree_at_a_proxy_sockets_name_does_not_block_the_next_start() {
        use std::os::unix::fs::PermissionsExt;
        with_desktop_fd_limit(|| {
            let tmp = tempfile::tempdir().unwrap();
            let elsewhere = tmp.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            let sentinel = elsewhere.join("sentinel");
            std::fs::write(&sentinel, b"sentinel").unwrap();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            let before = (mode(&elsewhere), mode(&sentinel));
            let dir = tmp.path().join("t");
            std::fs::create_dir(&dir).unwrap();
            std::fs::create_dir(dbus::socket_dir(&dir)).unwrap();
            let socket = dbus::SESSION_SOCKET;
            let planted = dbus::proxy_bus_path(&dir, socket);
            let bottom = plant_chain(&planted, 1500);
            rustix::fs::mkdirat(&bottom, "locked", Mode::RWXU).unwrap();
            let locked = rustix::fs::openat(
                &bottom,
                "locked",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            rustix::fs::symlinkat(&sentinel, &locked, "out").unwrap();
            rustix::fs::symlinkat(&elsewhere, &locked, "up").unwrap();
            rustix::fs::chmod(
                format!("/proc/self/fd/{}", locked.as_raw_fd()),
                Mode::empty(),
            )
            .unwrap();

            assert!(matches!(
                adopt_proxy_bus(&dir, socket, dbus::SESSION_NODE, own_uid()),
                Err(LaunchError::Plan(PlanError::WrongType {
                    expected: "a socket",
                    ..
                }))
            ));

            let app_bus = dbus::app_bus_path(&dir, socket);
            assert!(
                std::fs::symlink_metadata(&app_bus).is_err(),
                "the tree was kept"
            );
            assert_eq!(leftovers(&dir, &app_bus), Vec::<OsString>::new());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
            assert_eq!((mode(&elsewhere), mode(&sentinel)), before);
            let listener = UnixListener::bind(&planted).unwrap();
            adopt_proxy_bus(&dir, socket, dbus::SESSION_NODE, own_uid())
                .expect("a socket after a refused tree");
            drop(listener);
        });
    }

    /// When a run ends, each sidecar's directory goes with whatever its
    /// sidecar left in it, a level no one may open included.
    #[test]
    fn a_sidecars_unreadable_tree_goes_when_its_run_ends() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let child = || Command::new("true").spawn().unwrap();
        let relay = || run_log::relay().unwrap().1;
        let plant = |sidecar: &Path| {
            let locked = sidecar.join("x");
            std::fs::create_dir_all(&locked).unwrap();
            std::fs::write(locked.join("f"), b"").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            sidecar.to_path_buf()
        };
        let handles: Vec<(PathBuf, Box<dyn std::any::Any>)> = vec![
            (
                dbus::socket_dir(dir),
                Box::new(ProxyHandle {
                    child: child(),
                    alloc: RealAlloc::sidecar(dir.to_path_buf()),
                    socket_dir: plant(&dbus::socket_dir(dir)),
                    _stderr: relay(),
                }),
            ),
            (
                pipewire::dir(dir),
                Box::new(PwHandle {
                    child: child(),
                    alloc: RealAlloc::sidecar(dir.to_path_buf()),
                    dir: plant(&pipewire::dir(dir)),
                    _socket: None,
                    _stderr: relay(),
                }),
            ),
            (
                pipewire::pulse_dir(dir),
                Box::new(PulseHandle {
                    child: child(),
                    alloc: RealAlloc::sidecar(dir.to_path_buf()),
                    dir: plant(&pipewire::pulse_dir(dir)),
                    _socket: None,
                    _stderr: relay(),
                }),
            ),
        ];
        for (sidecar, handle) in handles {
            drop(handle);
            assert!(
                std::fs::symlink_metadata(&sidecar).is_err(),
                "{} is still there",
                sidecar.display()
            );
        }
    }

    /// A tree with more entries than one pass may touch still shrinks on
    /// every pass, so the starts that follow clear it in the end.
    #[test]
    fn clearing_a_tree_wider_than_the_budget_makes_progress_on_every_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("t");
        std::fs::create_dir(&top).unwrap();
        for i in 0..30 {
            std::fs::write(top.join(format!("f{i}")), b"").unwrap();
        }
        for i in 0..5 {
            let sub = top.join(format!("d{i}"));
            std::fs::create_dir_all(sub.join("deeper")).unwrap();
            std::fs::write(sub.join("deeper").join("f"), b"").unwrap();
            for j in 0..10 {
                std::fs::write(sub.join(format!("f{j}")), b"").unwrap();
            }
        }
        fn count(dir: &Path) -> usize {
            std::fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .map(|e| {
                            let e = e.unwrap();
                            1 + if e.file_type().unwrap().is_dir() {
                                count(&e.path())
                            } else {
                                0
                            }
                        })
                        .sum()
                })
                .unwrap_or(0)
        }
        let at = open_dir(tmp.path()).unwrap();
        let mut left = count(&top);
        let passes = left;
        for _ in 0..passes {
            match remove_tree(&at, OsStr::new("t"), &mut 8) {
                Ok(()) => {
                    assert!(std::fs::symlink_metadata(&top).is_err());
                    return;
                }
                Err(e) => assert_eq!(e, Errno::AGAIN),
            }
            let now = count(&top);
            assert!(now < left, "a pass left {now} of {left} entries");
            left = now;
        }
        panic!("{left} entries are never removed");
    }

    /// A run killed between moving a planted directory to a socket's name
    /// and clearing it leaves it there; the next start moves it aside
    /// rather than failing to rename its socket onto it.
    #[test]
    fn a_directory_left_at_a_sockets_name_does_not_block_the_next_adopt() {
        use std::os::unix::fs::FileTypeExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let socket = dbus::SESSION_SOCKET;
        std::fs::create_dir(dbus::socket_dir(&dir)).unwrap();
        let app_bus = dbus::app_bus_path(&dir, socket);
        std::fs::create_dir(&app_bus).unwrap();
        std::fs::write(app_bus.join("x"), b"").unwrap();
        let _bus = UnixListener::bind(dbus::proxy_bus_path(&dir, socket)).unwrap();
        let _bus_guard = adopt_proxy_bus(&dir, socket, dbus::SESSION_NODE, own_uid())
            .expect("a socket over a directory left at its name");
        assert!(std::fs::metadata(&app_bus).unwrap().file_type().is_socket());

        let made_in = tmp.path().join("pw");
        std::fs::create_dir(&made_in).unwrap();
        let target = dir.join("pw-socket");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("x"), b"").unwrap();
        let _pw = UnixListener::bind(made_in.join("made")).unwrap();
        let _pw_guard = adopt_socket(
            "pipewire",
            (&made_in, "made"),
            (&dir, "pw-socket"),
            own_uid(),
        )
        .expect("a socket over a directory left at its name");
        assert!(std::fs::metadata(&target).unwrap().file_type().is_socket());
        assert_eq!(leftovers(&dir, &app_bus), Vec::<OsString>::new());
        assert_eq!(leftovers(&dir, &target), Vec::<OsString>::new());
    }

    fn own_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn a_proxied_socket_of_another_user_stops_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let socket = dbus::SESSION_SOCKET;
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        let _listener = UnixListener::bind(dbus::proxy_bus_path(dir, socket)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE, own_uid() + 1),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a socket owned by this user",
                ..
            }))
        ));
        assert!(!dbus::app_bus_path(dir, socket).exists());
    }

    #[test]
    fn a_link_in_place_of_the_proxys_directory_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let socket = dbus::SESSION_SOCKET;
        let _listener = UnixListener::bind(elsewhere.join(socket)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dbus::socket_dir(&dir)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(&dir, socket, dbus::SESSION_NODE, own_uid()),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "dbus",
                expected: "a directory",
                ..
            }))
        ));
        assert!(elsewhere.join(socket).exists());
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

    /// A namespace is the identity of its nsfs file, and the check is
    /// asked of the descriptor the run already holds rather than of a
    /// path resolved a second time — which is where a reused pid would
    /// slip through.
    #[test]
    fn the_namespace_check_compares_the_held_descriptor_by_identity() {
        let (me, user) = (
            Path::new("/proc/self/ns/net"),
            Path::new("/proc/self/ns/user"),
        );
        if !me.exists() || !user.exists() {
            return;
        }
        let held = rustix::fs::open(me, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert!(same_namespace(held.as_fd(), me).unwrap());
        // Another namespace of the same process: a different inode on the
        // same filesystem, so the device alone would not tell them apart.
        assert!(!same_namespace(held.as_fd(), user).unwrap());
        // A path the run cannot ask about is never a match: a pid it
        // cannot check is one it must not act on either.
        assert!(same_namespace(held.as_fd(), Path::new("/proc/self/ns/nonesuch")).is_err());
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

    /// A child in the shape bwrap leaves a sandbox in: a network
    /// namespace owned by one user namespace, with the process itself
    /// moved on into a nested user namespace that owns nothing. Comes
    /// back with the link of the owning namespace, which the child
    /// reports before it moves. `None`, with a printed reason, where
    /// this host cannot make one.
    fn nested_child() -> Option<(Child, String)> {
        let child = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "/usr/bin/sh",
                "-c",
                "readlink /proc/self/ns/user; \
                 exec unshare --user /usr/bin/sh -c 'echo ready; exec sleep 30'",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(e) => {
                eprintln!("skipping: unshare(1) could not be started: {e}");
                return None;
            }
        };
        let said: Vec<String> = child
            .stdout
            .take()
            .map(|out| {
                std::io::BufReader::new(out)
                    .lines()
                    .map_while(Result::ok)
                    .take(2)
                    .collect()
            })
            .unwrap_or_default();
        match said.as_slice() {
            [owner, ready] if ready == "ready" => Some((child, owner.clone())),
            _ => {
                eprintln!("skipping: nested user namespaces are unavailable here");
                let _ = child.kill();
                let _ = child.wait();
                None
            }
        }
    }

    #[test]
    fn the_ns_get_userns_opcode_is_the_one_the_header_defines() {
        // `linux/nsfs.h`: `#define NSIO 0xb7` and
        // `#define NS_GET_USERNS _IO(NSIO, 0x1)`.
        assert_eq!(NS_GET_USERNS, 0xb701);
    }

    #[test]
    fn the_user_namespace_comes_from_the_network_namespace_it_owns() {
        let Some((mut child, owner)) = nested_child() else {
            return;
        };
        let netns = rustix::fs::open(
            format!("/proc/{}/ns/net", child.id()),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let userns = owning_userns(netns.as_fd()).unwrap();
        // The kernel opens it close-on-exec (`open_related_ns` in
        // `fs/nsfs.c`), so a namespace descriptor is not something the
        // sidecars bubbler spawns inherit.
        assert!(
            rustix::io::fcntl_getfd(&userns)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
        let link = |p: String| {
            std::fs::read_link(p)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        let got = link(format!("/proc/self/fd/{}", userns.as_raw_fd()));
        // A namespace link reads as `<type>:[<inode>]`, and the inode is
        // the namespace's identity (`namespaces(7)`).
        assert_eq!(got, owner, "not the namespace that owns the netns");
        // The path this replaced, and the reason it was a race: by now
        // the child is in a user namespace of its own, which owns
        // nothing and gives pasta no authority over the netns.
        assert_ne!(got, link(format!("/proc/{}/ns/user", child.id())));
        assert_ne!(got, link("/proc/self/ns/user".to_owned()));
        let _ = child.kill();
        let _ = child.wait();
    }
}
