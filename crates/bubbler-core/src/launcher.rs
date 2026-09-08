//! Spawns bubblewrap and the sidecars a sandbox needs — the filtering
//! D-Bus proxy and, for an isolated `network`, pasta. The only
//! process-spawning code in the crate; it never goes through a shell,
//! every spawn is preceded by a [`fds::sweep_cloexec`] so a child holds
//! only the descriptors it was meant to, and every sidecar is killed on
//! every way out of a run.

use std::ffi::{OsStr, OsString, c_void};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{Access, AtFlags, MemfdFlags, Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use rustix::ioctl::{self, Opcode};
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{
    DumpableBehavior, Pid, Signal, kill_process, set_dumpable_behavior,
    set_parent_process_death_signal, test_kill_process,
};
use rustix::thread::{
    CapabilitiesSecureBits, CapabilitySet, CapabilitySets, LinkNameSpaceType, capabilities,
    clear_ambient_capability_set, configure_capability_in_ambient_set, move_into_link_name_space,
    set_capabilities, set_capabilities_secure_bits, set_no_new_privs,
};
use signal_hook::SigId;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};

use bubbler_init::fds;

use crate::bwrap::{BwrapArgs, Explained, FdAllocator, Origin};
use crate::config::{EtcMode, NetworkConfig, Service, Userns, WaylandMode};
use crate::env::Env;
use crate::error::{ConfigError, LaunchError};
use crate::host::{Host, RealHost};
use crate::instance::Instance;
use crate::tty::{self, Pty, RawGuard, RelayEnd, StdioTarget, TtyMode};
use crate::wayland::{ProxyPlan, WaylandError};
use crate::{cgroup, dbus, exec, init_bin, network, pipewire, seccomp, service, version, wayland};

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

/// How long the Wayland proxy may take to leave after SIGTERM before it
/// is killed.
const WL_PROXY_STOP: Duration = Duration::from_secs(5);

/// How long the audio sidecar has to report the socket of the security
/// context it created.
const PW_READY: Duration = Duration::from_secs(5);

/// How long that sidecar may take to leave after SIGTERM before it is
/// killed.
const PW_STOP: Duration = Duration::from_secs(5);

/// The longest report line the audio sidecar is read for. What the
/// holder writes is a constant of bubbler's; anything longer is not the
/// holder answering.
const PW_REPORT_MAX: usize = 4096;

/// How long pasta has to report that it has configured the sandbox's
/// network namespace.
const PASTA_READY: Duration = Duration::from_secs(5);

/// How long pasta may take to leave after SIGTERM before it is killed.
const PASTA_STOP: Duration = Duration::from_secs(1);

/// How long `nft` has to install the outbound ruleset. Measured at 1.5 ms
/// on this host, so this is a bound on a hang and not on the work.
const NFT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the egress proxy has to report that it is listening. It
/// binds one socket after three `setns` calls; this is a bound on a hang
/// and not on the work.
const NET_PROXY_READY: Duration = Duration::from_secs(5);

/// How long the egress proxy may take to leave after SIGTERM before it
/// is killed.
const NET_PROXY_STOP: Duration = Duration::from_secs(5);

/// How long the supervisor has to appear inside the sandbox before the
/// run goes on without a pid to signal.
const SUPERVISOR_WAIT: Duration = Duration::from_secs(2);

/// The name a generated file takes in the run's runtime directory: the
/// path it is bound at inside the sandbox with its separators flattened,
/// and `prefix` in front of it, so `--explain` names the file a run
/// would write and no two destinations collide on one name.
pub(crate) fn data_name(prefix: &str, dest: &Path) -> OsString {
    let mut name = OsString::from(prefix);
    let mut first = true;
    for part in dest.components() {
        if let Component::Normal(part) = part {
            if !first {
                name.push("-");
            }
            name.push(part);
            first = false;
        }
    }
    name
}

/// What a sidecar's generated files are called apart from the
/// application sandbox's: both write into the run's one runtime
/// directory, and `portals` gives both of them a `/.flatpak-info`.
const SIDECAR_PREFIX: &str = "proxy-";

/// Allocator for `--dry-run`: numbers every fd 3, 4, ... and names each
/// generated file where a run would write it, without creating anything.
#[derive(Debug)]
pub struct DryRunAlloc {
    next: u32,
    dir: PathBuf,
    prefix: &'static str,
}

impl DryRunAlloc {
    /// `dir` is the run's runtime directory, which is where a real run
    /// writes the generated files. Fd numbering starts above the
    /// process's own stdio.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            next: 2,
            dir,
            prefix: "",
        }
    }

    /// [`DryRunAlloc::new`] naming the files a sidecar's own allocator
    /// would write, which are never the application sandbox's.
    pub fn sidecar(dir: PathBuf) -> Self {
        Self {
            prefix: SIDECAR_PREFIX,
            ..Self::new(dir)
        }
    }

    fn bump(&mut self) -> io::Result<OsString> {
        self.next += 1;
        Ok(OsString::from(self.next.to_string()))
    }
}

impl FdAllocator for DryRunAlloc {
    fn data(&mut self, _content: &[u8]) -> io::Result<OsString> {
        self.bump()
    }
    fn file(&mut self, dest: &Path, _content: &[u8]) -> io::Result<OsString> {
        Ok(self.dir.join(data_name(self.prefix, dest)).into_os_string())
    }
    fn init_socket(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn ready_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn listener(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn info_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn block_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
}

/// Allocator for a real run: memfds for seccomp filters, generated files
/// in the run's runtime directory, the control socket bubbler already
/// bound, and a sidecar ready pipe.
///
/// A generated file is the live source of a read-only bind, so its
/// content must not change and it must not be unlinked while any sandbox
/// holds that bind. Each allocator therefore owns the files it wrote and
/// is the only thing that unlinks them, when it drops after its own
/// sandbox has exited; and no two allocators of one run write the same
/// path, which is what [`RealAlloc::sidecar`]'s name prefix is for —
/// `portals` gives the application sandbox and the D-Bus proxy a
/// `/.flatpak-info` each, and the proxy is already running with its own
/// bound when the application's argv is built.
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
    /// Which of `fds` that socket became, so bubbler's own copy can be
    /// closed again once the sidecar holding it has been spawned.
    listen_fd: Option<RawFd>,
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
    /// The run's runtime directory, where the generated files go.
    dir: PathBuf,
    /// What this allocator's file names begin with, so a sidecar's are
    /// never the application sandbox's.
    prefix: &'static str,
    /// The generated files written there so far, removed when this
    /// allocator drops. It outlives the sandbox it built the argv for —
    /// a bind whose source is unlinked is exactly what this replaced.
    written: Vec<PathBuf>,
}

impl Drop for RealAlloc {
    fn drop(&mut self) {
        for path in self.written.drain(..) {
            // Nothing to report: the run is over, and a file left behind
            // is overwritten by the next start of the same instance.
            let _ = std::fs::remove_file(path);
        }
    }
}

impl RealAlloc {
    /// Allocate around an already inherited control socket fd. `dir` is
    /// the run's runtime directory, which the caller has created.
    pub fn new(socket: RawFd, dir: PathBuf) -> Self {
        let mut a = Self::in_dir(dir, "");
        a.socket = Some(socket);
        a
    }

    /// Allocate for a sidecar sandbox: generated files and a ready pipe,
    /// but no control socket to hand out. Its files are named apart from
    /// the application sandbox's, which are bound into a sandbox this
    /// one must not write under.
    pub fn sidecar(dir: PathBuf) -> Self {
        Self::in_dir(dir, SIDECAR_PREFIX)
    }

    fn in_dir(dir: PathBuf, prefix: &'static str) -> Self {
        Self {
            fds: Vec::new(),
            socket: None,
            listen: None,
            listen_fd: None,
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

    /// Keep `fd` open for the child and report the number it will see.
    fn keep(&mut self, fd: OwnedFd) -> OsString {
        let n = fd.as_raw_fd();
        self.fds.push(fd);
        OsString::from(n.to_string())
    }

    /// Close bubbler's own copy of the listening socket, once the
    /// sidecar that accepts on it has been spawned. Nothing to do where
    /// no listener was handed over.
    fn close_listener(&mut self) {
        if let Some(fd) = self.listen_fd.take() {
            self.fds.retain(|held| held.as_raw_fd() != fd);
        }
    }

    /// Clear `CLOEXEC` on every fd the next spawn is meant to inherit, or
    /// put it back once that spawn has happened.
    ///
    /// bubbler spawns more than one process per run — the D-Bus proxy
    /// before the sandbox, pasta after it — and each of these fds belongs
    /// to exactly one of them. They are `CLOEXEC` at rest, so the window
    /// in which they can be inherited is the one spawn they were built
    /// for.
    ///
    /// That window is process-wide, so only one thread may spawn while it
    /// is open. bubbler's other threads are the last-run log's copier
    /// ([`crate::run_log`]) and the KDL parser's
    /// ([`crate::config::parse_document`]); neither opens a descriptor or
    /// starts a process, and no configuration is parsed while the window
    /// is open.
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

    /// Every descriptor the spawn this allocator was built for is meant to
    /// inherit, which is what [`spawning`] keeps and marks the rest against.
    ///
    /// Three sources: the ones [`RealAlloc::inheritable`] opens the window
    /// for, the control socket bubbler dup'ed for the sandbox, and the
    /// write end of the info pipe — which is never close-on-exec at all,
    /// because bwrap reports the sandbox pid on it and the caller closes
    /// it by hand the moment bwrap has been started.
    ///
    /// Only descriptors that are still open: a caller that closes one
    /// takes it out of the allocator in the same breath, since a number
    /// left here after its descriptor is gone would exempt from the next
    /// sweep whatever the kernel had handed that number to since.
    fn intended(&self) -> Vec<RawFd> {
        let mut fds: Vec<RawFd> = self.fds.iter().map(AsRawFd::as_raw_fd).collect();
        fds.extend(self.socket);
        fds.extend(self.info_write.as_ref().map(AsRawFd::as_raw_fd));
        fds
    }
}

/// Mark every descriptor above stdio close-on-exec except the ones `keep`
/// names, immediately before a spawn.
///
/// bubbler is started by whatever the user runs it from, and a shell, a
/// terminal or a build system hands a process descriptors it never asked
/// for — `makepkg` runs a `check()` with two of its own open. bwrap passes
/// on every descriptor it holds, so without this each of those reaches the
/// sandbox, the supervisor, every command exec'd in it, the D-Bus and
/// Wayland proxies, pasta and the `nft` that holds CAP_NET_ADMIN over the
/// sandbox's namespaces. Nothing is closed: bubbler's own descriptors stay
/// open for the rest of the run and only stop crossing into children.
///
/// Like [`RealAlloc::inheritable`], the window is process-wide, so only
/// one thread may spawn while it is open; bubbler's only other thread
/// starts no process at all ([`crate::run_log`]).
fn spawning(keep: &[RawFd]) -> Result<(), LaunchError> {
    fds::sweep_cloexec(keep).map_err(LaunchError::Descriptors)
}

impl FdAllocator for RealAlloc {
    fn data(&mut self, content: &[u8]) -> io::Result<OsString> {
        // `MFD_CLOEXEC` and cleared again only around the spawn this argv
        // was built for ([`RealAlloc::inheritable`]): a data file holds
        // the sandbox's `/etc/passwd`, its `/.flatpak-info` and its
        // resolver, and no sidecar of the run has any use for one.
        let fd = rustix::fs::memfd_create("bubbler-data", MemfdFlags::CLOEXEC)?;
        let mut f = std::fs::File::from(fd);
        f.write_all(content)?;
        f.seek(SeekFrom::Start(0))?;
        Ok(self.keep(f.into()))
    }

    /// `O_NOFOLLOW` so a link cannot move the write out of the runtime
    /// directory, and the mode is set rather than left to the caller's
    /// umask, so what the sandbox sees does not depend on how bubbler
    /// was started. bwrap takes the destination's permissions from the
    /// source, so this is the mode `/etc/passwd` has inside.
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

    /// The sandboxed sidecar writes the ready byte, so it inherits the
    /// write end; the read end stays here and out of every child. One
    /// pipe per run: a second call replaces the first.
    fn ready_pipe(&mut self) -> io::Result<OsString> {
        let (read, write) = rustix::pipe::pipe()?;
        fcntl_setfd(&read, FdFlags::CLOEXEC)?;
        self.ready_read = Some(read);
        Ok(self.keep(write))
    }

    /// The socket bubbler bound and listened on for this sidecar, handed
    /// over by number. It is kept with the other inherited descriptors,
    /// so it is inheritable for exactly the one spawn it was built for.
    fn listener(&mut self) -> io::Result<OsString> {
        match self.listen.take() {
            Some(fd) => {
                self.listen_fd = Some(fd.as_raw_fd());
                Ok(self.keep(fd))
            }
            None => Err(io::Error::other("this sidecar has no listening socket")),
        }
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

/// The `network` grant of a config, if it has one.
fn network_of(services: &[Service]) -> Option<&NetworkConfig> {
    services.iter().find_map(|s| match s {
        Service::Network(cfg) => Some(cfg),
        _ => None,
    })
}

/// How the config's `wayland` grant is to be served, if it has one.
fn wayland_mode(services: &[Service]) -> Option<WaylandMode> {
    services.iter().find_map(|s| match s {
        Service::Wayland(mode) => Some(*mode),
        _ => None,
    })
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
    build_argv_on(env, inst, command, alloc, ctty, &RealHost)
}

/// [`build_argv`] against one view of the host, so a test can state which
/// device nodes and sockets the sandbox is built from.
fn build_argv_on(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    alloc: &mut dyn FdAllocator,
    ctty: bool,
    host: &dyn Host,
) -> Result<Vec<OsString>, LaunchError> {
    let (args, command) = build_args_on(env, inst, command, ctty, host)?;
    args.finish(command, alloc)
}

/// Every argument of an instance's argv with the node that produced it,
/// numbering fds the way [`build_argv`] does under `--dry-run`. Nothing
/// is created: an explanation describes a launch, it does not perform one.
pub fn explain(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    ctty: bool,
) -> Result<Vec<Explained>, LaunchError> {
    explain_on(env, inst, command, ctty, &RealHost)
}

/// [`explain`] against one view of the host, so a test can state which
/// sockets and device nodes the explanation is built from.
fn explain_on(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    ctty: bool,
    host: &dyn Host,
) -> Result<Vec<Explained>, LaunchError> {
    let (args, command) = build_args_on(env, inst, command, ctty, host)?;
    let mut alloc = DryRunAlloc::new(instance_runtime_dir(env, &inst.name));
    args.finish_explained(command, &mut alloc)
}

/// The builder and the command behind [`build_argv`], before the fds are
/// numbered: what the argv and the explanation of it are both made from.
///
/// Nothing here asks the compositor anything. A sandboxed `wayland`
/// binds the socket bubbler's own proxy accepts on however the
/// compositor answered about `wp_security_context_manager_v1`; that
/// answer decides only what the proxy connects to, which is the
/// sidecar's argv and not this one.
fn build_args_on<'a>(
    env: &Env,
    inst: &'a Instance,
    command: Option<&'a [OsString]>,
    ctty: bool,
    host: &dyn Host,
) -> Result<(BwrapArgs, &'a [OsString]), LaunchError> {
    let command = resolve_command(inst, command)?;
    let plan = dbus::plan(&inst.config.services, &inst.name);
    let instance_runtime = instance_runtime_dir(env, &inst.name);
    let wayland_plan =
        wayland_mode(&inst.config.services).map(|m| wayland::plan(m, &instance_runtime));
    // Resolved before the services rather than beside the bind at the
    // end: `portals` binds the same file as the `flatpak-spawn` shim, so
    // a run that cannot find the supervisor must fail before either.
    let init = init_bin::locate(env, host)?;
    let ctx = service::ServiceCtx {
        instance_runtime,
        dbus: plan.as_ref(),
        wayland: wayland_plan.as_ref(),
        init_bin: &init,
    };
    let mut args = BwrapArgs::baseline(env, &inst.home(), host);
    if inst.config.userns == Userns::Disable {
        args.tag(Origin::Userns);
        args.disable_userns();
    }
    if inst.config.etc == EtcMode::Host {
        args.tag(Origin::Etc);
        args.bind_host_etc(host);
    }
    if let Some(size) = inst.config.tmp {
        args.tag(Origin::Tmp);
        args.tmp_size(size.0);
    }
    if ctty {
        args.ctty();
    }
    // Two grants make the sandbox wait at startup, and each is tagged
    // with the node that asked for it. A portal call is answered by the
    // identity bubbler publishes from bwrap's own info document, so the
    // app waits until that file is there; an isolated `network` waits
    // until pasta has configured the namespace, which cannot happen
    // before bwrap has reported the pid to attach to.
    let waits = [
        inst.config
            .services
            .iter()
            .position(|s| matches!(s, Service::Portals { .. }))
            .filter(|_| plan.as_ref().is_some_and(|p| p.portals)),
        inst.config
            .services
            .iter()
            .position(|s| matches!(s, Service::Network(c) if c.is_isolated())),
    ];
    // One `--block-fd`, whichever grants asked for it: bwrap reads the fd
    // once, and a second flag would leave the sandbox waiting for a pipe
    // nothing closes. The portal grant is the one named where a config
    // holds both, so an explanation of a portal sandbox reads as before.
    if let Some(i) = waits.into_iter().flatten().next() {
        args.tag(Origin::Service(i));
        args.block_until_released();
    }
    args.tag(Origin::Seccomp);
    apply_seccomp(
        &mut args,
        seccomp::RuleSet::with(&inst.config.seccomp),
        env,
        &inst.name,
    )?;
    service::apply_all(&inst.config.services, env, &mut args, host, &ctx)?;
    service::apply_shares(
        &inst.config.services,
        &inst.config.shares,
        env,
        &mut args,
        host,
    )?;
    service::apply_env(&inst.config.env, &mut args)?;
    args.tag(Origin::Init);
    args.bind_init(&init);
    Ok((args, command))
}

/// Load `set` into the sandbox as one filter, or say on stderr that this
/// instance runs unfiltered. A profile asking for no filter is honoured,
/// but never silently — and one whose `allow` list leaves nothing to deny
/// asked for the same thing the long way round.
fn apply_seccomp(
    args: &mut BwrapArgs,
    set: Option<seccomp::RuleSet>,
    env: &Env,
    instance: &str,
) -> Result<(), LaunchError> {
    let Some(set) = set else {
        eprintln!("bubbler: seccomp disabled for instance {instance}");
        return Ok(());
    };
    let Some(program) = seccomp::compile(&set, env.seccomp_log)? else {
        eprintln!("bubbler: seccomp has no rules left for instance {instance}");
        return Ok(());
    };
    args.add_seccomp(program.bytes, program.arches);
    Ok(())
}

/// Complete bwrap argv (without the program name) for the sidecar that
/// creates one instance's PipeWire security context. `alloc` keeps the
/// read end of the pipe the holder inside reports the socket's path on.
pub fn pw_context_argv(
    env: &Env,
    ctx: &pipewire::Context<'_>,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Vec<OsString>, LaunchError> {
    let report = alloc.ready_pipe().map_err(LaunchError::Data)?;
    let init = init_bin::locate(env, host)?;
    let mut args = BwrapArgs::pw_context_baseline(
        &pipewire::host_socket(&env.runtime_dir),
        &pipewire::dir(ctx.instance_runtime),
        host,
    );
    // The sidecar has no `seccomp` node of its own: an instance may relax
    // its own filter, never the one around the process that holds its
    // security context open.
    args.tag(Origin::Seccomp);
    if let Some(program) = seccomp::compile(&seccomp::RuleSet::default_set(), env.seccomp_log)? {
        args.add_seccomp(program.bytes, program.arches);
    }
    args.tag(Origin::Command);
    // The supervisor binary a second time, under the name that selects
    // its holder mode: `pw-container` runs one word, and the basename of
    // that word is the whole of what chooses the mode.
    args.ro_bind(&init, Path::new(pipewire::HOLDER_INSIDE));
    // `pw-container` finds the session's daemon under this, and the
    // holder finds the descriptor to report on under the other. Nothing
    // else of the environment survives the baseline's `--clearenv`.
    args.setenv(OsStr::new("XDG_RUNTIME_DIR"), env.runtime_dir.as_os_str());
    args.setenv(OsStr::new(pipewire::REPORT_FD), &report);
    let properties = pipewire::properties(ctx.instance, ctx.run_id, ctx.audio);
    args.finish_plain(&pipewire::command(&properties), alloc)
}

/// Complete bwrap argv (without the program name) for the D-Bus proxy
/// sidecar of one instance. `buses` holds the host socket of each bus
/// the plan grants, already type-checked; `alloc` keeps the read end of
/// the pipe the proxy reports readiness on.
pub fn proxy_argv(
    env: &Env,
    plan: &dbus::Plan,
    buses: dbus::HostBuses<'_>,
    dir: &Path,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Vec<OsString>, LaunchError> {
    let (args, command) = proxy_args(env, plan, buses, dir, host, alloc)?;
    let plain: Vec<OsString> = command.into_iter().map(|(arg, _)| arg).collect();
    args.finish_plain(&plain, alloc)
}

/// Every argument of the sidecar's argv with what produced it, or `None`
/// when the instance grants no bus and so starts no proxy. The host bus
/// socket is not probed here, as nothing is started: `--dry-run` builds
/// the app's bus bind from a socket that does not exist yet either.
///
/// Each address is resolved the way a run would resolve it, since an
/// argv without them is not the argv that would be run. For the
/// accessibility bus that means reading `$AT_SPI_BUS_ADDRESS` and, when
/// the session set none, asking `org.a11y.Bus` where its socket is —
/// the one question this view asks anything. The sandbox's own argv
/// asks nothing: it binds the socket the sidecar will serve.
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
        .map(|_| dbus::guarded_host_a11y_bus(&RealHost, env))
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

/// The builder and the command behind [`proxy_argv`], each command
/// element with the node that asked for it. `alloc` numbers the ready
/// pipe first, which is where the sidecar's fd numbering starts.
fn proxy_args(
    env: &Env,
    plan: &dbus::Plan,
    buses: dbus::HostBuses<'_>,
    dir: &Path,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<(BwrapArgs, Vec<(OsString, Origin)>), LaunchError> {
    let ready = alloc.ready_pipe().map_err(LaunchError::Data)?;
    let program = dbus::proxy_program(env);
    let command = dbus::proxy_command_nodes(&program, plan, buses, dir, env.dbus_log, &ready);
    // A rule belongs to the node that asked for it; the proxy's own
    // invocation is the command it is.
    let command: Vec<(OsString, Origin)> = command
        .into_iter()
        .map(|(arg, node)| (arg, node.map_or(Origin::Command, Origin::Service)))
        .collect();
    let mut args = BwrapArgs::proxy_baseline(
        buses.session,
        buses.system,
        buses.a11y,
        &dbus::socket_dir(dir),
        host,
    );
    // The sidecar has no `seccomp` node of its own: an instance may relax
    // its own filter, never the one around the process holding its bus.
    args.tag(Origin::Seccomp);
    if let Some(program) = seccomp::compile(&seccomp::RuleSet::default_set(), env.seccomp_log)? {
        args.add_seccomp(program.bytes, program.arches);
    }
    // The proxy reads this to decide it is talking for a sandboxed app;
    // without `portals` it is only the `[Application]` section.
    args.tag(Origin::Identity);
    args.ro_bind_data(plan.flatpak_info.clone(), Path::new(dbus::FLATPAK_INFO));
    // An overriding binary is not on the sandbox's `PATH`, so it is bound
    // in at its own path; the packaged proxy needs no bind.
    if env.proxy_override.is_some() {
        args.tag(Origin::Command);
        let program = service::require_file(host, "dbus", program)?;
        args.ro_bind(&program, &program);
    }
    Ok((args, command))
}

/// Where a `wayland` grant sits in the config, which is what the
/// sidecar's arguments are attributed to.
fn wayland_node(services: &[Service]) -> Option<usize> {
    services
        .iter()
        .position(|s| matches!(s, Service::Wayland(_)))
}

/// Complete bwrap argv (without the program name) for the Wayland proxy
/// sidecar of one instance. `plan` says which sockets it serves and
/// connects to; `alloc` hands over the listening socket and keeps the
/// read end of the pipe the proxy reports readiness on.
pub fn wl_proxy_argv(
    env: &Env,
    plan: &ProxyPlan,
    node: usize,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Vec<OsString>, LaunchError> {
    let (args, command) = wl_proxy_args(env, plan, node, host, alloc)?;
    let plain: Vec<OsString> = command.into_iter().map(|(arg, _)| arg).collect();
    args.finish_plain(&plain, alloc)
}

/// Every argument of the Wayland sidecar's argv with what produced it,
/// or `None` when the instance grants no sandboxed `wayland` and so
/// starts no proxy. Nothing is probed and nothing is started: like the
/// D-Bus proxy's, this is the argv a run would build, described.
pub fn explain_wayland_proxy(
    env: &Env,
    inst: &Instance,
) -> Result<Option<Vec<Explained>>, LaunchError> {
    let (Some(plan), Some(node)) = (
        wl_proxy_plan(env, inst),
        wayland_node(&inst.config.services),
    ) else {
        return Ok(None);
    };
    let mut alloc = DryRunAlloc::sidecar(instance_runtime_dir(env, &inst.name));
    let (args, command) = wl_proxy_args(env, &plan, node, &RealHost, &mut alloc)?;
    Ok(Some(args.finish_plain_explained(&command, &mut alloc)?))
}

/// How an explanation describes the Wayland proxy of `inst`, or `None`
/// where the instance grants no sandboxed `wayland`.
///
/// The compositor is not asked anything — `--dry-run` and `--explain`
/// connect to nothing — so this is the run a compositor that implements
/// `wp_security_context_manager_v1` gets. One that does not says so on
/// stderr and has the proxy hide the privileged globals instead.
pub fn wl_proxy_plan(env: &Env, inst: &Instance) -> Option<ProxyPlan> {
    match wayland_mode(&inst.config.services) {
        Some(WaylandMode::Sandboxed { clipboard }) => Some(ProxyPlan::context(
            &instance_runtime_dir(env, &inst.name),
            clipboard,
        )),
        Some(WaylandMode::Host) | None => None,
    }
}

/// The builder and the command behind [`wl_proxy_argv`], each command
/// element with the node that asked for it. `alloc` numbers the
/// listening socket first and the ready pipe second, which is the order
/// the proxy's own arguments name them in.
fn wl_proxy_args(
    env: &Env,
    plan: &ProxyPlan,
    node: usize,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<(BwrapArgs, Vec<(OsString, Origin)>), LaunchError> {
    let listen = alloc.listener().map_err(LaunchError::Data)?;
    let ready = alloc.ready_pipe().map_err(LaunchError::Data)?;
    let (program, found) = wayland::locate_proxy(env, host)?;
    let command: Vec<(OsString, Origin)> = plan
        .command_nodes(&program, node, &listen, &ready)
        .into_iter()
        .map(|(arg, node)| (arg, node.map_or(Origin::Command, Origin::Service)))
        .collect();
    let mut args = BwrapArgs::wl_proxy_baseline(&plan.upstream, host);
    // The sidecar has no `seccomp` node of its own: an instance may relax
    // its own filter, never the one around the process holding its
    // connection to the compositor.
    args.tag(Origin::Seccomp);
    if let Some(program) = seccomp::compile(&seccomp::RuleSet::default_set(), env.seccomp_log)? {
        args.add_seccomp(program.bytes, program.arches);
    }
    // Where the binary was found is what says whether it is reachable
    // from in here: the installed one is under the read-only `/usr` this
    // sandbox already has, and bwrap would refuse a destination in there
    // anyway. An override or a build tree's copy is bound in at its own
    // path.
    if found != init_bin::Found::Installed {
        args.tag(Origin::Command);
        args.ro_bind(&program, &program);
    }
    Ok((args, command))
}

/// Where the `network` grant sits in the config, which is what the
/// egress proxy's arguments are attributed to.
fn network_node(services: &[Service]) -> Option<usize> {
    services
        .iter()
        .position(|s| matches!(s, Service::Network(_)))
}

/// Every argument of the egress proxy's argv with what produced it, or
/// `None` when the instance names no `allow-host` and so starts no
/// proxy.
///
/// Not a bwrap argv like the other two sidecars': the proxy runs in the
/// sandbox's own namespaces, which bubbler puts it in directly, so what
/// there is to describe is the program and the arguments it is given.
/// Nothing is started and nothing is created — the descriptor it will
/// report readiness on is named rather than numbered.
pub fn explain_net_proxy(
    env: &Env,
    inst: &Instance,
) -> Result<Option<Vec<Explained>>, LaunchError> {
    let (Some(cfg), Some(node)) = (
        network_of(&inst.config.services).filter(|c| !c.allow_hosts.is_empty()),
        network_node(&inst.config.services),
    ) else {
        return Ok(None);
    };
    // Probed like the sandbox's own argv, which binds this very path: an
    // explanation that named a binary the run could not find would
    // describe a launch that fails.
    let (program, _) = network::net_proxy_program(env, &RealHost)?;
    let mut items = vec![Explained {
        origin: Origin::Command,
        args: vec![OsString::from(network::NET_PROXY_INSIDE)],
        note: Some(format!("bound read-only from {}", program.display())),
    }];
    let argv = network::net_proxy_argv(
        cfg,
        network::ProxyFds {
            ready: OsStr::new("<ready-fd>"),
            log: OsStr::new("2"),
        },
        env.net_proxy_log,
    );
    // One option and its value to a line, which is how the grammar
    // reads and how the launcher builds it. The pairing holds because
    // every option that takes a value comes first and the one bare word,
    // `--log-tunnels`, is appended last: a flag added anywhere else
    // would shift every line after it.
    items.extend(argv.chunks(2).map(|pair| Explained {
        origin: Origin::Service(node),
        args: pair.to_vec(),
        note: None,
    }));
    Ok(Some(items))
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
/// reaches EOF or the child is gone: nothing is listening either way.
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

/// Whether `child` is still a process of this run's, and so still one to
/// signal.
///
/// A sidecar that has already been reaped — by the run's own check, or
/// by a readiness wait giving up on it — is not: that pid names whatever
/// the kernel has handed it to since, and a signal would go to a
/// stranger. `try_wait` answers from the status it cached the first
/// time, so a reaping anywhere in the run is caught here.
fn still_running(child: &mut Child) -> bool {
    !matches!(child.try_wait(), Ok(Some(_)))
}

/// A run's Wayland sidecar: the proxy the application connects to, the
/// socket it accepts on, and, where the compositor took one, the
/// security context it forwards through.
///
/// Dropping the handle stops the proxy and ends the context — the
/// compositor stops accepting when the write end of the close pipe hangs
/// up — so it must outlive the sandbox connecting through the socket.
#[derive(Debug)]
pub struct WaylandHandle {
    /// The proxy sidecar, in its own bwrap.
    child: Child,
    /// Holds the proxy's listening socket and both ends of its ready
    /// pipe; clearing it is what closes them.
    alloc: RealAlloc,
    /// Write end of the pipe handed to the compositor as `close_fd`;
    /// `None` where the compositor offers no security context.
    _close: Option<OwnedFd>,
    /// Removes the socket the application connects to when the run ends.
    _socket: FileGuard,
    /// Removes the socket the compositor accepts on, where there is one.
    _context: Option<FileGuard>,
}

impl Drop for WaylandHandle {
    /// Stop the proxy: SIGTERM, then SIGKILL if it is still there. The
    /// signal goes to bwrap, whose `--die-with-parent` takes the proxy
    /// inside it down with it; nothing else can, since the proxy holds
    /// no pipe of bubbler's it could see hang up.
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

/// Bind the socket this run's application connects to and put
/// `bubbler-wl-proxy` in front of it, so every message the application
/// sends the compositor is decoded and judged before it is forwarded and
/// a clipboard read has to follow input of the user's.
///
/// Where the compositor implements `wp_security_context_v1` the proxy
/// forwards through a second socket registered as a security context for
/// the instance, so the compositor withholds the privileged globals as
/// well; where it does not, the proxy connects to the session's own
/// socket and hides those globals itself. `Ok(None)` only for
/// `wayland "host"`, which asks for the session's socket outright.
///
/// Called before the argv is built, like the D-Bus proxy: the socket has
/// to be there for bwrap to bind. The handle must outlive the sandbox.
///
/// Nothing is connected to before the environment it would be connected
/// through has been checked: wayrs reads `$WAYLAND_DISPLAY` and
/// `$WAYLAND_SOCKET` itself, and both are untrusted host input.
///
/// Marks every descriptor of the calling process above stdio that this
/// spawn is not meant to hand over close-on-exec, so an embedder's own
/// open files do not cross into the sandbox; none is closed.
pub fn start_wayland(
    env: &Env,
    dir: &Path,
    inst: &Instance,
    host: &dyn Host,
) -> Result<Option<WaylandHandle>, LaunchError> {
    let (Some(WaylandMode::Sandboxed { clipboard }), Some(node)) = (
        wayland_mode(&inst.config.services),
        wayland_node(&inst.config.services),
    ) else {
        return Ok(None);
    };
    // The same check the bind makes, made before the connection rather
    // than after it: a display name that is a path would otherwise pick
    // the endpoint this run hands its listening socket to. Both values
    // go through it: the bind takes the name from `env`, and wayrs reads
    // the process environment itself, which nothing here can hand a
    // string of its own.
    let display = service::wayland_display(env)?;
    service::check_wayland_display(std::env::var_os("WAYLAND_DISPLAY").as_deref())?;
    wayland::refuse_inherited(std::env::var_os("WAYLAND_SOCKET").as_deref())?;
    let plan = match wayland::probe()? {
        true => ProxyPlan::context(dir, clipboard),
        false => {
            eprintln!(
                "bubbler: note: wayland: no wp_security_context_manager_v1; \
                 the proxy hides the privileged globals instead"
            );
            // The session's socket is bound into the proxy's sandbox, so
            // it is type-checked like every other bind source.
            // The probe follows symlinks, as the bind does and as
            // `wayland "host"` always has: the name is one component
            // under `$XDG_RUNTIME_DIR`, which is the user's own 0700
            // directory, so whatever could plant a link there is already
            // the user.
            let session = service::require_socket(host, "wayland", env.runtime_dir.join(display))?;
            ProxyPlan::fallback(dir, session, clipboard)
        }
    };
    // The compositor is accepting before the proxy can dial: the context
    // is what makes the connection behind it a sandboxed client's.
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
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let child = Command::new("bwrap")
        .args(&argv)
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    // From here on every exit path stops the proxy through the handle.
    let mut handle = WaylandHandle {
        child,
        alloc,
        _close: close,
        _socket: socket,
        _context: context,
    };
    // bubbler's own copy of the listening socket goes as soon as the
    // proxy has it. Nothing of bubbler's may be able to accept on the
    // sandbox's display socket, and a second holder would also keep the
    // kernel queueing connections in the backlog after the sidecar had
    // died — the application would wait on a socket nothing answers
    // instead of being refused outright.
    handle.alloc.close_listener();
    // What is left is CLOEXEC again before the instance's own bwrap is
    // spawned: the ready pipe belongs to this one spawn and no other.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let WaylandHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no ready pipe was allocated")))?;
    if !wait_ready(ready, child, Instant::now() + PROXY_READY) {
        let what = match child.try_wait() {
            Ok(Some(status)) => format!("it exited ({status})"),
            _ => format!("it did not report a listening socket within {PROXY_READY:?}"),
        };
        return Err(WaylandError::ProxyNotReady(what).into());
    }
    Ok(Some(handle))
}

/// Bind and listen on `path`, removing a socket an earlier run was
/// killed before its guard could.
///
/// Only a missing file is nothing to do: anything else here is this
/// instance's own 0700 directory refusing, which the bind would not
/// survive either.
fn bind_listener(path: &Path) -> Result<UnixListener, LaunchError> {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Err(WaylandError::Listen(path.to_path_buf(), e).into());
    }
    UnixListener::bind(path).map_err(|e| WaylandError::Listen(path.to_path_buf(), e).into())
}

/// Bind the socket the compositor accepts on and register it as a
/// security context for the instance, so a client arriving through it is
/// a sandboxed one. The write end of the close pipe and the guard that
/// removes the socket are the run's to hold: the context lasts exactly
/// as long as they do.
fn bind_context(dir: &Path, instance: &str) -> Result<(OwnedFd, FileGuard), LaunchError> {
    let path = wayland::context_socket_path(dir);
    let listener = bind_listener(&path)?;
    // From here the socket is this run's to remove, however the handshake
    // below goes.
    let guard = FileGuard(path);
    // Close-on-exec on both ends: nothing but this process may hold the
    // write end, or the compositor would keep accepting for as long as
    // whatever inherited it lived.
    let (close_read, close_write) =
        pipe_with(PipeFlags::CLOEXEC).map_err(|e| WaylandError::Pipe(e.into()))?;
    wayland::create_context(
        listener.into(),
        close_read,
        &dbus::app_id(instance),
        &dbus::flatpak_instance_id(instance),
    )?;
    Ok((close_write, guard))
}

/// A run's PipeWire security context: the sidecar that created it and
/// the directory its socket lives in.
///
/// `pw-container` tears the context down when its program exits, so
/// dropping this handle is what ends it, and it must outlive the sandbox
/// that connects through the socket.
#[derive(Debug)]
pub struct PwHandle {
    /// The sidecar sandbox: bwrap, `pw-container` in it, the holder in
    /// that.
    child: Child,
    /// Holds both ends of the pipe the holder reported on; clearing it
    /// is what closes them.
    alloc: RealAlloc,
    /// The instance's context directory, removed once the sidecar has
    /// exited. `pw-container` unlinks the name it chose, which the
    /// holder renamed away, so what is left there is bubbler's.
    dir: PathBuf,
    /// Removes the socket once it has been moved out of `dir`; `None`
    /// until then, when whatever is in there goes with the directory.
    _socket: Option<FileGuard>,
}

impl Drop for PwHandle {
    /// Stop the sidecar: SIGTERM, then SIGKILL if it is still there.
    ///
    /// The signal goes to bwrap and not to `pw-container`: the sidecar
    /// runs with `--new-session`, so it is in no process group of
    /// bubbler's, and `pw-container` ignores SIGTERM until its own
    /// program has exited (measured on 1.6.8). What ends it is bwrap
    /// dying, which takes the pid namespace `pw-container` is pid 1 of
    /// with it.
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
        // The directory is bubbler's own and holds nothing but the
        // context socket; the sandbox that bound it has exited by now.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Create this run's PipeWire security context and wait for its socket,
/// so the socket is there for bwrap to bind. `Ok(None)` where the
/// instance grants no audio at all. The handle must outlive the sandbox.
///
/// Called before the argv is built, like the other sidecars: what the
/// sandbox binds is what this creates, and a bind whose source is not
/// there is a failed start rather than a sandbox without audio.
///
/// Marks every descriptor of the calling process above stdio that this
/// spawn is not meant to hand over close-on-exec, so an embedder's own
/// open files do not cross into the sidecar; none is closed.
pub fn start_pw_context(
    env: &Env,
    dir: &Path,
    inst: &Instance,
    host: &dyn Host,
) -> Result<Option<PwHandle>, LaunchError> {
    let Some(audio) = inst.config.audio() else {
        return Ok(None);
    };
    // The session's own daemon, which nothing but this sidecar reaches.
    // Probed here and not where the sandbox's argv is built: that argv
    // names only the context's socket, and an explanation of it describes
    // a run on a host whose daemon may not be up yet.
    service::require_socket(host, "pipewire", pipewire::host_socket(&env.runtime_dir))?;
    // The sidecar's whole `/tmp`, and the only thing it can write.
    let pw = pipewire::dir(dir);
    mkdir_private(&pw)?;
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
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
    let child = Command::new("bwrap")
        .args(&argv)
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    // From here on every exit path stops the sidecar through the handle.
    let mut handle = PwHandle {
        child,
        alloc,
        dir: pw,
        _socket: None,
    };
    // The instance's own bwrap must not inherit these: a second holder
    // of the report pipe would keep bubbler from seeing it hang up.
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
    let PwHandle { child, alloc, .. } = &mut handle;
    let ready = alloc
        .ready_read
        .as_ref()
        .ok_or_else(|| LaunchError::Data(io::Error::other("no report pipe was allocated")))?;
    // The holder reports the name it renamed the socket to as its own
    // sandbox sees it — that sandbox's `/tmp` is this directory — so the
    // one answer bubbler takes is the name it planned for.
    if read_report(ready, child, Instant::now() + PW_READY).as_deref()
        != Some(pipewire::SOCKET_INSIDE)
    {
        let what = match child.try_wait() {
            Ok(Some(status)) => format!("it exited ({status})"),
            _ => format!(
                "it did not report `{}` within {PW_READY:?}",
                pipewire::SOCKET_INSIDE
            ),
        };
        return Err(LaunchError::PwContext(what));
    }
    handle._socket = Some(adopt_context_socket(dir, env.uid)?);
    Ok(Some(handle))
}

/// The line the holder reports the context socket on, without its
/// newline, or `None` when the deadline passes, the pipe reaches EOF or
/// the sidecar is gone.
///
/// A byte at a time: the line is one short path, and the descriptor stays
/// open afterwards, so a longer read would block on a pipe with nothing
/// more coming.
fn read_report(ready: &OwnedFd, child: &mut Child, deadline: Instant) -> Option<String> {
    let mut line = Vec::new();
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
            Ok(_) => {
                let mut byte = [0u8; 1];
                match rustix::io::read(ready, &mut byte) {
                    Ok(0) => return None,
                    Ok(_) if byte[0] == b'\n' => return String::from_utf8(line).ok(),
                    Ok(_) if line.len() >= PW_REPORT_MAX => return None,
                    Ok(_) => line.push(byte[0]),
                    Err(Errno::INTR) => {}
                    Err(_) => return None,
                }
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            return None;
        }
    }
}

/// Move the context socket out of the one directory the sidecar can
/// write, then prove that what was moved is a socket of this user's.
/// The returned guard removes it when the run ends.
///
/// The context keeps serving after the move: `pw-container` listens on
/// the socket it bound, not on the path, and the sandbox connects
/// through the new one.
// The move comes first and the check second, as [`adopt_proxy_bus`]'s
// does: the reverse leaves a window in which a sidecar that keeps
// swapping the name can put a symlink in the place of the socket that
// was just checked, and bwrap resolves a bind source through links.
// Nothing outside the instance directory can touch the entry once it is
// here, so its type cannot change after this. `O_NOFOLLOW` then makes a
// symlink fail with ELOOP instead of being followed, since `stat`
// through a path would report the type of the target.
fn adopt_context_socket(dir: &Path, uid: u32) -> Result<FileGuard, LaunchError> {
    let from = open_dir(&pipewire::dir(dir))?;
    let to = open_dir(dir)?;
    let path = pipewire::socket(dir);
    rustix::fs::renameat(&from, pipewire::SOCKET_NAME, &to, pipewire::SOCKET_NAME).map_err(
        |e| match e {
            Errno::NOENT => LaunchError::MissingResource {
                service: "pipewire",
                path: pipewire::dir(dir).join(pipewire::SOCKET_NAME),
            },
            e => LaunchError::Io(path.clone(), e.into()),
        },
    )?;
    // Whatever was moved is bubbler's to remove from here on, socket or not.
    let guard = FileGuard(path.clone());
    let wrong_type = |expected| LaunchError::WrongType {
        service: "pipewire",
        path: path.clone(),
        expected,
    };
    let socket = rustix::fs::openat(
        &to,
        pipewire::SOCKET_NAME,
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
            remove_moved_dir(&to, pipewire::SOCKET_NAME, &path);
        }
        return Err(wrong_type("a socket"));
    }
    if stat.st_uid != uid {
        return Err(wrong_type("a socket owned by this user"));
    }
    Ok(guard)
}

/// Start the filtering D-Bus proxy for an instance in its own sandbox and
/// wait for it to report readiness, so the socket exists before the
/// instance's own bwrap binds it. The handle must outlive the sandbox.
///
/// Marks every descriptor of the calling process above stdio that this
/// spawn is not meant to hand over close-on-exec, so an embedder's own
/// open files do not cross into the sandbox; none is closed.
pub fn start_proxy(
    env: &Env,
    dir: &Path,
    plan: &dbus::Plan,
    host: &dyn Host,
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
    // Resolved before the proxy starts, like the other two: the address
    // is what the session says its accessibility bus is, and asking for
    // it after the sandbox is up would be asking on behalf of a bus that
    // is already meant to be serving.
    let a11y_bus = plan
        .a11y
        .as_ref()
        .map(|_| {
            let path = dbus::guarded_host_a11y_bus(host, env)?;
            service::require_socket(host, dbus::A11Y_NODE, path)
        })
        .transpose()?;
    // The proxy gets this directory and nothing else of the instance's
    // runtime state, so it is created here rather than bound from above.
    mkdir_private(&dbus::socket_dir(dir))?;
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
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    spawning(&alloc.intended())?;
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
    handle.alloc.inheritable(false).map_err(LaunchError::Data)?;
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

/// Stop a sandbox that must not run after all, before the pipe it waits
/// on is closed by the failing run unwinding.
///
/// The sandbox process is killed by pid and not only through bwrap:
/// killing bwrap leaves its child where it is, and closing the block pipe
/// on the way out would then let it exec. It is pid 1 of its own pid
/// namespace and ignores signals it has no handler for, but SIGKILL from
/// an ancestor namespace is not among those (`pid_namespaces(7)`).
fn abort_sandbox(child: &mut Child, sandbox: Option<i32>) {
    if let Some(pid) = sandbox.and_then(Pid::from_raw) {
        let _ = kill_process(pid, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// A running pasta sidecar: the sandbox's network namespace is connected
/// to the outside for exactly as long as this handle is alive.
#[derive(Debug)]
struct PastaHandle {
    child: Child,
    /// Set once the run has reaped the sidecar, which is both what makes
    /// the notice below appear once and what stops the pid from being
    /// signalled after it has stopped being pasta's.
    exited: bool,
}

impl PastaHandle {
    /// Say, once, that the sidecar is gone. The sandbox keeps running:
    /// its namespace is simply no longer connected to anything, and
    /// killing an application over a lost network would lose whatever it
    /// has not written out.
    // Through the relay's own warning channel and not `eprintln!`: this
    // runs inside the loop that answers the exit check and the signals,
    // and one blocking write to a terminal that has stopped reading
    // would park that loop for good.
    fn check(&mut self, warn: &tty::Warn) {
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
    /// Stop pasta, and do not return until it is gone. pasta exits by
    /// itself when the namespace it serves does (`pasta(1)`, and bubbler
    /// does not pass `--no-netns-quit`), but a sidecar with a route out of
    /// the host must not be left to a condition bubbler does not control.
    fn drop(&mut self) {
        // A sidecar the run has already reaped is not signalled
        // ([`still_running`]); `exited` is the run's own check having
        // seen it go.
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

/// Whether the namespace `held` names is the one at `path`.
///
/// Compared by the identity of the nsfs file — device and inode — which
/// is what `namespaces(7)` gives as the test for two processes being in
/// the same namespace. Asked of the descriptor the run already holds
/// rather than of `/proc/<pid>/ns/net` a second time: resolving that path
/// again can land on a namespace the descriptor never named, which is the
/// pid reuse this check exists to catch.
fn same_namespace(held: BorrowedFd<'_>, path: &Path) -> Result<bool, LaunchError> {
    let theirs =
        rustix::fs::stat(path).map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))?;
    let ours = rustix::fs::fstat(held).map_err(|e| LaunchError::Data(e.into()))?;
    Ok((ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino))
}

/// `NS_GET_USERNS` as `linux/nsfs.h` defines it, `_IO(0xb7, 0x1)`: it
/// answers with a descriptor for the user namespace that owns the
/// namespace its argument descriptor names (`ioctl_ns(2)`).
const NS_GET_USERNS: Opcode = ioctl::opcode::none(0xb7, 0x1);

/// The `NS_GET_USERNS` call. Neither `NoArg` nor `Getter` describes it:
/// it takes no argument and answers with an open descriptor as its
/// return value, which `NoArg` throws away and `Getter` would read out
/// of a buffer the kernel never writes into.
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

/// The user namespace that owns the network namespace `netns` names.
///
/// Asked of the namespace rather than of a pid: bwrap moves the sandbox
/// into a nested user namespace shortly after reporting `child-pid`, so
/// `/proc/<pid>/ns/user` names whichever namespace the process is in by
/// the time the path is resolved, while the user namespace that owns a
/// network namespace is fixed when the namespace is created
/// (`ioctl_ns(2)`, `namespaces(7)`).
fn owning_userns(netns: BorrowedFd<'_>) -> rustix::io::Result<OwnedFd> {
    // SAFETY: `NsGetUserns` describes what `NS_GET_USERNS` does, and it
    // is made on a descriptor of an nsfs file, which is what `netns` is.
    unsafe { ioctl::ioctl(netns, NsGetUserns) }
}

/// The sandbox's network namespace, and the user namespace that owns it.
/// Both are needed twice — once to install the outbound ruleset, once to
/// hand pasta the namespace it configures — and both must stay open
/// across those spawns, so they are opened once and passed around.
struct SandboxNs {
    /// `/proc/<child-pid>/ns/net`, held open so the pid cannot be reused
    /// out from under the two spawns that follow.
    net: OwnedFd,
    /// The user namespace that owns [`SandboxNs::net`], which is where a
    /// process holds the capabilities to configure it.
    user: OwnedFd,
    /// `/proc/<child-pid>/ns/mnt`, which the egress proxy joins as well:
    /// it resolves names through the sandbox's own `/etc/resolv.conf`
    /// and sees the sandbox's filesystem and no more of the host's.
    /// Owned by the same user namespace as [`SandboxNs::net`], so the
    /// join costs no further capability.
    mnt: OwnedFd,
}

/// Open the sandbox's network namespace and the user namespace that owns
/// it, refusing a pid that is no longer a sandbox of bubbler's.
///
/// The pid comes from bwrap's info document, and a sandbox that died in
/// the meantime leaves it to be handed out again: `nft` and pasta both
/// act on the network namespace of whatever holds the pid *now*, so a
/// pid that is not in a namespace of its own is not the sandbox, and
/// acting on it would mean acting on the host's own network.
fn sandbox_namespaces(child_pid: i32) -> Result<SandboxNs, LaunchError> {
    let net_path = PathBuf::from(format!("/proc/{child_pid}/ns/net"));
    let net = rustix::fs::open(&net_path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| LaunchError::Io(net_path.clone(), e.into()))?;
    if same_namespace(net.as_fd(), Path::new("/proc/self/ns/net"))? {
        return Err(LaunchError::Network(
            "sandbox pid reused; refusing to configure the host network namespace".to_owned(),
        ));
    }
    let user = owning_userns(net.as_fd()).map_err(|e| LaunchError::Io(net_path, e.into()))?;
    let mnt_path = PathBuf::from(format!("/proc/{child_pid}/ns/mnt"));
    let mnt = rustix::fs::open(&mnt_path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| LaunchError::Io(mnt_path, e.into()))?;
    // Checked on its own descriptor and not left to the check above: a
    // pid reused in the window between the two `open`s would give a
    // mount namespace of a stranger's while the network namespace is
    // still the sandbox's, and the proxy would be joined to both.
    if same_namespace(mnt.as_fd(), Path::new("/proc/self/ns/mnt"))? {
        return Err(LaunchError::Network(
            "sandbox pid reused; refusing to join the host mount namespace".to_owned(),
        ));
    }
    Ok(SandboxNs { net, user, mnt })
}

/// Install the `outbound "deny"` ruleset in the sandbox's own network
/// namespace, or do nothing where the config filters nothing.
///
/// Runs before pasta and before the sandbox is let go of its
/// `--block-fd`, so the namespace has a policy before it has a route and
/// the application has not run an instruction either way. A failure here
/// stops the run: a sandbox that asked to be filtered and was not would
/// be a sandbox with a wider network than its config says.
///
/// `nft` is spawned rather than linked: the alternatives pull in either
/// `libnftnl` or `bindgen` for a text format that is stable and one
/// process away. It is handed the ruleset on stdin, and the ruleset is
/// built from typed values in [`network::ruleset`] — a user string
/// reaching this argv would be command injection into a process holding
/// `CAP_NET_ADMIN` over the sandbox's namespaces.
///
/// `cgroup` is the one this run's egress proxy will join, and it must
/// already exist: the rule carries a path but the kernel stores the id
/// it resolves to, so a cgroup made after this would be matched by
/// nothing. A config with an `allow-host` and no cgroup is refused
/// below rather than filtered less than it asked for.
fn install_rules(
    cfg: &NetworkConfig,
    ns: &SandboxNs,
    cgroup: Option<&network::Cgroup>,
) -> Result<(), LaunchError> {
    let Some(text) = network::ruleset(cfg, cgroup) else {
        // Nothing to install where nothing is filtered — and nothing
        // either where the ruleset could not be written, which is a run
        // that asked to be filtered and would have had the whole
        // network.
        if cfg.outbound == network::Outbound::Deny && cfg.is_isolated() {
            return Err(LaunchError::BadValue {
                service: "network",
                reason: "the ruleset an `allow-host` needs is written around the \
                         egress proxy's own cgroup, and none was made for this run"
                    .to_owned(),
            });
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
    // What the exec'd `nft` ends up holding, and why each step is
    // needed. The user namespace is entered first: entering the network
    // namespace takes the capabilities the user namespace grants
    // (`setns(2)`). Capabilities do not survive `execve`, so
    // CAP_NET_ADMIN goes into the inheritable and then the ambient set,
    // which is what carries it across (`capabilities(7)`); without it
    // the exec would depend on what the owning user namespace happens to
    // map this uid to. `SECBIT_NOROOT` then stops the kernel from
    // handing a uid-0 exec the full set on top of that — bwrap's own
    // nested user namespace maps bubbler to 0 — and `_LOCKED` keeps the
    // child from undoing it. `nft` therefore runs with CAP_NET_ADMIN in
    // the sandbox's user namespace and no other capability anywhere.
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
        // Only a `nft` that is really missing gets the message naming the
        // package. A `pre_exec` closure that failed comes back as a spawn
        // failure too, and telling somebody to install what they already
        // have would cost them the actual reason.
        io::ErrorKind::NotFound if on_path(network::NFT_BIN).is_none() => LaunchError::BadValue {
            service: "network",
            reason: format!(
                "`{}` is not on PATH; install the `nftables` package, or drop \
                 `outbound \"deny\"` to leave the sandbox network unfiltered",
                network::NFT_BIN
            ),
        },
        _ => LaunchError::Network(format!("starting `{}`: {e}", network::NFT_BIN)),
    })?;
    let mut stdin = child
        .stdin
        .take()
        .expect("stdin is piped, so the child always has one");
    let written = stdin.write_all(text.as_bytes());
    // Closed before the wait, or `nft` would sit on a read that never
    // ends and the wait below would spend its whole deadline. The write
    // itself is not on a deadline: it is bounded by the pipe buffer, and
    // a ruleset larger than that with an `nft` that reads none of it
    // leaves bubbler waiting — with the sandbox still held at its
    // `--block-fd`, so a hang here is a run that never starts rather than
    // one that starts unfiltered.
    drop(stdin);
    let deadline = Instant::now() + NFT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(e) => return Err(LaunchError::Network(format!("waiting for `nft`: {e}"))),
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
        return Err(LaunchError::Network(format!(
            "`{}` did not install the outbound ruleset within {} seconds",
            network::NFT_BIN,
            NFT_TIMEOUT.as_secs()
        )));
    };
    if !status.success() {
        return Err(LaunchError::Network(format!(
            "`{}` refused the outbound ruleset ({status})",
            network::NFT_BIN
        )));
    }
    written.map_err(|e| LaunchError::Network(format!("writing the outbound ruleset: {e}")))?;
    Ok(())
}

/// Where `bin` is found on `$PATH`, if anywhere.
///
/// Only ever asked on the way to an error message, which is why the
/// library reads the environment here at all: a failed spawn has to be
/// able to tell a package that is not installed from a failure of
/// bubbler's own, and the two arrive as the same `NotFound`.
fn on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        if dir.as_os_str().is_empty() {
            return None;
        }
        let candidate = dir.join(bin);
        rustix::fs::access(&candidate, Access::EXEC_OK)
            .is_ok()
            .then_some(candidate)
    })
}

/// Start pasta on the sandbox's network namespace and wait until it has
/// configured it. `child_pid` is the `child-pid` bwrap reported, and the
/// sandbox must still be held at its `--block-fd`: until this returns the
/// namespace has no route out at all.
///
/// pasta is handed two paths into bubbler's own descriptors rather than
/// paths of its own to open. It makes itself non-dumpable while it starts
/// (`pasta(1)`, self-isolation), and a non-dumpable process cannot open
/// `/proc/self/fd/...`, so the paths name bubbler's process — which is
/// why both descriptors have to stay open across the spawn.
fn start_pasta(
    env: &Env,
    cfg: &NetworkConfig,
    child_pid: i32,
    ns: &SandboxNs,
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
    // pasta's own messages go where bubbler's do, never to the caller's
    // stdout: that is the argv audit trail.
    let log = io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map_err(LaunchError::Data)?;
    // Nothing above stdio here either: pasta opens the two descriptors
    // through bubbler's own `/proc` entry rather than inheriting them, so
    // marking them close-on-exec — which they already are — costs nothing.
    spawning(&[])?;
    let child = Command::new(network::program(env))
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BadValue {
                service: "network",
                reason: format!(
                    "`{}` is not on PATH; install the `passt` package, or write \
                     `network \"host\"` to use the host network namespace",
                    network::PASTA_BIN
                ),
            },
            _ => LaunchError::Spawn(e),
        })?;
    // From here on every exit path stops pasta through the handle.
    let mut handle = PastaHandle {
        child,
        exited: false,
    };
    if !wait_ready(&ready, &mut handle.child, Instant::now() + PASTA_READY) {
        return Err(LaunchError::Network(
            "pasta did not configure the namespace".to_owned(),
        ));
    }
    Ok(handle)
}

/// A run's egress proxy.
///
/// The cgroup it is in belongs to the run and outlives it: a cgroup
/// still holding a process cannot be removed, so the handle is dropped
/// — which stops the proxy — before the cgroup's own guard is.
#[derive(Debug)]
struct NetProxyHandle {
    child: Child,
    /// Set once the run has reaped the sidecar, which is what makes the
    /// notice appear once and stops the pid from being signalled after
    /// it has stopped being the proxy's.
    exited: bool,
}

impl NetProxyHandle {
    /// Say, once, that the proxy is gone. The sandbox keeps running: its
    /// filter is unchanged, so what it loses is the one way out it had,
    /// and killing an application over that would lose whatever it has
    /// not written out.
    fn check(&mut self, warn: &tty::Warn) {
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
    /// Stop the proxy and do not return until it is gone. It also holds
    /// `PR_SET_PDEATHSIG`, but that only covers bubbler dying: a run
    /// that ends normally must not leave a process inside the sandbox's
    /// namespaces, and the cgroup cannot be removed while one is there.
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

/// What an isolated `network` starts once the sandbox has a pid: the
/// ruleset, pasta, and — where the config names an `allow-host` — the
/// egress proxy in its cgroup.
struct NetworkSidecars {
    pasta: PastaHandle,
    proxy: Option<NetProxyHandle>,
}

impl NetworkSidecars {
    /// Check on both sidecars, each of which says once that it is gone.
    fn check(&mut self, warn: &tty::Warn) {
        self.pasta.check(warn);
        if let Some(proxy) = self.proxy.as_mut() {
            proxy.check(warn);
        }
    }
}

/// Give the sandbox's namespace its policy, its route and — for an
/// `allow-host` — its one way out, in that order.
///
/// The order is the whole of the safety here: `cgroup` was made before
/// bwrap was spawned — earlier than the ruleset that names it, and early
/// enough that the sandbox inherited the leaf beside it — the ruleset is
/// installed before pasta connects anything, and the proxy is listening
/// before the caller releases the sandbox from its `--block-fd`. At no
/// point is the sandbox both connected and unfiltered, and at no point
/// can the application reach for a proxy that is not yet answering.
fn start_network(
    env: &Env,
    cfg: &NetworkConfig,
    child_pid: i32,
    cgroup: Option<&cgroup::SandboxCgroup>,
) -> Result<NetworkSidecars, LaunchError> {
    let ns = sandbox_namespaces(child_pid)?;
    install_rules(cfg, &ns, cgroup.map(cgroup::SandboxCgroup::spec))?;
    let pasta = start_pasta(env, cfg, child_pid, &ns)?;
    let proxy = cgroup
        .map(|cgroup| start_net_proxy(cfg, &ns, cgroup, env.net_proxy_log))
        .transpose()?;
    Ok(NetworkSidecars { pasta, proxy })
}

/// Start the egress proxy inside the sandbox's namespaces and wait until
/// it is listening.
///
/// The process bubbler forks holds nothing: it writes itself into the
/// run's cgroup, joins the sandbox's user, network and mount namespaces,
/// clears every capability set and locks `SECBIT_NOROOT`. What lets it
/// out is the cgroup and only the cgroup — the ruleset accepts that and
/// rejects the rest, so a bug in the proxy costs an attacker the names
/// the config listed and no capability at all.
///
/// It is exec'd from [`network::NET_PROXY_INSIDE`], which the sandbox's
/// own argv bound: after the mount join a host path of bubbler's
/// resolves to nothing.
///
/// `log_tunnels` is [`crate::env::Env::net_proxy_log`]: the proxy's
/// lines land on bubbler's stderr, which is the terminal the sandboxed
/// application is drawing on, so only the refusals are written unless
/// the caller asked for the rest.
fn start_net_proxy(
    cfg: &NetworkConfig,
    ns: &SandboxNs,
    cgroup: &cgroup::SandboxCgroup,
    log_tunnels: bool,
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
            // The proxy's audit lines go where bubbler's own do.
            log: OsStr::new("2"),
        },
        log_tunnels,
    );
    let mut cmd = Command::new(network::NET_PROXY_INSIDE);
    cmd.args(&argv)
        // Nothing of the host's environment: the proxy reads none of it,
        // and every variable is one more thing crossing into the
        // sandbox's namespaces.
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
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
    // What the exec'd proxy ends up holding, and why each step is in
    // this order. The pid goes into `cgroup.procs` first, while the
    // process is still bubbler's own uid in bubbler's own namespaces:
    // that is what the ruleset accepts, and doing it after the joins
    // would write through a descriptor from a namespace that no longer
    // matches. The user namespace is entered before the other two,
    // since entering a network or mount namespace takes the
    // capabilities its owning user namespace grants (`setns(2)`); the
    // mount namespace is owned by the same one, so it costs nothing
    // further. `chdir` follows the mount join because the inherited
    // working directory is a host dentry, and a process in the
    // sandbox's mount namespace holding one could walk back out through
    // it. Only then are the capability sets emptied — the joins needed
    // them. `SECBIT_NOROOT` stops the kernel from handing a uid-0
    // `execve` a full set on top of that — bwrap's outer user namespace
    // maps bubbler to 0, so without it the proxy would exec with every
    // capability in the sandbox's user namespace — and `_LOCKED` keeps
    // the child from undoing it. It is set *before* the sets are
    // emptied, since `PR_SET_SECUREBITS` itself takes CAP_SETPCAP:
    // dropping first leaves nothing to set it with. Then the ambient
    // set is cleared and every set emptied, which needs no capability
    // at all. `PR_SET_NO_NEW_PRIVS` then makes the bounding set moot:
    // no `execve` from here can gain a privilege, whatever it finds.
    // Last, the parent-death signal so a bubbler that is killed takes
    // the proxy with it, and `PR_SET_DUMPABLE 0` so nothing of the
    // user's may attach to it.
    unsafe {
        cmd.pre_exec(move || {
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
    // Never `LaunchError::Spawn`, whose text names bwrap: everything the
    // `pre_exec` closure returns — the `cgroup.procs` write, the three
    // `setns`, the `prctl`s — arrives here as a failed spawn too, and a
    // `NotFound` from one of those is not a missing binary either.
    let child = cmd
        .spawn()
        .map_err(|e| LaunchError::Network(format!("starting the egress proxy: {e}")))?;
    // From here on every exit path stops the proxy through the handle.
    let mut handle = NetProxyHandle {
        child,
        exited: false,
    };
    // bubbler's own copy of the write end goes now, so a proxy that dies
    // without writing gives the wait below an EOF instead of a deadline.
    drop(done);
    if !wait_ready(&ready, &mut handle.child, Instant::now() + NET_PROXY_READY) {
        let what = match handle.child.try_wait() {
            Ok(Some(status)) => format!("it exited ({status})"),
            _ => format!("it did not report a listening socket within {NET_PROXY_READY:?}"),
        };
        return Err(LaunchError::Network(format!(
            "the egress proxy did not start: {what}"
        )));
    }
    Ok(handle)
}

/// Put the calling thread on a session keyring of its own
/// (`keyctl(2)` `KEYCTL_JOIN_SESSION_KEYRING` with a null name, which
/// creates an anonymous one).
///
/// Called in the forked child before `execve`, so the sandbox never
/// inherits the login session keyring: `keyctl` is on the default
/// denylist, but a profile may take it off, and the keys behind
/// `@s` are the user's — not this instance's. A kernel without
/// `CONFIG_KEYS` answers ENOSYS and there is no keyring to inherit
/// either, so that one case is not a failure.
///
/// `rustix` wraps no keyring call, which is why this is `libc`.
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

/// `value` as decimal ASCII in `buf`, for the one write the proxy's
/// `pre_exec` makes: formatting through `format!` there would allocate,
/// which a forked child may not do.
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
// `node` is the config node that granted this bus, so a failure names what
// the user would have to change rather than the sidecar that failed.
fn adopt_proxy_bus(dir: &Path, socket: &str, node: &'static str) -> Result<FileGuard, LaunchError> {
    let from = open_dir(&dbus::socket_dir(dir))?;
    let to = open_dir(dir)?;
    let path = dbus::app_bus_path(dir, socket);
    rustix::fs::renameat(&from, socket, &to, socket).map_err(|e| match e {
        Errno::NOENT => LaunchError::MissingResource {
            service: node,
            path: dbus::proxy_bus_path(dir, socket),
        },
        e => LaunchError::Io(path.clone(), e.into()),
    })?;
    // Whatever was moved is bubbler's to remove from here on, socket or not.
    let guard = FileGuard(path.clone());
    let wrong_type = || LaunchError::WrongType {
        service: node,
        path: path.clone(),
        expected: "a socket",
    };
    let bus = rustix::fs::openat(
        &to,
        socket,
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
            remove_moved_dir(&to, socket, &path);
        }
        return Err(wrong_type());
    }
    Ok(guard)
}

/// Remove a directory the proxy planted where its socket belongs. Whatever
/// it holds goes with it: after the move nothing but bubbler can reach it.
fn remove_moved_dir(inst: &OwnedFd, socket: &str, path: &Path) {
    if rustix::fs::unlinkat(inst, socket, AtFlags::REMOVEDIR).is_err() {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// The one directory bubbler owns under `$XDG_RUNTIME_DIR`. Every
/// instance's runtime state is a subdirectory of it, which is why a host
/// bus address that resolves into it is refused.
pub const RUNTIME_SUBDIR: &str = "bubbler";

/// `$XDG_RUNTIME_DIR/bubbler/<name>`: an instance's runtime state on the
/// host. `name` is an instance name the caller has already validated.
pub fn instance_runtime_dir(env: &Env, name: &str) -> PathBuf {
    env.runtime_dir.join(RUNTIME_SUBDIR).join(name)
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
    mkdir_private(&env.runtime_dir.join(RUNTIME_SUBDIR))?;
    let dir = instance_runtime_dir(env, &inst.name);
    mkdir_private(&dir)?;
    Ok(dir)
}

/// Create the host directory behind every `app-runtime` grant and check
/// it is one, so the bind the argv names has a source before bwrap runs.
/// Only bubbler ever creates these, never a sandbox: `app/<id>` is a
/// rendezvous, and whoever creates it decides what the others bind.
///
/// An existing directory is reused whatever its mode — on a host running
/// a native KeePassXC it is already there at 0755, and `$XDG_RUNTIME_DIR`
/// being 0700 is what keeps it private.
///
/// Both levels are opened `O_NOFOLLOW|O_DIRECTORY` and the leaf is made
/// and checked relative to the `app` descriptor, so neither a symlink at
/// `app` nor one at `app/<id>` can move the source somewhere else while
/// the destination path stays the one the config named. No sandbox can
/// plant either — only the leaf is ever bound, so `app` itself is not a
/// directory any sandbox holds — but the check is what makes that
/// property something bubbler enforces rather than assumes.
///
/// The check is point-in-time: bwrap resolves the source path again when
/// it mounts, and the descriptors here are closed rather than handed to
/// it, because bwrap binds by path and has no fd form. That window is
/// not a hole. Nothing a sandbox controls can write `app/`, and a host
/// process that could is already the same uid as bubbler — it owns the
/// account and needs no swapped symlink to reach anything.
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
    let at = open_dir_nofollow(rustix::fs::CWD, &app, &app)?;
    for id in ids {
        let dir = service::app_runtime_dir(env, id);
        // `mkdir` reports EEXIST for a symlink too, since it does not
        // follow the last component, so the probe below is where one is
        // caught.
        match rustix::fs::mkdirat(&at, id, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(LaunchError::Io(dir, e.into())),
        }
        open_dir_nofollow(&at, id, &dir)?;
    }
    Ok(())
}

/// Open `path` under `at` as a directory without following a symlink in
/// its last component. `named` is the whole path, for the error only.
fn open_dir_nofollow<P: rustix::path::Arg>(
    at: impl AsFd,
    path: P,
    named: &Path,
) -> Result<OwnedFd, LaunchError> {
    rustix::fs::openat(
        at,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::NOTDIR => LaunchError::WrongType {
            service: "app-runtime",
            path: named.to_path_buf(),
            expected: "a directory",
        },
        e => LaunchError::Io(named.to_path_buf(), e.into()),
    })
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
/// says it never will. The bytes come back as bwrap wrote them.
// Portals read that same document back out of `bwrapinfo.json`.
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
/// control socket, the proxied bus socket once it has been moved, and the
/// Wayland socket the compositor accepts on.
#[derive(Debug)]
struct FileGuard(PathBuf);

impl Drop for FileGuard {
    fn drop(&mut self) {
        // Nothing to report: a concurrent start may have replaced the
        // socket, and a stale one is detected by connecting to it anyway.
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Removes this run's `$XDG_RUNTIME_DIR/.flatpak/bubbler-<instance>` when
/// the run leaves, on every path — only that entry, and only one this run
/// created: the `.flatpak` directory above it is shared with flatpak.
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

/// What every wait loop watches besides the sandbox process itself: the
/// signal flags, the supervisor a stop is forwarded to, and the sidecar
/// whose own exit the run has to notice.
struct Watch<'a> {
    /// Set by the signal handler; cleared as the run acts on it.
    stop: &'a AtomicBool,
    /// The process inside the sandbox a SIGTERM goes to, if it was found.
    supervisor: Option<Pid>,
    /// Latched once a stop has been seen, for as long as the run lasts.
    stopping: &'a AtomicBool,
    /// The sidecars an isolated `network` started, where the run has
    /// them.
    network: &'a mut Option<NetworkSidecars>,
    /// Where a word about the sidecar goes without blocking the loop.
    warn: &'a tty::Warn,
}

/// Forward a caught signal to the sandbox and report the exit code once
/// bwrap has one. The single place a run learns that it is over, and so
/// the one place the sidecar is checked on as well.
fn check_exit(child: &mut Child, w: &mut Watch<'_>) -> io::Result<Option<i32>> {
    if let Some(status) = child.try_wait()? {
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

/// Wait for a sandbox that has no terminal and no pipes of ours: nothing
/// to move, so the loop only watches for the exit and for signals.
fn wait_plain(child: &mut Child, w: &mut Watch<'_>) -> Result<i32, LaunchError> {
    loop {
        if let Some(code) = check_exit(child, w).map_err(LaunchError::Spawn)? {
            return Ok(code);
        }
        std::thread::sleep(POLL);
    }
}

/// Wait while copying the sandbox's output pipes to bubbler's own stdout
/// and stderr, which is all `tty "none"` needs.
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
        tty::pump(pipes, sink, &mut until, stopping)?
    };
    match failed {
        Some(e) => Err(LaunchError::Spawn(e)),
        None => Ok(code),
    }
}

/// The host side of a relayed run: what the user types, where the pty's
/// output goes, and where that output is drained instead when nothing of
/// bubbler's can take it, or after a detach.
struct RelayEnds<'a> {
    input: Option<BorrowedFd<'a>>,
    output: BorrowedFd<'a>,
    /// What to call `output` when it stops taking the sandbox's output.
    out_name: &'static str,
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
    w: &mut Watch<'_>,
    caught: &tty::Caught<'_>,
    master: BorrowedFd<'_>,
    ends: RelayEnds<'_>,
    raw: &mut Option<RawGuard<'_>>,
) -> Result<i32, LaunchError> {
    let mut failed = None;
    let end = {
        let mut until = until_exit(child, w, &mut failed);
        tty::relay(
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
            // Restored first: the note would otherwise be printed with the
            // terminal still raw, and its newline would not return the
            // cursor to the first column.
            if let Some(guard) = raw.as_mut() {
                guard.restore();
            }
            eprintln!("{}", tty::DETACHED_NOTE);
            let mut until = until_exit(child, w, &mut failed);
            match tty::relay(
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

/// Start the instance: bind its control socket, run bwrap around
/// `bubbler-init`, forward SIGINT/SIGTERM once as SIGTERM and return the
/// exit code to propagate. `mode` decides what the sandbox gets for stdio;
/// in `pty` mode bubbler allocates one and relays, so the sandbox never
/// holds a descriptor for the user's terminal. `AlreadyRunning` when the
/// instance is live; that is an exec, which the caller decides on.
///
/// Marks every descriptor of the calling process above stdio that this
/// spawn is not meant to hand over close-on-exec, so an embedder's own
/// open files do not cross into the sandbox; none is closed.
pub fn run(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    mode: TtyMode,
) -> Result<i32, LaunchError> {
    // Before anything is created: a host tool below its floor is a fact
    // about this run, and the reader has to see it whether or not the
    // run then fails for another reason.
    for line in version::warnings(version::bwrap(), version::proxy(env), &inst.config.services) {
        eprintln!("bubbler: warning: {line}");
    }
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
    let mut alloc = RealAlloc::new(inherited.as_raw_fd(), dir.clone());
    // A run with nothing to run must fail before a sidecar is started.
    resolve_command(inst, command)?;
    // Before the argv is built, so the proxy's socket is there for bwrap
    // to bind: a missing bind source is a failed start, not a warning.
    let plan = dbus::plan(&inst.config.services, &inst.name);
    let portals = plan.as_ref().is_some_and(|p| p.portals);
    let isolated = network_of(&inst.config.services).filter(|c| c.is_isolated());
    let _proxy = match &plan {
        Some(plan) => Some(start_proxy(env, &dir, plan, &RealHost)?),
        None => None,
    };
    // Between the proxy's ready byte and the sandbox's bind each socket
    // is moved where the proxy cannot reach it, and only then checked. The
    // guards stay in scope for the whole run; each removes its socket
    // when it drops.
    let mut buses: Vec<FileGuard> = Vec::new();
    if let Some(plan) = &plan {
        for (socket, node) in plan.buses() {
            buses.push(adopt_proxy_bus(&dir, socket, node)?);
        }
    }
    // Before the argv is built, for the same reason the D-Bus proxy is:
    // the socket the sandbox binds is the one this sidecar accepts on,
    // and a bind of a socket nothing is listening on is a failed start.
    // The handle holds the proxy and the security context open for the
    // whole run. `wayland "host"` asks for the session's socket outright,
    // and without the grant there is nothing to start.
    let _wayland = start_wayland(env, &dir, inst, &RealHost)?;
    // Before the argv is built, for the same reason: the socket an audio
    // grant binds is the one this sidecar's holder creates, and it is
    // the only PipeWire socket the sandbox is given.
    let _pw_context = start_pw_context(env, &dir, inst, &RealHost)?;
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
    // Before the argv is built, for the same reason the proxy is: a bind
    // whose source is not there is a failed start, not a warning.
    prepare_app_runtime(env, &inst.config.services)?;
    // Before bwrap is spawned, and not later: bwrap never changes cgroup,
    // so whatever cgroup it is started in becomes the root of the
    // sandbox's cgroup namespace. This moves bubbler into the run's
    // `sandbox` leaf, so the sandbox inherits it and the proxy's leaf
    // beside it is outside anything the application can name. Dropped
    // after the sidecars below, which is what puts bubbler back and
    // removes the directories.
    let net_cgroup = match isolated.filter(|c| !c.allow_hosts.is_empty()) {
        Some(_) => Some(cgroup::create(&inst.name, std::process::id())?),
        None => None,
    };
    // The operations rather than the flat argv, because the sweep below
    // reads their destinations. Flattened again straight after, so what
    // bwrap is handed is what `build_argv` would have produced.
    let (args, resolved) = build_args_on(env, inst, command, stdio.ctty(), &RealHost)?;
    let ops = args.finish_explained(resolved, &mut alloc)?;
    // Before the spawn and after the argv: a destination behind a link an
    // application planted is a write outside the sandbox on every bwrap
    // below 0.12.0, and the run is refused rather than made safe.
    service::sweep_destinations(&ops, env, &RealHost)?;
    let argv = crate::bwrap::flatten(ops);
    let stop = Arc::new(AtomicBool::new(false));
    // What `stop` becomes once a run has seen it: `stop` is cleared as
    // the signal is acted on, this stays set for the rest of the run.
    let stopping = AtomicBool::new(false);
    let winch = Arc::new(AtomicBool::new(false));
    let mut registered = SignalGuard(Vec::new());
    // SIGHUP among them: a terminal that goes away must still leave
    // through the same path, which stops the sandbox and hands the
    // settings back, rather than killing bubbler where it stands.
    for sig in [SIGINT, SIGTERM, SIGHUP] {
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
    // The sandbox's own fds are inheritable for exactly this spawn: the
    // proxy was started before it and pasta is started after it, and the
    // instance's control socket in particular is neither one's to hold.
    alloc.inheritable(true).map_err(LaunchError::Data)?;
    fcntl_setfd(&inherited, FdFlags::empty()).map_err(io_at)?;
    spawning(&alloc.intended())?;
    let mut cmd = Command::new("bwrap");
    cmd.args(&argv);
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
    alloc.inheritable(false).map_err(LaunchError::Data)?;
    // The sandbox holds the listening socket and the info pipe now; bubbler
    // keeping copies would make a dead instance look live and hide the EOF.
    // Each number is given up with its descriptor, so nothing a later
    // sweep is asked to spare is a number that has since been recycled.
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
    // pasta before the release, and before the supervisor is looked for:
    // a sandbox held at `--block-fd` has not forked the supervisor yet,
    // and one let go before its namespace is connected would start with
    // no network at all. A sandbox that cannot be connected is stopped
    // where it stands rather than run without what it was granted.
    let mut network = match isolated {
        Some(cfg) => {
            let started = match info.as_ref() {
                Some((child_pid, _)) => start_network(env, cfg, *child_pid, net_cgroup.as_ref()),
                None => Err(LaunchError::Network(
                    "bwrap reported no sandbox pid for pasta to attach to".to_owned(),
                )),
            };
            match started {
                Ok(handle) => Some(handle),
                Err(e) => {
                    abort_sandbox(&mut child, info.as_ref().map(|(pid, _)| *pid));
                    return Err(e);
                }
            }
        }
        None => None,
    };
    if portals || isolated.is_some() {
        release_block(&mut alloc);
    }
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
    let caught = tty::Caught {
        winch: &winch,
        stop: &stopping,
    };
    let warn = tty::Warn::new();
    let mut watch = Watch {
        stop: &stop,
        supervisor,
        stopping: &stopping,
        network: &mut network,
        warn: &warn,
    };
    let code = match &master {
        Some(master) => {
            let out = tty::output_fd(&stdio, &host);
            // With nothing of the user's able to take the output it goes
            // to the sink, which never refuses it, so the name is never
            // printed.
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
    }?;
    // After the wait and not before it: the generated files are the live
    // sources of the sandbox's read-only binds, and dropping the
    // allocator unlinks them.
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

    /// A dry run's allocator pointed where a real run of the instance
    /// [`inst`] builds would write its generated files, so an argv built
    /// here and one built by the launcher itself name the same paths.
    fn dry(e: &Env) -> DryRunAlloc {
        DryRunAlloc::new(instance_runtime_dir(e, "t"))
    }

    /// The directory a real allocator gets in a test that allocates
    /// descriptors and no generated file: one that is not there, so a
    /// call to [`FdAllocator::file`] would fail rather than write
    /// somewhere real.
    fn no_data_dir() -> PathBuf {
        PathBuf::from("/nonexistent/bubbler")
    }

    /// An `Env` whose `$BUBBLER_INIT` points at a stand-in binary, so
    /// argv building does not depend on where the test binary lives.
    fn env(tmp: &Path) -> Env {
        let init = tmp.join("bubbler-init");
        std::fs::write(&init, b"").unwrap();
        Env {
            home: tmp.join("home"),
            data_home: tmp.join("data"),
            config_home: tmp.join("config"),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: tmp.join("run"),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: Some(init),
            dbus_address: None,
            dbus_system_address: None,
            at_spi_bus_address: None,
            dbus_log: false,
            net_proxy_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
        }
    }

    fn inst(tmp: &Path, kdl: &str) -> Instance {
        Instance {
            name: "t".into(),
            dir: tmp.join("data/bubbler/instances/t"),
            config: crate::config::parse(kdl).unwrap(),
            config_version: Some(crate::instance::CONFIG_VERSION),
        }
    }

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    /// A host holding the stand-in supervisor binary and everything
    /// `gamepad hidraw=#true uinput=#true` looks for, so a device grant
    /// can be checked without the machine the tests run on having one.
    fn device_host(tmp: &Path) -> crate::host::fake::FakeHost {
        let (file, dir, _) = crate::host::fake::types();
        let mut host = crate::host::fake::FakeHost::default()
            .with(&tmp.join("bubbler-init").display().to_string(), file);
        for p in [
            "/dev/input",
            "/sys/class/input",
            "/sys/devices",
            "/sys/class/hidraw",
        ] {
            host = host.with(p, dir);
        }
        for p in ["/dev/hidraw0", "/dev/uinput"] {
            host = host.with(p, crate::host::fake::char_type());
        }
        host
    }

    fn device_argv(tmp: &Path, e: &Env, kdl: &str) -> Vec<String> {
        let argv = build_argv_on(
            e,
            &inst(tmp, kdl),
            None,
            &mut dry(e),
            false,
            &device_host(tmp),
        )
        .unwrap();
        strs(&argv)
    }

    /// A host with everything the origin tests grant: the stand-in
    /// supervisor, a home to share and `/etc/resolv.conf` for `network`.
    fn share_host(tmp: &Path) -> crate::host::fake::FakeHost {
        let (file, dir, _) = crate::host::fake::types();
        crate::host::fake::FakeHost::default()
            .with(&tmp.join("bubbler-init").display().to_string(), file)
            .with(&tmp.join("home").display().to_string(), dir)
            .with(&tmp.join("home/Downloads").display().to_string(), dir)
            .with("/etc/resolv.conf", file)
    }

    fn explained(tmp: &Path, e: &Env, kdl: &str) -> Vec<Explained> {
        explain_on(e, &inst(tmp, kdl), None, false, &share_host(tmp)).unwrap()
    }

    /// The one line each origin owns, for an assertion that reads like the
    /// output does.
    fn line(items: &[Explained], origin: Origin) -> String {
        strs(
            &items
                .iter()
                .filter(|i| i.origin == origin)
                .flat_map(|i| i.args.clone())
                .collect::<Vec<_>>(),
        )
        .join(" ")
    }

    #[test]
    fn an_explanation_flattens_back_to_the_argv_it_explains() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let kdl = "dbus\nportals\nnotify\nhome-share \"Downloads\"\nuserns \"disable\"\n\
                   env FOO=\"bar\"\ncommand \"true\"";
        let items = explained(tmp.path(), &e, kdl);
        let flat: Vec<OsString> = items.iter().flat_map(|i| i.args.clone()).collect();
        let argv = build_argv_on(
            &e,
            &inst(tmp.path(), kdl),
            None,
            &mut dry(&e),
            false,
            &share_host(tmp.path()),
        )
        .unwrap();
        assert_eq!(flat, argv);
    }

    #[test]
    fn every_argument_is_attributed_to_the_node_that_asked_for_it() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(
            tmp.path(),
            &e,
            "dbus\nportals\nnotify\nhome-share \"Downloads\"\nuserns \"disable\"\n\
             env FOO=\"bar\"\ncommand \"true\"",
        );
        let run = tmp.path().join("run");
        assert_eq!(
            line(&items, Origin::Service(0)),
            format!(
                "--ro-bind {run}/bubbler/t/bus {run}/bus \
                 --setenv DBUS_SESSION_BUS_ADDRESS unix:path={run}/bus",
                run = run.display()
            )
        );
        // The wait for the identity document belongs to the `portals`
        // node, next to the file that identity is written from — and so
        // does the `flatpak-spawn` shim that identity file calls for.
        assert_eq!(
            line(&items, Origin::Service(1)),
            format!(
                "--block-fd 4 --ro-bind {run}/bubbler/t/.flatpak-info /.flatpak-info \
                 --overlay-src /usr/bin --tmp-overlay /usr/bin \
                 --ro-bind {init} /usr/bin/flatpak-spawn --remount-ro /usr/bin",
                run = run.display(),
                init = tmp.path().join("bubbler-init").display()
            )
        );
        // `notify` is a rule for the proxy and nothing for bwrap.
        assert_eq!(line(&items, Origin::Service(2)), "");
        assert_eq!(
            line(&items, Origin::Service(3)),
            format!(
                "--ro-bind {home}/Downloads /home/bubbler/Downloads",
                home = tmp.path().join("home").display()
            )
        );
        assert_eq!(
            line(&items, Origin::Userns),
            "--unshare-user --disable-userns"
        );
        assert_eq!(line(&items, Origin::Seccomp), "--add-seccomp-fd 5");
        assert_eq!(line(&items, Origin::Env(0)), "--setenv FOO bar");
        assert_eq!(
            line(&items, Origin::Init),
            format!(
                "--ro-bind {init} /run/bubbler-init -- /run/bubbler-init --socket-fd 6",
                init = tmp.path().join("bubbler-init").display()
            )
        );
        assert_eq!(line(&items, Origin::Command), "-- true");
        // Nothing else is left over: what is not a grant is the baseline.
        let untagged: Vec<&Explained> = items
            .iter()
            .filter(|i| {
                !matches!(
                    i.origin,
                    Origin::Baseline
                        | Origin::Seccomp
                        | Origin::Userns
                        | Origin::Service(_)
                        | Origin::Env(_)
                        | Origin::Init
                        | Origin::Command
                )
            })
            .collect();
        assert!(untagged.is_empty(), "{untagged:?}");
    }

    /// The node replaces the value in place: one `--tmpfs /tmp`, still
    /// ahead of everything mounted under it, and the operation now
    /// belongs to the node that asked for it rather than to the baseline.
    #[test]
    fn a_tmp_node_replaces_the_cap_and_owns_the_operation() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(tmp.path(), &e, "tmp size=\"64M\"\ncommand \"true\"");
        assert_eq!(line(&items, Origin::Tmp), "--size 67108864 --tmpfs /tmp");
        let flat = strs(
            &items
                .iter()
                .flat_map(|i| i.args.clone())
                .collect::<Vec<_>>(),
        );
        assert_eq!(flat.iter().filter(|a| *a == "/tmp").count(), 1, "{flat:?}");
        assert!(!flat.contains(&"2147483648".to_owned()), "{flat:?}");

        // Without the node the baseline keeps both the cap and the
        // operation.
        let items = explained(tmp.path(), &e, "command \"true\"");
        assert_eq!(line(&items, Origin::Tmp), "");
        assert!(
            strs(
                &items
                    .iter()
                    .flat_map(|i| i.args.clone())
                    .collect::<Vec<_>>()
            )
            .contains(&"2147483648".to_owned())
        );

        // And the explanation heads a group with the node as written.
        let cfg = crate::config::parse("tmp size=\"64M\"\ncommand \"true\"").unwrap();
        let items = explained(tmp.path(), &e, "tmp size=\"64M\"\ncommand \"true\"");
        let out = crate::explain::render(
            &items,
            &crate::explain::View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: crate::explain::Source {
                    file: "config.kdl",
                    lines: &crate::config::Lines::default(),
                },
                rules: &[],
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert!(
            out.iter().any(|l| l.starts_with("  tmp size=\"64M\"")),
            "{out:?}"
        );
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
            let err = start_wayland(&e, &dir, &app, &RealHost).expect_err(bad);
            assert!(
                matches!(
                    err,
                    LaunchError::BadValue {
                        service: "wayland",
                        ..
                    }
                ),
                "{bad}: {err:?}"
            );
        }
        e.wayland_display = None;
        assert!(matches!(
            start_wayland(&e, &dir, &app, &RealHost),
            Err(LaunchError::MissingEnv {
                service: "wayland",
                var: "WAYLAND_DISPLAY"
            })
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
                start_wayland(&e, &dir, &app, &RealHost).unwrap().is_none(),
                "{kdl}"
            );
        }
        assert!(!wayland::socket_path(&dir).exists());
    }

    /// A grant that finds nothing to bind on this host contributes no
    /// argument, and is still a group of the explanation rather than
    /// missing from it.
    #[test]
    fn a_grant_that_binds_nothing_here_is_still_explained() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        // `share_host` holds no `/dev/hidraw*` and no `/sys/class/hidraw`.
        let kdl = "hidraw\ncommand \"true\"";
        let items = explained(tmp.path(), &e, kdl);
        assert_eq!(line(&items, Origin::Service(0)), "");
        let cfg = crate::config::parse(kdl).unwrap();
        let lines = crate::config::node_lines(kdl).unwrap();
        let out = crate::explain::render(
            &items,
            &crate::explain::View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: crate::explain::Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert!(
            out.iter()
                .any(|l| l.starts_with("  hidraw ") && l.ends_with("0 arguments")),
            "{out:?}"
        );
    }

    /// `--share-net` is inserted into phase 1, far from the bind the same
    /// node contributes, and must still be attributed to that node.
    #[test]
    fn the_network_node_owns_the_share_net_it_inserts_into_phase_one() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(
            tmp.path(),
            &e,
            "home-share \"Downloads\"\nnetwork \"host\"\ncommand \"true\"",
        );
        assert_eq!(
            line(&items, Origin::Service(1)),
            "--share-net --ro-bind /etc/resolv.conf /etc/resolv.conf"
        );
        let first = items.first().expect("the argv is never empty");
        assert_eq!(first.origin, Origin::Baseline);
        assert_eq!(first.args, [OsString::from("--unshare-all")]);
    }

    #[test]
    fn a_generated_fd_or_file_says_what_is_behind_it() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(tmp.path(), &e, "command \"true\"");
        let note = |flag: &str| {
            items
                .iter()
                .find(|i| i.args[0] == flag)
                .and_then(|i| i.note.clone())
                .unwrap_or_else(|| panic!("no {flag} in {items:?}"))
        };
        assert_eq!(
            note("--info-fd"),
            "pipe: bwrap reports the sandbox pid on it"
        );
        assert!(
            note("--add-seccomp-fd").starts_with("filter, "),
            "{items:?}"
        );
        let generated = items
            .iter()
            .find_map(|i| i.note.clone().filter(|n| n.starts_with("generated file")));
        assert_eq!(generated.as_deref(), Some("generated file, 88 bytes"));
        assert_eq!(note("--"), "socket: the exec channel bubbler-init serves");
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
    fn the_userns_node_reaches_the_namespace_phase() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plain = device_argv(tmp.path(), &e, "command \"x\"");
        assert!(!plain.iter().any(|a| a == "--unshare-user"), "{plain:?}");
        assert!(!plain.iter().any(|a| a == "--disable-userns"), "{plain:?}");

        let a = device_argv(tmp.path(), &e, "userns \"disable\"\ncommand \"x\"");
        let at = a
            .iter()
            .position(|s| s == "--unshare-user")
            .unwrap_or_else(|| panic!("{a:?}"));
        assert_eq!(a[at + 1], "--disable-userns", "{a:?}");
        // Phase 1: ahead of the filesystem skeleton the baseline lays down.
        let skeleton = a
            .iter()
            .position(|s| s == "--ro-bind")
            .unwrap_or_else(|| panic!("{a:?}"));
        assert!(at < skeleton, "{a:?}");
    }

    #[test]
    fn gamepad_device_properties_reach_the_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let bare = device_argv(tmp.path(), &e, "gamepad\ncommand \"x\"");
        assert!(!bare.iter().any(|a| a.contains("hidraw")), "{bare:?}");
        assert!(!bare.iter().any(|a| a.contains("uinput")), "{bare:?}");

        let a = device_argv(
            tmp.path(),
            &e,
            "gamepad hidraw=#true uinput=#true\ncommand \"x\"",
        );
        let has = |seq: &[&str]| a.windows(seq.len()).any(|w| w == seq);
        // The nodes are enumerated as the argv is built, so they are
        // bound with the `-try` form; `/dev/uinput` was asked for by name.
        assert!(
            has(&["--dev-bind-try", "/dev/hidraw0", "/dev/hidraw0"]),
            "{a:?}"
        );
        assert!(
            has(&["--ro-bind", "/sys/class/hidraw", "/sys/class/hidraw"]),
            "{a:?}"
        );
        assert!(has(&["--dev-bind", "/dev/uinput", "/dev/uinput"]), "{a:?}");
    }

    #[test]
    fn argv_uses_config_command_unless_overridden() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\" \"-e\" \"fish\"");
        let a = build_argv(&e, &i, None, &mut dry(&e), false).unwrap();
        assert_eq!(
            &a[a.len() - 4..],
            &[
                OsString::from("--"),
                "foot".into(),
                "-e".into(),
                "fish".into()
            ]
        );
        let a = build_argv(&e, &i, Some(&[OsString::from("ls")]), &mut dry(&e), false).unwrap();
        assert_eq!(&a[a.len() - 2..], &[OsString::from("--"), "ls".into()]);
    }

    #[test]
    fn the_init_binary_is_bound_and_wraps_the_command() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        let init = tmp.path().join("bubbler-init").display().to_string();
        assert!(
            a.windows(3)
                .any(|w| w == ["--ro-bind", init.as_str(), INIT_INSIDE])
        );
        // Fd 3 went to the info pipe, 4 to the seccomp filter; passwd
        // and group are files.
        assert_eq!(
            &a[a.len() - 6..],
            &["--", INIT_INSIDE, "--socket-fd", "5", "--", "foot"]
        );
    }

    #[test]
    fn a_missing_init_binary_is_a_missing_resource() {
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.init_override = Some(tmp.path().join("gone"));
        let i = inst(tmp.path(), "command \"foot\"");
        assert!(matches!(
            build_argv(&e, &i, None, &mut dry(&e), false),
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
        let a = build_argv(&e, &i, None, &mut dry(&e), false).unwrap();
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
            build_argv(&e, &i, None, &mut dry(&e), false),
            Err(LaunchError::Config(ConfigError::MissingCommand))
        ));
        assert!(matches!(
            build_argv(&e, &i, Some(&[]), &mut dry(&e), false),
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
            Err(LaunchError::WrongType {
                service: "app-runtime",
                ..
            })
        ));
        std::fs::remove_file(tmp.path().join("run/app/org.example.App")).unwrap();
        std::fs::write(tmp.path().join("run/app/org.example.App"), b"").unwrap();
        assert!(matches!(
            prepare_app_runtime(&e, &svcs),
            Err(LaunchError::WrongType {
                service: "app-runtime",
                ..
            })
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
            Err(LaunchError::WrongType {
                service: "app-runtime",
                ..
            })
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
            Err(LaunchError::WrongType {
                service: "app-runtime",
                ..
            })
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
        };
        let started = Instant::now();
        drop(handle);
        assert!(started.elapsed() < POLL, "the drop waited on a reaped pid");
        assert!(!socket.exists(), "the socket outlived the run");
    }

    /// Pinned: the sandbox the Wayland proxy runs in and the argv it is
    /// run with are the contract with `bubbler-wl-proxy`. Nothing of the
    /// session is in here but the socket it forwards to — the socket it
    /// accepts on arrives as descriptor 3 and is bound nowhere.
    #[test]
    fn wl_proxy_argv_runs_the_proxy_in_its_own_sandbox() {
        use crate::config::Clipboard;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = Path::new("/run/user/1000/bubbler/t");
        let plan = ProxyPlan::context(dir, Clipboard::Paste);
        // A host holding the packaged proxy and nothing else, so this is
        // the installed layout's argv and not this build tree's.
        let (file, _, _) = crate::host::fake::types();
        let host = FakeHost::default().with(wayland::PROXY_BIN, file);
        let argv = wl_proxy_argv(&e, &plan, 0, &host, &mut dry(&e)).unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--add-seccomp-fd",
                "5",
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
                "--size",
                "67108864",
                "--tmpfs",
                "/etc",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                "67108864",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/run/user/1000/bubbler/t/wayland-context",
                "/run/user/1000/bubbler/t/wayland-context",
                "--clearenv",
                "--",
                "/usr/lib/bubbler/bubbler-wl-proxy",
                "--listen-fd",
                "3",
                "--upstream",
                "/run/user/1000/bubbler/t/wayland-context",
                "--gate",
                "paste",
                "--log-fd",
                "2",
                "--ready-fd",
                "4",
            ]
        );
    }

    /// Without a security context the proxy is pointed at the session's
    /// own socket — the only one it can then reach — and told to hide
    /// the privileged globals itself. `clipboard="open"` is the gate.
    #[test]
    fn the_fallback_proxy_dials_the_session_socket_and_denies() {
        use crate::config::Clipboard;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = Path::new("/run/user/1000/bubbler/t");
        let plan = ProxyPlan::fallback(dir, "/run/user/1000/wayland-1".into(), Clipboard::Open);
        let (file, _, _) = crate::host::fake::types();
        let host = FakeHost::default().with(wayland::PROXY_BIN, file);
        let argv = strs(&wl_proxy_argv(&e, &plan, 0, &host, &mut dry(&e)).unwrap());
        let tail: Vec<&str> = argv
            .iter()
            .skip_while(|a| *a != "--")
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            [
                "--",
                "/usr/lib/bubbler/bubbler-wl-proxy",
                "--listen-fd",
                "3",
                "--upstream",
                "/run/user/1000/wayland-1",
                "--gate",
                "open",
                "--fallback-deny",
                "--log-fd",
                "2",
                "--ready-fd",
                "4",
            ]
        );
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/wayland-1",
                    "/run/user/1000/wayland-1"
                ]),
            "{argv:?}"
        );
        // The security-context socket is never bound: there is none.
        assert!(
            !argv.iter().any(|a| a.ends_with("wayland-context")),
            "{argv:?}"
        );
    }

    /// An overriding binary is not under the `/usr` the sidecar has, so
    /// it is bound in at its own path, and a name that is not a file is
    /// refused rather than handed to bwrap.
    #[test]
    fn an_overridden_proxy_binary_is_bound_into_its_own_sandbox() {
        use crate::config::Clipboard;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.wl_proxy_override = Some("/build/bubbler-wl-proxy".into());
        let plan = ProxyPlan::context(Path::new("/run/user/1000/bubbler/t"), Clipboard::Paste);
        let (file, _, _) = crate::host::fake::types();
        let host = FakeHost::default().with("/build/bubbler-wl-proxy", file);
        let argv = strs(&wl_proxy_argv(&e, &plan, 0, &host, &mut dry(&e)).unwrap());
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/build/bubbler-wl-proxy",
                    "/build/bubbler-wl-proxy"
                ]),
            "{argv:?}"
        );
        assert!(argv.contains(&"/build/bubbler-wl-proxy".to_owned()));
        assert!(matches!(
            wl_proxy_argv(&e, &plan, 0, &FakeHost::default(), &mut dry(&e)),
            Err(LaunchError::MissingResource {
                service: "wayland",
                ..
            })
        ));
    }

    #[test]
    fn pw_context_argv_runs_pw_container_in_its_own_sandbox() {
        use crate::config::AudioSet;
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let (file, _, _) = types();
        let host =
            FakeHost::default().with(&tmp.path().join("bubbler-init").display().to_string(), file);
        let dir = instance_runtime_dir(&e, "t");
        let ctx = pipewire::Context {
            instance_runtime: &dir,
            instance: "t",
            run_id: "4711",
            audio: AudioSet { microphone: false },
        };
        let argv =
            pw_context_argv(&e, &ctx, &host, &mut DryRunAlloc::sidecar(dir.clone())).unwrap();
        let run = e.runtime_dir.display().to_string();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all".to_owned(),
                "--die-with-parent".to_owned(),
                "--new-session".to_owned(),
                "--add-seccomp-fd".to_owned(),
                "4".to_owned(),
                "--ro-bind".to_owned(),
                "/usr".to_owned(),
                "/usr".to_owned(),
                "--symlink".to_owned(),
                "usr/bin".to_owned(),
                "/bin".to_owned(),
                "--symlink".to_owned(),
                "usr/lib".to_owned(),
                "/lib".to_owned(),
                "--symlink".to_owned(),
                "usr/lib64".to_owned(),
                "/lib64".to_owned(),
                "--symlink".to_owned(),
                "usr/bin".to_owned(),
                "/sbin".to_owned(),
                "--size".to_owned(),
                "67108864".to_owned(),
                "--tmpfs".to_owned(),
                "/etc".to_owned(),
                "--proc".to_owned(),
                "/proc".to_owned(),
                "--dev".to_owned(),
                "/dev".to_owned(),
                "--size".to_owned(),
                "67108864".to_owned(),
                "--tmpfs".to_owned(),
                "/tmp".to_owned(),
                "--ro-bind".to_owned(),
                format!("{run}/pipewire-0"),
                format!("{run}/pipewire-0"),
                "--bind".to_owned(),
                format!("{run}/bubbler/t/pw"),
                "/tmp".to_owned(),
                "--ro-bind".to_owned(),
                tmp.path().join("bubbler-init").display().to_string(),
                "/run/bubbler-pw-hold".to_owned(),
                "--clearenv".to_owned(),
                "--setenv".to_owned(),
                "XDG_RUNTIME_DIR".to_owned(),
                run.clone(),
                "--setenv".to_owned(),
                "BUBBLER_PW_REPORT_FD".to_owned(),
                "3".to_owned(),
                "--".to_owned(),
                "/usr/bin/pw-container".to_owned(),
                "-P".to_owned(),
                r#"{"pipewire.sec.engine":"org.bubbler","pipewire.sec.app-id":"t","pipewire.sec.instance-id":"4711","pipewire.access":"restricted","bubbler.audio":"playback"}"#.to_owned(),
                "--".to_owned(),
                "/run/bubbler-pw-hold".to_owned(),
            ]
        );
    }

    /// The grant set is the one thing about the sidecar that a config
    /// changes, and it reaches the daemon as a context property.
    #[test]
    fn a_microphone_grant_says_so_in_the_context_properties() {
        use crate::config::AudioSet;
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let (file, _, _) = types();
        let host =
            FakeHost::default().with(&tmp.path().join("bubbler-init").display().to_string(), file);
        let dir = instance_runtime_dir(&e, "t");
        let ctx = pipewire::Context {
            instance_runtime: &dir,
            instance: "t",
            run_id: "4711",
            audio: AudioSet { microphone: true },
        };
        let mut alloc = DryRunAlloc::sidecar(dir.clone());
        let argv = strs(&pw_context_argv(&e, &ctx, &host, &mut alloc).unwrap());
        assert!(
            argv.iter()
                .any(|a| a.contains(r#""bubbler.audio":"playback,microphone""#)),
            "{argv:?}"
        );
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
            dbus::HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: None,
                a11y: None,
            },
            Path::new("/run/user/1000/bubbler/t"),
            &FakeHost::default(),
            &mut DryRunAlloc::sidecar(PathBuf::from("/run/user/1000/bubbler/t")),
        )
        .unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--add-seccomp-fd",
                "4",
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
                "--size",
                "67108864",
                "--tmpfs",
                "/etc",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                "67108864",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/run/user/1000/bus",
                "/run/user/1000/bus",
                "--bind",
                "/run/user/1000/bubbler/t/dbus",
                "/run/user/1000/bubbler/t/dbus",
                "--ro-bind",
                "/run/user/1000/bubbler/t/proxy-.flatpak-info",
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
    fn a_system_bus_proxy_sees_that_socket_and_no_session_one() {
        use crate::config::{BusRule, Service};
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(
            &[Service::SystemBus {
                rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
            }],
            "t",
        )
        .expect("system-bus is granted");
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: None,
                    system: Some(Path::new(dbus::SYSTEM_BUS_PATH)),
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            )
            .unwrap(),
        );
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/dbus/system_bus_socket",
                    "/run/dbus/system_bus_socket",
                ]),
            "{argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "/run/user/1000/bus"),
            "the proxy reaches a session bus nothing granted: {argv:?}"
        );
        assert_eq!(
            &argv[argv.len() - 6..],
            &[
                "xdg-dbus-proxy",
                "--fd=3",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--talk=org.freedesktop.UPower",
            ]
        );
    }

    #[test]
    fn both_buses_run_in_one_proxy_sandbox() {
        use crate::config::{BusRule, Service};
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
                },
            ],
            "t",
        )
        .expect("both buses are granted");
        assert_eq!(
            plan.buses(),
            vec![
                (dbus::SESSION_SOCKET, dbus::SESSION_NODE),
                (dbus::SYSTEM_SOCKET, dbus::SYSTEM_NODE)
            ]
        );
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: Some(Path::new(dbus::SYSTEM_BUS_PATH)),
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            )
            .unwrap(),
        );
        // One sandbox, one process, two addresses: the second pair's
        // options apply to it alone (`xdg-dbus-proxy(1)`).
        assert_eq!(
            argv.iter().filter(|a| *a == "xdg-dbus-proxy").count(),
            1,
            "{argv:?}"
        );
        assert_eq!(
            &argv[argv.len() - 9..],
            &[
                "xdg-dbus-proxy",
                "--fd=3",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--talk=org.freedesktop.UPower",
            ]
        );
        // Still the one writable path, whatever the bus count.
        assert_eq!(
            argv.iter().filter(|a| *a == "--bind").count(),
            1,
            "{argv:?}"
        );
    }

    /// The third bus of the one sidecar: its host socket in the proxy's
    /// sandbox, its address in the proxy's command, and the nine rules
    /// behind the `--filter` of that address.
    #[test]
    fn the_a11y_bus_is_the_third_bus_of_the_one_proxy() {
        use crate::config::{BusRule, Service};
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
                },
                Service::A11y,
            ],
            "t",
        )
        .expect("three buses are granted");
        assert_eq!(
            plan.buses(),
            vec![
                (dbus::SESSION_SOCKET, dbus::SESSION_NODE),
                (dbus::SYSTEM_SOCKET, dbus::SYSTEM_NODE),
                (dbus::A11Y_SOCKET, dbus::A11Y_NODE),
            ]
        );
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: Some(Path::new(dbus::SYSTEM_BUS_PATH)),
                    a11y: Some(Path::new("/run/user/1000/at-spi/bus_0")),
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            )
            .unwrap(),
        );
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/at-spi/bus_0",
                    "/run/user/1000/at-spi/bus_0",
                ]),
            "{argv:?}"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == "xdg-dbus-proxy").count(),
            1,
            "{argv:?}"
        );
        let mut expected = vec![
            "unix:path=/run/user/1000/at-spi/bus_0",
            "/run/user/1000/bubbler/t/dbus/a11y",
            "--filter",
        ];
        expected.extend_from_slice(dbus::A11Y_RULES);
        assert_eq!(&argv[argv.len() - expected.len()..], expected, "{argv:?}");
        // Still the one writable path, whatever the bus count.
        assert_eq!(
            argv.iter().filter(|a| *a == "--bind").count(),
            1,
            "{argv:?}"
        );
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
                start_proxy(&e, &dir, &plan, &host).map(|_| ()),
                explain_proxy(&e, &cfg).map(|_| ()),
            ] {
                match got {
                    Err(LaunchError::BadValue { service, reason }) => {
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
                start_proxy(&e, &dir, &plan, &host).map(|_| ()),
                explain_proxy(&e, &cfg).map(|_| ()),
            ] {
                assert!(
                    matches!(
                        got,
                        Err(LaunchError::BadValue {
                            service: "dbus",
                            ..
                        })
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

    /// The egress proxy's traffic log is off unless the variable asked
    /// for it, and the explanation shows the argv a run would use: a
    /// flag printed here and not passed there, or the other way round,
    /// would be an explanation of a different process.
    #[test]
    fn the_net_proxy_is_explained_with_the_traffic_log_only_when_asked() {
        let tmp = tempfile::tempdir().unwrap();
        let proxy = tmp.path().join("bubbler-net-proxy");
        std::fs::write(&proxy, b"").unwrap();
        let inst = inst(
            tmp.path(),
            "network {\n    outbound \"deny\"\n    allow-host \"api.example\"\n}\n",
        );
        let words = |log: bool| {
            let mut e = env(tmp.path());
            e.net_proxy_override = Some(proxy.clone());
            e.net_proxy_log = log;
            let items = explain_net_proxy(&e, &inst)
                .expect("the proxy binary is there")
                .expect("an `allow-host` starts one");
            strs(&items.into_iter().flat_map(|i| i.args).collect::<Vec<_>>())
        };
        assert!(!words(false).iter().any(|w| w == "--log-tunnels"));
        assert_eq!(
            words(true).last().map(String::as_str),
            Some("--log-tunnels")
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
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: None,
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
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
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: None,
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &host,
                &mut dry(&e),
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
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: None,
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
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
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
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
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        assert!(a.windows(2).any(|w| w == ["--block-fd", "4"]), "{a:?}");
        for kdl in ["dbus\ncommand \"x\"", "command \"x\""] {
            let i = inst(tmp.path(), kdl);
            let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
            assert!(!a.contains(&"--block-fd".to_string()), "{kdl}: {a:?}");
        }
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
            let guard = adopt_proxy_bus(dir, socket, dbus::SESSION_NODE).unwrap();
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
            adopt_proxy_bus(tmp.path(), dbus::SYSTEM_SOCKET, dbus::SYSTEM_NODE),
            Err(LaunchError::MissingResource {
                service: "system-bus",
                ..
            })
        ));
    }

    #[test]
    fn anything_but_a_socket_in_the_proxys_directory_stops_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let socket = dbus::SESSION_SOCKET;
        std::fs::create_dir(dbus::socket_dir(dir)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE),
            Err(LaunchError::MissingResource {
                service: "dbus",
                ..
            })
        ));
        // A symlink is the attack: `stat` through it would report the type
        // of its target, and bwrap would bind that target.
        std::os::unix::fs::symlink("/etc", dbus::proxy_bus_path(dir, socket)).unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE),
            Err(LaunchError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            })
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
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE),
            Err(LaunchError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            })
        ));
        assert!(!dbus::app_bus_path(dir, socket).exists());
        // A directory is refused like anything else, and removed with what
        // is in it: `remove_file` cannot take one, and one left at this
        // name would fail the rename of every later start.
        std::fs::create_dir(dbus::proxy_bus_path(dir, socket)).unwrap();
        std::fs::write(dbus::proxy_bus_path(dir, socket).join("x"), b"").unwrap();
        assert!(matches!(
            adopt_proxy_bus(dir, socket, dbus::SESSION_NODE),
            Err(LaunchError::WrongType {
                service: "dbus",
                expected: "a socket",
                ..
            })
        ));
        assert!(
            !dbus::app_bus_path(dir, socket).exists(),
            "the directory was kept"
        );
        // And the next honest start works.
        let listener = UnixListener::bind(dbus::proxy_bus_path(dir, socket)).unwrap();
        adopt_proxy_bus(dir, socket, dbus::SESSION_NODE)
            .expect("a socket after a refused directory");
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
        let mut alloc = DryRunAlloc::new(PathBuf::from("/run/user/1000/bubbler/t"));
        assert_eq!(alloc.data(b"a").unwrap(), OsString::from("3"));
        assert_eq!(alloc.data(b"b").unwrap(), OsString::from("4"));
        assert_eq!(alloc.init_socket().unwrap(), OsString::from("5"));
        assert_eq!(alloc.ready_pipe().unwrap(), OsString::from("6"));
        assert_eq!(alloc.info_pipe().unwrap(), OsString::from("7"));
        assert_eq!(alloc.block_pipe().unwrap(), OsString::from("8"));
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

    #[test]
    fn exit_code_from_status() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }

    #[test]
    fn the_default_denylist_reaches_the_argv_as_one_seccomp_fd() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        // Straight after the info fd, and before the filesystem phase.
        assert_eq!(
            &a[7..12],
            &["--info-fd", "3", "--add-seccomp-fd", "4", "--ro-bind"],
            "{a:?}"
        );
        assert_eq!(
            &a[a.len() - 6..],
            &["--", INIT_INSIDE, "--socket-fd", "5", "--", "foot"]
        );
    }

    #[test]
    fn a_disabled_filter_leaves_the_argv_without_one() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "seccomp { disable }\ncommand \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        assert!(!a.iter().any(|x| x == "--add-seccomp-fd"), "{a:?}");
    }

    #[test]
    fn allowing_every_denied_syscall_leaves_no_program_to_load() {
        use crate::seccomp::{RuleSet, syscall_number};
        // A name no architecture in the filter has is a config error, so
        // only the ones it does can be allowed back. The numbered rules
        // of `enosys_numbered` have no such name at all, but config.rs
        // knows them by a second table, so they can still be named here.
        let set = RuleSet::default_set();
        let names: Vec<String> = set
            .eperm
            .iter()
            .chain(&set.enosys)
            .filter(|n| syscall_number(n).is_some())
            .map(|n| format!("\"{n}\""))
            .chain(
                set.enosys_numbered
                    .iter()
                    .map(|(n, _, _)| format!("\"{n}\"")),
            )
            .collect();
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(
            tmp.path(),
            &format!(
                "seccomp {{ allow \"ioctl\" {} }}\ncommand \"foot\"",
                names.join(" ")
            ),
        );
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        assert!(!a.iter().any(|x| x == "--add-seccomp-fd"), "{a:?}");
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

    /// The sweep runs over the very operations a launch is built from, so
    /// a home-share whose destination sits behind a planted link is
    /// refused with the argv the run would have used.
    #[test]
    fn a_built_argv_with_a_planted_destination_is_refused_before_the_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(tmp.path(), &e, "home-share \"Downloads\"\ncommand \"true\"");
        let home = tmp.path().join("data/bubbler/instances/t/home");

        let clean = share_host(tmp.path());
        assert!(crate::service::sweep_destinations(&items, &e, &clean).is_ok());

        let planted = share_host(tmp.path()).link(
            &home.join("Downloads").display().to_string(),
            "/oldroot/home/user/.config",
        );
        let err = crate::service::sweep_destinations(&items, &e, &planted).unwrap_err();
        assert!(
            err.to_string()
                .contains("/home/bubbler/Downloads is a symlink"),
            "{err}"
        );
    }
}
