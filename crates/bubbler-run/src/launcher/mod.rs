//! Spawns bubblewrap and the sidecars a sandbox needs: the D-Bus, Wayland and
//! egress proxies, the audio sidecars, pasta and `nft`. The only
//! process-spawning code in the crate; it never goes through a shell.
//! Every spawn is preceded by a [`fds::sweep_cloexec`](bubbler_init::fds::sweep_cloexec), so a child holds
//! only the descriptors it was meant to: each public function that spawns
//! marks the caller's other descriptors above stdio close-on-exec, closing
//! none. Every sidecar is killed on every way out of a run.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use rustix::process::{Pid, Signal, kill_process};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};

use crate::bwrap::Explained;
use crate::env::Env;
use crate::exec::SignalGuard;
pub use crate::exec::exit_code;
use crate::host::RealHost;
use crate::instance::Instance;
use crate::launch_error::{LaunchError, NetworkError};
pub use crate::paths::{RUNTIME_SUBDIR, instance_runtime_dir};
pub(crate) use crate::paths::{START_LOCK_SUFFIX, start_lock_path};
pub use crate::sidecar_argv::{
    DryRunAlloc, build_argv, explain, explain_net_proxy, explain_wayland_proxy, proxy_argv,
    pw_context_argv, pw_pulse_argv, resolve_command, wl_proxy_argv, wl_proxy_plan,
};
use crate::sidecar_argv::{build_args_on, network_of, proxy_args};
use crate::tty::{self, Pty, StdioTarget, TtyMode};
use crate::tty_relay::{self, RawGuard, RelayEnd};
use crate::{cgroup, dbus, dbus_a11y, exec, run_log, service, version, version_probe};

mod alloc;
mod control;
mod dbus_proxy;
mod identity;
mod network;
mod pipewire;
mod runtime_dir;
mod spawn;
mod wl_proxy;

pub(crate) use alloc::RealAlloc;
use alloc::spawning;
use control::{STOPPED_CODE, bind_control_socket, lock_for_teardown};
use identity::{FileGuard, publish_identity, read_sandbox_info, release_block, supervisor_pid};
use network::NetworkSidecars;
pub(crate) use runtime_dir::prepare_runtime_dir;
use runtime_dir::{join_session_keyring, prepare_app_runtime};

const POLL: Duration = Duration::from_millis(100);

// Past this the run goes on without a pid to stop the sandbox gracefully.
const INFO_TIMEOUT: Duration = Duration::from_secs(5);

const SUPERVISOR_WAIT: Duration = Duration::from_secs(2);

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
        Some(plan) => Some(dbus_proxy::start_proxy(env, &dir, plan, &RealHost, stop)?),
        None => None,
    };
    // Each socket is moved out of the proxy's reach, then checked; each guard removes its socket
    // at the end of the run.
    let mut buses: Vec<FileGuard> = Vec::new();
    if let Some(plan) = &plan {
        for (socket, node) in plan.buses() {
            buses.push(dbus_proxy::adopt_proxy_bus(&dir, socket, node, env.uid)?);
        }
    }
    if stop.load(Ordering::SeqCst) {
        return Ok(STOPPED_CODE);
    }
    // The sandbox binds the socket this sidecar accepts on, so it too starts before the argv.
    let _wayland = wl_proxy::start_wayland(env, &dir, inst, &RealHost, stop)?;
    if stop.load(Ordering::SeqCst) {
        return Ok(STOPPED_CODE);
    }
    // Before the argv: the context socket is the only PipeWire socket the sandbox gets.
    let _pw_context = pipewire::start_pw_context(env, &dir, inst, &RealHost, stop)?;
    if stop.load(Ordering::SeqCst) {
        return Ok(STOPPED_CODE);
    }
    // After the context it connects to, before the sandbox it serves; dropped before the context.
    let _pw_pulse = pipewire::start_pw_pulse(env, &dir, inst, &RealHost, stop)?;
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
    let mut cmd = spawn::bwrap_command(&argv, &mut alloc)?;
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
                    network::start_network(env, cfg, *child_pid, net_cgroup.as_ref(), stop)
                }
                None => Err(NetworkError::NoSandboxPid.into()),
            };
            match started {
                Ok(handle) => Some(handle),
                Err(e) => {
                    // A Ctrl-C kills the held bwrap too, which is the stop's doing; any other
                    // failure is reported.
                    let bwrap_ended = matches!(child.try_wait(), Ok(Some(_)));
                    spawn::abort_sandbox(&mut child, info.as_ref().map(|(pid, _)| *pid));
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
            spawn::abort_sandbox(&mut child, info.as_ref().map(|(pid, _)| *pid));
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
    use super::dbus_proxy::{ProxyHandle, adopt_proxy_bus, start_proxy};
    use super::pipewire::{PulseHandle, PwHandle, adopt_socket, start_pw_context, start_pw_pulse};
    use super::*;
    use crate::pipewire;
    use crate::sidecar_argv::test_support::*;

    use crate::bwrap::Origin;
    use bubbler_plan::plan_error::PlanError;

    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::process::Command;

    use std::os::unix::net::UnixListener;

    use rustix::fs::{Mode, OFlags};

    /// The directory a real allocator gets in a test that allocates
    /// descriptors and no generated file: one that is not there, so a
    /// call to [`FdAllocator::file`] would fail rather than write
    /// somewhere real.
    pub(super) fn no_data_dir() -> PathBuf {
        PathBuf::from("/nonexistent/bubbler")
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
    pub(super) fn plant_chain(top: &Path, depth: usize) -> OwnedFd {
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
    pub(super) fn with_desktop_fd_limit(test: impl FnOnce()) {
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

    pub(super) fn leftovers(dir: &Path, sidecar: &Path) -> Vec<OsString> {
        let mut prefix = sidecar.file_name().unwrap().to_owned();
        prefix.push(".");
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.as_bytes().starts_with(prefix.as_bytes()))
            .collect()
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

    pub(super) fn own_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }
}
