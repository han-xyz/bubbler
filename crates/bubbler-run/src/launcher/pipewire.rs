//! The PipeWire security context sidecar and the private PulseAudio server behind it.

use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process};

use crate::config::Service;
use crate::env::Env;
use crate::host::Host;
use crate::instance::Instance;
use crate::launch_error::{LaunchError, PULSE_READY, PW_READY, PipeWireError};
use crate::sidecar_argv::{pw_context_argv, pw_pulse_argv};
use crate::{pipewire, run_log, service};
use bubbler_plan::plan_error::PlanError;

use super::POLL;
use super::alloc::{RealAlloc, spawning};
use super::dbus_proxy::{clear_socket_name, remove_moved_dir, still_running};
use super::identity::FileGuard;
use super::runtime_dir::{
    fresh_sidecar_dir, mkdir_private, open_dir, open_dir_nofollow, remove_sidecar_dir,
};
use super::spawn::{bwrap_command, spawn_sidecar};

const PW_STOP: Duration = Duration::from_secs(5);

const PULSE_STOP: Duration = Duration::from_secs(5);

// The holder writes a constant of bubbler's; a longer line is not the holder answering.
const PW_REPORT_MAX: usize = 4096;

/// A run's PipeWire security context and its sidecar. `pw-container` tears the context down when
/// its program exits, so dropping this ends it; it must outlive the sandbox.
#[derive(Debug)]
pub struct PwHandle {
    pub(super) child: Child,
    pub(super) alloc: RealAlloc,
    // `pw-container` unlinks the name it chose, which the holder renamed away, so what is left
    // here is bubbler's.
    pub(super) dir: PathBuf,
    // `None` until the socket is moved out of `dir`; until then it goes with the directory.
    pub(super) _socket: Option<FileGuard>,
    pub(super) _stderr: run_log::Relay,
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
pub(super) fn adopt_socket(
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
    pub(super) child: Child,
    pub(super) alloc: RealAlloc,
    pub(super) dir: PathBuf,
    // `None` until the socket is moved out of `dir`; until then it goes with the directory.
    pub(super) _socket: Option<FileGuard>,
    pub(super) _stderr: run_log::Relay,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::RealHost;
    use crate::paths::instance_runtime_dir;
    use crate::sidecar_argv::test_support::*;

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
}
