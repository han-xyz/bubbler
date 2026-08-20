//! Spawns bubblewrap. The only process-spawning code in the crate; it
//! never goes through a shell.

use std::ffi::OsString;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustix::fs::{MemfdFlags, Mode};
use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use rustix::process::{Pid, Signal, kill_process};
use signal_hook::consts::{SIGINT, SIGTERM};

use crate::bwrap::{BwrapArgs, FdAllocator};
use crate::env::Env;
use crate::error::{ConfigError, LaunchError};
use crate::host::RealHost;
use crate::instance::Instance;
use crate::{exec, init_bin, service};

/// How often a running sandbox is checked for having exited.
const POLL: Duration = Duration::from_millis(100);

/// Allocator for `--dry-run`: numbers every fd 3, 4, ... without creating
/// anything, which is what a real run typically gets.
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
}

/// Allocator for a real run: memfds for data files, the control socket
/// bubbler already bound, and a sidecar ready pipe.
pub struct RealAlloc {
    /// Fds bwrap inherits; they stay open until it has been spawned.
    pub fds: Vec<OwnedFd>,
    /// The listening control socket, already dup'ed without `CLOEXEC`.
    pub socket: RawFd,
    /// Read end of the ready pipe, once [`FdAllocator::ready_pipe`] made one.
    pub ready_read: Option<OwnedFd>,
}

impl RealAlloc {
    /// Allocate around an already inherited control socket fd.
    pub fn new(socket: RawFd) -> Self {
        Self {
            fds: Vec::new(),
            socket,
            ready_read: None,
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
        Ok(OsString::from(self.socket.to_string()))
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
    let mut args = BwrapArgs::baseline(env, &inst.home(), &host);
    service::apply_all(&inst.config.services, env, &mut args, &host)?;
    service::apply_env(&inst.config.env, &mut args)?;
    args.bind_init(&init_bin::locate(env)?);
    args.finish(command, alloc)
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
    let root = env.runtime_dir.join("bubbler");
    mkdir_private(&root)?;
    let dir = root.join(&inst.name);
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
    let inherited = fcntl_dupfd_cloexec(listener.as_fd(), 3).map_err(io_at)?;
    // bwrap must inherit exactly this one fd; everything else stays CLOEXEC.
    fcntl_setfd(&inherited, FdFlags::empty()).map_err(io_at)?;
    let mut alloc = RealAlloc::new(inherited.as_raw_fd());
    let argv = build_argv(env, inst, command, &mut alloc)?;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [SIGINT, SIGTERM] {
        signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(LaunchError::Signal)?;
    }
    let mut child = Command::new("bwrap")
        .args(&argv)
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    // The sandbox holds the listening socket now; the path stays bound for
    // exec clients, and bubbler keeping a copy would only make a dead
    // instance still look live.
    drop(inherited);
    drop(listener);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(LaunchError::Spawn)? {
            break status;
        }
        if stop.swap(false, Ordering::SeqCst) {
            // Racing the child's own exit is normal, so a failed kill is
            // not an error. bubblewrap 0.11.2 exits on SIGTERM instead of
            // forwarding it, so the sandbox goes down through
            // --die-with-parent rather than through init's grace period.
            let _ = kill_process(Pid::from_child(&child), Signal::TERM);
        }
        std::thread::sleep(POLL);
    };
    // bwrap copies the data files out of the fds while it starts, so they
    // must stay open until it has exited.
    drop(alloc);
    // A concurrent start may have replaced the socket already; unlinking
    // it is a courtesy, and a stale one is detected by connecting anyway.
    let _ = std::fs::remove_file(&sock_path);
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
    fn dry_run_alloc_numbers_every_fd_from_three() {
        let mut alloc = DryRunAlloc::default();
        assert_eq!(alloc.data(b"a").unwrap(), OsString::from("3"));
        assert_eq!(alloc.data(b"b").unwrap(), OsString::from("4"));
        assert_eq!(alloc.init_socket().unwrap(), OsString::from("5"));
        assert_eq!(alloc.ready_pipe().unwrap(), OsString::from("6"));
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
    fn exit_code_from_status() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
