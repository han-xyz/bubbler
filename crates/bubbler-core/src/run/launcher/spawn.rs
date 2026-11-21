//! How bubbler starts bwrap and its sidecars, and finds the programs it starts.

use std::io;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use rustix::fs::Access;
use rustix::process::{Pid, Signal, kill_process};

use crate::bwrap::Argv;
use crate::run::launch_error::LaunchError;
use crate::run_log;

use super::alloc::RealAlloc;

// Before the failing run closes the block pipe, by pid: killing bwrap leaves its child. SIGKILL
// from an ancestor pid namespace reaches a pid 1 (`pid_namespaces(7)`).
pub(super) fn abort_sandbox(child: &mut Child, sandbox: Option<i32>) {
    if let Some(pid) = sandbox.and_then(Pid::from_raw) {
        let _ = kill_process(pid, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

// `bwrap`, found on bubbler's own `PATH`, to be started with an empty environment: it stays pid 1
// inside the sandbox, where its environ is readable, and `--clearenv` cleans only what it starts
// (https://github.com/containers/bubblewrap/issues/725). Its command line is readable there too,
// so `argv`'s options reach it through `--args` from a descriptor `alloc` holds until the spawn
// has happened ([`RealAlloc::close_options`]).
// The `--` and the command stay on argv: bwrap drops a command it finds in an `--args` file.
// Call before the spawn window opens, so the options descriptor is in it.
pub(super) fn bwrap_command(argv: &Argv, alloc: &mut RealAlloc) -> Result<Command, LaunchError> {
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
pub(super) fn spawn_sidecar(
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
pub(super) fn on_path(bin: &str) -> Option<PathBuf> {
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
