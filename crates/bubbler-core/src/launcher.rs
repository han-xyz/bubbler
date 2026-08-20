//! Spawns bubblewrap. The only process-spawning code in the crate; it
//! never goes through a shell.

use std::ffi::OsString;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use rustix::fs::Mode;
use rustix::io::Errno;

use crate::bwrap::BwrapArgs;
use crate::env::Env;
use crate::error::{ConfigError, LaunchError};
use crate::instance::Instance;
use crate::service;

/// Complete bwrap argv (without the program name) for an instance.
/// `command` from the CLI replaces the config's `command` entirely.
pub fn build_argv(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
) -> Result<Vec<OsString>, LaunchError> {
    let command: &[OsString] = match command {
        Some(c) if !c.is_empty() => c,
        _ => inst
            .config
            .command
            .as_deref()
            .ok_or(ConfigError::MissingCommand)?,
    };
    let mut args = BwrapArgs::baseline(env, &inst.home());
    let probe = |p: &Path| std::fs::metadata(p).ok().map(|m| m.file_type());
    service::apply_all(&inst.config.services, env, &mut args, &probe)?;
    Ok(args.finish(command))
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

/// Ensure `$XDG_RUNTIME_DIR/bubbler/<name>/` exists with mode 0700. Not a
/// lock; concurrent runs of one instance are allowed.
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

/// Build the argv, prepare the runtime dir, run `bwrap` to completion and
/// return the exit code to propagate.
pub fn run(env: &Env, inst: &Instance, command: Option<&[OsString]>) -> Result<i32, LaunchError> {
    let argv = build_argv(env, inst, command)?;
    prepare_runtime_dir(env, inst)?;
    let status = Command::new("bwrap")
        .args(&argv)
        .status()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    Ok(exit_code(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(tmp: &Path) -> Env {
        Env {
            home: tmp.join("home"),
            data_home: tmp.join("data"),
            runtime_dir: tmp.join("run"),
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
        }
    }

    fn inst(tmp: &Path, kdl: &str) -> Instance {
        Instance {
            name: "t".into(),
            dir: tmp.join("data/bubbler/instances/t"),
            config: crate::config::parse(kdl).unwrap(),
        }
    }

    #[test]
    fn argv_uses_config_command_unless_overridden() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\" \"-e\" \"fish\"");
        let a = build_argv(&e, &i, None).unwrap();
        assert_eq!(
            &a[a.len() - 4..],
            &[
                OsString::from("--"),
                "foot".into(),
                "-e".into(),
                "fish".into()
            ]
        );
        let a = build_argv(&e, &i, Some(&[OsString::from("ls")])).unwrap();
        assert_eq!(&a[a.len() - 2..], &[OsString::from("--"), "ls".into()]);
    }

    #[test]
    fn no_command_anywhere_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "");
        assert!(matches!(
            build_argv(&e, &i, None),
            Err(LaunchError::Config(ConfigError::MissingCommand))
        ));
        assert!(matches!(
            build_argv(&e, &i, Some(&[])),
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
    fn exit_code_from_status() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
