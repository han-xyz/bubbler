//! Spawns bubblewrap. The only process-spawning code in the crate; it
//! never goes through a shell.

use std::ffi::OsString;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use rustix::fs::{MemfdFlags, Mode};
use rustix::io::Errno;

use crate::bwrap::BwrapArgs;
use crate::env::Env;
use crate::error::{ConfigError, LaunchError};
use crate::host::RealHost;
use crate::instance::Instance;
use crate::service;

/// Complete bwrap argv (without the program name) for an instance.
/// `command` from the CLI replaces the config's `command` entirely.
/// `alloc` turns each generated data file into the fd number bwrap reads
/// it from.
pub fn build_argv(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    alloc: &mut dyn FnMut(&[u8]) -> io::Result<OsString>,
) -> Result<Vec<OsString>, LaunchError> {
    let command: &[OsString] = match command {
        Some(c) if !c.is_empty() => c,
        _ => inst
            .config
            .command
            .as_deref()
            .ok_or(ConfigError::MissingCommand)?,
    };
    let host = RealHost;
    let mut args = BwrapArgs::baseline(env, &inst.home(), &host);
    service::apply_all(&inst.config.services, env, &mut args, &host)?;
    args.finish(command, alloc)
}

/// Allocator for `--dry-run`: numbers data files 3, 4, ... without
/// creating anything, which is what a real run typically gets.
pub fn dry_run_alloc() -> impl FnMut(&[u8]) -> io::Result<OsString> {
    let mut next = 2u32;
    move |_| {
        next += 1;
        Ok(OsString::from(next.to_string()))
    }
}

/// Backs each data file with a memfd that bwrap inherits. The fds stay
/// open in `fds` until the child has been spawned.
fn memfd_alloc(fds: &mut Vec<OwnedFd>) -> impl FnMut(&[u8]) -> io::Result<OsString> + '_ {
    move |content| {
        // No `MFD_CLOEXEC`: bwrap is a child process and must inherit the fd.
        let fd = rustix::fs::memfd_create("bubbler-data", MemfdFlags::empty())?;
        let mut f = std::fs::File::from(fd);
        f.write_all(content)?;
        f.seek(SeekFrom::Start(0))?;
        let fd: OwnedFd = f.into();
        let n = fd.as_raw_fd();
        fds.push(fd);
        Ok(OsString::from(n.to_string()))
    }
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
/// directory is reused as is. Not a lock; concurrent runs of one instance
/// are allowed.
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
    let mut fds = Vec::new();
    let argv = build_argv(env, inst, command, &mut memfd_alloc(&mut fds))?;
    prepare_runtime_dir(env, inst)?;
    let status = Command::new("bwrap")
        .args(&argv)
        .status()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LaunchError::BwrapMissing,
            _ => LaunchError::Spawn(e),
        })?;
    // bwrap copies the data files out of the fds while it starts, so they
    // must stay open until it has exited.
    drop(fds);
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
            uid: 1000,
            gid: 1000,
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
        let a = build_argv(&e, &i, None, &mut dry_run_alloc()).unwrap();
        assert_eq!(
            &a[a.len() - 4..],
            &[
                OsString::from("--"),
                "foot".into(),
                "-e".into(),
                "fish".into()
            ]
        );
        let a = build_argv(&e, &i, Some(&[OsString::from("ls")]), &mut dry_run_alloc()).unwrap();
        assert_eq!(&a[a.len() - 2..], &[OsString::from("--"), "ls".into()]);
    }

    #[test]
    fn no_command_anywhere_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "");
        assert!(matches!(
            build_argv(&e, &i, None, &mut dry_run_alloc()),
            Err(LaunchError::Config(ConfigError::MissingCommand))
        ));
        assert!(matches!(
            build_argv(&e, &i, Some(&[]), &mut dry_run_alloc()),
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
    fn dry_run_alloc_numbers_data_files_from_three() {
        let mut alloc = dry_run_alloc();
        assert_eq!(alloc(b"a").unwrap(), OsString::from("3"));
        assert_eq!(alloc(b"b").unwrap(), OsString::from("4"));
    }

    #[test]
    fn memfd_alloc_leaves_the_content_readable_from_the_start() {
        use std::io::Read;
        let mut fds = Vec::new();
        let mut alloc = memfd_alloc(&mut fds);
        let fd = alloc(b"hello").unwrap();
        drop(alloc);
        assert_eq!(fds.len(), 1);
        assert_eq!(fd, OsString::from(fds[0].as_raw_fd().to_string()));
        // A dup shares the file offset, so this reads what bwrap would read.
        let mut got = String::new();
        std::fs::File::from(fds[0].try_clone().unwrap())
            .read_to_string(&mut got)
            .unwrap();
        assert_eq!(got, "hello");
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
