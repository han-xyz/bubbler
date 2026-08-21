//! Where the host copy of `bubbler-init` is. Every sandbox runs under it,
//! so a run that cannot find it fails before bwrap is spawned.

use std::path::PathBuf;

use crate::env::Env;
use crate::error::LaunchError;
use crate::host::Host;

/// File name of the supervisor binary.
pub const NAME: &str = "bubbler-init";

/// Where a packaged bubbler installs the supervisor.
pub const INSTALLED: &str = "/usr/lib/bubbler/bubbler-init";

/// `Ok` for a regular file, `WrongType` for anything else that exists and
/// `MissingResource` for nothing at all.
fn check(path: PathBuf, host: &dyn Host) -> Result<PathBuf, LaunchError> {
    match host.file_type(&path) {
        Some(t) if t.is_file() => Ok(path),
        Some(_) => Err(LaunchError::WrongType {
            service: "init",
            path,
            expected: "a regular file",
        }),
        None => Err(LaunchError::MissingResource {
            service: "init",
            path,
        }),
    }
}

/// Host path of `bubbler-init`: [`Env::init_override`] (`$BUBBLER_INIT`),
/// else next to the running executable, else [`INSTALLED`]. Must be a
/// regular file; an override that is not one is an error, never a
/// silent fallback to another binary.
pub fn locate(env: &Env, host: &dyn Host) -> Result<PathBuf, LaunchError> {
    if let Some(p) = &env.init_override {
        return check(p.clone(), host);
    }
    if let Some(sibling) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(NAME)))
        && host.file_type(&sibling).is_some_and(|t| t.is_file())
    {
        return Ok(sibling);
    }
    check(PathBuf::from(INSTALLED), host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::{FakeHost, types};
    use std::path::Path;

    fn env(init_override: Option<PathBuf>) -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            config_home: "/home/han/.config".into(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override,
            dbus_address: None,
            dbus_log: false,
            seccomp_log: false,
            profile_dir_override: None,
            proxy_override: None,
        }
    }

    #[test]
    fn an_override_wins_and_must_be_a_regular_file() {
        let (file, dir, _) = types();
        let host = FakeHost::default()
            .with("/opt/bubbler-init", file)
            .with("/opt/adir", dir);
        assert_eq!(
            locate(&env(Some("/opt/bubbler-init".into())), &host).unwrap(),
            PathBuf::from("/opt/bubbler-init")
        );
        assert!(matches!(
            locate(&env(Some("/opt/adir".into())), &host),
            Err(LaunchError::WrongType {
                service: "init",
                expected: "a regular file",
                ..
            })
        ));
        assert!(matches!(
            locate(&env(Some("/opt/gone".into())), &host),
            Err(LaunchError::MissingResource {
                service: "init",
                ..
            })
        ));
    }

    #[test]
    fn without_an_override_the_installed_path_is_the_last_resort() {
        let (file, _, _) = types();
        let host = FakeHost::default().with(INSTALLED, file);
        assert_eq!(locate(&env(None), &host).unwrap(), PathBuf::from(INSTALLED));
        assert!(matches!(
            locate(&env(None), &FakeHost::default()),
            Err(LaunchError::MissingResource { service: "init", path }) if path == Path::new(INSTALLED)
        ));
    }

    #[test]
    fn a_sibling_of_the_running_binary_is_preferred_over_the_installed_one() {
        let (file, _, _) = types();
        let sibling = std::env::current_exe()
            .expect("a test binary has a path")
            .parent()
            .expect("and a directory")
            .join(NAME);
        let host = FakeHost::default()
            .with(&sibling.to_string_lossy(), file)
            .with(INSTALLED, file);
        assert_eq!(locate(&env(None), &host).unwrap(), sibling);
    }
}
