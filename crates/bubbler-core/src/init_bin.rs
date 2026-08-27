//! Where the host copies of bubbler's own binaries are: the
//! `bubbler-init` supervisor every sandbox runs under, and — through
//! [`locate_binary`] — the `bubbler-wl-proxy` sidecar a sandboxed
//! `wayland` is served through. A run that cannot find one fails before
//! bwrap is spawned.

use std::path::{Path, PathBuf};

use crate::env::Env;
use crate::error::LaunchError;
use crate::host::Host;
use crate::service;

/// File name of the supervisor binary.
pub const NAME: &str = "bubbler-init";

/// Where a packaged bubbler installs the supervisor.
pub const INSTALLED: &str = "/usr/lib/bubbler/bubbler-init";

/// Which of the three places a binary of bubbler's was found in.
///
/// It is what decides whether a sandbox that runs the binary has to have
/// it bound in: the installed path is under the read-only `/usr` every
/// sandbox already has, while an override and a build tree's copy are
/// wherever the user put them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// The environment named it (`$BUBBLER_INIT`, `$BUBBLER_WL_PROXY`).
    Override,
    /// Beside the running executable, which is what a build tree has.
    Sibling,
    /// Where the package installs it.
    Installed,
}

/// Host path of one of bubbler's own binaries and where it was found:
/// `over` when the environment names one, else `name` next to the
/// running executable, else `installed`.
///
/// Must be a regular file; an override that is not one is an error,
/// never a silent fallback to another binary. `service` names the grant
/// a failure is reported against.
pub fn locate_binary(
    over: Option<&Path>,
    name: &str,
    installed: &str,
    service: &'static str,
    host: &dyn Host,
) -> Result<(PathBuf, Found), LaunchError> {
    if let Some(p) = over {
        let path = service::require_file(host, service, p.to_path_buf())?;
        return Ok((path, Found::Override));
    }
    if let Some(sibling) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        && host.file_type(&sibling).is_some_and(|t| t.is_file())
    {
        return Ok((sibling, Found::Sibling));
    }
    let path = service::require_file(host, service, PathBuf::from(installed))?;
    Ok((path, Found::Installed))
}

/// Host path of `bubbler-init`: [`Env::init_override`] (`$BUBBLER_INIT`),
/// else next to the running executable, else [`INSTALLED`]. Where it was
/// found does not matter here — the supervisor is bound into every
/// sandbox at [`crate::bwrap::INIT_INSIDE`] wherever it came from.
pub fn locate(env: &Env, host: &dyn Host) -> Result<PathBuf, LaunchError> {
    locate_binary(env.init_override.as_deref(), NAME, INSTALLED, "init", host).map(|(p, _)| p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::{FakeHost, types};
    use std::path::Path;

    fn env(init_override: Option<PathBuf>) -> Env {
        Env {
            home: "/home/user".into(),
            data_home: "/home/user/.local/share".into(),
            config_home: "/home/user/.config".into(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override,
            dbus_address: None,
            dbus_system_address: None,
            at_spi_bus_address: None,
            dbus_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
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
