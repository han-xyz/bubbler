//! The WirePlumber policy drop-in (`contrib/wireplumber/50-bubbler.conf`)
//! that scopes each instance's audio grant, embedded so bubbler can hand
//! it out (`bubbler audio-policy --print`) without a checkout of the
//! source tree it was built from.

use std::path::PathBuf;

use crate::env::Env;
use crate::host::Host;

/// The drop-in, exactly as shipped in `contrib/`. Loaded by the
/// real-PipeWire test bed and printed verbatim by `bubbler audio-policy
/// --print`.
pub const DROP_IN: &str = include_str!("../../../contrib/wireplumber/50-bubbler.conf");

/// File name WirePlumber loads the drop-in under, in any of
/// [`install_dirs`].
pub const DROP_IN_NAME: &str = "50-bubbler.conf";

/// The three `wireplumber.conf.d` directories bubbler looks for the
/// drop-in in, in the order [`installed`] searches (R9).
pub fn install_dirs(env: &Env) -> [PathBuf; 3] {
    [
        PathBuf::from("/usr/share/wireplumber/wireplumber.conf.d"),
        PathBuf::from("/etc/wireplumber/wireplumber.conf.d"),
        env.config_home.join("wireplumber/wireplumber.conf.d"),
    ]
}

/// Full path of the installed drop-in: the first of [`install_dirs`]
/// that holds a file named [`DROP_IN_NAME`]; `None` where none does,
/// which is what an absent policy is measured by everywhere else in
/// this module.
pub fn installed(host: &dyn Host, env: &Env) -> Option<PathBuf> {
    install_dirs(env).into_iter().find_map(|dir| {
        let path = dir.join(DROP_IN_NAME);
        host.file_type(&path).is_some().then_some(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::{self, FakeHost};
    use std::path::Path;

    fn env() -> Env {
        Env {
            home: PathBuf::from("/home/user"),
            data_home: PathBuf::from("/home/user/.local/share"),
            config_home: PathBuf::from("/home/user/.config"),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: PathBuf::from("/run/user/1000"),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
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

    /// The embedded copy is what a fresh read of the file on disk holds
    /// too (R10): a stale embed would ship a drop-in that does not
    /// match what `contrib/` documents and reviews.
    #[test]
    fn drop_in_matches_the_file_on_disk() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contrib/wireplumber/50-bubbler.conf");
        let disk =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(DROP_IN, disk);
    }

    #[test]
    fn installed_finds_the_file_in_any_of_the_three_directories() {
        let e = env();
        let (file, _, _) = fake::types();
        for dir in install_dirs(&e) {
            let path = dir.join(DROP_IN_NAME);
            let host = FakeHost::default().with(path.to_str().unwrap(), file);
            assert_eq!(
                installed(&host, &e),
                Some(path.clone()),
                "{}",
                dir.display()
            );
        }
    }

    #[test]
    fn installed_is_none_where_no_directory_holds_it() {
        let e = env();
        assert_eq!(installed(&FakeHost::default(), &e), None);
    }
}
