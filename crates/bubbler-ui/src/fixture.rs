//! An instance store in a temporary directory, for the tests of every
//! other module. Nothing here is compiled into the binary.

use std::path::Path;

use bubbler_core::env::{DEFAULT_DATA_DIRS, Env};
use bubbler_core::instance::Instance;
use tempfile::TempDir;

/// An [`Env`] whose store, profile layer and runtime directory are all
/// under `root`, so a test reads nothing of the host's and writes nothing
/// outside its own directory.
pub fn env(root: &Path) -> Env {
    Env {
        home: root.join("home"),
        data_home: root.join("data"),
        config_home: root.join("config"),
        data_dirs: DEFAULT_DATA_DIRS.iter().map(Into::into).collect(),
        runtime_dir: root.join("run"),
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
        // Into the test root as well, so a profile installed on this host
        // cannot be what a test resolves.
        profile_dir_override: Some(root.join("profiles")),
        proxy_override: None,
        pasta_override: None,
        wl_proxy_override: None,
        net_proxy_override: None,
    }
}

/// A store holding one instance per `(name, profile)` pair, seeded from
/// the built-in profile library. The directory is removed when the
/// returned handle is dropped.
pub fn store(instances: &[(&str, &str)]) -> (TempDir, Env) {
    let tmp = tempfile::tempdir().expect("a temporary directory");
    let env = env(tmp.path());
    std::fs::create_dir_all(&env.home).expect("a home");
    for (name, profile) in instances {
        Instance::create(&env, name, profile).expect("a seeded instance");
    }
    (tmp, env)
}
