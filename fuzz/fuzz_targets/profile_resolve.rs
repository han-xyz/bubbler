//! The `include` graph flattener, over layers built from the input.
//!
//! The input is split on NUL into layer files `p0.kdl`, `p1.kdl`, ...,
//! written into a system profile directory, and `p0` is resolved. What
//! is being fuzzed is the traversal: cycles, self-includes, names that
//! are not there, and chains past `MAX_DEPTH` all have to come back as
//! errors rather than as a stack that ran out.

#![no_main]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use bubbler_core::config;
use bubbler_core::env::{DEFAULT_DATA_DIRS, Env};
use bubbler_core::profile::Resolver;
use libfuzzer_sys::fuzz_target;

/// Layers are files, so the resolver needs a directory. One per process,
/// rewritten per run: making a temporary directory per execution would
/// leave the fuzzer measuring the filesystem.
static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();

/// At most this many layers per run. The depth limit is eight, so a
/// dozen files is room for a chain that reaches it and for one that
/// does not.
const MAX_LAYERS: usize = 12;

fn env(root: &Path) -> Env {
    Env {
        home: root.join("home"),
        data_home: root.join("data"),
        config_home: root.join("config"),
        data_dirs: DEFAULT_DATA_DIRS.iter().map(PathBuf::from).collect(),
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
        profile_dir_override: Some(root.join("system")),
        proxy_override: None,
        pasta_override: None,
        wl_proxy_override: None,
        net_proxy_override: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let root = ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir_all(dir.path().join("system")).expect("the system layer directory");
        dir
    });
    let system = root.path().join("system");
    for (i, layer) in data.split(|b| *b == 0).take(MAX_LAYERS).enumerate() {
        let text = String::from_utf8_lossy(layer).into_owned();
        if std::fs::write(system.join(format!("p{i}.kdl")), text).is_err() {
            return;
        }
    }
    let resolver = Resolver::new(&env(root.path()));
    let Ok(resolved) = resolver.resolve("p0") else {
        return;
    };
    // What resolution produced is what an instance is seeded with, so it
    // has to be text the parser reads back as the same grants.
    let back = config::parse_profile(&resolved.text).expect("the flattened profile parses");
    assert_eq!(back.config, resolved.config, "flattening lost a grant");
    for i in 0..MAX_LAYERS {
        let _ = std::fs::remove_file(system.join(format!("p{i}.kdl")));
    }
});
