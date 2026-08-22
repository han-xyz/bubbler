//! The `wraps.kdl` registry, which dispatch turns into instance names.
//!
//! A shim on `PATH` is run by its own name and bubbler looks that name
//! up here; a line this parser misreads is a shim that opens a
//! different sandbox than the one it names. The file is under the
//! user's own config directory, so this is a robustness target rather
//! than a boundary one — but the misparse is the interesting failure,
//! not the panic.

#![no_main]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use bubbler_core::env::{DEFAULT_DATA_DIRS, Env};
use bubbler_core::wrap;
use libfuzzer_sys::fuzz_target;

/// The registry is read from a file, so the target needs one. One
/// directory per process, rewritten per run.
static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();

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
        dbus_log: false,
        seccomp_log: false,
        test_allow_path: None,
        profile_dir_override: None,
        proxy_override: None,
        pasta_override: None,
    }
}

fuzz_target!(|data: &[u8]| {
    // The same bytes are also an `argv[0]`: a shim is dispatched by the
    // name a shell found on `PATH`, which is caller-controlled.
    if let Some(name) = wrap::shim_name(Some(OsStr::new(
        &String::from_utf8_lossy(data).into_owned(),
    ))) {
        assert!(
            wrap::is_shim_name(&name),
            "dispatched on a name wrap refuses"
        );
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let root = ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir_all(dir.path().join("config").join("bubbler"))
            .expect("the config directory");
        dir
    });
    let env = env(root.path());
    if std::fs::write(wrap::registry_path(&env), text).is_err() {
        return;
    }
    let Ok(wraps) = wrap::load(&env) else {
        return;
    };
    for w in &wraps {
        // Every name that survives the parse is one bubbler would write
        // a shim for, and every instance one it would open.
        assert!(wrap::is_shim_name(&w.name), "loaded an unusable shim name");
        assert!(
            wrap::shim_name(Some(OsStr::new(&w.name))).as_deref() == Some(w.name.as_str()),
            "a registered shim does not dispatch by its own name"
        );
    }
});
