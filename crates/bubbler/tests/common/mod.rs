//! Shared helpers for CLI integration tests.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Returns false (after printing why) when real bwrap runs cannot work
/// here: no `bwrap` on PATH or no user namespaces.
pub fn require_bwrap() -> bool {
    let has_bwrap = Command::new("bwrap")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    let has_userns = Path::new("/proc/self/ns/user").exists();
    if !has_bwrap || !has_userns {
        eprintln!("skipping: bwrap={has_bwrap} userns={has_userns}");
    }
    has_bwrap && has_userns
}

/// The `bubbler-init` binary cargo builds next to the `bubbler` binary,
/// if it is there. `cargo test --workspace` builds it as a workspace
/// member; `cargo test -p bubbler` does not, so tests that need the real
/// supervisor skip with a printed reason instead of failing.
pub fn real_init() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_BIN_EXE_bubbler"))
        .parent()
        .expect("a cargo binary always has a parent directory")
        .join("bubbler-init");
    if path.is_file() {
        return Some(path);
    }
    eprintln!("skipping: {} is not built", path.display());
    None
}

/// A `bubbler` Command with an isolated HOME, XDG_DATA_HOME and
/// XDG_RUNTIME_DIR under `root`, a known TERM, and `$BUBBLER_INIT`
/// pointing at the stand-in `root/bubbler-init`, so argv assertions do
/// not depend on where the test binary lives. Tests that really start a
/// sandbox override it with [`real_init`].
pub fn bubbler(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bubbler"));
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("BUBBLER_INIT", root.join("bubbler-init"))
        .env("TERM", "dumb");
    c
}

/// [`bubbler`] pointed at the real supervisor binary, for tests that
/// start an actual sandbox instead of only building its argv.
pub fn bubbler_live(root: &Path, init: &Path) -> Command {
    let mut c = bubbler(root);
    c.env("BUBBLER_INIT", init);
    c
}
