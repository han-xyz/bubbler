//! Shared helpers for CLI integration tests.

use std::path::Path;
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

/// A `bubbler` Command with an isolated HOME, XDG_DATA_HOME and
/// XDG_RUNTIME_DIR under `root`, and a known TERM.
pub fn bubbler(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bubbler"));
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("TERM", "dumb");
    c
}
