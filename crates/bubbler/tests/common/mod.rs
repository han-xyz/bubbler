//! Shared helpers for CLI integration tests.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
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

/// [`bubbler_live`] with the session's real `XDG_RUNTIME_DIR` and
/// `DBUS_SESSION_BUS_ADDRESS`, which a proxied bus needs; HOME and
/// XDG_DATA_HOME stay under `root`. Instance runtime state therefore
/// lands in the real runtime dir, so such tests need distinctive names.
pub fn bubbler_dbus(root: &Path, init: &Path) -> Command {
    let mut c = bubbler_live(root, init);
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        c.env("XDG_RUNTIME_DIR", dir);
    }
    if let Some(addr) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") {
        c.env("DBUS_SESSION_BUS_ADDRESS", addr);
    }
    c
}

/// Whether `program` is on `PATH`. Only the spawn is checked: `dbus-send`
/// exits 1 on `--version` even when it is installed.
fn has_program(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok()
}

/// The host session bus socket, resolved the way bubbler resolves it.
pub fn host_bus() -> Option<PathBuf> {
    let from_address = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").and_then(|a| {
        let rest = a.as_bytes().strip_prefix(b"unix:path=")?.to_vec();
        let end = rest.iter().position(|b| *b == b',').unwrap_or(rest.len());
        Some(PathBuf::from(OsStr::from_bytes(&rest[..end])))
    });
    from_address
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("bus")))
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket()))
}

/// Whether the session bus has an owner for `name` right now. Asking
/// does not activate the service, so a portal that is merely
/// activatable counts as absent.
fn bus_name_has_owner(name: &str) -> bool {
    Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            &format!("string:{name}"),
        ])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("true"))
}

/// Returns false (after printing why) when portal calls cannot be tested
/// here: no proxied session bus, or no running xdg-desktop-portal.
pub fn require_portal() -> bool {
    if !require_dbus() {
        return false;
    }
    let desktop = bus_name_has_owner("org.freedesktop.portal.Desktop");
    if !desktop {
        eprintln!("skipping: no org.freedesktop.portal.Desktop on the session bus");
    }
    desktop
}

/// Returns false (after printing why) when a proxied session bus cannot
/// be tested here: no bwrap, no `xdg-dbus-proxy` or `dbus-send`, or no
/// session bus on the host.
pub fn require_dbus() -> bool {
    if !require_bwrap() {
        return false;
    }
    let proxy = has_program("xdg-dbus-proxy");
    let send = has_program("dbus-send");
    let bus = host_bus();
    if !proxy || !send || bus.is_none() {
        eprintln!("skipping: xdg-dbus-proxy={proxy} dbus-send={send} bus={bus:?}");
        return false;
    }
    true
}
