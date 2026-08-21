//! Host environment facts needed to build a sandbox. Filled in by the
//! binary so the library never reads process environment itself.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// Path of the private home inside every sandbox. Fixed so host home
/// paths are not part of the sandbox layout; the synthetic `/etc/passwd`
/// names its owner `bubbler`, so the host user name stays hidden too.
pub const SANDBOX_HOME: &str = "/home/bubbler";

/// Environment variables copied from the host into the sandbox when set:
/// terminal and locale. `LC_*` is not listed here; [`is_passthrough`] is
/// the whole policy. `TZ` may name a path, so this is not a value-only list.
pub const PASSTHROUGH_VARS: &[&str] = &["TERM", "LANG", "LANGUAGE", "COLORTERM", "TZ"];

/// Whether a host variable is copied into the sandbox: one of
/// [`PASSTHROUGH_VARS`] or an `LC_*` locale override. Compared by bytes,
/// since environment names need not be UTF-8.
pub fn is_passthrough(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    name.starts_with(b"LC_") || PASSTHROUGH_VARS.iter().any(|v| v.as_bytes() == name)
}

/// Host-side facts the builder and services need.
#[derive(Debug, Clone)]
pub struct Env {
    /// Real `$HOME`; source of `home-share` paths.
    pub home: PathBuf,
    /// `$XDG_DATA_HOME` (or `$HOME/.local/share`); instances live under it.
    pub data_home: PathBuf,
    /// `$XDG_CONFIG_HOME` (or `$HOME/.config`); the user's profile layer
    /// lives in `bubbler/profiles/` under it.
    pub config_home: PathBuf,
    /// `$XDG_RUNTIME_DIR`; required, sockets live here.
    pub runtime_dir: PathBuf,
    /// Real user id; unchanged inside the sandbox, so synthetic
    /// `/etc/passwd` entries must use it.
    pub uid: u32,
    /// Real group id; unchanged inside the sandbox.
    pub gid: u32,
    /// `$WAYLAND_DISPLAY` if set.
    pub wayland_display: Option<OsString>,
    /// `$DISPLAY` if set.
    pub display: Option<OsString>,
    /// `$XAUTHORITY` if set.
    pub xauthority: Option<PathBuf>,
    /// Already-filtered `(name, value)` pairs that were set on the host,
    /// selected by [`is_passthrough`].
    pub passthrough: Vec<(OsString, OsString)>,
    /// `$BUBBLER_INIT`: host path of the `bubbler-init` binary to bind
    /// into the sandbox, overriding the usual search.
    pub init_override: Option<PathBuf>,
    /// `$DBUS_SESSION_BUS_ADDRESS` as the host set it; only a
    /// `unix:path=` address names a socket bubbler can proxy.
    pub dbus_address: Option<OsString>,
    /// `$DBUS_SYSTEM_BUS_ADDRESS` as the host set it; only a `unix:path=`
    /// address names a socket bubbler can proxy, and the compiled-in
    /// `/run/dbus/system_bus_socket` is used when it names none.
    pub dbus_system_address: Option<OsString>,
    /// `$BUBBLER_DBUS_LOG=1`: run the D-Bus proxy with `--log`, which
    /// prints every filtered message to bubbler's stderr.
    pub dbus_log: bool,
    /// `$BUBBLER_SECCOMP_LOG=1`: the seccomp filter logs what it would
    /// have denied to the audit log instead of denying it, which is how a
    /// profile's `seccomp` node is worked out. Not a sandbox at all.
    pub seccomp_log: bool,
    /// `$BUBBLER_TEST_ALLOW_PATH`: one extra path `path-share` accepts at
    /// either end, on top of the fixed roots of its denylist; it never
    /// lifts the roots named here. Absolute, not `/`, and resolved so it
    /// compares against a canonical source. A test and debugging hook;
    /// nothing shipped sets it.
    pub test_allow_path: Option<PathBuf>,
    /// `$BUBBLER_PROFILE_DIR`: directory holding the system profile
    /// layer, replacing `/usr/share/bubbler/profiles`.
    pub profile_dir_override: Option<PathBuf>,
    /// `$BUBBLER_DBUS_PROXY`: host path of the proxy binary to run
    /// instead of the one on `PATH`. A test and debugging hook; it must
    /// be a regular file and is bound into the proxy sandbox at its own
    /// path.
    pub proxy_override: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn passthrough_is_the_allowlist_plus_lc_prefix() {
        for ok in [
            "TERM",
            "LANG",
            "LANGUAGE",
            "COLORTERM",
            "TZ",
            "LC_ALL",
            "LC_",
        ] {
            assert!(is_passthrough(OsStr::new(ok)), "{ok}");
        }
        for no in [
            "PATH", "HOME", "DISPLAY", "TERMINFO", "lc_all", "XLC_ALL", "",
        ] {
            assert!(!is_passthrough(OsStr::new(no)), "{no}");
        }
        assert!(!is_passthrough(OsStr::from_bytes(b"LC\xff")));
    }
}
