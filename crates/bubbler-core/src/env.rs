//! Host environment facts needed to build a sandbox. Filled in by the
//! binary so the library never reads process environment itself.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// Path of the private home inside every sandbox. Fixed so host home
/// paths are not part of the sandbox layout; the synthetic `/etc/passwd`
/// names its owner `bubbler`, so the host user name stays hidden too.
pub const SANDBOX_HOME: &str = "/home/bubbler";

/// Where a desktop entry is looked up when `$XDG_DATA_DIRS` is unset,
/// as the XDG base directory specification names them.
pub const DEFAULT_DATA_DIRS: &[&str] = &["/usr/local/share", "/usr/share"];

/// The same for `$XDG_CONFIG_DIRS`.
pub const DEFAULT_CONFIG_DIRS: &[&str] = &["/etc/xdg"];

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

/// `$XDG_DATA_DIRS` or `$XDG_CONFIG_DIRS` split into directories, or
/// `defaults` when it is unset or empty, which is what the XDG base
/// directory specification asks for.
///
/// A relative entry is dropped rather than resolved: that specification
/// says every path in these variables must be absolute and that an
/// implementation meeting a relative one is to consider it invalid and
/// ignore it. An empty entry means the current directory and goes the
/// same way. What it would otherwise cost is a launcher entry read from
/// wherever the process happened to be started.
pub fn xdg_dirs(value: Option<OsString>, defaults: &[&str]) -> Vec<PathBuf> {
    value
        .filter(|v| !v.is_empty())
        .map(|v| {
            std::env::split_paths(&v)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_else(|| defaults.iter().map(PathBuf::from).collect())
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
    /// `$XDG_CONFIG_DIRS` (or `/etc/xdg`), in precedence order and
    /// absolute like [`Env::data_dirs`]; where WirePlumber looks for its
    /// configuration after `$XDG_CONFIG_HOME`.
    pub config_dirs: Vec<PathBuf>,
    /// `$XDG_DATA_DIRS` (or `/usr/local/share:/usr/share`), in precedence
    /// order; where an application's own desktop entry is looked up,
    /// under `$XDG_DATA_HOME`'s copy of the same name. Absolute: the XDG
    /// base directory specification says a relative entry is invalid, and
    /// the binary drops it before filling this in.
    pub data_dirs: Vec<PathBuf>,
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
    /// `$AT_SPI_BUS_ADDRESS` as the host set it: where the session says
    /// its accessibility bus is, which is what at-spi2's own clients
    /// read before they ask `org.a11y.Bus`. Untrusted like the D-Bus
    /// addresses, and only a `unix:path=` address names a socket bubbler
    /// can proxy.
    pub at_spi_bus_address: Option<OsString>,
    /// `$BUBBLER_DBUS_LOG=1`: run the D-Bus proxy with `--log`, which
    /// prints every filtered message to bubbler's stderr.
    pub dbus_log: bool,
    /// `$BUBBLER_NET_PROXY_LOG=1`: run the egress proxy with
    /// `--log-tunnels`, so every tunnel it opens is printed to bubbler's
    /// stderr; refusals are printed regardless.
    pub net_proxy_log: bool,
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
    /// `$BUBBLER_PASTA`: host path of the pasta binary to run instead of
    /// the one on `PATH`, for an isolated `network`. A test and debugging
    /// hook, like `$BUBBLER_DBUS_PROXY`; nothing shipped sets it.
    pub pasta_override: Option<PathBuf>,
    /// `$BUBBLER_WL_PROXY`: host path of the Wayland proxy binary to run
    /// instead of the installed one, which is what a build tree runs its
    /// own from. A test and debugging hook; it must be a regular file.
    pub wl_proxy_override: Option<PathBuf>,
    /// `$BUBBLER_NET_PROXY`: host path of the egress proxy binary to run
    /// instead of the installed one, for a sandbox with an
    /// `allow-host`. A test and debugging hook, like
    /// `$BUBBLER_WL_PROXY`; it must be a regular file.
    pub net_proxy_override: Option<PathBuf>,
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
            "PATH",
            "HOME",
            "DISPLAY",
            "TERMINFO",
            "lc_all",
            "XLC_ALL",
            "",
            // A token the session issued to bubbler activates a window
            // in that session; nothing inside the sandbox may hold one.
            "XDG_ACTIVATION_TOKEN",
        ] {
            assert!(!is_passthrough(OsStr::new(no)), "{no}");
        }
        assert!(!is_passthrough(OsStr::from_bytes(b"LC\xff")));
    }

    #[test]
    fn a_relative_data_directory_is_ignored_and_only_an_unset_list_defaults() {
        let default: Vec<PathBuf> = DEFAULT_DATA_DIRS.iter().map(PathBuf::from).collect();
        assert_eq!(xdg_dirs(None, DEFAULT_DATA_DIRS), default);
        assert_eq!(
            xdg_dirs(Some(OsString::from("")), DEFAULT_DATA_DIRS),
            default
        );
        assert_eq!(
            xdg_dirs(
                Some(OsString::from("/opt/share:share:../share::/usr/share")),
                DEFAULT_DATA_DIRS
            ),
            vec![PathBuf::from("/opt/share"), PathBuf::from("/usr/share")],
            "a relative or empty entry is dropped, the absolute ones kept in order"
        );
        // A list that names nothing absolute names nowhere to look. The
        // defaults are for a variable nobody set, not for one whose every
        // entry the specification says to ignore.
        assert!(xdg_dirs(Some(OsString::from("share:../share")), DEFAULT_DATA_DIRS).is_empty());
        assert!(xdg_dirs(Some(OsString::from(":")), DEFAULT_DATA_DIRS).is_empty());
    }
}
