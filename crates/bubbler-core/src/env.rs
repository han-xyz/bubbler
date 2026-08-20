//! Host environment facts needed to build a sandbox. Filled in by the
//! binary so the library never reads process environment itself.

use std::ffi::OsString;
use std::path::PathBuf;

/// Path of the private home inside every sandbox. Fixed so the real
/// username never leaks into the sandbox.
pub const SANDBOX_HOME: &str = "/home/bubbler";

/// Environment variables copied from the host into the sandbox when set.
/// Locale and terminal only; nothing that points at host paths.
pub const PASSTHROUGH_VARS: &[&str] = &["TERM", "LANG", "LANGUAGE", "COLORTERM", "TZ"];

/// Host-side facts the builder and services need.
#[derive(Debug, Clone)]
pub struct Env {
    /// Real `$HOME`; source of `home-share` paths.
    pub home: PathBuf,
    /// `$XDG_DATA_HOME` (or `$HOME/.local/share`); instances live under it.
    pub data_home: PathBuf,
    /// `$XDG_RUNTIME_DIR`; required, sockets live here.
    pub runtime_dir: PathBuf,
    /// `$WAYLAND_DISPLAY` if set.
    pub wayland_display: Option<OsString>,
    /// `$DISPLAY` if set.
    pub display: Option<OsString>,
    /// `$XAUTHORITY` if set.
    pub xauthority: Option<PathBuf>,
    /// Already-filtered `(name, value)` pairs from [`PASSTHROUGH_VARS`]
    /// (and `LC_*`) that were set on the host.
    pub passthrough: Vec<(OsString, OsString)>,
}
