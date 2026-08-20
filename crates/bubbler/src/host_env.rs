//! Reads the process environment once and turns it into `bubbler_core::env::Env`.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result};
use bubbler_core::env::{Env, is_passthrough};

/// Build an [`Env`] from the current process environment. A missing or
/// empty `$HOME` or `$XDG_RUNTIME_DIR` is an error: both are needed for
/// any sandbox, and an empty one would silently become a relative path.
/// `$BUBBLER_INIT` overrides where the `bubbler-init` binary is taken from.
pub fn from_process() -> Result<Env> {
    let home = PathBuf::from(
        env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .context("HOME is not set")?,
    );
    let data_home = env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    let runtime_dir = PathBuf::from(
        env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .context("XDG_RUNTIME_DIR is not set; a session manager should set it")?,
    );
    let passthrough: Vec<(OsString, OsString)> =
        env::vars_os().filter(|(k, _)| is_passthrough(k)).collect();
    Ok(Env {
        home,
        data_home,
        runtime_dir,
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        wayland_display: env::var_os("WAYLAND_DISPLAY").filter(|v| !v.is_empty()),
        display: env::var_os("DISPLAY").filter(|v| !v.is_empty()),
        xauthority: env::var_os("XAUTHORITY")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from),
        passthrough,
        init_override: env::var_os("BUBBLER_INIT")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from),
    })
}

/// The user's editor: `$VISUAL`, else `$EDITOR`. An empty value counts as
/// unset, so it does not turn into an argv with a blank program.
pub fn editor() -> Option<OsString> {
    env::var_os("VISUAL")
        .filter(|v| !v.is_empty())
        .or_else(|| env::var_os("EDITOR").filter(|v| !v.is_empty()))
}
