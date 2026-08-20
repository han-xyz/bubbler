//! Reads the process environment once and turns it into `bubbler_core::env::Env`.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result};
use bubbler_core::env::{Env, PASSTHROUGH_VARS};

/// Build an [`Env`] from the current process environment. Missing `$HOME`
/// or `$XDG_RUNTIME_DIR` are errors: both are needed for any sandbox.
pub fn from_process() -> Result<Env> {
    let home = PathBuf::from(env::var_os("HOME").context("HOME is not set")?);
    let data_home = env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    let runtime_dir = PathBuf::from(
        env::var_os("XDG_RUNTIME_DIR")
            .context("XDG_RUNTIME_DIR is not set; a session manager should set it")?,
    );
    let passthrough: Vec<(OsString, OsString)> = env::vars_os()
        .filter(|(k, _)| {
            let k = k.to_string_lossy();
            PASSTHROUGH_VARS.contains(&k.as_ref()) || k.starts_with("LC_")
        })
        .collect();
    Ok(Env {
        home,
        data_home,
        runtime_dir,
        wayland_display: env::var_os("WAYLAND_DISPLAY").filter(|v| !v.is_empty()),
        display: env::var_os("DISPLAY").filter(|v| !v.is_empty()),
        xauthority: env::var_os("XAUTHORITY")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from),
        passthrough,
    })
}
