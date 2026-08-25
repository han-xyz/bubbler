//! The host facts this process needs, read from its environment once.
//!
//! Only what reading the instance store takes: the editor never builds a
//! sandbox, it hands every launch to the `bubbler` binary, which reads
//! its own environment for the rest.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result};
use bubbler_core::env::{DEFAULT_DATA_DIRS, Env};

/// Build an [`Env`] from the current process environment. A missing or
/// empty `$HOME` or `$XDG_RUNTIME_DIR` is an error for the same reason it
/// is one in the CLI: the instance store and the control sockets hang off
/// them, and an empty one would silently become a relative path.
///
/// The fields a sandbox is built from — the display sockets, the bus
/// addresses, the binary overrides — are left unset: nothing here builds
/// one, and a value read but never used is a claim this process cannot
/// keep.
pub fn from_process() -> Result<Env> {
    let home = PathBuf::from(
        env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .context("HOME is not set")?,
    );
    let data_home = var_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
    let config_home = var_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    let data_dirs: Vec<PathBuf> = env::var_os("XDG_DATA_DIRS")
        .filter(|v| !v.is_empty())
        .map(|v| {
            env::split_paths(&v)
                .filter(|d| !d.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_else(|| DEFAULT_DATA_DIRS.iter().map(PathBuf::from).collect());
    let runtime_dir = var_path("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR is not set; a session manager should set it")?;
    Ok(Env {
        home,
        data_home,
        config_home,
        data_dirs,
        runtime_dir,
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        wayland_display: None,
        display: None,
        xauthority: None,
        passthrough: vec![],
        init_override: None,
        dbus_address: None,
        dbus_system_address: None,
        at_spi_bus_address: None,
        dbus_log: false,
        seccomp_log: false,
        test_allow_path: None,
        profile_dir_override: var_path("BUBBLER_PROFILE_DIR"),
        proxy_override: None,
        pasta_override: None,
        wl_proxy_override: None,
    })
}

/// One environment variable as a path, where an empty value counts as
/// unset: an empty one would be the current directory, which is not what
/// any of these name.
fn var_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `$PATH` split into directories, which is where the `bubbler` binary is
/// looked for when it is not beside this one.
pub fn search_path() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|p| {
            env::split_paths(&p)
                .filter(|d| !d.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The shell an `exec` starts by default: `$SHELL`, else `/bin/sh`. It is
/// run as a program, never through a shell, so a value with arguments in
/// it is a program name with spaces and fails as one.
pub fn shell() -> OsString {
    env::var_os("SHELL")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| OsString::from("/bin/sh"))
}
