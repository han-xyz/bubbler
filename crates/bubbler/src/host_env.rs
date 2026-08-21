//! Reads the process environment once and turns it into `bubbler_core::env::Env`.

use std::env;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bubbler_core::env::{Env, is_passthrough};
use rustix::fs::{Mode, OFlags};
use rustix::io::fcntl_getfd;

/// Open `/dev/null` onto any of fds 0, 1 and 2 this process was started
/// without, so a sandbox told to inherit "bubbler's stdout" can never be
/// handed whatever bubbler opened into that slot instead. Must run before
/// anything else opens a descriptor: the kernel hands out the lowest free
/// number, so each open lands exactly in the gap it is meant for.
///
/// The Rust runtime already does this on Linux (`sanitize_standard_fds`),
/// verified by removing this call and finding `/dev/null` on the
/// sandbox's stdout all the same. It stays because the guarantee the
/// terminal plan rests on should be bubbler's own and visible, not an
/// implementation detail of the runtime it happens to be built with.
pub fn fill_closed_stdio() -> Result<()> {
    // The std handles name fds 0, 1 and 2 whether or not they are open, so
    // the probe needs no raw descriptor of its own.
    let present = [
        fcntl_getfd(io::stdin().as_fd()).is_ok(),
        fcntl_getfd(io::stdout().as_fd()).is_ok(),
        fcntl_getfd(io::stderr().as_fd()).is_ok(),
    ];
    for (i, present) in present.iter().enumerate() {
        if *present {
            continue;
        }
        // No CLOEXEC: this is standard input or output, and every child
        // that inherits it must keep it.
        let fd = rustix::fs::open(Path::new("/dev/null"), OFlags::RDWR, Mode::empty())
            .context("opening /dev/null for a closed standard descriptor")?;
        // Filling the gaps in order means each open lands on its own
        // number; anything else and the slot is left as it was found.
        if fd.as_raw_fd() == i as RawFd {
            // Leaked on purpose: it is this process's fd `i` from here on.
            std::mem::forget(fd);
        }
    }
    Ok(())
}

/// Build an [`Env`] from the current process environment. A missing or
/// empty `$HOME` or `$XDG_RUNTIME_DIR` is an error: both are needed for
/// any sandbox, and an empty one would silently become a relative path.
/// `$BUBBLER_INIT` and `$BUBBLER_DBUS_PROXY` override where the
/// `bubbler-init` and `xdg-dbus-proxy` binaries are taken from.
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
        dbus_address: env::var_os("DBUS_SESSION_BUS_ADDRESS").filter(|v| !v.is_empty()),
        dbus_log: env::var_os("BUBBLER_DBUS_LOG").is_some_and(|v| v == "1"),
        seccomp_log: env::var_os("BUBBLER_SECCOMP_LOG").is_some_and(|v| v == "1"),
        test_allow_path: test_allow_path()?,
        proxy_override: env::var_os("BUBBLER_DBUS_PROXY")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from),
    })
}

/// `$BUBBLER_TEST_ALLOW_PATH`: the one extra root `path-share` accepts,
/// at both ends of a share, for tests and debugging. It must be absolute
/// and not `/`, and is resolved here so it compares against the canonical
/// source; a path that does not exist is kept as written and therefore
/// matches nothing.
fn test_allow_path() -> Result<Option<PathBuf>> {
    let Some(value) = env::var_os("BUBBLER_TEST_ALLOW_PATH").filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        anyhow::bail!(
            "BUBBLER_TEST_ALLOW_PATH must be an absolute path, not `{}`",
            path.display()
        );
    }
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    // `/` would allow every share the denylist exists to refuse, which is
    // more than a debugging hook is ever meant to hand out.
    if path == Path::new("/") {
        anyhow::bail!("BUBBLER_TEST_ALLOW_PATH cannot be `/`");
    }
    Ok(Some(path))
}

/// The user's editor: `$VISUAL`, else `$EDITOR`. An empty value counts as
/// unset, so it does not turn into an argv with a blank program.
pub fn editor() -> Option<OsString> {
    env::var_os("VISUAL")
        .filter(|v| !v.is_empty())
        .or_else(|| env::var_os("EDITOR").filter(|v| !v.is_empty()))
}
