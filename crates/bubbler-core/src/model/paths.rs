//! Where an instance's runtime state lives under `$XDG_RUNTIME_DIR`: the
//! directory layout every layer agrees on, as path joins and nothing else.

use std::path::{Path, PathBuf};

use crate::env::Env;

/// The one directory bubbler owns under `$XDG_RUNTIME_DIR`, holding every instance's runtime
/// state; a host bus address resolving into it is refused.
pub const RUNTIME_SUBDIR: &str = "bubbler";

/// `$XDG_RUNTIME_DIR/bubbler/<name>`: an instance's runtime state on the
/// host. `name` is an instance name the caller has already validated.
pub fn instance_runtime_dir(env: &Env, name: &str) -> PathBuf {
    env.runtime_dir.join(RUNTIME_SUBDIR).join(name)
}

/// `@` is no character of an instance name, so the lock file is no instance's runtime directory.
pub(crate) const START_LOCK_SUFFIX: &str = "@start.lock";

/// The lock a start holds from its liveness check through its bind, beside the runtime
/// directory so removing that leaves it. Only a throwaway sandbox removes its own: a lock on an
/// unlinked file is one nobody else sees.
pub(crate) fn start_lock_path(env: &Env, name: &str) -> PathBuf {
    env.runtime_dir
        .join(RUNTIME_SUBDIR)
        .join(format!("{name}{START_LOCK_SUFFIX}"))
}

/// Name of the control socket inside an instance's runtime directory.
pub const SOCKET_NAME: &str = "init.sock";

/// `$XDG_RUNTIME_DIR/bubbler/<name>/init.sock`. `name` is an instance
/// name the caller has already validated.
pub fn socket_path(env: &Env, name: &str) -> PathBuf {
    env.runtime_dir
        .join(RUNTIME_SUBDIR)
        .join(name)
        .join(SOCKET_NAME)
}

/// Name of the log inside the instance directory.
pub const LOG_FILE: &str = "last-run.log";

/// The log of the instance whose directory is `dir`.
pub fn log_path(dir: &Path) -> PathBuf {
    dir.join(LOG_FILE)
}

/// File name of the session bus socket, in the proxy's directory and in
/// the instance's after the launcher moves it.
pub const SESSION_SOCKET: &str = "bus";

/// File name of the system bus socket, in the same two directories.
pub const SYSTEM_SOCKET: &str = "system";

/// The only directory the proxy sandbox may write to. The instance
/// directory above it is never handed to the proxy: it holds the control
/// socket, and reaching that socket means running commands in the app.
pub fn socket_dir(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join("dbus")
}

/// Where the proxy creates one filtered socket, in [`socket_dir`]: the
/// one path the proxy sandbox can write to. `socket` is [`SESSION_SOCKET`],
/// [`SYSTEM_SOCKET`] or [`crate::dbus::A11Y_SOCKET`].
pub fn proxy_bus_path(instance_runtime: &Path, socket: &str) -> PathBuf {
    socket_dir(instance_runtime).join(socket)
}

/// Where a sandbox's bus bind comes from: the socket after the launcher
/// has checked it and moved it out of [`socket_dir`]. The proxy cannot
/// reach this path, so nothing can be swapped for it once it is there.
pub fn app_bus_path(instance_runtime: &Path, socket: &str) -> PathBuf {
    instance_runtime.join(socket)
}
