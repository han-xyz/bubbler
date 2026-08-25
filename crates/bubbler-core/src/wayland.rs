//! Registering a sandbox with the compositor through
//! `wp_security_context_v1` (wayland-protocols staging,
//! `security-context-v1.xml`).
//!
//! A sandbox engine binds and listens on a socket of its own, hands the
//! compositor that listening fd plus metadata (engine, application id,
//! instance id), and binds the socket into the sandbox instead of the
//! session's. Clients arriving on it are marked as sandboxed, and the
//! compositor withholds the privileged globals — screen capture,
//! clipboard management, input injection, overlays, window management —
//! from them. Which globals those are is the compositor's policy, not
//! bubbler's; bubbler only attaches the metadata.
//!
//! The two fds of `create_listener`, per the protocol:
//! - `listen_fd` must already be `bind(2)`-ed and `listen(2)`-ing when
//!   the request is sent, and the compositor keeps accepting on it after
//!   the client that created the context disconnects.
//! - `close_fd` tells the compositor to stop accepting when it signals
//!   hangup, so the write end of a pipe held for the run's lifetime ends
//!   the context when the run ends.
//!
//! Metadata is set at most once each and nothing but `destroy` may
//! follow `commit`, so
//! the handshake is one-shot: bind the manager, create the listener, set
//! the three strings, commit, destroy, roundtrip.
//!
//! [`probe`] and [`create_context`] connect over `$WAYLAND_DISPLAY` in
//! `$XDG_RUNTIME_DIR`, which wayrs reads from the process environment
//! itself. Nothing here can check that value, so the launcher validates
//! its shape — one path component — before calling in; an absolute or
//! `..` name would otherwise steer the connection, and the listening fd
//! with it, at an endpoint of the caller's choosing.
//!
//! wayrs also honours `$WAYLAND_SOCKET`, a connection *file descriptor*
//! inherited from a parent, which it adopts and closes with the
//! connection — a number that may well be a descriptor this process is
//! using for something else. The launcher refuses to run rather than
//! connect that way; see [`refuse_inherited`].

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use thiserror::Error;
use wayrs_client::proxy::Proxy;
use wayrs_client::{ConnectError, Connection};
use wayrs_protocols::security_context_v1::WpSecurityContextManagerV1;

use crate::config::WaylandMode;

/// Sandbox engine name bubbler identifies itself to compositors by. It
/// pairs with the application id: the two together name an application.
pub const ENGINE: &str = "org.bubbler";

/// File name of bubbler's own listening socket under the instance's
/// runtime directory. The name inside the sandbox is the host's
/// `$WAYLAND_DISPLAY`; this one is never seen by the application.
pub const SOCKET_NAME: &str = "wayland";

/// Which Wayland socket a run binds into the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaylandPlan {
    /// bubbler's own listening socket, registered with the compositor as
    /// a security context, so the sandbox is a restricted client.
    Context {
        /// Host path of the socket the launcher binds and listens on.
        socket: PathBuf,
    },
    /// The session's own socket, with every global the compositor
    /// offers, and why it came to that.
    Raw {
        /// What made this a raw socket rather than a security context.
        reason: RawReason,
    },
}

/// Why a run binds the session socket rather than a security context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawReason {
    /// The configuration asked for it with `wayland "host"`.
    ConfigHost,
    /// The compositor offers no `wp_security_context_manager_v1`, so
    /// there is nothing to register with.
    NoManager,
}

/// Failures of the security-context handshake, named by the step that
/// failed so the launcher can say what bubbler was doing.
#[derive(Debug, Error)]
pub enum WaylandError {
    /// No connection to the compositor: the environment names none, or
    /// the socket refused it.
    // No `{source}` in the message: the cause is chained below, and
    // printing it here too shows it twice.
    #[error("connecting to the compositor at {display}")]
    Connect {
        /// What `$WAYLAND_DISPLAY` named when the attempt was made, or
        /// the literal `$WAYLAND_DISPLAY` when it was unset.
        display: String,
        /// What the connection attempt failed with.
        #[source]
        source: io::Error,
    },
    /// The compositor does not implement the protocol. Not an error on
    /// its own — the launcher falls back to the session socket — but
    /// [`create_context`] reports it, since by then the global was
    /// expected to be there.
    #[error("the compositor offers no wp_security_context_manager_v1")]
    NoManager,
    /// The compositor rejected the handshake, or the metadata could not
    /// be put on the wire.
    #[error("registering the security context: {0}")]
    Protocol(String),
    /// The listening socket the compositor is to accept on could not be
    /// created. Raised by the launcher, which binds it.
    #[error("creating the listening socket {0}")]
    Listen(PathBuf, #[source] io::Error),
    /// The pipe whose hangup ends the context could not be created.
    /// Raised by the launcher, which holds its write end.
    #[error("creating the pipe that ends the security context")]
    Pipe(#[source] io::Error),
    /// A compositor connection was inherited through `$WAYLAND_SOCKET`.
    /// bubbler refuses it rather than let wayrs adopt a descriptor
    /// number this process may already be using for the run's own files.
    #[error(
        "$WAYLAND_SOCKET is set; bubbler must be started without an inherited compositor connection"
    )]
    InheritedSocket,
}

impl WaylandError {
    // Every connection failure is tagged with the display the process
    // environment named, since that is the input the user can act on.
    fn connect(source: io::Error) -> Self {
        let display = std::env::var_os("WAYLAND_DISPLAY").map_or_else(
            || "$WAYLAND_DISPLAY".to_owned(),
            |d| d.to_string_lossy().into_owned(),
        );
        Self::Connect { display, source }
    }
}

impl From<ConnectError> for WaylandError {
    fn from(e: ConnectError) -> Self {
        Self::connect(match e {
            ConnectError::NotEnoughEnvVars => {
                io::Error::other("WAYLAND_DISPLAY or XDG_RUNTIME_DIR unset")
            }
            ConnectError::Io(e) => e,
        })
    }
}

/// Where a run's own listening socket goes: [`SOCKET_NAME`] under the
/// instance's runtime directory, which only bubbler can write to.
pub fn socket_path(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join(SOCKET_NAME)
}

/// Refuses an inherited compositor connection, given whatever
/// `$WAYLAND_SOCKET` holds. wayrs would take the value as a descriptor
/// number, use it as the connection and close it when the connection
/// drops; nothing says that descriptor is not one this run opened for
/// itself, and a closed control socket is a broken run.
pub fn refuse_inherited(socket: Option<&OsStr>) -> Result<(), WaylandError> {
    match socket {
        Some(_) => Err(WaylandError::InheritedSocket),
        None => Ok(()),
    }
}

/// Which socket a run binds, from the configured mode and what [`probe`]
/// found. `manager_present` is `None` when nothing asked the compositor
/// — `--dry-run` and `--explain` never connect — and the answer is then
/// the security context, which is what a real run builds on a compositor
/// that supports it.
pub fn plan(
    mode: WaylandMode,
    manager_present: Option<bool>,
    instance_runtime: &Path,
) -> WaylandPlan {
    match (mode, manager_present) {
        (WaylandMode::Host, _) => WaylandPlan::Raw {
            reason: RawReason::ConfigHost,
        },
        (WaylandMode::Sandboxed, Some(false)) => WaylandPlan::Raw {
            reason: RawReason::NoManager,
        },
        (WaylandMode::Sandboxed, Some(true) | None) => WaylandPlan::Context {
            socket: socket_path(instance_runtime),
        },
    }
}

/// Whether the compositor offers `wp_security_context_manager_v1`, by
/// connecting and reading the registry once. Grants nothing; a failure
/// here means there is no compositor to talk to at all.
pub fn probe() -> Result<bool, WaylandError> {
    let mut conn = Connection::<()>::connect()?;
    conn.blocking_roundtrip().map_err(WaylandError::connect)?;
    let manager = WpSecurityContextManagerV1::INTERFACE.name;
    Ok(conn
        .globals()
        .iter()
        .any(|g| g.interface.as_c_str() == manager))
}

/// Registers `listener` with the compositor as a security context for
/// `app_id`/`instance_id` under engine [`ENGINE`], so clients that
/// connect through it are sandboxed ones.
///
/// `listener` must already be listening. The compositor keeps accepting
/// on it after this call returns and bubbler's connection is dropped,
/// until `close_fd` signals hangup — the caller holds its write end for
/// as long as the sandbox may connect.
pub fn create_context(
    listener: OwnedFd,
    close_fd: OwnedFd,
    app_id: &str,
    instance_id: &str,
) -> Result<(), WaylandError> {
    let mut conn = Connection::<()>::connect()?;
    conn.blocking_roundtrip().map_err(WaylandError::connect)?;
    let manager = conn
        .bind_singleton::<WpSecurityContextManagerV1>(1..=1)
        .map_err(|_| WaylandError::NoManager)?;
    let ctx = manager.create_listener(&mut conn, listener, close_fd);
    let cstr = |s: &str| CString::new(s).map_err(|e| WaylandError::Protocol(e.to_string()));
    ctx.set_sandbox_engine(&mut conn, cstr(ENGINE)?);
    ctx.set_app_id(&mut conn, cstr(app_id)?);
    ctx.set_instance_id(&mut conn, cstr(instance_id)?);
    ctx.commit(&mut conn);
    ctx.destroy(&mut conn);
    manager.destroy(&mut conn);
    // The requests are only queued until something flushes them, and this
    // roundtrip is where the compositor's verdict comes back: a rejected
    // fd, rejected metadata or a nested context arrives as `wl_display.error`,
    // which wayrs raises out of the roundtrip. The connection stood, so
    // that is a protocol failure, not a connection one.
    conn.blocking_roundtrip()
        .map_err(|e| WaylandError::Protocol(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WaylandMode;
    use std::path::Path;

    #[test]
    fn plan_follows_mode_and_probe() {
        let rt = Path::new("/run/user/1000/bubbler/t");
        assert!(matches!(
            plan(WaylandMode::Host, Some(true), rt),
            WaylandPlan::Raw {
                reason: RawReason::ConfigHost
            }
        ));
        assert!(matches!(
            plan(WaylandMode::Sandboxed, Some(false), rt),
            WaylandPlan::Raw {
                reason: RawReason::NoManager
            }
        ));
        for probe in [Some(true), None] {
            match plan(WaylandMode::Sandboxed, probe, rt) {
                WaylandPlan::Context { socket } => assert_eq!(socket, rt.join("wayland")),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn connect_errors_carry_their_cause() {
        let e = WaylandError::from(ConnectError::NotEnoughEnvVars);
        assert!(e.to_string().contains("connecting to the compositor at"));
        let cause = std::error::Error::source(&e).expect("Connect chains its cause");
        assert!(
            cause
                .to_string()
                .contains("WAYLAND_DISPLAY or XDG_RUNTIME_DIR unset")
        );

        let e = WaylandError::from(ConnectError::Io(io::Error::other("boom")));
        let cause = std::error::Error::source(&e).expect("Connect chains its cause");
        assert!(cause.to_string().contains("boom"));
    }

    #[test]
    fn errors_name_the_step() {
        let e = WaylandError::NoManager;
        assert!(e.to_string().contains("wp_security_context_manager_v1"));
        let e = WaylandError::Listen("/x".into(), std::io::Error::other("boom"));
        assert!(e.to_string().contains("/x"));
        let e = WaylandError::Pipe(std::io::Error::other("boom"));
        assert!(e.to_string().contains("ends the security context"));
    }

    /// The value is not read here but passed in, so the rule can be
    /// tested without a process-wide environment a parallel test shares.
    #[test]
    fn an_inherited_connection_is_refused() {
        assert!(refuse_inherited(None).is_ok());
        for set in ["", "5", "not a number"] {
            let e = refuse_inherited(Some(OsStr::new(set)))
                .expect_err("$WAYLAND_SOCKET set at all is a refusal");
            assert!(matches!(e, WaylandError::InheritedSocket), "{e:?}");
            assert!(e.to_string().contains("$WAYLAND_SOCKET is set"));
        }
    }
}
