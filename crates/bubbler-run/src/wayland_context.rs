//! Registering a sandbox with the compositor through
//! `wp_security_context_v1` (wayland-protocols staging,
//! `security-context-v1.xml`).
//!
//! [`probe`] and [`create_context`] connect over `$WAYLAND_DISPLAY` in
//! `$XDG_RUNTIME_DIR`, which wayrs reads from the process environment
//! itself. Nothing here can check that value, so the launcher validates
//! its shape — one path component — before calling in.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use thiserror::Error;
use wayrs_client::proxy::Proxy;
use wayrs_client::{ConnectError, Connection};
use wayrs_protocols::security_context_v1::WpSecurityContextManagerV1;

use crate::wayland::ENGINE;

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
    /// The proxy sidecar did not report that it is accepting
    /// connections, so the application would connect to a socket nothing
    /// is listening on. The string says what happened to it instead.
    #[error("bubbler-wl-proxy did not start; {0}")]
    ProxyNotReady(String),
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

/// Refuses an inherited compositor connection, given whatever
/// `$WAYLAND_SOCKET` holds.
pub(crate) fn refuse_inherited(socket: Option<&OsStr>) -> Result<(), WaylandError> {
    match socket {
        Some(_) => Err(WaylandError::InheritedSocket),
        None => Ok(()),
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
