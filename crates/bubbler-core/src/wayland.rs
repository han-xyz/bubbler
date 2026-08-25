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

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use thiserror::Error;
use wayrs_client::proxy::Proxy;
use wayrs_client::{ConnectError, Connection};
use wayrs_protocols::security_context_v1::WpSecurityContextManagerV1;

use crate::config::{Clipboard, WaylandMode};
use crate::env::Env;
use crate::error::LaunchError;
use crate::host::Host;
use crate::init_bin::{self, Found};

/// Sandbox engine name bubbler identifies itself to compositors by. It
/// pairs with the application id: the two together name an application.
pub const ENGINE: &str = "org.bubbler";

/// File name of the socket the application connects to, under the
/// instance's runtime directory. bubbler's own proxy accepts on it; the
/// name inside the sandbox is the host's `$WAYLAND_DISPLAY`, and this
/// one is never seen by the application.
pub const SOCKET_NAME: &str = "wayland";

/// File name of the socket the compositor accepts on as this run's
/// security context, beside [`SOCKET_NAME`]. Only the proxy connects to
/// it: the application reaches the compositor through the proxy, which
/// is where the clipboard gate applies.
pub const CONTEXT_SOCKET_NAME: &str = "wayland-context";

/// File name of the proxy binary.
pub const PROXY_NAME: &str = "bubbler-wl-proxy";

/// Where the Wayland proxy is installed, beside `bubbler-init`. Not a
/// `PATH` name like the D-Bus proxy's: the binary is bubbler's own, and
/// a run must not pick up whatever else on a `PATH` answers to the name.
pub const PROXY_BIN: &str = "/usr/lib/bubbler/bubbler-wl-proxy";

// The proxy's own file rather than a copy kept in step by hand: a name
// in one list and not the other would be a global core calls hidden and
// the proxy forwards.
include!("../../bubbler-wl-proxy/src/privileged.rs");

/// Host path of the proxy binary and where it was found:
/// [`Env::wl_proxy_override`] (`$BUBBLER_WL_PROXY`), else next to the
/// running executable, else [`PROXY_BIN`]. The same lookup
/// `bubbler-init` gets, and for the same reason: a build tree runs what
/// it just built without being told where it is.
///
/// The [`Found`] half is what says whether the sidecar's sandbox has to
/// bind the binary in. A run cannot go on without one — the application
/// would connect to a socket nothing accepts on — so a missing binary
/// fails the launch rather than warning.
pub fn locate_proxy(env: &Env, host: &dyn Host) -> Result<(PathBuf, Found), LaunchError> {
    init_bin::locate_binary(
        env.wl_proxy_override.as_deref(),
        PROXY_NAME,
        PROXY_BIN,
        "wayland",
        host,
    )
}

/// Which Wayland socket a run binds into the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaylandPlan {
    /// bubbler's own listening socket, which its Wayland proxy accepts
    /// the application on. What the proxy connects to in turn — the
    /// security-context socket, or the session's where the compositor
    /// offers no context — is [`ProxyPlan`] and no concern of the
    /// sandbox's: either way the application sees this one socket.
    Proxy {
        /// Host path of the socket the proxy accepts on.
        socket: PathBuf,
    },
    /// The session's own socket, with every global the compositor
    /// offers and no proxy in front of it, because the configuration
    /// asked for it (`wayland "host"`).
    Host,
}

/// How the Wayland proxy is run for one instance: which socket it
/// accepts the application on, which it connects to for it, and what it
/// does with a clipboard read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPlan {
    /// Host path the application connects to, which the sandbox binds
    /// at the host's display name.
    pub listener: PathBuf,
    /// Host path the proxy connects to on the application's behalf.
    pub upstream: PathBuf,
    /// Whether the compositor accepts on `upstream` as a security
    /// context. Without one the proxy hides the privileged globals
    /// itself, which is what `--fallback-deny` asks of it.
    pub context: bool,
    /// Whether a clipboard read has to follow input of the user's.
    pub clipboard: Clipboard,
}

impl ProxyPlan {
    /// The plan for a compositor that took the security context: the
    /// proxy connects to [`CONTEXT_SOCKET_NAME`], which the compositor
    /// accepts on, and the compositor withholds the privileged globals
    /// by itself.
    pub fn context(instance_runtime: &Path, clipboard: Clipboard) -> Self {
        Self {
            listener: socket_path(instance_runtime),
            upstream: context_socket_path(instance_runtime),
            context: true,
            clipboard,
        }
    }

    /// The plan for a compositor that offers no
    /// `wp_security_context_manager_v1`: the proxy connects to the
    /// session's own socket at `session` and applies bubbler's own
    /// [`PRIVILEGED`] denylist in the compositor's place.
    pub fn fallback(instance_runtime: &Path, session: PathBuf, clipboard: Clipboard) -> Self {
        Self {
            listener: socket_path(instance_runtime),
            upstream: session,
            context: false,
            clipboard,
        }
    }

    /// What the gate is called on the proxy's command line.
    pub fn gate(&self) -> &'static str {
        match self.clipboard {
            Clipboard::Paste => "paste",
            Clipboard::Open => "open",
        }
    }

    /// The proxy's own argv, `program` first, each element with the
    /// index of the `wayland` node behind it or `None` where it is the
    /// invocation itself. `listen_fd` numbers the listening socket the
    /// proxy adopts and accepts on, `ready_fd` the pipe it writes one
    /// byte to once it is listening.
    ///
    /// `--log-fd 2` is the proxy's own stderr, which is bubbler's: an
    /// audit line belongs in the run's log beside everything else the
    /// run said.
    pub fn command_nodes(
        &self,
        program: &Path,
        node: usize,
        listen_fd: &OsStr,
        ready_fd: &OsStr,
    ) -> Vec<(OsString, Option<usize>)> {
        let o = |s: &str| OsString::from(s);
        let mut argv = vec![
            (program.as_os_str().to_os_string(), None),
            (o("--listen-fd"), None),
            (listen_fd.to_os_string(), None),
            (o("--upstream"), None),
            (self.upstream.clone().into_os_string(), None),
            // The one element of the invocation a node decides.
            (o("--gate"), Some(node)),
            (o(self.gate()), Some(node)),
        ];
        if !self.context {
            argv.push((o("--fallback-deny"), None));
        }
        for arg in ["--log-fd", "2", "--ready-fd"] {
            argv.push((o(arg), None));
        }
        argv.push((ready_fd.to_os_string(), None));
        argv
    }
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

/// Where a run's own listening socket goes: [`SOCKET_NAME`] under the
/// instance's runtime directory, which only bubbler can write to.
pub fn socket_path(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join(SOCKET_NAME)
}

/// Where the socket the compositor accepts on goes:
/// [`CONTEXT_SOCKET_NAME`] beside [`socket_path`], in the same
/// directory only bubbler can write to.
pub fn context_socket_path(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join(CONTEXT_SOCKET_NAME)
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

/// Which socket a run binds, from the configured mode alone. What the
/// compositor answered about `wp_security_context_manager_v1` does not
/// enter into it: a sandboxed `wayland` connects to bubbler's proxy
/// either way, and the answer decides only what the proxy connects to.
pub fn plan(mode: WaylandMode, instance_runtime: &Path) -> WaylandPlan {
    match mode {
        WaylandMode::Host => WaylandPlan::Host,
        WaylandMode::Sandboxed { .. } => WaylandPlan::Proxy {
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
    use crate::config::{Clipboard, WaylandMode};
    use std::path::Path;

    fn env(wl_proxy_override: Option<PathBuf>) -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            config_home: "/home/han/.config".into(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
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
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            wl_proxy_override,
        }
    }

    #[test]
    fn an_override_wins_and_must_be_a_regular_file() {
        let (file, dir, _) = crate::host::fake::types();
        let host = crate::host::fake::FakeHost::default()
            .with("/build/bubbler-wl-proxy", file)
            .with("/build/adir", dir);
        assert_eq!(
            locate_proxy(&env(Some("/build/bubbler-wl-proxy".into())), &host).unwrap(),
            (PathBuf::from("/build/bubbler-wl-proxy"), Found::Override)
        );
        assert!(matches!(
            locate_proxy(&env(Some("/build/adir".into())), &host),
            Err(LaunchError::WrongType {
                service: "wayland",
                expected: "a regular file",
                ..
            })
        ));
        assert!(matches!(
            locate_proxy(&env(Some("/build/gone".into())), &host),
            Err(LaunchError::MissingResource {
                service: "wayland",
                ..
            })
        ));
    }

    /// A run cannot serve the grant without the binary, so the last
    /// resort failing is a failed launch and not a warning.
    #[test]
    fn without_an_override_the_installed_path_is_the_last_resort() {
        let (file, _, _) = crate::host::fake::types();
        let host = crate::host::fake::FakeHost::default().with(PROXY_BIN, file);
        assert_eq!(
            locate_proxy(&env(None), &host).unwrap(),
            (PathBuf::from(PROXY_BIN), Found::Installed)
        );
        assert!(matches!(
            locate_proxy(&env(None), &crate::host::fake::FakeHost::default()),
            Err(LaunchError::MissingResource { service: "wayland", path }) if path == Path::new(PROXY_BIN)
        ));
    }

    /// A build tree runs what it just built: the copy beside the running
    /// `bubbler` wins over an installed one, so nothing has to be told
    /// where it is.
    #[test]
    fn a_sibling_of_the_running_binary_is_preferred_over_the_installed_one() {
        let (file, _, _) = crate::host::fake::types();
        let sibling = std::env::current_exe()
            .expect("a test binary has a path")
            .parent()
            .expect("and a directory")
            .join(PROXY_NAME);
        let host = crate::host::fake::FakeHost::default()
            .with(&sibling.to_string_lossy(), file)
            .with(PROXY_BIN, file);
        assert_eq!(
            locate_proxy(&env(None), &host).unwrap(),
            (sibling, Found::Sibling)
        );
    }

    /// Pinned: the list is a denylist, and an entry lost to an edit is a
    /// privileged global handed to a sandbox on a compositor that does
    /// not hide it itself. A duplicate would hide the loss of another.
    #[test]
    fn the_privileged_denylist_is_pinned_sorted_and_unique() {
        assert_eq!(PRIVILEGED.len(), 40);
        let mut sorted = PRIVILEGED.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), PRIVILEGED);
        // The clipboard managers a sandbox must not reach without focus,
        // and the capture, injection and grab protocols beside them.
        for name in [
            "zwlr_data_control_manager_v1",
            "ext_data_control_manager_v1",
            "zwlr_screencopy_manager_v1",
            "zwlr_export_dmabuf_manager_v1",
            "zwp_virtual_keyboard_manager_v1",
            "zwlr_input_inhibit_manager_v1",
            "zwp_xwayland_keyboard_grab_manager_v1",
            "ext_transient_seat_manager_v1",
            "xx_input_method_manager_v2",
            "ext_idle_notifier_v1",
            "wp_security_context_manager_v1",
        ] {
            assert!(PRIVILEGED.contains(&name), "{name}");
        }
        // The application side of the protocols the denylist does not
        // cover: hiding these would break input methods and windows.
        for name in ["zwp_text_input_manager_v3", "xdg_wm_base", "wl_seat"] {
            assert!(!PRIVILEGED.contains(&name), "{name}");
        }
    }

    /// The mode alone decides it: a sandboxed grant connects to the
    /// proxy whatever the compositor answered, and `"host"` to the
    /// session.
    #[test]
    fn plan_follows_the_mode() {
        let rt = Path::new("/run/user/1000/bubbler/t");
        assert_eq!(plan(WaylandMode::Host, rt), WaylandPlan::Host);
        for mode in [
            WaylandMode::default(),
            WaylandMode::Sandboxed {
                clipboard: Clipboard::Open,
            },
        ] {
            assert_eq!(
                plan(mode, rt),
                WaylandPlan::Proxy {
                    socket: rt.join("wayland")
                }
            );
        }
    }

    /// The two sockets are siblings and distinct: the application's is
    /// the one the sandbox binds, the compositor's the one the proxy
    /// connects to.
    #[test]
    fn the_application_and_the_compositor_get_different_sockets() {
        let rt = Path::new("/run/user/1000/bubbler/t");
        assert_eq!(socket_path(rt), rt.join("wayland"));
        assert_eq!(context_socket_path(rt), rt.join("wayland-context"));
        assert_ne!(socket_path(rt), context_socket_path(rt));
    }

    /// Pinned: this argv is the contract with `bubbler-wl-proxy`, and
    /// the gate is the one element the config decides.
    #[test]
    fn the_proxy_command_is_the_argv_the_binary_parses() {
        let rt = Path::new("/run/user/1000/bubbler/t");
        let plan = ProxyPlan::context(rt, Clipboard::Paste);
        assert_eq!(plan.gate(), "paste");
        let argv = plan.command_nodes(Path::new("/wl"), 2, OsStr::new("3"), OsStr::new("4"));
        let flat: Vec<String> = argv
            .iter()
            .map(|(a, _)| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            flat,
            [
                "/wl",
                "--listen-fd",
                "3",
                "--upstream",
                "/run/user/1000/bubbler/t/wayland-context",
                "--gate",
                "paste",
                "--log-fd",
                "2",
                "--ready-fd",
                "4",
            ]
        );
        // Only the gate is a node's; the rest is the invocation.
        let nodes: Vec<Option<usize>> = argv.iter().map(|(_, n)| *n).collect();
        assert_eq!(
            nodes,
            [
                None,
                None,
                None,
                None,
                None,
                Some(2),
                Some(2),
                None,
                None,
                None,
                None
            ]
        );
    }

    /// Without a security context the proxy connects to the session's
    /// own socket and is told to hide the privileged globals itself.
    #[test]
    fn the_fallback_plan_denies_and_dials_the_session() {
        let rt = Path::new("/run/user/1000/bubbler/t");
        let plan = ProxyPlan::fallback(rt, "/run/user/1000/wayland-1".into(), Clipboard::Open);
        assert!(!plan.context);
        assert_eq!(plan.gate(), "open");
        let argv = plan.command_nodes(Path::new("/wl"), 0, OsStr::new("3"), OsStr::new("4"));
        let flat: Vec<String> = argv
            .iter()
            .map(|(a, _)| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            flat,
            [
                "/wl",
                "--listen-fd",
                "3",
                "--upstream",
                "/run/user/1000/wayland-1",
                "--gate",
                "open",
                "--fallback-deny",
                "--log-fd",
                "2",
                "--ready-fd",
                "4",
            ]
        );
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
