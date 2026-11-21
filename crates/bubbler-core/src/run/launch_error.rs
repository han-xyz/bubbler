//! The run layer's error: what a launch, an exec or a probe of a
//! running instance can fail with, holding the plan layer's and each
//! run module's own errors.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::model::error::ConfigError;
use crate::plan::plan_error::PlanError;
use crate::wayland_context::WaylandError;

/// Failures while turning a config into a running sandbox.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// `bwrap` not on `PATH`.
    #[error("bwrap not found on PATH; install bubblewrap")]
    BwrapMissing,
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
    /// Creating an fd bwrap must inherit failed: a data file, the control
    /// socket or a sidecar's ready pipe.
    #[error("preparing an fd for bwrap")]
    Data(#[source] io::Error),
    /// Reading this process's own open descriptors, or marking the ones a
    /// child must not inherit close-on-exec, failed. Nothing is spawned
    /// after this.
    #[error("keeping inherited descriptors out of the child")]
    Descriptors(#[source] io::Error),
    /// Spawning `bwrap` failed for a reason other than it being missing.
    #[error("failed to run bwrap")]
    Spawn(#[source] io::Error),
    /// Allocating the sandbox's pseudoterminal, or relaying through it,
    /// failed; the sandbox would have had to use the host's terminal.
    #[error("setting up the sandbox terminal")]
    Pty(#[source] io::Error),
    /// The D-Bus proxy did not report readiness in time, so the sandbox
    /// would have started without the bus socket it expects.
    #[error("the D-Bus proxy did not become ready")]
    ProxyNotReady,
    /// A stop signal arrived while a sidecar was starting, and the start
    /// ended there. `crate::launcher::run` exits with a stopped run's
    /// code in its place.
    #[error("the start was stopped by a signal")]
    Stopped,
    /// Nothing listens on the instance's control socket.
    #[error("instance `{0}` is not running")]
    NotRunning(String),
    /// A fresh start was asked for while the instance is already running.
    #[error("instance `{0}` is already running")]
    AlreadyRunning(String),
    /// Installing the SIGINT/SIGTERM handlers failed, so a signal could
    /// not be forwarded into the sandbox.
    #[error("installing signal handlers")]
    Signal(#[source] io::Error),
    /// What the run was to bind, set or filter could not be resolved.
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// The sidecar that creates this run's PipeWire security context did
    /// not report the socket it made. The run stops here.
    #[error("pw-container did not create this instance's PipeWire security context: {0}")]
    PwContext(String),
    /// The private PulseAudio server of a `pulseaudio` grant did not
    /// come up. The run stops here.
    #[error("pipewire-pulse did not serve this instance's private PulseAudio socket: {0}")]
    PwPulse(String),
    /// The pasta sidecar could not be started or did not report that it
    /// had configured the sandbox's network namespace. The sandbox is
    /// stopped rather than let go.
    #[error("connecting the sandbox network namespace: {0}")]
    Network(String),
    /// The accessibility bus could not be found: `$AT_SPI_BUS_ADDRESS`
    /// named no socket bubbler can bind, the session bus could not be
    /// reached, or `org.a11y.Bus` did not answer with a `unix:path=`
    /// address.
    #[error("finding the accessibility bus: {0}")]
    A11y(String),
    /// The other end of the exec channel spoke out of protocol or hung up.
    #[error("exec channel: {0}")]
    Protocol(String),
    /// The compositor refused, or could not be asked for, the Wayland
    /// security context the `wayland` grant registers the sandbox as.
    /// The run stops rather than fall back to the session socket.
    #[error(transparent)]
    Wayland(#[from] WaylandError),
    /// Command resolution failed (config had no `command` and none given).
    #[error(transparent)]
    Config(#[from] ConfigError),
}
