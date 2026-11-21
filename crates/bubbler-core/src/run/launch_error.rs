//! The run layer's error: what a launch, an exec or a probe of a
//! running instance can fail with, holding the plan layer's and each
//! run module's own errors.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::model::error::ConfigError;
use crate::plan::plan_error::PlanError;
use crate::run::dbus_a11y::A11yError;
use crate::run::exec::ControlError;
use crate::run::launcher::{NetworkError, PipeWireError};
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
    /// A PipeWire sidecar of the `pipewire` or `pulseaudio` grant did not
    /// come up. The run stops here.
    #[error(transparent)]
    PipeWire(#[from] PipeWireError),
    /// The sandbox's network namespace could not be connected or
    /// filtered. The sandbox is stopped rather than let go.
    #[error(transparent)]
    Network(#[from] NetworkError),
    /// The accessibility bus could not be found.
    #[error(transparent)]
    A11y(#[from] A11yError),
    /// The other end of the exec channel spoke out of protocol or hung up.
    #[error(transparent)]
    Control(#[from] ControlError),
    /// The compositor refused, or could not be asked for, the Wayland
    /// security context the `wayland` grant registers the sandbox as.
    /// The run stops rather than fall back to the session socket.
    #[error(transparent)]
    Wayland(#[from] WaylandError),
    /// Command resolution failed (config had no `command` and none given).
    #[error(transparent)]
    Config(#[from] ConfigError),
}
