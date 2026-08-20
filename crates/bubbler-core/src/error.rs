//! Error types, one enum per module boundary so callers can match on
//! what went wrong.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Failures while reading an instance or profile configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// KDL syntax error; the source carries the location.
    #[error("invalid KDL")]
    Parse(#[from] kdl::KdlError),
    /// A top-level node that is not a known service or `command`.
    #[error("unknown node `{0}`")]
    UnknownNode(String),
    /// A property the node does not accept.
    #[error("node `{node}` does not accept property `{prop}`")]
    UnknownProperty {
        /// Name of the node that carried the property.
        node: String,
        /// The offending property name.
        prop: String,
    },
    /// An argument with the wrong shape or value.
    #[error("bad argument for `{node}`: {reason}")]
    BadArgument {
        /// Name of the node that carried the argument.
        node: String,
        /// What the node expected instead.
        reason: String,
    },
    /// A node or `env` key that may appear only once appeared again.
    #[error("`{0}` given more than once")]
    Duplicate(String),
    /// Neither the config nor the CLI supplied a command to run.
    #[error("no command: add a `command` node to the config or pass one after `--`")]
    MissingCommand,
}

/// Failures while creating, opening or listing instances.
#[derive(Debug, Error)]
pub enum InstanceError {
    /// `create` on an existing instance.
    #[error("instance `{0}` already exists")]
    AlreadyExists(String),
    /// `open` on a missing instance.
    #[error("instance `{0}` not found")]
    NotFound(String),
    /// Name is empty, is `.` or `..`, starts with `-`, has the reserved
    /// `try-<digits>` shape, or contains characters outside `[A-Za-z0-9._-]`.
    #[error(
        "invalid instance name `{0}`: use letters, digits, `.`, `_` and `-`, \
         not starting with `-`, not `.` or `..`, and not `try-<digits>`, \
         which `bubbler try` reserves"
    )]
    InvalidName(String),
    /// Unknown profile name passed to `create`.
    #[error("unknown profile `{0}`")]
    UnknownProfile(String),
    /// A grant name that is not one of the bare service nodes.
    #[error("unknown grant `{0}`: valid grants are {names}", names = crate::instance::GRANTS.join(", "))]
    InvalidGrant(String),
    /// The instance path is a symlink; bubbler never deletes through one.
    #[error("{0} is a symlink; refusing to delete through it")]
    IsSymlink(PathBuf),
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
    /// The instance's `config.kdl` is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// Failures while turning a config into a running sandbox.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// `bwrap` not on `PATH`.
    #[error("bwrap not found on PATH; install bubblewrap")]
    BwrapMissing,
    /// A service needs a host path that does not exist.
    #[error("service `{service}` needs `{path}` which does not exist")]
    MissingResource {
        /// Name of the service that made the request.
        service: &'static str,
        /// The host path that is missing.
        path: PathBuf,
    },
    /// A host path exists but is of the wrong type to bind, e.g. a
    /// directory where a socket is expected.
    #[error("service `{service}` needs `{path}` to be {expected}")]
    WrongType {
        /// Name of the service that made the request.
        service: &'static str,
        /// The host path with the wrong type.
        path: PathBuf,
        /// What the service expected, as an article plus noun.
        expected: &'static str,
    },
    /// A service needs an environment variable that is unset.
    #[error("service `{service}` needs ${var} to be set")]
    MissingEnv {
        /// Name of the service that made the request.
        service: &'static str,
        /// The environment variable that must be set.
        var: &'static str,
    },
    /// A service was given a value it cannot interpret.
    #[error("service `{service}`: {reason}")]
    BadValue {
        /// Name of the service that rejected the value.
        service: &'static str,
        /// Why the value was rejected.
        reason: String,
    },
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
    /// Creating an fd bwrap must inherit failed: a data file, the control
    /// socket or a sidecar's ready pipe.
    #[error("preparing an fd for bwrap")]
    Data(#[source] io::Error),
    /// Spawning `bwrap` failed for a reason other than it being missing.
    #[error("failed to run bwrap")]
    Spawn(#[source] io::Error),
    /// Allocating the sandbox's pseudoterminal, or relaying through it,
    /// failed; the sandbox would have had to use the host's terminal.
    #[error("the sandbox terminal")]
    Pty(#[source] io::Error),
    /// The D-Bus proxy did not report readiness in time, so the sandbox
    /// would have started without the bus socket it expects.
    #[error("the D-Bus proxy did not become ready")]
    ProxyNotReady,
    /// Nothing listens on the instance's control socket.
    #[error("instance `{0}` is not running")]
    NotRunning(String),
    /// A fresh start was asked for while the instance is already running.
    #[error("instance `{0}` is already running")]
    AlreadyRunning(String),
    /// The other end of the exec channel spoke out of protocol or hung up.
    #[error("exec channel: {0}")]
    Protocol(String),
    /// Installing the SIGINT/SIGTERM handlers failed, so a signal could
    /// not be forwarded into the sandbox.
    #[error("installing signal handlers")]
    Signal(#[source] io::Error),
    /// Command resolution failed (config had no `command` and none given).
    #[error(transparent)]
    Config(#[from] ConfigError),
}
