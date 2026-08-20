//! Error types, one enum per module boundary so callers can match on
//! what went wrong.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Failures while reading an instance or profile configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// KDL syntax error.
    #[error("invalid KDL: {0}")]
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
    /// A node that may appear only once appeared again.
    #[error("node `{0}` given more than once")]
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
    /// Name contains characters outside `[A-Za-z0-9._-]` or is `.`/`..`.
    #[error("invalid instance name `{0}`")]
    InvalidName(String),
    /// Unknown profile name passed to `create`.
    #[error("unknown profile `{0}`")]
    UnknownProfile(String),
    /// Filesystem failure at a specific path.
    #[error("{0}: {1}")]
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
    #[error("{0}: {1}")]
    Io(PathBuf, #[source] io::Error),
    /// Spawning `bwrap` failed for a reason other than it being missing.
    #[error("failed to run bwrap: {0}")]
    Spawn(#[source] io::Error),
}
