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
    /// Larger than [`crate::config::MAX_BYTES`], and so refused before
    /// the parser sees it.
    #[error("configuration is {bytes} bytes; bubbler parses at most {max}")]
    TooLarge {
        /// Size of the text that was offered.
        bytes: usize,
        /// The bound it passed, [`crate::config::MAX_BYTES`].
        max: usize,
    },
    /// `{` nested deeper than [`crate::config::MAX_NESTING`]. The KDL
    /// parser descends by recursion, so a file deep enough overflows the
    /// stack and aborts the process instead of failing to parse.
    #[error("`{{` nested deeper than {max} at line {line}")]
    TooDeep {
        /// Line the bound was passed on, counting from one.
        line: u32,
        /// The bound it passed, [`crate::config::MAX_NESTING`].
        max: usize,
    },
}

/// Failures while resolving a profile through its layers.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// No layer holds a profile of that name. A name that could name a
    /// path is never looked up and lands here too.
    #[error("unknown profile `{0}`")]
    NotFound(String),
    /// The `include` chain came back to a layer it had already read.
    #[error("include cycle: {}", .0.join(" -> "))]
    Cycle(Vec<String>),
    /// The `include` chain is longer than [`crate::profile::MAX_DEPTH`].
    #[error("include nesting deeper than {max}: {chain}", max = crate::profile::MAX_DEPTH, chain = .0.join(" -> "))]
    TooDeep(Vec<String>),
    /// One layer, or the flattened result, did not parse.
    // No `{source}` in the message: the cause is chained below, and
    // printing it here too shows it twice.
    #[error("{origin}")]
    Parse {
        /// The layer's path, or which built-in or flattened profile it was.
        origin: String,
        /// What the parser rejected.
        #[source]
        source: ConfigError,
    },
    /// `include "<own name>"` in the last layer that holds the name: the
    /// include asks for the layer below, and there is none. Distinct from
    /// [`ProfileError::NotFound`], which would name a profile that plainly
    /// exists.
    #[error("`{0}`: include of its own name has no layer below")]
    SelfIncludeAtBottom(String),
    /// Two layers grant the same path in ways that cannot both hold.
    /// Taking either silently would be a privilege change nobody wrote.
    #[error("`{node}` is granted as {a} and as {b}")]
    Conflict {
        /// The node both layers name, without the conflicting part.
        node: String,
        /// The first layer's version, with where it came from.
        a: String,
        /// The second layer's version, with where it came from.
        b: String,
    },
    /// A name that is not one path component of the profile name grammar.
    /// Only `bubbler profile edit` reaches this: looking such a name up is
    /// [`ProfileError::NotFound`], since no layer can hold it.
    #[error(
        "invalid profile name `{0}`: use letters, digits, `.`, `_` and `-`, \
         not starting with `-`, and not `.` or `..`"
    )]
    InvalidName(String),
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
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
    /// A grant name that is not one of the bare service nodes.
    #[error("unknown grant `{0}`: valid grants are {names}", names = crate::instance::GRANTS.join(", "))]
    InvalidGrant(String),
    /// The instance path is a symlink; bubbler never deletes through one.
    #[error("{0} is a symlink; refusing to delete through it")]
    IsSymlink(PathBuf),
    /// `reseed` while the instance is running. The live sandbox was built
    /// from `config.kdl` as it stands, so rewriting it now would describe
    /// grants that sandbox does not have.
    #[error("instance `{0}` is running; stop it before reseeding")]
    AlreadyRunning(String),
    /// `config.kdl` carries no `// bubbler profile: <name>` header, so
    /// there is no profile to re-flatten it from.
    #[error("{0} has no `// bubbler profile: <name>` header to reseed from")]
    NoProfileHeader(PathBuf),
    /// The instance's runtime socket paths are longer than a
    /// `sockaddr_un` holds, so the kernel would truncate them silently.
    #[error("{0} is longer than the 107 bytes a Unix socket path may have; use a shorter name")]
    SocketPathTooLong(PathBuf),
    /// Asking the instance's control socket whether it is running failed.
    #[error("checking whether the instance is running")]
    Probe(#[source] LaunchError),
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
    /// The instance's `config.kdl` is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The profile the instance is seeded from could not be resolved.
    #[error(transparent)]
    Profile(#[from] ProfileError),
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
    #[error("setting up the sandbox terminal")]
    Pty(#[source] io::Error),
    /// Turning the seccomp rule set into a BPF program failed; the
    /// message is the compiler's own.
    #[error("compiling the seccomp filter: {0}")]
    Seccomp(String),
    /// The D-Bus proxy did not report readiness in time, so the sandbox
    /// would have started without the bus socket it expects.
    #[error("the D-Bus proxy did not become ready")]
    ProxyNotReady,
    /// The pasta sidecar could not be started or did not report that it
    /// had configured the sandbox's network namespace. The sandbox is
    /// stopped rather than let go: an isolated `network` that reached
    /// nothing would look like a broken application.
    #[error("connecting the sandbox network namespace: {0}")]
    Network(String),
    /// The accessibility bus could not be found: `$AT_SPI_BUS_ADDRESS`
    /// named no socket bubbler can bind, `dbus-send` is missing, or
    /// `org.a11y.Bus` did not answer with a `unix:path=` address. An
    /// `a11y` sandbox stops here rather than start with a socket that
    /// has no bus behind it.
    #[error("finding the accessibility bus: {0}")]
    A11y(String),
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
    /// The compositor refused, or could not be asked for, the Wayland
    /// security context the `wayland` grant registers the sandbox as.
    /// The run stops rather than fall back to the session socket, which
    /// would be a weaker sandbox than the configuration asked for.
    #[error(transparent)]
    Wayland(#[from] crate::wayland::WaylandError),
    /// Command resolution failed (config had no `command` and none given).
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// Failures that stop a lint run before it has an answer, as opposed to
/// the findings a run reports.
#[derive(Debug, Error)]
pub enum LintError {
    /// The profile could not be resolved through its layers.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// A layer, or the config itself, is not something bubbler parses.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
}

/// Failures while reading, writing or placing a `PATH` shim.
#[derive(Debug, Error)]
pub enum WrapError {
    /// A shim name outside the grammar instance names use, so it could
    /// name a path outside the shim directory, or a command nobody can
    /// type.
    #[error(
        "invalid shim name `{0}`: use letters, digits, `.`, `_` and `-`, \
         not starting with `-`, and not `.` or `..`"
    )]
    InvalidName(String),
    /// A name bubbler resolves through `PATH` itself.
    #[error(
        "refusing to name a shim `{0}`: bubbler runs that program itself, \
         so the shim would shadow the real one"
    )]
    Reserved(String),
    /// The registry already maps the name to another instance.
    #[error("`{name}` already opens instance `{instance}`; run `bubbler unwrap {name}` first")]
    NameTaken {
        /// The shim name that is taken.
        name: String,
        /// The instance it already opens.
        instance: String,
    },
    /// The instance has no `command`, so a shim would have nothing to
    /// run: what a shim hands `open` is that command plus whatever the
    /// user typed after it.
    #[error("instance `{0}` has no `command` to run; add one to its config.kdl first")]
    NoCommand(String),
    /// `unwrap` on a name the registry does not hold.
    #[error("no shim named `{0}`")]
    NotWrapped(String),
    /// Something that is not one of bubbler's shims already has that
    /// path. bubbler never moves it aside or deletes it.
    #[error("{0} exists and is not a bubbler shim; move it aside first")]
    Occupied(PathBuf),
    /// The registry is not KDL bubbler will parse: a syntax error, or
    /// text past the bounds `crate::config::parse_document` holds the
    /// parser to.
    #[error("{path}: invalid KDL")]
    Parse {
        /// The registry's path.
        path: PathBuf,
        /// What the parser rejected.
        #[source]
        source: ConfigError,
    },
    /// The registry parses but says something bubbler would not write.
    #[error("{path}: {reason}")]
    Malformed {
        /// The registry's path.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
    /// The instance a shim would open cannot be reached.
    #[error(transparent)]
    Instance(#[from] InstanceError),
}

/// Failures while generating, writing or removing a desktop entry.
#[derive(Debug, Error)]
pub enum DesktopError {
    /// The instance has neither a `command` to look an entry up by nor a
    /// `desktop` node naming one.
    #[error(
        "instance `{0}` has no `command` node, so there is no application to \
         find an entry for; name one with `desktop \"<name>.desktop\"`"
    )]
    NoCommand(String),
    /// The `desktop` node names an entry no application directory holds.
    #[error("no `{name}` in {}", .dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", "))]
    HintNotFound {
        /// The file name the `desktop` node asked for.
        name: String,
        /// The directories that were searched, in lookup order.
        dirs: Vec<PathBuf>,
    },
    /// Nothing in the application directories launches this command.
    #[error(
        "no desktop entry runs `{command}`; name one with `desktop \
         \"<name>.desktop\"` in the instance's config.kdl"
    )]
    NotFound {
        /// Basename of the command that was searched for.
        command: String,
    },
    /// More than one entry launches this command, and guessing between
    /// them would pick an application's helper entry as often as its own.
    #[error(
        "{n} desktop entries run `{command}`: {}; name one with `desktop \
         \"<name>.desktop\"` in the instance's config.kdl",
        .candidates.join(", "), n = .candidates.len()
    )]
    Ambiguous {
        /// Basename of the command that was searched for.
        command: String,
        /// File names of the entries that matched, in lookup order.
        candidates: Vec<String>,
    },
    /// The source file has no `[Desktop Entry]` group, so it is not a
    /// desktop entry at all.
    #[error("no `[Desktop Entry]` group")]
    NoEntryGroup,
    /// The source file's `[Desktop Entry]` group has no `Exec` key, so
    /// there is no command line to wrap: a `Link` or `Directory` entry.
    #[error("no `Exec` key in its `[Desktop Entry]` group")]
    NoExec,
    /// The source says it is to be treated as if it were not there, so a
    /// copy of it would be an entry that does nothing.
    #[error("it carries `Hidden=true`, which means the entry is not to be used at all")]
    Hidden,
    /// The source is itself a generated entry. Patching it again would
    /// suffix the name twice and wrap the wrapper.
    #[error("it is bubbler's own entry for instance `{0}`, not an application's")]
    Generated(String),
    /// A desktop entry is UTF-8 by specification; this file is not.
    #[error("{0} is not UTF-8, so it is not a desktop entry")]
    NotUtf8(PathBuf),
    /// The path of the `bubbler` binary is not UTF-8, so it cannot go
    /// into a file that is.
    #[error("the path of this bubbler binary is not UTF-8, so no entry can name it")]
    ProgramNotUtf8,
    /// The target exists and carries no marker of bubbler's, so bubbler
    /// did not write it and will not overwrite it.
    #[error("{0} exists and is not bubbler's; move it aside first")]
    Foreign(PathBuf),
    /// The target is bubbler's entry for a different instance.
    #[error("{path} is the entry of instance `{instance}`; remove that one first")]
    OtherInstance {
        /// The target path.
        path: PathBuf,
        /// The instance the file there belongs to.
        instance: String,
    },
    /// `--remove` found no entry of this instance's.
    #[error("no desktop entry of instance `{instance}` in {}", .dir.display())]
    NotGenerated {
        /// The instance whose entry was looked for.
        instance: String,
        /// The directory that was searched.
        dir: PathBuf,
    },
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
}
