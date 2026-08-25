//! KDL instance/profile configuration. Each top-level node is either a
//! service grant or `command`. Unknown nodes are errors: silently
//! ignoring a grant would produce a different sandbox than the file says.

use std::ffi::{OsStr, OsString};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use kdl::{KdlDocument, KdlNode};

pub use crate::error::ConfigError;
pub use crate::network::{
    AllowOut, Cidr, Forward, Mode as NetworkMode, NetworkConfig, Outbound, Proto,
};
pub use crate::seccomp::{Errno, SeccompConfig};
pub use crate::tty::TtyMode;

use crate::dbus;
use crate::seccomp::syscall_number;

/// Largest configuration bubbler hands to the KDL parser. A profile or
/// a `config.kdl` is a screenful of grants; a megabyte is already far
/// past anything a person writes.
pub const MAX_BYTES: usize = 1024 * 1024;

/// Deepest `{`…`}` nesting bubbler hands to the KDL parser. The deepest
/// node bubbler defines is two levels (`network { dns { … } }`), so this
/// is room to spare for a config that means something.
///
/// Measured against `kdl` 6.7.1 on x86_64, parsing well-formed nesting
/// until the process aborts: 1348 levels on the 8 MiB stack a main
/// thread has in a release build, 253 in a debug build, and 61 on the
/// 2 MiB stack of a spawned thread in a debug build. The bound sits
/// under the smallest of those rather than under the largest: bubbler
/// parses on its main thread, but a library user parsing on a thread of
/// its own in a debug build is the case that has the least room, and
/// this is a bound the parser survives there too.
pub const MAX_NESTING: usize = 32;

/// Keys `env` may not set: the sandbox owns them.
pub const RESERVED_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "XDG_RUNTIME_DIR",
    "USER",
    "LOGNAME",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XAUTHORITY",
    "XDG_SESSION_TYPE",
    "PULSE_SERVER",
    "DBUS_SESSION_BUS_ADDRESS",
    "DBUS_SYSTEM_BUS_ADDRESS",
];

/// `/etc` entries `etc-share` may not name: the sandbox generates its own
/// `passwd` and `group`, and binding the host's account files back in
/// would undo that and leak the shadow hashes. The `-` and `+` forms are
/// the backup and NIS-compatibility files next to them.
pub const RESERVED_ETC: &[&str] = &[
    "passwd", "passwd-", "passwd+", "group", "group-", "group+", "shadow", "shadow-", "shadow+",
    "gshadow", "gshadow-", "gshadow+",
];

/// Every top-level node a `config.kdl` may hold, in the order the
/// README documents them. The parser resolves a node name against this
/// list before it reaches a match arm and
/// [`crate::catalogue::GRANTS`] describes each entry, so what bubbler
/// takes and what bubbler documents are one list. `include` is not here:
/// it is the one node only a profile layer takes.
pub const NODES: &[&str] = &[
    "wayland",
    "x11",
    "network",
    "dri",
    "pipewire",
    "pulseaudio",
    "gamepad",
    "hidraw",
    "camera",
    "home-share",
    "path-share",
    "etc-share",
    "app-runtime",
    "dbus",
    "system-bus",
    "portals",
    "notify",
    "tray",
    "mpris",
    "tty",
    "userns",
    "seccomp",
    "env",
    "lint-allow",
    "desktop",
    "command",
];

/// Whether the sandbox may create user namespaces of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Userns {
    /// The baseline's `--unshare-all`, which leaves nested user
    /// namespaces working: a browser's own sandbox and Steam's
    /// pressure-vessel both need them.
    #[default]
    Allow,
    /// `--unshare-user --disable-userns`: the sandbox cannot create a
    /// further user namespace, and so cannot regain inside it the
    /// capabilities that make mount and pid namespaces reachable again.
    Disable,
}

impl FromStr for Userns {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "disable" => Ok(Self::Disable),
            _ => Err(ConfigError::BadArgument {
                node: "userns".to_owned(),
                reason: format!("expected `allow` or `disable`, got `{s}`"),
            }),
        }
    }
}

/// What `wayland` binds: bubbler's own socket registered with the
/// compositor as a security context, or the host's socket as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WaylandMode {
    /// A `wp_security_context_v1` listener the compositor treats as
    /// sandboxed, falling back to the host socket with a warning where
    /// the compositor offers none.
    #[default]
    Sandboxed,
    /// The host's socket: the compositor cannot tell the sandbox from
    /// the session (`wayland "host"`).
    Host,
}

impl FromStr for WaylandMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "host" => Ok(Self::Host),
            _ => Err(ConfigError::BadArgument {
                node: "wayland".to_owned(),
                reason: format!("expected `host`, got `{s}`"),
            }),
        }
    }
}

/// Absolute path of the X server bubbler starts inside the sandbox.
/// A host binary under the read-only `/usr`, so the sandbox holds no
/// copy of its own and cannot replace it.
pub const XWAYLAND: &str = "/usr/bin/Xwayland";

/// The window the nested X server draws itself in, as one Wayland
/// client of the sandbox's own compositor connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedX11 {
    /// `<width>x<height>` of the window, `1280x720` unless the node
    /// says otherwise. Ignored when `fullscreen` is set.
    pub geometry: String,
    /// Take the whole output instead of a window, dropping the
    /// decorations with it.
    pub fullscreen: bool,
    /// Keep keyboard and pointer inside the server's window
    /// (`-host-grab`, released with Ctrl+Shift).
    pub grab: bool,
}

impl Default for NestedX11 {
    fn default() -> Self {
        Self {
            geometry: "1280x720".to_owned(),
            fullscreen: false,
            grab: false,
        }
    }
}

impl NestedX11 {
    /// The Xwayland command line, in the order the server takes it.
    /// `-nolisten tcp` keeps the display off the network and `-noreset`
    /// stops a client's exit from resetting the server; `-ac` is the
    /// access control X11 has no use for here, the display being the
    /// sandbox's own. The `-displayfd` the supervisor reads the display
    /// number from is appended when it starts the server, not here.
    pub fn xwayland_argv(&self) -> Vec<OsString> {
        let mut argv: Vec<OsString> = [
            XWAYLAND,
            ":0",
            "-noreset",
            "-nolisten",
            "tcp",
            "-ac",
            "-hidpi",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        // A fullscreen server has no window to decorate or to size.
        if self.fullscreen {
            argv.push(OsString::from("-fullscreen"));
        } else {
            argv.push(OsString::from("-decorate"));
            argv.push(OsString::from("-geometry"));
            argv.push(OsString::from(&self.geometry));
        }
        if self.grab {
            argv.push(OsString::from("-host-grab"));
        }
        argv
    }
}

/// Which X server an `x11` grant means: one the sandbox runs for itself,
/// or the session's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X11Mode {
    /// A rootful Xwayland started inside the sandbox by `bubbler-init`,
    /// which is a Wayland client of the instance's own socket: the X
    /// clients inside see no display but this one.
    Nested(NestedX11),
    /// The session's X socket and Xauthority cookie (`x11 "host"`):
    /// every X client on the display can read every other's input and
    /// windows, this sandbox included.
    Host,
}

impl Default for X11Mode {
    fn default() -> Self {
        Self::Nested(NestedX11::default())
    }
}

/// Whether a shared path is writable inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    /// Bound with `--ro-bind` (default).
    ReadOnly,
    /// Bound with `--bind`.
    ReadWrite,
}

/// One accepted lint finding: the check it silences and why. Only
/// warnings and notes can be silenced; an error names something the file
/// cannot do, and there is nothing to accept about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintAllow {
    /// A check id from [`crate::lint::CHECKS`].
    pub id: String,
    /// Why this file accepts the finding. Required: the reason is the
    /// whole value of writing the node down.
    pub reason: String,
}

/// One rule for the filtering D-Bus proxy. `See`, `Talk` and `Own` are the
/// three policy levels for a well-known name; `Call` and `Broadcast` pair a
/// name with an `[METHOD][@PATH]` rule narrowing it to single methods,
/// signals or object subtrees (`xdg-dbus-proxy(1)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusRule {
    /// The name is visible: it shows up in `ListNames` and its owner
    /// changes are delivered.
    See(String),
    /// Method calls and signals may be sent to the name; implies `See`.
    Talk(String),
    /// The sandbox may request the name; implies `Talk`.
    Own(String),
    /// Calls to the name are allowed for one rule only.
    Call(String, String),
    /// Broadcast signals from the name are received for one rule only.
    Broadcast(String, String),
}

impl BusRule {
    /// The name and node word of a policy rule, or `None` for `call` and
    /// `broadcast`, which narrow a policy rather than set one. A name
    /// holds one policy: two of them for the same name would leave which
    /// one the proxy applies to argument order.
    pub fn policy(&self) -> Option<(&str, &'static str)> {
        match self {
            BusRule::See(n) => Some((n, "see")),
            BusRule::Talk(n) => Some((n, "talk")),
            BusRule::Own(n) => Some((n, "own")),
            BusRule::Call(..) | BusRule::Broadcast(..) => None,
        }
    }
}

/// One granted resource. Order in the config file is irrelevant; the
/// builder's phases decide argv order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    /// Access to the compositor: a security-context socket by default,
    /// the host socket under `wayland "host"`.
    Wayland(WaylandMode),
    /// An X display: a nested Xwayland of the sandbox's own by default,
    /// the session's socket and cookie under `x11 "host"`, which offers
    /// no isolation between X clients.
    X11(X11Mode),
    /// A network namespace, and what it is connected to: the sandbox's
    /// own by default, the host's under `network "host"`.
    Network(NetworkConfig),
    /// GPU access: the `/dev/dri` device nodes, bound read-write, plus the
    /// `/sys` entries a userspace driver reads to match a node to its
    /// hardware.
    Dri,
    /// Access to the host PipeWire socket.
    Pipewire,
    /// Access to the host PulseAudio socket.
    Pulseaudio,
    /// Bind `$HOME/<path>` on the host to the same relative path inside the
    /// private home.
    HomeShare {
        /// Relative to `$HOME`; no absolute paths, no `..`.
        path: PathBuf,
        /// Read-only unless `mode=rw`.
        mode: ShareMode,
    },
    /// Bind a host path outside the home at that same path inside the
    /// sandbox. Reserved roots (`/etc`, `/home`, `/run`, ...) are refused
    /// when the sandbox is built, not here.
    PathShare {
        /// Absolute, as written in the file; no `..`.
        path: PathBuf,
        /// Read-only unless `mode=rw`.
        mode: ShareMode,
    },
    /// Bind one host `/etc` entry read-only at the same path, on top of
    /// the baseline `/etc` allowlist.
    EtcShare {
        /// Entry name directly under `/etc`.
        name: OsString,
    },
    /// A session bus filtered by an `xdg-dbus-proxy` sidecar: the sandbox
    /// reaches only what `rules` allow, never the host bus itself.
    Dbus {
        /// Proxy filter rules, in file order; repeats are harmless.
        rules: Vec<BusRule>,
    },
    /// The system bus, filtered by the same `xdg-dbus-proxy` sidecar. The
    /// `rules` list is the whole confinement: behind a granted name the
    /// sandbox is an ordinary process of the user, since the bus sees the
    /// proxy's credentials and not the sandbox's.
    SystemBus {
        /// Proxy filter rules, in file order; never an `own`.
        rules: Vec<BusRule>,
    },
    /// The XDG desktop portal rule bundle plus the `/.flatpak-info` file
    /// portals read to identify the sandbox. Requires [`Service::Dbus`].
    Portals,
    /// Talk to `org.freedesktop.Notifications`. Requires [`Service::Dbus`].
    Notify,
    /// Talk to `org.kde.StatusNotifierWatcher`, which is what registering
    /// a tray icon takes. Requires [`Service::Dbus`].
    Tray,
    /// Game controllers: the `/dev/input` device nodes, which are every
    /// input device the host has, plus the sysfs and udev database entries
    /// that identify them.
    Gamepad {
        /// Also bind every `/dev/hidraw*` node, which is what a controller
        /// driven through hidapi rather than evdev takes.
        hidraw: bool,
        /// Also bind `/dev/uinput`: the sandbox can create virtual input
        /// devices for the whole session.
        uinput: bool,
    },
    /// Every `/dev/hidraw*` node the host has at launch, plus
    /// `/sys/class/hidraw`: the raw HID interfaces a security key, a
    /// hardware wallet or a controller driven through hidapi is opened
    /// through. `gamepad hidraw=#true` grants the same thing.
    Hidraw,
    /// Cameras through `org.freedesktop.portal.Camera`, which needs no
    /// device in the sandbox: the portal opens the node in the host
    /// daemon and hands back a connected PipeWire socket. Requires
    /// [`Service::Portals`], whose `/.flatpak-info` is what earns the
    /// instance a permission of its own rather than the blanket one
    /// every unsandboxed process on the machine shares.
    Camera {
        /// Also bind the V4L2 device nodes, for the plain V4L2 clients
        /// that will never speak the portal. Every `/dev/video*` and
        /// `/dev/media*` the host has, a virtual camera among them.
        nodes: bool,
    },
    /// Own `org.mpris.MediaPlayer2.<name>` so media keys and player
    /// controls reach the app. Requires [`Service::Dbus`].
    Mpris {
        /// Appended to `org.mpris.MediaPlayer2.`; `*` allowed as the last
        /// element.
        name: String,
    },
    /// Share `$XDG_RUNTIME_DIR/app/<id>` with everything else that names
    /// the same id: the directory applications serve their own sockets
    /// in, so one sandbox can reach another's. One id is one trust
    /// domain; nothing about the boundary tells the peers apart.
    AppRuntime {
        /// Reverse-DNS application id, the directory's name under `app/`.
        id: String,
        /// Read-only unless `mode=rw`. `connect()` works either way, so
        /// only a sandbox that *serves* a socket needs `rw`.
        mode: ShareMode,
    },
}

impl Service {
    /// The KDL node this grant is written as, which is what
    /// [`crate::catalogue::GRANTS`] is keyed by. Every variant is named
    /// here: a grant whose node the catalogue cannot look up is one
    /// nothing can explain to the user.
    pub fn node_name(&self) -> &'static str {
        match self {
            Self::Wayland(_) => "wayland",
            Self::X11(_) => "x11",
            Self::Network(_) => "network",
            Self::Dri => "dri",
            Self::Pipewire => "pipewire",
            Self::Pulseaudio => "pulseaudio",
            Self::HomeShare { .. } => "home-share",
            Self::PathShare { .. } => "path-share",
            Self::EtcShare { .. } => "etc-share",
            Self::Dbus { .. } => "dbus",
            Self::SystemBus { .. } => "system-bus",
            Self::Portals => "portals",
            Self::Notify => "notify",
            Self::Tray => "tray",
            Self::Gamepad { .. } => "gamepad",
            Self::Hidraw => "hidraw",
            Self::Camera { .. } => "camera",
            Self::Mpris { .. } => "mpris",
            Self::AppRuntime { .. } => "app-runtime",
        }
    }
}

/// Parsed `config.kdl`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstanceConfig {
    /// Granted services, in file order.
    pub services: Vec<Service>,
    /// Default argv for `run`, if the file has a `command` node.
    pub command: Option<Vec<OsString>>,
    /// Extra environment variables, in file order; never a key from
    /// [`RESERVED_ENV`].
    pub env: Vec<(String, String)>,
    /// How the sandbox's stdio reaches the user's terminal; `pty` unless
    /// a `tty` node says otherwise.
    pub tty: TtyMode,
    /// Changes to the default seccomp denylist; empty unless a `seccomp`
    /// node relaxes or extends it.
    pub seccomp: SeccompConfig,
    /// Whether the sandbox may nest user namespaces; `allow` unless a
    /// `userns` node says otherwise.
    pub userns: Userns,
    /// Lint findings this file has accepted, in file order.
    pub lint_allows: Vec<LintAllow>,
    /// Basename of the desktop entry `bubbler desktop` writes this
    /// instance's launcher entry from, where the command's own entry is
    /// not named after it.
    pub desktop: Option<String>,
}

/// One profile layer as written: the same nodes an instance config may
/// hold, plus the `include` names layered underneath it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawProfile {
    /// The layer's own nodes.
    pub config: InstanceConfig,
    /// Profile names to resolve and merge under this layer, in file order.
    pub includes: Vec<String>,
    /// Whether a `tty` node was written. [`InstanceConfig::tty`] cannot
    /// say, and a layer without the node must not override the one below.
    pub tty_set: bool,
    /// Whether a `userns` node was written, for the same reason
    /// [`RawProfile::tty_set`] exists.
    pub userns_set: bool,
}

/// Parse KDL v2 text into an [`InstanceConfig`]. `include` is rejected:
/// an instance config must grant what it says on one screen.
pub fn parse(text: &str) -> Result<InstanceConfig, ConfigError> {
    Ok(parse_doc(text, false)?.0.config)
}

/// Where the nodes of a config are, counting from one. A line is `None`
/// only where a node's span falls outside the text it was parsed from,
/// which the parser's own spans are not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lines {
    /// Line of each granted service, parallel to
    /// [`InstanceConfig::services`].
    pub services: Vec<Option<u32>>,
    /// Line of each variable, parallel to [`InstanceConfig::env`]; one
    /// `env` node setting several of them gives them all its own line.
    pub env: Vec<Option<u32>>,
    /// Line of the `userns` node, if the file has one.
    pub userns: Option<u32>,
    /// Line of the `seccomp` node, if the file has one.
    pub seccomp: Option<u32>,
}

/// Where the nodes of the config [`parse`] returns were written, so
/// `--explain` can name the line an argument came from.
pub fn node_lines(text: &str) -> Result<Lines, ConfigError> {
    Ok(parse_doc(text, false)?.1)
}

/// Parse one profile layer, which may also `include` other profiles.
///
/// A bundle node (`portals`, `notify`, `mpris`) without `dbus` is not an
/// error here: the `dbus` grant may come from an included layer. The
/// resolver applies that check to the merged result.
pub fn parse_profile(text: &str) -> Result<RawProfile, ConfigError> {
    Ok(parse_doc(text, true)?.0)
}

/// Parse KDL text through the one bound bubbler puts on the parser.
///
/// Every configuration bubbler reads is parsed here. `kdl` 6 descends
/// into `{` by recursion, so a file nested deeply enough overflows the
/// stack and aborts the process instead of returning an error, and the
/// text is measured before the parser is handed it.
///
/// The measurement is a pre-check and not a parser: it counts `{` and
/// `}` outside strings and comments and decides nothing about what the
/// document means. Text it accepts may still be invalid KDL.
pub fn parse_document(text: &str) -> Result<KdlDocument, ConfigError> {
    check_bounds(text)?;
    Ok(KdlDocument::parse(text)?)
}

/// Refuse text past [`MAX_BYTES`] or [`MAX_NESTING`]. Counting the
/// braces by hand is the point: see [`parse_document`].
fn check_bounds(text: &str) -> Result<(), ConfigError> {
    if text.len() > MAX_BYTES {
        return Err(ConfigError::TooLarge {
            bytes: text.len(),
            max: MAX_BYTES,
        });
    }
    let b = text.as_bytes();
    let mut depth: usize = 0;
    let mut i = 0;
    while i < b.len() {
        i = match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => line_comment_end(b, i),
            b'/' if b.get(i + 1) == Some(&b'*') => block_comment_end(b, i),
            b'"' => string_end(b, i, 0),
            // `#` opens a raw string (`#"…"#`) and also the keywords
            // `#true`, `#null` and their kin, which hold no braces.
            b'#' => {
                let hashes = b[i..].iter().take_while(|c| **c == b'#').count();
                if b.get(i + hashes) == Some(&b'"') {
                    string_end(b, i + hashes, hashes)
                } else {
                    i + hashes
                }
            }
            b'{' => {
                depth += 1;
                if depth > MAX_NESTING {
                    return Err(ConfigError::TooDeep {
                        line: line_at(text, i).unwrap_or(0),
                        max: MAX_NESTING,
                    });
                }
                i + 1
            }
            // A `}` too many is the parser's to reject, not this
            // count's: it says nothing about how deep the file goes.
            b'}' => {
                depth = depth.saturating_sub(1);
                i + 1
            }
            _ => i + 1,
        };
    }
    Ok(())
}

/// Index of the newline that ends the `//` comment at `at`, or the end
/// of the text.
fn line_comment_end(b: &[u8], at: usize) -> usize {
    match b[at..].iter().position(|c| *c == b'\n') {
        Some(n) => at + n,
        None => b.len(),
    }
}

/// Index just past the `/* */` comment at `at`. KDL nests them, so the
/// first `*/` does not always end one.
fn block_comment_end(b: &[u8], at: usize) -> usize {
    let mut open: usize = 1;
    let mut i = at + 2;
    while i + 1 < b.len() {
        match (b[i], b[i + 1]) {
            (b'/', b'*') => {
                open += 1;
                i += 2;
            }
            (b'*', b'/') => {
                open -= 1;
                i += 2;
                if open == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    b.len()
}

/// Index just past the string whose opening quote is at `quote`, opened
/// by `hashes` `#` before it. A quoted string ends at the first `"` that
/// is not escaped; a raw string has no escapes and ends at a `"`
/// followed by at least as many `#` as opened it.
fn string_end(b: &[u8], quote: usize, hashes: usize) -> usize {
    let mut i = quote + 1;
    while i < b.len() {
        match b[i] {
            b'\\' if hashes == 0 => i += 2,
            b'"' => {
                let after = i + 1;
                if b[after..].iter().take_while(|c| **c == b'#').count() >= hashes {
                    return after + hashes;
                }
                i = after;
            }
            _ => i += 1,
        }
    }
    b.len()
}

/// Line number, counting from one, of the byte at `offset` in `text`.
fn line_at(text: &str, offset: usize) -> Option<u32> {
    let before = text.get(..offset)?;
    u32::try_from(before.bytes().filter(|b| *b == b'\n').count() + 1).ok()
}

/// The parsed layer and where its nodes are: `--explain` names the node
/// a bwrap argument came from.
fn parse_doc(text: &str, profile: bool) -> Result<(RawProfile, Lines), ConfigError> {
    let doc: KdlDocument = parse_document(text)?;
    let mut cfg = InstanceConfig::default();
    let mut lines = Lines::default();
    let mut includes: Vec<String> = Vec::new();
    let mut seen_tty = false;
    let mut seen_userns = false;
    let mut seen_seccomp = false;
    for node in doc.nodes() {
        let name = node.name().value();
        reject_types(node)?;
        // Resolved against the table rather than by falling off the end
        // of the match: an arm added without an entry there is a node
        // the catalogue never describes, and the two lists would drift.
        if !NODES.contains(&name) && name != "include" {
            return Err(ConfigError::UnknownNode(name.to_owned()));
        }
        match name {
            "dri" | "pipewire" | "pulseaudio" | "portals" | "notify" | "tray" | "hidraw" => {
                reject_entries(node)?;
                let svc = match name {
                    "dri" => Service::Dri,
                    "pipewire" => Service::Pipewire,
                    "pulseaudio" => Service::Pulseaudio,
                    "portals" => Service::Portals,
                    "notify" => Service::Notify,
                    "tray" => Service::Tray,
                    "hidraw" => Service::Hidraw,
                    // Unreachable through the arm above, and an error
                    // rather than a fallback: a name added to that list
                    // and forgotten here would otherwise grant whichever
                    // service the fallback named.
                    other => return Err(ConfigError::UnknownNode(other.to_owned())),
                };
                if cfg.services.contains(&svc) {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(svc);
            }
            "home-share" => {
                let (path, mode) = parse_share(node, "path", validate_relative)?;
                // The path alone, not the path and the mode: nothing
                // downstream chooses between two modes for one home path,
                // so file order would decide how wide the share is.
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::HomeShare { path: held, .. } if *held == path))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(Service::HomeShare { path, mode });
            }
            "path-share" => {
                let (path, mode) = parse_share(node, "path", validate_absolute)?;
                let svc = Service::PathShare { path, mode };
                if cfg.services.contains(&svc) {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(svc);
            }
            "app-runtime" => {
                let (id, mode) = parse_share(node, "id", validate_app_id)?;
                // The id alone: one directory cannot be bound twice, so
                // two modes for one id would leave the width of the
                // grant to file order.
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::AppRuntime { id: held, .. } if *held == id))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(Service::AppRuntime { id, mode });
            }
            "etc-share" => {
                let svc = parse_etc_share(node)?;
                if cfg.services.contains(&svc) {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(svc);
            }
            "dbus" => {
                if has_dbus(&cfg.services) {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(parse_dbus(node)?);
            }
            "wayland" => {
                if node.children().is_some() {
                    return Err(bad(node, "takes no children"));
                }
                let mut mode = WaylandMode::default();
                let mut seen_mode = false;
                for e in node.entries() {
                    if let Some(p) = e.name() {
                        return Err(ConfigError::UnknownProperty {
                            node: name.to_owned(),
                            prop: p.value().to_owned(),
                        });
                    }
                    if seen_mode {
                        return Err(bad(node, "expects at most one mode argument"));
                    }
                    seen_mode = true;
                    let s = e
                        .value()
                        .as_string()
                        .ok_or_else(|| bad(node, "mode must be \"host\""))?;
                    mode = WaylandMode::from_str(s)?;
                }
                // By variant, like `network`: two `wayland` nodes differ
                // in mode, and which socket the config asks for would be
                // a matter of their order in the file.
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::Wayland(_)))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(Service::Wayland(mode));
            }
            "x11" => {
                // By variant, and before the node itself is read, like
                // `network`: two `x11` nodes differ in mode or window,
                // and which server the config asks for would be a matter
                // of their order in the file.
                if cfg.services.iter().any(|s| matches!(s, Service::X11(_))) {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(Service::X11(parse_x11(node)?));
            }
            "network" => {
                // By variant, like `gamepad`: two `network` nodes differ
                // in mode or children, and which sandbox the config asks
                // for would be a matter of their order in the file.
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::Network { .. }))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(parse_network(node)?);
            }
            "gamepad" => {
                // By variant: two `gamepad` nodes differing only in their
                // properties would leave the device list to file order.
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::Gamepad { .. }))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(parse_gamepad(node)?);
            }
            "camera" => {
                // By variant, for the same reason `gamepad` is.
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::Camera { .. }))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(parse_camera(node)?);
            }
            "system-bus" => {
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::SystemBus { .. }))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(parse_system_bus(node)?);
            }
            "mpris" => {
                if cfg
                    .services
                    .iter()
                    .any(|s| matches!(s, Service::Mpris { .. }))
                {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(parse_mpris(node)?);
            }
            "tty" => {
                if seen_tty {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                seen_tty = true;
                cfg.tty = parse_tty(node)?;
            }
            "userns" => {
                if seen_userns {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                seen_userns = true;
                cfg.userns = parse_userns(node)?;
            }
            "seccomp" => {
                if seen_seccomp {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                seen_seccomp = true;
                cfg.seccomp = parse_seccomp(node)?;
            }
            "env" => parse_env(node, &mut cfg.env)?,
            "lint-allow" => {
                let allow = parse_lint_allow(node)?;
                if cfg.lint_allows.iter().any(|a| a.id == allow.id) {
                    return Err(ConfigError::Duplicate(format!("{name} \"{}\"", allow.id)));
                }
                cfg.lint_allows.push(allow);
            }
            "include" => {
                if !profile {
                    return Err(bad(node, "include is only valid in profiles"));
                }
                includes.push(parse_include(node)?);
            }
            "desktop" => {
                if cfg.desktop.is_some() {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.desktop = Some(parse_desktop(node)?);
            }
            "command" => {
                if cfg.command.is_some() {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.command = Some(parse_command(node)?);
            }
            other => return Err(ConfigError::UnknownNode(other.to_owned())),
        }
        // What a node granted is counted rather than recorded per arm, so
        // a node added to the match above is placed without being listed
        // a second time here; only the two that grant nothing are named.
        let grew = lines.services.len() < cfg.services.len() || lines.env.len() < cfg.env.len();
        if grew || matches!(name, "userns" | "seccomp") {
            let line = line_at(text, node.span().offset());
            lines.services.resize(cfg.services.len(), line);
            lines.env.resize(cfg.env.len(), line);
            match name {
                "userns" => lines.userns = line,
                "seccomp" => lines.seccomp = line,
                _ => {}
            }
        }
    }
    if !profile && let Some(node) = bundle_without_dbus(&cfg.services) {
        return Err(ConfigError::BadArgument {
            node: node.to_owned(),
            reason: "requires dbus".to_owned(),
        });
    }
    if !profile && camera_without_portals(&cfg.services) {
        return Err(ConfigError::BadArgument {
            node: "camera".to_owned(),
            reason: "requires portals".to_owned(),
        });
    }
    if !profile && nested_x11_without_display_stack(&cfg.services) {
        return Err(ConfigError::BadArgument {
            node: "x11".to_owned(),
            reason: "requires wayland and dri".to_owned(),
        });
    }
    Ok((
        RawProfile {
            config: cfg,
            includes,
            tty_set: seen_tty,
            userns_set: seen_userns,
        },
        lines,
    ))
}

/// `include "<profile>"`: one string argument, repeatable. The name is
/// checked against the profile directories by the resolver, which is
/// where a name that cannot be looked up is a `NotFound`.
fn parse_include(node: &KdlNode) -> Result<String, ConfigError> {
    let name = one_string_arg(node)?;
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    Ok(name.to_owned())
}

/// Two `dbus` nodes hold different rules, so the grant is recognised by
/// its variant rather than by value.
fn has_dbus(services: &[Service]) -> bool {
    services.iter().any(|s| matches!(s, Service::Dbus { .. }))
}

/// The bundles are only sets of proxy rules; without `dbus` there is no
/// proxy to carry them, and the grant would be silently dropped.
fn bundle_without_dbus(services: &[Service]) -> Option<&'static str> {
    if has_dbus(services) {
        return None;
    }
    services.iter().find_map(|s| match s {
        Service::Portals => Some("portals"),
        Service::Notify => Some("notify"),
        Service::Tray => Some("tray"),
        Service::Mpris { .. } => Some("mpris"),
        _ => None,
    })
}

/// Whether a `camera` node is granted with no `portals` to carry it.
/// The portal is the whole of the bare grant and half of `nodes=#true`,
/// and without `/.flatpak-info` the portal reads the sandbox as an
/// ordinary process: the permission it stores is then the blanket one
/// every unsandboxed process on the machine shares, not this instance's.
fn camera_without_portals(services: &[Service]) -> bool {
    services.iter().any(|s| matches!(s, Service::Camera { .. }))
        && !services.contains(&Service::Portals)
}

/// Whether a nested `x11` is granted without what the server it starts
/// needs: the Xwayland inside is a Wayland client, and it renders
/// through glamor, which has no software path here — without `wayland`
/// it has nothing to connect to and without `dri` it dies on the first
/// frame, so the display the config promises would never exist.
fn nested_x11_without_display_stack(services: &[Service]) -> bool {
    services
        .iter()
        .any(|s| matches!(s, Service::X11(X11Mode::Nested(_))))
        && !(services.iter().any(|s| matches!(s, Service::Wayland(_)))
            && services.contains(&Service::Dri))
}

fn bad(node: &KdlNode, reason: &str) -> ConfigError {
    ConfigError::BadArgument {
        node: node.name().value().to_owned(),
        reason: reason.to_owned(),
    }
}

/// KDL type annotations are syntax we do not interpret, so they must not
/// pass silently.
fn reject_types(node: &KdlNode) -> Result<(), ConfigError> {
    if node.ty().is_some() || node.entries().iter().any(|e| e.ty().is_some()) {
        return Err(bad(node, "type annotations are not supported"));
    }
    Ok(())
}

/// Flag-style services take no arguments, properties or children.
fn reject_entries(node: &KdlNode) -> Result<(), ConfigError> {
    reject_arguments(node)?;
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    Ok(())
}

fn reject_arguments(node: &KdlNode) -> Result<(), ConfigError> {
    if let Some(e) = node.entries().first() {
        if let Some(p) = e.name() {
            return Err(ConfigError::UnknownProperty {
                node: node.name().value().to_owned(),
                prop: p.value().to_owned(),
            });
        }
        return Err(bad(node, "takes no arguments"));
    }
    Ok(())
}

/// `<node> "<value>" [mode=ro|rw]`, the shape `home-share`, `path-share`
/// and `app-runtime` have in common; `validate` decides which values the
/// node accepts and normalises them, and `what` names them in its errors.
fn parse_share<T>(
    node: &KdlNode,
    what: &str,
    validate: fn(&KdlNode, &str) -> Result<T, ConfigError>,
) -> Result<(T, ShareMode), ConfigError> {
    let mut value: Option<T> = None;
    let mut mode = ShareMode::ReadOnly;
    for e in node.entries() {
        match e.name().map(|n| n.value()) {
            None => {
                if value.is_some() {
                    return Err(bad(node, &format!("expects exactly one {what} argument")));
                }
                let s = e
                    .value()
                    .as_string()
                    .ok_or_else(|| bad(node, &format!("{what} must be a string")))?;
                value = Some(validate(node, s)?);
            }
            Some("mode") => {
                mode = match e.value().as_string() {
                    Some("ro") => ShareMode::ReadOnly,
                    Some("rw") => ShareMode::ReadWrite,
                    _ => return Err(bad(node, "mode must be \"ro\" or \"rw\"")),
                };
            }
            Some(p) => {
                return Err(ConfigError::UnknownProperty {
                    node: node.name().value().to_owned(),
                    prop: p.to_owned(),
                });
            }
        }
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    let value = value.ok_or_else(|| bad(node, &format!("expects exactly one {what} argument")))?;
    Ok((value, mode))
}

/// The id of an `app-runtime` node. Validated as an application id
/// because that is what every consumer of the `app/` convention writes:
/// it rules out `.`, `..`, anything holding `/`, and every single-element
/// name, so an id can never name one of bubbler's own runtime children.
fn validate_app_id(node: &KdlNode, s: &str) -> Result<String, ConfigError> {
    if !dbus::is_valid_app_id(s) {
        return Err(bad(
            node,
            "expects an application id such as \"org.example.App\": at least two \
             `.`-separated elements of letters, digits and `_`, `-` allowed in the last",
        ));
    }
    Ok(s.to_owned())
}

fn parse_etc_share(node: &KdlNode) -> Result<Service, ConfigError> {
    let mut name: Option<OsString> = None;
    for e in node.entries() {
        if let Some(p) = e.name() {
            return Err(ConfigError::UnknownProperty {
                node: node.name().value().to_owned(),
                prop: p.value().to_owned(),
            });
        }
        if name.is_some() {
            return Err(bad(node, "expects exactly one name argument"));
        }
        let s = e
            .value()
            .as_string()
            .ok_or_else(|| bad(node, "name must be a string"))?;
        let mut c = Path::new(s).components();
        let (Some(Component::Normal(n)), None) = (c.next(), c.next()) else {
            return Err(bad(node, "name must be a single entry directly under /etc"));
        };
        if let Some(r) = RESERVED_ETC.iter().find(|r| n == OsStr::new(**r)) {
            return Err(bad(node, &format!("the sandbox owns /etc/{r}")));
        }
        name = Some(n.to_os_string());
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    let name = name.ok_or_else(|| bad(node, "expects exactly one name argument"))?;
    Ok(Service::EtcShare { name })
}

/// A D-Bus well-known name: at least two `[A-Za-z_-][A-Za-z0-9_-]*`
/// elements joined by `.`, where the last may be `*` to cover the name and
/// every name below it.
pub fn is_bus_name(s: &str) -> bool {
    is_name_glob(s, 2)
}

/// `mpris name` is a suffix of a bus name, so one element is enough there.
fn is_name_glob(s: &str, min_elements: usize) -> bool {
    let mut count = 0;
    let mut elements = s.split('.').peekable();
    while let Some(e) = elements.next() {
        count += 1;
        let last = elements.peek().is_none();
        if !is_name_element(e) && !(last && e == "*") {
            return false;
        }
    }
    count >= min_elements
}

fn is_name_element(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'-')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `dbus` itself is bare; every rule is a child node. Names are checked
/// here so a typo cannot become a silent hole in the proxy filter.
fn parse_dbus(node: &KdlNode) -> Result<Service, ConfigError> {
    Ok(Service::Dbus {
        rules: parse_bus_rules(node, true)?,
    })
}

/// `system-bus { see|talk|call|broadcast "<name>" }`: the children `dbus`
/// takes minus `own`, and at least one of them, since a bus that answers
/// nothing is not what the node was written for.
fn parse_system_bus(node: &KdlNode) -> Result<Service, ConfigError> {
    let rules = parse_bus_rules(node, false)?;
    if rules.is_empty() {
        return Err(bad(
            node,
            "expects at least one `see`, `talk`, `call` or `broadcast` rule",
        ));
    }
    Ok(Service::SystemBus { rules })
}

/// The rule children both bus nodes take, `own` among them only when
/// `own_allowed`.
fn parse_bus_rules(node: &KdlNode, own_allowed: bool) -> Result<Vec<BusRule>, ConfigError> {
    reject_arguments(node)?;
    let mut rules = Vec::new();
    let Some(children) = node.children() else {
        return Ok(rules);
    };
    for child in children.nodes() {
        reject_types(child)?;
        if child.children().is_some() {
            return Err(bad(child, "takes no children"));
        }
        let kind = child.name().value();
        let arg = one_string_arg(child)?;
        let rule = match kind {
            "see" | "talk" | "own" => {
                if kind == "own" && !own_allowed {
                    return Err(bad(node, "own is not allowed on the system bus"));
                }
                let name = bus_name(child, arg)?;
                match kind {
                    "see" => BusRule::See(name),
                    "talk" => BusRule::Talk(name),
                    _ => BusRule::Own(name),
                }
            }
            "call" | "broadcast" => {
                let (name, rule) = arg
                    .split_once('=')
                    .ok_or_else(|| bad(child, "expects \"<name>=<rule>\""))?;
                let name = bus_name(child, name)?;
                if rule.is_empty() || rule.chars().any(|c| c.is_whitespace() || c == '\0') {
                    return Err(bad(
                        child,
                        "rule after `=` must be non-empty and hold no whitespace",
                    ));
                }
                let rule = rule.to_owned();
                if kind == "call" {
                    BusRule::Call(name, rule)
                } else {
                    BusRule::Broadcast(name, rule)
                }
            }
            other => return Err(ConfigError::UnknownNode(other.to_owned())),
        };
        if let Some((name, level)) = rule.policy()
            && let Some((_, was)) = rules
                .iter()
                .filter_map(BusRule::policy)
                .find(|(n, _)| *n == name)
            && was != level
        {
            return Err(bad(
                node,
                &format!("grants `{name}` as `{was}` and as `{level}`; one name takes one policy"),
            ));
        }
        rules.push(rule);
    }
    Ok(rules)
}

/// The value is not echoed back: it is arbitrary text and may hold the
/// control bytes the error message would then carry.
fn bus_name(node: &KdlNode, s: &str) -> Result<String, ConfigError> {
    if !is_bus_name(s) {
        return Err(bad(
            node,
            "expects a D-Bus well-known name such as \"org.example.App\", \
             optionally ending in `.*`",
        ));
    }
    Ok(s.to_owned())
}

fn one_string_arg(node: &KdlNode) -> Result<&str, ConfigError> {
    if let Some(p) = node.entries().iter().find_map(|e| e.name()) {
        return Err(ConfigError::UnknownProperty {
            node: node.name().value().to_owned(),
            prop: p.value().to_owned(),
        });
    }
    let [e] = node.entries() else {
        return Err(bad(node, "expects exactly one string argument"));
    };
    e.value()
        .as_string()
        .ok_or_else(|| bad(node, "expects exactly one string argument"))
}

fn parse_mpris(node: &KdlNode) -> Result<Service, ConfigError> {
    let mut name: Option<String> = None;
    for e in node.entries() {
        match e.name().map(|n| n.value()) {
            Some("name") => {
                let s = e
                    .value()
                    .as_string()
                    .ok_or_else(|| bad(node, "name must be a string"))?;
                if !is_name_glob(s, 1) {
                    return Err(bad(
                        node,
                        "name must be dot-separated name elements, `*` allowed last",
                    ));
                }
                name = Some(s.to_owned());
            }
            Some(p) => {
                return Err(ConfigError::UnknownProperty {
                    node: node.name().value().to_owned(),
                    prop: p.to_owned(),
                });
            }
            None => return Err(bad(node, "expects a name=\"...\" property, not arguments")),
        }
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    let name = name.ok_or_else(|| bad(node, "expects a name=\"...\" property"))?;
    Ok(Service::Mpris { name })
}

/// bwrap 0.11.2 exits when `--setenv` is given an empty key or one holding
/// `=`, so only a C-identifier key can reach it.
fn is_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Names a byte that cannot appear in a value bubbler turns into an argv
/// element: `execve` cuts a string at NUL, and a line break would forge an
/// extra element in `--dry-run` output, which is one element per line.
fn forbidden_byte(s: &str) -> Option<&'static str> {
    s.bytes().find_map(|b| match b {
        0 => Some("a NUL byte"),
        b'\n' => Some("a newline"),
        b'\r' => Some("a carriage return"),
        _ => None,
    })
}

/// `lint-allow "<check-id>" reason="<text>"`. The id is resolved against
/// the check table, so a typo cannot leave a finding un-silenced and the
/// file's author none the wiser; an id whose check reports an error is
/// refused for the same reason, since nothing would ever silence it.
fn parse_lint_allow(node: &KdlNode) -> Result<LintAllow, ConfigError> {
    let mut id: Option<&str> = None;
    let mut reason: Option<&str> = None;
    for e in node.entries() {
        match e.name().map(|n| n.value()) {
            None => {
                if id.is_some() {
                    return Err(bad(node, "expects exactly one check id argument"));
                }
                id = Some(
                    e.value()
                        .as_string()
                        .ok_or_else(|| bad(node, "check id must be a string"))?,
                );
            }
            Some("reason") => {
                reason = Some(
                    e.value()
                        .as_string()
                        .ok_or_else(|| bad(node, "reason must be a string"))?,
                );
            }
            Some(p) => {
                return Err(ConfigError::UnknownProperty {
                    node: node.name().value().to_owned(),
                    prop: p.to_owned(),
                });
            }
        }
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    let id = id.ok_or_else(|| bad(node, "expects exactly one check id argument"))?;
    let Some(check) = crate::lint::check(id) else {
        // The id is echoed back only after the table has recognised the
        // shape of it: a plain kebab-case word carries no control bytes.
        let shape = id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        return Err(match shape {
            true => bad(node, &format!("`{id}` is not a lint check")),
            false => bad(
                node,
                "expects a lint check id such as \"x11-without-reason\"",
            ),
        });
    };
    if check.severity == crate::lint::Severity::Error {
        return Err(bad(
            node,
            &format!("`{id}` reports an error, and an error cannot be accepted away"),
        ));
    }
    let reason = reason.ok_or_else(|| bad(node, "expects a reason=\"...\" property"))?;
    if reason.trim().is_empty() {
        return Err(bad(node, "reason must say why the finding is accepted"));
    }
    if let Some(what) = forbidden_byte(reason) {
        return Err(bad(node, &format!("reason contains {what}")));
    }
    Ok(LintAllow {
        id: id.to_owned(),
        reason: reason.to_owned(),
    })
}

fn parse_env(node: &KdlNode, out: &mut Vec<(String, String)>) -> Result<(), ConfigError> {
    if node.entries().is_empty() {
        return Err(bad(node, "expects KEY=\"value\" properties"));
    }
    for e in node.entries() {
        let key = e
            .name()
            .ok_or_else(|| bad(node, "expects KEY=\"value\" properties, not arguments"))?
            .value();
        let val = e
            .value()
            .as_string()
            .ok_or_else(|| bad(node, "values must be strings"))?;
        if !is_env_key(key) {
            return Err(bad(node, &format!("`{key}` is not a usable variable name")));
        }
        if let Some(what) = forbidden_byte(val) {
            return Err(bad(node, &format!("value of {key} contains {what}")));
        }
        if RESERVED_ENV.contains(&key) {
            return Err(bad(
                node,
                &format!("{key} is set by bubbler and cannot be overridden"),
            ));
        }
        if out.iter().any(|(k, _)| k == key) {
            return Err(ConfigError::Duplicate(key.to_owned()));
        }
        out.push((key.to_owned(), val.to_owned()));
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    Ok(())
}

/// Only absolute paths whose every other component is a normal name. The
/// path is bound at what it says, so `..` in it would name one thing here
/// and another inside the sandbox.
fn validate_absolute(node: &KdlNode, s: &str) -> Result<PathBuf, ConfigError> {
    let p = Path::new(s);
    let mut comps = p.components();
    if comps.next() != Some(Component::RootDir) || !comps.all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(bad(
            node,
            "path must be absolute and contain no `.` or `..` component",
        ));
    }
    Ok(p.components().collect())
}

/// Only plain relative paths: every component must be a normal name.
fn validate_relative(node: &KdlNode, s: &str) -> Result<PathBuf, ConfigError> {
    let p = Path::new(s);
    if s.is_empty() || !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(bad(
            node,
            "path must be relative to the home directory and contain no `..`",
        ));
    }
    Ok(p.components().collect())
}

/// `network ["host"|"none"] { dns "<ip>"; allow-port <n> [udp=#true];
/// outbound "deny"; allow-out "<ip>[/<len>]" [port=<n>] [proto="tcp"];
/// no-ipv6 }`. The bare node is the sandbox's own network namespace,
/// which is the default; the two spellings name the host's namespace and
/// no namespace at all.
///
/// `dns` says what the sandbox's resolver file holds, so it belongs to
/// the two modes that have a network to carry a query; under `none` it
/// is refused. The other children configure the sandbox's own namespace
/// — the pasta sidecar and the nftables ruleset in it — and only the
/// isolated mode has one. None of them is ignored where it cannot apply:
/// that would leave a config granting less than it says. `allow-out`
/// without `outbound "deny"` is refused for the same reason from the
/// other side: it would name rules nothing installs.
fn parse_network(node: &KdlNode) -> Result<Service, ConfigError> {
    let mut cfg = NetworkConfig::default();
    let mut seen_mode = false;
    let mut seen_outbound = false;
    for e in node.entries() {
        if let Some(p) = e.name() {
            return Err(ConfigError::UnknownProperty {
                node: node.name().value().to_owned(),
                prop: p.value().to_owned(),
            });
        }
        if seen_mode {
            return Err(bad(node, "expects at most one mode argument"));
        }
        seen_mode = true;
        let s = e
            .value()
            .as_string()
            .ok_or_else(|| bad(node, "mode must be \"host\" or \"none\""))?;
        cfg.mode = NetworkMode::from_str(s)?;
    }
    for child in node.children().into_iter().flat_map(KdlDocument::nodes) {
        reject_types(child)?;
        if child.children().is_some() {
            return Err(bad(child, "takes no children"));
        }
        match child.name().value() {
            "dns" => {
                let ip = parse_dns(child)?;
                // The sandbox's loopback is its own, so such an address
                // names a resolver inside the sandbox and never the host
                // one meant. pasta refuses a loopback `--dns-forward` for
                // the same reason.
                if ip.is_loopback() && cfg.mode == NetworkMode::Isolated {
                    return Err(bad(
                        child,
                        "a loopback address is the sandbox's own loopback in an isolated \
                         network namespace, not the host's; name a routable resolver, or \
                         write `network \"host\"`",
                    ));
                }
                if cfg.dns.contains(&ip) {
                    return Err(ConfigError::Duplicate(format!("dns \"{ip}\"")));
                }
                cfg.dns.push(ip);
            }
            "allow-port" => {
                let f = parse_allow_port(child)?;
                if cfg.forwards.contains(&f) {
                    let udp = if f.udp { " udp=#true" } else { "" };
                    return Err(ConfigError::Duplicate(format!(
                        "allow-port {}{udp}",
                        f.port
                    )));
                }
                cfg.forwards.push(f);
            }
            "no-ipv6" => {
                reject_entries(child)?;
                if cfg.no_ipv6 {
                    return Err(ConfigError::Duplicate("no-ipv6".to_owned()));
                }
                cfg.no_ipv6 = true;
            }
            "outbound" => {
                if seen_outbound {
                    return Err(ConfigError::Duplicate("outbound".to_owned()));
                }
                seen_outbound = true;
                cfg.outbound = Outbound::from_str(one_string_arg(child)?)?;
            }
            "allow-out" => {
                let allowed = parse_allow_out(child)?;
                if cfg.allow_out.contains(&allowed) {
                    return Err(ConfigError::Duplicate(format!("allow-out {allowed}")));
                }
                cfg.allow_out.push(allowed);
            }
            other => return Err(ConfigError::UnknownNode(other.to_owned())),
        }
    }
    if cfg.mode == NetworkMode::None && !cfg.dns.is_empty() {
        return Err(bad(
            node,
            "`dns` names a resolver the sandbox would have to reach over a network, \
             and `none` grants none",
        ));
    }
    if cfg.mode != NetworkMode::Isolated {
        if !cfg.forwards.is_empty() {
            return Err(bad(
                node,
                "`allow-port` forwards into the sandbox's own network namespace, \
                 which `host` and `none` do not have",
            ));
        }
        if cfg.no_ipv6 {
            return Err(bad(
                node,
                "`no-ipv6` configures the pasta sidecar, which only the isolated \
                 network namespace runs",
            ));
        }
        if seen_outbound || !cfg.allow_out.is_empty() {
            return Err(bad(
                node,
                "`outbound` filters the sandbox's own network namespace, which `host` \
                 and `none` do not have; rules under `host` would land on the host's \
                 own ruleset",
            ));
        }
    }
    if cfg.no_ipv6
        && (cfg.dns.iter().any(IpAddr::is_ipv6) || cfg.allow_out.iter().any(|a| a.dest.is_ipv6()))
    {
        return Err(bad(
            node,
            "`no-ipv6` leaves the sandbox no IPv6 address, so an IPv6 `dns` or \
             `allow-out` under it names something nothing in the sandbox could reach",
        ));
    }
    if cfg.outbound != Outbound::Deny && !cfg.allow_out.is_empty() {
        return Err(bad(
            node,
            "`allow-out` names destinations that are only a rule under \
             `outbound \"deny\"`; without it nothing is filtered and nothing is \
             installed",
        ));
    }
    Ok(Service::Network(cfg))
}

/// `allow-out "<ip>[/<len>]" [port=<n>] [proto="tcp"|"udp"]`: one
/// destination, every port and both protocols unless the properties
/// narrow it.
fn parse_allow_out(node: &KdlNode) -> Result<AllowOut, ConfigError> {
    let mut dest: Option<Cidr> = None;
    let mut port: Option<u16> = None;
    let mut proto: Option<Proto> = None;
    for e in node.entries() {
        match e.name().map(|n| n.value()) {
            None => {
                if dest.is_some() {
                    return Err(bad(node, "expects exactly one destination argument"));
                }
                let s = e
                    .value()
                    .as_string()
                    .ok_or_else(|| bad(node, "destination must be a quoted address"))?;
                dest = Some(Cidr::from_str(s)?);
            }
            Some("port") => {
                if port.is_some() {
                    return Err(ConfigError::Duplicate("allow-out port".to_owned()));
                }
                port = Some(
                    e.value()
                        .as_integer()
                        .and_then(|n| u16::try_from(n).ok())
                        .filter(|n| *n != 0)
                        .ok_or_else(|| bad(node, "expects a port number from 1 to 65535"))?,
                );
            }
            Some("proto") => {
                if proto.is_some() {
                    return Err(ConfigError::Duplicate("allow-out proto".to_owned()));
                }
                let s = e
                    .value()
                    .as_string()
                    .ok_or_else(|| bad(node, "proto must be \"tcp\" or \"udp\""))?;
                proto = Some(Proto::from_str(s)?);
            }
            Some(p) => {
                return Err(ConfigError::UnknownProperty {
                    node: node.name().value().to_owned(),
                    prop: p.to_owned(),
                });
            }
        }
    }
    let dest = dest.ok_or_else(|| bad(node, "expects exactly one destination argument"))?;
    Ok(AllowOut { dest, port, proto })
}

/// `dns "<ip>"`. The value is not echoed back: it is arbitrary text and
/// may hold the control bytes the error message would then carry.
fn parse_dns(node: &KdlNode) -> Result<IpAddr, ConfigError> {
    let s = one_string_arg(node)?;
    IpAddr::from_str(s).map_err(|_| bad(node, "expects an IP address such as \"1.1.1.1\""))
}

/// `allow-port <n> [udp=#true]`: one port number, TCP unless the property
/// says otherwise.
fn parse_allow_port(node: &KdlNode) -> Result<Forward, ConfigError> {
    let mut port: Option<u16> = None;
    let mut udp: Option<bool> = None;
    for e in node.entries() {
        match e.name().map(|n| n.value()) {
            None => {
                if port.is_some() {
                    return Err(bad(node, "expects exactly one port argument"));
                }
                port = Some(
                    e.value()
                        .as_integer()
                        .and_then(|n| u16::try_from(n).ok())
                        .filter(|n| *n != 0)
                        .ok_or_else(|| bad(node, "expects a port number from 1 to 65535"))?,
                );
            }
            Some("udp") => {
                if udp.is_some() {
                    return Err(ConfigError::Duplicate("allow-port udp".to_owned()));
                }
                udp = Some(
                    e.value()
                        .as_bool()
                        .ok_or_else(|| bad(node, "udp must be #true or #false"))?,
                );
            }
            Some(p) => {
                return Err(ConfigError::UnknownProperty {
                    node: node.name().value().to_owned(),
                    prop: p.to_owned(),
                });
            }
        }
    }
    let port = port.ok_or_else(|| bad(node, "expects exactly one port argument"))?;
    Ok(Forward {
        port,
        udp: udp.unwrap_or(false),
    })
}

/// `gamepad [hidraw=#true] [uinput=#true]`: the bare node is the evdev
/// grant, and each property adds one more class of device node to it.
fn parse_gamepad(node: &KdlNode) -> Result<Service, ConfigError> {
    let mut hidraw: Option<bool> = None;
    let mut uinput: Option<bool> = None;
    for e in node.entries() {
        let Some(prop) = e.name().map(|n| n.value()) else {
            return Err(bad(node, "takes no arguments"));
        };
        let slot = match prop {
            "hidraw" => &mut hidraw,
            "uinput" => &mut uinput,
            _ => {
                return Err(ConfigError::UnknownProperty {
                    node: node.name().value().to_owned(),
                    prop: prop.to_owned(),
                });
            }
        };
        // Written twice, the two entries disagree about a device class
        // and the winner would be a matter of their order in the line.
        if slot.is_some() {
            return Err(ConfigError::Duplicate(format!(
                "{} {prop}",
                node.name().value()
            )));
        }
        *slot = Some(
            e.value()
                .as_bool()
                .ok_or_else(|| bad(node, &format!("{prop} must be #true or #false")))?,
        );
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    Ok(Service::Gamepad {
        hidraw: hidraw.unwrap_or(false),
        uinput: uinput.unwrap_or(false),
    })
}

/// `<width>x<height>`, both positive decimals, as Xwayland's
/// `-geometry` takes it. Returns the canonical spelling: a value the
/// parser accepted and rewrote differently would not survive being
/// written back to the config file.
fn parse_geometry(s: &str) -> Option<String> {
    let (w, h) = s.split_once('x')?;
    // No sign, no leading zero, no unit: `-1`, `01` and `1280px` are all
    // things Xwayland would read as something else.
    let positive = |part: &str| match part.bytes().all(|b| b.is_ascii_digit()) {
        true if !part.starts_with('0') => part.parse::<u32>().ok(),
        _ => None,
    };
    Some(format!("{}x{}", positive(w)?, positive(h)?))
}

/// `x11 ["host"] [geometry="WxH"] [fullscreen=#true] [grab=#true]`: the
/// bare node is a nested Xwayland the properties describe the window of.
/// A property with `"host"` is an error rather than a value dropped
/// quietly: the session's server is not this sandbox's to size.
fn parse_x11(node: &KdlNode) -> Result<X11Mode, ConfigError> {
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    let mut host = false;
    let mut seen_mode = false;
    let mut geometry: Option<String> = None;
    let mut fullscreen: Option<bool> = None;
    let mut grab: Option<bool> = None;
    for e in node.entries() {
        let Some(prop) = e.name().map(|n| n.value()) else {
            if seen_mode {
                return Err(bad(node, "expects at most one mode argument"));
            }
            seen_mode = true;
            let s = e
                .value()
                .as_string()
                .ok_or_else(|| bad(node, "mode must be \"host\""))?;
            if s != "host" {
                return Err(bad(node, &format!("expected `host`, got `{s}`")));
            }
            host = true;
            continue;
        };
        // Written twice, the two entries disagree about the window and
        // the winner would be a matter of their order in the line.
        let dup = || ConfigError::Duplicate(format!("{} {prop}", node.name().value()));
        match prop {
            "geometry" => {
                if geometry.is_some() {
                    return Err(dup());
                }
                let s = e
                    .value()
                    .as_string()
                    .ok_or_else(|| bad(node, "geometry must be a string like \"1280x720\""))?;
                geometry = Some(parse_geometry(s).ok_or_else(|| {
                    bad(
                        node,
                        &format!("geometry must be `<width>x<height>`, got `{s}`"),
                    )
                })?);
            }
            "fullscreen" | "grab" => {
                let slot = match prop {
                    "fullscreen" => &mut fullscreen,
                    _ => &mut grab,
                };
                if slot.is_some() {
                    return Err(dup());
                }
                *slot = Some(
                    e.value()
                        .as_bool()
                        .ok_or_else(|| bad(node, &format!("{prop} must be #true or #false")))?,
                );
            }
            other => {
                return Err(ConfigError::UnknownProperty {
                    node: node.name().value().to_owned(),
                    prop: other.to_owned(),
                });
            }
        }
    }
    let default = NestedX11::default();
    if host {
        if geometry.is_some() || fullscreen.is_some() || grab.is_some() {
            return Err(bad(node, "\"host\" takes no properties"));
        }
        return Ok(X11Mode::Host);
    }
    Ok(X11Mode::Nested(NestedX11 {
        geometry: geometry.unwrap_or(default.geometry),
        fullscreen: fullscreen.unwrap_or(default.fullscreen),
        grab: grab.unwrap_or(default.grab),
    }))
}

/// `camera [nodes=#true]`: the bare node is the portal grant, which
/// binds nothing, and the property adds the V4L2 device nodes to it.
fn parse_camera(node: &KdlNode) -> Result<Service, ConfigError> {
    let mut nodes: Option<bool> = None;
    for e in node.entries() {
        let Some(prop) = e.name().map(|n| n.value()) else {
            return Err(bad(node, "takes no arguments"));
        };
        if prop != "nodes" {
            return Err(ConfigError::UnknownProperty {
                node: node.name().value().to_owned(),
                prop: prop.to_owned(),
            });
        }
        // Written twice, the two entries disagree about the device nodes
        // and the winner would be a matter of their order in the line.
        if nodes.is_some() {
            return Err(ConfigError::Duplicate(format!(
                "{} {prop}",
                node.name().value()
            )));
        }
        nodes = Some(
            e.value()
                .as_bool()
                .ok_or_else(|| bad(node, &format!("{prop} must be #true or #false")))?,
        );
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    Ok(Service::Camera {
        nodes: nodes.unwrap_or(false),
    })
}

/// `userns "allow"|"disable"`, the same shape `tty` has.
fn parse_userns(node: &KdlNode) -> Result<Userns, ConfigError> {
    let arg = one_string_arg(node)?;
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    Userns::from_str(arg)
}

/// `tty "pty"|"passthrough"|"none"`. The name of the mode is the whole
/// node: an unknown one is an error, never a silent fallback to the
/// default, which would give the sandbox a terminal the file refused it.
fn parse_tty(node: &KdlNode) -> Result<TtyMode, ConfigError> {
    let arg = one_string_arg(node)?;
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    TtyMode::from_str(arg)
}

/// `seccomp` itself is bare; every rule is a child node. Names are resolved
/// by libseccomp here, so a typo cannot silently leave a syscall allowed
/// the profile meant to deny.
fn parse_seccomp(node: &KdlNode) -> Result<SeccompConfig, ConfigError> {
    reject_arguments(node)?;
    let mut cfg = SeccompConfig::default();
    let Some(children) = node.children() else {
        return Ok(cfg);
    };
    for child in children.nodes() {
        reject_types(child)?;
        if child.children().is_some() {
            return Err(bad(child, "takes no children"));
        }
        match child.name().value() {
            "allow" => {
                if let Some(p) = child.entries().iter().find_map(|e| e.name()) {
                    return Err(ConfigError::UnknownProperty {
                        node: "allow".to_owned(),
                        prop: p.value().to_owned(),
                    });
                }
                cfg.allow.extend(syscall_names(child)?);
            }
            "deny" => {
                let errno = deny_errno(child)?;
                for name in syscall_names(child)? {
                    if name == "prctl" {
                        // glibc and Chromium call `prctl` for themselves,
                        // so denying it breaks the sandbox from within.
                        return Err(bad(child, "glibc and Chromium need prctl"));
                    }
                    cfg.deny.push((name, errno));
                }
            }
            "disable" => {
                reject_entries(child)?;
                cfg.disable = true;
            }
            other => return Err(ConfigError::UnknownNode(other.to_owned())),
        }
    }
    Ok(cfg)
}

/// The syscall names argued to one `allow` or `deny` child. `errno` is
/// [`deny_errno`]'s business; any other property is an error.
fn syscall_names(node: &KdlNode) -> Result<Vec<String>, ConfigError> {
    let mut names = Vec::new();
    for e in node.entries() {
        if let Some(p) = e.name() {
            if p.value() == "errno" {
                continue;
            }
            return Err(ConfigError::UnknownProperty {
                node: node.name().value().to_owned(),
                prop: p.value().to_owned(),
            });
        }
        let s = e
            .value()
            .as_string()
            .ok_or_else(|| bad(node, "expects syscall names as strings"))?;
        names.push(syscall_name(node, s)?);
    }
    if names.is_empty() {
        return Err(bad(node, "expects at least one syscall name"));
    }
    Ok(names)
}

/// A name is echoed back only once it is known to be a plain identifier:
/// config text is untrusted and may hold the control bytes the error
/// message would then carry.
fn syscall_name(node: &KdlNode, s: &str) -> Result<String, ConfigError> {
    let plain = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !plain {
        return Err(bad(node, "expects a syscall name such as \"keyctl\""));
    }
    if syscall_number(s).is_none() {
        return Err(bad(
            node,
            &format!("`{s}` is not a syscall name libseccomp knows"),
        ));
    }
    Ok(s.to_owned())
}

/// `deny` without `errno` means `EPERM`; KDL lets a property repeat, and
/// the last one wins.
fn deny_errno(node: &KdlNode) -> Result<Errno, ConfigError> {
    let mut errno = Errno::Eperm;
    // Every occurrence is checked, not only the one KDL lets win: a
    // misspelled value that a later one overrides is still a mistake.
    for e in node
        .entries()
        .iter()
        .filter(|e| e.name().is_some_and(|n| n.value() == "errno"))
    {
        errno = match e.value().as_string() {
            Some("EPERM") => Errno::Eperm,
            Some("ENOSYS") => Errno::Enosys,
            _ => return Err(bad(node, "errno must be \"EPERM\" or \"ENOSYS\"")),
        };
    }
    Ok(errno)
}

/// `desktop "<name>.desktop"`: the basename of the vendor entry an
/// instance's launcher entry is written from. A basename and not a path,
/// because the entry is looked up in the XDG application directories; a
/// path here would name a file outside them that nothing re-checks.
fn parse_desktop(node: &KdlNode) -> Result<String, ConfigError> {
    let name = one_string_arg(node)?;
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    let plain = name
        .strip_suffix(".desktop")
        .is_some_and(|stem| !stem.is_empty() && !stem.contains('/') && stem != "." && stem != "..");
    if !plain || forbidden_byte(name).is_some() {
        // Not echoed back: the value is config text and may hold the
        // control bytes the error message would then carry.
        return Err(bad(
            node,
            "expects the file name of a desktop entry, such as \"org.example.App.desktop\"",
        ));
    }
    Ok(name.to_owned())
}

fn parse_command(node: &KdlNode) -> Result<Vec<OsString>, ConfigError> {
    let mut argv = Vec::new();
    for e in node.entries() {
        if let Some(p) = e.name() {
            return Err(ConfigError::UnknownProperty {
                node: node.name().value().to_owned(),
                prop: p.value().to_owned(),
            });
        }
        let s = e
            .value()
            .as_string()
            .ok_or_else(|| bad(node, "arguments must be strings"))?;
        if let Some(what) = forbidden_byte(s) {
            // Positional, not quoted back: echoing the value would put the
            // control byte in the error message too.
            return Err(bad(
                node,
                &format!("argument {} contains {what}", argv.len() + 1),
            ));
        }
        argv.push(OsString::from(s));
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
    }
    if argv.is_empty() {
        return Err(bad(node, "needs at least one argument"));
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn every_node_is_paired_with_the_line_it_is_on() {
        let text = "// a comment\nwayland\n\nnetwork\ntty \"none\"\n\
                    home-share \"Downloads\" mode=rw\nenv A=\"1\" B=\"2\"\n\
                    userns \"disable\"\nseccomp {\n    disable\n}\ncommand \"true\"\n";
        let cfg = parse(text).unwrap();
        let lines = node_lines(text).unwrap();
        assert_eq!(lines.services.len(), cfg.services.len());
        assert_eq!(lines.services, vec![Some(2), Some(4), Some(6)]);
        // One node setting two variables gives both its own line.
        assert_eq!(lines.env, vec![Some(7), Some(7)]);
        assert_eq!(lines.userns, Some(8));
        assert_eq!(lines.seccomp, Some(9));
        // A node that grants nothing takes no place in the lists.
        let bare = node_lines("tty \"none\"\ncommand \"x\"").unwrap();
        assert_eq!(bare, Lines::default());
        // A block node is reported at the line it opens on.
        assert_eq!(
            node_lines("wayland\ndbus {\n    talk \"org.a.B\"\n}\n")
                .unwrap()
                .services,
            vec![Some(1), Some(2)]
        );
    }

    #[test]
    fn the_terminal_mode_is_a_private_pty_unless_the_file_says_otherwise() {
        assert_eq!(parse("").unwrap().tty, TtyMode::Pty);
        assert_eq!(
            parse("tty \"passthrough\"").unwrap().tty,
            TtyMode::Passthrough
        );
        assert_eq!(parse("tty \"none\"").unwrap().tty, TtyMode::None);
        assert!(matches!(
            parse("tty \"weird\""),
            Err(ConfigError::BadArgument { node, .. }) if node == "tty"
        ));
        assert!(matches!(parse("tty"), Err(ConfigError::BadArgument { .. })));
        assert!(matches!(
            parse("tty \"pty\" \"none\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("tty \"pty\" { x; }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("tty \"pty\"\ntty \"none\""),
            Err(ConfigError::Duplicate(n)) if n == "tty"
        ));
    }

    #[test]
    fn user_namespaces_are_allowed_unless_the_file_disables_them() {
        assert_eq!(parse("").unwrap().userns, Userns::Allow);
        assert_eq!(parse("userns \"allow\"").unwrap().userns, Userns::Allow);
        assert_eq!(parse("userns \"disable\"").unwrap().userns, Userns::Disable);
        assert!(matches!(
            parse("userns \"off\""),
            Err(ConfigError::BadArgument { node, .. }) if node == "userns"
        ));
        assert!(matches!(
            parse("userns"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("userns \"allow\" \"disable\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("userns \"disable\" { x; }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("userns \"allow\"\nuserns \"disable\""),
            Err(ConfigError::Duplicate(n)) if n == "userns"
        ));
    }

    #[test]
    fn userns_set_says_whether_the_node_was_written() {
        assert!(!parse_profile("wayland").unwrap().userns_set);
        let raw = parse_profile("userns \"allow\"").unwrap();
        assert!(raw.userns_set);
        assert_eq!(raw.config.userns, Userns::Allow);
    }

    #[test]
    fn gamepad_device_classes_are_properties_that_default_to_false() {
        assert_eq!(
            parse("gamepad").unwrap().services,
            vec![Service::Gamepad {
                hidraw: false,
                uinput: false
            }]
        );
        assert_eq!(
            parse("gamepad hidraw=#true").unwrap().services,
            vec![Service::Gamepad {
                hidraw: true,
                uinput: false
            }]
        );
        assert_eq!(
            parse("gamepad uinput=#true hidraw=#false")
                .unwrap()
                .services,
            vec![Service::Gamepad {
                hidraw: false,
                uinput: true
            }]
        );
        assert!(matches!(
            parse("gamepad foo=#true"),
            Err(ConfigError::UnknownProperty { node, prop })
                if node == "gamepad" && prop == "foo"
        ));
        assert!(matches!(
            parse("gamepad hidraw=\"yes\""),
            Err(ConfigError::BadArgument { node, .. }) if node == "gamepad"
        ));
        assert!(matches!(
            parse("gamepad \"hidraw\""),
            Err(ConfigError::BadArgument { .. })
        ));
        // One grant however the two nodes differ: a second one would
        // otherwise decide the device list by file order.
        assert!(matches!(
            parse("gamepad\ngamepad uinput=#true"),
            Err(ConfigError::Duplicate(n)) if n == "gamepad"
        ));
        // Same for one property written twice, whichever way round.
        for text in [
            "gamepad uinput=#true uinput=#false",
            "gamepad uinput=#false uinput=#true",
            "gamepad hidraw=#true uinput=#true hidraw=#true",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::Duplicate(ref n)) if n.contains(' ')),
                "{text}: {:?}",
                parse(text)
            );
        }
    }

    #[test]
    fn parses_full_example() {
        let cfg = parse(
            r#"
            wayland
            dri
            x11
            network
            home-share "Downloads"
            home-share "Projects/x" mode=rw
            command "foot" "-e" "fish"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.services,
            vec![
                Service::Wayland(WaylandMode::Sandboxed),
                Service::Dri,
                Service::X11(X11Mode::Nested(NestedX11::default())),
                Service::Network(NetworkConfig::default()),
                Service::HomeShare {
                    path: "Downloads".into(),
                    mode: ShareMode::ReadOnly
                },
                Service::HomeShare {
                    path: "Projects/x".into(),
                    mode: ShareMode::ReadWrite
                },
            ]
        );
        assert_eq!(
            cfg.command.unwrap(),
            vec![OsString::from("foot"), "-e".into(), "fish".into()]
        );
    }

    /// The bare node and the one mode name it takes. A second `wayland`
    /// node is a duplicate whatever the two modes say: which socket the
    /// config asks for would otherwise be a matter of file order.
    #[test]
    fn wayland_host_parses_and_anything_else_is_refused() {
        let cfg = parse("wayland \"host\"\ncommand \"true\"").unwrap();
        assert!(cfg.services.contains(&Service::Wayland(WaylandMode::Host)));
        let bare = parse("wayland\ncommand \"true\"").unwrap();
        assert!(
            bare.services
                .contains(&Service::Wayland(WaylandMode::Sandboxed))
        );
        for bad in [
            "wayland \"other\"",
            "wayland 1",
            "wayland foo=\"host\"",
            "wayland { x }",
        ] {
            assert!(parse(&format!("{bad}\ncommand \"true\"")).is_err(), "{bad}");
        }
        assert!(matches!(
            parse("wayland\nwayland \"host\"\ncommand \"true\""),
            Err(ConfigError::Duplicate(n)) if n == "wayland"
        ));
    }

    /// The bare node with its properties, the one mode name it takes,
    /// and what neither of them accepts. A second `x11` node is a
    /// duplicate whatever the two modes say: which X server the config
    /// asks for would otherwise be a matter of file order.
    #[test]
    fn x11_parses_nested_properties_and_host_and_refuses_the_rest() {
        let base = "wayland\ndri\ncommand \"true\"\n";
        let d = parse(&format!("x11\n{base}")).unwrap();
        assert!(
            d.services
                .contains(&Service::X11(X11Mode::Nested(NestedX11::default())))
        );
        let p = parse(&format!(
            "x11 geometry=\"1920x1080\" fullscreen=#true grab=#true\n{base}"
        ))
        .unwrap();
        assert!(
            p.services
                .contains(&Service::X11(X11Mode::Nested(NestedX11 {
                    geometry: "1920x1080".into(),
                    fullscreen: true,
                    grab: true
                })))
        );
        let h = parse(&format!("x11 \"host\"\n{base}")).unwrap();
        assert!(h.services.contains(&Service::X11(X11Mode::Host)));
        for bad in [
            "x11 \"other\"",
            "x11 \"host\" grab=#true",
            "x11 geometry=\"wide\"",
            "x11 geometry=\"0x10\"",
            "x11 geometry=1920",
            "x11 fullscreen=1",
            "x11 foo=#true",
            "x11 { a }",
        ] {
            assert!(parse(&format!("{bad}\n{base}")).is_err(), "{bad}");
        }
        assert!(matches!(
            parse(&format!("x11\nx11 \"host\"\n{base}")),
            Err(ConfigError::Duplicate(n)) if n == "x11"
        ));
    }

    /// The server inside is a Wayland client and needs the GPU nodes to
    /// render, so a nested `x11` without either would start nothing:
    /// the file is refused rather than left to fail at launch. A profile
    /// layer may take both from an include, so only the flattened
    /// config an instance runs is checked.
    #[test]
    fn nested_x11_requires_wayland_and_dri_on_the_flattened_config() {
        for cfg in [
            "x11\ncommand \"true\"",
            "x11\nwayland\ncommand \"true\"",
            "x11\ndri\ncommand \"true\"",
        ] {
            assert!(
                matches!(parse(cfg), Err(ConfigError::BadArgument { node, reason })
                    if node == "x11" && reason == "requires wayland and dri"),
                "{cfg}"
            );
        }
        assert!(parse("x11 \"host\"\ncommand \"true\"").is_ok());
        assert!(parse_profile("x11").is_ok());
    }

    /// The argv is the contract with Xwayland, and the flags are fixed
    /// so the display cannot be listened on TCP or the server reset by a
    /// client: only the window the properties describe changes.
    #[test]
    fn xwayland_argv_is_fixed_and_ordered() {
        let w = NestedX11::default().xwayland_argv();
        assert_eq!(
            w,
            [
                "/usr/bin/Xwayland",
                ":0",
                "-noreset",
                "-nolisten",
                "tcp",
                "-ac",
                "-hidpi",
                "-decorate",
                "-geometry",
                "1280x720"
            ]
            .map(OsString::from)
        );
        let f = NestedX11 {
            geometry: "1x1".into(),
            fullscreen: true,
            grab: true,
        }
        .xwayland_argv();
        assert_eq!(
            f,
            [
                "/usr/bin/Xwayland",
                ":0",
                "-noreset",
                "-nolisten",
                "tcp",
                "-ac",
                "-hidpi",
                "-fullscreen",
                "-host-grab"
            ]
            .map(OsString::from)
        );
    }

    /// The three modes, and what a bare node means now.
    #[test]
    fn network_modes_are_the_bare_node_and_two_names() {
        let net = |text: &str| match parse(text).unwrap().services.as_slice() {
            [Service::Network(cfg)] => cfg.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(net("network").mode, NetworkMode::Isolated);
        assert_eq!(net("network \"host\"").mode, NetworkMode::Host);
        assert_eq!(net("network \"none\"").mode, NetworkMode::None);
        for bad in [
            "network \"isolated\"",
            "network \"pasta\"",
            "network \"host\" \"none\"",
            "network #true",
            "network mode=\"host\"",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn network_children_are_dns_allow_port_and_no_ipv6() {
        let cfg = parse(
            "network {\n    dns \"1.1.1.1\"\n    dns \"2606:4700:4700::1111\"\n    \
             allow-port 8080\n    allow-port 5353 udp=#true\n}",
        )
        .unwrap();
        let Some(Service::Network(net)) = cfg.services.first() else {
            panic!("{:?}", cfg.services)
        };
        assert_eq!(
            net.dns,
            vec![
                IpAddr::from([1, 1, 1, 1]),
                IpAddr::from_str("2606:4700:4700::1111").unwrap()
            ]
        );
        assert_eq!(
            net.forwards,
            vec![
                Forward {
                    port: 8080,
                    udp: false
                },
                Forward {
                    port: 5353,
                    udp: true
                }
            ]
        );
        assert!(!net.no_ipv6);
        // Its own node: `no-ipv6` and the IPv6 resolver above cannot
        // both hold, which the next test is about.
        let cfg = parse("network {\n    no-ipv6\n}").unwrap();
        let Some(Service::Network(net)) = cfg.services.first() else {
            panic!("{:?}", cfg.services)
        };
        assert!(net.no_ipv6);
    }

    /// `no-ipv6` is pasta's `-4`, which leaves the namespace no IPv6
    /// address: a v6 resolver or destination under it names something
    /// nothing in the sandbox could reach, so it is refused rather than
    /// written into a ruleset nothing can match.
    #[test]
    fn no_ipv6_refuses_the_ipv6_addresses_it_would_make_unreachable() {
        for text in [
            "network {\n    dns \"2606:4700:4700::1111\"\n    no-ipv6\n}",
            "network {\n    no-ipv6\n    outbound \"deny\"\n    \
             allow-out \"2606:4700:4700::1111\"\n}",
            "network {\n    no-ipv6\n    outbound \"deny\"\n    allow-out \"2606:4700::/32\"\n}",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { node, .. }) if node == "network"),
                "{text}: {:?}",
                parse(text)
            );
        }
        // The v4 halves of the same nodes are what `no-ipv6` leaves.
        assert!(
            parse(
                "network {\n    dns \"1.1.1.1\"\n    no-ipv6\n    outbound \"deny\"\n    \
                 allow-out \"1.1.1.1\"\n}"
            )
            .is_ok()
        );
    }

    /// The mode×child matrix: `dns` describes a file and is valid
    /// wherever there is a network to reach a resolver over; the other
    /// two configure the sidecar only the isolated mode runs. Each is
    /// refused rather than ignored where it cannot apply.
    #[test]
    fn sidecar_children_need_the_isolated_mode() {
        for mode in ["", " \"host\""] {
            let text = format!("network{mode} {{\n    dns \"1.1.1.1\"\n}}");
            assert!(parse(&text).is_ok(), "{text}");
        }
        // `none` is no network, so a nameserver named under it is a
        // server nothing in the sandbox could ever send a query to.
        let text = "network \"none\" {\n    dns \"1.1.1.1\"\n}";
        assert!(
            matches!(parse(text), Err(ConfigError::BadArgument { node, .. }) if node == "network"),
            "{:?}",
            parse(text)
        );
        for child in ["allow-port 80", "no-ipv6"] {
            let ok = format!("network {{\n    {child}\n}}");
            assert!(parse(&ok).is_ok(), "{ok}");
            for mode in ["\"host\"", "\"none\""] {
                let text = format!("network {mode} {{\n    {child}\n}}");
                assert!(
                    matches!(parse(&text), Err(ConfigError::BadArgument { node, .. }) if node == "network"),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn network_child_arguments_are_checked() {
        for bad in [
            "network {\n    dns \"not-an-ip\"\n}",
            "network {\n    dns\n}",
            "network {\n    allow-port 0\n}",
            "network {\n    allow-port 65536\n}",
            "network {\n    allow-port -1\n}",
            "network {\n    allow-port \"80\"\n}",
            "network {\n    allow-port 80 tcp=#true\n}",
            "network {\n    no-ipv6 #true\n}",
            "network {\n    allow-ports 80\n}",
            "network {\n    dns \"1.1.1.1\" { x }\n}",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(parse("network {\n    allow-port 65535\n}").is_ok());
    }

    #[test]
    fn outbound_deny_takes_allow_out_children_with_ports_and_protocols() {
        let cfg = parse(
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\"\n    \
             allow-out \"140.82.112.0/20\" port=443 proto=\"tcp\"\n    \
             allow-out \"2606:4700:4700::1111\" port=853\n    \
             allow-out \"10.0.0.0/8\" proto=\"udp\"\n}",
        )
        .unwrap();
        let Some(Service::Network(net)) = cfg.services.first() else {
            panic!("{:?}", cfg.services)
        };
        assert_eq!(net.outbound, Outbound::Deny);
        let cidr = |s: &str| Cidr::from_str(s).unwrap();
        assert_eq!(
            net.allow_out,
            vec![
                AllowOut {
                    dest: cidr("1.1.1.1"),
                    port: None,
                    proto: None,
                },
                AllowOut {
                    dest: cidr("140.82.112.0/20"),
                    port: Some(443),
                    proto: Some(Proto::Tcp),
                },
                AllowOut {
                    dest: cidr("2606:4700:4700::1111"),
                    port: Some(853),
                    proto: None,
                },
                AllowOut {
                    dest: cidr("10.0.0.0/8"),
                    port: None,
                    proto: Some(Proto::Udp),
                },
            ]
        );
        // The default, and the spelling that says so on purpose.
        assert_eq!(
            parse("network").unwrap().services.first(),
            Some(&Service::Network(NetworkConfig::default()))
        );
        assert!(parse("network {\n    outbound \"allow\"\n}").is_ok());
    }

    /// A rule nothing installs is a config that grants less than it
    /// says, so `allow-out` needs its switch; and there is no namespace
    /// of bubbler's to filter outside the isolated mode, where rules
    /// would land on the host's own ruleset.
    #[test]
    fn outbound_needs_the_isolated_mode_and_allow_out_needs_outbound_deny() {
        let inert = "network {\n    allow-out \"1.1.1.1\"\n}";
        assert!(
            matches!(parse(inert), Err(ConfigError::BadArgument { node, .. }) if node == "network"),
            "{:?}",
            parse(inert)
        );
        let inert = "network {\n    outbound \"allow\"\n    allow-out \"1.1.1.1\"\n}";
        assert!(parse(inert).is_err(), "{inert}");
        for child in [
            "outbound \"deny\"",
            "outbound \"allow\"",
            "allow-out \"1.1.1.1\"",
        ] {
            for mode in ["\"host\"", "\"none\""] {
                let text = format!("network {mode} {{\n    {child}\n}}");
                assert!(
                    matches!(parse(&text), Err(ConfigError::BadArgument { node, .. }) if node == "network"),
                    "{text}: {:?}",
                    parse(&text)
                );
            }
        }
    }

    #[test]
    fn outbound_and_allow_out_arguments_are_checked() {
        for bad in [
            "network {\n    outbound\n}",
            "network {\n    outbound \"drop\"\n}",
            "network {\n    outbound \"deny\" \"allow\"\n}",
            "network {\n    outbound #true\n}",
            "network {\n    outbound \"deny\"\n    outbound \"deny\"\n}",
            "network {\n    outbound \"deny\"\n    allow-out\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" \"9.9.9.9\"\n}",
            "network {\n    outbound \"deny\"\n    allow-out 1\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"example.com\"\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1/24\"\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1/33\"\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=0\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=65536\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=\"443\"\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" proto=\"icmp\"\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" proto=#true\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" ports=443\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" { x }\n}",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\"\n    allow-out \"1.1.1.1\"\n}",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        // Narrowing the same address twice is two rules, not a duplicate.
        assert!(
            parse(
                "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443\n    \
                 allow-out \"1.1.1.1\" port=80\n}"
            )
            .is_ok()
        );
        assert!(parse("network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1/32\"\n}").is_ok());
    }

    /// pasta refuses a loopback `--dns-forward`, and for the same reason
    /// a loopback resolver in an isolated namespace names the sandbox
    /// itself. Under `host` the loopback is the host's own and a stub
    /// resolver there is the normal case.
    #[test]
    fn a_loopback_resolver_is_refused_only_where_it_would_be_the_sandbox() {
        for addr in ["127.0.0.1", "127.0.0.53", "::1"] {
            let isolated = format!("network {{\n    dns \"{addr}\"\n}}");
            assert!(
                matches!(parse(&isolated), Err(ConfigError::BadArgument { node, .. }) if node == "dns"),
                "{isolated}: {:?}",
                parse(&isolated)
            );
            let text = format!("network \"host\" {{\n    dns \"{addr}\"\n}}");
            assert!(parse(&text).is_ok(), "{text}");
        }
        assert!(parse("network {\n    dns \"1.1.1.1\"\n}").is_ok());
    }

    #[test]
    fn duplicate_network_nodes_and_children_are_errors() {
        for (text, name) in [
            ("network\nnetwork \"host\"", "network"),
            (
                "network {\n    dns \"1.1.1.1\"\n    dns \"1.1.1.1\"\n}",
                "dns \"1.1.1.1\"",
            ),
            (
                "network {\n    allow-port 80\n    allow-port 80\n}",
                "allow-port 80",
            ),
            ("network {\n    no-ipv6\n    no-ipv6\n}", "no-ipv6"),
            (
                "network {\n    outbound \"deny\"\n    outbound \"deny\"\n}",
                "outbound",
            ),
            // The whole child is named, not only its address: two rules
            // differing in a port are two rules, so a message that left
            // the port out would name something the file does not hold.
            (
                "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443 \
                 proto=\"tcp\"\n    allow-out \"1.1.1.1\" port=443 proto=\"tcp\"\n}",
                "allow-out \"1.1.1.1\" port=443 proto=\"tcp\"",
            ),
            (
                "network {\n    outbound \"deny\"\n    allow-out \"2606:4700::/32\"\n    \
                 allow-out \"2606:4700::/32\"\n}",
                "allow-out \"2606:4700::/32\"",
            ),
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::Duplicate(ref n)) if n == name),
                "{text}: {:?}",
                parse(text)
            );
        }
        // One port over two protocols is two grants, not a repeat.
        assert!(parse("network {\n    allow-port 80\n    allow-port 80 udp=#true\n}").is_ok());
        assert!(
            parse(
                "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443 \
                 proto=\"tcp\"\n    allow-out \"1.1.1.1\" port=443 proto=\"udp\"\n}"
            )
            .is_ok()
        );
    }

    #[test]
    fn empty_config_has_no_services_and_no_command() {
        let cfg = parse("").unwrap();
        assert!(cfg.services.is_empty());
        assert!(cfg.command.is_none());
    }

    #[test]
    fn unknown_node_is_an_error() {
        assert!(matches!(parse("bluetooth"), Err(ConfigError::UnknownNode(n)) if n == "bluetooth"));
    }

    #[test]
    fn device_and_audio_services_are_flag_nodes() {
        let cfg = parse("dri\npipewire\npulseaudio").unwrap();
        assert_eq!(
            cfg.services,
            vec![Service::Dri, Service::Pipewire, Service::Pulseaudio]
        );
        assert!(matches!(parse("dri\ndri"), Err(ConfigError::Duplicate(n)) if n == "dri"));
        assert!(matches!(
            parse("pulseaudio 1"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("pipewire foo=bar"),
            Err(ConfigError::UnknownProperty { .. })
        ));
    }

    #[test]
    fn hidraw_is_a_flag_node_and_coexists_with_the_gamepad_alias() {
        let cfg = parse("hidraw").unwrap();
        assert_eq!(cfg.services, vec![Service::Hidraw]);
        assert!(matches!(parse("hidraw\nhidraw"), Err(ConfigError::Duplicate(n)) if n == "hidraw"));
        assert!(matches!(
            parse("hidraw 1"),
            Err(ConfigError::BadArgument { .. })
        ));
        // `gamepad hidraw=#true` is the older spelling of the same grant,
        // so a config holding both is one grant written twice, not a
        // duplicate node.
        let cfg = parse("hidraw\ngamepad hidraw=#true").unwrap();
        assert_eq!(
            cfg.services,
            vec![
                Service::Hidraw,
                Service::Gamepad {
                    hidraw: true,
                    uinput: false
                }
            ]
        );
    }

    #[test]
    fn duplicate_flag_service_is_an_error() {
        assert!(
            matches!(parse("wayland\nwayland"), Err(ConfigError::Duplicate(n)) if n == "wayland")
        );
    }

    #[test]
    fn flag_service_rejects_arguments_and_properties() {
        assert!(matches!(
            parse("wayland 1"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("network foo=bar"),
            Err(ConfigError::UnknownProperty { .. })
        ));
    }

    #[test]
    fn home_share_rejects_absolute_and_parent_paths() {
        assert!(matches!(
            parse(r#"home-share "/etc""#),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse(r#"home-share "../x""#),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse(r#"home-share "a/../x""#),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn home_share_rejects_bad_mode_and_missing_path() {
        assert!(matches!(
            parse(r#"home-share "a" mode=wx"#),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("home-share"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse(r#"home-share "a" "b""#),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn command_needs_at_least_one_string() {
        assert!(matches!(
            parse("command"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("command 3"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse(
                r#"command "a"
command "b""#
            ),
            Err(ConfigError::Duplicate(_))
        ));
    }

    #[test]
    fn command_rejects_children() {
        assert!(matches!(
            parse(r#"command "a" { wayland }"#),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn type_annotations_are_rejected() {
        assert!(matches!(
            parse("(foo)wayland"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse(r#"home-share (t)"a""#),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn home_share_normalises_path() {
        // `PathBuf` compares component-wise, so assert on the stored bytes.
        for text in [
            r#"home-share "a//b""#,
            r#"home-share "a/./b""#,
            r#"home-share "a/b/""#,
        ] {
            let services = parse(text).unwrap().services;
            let [Service::HomeShare { path, .. }] = &services[..] else {
                panic!("expected exactly one home-share, got {services:?}");
            };
            assert_eq!(path.to_str().unwrap(), "a/b");
        }
    }

    #[test]
    fn home_share_rejects_one_path_twice_whatever_the_modes() {
        for text in [
            "home-share \"D\"\nhome-share \"D\"",
            "home-share \"D\"\nhome-share \"D\" mode=rw",
            "home-share \"D\" mode=rw\nhome-share \"D\"",
            "home-share \"D\"\nhome-share \"D/\"",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::Duplicate(n)) if n == "home-share"),
                "{text}"
            );
        }
        // A share below another is a different path, and the inner bind
        // lands on top of the outer one rather than replacing it.
        assert!(parse("home-share \"D\"\nhome-share \"D/sub\" mode=rw").is_ok());
    }

    #[test]
    fn path_share_takes_an_absolute_path_and_mode() {
        let cfg = parse("path-share \"/kioxia/Steam\"\npath-share \"/mnt/data\" mode=rw").unwrap();
        assert_eq!(
            cfg.services,
            vec![
                Service::PathShare {
                    path: "/kioxia/Steam".into(),
                    mode: ShareMode::ReadOnly
                },
                Service::PathShare {
                    path: "/mnt/data".into(),
                    mode: ShareMode::ReadWrite
                },
            ]
        );
    }

    #[test]
    fn path_share_rejects_relative_and_parent_paths() {
        for text in [
            r#"path-share "kioxia""#,
            r#"path-share "./kioxia""#,
            r#"path-share "../kioxia""#,
            r#"path-share "/a/../b""#,
            r#"path-share """#,
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { .. })),
                "{text}"
            );
        }
    }

    #[test]
    fn path_share_rejects_bad_mode_missing_and_extra_arguments() {
        for text in [
            r#"path-share "/a" mode=wx"#,
            "path-share",
            "path-share 3",
            r#"path-share "/a" "/b""#,
            r#"path-share (t)"/a""#,
            "path-share \"/a\" {\n    mode\n}",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { .. })),
                "{text}"
            );
        }
        assert!(matches!(
            parse(r#"path-share "/a" ro=#true"#),
            Err(ConfigError::UnknownProperty { .. })
        ));
    }

    #[test]
    fn path_share_normalises_path_and_rejects_the_same_node_twice() {
        // `PathBuf` compares component-wise, so assert on the stored bytes.
        for text in [
            r#"path-share "//kioxia/Steam""#,
            r#"path-share "/kioxia/./Steam""#,
            r#"path-share "/kioxia/Steam/""#,
        ] {
            let services = parse(text).unwrap().services;
            let [Service::PathShare { path, .. }] = &services[..] else {
                panic!("expected exactly one path-share, got {services:?}");
            };
            assert_eq!(path.to_str().unwrap(), "/kioxia/Steam");
        }
        assert!(matches!(
            parse("path-share \"/a\"\npath-share \"/a/\""),
            Err(ConfigError::Duplicate(n)) if n == "path-share"
        ));
        // Two modes for one path is not the same node; the launcher
        // rejects it as an overlap, with both paths named.
        assert!(parse("path-share \"/a\"\npath-share \"/a\" mode=rw").is_ok());
    }

    #[test]
    fn app_runtime_takes_an_application_id_and_mode() {
        let cfg = parse(
            "app-runtime \"org.keepassxc.KeePassXC\"\napp-runtime \"com.discordapp.Discord\" mode=rw",
        )
        .unwrap();
        assert_eq!(
            cfg.services,
            vec![
                Service::AppRuntime {
                    id: "org.keepassxc.KeePassXC".to_owned(),
                    mode: ShareMode::ReadOnly
                },
                Service::AppRuntime {
                    id: "com.discordapp.Discord".to_owned(),
                    mode: ShareMode::ReadWrite
                },
            ]
        );
    }

    #[test]
    fn app_runtime_rejects_an_id_that_could_name_another_runtime_entry() {
        // The first four are the names that would matter: `bubbler` holds
        // every instance's control socket, and the rest are traversal.
        for text in [
            r#"app-runtime "bubbler""#,
            r#"app-runtime "..""#,
            r#"app-runtime "../bubbler""#,
            r#"app-runtime "org.a/../../bubbler""#,
            r#"app-runtime ".flatpak""#,
            r#"app-runtime """#,
            r#"app-runtime "org.example.App!""#,
            r#"app-runtime "org.exa-mple.App""#,
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { node, .. }) if node == "app-runtime"),
                "{text}"
            );
        }
        // A `-` is allowed in the last element only, which is what the
        // portal's own grammar says.
        assert!(parse(r#"app-runtime "org.example.App-1""#).is_ok());
    }

    #[test]
    fn app_runtime_rejects_bad_mode_missing_and_extra_arguments() {
        for text in [
            r#"app-runtime "org.example.App" mode=wx"#,
            "app-runtime",
            "app-runtime 3",
            r#"app-runtime "org.example.App" "org.example.Other""#,
            r#"app-runtime (t)"org.example.App""#,
            "app-runtime \"org.example.App\" {\n    mode\n}",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { .. })),
                "{text}"
            );
        }
        assert!(matches!(
            parse(r#"app-runtime "org.example.App" rw=#true"#),
            Err(ConfigError::UnknownProperty { .. })
        ));
    }

    #[test]
    fn app_runtime_rejects_one_id_twice_whatever_the_modes() {
        for text in [
            "app-runtime \"org.example.App\"\napp-runtime \"org.example.App\"",
            "app-runtime \"org.example.App\"\napp-runtime \"org.example.App\" mode=rw",
            "app-runtime \"org.example.App\" mode=rw\napp-runtime \"org.example.App\"",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::Duplicate(n)) if n == "app-runtime"),
                "{text}"
            );
        }
        assert!(
            parse("app-runtime \"org.example.App\"\napp-runtime \"org.example.Other\"").is_ok()
        );
    }

    #[test]
    fn env_properties_are_collected_in_order() {
        let cfg = parse("env A=\"1\" B=\"two\"\nenv C=\"3\"").unwrap();
        assert_eq!(
            cfg.env,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two".into()),
                ("C".into(), "3".into())
            ]
        );
    }

    #[test]
    fn env_rejects_duplicates_reserved_args_and_non_strings() {
        assert!(
            matches!(parse("env A=\"1\"\nenv A=\"2\""), Err(ConfigError::Duplicate(k)) if k == "A")
        );
        assert!(matches!(
            parse("env HOME=\"/x\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("env PULSE_SERVER=\"x\""),
            Err(ConfigError::BadArgument { .. })
        ));
        // Either bus address would point a client at a socket bubbler
        // did not filter.
        for key in ["DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS"] {
            assert!(
                matches!(
                    parse(&format!(
                        "env {key}=\"unix:path=/run/dbus/system_bus_socket\""
                    )),
                    Err(ConfigError::BadArgument { .. })
                ),
                "{key}"
            );
        }
        assert!(matches!(
            parse("env \"A=1\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("env A=1"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(parse("env"), Err(ConfigError::BadArgument { .. })));
        assert!(matches!(
            parse("env \"\"=\"x\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("env \"A=B\"=\"x\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("env \"A B\"=\"x\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("env A=\"x\\u{0}y\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("env A=\"1\" { x }"),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn etc_share_takes_one_plain_name() {
        let cfg = parse("etc-share \"java\"").unwrap();
        assert_eq!(
            cfg.services,
            vec![Service::EtcShare {
                name: "java".into()
            }]
        );
        assert!(matches!(
            parse("etc-share \"a/b\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("etc-share \"..\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("etc-share \"a\" \"b\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("etc-share \"a\" mode=rw"),
            Err(ConfigError::UnknownProperty { .. })
        ));
        assert!(matches!(
            parse("etc-share \"a\"\netc-share \"a\""),
            Err(ConfigError::Duplicate(_))
        ));
        assert_eq!(
            parse("etc-share \"a/\"").unwrap().services,
            vec![Service::EtcShare { name: "a".into() }]
        );
        assert!(matches!(
            parse("etc-share \"a\"\netc-share \"a/\""),
            Err(ConfigError::Duplicate(_))
        ));
    }

    #[test]
    fn env_and_command_values_reject_bytes_that_cannot_be_argv() {
        for text in [
            r#"env A="x\ny""#,
            r#"env A="x\ry""#,
            r#"command "a\nb""#,
            r#"command "a\rb""#,
            r#"command "a\u{0}b""#,
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { .. })),
                "{text}"
            );
        }
        assert!(parse("env A=\"x y\"\ncommand \"a b\"").is_ok());
    }

    #[test]
    fn etc_share_refuses_the_account_files() {
        for name in [
            "passwd", "passwd-", "passwd+", "group", "group-", "group+", "shadow", "shadow-",
            "shadow+", "gshadow", "gshadow-", "gshadow+",
        ] {
            let r = parse(&format!("etc-share \"{name}\""));
            assert!(
                matches!(&r, Err(ConfigError::BadArgument { reason, .. }) if reason == &format!("the sandbox owns /etc/{name}")),
                "{name}: {r:?}"
            );
        }
        assert!(parse("etc-share \"passwdx\"").is_ok());
    }

    #[test]
    fn kdl_syntax_error_is_parse() {
        assert!(matches!(parse("wayland {"), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn dbus_children_and_bundles() {
        let cfg = parse(
            r#"
            dbus {
                talk "org.freedesktop.Notifications"
                own "org.mpris.MediaPlayer2.firefox.*"
                call "org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.Read@/org/freedesktop/portal/desktop"
                broadcast "org.freedesktop.portal.Desktop=@/org/freedesktop/portal/desktop"
            }
            portals
            notify
            mpris name="firefox.*"
            "#,
        )
        .unwrap();
        assert!(matches!(&cfg.services[0], Service::Dbus { rules } if rules.len() == 4));
        assert!(cfg.services.contains(&Service::Portals));
        assert!(cfg.services.contains(&Service::Notify));
        assert!(cfg.services.contains(&Service::Mpris {
            name: "firefox.*".into()
        }));
        let [Service::Dbus { rules }, ..] = &cfg.services[..] else {
            panic!("expected dbus first, got {:?}", cfg.services);
        };
        assert_eq!(
            rules[2],
            BusRule::Call(
                "org.freedesktop.portal.Desktop".into(),
                "org.freedesktop.portal.Settings.Read@/org/freedesktop/portal/desktop".into()
            )
        );
        assert_eq!(
            rules[3],
            BusRule::Broadcast(
                "org.freedesktop.portal.Desktop".into(),
                "@/org/freedesktop/portal/desktop".into()
            )
        );
    }

    #[test]
    fn see_talk_and_own_map_to_their_own_variants() {
        let cfg = parse("dbus { see \"a.b\"; talk \"c.d\"; own \"e.f\" }").unwrap();
        assert_eq!(
            cfg.services,
            vec![Service::Dbus {
                rules: vec![
                    BusRule::See("a.b".into()),
                    BusRule::Talk("c.d".into()),
                    BusRule::Own("e.f".into()),
                ]
            }]
        );
    }

    #[test]
    fn the_system_bus_takes_the_dbus_children_except_own() {
        let cfg = parse(
            r#"
            system-bus {
                see "org.freedesktop.NetworkManager"
                talk "org.freedesktop.UPower"
                call "org.freedesktop.UDisks2=org.freedesktop.DBus.ObjectManager.GetManagedObjects@/org/freedesktop/UDisks2"
                broadcast "org.freedesktop.UDisks2=@/org/freedesktop/UDisks2"
            }
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.services,
            vec![Service::SystemBus {
                rules: vec![
                    BusRule::See("org.freedesktop.NetworkManager".into()),
                    BusRule::Talk("org.freedesktop.UPower".into()),
                    BusRule::Call(
                        "org.freedesktop.UDisks2".into(),
                        "org.freedesktop.DBus.ObjectManager.GetManagedObjects@/org/freedesktop/UDisks2"
                            .into()
                    ),
                    BusRule::Broadcast(
                        "org.freedesktop.UDisks2".into(),
                        "@/org/freedesktop/UDisks2".into()
                    ),
                ]
            }]
        );
    }

    #[test]
    fn the_system_bus_refuses_own_and_an_empty_node() {
        // The name would be owned with the proxy's credentials, which are
        // the user's own, so the message says so rather than parsing it.
        let Err(ConfigError::BadArgument { node, reason }) =
            parse("system-bus { own \"org.example.App\" }")
        else {
            panic!("own was accepted on the system bus");
        };
        assert_eq!(node, "system-bus");
        assert!(reason.contains("own"), "{reason}");
        // A bus that answers nothing is a node the user did not mean.
        for text in ["system-bus", "system-bus {}", "system-bus { }"] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { node, .. }) if node == "system-bus"),
                "{text}"
            );
        }
        assert!(matches!(
            parse("system-bus { talk \"a.b\" }\nsystem-bus { talk \"c.d\" }"),
            Err(ConfigError::Duplicate(n)) if n == "system-bus"
        ));
    }

    #[test]
    fn one_bus_name_takes_one_policy_in_a_node() {
        // Which of the two the proxy would then apply is argument order,
        // so the config is refused rather than resolved.
        for text in [
            "dbus { talk \"a.b\"; see \"a.b\" }",
            "dbus { own \"a.b\"; talk \"a.b\" }",
            "system-bus { see \"a.b\"; talk \"a.b\" }",
        ] {
            let Err(ConfigError::BadArgument { reason, .. }) = parse(text) else {
                panic!("{text} was accepted");
            };
            assert!(reason.contains("a.b"), "{text}: {reason}");
        }
        // A repeat of the same policy is one policy, and `call` and
        // `broadcast` filter messages rather than setting one.
        parse("dbus { talk \"a.b\"; talk \"a.b\" }").unwrap();
        parse("system-bus { see \"a.b\"; call \"a.b=c.d@/e\" }").unwrap();
        // Two names are two policies.
        parse("dbus { talk \"a.b\"; see \"a.c\" }").unwrap();
    }

    #[test]
    fn the_system_bus_stands_on_its_own_and_beside_the_session_one() {
        // The two buses are independent: a sandbox may have UPower and no
        // session bus at all.
        assert_eq!(
            parse("system-bus { talk \"org.freedesktop.UPower\" }")
                .unwrap()
                .services,
            vec![Service::SystemBus {
                rules: vec![BusRule::Talk("org.freedesktop.UPower".into())]
            }]
        );
        assert_eq!(
            parse("dbus\nsystem-bus { talk \"org.freedesktop.UPower\" }")
                .unwrap()
                .services,
            vec![
                Service::Dbus { rules: vec![] },
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())]
                }
            ]
        );
        // A bundle is a set of session-bus rules; the system bus does not
        // carry one.
        assert!(matches!(
            parse("system-bus { talk \"a.b\" }\nnotify"),
            Err(ConfigError::BadArgument { node, .. }) if node == "notify"
        ));
        for text in [
            "system-bus \"x\" { talk \"a.b\" }",
            "system-bus foo=1 { talk \"a.b\" }",
            "system-bus { talk \"a b\" }",
            "system-bus { hidraw \"a.b\" }",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_bundle_may_precede_the_dbus_node() {
        assert_eq!(
            parse("notify\ndbus").unwrap().services,
            vec![Service::Notify, Service::Dbus { rules: vec![] }]
        );
    }

    #[test]
    fn camera_is_a_portal_grant_with_an_optional_device_property() {
        let cfg = parse("dbus\nportals\ncamera").unwrap();
        assert_eq!(cfg.services.last(), Some(&Service::Camera { nodes: false }));
        assert_eq!(
            parse("dbus\nportals\ncamera nodes=#true")
                .unwrap()
                .services
                .last(),
            Some(&Service::Camera { nodes: true })
        );
        assert_eq!(
            parse("dbus\nportals\ncamera nodes=#false")
                .unwrap()
                .services
                .last(),
            Some(&Service::Camera { nodes: false })
        );
        // The portal is what carries the grant, and without
        // `/.flatpak-info` the sandbox falls into the blanket permission
        // every unsandboxed process on the machine shares.
        assert!(matches!(
            parse("dbus\ncamera"),
            Err(ConfigError::BadArgument { node, reason })
                if node == "camera" && reason == "requires portals"
        ));
        assert!(matches!(
            parse("dbus\ncamera nodes=#true"),
            Err(ConfigError::BadArgument { node, reason })
                if node == "camera" && reason == "requires portals"
        ));
        // A profile layer may take its `portals` from an include, so the
        // requirement is checked on the flattened config only.
        assert!(parse_profile("camera").is_ok());
        assert!(matches!(
            parse("dbus\nportals\ncamera foo=#true"),
            Err(ConfigError::UnknownProperty { node, prop })
                if node == "camera" && prop == "foo"
        ));
        assert!(matches!(
            parse("dbus\nportals\ncamera nodes=\"yes\""),
            Err(ConfigError::BadArgument { node, .. }) if node == "camera"
        ));
        assert!(matches!(
            parse("dbus\nportals\ncamera \"nodes\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus\nportals\ncamera { nodes; }"),
            Err(ConfigError::BadArgument { .. })
        ));
        // By variant, like `gamepad`: two nodes differing only in the
        // property would leave the device binds to file order.
        assert!(matches!(
            parse("dbus\nportals\ncamera\ncamera nodes=#true"),
            Err(ConfigError::Duplicate(n)) if n == "camera"
        ));
        assert!(matches!(
            parse("dbus\nportals\ncamera nodes=#true nodes=#false"),
            Err(ConfigError::Duplicate(n)) if n == "camera nodes"
        ));
    }

    #[test]
    fn tray_and_gamepad_are_bare_grants() {
        let cfg = parse("dbus\ntray\ngamepad").unwrap();
        assert_eq!(
            cfg.services,
            vec![
                Service::Dbus { rules: vec![] },
                Service::Tray,
                Service::Gamepad {
                    hidraw: false,
                    uinput: false
                }
            ]
        );
        assert!(matches!(
            parse("dbus\ntray\ntray"),
            Err(ConfigError::Duplicate(n)) if n == "tray"
        ));
        assert!(matches!(
            parse("gamepad\ngamepad"),
            Err(ConfigError::Duplicate(n)) if n == "gamepad"
        ));
        assert!(matches!(
            parse("tray"),
            Err(ConfigError::BadArgument { node, reason })
                if node == "tray" && reason == "requires dbus"
        ));
        // `gamepad` is device access, not a set of proxy rules, so it
        // stands on its own.
        assert!(parse("gamepad").is_ok());
        // A bare node nothing answers to is never some other grant.
        assert!(matches!(
            parse("joystick"),
            Err(ConfigError::UnknownNode(n)) if n == "joystick"
        ));
        assert!(matches!(
            parse("dbus\ntray \"x\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("gamepad { hidraw; }"),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn bundles_require_dbus_and_names_are_validated() {
        assert!(matches!(
            parse("notify"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus\nmpris"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus { talk \"nodots\" }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus { talk \"a.*.b\" }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus { talk \"a.b c\" }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus { call \"a.b\" }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus { call \"a.b=x y\" }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus { call \"a.b=\" }"),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus { frob \"a.b\" }"),
            Err(ConfigError::UnknownNode(_))
        ));
        assert!(matches!(
            parse("dbus\ndbus"),
            Err(ConfigError::Duplicate(_))
        ));
        assert!(matches!(
            parse("dbus { talk \"a.b\" }\ndbus"),
            Err(ConfigError::Duplicate(_))
        ));
        assert_eq!(
            parse("dbus").unwrap().services,
            vec![Service::Dbus { rules: vec![] }]
        );
        for ok in ["a.b", "org.freedesktop.portal.*", "a-b.c_d", "_a.b9"] {
            assert!(is_bus_name(ok), "{ok}");
        }
        for bad in [
            "a", ".a.b", "a..b", "a.9b", "a.*.b", "*", "a.b.", "a.b=", "",
        ] {
            assert!(!is_bus_name(bad), "{bad}");
        }
    }

    #[test]
    fn the_dbus_node_takes_no_arguments_and_its_rules_take_one_name_each() {
        assert!(matches!(
            parse("dbus \"x\""),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("dbus foo=bar"),
            Err(ConfigError::UnknownProperty { .. })
        ));
        assert!(matches!(
            parse("dbus\nnotify { talk \"a.b\" }"),
            Err(ConfigError::BadArgument { .. })
        ));
        for text in [
            "dbus { talk }",
            "dbus { talk 1 }",
            "dbus { talk \"a.b\" \"c.d\" }",
            "dbus { talk \"a.b\" { own \"c.d\" } }",
            "dbus { (t)talk \"a.b\" }",
            "dbus { talk (t)\"a.b\" }",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { .. })),
                "{text}"
            );
        }
        assert!(matches!(
            parse("dbus { talk \"a.b\" name=\"x\" }"),
            Err(ConfigError::UnknownProperty { .. })
        ));
        // The proxy takes repeated rules; deduplicating is the emitter's job.
        let cfg = parse("dbus { talk \"a.b\"\ntalk \"a.b\" }").unwrap();
        assert!(matches!(&cfg.services[0], Service::Dbus { rules } if rules.len() == 2));
    }

    #[test]
    fn mpris_name_is_a_bus_name_suffix() {
        assert_eq!(
            parse("dbus\nmpris name=\"firefox.*\"").unwrap().services,
            vec![
                Service::Dbus { rules: vec![] },
                Service::Mpris {
                    name: "firefox.*".into()
                }
            ]
        );
        assert_eq!(
            parse("dbus\nmpris name=\"firefox\"").unwrap().services[1],
            Service::Mpris {
                name: "firefox".into()
            }
        );
        for text in [
            "dbus\nmpris name=\"a b\"",
            "dbus\nmpris name=\"\"",
            "dbus\nmpris name=\".a\"",
            "dbus\nmpris name=\"9a\"",
            "dbus\nmpris name=\"a.*.b\"",
            "dbus\nmpris name=\"a.\"",
            "dbus\nmpris name=1",
            "dbus\nmpris \"firefox\"",
            "dbus\nmpris name=\"a\" { x }",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { .. })),
                "{text}"
            );
        }
        assert!(matches!(
            parse("dbus\nmpris nome=\"a\""),
            Err(ConfigError::UnknownProperty { .. })
        ));
        assert!(matches!(
            parse("dbus\nmpris name=\"a\"\nmpris name=\"b\""),
            Err(ConfigError::Duplicate(_))
        ));
        assert!(matches!(
            parse("dbus\nportals\nportals"),
            Err(ConfigError::Duplicate(_))
        ));
    }

    #[test]
    fn seccomp_children_collect_allows_and_denies_in_file_order() {
        let cfg = parse(
            r#"
            seccomp {
                allow "ptrace" "perf_event_open"
                deny "unshare" "setns"
                deny "clone3" errno="ENOSYS"
            }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.seccomp.allow, ["ptrace", "perf_event_open"]);
        assert_eq!(
            cfg.seccomp.deny,
            vec![
                ("unshare".to_owned(), Errno::Eperm),
                ("setns".to_owned(), Errno::Eperm),
                ("clone3".to_owned(), Errno::Enosys),
            ]
        );
        assert!(!cfg.seccomp.disable);
    }

    #[test]
    fn without_a_seccomp_node_the_default_denylist_stands() {
        assert_eq!(parse("").unwrap().seccomp, SeccompConfig::default());
        assert_eq!(parse("seccomp").unwrap().seccomp, SeccompConfig::default());
        assert_eq!(
            parse("seccomp { }").unwrap().seccomp,
            SeccompConfig::default()
        );
        assert!(parse("seccomp { disable }").unwrap().seccomp.disable);
        assert!(matches!(
            parse("seccomp\nseccomp"),
            Err(ConfigError::Duplicate(n)) if n == "seccomp"
        ));
    }

    #[test]
    fn a_syscall_no_architecture_in_the_filter_has_is_an_error_not_a_skip() {
        for text in [
            r#"seccomp { allow "nosuchcall" }"#,
            r#"seccomp { deny "nosuchcall" }"#,
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { node, .. }) if node == "allow" || node == "deny"),
                "{text}"
            );
        }
        assert!(parse(r#"seccomp { allow "keyctl" "clone3" }"#).is_ok());
        // `vm86old` is i386-only, and the filter carries i386 on x86_64,
        // so naming it there is a rule rather than a mistake.
        #[cfg(target_arch = "x86_64")]
        assert!(parse(r#"seccomp { allow "vm86old" }"#).is_ok());
    }

    #[test]
    fn prctl_can_never_be_denied() {
        let r = parse(r#"seccomp { deny "prctl" }"#);
        assert!(
            matches!(&r, Err(ConfigError::BadArgument { node, reason }) if node == "deny" && reason.contains("prctl")),
            "{r:?}"
        );
        assert!(parse(r#"seccomp { allow "prctl" }"#).is_ok());
    }

    #[test]
    fn a_repeated_errno_takes_the_last_one() {
        let cfg = parse(r#"seccomp { deny "read" errno="EPERM" errno="ENOSYS" }"#).unwrap();
        assert_eq!(cfg.seccomp.deny, [("read".to_owned(), Errno::Enosys)]);
        let cfg = parse(r#"seccomp { deny "read" errno="ENOSYS" errno="EPERM" }"#).unwrap();
        assert_eq!(cfg.seccomp.deny, [("read".to_owned(), Errno::Eperm)]);
        // Still checked, wherever it stands.
        assert!(matches!(
            parse(r#"seccomp { deny "read" errno="EIO" errno="EPERM" }"#),
            Err(ConfigError::BadArgument { .. })
        ));
    }

    #[test]
    fn seccomp_children_are_checked_like_the_dbus_ones() {
        assert!(matches!(
            parse(r#"seccomp "x""#),
            Err(ConfigError::BadArgument { .. })
        ));
        assert!(matches!(
            parse("seccomp foo=bar"),
            Err(ConfigError::UnknownProperty { .. })
        ));
        assert!(matches!(
            parse(r#"seccomp { frob "read" }"#),
            Err(ConfigError::UnknownNode(n)) if n == "frob"
        ));
        for text in [
            "seccomp { allow }",
            "seccomp { deny }",
            "seccomp { allow 1 }",
            r#"seccomp { allow "read" { deny "write" } }"#,
            r#"seccomp { (t)allow "read" }"#,
            r#"seccomp { allow (t)"read" }"#,
            r#"seccomp { allow "a b" }"#,
            r#"seccomp { allow "" }"#,
            r#"seccomp { deny "read" errno="EIO" }"#,
            r#"seccomp { deny "read" errno=1 }"#,
            r#"seccomp { disable "x" }"#,
            "seccomp { disable { x } }",
        ] {
            assert!(
                matches!(parse(text), Err(ConfigError::BadArgument { .. })),
                "{text}"
            );
        }
        assert!(matches!(
            parse(r#"seccomp { allow "read" errno="EPERM" }"#),
            Err(ConfigError::UnknownProperty { prop, .. }) if prop == "errno"
        ));
        assert!(matches!(
            parse(r#"seccomp { deny "read" foo="x" }"#),
            Err(ConfigError::UnknownProperty { .. })
        ));
    }

    #[test]
    fn include_is_a_profile_node_only() {
        let raw = parse_profile("include \"gui\"\nwayland\ninclude \"audio\"").unwrap();
        assert_eq!(raw.includes, vec!["gui".to_string(), "audio".to_string()]);
        assert_eq!(
            raw.config.services,
            vec![Service::Wayland(WaylandMode::Sandboxed)]
        );
        assert!(!raw.tty_set);

        let err = parse("include \"gui\"").unwrap_err();
        assert!(
            matches!(&err, ConfigError::BadArgument { node, .. } if node == "include"),
            "{err:?}"
        );
        assert!(err.to_string().contains("only valid in profiles"), "{err}");

        for text in [
            "include",
            "include \"a\" \"b\"",
            "include name=\"a\"",
            "include \"a\" { x; }",
        ] {
            assert!(parse_profile(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_profile_layer_may_leave_the_dbus_grant_to_a_lower_one() {
        // The bundle check belongs to the merged result, not to a layer
        // that only adds `notify` on top of an included `dbus`.
        assert!(parse_profile("include \"base\"\nnotify").is_ok());
        assert!(matches!(
            parse("notify"),
            Err(ConfigError::BadArgument { node, .. }) if node == "notify"
        ));
    }

    #[test]
    fn lint_allow_names_a_check_and_says_why() {
        let cfg =
            parse("lint-allow \"x11-without-reason\" reason=\"the client has no Wayland backend\"")
                .unwrap();
        assert_eq!(
            cfg.lint_allows,
            vec![LintAllow {
                id: "x11-without-reason".to_owned(),
                reason: "the client has no Wayland backend".to_owned(),
            }]
        );
        assert!(parse("").unwrap().lint_allows.is_empty());
    }

    #[test]
    fn lint_allow_refuses_what_it_could_never_silence() {
        // A typo, a check that reports an error, and a node that names no
        // check at all: each would be a suppression that suppresses
        // nothing, and nothing would ever say so.
        for text in [
            "lint-allow \"x11-without-reasons\" reason=\"typo\"",
            "lint-allow \"bundle-without-dbus\" reason=\"no\"",
            "lint-allow reason=\"nothing to allow\"",
            "lint-allow \"x11-without-reason\"",
            "lint-allow \"x11-without-reason\" reason=\"  \"",
            "lint-allow \"x11-without-reason\" \"seccomp-disabled\" reason=\"two\"",
            "lint-allow \"x11-without-reason\" why=\"wrong property\"",
            "lint-allow \"x11-without-reason\" reason=\"r\" { x; }",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(matches!(
            parse(
                "lint-allow \"x11-without-reason\" reason=\"a\"\nlint-allow \"x11-without-reason\" reason=\"b\""
            ),
            Err(ConfigError::Duplicate(_))
        ));
    }

    #[test]
    fn tty_set_says_whether_the_node_was_written() {
        assert!(!parse_profile("wayland").unwrap().tty_set);
        let raw = parse_profile("tty \"pty\"").unwrap();
        assert!(raw.tty_set);
        assert_eq!(raw.config.tty, TtyMode::Pty);
    }

    #[test]
    fn the_node_table_is_the_list_of_nodes_the_parser_takes() {
        // Every name in the table reaches an arm of its own: a name the
        // table holds and the parser does not would be a node the
        // catalogue describes and no config can hold.
        for node in NODES {
            let err = parse(node).err();
            assert!(
                !matches!(err, Some(ConfigError::UnknownNode(_))),
                "`{node}` is in NODES and the parser does not take it"
            );
        }
        assert!(matches!(
            parse("teleport"),
            Err(ConfigError::UnknownNode(n)) if n == "teleport"
        ));
        // `include` is the one node only a profile takes, so it is not in
        // the table an instance config is measured against.
        assert!(!NODES.contains(&"include"));
        assert!(parse_profile("include \"generic\"").is_ok());
        let mut sorted = NODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), NODES.len(), "NODES holds a name twice");
    }

    #[test]
    fn every_grant_knows_the_node_it_is_written_as() {
        for (text, node) in [
            ("wayland", "wayland"),
            ("x11", "x11"),
            ("network \"host\"", "network"),
            ("dri", "dri"),
            ("pipewire", "pipewire"),
            ("pulseaudio", "pulseaudio"),
            ("home-share \"Downloads\"", "home-share"),
            ("path-share \"/mnt/data\"", "path-share"),
            ("etc-share \"vulkan\"", "etc-share"),
            ("app-runtime \"org.example.App\"", "app-runtime"),
            ("dbus", "dbus"),
            (
                "system-bus { talk \"org.freedesktop.UPower\" }",
                "system-bus",
            ),
            ("portals", "portals"),
            ("notify", "notify"),
            ("tray", "tray"),
            ("gamepad", "gamepad"),
            ("hidraw", "hidraw"),
            ("camera", "camera"),
            ("mpris name=\"x\"", "mpris"),
        ] {
            let cfg = parse_profile(text)
                .unwrap_or_else(|e| panic!("{text}: {e}"))
                .config;
            let [svc] = cfg.services.as_slice() else {
                panic!("{text} granted no single service");
            };
            assert_eq!(svc.node_name(), node, "{text}");
            assert!(NODES.contains(&svc.node_name()), "{node} is not in NODES");
        }
    }

    #[test]
    fn the_desktop_node_names_one_entry_file_and_nothing_else() {
        assert_eq!(parse("").unwrap().desktop, None);
        assert_eq!(
            parse("desktop \"org.mozilla.Thunderbird.desktop\"")
                .unwrap()
                .desktop
                .as_deref(),
            Some("org.mozilla.Thunderbird.desktop")
        );
        // A path, a name that is not an entry, and every shape that is
        // not one string: each would name a file the lookup would have to
        // guess at.
        for text in [
            "desktop \"/usr/share/applications/kitty.desktop\"",
            "desktop \"sub/kitty.desktop\"",
            "desktop \"kitty\"",
            "desktop \".desktop\"",
            "desktop \"..desktop\"",
            "desktop \"\"",
            "desktop",
            "desktop \"a.desktop\" \"b.desktop\"",
            "desktop name=\"a.desktop\"",
            "desktop \"a.desktop\" { x; }",
            "desktop 1",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(matches!(
            parse("desktop \"a.desktop\"\ndesktop \"b.desktop\""),
            Err(ConfigError::Duplicate(n)) if n == "desktop"
        ));
    }

    /// Nesting the KDL parser would recurse into the stack on. The
    /// minimised input from the fuzzer: a node and nothing but open
    /// braces, which aborted the process before the bound existed.
    fn brace_bomb(n: usize) -> String {
        format!("a {}", "{".repeat(n))
    }

    /// `n` levels of well-formed children, which the parser accepts as
    /// far as the bound lets it reach.
    fn nested(n: usize) -> String {
        let mut s = String::new();
        for _ in 0..n {
            s.push_str("a {\n");
        }
        for _ in 0..n {
            s.push_str("}\n");
        }
        s
    }

    #[test]
    fn nesting_past_the_bound_is_refused_before_the_parser_recurses() {
        let evil = brace_bomb(1400);
        assert!(matches!(parse(&evil), Err(ConfigError::TooDeep { .. })));
        assert!(matches!(
            parse_profile(&evil),
            Err(ConfigError::TooDeep { .. })
        ));
        assert!(matches!(
            node_lines(&evil),
            Err(ConfigError::TooDeep { .. })
        ));
    }

    #[test]
    fn the_bound_admits_its_own_depth_and_stops_one_past_it() {
        // The parser and not the pre-check alone: this runs on the 2 MiB
        // stack a spawned thread has, where an unoptimised `kdl` 6.7.1
        // overflows at 62 levels. A bound the parser survives even there
        // is what [`MAX_NESTING`] is for, so a rise past what that stack
        // takes aborts this test rather than someone's process.
        assert!(parse_document(&nested(MAX_NESTING)).is_ok());
        assert!(matches!(
            check_bounds(&nested(MAX_NESTING + 1)),
            Err(ConfigError::TooDeep { line, max })
                if line == u32::try_from(MAX_NESTING).unwrap() + 1 && max == MAX_NESTING
        ));
        // And the whole way through: `parse` refuses it rather than
        // reaching the parser with it.
        assert!(matches!(
            parse_profile(&nested(MAX_NESTING + 1)),
            Err(ConfigError::TooDeep { .. })
        ));
    }

    #[test]
    fn a_configuration_past_the_size_bound_is_refused_unparsed() {
        let big = "// filler\n".repeat(MAX_BYTES / 10 + 1);
        assert!(big.len() > MAX_BYTES);
        assert!(matches!(
            parse(&big),
            Err(ConfigError::TooLarge { bytes, max }) if bytes == big.len() && max == MAX_BYTES
        ));
    }

    #[test]
    fn the_pre_check_counts_braces_outside_strings_and_comments() {
        let braces = "{".repeat(MAX_NESTING * 4);
        // A profile that grants what it says still parses, however many
        // braces its text holds where nesting is not what they mean.
        for text in [
            format!("// {braces}\ncommand \"true\"\n"),
            format!("/* {braces} */\ncommand \"true\"\n"),
            format!("/* /* {braces} */ */\ncommand \"true\"\n"),
            format!("command \"{braces}\"\n"),
            format!("command #\"{braces}\"#\n"),
            format!("command \"\"\"\n{braces}\n\"\"\"\n"),
            "dbus {\n    talk \"org.a.B\"\n}\ncommand \"true\"\n".to_owned(),
        ] {
            assert!(parse(&text).is_ok(), "{text}");
        }
    }
}
