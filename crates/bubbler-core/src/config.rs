//! KDL instance/profile configuration. Each top-level node is either a
//! service grant or `command`. Unknown nodes are errors: silently
//! ignoring a grant would produce a different sandbox than the file says.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use kdl::{KdlDocument, KdlNode};

pub use crate::error::ConfigError;
pub use crate::tty::TtyMode;

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
];

/// `/etc` entries `etc-share` may not name: the sandbox generates its own
/// `passwd` and `group`, and binding the host's account files back in
/// would undo that and leak the shadow hashes. The `-` and `+` forms are
/// the backup and NIS-compatibility files next to them.
pub const RESERVED_ETC: &[&str] = &[
    "passwd", "passwd-", "passwd+", "group", "group-", "group+", "shadow", "shadow-", "shadow+",
    "gshadow", "gshadow-", "gshadow+",
];

/// Whether a shared path is writable inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    /// Bound with `--ro-bind` (default).
    ReadOnly,
    /// Bound with `--bind`.
    ReadWrite,
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

/// One granted resource. Order in the config file is irrelevant; the
/// builder's phases decide argv order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    /// Access to the host Wayland socket.
    Wayland,
    /// Access to the host X11 socket. X11 offers no isolation between
    /// clients; this is a compatibility grant, not a safe one.
    X11,
    /// Keep the host network namespace.
    Network,
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
    /// The XDG desktop portal rule bundle plus the `/.flatpak-info` file
    /// portals read to identify the sandbox. Requires [`Service::Dbus`].
    Portals,
    /// Talk to `org.freedesktop.Notifications`. Requires [`Service::Dbus`].
    Notify,
    /// Own `org.mpris.MediaPlayer2.<name>` so media keys and player
    /// controls reach the app. Requires [`Service::Dbus`].
    Mpris {
        /// Appended to `org.mpris.MediaPlayer2.`; `*` allowed as the last
        /// element.
        name: String,
    },
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
}

/// Parse KDL v2 text into an [`InstanceConfig`].
pub fn parse(text: &str) -> Result<InstanceConfig, ConfigError> {
    let doc: KdlDocument = KdlDocument::parse(text)?;
    let mut cfg = InstanceConfig::default();
    let mut seen_tty = false;
    for node in doc.nodes() {
        let name = node.name().value();
        reject_types(node)?;
        match name {
            "wayland" | "x11" | "network" | "dri" | "pipewire" | "pulseaudio" | "portals"
            | "notify" => {
                reject_entries(node)?;
                let svc = match name {
                    "wayland" => Service::Wayland,
                    "x11" => Service::X11,
                    "network" => Service::Network,
                    "dri" => Service::Dri,
                    "pipewire" => Service::Pipewire,
                    "portals" => Service::Portals,
                    "notify" => Service::Notify,
                    _ => Service::Pulseaudio,
                };
                if cfg.services.contains(&svc) {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(svc);
            }
            "home-share" => cfg.services.push(parse_home_share(node)?),
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
            "env" => parse_env(node, &mut cfg.env)?,
            "command" => {
                if cfg.command.is_some() {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.command = Some(parse_command(node)?);
            }
            other => return Err(ConfigError::UnknownNode(other.to_owned())),
        }
    }
    if let Some(node) = bundle_without_dbus(&cfg.services) {
        return Err(ConfigError::BadArgument {
            node: node.to_owned(),
            reason: "requires dbus".to_owned(),
        });
    }
    Ok(cfg)
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
        Service::Mpris { .. } => Some("mpris"),
        _ => None,
    })
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

fn parse_home_share(node: &KdlNode) -> Result<Service, ConfigError> {
    let mut path: Option<PathBuf> = None;
    let mut mode = ShareMode::ReadOnly;
    for e in node.entries() {
        match e.name().map(|n| n.value()) {
            None => {
                if path.is_some() {
                    return Err(bad(node, "expects exactly one path argument"));
                }
                let s = e
                    .value()
                    .as_string()
                    .ok_or_else(|| bad(node, "path must be a string"))?;
                path = Some(validate_relative(node, s)?);
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
    let path = path.ok_or_else(|| bad(node, "expects exactly one path argument"))?;
    Ok(Service::HomeShare { path, mode })
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
    reject_arguments(node)?;
    let mut rules = Vec::new();
    let Some(children) = node.children() else {
        return Ok(Service::Dbus { rules });
    };
    for child in children.nodes() {
        reject_types(child)?;
        if child.children().is_some() {
            return Err(bad(child, "takes no children"));
        }
        let kind = child.name().value();
        let arg = one_string_arg(child)?;
        rules.push(match kind {
            "see" | "talk" | "own" => {
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
        });
    }
    Ok(Service::Dbus { rules })
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
    fn parses_full_example() {
        let cfg = parse(
            r#"
            wayland
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
                Service::Wayland,
                Service::X11,
                Service::Network,
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
    fn a_bundle_may_precede_the_dbus_node() {
        assert_eq!(
            parse("notify\ndbus").unwrap().services,
            vec![Service::Notify, Service::Dbus { rules: vec![] }]
        );
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
    fn dbus_is_the_only_node_with_children() {
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
}
