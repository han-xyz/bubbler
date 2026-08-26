//! Canonical KDL for an [`InstanceConfig`]: what a flattened profile is
//! written back as. Every node the parser accepts, this writes, so
//! `parse(render(parse(text)))` is `parse(text)` again.

use std::ffi::{OsStr, OsString};

use crate::config::{
    BusRule, Clipboard, Disabled, InstanceConfig, LintAllow, NestedX11, Node, Service, ShareMode,
    Userns, WaylandMode, X11Mode,
};
use crate::error::ConfigError;
use crate::network::{Mode as NetworkMode, NetworkConfig, Outbound};
use crate::seccomp::{Errno, SeccompConfig};
use crate::tty::TtyMode;

/// Canonical KDL for `cfg`: the nodes in the order the config holds them,
/// one per line, block nodes indented by four spaces.
pub fn render(cfg: &InstanceConfig) -> Result<String, ConfigError> {
    let mut out = String::new();
    for node in nodes(cfg)? {
        out.push_str(&node);
        out.push('\n');
    }
    Ok(out)
}

/// The nodes of `cfg` as separate strings, so a caller can pair each with
/// where it came from. A block node is one multi-line string, and a
/// disabled entry is one node on its `/-` line.
pub fn nodes(cfg: &InstanceConfig) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    // Ahead of the grants: a finding the file has accepted is about the
    // file, and reading it first says what the nodes below were allowed
    // to be.
    section(
        cfg,
        |n| matches!(n, Node::LintAllow(_)),
        cfg.lint_allows.iter().map(lint_allow).collect(),
        &mut out,
    )?;
    let services: Vec<String> = cfg
        .services
        .iter()
        .map(service)
        .collect::<Result<_, ConfigError>>()?;
    section(cfg, |n| matches!(n, Node::Service(_)), services, &mut out)?;
    section(
        cfg,
        |n| matches!(n, Node::Env(_)),
        cfg.env.iter().map(|(k, v)| env(k, v)).collect(),
        &mut out,
    )?;
    section(
        cfg,
        |n| matches!(n, Node::Tty(_)),
        (cfg.tty != TtyMode::default())
            .then(|| tty(cfg.tty))
            .into_iter()
            .collect(),
        &mut out,
    )?;
    section(
        cfg,
        |n| matches!(n, Node::Userns(_)),
        (cfg.userns != Userns::default())
            .then(|| userns(cfg.userns))
            .into_iter()
            .collect(),
        &mut out,
    )?;
    section(
        cfg,
        |n| matches!(n, Node::Seccomp(_)),
        (cfg.seccomp != SeccompConfig::default())
            .then(|| seccomp(&cfg.seccomp))
            .into_iter()
            .collect(),
        &mut out,
    )?;
    section(
        cfg,
        |n| matches!(n, Node::Desktop(_)),
        cfg.desktop.iter().map(|n| desktop(n)).collect(),
        &mut out,
    )?;
    section(
        cfg,
        |n| matches!(n, Node::Command(_)),
        cfg.command
            .as_ref()
            .map(|argv| command(argv))
            .transpose()?
            .into_iter()
            .collect(),
        &mut out,
    )?;
    Ok(out)
}

/// One section of the file: its `enabled` nodes with the disabled
/// entries of the same section written back among them, each before the
/// entry it was read above. An entry pointing past the last one is
/// written after it rather than dropped: the section may have lost the
/// node it sat above since.
fn section(
    cfg: &InstanceConfig,
    is: fn(&Node) -> bool,
    enabled: Vec<String>,
    out: &mut Vec<String>,
) -> Result<(), ConfigError> {
    let end = enabled.len();
    for (i, node) in enabled.into_iter().enumerate() {
        for d in cfg.disabled.iter().filter(|d| is(&d.node) && d.before == i) {
            out.push(disabled(d)?);
        }
        out.push(node);
    }
    for d in cfg
        .disabled
        .iter()
        .filter(|d| is(&d.node) && d.before >= end)
    {
        out.push(disabled(d)?);
    }
    Ok(())
}

/// One parsed node as the KDL line it was read from. A node is one line,
/// or one block: what the emitter writes here is what
/// [`crate::config::NODES`] takes back.
pub fn node(n: &Node) -> Result<String, ConfigError> {
    Ok(match n {
        Node::Service(s) => service(s)?,
        Node::Env(pairs) => {
            // An `env` node without a variable is refused by the parser,
            // so writing one would produce KDL that no longer reads back.
            if pairs.is_empty() {
                return Err(ConfigError::BadArgument {
                    node: "env".to_owned(),
                    reason: "sets no variable, and an env node without one is not a config \
                             bubbler parses"
                        .to_owned(),
                });
            }
            let mut out = String::from("env");
            for (key, value) in pairs {
                out.push_str(&format!(" {key}={}", quote(value)));
            }
            out
        }
        // One node accepts one check id, and two of them would be two
        // lines: a `/-` prefix on the first would leave the second
        // granted.
        Node::LintAllow(allows) => match allows.as_slice() {
            [one] => lint_allow(one),
            other => {
                return Err(ConfigError::BadArgument {
                    node: "lint-allow".to_owned(),
                    reason: format!("accepts one check id, not {}", other.len()),
                });
            }
        },
        Node::Tty(mode) => tty(*mode),
        Node::Userns(mode) => userns(*mode),
        Node::Seccomp(cfg) => seccomp(cfg),
        Node::Desktop(name) => desktop(name),
        Node::Command(argv) => command(argv)?,
    })
}

/// One disabled entry as the line a config keeps it on. Only the first
/// line takes the `/-`: the rest of a block node is inside the node the
/// prefix drops, and a second prefix would be a comment in the children.
pub fn disabled(d: &Disabled) -> Result<String, ConfigError> {
    Ok(format!("/-{}", node(&d.node)?))
}

/// One grant as its KDL node.
pub fn service(s: &Service) -> Result<String, ConfigError> {
    // A new `Service` variant must be given a rendering here: a grant the
    // emitter drops would be a sandbox weaker than the profile it came from.
    Ok(match s {
        Service::Wayland(WaylandMode::Sandboxed { clipboard }) => match clipboard {
            // The default is the bare node: a property that says what the
            // node says already is one more thing to keep in step.
            Clipboard::Paste => "wayland".to_owned(),
            Clipboard::Open => "wayland clipboard=\"open\"".to_owned(),
        },
        Service::Wayland(WaylandMode::Host) => "wayland \"host\"".to_owned(),
        Service::X11(X11Mode::Nested(n)) => x11(n),
        Service::X11(X11Mode::Host) => "x11 \"host\"".to_owned(),
        Service::Network(cfg) => network(cfg),
        Service::Dri => "dri".to_owned(),
        Service::Pipewire => "pipewire".to_owned(),
        Service::Pulseaudio => "pulseaudio".to_owned(),
        Service::Portals => "portals".to_owned(),
        Service::Notify => "notify".to_owned(),
        Service::Tray => "tray".to_owned(),
        Service::A11y => "a11y".to_owned(),
        Service::InputMethod => "input-method".to_owned(),
        Service::Hidraw => "hidraw".to_owned(),
        Service::Camera { nodes } => match nodes {
            // `#false` is the default, so only the device grant is written.
            true => "camera nodes=#true".to_owned(),
            false => "camera".to_owned(),
        },
        Service::Gamepad { hidraw, uinput } => {
            let mut node = String::from("gamepad");
            // `#false` is the default, so only a granted class is written.
            for (name, on) in [("hidraw", hidraw), ("uinput", uinput)] {
                if *on {
                    node.push_str(&format!(" {name}=#true"));
                }
            }
            node
        }
        Service::HomeShare { path, mode } => {
            let path = text("home-share", "path", path.as_os_str())?;
            format!("home-share {} mode={}", quote(path), share_mode(*mode))
        }
        Service::PathShare { path, mode } => {
            let path = text("path-share", "path", path.as_os_str())?;
            format!("path-share {} mode={}", quote(path), share_mode(*mode))
        }
        Service::EtcShare { name } => {
            format!("etc-share {}", quote(text("etc-share", "name", name)?))
        }
        Service::AppRuntime { id, mode } => {
            format!("app-runtime {} mode={}", quote(id), share_mode(*mode))
        }
        Service::Mpris { name } => format!("mpris name={}", quote(name)),
        Service::Dbus { rules } => {
            if rules.is_empty() {
                return Ok("dbus".to_owned());
            }
            bus_block("dbus", rules)
        }
        Service::SystemBus { rules } => {
            // Unlike `dbus`, the parser refuses the node without rules, so
            // an empty one would render KDL that no longer reads back.
            if rules.is_empty() {
                return Err(ConfigError::BadArgument {
                    node: "system-bus".to_owned(),
                    reason: "has no rules, and a system bus without one is not a config \
                             bubbler parses"
                        .to_owned(),
                });
            }
            // `own` is refused there for the same reason the node itself
            // is narrow: the name would be owned with the user's own
            // credentials.
            if let Some(name) = rules.iter().find_map(|r| match r {
                BusRule::Own(n) => Some(n),
                _ => None,
            }) {
                return Err(ConfigError::BadArgument {
                    node: "system-bus".to_owned(),
                    reason: format!(
                        "owns `{name}`, and `own` on the system bus is not a config \
                         bubbler parses"
                    ),
                });
            }
            bus_block("system-bus", rules)
        }
    })
}

/// `node` cut to `max` characters for a display column, with the cut
/// marked `…`. Where something follows the node's first quoted argument
/// — the `mode=` of a share, a second argument, the brace closing a
/// block — the cut is made *inside* that argument so what follows stays
/// in view: a `home-share` whose mode fell off the end would hide the
/// one thing the reader is looking for. A node with nothing after its
/// argument, and one whose remainder does not fit on its own, is cut at
/// the end as any other text would be. Display only: the result is not
/// KDL the parser reads back.
pub fn shorten(node: &str, max: usize) -> String {
    if node.chars().count() <= max {
        return node.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    shorten_in_argument(node, max).unwrap_or_else(|| {
        node.chars()
            .take(max - 1)
            .chain(std::iter::once('…'))
            .collect()
    })
}

/// `node` cut inside its first quoted argument, or `None` where that
/// buys nothing: no quoted argument, nothing after it, or a remainder
/// leaving no room for even one character of the argument itself.
fn shorten_in_argument(node: &str, max: usize) -> Option<String> {
    let chars: Vec<char> = node.chars().collect();
    let open = chars.iter().position(|c| *c == '"')?;
    let close = closing_quote(&chars, open)?;
    if close + 1 == chars.len() {
        return None;
    }
    // The `…` takes a column of its own, between what is kept of the
    // argument and the closing quote.
    let budget = max
        .checked_sub(open + 1 + (chars.len() - close) + 1)
        .filter(|b| *b > 0)?;
    // Never end on a lone `\`, which would read as escaping the quote
    // the cut puts right after it.
    let inner = &chars[open + 1..close];
    let mut kept = budget.min(inner.len());
    while kept > 0
        && inner[..kept]
            .iter()
            .rev()
            .take_while(|c| **c == '\\')
            .count()
            % 2
            == 1
    {
        kept -= 1;
    }
    if kept == 0 {
        return None;
    }
    Some(
        chars[..=open]
            .iter()
            .chain(&inner[..kept])
            .chain(std::iter::once(&'…'))
            .chain(&chars[close..])
            .collect(),
    )
}

/// Index of the `"` closing the one at `open`, honouring `\"` inside it.
fn closing_quote(chars: &[char], open: usize) -> Option<usize> {
    let mut i = open + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// The `mode=` value of a share. Written on every share, default or
/// not: how wide a bind is open is what a reader of the file is looking
/// for, and a node that says nothing leaves them to remember the default.
fn share_mode(mode: ShareMode) -> &'static str {
    match mode {
        ShareMode::ReadOnly => "ro",
        ShareMode::ReadWrite => "rw",
    }
}

/// `x11` and only the properties that differ from the window a bare
/// node describes: a default written out would be read back as the same
/// server, and the shortest spelling is the one a user wrote.
fn x11(n: &NestedX11) -> String {
    let mut node = String::from("x11");
    if n.geometry != NestedX11::default().geometry {
        node.push_str(&format!(" geometry={}", quote(&n.geometry)));
    }
    // `#false` is the default, so only what the node turns on is written.
    for (name, on) in [("fullscreen", n.fullscreen), ("grab", n.grab)] {
        if on {
            node.push_str(&format!(" {name}=#true"));
        }
    }
    // A dropped `wm=` would give the instance back the unmanaged server
    // the user wrote the property to be rid of.
    if let Some(wm) = &n.wm {
        node.push_str(&format!(" wm={}", quote(wm)));
    }
    node
}

/// The `network` node: its mode where it is not the default, then one
/// line per child.
fn network(cfg: &NetworkConfig) -> String {
    let mut node = String::from("network");
    match cfg.mode {
        // Isolated is what a bare node means, so it is never written out.
        NetworkMode::Isolated => {}
        NetworkMode::Host => node.push_str(" \"host\""),
        NetworkMode::None => node.push_str(" \"none\""),
    }
    let mut kids: Vec<String> = Vec::new();
    // The switch first: it is what decides whether the `allow-out` lines
    // below it are rules or a parse error.
    if cfg.outbound == Outbound::Deny {
        kids.push("outbound \"deny\"".to_owned());
    }
    kids.extend(
        cfg.dns
            .iter()
            .map(|ip| format!("dns {}", quote(&ip.to_string()))),
    );
    // Rendered by the node itself, so the file a config is written back
    // as and the message that names a duplicate cannot disagree.
    for a in &cfg.allow_out {
        kids.push(format!("allow-out {a}"));
    }
    for f in &cfg.forwards {
        let udp = if f.udp { " udp=#true" } else { "" };
        kids.push(format!("allow-port {}{udp}", f.port));
    }
    if cfg.no_ipv6 {
        kids.push("no-ipv6".to_owned());
    }
    if kids.is_empty() {
        return node;
    }
    node.push_str(" {\n");
    for kid in kids {
        node.push_str(&format!("    {kid}\n"));
    }
    node.push('}');
    node
}

/// A bus node with its rule children, one per line.
fn bus_block(name: &str, rules: &[BusRule]) -> String {
    let mut node = format!("{name} {{\n");
    for r in rules {
        let (kind, arg) = match r {
            BusRule::See(n) => ("see", n.clone()),
            BusRule::Talk(n) => ("talk", n.clone()),
            BusRule::Own(n) => ("own", n.clone()),
            BusRule::Call(n, rule) => ("call", format!("{n}={rule}")),
            BusRule::Broadcast(n, rule) => ("broadcast", format!("{n}={rule}")),
        };
        node.push_str(&format!("    {kind} {}\n", quote(&arg)));
    }
    node.push('}');
    node
}

/// One `lint-allow "<id>" reason="<text>"` node.
pub fn lint_allow(a: &LintAllow) -> String {
    format!("lint-allow {} reason={}", quote(&a.id), quote(&a.reason))
}

/// One `env KEY="value"` node.
pub fn env(key: &str, value: &str) -> String {
    format!("env {key}={}", quote(value))
}

/// The `tty` node for `mode`.
pub fn tty(mode: TtyMode) -> String {
    let name = match mode {
        TtyMode::Pty => "pty",
        TtyMode::Passthrough => "passthrough",
        TtyMode::None => "none",
    };
    format!("tty {}", quote(name))
}

/// The `userns` node for `mode`.
pub fn userns(mode: Userns) -> String {
    let name = match mode {
        Userns::Allow => "allow",
        Userns::Disable => "disable",
    };
    format!("userns {}", quote(name))
}

/// The `seccomp` block for `cfg`, including an empty one.
pub fn seccomp(cfg: &SeccompConfig) -> String {
    let mut node = String::from("seccomp {\n");
    if !cfg.allow.is_empty() {
        let names: Vec<String> = cfg.allow.iter().map(|n| quote(n)).collect();
        node.push_str(&format!("    allow {}\n", names.join(" ")));
    }
    // One node per denial: `errno` is a property of the node, so grouping
    // would reorder the list when the two errnos are interleaved.
    for (name, errno) in &cfg.deny {
        let errno = match errno {
            Errno::Eperm => "EPERM",
            Errno::Enosys => "ENOSYS",
        };
        node.push_str(&format!(
            "    deny {} errno={}\n",
            quote(name),
            quote(errno)
        ));
    }
    if cfg.disable {
        node.push_str("    disable\n");
    }
    node.push('}');
    node
}

/// The `desktop` node naming the entry an instance's launcher entry is
/// written from.
pub fn desktop(name: &str) -> String {
    format!("desktop {}", quote(name))
}

/// The `command` node for `argv`.
pub fn command(argv: &[OsString]) -> Result<String, ConfigError> {
    let mut node = String::from("command");
    for a in argv {
        node.push(' ');
        node.push_str(&quote(text("command", "argument", a)?));
    }
    Ok(node)
}

/// Config values come from KDL text and are therefore UTF-8. A caller
/// that built an [`InstanceConfig`] by hand may not have kept that, and a
/// lossy rendering would name a different path than the grant did.
fn text<'a>(node: &str, what: &str, s: &'a OsStr) -> Result<&'a str, ConfigError> {
    s.to_str().ok_or_else(|| ConfigError::BadArgument {
        node: node.to_owned(),
        reason: format!("{what} is not valid UTF-8 and cannot be written as KDL"),
    })
}

/// `s` as a KDL v2 quoted string. Only escapes KDL defines are used, and
/// every other control character goes as `\u{..}`, so a value read out of
/// a config file goes back into one unchanged.
pub(crate) fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn round_trip(text: &str) {
        let cfg = parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        let rendered = render(&cfg).unwrap();
        let again = parse(&rendered).unwrap_or_else(|e| panic!("{rendered}: {e}"));
        assert_eq!(cfg, again, "rendered as:\n{rendered}");
    }

    /// Every shape the `network` node has: each mode, and the children
    /// in every combination the parser accepts.
    #[test]
    fn every_network_shape_round_trips() {
        for text in [
            "network\n",
            "network \"host\"\n",
            "network \"none\"\n",
            "network {\n    dns \"1.1.1.1\"\n}\n",
            "network \"host\" {\n    dns \"1.1.1.1\"\n    dns \"9.9.9.9\"\n}\n",
            "network \"host\" {\n    dns \"::1\"\n}\n",
            "network {\n    allow-port 8080\n}\n",
            "network {\n    allow-port 53 udp=#true\n}\n",
            "network {\n    no-ipv6\n}\n",
            "network {\n    outbound \"deny\"\n}\n",
            "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\"\n}\n",
            "network {\n    outbound \"deny\"\n    allow-out \"140.82.112.0/20\" port=443 \
             proto=\"tcp\"\n}\n",
            "network {\n    outbound \"deny\"\n    allow-out \"2606:4700::/32\" port=853\n}\n",
            "network {\n    outbound \"deny\"\n    allow-out \"10.0.0.0/8\" proto=\"udp\"\n}\n",
            "network {\n    outbound \"deny\"\n    dns \"1.1.1.1\"\n    \
             allow-out \"1.1.1.1\" port=53\n    allow-port 8080\n    \
             allow-port 53 udp=#true\n    no-ipv6\n}\n",
            "network {\n    dns \"1.1.1.1\"\n    allow-port 8080\n    \
             allow-port 53 udp=#true\n    no-ipv6\n}\n",
        ] {
            round_trip(text);
            // Canonical already: what the emitter writes is the input.
            assert_eq!(render(&parse(text).unwrap()).unwrap(), text);
        }
    }

    /// Both modes and the gate, since the emitter is what a saved config
    /// and `reseed` are written from: a dropped `"host"` would tighten
    /// the grant behind the user's back, a dropped bare node widen it,
    /// and a dropped `clipboard="open"` turn a gate back on under an
    /// application that was configured without one.
    #[test]
    fn both_wayland_modes_round_trip() {
        for (text, mode) in [
            ("wayland\n", WaylandMode::default()),
            ("wayland \"host\"\n", WaylandMode::Host),
            (
                "wayland clipboard=\"open\"\n",
                WaylandMode::Sandboxed {
                    clipboard: Clipboard::Open,
                },
            ),
        ] {
            round_trip(text);
            // Canonical already: what the emitter writes is the input.
            assert_eq!(render(&parse(text).unwrap()).unwrap(), text);
            assert_eq!(service(&Service::Wayland(mode)).unwrap(), text.trim_end());
        }
    }

    /// Both modes and every property, since the emitter is what a saved
    /// config and `reseed` are written from: a dropped `"host"` would
    /// tighten the grant behind the user's back, a dropped bare node
    /// widen it, and a dropped property hand a game a windowed server.
    #[test]
    fn both_x11_modes_and_their_properties_round_trip() {
        for (text, svc) in [
            ("x11\n", Service::X11(X11Mode::Nested(NestedX11::default()))),
            (
                "x11 geometry=\"1920x1080\"\n",
                Service::X11(X11Mode::Nested(NestedX11 {
                    geometry: "1920x1080".to_owned(),
                    ..NestedX11::default()
                })),
            ),
            (
                "x11 fullscreen=#true\n",
                Service::X11(X11Mode::Nested(NestedX11 {
                    fullscreen: true,
                    ..NestedX11::default()
                })),
            ),
            (
                "x11 grab=#true\n",
                Service::X11(X11Mode::Nested(NestedX11 {
                    grab: true,
                    ..NestedX11::default()
                })),
            ),
            (
                "x11 wm=\"openbox\"\n",
                Service::X11(X11Mode::Nested(NestedX11 {
                    wm: Some("openbox".to_owned()),
                    ..NestedX11::default()
                })),
            ),
            (
                "x11 geometry=\"1920x1080\" fullscreen=#true\n",
                Service::X11(X11Mode::Nested(NestedX11 {
                    geometry: "1920x1080".to_owned(),
                    fullscreen: true,
                    grab: false,
                    wm: None,
                })),
            ),
            (
                "x11 geometry=\"1920x1080\" fullscreen=#true grab=#true\n",
                Service::X11(X11Mode::Nested(NestedX11 {
                    geometry: "1920x1080".to_owned(),
                    fullscreen: true,
                    grab: true,
                    wm: None,
                })),
            ),
            (
                "x11 geometry=\"1920x1080\" fullscreen=#true grab=#true wm=\"twm\"\n",
                Service::X11(X11Mode::Nested(NestedX11 {
                    geometry: "1920x1080".to_owned(),
                    fullscreen: true,
                    grab: true,
                    wm: Some("twm".to_owned()),
                })),
            ),
            ("x11 \"host\"\n", Service::X11(X11Mode::Host)),
        ] {
            let cfg = format!("wayland\ndri\n{text}");
            round_trip(&cfg);
            // Canonical already: what the emitter writes is the input.
            assert_eq!(render(&parse(&cfg).unwrap()).unwrap(), cfg);
            assert_eq!(service(&svc).unwrap(), text.trim_end());
        }
    }

    #[test]
    fn every_builtin_profile_round_trips() {
        for name in crate::profile::NAMES {
            let text = crate::profile::lookup(name).expect("NAMES lists built-in profiles");
            round_trip(text);
        }
    }

    #[test]
    fn every_node_round_trips() {
        round_trip("");
        round_trip(
            r#"
            lint-allow "x11-without-reason" reason="the client has no Wayland backend"
            lint-allow "seccomp-disabled" reason="32-bit client"
            wayland
            x11
            network
            dri
            pipewire
            pulseaudio
            home-share "Downloads"
            home-share "Projects/x" mode=rw
            path-share "/kioxia/Steam"
            path-share "/mnt/data" mode=rw
            etc-share "vulkan"
            app-runtime "org.keepassxc.KeePassXC"
            app-runtime "com.discordapp.Discord" mode=rw
            dbus {
                see "org.freedesktop.ScreenSaver"
                talk "ca.desrt.dconf"
                own "org.example.App"
                call "org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.Read@/org/freedesktop/portal/desktop"
                broadcast "org.freedesktop.portal.Desktop=@/org/freedesktop/portal/desktop"
            }
            system-bus {
                see "org.freedesktop.NetworkManager"
                talk "org.freedesktop.UPower"
                call "org.freedesktop.UDisks2=org.freedesktop.DBus.ObjectManager.GetManagedObjects@/org/freedesktop/UDisks2"
                broadcast "org.freedesktop.UDisks2=@/org/freedesktop/UDisks2"
            }
            portals
            notify
            tray
            gamepad hidraw=#true uinput=#true
            camera nodes=#true
            mpris name="firefox.*"
            a11y
            input-method
            tty "passthrough"
            userns "disable"
            seccomp {
                allow "perf_event_open" "keyctl"
                deny "unshare" errno="EPERM"
                deny "clone3" errno="ENOSYS"
                disable
            }
            env MOZ_ENABLE_WAYLAND="1"
            env A="b"
            desktop "firefox.desktop"
            command "firefox" "--new-window"
            "#,
        );
        // A `dbus` grant with no rules is a node of its own shape.
        round_trip("dbus\nportals");
        // The system bus needs neither the session bus nor a bundle.
        round_trip("system-bus { talk \"org.freedesktop.UPower\" }");
        round_trip("tty \"none\"");
        round_trip("seccomp { disable; }");
        round_trip("gamepad");
        round_trip("gamepad hidraw=#true");
        round_trip("gamepad uinput=#true");
        round_trip("hidraw");
        // The bare grant and the older `gamepad` spelling of it are two
        // nodes, and both have to survive a round trip unchanged.
        round_trip("hidraw\ngamepad hidraw=#true");
        round_trip("dbus\nportals\ncamera");
        round_trip("dbus\nportals\ncamera nodes=#true");
        round_trip("dbus\na11y");
        round_trip("dbus\ninput-method");
    }

    #[test]
    fn defaults_are_left_out_rather_than_written_back() {
        // `userns "allow"` and a `gamepad` with both properties off are
        // the defaults, so the canonical form of each is the shorter node.
        let cfg = parse("gamepad uinput=#false\nuserns \"allow\"").unwrap();
        assert_eq!(render(&cfg).unwrap(), "gamepad\n");
        let cfg = parse("dbus\nportals\ncamera nodes=#false").unwrap();
        assert_eq!(render(&cfg).unwrap(), "dbus\nportals\ncamera\n");
    }

    #[test]
    fn a_share_always_says_its_mode() {
        // How wide a share is open is the thing to see at a glance, so
        // `mode=ro` is written out even though leaving it off would parse
        // to the same grant.
        assert_eq!(
            service(&Service::HomeShare {
                path: "x".into(),
                mode: ShareMode::ReadOnly,
            })
            .unwrap(),
            r#"home-share "x" mode=ro"#
        );
        assert_eq!(
            service(&Service::PathShare {
                path: "/mnt/data".into(),
                mode: ShareMode::ReadOnly,
            })
            .unwrap(),
            r#"path-share "/mnt/data" mode=ro"#
        );
        assert_eq!(
            service(&Service::AppRuntime {
                id: "org.example.App".to_owned(),
                mode: ShareMode::ReadOnly,
            })
            .unwrap(),
            r#"app-runtime "org.example.App" mode=ro"#
        );
        // A bare node still parses as read-only; it is only written back
        // with the mode spelled out.
        let cfg = parse("home-share \"x\"\napp-runtime \"org.example.App\"").unwrap();
        assert_eq!(
            render(&cfg).unwrap(),
            "home-share \"x\" mode=ro\napp-runtime \"org.example.App\" mode=ro\n"
        );
    }

    #[test]
    fn a_node_too_wide_for_its_column_is_cut_inside_its_argument() {
        // The mode is what a share is read for, so the cut goes into the
        // path or id and what follows it stays on screen.
        assert_eq!(
            shorten(r#"app-runtime "org.keepassxc.KeePassXC" mode=ro"#, 40),
            r#"app-runtime "org.keepassxc.Kee…" mode=ro"#
        );
        assert_eq!(
            shorten(r#"home-share "Documents/Reports/2026" mode=rw"#, 29),
            r#"home-share "Documen…" mode=rw"#
        );
        // A block node keeps the brace that closes it.
        assert_eq!(
            shorten(r#"dbus { talk "ca.desrt.dconf" }"#, 24),
            r#"dbus { talk "ca.desr…" }"#
        );
        // A node that fits is left alone, and one with nothing after its
        // argument is cut at the end, where there is nothing to protect.
        assert_eq!(
            shorten(r#"home-share "Downloads" mode=ro"#, 40),
            r#"home-share "Downloads" mode=ro"#
        );
        assert_eq!(
            shorten(r#"etc-share "a-very-long-entry-name""#, 20),
            r#"etc-share "a-very-l…"#
        );
        // A remainder too wide on its own leaves no argument to cut, so
        // the node is cut at the end rather than into nonsense.
        assert_eq!(
            shorten(r#"home-share "x" reason="a reason far too long""#, 20),
            r#"home-share "x" reas…"#
        );
        // And never a cut leaving a `\` to escape the quote put after it.
        assert_eq!(
            shorten(r#"home-share "a\\b" mode=ro"#, 24),
            r#"home-share "a…" mode=ro"#
        );
    }

    #[test]
    fn quoting_survives_the_characters_kdl_escapes() {
        // Every one of these is a legal component of a shared path, and a
        // renderer that dropped the escaping would name another file.
        for odd in ["a b", "a\"b", "a\\b", "a\tb", "a\u{7}b", "a\nb", "ä"] {
            let text = format!("home-share {}", quote(odd));
            let cfg = parse(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(
                cfg.services,
                vec![Service::HomeShare {
                    path: odd.into(),
                    mode: ShareMode::ReadOnly
                }],
                "{text}"
            );
            round_trip(&text);
        }
    }

    #[test]
    fn a_value_that_is_not_utf8_is_refused_rather_than_mangled() {
        use std::os::unix::ffi::OsStringExt;
        let argv = vec![OsString::from_vec(vec![0x66, 0xff])];
        assert!(matches!(
            command(&argv),
            Err(ConfigError::BadArgument { node, .. }) if node == "command"
        ));
        let cfg = InstanceConfig {
            services: vec![Service::EtcShare {
                name: OsString::from_vec(vec![0xff]),
            }],
            ..InstanceConfig::default()
        };
        assert!(render(&cfg).is_err());
    }

    #[test]
    fn a_system_bus_without_rules_is_refused_rather_than_written() {
        // The parser refuses it too, so writing the node out would produce
        // a profile that cannot be read back.
        let cfg = InstanceConfig {
            services: vec![Service::SystemBus { rules: vec![] }],
            ..InstanceConfig::default()
        };
        assert!(matches!(
            render(&cfg),
            Err(ConfigError::BadArgument { node, .. }) if node == "system-bus"
        ));
    }

    #[test]
    fn a_system_bus_that_owns_a_name_is_refused_rather_than_written() {
        // The parser refuses `own` there, for the same reason the node
        // itself exists: the name would be owned with the user's own
        // credentials.
        let cfg = InstanceConfig {
            services: vec![Service::SystemBus {
                rules: vec![
                    BusRule::Talk("org.freedesktop.UPower".to_owned()),
                    BusRule::Own("org.example.App".to_owned()),
                ],
            }],
            ..InstanceConfig::default()
        };
        let Err(ConfigError::BadArgument { node, reason }) = render(&cfg) else {
            panic!("an owned name was written to the system bus");
        };
        assert_eq!(node, "system-bus");
        assert!(reason.contains("org.example.App"), "{reason}");
    }

    #[test]
    fn nodes_come_out_in_config_order() {
        let cfg = parse("network\nwayland\nenv B=\"2\"\nenv A=\"1\"\ncommand \"x\"").unwrap();
        assert_eq!(
            nodes(&cfg).unwrap(),
            vec![
                "network",
                "wayland",
                "env B=\"2\"",
                "env A=\"1\"",
                "command \"x\""
            ]
        );
    }

    #[test]
    fn the_desktop_hint_is_written_beside_the_command_it_names_the_entry_for() {
        let cfg = parse("command \"kitty\"\ndesktop \"kitty.desktop\"\nwayland").unwrap();
        assert_eq!(
            nodes(&cfg).unwrap(),
            vec!["wayland", "desktop \"kitty.desktop\"", "command \"kitty\""]
        );
        // No node where the config names no entry: the lookup then goes
        // by the command, which is what most instances need.
        assert_eq!(render(&parse("wayland").unwrap()).unwrap(), "wayland\n");
    }

    #[test]
    fn an_accepted_finding_is_written_above_the_grant_it_is_about() {
        let cfg =
            parse("x11 \"host\"\nlint-allow \"x11-without-reason\" reason=\"no Wayland\"").unwrap();
        assert_eq!(
            nodes(&cfg).unwrap(),
            vec![
                "lint-allow \"x11-without-reason\" reason=\"no Wayland\"",
                "x11 \"host\""
            ]
        );
    }

    /// Every layout a `/-` line can have in a file: the config is written
    /// back as the text it was read from, so turning one node off in the
    /// editor rewrites one line and leaves the rest of the file alone.
    #[test]
    fn a_disabled_node_is_written_back_where_it_was() {
        for text in [
            "/-home-share \"x\" mode=ro\ndri\n",
            "dri\n/-home-share \"x\" mode=ro\npipewire\n",
            "dri\npipewire\n/-home-share \"x\" mode=ro\n",
            "dri\n/-dbus {\n    talk \"org.a.B\"\n}\n",
            "dri\n/-home-share \"a\" mode=ro\n/-home-share \"b\" mode=ro\npipewire\n",
            "/-dri\n/-pipewire\n",
            "home-share \"x\" mode=ro\n/-home-share \"x\" mode=ro\n",
            // The nodes a file holds one of: a disabled one is written
            // back on the side of the enabled node it was read on.
            "tty \"none\"\n/-tty \"passthrough\"\n\
             userns \"disable\"\n/-userns \"allow\"\n\
             seccomp {\n    disable\n}\n/-seccomp {\n    disable\n}\n\
             desktop \"org.example.App.desktop\"\n\
             /-desktop \"org.example.Other.desktop\"\n\
             command \"true\"\n/-command \"false\"\n",
            "/-tty \"passthrough\"\ntty \"none\"\n\
             /-userns \"allow\"\nuserns \"disable\"\n\
             /-command \"false\"\ncommand \"true\"\n",
            "lint-allow \"network-host\" reason=\"why\"\n\
             /-lint-allow \"own-too-wide\" reason=\"why\"\n\
             dri\n/-home-share \"x\" mode=ro\nenv A=\"1\"\n/-env B=\"2\"\n\
             /-tty \"none\"\n/-command \"false\"\ncommand \"true\"\n",
        ] {
            round_trip(text);
            assert_eq!(render(&parse(text).unwrap()).unwrap(), text);
        }
        // The one layout that is not its own canonical text: a file whose
        // last line has no newline gets one.
        assert_eq!(
            render(&parse("dri\n/-pipewire").unwrap()).unwrap(),
            "dri\n/-pipewire\n"
        );
    }

    #[test]
    fn a_disabled_block_node_is_prefixed_on_its_first_line_only() {
        let entry = Disabled {
            node: Node::Service(Service::Dbus {
                rules: vec![BusRule::Talk("org.a.B".to_owned())],
            }),
            before: 0,
        };
        assert_eq!(
            disabled(&entry).unwrap(),
            "/-dbus {\n    talk \"org.a.B\"\n}"
        );
    }

    #[test]
    fn a_node_is_written_as_the_line_it_was_read_from() {
        // One node in, one line out, for every kind of node a config
        // holds: the editor writes a row back from this.
        for text in [
            "wayland \"host\"",
            "x11 wm=\"twm\"",
            "network {\n    no-ipv6\n}",
            "home-share \"x\" mode=rw",
            "dbus {\n    talk \"org.a.B\"\n}",
            "env A=\"1\" B=\"2\"",
            "lint-allow \"network-host\" reason=\"why\"",
            "tty \"none\"",
            "userns \"disable\"",
            "seccomp {\n    disable\n}",
            "desktop \"org.example.App.desktop\"",
            "command \"true\" \"--now\"",
        ] {
            let doc = crate::config::parse_document(text).unwrap();
            let parsed = crate::config::parse_node(doc.nodes().first().unwrap(), false).unwrap();
            assert_eq!(node(&parsed).unwrap(), text);
        }
    }

    #[test]
    fn a_node_that_is_not_one_node_is_refused_rather_than_written() {
        // The parser cannot make either of these, and writing them would
        // produce a file that reads back as something else: an empty node
        // as no node at all, two allows as two lines under one `/-`.
        for node in [
            Node::Env(Vec::new()),
            Node::LintAllow(Vec::new()),
            Node::LintAllow(vec![
                LintAllow {
                    id: "network-host".to_owned(),
                    reason: "why".to_owned(),
                },
                LintAllow {
                    id: "own-too-wide".to_owned(),
                    reason: "why".to_owned(),
                },
            ]),
        ] {
            assert!(super::node(&node).is_err(), "{node:?}");
        }
    }
}
