//! Canonical KDL for an [`InstanceConfig`]: what a flattened profile is
//! written back as. Every node the parser accepts, this writes, so
//! `parse(render(parse(text)))` is `parse(text)` again.

use std::ffi::{OsStr, OsString};

use crate::config::{BusRule, InstanceConfig, Service, ShareMode, Userns};
use crate::error::ConfigError;
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
/// where it came from. A block node is one multi-line string.
pub fn nodes(cfg: &InstanceConfig) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    for s in &cfg.services {
        out.push(service(s)?);
    }
    out.extend(cfg.env.iter().map(|(k, v)| env(k, v)));
    if cfg.tty != TtyMode::default() {
        out.push(tty(cfg.tty));
    }
    if cfg.userns != Userns::default() {
        out.push(userns(cfg.userns));
    }
    if cfg.seccomp != SeccompConfig::default() {
        out.push(seccomp(&cfg.seccomp));
    }
    if let Some(argv) = &cfg.command {
        out.push(command(argv)?);
    }
    Ok(out)
}

/// One grant as its KDL node.
pub fn service(s: &Service) -> Result<String, ConfigError> {
    // A new `Service` variant must be given a rendering here: a grant the
    // emitter drops would be a sandbox weaker than the profile it came from.
    Ok(match s {
        Service::Wayland => "wayland".to_owned(),
        Service::X11 => "x11".to_owned(),
        Service::Network => "network".to_owned(),
        Service::Dri => "dri".to_owned(),
        Service::Pipewire => "pipewire".to_owned(),
        Service::Pulseaudio => "pulseaudio".to_owned(),
        Service::Portals => "portals".to_owned(),
        Service::Notify => "notify".to_owned(),
        Service::Tray => "tray".to_owned(),
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
            let mut node = format!("home-share {}", quote(path));
            // `ro` is the default, so only `rw` has to be written out.
            if *mode == ShareMode::ReadWrite {
                node.push_str(" mode=rw");
            }
            node
        }
        Service::PathShare { path, mode } => {
            let path = text("path-share", "path", path.as_os_str())?;
            let mut node = format!("path-share {}", quote(path));
            // `ro` is the default, so only `rw` has to be written out.
            if *mode == ShareMode::ReadWrite {
                node.push_str(" mode=rw");
            }
            node
        }
        Service::EtcShare { name } => {
            format!("etc-share {}", quote(text("etc-share", "name", name)?))
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
fn quote(s: &str) -> String {
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
            mpris name="firefox.*"
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
    }

    #[test]
    fn defaults_are_left_out_rather_than_written_back() {
        // `userns "allow"` and a `gamepad` with both properties off are
        // the defaults, so the canonical form of each is the shorter node.
        let cfg = parse("gamepad uinput=#false\nuserns \"allow\"").unwrap();
        assert_eq!(render(&cfg).unwrap(), "gamepad\n");
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
}
