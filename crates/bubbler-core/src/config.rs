//! KDL instance/profile configuration. Each top-level node is either a
//! service grant or `command`. Unknown nodes are errors: silently
//! ignoring a grant would produce a different sandbox than the file says.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use kdl::{KdlDocument, KdlNode};

pub use crate::error::ConfigError;

/// Whether a shared path is writable inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    /// Bound with `--ro-bind` (default).
    ReadOnly,
    /// Bound with `--bind`.
    ReadWrite,
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
    /// Bind `$HOME/<path>` on the host to the same relative path inside the
    /// private home.
    HomeShare {
        /// Relative to `$HOME`; no absolute paths, no `..`.
        path: PathBuf,
        /// Read-only unless `mode=rw`.
        mode: ShareMode,
    },
}

/// Parsed `config.kdl`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstanceConfig {
    /// Granted services, in file order.
    pub services: Vec<Service>,
    /// Default argv for `run`, if the file has a `command` node.
    pub command: Option<Vec<OsString>>,
}

/// Parse KDL v2 text into an [`InstanceConfig`].
pub fn parse(text: &str) -> Result<InstanceConfig, ConfigError> {
    let doc: KdlDocument = KdlDocument::parse(text)?;
    let mut cfg = InstanceConfig::default();
    for node in doc.nodes() {
        let name = node.name().value();
        reject_types(node)?;
        match name {
            "wayland" | "x11" | "network" => {
                reject_entries(node)?;
                let svc = match name {
                    "wayland" => Service::Wayland,
                    "x11" => Service::X11,
                    _ => Service::Network,
                };
                if cfg.services.contains(&svc) {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.services.push(svc);
            }
            "home-share" => cfg.services.push(parse_home_share(node)?),
            "command" => {
                if cfg.command.is_some() {
                    return Err(ConfigError::Duplicate(name.to_owned()));
                }
                cfg.command = Some(parse_command(node)?);
            }
            other => return Err(ConfigError::UnknownNode(other.to_owned())),
        }
    }
    Ok(cfg)
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
    if let Some(e) = node.entries().first() {
        if let Some(p) = e.name() {
            return Err(ConfigError::UnknownProperty {
                node: node.name().value().to_owned(),
                prop: p.value().to_owned(),
            });
        }
        return Err(bad(node, "takes no arguments"));
    }
    if node.children().is_some() {
        return Err(bad(node, "takes no children"));
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
        assert!(
            matches!(parse("pulseaudio"), Err(ConfigError::UnknownNode(n)) if n == "pulseaudio")
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
    fn kdl_syntax_error_is_parse() {
        assert!(matches!(parse("wayland {"), Err(ConfigError::Parse(_))));
    }
}
