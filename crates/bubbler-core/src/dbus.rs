//! What the filtering session-bus sidecar needs: the proxy's rule list,
//! the `.flatpak-info` portals identify the sandbox by, and where the
//! filtered socket lives. The sandbox never reaches the host bus itself.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::config::{BusRule, Service};
use crate::env::Env;

/// Program that filters the session bus; found on `PATH` inside the
/// proxy sandbox.
pub const PROXY_BIN: &str = "xdg-dbus-proxy";

/// Where portals expect the sandbox identity file.
pub const FLATPAK_INFO: &str = "/.flatpak-info";

/// Rules the `portals` bundle grants, in the order flatpak grants them.
const PORTAL_RULES: &[&str] = &[
    "--talk=org.freedesktop.portal.Desktop",
    "--talk=org.freedesktop.portal.Documents",
    "--talk=org.freedesktop.portal.FileChooser",
    "--talk=org.freedesktop.portal.Flatpak",
    "--call=org.freedesktop.portal.*=*",
    "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
];

/// Everything the launcher needs to run one instance's proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// `xdg-dbus-proxy` policy arguments, deduplicated, explicit `dbus`
    /// rules first and bundles after them.
    pub rules: Vec<OsString>,
    /// Contents of `/.flatpak-info` for the proxy, and for the sandbox
    /// itself when `portals` is granted.
    pub flatpak_info: Vec<u8>,
    /// Whether the `portals` bundle was granted.
    pub portals: bool,
}

/// The proxy plan for `services`, or `None` when `dbus` is not granted
/// and no proxy runs at all. `instance` is a validated instance name.
pub fn plan(services: &[Service], instance: &str) -> Option<Plan> {
    let explicit = services.iter().find_map(|s| match s {
        Service::Dbus { rules } => Some(rules),
        _ => None,
    })?;
    let portals = services.contains(&Service::Portals);
    let mut rules = Vec::new();
    for rule in explicit {
        push(&mut rules, render(rule));
    }
    for s in services {
        match s {
            Service::Portals => {
                for r in PORTAL_RULES {
                    push(&mut rules, (*r).to_owned());
                }
            }
            Service::Notify => push(
                &mut rules,
                "--talk=org.freedesktop.Notifications".to_owned(),
            ),
            Service::Mpris { name } => {
                push(&mut rules, format!("--own=org.mpris.MediaPlayer2.{name}"));
            }
            _ => {}
        }
    }
    Some(Plan {
        rules,
        flatpak_info: flatpak_info(instance, portals),
        portals,
    })
}

/// Append `rule` unless it is already there: the proxy takes repeats, but
/// a deduplicated list is what the user can compare against the config.
fn push(rules: &mut Vec<OsString>, rule: String) {
    let rule = OsString::from(rule);
    if !rules.contains(&rule) {
        rules.push(rule);
    }
}

/// One policy argument in the glued `--talk=<name>` form. A name may
/// start with `-`, which a separated `--talk <name>` would turn into an
/// option of its own.
fn render(rule: &BusRule) -> String {
    match rule {
        BusRule::See(n) => format!("--see={n}"),
        BusRule::Talk(n) => format!("--talk={n}"),
        BusRule::Own(n) => format!("--own={n}"),
        BusRule::Call(n, r) => format!("--call={n}={r}"),
        BusRule::Broadcast(n, r) => format!("--broadcast={n}={r}"),
    }
}

/// The `/.flatpak-info` a sandbox is identified by. Without `portals` the
/// proxy still gets the `[Application]` section, which is what makes
/// `xdg-dbus-proxy` treat the peer as a sandboxed app.
// An instance name is `[A-Za-z0-9._-]+`, so it cannot start a new key or
// section in this file.
pub fn flatpak_info(instance: &str, portals: bool) -> Vec<u8> {
    let mut s = format!("[Application]\nname=org.bubbler.{instance}\n");
    if portals {
        s.push_str(&format!("\n[Instance]\ninstance-id={instance}\n"));
    }
    s.into_bytes()
}

/// The only directory the proxy sandbox may write to. The instance
/// directory above it is never handed to the proxy: it holds the control
/// socket, and reaching that socket means running commands in the app.
pub fn socket_dir(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join("dbus")
}

/// The filtered socket, in [`socket_dir`]. The single source of truth for
/// the proxy command, the proxy's bind and the sandbox's own bind.
pub fn bus_path(instance_runtime: &Path) -> PathBuf {
    socket_dir(instance_runtime).join("bus")
}

/// Host session bus socket: the `unix:path=` of `$DBUS_SESSION_BUS_ADDRESS`
/// when it names one, else `$XDG_RUNTIME_DIR/bus`. The caller must still
/// check that the result is a socket.
pub fn host_bus(env: &Env) -> PathBuf {
    env.dbus_address
        .as_deref()
        .and_then(unix_path)
        .unwrap_or_else(|| env.runtime_dir.join("bus"))
}

/// Path out of a `unix:path=<path>[,<key>=<value>]...` D-Bus address.
/// Other transports (`tcp:`, `unix:abstract=`) name no socket to bind, so
/// they yield `None` and the runtime dir is used instead.
fn unix_path(address: &OsStr) -> Option<PathBuf> {
    let rest = address.as_bytes().strip_prefix(b"unix:path=")?;
    let end = rest.iter().position(|b| *b == b',').unwrap_or(rest.len());
    let path = &rest[..end];
    (!path.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(path)))
}

/// Argv of the proxy itself, run inside its own sandbox: it connects to
/// `host_bus`, serves the filtered socket in the `dbus/` subdirectory of
/// `instance_runtime` and exits when `ready_fd` is closed
/// (`xdg-dbus-proxy(1)`).
pub fn proxy_command(
    plan: &Plan,
    host_bus: &Path,
    instance_runtime: &Path,
    log: bool,
    ready_fd: &OsStr,
) -> Vec<OsString> {
    let mut fd = OsString::from("--fd=");
    fd.push(ready_fd);
    let mut address = OsString::from("unix:path=");
    address.push(host_bus);
    // The address and the socket path must precede the per-proxy options.
    let mut argv = vec![
        OsString::from(PROXY_BIN),
        fd,
        address,
        bus_path(instance_runtime).into_os_string(),
        OsString::from("--filter"),
    ];
    if log {
        argv.push(OsString::from("--log"));
    }
    argv.extend(plan.rules.iter().cloned());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[OsString]) -> Vec<&str> {
        v.iter()
            .map(|s| s.to_str().expect("test rules are ASCII"))
            .collect()
    }

    fn env() -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_log: false,
        }
    }

    #[test]
    fn no_dbus_means_no_proxy() {
        assert!(plan(&[Service::Wayland], "t").is_none());
        assert!(plan(&[], "t").is_none());
    }

    #[test]
    fn firefox_like_rules_are_bundles_in_service_order() {
        let p = plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::Portals,
                Service::Notify,
                Service::Mpris {
                    name: "firefox.*".into(),
                },
            ],
            "ff",
        )
        .expect("dbus is granted");
        assert_eq!(
            strs(&p.rules),
            vec![
                "--talk=org.freedesktop.portal.Desktop",
                "--talk=org.freedesktop.portal.Documents",
                "--talk=org.freedesktop.portal.FileChooser",
                "--talk=org.freedesktop.portal.Flatpak",
                "--call=org.freedesktop.portal.*=*",
                "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
                "--talk=org.freedesktop.Notifications",
                "--own=org.mpris.MediaPlayer2.firefox.*",
            ]
        );
        assert!(p.portals);
        assert_eq!(
            p.flatpak_info,
            b"[Application]\nname=org.bubbler.ff\n\n[Instance]\ninstance-id=ff\n".to_vec()
        );
    }

    #[test]
    fn explicit_rules_come_first_and_are_deduplicated() {
        let p = plan(
            &[
                Service::Notify,
                Service::Dbus {
                    rules: vec![
                        BusRule::See("a.b".into()),
                        BusRule::Talk("org.freedesktop.Notifications".into()),
                        BusRule::See("a.b".into()),
                    ],
                },
            ],
            "t",
        )
        .expect("dbus is granted");
        assert_eq!(
            strs(&p.rules),
            vec!["--see=a.b", "--talk=org.freedesktop.Notifications"]
        );
    }

    #[test]
    fn every_rule_variant_has_a_glued_form() {
        let p = plan(
            &[Service::Dbus {
                rules: vec![
                    BusRule::See("a.b".into()),
                    BusRule::Talk("-c.d".into()),
                    BusRule::Own("e.f".into()),
                    BusRule::Call("g.h".into(), "i.j@/k".into()),
                    BusRule::Broadcast("l.m".into(), "@/n/*".into()),
                ],
            }],
            "t",
        )
        .expect("dbus is granted");
        assert_eq!(
            strs(&p.rules),
            vec![
                "--see=a.b",
                "--talk=-c.d",
                "--own=e.f",
                "--call=g.h=i.j@/k",
                "--broadcast=l.m=@/n/*",
            ]
        );
    }

    #[test]
    fn without_portals_the_flatpak_info_is_the_application_section_only() {
        let p = plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        assert!(!p.portals);
        assert_eq!(
            p.flatpak_info,
            b"[Application]\nname=org.bubbler.t\n".to_vec()
        );
    }

    #[test]
    fn host_bus_prefers_the_address_and_falls_back_to_the_runtime_dir() {
        let mut e = env();
        assert_eq!(host_bus(&e), PathBuf::from("/run/user/1000/bus"));
        e.dbus_address = Some("unix:path=/tmp/other,guid=deadbeef".into());
        assert_eq!(host_bus(&e), PathBuf::from("/tmp/other"));
        for ignored in [
            "tcp:host=localhost,port=1",
            "unix:abstract=/x",
            "",
            "unix:path=",
        ] {
            e.dbus_address = Some(ignored.into());
            assert_eq!(
                host_bus(&e),
                PathBuf::from("/run/user/1000/bus"),
                "{ignored}"
            );
        }
    }

    #[test]
    fn proxy_command_is_the_documented_invocation() {
        let p = plan(&[Service::Dbus { rules: vec![] }, Service::Notify], "t")
            .expect("dbus is granted");
        let argv = proxy_command(
            &p,
            Path::new("/run/user/1000/bus"),
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        assert_eq!(
            strs(&argv),
            vec![
                "xdg-dbus-proxy",
                "--fd=4",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "--talk=org.freedesktop.Notifications",
            ]
        );
        let logged = proxy_command(
            &p,
            Path::new("/run/user/1000/bus"),
            Path::new("/run/user/1000/bubbler/t"),
            true,
            OsStr::new("4"),
        );
        assert_eq!(logged[5], OsString::from("--log"));
    }
}
