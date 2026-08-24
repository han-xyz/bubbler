//! What the filtering D-Bus sidecar needs: the proxy's rule list per bus,
//! the `.flatpak-info` portals identify the sandbox by, where portals look
//! that identity up, and where the filtered sockets live. The sandbox
//! never reaches a host bus itself.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::config::{BusRule, Service};
use crate::env::Env;
use crate::error::LaunchError;

/// Program that filters the buses; found on `PATH` inside the proxy
/// sandbox. One process serves every bus an instance is granted.
pub const PROXY_BIN: &str = "xdg-dbus-proxy";

/// File name of the session bus socket, in the proxy's directory and in
/// the instance's after the launcher moves it.
pub const SESSION_SOCKET: &str = "bus";

/// File name of the system bus socket, in the same two directories.
pub const SYSTEM_SOCKET: &str = "system";

/// Config node that grants the session bus, for errors about its socket.
pub const SESSION_NODE: &str = "dbus";

/// Config node that grants the system bus, for errors about its socket.
pub const SYSTEM_NODE: &str = "system-bus";

/// Where a system bus socket lives: the host's when no address overrides
/// it, and the path the filtered one is bound at inside the sandbox.
// libdbus and libsystemd both compile in this path, so a sandbox that has
// the socket there needs no environment variable to find it.
pub const SYSTEM_BUS_PATH: &str = "/run/dbus/system_bus_socket";

/// Where portals expect the sandbox identity file.
pub const FLATPAK_INFO: &str = "/.flatpak-info";

/// Directory of live sandbox instances under `$XDG_RUNTIME_DIR`. It is
/// flatpak's; bubbler only ever adds and removes its own entry in it.
pub const FLATPAK_DIR: &str = ".flatpak";

/// bwrap's `--info-fd` document, published for one instance. Portals read
/// `child-pid` out of it to get a pidfd of the sandbox.
pub const BWRAPINFO: &str = "bwrapinfo.json";

/// Rules the `portals` bundle grants: the three portal services a
/// sandboxed app talks to, plus the `--call`/`--broadcast` pair from the
/// `xdg-dbus-proxy(1)` EXAMPLES section.
// Not `org.freedesktop.portal.Flatpak`: that is the spawn portal, which
// starts processes outside the sandbox, and Settings, FileChooser and
// Notification all live on `portal.Desktop`.
const PORTAL_RULES: &[&str] = &[
    "--talk=org.freedesktop.portal.Desktop",
    "--talk=org.freedesktop.portal.Documents",
    "--talk=org.freedesktop.portal.FileChooser",
    "--call=org.freedesktop.portal.*=*",
    "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
];

/// One policy argument with the node that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The argument as `xdg-dbus-proxy` takes it, e.g. `--talk=org.a.B`.
    pub arg: OsString,
    /// Position in the instance config's `services` of the node that
    /// contributed it: the bus node for its own rules, the bundle's node
    /// for a bundle's. A repeat keeps the first node that asked.
    pub node: usize,
}

/// One bus the proxy filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Position in the instance config's `services` of the node that
    /// granted this bus. The address, the socket and the options that
    /// apply to them are that node's, as its rules are.
    pub node: usize,
    /// `xdg-dbus-proxy` policy arguments for this bus, deduplicated,
    /// explicit rules first and bundles after them.
    pub rules: Vec<Rule>,
}

/// Everything the launcher needs to run one instance's proxy. One process
/// serves both buses (`xdg-dbus-proxy(1)`: options apply to the address
/// they follow), so a plan exists as soon as either is granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The session bus, when `dbus` is granted.
    pub session: Option<Section>,
    /// The system bus, when `system-bus` is granted.
    pub system: Option<Section>,
    /// Contents of `/.flatpak-info` for the proxy, and for the sandbox
    /// itself when `portals` is granted.
    pub flatpak_info: Vec<u8>,
    /// Whether the `portals` bundle was granted.
    pub portals: bool,
    /// `org.bubbler.<instance>`: the id portals file this sandbox's
    /// permissions and documents under.
    pub app_id: String,
}

impl Plan {
    /// The buses the proxy serves, in the order it is told to bind them:
    /// each socket's file name — the one it has in the proxy's directory
    /// and, once the launcher has moved it, in the instance's — with the
    /// config node that granted it, so a failure names what to change.
    pub fn buses(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        if self.session.is_some() {
            out.push((SESSION_SOCKET, SESSION_NODE));
        }
        if self.system.is_some() {
            out.push((SYSTEM_SOCKET, SYSTEM_NODE));
        }
        out
    }
}

/// The proxy plan for `services`, or `None` when neither bus is granted
/// and no proxy runs at all. `instance` is a validated instance name.
pub fn plan(services: &[Service], instance: &str) -> Option<Plan> {
    let session = services.iter().enumerate().find_map(|(i, s)| match s {
        Service::Dbus { rules } => Some((i, rules)),
        _ => None,
    });
    let system = services.iter().enumerate().find_map(|(i, s)| match s {
        Service::SystemBus { rules } => Some((i, rules)),
        _ => None,
    });
    if session.is_none() && system.is_none() {
        return None;
    }
    let portals = services.contains(&Service::Portals);
    let session = session.map(|(node, explicit)| {
        let mut rules = explicit_rules(explicit, node);
        // Bundles are sets of session-bus rules; the system bus never
        // gets one, and its own list is the whole confinement.
        for (i, s) in services.iter().enumerate() {
            match s {
                Service::Portals => {
                    for r in PORTAL_RULES {
                        push(&mut rules, (*r).to_owned(), i);
                    }
                }
                Service::Notify => push(
                    &mut rules,
                    "--talk=org.freedesktop.Notifications".to_owned(),
                    i,
                ),
                // The watcher is all a tray icon takes: an item registers
                // on the app's own unique name, and the calls the host
                // makes back into it are incoming, which the proxy does
                // not filter (`xdg-dbus-proxy(1)`).
                Service::Tray => push(
                    &mut rules,
                    "--talk=org.kde.StatusNotifierWatcher".to_owned(),
                    i,
                ),
                Service::Mpris { name } => {
                    push(
                        &mut rules,
                        format!("--own=org.mpris.MediaPlayer2.{name}"),
                        i,
                    );
                }
                // Every other grant is listed rather than caught by a
                // wildcard: a new bundle must be given its rules here, and
                // a wildcard would silently give it none.
                Service::Wayland
                | Service::X11
                | Service::Network { .. }
                | Service::Dri
                | Service::Pipewire
                | Service::Pulseaudio
                | Service::Gamepad { .. }
                | Service::Hidraw
                // `camera` adds no rule of its own: the Camera interface
                // lives on `org.freedesktop.portal.Desktop`, which the
                // `portals` bundle above already talks to.
                | Service::Camera { .. }
                | Service::HomeShare { .. }
                | Service::PathShare { .. }
                | Service::EtcShare { .. }
                | Service::Dbus { .. }
                | Service::SystemBus { .. }
                | Service::AppRuntime { .. } => {}
            }
        }
        Section { node, rules }
    });
    let system = system.map(|(node, explicit)| Section {
        node,
        rules: explicit_rules(explicit, node),
    });
    Some(Plan {
        session,
        system,
        flatpak_info: flatpak_info(instance, portals),
        portals,
        app_id: app_id(instance),
    })
}

/// The config's own rules for one bus, in file order, all of them the
/// bus node's own.
fn explicit_rules(rules: &[BusRule], node: usize) -> Vec<Rule> {
    let mut out = Vec::new();
    for rule in rules {
        push(&mut out, render(rule), node);
    }
    out
}

/// Append `rule` unless it is already there: the proxy takes repeats, but
/// a deduplicated list is what the user can compare against the config.
fn push(rules: &mut Vec<Rule>, rule: String, node: usize) {
    let arg = OsString::from(rule);
    if !rules.iter().any(|r| r.arg == arg) {
        rules.push(Rule { arg, node });
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

/// Application id of an instance: `org.bubbler.` and the instance name as
/// one trailing element. Every `.` in the name becomes `_`, because only
/// the last element of an id may hold `-`, and a leading digit is
/// prefixed, which flatpak's own name check rejects even though the
/// portal's does not.
pub fn app_id(instance: &str) -> String {
    let mut tail = instance.replace('.', "_");
    if tail.starts_with(|c: char| c.is_ascii_digit()) {
        tail.insert(0, '_');
    }
    format!("org.bubbler.{tail}")
}

/// Whether `id` is an application id xdg-desktop-portal accepts: at least
/// two `.`-separated non-empty elements of `[A-Za-z0-9_]`, `-` allowed
/// only in the last one, at most 255 bytes.
// Mirrors `xdp_is_valid_app_id` (xdg-desktop-portal, shared/xdp-utils.c).
// An id it rejects makes the portal refuse every operation of the sandbox.
pub fn is_valid_app_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 255 {
        return false;
    }
    let last = id.split('.').count() - 1;
    last >= 1
        && id.split('.').enumerate().all(|(i, element)| {
            !element.is_empty()
                && element
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || (i == last && b == b'-'))
        })
}

/// The `/.flatpak-info` a sandbox is identified by. Without `portals` the
/// proxy still gets the `[Application]` section, which is what makes
/// `xdg-dbus-proxy` treat the peer as a sandboxed app.
// An instance name is `[A-Za-z0-9._-]+`, so it cannot start a new key or
// section in this file.
pub fn flatpak_info(instance: &str, portals: bool) -> Vec<u8> {
    let mut s = format!("[Application]\nname={}\n", app_id(instance));
    if portals {
        s.push_str(&format!(
            "\n[Instance]\ninstance-id={}\n",
            flatpak_instance_id(instance)
        ));
    }
    s.into_bytes()
}

/// `bubbler-<instance>`: the `instance-id` portals look a sandbox up by.
/// Namespaced because the `.flatpak` directory is shared with flatpak,
/// whose own instance ids are plain numbers.
pub fn flatpak_instance_id(instance: &str) -> String {
    format!("bubbler-{instance}")
}

/// `$XDG_RUNTIME_DIR/.flatpak/bubbler-<instance>`: where xdg-desktop-portal
/// looks a sandboxed caller up, by the `instance-id` in its
/// `/.flatpak-info`. `instance` is a validated instance name.
pub fn flatpak_instance_dir(env: &Env, instance: &str) -> PathBuf {
    env.runtime_dir
        .join(FLATPAK_DIR)
        .join(flatpak_instance_id(instance))
}

/// The only directory the proxy sandbox may write to. The instance
/// directory above it is never handed to the proxy: it holds the control
/// socket, and reaching that socket means running commands in the app.
pub fn socket_dir(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join("dbus")
}

/// Where the proxy creates one filtered socket, in [`socket_dir`]: the
/// one path the proxy sandbox can write to. `socket` is [`SESSION_SOCKET`]
/// or [`SYSTEM_SOCKET`].
pub fn proxy_bus_path(instance_runtime: &Path, socket: &str) -> PathBuf {
    socket_dir(instance_runtime).join(socket)
}

/// Where a sandbox's bus bind comes from: the socket after the launcher
/// has checked it and moved it out of [`socket_dir`]. The proxy cannot
/// reach this path, so nothing can be swapped for it once it is there.
pub fn app_bus_path(instance_runtime: &Path, socket: &str) -> PathBuf {
    instance_runtime.join(socket)
}

/// Host session bus socket: the `unix:path=` of `$DBUS_SESSION_BUS_ADDRESS`
/// when it is set, else `$XDG_RUNTIME_DIR/bus`. The caller must still
/// check that the result is a socket.
pub fn host_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    Ok(address_path(
        env.dbus_address.as_deref(),
        "DBUS_SESSION_BUS_ADDRESS",
        "dbus",
    )?
    .unwrap_or_else(|| env.runtime_dir.join("bus")))
}

/// Host system bus socket: the `unix:path=` of `$DBUS_SYSTEM_BUS_ADDRESS`
/// when it is set, else [`SYSTEM_BUS_PATH`], which is what libdbus and
/// libsystemd fall back to. The caller must still check that the result
/// is a socket.
pub fn host_system_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    Ok(address_path(
        env.dbus_system_address.as_deref(),
        "DBUS_SYSTEM_BUS_ADDRESS",
        "system-bus",
    )?
    .unwrap_or_else(|| PathBuf::from(SYSTEM_BUS_PATH)))
}

/// The socket a `DBUS_*_BUS_ADDRESS` names: `None` when the variable is
/// unset or empty, so the caller's default path applies. A transport
/// bubbler cannot bind (`tcp:`, `unix:abstract=`) is an error naming the
/// variable rather than that default: the session is on the bus the
/// variable names, and proxying another one would filter the wrong bus.
fn address_path(
    address: Option<&OsStr>,
    var: &'static str,
    service: &'static str,
) -> Result<Option<PathBuf>, LaunchError> {
    let Some(address) = address.filter(|a| !a.is_empty()) else {
        return Ok(None);
    };
    match unix_path(address) {
        Some(p) => Ok(Some(p)),
        // The value itself is not echoed: it is host input, and an
        // address may hold anything.
        None => Err(LaunchError::BadValue {
            service,
            reason: format!(
                "${var} names no Unix socket path; bubbler can proxy only a \
                 `unix:path=<path>` address"
            ),
        }),
    }
}

/// Path out of a `unix:path=<path>[,<key>=<value>]...` D-Bus address;
/// `None` for any other transport, and for an empty path.
fn unix_path(address: &OsStr) -> Option<PathBuf> {
    let rest = address.as_bytes().strip_prefix(b"unix:path=")?;
    let end = rest.iter().position(|b| *b == b',').unwrap_or(rest.len());
    let path = &rest[..end];
    (!path.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(path)))
}

/// The proxy binary to run: `$BUBBLER_DBUS_PROXY` when it is set, else
/// [`PROXY_BIN`] from `PATH` inside the proxy sandbox.
pub fn proxy_program(env: &Env) -> PathBuf {
    env.proxy_override
        .clone()
        .unwrap_or_else(|| PathBuf::from(PROXY_BIN))
}

/// Argv of the proxy itself, run inside its own sandbox: it connects to
/// each granted host bus, serves the filtered socket for it in the
/// `dbus/` subdirectory of `instance_runtime` and exits when `ready_fd`
/// is closed (`xdg-dbus-proxy(1)`).
///
/// `session_bus` and `system_bus` are the host sockets the launcher has
/// resolved for the sections the plan holds. A section given no socket is
/// left out rather than pointed somewhere else; the sandbox's bind of it
/// then fails, since the proxy never creates it.
pub fn proxy_command(
    program: &Path,
    plan: &Plan,
    session_bus: Option<&Path>,
    system_bus: Option<&Path>,
    instance_runtime: &Path,
    log: bool,
    ready_fd: &OsStr,
) -> Vec<OsString> {
    proxy_command_nodes(
        program,
        plan,
        session_bus,
        system_bus,
        instance_runtime,
        log,
        ready_fd,
    )
    .into_iter()
    .map(|(arg, _)| arg)
    .collect()
}

/// [`proxy_command`] with the node behind each element: a rule carries
/// the position in the config's `services` of the node that asked for it,
/// and the proxy's own invocation carries none.
pub fn proxy_command_nodes(
    program: &Path,
    plan: &Plan,
    session_bus: Option<&Path>,
    system_bus: Option<&Path>,
    instance_runtime: &Path,
    log: bool,
    ready_fd: &OsStr,
) -> Vec<(OsString, Option<usize>)> {
    let mut fd = OsString::from("--fd=");
    fd.push(ready_fd);
    let mut argv = vec![(program.as_os_str().to_os_string(), None), (fd, None)];
    for (section, host, socket) in [
        (plan.session.as_ref(), session_bus, SESSION_SOCKET),
        (plan.system.as_ref(), system_bus, SYSTEM_SOCKET),
    ] {
        let (Some(section), Some(host)) = (section, host) else {
            continue;
        };
        let mut address = OsString::from("unix:path=");
        address.push(host);
        // The address and the socket path must precede the options of
        // that bus: an option applies to the address before it. All of
        // them are the granting node's, so an explanation reads one bus
        // at a time instead of both addresses in one group.
        let node = Some(section.node);
        argv.push((address, node));
        argv.push((
            proxy_bus_path(instance_runtime, socket).into_os_string(),
            node,
        ));
        argv.push((OsString::from("--filter"), node));
        if log {
            argv.push((OsString::from("--log"), node));
        }
        argv.extend(section.rules.iter().map(|r| (r.arg.clone(), Some(r.node))));
    }
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

    fn args(rules: &[Rule]) -> Vec<&str> {
        rules
            .iter()
            .map(|r| r.arg.to_str().expect("test rules are ASCII"))
            .collect()
    }

    /// The session bus's rules; the plan under test grants that bus.
    fn session(p: &Plan) -> Vec<&str> {
        args(&p.session.as_ref().expect("dbus is granted").rules)
    }

    /// The system bus's rules; the plan under test grants that bus.
    fn system(p: &Plan) -> Vec<&str> {
        args(&p.system.as_ref().expect("system-bus is granted").rules)
    }

    fn env() -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            config_home: "/home/han/.config".into(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            dbus_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
        }
    }

    #[test]
    fn no_bus_means_no_proxy() {
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
            session(&p),
            vec![
                "--talk=org.freedesktop.portal.Desktop",
                "--talk=org.freedesktop.portal.Documents",
                "--talk=org.freedesktop.portal.FileChooser",
                "--call=org.freedesktop.portal.*=*",
                "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
                "--talk=org.freedesktop.Notifications",
                "--own=org.mpris.MediaPlayer2.firefox.*",
            ]
        );
        assert!(p.portals);
        assert_eq!(
            p.flatpak_info,
            b"[Application]\nname=org.bubbler.ff\n\n[Instance]\ninstance-id=bubbler-ff\n".to_vec()
        );
    }

    /// Every rule names the node that asked for it, which is what
    /// `--explain --proxy` groups them under.
    #[test]
    fn each_rule_carries_the_node_that_contributed_it() {
        let services = [
            Service::Wayland,
            Service::Dbus {
                rules: vec![BusRule::Own("org.a.B".into())],
            },
            Service::Notify,
            Service::SystemBus {
                rules: vec![BusRule::Talk("org.freedesktop.UDisks2".into())],
            },
        ];
        let p = plan(&services, "t").expect("dbus is granted");
        let nodes: Vec<(&str, usize)> = p
            .session
            .as_ref()
            .expect("dbus is granted")
            .rules
            .iter()
            .map(|r| (r.arg.to_str().expect("ASCII"), r.node))
            .collect();
        assert_eq!(
            nodes,
            vec![
                ("--own=org.a.B", 1),
                ("--talk=org.freedesktop.Notifications", 2),
            ]
        );
        let system = &p.system.as_ref().expect("system-bus is granted").rules;
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].node, 3);
        // A rule two nodes ask for keeps the first that did.
        let p = plan(
            &[
                Service::Dbus {
                    rules: vec![BusRule::Talk("org.freedesktop.Notifications".into())],
                },
                Service::Notify,
            ],
            "t",
        )
        .expect("dbus is granted");
        let rules = &p.session.as_ref().expect("dbus is granted").rules;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].node, 0);
    }

    #[test]
    fn tray_grants_only_the_status_notifier_watcher() {
        let p =
            plan(&[Service::Dbus { rules: vec![] }, Service::Tray], "t").expect("dbus is granted");
        assert_eq!(session(&p), vec!["--talk=org.kde.StatusNotifierWatcher"]);
        assert!(p.system.is_none());
        assert!(!p.portals);
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
            session(&p),
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
            session(&p),
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
    fn an_app_id_is_one_the_portal_accepts_however_the_instance_is_named() {
        for (instance, id) in [
            ("t", "org.bubbler.t"),
            ("ff", "org.bubbler.ff"),
            ("my.app", "org.bubbler.my_app"),
            ("a_b.c-d", "org.bubbler.a_b_c-d"),
            ("2fa", "org.bubbler._2fa"),
            (".hidden", "org.bubbler._hidden"),
            ("..", "org.bubbler.__"),
        ] {
            assert_eq!(app_id(instance), id, "{instance}");
            assert!(is_valid_app_id(&app_id(instance)), "{instance}");
        }
    }

    #[test]
    fn the_app_id_grammar_is_the_one_xdg_desktop_portal_checks() {
        for ok in [
            "a.b",
            "org.bubbler.t",
            "org.bubbler.2t",
            "org.bubbler.a-b",
            "a.b.c_d",
            "org.bubbler._",
            &format!("a.{}", "x".repeat(253)),
        ] {
            assert!(is_valid_app_id(ok), "{ok}");
        }
        // The last two are what an instance name with a dash and a dot,
        // or with a leading dot, used to produce.
        for no in [
            "",
            "a",
            "a.",
            ".a",
            "a..b",
            "org.bubbler.a b",
            "a.b/c",
            "a.b\u{e9}",
            &format!("a.{}", "x".repeat(254)),
            "org.bubbler.my-app.v2",
            "org.bubbler..hidden",
        ] {
            assert!(!is_valid_app_id(no), "{no}");
        }
    }

    #[test]
    fn without_portals_the_flatpak_info_is_the_application_section_only() {
        let p = plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        assert!(p.session.is_some() && p.system.is_none());
        assert!(!p.portals);
        assert_eq!(
            p.flatpak_info,
            b"[Application]\nname=org.bubbler.t\n".to_vec()
        );
    }

    #[test]
    fn portals_look_the_instance_up_under_the_runtime_dir() {
        // Namespaced: flatpak names its own instances in the same
        // directory, with plain numbers.
        assert_eq!(
            flatpak_instance_dir(&env(), "t"),
            PathBuf::from("/run/user/1000/.flatpak/bubbler-t")
        );
        assert_eq!(
            flatpak_instance_dir(&env(), "t").join(BWRAPINFO),
            PathBuf::from("/run/user/1000/.flatpak/bubbler-t/bwrapinfo.json")
        );
    }

    #[test]
    fn host_bus_prefers_the_address_and_falls_back_to_the_runtime_dir() {
        let mut e = env();
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/run/user/1000/bus"));
        e.dbus_address = Some("unix:path=/tmp/other,guid=deadbeef".into());
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/tmp/other"));
        // An unset variable and an empty one both mean "wherever the bus
        // usually is".
        e.dbus_address = Some("".into());
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/run/user/1000/bus"));
        // A transport that names no socket is refused: proxying the
        // default socket instead would be a bus the session is not on.
        for bad in [
            "tcp:host=localhost,port=1",
            "unix:abstract=/x",
            "unix:path=",
        ] {
            e.dbus_address = Some(bad.into());
            let Err(LaunchError::BadValue { service, reason }) = host_bus(&e) else {
                panic!("{bad} was accepted");
            };
            assert_eq!(service, "dbus");
            assert!(reason.contains("DBUS_SESSION_BUS_ADDRESS"), "{reason}");
        }
    }

    #[test]
    fn proxy_command_is_the_documented_invocation() {
        let p = plan(&[Service::Dbus { rules: vec![] }, Service::Notify], "t")
            .expect("dbus is granted");
        let argv = proxy_command(
            Path::new(PROXY_BIN),
            &p,
            Some(Path::new("/run/user/1000/bus")),
            None,
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        // The session-only invocation is what it was before the system
        // bus existed: a config without `system-bus` runs the same proxy.
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
            Path::new(PROXY_BIN),
            &p,
            Some(Path::new("/run/user/1000/bus")),
            None,
            Path::new("/run/user/1000/bubbler/t"),
            true,
            OsStr::new("4"),
        );
        assert_eq!(logged[5], OsString::from("--log"));
    }

    /// Each bus's address, socket and options carry the node that granted
    /// that bus, and not the proxy's own invocation: an option applies to
    /// the address before it, so an explanation has to read one bus at a
    /// time rather than one `command` group holding both addresses.
    #[test]
    fn each_bus_pair_carries_the_node_that_granted_that_bus() {
        let p = plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::Notify,
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
                },
            ],
            "t",
        )
        .expect("both buses are granted");
        let argv = proxy_command_nodes(
            Path::new(PROXY_BIN),
            &p,
            Some(Path::new("/run/user/1000/bus")),
            Some(Path::new(SYSTEM_BUS_PATH)),
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        let nodes: Vec<Option<usize>> = argv.iter().map(|(_, node)| *node).collect();
        assert_eq!(
            nodes,
            [
                None,    // xdg-dbus-proxy
                None,    // --fd=4
                Some(0), // unix:path=<session bus>
                Some(0), // <the socket it is served on>
                Some(0), // --filter
                Some(1), // --talk=org.freedesktop.Notifications
                Some(2), // unix:path=<system bus>
                Some(2),
                Some(2), // --filter
                Some(2), // --talk=org.freedesktop.UPower
            ]
        );
    }

    #[test]
    fn the_system_bus_alone_is_a_plan_and_a_proxy_of_its_own() {
        let p = plan(
            &[Service::SystemBus {
                rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
            }],
            "t",
        )
        .expect("system-bus is granted");
        assert!(p.session.is_none());
        assert_eq!(system(&p), vec!["--talk=org.freedesktop.UPower"]);
        assert_eq!(p.buses(), vec![(SYSTEM_SOCKET, SYSTEM_NODE)]);
        // No session address and no session socket: the proxy is told
        // about the one bus the config granted.
        assert_eq!(
            strs(&proxy_command(
                Path::new(PROXY_BIN),
                &p,
                None,
                Some(Path::new(SYSTEM_BUS_PATH)),
                Path::new("/run/user/1000/bubbler/t"),
                false,
                OsStr::new("4"),
            )),
            vec![
                "xdg-dbus-proxy",
                "--fd=4",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--talk=org.freedesktop.UPower",
            ]
        );
    }

    #[test]
    fn both_buses_are_one_proxy_with_the_session_pair_first() {
        let p = plan(
            &[
                Service::Dbus {
                    rules: vec![BusRule::Talk("ca.desrt.dconf".into())],
                },
                Service::Notify,
                Service::SystemBus {
                    rules: vec![
                        BusRule::Talk("org.freedesktop.UPower".into()),
                        BusRule::See("org.freedesktop.UDisks2".into()),
                    ],
                },
            ],
            "t",
        )
        .expect("both buses are granted");
        // A bundle is a session-bus rule set; the system section holds
        // only what the node wrote.
        assert_eq!(
            session(&p),
            vec![
                "--talk=ca.desrt.dconf",
                "--talk=org.freedesktop.Notifications"
            ]
        );
        assert_eq!(
            system(&p),
            vec![
                "--talk=org.freedesktop.UPower",
                "--see=org.freedesktop.UDisks2"
            ]
        );
        assert_eq!(
            p.buses(),
            vec![(SESSION_SOCKET, SESSION_NODE), (SYSTEM_SOCKET, SYSTEM_NODE)]
        );
        assert_eq!(
            strs(&proxy_command(
                Path::new(PROXY_BIN),
                &p,
                Some(Path::new("/run/user/1000/bus")),
                Some(Path::new(SYSTEM_BUS_PATH)),
                Path::new("/run/user/1000/bubbler/t"),
                true,
                OsStr::new("4"),
            )),
            vec![
                "xdg-dbus-proxy",
                "--fd=4",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "--log",
                "--talk=ca.desrt.dconf",
                "--talk=org.freedesktop.Notifications",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--log",
                "--talk=org.freedesktop.UPower",
                "--see=org.freedesktop.UDisks2",
            ]
        );
    }

    #[test]
    fn the_system_bus_address_falls_back_to_the_compiled_in_path() {
        let mut e = env();
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from(SYSTEM_BUS_PATH));
        e.dbus_system_address = Some("unix:path=/tmp/other,guid=deadbeef".into());
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from("/tmp/other"));
        e.dbus_system_address = Some("".into());
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from(SYSTEM_BUS_PATH));
        for bad in [
            "tcp:host=localhost,port=1",
            "unix:abstract=/x",
            "unix:path=",
        ] {
            e.dbus_system_address = Some(bad.into());
            let Err(LaunchError::BadValue { service, reason }) = host_system_bus(&e) else {
                panic!("{bad} was accepted");
            };
            assert_eq!(service, "system-bus");
            assert!(reason.contains("DBUS_SYSTEM_BUS_ADDRESS"), "{reason}");
        }
        // The two addresses are read from their own variables.
        e.dbus_address = Some("unix:path=/tmp/session".into());
        e.dbus_system_address = None;
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/tmp/session"));
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from(SYSTEM_BUS_PATH));
    }
}
