//! Properties that have to hold for every configuration, not only the
//! ones a unit test wrote down.
//!
//! Three of them: a config survives being written and read back, a
//! patched desktop entry cannot be patched a second time, and the
//! include resolver terminates on any graph of layers.

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bubbler_core::config::{
    AllowOut, BusRule, Cidr, Disabled, Errno, InstanceConfig, LintAllow, NetworkConfig,
    NetworkMode, Node, Outbound, Portal, Proto, SeccompConfig, Service, ShareMode, TmpSize,
    TtyMode, Userns, WaylandMode, X11Mode,
};
use bubbler_core::env::{DEFAULT_DATA_DIRS, Env};
use bubbler_core::error::{DesktopError, ProfileError};
use bubbler_core::network::{AllowHost, Forward, HostPattern};
use bubbler_core::profile::{MAX_DEPTH, Resolver};
use bubbler_core::{config, desktop, kdl_out, lint};
use proptest::prelude::*;

/// Syscall names `libseccomp` knows, which is what the `seccomp` node
/// takes; an invented name is a parse error rather than a round trip.
const SYSCALLS: &[&str] = &[
    "ptrace",
    "keyctl",
    "add_key",
    "bpf",
    "userfaultfd",
    "perf_event_open",
];

/// Well-known bus names, in the shape `dbus` rules take.
const BUS_NAMES: &[&str] = &[
    "org.example.App",
    "org.freedesktop.Notifications",
    "org.kde.StatusNotifierWatcher",
    "com.example.Player",
];

/// `/etc` entries `etc-share` accepts: none of them is on the reserved
/// account-file list.
const ETC_ENTRIES: &[&str] = &["fonts", "hostname", "ssl", "machine-id"];

/// Application ids, which take at least two `.`-separated elements.
const APP_IDS: &[&str] = &["org.example.App", "com.example.Player"];

/// Resolver addresses that are not loopback: an isolated namespace's
/// loopback is its own, and the parser refuses one there.
const RESOLVERS: &[&str] = &["1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"];

/// Names in the shape `allow-host` takes: plain, wildcarded and one an
/// `xn--` form, since none of the three is converted on the way through.
const HOST_NAMES: &[&str] = &[
    "api.example.com",
    "claude.ai",
    "*.example.com",
    "xn--bcher-kva.example",
    "a1.b2",
];

/// Addresses and networks in the shape `allow-out` takes, v4 and v6.
const DESTINATIONS: &[&str] = &[
    "1.1.1.1",
    "140.82.112.0/20",
    "10.0.0.0/8",
    "2606:4700:4700::1111",
    "2606:4700::/32",
];

fn share_mode() -> impl Strategy<Value = ShareMode> {
    prop_oneof![Just(ShareMode::ReadOnly), Just(ShareMode::ReadWrite)]
}

/// One to three lowercase path components, which both `home-share` and
/// (under a root) `path-share` accept.
fn rel_path() -> impl Strategy<Value = PathBuf> {
    prop::collection::vec("[a-z]{1,5}", 1..3).prop_map(|parts| parts.iter().collect())
}

/// The grants written as a bare node, each at most once.
fn flag_services() -> impl Strategy<Value = Vec<Service>> {
    prop::collection::vec(any::<bool>(), 6).prop_map(|on| {
        [
            Service::Wayland(WaylandMode::default()),
            // `"host"`: every subset of this list has to parse, and the
            // nested default requires `wayland` and `dri` behind it.
            Service::X11(X11Mode::Host),
            Service::Dri { kms: false },
            Service::Pipewire,
            Service::Pulseaudio,
            Service::Hidraw,
        ]
        .into_iter()
        .zip(on)
        .filter_map(|(svc, on)| on.then_some(svc))
        .collect()
    })
}

/// The four grants that name a path or an id. Each list is made unique
/// on the key the parser refuses a repeat of, so the generated config is
/// one the parser accepts.
fn share_services() -> impl Strategy<Value = Vec<Service>> {
    (
        prop::collection::vec((rel_path(), share_mode(), any::<bool>()), 0..3),
        prop::collection::vec((rel_path(), share_mode(), any::<bool>()), 0..3),
        prop::collection::vec(prop::sample::select(ETC_ENTRIES), 0..3),
        prop::collection::vec((prop::sample::select(APP_IDS), share_mode()), 0..2),
    )
        .prop_map(|(home, path, etc, app)| {
            let mut out = Vec::new();
            let mut seen: Vec<PathBuf> = Vec::new();
            for (path, mode, optional) in home {
                if seen.contains(&path) {
                    continue;
                }
                seen.push(path.clone());
                out.push(Service::HomeShare {
                    path,
                    mode,
                    optional,
                });
            }
            let mut seen: Vec<PathBuf> = Vec::new();
            for (rel, mode, optional) in path {
                let path = Path::new("/opt").join(rel);
                if seen.contains(&path) {
                    continue;
                }
                seen.push(path.clone());
                out.push(Service::PathShare {
                    path,
                    mode,
                    optional,
                });
            }
            let mut seen: Vec<&str> = Vec::new();
            for name in etc {
                if seen.contains(&name) {
                    continue;
                }
                seen.push(name);
                out.push(Service::EtcShare {
                    name: OsString::from(name),
                });
            }
            let mut seen: Vec<&str> = Vec::new();
            for (id, mode) in app {
                if seen.contains(&id) {
                    continue;
                }
                seen.push(id);
                out.push(Service::AppRuntime {
                    id: id.to_owned(),
                    mode,
                });
            }
            out
        })
}

/// Proxy rules for one bus. A name takes one policy, so a generated
/// second policy for a name already granted is dropped rather than
/// generated around.
fn bus_rules(own_allowed: bool) -> impl Strategy<Value = Vec<BusRule>> {
    prop::collection::vec((0usize..BUS_NAMES.len(), 0u8..5, "[A-Za-z]{1,6}"), 0..4).prop_map(
        move |raw| {
            let mut out: Vec<BusRule> = Vec::new();
            for (idx, kind, member) in raw {
                let name = BUS_NAMES[idx].to_owned();
                let rule = match kind {
                    0 => BusRule::See(name),
                    2 if own_allowed => BusRule::Own(name),
                    // `own` is not a rule the system bus takes, so
                    // there it is generated as the `talk` under it.
                    1 | 2 => BusRule::Talk(name),
                    3 => BusRule::Call(name, member),
                    _ => BusRule::Broadcast(name, member),
                };
                let conflict = match rule.policy() {
                    Some((name, level)) => out
                        .iter()
                        .filter_map(BusRule::policy)
                        .any(|(held, was)| held == name && was != level),
                    None => false,
                };
                if !conflict {
                    out.push(rule);
                }
            }
            out
        },
    )
}

/// The bus grants and the bundles that need one: `portals`, `notify`,
/// `tray` and `mpris` are parse errors without `dbus`, and `camera`
/// without `portals`.
fn bus_services() -> impl Strategy<Value = Vec<Service>> {
    (
        prop::option::of(bus_rules(true)),
        prop::option::of(bus_rules(false)),
        prop::option::of(prop::collection::vec(
            prop::sample::select(Portal::ALL),
            0..=6,
        )),
        any::<bool>(),
        any::<bool>(),
        prop::option::of(prop::sample::select(
            &["mpv", "Firefox", "chromium.instance2"][..],
        )),
        prop::option::of(any::<bool>()),
    )
        .prop_map(|(dbus, system_bus, portals, notify, tray, mpris, camera)| {
            let mut out = Vec::new();
            // A `system-bus` with no rules is a grant the emitter
            // refuses to write: the rule list is the whole
            // confinement, so an empty one says nothing.
            let system_bus = system_bus.filter(|rules: &Vec<BusRule>| !rules.is_empty());
            let Some(rules) = dbus else {
                if let Some(rules) = system_bus {
                    out.push(Service::SystemBus { rules });
                }
                return out;
            };
            out.push(Service::Dbus { rules });
            if let Some(rules) = system_bus {
                out.push(Service::SystemBus { rules });
            }
            if let Some(children) = &portals {
                // The parser refuses a child written twice, so the
                // generated set is one of each.
                let mut children = children.clone();
                children.sort_by_key(|c| c.node_name());
                children.dedup();
                out.push(Service::Portals { children });
            }
            if notify {
                out.push(Service::Notify);
            }
            if tray {
                out.push(Service::Tray);
            }
            if let Some(name) = mpris {
                out.push(Service::Mpris {
                    name: name.to_owned(),
                });
            }
            if let (true, Some(nodes)) = (portals.is_some(), camera) {
                out.push(Service::Camera { nodes });
            }
            out
        })
}

/// `network`, with only the children its mode has somewhere to put:
/// `allow-port`, `no-ipv6` and the outbound filter configure the sandbox's
/// own namespace, which only the isolated mode has, and `none` has no
/// network to resolve on. Two more rules the parser holds and this has to
/// as well: `allow-out` is only a rule under `outbound "deny"`, and
/// `no-ipv6` leaves no IPv6 for a v6 address of either kind to be reached
/// over.
fn network_service() -> impl Strategy<Value = Option<Service>> {
    prop::option::of(
        (
            0u8..3,
            prop::collection::vec(prop::sample::select(RESOLVERS), 0..2),
            prop::collection::vec((1024u16..9000, any::<bool>()), 0..2),
            any::<bool>(),
            any::<bool>(),
            prop::collection::vec(
                (
                    prop::sample::select(DESTINATIONS),
                    prop::option::of(1u16..9000),
                    0u8..3,
                ),
                0..3,
            ),
            prop::collection::vec(
                (
                    prop::sample::select(HOST_NAMES),
                    prop::option::of(1u16..9000),
                ),
                0..3,
            ),
        )
            .prop_map(
                |(mode, dns, forwards, no_ipv6, deny, allow_out, allow_hosts)| {
                    let mode = match mode {
                        0 => NetworkMode::Isolated,
                        1 => NetworkMode::Host,
                        _ => NetworkMode::None,
                    };
                    let mut cfg = NetworkConfig {
                        mode,
                        ..NetworkConfig::default()
                    };
                    if mode != NetworkMode::None {
                        for ip in dns {
                            let ip =
                                IpAddr::from_str(ip).expect("the table holds literal addresses");
                            if !cfg.dns.contains(&ip) {
                                cfg.dns.push(ip);
                            }
                        }
                    }
                    if mode == NetworkMode::Isolated {
                        for (port, udp) in forwards {
                            if !cfg.forwards.iter().any(|f| f.port == port) {
                                cfg.forwards.push(Forward { port, udp });
                            }
                        }
                        cfg.no_ipv6 = no_ipv6;
                        if no_ipv6 {
                            cfg.dns.retain(|ip| ip.is_ipv4());
                        }
                        if deny {
                            cfg.outbound = Outbound::Deny;
                            for (dest, port, proto) in allow_out {
                                let dest = Cidr::from_str(dest)
                                    .expect("the table holds literal destinations");
                                if no_ipv6 && dest.is_ipv6() {
                                    continue;
                                }
                                let rule = AllowOut {
                                    dest,
                                    port,
                                    proto: match proto {
                                        0 => None,
                                        1 => Some(Proto::Tcp),
                                        _ => Some(Proto::Udp),
                                    },
                                };
                                if !cfg.allow_out.contains(&rule) {
                                    cfg.allow_out.push(rule);
                                }
                            }
                            // `allow-host` is a rule under the filter like
                            // the destinations are, and the same name on two
                            // ports is two entries rather than a duplicate.
                            for (name, port) in allow_hosts {
                                let rule = AllowHost {
                                    pattern: HostPattern::parse(name)
                                        .expect("the table holds names the parser takes"),
                                    port: port.unwrap_or(AllowHost::DEFAULT_PORT),
                                };
                                if !cfg.allow_hosts.contains(&rule) {
                                    cfg.allow_hosts.push(rule);
                                }
                            }
                        }
                    }
                    Service::Network(cfg)
                },
            ),
    )
}

fn gamepad_service() -> impl Strategy<Value = Option<Service>> {
    prop::option::of(
        (any::<bool>(), any::<bool>())
            .prop_map(|(hidraw, uinput)| Service::Gamepad { hidraw, uinput }),
    )
}

/// Environment variables. The prefix keeps the key off the reserved
/// list, which the parser refuses outright.
fn env_vars() -> impl Strategy<Value = Vec<(String, String)>> {
    prop::collection::vec(("APP_[A-Z]{1,5}", "[A-Za-z0-9_./:-]{0,10}"), 0..3).prop_map(|raw| {
        let mut out: Vec<(String, String)> = Vec::new();
        for (key, value) in raw {
            if out.iter().any(|(held, _)| *held == key) {
                continue;
            }
            out.push((key, value));
        }
        out
    })
}

/// Accepted findings. Only warnings and notes can be accepted, so the
/// pool is the check table minus its errors.
fn lint_allows() -> impl Strategy<Value = Vec<LintAllow>> {
    let ids: Vec<&'static str> = lint::CHECKS
        .iter()
        .filter(|c| c.severity != lint::Severity::Error)
        .map(|c| c.id)
        .collect();
    prop::collection::vec((prop::sample::select(ids), "[a-z ]{1,20}"), 0..3).prop_map(|raw| {
        let mut out: Vec<LintAllow> = Vec::new();
        for (id, reason) in raw {
            if reason.trim().is_empty() || out.iter().any(|a| a.id == id) {
                continue;
            }
            out.push(LintAllow {
                id: id.to_owned(),
                reason,
            });
        }
        out
    })
}

fn seccomp_config() -> impl Strategy<Value = SeccompConfig> {
    (
        prop::collection::vec(prop::sample::select(SYSCALLS), 0..3),
        prop::collection::vec(
            (
                prop::sample::select(SYSCALLS),
                prop_oneof![Just(Errno::Eperm), Just(Errno::Enosys)],
            ),
            0..3,
        ),
        any::<bool>(),
    )
        .prop_map(|(allow, deny, disable)| SeccompConfig {
            allow: allow.into_iter().map(str::to_owned).collect(),
            deny: deny
                .into_iter()
                .map(|(name, errno)| (name.to_owned(), errno))
                .collect(),
            disable,
        })
}

fn command() -> impl Strategy<Value = Option<Vec<OsString>>> {
    prop::option::of(
        prop::collection::vec("[a-z][a-z0-9_.-]{0,7}", 1..4)
            .prop_map(|argv| argv.into_iter().map(OsString::from).collect()),
    )
}

/// A kind of node a `/-` line may keep, and where in its section it
/// sits, before either is fitted to the config it is written into.
fn disabled_kinds() -> impl Strategy<Value = Vec<(u8, usize)>> {
    prop::collection::vec((0u8..9, 0usize..4), 0..5)
}

/// The generated `/-` lines fitted to the config that holds them: one
/// node per kind, `before` inside its own section, and the list in the
/// order the emitter writes it — by section, and by `before` within one.
/// A config holding them in any other order is one the emitter cannot
/// write, so it is not one the parser could return either.
fn fit_disabled(cfg: &InstanceConfig, kinds: &[(u8, usize)]) -> Vec<Disabled> {
    let mut out: Vec<Disabled> = kinds
        .iter()
        .map(|(kind, before)| {
            let (node, len) = match kind {
                0 => (
                    Node::LintAllow(vec![LintAllow {
                        id: "network-host".to_owned(),
                        reason: "kept".to_owned(),
                    }]),
                    cfg.lint_allows.len(),
                ),
                1 => (
                    Node::Service(Service::HomeShare {
                        path: PathBuf::from("kept"),
                        mode: ShareMode::ReadOnly,
                        optional: false,
                    }),
                    cfg.services.len(),
                ),
                2 => (
                    Node::Env(vec![("KEPT".to_owned(), "1".to_owned())]),
                    cfg.env.len(),
                ),
                // The rest are the nodes a file holds one of, so their
                // section is one long or empty.
                3 => (
                    Node::Tty(TtyMode::None),
                    usize::from(cfg.tty != TtyMode::Pty),
                ),
                4 => (
                    Node::Userns(Userns::Disable),
                    usize::from(cfg.userns != Userns::Allow),
                ),
                5 => (
                    Node::Seccomp(SeccompConfig {
                        allow: Vec::new(),
                        deny: Vec::new(),
                        disable: true,
                    }),
                    usize::from(cfg.seccomp != SeccompConfig::default()),
                ),
                6 => (
                    Node::Desktop("kept.desktop".to_owned()),
                    usize::from(cfg.desktop.is_some()),
                ),
                7 => (
                    Node::Tmp(TmpSize(1024 * 1024 * 1024)),
                    usize::from(cfg.tmp.is_some()),
                ),
                _ => (
                    Node::Command(vec![OsString::from("kept")]),
                    usize::from(cfg.command.is_some()),
                ),
            };
            Disabled {
                node,
                before: before % (len + 1),
            }
        })
        .collect();
    out.sort_by_key(|d| (config::section_rank(&d.node), d.before));
    out
}

/// A configuration the parser accepts, assembled so that every grant
/// that requires another is generated behind it.
fn instance_config() -> impl Strategy<Value = InstanceConfig> {
    (
        (
            flag_services(),
            share_services(),
            bus_services(),
            network_service(),
            gamepad_service(),
        ),
        lint_allows(),
        env_vars(),
        prop_oneof![
            Just(TtyMode::Pty),
            Just(TtyMode::Passthrough),
            Just(TtyMode::None)
        ],
        prop_oneof![Just(Userns::Allow), Just(Userns::Disable)],
        tmp_size(),
        seccomp_config(),
        prop::option::of("[a-z][a-z0-9.-]{0,8}".prop_map(|s| format!("{s}.desktop"))),
        command(),
        disabled_kinds(),
    )
        .prop_map(
            |(
                (flags, shares, bus, network, gamepad),
                lint_allows,
                env,
                tty,
                userns,
                tmp,
                seccomp,
                desktop,
                command,
                kinds,
            )| {
                let mut services = Vec::new();
                services.extend(bus);
                services.extend(flags);
                services.extend(shares);
                services.extend(network);
                services.extend(gamepad);
                let mut cfg = InstanceConfig {
                    services,
                    // A `--share` is never in a file, so a round trip
                    // through KDL has none to carry.
                    shares: Vec::new(),
                    command,
                    env,
                    tmp,
                    tty,
                    seccomp,
                    userns,
                    lint_allows,
                    desktop,
                    disabled: Vec::new(),
                };
                // The `/-` lines last: where one sits is an index into a
                // section of the config above.
                cfg.disabled = fit_disabled(&cfg, &kinds);
                cfg
            },
        )
}

/// A `tmp size=` the parser takes: a count of one of the three units,
/// no more than the 64G cap, or no node at all.
fn tmp_size() -> impl Strategy<Value = Option<TmpSize>> {
    prop::option::of(
        (
            1u64..=64,
            prop::sample::select(&[1024u64, 1024 * 1024, 1024 * 1024 * 1024][..]),
        )
            .prop_map(|(n, scale)| TmpSize(n * scale)),
    )
}

/// A `.desktop` file of the shape a vendor ships: the group header, a
/// name, an `Exec` with field codes, and optionally a second group and
/// an action.
fn desktop_entry() -> impl Strategy<Value = String> {
    (
        "[A-Za-z ]{1,10}",
        prop::sample::select(&["%U", "%f", "%F", ""][..]),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(name, field, try_exec, activatable, action, crlf)| {
            let mut lines = vec![
                "[Desktop Entry]".to_owned(),
                format!("Name={name}"),
                format!("Exec=/usr/bin/app {field}"),
                "Type=Application".to_owned(),
            ];
            if try_exec {
                lines.push("TryExec=/usr/bin/app".to_owned());
            }
            if activatable {
                lines.push("DBusActivatable=true".to_owned());
            }
            if action {
                lines.push("Actions=new;".to_owned());
                lines.push(String::new());
                lines.push("[Desktop Action new]".to_owned());
                lines.push("Name=New Window".to_owned());
                lines.push("Exec=/usr/bin/app --new".to_owned());
            }
            let eol = if crlf { "\r\n" } else { "\n" };
            lines.join(eol) + eol
        })
}

proptest! {
    /// Anything the emitter writes, the parser reads back as the same
    /// grants. A round trip that loses or widens one is the failure
    /// nothing else in the suite detects: the sandbox would differ from
    /// the file that describes it.
    #[test]
    fn a_config_survives_being_written_out_and_read_back(cfg in instance_config()) {
        let text = kdl_out::render(&cfg).expect("every generated value is UTF-8");
        let back = config::parse(&text)
            .unwrap_or_else(|e| panic!("rendered config does not parse: {e}\n{text}"));
        prop_assert_eq!(back, cfg);
    }

    /// However a file orders its `/-` lines, the config holds them in
    /// the order the emitter writes them back. A section is written in
    /// one piece, so a line kept above a node of a later section is
    /// written below it, and a list in file order would parse from its
    /// own rendering as a config that is not the one rendered.
    #[test]
    fn disabled_lines_are_held_in_the_order_they_are_written(cfg in instance_config()) {
        let mut enabled = cfg.clone();
        enabled.disabled = Vec::new();
        let mut text = String::new();
        // Every `/-` line first and in reverse, which is the one order
        // the emitter never writes.
        for entry in cfg.disabled.iter().rev() {
            text.push_str(&kdl_out::disabled(entry).expect("every generated node writes"));
            text.push('\n');
        }
        text.push_str(&kdl_out::render(&enabled).expect("every generated value is UTF-8"));
        let back = config::parse(&text)
            .unwrap_or_else(|e| panic!("moved config does not parse: {e}\n{text}"));
        let ranks: Vec<u8> = back.disabled.iter().map(|d| config::section_rank(&d.node)).collect();
        prop_assert!(ranks.is_sorted(), "{ranks:?}\n{text}");
        prop_assert_eq!(back.disabled.len(), cfg.disabled.len());
    }

    /// The generated entry carries the marker key, and the marker is
    /// what stops a second patch: patching twice would give an `Exec`
    /// of `bubbler open i -- bubbler open i -- …`, which is a launcher
    /// entry that starts a sandbox inside a sandbox.
    #[test]
    fn a_patched_desktop_entry_is_never_patched_again(text in desktop_entry()) {
        let program = Path::new("/usr/bin/bubbler");
        let out = desktop::patch(&text, "inst", program).expect("a vendor-shaped entry patches");
        prop_assert_eq!(desktop::owner(&out), Some("inst"));
        prop_assert!(matches!(
            desktop::patch(&out, "inst", program),
            Err(DesktopError::Generated(owner)) if owner == "inst"
        ));
        // One launch prefix per `Exec`, in the entry group and in every
        // action group alike.
        for line in out.lines().filter(|l| l.starts_with("Exec=")) {
            prop_assert_eq!(line.matches("open inst --").count(), 1);
        }
    }

    /// `patch` reads files a distro shipped, so it answers on anything
    /// rather than dying on it.
    #[test]
    fn patching_arbitrary_text_answers_instead_of_panicking(text in "\\PC{0,200}") {
        let _ = desktop::patch(&text, "inst", Path::new("/usr/bin/bubbler"));
    }
}

proptest! {
    // Each case writes a directory of layers, so the case count is set
    // by what the filesystem costs rather than by the default.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any graph of `include`s terminates with an answer. Cycles and
    /// chains past [`MAX_DEPTH`] are errors that name themselves; what
    /// must never happen is the resolver recursing until the stack ends.
    #[test]
    fn the_include_resolver_answers_on_any_graph_of_layers(
        graph in prop::collection::vec(
            prop::collection::vec(0usize..12, 0..3),
            1..12,
        ),
    ) {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let system = tmp.path().join("system");
        std::fs::create_dir_all(&system).expect("the system layer directory");
        let names: Vec<String> = (0..graph.len()).map(|i| format!("p{i}")).collect();
        for (i, includes) in graph.iter().enumerate() {
            let mut text = String::new();
            for inc in includes {
                // Out-of-range indices are left in: a profile naming one
                // that does not exist is a layer the resolver has to
                // answer about too.
                text.push_str(&format!("include \"p{inc}\"\n"));
            }
            text.push_str("wayland\n");
            std::fs::write(system.join(format!("{}.kdl", names[i])), text)
                .expect("a layer file");
        }
        let resolver = Resolver::new(&env(tmp.path(), &system));
        for name in &names {
            match resolver.resolve(name) {
                Ok(resolved) => {
                    let back = config::parse_profile(&resolved.text)
                        .expect("the flattened text is what the emitter wrote");
                    prop_assert_eq!(back.config, resolved.config);
                }
                // Every refusal names a layer; none of them may be a
                // depth the resolver walked past.
                Err(ProfileError::TooDeep(chain)) => {
                    prop_assert!(chain.len() <= MAX_DEPTH + 1);
                }
                Err(_) => {}
            }
        }
    }
}

/// An environment rooted at `root`, with `system` as the system profile
/// layer and no user layer on disk.
fn env(root: &Path, system: &Path) -> Env {
    Env {
        home: root.join("home"),
        data_home: root.join("data"),
        config_home: root.join("config"),
        data_dirs: DEFAULT_DATA_DIRS.iter().map(PathBuf::from).collect(),
        runtime_dir: root.join("run"),
        uid: 1000,
        gid: 1000,
        wayland_display: None,
        display: None,
        xauthority: None,
        passthrough: vec![],
        init_override: None,
        dbus_address: None,
        dbus_system_address: None,
        at_spi_bus_address: None,
        dbus_log: false,
        net_proxy_log: false,
        seccomp_log: false,
        test_allow_path: None,
        profile_dir_override: Some(system.to_path_buf()),
        proxy_override: None,
        pasta_override: None,
        wl_proxy_override: None,
        net_proxy_override: None,
    }
}
