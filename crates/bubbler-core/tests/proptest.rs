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
    BusRule, Errno, InstanceConfig, LintAllow, NetworkConfig, NetworkMode, SeccompConfig, Service,
    ShareMode, TtyMode, Userns,
};
use bubbler_core::env::{DEFAULT_DATA_DIRS, Env};
use bubbler_core::error::{DesktopError, ProfileError};
use bubbler_core::network::Forward;
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
            Service::Wayland,
            Service::X11,
            Service::Dri,
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
        prop::collection::vec((rel_path(), share_mode()), 0..3),
        prop::collection::vec((rel_path(), share_mode()), 0..3),
        prop::collection::vec(prop::sample::select(ETC_ENTRIES), 0..3),
        prop::collection::vec((prop::sample::select(APP_IDS), share_mode()), 0..2),
    )
        .prop_map(|(home, path, etc, app)| {
            let mut out = Vec::new();
            let mut seen: Vec<PathBuf> = Vec::new();
            for (path, mode) in home {
                if seen.contains(&path) {
                    continue;
                }
                seen.push(path.clone());
                out.push(Service::HomeShare { path, mode });
            }
            let mut seen: Vec<PathBuf> = Vec::new();
            for (rel, mode) in path {
                let path = Path::new("/opt").join(rel);
                if seen.contains(&path) {
                    continue;
                }
                seen.push(path.clone());
                out.push(Service::PathShare { path, mode });
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
        any::<bool>(),
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
            if portals {
                out.push(Service::Portals);
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
            if let (true, Some(nodes)) = (portals, camera) {
                out.push(Service::Camera { nodes });
            }
            out
        })
}

/// `network`, with only the children its mode has somewhere to put:
/// `allow-port` and `no-ipv6` configure the pasta sidecar, which only
/// the isolated namespace runs, and `none` has no network to resolve on.
fn network_service() -> impl Strategy<Value = Option<Service>> {
    prop::option::of(
        (
            0u8..3,
            prop::collection::vec(prop::sample::select(RESOLVERS), 0..2),
            prop::collection::vec((1024u16..9000, any::<bool>()), 0..2),
            any::<bool>(),
        )
            .prop_map(|(mode, dns, forwards, no_ipv6)| {
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
                        let ip = IpAddr::from_str(ip).expect("the table holds literal addresses");
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
                }
                Service::Network(cfg)
            }),
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
        seccomp_config(),
        prop::option::of("[a-z][a-z0-9.-]{0,8}".prop_map(|s| format!("{s}.desktop"))),
        command(),
    )
        .prop_map(
            |(
                (flags, shares, bus, network, gamepad),
                lint_allows,
                env,
                tty,
                userns,
                seccomp,
                desktop,
                command,
            )| {
                let mut services = Vec::new();
                services.extend(bus);
                services.extend(flags);
                services.extend(shares);
                services.extend(network);
                services.extend(gamepad);
                InstanceConfig {
                    services,
                    command,
                    env,
                    tty,
                    seccomp,
                    userns,
                    lint_allows,
                    desktop,
                }
            },
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
        dbus_log: false,
        seccomp_log: false,
        test_allow_path: None,
        profile_dir_override: Some(system.to_path_buf()),
        proxy_override: None,
        pasta_override: None,
    }
}
