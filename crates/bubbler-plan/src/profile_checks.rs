//! Checks of the shipped profiles that need the plan layer: each one
//! resolves a profile in the model and then lints, plans or explains it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::config::{self, Service};
use crate::error::ProfileError;
use crate::host::fake::{self, FakeHost};
use crate::lint;
use crate::profile::test_support::{env, resolver};
use crate::profile::*;

/// The node entries of a header's `Bare by design. Add:` block: the
/// lines three spaces in, with a `{ … }` entry read to its closing
/// brace. Prose sits five spaces in and is skipped, so what comes
/// back is what a reader selects and pastes, character for character.
fn opt_in_nodes(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut lines = text
        .lines()
        .skip_while(|l| *l != "// Bare by design. Add:")
        .skip(1)
        .map_while(|l| l.strip_prefix("//"));
    while let Some(body) = lines.next() {
        let Some(entry) = body.strip_prefix("   ") else {
            continue;
        };
        if entry.starts_with(' ') {
            continue;
        }
        let mut node = entry.to_owned();
        if entry.ends_with('{') {
            for body in lines.by_ref() {
                let inner = body.strip_prefix("   ").unwrap_or(body);
                node.push('\n');
                node.push_str(inner);
                if inner.trim() == "}" {
                    break;
                }
            }
        }
        out.push(node);
    }
    out
}

/// Paste `nodes` into `profile` the way a reader does: appended, but
/// a block node replacing the bare node of the same name where the
/// profile already grants one, since a config holds one `dbus` node
/// and the two headers that need it say so. Also reports whether a
/// node was replaced.
fn paste(profile: &str, nodes: &[String]) -> (String, bool) {
    let mut text = profile.to_owned();
    let mut replaced = false;
    for node in nodes {
        let name: String = node
            .chars()
            .take_while(|c| !matches!(c, ' ' | '\n' | '{'))
            .collect();
        let bare = format!("\n{name}\n");
        if node.contains('{') && text.contains(&bare) {
            text = text.replacen(&bare, "\n", 1);
            replaced = true;
        }
        text.push_str(node);
        text.push('\n');
    }
    (text, replaced)
}

/// A `Bare by design. Add:` block is text a reader pastes into a
/// config, so every block is pasted into its own profile here and the
/// result has to parse as a config and lint clean. An entry that
/// stops fitting the profile it sits in — a `dbus` block beside the
/// bare `dbus` already granted, a bundle whose `dbus` went missing, a
/// `lint-allow` naming a check nothing raises any more — fails here
/// rather than in somebody's editor.
#[test]
fn every_opt_in_a_header_lists_pastes_back_into_its_own_profile() {
    let (file, dir, _) = fake::types();
    let search_path = [PathBuf::from("/usr/bin")];
    for name in NAMES {
        let text = lookup(name).expect("NAMES lists built-in profiles");
        let nodes = opt_in_nodes(text);
        assert_eq!(
            nodes.is_empty(),
            !text.contains("// Bare by design. Add:"),
            "{name}: the block and what this test reads out of it disagree"
        );
        let (pasted, replaced) = paste(text, &nodes);
        // The reader is told which node a block replaces; this does
        // the same, so the two cannot drift apart.
        assert!(
            !replaced || text.contains("in place of the bare `dbus` node above"),
            "{name} replaces a node its header does not name"
        );
        let cfg = config::parse(&pasted)
            .unwrap_or_else(|err| panic!("{name} with its opt-ins pasted in: {err}"));

        // The host is built from what the pasted config asks for, so
        // the run measures the grants and not this machine. This also
        // marks both files of the WirePlumber policy installed, or
        // every `pipewire`/`pulseaudio` grant would carry
        // `audio-policy-missing` regardless of what the profile asks.
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let mut host = FakeHost::default()
            .with(
                "/usr/share/wireplumber/wireplumber.conf.d/50-bubbler.conf",
                file,
            )
            .text(
                "/usr/share/wireplumber/wireplumber.conf.d/50-bubbler.conf",
                crate::audio_policy::DROP_IN,
            )
            .with(
                "/usr/share/wireplumber/scripts/bubbler/refuse-links.lua",
                file,
            )
            .text(
                "/usr/share/wireplumber/scripts/bubbler/refuse-links.lua",
                crate::audio_policy::HOOK,
            );
        {
            let mut add = |p: &Path, t| {
                host = std::mem::take(&mut host)
                    .with(p.to_str().expect("built-in profiles hold UTF-8 paths"), t);
            };
            for s in &cfg.services {
                match s {
                    Service::HomeShare { path, .. } => add(&e.home.join(path), dir),
                    Service::PathShare { path, .. } => add(path, dir),
                    Service::EtcShare { name } => add(&Path::new("/etc").join(name), dir),
                    _ => {}
                }
            }
            if let Some(argv) = &cfg.command {
                let argv0 = argv[0].to_str().expect("built-in commands hold UTF-8");
                add(&Path::new("/usr/bin").join(argv0), file);
            }
            if let Some(entry) = &cfg.desktop {
                add(&Path::new("/usr/share/applications").join(entry), file);
            }
        }
        let r = resolver(tmp.path(), &[(name, pasted.as_str())], &[]);
        let ctx = lint::Context {
            env: &e,
            host: &host,
            search_path: &search_path,
            loaded_revision: &|_: &crate::env::Env| crate::audio_policy::LoadedRevision::Current,
            app_id_twin: None,
        };
        let report =
            lint::lint_profile(&ctx, &r, name).unwrap_or_else(|err| panic!("{name}: {err}"));
        // vesktop's own live grant carries `microphone`, not an
        // opt-in from its header block, so `pipewire-microphone`
        // fires on it regardless of what is pasted; its header
        // explains the note, which is what R14 asks for.
        let expected = if *name == "vesktop" {
            vec![
                "note[pipewire-microphone]: `pulseaudio { microphone }` adds every \
                 microphone and line-in the session has, and capture from them"
                    .to_owned(),
            ]
        } else {
            Vec::new()
        };
        assert_eq!(
            report
                .findings
                .iter()
                .map(|f| format!("{}[{}]: {}", f.severity, f.id, f.message))
                .collect::<Vec<_>>(),
            expected,
            "{name} with its opt-ins pasted in does not lint clean"
        );
    }
}

/// The mode is one choice and the including layer makes it; the
/// children are grants of their own and add up.
#[test]
fn network_takes_its_mode_from_the_including_layer_and_unions_the_children() {
    let tmp = tempfile::tempdir().unwrap();
    let r = resolver(
        tmp.path(),
        &[
            (
                "base",
                "network {\n    dns \"1.1.1.1\"\n    allow-port 80\n}\n",
            ),
            (
                "app",
                "include \"base\"\nnetwork {\n    dns \"9.9.9.9\"\n    \
                 allow-port 80\n    allow-port 443\n    no-ipv6\n}\n",
            ),
        ],
        &[],
    );
    let cfg = r.resolve("app").unwrap().config;
    let [Service::Network(net)] = cfg.services.as_slice() else {
        panic!("{:?}", cfg.services)
    };
    assert_eq!(net.mode, crate::network::Mode::Isolated);
    assert_eq!(
        net.dns,
        vec![
            std::net::IpAddr::from([1, 1, 1, 1]),
            std::net::IpAddr::from([9, 9, 9, 9])
        ]
    );
    assert_eq!(
        net.forwards
            .iter()
            .map(|f| (f.port, f.udp))
            .collect::<Vec<_>>(),
        vec![(80, false), (443, false)]
    );
    assert!(net.no_ipv6);
}

#[test]
fn an_including_layer_can_move_the_network_onto_the_host() {
    let tmp = tempfile::tempdir().unwrap();
    let r = resolver(
        tmp.path(),
        &[
            ("base", "network {\n    dns \"1.1.1.1\"\n}\n"),
            ("app", "include \"base\"\nnetwork \"host\"\n"),
        ],
        &[],
    );
    let resolved = r.resolve("app").unwrap();
    let [Service::Network(net)] = resolved.config.services.as_slice() else {
        panic!("{:?}", resolved.config.services)
    };
    assert_eq!(net.mode, crate::network::Mode::Host);
    assert_eq!(net.dns, vec![std::net::IpAddr::from([1, 1, 1, 1])]);
    assert_eq!(
        resolved.text,
        "network \"host\" {\n    dns \"1.1.1.1\"\n}\n"
    );
}

/// `outbound` is a choice the including layer makes, like the mode;
/// the destinations are grants and add up. A layer that turns the
/// filter *off* while a layer below it lists destinations is refused
/// on the re-read rather than flattened into rules nothing installs.
#[test]
fn outbound_comes_from_the_including_layer_and_the_destinations_add_up() {
    let tmp = tempfile::tempdir().unwrap();
    let r = resolver(
        tmp.path(),
        &[
            (
                "base",
                "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443\n    \
                 allow-host \"claude.ai\" port=8443\n}\n",
            ),
            (
                "app",
                "include \"base\"\nnetwork {\n    outbound \"deny\"\n    \
                 allow-out \"1.1.1.1\" port=443\n    allow-out \"9.9.9.9\"\n    \
                 allow-host \"api.example.com\"\n}\n",
            ),
            ("open", "include \"base\"\nnetwork\n"),
        ],
        &[],
    );
    let resolved = r.resolve("app").unwrap();
    let [Service::Network(net)] = resolved.config.services.as_slice() else {
        panic!("{:?}", resolved.config.services)
    };
    assert_eq!(net.outbound, crate::network::Outbound::Deny);
    assert_eq!(
        net.allow_out
            .iter()
            .map(|a| (a.dest.to_string(), a.port))
            .collect::<Vec<_>>(),
        vec![
            ("1.1.1.1".to_owned(), Some(443)),
            ("9.9.9.9".to_owned(), None)
        ]
    );
    // A name a layer below granted is still granted: a merge that
    // dropped it would leave the proxy with fewer names than the
    // profiles between them asked for.
    assert_eq!(
        net.allow_hosts
            .iter()
            .map(|a| (a.pattern.to_string(), a.port))
            .collect::<Vec<_>>(),
        vec![
            ("claude.ai".to_owned(), 8443),
            ("api.example.com".to_owned(), 443)
        ]
    );
    assert_eq!(
        resolved.text,
        "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443\n    \
         allow-out \"9.9.9.9\"\n    allow-host \"claude.ai\" port=8443\n    \
         allow-host \"api.example.com\"\n}\n"
    );
    // A layer above one that filters cannot drop the filter by
    // saying nothing, which is what a bare `network` node says.
    let err = r.resolve("open").unwrap_err();
    let ProfileError::Conflict { node, a, b } = &err else {
        panic!("{err:?}")
    };
    assert_eq!(node, "network");
    assert!(a.contains("outbound \"deny\""), "{a}");
    assert!(b.contains("without it"), "{b}");
}

/// The `claude-code` profiles launch without error on a host lacking
/// both the native installer's `~/.local/bin/claude` and the npm
/// global's `~/.local/share/claude`: both `home-share` entries are
/// optional, so the fake host binds neither and `--explain` reports
/// both skipped rather than the launch failing.
#[test]
fn claude_code_profiles_launch_and_explain_without_the_native_install() {
    let tmp = tempfile::tempdir().unwrap();
    let e = env(tmp.path());
    let r = Resolver::new(&e);
    let (file, ..) = fake::types();

    for name in ["claude-code", "claude-code-strict"] {
        let cfg = r.resolve(name).unwrap().config;
        // `claude-code-strict` filters egress through a proxy binary
        // that `network()` requires present before granting anything
        // else; the fake host holds nothing beyond that, so both
        // `.local` shares stay absent for both profiles.
        let host = FakeHost::default().with(crate::network::NET_PROXY_INSTALLED, file);
        let ctx = crate::service::ServiceCtx {
            instance_runtime: tmp.path().join("run"),
            dbus: None,
            wayland: None,
            init_bin: Path::new(crate::init_bin::INSTALLED),
        };
        let mut args = crate::bwrap::BwrapArgs::baseline(&e, Path::new("/i/home"), &host);
        crate::service::apply_all(&cfg.services, &e, &mut args, &host, &ctx)
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        let items = args
            .finish_explained(
                &[OsString::from("x")],
                &mut crate::sidecar_argv::DryRunAlloc::new(PathBuf::from(
                    "/run/user/1000/bubbler/i",
                )),
            )
            .unwrap();

        let argv: Vec<OsString> = items.iter().flat_map(|i| i.args.clone()).collect();
        for needle in [".local/bin/claude", ".local/share/claude"] {
            assert!(
                !argv.iter().any(|a| a.to_string_lossy().contains(needle)),
                "{name}: unexpected bind for {needle}: {argv:?}"
            );
        }

        let view = crate::explain::View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: crate::explain::Source {
                file: "config.kdl",
                lines: &crate::config::Lines::default(),
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            own_cgroup: None,
            net_proxy_log: false,
            seccomp_log: false,
            proxy: false,
            full: false,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = crate::explain::render(&items, &view).unwrap();
        for skipped in [
            "    home-share \".local/bin/claude\" mode=ro optional=#true  \
             absent on this host, skipped",
            "    home-share \".local/share/claude\" mode=ro optional=#true  \
             absent on this host, skipped",
        ] {
            assert!(out.contains(&skipped.to_owned()), "{name}: {out:?}");
        }
    }
}
