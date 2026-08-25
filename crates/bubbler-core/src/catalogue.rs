//! What every config node grants, as data: the line a list shows, the
//! cost a reader has to weigh before granting it, and the grammar of the
//! node. One table, read by the config man page and by the interactive
//! editor, so what bubbler takes and what bubbler explains cannot drift.

use std::fmt;

/// How far a node reaches when it is written as wide as it can be
/// written. The ceiling, not what one config asks for: a reader deciding
/// whether to grant a node needs the worst it can mean, and [`Grant::cost`]
/// says which spelling reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// One resource, with no authority over anything the sandbox is not
    /// already given.
    Narrow,
    /// Hands over more than the name of the node suggests: a whole class
    /// of devices, a whole tree, or a socket with no filtering of its own.
    Wide,
    /// The sandbox gains power over things outside it — the session, the
    /// user's other applications, or the kernel surface the filter covers.
    Outward,
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Narrow => "narrow",
            Self::Wide => "wide",
            Self::Outward => "outward",
        })
    }
}

/// One config node as a reader needs it explained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// The KDL node name, as [`crate::config::NODES`] holds it and
    /// [`crate::config::Service::node_name`] returns it.
    pub node: &'static str,
    /// One line, present tense: what the sandbox gets.
    pub summary: &'static str,
    /// What granting it gives away, which is the part a summary cannot
    /// carry. One to three sentences.
    pub cost: &'static str,
    /// The widest thing the node can be written to grant.
    pub risk: Risk,
    /// How the node is written, with the properties and children it takes.
    pub grammar: &'static str,
}

/// Every node a config may hold, in the order [`crate::config::NODES`]
/// lists them, which is the order the README documents them in. A unit
/// test holds the two lists together: a node the parser takes and the
/// catalogue does not describe is a grant nothing can explain.
pub static GRANTS: &[Grant] = &[
    Grant {
        node: "wayland",
        summary: "a Wayland socket the compositor treats as sandboxed",
        cost: "By default bubbler registers its own socket with the compositor as a \
               security context, and the compositor hides its privileged globals from \
               clients on it: screen capture, reading the clipboard without focus, input \
               injection, overlays and window management, exactly which being the \
               compositor's policy. The application reaches that socket through a \
               proxy of bubbler's, which forwards a clipboard read only just after a \
               key, button or touch of yours, so a sandbox cannot poll the selection \
               in the background for whatever you copy next; `clipboard=\"open\"` \
               forwards every read and logs it instead, and lint warns. On a compositor \
               without the protocol the proxy connects to the session socket and \
               hides the privileged interfaces in the compositor's place, and the \
               run prints a note saying so. `wayland \
               \"host\"` binds the session socket as it is, with no proxy in front of \
               it; lint warns. `x11 \"host\"` bypasses all of this, its server being a \
               client of your session; a bare `x11`'s Xwayland is a client of this \
               socket like any other and is filtered and gated with it.",
        risk: Risk::Narrow,
        grammar: "wayland [\"host\"] [clipboard=\"open\"]",
    },
    Grant {
        node: "x11",
        summary: "an X server of the sandbox's own, or the session's",
        cost: "Bare, bubbler starts a rootful Xwayland inside the sandbox as a client of \
               the instance's Wayland socket, on the first X connection, so an instance \
               whose command never speaks X runs no server at all: X clients see only \
               that one, in one compositor window (needs `wayland` and `dri`). Nothing \
               manages those windows unless `wm=` names a program, which the supervisor \
               resolves on the sandbox's `PATH` and runs inside as one more sandboxed \
               process. `\"host\"` binds the session's X socket and cookie instead: X11 \
               has no isolation between clients, so a sandbox on your display can keylog \
               every other client, Xwayland included, and the security context does not \
               apply; lint warns unless the config says why.",
        risk: Risk::Outward,
        grammar: "x11 [\"host\"] [geometry=\"WxH\"] [fullscreen=#true] [grab=#true] \
                  [wm=\"<program>\"]",
    },
    Grant {
        node: "network",
        summary: "a network namespace, the sandbox's own unless the node says otherwise",
        cost: "The sandbox reaches the internet, which is where anything it reads can go. \
               `network \"host\"` gives it the host's namespace instead: loopback services, \
               abstract unix sockets, which have no permission checks at all, and the \
               host's interfaces, addresses and VPN tunnels. `allow-port` opens a path \
               from the host's loopback back into the sandbox. `outbound \"deny\"` narrows \
               the isolated namespace to the addresses `allow-out` names, by address and \
               never by name.",
        risk: Risk::Wide,
        grammar: "network [\"host\"|\"none\"] { dns \"<ip>\"; allow-port <n> [udp=#true]; \
                  outbound \"deny\"; allow-out \"<ip>[/<len>]\" [port=<n>] \
                  [proto=\"tcp\"|\"udp\"]; no-ipv6 }",
    },
    Grant {
        node: "dri",
        summary: "the GPU: /dev/dri, the NVIDIA nodes, and the sysfs a driver reads",
        cost: "The device nodes are bound read-write, since bwrap has no read-only device \
               bind, and the sysfs half is `/sys/dev/char`, `/sys/devices/system/cpu` and \
               every `/sys/devices/pci*` root — the attributes of every PCI device on the \
               machine, not only the GPU.",
        risk: Risk::Wide,
        grammar: "dri",
    },
    Grant {
        node: "pipewire",
        summary: "the session's PipeWire socket",
        cost: "Capture as well as playback: everything the session exposes, the microphone \
               among it, with no portal in between and no prompt. The `camera` grant is \
               the portal-mediated way to reach a device instead.",
        risk: Risk::Wide,
        grammar: "pipewire",
    },
    Grant {
        node: "pulseaudio",
        summary: "the session's PulseAudio socket, and `PULSE_SERVER` pointing at it",
        cost: "The same reach `pipewire` has, through the older protocol: recording as \
               well as playing, with nothing between the sandbox and the server.",
        risk: Risk::Wide,
        grammar: "pulseaudio",
    },
    Grant {
        node: "gamepad",
        summary: "game controllers: /dev/input, and the sysfs and udev data that name them",
        cost: "`/dev/input` is every input device the machine has, keyboards included; what \
               stops a sandbox from reading yours is the permissions on the nodes, not \
               bubbler. The `/sys/devices` bind is the whole device tree, and \
               `uinput=#true` lets the sandbox create virtual input devices and type into \
               your session.",
        risk: Risk::Outward,
        grammar: "gamepad [hidraw=#true] [uinput=#true]",
    },
    Grant {
        node: "hidraw",
        summary: "every /dev/hidraw* node the host has at launch",
        cost: "Every HID device on the machine, not the one you meant: a security key, a \
               hardware wallet and whatever else udev has given your login an ACL on. The \
               list is frozen at launch, so a device plugged in later has no node inside.",
        risk: Risk::Wide,
        grammar: "hidraw",
    },
    Grant {
        node: "camera",
        summary: "cameras through the portal, which binds no device at all",
        cost: "The bare node needs `portals` and hands over nothing: the host daemon opens \
               the device and the instance holds a revocable permission of its own. \
               `nodes=#true` binds every `/dev/video*` and `/dev/media*` the host has \
               instead, a virtual camera among them, with no prompt and no revoking.",
        risk: Risk::Wide,
        grammar: "camera [nodes=#true]",
    },
    Grant {
        node: "home-share",
        summary: "one path under $HOME, at the same relative path in the private home",
        cost: "The source must resolve inside your home and is bound read-only unless \
               `mode=rw`, which lets the sandbox change what it was shown. A directory \
               holding another application's state (`.config`, `.local/share`) is that \
               application's data, and the linter says so.",
        risk: Risk::Wide,
        grammar: "home-share \"<path under $HOME>\" [mode=ro|rw]",
    },
    Grant {
        node: "path-share",
        summary: "a host path outside the home, at that same path inside",
        cost: "Read-only unless `mode=rw`. The paths the sandbox is built out of are \
               refused on both ends — including the instance store, since a sandbox that \
               can write a `config.kdl` grants itself anything on the next run — but \
               everything else on the machine is shareable, and a mountpoint is a whole \
               disk.",
        risk: Risk::Wide,
        grammar: "path-share \"<absolute path>\" [mode=ro|rw]",
    },
    Grant {
        node: "etc-share",
        summary: "one entry under /etc, read-only, on top of the baseline allowlist",
        cost: "One path component, never a tree of your own choosing, and never the \
               account files: the sandbox generates its own `passwd` and `group`, and \
               binding the host's back in would undo that and hand over the shadow hashes.",
        risk: Risk::Narrow,
        grammar: "etc-share \"<entry under /etc>\"",
    },
    Grant {
        node: "app-runtime",
        summary: "$XDG_RUNTIME_DIR/app/<id>, shared with everything else naming that id",
        cost: "One id is one trust domain: every sandbox granted it, and every unsandboxed \
               process of yours, can read, write and replace what is in that directory, \
               and no side can tell its peers apart. `mode=rw` is for the side that serves \
               a socket, and it can unlink the one the others connect to.",
        risk: Risk::Outward,
        grammar: "app-runtime \"<app.id>\" [mode=ro|rw]",
    },
    Grant {
        node: "dbus",
        summary: "the session bus through a filtering xdg-dbus-proxy, and nothing it does not name",
        cost: "Each rule is its own grant, and the globs are wide: `own \"org.*\"` claims \
               every name under `org.`. The proxy speaks to the bus with your credentials, \
               so a name the sandbox is given is reached as you — `own \
               \"org.freedesktop.secrets\"` is the login keyring, every secret in it.",
        risk: Risk::Outward,
        grammar: "dbus { see|talk|own \"<name>\"; call|broadcast \"<name>=<rule>\" }",
    },
    Grant {
        node: "system-bus",
        summary: "the system bus through the same proxy, with no default name at all",
        cost: "The `talk` list is the entire confinement and it is weaker than the session \
               bus one: the bus and polkit see the proxy, running as your user, so behind \
               a granted name the sandbox is judged an ordinary local process of yours — \
               an `auth_admin` method pops a password prompt with nothing on it to say \
               which sandbox asked. Grant one name at a time, and prefer a portal.",
        risk: Risk::Outward,
        grammar: "system-bus { see|talk \"<name>\"; call|broadcast \"<name>=<rule>\" }",
    },
    Grant {
        node: "portals",
        summary: "the XDG portal rule bundle plus the /.flatpak-info portals identify the sandbox by",
        cost: "Portal operations run outside the sandbox: a file chooser runs on the host \
               and only the file you pick appears inside, under $XDG_RUNTIME_DIR/doc, \
               readable or writable as the portal granted it; `OpenURI` hands a link to \
               a host application. Each one is the user's choice at the time, which is \
               what makes this the narrow way to reach files, cameras and screencasts. \
               Requires `dbus`; the spawn portal is not among the rules. Without a \
               document portal on the host the launch warns and picked files stay \
               unreachable.",
        risk: Risk::Narrow,
        grammar: "portals",
    },
    Grant {
        node: "notify",
        summary: "talk to org.freedesktop.Notifications",
        cost: "Desktop notifications, whose text and actions the sandbox writes: the \
               notification is shown as coming from it, and clicking an action calls back \
               into the sandbox. Requires `dbus`.",
        risk: Risk::Narrow,
        grammar: "notify",
    },
    Grant {
        node: "tray",
        summary: "talk to org.kde.StatusNotifierWatcher, which is what a tray icon takes",
        cost: "One rule, and the item itself is served on the sandbox's own unique name, so \
               nothing has to be owned. Never widen it to `own \"org.kde.*\"`: that covers \
               the watcher's name, and owning it means impersonating the tray and \
               collecting every other application's items. Requires `dbus`.",
        risk: Risk::Narrow,
        grammar: "tray",
    },
    Grant {
        node: "mpris",
        summary: "own org.mpris.MediaPlayer2.<name>, so media keys reach the player",
        cost: "The name is owned with your credentials on the session bus, so name the \
               application rather than a prefix: `name=\"*\"` owns the whole player tree and \
               lets the sandbox impersonate every player on the bus. Requires `dbus`.",
        risk: Risk::Narrow,
        grammar: "mpris name=\"<suffix>\"",
    },
    Grant {
        node: "a11y",
        summary: "the session's accessibility bus, which is how a screen reader reads this app",
        cost: "Assistive tools on the host can read and drive this app's widgets; the app \
               can register itself and nothing else: the keystroke listener and \
               input-injection calls the same bus offers are not in its rules, so it \
               cannot read what you type into your other windows or type into them. The \
               bus itself has no per-client policy, which is why the rule set is fixed \
               and the node takes nothing. Requires `dbus`.",
        risk: Risk::Narrow,
        grammar: "a11y",
    },
    Grant {
        node: "input-method",
        summary: "fcitx5 and IBus over their sandboxed portal names",
        cost: "The input method daemon gets the keys typed into this app's text fields, \
               through the portal name that carries no configuration or control \
               interface: the daemons' own names, which can reconfigure, restart or stop \
               them for the whole session, are not granted. On Wayland the compositor \
               already handles input methods with no grant at all; this is the bus path \
               that toolkit IM modules and Xwayland clients take. Requires `dbus`.",
        risk: Risk::Narrow,
        grammar: "input-method",
    },
    Grant {
        node: "tty",
        summary: "how the sandbox's stdio reaches your terminal",
        cost: "`pty` is the default: bubbler allocates a pseudoterminal, relays it, and the \
               sandbox never holds a descriptor of your terminal. `passthrough` hands over \
               your own descriptors, which reach the terminal again through \
               `/dev/console`; `none` gives the sandbox no terminal at all.",
        risk: Risk::Outward,
        grammar: "tty \"pty\"|\"passthrough\"|\"none\"",
    },
    Grant {
        node: "userns",
        summary: "whether the sandbox may nest user namespaces of its own",
        cost: "A restriction rather than a grant. `disable` closes the door a nested user \
               namespace opens, and costs the inner sandbox of Firefox and Chromium and \
               anything that nests a container — Steam's pressure-vessel among them. It \
               also fails the launch outright on a host without unprivileged user \
               namespaces.",
        risk: Risk::Narrow,
        grammar: "userns \"allow\"|\"disable\"",
    },
    Grant {
        node: "seccomp",
        summary: "changes to the default syscall denylist for this instance",
        cost: "`allow` takes names off the list, including the `ioctl` rules that deny \
               `TIOCSTI` and `TIOCLINUX`; `deny` adds names. `disable` loads no filter at \
               all, which hands the sandbox the kernel surface the default covers — the \
               keyring, `bpf`, `perf_event_open`, module loading — and every run of that \
               instance says so on stderr.",
        risk: Risk::Outward,
        grammar: "seccomp { allow \"<syscall>\"; deny \"<syscall>\" [errno=\"EPERM\"|\"ENOSYS\"]; disable }",
    },
    Grant {
        node: "env",
        summary: "extra environment variables for the command",
        cost: "The sandbox starts with a cleared environment, and these are added to it. \
               The variables bubbler owns are refused, and a value that looks like a \
               credential is a lint warning: the config file is not a secret store, and \
               everything in the sandbox can read `/proc/self/environ`.",
        risk: Risk::Narrow,
        grammar: "env KEY=\"value\" ...",
    },
    Grant {
        node: "lint-allow",
        summary: "accept one lint finding in this file, with the reason written down",
        cost: "Only warnings and notes can be accepted; an error names something the file \
               cannot do. The reason is required and is the whole value of the node, and a \
               suppression that silences nothing is itself a finding.",
        risk: Risk::Narrow,
        grammar: "lint-allow \"<check-id>\" reason=\"<text>\"",
    },
    Grant {
        node: "desktop",
        summary: "the desktop entry `bubbler desktop` copies this instance's launcher entry from",
        cost: "A hint for one subcommand: it grants nothing and reaches no host path at \
               launch. Write it where the vendor entry is not named after the command — \
               `org.mozilla.Thunderbird.desktop` for `thunderbird` — so the lookup does \
               not have to guess between candidates.",
        risk: Risk::Narrow,
        grammar: "desktop \"<name>.desktop\"",
    },
    Grant {
        node: "command",
        summary: "the default argv `bubbler run` starts in the sandbox",
        cost: "One argv, no shell: every argument is passed as written, and none of it is \
               expanded or split. The command is looked up in the sandbox's own `PATH`, so \
               it has to be something the read-only `/usr` inside actually holds.",
        risk: Risk::Narrow,
        grammar: "command \"<argv0>\" \"<arg>\" ...",
    },
];

/// The catalogue entry for the node `node`, if it is one bubbler takes.
pub fn grant(node: &str) -> Option<&'static Grant> {
    GRANTS.iter().find(|g| g.node == node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InstanceConfig, NODES, parse_profile};

    /// One minimal node of every kind, so what the catalogue describes is
    /// measured against what the parser takes rather than against itself.
    /// `parse_profile`, because the cross-node checks an instance config
    /// gets (`camera` needs `portals`) are not what is under test here.
    const SAMPLES: &[(&str, &str)] = &[
        ("wayland", "wayland \"host\""),
        ("x11", "x11 \"host\""),
        ("network", "network \"host\""),
        ("dri", "dri"),
        ("pipewire", "pipewire"),
        ("pulseaudio", "pulseaudio"),
        ("gamepad", "gamepad uinput=#true"),
        ("hidraw", "hidraw"),
        ("camera", "camera nodes=#true"),
        ("home-share", "home-share \"Downloads\" mode=rw"),
        ("path-share", "path-share \"/mnt/data\""),
        ("etc-share", "etc-share \"vulkan\""),
        ("app-runtime", "app-runtime \"org.example.App\""),
        ("dbus", "dbus { talk \"ca.desrt.dconf\" }"),
        (
            "system-bus",
            "system-bus { talk \"org.freedesktop.UPower\" }",
        ),
        ("portals", "portals"),
        ("notify", "notify"),
        ("tray", "tray"),
        ("mpris", "mpris name=\"example\""),
        ("a11y", "a11y"),
        ("input-method", "input-method"),
        ("tty", "tty \"none\""),
        ("userns", "userns \"disable\""),
        ("seccomp", "seccomp { disable }"),
        ("env", "env A=\"1\""),
        (
            "lint-allow",
            "lint-allow \"x11-without-reason\" reason=\"no Wayland backend\"",
        ),
        ("desktop", "desktop \"org.example.App.desktop\""),
        ("command", "command \"true\""),
    ];

    #[test]
    fn every_node_the_parser_takes_is_described_once_and_in_order() {
        let described: Vec<&str> = GRANTS.iter().map(|g| g.node).collect();
        assert_eq!(described, NODES);
        assert!(grant("wayland").is_some());
        assert!(grant("teleport").is_none());
    }

    #[test]
    fn every_entry_carries_the_three_things_a_reader_needs() {
        for g in GRANTS {
            assert!(!g.summary.is_empty(), "{}: no summary", g.node);
            assert!(
                !g.summary.contains('\n'),
                "{}: summary is not one line",
                g.node
            );
            assert!(
                g.cost.len() > g.summary.len(),
                "{}: cost says no more than the summary",
                g.node
            );
            assert!(
                !g.cost.contains('\n'),
                "{}: cost is not one paragraph",
                g.node
            );
            // The grammar opens with the node, so a reader can find the
            // entry by the line they wrote.
            assert!(
                g.grammar.starts_with(g.node),
                "{}: grammar does not start with the node",
                g.node
            );
            assert!(
                !g.grammar.contains('\n'),
                "{}: grammar is not one line",
                g.node
            );
        }
    }

    #[test]
    fn each_described_node_parses_and_grants_what_it_is_named_after() {
        let sampled: Vec<&str> = SAMPLES.iter().map(|(node, _)| *node).collect();
        assert_eq!(sampled, NODES, "a node is described with no sample of it");
        for (node, text) in SAMPLES {
            let cfg = parse_profile(text)
                .unwrap_or_else(|e| panic!("{text}: {e}"))
                .config;
            // Every sample changes the config, so a node whose arm the
            // parser lost would be caught here rather than accepted and
            // dropped.
            assert_ne!(cfg, InstanceConfig::default(), "{text} granted nothing");
            if let [svc] = cfg.services.as_slice() {
                assert_eq!(svc.node_name(), *node, "{text}");
            }
            assert!(grant(node).is_some(), "{node} has no catalogue entry");
        }
    }

    #[test]
    fn the_levels_are_told_apart_in_writing() {
        assert_eq!(Risk::Narrow.to_string(), "narrow");
        assert_eq!(Risk::Wide.to_string(), "wide");
        assert_eq!(Risk::Outward.to_string(), "outward");
        // Every level is used: one that describes nothing is a level the
        // table draws no distinction with.
        for risk in [Risk::Narrow, Risk::Wide, Risk::Outward] {
            assert!(
                GRANTS.iter().any(|g| g.risk == risk),
                "{risk} describes nothing"
            );
        }
    }
}
