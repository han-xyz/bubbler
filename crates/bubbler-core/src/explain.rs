//! Reading format for a bwrap argv: every argument under the node that
//! produced it. It is deliberately not diffable — `--dry-run` is, one
//! element per line — and deliberately not a permission explainer: it
//! says which node an argument came from, never why the baseline holds
//! what it holds.

use std::ffi::OsStr;

use crate::bwrap::{Explained, Origin};
use crate::config::{InstanceConfig, Lines, SeccompConfig, Service, WaylandMode};
use crate::dbus;
use crate::error::ConfigError;
use crate::kdl_out;
use crate::network::{self, NetworkConfig};
use crate::wayland;

/// Arguments of the baseline listed before the rest is summed up. The
/// baseline is the same in every sandbox and the longest group by far.
const BASELINE_SHOWN: usize = 8;

/// Longest node text a header shows. A `path-share` of a deep path would
/// otherwise set the width of the column for every other group.
const LABEL_MAX: usize = 40;

/// Where the nodes of a config were written, for the group headers.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    /// File the lines are counted in, as it is worth naming to the user.
    pub file: &'a str,
    /// Line of each node; empty where they are not known.
    pub lines: &'a Lines,
}

impl Source<'_> {
    /// `<file>:<line>` of the node behind `origin`, empty for one the
    /// file does not answer for.
    fn of(&self, origin: Origin) -> String {
        let line = match origin {
            Origin::Service(i) => self.lines.services.get(i).copied().flatten(),
            Origin::Env(i) => self.lines.env.get(i).copied().flatten(),
            Origin::Userns => self.lines.userns,
            // Every sandbox has a filter; only a `seccomp` node has a line.
            Origin::Seccomp => self.lines.seccomp,
            _ => None,
        };
        match line {
            Some(line) => format!("{}:{line}", self.file),
            None => String::new(),
        }
    }
}

/// What one rendering is of.
#[derive(Debug, Clone, Copy)]
pub struct View<'a> {
    /// First line: the program the argv belongs to.
    pub title: &'a str,
    /// The config the origins index into.
    pub cfg: &'a InstanceConfig,
    /// Instance the config belongs to, for the identities a grant carries
    /// that no argument of it shows. A validated instance name.
    pub instance: &'a str,
    /// Where that config's nodes are.
    pub source: Source<'a>,
    /// The D-Bus proxy rules each node contributes, as [`rules`] collects
    /// them, so a node whose whole grant is rules can show them.
    pub rules: &'a [(usize, String)],
    /// The sidecar's argv rather than the sandbox's: its groups are the
    /// rules themselves, and a grant that contributes neither an argument
    /// nor a rule to it is not a group of it.
    pub proxy: bool,
    /// List the baseline instead of summing it up after its first
    /// arguments.
    pub full: bool,
}

/// The proxy rules each node of `cfg` contributes, as (position in
/// `services`, rule), in the order the proxy is given them. Empty when
/// the config grants no bus and starts no proxy. `instance` is a
/// validated instance name.
pub fn rules(cfg: &InstanceConfig, instance: &str) -> Vec<(usize, String)> {
    let Some(plan) = dbus::plan(&cfg.services, instance) else {
        return Vec::new();
    };
    [plan.session.as_ref(), plan.system.as_ref()]
        .into_iter()
        .flatten()
        .flat_map(|s| &s.rules)
        .map(|r| (r.node, r.arg.to_string_lossy().into_owned()))
        .collect()
}

/// One node's arguments. Arguments of one origin are collected into a
/// single group even where the phases separate them: `network` inserts
/// `--share-net` into phase 1 and binds `/etc/resolv.conf` in phase 4,
/// and both are that node's.
struct Group<'a> {
    origin: Origin,
    label: String,
    source: String,
    items: Vec<&'a Explained>,
}

impl Group<'_> {
    /// Argv elements, which is what the counts are in: an operation is a
    /// line here but several arguments to bwrap.
    fn len(&self) -> usize {
        self.items.iter().map(|i| i.args.len()).sum()
    }
}

/// Whether a service also carries rules for the D-Bus proxy, which are
/// not bwrap arguments and so are invisible in an argv.
fn carries_rules(s: &Service) -> bool {
    matches!(
        s,
        Service::Dbus { .. }
            | Service::SystemBus { .. }
            | Service::Portals
            | Service::Notify
            | Service::Tray
            | Service::Mpris { .. }
    )
}

/// `label` cut to [`LABEL_MAX`] characters, with the cut marked.
fn shorten(label: String) -> String {
    if label.chars().count() <= LABEL_MAX {
        return label;
    }
    label
        .chars()
        .take(LABEL_MAX - 1)
        .chain(std::iter::once('…'))
        .collect()
}

/// The node an origin names, as its KDL. A block node is named by the
/// line it opens on, since the rules under it are not arguments.
fn label(origin: Origin, cfg: &InstanceConfig) -> Result<String, ConfigError> {
    Ok(shorten(match origin {
        Origin::Baseline => "baseline".to_owned(),
        Origin::Seccomp => "seccomp".to_owned(),
        Origin::Userns => "userns".to_owned(),
        Origin::Ctty => "ctty".to_owned(),
        Origin::Identity => "identity".to_owned(),
        Origin::Init => "init".to_owned(),
        Origin::Command => "command".to_owned(),
        Origin::Env(i) => match cfg.env.get(i) {
            Some((k, _)) => format!("env {k}"),
            None => format!("env #{i}"),
        },
        Origin::Service(i) => match cfg.services.get(i) {
            Some(s) => kdl_out::service(s)?
                .lines()
                .next()
                .unwrap_or_default()
                .trim_end_matches(" {")
                .to_owned(),
            None => format!("service #{i}"),
        },
    }))
}

/// Where the node behind `origin` was written, in this view. The
/// sidecar's filter is never the config's: it gets the default rule set
/// whatever a `seccomp` node says, so that group names no line of the
/// file it did not come from.
fn source(origin: Origin, view: &View) -> String {
    match view.proxy && origin == Origin::Seccomp {
        true => String::new(),
        false => view.source.of(origin),
    }
}

/// Groups in emit order: a group appears where its first argument does.
/// In the sandbox's own argv a granted service that produced no argument
/// at all keeps its place among the services around it, so that a grant
/// which reaches the sandbox another way is not simply missing; in the
/// sidecar's, the nodes are only those its rules came from.
fn groups<'a>(items: &'a [Explained], view: &View) -> Result<Vec<Group<'a>>, ConfigError> {
    let mut out: Vec<Group> = Vec::new();
    for item in items {
        match out.iter_mut().find(|g| g.origin == item.origin) {
            Some(g) => g.items.push(item),
            None => out.push(Group {
                origin: item.origin,
                label: label(item.origin, view.cfg)?,
                source: source(item.origin, view),
                items: vec![item],
            }),
        }
    }
    if view.proxy {
        return Ok(out);
    }
    // A `seccomp` node that leaves nothing to load — `disable`, or an
    // `allow` list that empties the denylist — produced no argument to be
    // found under, and that is the one worth seeing. It belongs where the
    // filter is loaded, which is after the baseline and ahead of the
    // grants.
    if view.cfg.seccomp != SeccompConfig::default()
        && !out.iter().any(|g| g.origin == Origin::Seccomp)
    {
        let at = out
            .iter()
            .position(|g| !matches!(g.origin, Origin::Baseline | Origin::Userns))
            .unwrap_or(out.len());
        out.insert(
            at,
            Group {
                origin: Origin::Seccomp,
                label: label(Origin::Seccomp, view.cfg)?,
                source: source(Origin::Seccomp, view),
                items: Vec::new(),
            },
        );
    }
    let first_service = out
        .iter()
        .position(|g| matches!(g.origin, Origin::Service(_)));
    let mut after = None;
    for i in 0..view.cfg.services.len() {
        let origin = Origin::Service(i);
        if let Some(at) = out.iter().position(|g| g.origin == origin) {
            after = Some(at);
            continue;
        }
        let at = match (after, first_service) {
            (Some(prev), _) => prev + 1,
            (None, Some(first)) => first,
            // No service reached bwrap at all: the grants still belong
            // where services are emitted, ahead of the command.
            (None, None) => out
                .iter()
                .position(|g| matches!(g.origin, Origin::Init | Origin::Ctty | Origin::Command))
                .unwrap_or(out.len()),
        };
        out.insert(
            at,
            Group {
                origin,
                label: label(origin, view.cfg)?,
                source: source(origin, view),
                items: Vec::new(),
            },
        );
        after = Some(at);
    }
    Ok(out)
}

/// One operation as a line: the arguments as written, then what a
/// generated fd among them refers to. A path that is not UTF-8 is shown
/// with the replacement character; `--dry-run` is the byte-exact form.
fn operation(item: &Explained) -> String {
    let mut line = item
        .args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(note) = &item.note {
        line.push_str(&format!("  ({note})"));
    }
    line
}

/// What a node granted that is not an argument, each on its own line
/// under a lead-in naming what it is: it is the whole grant of a node
/// that contributes no argument, and easy to miss under one that does.
fn listed(empty: bool, items: Vec<String>) -> Vec<String> {
    under(if empty { "rule-only: " } else { "rules: " }, items)
}

/// `items` under a lead-in, the first line carrying it and the rest
/// aligned beneath.
fn under(lead: &str, items: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        let prefix = match out.is_empty() {
            true => lead.to_owned(),
            false => " ".repeat(lead.chars().count()),
        };
        out.push(format!("    {prefix}{item}"));
    }
    out
}

/// The outbound ruleset, exactly as `nft -f -` is fed it. A grant that
/// is neither a bwrap argument nor a D-Bus rule, so nothing else in this
/// view would show it; the nesting is kept, with each tab widened to
/// four columns so a terminal shows what the file holds.
fn ruleset_lines(cfg: &NetworkConfig) -> Vec<String> {
    let Some(text) = network::ruleset(cfg) else {
        return Vec::new();
    };
    under(
        "ruleset: ",
        text.lines().map(|l| l.replace('\t', "    ")).collect(),
    )
}

/// The pasta argv an isolated `network` node is served by. The two
/// descriptors and the sandbox pid are only known once bwrap is running,
/// so they are named here rather than numbered; `--dry-run` is the
/// sandbox's own argv and says nothing about sidecars.
fn sidecar_line(cfg: &NetworkConfig) -> String {
    let argv = network::pasta_argv(
        cfg,
        network::Attach {
            userns: OsStr::new("<userns>"),
            ready: OsStr::new("<ready-fd>"),
            child: OsStr::new("<child-pid>"),
        },
    );
    let mut line = String::from("    sidecar: pasta");
    for a in &argv {
        line.push(' ');
        line.push_str(&a.to_string_lossy());
    }
    line
}

/// The D-Bus proxy rules of the node at `index`, in the order the proxy
/// is given them.
fn rules_of(index: usize, rules: &[(usize, String)]) -> Vec<String> {
    rules
        .iter()
        .filter(|(node, _)| *node == index)
        .map(|(_, rule)| rule.clone())
        .collect()
}

/// What a `camera` node grants that no bwrap argument shows. The Camera
/// interface is on `org.freedesktop.portal.Desktop`, which the `portals`
/// rules already talk to, so the node adds no rule of its own either and
/// would otherwise render as a grant that did nothing.
const CAMERA_PORTAL: &str = "org.freedesktop.portal.Camera, carried by the portals bundle";

/// What a `seccomp` node did to the default denylist, which is the whole
/// grant of one that disables the filter and loads no program at all.
fn seccomp_lines(cfg: &SeccompConfig) -> Vec<String> {
    if cfg.disable {
        return vec!["filter disabled".to_owned()];
    }
    let mut out = Vec::new();
    if !cfg.allow.is_empty() {
        out.push(format!("allow {}", cfg.allow.join(", ")));
    }
    if !cfg.deny.is_empty() {
        let deny: Vec<String> = cfg
            .deny
            .iter()
            .map(|(name, errno)| format!("{name} ({})", errno.name()))
            .collect();
        out.push(format!("deny {}", deny.join(", ")));
    }
    out
}

/// The view's title, then one block per node in emit order, then a
/// summary line.
pub fn render(items: &[Explained], view: &View) -> Result<Vec<String>, ConfigError> {
    let groups = groups(items, view)?;
    let width = |f: &dyn Fn(&Group) -> usize| groups.iter().map(f).max().unwrap_or(0);
    let lw = width(&|g| g.label.chars().count());
    let sw = width(&|g| g.source.chars().count());
    let mut out = vec![view.title.to_owned(), String::new()];
    let mut hidden = 0;
    for g in &groups {
        let n = g.len();
        let plural = if n == 1 { "argument" } else { "arguments" };
        let header = match sw {
            0 => format!("  {:<lw$}  {n} {plural}", g.label),
            _ => format!("  {:<lw$}  {:<sw$}  {n} {plural}", g.label, g.source),
        };
        out.push(header.trim_end().to_owned());
        let elide = !view.full && g.origin == Origin::Baseline;
        let mut shown = 0;
        for item in &g.items {
            if elide && shown >= BASELINE_SHOWN {
                hidden += n - shown;
                out.push(format!("    ... {} more (--explain=full)", n - shown));
                break;
            }
            shown += item.args.len();
            out.push(format!("    {}", operation(item)));
        }
        // Only in the sandbox's own argv: in the sidecar's the rules are
        // the arguments listed above, and its filter is not the config's.
        if !view.proxy {
            match g.origin {
                Origin::Service(i) => match view.cfg.services.get(i) {
                    Some(s) if carries_rules(s) => {
                        out.extend(listed(n == 0, rules_of(i, view.rules)));
                    }
                    Some(Service::Camera { .. }) => {
                        out.extend(listed(n == 0, vec![CAMERA_PORTAL.to_owned()]));
                    }
                    // An isolated `network` is half a sidecar: its own
                    // arguments are only the resolver file, and what
                    // connects the namespace is the process below.
                    Some(Service::Network(cfg)) if cfg.is_isolated() => {
                        out.push(sidecar_line(cfg));
                        out.extend(ruleset_lines(cfg));
                    }
                    // Which socket the one `--ro-bind` names is the whole
                    // difference between the two modes. No probe is run
                    // for an explanation, so this is what a run gets on a
                    // compositor that implements the protocol; one that
                    // does not says so on stderr and binds the session's.
                    Some(Service::Wayland(WaylandMode::Sandboxed)) => out.push(format!(
                        "    security-context: engine={} app={} instance={}",
                        wayland::ENGINE,
                        dbus::app_id(view.instance),
                        dbus::flatpak_instance_id(view.instance)
                    )),
                    Some(Service::Wayland(WaylandMode::Host)) => {
                        out.push("    raw socket: wayland \"host\"".to_owned());
                    }
                    _ => {}
                },
                Origin::Seccomp => out.extend(listed(n == 0, seccomp_lines(&view.cfg.seccomp))),
                _ => {}
            }
        }
        out.push(String::new());
    }
    let total: usize = groups.iter().map(Group::len).sum();
    let plural = if groups.len() == 1 { "group" } else { "groups" };
    let mut summary = format!("{total} arguments in {} {plural}", groups.len());
    if hidden > 0 {
        summary.push_str(&format!(", {hidden} hidden (--explain=full)"));
    }
    if !view.proxy && !view.rules.is_empty() {
        let plural = if view.rules.len() == 1 {
            "rule"
        } else {
            "rules"
        };
        summary.push_str(&format!(
            "; {} D-Bus {plural} to the proxy (--proxy)",
            view.rules.len()
        ));
    }
    out.push(summary);
    Ok(out)
}

/// One JSON object per operation, in argv order and with nothing elided:
/// `{"origin":{"kind","node","index","line"},"args":[...],"note"}`. The
/// result has no trailing newline. An argument that is not UTF-8 is
/// written with the replacement character, since JSON has no byte
/// strings; `--dry-run` is the byte-exact form.
pub fn render_json(items: &[Explained], view: &View) -> Result<String, ConfigError> {
    let mut out = String::from("[\n");
    for (n, item) in items.iter().enumerate() {
        let (kind, index) = match item.origin {
            Origin::Baseline => ("baseline", None),
            Origin::Seccomp => ("seccomp", None),
            Origin::Userns => ("userns", None),
            Origin::Ctty => ("ctty", None),
            Origin::Identity => ("identity", None),
            Origin::Init => ("init", None),
            Origin::Command => ("command", None),
            Origin::Service(i) => ("service", Some(i)),
            Origin::Env(i) => ("env", Some(i)),
        };
        // The same `<file>:<line>` the text form heads a group with, split
        // back into the number alone.
        let line = source(item.origin, view)
            .rsplit(':')
            .next()
            .and_then(|l| l.parse::<u32>().ok());
        let args: Vec<String> = item.args.iter().map(|a| quote_os(a)).collect();
        out.push_str("  {\"origin\": {");
        out.push_str(&format!("\"kind\": {}", quote(kind)));
        out.push_str(&format!(
            ", \"node\": {}",
            quote(&label(item.origin, view.cfg)?)
        ));
        out.push_str(&match index {
            Some(i) => format!(", \"index\": {i}"),
            None => ", \"index\": null".to_owned(),
        });
        out.push_str(&match line {
            Some(l) => format!(", \"line\": {l}"),
            None => ", \"line\": null".to_owned(),
        });
        out.push_str(&format!("}}, \"args\": [{}]", args.join(", ")));
        out.push_str(&match &item.note {
            Some(note) => format!(", \"note\": {}", quote(note)),
            None => ", \"note\": null".to_owned(),
        });
        out.push_str(if n + 1 == items.len() { "}\n" } else { "},\n" });
    }
    out.push(']');
    Ok(out)
}

/// A JSON string literal, with the control characters JSON refuses
/// written as escapes.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// [`quote`] for an argument, which is not necessarily UTF-8.
fn quote_os(s: &OsStr) -> String {
    quote(&s.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ShareMode;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    fn item(origin: Origin, args: &[&str], note: Option<&str>) -> Explained {
        Explained {
            origin,
            args: args.iter().map(OsString::from).collect(),
            note: note.map(str::to_owned),
        }
    }

    fn cfg(kdl: &str) -> InstanceConfig {
        crate::config::parse(kdl).unwrap()
    }

    /// Thirteen baseline arguments, so the elision has something to hide.
    fn baseline() -> Vec<Explained> {
        vec![
            item(Origin::Baseline, &["--unshare-all"], None),
            item(Origin::Baseline, &["--die-with-parent"], None),
            item(Origin::Baseline, &["--new-session"], None),
            item(Origin::Baseline, &["--hostname", "bubbler"], None),
            item(
                Origin::Baseline,
                &["--info-fd", "3"],
                Some("pipe: bwrap reports the sandbox pid on it"),
            ),
            item(Origin::Baseline, &["--tmpfs", "/etc"], None),
            item(Origin::Baseline, &["--ro-bind", "/usr", "/usr"], None),
            item(Origin::Baseline, &["--clearenv"], None),
        ]
    }

    #[test]
    fn a_group_carries_the_node_it_came_from_and_the_line_it_is_on() {
        let cfg = cfg(
            "wayland\ndbus\nportals\nnotify\nhome-share \"Downloads\" mode=rw\ncommand \"true\"",
        );
        let mut items = baseline();
        items.extend([
            item(
                Origin::Service(0),
                &["--ro-bind", "/run/t/wayland", "/run/wayland-1"],
                None,
            ),
            item(
                Origin::Service(1),
                &["--ro-bind", "/run/t/bus", "/run/bus"],
                None,
            ),
            item(
                Origin::Service(4),
                &["--bind", "/home/you/D", "/home/bubbler/D"],
                None,
            ),
            item(
                Origin::Service(0),
                &["--setenv", "WAYLAND_DISPLAY", "wayland-1"],
                None,
            ),
            item(Origin::Command, &["--", "true"], None),
        ]);
        let lines = Lines {
            services: vec![Some(1), Some(2), Some(3), Some(4), Some(5)],
            ..Lines::default()
        };
        let rules = rules(&cfg, "t");
        let out = render(
            &items,
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &rules,
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert_eq!(out.join("\n"), GOLDEN);
    }

    /// The whole of one rendering: group order, the column widths, the
    /// elision, the rules of a node that contributes no argument.
    const GOLDEN: &str = "\
bwrap

  baseline                                      13 arguments
    --unshare-all
    --die-with-parent
    --new-session
    --hostname bubbler
    --info-fd 3  (pipe: bwrap reports the sandbox pid on it)
    --tmpfs /etc
    ... 4 more (--explain=full)

  wayland                         config.kdl:1  6 arguments
    --ro-bind /run/t/wayland /run/wayland-1
    --setenv WAYLAND_DISPLAY wayland-1
    security-context: engine=org.bubbler app=org.bubbler.t instance=bubbler-t

  dbus                            config.kdl:2  3 arguments
    --ro-bind /run/t/bus /run/bus

  portals                         config.kdl:3  0 arguments
    rule-only: --talk=org.freedesktop.portal.Desktop
               --talk=org.freedesktop.portal.Documents
               --talk=org.freedesktop.portal.FileChooser
               --call=org.freedesktop.portal.*=*
               --broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*

  notify                          config.kdl:4  0 arguments
    rule-only: --talk=org.freedesktop.Notifications

  home-share \"Downloads\" mode=rw  config.kdl:5  3 arguments
    --bind /home/you/D /home/bubbler/D

  command                                       2 arguments
    -- true

27 arguments in 7 groups, 4 hidden (--explain=full); 6 D-Bus rules to the proxy (--proxy)";

    /// Which socket a `wayland` grant binds is not visible in its
    /// arguments — both are one `--ro-bind` — so the mode is a line of
    /// its own, in the bare node's case the identity a run registers.
    #[test]
    fn a_wayland_grant_says_which_socket_it_binds() {
        let cfg = cfg("wayland \"host\"\ncommand \"true\"");
        let lines = Lines::default();
        let out = render(
            &[item(
                Origin::Service(0),
                &["--ro-bind", "/run/wayland-1", "/run/wayland-1"],
                None,
            )],
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert!(
            out.contains(&"    raw socket: wayland \"host\"".to_owned()),
            "{out:#?}"
        );
    }

    #[test]
    fn a_camera_grant_shows_the_portal_it_reaches_the_sandbox_through() {
        let bare = cfg("dbus\nportals\ncamera\ncommand \"true\"");
        let lines = Lines {
            services: vec![Some(1), Some(2), Some(3)],
            ..Lines::default()
        };
        let bare_rules = rules(&bare, "t");
        let render_with = |items: &[Explained]| {
            render(
                items,
                &View {
                    title: "bwrap",
                    instance: "t",
                    cfg: &bare,
                    source: Source {
                        file: "config.kdl",
                        lines: &lines,
                    },
                    rules: &bare_rules,
                    proxy: false,
                    full: false,
                },
            )
            .unwrap()
        };
        // The bare grant is the whole of what the node did, and without
        // the line it would render as a grant that reached nothing.
        let out = render_with(&[item(Origin::Command, &["--", "true"], None)]);
        assert!(
            out.contains(&format!("    rule-only: {CAMERA_PORTAL}")),
            "{out:#?}"
        );
        assert!(out.iter().any(|l| l.starts_with("  camera ")), "{out:#?}");

        // With `nodes=#true` the binds are the node's arguments and the
        // portal is what it grants beside them.
        let with_nodes = cfg("dbus\nportals\ncamera nodes=#true\ncommand \"true\"");
        let node_rules = rules(&with_nodes, "t");
        let out = render(
            &[item(
                Origin::Service(2),
                &["--dev-bind-try", "/dev/video0", "/dev/video0"],
                None,
            )],
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &with_nodes,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &node_rules,
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert!(
            out.contains(&format!("    rules: {CAMERA_PORTAL}")),
            "{out:#?}"
        );
    }

    #[test]
    fn full_lists_the_baseline_and_hides_nothing() {
        let cfg = cfg("command \"true\"");
        let out = render(
            &baseline(),
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &Lines::default(),
                },
                rules: &[],
                proxy: false,
                full: true,
            },
        )
        .unwrap();
        assert!(
            !out.iter().any(|l| l.contains("more (--explain=full)")),
            "{out:?}"
        );
        assert_eq!(out.last().unwrap(), "13 arguments in 1 group");
        assert_eq!(out[2], "  baseline  13 arguments");
        assert_eq!(out.len(), 3 + baseline().len() + 2);
    }

    /// The one group order rule: a node appears where its first argument
    /// does, and one that produced none keeps its place among the rest.
    #[test]
    fn a_node_with_no_arguments_keeps_its_place_in_the_file_order() {
        let cfg = cfg("dbus\ntray\nnotify\nwayland\ncommand \"true\"");
        let items = [
            item(
                Origin::Service(0),
                &["--ro-bind", "/run/t/bus", "/run/bus"],
                None,
            ),
            item(Origin::Service(3), &["--ro-bind", "/run/w", "/run/w"], None),
        ];
        let lines = Lines {
            services: vec![Some(1), Some(2), Some(3), Some(4)],
            ..Lines::default()
        };
        let out = render(
            &items,
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        let headers: Vec<&str> = out
            .iter()
            .filter(|l| l.starts_with("  ") && l.contains("argument"))
            .map(|l| l.split_whitespace().next().unwrap_or_default())
            .collect();
        assert_eq!(headers, ["dbus", "tray", "notify", "wayland"]);
    }

    /// The sidecar's argv: its groups are the rules it was given, and a
    /// grant that contributed neither an argument nor a rule to it is not
    /// a group of it.
    #[test]
    fn the_proxy_view_lists_only_the_nodes_its_arguments_came_from() {
        let cfg = cfg("wayland\ndbus\nnotify\ncommand \"true\"");
        let items = [
            item(Origin::Baseline, &["--unshare-all"], None),
            item(Origin::Command, &["--filter"], None),
            item(
                Origin::Service(2),
                &["--talk=org.freedesktop.Notifications"],
                None,
            ),
        ];
        let lines = Lines {
            services: vec![Some(1), Some(2), Some(3)],
            ..Lines::default()
        };
        let rules = rules(&cfg, "t");
        let view = View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: Source {
                file: "config.kdl",
                lines: &lines,
            },
            rules: &rules,
            proxy: true,
            full: true,
        };
        let out = render(&items, &view).unwrap();
        assert!(!out.iter().any(|l| l.contains("wayland")), "{out:?}");
        // The rule is the argument, not a line under a zero-argument group.
        assert!(!out.iter().any(|l| l.contains("rule-only")), "{out:?}");
        assert_eq!(out[8], "  notify    config.kdl:3  1 argument");
        assert_eq!(out[9], "    --talk=org.freedesktop.Notifications");
    }

    /// A grant that reaches the sandbox through nothing at all on this
    /// host still says so, rather than being missing from the listing.
    #[test]
    fn a_grant_that_produced_nothing_is_still_a_group() {
        let cfg = cfg("hidraw\ncommand \"true\"");
        let items = [item(Origin::Command, &["--", "true"], None)];
        let lines = Lines {
            services: vec![Some(1)],
            ..Lines::default()
        };
        let out = render(
            &items,
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert_eq!(out[2], "  hidraw   config.kdl:1  0 arguments");
    }

    /// `userns`, `seccomp` and `env` are nodes of the file too, and a
    /// `seccomp` group without one of them is the default filter.
    #[test]
    fn the_nodes_that_are_not_grants_are_placed_as_well() {
        let cfg = cfg("env A=\"1\"\nuserns \"disable\"\ncommand \"true\"");
        let items = [
            item(Origin::Seccomp, &["--add-seccomp-fd", "4"], None),
            item(
                Origin::Userns,
                &["--unshare-user", "--disable-userns"],
                None,
            ),
            item(Origin::Env(0), &["--setenv", "A", "1"], None),
        ];
        let lines = Lines {
            env: vec![Some(1)],
            userns: Some(2),
            ..Lines::default()
        };
        let out = render(
            &items,
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert_eq!(out[2], "  seccomp                2 arguments");
        assert_eq!(out[5], "  userns   config.kdl:2  2 arguments");
        assert_eq!(out[8], "  env A    config.kdl:1  3 arguments");
    }

    /// A `seccomp` node is a node of the file like any other, and the one
    /// that loads no program at all is the one worth seeing.
    #[test]
    fn a_seccomp_node_that_loads_nothing_is_still_a_group() {
        let cfg = cfg("wayland\nseccomp {\n    disable\n}\ncommand \"true\"");
        let items = [
            item(Origin::Baseline, &["--unshare-all"], None),
            item(Origin::Service(0), &["--ro-bind", "/run/w", "/run/w"], None),
            item(Origin::Command, &["--", "true"], None),
        ];
        let lines = Lines {
            services: vec![Some(1)],
            seccomp: Some(2),
            ..Lines::default()
        };
        let out = render(
            &items,
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert_eq!(out[5], "  seccomp   config.kdl:2  0 arguments");
        assert_eq!(out[6], "    rule-only: filter disabled");
        assert_eq!(out[8], "  wayland   config.kdl:1  3 arguments");
    }

    /// What a `seccomp` node changed, under the arguments it did produce.
    #[test]
    fn a_seccomp_node_that_changes_the_filter_says_what_it_changed() {
        let cfg = cfg("seccomp {\n    allow \"ptrace\" \"perf_event_open\"\n    \
             deny \"read\" errno=\"ENOSYS\"\n}\ncommand \"true\"");
        let items = [item(Origin::Seccomp, &["--add-seccomp-fd", "4"], None)];
        let out = render(
            &items,
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &Lines::default(),
                },
                rules: &[],
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert_eq!(out[3], "    --add-seccomp-fd 4");
        assert_eq!(out[4], "    rules: allow ptrace, perf_event_open");
        assert_eq!(out[5], "           deny read (ENOSYS)");
    }

    #[test]
    fn a_label_too_long_for_the_column_is_cut_short() {
        let deep = PathBuf::from(format!("/srv/{}/data", "x".repeat(60)));
        let cfg = InstanceConfig {
            services: vec![Service::PathShare {
                path: deep,
                mode: ShareMode::ReadOnly,
            }],
            ..InstanceConfig::default()
        };
        let text = label(Origin::Service(0), &cfg).unwrap();
        assert_eq!(text.chars().count(), LABEL_MAX);
        assert!(text.starts_with("path-share \"/srv/xxx"), "{text}");
        assert!(text.ends_with('…'), "{text}");
    }

    #[test]
    fn json_holds_every_operation_with_its_origin() {
        let cfg = cfg("wayland\ncommand \"true\"");
        let items = [
            item(
                Origin::Seccomp,
                &["--add-seccomp-fd", "5"],
                Some("EPERM program, 376 bytes"),
            ),
            item(
                Origin::Service(0),
                &["--ro-bind", "/run/wayland-1", "/run/wayland-1"],
                None,
            ),
        ];
        let lines = Lines {
            services: vec![Some(1)],
            ..Lines::default()
        };
        let json = render_json(
            &items,
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                proxy: false,
                full: false,
            },
        )
        .unwrap();
        assert_eq!(
            json,
            "[\n  \
             {\"origin\": {\"kind\": \"seccomp\", \"node\": \"seccomp\", \"index\": null, \
             \"line\": null}, \"args\": [\"--add-seccomp-fd\", \"5\"], \
             \"note\": \"EPERM program, 376 bytes\"},\n  \
             {\"origin\": {\"kind\": \"service\", \"node\": \"wayland\", \"index\": 0, \
             \"line\": 1}, \"args\": [\"--ro-bind\", \"/run/wayland-1\", \"/run/wayland-1\"], \
             \"note\": null}\n]"
        );
    }

    #[test]
    fn a_quoted_string_survives_the_characters_json_refuses() {
        assert_eq!(quote("a\"b\\c\nd\te"), "\"a\\\"b\\\\c\\nd\\te\"");
        assert_eq!(quote("\u{1}"), "\"\\u0001\"");
        assert_eq!(
            quote_os(OsStr::from_bytes(b"/tmp/\xff")),
            "\"/tmp/\u{fffd}\""
        );
    }
}
