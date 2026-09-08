//! Reading format for a bwrap argv: every argument under the node that
//! produced it. It is deliberately not diffable — `--dry-run` is, one
//! element per line — and deliberately not a permission explainer: it
//! says which node an argument came from, never why the baseline holds
//! what it holds.

use std::ffi::OsStr;
use std::path::Path;

use unicode_width::UnicodeWidthStr;

use crate::bwrap::{Explained, Origin};
use crate::cgroup;
use crate::config::{
    AudioSet, InstanceConfig, Lines, SeccompConfig, Service, WaylandMode, X11Mode,
};
use crate::dbus;
use crate::error::ConfigError;
use crate::json;
use crate::kdl_out;
use crate::network::{self, NetworkConfig};
use crate::pipewire;
use crate::wayland;

/// Arguments of the baseline listed before the rest is summed up. The
/// baseline is the same in every sandbox and the longest group by far.
const BASELINE_SHOWN: usize = 8;

/// What a `dri kms=#true` group is headed with. The card nodes are two
/// arguments like any other, and neither they nor the masks that are
/// missing beside them say what granting them opens.
const KMS_NOTE: &str = " (kms: card nodes, EDID and framebuffer geometry readable)";

/// What a bare `dri` group is headed with where the grant bound a
/// primary node anyway: a GPU on the proprietary NVIDIA driver, whose
/// EGL will not drive a Wayland display without it. The file says
/// nothing about that node, so the header says what it reads through
/// it: connectors, their modes, the monitors' EDID — measured with
/// `modetest`, not the master-only reach [`KMS_NOTE`] carries.
const NVIDIA_NOTE: &str = " (nvidia: primary node bound for its EGL — connectors, their modes, the monitors' EDID readable)";

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
    /// How the Wayland proxy is run for this instance, which no argument
    /// of the sandbox's own argv shows; `None` where the config grants
    /// no sandboxed `wayland` and so starts none.
    pub wl_proxy: Option<&'a wayland::ProxyPlan>,
    /// Whether the egress proxy will be run with `--log-tunnels`, which
    /// is [`crate::env::Env::net_proxy_log`] and shows in its sidecar
    /// line; nothing else of the explanation depends on it.
    pub net_proxy_log: bool,
    /// What an audio grant's group header ends with:
    /// [`crate::audio_policy::EXPLAIN_SUFFIX`] where this host has no
    /// policy drop-in, else empty. Asked of the host by the caller, like
    /// `bwrap` below: an explanation describes a run, and probes for it
    /// itself.
    pub audio_policy: &'static str,
    /// The sidecar's argv rather than the sandbox's: its groups are the
    /// rules themselves, and a grant that contributes neither an argument
    /// nor a rule to it is not a group of it.
    pub proxy: bool,
    /// List the baseline instead of summing it up after its first
    /// arguments.
    pub full: bool,
    /// The version of the `bwrap` this argv would be handed, so a reader
    /// sees both halves of the sandbox: the arguments, and the binary
    /// that carries them out. [`crate::version::Version::Unknown`] where
    /// the tool could not be asked.
    pub bwrap: crate::version::Version,
}

/// The proxy rules each node of `cfg` contributes, as (position in
/// `services`, rule), in the order the proxy is given them. Empty when
/// the config grants no bus and starts no proxy. `instance` is a
/// validated instance name.
pub fn rules(cfg: &InstanceConfig, instance: &str) -> Vec<(usize, String)> {
    let Some(plan) = dbus::plan(&cfg.services, instance) else {
        return Vec::new();
    };
    [
        plan.session.as_ref(),
        plan.system.as_ref(),
        plan.a11y.as_ref(),
    ]
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

/// Whether a group holds a `--dev-bind` of a primary DRM node. Read off
/// the arguments rather than probed again: what the note beside them
/// says is that they are there, and a run this explains would be the one
/// that put them there.
fn binds_a_primary_node(items: &[&Explained]) -> bool {
    items.iter().any(|i| {
        let [flag, src, ..] = i.args.as_slice() else {
            return false;
        };
        let src = Path::new(src);
        flag == "--dev-bind"
            && src.parent() == Some(Path::new("/dev/dri"))
            && src
                .file_name()
                .is_some_and(|n| n.as_encoded_bytes().starts_with(b"card"))
    })
}

/// Whether a service also carries rules for the D-Bus proxy, which are
/// not bwrap arguments and so are invisible in an argv.
fn carries_rules(s: &Service) -> bool {
    matches!(
        s,
        Service::Dbus { .. }
            | Service::SystemBus { .. }
            | Service::Portals { .. }
            | Service::Notify
            | Service::Tray
            | Service::Mpris { .. }
            | Service::A11y
            | Service::InputMethod
            | Service::Camera { .. }
    )
}

/// The node an origin names, as its KDL. A block node is named by the
/// line it opens on, since the rules under it are not arguments.
fn label(origin: Origin, cfg: &InstanceConfig) -> Result<String, ConfigError> {
    Ok(kdl_out::shorten(
        &match origin {
            Origin::Baseline => "baseline".to_owned(),
            Origin::Seccomp => "seccomp".to_owned(),
            Origin::Userns => "userns".to_owned(),
            // Only reached in Host mode: the allowlist's items stay
            // tagged `Origin::Baseline`, so there is no bare-node case
            // to spell here.
            Origin::Etc => "etc \"host\"".to_owned(),
            Origin::Tmp => match cfg.tmp {
                Some(size) => kdl_out::tmp(size),
                None => "tmp".to_owned(),
            },
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
            Origin::Share(i) => match cfg.shares.get(i) {
                Some(s) => format!(
                    "--share {} mode={}",
                    kdl_out::quote(&s.path.to_string_lossy()),
                    kdl_out::share_mode(s.mode)
                ),
                None => format!("--share #{i}"),
            },
        },
        LABEL_MAX,
    ))
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
fn ruleset_lines(cfg: &NetworkConfig, instance: &str) -> Vec<String> {
    let cgroup = match cfg.allow_hosts.is_empty() {
        true => None,
        false => placeholder_cgroup(instance),
    };
    let Some(text) = network::ruleset(cfg, cgroup.as_ref()) else {
        return Vec::new();
    };
    under(
        "ruleset: ",
        text.lines().map(|l| l.replace('\t', "    ")).collect(),
    )
}

/// The cgroup an explanation writes the `allow-host` rules around: the
/// proxy leaf of the pair a run of this instance would create, with
/// bubbler's own pid — which a run that is not happening does not have —
/// left as `<pid>`.
///
/// bubbler's own cgroup is read where it can be, since that is what
/// decides the `level` the rule matches at and so what the block would
/// actually say; a host that will not answer gets a placeholder there
/// too, and the shape is still the shape. `None` only where neither
/// makes a path a rule could carry, and then the block is left out
/// rather than shown wrong.
fn placeholder_cgroup(instance: &str) -> Option<network::Cgroup> {
    let own = cgroup::own_path().unwrap_or_else(|_| "<own-cgroup>".to_owned());
    network::Cgroup::new(&cgroup::placeholder(&own, instance)).ok()
}

/// The egress proxy an `allow-host` is served by, as the launcher will
/// run it. `None` where the node names no name to reach.
///
/// The descriptor it reports readiness on is only known once the run has
/// made the pipe, so it is named here rather than numbered; the log
/// descriptor is bubbler's own stderr, always.
fn net_proxy_line(cfg: &NetworkConfig, log_tunnels: bool) -> Option<String> {
    if cfg.allow_hosts.is_empty() {
        return None;
    }
    let argv = network::net_proxy_argv(
        cfg,
        network::ProxyFds {
            ready: OsStr::new("<ready-fd>"),
            log: OsStr::new("2"),
        },
        log_tunnels,
    );
    let mut line = format!("    sidecar: {}", network::NET_PROXY_INSIDE);
    for a in &argv {
        line.push(' ');
        line.push_str(&a.to_string_lossy());
    }
    Some(line)
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

/// The Wayland proxy a bare `wayland` node is served by: which socket
/// the application connects to, which the proxy forwards to, and what it
/// does with a clipboard read. None of it is a bwrap argument of the
/// sandbox, so nothing else in this view would show it.
fn wl_sidecar_line(plan: &wayland::ProxyPlan) -> String {
    // The count is the denylist's length, not a measurement: how many of
    // those a compositor actually offers is only known once a client has
    // read the registry, which an explanation never does. It is shown
    // whether or not the compositor also took a security context: the
    // proxy applies PRIVILEGED either way, and `context` says only
    // whether the compositor withholds them as well — which is what the
    // last field reports, since one enforcer and two are not the same
    // sandbox.
    format!(
        "    sidecar: bubbler-wl-proxy listener {} → upstream {}, gate {}, \
         hides {} privileged globals, compositor enforces too: {}",
        plan.listener.display(),
        plan.upstream.display(),
        plan.gate(),
        wayland::PRIVILEGED.len(),
        match plan.context {
            true => "yes",
            false => "no",
        }
    )
}

/// Where the first of an instance's audio grants sits, which is the
/// group the one context they share is described under.
fn audio_node(services: &[Service]) -> Option<usize> {
    services
        .iter()
        .position(|s| matches!(s, Service::Pipewire { .. } | Service::Pulseaudio { .. }))
}

/// The `pw-container` an audio grant is served through, and what the
/// context it creates says about the sandbox. Neither is an argument of
/// the sandbox's own argv: the one bind names a socket, and everything
/// that makes it this instance's socket is on the other side of it.
///
/// The run id is only known once there is a run, so it is named here
/// rather than filled in, the way the sidecar descriptors of the other
/// grants are.
fn pw_context_lines(instance: &str, audio: AudioSet) -> [String; 2] {
    let properties = pipewire::properties(instance, pipewire::RUN_ID_SHOWN, audio);
    let mut sidecar = String::from("    sidecar:");
    for arg in pipewire::command(&properties) {
        sidecar.push(' ');
        sidecar.push_str(&arg.to_string_lossy());
    }
    [
        sidecar,
        format!(
            "    (context: {} {instance} {})",
            pipewire::ENGINE,
            pipewire::grant(audio)
        ),
    ]
}

/// The private PulseAudio server a `pulseaudio` grant is served by, and
/// what bubbler's own configuration of it withholds. It runs on the
/// context the group above describes; only the protocol its clients
/// speak is older.
fn pw_pulse_lines() -> [String; 2] {
    let mut sidecar = String::from("    sidecar:");
    for arg in pipewire::pulse_command() {
        sidecar.push(' ');
        sidecar.push_str(&arg.to_string_lossy());
    }
    [
        sidecar,
        "    (pulse: a private server on this run's context, module loading refused)".to_owned(),
    ]
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

/// `text` padded with spaces to `columns` on screen. `{:<n$}` counts
/// characters, which would put a label named in a wide script out of
/// line with the column beside it by its own width again.
fn pad(text: &str, columns: usize) -> String {
    let mut out = text.to_owned();
    out.push_str(&" ".repeat(columns.saturating_sub(text.width())));
    out
}

/// The view's title, then one block per node in emit order, then a
/// summary line.
pub fn render(items: &[Explained], view: &View) -> Result<Vec<String>, ConfigError> {
    let groups = groups(items, view)?;
    let width = |f: &dyn Fn(&Group) -> usize| groups.iter().map(f).max().unwrap_or(0);
    let lw = width(&|g| g.label.width());
    let sw = width(&|g| g.source.width());
    let mut out = vec![view.title.to_owned(), String::new()];
    let mut hidden = 0;
    for g in &groups {
        let n = g.len();
        let plural = if n == 1 { "argument" } else { "arguments" };
        let header = match sw {
            0 => format!("  {}  {n} {plural}", pad(&g.label, lw)),
            _ => format!(
                "  {}  {}  {n} {plural}",
                pad(&g.label, lw),
                pad(&g.source, sw)
            ),
        };
        let mut header = header.trim_end().to_owned();
        if let Origin::Service(i) = g.origin {
            match view.cfg.services.get(i) {
                Some(Service::Dri { kms: true }) => header.push_str(KMS_NOTE),
                Some(Service::Dri { kms: false }) if binds_a_primary_node(&g.items) => {
                    header.push_str(NVIDIA_NOTE);
                }
                // One context and one policy for the whole instance, so
                // the absent drop-in is said once, on the group that
                // describes the context — which is the node `lint`'s
                // `audio-policy-missing` names as well.
                Some(Service::Pipewire { .. } | Service::Pulseaudio { .. })
                    if audio_node(&view.cfg.services) == Some(i) =>
                {
                    header.push_str(view.audio_policy);
                }
                _ => {}
            }
        }
        out.push(header);
        // First line of the group rather than last: it is a fact about
        // the baseline, not one of the arguments the elision counts.
        if g.origin == Origin::Baseline {
            out.push(format!("    bwrap {}", view.bwrap.text()));
        }
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
                    // Checked before `carries_rules`: a `Portals` service
                    // matches both, and its children are a grant of their
                    // own on top of the bundle's rules.
                    Some(Service::Portals { children }) => {
                        out.extend(listed(n == 0, rules_of(i, view.rules)));
                        if !children.is_empty() {
                            out.extend(under(
                                "children: ",
                                children
                                    .iter()
                                    .map(|c| format!("{} — {}", c.node_name(), c.cost_line()))
                                    .collect(),
                            ));
                        }
                    }
                    Some(s) if carries_rules(s) => {
                        out.extend(listed(n == 0, rules_of(i, view.rules)));
                    }
                    // An isolated `network` is half a sidecar: its own
                    // arguments are only the resolver file, and what
                    // connects the namespace is the process below.
                    Some(Service::Network(cfg)) if cfg.is_isolated() => {
                        out.push(sidecar_line(cfg));
                        out.extend(net_proxy_line(cfg, view.net_proxy_log));
                        out.extend(ruleset_lines(cfg, view.instance));
                    }
                    // The one `--ro-bind` names the proxy's own socket
                    // whatever the compositor answered; only what the
                    // proxy connects to changes. No probe is run for an
                    // explanation, so the sidecar line below is what a
                    // run gets on a compositor that implements the
                    // protocol; one that does not says so on stderr and
                    // has the proxy dial the session's socket instead.
                    Some(Service::Wayland(WaylandMode::Sandboxed { .. })) => {
                        out.push(format!(
                            "    security-context: engine={} app={} instance={}",
                            wayland::ENGINE,
                            dbus::app_id(view.instance),
                            dbus::flatpak_instance_id(view.instance)
                        ));
                        out.extend(view.wl_proxy.map(wl_sidecar_line));
                    }
                    // One context serves both audio nodes, so it is
                    // described under the first of them; a second group
                    // saying the same would read as a second sidecar.
                    Some(s @ (Service::Pipewire { .. } | Service::Pulseaudio { .. })) => {
                        if audio_node(&view.cfg.services) == Some(i) {
                            out.extend(
                                view.cfg
                                    .audio()
                                    .map(|audio| pw_context_lines(view.instance, audio))
                                    .into_iter()
                                    .flatten(),
                            );
                        }
                        // The pulse server is one grant's own, however
                        // many grants share the context above it.
                        if matches!(s, Service::Pulseaudio { .. }) {
                            out.extend(pw_pulse_lines());
                        }
                    }
                    Some(Service::Wayland(WaylandMode::Host)) => {
                        out.push("    raw socket: wayland \"host\"".to_owned());
                    }
                    Some(Service::X11(X11Mode::Host)) => {
                        out.push("    raw socket: x11 \"host\"".to_owned());
                    }
                    // An optional share with no argument bound nothing: a
                    // required one would have refused the launch instead,
                    // so this is the one case zero arguments means a
                    // grant that a live run quietly does not act on.
                    Some(
                        s @ (Service::HomeShare { optional: true, .. }
                        | Service::PathShare { optional: true, .. }),
                    ) if n == 0 => {
                        out.push(format!(
                            "    {}  absent on this host, skipped",
                            kdl_out::service(s)?
                        ));
                    }
                    // The nested mode needs no line of its own: the argv
                    // it hands the supervisor is an argument above, and
                    // that one carries the explanation.
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
            Origin::Etc => ("etc", None),
            Origin::Tmp => ("tmp", None),
            Origin::Ctty => ("ctty", None),
            Origin::Identity => ("identity", None),
            Origin::Init => ("init", None),
            Origin::Command => ("command", None),
            Origin::Service(i) => ("service", Some(i)),
            Origin::Share(i) => ("share", Some(i)),
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
        out.push_str(&format!("\"kind\": {}", json::string(kind)));
        out.push_str(&format!(
            ", \"node\": {}",
            json::string(&label(item.origin, view.cfg)?)
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
            Some(note) => format!(", \"note\": {}", json::string(note)),
            None => ", \"note\": null".to_owned(),
        });
        out.push_str(if n + 1 == items.len() { "}\n" } else { "},\n" });
    }
    out.push(']');
    Ok(out)
}

/// [`json::string`] for an argument, which is not necessarily UTF-8.
fn quote_os(s: &OsStr) -> String {
    json::string(&s.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Clipboard, Share, ShareMode};
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
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
    bwrap 0.12.0
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
    rule-only: --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.FileChooser.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.OpenURI.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Notification.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Print.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Email.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Trash.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Account.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Inhibit.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.ProxyResolver.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.NetworkMonitor.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.MemoryMonitor.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.PowerProfileMonitor.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Realtime.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.GameMode.*@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Documents=*
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.FileChooser.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.OpenURI.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Notification.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Print.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Email.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Trash.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Account.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Inhibit.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.ProxyResolver.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.NetworkMonitor.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.MemoryMonitor.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.PowerProfileMonitor.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Realtime.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.GameMode.*@/org/freedesktop/portal/desktop
               --broadcast=org.freedesktop.portal.Documents=*
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*@/org/freedesktop/portal/desktop/request/*
               --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*@/org/freedesktop/portal/desktop/session/*
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*@/org/freedesktop/portal/desktop/request/*
               --broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*@/org/freedesktop/portal/desktop/session/*
               --call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.Get@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.GetAll@/org/freedesktop/portal/desktop
               --call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Introspectable.Introspect@/org/freedesktop/portal/desktop

  notify                          config.kdl:4  0 arguments
    rule-only: --talk=org.freedesktop.Notifications

  home-share \"Downloads\" mode=rw  config.kdl:5  3 arguments
    --bind /home/you/D /home/bubbler/D

  command                                       2 arguments
    -- true

27 arguments in 7 groups, 4 hidden (--explain=full); 40 D-Bus rules to the proxy (--proxy)";

    /// The host bind and the two synthetic files render as one group
    /// headed by the node that put them there, not folded into the
    /// baseline that would exist without it.
    #[test]
    fn an_etc_host_grant_groups_the_bind_and_the_synthetic_files_together() {
        let cfg = cfg("etc \"host\"\ncommand \"true\"");
        let lines = Lines::default();
        let items = [
            item(Origin::Etc, &["--ro-bind", "/etc", "/etc"], None),
            item(Origin::Etc, &["--ro-bind-data", "4", "/etc/passwd"], None),
            item(Origin::Etc, &["--ro-bind-data", "5", "/etc/group"], None),
            item(Origin::Command, &["--", "true"], None),
        ];
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        let at = out
            .iter()
            .position(|l| l.starts_with("  etc"))
            .unwrap_or_else(|| panic!("{out:#?}"));
        assert_eq!(out[at], "  etc \"host\"  9 arguments");
        assert_eq!(
            &out[at + 1..at + 4],
            [
                "    --ro-bind /etc /etc".to_owned(),
                "    --ro-bind-data 4 /etc/passwd".to_owned(),
                "    --ro-bind-data 5 /etc/group".to_owned(),
            ],
            "{out:#?}"
        );
    }

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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert!(
            out.contains(&"    raw socket: wayland \"host\"".to_owned()),
            "{out:#?}"
        );
    }

    /// The proxy in front of a sandboxed `wayland` is a process, not an
    /// argument, so it is a line of its own: which socket the
    /// application reaches, which the proxy forwards to, and what it
    /// does with a clipboard read.
    #[test]
    fn a_sandboxed_wayland_grant_names_the_proxy_in_front_of_it() {
        let dir = Path::new("/run/user/1000/bubbler/t");
        let session = PathBuf::from("/run/user/1000/wayland-1");
        for (plan, expected) in [
            (
                wayland::ProxyPlan::context(dir, Clipboard::Paste),
                "    sidecar: bubbler-wl-proxy listener \
                 /run/user/1000/bubbler/t/wayland → upstream /run/user/1000/bubbler/t/wayland-context, gate paste, hides 40 privileged globals, compositor enforces too: yes",
            ),
            (
                wayland::ProxyPlan::fallback(dir, session, Clipboard::Open),
                "    sidecar: bubbler-wl-proxy listener \
                 /run/user/1000/bubbler/t/wayland → upstream /run/user/1000/wayland-1, gate open, hides 40 privileged globals, compositor enforces too: no",
            ),
        ] {
            let cfg = cfg("wayland\ncommand \"true\"");
            let lines = Lines::default();
            let out = render(
                &[item(
                    Origin::Service(0),
                    &["--ro-bind", "/run/t/wayland", "/run/wayland-1"],
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
                    wl_proxy: Some(&plan),
                    audio_policy: "",
                    net_proxy_log: false,
                    proxy: false,
                    full: false,
                    bwrap: crate::version::Version::Known(0, 12, 0),
                },
            )
            .unwrap();
            assert!(out.contains(&expected.to_owned()), "{out:#?}");
            // Beneath the identity the compositor is given, which is the
            // other half of what the one bind does not show.
            let at = |needle: &str| out.iter().position(|l| l.starts_with(needle));
            assert!(at("    security-context:") < at("    sidecar:"), "{out:#?}");
        }
    }

    /// One bind shows a path and nothing else: which daemon is behind
    /// it, and what the sandbox may do there, are the context's — and
    /// the context is a process, not an argument.
    #[test]
    fn an_audio_grant_names_the_context_it_is_served_through() {
        for (kdl, grant) in [
            ("pipewire\ncommand \"true\"", "playback"),
            (
                "pulseaudio {\n    microphone\n}\ncommand \"true\"",
                "playback,microphone",
            ),
        ] {
            let cfg = cfg(kdl);
            let lines = Lines::default();
            let out = render(
                &[item(
                    Origin::Service(0),
                    &[
                        "--ro-bind",
                        "/run/user/1000/bubbler/t/pw/pipewire-0",
                        "/run/user/1000/pipewire-0",
                    ],
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
                    wl_proxy: None,
                    audio_policy: "",
                    net_proxy_log: false,
                    proxy: false,
                    full: false,
                    bwrap: crate::version::Version::Known(0, 12, 0),
                },
            )
            .unwrap();
            assert!(
                out.contains(&format!("    (context: org.bubbler t {grant})")),
                "{out:#?}"
            );
            assert!(
                out.contains(&format!(
                    "    sidecar: /usr/bin/pw-container -P \
                     {{\"pipewire.sec.engine\":\"org.bubbler\",\
                     \"pipewire.sec.app-id\":\"t\",\
                     \"pipewire.sec.instance-id\":\"<run id>\",\
                     \"pipewire.access\":\"restricted\",\
                     \"bubbler.audio\":\"{grant}\"}} -- /run/bubbler-pw-hold"
                )),
                "{out:#?}"
            );
        }
    }

    /// The pulse grant is served by a server of its own on the one
    /// context both grants share, so its group names that server and the
    /// context line stays where the first grant is.
    #[test]
    fn the_pulse_group_names_the_server_it_is_served_by() {
        let cfg = cfg("pipewire\npulseaudio\ncommand \"true\"");
        let lines = Lines::default();
        let out = render(
            &[
                item(
                    Origin::Service(0),
                    &[
                        "--ro-bind",
                        "/run/user/1000/bubbler/t/pipewire-0",
                        "/run/user/1000/pipewire-0",
                    ],
                    None,
                ),
                item(
                    Origin::Service(1),
                    &[
                        "--ro-bind",
                        "/run/user/1000/bubbler/t/pw/pulse/native",
                        "/run/user/1000/pulse/native",
                    ],
                    None,
                ),
            ],
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        let count = |needle: &str| out.iter().filter(|l| l.contains(needle)).count();
        let at = |needle: &str| {
            out.iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} is missing from {out:#?}"))
        };
        // One context for the instance, described under the first of its
        // grants; the pulse server is the pulse group's own.
        assert_eq!(count("(context: org.bubbler t playback)"), 1, "{out:#?}");
        assert!(at("(context:") < at("  pulseaudio"), "{out:#?}");
        assert_eq!(
            count("sidecar: /usr/bin/pipewire -c pipewire-pulse.conf"),
            1,
            "{out:#?}"
        );
        assert!(
            at("  pulseaudio") < at("sidecar: /usr/bin/pipewire"),
            "{out:#?}"
        );
        assert_eq!(
            count("(pulse: a private server on this run's context, module loading refused)"),
            1,
            "{out:#?}"
        );
    }

    /// Where an absent policy drop-in is said: on the header of the one
    /// group that describes the context, not on every audio node's.
    #[test]
    fn a_missing_audio_policy_ends_the_header_of_the_group_the_context_is_under() {
        let cfg = cfg("pipewire\npulseaudio\ncommand \"true\"");
        let lines = Lines::default();
        let headers = |suffix: &'static str| {
            let out = render(
                &[
                    item(
                        Origin::Service(0),
                        &["--ro-bind", "/run/t/pw", "/run/pw"],
                        None,
                    ),
                    item(
                        Origin::Service(1),
                        &["--ro-bind", "/run/t/pa", "/run/pa"],
                        None,
                    ),
                ],
                &View {
                    title: "bwrap",
                    instance: "t",
                    cfg: &cfg,
                    source: Source {
                        file: "config.kdl",
                        lines: &lines,
                    },
                    rules: &[],
                    wl_proxy: None,
                    audio_policy: suffix,
                    net_proxy_log: false,
                    proxy: false,
                    full: false,
                    bwrap: crate::version::Version::Known(0, 12, 0),
                },
            )
            .unwrap();
            out.into_iter()
                .filter(|l| l.starts_with("  pipewire") || l.starts_with("  pulseaudio"))
                .collect::<Vec<_>>()
        };
        let absent = headers(crate::audio_policy::EXPLAIN_SUFFIX);
        assert!(
            absent[0].ends_with(crate::audio_policy::EXPLAIN_SUFFIX),
            "{absent:?}"
        );
        assert!(
            !absent[1].ends_with(crate::audio_policy::EXPLAIN_SUFFIX),
            "{absent:?}"
        );
        assert!(
            headers("").iter().all(|h| !h.contains("policy drop-in")),
            "an installed drop-in says nothing"
        );
    }

    /// What `dri kms=#true` costs is not in its arguments: the card
    /// nodes are two `--dev-bind`s like the render nodes, and the sysfs
    /// the bare node masks is simply not masked.
    #[test]
    fn a_dri_group_says_what_kms_costs() {
        let lines = Lines::default();
        let head = |kdl: &str| {
            let cfg = cfg(kdl);
            let out = render(
                &[item(
                    Origin::Service(0),
                    &["--dev-bind", "/dev/dri/renderD128", "/dev/dri/renderD128"],
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
                    wl_proxy: None,
                    audio_policy: "",
                    net_proxy_log: false,
                    proxy: false,
                    full: false,
                    bwrap: crate::version::Version::Known(0, 12, 0),
                },
            )
            .unwrap();
            out.iter()
                .find(|l| l.starts_with("  dri"))
                .cloned()
                .unwrap_or_else(|| panic!("{out:#?}"))
        };
        assert_eq!(head("dri\ncommand \"true\""), "  dri  3 arguments");
        assert_eq!(
            head("dri kms=#true\ncommand \"true\""),
            "  dri kms=#true  3 arguments (kms: card nodes, EDID and framebuffer geometry \
             readable)"
        );
    }

    /// The bare node binds a primary node of its own where the GPU is on
    /// the proprietary NVIDIA driver, and the group carries a note of
    /// its own for what that node reads, distinct from `kms`'s.
    #[test]
    fn a_dri_group_says_when_a_primary_node_came_with_the_bare_node() {
        let cfg = cfg("dri\ncommand \"true\"");
        let lines = Lines::default();
        let out = render(
            &[
                item(
                    Origin::Service(0),
                    &["--dev-bind", "/dev/dri/renderD128", "/dev/dri/renderD128"],
                    None,
                ),
                item(
                    Origin::Service(0),
                    &["--dev-bind", "/dev/dri/card1", "/dev/dri/card1"],
                    None,
                ),
            ],
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert_eq!(
            out.iter().find(|l| l.starts_with("  dri")),
            Some(
                &"  dri  6 arguments (nvidia: primary node bound for its EGL — connectors, \
                  their modes, the monitors' EDID readable)"
                    .to_owned()
            ),
            "{out:#?}"
        );
    }

    /// Which X server an `x11` grant runs is not in its arguments
    /// either: the nested one is a display variable plus the argv the
    /// supervisor starts on the first X connection, with the window
    /// manager beside it, and the notes are what say so.
    #[test]
    fn an_x11_grant_shows_the_server_it_runs() {
        let nested = cfg("wayland\ndri\nx11\ncommand \"true\"");
        let lines = Lines::default();
        let render_with = |cfg: &InstanceConfig, items: &[Explained]| {
            render(
                items,
                &View {
                    title: "bwrap",
                    instance: "t",
                    cfg,
                    source: Source {
                        file: "config.kdl",
                        lines: &lines,
                    },
                    rules: &[],
                    wl_proxy: None,
                    audio_policy: "",
                    net_proxy_log: false,
                    proxy: false,
                    full: false,
                    bwrap: crate::version::Version::Known(0, 12, 0),
                },
            )
            .unwrap()
        };
        let out = render_with(
            &nested,
            &[
                item(Origin::Service(2), &["--setenv", "DISPLAY", ":0"], None),
                item(
                    Origin::Service(2),
                    &["--x11", "/usr/bin/Xwayland", ":0", "--"],
                    Some(
                        "nested Xwayland, started by bubbler-init on the first X connection; \
                         -listenfd is added at run time",
                    ),
                ),
                item(
                    Origin::Service(2),
                    &["--wm", "openbox"],
                    Some("window manager inside the sandbox, started with the server"),
                ),
            ],
        );
        let at = out
            .iter()
            .position(|l| l.starts_with("  x11 "))
            .unwrap_or_else(|| panic!("{out:#?}"));
        assert_eq!(
            &out[at + 1..at + 4],
            [
                "    --setenv DISPLAY :0".to_owned(),
                "    --x11 /usr/bin/Xwayland :0 --  (nested Xwayland, started by bubbler-init \
                 on the first X connection; -listenfd is added at run time)"
                    .to_owned(),
                "    --wm openbox  (window manager inside the sandbox, started with the server)"
                    .to_owned(),
            ],
            "{out:#?}"
        );
        let host = cfg("x11 \"host\"\ncommand \"true\"");
        let out = render_with(
            &host,
            &[item(
                Origin::Service(0),
                &["--ro-bind", "/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0"],
                None,
            )],
        );
        assert!(
            out.contains(&"    raw socket: x11 \"host\"".to_owned()),
            "{out:#?}"
        );
    }

    /// Neither node puts an argument in the argv, so without the rules
    /// beneath them both would render as grants that reached nothing.
    #[test]
    fn the_a11y_and_input_method_grants_show_the_rules_they_are() {
        let cfg = cfg("dbus\na11y\ninput-method\ncommand \"true\"");
        let lines = Lines {
            services: vec![Some(1), Some(2), Some(3)],
            ..Lines::default()
        };
        let rules = rules(&cfg, "t");
        let out = render(
            &[
                item(
                    Origin::Service(1),
                    &["--ro-bind", "/run/t/a11y", "/run/at-spi/bus"],
                    None,
                ),
                item(
                    Origin::Service(1),
                    &[
                        "--setenv",
                        "AT_SPI_BUS_ADDRESS",
                        "unix:path=/run/at-spi/bus",
                    ],
                    None,
                ),
                item(
                    Origin::Service(2),
                    &["--setenv", "IBUS_USE_PORTAL", "1"],
                    None,
                ),
                item(Origin::Command, &["--", "true"], None),
            ],
            &View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &rules,
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        // The bind and the variable are what the argv shows of either
        // grant; the rules under them are the rest of what they are.
        // The accessibility rules are the `a11y` node's, and none of
        // them is on the session bus.
        assert!(
            out.iter().any(|l| l
                .contains("rules: --call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Embed@")),
            "{out:#?}"
        );
        let a11y = out
            .iter()
            .filter(|l| l.contains("org.a11y.atspi.Registry"))
            .count();
        assert_eq!(a11y, dbus::A11Y_RULES.len(), "{out:#?}");
        assert!(
            out.iter()
                .any(|l| l.contains("rules: --talk=org.freedesktop.portal.Fcitx")),
            "{out:#?}"
        );
        assert!(
            out.iter()
                .any(|l| l.trim() == "--talk=org.freedesktop.portal.IBus"),
            "{out:#?}"
        );
    }

    /// Every child is one line under the `portals` group, so a reader
    /// sees what the block granted without counting proxy rules.
    #[test]
    fn the_portals_group_lists_its_children() {
        let with_children = cfg("dbus\nportals {\n    screencast\n    location\n}");
        let items = [item(Origin::Service(1), &[], None)];
        let view = View {
            title: "bwrap",
            instance: "t",
            cfg: &with_children,
            source: Source {
                file: "config.kdl",
                lines: &Lines::default(),
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: false,
            full: false,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = render(&items, &view).unwrap();
        assert!(
            out.iter().any(|l| l
                == "    children: screencast — capture the screen after a portal dialog"),
            "{out:#?}"
        );
        assert!(
            out.iter()
                .any(|l| l.trim() == "location — read the host's location"),
            "{out:#?}"
        );
        // A bare node lists nothing.
        let bare = cfg("dbus\nportals");
        let view = View { cfg: &bare, ..view };
        let out = render(&items, &view).unwrap();
        assert!(!out.iter().any(|l| l.contains("children:")), "{out:#?}");
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
                    wl_proxy: None,
                    audio_policy: "",
                    net_proxy_log: false,
                    proxy: false,
                    full: false,
                    bwrap: crate::version::Version::Known(0, 12, 0),
                },
            )
            .unwrap()
        };
        // The bare grant is the whole of what the node did, and without
        // the line it would render as a grant that reached nothing.
        let camera = dbus::camera_rules();
        let out = render_with(&[item(Origin::Command, &["--", "true"], None)]);
        assert!(
            out.contains(&format!("    rule-only: {}", camera[0])),
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert!(
            out.contains(&format!("    rules: {}", camera[0])),
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: true,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert!(
            !out.iter().any(|l| l.contains("more (--explain=full)")),
            "{out:?}"
        );
        assert_eq!(out.last().unwrap(), "13 arguments in 1 group");
        assert_eq!(out[2], "  baseline  13 arguments");
        assert_eq!(out[3], "    bwrap 0.12.0");
        assert_eq!(out.len(), 4 + baseline().len() + 2);
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
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
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: true,
            full: true,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = render(&items, &view).unwrap();
        assert!(!out.iter().any(|l| l.contains("wayland")), "{out:?}");
        // The rule is the argument, not a line under a zero-argument group.
        assert!(!out.iter().any(|l| l.contains("rule-only")), "{out:?}");
        assert_eq!(out[9], "  notify    config.kdl:3  1 argument");
        assert_eq!(out[10], "    --talk=org.freedesktop.Notifications");
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert_eq!(out[6], "  seccomp   config.kdl:2  0 arguments");
        assert_eq!(out[7], "    rule-only: filter disabled");
        assert_eq!(out[9], "  wayland   config.kdl:1  3 arguments");
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
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
                optional: false,
            }],
            ..InstanceConfig::default()
        };
        let text = label(Origin::Service(0), &cfg).unwrap();
        assert_eq!(text.chars().count(), LABEL_MAX);
        assert!(text.starts_with("path-share \"/srv/xxx"), "{text}");
        // The cut is inside the path, so the mode is still on the line:
        // a group header that dropped it would hide how wide the bind is.
        assert!(text.ends_with("…\" mode=ro"), "{text}");
    }

    /// The header of the node that motivated the rule: an application id
    /// long enough that the whole line does not fit the column.
    #[test]
    fn a_long_app_runtime_keeps_its_mode_in_the_header() {
        let cfg = InstanceConfig {
            services: vec![Service::AppRuntime {
                id: "org.keepassxc.KeePassXC".to_owned(),
                mode: ShareMode::ReadOnly,
            }],
            ..InstanceConfig::default()
        };
        assert_eq!(
            label(Origin::Service(0), &cfg).unwrap(),
            r#"app-runtime "org.keepassxc.Kee…" mode=ro"#
        );
    }

    /// A per-run share is its own group, named by the flag that made it
    /// and naming no line: the file it would be in never had the node.
    #[test]
    fn a_share_is_a_group_of_its_own_with_no_line_to_name() {
        let cfg = InstanceConfig {
            shares: vec![Share {
                path: PathBuf::from("/srv/src"),
                mode: ShareMode::ReadWrite,
            }],
            ..InstanceConfig::default()
        };
        let items = [item(
            Origin::Share(0),
            &["--bind", "/srv/src", "/srv/src"],
            None,
        )];
        let view = View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: Source {
                file: "config.kdl",
                lines: &Lines::default(),
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: false,
            full: false,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = render(&items, &view).unwrap();
        assert_eq!(
            out[2], r#"  --share "/srv/src" mode=rw  3 arguments"#,
            "{out:?}"
        );
        let json = render_json(&items, &view).unwrap();
        assert!(
            json.contains(
                r#""kind": "share", "node": "--share \"/srv/src\" mode=rw", "index": 0, "line": null"#
            ),
            "{json}"
        );
    }

    /// An optional share whose source is absent binds nothing, so its
    /// group has no arguments; the skip is the only thing left to say
    /// about it.
    #[test]
    fn an_absent_optional_home_share_is_reported_skipped() {
        let cfg = InstanceConfig {
            services: vec![Service::HomeShare {
                path: PathBuf::from("Downloads"),
                mode: ShareMode::ReadOnly,
                optional: true,
            }],
            ..InstanceConfig::default()
        };
        let view = View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: Source {
                file: "config.kdl",
                lines: &Lines::default(),
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: false,
            full: false,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = render(&[], &view).unwrap();
        assert!(
            out.contains(
                &"    home-share \"Downloads\" mode=ro optional=#true  \
                  absent on this host, skipped"
                    .to_owned()
            ),
            "{out:?}"
        );
    }

    /// The same skip line, for the other share kind.
    #[test]
    fn an_absent_optional_path_share_is_reported_skipped() {
        let cfg = InstanceConfig {
            services: vec![Service::PathShare {
                path: PathBuf::from("/opt/tool"),
                mode: ShareMode::ReadOnly,
                optional: true,
            }],
            ..InstanceConfig::default()
        };
        let view = View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: Source {
                file: "config.kdl",
                lines: &Lines::default(),
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: false,
            full: false,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = render(&[], &view).unwrap();
        assert!(
            out.contains(
                &"    path-share \"/opt/tool\" mode=ro optional=#true  \
                  absent on this host, skipped"
                    .to_owned()
            ),
            "{out:?}"
        );
    }

    /// A present optional share binds exactly as a required one would,
    /// and the skip line belongs to the one it does not bind: a group
    /// with an argument is never the one `n == 0` matches.
    #[test]
    fn a_present_optional_home_share_binds_normally_and_is_not_reported_skipped() {
        let cfg = InstanceConfig {
            services: vec![Service::HomeShare {
                path: PathBuf::from("Downloads"),
                mode: ShareMode::ReadOnly,
                optional: true,
            }],
            ..InstanceConfig::default()
        };
        let items = [item(
            Origin::Service(0),
            &[
                "--ro-bind",
                "/home/user/Downloads",
                "/home/bubbler/Downloads",
            ],
            None,
        )];
        let view = View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: Source {
                file: "config.kdl",
                lines: &Lines::default(),
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: false,
            full: false,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = render(&items, &view).unwrap();
        assert!(
            out.contains(&"    --ro-bind /home/user/Downloads /home/bubbler/Downloads".to_owned()),
            "{out:?}"
        );
        assert!(!out.iter().any(|l| l.contains("skipped")), "{out:?}");
    }

    /// A share that is not optional gets no such line even with no
    /// arguments: the group being empty here only means the test built
    /// no `Explained` item for it, never that a live launch would have
    /// skipped a required source silently.
    #[test]
    fn a_required_share_with_no_items_says_nothing_about_being_skipped() {
        let cfg = InstanceConfig {
            services: vec![Service::HomeShare {
                path: PathBuf::from("Downloads"),
                mode: ShareMode::ReadOnly,
                optional: false,
            }],
            ..InstanceConfig::default()
        };
        let view = View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: Source {
                file: "config.kdl",
                lines: &Lines::default(),
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: false,
            full: false,
            bwrap: crate::version::Version::Known(0, 12, 0),
        };
        let out = render(&[], &view).unwrap();
        assert!(!out.iter().any(|l| l.contains("skipped")), "{out:?}");
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
                wl_proxy: None,
                audio_policy: "",
                net_proxy_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
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
    fn an_argument_that_is_not_utf8_is_quoted_lossily() {
        assert_eq!(
            quote_os(OsStr::from_bytes(b"/tmp/\xff")),
            "\"/tmp/\u{fffd}\""
        );
        assert_eq!(
            quote_os(OsStr::from_bytes(b"/tmp/\x1b[2J")),
            "\"/tmp/\\u001b[2J\""
        );
    }

    /// The baseline group opens with the bwrap the run would use: which
    /// arguments bwrap gets is only half of what a sandbox is, and the
    /// other half is which bwrap reads them.
    #[test]
    fn the_baseline_group_names_the_bwrap_version() {
        let cfg = InstanceConfig::default();
        let lines = Lines::default();
        let items = vec![
            item(Origin::Baseline, &["--unshare-all"], None),
            item(Origin::Command, &["--", "true"], None),
        ];
        let view = |bwrap| View {
            title: "bwrap",
            instance: "t",
            cfg: &cfg,
            source: Source {
                file: "config.kdl",
                lines: &lines,
            },
            rules: &[],
            wl_proxy: None,
            audio_policy: "",
            net_proxy_log: false,
            proxy: false,
            full: false,
            bwrap,
        };
        let out = render(&items, &view(crate::version::Version::Known(0, 12, 0))).unwrap();
        let at = out
            .iter()
            .position(|l| l.starts_with("  baseline"))
            .unwrap();
        assert_eq!(out[at + 1], "    bwrap 0.12.0", "{out:?}");

        let out = render(&items, &view(crate::version::Version::Unknown)).unwrap();
        let at = out
            .iter()
            .position(|l| l.starts_with("  baseline"))
            .unwrap();
        assert_eq!(out[at + 1], "    bwrap unknown", "{out:?}");
    }
}
