//! Static checks over a profile or an instance config: what the file
//! grants, measured against what a sandbox is meant to give away.
//!
//! Findings are read off each layer's KDL rather than the flattened
//! result, so every one of them names the file and line that has to
//! change. Errors say the file will not do what it says; warnings say it
//! grants more than it probably means to and can be accepted with a
//! `lint-allow` node; notes are for information and fail nothing.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use kdl::{KdlDocument, KdlNode};

use crate::config;
use crate::env::Env;
use crate::error::LintError;
use crate::host::Host;
use crate::profile::Resolver;
use crate::service;

/// How much a finding weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The file will not do what it says. Never suppressible.
    Error,
    /// Defensible, but the file should say so on purpose.
    Warning,
    /// Information only.
    Note,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
        })
    }
}

/// One check the linter runs, named by a stable id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    /// Kebab-case identifier, as `lint-allow` and `--format json` name it.
    pub id: &'static str,
    /// What a finding of this check weighs.
    pub severity: Severity,
}

/// Each check as a constant the code that reports it names, so a
/// finding cannot carry an id no table holds.
const BUNDLE_WITHOUT_DBUS: Check = Check {
    id: "bundle-without-dbus",
    severity: Severity::Error,
};
const CAMERA_NODES_NONE_PRESENT: Check = Check {
    id: "camera-nodes-none-present",
    severity: Severity::Note,
};
const CAMERA_NODES_NO_HOTPLUG: Check = Check {
    id: "camera-nodes-no-hotplug",
    severity: Severity::Note,
};
const CAMERA_WITHOUT_PORTALS: Check = Check {
    id: "camera-without-portals",
    severity: Severity::Error,
};
const COMMAND_NOT_FOUND: Check = Check {
    id: "command-not-found",
    severity: Severity::Note,
};
const DBUS_WITHOUT_RULES: Check = Check {
    id: "dbus-without-rules",
    severity: Severity::Warning,
};
const DUP_NAME_POLICY: Check = Check {
    id: "dup-name-policy",
    severity: Severity::Error,
};
const ENV_LOOKS_SECRET: Check = Check {
    id: "env-looks-secret",
    severity: Severity::Warning,
};
const HOME_SHARE_SENSITIVE: Check = Check {
    id: "home-share-sensitive",
    severity: Severity::Warning,
};
const LINT_ALLOW_UNUSED: Check = Check {
    id: "lint-allow-unused",
    severity: Severity::Note,
};
const MPRIS_WILDCARD: Check = Check {
    id: "mpris-wildcard",
    severity: Severity::Warning,
};
const OWN_ON_SYSTEM_BUS: Check = Check {
    id: "own-on-system-bus",
    severity: Severity::Error,
};
const OWN_TOO_WIDE: Check = Check {
    id: "own-too-wide",
    severity: Severity::Warning,
};
const OZONE_HINT_UNNECESSARY: Check = Check {
    id: "ozone-hint-unnecessary",
    severity: Severity::Note,
};
const PATH_SHARE_MOUNTPOINT: Check = Check {
    id: "path-share-mountpoint",
    severity: Severity::Warning,
};
const PATH_SHARE_RESERVED: Check = Check {
    id: "path-share-reserved",
    severity: Severity::Error,
};
const PATH_SHARE_SOCKET: Check = Check {
    id: "path-share-socket",
    severity: Severity::Warning,
};
const PORTAL_TALK_WITHOUT_PORTALS: Check = Check {
    id: "portal-talk-without-portals",
    severity: Severity::Warning,
};
const SECCOMP_DISABLED: Check = Check {
    id: "seccomp-disabled",
    severity: Severity::Warning,
};
const SECRETS_ACCESS: Check = Check {
    id: "secrets-access",
    severity: Severity::Note,
};
const SHARE_SOURCE_MISSING: Check = Check {
    id: "share-source-missing",
    severity: Severity::Error,
};
const SYSTEM_BUS_POLKIT_NAME: Check = Check {
    id: "system-bus-polkit-name",
    severity: Severity::Warning,
};
const TTY_PASSTHROUGH: Check = Check {
    id: "tty-passthrough",
    severity: Severity::Warning,
};
const USERNS_DISABLED_WITH_NESTED_SANDBOX: Check = Check {
    id: "userns-disabled-with-nested-sandbox",
    severity: Severity::Warning,
};
const X11_WITHOUT_REASON: Check = Check {
    id: "x11-without-reason",
    severity: Severity::Warning,
};

/// Every check, sorted by id. `lint-allow` resolves its argument here,
/// so a check taken out of this table makes the profiles naming it
/// errors rather than silently accepting nothing.
pub const CHECKS: &[Check] = &[
    BUNDLE_WITHOUT_DBUS,
    CAMERA_NODES_NONE_PRESENT,
    CAMERA_NODES_NO_HOTPLUG,
    CAMERA_WITHOUT_PORTALS,
    COMMAND_NOT_FOUND,
    DBUS_WITHOUT_RULES,
    DUP_NAME_POLICY,
    ENV_LOOKS_SECRET,
    HOME_SHARE_SENSITIVE,
    LINT_ALLOW_UNUSED,
    MPRIS_WILDCARD,
    OWN_ON_SYSTEM_BUS,
    OWN_TOO_WIDE,
    OZONE_HINT_UNNECESSARY,
    PATH_SHARE_MOUNTPOINT,
    PATH_SHARE_RESERVED,
    PATH_SHARE_SOCKET,
    PORTAL_TALK_WITHOUT_PORTALS,
    SECCOMP_DISABLED,
    SECRETS_ACCESS,
    SHARE_SOURCE_MISSING,
    SYSTEM_BUS_POLKIT_NAME,
    TTY_PASSTHROUGH,
    USERNS_DISABLED_WITH_NESTED_SANDBOX,
    X11_WITHOUT_REASON,
];

/// The check `id` names, if it is one.
pub fn check(id: &str) -> Option<&'static Check> {
    CHECKS.iter().find(|c| c.id == id)
}

/// Where a finding was written: a file, or a profile compiled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Where {
    /// A profile or `config.kdl` on disk.
    File(PathBuf),
    /// A built-in profile, which has no path to name.
    BuiltIn(String),
}

impl Where {
    /// How a finding line starts: the path, or `built-in:<name>`. Not a
    /// `String`, because a profile path need not be UTF-8.
    pub fn label(&self) -> OsString {
        match self {
            Self::File(p) => p.clone().into_os_string(),
            Self::BuiltIn(name) => OsString::from(format!("built-in:{name}")),
        }
    }
}

/// One thing a check found, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The layer that holds the node.
    pub at: Where,
    /// 1-based line of the node, absent for a built-in layer.
    pub line: Option<u32>,
    /// 1-based column of the node, absent for a built-in layer.
    pub col: Option<u32>,
    /// What the finding weighs.
    pub severity: Severity,
    /// Id of the check that reported it.
    pub id: &'static str,
    /// What is wrong, in one sentence.
    pub message: String,
    /// What to do about it. Every check carries one: a finding a reader
    /// cannot act on is one they route around.
    pub help: String,
}

/// The result of one lint run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// Findings in layer order, then file order within a layer.
    pub findings: Vec<Finding>,
    /// The layers that were read, in the order they were read.
    pub layers: Vec<Where>,
}

impl Report {
    /// How many findings of `severity` the run reported.
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Fold another report into this one, as `profile lint --all` does.
    /// Two profiles that `include` one base read that base twice, so both
    /// the layer and anything found in it are counted once.
    pub fn absorb(&mut self, other: Report) {
        for layer in other.layers {
            if !self.layers.contains(&layer) {
                self.layers.push(layer);
            }
        }
        for finding in other.findings {
            let seen = self.findings.iter().any(|f| {
                (&f.at, f.line, f.col, f.id) == (&finding.at, finding.line, finding.col, finding.id)
            });
            if !seen {
                self.findings.push(finding);
            }
        }
    }
}

/// What the checks need besides the file: the host tree they probe, the
/// home a `home-share` is relative to, and the directories a `command` is
/// looked for in.
pub struct Context<'a> {
    /// Host-side facts, for `$HOME` and the reserved `path-share` roots.
    pub env: &'a Env,
    /// Filesystem the share and socket checks probe.
    pub host: &'a dyn Host,
    /// `$PATH` split into directories, for `command-not-found`.
    pub search_path: &'a [PathBuf],
}

/// Commands known to start a sandbox of their own inside this one, which
/// takes a user namespace. A heuristic list, and the message says so.
const NESTERS: &[&str] = &[
    "chromium",
    "chrome",
    "code",
    "codium",
    "vesktop",
    "discord",
    "steam",
    "lutris",
    "firefox",
    "thunderbird",
    "obsidian",
    "signal-desktop",
];

/// Home directories the private home exists to keep out, together with
/// everything under them: one key file out of `.ssh` is the key. firejail
/// blacklists the same set for every profile it ships.
const SENSITIVE_TREE: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".pki",
    ".password-store",
    ".local/share/keyrings",
    ".mozilla",
];

/// Home directories that are sensitive whole and not one subdirectory at
/// a time: they hold every application's state, and an application's own
/// share of its own directory under them is what a profile is for.
const SENSITIVE_ROOT: &[&str] = &[".config", ".local", ".local/share", ".cache"];

/// System-bus names whose interesting methods are behind an `auth_admin`
/// polkit action, which polkit judges against the proxy's credentials —
/// that is, against the user.
const POLKIT_NAMES: &[&str] = &[
    "org.freedesktop.UDisks2",
    "org.freedesktop.NetworkManager",
    "org.freedesktop.systemd1",
    "org.freedesktop.PackageKit",
    "org.freedesktop.login1",
    "org.freedesktop.hostname1",
    "org.freedesktop.timedate1",
];

/// Underscore-separated words that make an environment variable name
/// look like a credential. Whole segments, not substrings: `GITHUB_TOKEN`
/// is one and `TOKENIZERS_PARALLELISM` is not.
const SECRET_SEGMENTS: &[&str] = &[
    "TOKEN",
    "TOKENS",
    "SECRET",
    "SECRETS",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "CREDENTIAL",
    "CREDENTIALS",
    "PAT",
];

/// Pairs of segments that mean the same as one of [`SECRET_SEGMENTS`].
const SECRET_PAIRS: &[[&str; 2]] = &[["API", "KEY"], ["ACCESS", "KEY"], ["SECRET", "KEY"]];

/// Prefixes of credentials that are recognisable on sight.
const SECRET_VALUES: &[&str] = &["ghp_", "sk-", "AKIA"];

/// The Secret Service name: one session-bus name for every secret the
/// login keyring holds, with no partitioning between applications.
const SECRETS_NAME: &str = "org.freedesktop.secrets";

/// The prefix every XDG desktop portal name starts with.
const PORTAL_PREFIX: &str = "org.freedesktop.portal.";

/// The bundle nodes, which are sets of proxy rules and nothing else.
const BUNDLES: &[&str] = &["portals", "notify", "tray", "mpris"];

/// Checks that name exactly what the parser or the resolver refuses. A
/// report whose errors are all from this set has already said why the
/// config does not parse, so the run is a verdict; anything else leaves
/// the parse failure unexplained and the run has to report that instead.
const PARSER_EQUIVALENT: &[&str] = &[
    BUNDLE_WITHOUT_DBUS.id,
    CAMERA_WITHOUT_PORTALS.id,
    DUP_NAME_POLICY.id,
    OWN_ON_SYSTEM_BUS.id,
];

/// Whether the report's errors, taken together, say why the config would
/// not parse. No errors at all explain nothing.
fn explains_a_parse_failure(report: &Report) -> bool {
    let mut errors = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .peekable();
    errors.peek().is_some() && errors.all(|f| PARSER_EQUIVALENT.contains(&f.id))
}

/// Lint one profile, resolved through its layers and `include`s.
///
/// A finding is reported against the layer that wrote the node. The
/// flattened profile is resolved too, so a layer that does not parse and
/// no check explains is a failed run rather than a clean report.
pub fn lint_profile(ctx: &Context, resolver: &Resolver, name: &str) -> Result<Report, LintError> {
    let layers = resolver.layers(name)?;
    let mut sources = Vec::with_capacity(layers.len());
    for layer in layers {
        let at = match &layer.path {
            Some(p) => Where::File(p.clone()),
            None => Where::BuiltIn(layer.name.clone()),
        };
        sources.push(Source::read(at, layer.text)?);
    }
    let report = run(ctx, &sources);
    if !explains_a_parse_failure(&report) {
        resolver.resolve(name)?;
    }
    Ok(report)
}

/// Lint one `config.kdl`, which has a single layer and no `include`s.
pub fn lint_config(ctx: &Context, path: &Path) -> Result<Report, LintError> {
    let text = fs::read_to_string(path).map_err(|e| LintError::Io(path.to_path_buf(), e))?;
    lint_text(ctx, Where::File(path.to_path_buf()), text)
}

/// Lint one config already in hand. A file the parser rejects is a failed
/// run rather than a clean report, unless a check already said what is
/// wrong with it — `own` on the system bus is refused by both.
fn lint_text(ctx: &Context, at: Where, text: String) -> Result<Report, LintError> {
    let source = Source::read(at, text)?;
    let report = run(ctx, std::slice::from_ref(&source));
    if !explains_a_parse_failure(&report) {
        config::parse(&source.text)?;
    }
    Ok(report)
}

/// Exit code for a report: 0 clean, 1 warnings, 2 errors. `deny_warnings`
/// turns 1 into 2, which is what a CI job asks for. A run that could not
/// be made at all is 3, and that is the caller's `LintError`.
pub fn exit_code(report: &Report, deny_warnings: bool) -> i32 {
    if report.count(Severity::Error) > 0 {
        return 2;
    }
    if report.count(Severity::Warning) > 0 {
        return if deny_warnings { 2 } else { 1 };
    }
    0
}

/// One finding as the lines it prints: the finding itself and its help.
/// `OsString` because a layer is named by its path.
pub fn render_finding(f: &Finding) -> Vec<OsString> {
    let mut line = f.at.label();
    if let (Some(l), Some(c)) = (f.line, f.col) {
        line.push(format!(":{l}:{c}"));
    }
    line.push(format!(": {}[{}]: {}", f.severity, f.id, f.message));
    vec![line, OsString::from(format!("  help: {}", f.help))]
}

/// The whole text report: every finding, then a blank line and a summary.
pub fn render_text(report: &Report) -> Vec<OsString> {
    let mut out: Vec<OsString> = report.findings.iter().flat_map(render_finding).collect();
    if !out.is_empty() {
        out.push(OsString::new());
    }
    out.push(OsString::from(summary(report)));
    out
}

/// `N layers linted, E errors, W warnings, K notes`.
pub fn summary(report: &Report) -> String {
    format!(
        "{}, {}, {}, {}",
        plural(report.layers.len(), "layer linted", "layers linted"),
        plural(report.count(Severity::Error), "error", "errors"),
        plural(report.count(Severity::Warning), "warning", "warnings"),
        plural(report.count(Severity::Note), "note", "notes"),
    )
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The report as JSON: one object per finding, then a summary object.
/// Paths go through `to_string_lossy`, since JSON is UTF-8 and this is a
/// report rather than the argv audit trail `--dry-run` prints.
pub fn render_json(report: &Report) -> String {
    let mut out = String::from("[\n");
    for f in &report.findings {
        out.push_str("  {\"file\": ");
        out.push_str(&json_string(&f.at.label().to_string_lossy()));
        out.push_str(&format!(
            ", \"line\": {}, \"col\": {}, \"severity\": {}, \"check\": {}, \"message\": {}, \"help\": {}}},\n",
            f.line.map_or_else(|| "null".to_owned(), |l| l.to_string()),
            f.col.map_or_else(|| "null".to_owned(), |c| c.to_string()),
            json_string(&f.severity.to_string()),
            json_string(f.id),
            json_string(&f.message),
            json_string(&f.help),
        ));
    }
    out.push_str(&format!(
        "  {{\"layers\": {}, \"errors\": {}, \"warnings\": {}, \"notes\": {}}}\n]\n",
        report.layers.len(),
        report.count(Severity::Error),
        report.count(Severity::Warning),
        report.count(Severity::Note),
    ));
    out
}

/// `s` as a JSON string literal. Every control character is escaped, so a
/// message built from config text stays one line of valid JSON.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One layer as the checks read it.
struct Source {
    at: Where,
    text: String,
    doc: KdlDocument,
}

impl Source {
    fn read(at: Where, text: String) -> Result<Self, LintError> {
        let doc = KdlDocument::parse(&text).map_err(config::ConfigError::from)?;
        Ok(Self { at, text, doc })
    }

    /// Line and column of a byte offset into the layer, both 1-based and
    /// counted in characters. A built-in layer has no file to point into,
    /// so it reports neither.
    fn position(&self, offset: usize) -> (Option<u32>, Option<u32>) {
        if matches!(self.at, Where::BuiltIn(_)) {
            return (None, None);
        }
        // A span past the end would panic the slice; `min` keeps a
        // document the parser rewrote from taking the run down with it.
        let before = &self.text[..offset.min(self.text.len())];
        let line = 1 + before.bytes().filter(|b| *b == b'\n').count();
        let col = 1 + match before.rfind('\n') {
            Some(nl) => before[nl + 1..].chars().count(),
            None => before.chars().count(),
        };
        (
            Some(u32::try_from(line).unwrap_or(u32::MAX)),
            Some(u32::try_from(col).unwrap_or(u32::MAX)),
        )
    }
}

/// A finding before it is paired with the layer it came from; `offset` orders
/// the findings of one layer the way the file reads.
struct Pending {
    layer: usize,
    offset: usize,
    check: &'static Check,
    message: String,
    help: String,
}

/// Findings collected so far, in the order the checks ran.
#[derive(Default)]
struct Findings(Vec<Pending>);

impl Findings {
    fn push(
        &mut self,
        layer: usize,
        node: &KdlNode,
        check: &'static Check,
        message: String,
        help: &str,
    ) {
        self.0.push(Pending {
            layer,
            offset: node.name().span().offset(),
            check,
            message,
            help: help.to_owned(),
        });
    }
}

/// Run every check over `sources`, which are in merge order, and drop the
/// warnings and notes a `lint-allow` node accepted. Errors are never
/// dropped: they name something the file cannot do.
fn run(ctx: &Context, sources: &[Source]) -> Report {
    let mut f = Findings::default();
    for (i, source) in sources.iter().enumerate() {
        per_layer(ctx, i, source, &mut f);
    }
    across_layers(ctx, sources, &mut f);
    let allowed: Vec<&str> = sources
        .iter()
        .flat_map(|s| top(s, "lint-allow"))
        .filter_map(arg)
        .collect();
    unused_allows(sources, &mut f);
    let mut items = f.0;
    items.sort_by_key(|p| (p.layer, p.offset));
    let findings = items
        .into_iter()
        .filter_map(|p| {
            // A `lint-allow` that accepts nothing cannot be accepted
            // away: the node doing the accepting would be the unused one.
            if p.check.severity != Severity::Error
                && p.check.id != LINT_ALLOW_UNUSED.id
                && allowed.contains(&p.check.id)
            {
                return None;
            }
            let source = &sources[p.layer];
            let (line, col) = source.position(p.offset);
            Some(Finding {
                at: source.at.clone(),
                line,
                col,
                severity: p.check.severity,
                id: p.check.id,
                message: p.message,
                help: p.help,
            })
        })
        .collect();
    Report {
        findings,
        layers: sources.iter().map(|s| s.at.clone()).collect(),
    }
}

/// Report every `lint-allow` node that accepted nothing: no check of any
/// layer reported the id it names. Errors are never accepted, so naming
/// one is naming nothing — but the parser refuses those ids already.
///
/// Read from the findings collected so far, which is why this runs last.
fn unused_allows(sources: &[Source], f: &mut Findings) {
    let silenced: Vec<&'static str> =
        f.0.iter()
            .filter(|p| p.check.severity != Severity::Error)
            .map(|p| p.check.id)
            .collect();
    for (i, source) in sources.iter().enumerate() {
        for node in top(source, "lint-allow") {
            let Some(id) = arg(node) else {
                continue;
            };
            if silenced.contains(&id) {
                continue;
            }
            f.push(
                i,
                node,
                &LINT_ALLOW_UNUSED,
                format!("`lint-allow \"{id}\"` accepts nothing: no layer reports `{id}`"),
                "drop the node; a suppression that silences nothing outlives what it was \
                 written for",
            );
        }
    }
}

/// Top-level nodes of `source` named `name`, in file order.
fn top<'a>(source: &'a Source, name: &str) -> Vec<&'a KdlNode> {
    source
        .doc
        .nodes()
        .iter()
        .filter(|n| n.name().value() == name)
        .collect()
}

/// Every rule child of every bus node of `source`, each paired with the
/// bus it belongs to. The two proxies are separate filters, so a rule is
/// never read outside the bus that carries it.
fn bus_rules(source: &Source) -> Vec<(&'static str, &KdlNode)> {
    let mut out = Vec::new();
    for bus in ["dbus", "system-bus"] {
        for node in top(source, bus) {
            out.extend(kids(node).map(|r| (bus, r)));
        }
    }
    out
}

/// The last layer that writes a `name` node, and that node: the merge
/// keeps that one, so a finding about it belongs to that layer and not to
/// the layer it overrode.
fn last<'a>(sources: &'a [Source], name: &str) -> Option<(usize, &'a KdlNode)> {
    sources
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, s)| top(s, name).last().map(|n| (i, *n)))
}

/// Child nodes of `node`, or none when it has no block.
fn kids(node: &KdlNode) -> impl Iterator<Item = &KdlNode> {
    node.children().into_iter().flat_map(KdlDocument::nodes)
}

/// The node's first positional argument as a string.
fn arg(node: &KdlNode) -> Option<&str> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
}

/// What a `camera nodes=#true` costs that the portal half does not: a
/// device list frozen at launch, and, on a host with no camera, nothing
/// to bind at all.
fn camera_nodes(ctx: &Context, i: usize, node: &KdlNode, f: &mut Findings) {
    let dev = Path::new("/dev");
    let present = ctx.host.list_dir(dev).into_iter().any(|name| {
        let bytes = name.as_encoded_bytes();
        (bytes.starts_with(b"video") || bytes.starts_with(b"media"))
            && ctx
                .host
                .file_type(&dev.join(&name))
                .is_some_and(|t| t.is_char_device())
    });
    if !present {
        f.push(
            i,
            node,
            &CAMERA_NODES_NONE_PRESENT,
            "`camera nodes=#true` and this host has no `/dev/video*` or `/dev/media*` node, \
             so the device half of the grant binds nothing"
                .to_owned(),
            "the portal half needs no node in the sandbox; drop `nodes=#true` unless the \
             application is a plain V4L2 client",
        );
    }
    f.push(
        i,
        node,
        &CAMERA_NODES_NO_HOTPLUG,
        "`camera nodes=#true` binds the nodes this host has at launch: a camera plugged in \
         later has no node inside, and with a network namespace of its own the sandbox is \
         never told about one either"
            .to_owned(),
        "restart the instance after plugging a camera in; the portal half follows hotplug \
         in the host daemon instead",
    );
}

/// The node's `key=` property as a string.
fn prop<'a>(node: &'a KdlNode, key: &str) -> Option<&'a str> {
    node.entries()
        .iter()
        .find(|e| e.name().is_some_and(|n| n.value() == key))
        .and_then(|e| e.value().as_string())
}

/// The node's `key=` property as a boolean, which is what the device
/// properties of `gamepad` and `camera` are written as.
fn flag(node: &KdlNode, key: &str) -> Option<bool> {
    node.entries()
        .iter()
        .find(|e| e.name().is_some_and(|n| n.value() == key))
        .and_then(|e| e.value().as_bool())
}

/// The bus name a rule child names: the whole argument for a policy rule,
/// the part before `=` for `call` and `broadcast`.
fn rule_name(node: &KdlNode) -> Option<&str> {
    let a = arg(node)?;
    match node.name().value() {
        "call" | "broadcast" => a.split('=').next(),
        _ => Some(a),
    }
}

/// Checks that need one layer and nothing else.
fn per_layer(ctx: &Context, i: usize, source: &Source, f: &mut Findings) {
    for node in source.doc.nodes() {
        match node.name().value() {
            "x11" => f.push(
                i,
                node,
                &X11_WITHOUT_REASON,
                "`x11` gives no isolation between X clients: any of them can read another's \
                 input and windows"
                    .to_owned(),
                "prefer `wayland`, or accept it with \
                 `lint-allow \"x11-without-reason\" reason=\"...\"`",
            ),
            "tty" if arg(node) == Some("passthrough") => f.push(
                i,
                node,
                &TTY_PASSTHROUGH,
                "`tty \"passthrough\"` hands the sandbox this terminal's own descriptors"
                    .to_owned(),
                "leave the default `pty` unless the command has to share the caller's terminal",
            ),
            "seccomp" if kids(node).any(|c| c.name().value() == "disable") => f.push(
                i,
                node,
                &SECCOMP_DISABLED,
                "`seccomp { disable }` leaves the sandbox with no syscall filter at all".to_owned(),
                "allow the syscalls the app needs instead, or accept it with \
                 `lint-allow \"seccomp-disabled\" reason=\"...\"`",
            ),
            "env" => env_node(i, node, f),
            "home-share" => home_share(ctx, i, node, f),
            "path-share" => path_share(ctx, i, node, f),
            "etc-share" => {
                if let Some(name) = arg(node) {
                    share_source(
                        ctx,
                        i,
                        node,
                        "etc-share",
                        name,
                        &Path::new("/etc").join(name),
                        f,
                    );
                }
            }
            "camera" if flag(node, "nodes") == Some(true) => camera_nodes(ctx, i, node, f),
            "dbus" => dbus_node(i, node, f),
            "system-bus" => system_bus(i, node, f),
            "mpris" if prop(node, "name").is_some_and(|n| n == "*") => f.push(
                i,
                node,
                &MPRIS_WILDCARD,
                "`mpris name=\"*\"` owns every media player name on the bus".to_owned(),
                "name the player, e.g. `mpris name=\"firefox\"`",
            ),
            _ => {}
        }
    }
}

fn env_node(i: usize, node: &KdlNode, f: &mut Findings) {
    for e in node.entries() {
        let Some(key) = e.name().map(|n| n.value()) else {
            continue;
        };
        if key == "ELECTRON_OZONE_PLATFORM_HINT" {
            f.push(
                i,
                node,
                &OZONE_HINT_UNNECESSARY,
                "`env ELECTRON_OZONE_PLATFORM_HINT` was measured to change nothing here: \
                 an Electron app picks Wayland up from the socket alone"
                    .to_owned(),
                "drop the variable",
            );
        }
        let value = e.value().as_string().unwrap_or_default();
        if !looks_secret(key, value) {
            continue;
        }
        f.push(
            i,
            node,
            &ENV_LOOKS_SECRET,
            format!("`env {key}` looks like a credential, and a profile is a file people share"),
            "keep secrets out of the config; the sandbox is not a secret store",
        );
    }
}

/// Whether a variable is named or valued like a credential. Matched by
/// hand rather than with a pattern crate, which is a dependency this
/// would be the only user of.
fn looks_secret(key: &str, value: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    let segments: Vec<&str> = upper.split('_').collect();
    segments.iter().any(|s| SECRET_SEGMENTS.contains(s))
        || segments
            .windows(2)
            .any(|w| SECRET_PAIRS.contains(&[w[0], w[1]]))
        || SECRET_VALUES.iter().any(|p| value.starts_with(p))
}

fn home_share(ctx: &Context, i: usize, node: &KdlNode, f: &mut Findings) {
    let Some(path) = arg(node) else {
        return;
    };
    let sensitive = SENSITIVE_TREE
        .iter()
        .find(|s| Path::new(path).starts_with(s))
        .or_else(|| {
            SENSITIVE_ROOT
                .iter()
                .find(|s| Path::new(**s) == Path::new(path))
        });
    if let Some(root) = sensitive {
        let what = match Path::new(root) == Path::new(path) {
            true => "shares a directory the private home exists to keep out".to_owned(),
            false => format!("is under `{root}`, which the private home exists to keep out"),
        };
        f.push(
            i,
            node,
            &HOME_SHARE_SENSITIVE,
            format!("`home-share \"{path}\"` {what}"),
            "share the directory the app works in, not the one holding your keys, \
             sessions or other applications' configuration",
        );
    }
    share_source(
        ctx,
        i,
        node,
        "home-share",
        path,
        &ctx.env.home.join(path),
        f,
    );
}

fn path_share(ctx: &Context, i: usize, node: &KdlNode, f: &mut Findings) {
    let Some(written) = arg(node) else {
        return;
    };
    let path = Path::new(written);
    if let Some(reason) = service::reserved_reason(ctx.host, ctx.env, path) {
        f.push(
            i,
            node,
            &PATH_SHARE_RESERVED,
            reason,
            "name a directory outside the sandbox's own layout; the launcher refuses this one",
        );
    }
    // Before the type check below, which would otherwise report a socket
    // source as a share of the wrong type and say nothing about what a
    // shared socket is.
    let source = ctx.host.canonicalize(path).unwrap_or_else(|| path.into());
    let named_socket = path
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|n| n.ends_with(".sock") || n.ends_with(".socket"));
    let is_socket = ctx.host.file_type(&source).is_some_and(|t| t.is_socket());
    if named_socket || is_socket {
        let how = if is_socket { "is" } else { "is named like" };
        f.push(
            i,
            node,
            &PATH_SHARE_SOCKET,
            format!(
                "`path-share \"{written}\"` {how} a socket, and a socket is a command \
                 channel out of the sandbox"
            ),
            "share the files the app reads, not a control socket",
        );
        return;
    }
    if !share_source(ctx, i, node, "path-share", written, &source, f) {
        return;
    }
    if prop(node, "mode") == Some("rw") && ctx.host.is_mountpoint(&source) == Some(true) {
        f.push(
            i,
            node,
            &PATH_SHARE_MOUNTPOINT,
            format!("`path-share \"{written}\" mode=rw` shares a whole mounted filesystem"),
            "name the directory the app writes in, or share it `mode=ro`",
        );
    }
    let socket = ctx.host.list_dir(&source).into_iter().find(|name| {
        ctx.host
            .file_type(&source.join(name))
            .is_some_and(|t| t.is_socket())
    });
    if let Some(name) = socket {
        f.push(
            i,
            node,
            &PATH_SHARE_SOCKET,
            format!(
                "`path-share \"{written}\"` holds the socket `{}`, and a socket is a \
                 command channel out of the sandbox",
                name.to_string_lossy()
            ),
            "share the files the app reads, not the directory a control socket is in",
        );
    }
}

/// Report a share whose host source is not a directory or a regular file,
/// and say which of the two it is: absent, or there as something else.
/// Returns whether the source is one a share should name.
///
/// `path-share` is the only one the launcher holds to this, but a
/// `home-share` or `etc-share` of a fifo or a device node is a bind
/// nobody means to write, so the lint holds all three to it.
fn share_source(
    ctx: &Context,
    i: usize,
    node: &KdlNode,
    what: &str,
    written: &str,
    source: &Path,
    f: &mut Findings,
) -> bool {
    let Some(ty) = ctx.host.file_type(source) else {
        f.push(
            i,
            node,
            &SHARE_SOURCE_MISSING,
            format!(
                "`{what} \"{written}\"` names {}, which is not on this host",
                source.display()
            ),
            "create it, or drop the node; a missing source fails the run rather than \
             skipping the bind",
        );
        return false;
    };
    if ty.is_dir() || ty.is_file() {
        return true;
    }
    f.push(
        i,
        node,
        &SHARE_SOURCE_MISSING,
        format!(
            "`{what} \"{written}\"` names {}, which is {}, not a directory or a regular file",
            source.display(),
            kind(ty)
        ),
        "name a directory or a regular file; nothing else is a share the sandbox can use",
    );
    false
}

/// What a file type is called in a finding, with its article.
fn kind(ty: std::fs::FileType) -> &'static str {
    if ty.is_socket() {
        "a socket"
    } else if ty.is_fifo() {
        "a named pipe"
    } else if ty.is_char_device() {
        "a character device"
    } else if ty.is_block_device() {
        "a block device"
    } else {
        "neither"
    }
}

/// The session bus's own rules: a name claimed more widely than the app
/// owns, and the one name that is every secret the keyring holds.
fn dbus_node(i: usize, node: &KdlNode, f: &mut Findings) {
    for rule in kids(node) {
        let level = rule.name().value();
        if level == "own" {
            own_too_wide(i, rule, f);
        }
        if !matches!(level, "talk" | "own") || rule_name(rule) != Some(SECRETS_NAME) {
            continue;
        }
        f.push(
            i,
            rule,
            &SECRETS_ACCESS,
            format!(
                "`{level} \"{SECRETS_NAME}\"` reaches the whole login keyring: the Secret \
                 Service API partitions nothing between the applications that call it"
            ),
            "keep the app's secrets in the private home, or accept it with \
             `lint-allow \"secrets-access\" reason=\"...\"`",
        );
    }
}

fn own_too_wide(i: usize, rule: &KdlNode, f: &mut Findings) {
    let Some(name) = arg(rule) else {
        return;
    };
    let Some(prefix) = name.strip_suffix('*') else {
        return;
    };
    if prefix.split('.').filter(|e| !e.is_empty()).count() >= 3 {
        return;
    }
    f.push(
        i,
        rule,
        &OWN_TOO_WIDE,
        format!("`own \"{name}\"` claims every well-known name under `{prefix}`"),
        "name the application itself, e.g. `own \"org.example.App.*\"`",
    );
}

fn system_bus(i: usize, node: &KdlNode, f: &mut Findings) {
    for rule in kids(node) {
        let Some(name) = rule_name(rule) else {
            continue;
        };
        match rule.name().value() {
            "own" => f.push(
                i,
                rule,
                &OWN_ON_SYSTEM_BUS,
                format!(
                    "`own \"{name}\"` on the system bus: the bus sees the proxy's \
                     credentials, so the name would be owned as you"
                ),
                "own names on the session bus; the system bus takes `see`, `talk` and `call`",
            ),
            "talk" => {
                let bare = name.strip_suffix(".*").unwrap_or(name);
                if !POLKIT_NAMES.contains(&bare) {
                    continue;
                }
                f.push(
                    i,
                    rule,
                    &SYSTEM_BUS_POLKIT_NAME,
                    format!(
                        "`talk \"{name}\"` reaches every method of a service whose \
                         privileged actions polkit judges as you"
                    ),
                    "narrow it to what the app needs, e.g. \
                     `call \"<name>=<interface>.<method>@<path>\"`",
                );
            }
            _ => {}
        }
    }
}

/// Checks that need the whole set of layers: a grant one layer relies on
/// may be written in another.
fn across_layers(ctx: &Context, sources: &[Source], f: &mut Findings) {
    let anywhere = |name: &str| sources.iter().any(|s| !top(s, name).is_empty());
    let has_dbus = anywhere("dbus");
    let has_portals = anywhere("portals");
    let has_bundle = BUNDLES.iter().any(|b| anywhere(b));

    if !has_dbus {
        for (i, source) in sources.iter().enumerate() {
            for node in source.doc.nodes() {
                let name = node.name().value();
                if !BUNDLES.contains(&name) {
                    continue;
                }
                f.push(
                    i,
                    node,
                    &BUNDLE_WITHOUT_DBUS,
                    format!(
                        "`{name}` is a set of proxy rules and no layer grants `dbus` to carry them"
                    ),
                    "add a `dbus` node, or drop this one",
                );
            }
        }
    }

    if has_dbus && !has_bundle {
        let empty = sources
            .iter()
            .flat_map(|s| top(s, "dbus"))
            .all(|n| kids(n).next().is_none());
        let first = sources
            .iter()
            .enumerate()
            .find_map(|(i, s)| top(s, "dbus").first().map(|n| (i, *n)));
        if let Some((i, node)) = first.filter(|_| empty) {
            f.push(
                i,
                node,
                &DBUS_WITHOUT_RULES,
                "`dbus` names nothing and no layer adds a bundle, so the proxy it starts \
                 answers nothing"
                    .to_owned(),
                "add `see`, `talk` or `own` rules or a bundle such as `portals`, \
                 or drop the node",
            );
        }
    }

    if !has_portals {
        for (i, source) in sources.iter().enumerate() {
            for node in top(source, "camera") {
                f.push(
                    i,
                    node,
                    &CAMERA_WITHOUT_PORTALS,
                    "`camera` is a portal grant and no layer grants `portals`, so the \
                     sandbox has no `/.flatpak-info` and the portal reads it as an \
                     ordinary process of yours"
                        .to_owned(),
                    "add `portals` (and the `dbus` that carries it), or drop this node",
                );
            }
            for (_, rule) in bus_rules(source) {
                let Some(name) = rule_name(rule).filter(|n| n.starts_with(PORTAL_PREFIX)) else {
                    continue;
                };
                f.push(
                    i,
                    rule,
                    &PORTAL_TALK_WITHOUT_PORTALS,
                    format!(
                        "`{name}` is a portal name, and without `portals` the sandbox has no \
                         `/.flatpak-info`, so every portal call is refused"
                    ),
                    "add `portals`, or drop the rule",
                );
            }
        }
    }

    // Keyed by bus as well as name: the two proxies are separate, so one
    // name may hold a different policy on each.
    let mut policies: Vec<(&str, String, &str, usize)> = Vec::new();
    for (i, source) in sources.iter().enumerate() {
        for (bus, rule) in bus_rules(source) {
            let level = match rule.name().value() {
                level @ ("see" | "talk" | "own") => level,
                _ => continue,
            };
            let Some(name) = rule_name(rule) else {
                continue;
            };
            match policies
                .iter()
                .find(|(b, n, _, _)| *b == bus && n == name)
                .filter(|(_, _, was, _)| *was != level)
            {
                Some((_, _, was, whence)) => {
                    // Naming the layer only says something when it is
                    // another one; both rules in one file are read there.
                    let both = match *whence == i {
                        true => format!("as `{was}` and as `{level}` twice in this file"),
                        false => format!(
                            "as `{was}` in {} and as `{level}` here",
                            sources[*whence].at.label().to_string_lossy()
                        ),
                    };
                    f.push(
                        i,
                        rule,
                        &DUP_NAME_POLICY,
                        format!("`{name}` is granted {both}; one name takes one policy"),
                        "keep the narrower of the two",
                    );
                }
                None => policies.push((bus, name.to_owned(), level, i)),
            }
        }
    }

    let command = last(sources, "command").and_then(|(i, n)| arg(n).map(|a| (i, n, a)));
    if let Some((i, node, disable)) =
        last(sources, "userns").map(|(i, n)| (i, n, arg(n) == Some("disable")))
        && disable
        && let Some((_, _, argv0)) = command
        && is_nester(argv0)
    {
        f.push(
            i,
            node,
            &USERNS_DISABLED_WITH_NESTED_SANDBOX,
            format!(
                "`userns \"disable\"` with `command \"{argv0}\"`, which is known to start a \
                 sandbox of its own inside this one; the list of such commands is a heuristic"
            ),
            "drop `userns \"disable\"` if the app does not start",
        );
    }
    if let Some((i, node, argv0)) = command
        && !on_path(ctx, argv0)
    {
        f.push(
            i,
            node,
            &COMMAND_NOT_FOUND,
            format!("`{argv0}` is not on this host's PATH"),
            "a profile may be written for software you have not installed; \
             otherwise fix the `command` node",
        );
    }
}

/// Whether a command starts a sandbox of its own, by basename.
fn is_nester(argv0: &str) -> bool {
    let base = Path::new(argv0)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(argv0);
    base.starts_with("electron") || NESTERS.contains(&base)
}

/// Whether a `command` names a file this host has: the path itself when
/// it holds a separator, else one of the `$PATH` directories.
fn on_path(ctx: &Context, argv0: &str) -> bool {
    let path = Path::new(argv0);
    if path.components().count() > 1 {
        return ctx.host.file_type(path).is_some();
    }
    ctx.search_path
        .iter()
        .any(|dir| ctx.host.file_type(&dir.join(argv0)).is_some())
}

/// Lint every profile name any layer holds, as `--all` does.
pub fn lint_all(ctx: &Context, resolver: &Resolver) -> Result<Report, LintError> {
    let mut out = Report::default();
    for entry in resolver.list()? {
        out.absorb(lint_profile(ctx, resolver, &entry.name)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Service;
    use crate::host::fake::{self, FakeHost};
    use crate::profile;

    /// A host environment with a fixed home, so a `home-share` source is
    /// the same path in every test.
    fn env() -> Env {
        Env {
            home: PathBuf::from("/home/han"),
            data_home: PathBuf::from("/home/han/.local/share"),
            config_home: PathBuf::from("/home/han/.config"),
            runtime_dir: PathBuf::from("/run/user/1000"),
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
        }
    }

    /// Run `f` with a context over `host`, `/home/han` and a `$PATH` of
    /// `/usr/bin`.
    fn with<T>(host: &dyn Host, f: impl FnOnce(&Context) -> T) -> T {
        let e = env();
        let path = [PathBuf::from("/usr/bin")];
        f(&Context {
            env: &e,
            host,
            search_path: &path,
        })
    }

    /// Lint several layers, in merge order, as files `/p/<i>.kdl`.
    fn lint(ctx: &Context, layers: &[&str]) -> Report {
        let sources: Vec<Source> = layers
            .iter()
            .enumerate()
            .map(|(i, text)| {
                Source::read(
                    Where::File(PathBuf::from(format!("/p/{i}.kdl"))),
                    (*text).to_owned(),
                )
                .expect("test layers are valid KDL")
            })
            .collect();
        run(ctx, &sources)
    }

    /// The ids a run reported, in order.
    fn ids(report: &Report) -> Vec<&str> {
        report.findings.iter().map(|f| f.id).collect()
    }

    /// A host holding only `/usr/bin/foot`, which the `command` node of
    /// most of these fixtures names.
    fn host() -> FakeHost {
        let (file, _, _) = fake::types();
        FakeHost::default().with("/usr/bin/foot", file)
    }

    #[test]
    fn x11_is_a_warning_a_lint_allow_node_accepts() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["x11"]);
            assert_eq!(ids(&report), ["x11-without-reason"]);
            assert_eq!(report.findings[0].severity, Severity::Warning);
            assert_eq!(ids(&lint(ctx, &["wayland"])), [] as [&str; 0]);
            let allowed = lint(
                ctx,
                &["x11\nlint-allow \"x11-without-reason\" reason=\"no Wayland backend\""],
            );
            assert_eq!(ids(&allowed), [] as [&str; 0]);
        });
    }

    #[test]
    fn a_camera_grant_is_measured_against_the_portal_and_the_host() {
        let (file, dir, _) = fake::types();
        let with_camera = FakeHost::default()
            .with("/usr/bin/foot", file)
            .with("/dev", dir)
            .with("/dev/video0", fake::char_type());
        with(&with_camera, |ctx| {
            // The portal is the grant; the device nodes are an extra on
            // top of it, and neither works without `/.flatpak-info`.
            assert_eq!(ids(&lint(ctx, &["camera"])), ["camera-without-portals"]);
            assert_eq!(lint(ctx, &["camera"]).findings[0].severity, Severity::Error);
            // The `portals` may be written in another layer.
            assert_eq!(
                ids(&lint(ctx, &["dbus\nportals", "camera"])),
                [] as [&str; 0]
            );
            // A host with a camera: only the frozen device list is worth
            // saying, and the bare grant carries neither note.
            assert_eq!(
                ids(&lint(ctx, &["dbus\nportals\ncamera nodes=#true"])),
                ["camera-nodes-no-hotplug"]
            );
            assert_eq!(
                ids(&lint(ctx, &["dbus\nportals\ncamera nodes=#false"])),
                [] as [&str; 0]
            );
        });
        with(&host(), |ctx| {
            // No node on this host, so the device half binds nothing.
            let report = lint(ctx, &["dbus\nportals\ncamera nodes=#true"]);
            assert_eq!(
                ids(&report),
                ["camera-nodes-none-present", "camera-nodes-no-hotplug"]
            );
            assert!(
                report.findings.iter().all(|f| f.severity == Severity::Note),
                "{report:#?}"
            );
        });
    }

    #[test]
    fn a_lint_allow_node_reaches_across_layers() {
        // The accepted finding and the node it is about need not be in
        // the same file: a user layer may accept what a built-in grants.
        with(&host(), |ctx| {
            let report = lint(
                ctx,
                &[
                    "x11",
                    "lint-allow \"x11-without-reason\" reason=\"measured\"",
                ],
            );
            assert_eq!(ids(&report), [] as [&str; 0]);
        });
    }

    #[test]
    fn a_disabled_seccomp_filter_and_a_passed_through_terminal_are_warnings() {
        with(&host(), |ctx| {
            assert_eq!(
                ids(&lint(ctx, &["seccomp {\n    disable\n}"])),
                ["seccomp-disabled"]
            );
            assert_eq!(
                ids(&lint(ctx, &["seccomp {\n    allow \"keyctl\"\n}"])),
                [] as [&str; 0]
            );
            assert_eq!(
                ids(&lint(ctx, &["tty \"passthrough\""])),
                ["tty-passthrough"]
            );
            assert_eq!(ids(&lint(ctx, &["tty \"none\""])), [] as [&str; 0]);
        });
    }

    #[test]
    fn an_environment_value_shaped_like_a_credential_is_a_warning() {
        with(&host(), |ctx| {
            for text in [
                "env GITHUB_TOKEN=\"x\"",
                "env api_key=\"x\"",
                "env MY_APIKEY=\"x\"",
                "env MY_PAT=\"x\"",
                "env AWS_SECRET_ACCESS_KEY=\"x\"",
                "env WHATEVER=\"ghp_abcdef\"",
                "env KEY=\"AKIAEXAMPLE\"",
            ] {
                assert_eq!(ids(&lint(ctx, &[text])), ["env-looks-secret"], "{text}");
            }
            // Whole underscore-separated words, not substrings: a name
            // that merely starts with one of them is not a credential.
            for text in [
                "env SAL_USE_VCLPLUGIN=\"gtk3\"",
                "env TOKENIZERS_PARALLELISM=\"false\"",
                "env COMPAT_MODE=\"1\"",
                "env KEYBOARD_LAYOUT=\"us\"",
            ] {
                assert_eq!(ids(&lint(ctx, &[text])), [] as [&str; 0], "{text}");
            }
        });
    }

    #[test]
    fn the_electron_ozone_hint_is_a_note() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["env ELECTRON_OZONE_PLATFORM_HINT=\"auto\""]);
            assert_eq!(ids(&report), ["ozone-hint-unnecessary"]);
            assert_eq!(report.findings[0].severity, Severity::Note);
            assert_eq!(
                ids(&lint(ctx, &["env ELECTRON_ENABLE_LOGGING=\"1\""])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn sharing_a_directory_the_private_home_exists_to_keep_out_is_a_warning() {
        let (_, dir, _) = fake::types();
        let host = host()
            .with("/home/han/.ssh", dir)
            .with("/home/han/.ssh/keys", dir)
            .with("/home/han/.local/share", dir)
            .with("/home/han/.config/app", dir)
            .with("/home/han/Downloads", dir);
        with(&host, |ctx| {
            assert_eq!(
                ids(&lint(ctx, &["home-share \".ssh\""])),
                ["home-share-sensitive"]
            );
            assert_eq!(
                ids(&lint(ctx, &["home-share \".local/share\""])),
                ["home-share-sensitive"]
            );
            // A tree of keys is sensitive one directory at a time; the
            // directories that hold every application's state are not,
            // since one application's own is what a profile shares.
            let report = lint(ctx, &["home-share \".ssh/keys\""]);
            assert_eq!(ids(&report), ["home-share-sensitive"]);
            assert!(report.findings[0].message.contains("`.ssh`"), "{report:?}");
            assert_eq!(
                ids(&lint(ctx, &["home-share \".config/app\" mode=rw"])),
                [] as [&str; 0]
            );
            assert_eq!(
                ids(&lint(ctx, &["home-share \"Downloads\" mode=rw"])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_lint_allow_that_accepts_nothing_is_a_note() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["lint-allow \"x11-without-reason\" reason=\"none\""]);
            assert_eq!(ids(&report), ["lint-allow-unused"]);
            assert_eq!(report.findings[0].severity, Severity::Note);
            // One that does accept a finding says nothing, in its own
            // layer or in another.
            assert_eq!(
                ids(&lint(
                    ctx,
                    &["x11\nlint-allow \"x11-without-reason\" reason=\"m\""]
                )),
                [] as [&str; 0]
            );
            assert_eq!(
                ids(&lint(
                    ctx,
                    &["lint-allow \"x11-without-reason\" reason=\"m\"", "x11"]
                )),
                [] as [&str; 0]
            );
            // The note is not suppressible by a node of its own: that
            // node would be the unused one.
            assert_eq!(
                ids(&lint(
                    ctx,
                    &["lint-allow \"lint-allow-unused\" reason=\"no\""]
                )),
                ["lint-allow-unused"]
            );
        });
    }

    #[test]
    fn reaching_the_secret_service_is_a_note() {
        with(&host(), |ctx| {
            for rule in ["talk", "own"] {
                let text = format!("dbus {{\n    {rule} \"org.freedesktop.secrets\"\n}}");
                let report = lint(ctx, &[&text]);
                assert_eq!(ids(&report), ["secrets-access"], "{text}");
                assert_eq!(report.findings[0].severity, Severity::Note);
                assert!(
                    report.findings[0].message.contains("login keyring"),
                    "{report:?}"
                );
            }
            // The name lives on the session bus; the same string on the
            // system bus reaches no keyring.
            assert_eq!(
                ids(&lint(
                    ctx,
                    &["system-bus {\n    talk \"org.freedesktop.secrets\"\n}"]
                )),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_share_whose_source_is_not_on_this_host_is_an_error() {
        let (_, dir, _) = fake::types();
        let host = host()
            .with("/home/han/Downloads", dir)
            .with("/etc/vulkan", dir);
        with(&host, |ctx| {
            for text in [
                "home-share \"Games\"",
                "path-share \"/kioxia/Steam\"",
                "etc-share \"OpenCL\"",
            ] {
                let report = lint(ctx, &[text]);
                assert_eq!(ids(&report), ["share-source-missing"], "{text}");
                assert_eq!(report.findings[0].severity, Severity::Error, "{text}");
            }
            assert_eq!(
                ids(&lint(
                    ctx,
                    &["home-share \"Downloads\"\netc-share \"vulkan\""]
                )),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_share_source_that_is_not_a_directory_or_a_file_is_an_error() {
        let (file, dir, sock, fifo) = fake::every_type();
        let host = FakeHost::default()
            .with("/usr/bin/foot", file)
            .with("/home/han/pipe", fifo)
            .with("/etc/sock", sock)
            .with("/kioxia/pipe", fifo)
            .with("/kioxia/sock", sock)
            .with("/kioxia/data", dir);
        with(&host, |ctx| {
            for text in [
                "home-share \"pipe\"",
                "etc-share \"sock\"",
                "path-share \"/kioxia/pipe\"",
            ] {
                let report = lint(ctx, &[text]);
                assert_eq!(ids(&report), ["share-source-missing"], "{text}");
                assert!(
                    report.findings[0]
                        .message
                        .contains("not a directory or a regular file"),
                    "{text}: {}",
                    report.findings[0].message
                );
            }
            // A `path-share` of a socket is named by the check that says
            // what a shared socket is, not by the type check.
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia/sock\""])),
                ["path-share-socket"]
            );
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia/data\""])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_path_share_of_a_root_bubbler_never_shares_is_an_error() {
        let (_, dir, _) = fake::types();
        let host = host().with("/home/han", dir).with("/kioxia/Steam", dir);
        with(&host, |ctx| {
            let report = lint(ctx, &["path-share \"/home/han\" mode=rw"]);
            assert_eq!(ids(&report), ["path-share-reserved"]);
            assert_eq!(report.findings[0].severity, Severity::Error);
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia/Steam\" mode=rw"])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_writable_share_of_a_whole_mounted_filesystem_is_a_warning() {
        let (_, dir, _) = fake::types();
        let host = host()
            .with("/kioxia", dir)
            .mount("/kioxia")
            .with("/kioxia/Steam", dir);
        with(&host, |ctx| {
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia\" mode=rw"])),
                ["path-share-mountpoint"]
            );
            // Read-only is the case the README already permits, and a
            // directory on the mount is not the mount.
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia\""])),
                [] as [&str; 0]
            );
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia/Steam\" mode=rw"])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_share_that_reaches_a_socket_is_a_warning() {
        let (file, dir, sock) = fake::types();
        let host = host()
            .with("/kioxia/run", dir)
            .with("/kioxia/run/kitty.sock", sock)
            .with("/kioxia/data", dir)
            .with("/kioxia/data/save", file)
            .with("/kioxia/data/kitty.socket", file);
        with(&host, |ctx| {
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia/run\""])),
                ["path-share-socket"]
            );
            // Named like one is enough: the launcher would refuse it, and
            // a regular file with that name is a socket path in waiting.
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia/data/kitty.socket\""])),
                ["path-share-socket"]
            );
            assert_eq!(
                ids(&lint(ctx, &["path-share \"/kioxia/data\""])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn an_own_rule_wider_than_the_application_is_a_warning() {
        with(&host(), |ctx| {
            for name in ["org.*", "org.kde.*", "com.steampowered.*"] {
                let text = format!("dbus {{\n    own \"{name}\"\n}}");
                assert_eq!(ids(&lint(ctx, &[&text])), ["own-too-wide"], "{name}");
            }
            for name in ["org.mozilla.firefox.*", "net.lutris.Lutris"] {
                let text = format!("dbus {{\n    own \"{name}\"\n}}");
                assert_eq!(ids(&lint(ctx, &[&text])), [] as [&str; 0], "{name}");
            }
        });
    }

    #[test]
    fn owning_every_media_player_name_is_a_warning() {
        with(&host(), |ctx| {
            assert_eq!(
                ids(&lint(ctx, &["dbus\nmpris name=\"*\""])),
                ["mpris-wildcard"]
            );
            assert_eq!(
                ids(&lint(ctx, &["dbus\nmpris name=\"firefox.*\""])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn talking_to_a_polkit_backed_system_service_is_a_warning() {
        with(&host(), |ctx| {
            let text = "system-bus {\n    talk \"org.freedesktop.UDisks2\"\n}";
            assert_eq!(ids(&lint(ctx, &[text])), ["system-bus-polkit-name"]);
            // `see` and a narrowed `call` are the forms the shipped
            // profiles use, and neither reaches a privileged method.
            let narrow = "system-bus {\n    see \"org.freedesktop.UDisks2\"\n    \
                          call \"org.freedesktop.UDisks2=org.freedesktop.DBus.ObjectManager.GetManagedObjects@/org/freedesktop/UDisks2\"\n}";
            assert_eq!(ids(&lint(ctx, &[narrow])), [] as [&str; 0]);
            let other = "system-bus {\n    talk \"org.freedesktop.UPower\"\n}";
            assert_eq!(ids(&lint(ctx, &[other])), [] as [&str; 0]);
        });
    }

    #[test]
    fn owning_a_name_on_the_system_bus_is_an_error_the_lint_names() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["system-bus {\n    own \"org.example.App\"\n}"]);
            assert_eq!(ids(&report), ["own-on-system-bus"]);
            assert_eq!(report.findings[0].severity, Severity::Error);
            // The parser refuses the same node; the lint has to reach it
            // anyway, or the file would only ever be "does not parse".
            assert!(config::parse("system-bus {\n    own \"org.example.App\"\n}").is_err());
        });
    }

    #[test]
    fn a_bundle_whose_bus_no_layer_grants_is_an_error() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["notify\ntray"]);
            assert_eq!(ids(&report), ["bundle-without-dbus", "bundle-without-dbus"]);
            assert_eq!(report.findings[0].severity, Severity::Error);
            // The `dbus` node may be in any layer, which is exactly the
            // case one file alone cannot check.
            assert_eq!(ids(&lint(ctx, &["dbus", "notify"])), [] as [&str; 0]);
        });
    }

    #[test]
    fn a_dbus_grant_that_names_nothing_is_a_warning() {
        with(&host(), |ctx| {
            assert_eq!(ids(&lint(ctx, &["dbus"])), ["dbus-without-rules"]);
            assert_eq!(ids(&lint(ctx, &["dbus", "notify"])), [] as [&str; 0]);
            assert_eq!(
                ids(&lint(ctx, &["dbus {\n    talk \"ca.desrt.dconf\"\n}"])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_portal_rule_without_the_portals_grant_is_a_warning() {
        with(&host(), |ctx| {
            let text = "dbus {\n    talk \"org.freedesktop.portal.Desktop\"\n}";
            assert_eq!(ids(&lint(ctx, &[text])), ["portal-talk-without-portals"]);
            assert_eq!(ids(&lint(ctx, &[text, "portals"])), [] as [&str; 0]);
        });
    }

    #[test]
    fn one_bus_name_given_two_policies_across_layers_is_an_error() {
        with(&host(), |ctx| {
            let report = lint(
                ctx,
                &[
                    "dbus {\n    see \"org.example.App\"\n}",
                    "dbus {\n    talk \"org.example.App\"\n}",
                ],
            );
            assert_eq!(ids(&report), ["dup-name-policy"]);
            assert_eq!(report.findings[0].severity, Severity::Error);
            // Named against the layer that wrote the second policy, with
            // the first layer in the message.
            assert_eq!(report.findings[0].at, Where::File("/p/1.kdl".into()));
            assert!(
                report.findings[0].message.contains("/p/0.kdl"),
                "{report:?}"
            );
            // One layer holding both is the same error without a second
            // file to name.
            let report = lint(
                ctx,
                &["dbus {\n    see \"org.example.App\"\n    talk \"org.example.App\"\n}"],
            );
            assert_eq!(ids(&report), ["dup-name-policy"]);
            assert!(
                report.findings[0].message.contains("twice in this file"),
                "{report:?}"
            );
            // The same policy twice is a repeat, not a conflict, and the
            // two buses are separate filters.
            assert_eq!(
                ids(&lint(
                    ctx,
                    &[
                        "dbus {\n    see \"org.freedesktop.UDisks2\"\n}",
                        "system-bus {\n    talk \"org.example.Other\"\n}",
                    ]
                )),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn disabling_user_namespaces_under_a_nesting_command_is_a_warning() {
        let (file, _, _) = fake::types();
        let host = FakeHost::default()
            .with("/usr/bin/chromium", file)
            .with("/usr/bin/foot", file);
        with(&host, |ctx| {
            assert_eq!(
                ids(&lint(ctx, &["userns \"disable\"\ncommand \"chromium\""])),
                ["userns-disabled-with-nested-sandbox"]
            );
            assert_eq!(
                ids(&lint(ctx, &["userns \"disable\"\ncommand \"foot\""])),
                [] as [&str; 0]
            );
            assert_eq!(
                ids(&lint(ctx, &["userns \"allow\"\ncommand \"chromium\""])),
                [] as [&str; 0]
            );
            // The last layer to write the node is the one that decides.
            assert_eq!(
                ids(&lint(
                    ctx,
                    &[
                        "userns \"disable\"",
                        "userns \"allow\"\ncommand \"chromium\""
                    ]
                )),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn a_command_this_host_does_not_have_is_a_note() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["command \"keepassxc\""]);
            assert_eq!(ids(&report), ["command-not-found"]);
            assert_eq!(report.findings[0].severity, Severity::Note);
            assert_eq!(ids(&lint(ctx, &["command \"foot\""])), [] as [&str; 0]);
            assert_eq!(
                ids(&lint(ctx, &["command \"/usr/bin/foot\""])),
                [] as [&str; 0]
            );
        });
    }

    #[test]
    fn lint_allow_never_silences_an_error() {
        with(&host(), |ctx| {
            // The parser refuses the node for an error check, so the only
            // way to write one is a warning id, which leaves the error.
            let report = lint(
                ctx,
                &["notify\nlint-allow \"bundle-without-dbus\" reason=\"no\""],
            );
            // The error stands, and the node that tried to accept it is
            // reported as accepting nothing.
            assert_eq!(ids(&report), ["bundle-without-dbus", "lint-allow-unused"]);
            assert!(config::parse("lint-allow \"bundle-without-dbus\" reason=\"no\"").is_err());
        });
    }

    #[test]
    fn findings_come_out_in_file_order_and_point_at_the_node() {
        with(&host(), |ctx| {
            let report = lint(
                ctx,
                &["wayland\n  x11\ndbus {\n    own \"org.kde.*\"\n}\ntty \"passthrough\""],
            );
            assert_eq!(
                ids(&report),
                ["x11-without-reason", "own-too-wide", "tty-passthrough"]
            );
            // A rule inside a block points at the rule, not at the block.
            let at: Vec<(Option<u32>, Option<u32>)> =
                report.findings.iter().map(|f| (f.line, f.col)).collect();
            assert_eq!(
                at,
                [(Some(2), Some(3)), (Some(4), Some(5)), (Some(6), Some(1))]
            );
        });
    }

    #[test]
    fn a_built_in_layer_has_no_line_to_point_at() {
        with(&host(), |ctx| {
            let source = Source::read(Where::BuiltIn("steam".to_owned()), "x11".to_owned())
                .expect("valid KDL");
            let report = run(ctx, std::slice::from_ref(&source));
            assert_eq!(
                (report.findings[0].line, report.findings[0].col),
                (None, None)
            );
            assert_eq!(
                render_finding(&report.findings[0])[0].to_string_lossy(),
                "built-in:steam: warning[x11-without-reason]: `x11` gives no isolation between \
                 X clients: any of them can read another's input and windows"
            );
        });
    }

    #[test]
    fn exit_codes_follow_the_worst_finding() {
        let clean = Report::default();
        assert_eq!(exit_code(&clean, false), 0);
        assert_eq!(exit_code(&clean, true), 0);
        with(&host(), |ctx| {
            let note = lint(ctx, &["command \"keepassxc\""]);
            assert_eq!(exit_code(&note, true), 0);
            let warning = lint(ctx, &["x11"]);
            assert_eq!(exit_code(&warning, false), 1);
            assert_eq!(exit_code(&warning, true), 2);
            let error = lint(ctx, &["x11\nnotify"]);
            assert_eq!(exit_code(&error, false), 2);
        });
    }

    #[test]
    fn the_text_report_is_the_shape_an_editor_parses() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["x11\ncommand \"keepassxc\""]);
            let lines: Vec<String> = render_text(&report)
                .iter()
                .map(|l| l.to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                lines,
                vec![
                    "/p/0.kdl:1:1: warning[x11-without-reason]: `x11` gives no isolation between \
                     X clients: any of them can read another's input and windows"
                        .to_owned(),
                    "  help: prefer `wayland`, or accept it with `lint-allow \
                     \"x11-without-reason\" reason=\"...\"`"
                        .to_owned(),
                    "/p/0.kdl:2:1: note[command-not-found]: `keepassxc` is not on this host's PATH"
                        .to_owned(),
                    "  help: a profile may be written for software you have not installed; \
                     otherwise fix the `command` node"
                        .to_owned(),
                    String::new(),
                    "1 layer linted, 0 errors, 1 warning, 1 note".to_owned(),
                ]
            );
        });
    }

    #[test]
    fn the_json_report_is_one_object_per_finding_and_a_summary() {
        with(&host(), |ctx| {
            let report = lint(ctx, &["tty \"passthrough\""]);
            assert_eq!(
                render_json(&report),
                "[\n  {\"file\": \"/p/0.kdl\", \"line\": 1, \"col\": 1, \"severity\": \
                 \"warning\", \"check\": \"tty-passthrough\", \"message\": \
                 \"`tty \\\"passthrough\\\"` hands the sandbox this terminal's own \
                 descriptors\", \"help\": \"leave the default `pty` unless the command has \
                 to share the caller's terminal\"},\n  {\"layers\": 1, \"errors\": 0, \
                 \"warnings\": 1, \"notes\": 0}\n]\n"
            );
            assert_eq!(
                render_json(&Report::default()),
                "[\n  {\"layers\": 0, \"errors\": 0, \"warnings\": 0, \"notes\": 0}\n]\n"
            );
        });
    }

    #[test]
    fn every_builtin_profile_lints_clean() {
        // The host is built from what each profile asks for, so the run
        // measures the grants rather than this machine's directories.
        let tmp = tempfile::tempdir().expect("a temp dir");
        let mut e = env();
        e.config_home = tmp.path().join("config");
        e.profile_dir_override = Some(tmp.path().join("system"));
        let resolver = Resolver::new(&e);
        let search_path = [PathBuf::from("/usr/bin")];
        let (file, dir, _) = fake::types();
        for name in profile::NAMES {
            let text = profile::lookup(name).expect("NAMES lists built-in profiles");
            let cfg = config::parse_profile(text)
                .unwrap_or_else(|err| panic!("{name}: {err}"))
                .config;
            let mut host = FakeHost::default();
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
            let ctx = Context {
                env: &e,
                host: &host,
                search_path: &search_path,
            };
            let report =
                lint_profile(&ctx, &resolver, name).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(
                report
                    .findings
                    .iter()
                    .map(|f| format!("{}[{}]: {}", f.severity, f.id, f.message))
                    .collect::<Vec<_>>(),
                Vec::<String>::new(),
                "{name} does not lint clean"
            );
        }
    }

    /// A resolver over `<tmp>` with `files` written into the user layer,
    /// and the environment it was built from.
    fn profiles(tmp: &Path, files: &[(&str, &str)]) -> (Env, Resolver) {
        let mut e = env();
        e.config_home = tmp.join("config");
        e.profile_dir_override = Some(tmp.join("system"));
        let r = Resolver::new(&e);
        std::fs::create_dir_all(r.user_dir()).expect("a writable temp dir");
        for (name, text) in files {
            std::fs::write(r.user_dir().join(format!("{name}.kdl")), text)
                .expect("a writable temp dir");
        }
        (e, r)
    }

    #[test]
    fn an_error_that_is_not_the_parser_s_leaves_a_parse_failure_to_stop_the_run() {
        // The share error is real, and it says nothing about why the
        // layer above it will not parse, so the run reports the parse
        // failure rather than a verdict built on half the file.
        let tmp = tempfile::tempdir().expect("a temp dir");
        let (e, r) = profiles(
            tmp.path(),
            &[
                ("base", "home-share \"NoSuchDir\"\n"),
                ("app", "include \"base\"\nbluetooth\n"),
            ],
        );
        let host = host();
        let search = [PathBuf::from("/usr/bin")];
        let ctx = Context {
            env: &e,
            host: &host,
            search_path: &search,
        };
        let err = lint_profile(&ctx, &r, "app").expect_err("`bluetooth` is not a node");
        assert!(matches!(err, LintError::Profile(_)), "{err:?}");
        // An error the parser raises itself does explain it, so that one
        // is a report and not a failed run.
        let report = lint_text(
            &ctx,
            Where::File("/p/0.kdl".into()),
            "system-bus {\n    own \"org.example.App\"\n}".to_owned(),
        )
        .expect("the finding says why the parser refuses it");
        assert_eq!(ids(&report), ["own-on-system-bus"]);
    }

    #[test]
    fn folding_two_reports_together_counts_a_shared_layer_once() {
        // `--all` reads a base profile once per profile that includes it,
        // and neither the layer nor what was found in it is doubled.
        let tmp = tempfile::tempdir().expect("a temp dir");
        let (e, r) = profiles(
            tmp.path(),
            &[
                ("base", "x11\ncommand \"foot\"\n"),
                ("a", "include \"base\"\n"),
                ("b", "include \"base\"\n"),
            ],
        );
        let host = host();
        let search = [PathBuf::from("/usr/bin")];
        let ctx = Context {
            env: &e,
            host: &host,
            search_path: &search,
        };
        let mut all = Report::default();
        for name in ["a", "b"] {
            all.absorb(lint_profile(&ctx, &r, name).unwrap_or_else(|e| panic!("{name}: {e}")));
        }
        assert_eq!(ids(&all), ["x11-without-reason"]);
        assert_eq!(all.layers.len(), 3);
        assert_eq!(
            summary(&all),
            "3 layers linted, 0 errors, 1 warning, 0 notes"
        );
    }

    #[test]
    fn a_layer_no_check_explains_stops_the_run_rather_than_reading_clean() {
        with(&host(), |ctx| {
            let err = lint_text(ctx, Where::File("/p/0.kdl".into()), "bluetooth".to_owned())
                .expect_err("an unknown node is not a clean config");
            assert!(matches!(err, LintError::Config(_)), "{err:?}");
        });
    }
}
