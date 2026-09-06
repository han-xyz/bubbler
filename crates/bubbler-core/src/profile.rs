//! Profiles in three layers: the user's, the system's, and the ones
//! compiled into the binary. A profile only seeds a new instance's
//! `config.kdl`; editing the instance never changes the profile.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::{
    self, BusRule, ConfigError, Disabled, InstanceConfig, LintAllow, Node, Outbound, RawProfile,
    Service, ShareMode, TmpSize, Userns,
};
use crate::env::Env;
use crate::error::{ProfileError, ReadError};
use crate::instance::is_plain_name;
use crate::kdl_out;
use crate::seccomp::SeccompConfig;
use crate::tty::TtyMode;

/// Names of all built-in profiles, sorted.
pub const NAMES: &[&str] = &[
    "agent",
    "alacritty",
    "chromium",
    "claude-code",
    "claude-code-strict",
    "code",
    "firefox",
    "generic",
    "keepassxc",
    "kitty",
    "libreoffice",
    "lutris",
    "mpv",
    "spotify",
    "steam",
    "thunderbird",
    "vesktop",
];

/// First line of a seeded `config.kdl`, and of a profile `profile edit`
/// writes, followed by the profile name. It is what `reseed` reads back
/// to know which profile to flatten again, so the three places that write
/// it must write the same bytes.
pub(crate) const PROFILE_HEADER: &str = "// bubbler profile: ";

/// Where the system profile layer lives unless `$BUBBLER_PROFILE_DIR`
/// names another directory.
pub const SYSTEM_DIR: &str = "/usr/share/bubbler/profiles";

/// Longest chain of `include`s a profile may build. A limit is what keeps
/// a mistyped include set from being read until the stack runs out.
pub const MAX_DEPTH: usize = 8;

/// KDL text of a built-in profile, if the name is known.
pub fn lookup(name: &str) -> Option<&'static str> {
    match name {
        "agent" => Some(include_str!("../profiles/agent.kdl")),
        "alacritty" => Some(include_str!("../profiles/alacritty.kdl")),
        "chromium" => Some(include_str!("../profiles/chromium.kdl")),
        "claude-code" => Some(include_str!("../profiles/claude-code.kdl")),
        "claude-code-strict" => Some(include_str!("../profiles/claude-code-strict.kdl")),
        "code" => Some(include_str!("../profiles/code.kdl")),
        "firefox" => Some(include_str!("../profiles/firefox.kdl")),
        "generic" => Some(include_str!("../profiles/generic.kdl")),
        "keepassxc" => Some(include_str!("../profiles/keepassxc.kdl")),
        "kitty" => Some(include_str!("../profiles/kitty.kdl")),
        "libreoffice" => Some(include_str!("../profiles/libreoffice.kdl")),
        "lutris" => Some(include_str!("../profiles/lutris.kdl")),
        "mpv" => Some(include_str!("../profiles/mpv.kdl")),
        "spotify" => Some(include_str!("../profiles/spotify.kdl")),
        "steam" => Some(include_str!("../profiles/steam.kdl")),
        "thunderbird" => Some(include_str!("../profiles/thunderbird.kdl")),
        "vesktop" => Some(include_str!("../profiles/vesktop.kdl")),
        _ => None,
    }
}

/// Which layer a profile, or one node of a flattened profile, came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `$XDG_CONFIG_HOME/bubbler/profiles`.
    User,
    /// [`SYSTEM_DIR`] or `$BUBBLER_PROFILE_DIR`.
    System,
    /// Compiled into the binary.
    BuiltIn,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "user",
            Self::System => "system",
            Self::BuiltIn => "built-in",
        })
    }
}

/// One layer holding a profile of a given name, with its text unparsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// Profile name this layer holds.
    pub name: String,
    /// Which layer this is.
    pub origin: Origin,
    /// File the text was read from; `None` for a built-in.
    pub path: Option<PathBuf>,
    /// The profile as written.
    pub text: String,
}

impl Layer {
    /// How this layer is named in an error message.
    fn label(&self) -> String {
        match &self.path {
            Some(p) => p.display().to_string(),
            None => format!("built-in profile `{}`", self.name),
        }
    }
}

/// One profile name and the layer that provides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Profile name, without the `.kdl` suffix.
    pub name: String,
    /// The layer the name resolves to.
    pub origin: Origin,
    /// File it is read from; `None` for a built-in.
    pub path: Option<PathBuf>,
}

/// One node of a flattened profile and the layer that contributed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeOrigin {
    /// The node as it is written into `config.kdl`.
    pub node: String,
    /// The layer it came from.
    pub origin: Origin,
    /// File it came from; `None` for a built-in.
    pub path: Option<PathBuf>,
}

/// A profile with its `include`s resolved and merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The flattened configuration, exactly as [`Resolved::text`] parses.
    pub config: InstanceConfig,
    /// Canonical KDL of `config`, the text an instance is seeded with.
    pub text: String,
    /// Every node of `text`, in order, with where it came from.
    pub origins: Vec<NodeOrigin>,
}

/// The three profile layers, searched user first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolver {
    user_dir: PathBuf,
    system_dir: PathBuf,
}

/// A layer's identity while an `include` chain is being followed. Two
/// layers of the same profile name are different identities, which is
/// what lets `include "<own name>"` extend the layer below it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LayerId {
    File(PathBuf),
    BuiltIn(String),
}

impl LayerId {
    fn label(&self) -> String {
        match self {
            Self::File(p) => p.display().to_string(),
            Self::BuiltIn(n) => format!("built-in profile `{n}`"),
        }
    }
}

fn chain_labels(chain: &[LayerId], last: &LayerId) -> Vec<String> {
    chain
        .iter()
        .chain(std::iter::once(last))
        .map(LayerId::label)
        .collect()
}

impl Resolver {
    /// The layers as this host's environment describes them.
    pub fn new(env: &Env) -> Self {
        Self {
            user_dir: env.config_home.join("bubbler").join("profiles"),
            system_dir: env
                .profile_dir_override
                .clone()
                .unwrap_or_else(|| PathBuf::from(SYSTEM_DIR)),
        }
    }

    /// Directory of the user layer, where `bubbler profile edit` writes.
    pub fn user_dir(&self) -> &Path {
        &self.user_dir
    }

    /// Directory of the system layer.
    pub fn system_dir(&self) -> &Path {
        &self.system_dir
    }

    /// Path of `name` in the user layer, ready for an editor to open: the
    /// directory exists, and a name the user layer does not hold yet is
    /// written with a starting point. An existing file is never touched.
    pub fn edit_path(&self, name: &str) -> Result<PathBuf, ProfileError> {
        if !is_plain_name(name) {
            return Err(ProfileError::InvalidName(name.to_owned()));
        }
        let below = self.lookup(name)?.iter().any(|l| l.origin != Origin::User);
        fs::create_dir_all(&self.user_dir)
            .map_err(|e| ProfileError::Io(self.user_dir.clone(), e))?;
        let path = self.user_dir.join(format!("{name}.kdl"));
        // `create_new`: asking and writing are one operation, so a profile
        // that appears in between is opened as it is rather than replaced.
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => f
                .write_all(starter(name, below).as_bytes())
                .map_err(|e| ProfileError::Io(path.clone(), e))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(ProfileError::Io(path, e)),
        }
        Ok(path)
    }

    /// Every layer holding `name`, user first, then system, then built-in.
    /// A name that is not a plain profile name matches nothing rather than
    /// reaching a file outside the two directories.
    pub fn lookup(&self, name: &str) -> Result<Vec<Layer>, ProfileError> {
        let mut out = Vec::new();
        if !is_plain_name(name) {
            return Ok(out);
        }
        let file = format!("{name}.kdl");
        for (origin, dir) in [
            (Origin::User, &self.user_dir),
            (Origin::System, &self.system_dir),
        ] {
            let path = dir.join(&file);
            match config::read_bounded(&path) {
                Ok(text) => out.push(Layer {
                    name: name.to_owned(),
                    origin,
                    path: Some(path),
                    text,
                }),
                // A layer past the parser's bound is refused as the
                // parser refuses it, named by the file it was read
                // from, since that is the layer nothing below can fix.
                Err(ReadError::TooLarge(source)) => {
                    return Err(ProfileError::Parse {
                        origin: path.display().to_string(),
                        source,
                    });
                }
                Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
                Err(ReadError::Io(e)) => return Err(ProfileError::Io(path, e)),
            }
        }
        if let Some(text) = lookup(name) {
            out.push(Layer {
                name: name.to_owned(),
                origin: Origin::BuiltIn,
                path: None,
                text: text.to_owned(),
            });
        }
        Ok(out)
    }

    /// Every profile name any layer holds, sorted, each with the layer it
    /// resolves to. A name several layers hold is listed once.
    pub fn list(&self) -> Result<Vec<Entry>, ProfileError> {
        let mut out: Vec<Entry> = Vec::new();
        let mut push = |name: String, origin: Origin, path: Option<PathBuf>| {
            if !out.iter().any(|e| e.name == name) {
                out.push(Entry { name, origin, path });
            }
        };
        for (origin, dir) in [
            (Origin::User, &self.user_dir),
            (Origin::System, &self.system_dir),
        ] {
            for name in names_in(dir)? {
                let path = dir.join(format!("{name}.kdl"));
                push(name, origin, Some(path));
            }
        }
        for name in NAMES {
            push((*name).to_owned(), Origin::BuiltIn, None);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Resolve `name` through its layers and `include`s into one flattened
    /// configuration.
    pub fn resolve(&self, name: &str) -> Result<Resolved, ProfileError> {
        let mut acc = Merged::default();
        let mut chain = Vec::new();
        let mut done = Vec::new();
        self.expand(name, 0, &mut Visit::Merge(&mut acc), &mut chain, &mut done)?;
        acc.finish(name)
    }

    /// Every layer [`Resolver::resolve`] would merge, in merge order.
    /// A layer whose nodes the parser rejects is still returned: the
    /// linter has more to say about such a file than "it does not parse",
    /// and the layers under it are reached through its `include` nodes.
    pub fn layers(&self, name: &str) -> Result<Vec<Layer>, ProfileError> {
        let mut out = Vec::new();
        let mut chain = Vec::new();
        let mut done = Vec::new();
        self.expand(
            name,
            0,
            &mut Visit::Collect(&mut out),
            &mut chain,
            &mut done,
        )?;
        Ok(out)
    }

    /// Visit the `skip`th layer of `name`, its `include`s first. `done`
    /// carries the layers already visited across the whole traversal.
    fn expand(
        &self,
        name: &str,
        skip: usize,
        visit: &mut Visit<'_>,
        chain: &mut Vec<LayerId>,
        done: &mut Vec<LayerId>,
    ) -> Result<(), ProfileError> {
        let layers = self.lookup(name)?;
        let below = layers.len().saturating_sub(skip + 1);
        let Some(layer) = layers.into_iter().nth(skip) else {
            return Err(ProfileError::NotFound(name.to_owned()));
        };
        let label = layer.label();
        let id = match &layer.path {
            Some(p) => LayerId::File(p.clone()),
            None => LayerId::BuiltIn(name.to_owned()),
        };
        if chain.contains(&id) {
            return Err(ProfileError::Cycle(chain_labels(chain, &id)));
        }
        // A layer two branches both include is visited once, at the first
        // place it is reached: merging it again would put its nodes over
        // the nearer layer that included it, and a diamond of includes
        // would cost a re-read per path through it.
        if done.contains(&id) {
            return Ok(());
        }
        if chain.len() >= MAX_DEPTH {
            return Err(ProfileError::TooDeep(chain_labels(chain, &id)));
        }
        let collecting = matches!(visit, Visit::Collect(_));
        let raw = match config::parse_profile(&layer.text) {
            Ok(raw) => Some(raw),
            Err(source) if !collecting => {
                return Err(ProfileError::Parse {
                    origin: label,
                    source,
                });
            }
            Err(_) => None,
        };
        let includes = match &raw {
            Some(raw) => raw.includes.clone(),
            // A layer the parser rejects still names the layers under it,
            // and a caller that collects has to reach them before it can
            // say what is wrong where.
            None => includes_of(&layer.text).map_err(|source| ProfileError::Parse {
                origin: label.clone(),
                source,
            })?,
        };
        chain.push(id);
        for inc in &includes {
            // `include "<own name>"` names the layer below this one, which
            // is how a user profile extends the built-in of the same name
            // instead of forking it.
            if inc != name {
                self.expand(inc, 0, visit, chain, done)?;
                continue;
            }
            // Saying so beats `NotFound` on a name the file itself has:
            // the profile exists, it is this layer, and there is nothing
            // under it to extend.
            if below == 0 {
                return Err(ProfileError::SelfIncludeAtBottom(label));
            }
            self.expand(inc, skip + 1, visit, chain, done)?;
        }
        match visit {
            Visit::Merge(acc) => {
                let src = Src {
                    origin: layer.origin,
                    path: layer.path.clone(),
                    label,
                };
                // `None` only where the arm above returned already.
                if let Some(raw) = &raw {
                    acc.merge(raw, &src)?;
                }
            }
            Visit::Collect(out) => out.push(layer),
        }
        if let Some(id) = chain.pop() {
            done.push(id);
        }
        Ok(())
    }
}

/// What a traversal does with each layer it reaches.
enum Visit<'a> {
    /// Merge it into the flattened configuration.
    Merge(&'a mut Merged),
    /// Keep it as it was read, for a caller that reads it itself.
    Collect(&'a mut Vec<Layer>),
}

/// The `include` names of a layer whose nodes the parser rejected, read
/// straight from its KDL. Only the shape `parse_profile` accepts is
/// followed, so a malformed `include` node names no layer at all rather
/// than the wrong one.
fn includes_of(text: &str) -> Result<Vec<String>, ConfigError> {
    let doc = config::parse_document(text)?;
    Ok(doc
        .nodes()
        .iter()
        .filter(|n| n.name().value() == "include" && n.children().is_none())
        .filter_map(|n| match n.entries() {
            [e] if e.name().is_none() => e.value().as_string(),
            _ => None,
        })
        .map(str::to_owned)
        .collect())
}

/// Profile names in `dir`: every readable `<name>.kdl` whose name is a
/// plain profile name. A missing directory holds none.
fn names_in(dir: &Path) -> Result<Vec<String>, ProfileError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ProfileError::Io(dir.to_path_buf(), e)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| ProfileError::Io(dir.to_path_buf(), e))?;
        if let Some(name) = entry
            .file_name()
            .to_str()
            .and_then(|f| f.strip_suffix(".kdl"))
            .filter(|n| is_plain_name(n))
            .map(str::to_owned)
            && entry.path().is_file()
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// What a new user profile holds when no layer below carries the name:
/// the same commented examples the `generic` profile is written with. An
/// empty file would say nothing about what a profile may grant.
const TEMPLATE: &str = "\
// Grants a new instance is seeded with, e.g.:
//   wayland
//   network
//   home-share \"Downloads\" mode=rw
// and a default command:
//   command \"foot\"
";

/// The text `edit_path` writes for a profile the user layer does not hold
/// yet: an `include` of the layer below, so editing extends the shipped
/// profile instead of forking it, or [`TEMPLATE`] when there is none.
fn starter(name: &str, below: bool) -> String {
    // The name passed the profile name grammar, so it holds no quote,
    // backslash or newline that would need escaping here.
    let body = if below {
        format!("include \"{name}\"\n")
    } else {
        TEMPLATE.to_owned()
    };
    format!("{PROFILE_HEADER}{name} (user layer)\n{body}")
}

/// The flattened profile as `bubbler profile show` prints it: the header
/// a seeded `config.kdl` carries, then every node under a `// from:`
/// comment naming the layer that contributed it. Consecutive nodes from
/// one layer share the comment. Lines are `OsString` because a profile
/// path need not be UTF-8.
pub fn show(name: &str, resolved: &Resolved) -> Vec<OsString> {
    let mut out = vec![OsString::from(format!("{PROFILE_HEADER}{name}"))];
    let mut last: Option<&NodeOrigin> = None;
    for node in &resolved.origins {
        if last.is_none_or(|p| (p.origin, &p.path) != (node.origin, &node.path)) {
            let mut line = OsString::from("// from: ");
            match &node.path {
                Some(p) => line.push(p),
                None => line.push("built-in"),
            }
            out.push(line);
        }
        out.push(OsString::from(&node.node));
        last = Some(node);
    }
    out
}

/// The layer one merged node came from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Src {
    origin: Origin,
    path: Option<PathBuf>,
    label: String,
}

/// Layers merged so far, each item paired with the layer that put it
/// there. Included layers merge first, so a later item is the more
/// specific one.
#[derive(Debug, Default)]
struct Merged {
    services: Vec<(Service, Src)>,
    env: Vec<(String, String, Src)>,
    tmp: Option<(TmpSize, Src)>,
    tty: Option<(TtyMode, Src)>,
    userns: Option<(Userns, Src)>,
    seccomp: SeccompConfig,
    seccomp_src: Option<Src>,
    command: Option<(Vec<OsString>, Src)>,
    desktop: Option<(String, Src)>,
    lint_allows: Vec<(LintAllow, Src)>,
    disabled: Vec<(Disabled, Src)>,
}

impl Merged {
    fn merge(&mut self, raw: &RawProfile, src: &Src) -> Result<(), ProfileError> {
        for svc in &raw.config.services {
            self.add_service(svc, src)?;
        }
        // Union by id, the later layer's reason winning, so a profile
        // that includes another can restate why it accepts a finding
        // without the included layer's wording overriding it.
        for allow in &raw.config.lint_allows {
            match self.lint_allows.iter_mut().find(|(a, _)| a.id == allow.id) {
                Some(slot) => *slot = (allow.clone(), src.clone()),
                None => self.lint_allows.push((allow.clone(), src.clone())),
            }
        }
        // Kept as written, layer by layer, and never merged with one
        // another or with a grant: a `/-` line grants nothing, so there
        // is no conflict between two of them to resolve.
        for entry in &raw.config.disabled {
            self.disabled.push((entry.clone(), src.clone()));
        }
        for (key, value) in &raw.config.env {
            match self.env.iter_mut().find(|(k, _, _)| k == key) {
                Some(slot) => *slot = (key.clone(), value.clone(), src.clone()),
                None => self.env.push((key.clone(), value.clone(), src.clone())),
            }
        }
        // One cap, not a set: the including layer replaces it.
        if let Some(size) = raw.config.tmp {
            self.tmp = Some((size, src.clone()));
        }
        if raw.tty_set {
            self.tty = Some((raw.config.tty, src.clone()));
        }
        // A restriction, not a grant: the including layer decides it, the
        // same way `tty` works, so a profile can lift what it includes.
        if raw.userns_set {
            self.userns = Some((raw.config.userns, src.clone()));
        }
        if let Some(argv) = &raw.config.command {
            self.command = Some((argv.clone(), src.clone()));
        }
        // One file, not a set: the including layer replaces it, the way
        // it replaces the command the entry would launch.
        if let Some(name) = &raw.config.desktop {
            self.desktop = Some((name.clone(), src.clone()));
        }
        let sec = &raw.config.seccomp;
        if *sec != SeccompConfig::default() {
            for name in &sec.allow {
                if !self.seccomp.allow.contains(name) {
                    self.seccomp.allow.push(name.clone());
                }
            }
            // Denials are unioned as written, not by syscall: two layers
            // denying the same call with different errnos both deny it.
            for rule in &sec.deny {
                if !self.seccomp.deny.contains(rule) {
                    self.seccomp.deny.push(rule.clone());
                }
            }
            self.seccomp.disable |= sec.disable;
            self.seccomp_src = Some(src.clone());
        }
        Ok(())
    }

    /// Add one grant. Repeats of the same grant collapse; a share of the
    /// same path in two modes is a conflict rather than a silent choice.
    /// Every variant is listed: a new grant must be given a merge rule
    /// here, since collapsing one that carries a mode would pick a
    /// privilege level nobody wrote.
    fn add_service(&mut self, svc: &Service, src: &Src) -> Result<(), ProfileError> {
        match svc {
            Service::HomeShare { .. } => {
                if self.holds_share(svc, src, "home-share", home_share)? {
                    return Ok(());
                }
            }
            Service::PathShare { .. } => {
                if self.holds_share(svc, src, "path-share", path_share)? {
                    return Ok(());
                }
            }
            Service::AppRuntime { .. } => {
                if self.holds_share(svc, src, "app-runtime", app_runtime)? {
                    return Ok(());
                }
            }
            Service::Dbus { rules } => {
                if let Some((held_rules, held_src)) =
                    self.services.iter_mut().find_map(|(s, src)| match s {
                        Service::Dbus { rules: held } => Some((held, src)),
                        _ => None,
                    })
                {
                    union_bus_rules("dbus", held_rules, held_src, rules, src)?;
                    *held_src = src.clone();
                    return Ok(());
                }
            }
            Service::Network(cfg) => {
                if let Some((held, held_src)) =
                    self.services.iter_mut().find_map(|(s, src)| match s {
                        Service::Network(held) => Some((held, src)),
                        _ => None,
                    })
                {
                    // The mode is one choice and the including layer makes
                    // it; the children are grants of their own, so they add
                    // up rather than being replaced wholesale.
                    held.mode = cfg.mode;
                    // `outbound` is not the mode: a filter, once a layer
                    // has asked for one, is a floor. A layer above it
                    // that says nothing about `outbound` — which is every
                    // bare `network` node — would otherwise turn the
                    // filter off by omission, and widening a sandbox by
                    // omission is the one thing a merge must never do.
                    // Turning it *on* from above is fine, and unions.
                    if held.outbound == Outbound::Deny && cfg.outbound != Outbound::Deny {
                        return Err(ProfileError::Conflict {
                            node: "network".to_owned(),
                            a: format!("outbound \"deny\" in {}", held_src.label),
                            b: format!(
                                "a `network` node without it in {}; write \
                                 `outbound \"deny\"` there too, or do not include the layer \
                                 that filters",
                                src.label
                            ),
                        });
                    }
                    held.outbound = cfg.outbound;
                    for ip in &cfg.dns {
                        if !held.dns.contains(ip) {
                            held.dns.push(*ip);
                        }
                    }
                    for f in &cfg.forwards {
                        if !held.forwards.contains(f) {
                            held.forwards.push(*f);
                        }
                    }
                    for a in &cfg.allow_out {
                        if !held.allow_out.contains(a) {
                            held.allow_out.push(*a);
                        }
                    }
                    for a in &cfg.allow_hosts {
                        if !held.allow_hosts.contains(a) {
                            held.allow_hosts.push(a.clone());
                        }
                    }
                    held.no_ipv6 |= cfg.no_ipv6;
                    *held_src = src.clone();
                    return Ok(());
                }
            }
            Service::Gamepad { hidraw, uinput } => {
                if let Some((held_hidraw, held_uinput, held_src)) =
                    self.services.iter_mut().find_map(|(s, src)| match s {
                        Service::Gamepad {
                            hidraw: h,
                            uinput: u,
                        } => Some((h, u, src)),
                        _ => None,
                    })
                {
                    // Each property is a grant of its own, so they add up
                    // rather than the last layer deciding both.
                    *held_hidraw |= *hidraw;
                    *held_uinput |= *uinput;
                    *held_src = src.clone();
                    return Ok(());
                }
            }
            Service::Portals { children } => {
                if let Some((held, held_src)) =
                    self.services.iter_mut().find_map(|(s, src)| match s {
                        Service::Portals { children: held } => Some((held, src)),
                        _ => None,
                    })
                {
                    // Each child is a grant of its own, so they add up
                    // rather than the last layer deciding the set.
                    for c in children {
                        if !held.contains(c) {
                            held.push(*c);
                        }
                    }
                    *held_src = src.clone();
                    return Ok(());
                }
            }
            Service::Camera { nodes } => {
                if let Some((held_nodes, held_src)) =
                    self.services.iter_mut().find_map(|(s, src)| match s {
                        Service::Camera { nodes: held } => Some((held, src)),
                        _ => None,
                    })
                {
                    // The device half is a grant of its own on top of the
                    // portal, so it adds up rather than the last layer
                    // deciding it.
                    *held_nodes |= *nodes;
                    *held_src = src.clone();
                    return Ok(());
                }
            }
            Service::SystemBus { rules } => {
                if let Some((held_rules, held_src)) =
                    self.services.iter_mut().find_map(|(s, src)| match s {
                        Service::SystemBus { rules: held } => Some((held, src)),
                        _ => None,
                    })
                {
                    union_bus_rules("system-bus", held_rules, held_src, rules, src)?;
                    *held_src = src.clone();
                    return Ok(());
                }
            }
            Service::Mpris { .. } => {
                if let Some(slot) = self
                    .services
                    .iter_mut()
                    .find(|(s, _)| matches!(s, Service::Mpris { .. }))
                {
                    // A name, not a set: the including layer replaces it.
                    *slot = (svc.clone(), src.clone());
                    return Ok(());
                }
            }
            Service::Wayland(_) => {
                if let Some(slot) = self
                    .services
                    .iter_mut()
                    .find(|(s, _)| matches!(s, Service::Wayland(_)))
                {
                    // A mode, not a set: the including layer replaces it.
                    *slot = (svc.clone(), src.clone());
                    return Ok(());
                }
            }
            Service::X11(_) => {
                if let Some(slot) = self
                    .services
                    .iter_mut()
                    .find(|(s, _)| matches!(s, Service::X11(_)))
                {
                    // A server, not a set: the including layer replaces
                    // it, mode and window together.
                    *slot = (svc.clone(), src.clone());
                    return Ok(());
                }
            }
            Service::Dri { .. }
            | Service::Pipewire
            | Service::Pulseaudio
            | Service::Notify
            | Service::Tray
            | Service::A11y
            | Service::InputMethod
            | Service::Hidraw
            | Service::EtcShare { .. } => {
                if self.services.iter().any(|(s, _)| s == svc) {
                    return Ok(());
                }
            }
        }
        self.services.push((svc.clone(), src.clone()));
        Ok(())
    }

    /// Whether a share of the same kind and key is already merged, after
    /// checking the two modes agree. `same` selects the shares of one
    /// kind, so `home-share "x"` is never measured against
    /// `path-share "/x"`; `name` names the node when its key is not text
    /// a KDL file could hold. The key is a path for the two share nodes
    /// and the id for `app-runtime`.
    fn holds_share<K: PartialEq + ?Sized>(
        &self,
        svc: &Service,
        src: &Src,
        name: &str,
        same: fn(&Service) -> Option<(&K, ShareMode)>,
    ) -> Result<bool, ProfileError> {
        let Some((key, mode)) = same(svc) else {
            return Ok(false);
        };
        let held = self
            .services
            .iter()
            .find_map(|(s, s_src)| same(s).filter(|&(k, _)| k == key).map(|(_, m)| (m, s_src)));
        let Some((held_mode, held_src)) = held else {
            return Ok(false);
        };
        if held_mode != mode {
            let node = kdl_out::service(svc).unwrap_or_else(|_| name.to_owned());
            let node = kdl_out::without_mode(&node);
            return Err(mode_conflict(node, held_mode, held_src, mode, src));
        }
        Ok(true)
    }

    /// The flattened profile: its config, its canonical KDL, and where
    /// each node came from. The text is parsed back so what an instance is
    /// seeded with is known to be a config bubbler accepts, including the
    /// checks no single layer could make (`portals` needs `dbus`).
    fn finish(self, name: &str) -> Result<Resolved, ProfileError> {
        let bad = |source| ProfileError::Parse {
            origin: format!("flattened profile `{name}`"),
            source,
        };
        // Same order as `kdl_out::nodes`, so the nodes and their origins
        // stay in step; a unit test holds the two together.
        let mut origins = Vec::new();
        for (allow, src) in &self.lint_allows {
            origins.push((kdl_out::lint_allow(allow), src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::LintAllow(_)),
            name,
            &mut origins,
        )?;
        for (svc, src) in &self.services {
            origins.push((kdl_out::service(svc).map_err(bad)?, src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Service(_)),
            name,
            &mut origins,
        )?;
        for (key, value, src) in &self.env {
            origins.push((kdl_out::env(key, value), src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Env(_)),
            name,
            &mut origins,
        )?;
        if let Some((size, src)) = &self.tmp {
            origins.push((kdl_out::tmp(*size), src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Tmp(_)),
            name,
            &mut origins,
        )?;
        if let Some((mode, src)) = &self.tty
            && *mode != TtyMode::default()
        {
            origins.push((kdl_out::tty(*mode), src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Tty(_)),
            name,
            &mut origins,
        )?;
        if let Some((mode, src)) = &self.userns
            && *mode != Userns::default()
        {
            origins.push((kdl_out::userns(*mode), src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Userns(_)),
            name,
            &mut origins,
        )?;
        if let Some(src) = &self.seccomp_src
            && self.seccomp != SeccompConfig::default()
        {
            origins.push((kdl_out::seccomp(&self.seccomp), src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Seccomp(_)),
            name,
            &mut origins,
        )?;
        if let Some((name, src)) = &self.desktop {
            origins.push((kdl_out::desktop(name), src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Desktop(_)),
            name,
            &mut origins,
        )?;
        if let Some((argv, src)) = &self.command {
            origins.push((kdl_out::command(argv).map_err(bad)?, src));
        }
        kept(
            &self.disabled,
            |n| matches!(n, Node::Command(_)),
            name,
            &mut origins,
        )?;
        let mut text = String::new();
        for (node, _) in &origins {
            text.push_str(node);
            text.push('\n');
        }
        let config = config::parse(&text).map_err(bad)?;
        Ok(Resolved {
            config,
            text,
            origins: origins
                .into_iter()
                .map(|(node, src)| NodeOrigin {
                    node,
                    origin: src.origin,
                    path: src.path.clone(),
                })
                .collect(),
        })
    }
}

/// The `/-` lines of one section, written under the section's last node.
/// Where a layer wrote one is an index into that layer's own nodes, and
/// the merged section is not the one it counted, so the position a
/// single layer had is not carried across the merge.
fn kept<'a>(
    disabled: &'a [(Disabled, Src)],
    is: fn(&Node) -> bool,
    name: &str,
    origins: &mut Vec<(String, &'a Src)>,
) -> Result<(), ProfileError> {
    for (entry, src) in disabled.iter().filter(|(d, _)| is(&d.node)) {
        let node = kdl_out::disabled(entry).map_err(|source| ProfileError::Parse {
            origin: format!("flattened profile `{name}`"),
            source,
        })?;
        origins.push((node, src));
    }
    Ok(())
}

/// Union `rules` into `held`, dropping repeats. A name the two layers
/// give two policy levels is a conflict rather than a union: which level
/// applied would be layer order, and that is a privilege nobody wrote.
fn union_bus_rules(
    node: &str,
    held: &mut Vec<BusRule>,
    held_src: &Src,
    rules: &[BusRule],
    src: &Src,
) -> Result<(), ProfileError> {
    for r in rules {
        if let Some((name, level)) = r.policy()
            && let Some((_, was)) = held
                .iter()
                .filter_map(BusRule::policy)
                .find(|(n, _)| *n == name)
            && was != level
        {
            return Err(ProfileError::Conflict {
                node: node.to_owned(),
                a: format!("{was} \"{name}\" in {}", held_src.label),
                b: format!("{level} \"{name}\" in {}", src.label),
            });
        }
        if !held.contains(r) {
            held.push(r.clone());
        }
    }
    Ok(())
}

/// The path and mode of a `home-share` node, and nothing else.
fn home_share(s: &Service) -> Option<(&Path, ShareMode)> {
    match s {
        Service::HomeShare { path, mode } => Some((path, *mode)),
        _ => None,
    }
}

/// The path and mode of a `path-share` node, and nothing else.
fn path_share(s: &Service) -> Option<(&Path, ShareMode)> {
    match s {
        Service::PathShare { path, mode } => Some((path, *mode)),
        _ => None,
    }
}

/// The id and mode of an `app-runtime` node, and nothing else.
fn app_runtime(s: &Service) -> Option<(&str, ShareMode)> {
    match s {
        Service::AppRuntime { id, mode } => Some((id, *mode)),
        _ => None,
    }
}

fn mode_conflict(node: &str, a: ShareMode, a_src: &Src, b: ShareMode, b_src: &Src) -> ProfileError {
    ProfileError::Conflict {
        node: node.to_owned(),
        a: format!("mode={} in {}", kdl_out::share_mode(a), a_src.label),
        b: format!("mode={} in {}", kdl_out::share_mode(b), b_src.label),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BusRule, Clipboard, NestedX11, NetworkConfig, Portal, WaylandMode, X11Mode,
    };
    use crate::host::fake::{self, FakeHost};
    use crate::lint;

    fn env(root: &Path) -> Env {
        Env {
            home: root.join("home"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
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
            profile_dir_override: Some(root.join("system")),
            proxy_override: None,
            pasta_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
        }
    }

    /// A resolver over `<tmp>/config/bubbler/profiles` and `<tmp>/system`,
    /// with the named files written into them.
    fn resolver(tmp: &Path, user: &[(&str, &str)], system: &[(&str, &str)]) -> Resolver {
        let r = Resolver::new(&env(tmp));
        for (dir, files) in [
            (r.user_dir().to_path_buf(), user),
            (r.system_dir().to_path_buf(), system),
        ] {
            if files.is_empty() {
                continue;
            }
            fs::create_dir_all(&dir).unwrap();
            for (name, text) in files {
                fs::write(dir.join(format!("{name}.kdl")), text).unwrap();
            }
        }
        r
    }

    #[test]
    fn every_builtin_profile_resolves() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        for n in NAMES {
            let resolved = r.resolve(n).unwrap();
            assert_eq!(config::parse(&resolved.text).unwrap(), resolved.config);
            assert_eq!(resolved.text, kdl_out::render(&resolved.config).unwrap());
            assert!(
                resolved.origins.iter().all(|o| o.origin == Origin::BuiltIn),
                "{n}"
            );
        }
        // Gecko picks Wayland on its own since Firefox 121, so the profile
        // sets nothing. What it grants is pinned node for node in
        // `the_desktop_profiles_grant_what_their_apps_need_and_nothing_wider`.
        let ff = r.resolve("firefox").unwrap().config;
        assert!(ff.env.is_empty(), "{:?}", ff.env);
        // One grant per profile the app does not work without, so a
        // profile edited into something weaker is caught here and not by
        // whoever runs it.
        let cfg = |n: &str| r.resolve(n).unwrap().config;
        let home_share = |p: &str, mode| Service::HomeShare {
            path: PathBuf::from(p),
            mode,
        };
        assert!(
            cfg("mpv")
                .services
                .contains(&home_share("Videos", ShareMode::ReadOnly))
        );
        assert!(cfg("thunderbird").env.is_empty());
        assert!(
            cfg("libreoffice")
                .env
                .contains(&("SAL_USE_VCLPLUGIN".to_owned(), "gtk3".to_owned()))
        );
        assert!(cfg("vesktop").services.contains(&Service::Pulseaudio));
        let steam = cfg("steam");
        assert!(steam.services.contains(&Service::Gamepad {
            hidraw: false,
            uinput: false
        }));
        // steamwebhelper is an X11 client. The 32-bit runtime needs no
        // `seccomp` node any more: the default filter carries i386.
        assert_eq!(steam.seccomp, SeccompConfig::default());
        assert!(steam.services.contains(&Service::X11(X11Mode::Host)));
        // Neither gaming profile reaches a bus at all. The names each
        // client claims for itself, and the UDisks2 enumeration Wine
        // builds a drive list from, are opt-ins their headers spell out
        // node for node; a run starts without them.
        for n in ["steam", "lutris"] {
            let services = cfg(n).services;
            assert!(
                !services
                    .iter()
                    .any(|s| matches!(s, Service::Dbus { .. } | Service::SystemBus { .. })),
                "{n}: {services:?}"
            );
        }
        // `portals` would write /.flatpak-info, which Steam's own runtime
        // reads as being the unofficial Steam Flatpak: it then refuses to
        // start without a flatpak-portal service to talk to.
        assert!(
            !steam
                .services
                .iter()
                .any(|s| matches!(s, Service::Portals { .. }))
        );
        // ~/.steam is a directory of absolute symlinks into the host home:
        // shared, every one of them dangles inside and the account name
        // the synthetic passwd hides leaks in with them.
        assert!(
            !steam
                .services
                .iter()
                .any(|s| matches!(s, Service::HomeShare { .. })),
            "{:?}",
            steam.services
        );

        let lutris = cfg("lutris");
        assert!(lutris.services.contains(&Service::X11(X11Mode::Host)));
        assert_eq!(lutris.seccomp, SeccompConfig::default());
        assert!(
            lutris
                .services
                .contains(&home_share("Games", ShareMode::ReadWrite))
        );

        for n in [
            "chromium",
            "libreoffice",
            "lutris",
            "mpv",
            "steam",
            "thunderbird",
            "vesktop",
        ] {
            assert_eq!(cfg(n).command, Some(vec![OsString::from(n)]), "{n}");
        }

        assert!(matches!(r.resolve("nope"), Err(ProfileError::NotFound(n)) if n == "nope"));
    }

    /// The desktop profiles are bare: a display, what the application
    /// draws and plays with, and the one directory it works in. A bus,
    /// notifications, a tray icon and the rest are opt-ins their headers
    /// list node for node, so this pins the whole grant set of each
    /// rather than a few nodes of it.
    #[test]
    fn the_desktop_profiles_grant_what_their_apps_need_and_nothing_wider() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        let cfg = |n: &str| r.resolve(n).unwrap().config;
        let home_share = |p: &str, mode| Service::HomeShare {
            path: PathBuf::from(p),
            mode,
        };
        let wayland = || Service::Wayland(WaylandMode::default());
        let network = || Service::Network(NetworkConfig::default());

        // A password manager opens a database on a display. Everything it
        // does not carry — no network, no bus name, no HID device, no
        // runtime directory shared with a browser — is a comment in the
        // profile saying what adding it back buys and costs.
        let kp = cfg("keepassxc");
        assert_eq!(kp.command, Some(vec![OsString::from("keepassxc")]));
        assert_eq!(
            kp.services,
            vec![wayland(), home_share("Documents", ShareMode::ReadWrite)]
        );

        // An editor draws, fetches and opens files. The Secret Storage
        // API, which has no per-application partitioning and so hands
        // over every secret in the login keyring, is an opt-in.
        let code = cfg("code");
        assert_eq!(code.command, Some(vec![OsString::from("code")]));
        assert_eq!(
            code.services,
            vec![
                wayland(),
                Service::Dri { kms: false },
                network(),
                Service::Dbus { rules: Vec::new() },
                Service::Portals {
                    children: Vec::new(),
                },
                home_share("Projects", ShareMode::ReadWrite),
            ]
        );
        // Electron 42 picks the Wayland backend on its own, so an ozone
        // hint here would be a variable nobody reads.
        assert!(code.env.is_empty(), "{:?}", code.env);

        // A music player needs the sound socket its CEF layer opens and
        // the network it streams over; the media keys, the tray icon and
        // the power-save names are opt-ins.
        let sp = cfg("spotify");
        assert_eq!(sp.command, Some(vec![OsString::from("spotify")]));
        assert_eq!(
            sp.services,
            vec![
                wayland(),
                Service::Dri { kms: false },
                Service::Pulseaudio,
                network()
            ]
        );

        // A terminal makes its own ptys in the private devpts `--dev`
        // gives it; the host's is never bound, and it asks for nothing
        // else. The portal read it follows the colour scheme with is an
        // opt-in.
        let kitty = cfg("kitty");
        assert_eq!(kitty.command, Some(vec![OsString::from("kitty")]));
        assert_eq!(kitty.services, vec![wayland(), Service::Dri { kms: false }]);

        // The same shape for a chat client: a call takes sound and a
        // network, and screen sharing is `pipewire` plus `portals` on
        // top, as its header says.
        assert_eq!(
            cfg("vesktop").services,
            vec![
                wayland(),
                Service::Dri { kms: false },
                Service::Pulseaudio,
                network()
            ]
        );

        // A browser draws, plays, fetches, and saves what it downloads
        // into one directory; the portal is its file chooser and its
        // screen-share picker. The remote-instance bus name, the media
        // keys and the notifications are opt-ins, and the bus it does
        // carry holds no rule of its own.
        let ff = cfg("firefox");
        assert_eq!(
            ff.services,
            vec![
                wayland(),
                Service::Dri { kms: false },
                Service::Pulseaudio,
                network(),
                Service::Dbus { rules: Vec::new() },
                Service::Portals {
                    children: vec![Portal::ScreenCast],
                },
                home_share("Downloads", ShareMode::ReadWrite),
            ]
        );
        // Chromium needs the same set: the two differ in their opt-ins,
        // not in what it takes to run them.
        assert_eq!(cfg("chromium").services, ff.services);

        // Mail is a network and somewhere to save an attachment. Gecko
        // composites in software without `dri`, and the GPU, the portal
        // chooser and the new-mail notifications are opt-ins.
        assert_eq!(
            cfg("thunderbird").services,
            vec![
                wayland(),
                network(),
                home_share("Downloads", ShareMode::ReadWrite),
            ]
        );

        // A document editor is a display and the documents. It keeps one
        // `env` node, because bubbler clears the environment and VCL then
        // has nothing to autodetect from.
        let lo = cfg("libreoffice");
        assert_eq!(
            lo.services,
            vec![wayland(), home_share("Documents", ShareMode::ReadWrite)]
        );
        assert_eq!(
            lo.env,
            vec![("SAL_USE_VCLPLUGIN".to_owned(), "gtk3".to_owned())]
        );
    }

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
            // the run measures the grants and not this machine. This
            // also keeps `pulse.allow-module-loading` off, or every
            // `pulseaudio` grant would carry the daemon-default note.
            let tmp = tempfile::tempdir().unwrap();
            let e = env(tmp.path());
            let mut host = FakeHost::default().text(
                "/usr/share/pipewire/pipewire-pulse.conf",
                "pulse.properties = {\n    pulse.allow-module-loading = false\n}\n",
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
            };
            let report =
                lint::lint_profile(&ctx, &r, name).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(
                report
                    .findings
                    .iter()
                    .map(|f| format!("{}[{}]: {}", f.severity, f.id, f.message))
                    .collect::<Vec<_>>(),
                Vec::<String>::new(),
                "{name} with its opt-ins pasted in does not lint clean"
            );
        }
    }

    /// The `Stricter:` block in `claude-code`'s header is
    /// `claude-code-strict`'s own `lint-allow` and `network` node,
    /// written out for a reader to paste over the bare one. It sits five
    /// spaces in, which is where `opt_in_nodes` above reads prose and
    /// skips it — a lone `allow-host` line is not a config, so the
    /// paste-back test cannot be what holds the two files together.
    /// This is, and it compares the *text*: the comment over each group
    /// of names is the pruning instruction the header tells the reader
    /// to act on, and a comment corrected in one file only is the drift
    /// a comparison of parsed nodes would miss.
    #[test]
    fn the_stricter_paste_in_is_the_strict_profile_s_network_node() {
        let header = lookup("claude-code").expect("NAMES lists built-in profiles");
        // Everything commented under the heading, five spaces in: the
        // prose of that paragraph sits one space in and drops out here,
        // so what is left is the KDL a reader selects.
        let pasted: String = header
            .lines()
            .skip_while(|l| !l.starts_with("// Stricter:"))
            .map_while(|l| l.strip_prefix("//"))
            .filter_map(|body| body.strip_prefix("     "))
            .fold(String::new(), |mut out, line| {
                out.push_str(line);
                out.push('\n');
                out
            });
        assert!(pasted.starts_with("lint-allow "), "{pasted}");

        // The same slice of the profile: from its `lint-allow` to the
        // end of the `network` block.
        let strict = lookup("claude-code-strict").expect("NAMES lists built-in profiles");
        let from = strict
            .find("lint-allow ")
            .expect("the strict profile accepts the outbound-deny note");
        let to = strict[from..]
            .find("\n}\n")
            .expect("the strict profile's network node is a block")
            + from
            + "\n}\n".len();
        assert_eq!(pasted, strict[from..to]);

        // And it is a config, not only matching text.
        let node = |text: &str| {
            let cfg = config::parse(text).unwrap_or_else(|err| panic!("{text}\n{err}"));
            let network = cfg
                .services
                .iter()
                .find(|s| matches!(s, Service::Network(_)))
                .expect("both hold a network node")
                .clone();
            (network, cfg.lint_allows)
        };
        assert_eq!(node(&pasted), node(strict));
    }

    #[test]
    fn hidraw_written_in_two_layers_is_merged_into_one_node() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[],
            &[("app", "include \"base\"\nhidraw\n"), ("base", "hidraw\n")],
        );
        let resolved = r.resolve("app").unwrap();
        assert_eq!(resolved.config.services, vec![Service::Hidraw]);
        assert_eq!(resolved.text, "hidraw\n");
    }

    #[test]
    fn only_the_gaming_profiles_grant_x11_and_only_apps_without_a_nested_sandbox_disable_userns() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        let mut x11: Vec<&str> = Vec::new();
        let mut closed: Vec<&str> = Vec::new();
        for n in NAMES {
            let cfg = r.resolve(n).unwrap().config;
            if cfg.services.iter().any(|s| matches!(s, Service::X11(_))) {
                x11.push(n);
            }
            if cfg.userns == Userns::Disable {
                closed.push(n);
            }
        }
        // X11 gives a client the whole display: no profile gets it for
        // convenience, only the two whose apps have no Wayland path.
        assert_eq!(x11, ["lutris", "steam"]);
        // Proton, umu and pressure-vessel nest their own bubblewrap, and a
        // browser's, Electron's or CEF's inner sandbox is a user namespace
        // too; the door is shut only where nothing inside needs it. An
        // agent's own sandbox is the deliberate exception: bubbler is
        // the boundary, and the inner one warns and is skipped.
        assert_eq!(
            closed,
            [
                "agent",
                "alacritty",
                "claude-code",
                "claude-code-strict",
                "keepassxc",
                "kitty",
                "libreoffice",
                "mpv"
            ]
        );
    }

    #[test]
    fn the_user_layer_wins_over_system_and_built_in() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[("firefox", "network\n")],
            &[("firefox", "x11\n"), ("only-system", "dri\n")],
        );
        assert_eq!(
            r.resolve("firefox").unwrap().config.services,
            vec![Service::Network(NetworkConfig::default())]
        );
        assert_eq!(
            r.resolve("only-system").unwrap().config.services,
            vec![Service::Dri { kms: false }]
        );
        let entries = r.list().unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        // Every built-in, each named once however many layers hold it,
        // plus the one only the system layer has.
        let mut expected: Vec<&str> = NAMES.to_vec();
        expected.push("only-system");
        expected.sort_unstable();
        assert_eq!(names, expected);
        let by = |n: &str| entries.iter().find(|e| e.name == n).unwrap().clone();
        assert_eq!(by("firefox").origin, Origin::User);
        assert_eq!(by("firefox").path, Some(r.user_dir().join("firefox.kdl")));
        assert_eq!(by("only-system").origin, Origin::System);
        assert_eq!(by("alacritty").origin, Origin::BuiltIn);
        assert_eq!(by("alacritty").path, None);
    }

    #[test]
    fn a_layer_that_does_not_parse_is_an_error_naming_its_path() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[("firefox", "bogus\n")], &[]);
        let err = r.resolve("firefox").unwrap_err();
        let path = r.user_dir().join("firefox.kdl");
        let ProfileError::Parse { origin, source } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(origin, &path.display().to_string());
        // Never a fall-through to the built-in firefox, which parses. The
        // reason is the chained cause, not part of this message.
        assert!(
            source.to_string().contains("unknown node `bogus`"),
            "{source}"
        );
    }

    #[test]
    fn a_name_that_could_name_a_path_is_never_looked_up() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        fs::write(tmp.path().join("escape.kdl"), "network\n").unwrap();
        for bad in ["../escape", "/etc/passwd", "a/b", "", ".", "..", "-x"] {
            assert!(r.lookup(bad).unwrap().is_empty(), "{bad}");
            assert!(
                matches!(r.resolve(bad), Err(ProfileError::NotFound(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn include_of_the_own_name_extends_the_layer_below() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[(
                "firefox",
                "include \"firefox\"\nnetwork\nenv MOZ_ENABLE_WAYLAND=\"0\"\n",
            )],
            &[],
        );
        let resolved = r.resolve("firefox").unwrap();
        let cfg = &resolved.config;
        assert!(
            cfg.services
                .contains(&Service::Wayland(WaylandMode::default()))
        );
        assert!(
            cfg.services
                .contains(&Service::Network(NetworkConfig::default()))
        );
        // The including layer overrides by key, and says so.
        assert_eq!(
            cfg.env,
            vec![("MOZ_ENABLE_WAYLAND".to_owned(), "0".to_owned())]
        );
        let env_node = resolved
            .origins
            .iter()
            .find(|o| o.node.starts_with("env "))
            .unwrap();
        assert_eq!(env_node.origin, Origin::User);
        let wayland = resolved
            .origins
            .iter()
            .find(|o| o.node == "wayland")
            .unwrap();
        assert_eq!(wayland.origin, Origin::BuiltIn);
        // Self-include at the deepest layer has nothing below it, and
        // says that rather than calling a profile that exists unknown.
        let r = resolver(tmp.path(), &[("solo", "include \"solo\"\n")], &[]);
        let err = r.resolve("solo").unwrap_err();
        let ProfileError::SelfIncludeAtBottom(origin) = &err else {
            panic!("{err:?}")
        };
        assert!(origin.ends_with("solo.kdl"), "{origin}");
        assert!(err.to_string().contains("has no layer below"), "{err}");
    }

    /// A mode, not a set: the including layer decides it, and it may
    /// tighten as well as widen. A merge that only ever widened would
    /// hand the layer above a socket it did not ask for.
    #[test]
    fn wayland_mode_is_replaced_by_the_including_layer_in_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        for (base, app, want) in [
            (
                "wayland \"host\"\n",
                "include \"base\"\nwayland\n",
                WaylandMode::default(),
            ),
            (
                "wayland\n",
                "include \"base\"\nwayland \"host\"\n",
                WaylandMode::Host,
            ),
            // The gate travels with the mode: a layer that writes the
            // bare node over `clipboard="open"` gets the gate back,
            // rather than a node whose property came from below it.
            (
                "wayland clipboard=\"open\"\n",
                "include \"base\"\nwayland\n",
                WaylandMode::default(),
            ),
            (
                "wayland\n",
                "include \"base\"\nwayland clipboard=\"open\"\n",
                WaylandMode::Sandboxed {
                    clipboard: Clipboard::Open,
                },
            ),
        ] {
            let r = resolver(tmp.path(), &[("base", base), ("app", app)], &[]);
            let cfg = r.resolve("app").unwrap().config;
            assert_eq!(cfg.services, vec![Service::Wayland(want)], "{app}");
        }
    }

    /// A server, not a set: the including layer decides which one and
    /// what its window is, and it may tighten as well as widen. Merging
    /// the properties field by field would hand a layer a window no
    /// file asked for.
    #[test]
    fn x11_mode_is_replaced_by_the_including_layer_in_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        let full = NestedX11 {
            geometry: NestedX11::default().geometry,
            fullscreen: true,
            grab: false,
            wm: None,
        };
        // The display stack the nested server needs, in the layer below:
        // the requirement is on the flattened config, not on one file.
        let stack = "wayland\ndri\n";
        for (base, app, want) in [
            ("x11\n", "include \"base\"\nx11 \"host\"\n", X11Mode::Host),
            (
                "x11 \"host\"\n",
                "include \"base\"\nx11\n",
                X11Mode::Nested(NestedX11::default()),
            ),
            (
                "x11\n",
                "include \"base\"\nx11 fullscreen=#true\n",
                X11Mode::Nested(full),
            ),
        ] {
            let r = resolver(
                tmp.path(),
                &[("base", &format!("{stack}{base}")), ("app", app)],
                &[],
            );
            let cfg = r.resolve("app").unwrap().config;
            assert_eq!(
                cfg.services,
                vec![
                    Service::Wayland(WaylandMode::default()),
                    Service::Dri { kms: false },
                    Service::X11(want)
                ],
                "{app}"
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

    /// A merge that would grant a forward into a namespace the mode does
    /// not have is refused, rather than flattened into a config the
    /// parser would then reject on the next read.
    #[test]
    fn a_forward_merged_onto_the_host_mode_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[
                ("base", "network {\n    allow-port 80\n}\n"),
                ("app", "include \"base\"\nnetwork \"host\"\n"),
            ],
            &[],
        );
        assert!(matches!(r.resolve("app"), Err(ProfileError::Parse { .. })));
    }

    #[test]
    fn includes_resolve_depth_first_before_the_including_file() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[
                ("app", "include \"mid\"\ncommand \"app\"\ntty \"none\"\n"),
                ("mid", "include \"base\"\nnetwork\ncommand \"mid\"\n"),
                ("base", "wayland\ncommand \"base\"\ntty \"passthrough\"\n"),
            ],
            &[],
        );
        let cfg = r.resolve("app").unwrap().config;
        assert_eq!(
            cfg.services,
            vec![
                Service::Wayland(WaylandMode::default()),
                Service::Network(NetworkConfig::default())
            ]
        );
        assert_eq!(cfg.command.unwrap(), vec![OsString::from("app")]);
        assert_eq!(cfg.tty, TtyMode::None);
        // A layer without a `tty` node leaves the one below alone.
        let r = resolver(
            tmp.path(),
            &[("app", "include \"base\"\n"), ("base", "tty \"none\"\n")],
            &[],
        );
        assert_eq!(r.resolve("app").unwrap().config.tty, TtyMode::None);
    }

    #[test]
    fn the_desktop_entry_is_one_name_the_including_layer_decides() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[
                (
                    "app",
                    "include \"base\"\ncommand \"thunderbird\"\n\
                     desktop \"org.mozilla.Thunderbird.desktop\"\n",
                ),
                ("base", "desktop \"base.desktop\"\n"),
            ],
            &[],
        );
        let resolved = r.resolve("app").unwrap();
        // One file, not a set: the including layer replaces it, the way
        // `command` works.
        assert_eq!(
            resolved.config.desktop.as_deref(),
            Some("org.mozilla.Thunderbird.desktop")
        );
        // The flattened text and its per-node origins are the emitter's
        // order, so the hint lands with the nodes rather than beside them.
        assert_eq!(
            resolved.text,
            kdl_out::render(&resolved.config).unwrap(),
            "{}",
            resolved.text
        );
        assert!(
            resolved
                .origins
                .iter()
                .any(|o| o.node == "desktop \"org.mozilla.Thunderbird.desktop\""),
            "{:?}",
            resolved.origins
        );

        // A layer without the node leaves the one below alone.
        let r = resolver(
            tmp.path(),
            &[
                ("app", "include \"base\"\nwayland\n"),
                ("base", "desktop \"base.desktop\"\n"),
            ],
            &[],
        );
        assert_eq!(
            r.resolve("app").unwrap().config.desktop.as_deref(),
            Some("base.desktop")
        );
    }

    #[test]
    fn the_tmp_cap_is_one_size_the_including_layer_decides() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[
                ("app", "include \"base\"\ntmp size=\"512M\"\n"),
                ("base", "tmp size=\"8G\"\n/-tmp size=\"1G\"\n"),
            ],
            &[],
        );
        let resolved = r.resolve("app").unwrap();
        // One cap, not a set: the including layer replaces it, up or down.
        assert_eq!(resolved.config.tmp, Some(TmpSize(512 * 1024 * 1024)));
        assert_eq!(
            resolved.text,
            kdl_out::render(&resolved.config).unwrap(),
            "{}",
            resolved.text
        );
        let nodes: Vec<&str> = resolved.origins.iter().map(|o| o.node.as_str()).collect();
        assert_eq!(nodes, vec!["tmp size=\"512M\"", "/-tmp size=\"1G\""]);

        // A layer without the node leaves the one below alone.
        let r = resolver(
            tmp.path(),
            &[
                ("app", "include \"base\"\nwayland\n"),
                ("base", "tmp size=\"8G\"\n"),
            ],
            &[],
        );
        assert_eq!(
            r.resolve("app").unwrap().config.tmp,
            Some(TmpSize(8 * 1024 * 1024 * 1024))
        );
    }

    #[test]
    fn userns_follows_the_including_layer_and_gamepad_properties_are_unioned() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[
                (
                    "app",
                    "include \"base\"\nuserns \"allow\"\ngamepad uinput=#true\n",
                ),
                ("base", "userns \"disable\"\ngamepad hidraw=#true\n"),
            ],
            &[],
        );
        let cfg = r.resolve("app").unwrap().config;
        // A restriction, so the including layer decides it outright.
        assert_eq!(cfg.userns, Userns::Allow);
        // Device classes are grants, and grants only ever add up.
        assert_eq!(
            cfg.services,
            vec![Service::Gamepad {
                hidraw: true,
                uinput: true
            }]
        );

        // A layer without the node leaves the one below alone.
        let r = resolver(
            tmp.path(),
            &[
                ("app", "include \"base\"\ngamepad\n"),
                ("base", "userns \"disable\"\ngamepad hidraw=#true\n"),
            ],
            &[],
        );
        let resolved = r.resolve("app").unwrap();
        assert_eq!(resolved.config.userns, Userns::Disable);
        assert_eq!(
            resolved.config.services,
            vec![Service::Gamepad {
                hidraw: true,
                uinput: false
            }]
        );
        assert!(
            resolved.text.contains("userns \"disable\""),
            "{}",
            resolved.text
        );
        assert!(
            resolved.text.contains("gamepad hidraw=#true"),
            "{}",
            resolved.text
        );
        // The flattened text and the origins are built from two lists in
        // the same order, so the new node must sit in both the same way.
        assert_eq!(resolved.text, kdl_out::render(&resolved.config).unwrap());
    }

    #[test]
    fn a_cycle_is_an_error_naming_the_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[("a", "include \"b\"\n"), ("b", "include \"a\"\n")],
            &[],
        );
        let err = r.resolve("a").unwrap_err();
        let ProfileError::Cycle(chain) = &err else {
            panic!("{err:?}")
        };
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], chain[2]);
        assert!(err.to_string().contains("a.kdl -> "), "{err}");
    }

    #[test]
    fn nesting_stops_at_the_depth_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let deep: Vec<(String, String)> = (0..MAX_DEPTH + 1)
            .map(|i| (format!("p{i}"), format!("include \"p{}\"\n", i + 1)))
            .collect();
        let mut files: Vec<(&str, &str)> =
            deep.iter().map(|(n, t)| (n.as_str(), t.as_str())).collect();
        files.push(("p9", "wayland\n"));
        let r = resolver(tmp.path(), &files, &[]);
        let err = r.resolve("p0").unwrap_err();
        let ProfileError::TooDeep(chain) = &err else {
            panic!("{err:?}")
        };
        assert_eq!(chain.len(), MAX_DEPTH + 1);
        // A chain of exactly MAX_DEPTH layers still resolves.
        assert!(r.resolve("p2").is_ok());
    }

    #[test]
    fn grants_union_and_the_same_share_in_two_modes_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[(
                "a",
                "include \"b\"\nwayland\nhome-share \"D\"\nhome-share \"E\" mode=rw\n\
                 path-share \"/kioxia/Steam\"\netc-share \"vulkan\"\n",
            )],
            &[(
                "b",
                "wayland\nnetwork\nhome-share \"D\"\nhome-share \"E\" mode=rw\n\
                 path-share \"/kioxia/Steam\"\netc-share \"vulkan\"\n",
            )],
        );
        let cfg = r.resolve("a").unwrap().config;
        assert_eq!(
            cfg.services,
            vec![
                Service::Wayland(WaylandMode::default()),
                Service::Network(NetworkConfig::default()),
                Service::HomeShare {
                    path: "D".into(),
                    mode: ShareMode::ReadOnly
                },
                Service::HomeShare {
                    path: "E".into(),
                    mode: ShareMode::ReadWrite
                },
                Service::PathShare {
                    path: "/kioxia/Steam".into(),
                    mode: ShareMode::ReadOnly
                },
                Service::EtcShare {
                    name: "vulkan".into()
                },
            ]
        );

        let r = resolver(
            tmp.path(),
            &[("a", "include \"b\"\nhome-share \"D\" mode=rw\n")],
            &[("b", "home-share \"D\"\n")],
        );
        let err = r.resolve("a").unwrap_err();
        let ProfileError::Conflict { node, a, b } = &err else {
            panic!("{err:?}")
        };
        // The header names the node, never one of the two modes: it is
        // the modes that are in dispute, and `a`/`b` below say them.
        assert_eq!(node, "home-share \"D\"");
        assert!(a.contains("mode=ro") && a.contains("b.kdl"), "{a}");
        assert!(b.contains("mode=rw") && b.contains("a.kdl"), "{b}");

        // `path-share` carries a mode too, so it needs the same rule: a
        // layer that collapsed the pair would hand out `rw` or take it
        // away, and neither is what either file asked for.
        let r = resolver(
            tmp.path(),
            &[("a", "include \"b\"\npath-share \"/kioxia/Steam\"\n")],
            &[("b", "path-share \"/kioxia/Steam\" mode=rw\n")],
        );
        let err = r.resolve("a").unwrap_err();
        let ProfileError::Conflict { node, a, b } = &err else {
            panic!("{err:?}")
        };
        assert_eq!(node, "path-share \"/kioxia/Steam\"");
        assert!(a.contains("mode=rw") && a.contains("b.kdl"), "{a}");
        assert!(b.contains("mode=ro") && b.contains("a.kdl"), "{b}");

        // `app-runtime` is keyed by its id rather than a path, and one
        // id is one directory: two modes for it would decide by layer
        // order whether the sandbox may serve sockets there.
        let r = resolver(
            tmp.path(),
            &[(
                "a",
                "include \"b\"\napp-runtime \"org.keepassxc.KeePassXC\" mode=rw\n\
                 app-runtime \"org.example.Other\"\n",
            )],
            &[("b", "app-runtime \"org.keepassxc.KeePassXC\" mode=rw\n")],
        );
        // The same id in the same mode is one grant, and an unrelated id
        // beside it is a second.
        assert_eq!(
            r.resolve("a").unwrap().config.services,
            vec![
                Service::AppRuntime {
                    id: "org.keepassxc.KeePassXC".to_owned(),
                    mode: ShareMode::ReadWrite
                },
                Service::AppRuntime {
                    id: "org.example.Other".to_owned(),
                    mode: ShareMode::ReadOnly
                },
            ]
        );
        let r = resolver(
            tmp.path(),
            &[(
                "a",
                "include \"b\"\napp-runtime \"org.keepassxc.KeePassXC\"\n",
            )],
            &[("b", "app-runtime \"org.keepassxc.KeePassXC\" mode=rw\n")],
        );
        let err = r.resolve("a").unwrap_err();
        let ProfileError::Conflict { node, a, b } = &err else {
            panic!("{err:?}")
        };
        assert_eq!(node, "app-runtime \"org.keepassxc.KeePassXC\"");
        assert!(a.contains("mode=rw") && a.contains("b.kdl"), "{a}");
        assert!(b.contains("mode=ro") && b.contains("a.kdl"), "{b}");
    }

    #[test]
    fn two_layers_may_not_grant_one_bus_name_two_policies() {
        let tmp = tempfile::tempdir().unwrap();
        for (node, upper, lower) in [
            (
                "dbus",
                "dbus { see \"org.a.B\" }",
                "dbus { talk \"org.a.B\" }",
            ),
            (
                "system-bus",
                "system-bus { talk \"org.a.B\" }",
                "system-bus { see \"org.a.B\" }",
            ),
        ] {
            let r = resolver(
                tmp.path(),
                &[("a", &format!("include \"b\"\n{upper}\n"))],
                &[("b", &format!("{lower}\n"))],
            );
            let err = r.resolve("a").unwrap_err();
            let ProfileError::Conflict { node: n, a, b } = &err else {
                panic!("{err:?}")
            };
            assert_eq!(n, node);
            assert!(a.contains("org.a.B") && a.contains("b.kdl"), "{a}");
            assert!(b.contains("org.a.B") && b.contains("a.kdl"), "{b}");
        }
        // The narrowing rules are not policies: one layer may see a name
        // the other calls one method on.
        let r = resolver(
            tmp.path(),
            &[("a", "include \"b\"\nsystem-bus { see \"org.a.B\" }\n")],
            &[("b", "system-bus { call \"org.a.B=c.D@/e\" }\n")],
        );
        r.resolve("a").unwrap();
    }

    #[test]
    fn system_bus_rules_union_across_layers_and_stay_off_the_session_bus() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[(
                "a",
                "include \"b\"\ndbus { talk \"org.a.B\" }\n                 system-bus { talk \"org.freedesktop.UPower\"; see \"org.freedesktop.NM\" }\n",
            )],
            &[(
                "b",
                "system-bus { talk \"org.freedesktop.UPower\"; talk \"org.freedesktop.UDisks2\" }\n",
            )],
        );
        let cfg = &r.resolve("a").unwrap().config;
        let Some(Service::SystemBus { rules }) = cfg
            .services
            .iter()
            .find(|s| matches!(s, Service::SystemBus { .. }))
        else {
            panic!("{:?}", cfg.services)
        };
        // The lower layer first, and a rule both layers wrote once.
        assert_eq!(
            *rules,
            vec![
                BusRule::Talk("org.freedesktop.UPower".to_owned()),
                BusRule::Talk("org.freedesktop.UDisks2".to_owned()),
                BusRule::See("org.freedesktop.NM".to_owned()),
            ]
        );
        // The two nodes are separate grants; neither takes the other's
        // rules.
        let Some(Service::Dbus { rules }) = cfg
            .services
            .iter()
            .find(|s| matches!(s, Service::Dbus { .. }))
        else {
            panic!("{:?}", cfg.services)
        };
        assert_eq!(*rules, vec![BusRule::Talk("org.a.B".to_owned())]);
    }

    #[test]
    fn dbus_rules_union_and_mpris_and_seccomp_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[(
                "a",
                "include \"b\"\ndbus { talk \"org.a.B\"; own \"org.x.Y\" }\nmpris name=\"top\"\n\
                 seccomp { allow \"keyctl\"; deny \"unshare\" errno=\"ENOSYS\" }\n",
            )],
            &[(
                "b",
                "dbus { talk \"org.a.B\"; see \"org.c.D\" }\nmpris name=\"below\"\nnotify\n\
                 seccomp { allow \"keyctl\"; deny \"unshare\"; disable }\n",
            )],
        );
        let resolved = r.resolve("a").unwrap();
        let cfg = &resolved.config;
        let Some(Service::Dbus { rules }) = cfg
            .services
            .iter()
            .find(|s| matches!(s, Service::Dbus { .. }))
        else {
            panic!("{:?}", cfg.services)
        };
        assert_eq!(
            *rules,
            vec![
                BusRule::Talk("org.a.B".to_owned()),
                BusRule::See("org.c.D".to_owned()),
                BusRule::Own("org.x.Y".to_owned()),
            ]
        );
        assert!(cfg.services.contains(&Service::Mpris {
            name: "top".to_owned()
        }));
        assert_eq!(
            cfg.services
                .iter()
                .filter(|s| matches!(s, Service::Mpris { .. }))
                .count(),
            1
        );
        assert_eq!(cfg.seccomp.allow, vec!["keyctl".to_owned()]);
        assert_eq!(cfg.seccomp.deny.len(), 2);
        assert!(cfg.seccomp.disable);
        assert_eq!(resolved.text, kdl_out::render(&resolved.config).unwrap());
    }

    #[test]
    fn a_bundle_needs_dbus_in_the_merged_result_not_in_every_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[("a", "include \"b\"\nnotify\n"), ("lone", "notify\n")],
            &[("b", "dbus\n")],
        );
        assert!(
            r.resolve("a")
                .unwrap()
                .config
                .services
                .contains(&Service::Notify)
        );
        let err = r.resolve("lone").unwrap_err();
        assert!(
            matches!(&err, ProfileError::Parse { origin, .. } if origin.contains("flattened")),
            "{err:?}"
        );
    }

    #[test]
    fn a_layer_two_branches_include_is_merged_once_at_its_first_place() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[
                ("a", "include \"b\"\ninclude \"c\"\n"),
                ("b", "include \"base\"\nnetwork\ncommand \"b\"\n"),
                ("c", "include \"base\"\ndri\n"),
                ("base", "wayland\ncommand \"base\"\n"),
            ],
            &[],
        );
        let cfg = r.resolve("a").unwrap().config;
        assert_eq!(
            cfg.services,
            vec![
                Service::Wayland(WaylandMode::default()),
                Service::Network(NetworkConfig::default()),
                Service::Dri { kms: false }
            ]
        );
        // `base` merged under `b`, not again between `b` and `c`, where it
        // would have taken the command back.
        assert_eq!(cfg.command.unwrap(), vec![OsString::from("b")]);
    }

    #[test]
    fn a_missing_include_names_the_profile_it_could_not_find() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[("a", "include \"gone\"\n")], &[]);
        assert!(matches!(r.resolve("a"), Err(ProfileError::NotFound(n)) if n == "gone"));
    }

    /// `show` as a single string, for tests whose paths are all UTF-8.
    fn shown(name: &str, r: &Resolver) -> String {
        let mut out = String::new();
        for line in show(name, &r.resolve(name).unwrap()) {
            out.push_str(&line.into_string().unwrap());
            out.push('\n');
        }
        out
    }

    #[test]
    fn show_names_the_layer_each_run_of_nodes_came_from() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[("a", "include \"b\"\nnetwork\ncommand \"a\"\n")],
            &[("b", "wayland\ndri\n")],
        );
        assert_eq!(
            shown("a", &r),
            format!(
                "// bubbler profile: a\n\
                 // from: {system}/b.kdl\n\
                 wayland\n\
                 dri\n\
                 // from: {user}/a.kdl\n\
                 network\n\
                 command \"a\"\n",
                system = r.system_dir().display(),
                user = r.user_dir().display(),
            )
        );
    }

    #[test]
    fn show_of_a_built_in_says_so_and_a_profile_granting_nothing_is_its_header() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        assert_eq!(shown("generic", &r), "// bubbler profile: generic\n");
        let alacritty = shown("alacritty", &r);
        assert!(
            alacritty.starts_with("// bubbler profile: alacritty\n// from: built-in\n"),
            "{alacritty}"
        );
        assert_eq!(alacritty.matches("// from:").count(), 1, "{alacritty}");
        // Every run of the same layer is one comment, and the nodes are
        // the flattened text itself.
        let resolved = r.resolve("alacritty").unwrap();
        let nodes: String =
            alacritty
                .lines()
                .filter(|l| !l.starts_with("//"))
                .fold(String::new(), |mut s, l| {
                    s.push_str(l);
                    s.push('\n');
                    s
                });
        assert_eq!(nodes, resolved.text);
    }

    #[test]
    fn edit_path_seeds_an_include_of_the_layer_below() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[("only-system", "dri\n")]);
        for name in ["firefox", "only-system"] {
            let path = r.edit_path(name).unwrap();
            assert_eq!(path, r.user_dir().join(format!("{name}.kdl")));
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                format!("// bubbler profile: {name} (user layer)\ninclude \"{name}\"\n")
            );
            // What it seeds must resolve, or the editor opens a file that
            // is already broken.
            assert!(r.resolve(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn edit_path_seeds_a_template_when_no_layer_below_holds_the_name() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        let path = r.edit_path("mine").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            format!("// bubbler profile: mine (user layer)\n{TEMPLATE}")
        );
        // A template of commented examples only, so the profile resolves
        // to the same baseline `generic` does.
        assert!(!text.contains("include"), "{text}");
        assert_eq!(r.resolve("mine").unwrap().text, "");
    }

    #[test]
    fn edit_path_never_touches_a_profile_that_is_already_there() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[("mine", "network\n")], &[]);
        let path = r.edit_path("mine").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "network\n");
    }

    #[test]
    fn accepted_findings_are_unioned_by_id_with_the_nearer_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[(
                "app",
                "include \"base\"\nlint-allow \"x11-without-reason\" reason=\"mine\"\n",
            )],
            &[(
                "base",
                "x11 \"host\"\nlint-allow \"x11-without-reason\" reason=\"theirs\"\n\
                 lint-allow \"tty-passthrough\" reason=\"base\"\n",
            )],
        );
        let resolved = r.resolve("app").unwrap();
        assert_eq!(
            resolved.config.lint_allows,
            vec![
                LintAllow {
                    id: "x11-without-reason".to_owned(),
                    reason: "mine".to_owned(),
                },
                LintAllow {
                    id: "tty-passthrough".to_owned(),
                    reason: "base".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn layers_are_the_files_resolve_would_merge_in_merge_order() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[("app", "include \"base\"\nnetwork\n")],
            &[("base", "wayland\n")],
        );
        let layers = r.layers("app").unwrap();
        assert_eq!(
            layers.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
            ["base", "app"]
        );
        assert_eq!(layers[1].origin, Origin::User);
    }

    #[test]
    fn a_layer_the_parser_rejects_is_still_collected_with_the_ones_under_it() {
        // The linter has more to say about such a file than "it does not
        // parse", and the layers it includes have to be reached anyway.
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[(
                "app",
                "include \"base\"\nsystem-bus {\n    own \"org.example.App\"\n}\n",
            )],
            &[("base", "wayland\n")],
        );
        assert!(r.resolve("app").is_err());
        let layers = r.layers("app").unwrap();
        assert_eq!(
            layers.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
            ["base", "app"]
        );
    }

    #[test]
    fn edit_path_refuses_a_name_that_could_name_a_path() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        for bad in ["../escape", "/etc/passwd", "a/b", "", ".", "..", "-x"] {
            assert!(
                matches!(r.edit_path(bad), Err(ProfileError::InvalidName(n)) if n == bad),
                "{bad}"
            );
        }
        assert!(!r.user_dir().join("escape.kdl").exists());
    }

    #[test]
    fn a_layer_carries_its_disabled_entries_into_the_flattened_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(
            tmp.path(),
            &[("mine", "include \"under\"\ndri\n/-home-share \"mine\"\n")],
            &[("under", "pipewire\n/-home-share \"under\"\n")],
        );
        let resolved = r.resolve("mine").unwrap();
        // The included layer's entries come first, the way its grants do,
        // and nothing merges two disabled entries into one.
        assert_eq!(
            resolved
                .config
                .disabled
                .iter()
                .map(|d| kdl_out::disabled(d).unwrap())
                .collect::<Vec<_>>(),
            vec![
                "/-home-share \"under\" mode=ro",
                "/-home-share \"mine\" mode=ro"
            ]
        );
        // A disabled entry is a line of the seed like any other, and the
        // text an instance is seeded with is what the config parses as.
        assert_eq!(config::parse(&resolved.text).unwrap(), resolved.config);
        assert_eq!(resolved.text, kdl_out::render(&resolved.config).unwrap());
        // What it grants is untouched: the entry is a line, not a grant.
        assert_eq!(
            resolved.config.services,
            vec![Service::Pipewire, Service::Dri { kms: false }]
        );
    }

    /// The three profiles whose applications share a screen do it
    /// through the child rather than through a wildcard nobody wrote.
    #[test]
    fn the_browser_profiles_grant_the_screencast_child() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        for name in ["firefox", "chromium"] {
            let cfg = Resolver::new(&e).resolve(name).unwrap().config;
            assert!(
                cfg.services.contains(&Service::Portals {
                    children: vec![Portal::ScreenCast]
                }),
                "{name}: {:?}",
                cfg.services
            );
        }
        // `vesktop` is bare by design: the grant is in its header block,
        // which `every_opt_in_a_header_lists_pastes_back_into_its_own_profile`
        // runs through the parser and the linter.
        let cfg = Resolver::new(&e).resolve("vesktop").unwrap().config;
        assert!(
            !cfg.services
                .iter()
                .any(|s| matches!(s, Service::Portals { .. }))
        );
    }
}
