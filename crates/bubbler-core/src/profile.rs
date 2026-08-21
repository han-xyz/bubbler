//! Profiles in three layers: the user's, the system's, and the ones
//! compiled into the binary. A profile only seeds a new instance's
//! `config.kdl`; editing the instance never changes the profile.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::{self, InstanceConfig, RawProfile, Service, ShareMode, Userns};
use crate::env::Env;
use crate::error::ProfileError;
use crate::instance::is_plain_name;
use crate::kdl_out;
use crate::seccomp::SeccompConfig;
use crate::tty::TtyMode;

/// Names of all built-in profiles, sorted.
pub const NAMES: &[&str] = &[
    "alacritty",
    "chromium",
    "firefox",
    "generic",
    "libreoffice",
    "mpv",
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
        "alacritty" => Some(include_str!("../profiles/alacritty.kdl")),
        "chromium" => Some(include_str!("../profiles/chromium.kdl")),
        "firefox" => Some(include_str!("../profiles/firefox.kdl")),
        "generic" => Some(include_str!("../profiles/generic.kdl")),
        "libreoffice" => Some(include_str!("../profiles/libreoffice.kdl")),
        "mpv" => Some(include_str!("../profiles/mpv.kdl")),
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
    /// Which layer this is.
    pub origin: Origin,
    /// File the text was read from; `None` for a built-in.
    pub path: Option<PathBuf>,
    /// The profile as written.
    pub text: String,
}

impl Layer {
    /// How this layer is named in an error message.
    fn label(&self, name: &str) -> String {
        match &self.path {
            Some(p) => p.display().to_string(),
            None => format!("built-in profile `{name}`"),
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
            match fs::read_to_string(&path) {
                Ok(text) => out.push(Layer {
                    origin,
                    path: Some(path),
                    text,
                }),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(ProfileError::Io(path, e)),
            }
        }
        if let Some(text) = lookup(name) {
            out.push(Layer {
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
        self.expand(name, 0, &mut acc, &mut chain)?;
        acc.finish(name)
    }

    /// Merge the `skip`th layer of `name`, its `include`s first.
    fn expand(
        &self,
        name: &str,
        skip: usize,
        acc: &mut Merged,
        chain: &mut Vec<LayerId>,
    ) -> Result<(), ProfileError> {
        let layers = self.lookup(name)?;
        let below = layers.len().saturating_sub(skip + 1);
        let Some(layer) = layers.into_iter().nth(skip) else {
            return Err(ProfileError::NotFound(name.to_owned()));
        };
        let label = layer.label(name);
        let id = match &layer.path {
            Some(p) => LayerId::File(p.clone()),
            None => LayerId::BuiltIn(name.to_owned()),
        };
        if chain.contains(&id) {
            return Err(ProfileError::Cycle(chain_labels(chain, &id)));
        }
        // A layer two branches both include is merged once, at the first
        // place it is reached: merging it again would put its nodes over
        // the nearer layer that included it, and a diamond of includes
        // would cost a re-read per path through it.
        if acc.done.contains(&id) {
            return Ok(());
        }
        if chain.len() >= MAX_DEPTH {
            return Err(ProfileError::TooDeep(chain_labels(chain, &id)));
        }
        let raw = config::parse_profile(&layer.text).map_err(|source| ProfileError::Parse {
            origin: label.clone(),
            source,
        })?;
        chain.push(id);
        for inc in &raw.includes {
            // `include "<own name>"` names the layer below this one, which
            // is how a user profile extends the built-in of the same name
            // instead of forking it.
            if inc != name {
                self.expand(inc, 0, acc, chain)?;
                continue;
            }
            // Saying so beats `NotFound` on a name the file itself has:
            // the profile exists, it is this layer, and there is nothing
            // under it to extend.
            if below == 0 {
                return Err(ProfileError::SelfIncludeAtBottom(label));
            }
            self.expand(inc, skip + 1, acc, chain)?;
        }
        let src = Src {
            origin: layer.origin,
            path: layer.path.clone(),
            label,
        };
        acc.merge(&raw, &src)?;
        if let Some(id) = chain.pop() {
            acc.done.push(id);
        }
        Ok(())
    }
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
    tty: Option<(TtyMode, Src)>,
    userns: Option<(Userns, Src)>,
    seccomp: SeccompConfig,
    seccomp_src: Option<Src>,
    command: Option<(Vec<OsString>, Src)>,
    /// Layers already merged, so a shared one is read and merged once.
    done: Vec<LayerId>,
}

impl Merged {
    fn merge(&mut self, raw: &RawProfile, src: &Src) -> Result<(), ProfileError> {
        for svc in &raw.config.services {
            self.add_service(svc, src)?;
        }
        for (key, value) in &raw.config.env {
            match self.env.iter_mut().find(|(k, _, _)| k == key) {
                Some(slot) => *slot = (key.clone(), value.clone(), src.clone()),
                None => self.env.push((key.clone(), value.clone(), src.clone())),
            }
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
            Service::Dbus { rules } => {
                if let Some((held_rules, held_src)) =
                    self.services.iter_mut().find_map(|(s, src)| match s {
                        Service::Dbus { rules: held } => Some((held, src)),
                        _ => None,
                    })
                {
                    for r in rules {
                        if !held_rules.contains(r) {
                            held_rules.push(r.clone());
                        }
                    }
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
            Service::Wayland
            | Service::X11
            | Service::Network
            | Service::Dri
            | Service::Pipewire
            | Service::Pulseaudio
            | Service::Portals
            | Service::Notify
            | Service::Tray
            | Service::EtcShare { .. } => {
                if self.services.iter().any(|(s, _)| s == svc) {
                    return Ok(());
                }
            }
        }
        self.services.push((svc.clone(), src.clone()));
        Ok(())
    }

    /// Whether a share of the same kind and path is already merged, after
    /// checking the two modes agree. `same` selects the shares of one
    /// kind, so `home-share "x"` is never measured against
    /// `path-share "/x"`; `name` names the node when its path is not text
    /// a KDL file could hold.
    fn holds_share(
        &self,
        svc: &Service,
        src: &Src,
        name: &str,
        same: fn(&Service) -> Option<(&Path, ShareMode)>,
    ) -> Result<bool, ProfileError> {
        let Some((path, mode)) = same(svc) else {
            return Ok(false);
        };
        let held = self
            .services
            .iter()
            .find_map(|(s, s_src)| same(s).filter(|&(p, _)| p == path).map(|(_, m)| (m, s_src)));
        let Some((held_mode, held_src)) = held else {
            return Ok(false);
        };
        if held_mode != mode {
            let node = kdl_out::service(svc).unwrap_or_else(|_| name.to_owned());
            return Err(mode_conflict(&node, held_mode, held_src, mode, src));
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
        for (svc, src) in &self.services {
            origins.push((kdl_out::service(svc).map_err(bad)?, src));
        }
        for (key, value, src) in &self.env {
            origins.push((kdl_out::env(key, value), src));
        }
        if let Some((mode, src)) = &self.tty
            && *mode != TtyMode::default()
        {
            origins.push((kdl_out::tty(*mode), src));
        }
        if let Some((mode, src)) = &self.userns
            && *mode != Userns::default()
        {
            origins.push((kdl_out::userns(*mode), src));
        }
        if let Some(src) = &self.seccomp_src
            && self.seccomp != SeccompConfig::default()
        {
            origins.push((kdl_out::seccomp(&self.seccomp), src));
        }
        if let Some((argv, src)) = &self.command {
            origins.push((kdl_out::command(argv).map_err(bad)?, src));
        }
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

fn mode_conflict(node: &str, a: ShareMode, a_src: &Src, b: ShareMode, b_src: &Src) -> ProfileError {
    let word = |m| match m {
        ShareMode::ReadOnly => "ro",
        ShareMode::ReadWrite => "rw",
    };
    ProfileError::Conflict {
        node: node.to_owned(),
        a: format!("mode={} in {}", word(a), a_src.label),
        b: format!("mode={} in {}", word(b), b_src.label),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BusRule;

    fn env(root: &Path) -> Env {
        Env {
            home: root.join("home"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            runtime_dir: root.join("run"),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: Some(root.join("system")),
            proxy_override: None,
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
        let ff = r.resolve("firefox").unwrap().config;
        assert!(ff.services.contains(&Service::Dri));
        assert!(ff.services.contains(&Service::Portals));
        assert!(
            ff.env
                .contains(&("MOZ_ENABLE_WAYLAND".to_owned(), "1".to_owned()))
        );
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
        assert!(
            cfg("thunderbird")
                .env
                .contains(&("MOZ_ENABLE_WAYLAND".to_owned(), "1".to_owned()))
        );
        assert!(
            cfg("libreoffice")
                .env
                .contains(&("SAL_USE_VCLPLUGIN".to_owned(), "gtk3".to_owned()))
        );
        assert!(
            cfg("chromium")
                .services
                .contains(&home_share("Downloads", ShareMode::ReadWrite))
        );
        assert!(cfg("vesktop").services.contains(&Service::Tray));
        let steam = cfg("steam");
        assert!(steam.services.contains(&Service::Gamepad {
            hidraw: false,
            uinput: false
        }));
        // The 32-bit runtime would be killed by a filter built for this
        // architecture alone.
        assert!(steam.seccomp.disable);
        for n in [
            "chromium",
            "libreoffice",
            "mpv",
            "steam",
            "thunderbird",
            "vesktop",
        ] {
            assert_eq!(cfg(n).command, Some(vec![OsString::from(n)]), "{n}");
        }

        assert!(matches!(r.resolve("nope"), Err(ProfileError::NotFound(n)) if n == "nope"));
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
            vec![Service::Network]
        );
        assert_eq!(
            r.resolve("only-system").unwrap().config.services,
            vec![Service::Dri]
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
        assert!(cfg.services.contains(&Service::Wayland));
        assert!(cfg.services.contains(&Service::Network));
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
        assert_eq!(cfg.services, vec![Service::Wayland, Service::Network]);
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
                Service::Wayland,
                Service::Network,
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
        assert_eq!(node, "home-share \"D\" mode=rw");
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
            vec![Service::Wayland, Service::Network, Service::Dri]
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
}
