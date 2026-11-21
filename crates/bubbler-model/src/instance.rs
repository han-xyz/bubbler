//! Named instances: a directory with `config.kdl` and a private `home/`.
//! Layout: `$XDG_DATA_HOME/bubbler/instances/<name>/`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::{
    self, InstanceConfig, NetworkConfig, Portal, Service, WaylandMode, X11Mode, dbus,
};
use crate::env::Env;
use crate::error::{InstanceError, ReadError};
use crate::profile::PROFILE_HEADER;

pub(crate) use crate::checks::APP_ID_SHARED_CHECK;
pub(crate) use crate::names::is_plain_name;
use crate::names::validate_name;

pub const CONFIG_FILE: &str = "config.kdl";

/// Header line recording which meanings a `config.kdl` was written
/// against. Second line of a seeded file, after the profile header.
pub const CONFIG_HEADER: &str = "// bubbler config: ";

/// The meanings this bubbler writes. Version 3 is where a bare `portals`
/// node stopped carrying the privileged portal interfaces; version 2 is
/// where a bare `network` node became the sandbox's own network
/// namespace; version 1 is every file written before that, which has no
/// header at all.
pub const CONFIG_VERSION: u32 = 3;

// Each migration is measured against the version that introduced it,
// not against [`CONFIG_VERSION`]: a file that has been through one has
// been through it whatever came after.
const ISOLATED_NETWORK_VERSION: u32 = 2;

const PORTAL_CHILDREN_VERSION: u32 = 3;

/// Directory holding all instances.
pub fn instances_root(env: &Env) -> PathBuf {
    env.data_home.join("bubbler").join("instances")
}

/// Where `name`'s configuration would live, without opening the instance,
/// so a caller can name the file in an error message.
pub fn config_path(env: &Env, name: &str) -> PathBuf {
    instances_root(env).join(name).join(CONFIG_FILE)
}

/// Where `name`'s configuration lives, checked to be an existing regular
/// file but not parsed, so a broken config can still be opened by an editor.
pub fn config_path_checked(env: &Env, name: &str) -> Result<PathBuf, InstanceError> {
    validate_name(name)?;
    let path = config_path(env, name);
    match fs::metadata(&path) {
        Ok(m) if m.is_file() => Ok(path),
        Ok(_) => Err(InstanceError::NotFound(name.to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Err(InstanceError::NotFound(name.to_owned()))
        }
        Err(e) => Err(InstanceError::Io(path, e)),
    }
}

/// A created instance with its parsed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Validated name: `[A-Za-z0-9._-]+`, not starting with `-`, and not
    /// `.` or `..`.
    pub name: String,
    /// `<instances_root>/<name>`.
    pub dir: PathBuf,
    /// Parsed `config.kdl`.
    pub config: InstanceConfig,
    /// Version its header records, or `None` for a file written before
    /// there was one. [`Instance::migration_warning`] is what reads it.
    pub config_version: Option<u32>,
}

/// The existing instance, other than `name` itself, whose portal app id is
/// `name`'s.
pub fn app_id_twin(env: &Env, name: &str) -> Result<Option<String>, InstanceError> {
    let names = list_in(&instances_root(env))?;
    Ok(dbus::app_id_twin(name, &names).map(str::to_owned))
}

// The warning `name`'s run, or its keeping, prints when another instance
// in `root` shares its app id and `config` does not accept that.
pub fn app_id_warning_in(
    root: &Path,
    name: &str,
    config: &InstanceConfig,
) -> Result<Option<String>, InstanceError> {
    if config.accepts(APP_ID_SHARED_CHECK) {
        return Ok(None);
    }
    let names = list_in(root)?;
    Ok(dbus::app_id_twin(name, &names).map(|other| {
        format!(
            "instance `{name}` shares the portal app id `{}` with instance `{other}`, and with \
             it portal permissions, forwarded documents and the window app id; rename one \
             of the two, or accept it with `lint-allow \"{APP_ID_SHARED_CHECK}\"`",
            dbus::app_id(name),
        )
    }))
}

// Names of the instances under `root`, sorted. An absent root holds none.
fn list_in(root: &Path) -> Result<Vec<String>, InstanceError> {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(InstanceError::Io(root.to_path_buf(), e)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io_err(root))?;
        if let Some(n) = entry.file_name().to_str()
            && validate_name(n).is_ok()
            && entry.path().join(CONFIG_FILE).is_file()
        {
            names.push(n.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

pub fn io_err(path: &Path) -> impl FnOnce(io::Error) -> InstanceError + '_ {
    move |e| InstanceError::Io(path.to_path_buf(), e)
}

// One `config.kdl`, refused on its size before it is read. A file past
// the parser's bound is the [`crate::error::ConfigError`] the parser
// gives; anything else names the path, the way [`io_err`] does.
pub fn read_config(path: &Path) -> Result<String, InstanceError> {
    config::read_bounded(path).map_err(|e| match e {
        ReadError::Io(e) => InstanceError::Io(path.to_path_buf(), e),
        ReadError::TooLarge(e) => InstanceError::Config(e),
    })
}

fn grant_service(name: &str) -> Option<Service> {
    Some(match name {
        // Always the security context: `--grant wayland` is not where a
        // user asks for the session's own socket.
        "wayland" => Service::Wayland(WaylandMode::default()),
        // The sandbox's own server: `--grant x11` is not where a user
        // asks for the session's display, and it needs `--grant wayland
        // --grant dri` with it, which the config check names.
        "x11" => Service::X11(X11Mode::default()),
        "network" => Service::Network(NetworkConfig::default()),
        "dri" => Service::Dri { kms: false },
        "pipewire" => Service::Pipewire {
            microphone: false,
            devices: false,
            exclusive: false,
            capturable: false,
        },
        "pulseaudio" => Service::Pulseaudio {
            microphone: false,
            exclusive: false,
            capturable: false,
        },
        "dbus" => Service::Dbus { rules: Vec::new() },
        "portals" => Service::Portals {
            children: Vec::new(),
        },
        // A child is written as the node that carries it: `--grant
        // screencast` on a config that already has `portals` adds the
        // child to it, which `with_grants` does below.
        name if Portal::from_name(name).is_some() => Service::Portals {
            children: vec![Portal::from_name(name).expect("just matched")],
        },
        "notify" => Service::Notify,
        "tray" => Service::Tray,
        "a11y" => Service::A11y,
        "input-method" => Service::InputMethod,
        "gamepad" => Service::Gamepad {
            hidraw: false,
            uinput: false,
        },
        "hidraw" => Service::Hidraw,
        "camera" => Service::Camera { nodes: false },
        _ => return None,
    })
}

// Add one bare service node per grant. A grant the config already holds
// is skipped: the parser rejects a duplicate.
pub fn with_grants(cfg: &mut InstanceConfig, grants: &[&str]) -> Result<(), InstanceError> {
    for g in grants {
        let svc = grant_service(g).ok_or_else(|| InstanceError::InvalidGrant((*g).to_owned()))?;
        // Two `dbus` nodes hold different rules, so that grant is
        // recognised by its variant rather than by value.
        let held = match &svc {
            Service::Dbus { .. } => cfg
                .services
                .iter()
                .any(|s| matches!(s, Service::Dbus { .. })),
            // A `gamepad` already in the config may carry properties this
            // bare grant does not, and the parser takes one node only.
            Service::Gamepad { .. } => cfg
                .services
                .iter()
                .any(|s| matches!(s, Service::Gamepad { .. })),
            // Same for `camera`, whose `nodes` property a config may
            // already carry.
            Service::Camera { .. } => cfg
                .services
                .iter()
                .any(|s| matches!(s, Service::Camera { .. })),
            // The same for `network`, whose mode and children the bare
            // grant does not carry.
            Service::Network { .. } => cfg
                .services
                .iter()
                .any(|s| matches!(s, Service::Network { .. })),
            // And for the two display grants, whose mode the bare grant
            // does not carry either: `--grant x11` on a profile holding
            // `x11 "host"` would otherwise write a second node the
            // parser refuses.
            Service::Wayland(_) => cfg
                .services
                .iter()
                .any(|s| matches!(s, Service::Wayland(_))),
            Service::X11(_) => cfg.services.iter().any(|s| matches!(s, Service::X11(_))),
            // The one grant that merges into a node already held: a
            // second `portals` node is a duplicate, so a child has to
            // join the first rather than fail the "one node" check above.
            Service::Portals { children } => {
                match cfg.services.iter_mut().find_map(|s| match s {
                    Service::Portals { children } => Some(children),
                    _ => None,
                }) {
                    Some(held) => {
                        for c in children {
                            if !held.contains(c) {
                                held.push(*c);
                            }
                        }
                        true
                    }
                    None => false,
                }
            }
            other => cfg.services.contains(other),
        };
        if !held {
            cfg.services.push(svc);
        }
    }
    Ok(())
}

/// The profile name the first line records, if that line is the header a
/// seeded config carries and what follows it is a profile name. A config
/// written by hand without it names no profile to re-flatten.
pub fn profile_header(text: &str) -> Option<&str> {
    let name = text
        .lines()
        .next()?
        .strip_prefix(PROFILE_HEADER)?
        .trim_end();
    is_plain_name(name).then_some(name)
}

// The version the header records, if the file has one. Only the leading
// comment block is read: a `// bubbler config:` line further down is
// part of somebody's notes, not a header.
pub fn config_version(text: &str) -> Option<u32> {
    text.lines()
        .take_while(|l| {
            let l = l.trim_start();
            l.is_empty() || l.starts_with("//")
        })
        .find_map(|l| l.trim_start().strip_prefix(CONFIG_HEADER))
        .and_then(|v| v.trim().parse().ok())
}

impl Instance {
    /// The line a real run prints when another instance shares this one's
    /// portal app id, unless the config accepts it with a `lint-allow`.
    pub fn app_id_warning(&self, env: &Env) -> Result<Option<String>, InstanceError> {
        app_id_warning_in(&instances_root(env), &self.name, &self.config)
    }

    /// Private home directory on the host, bound to `/home/bubbler` inside.
    pub fn home(&self) -> PathBuf {
        self.dir.join("home")
    }

    /// Path of `config.kdl`.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    /// Open an existing instance and parse its config.
    pub fn open(env: &Env, name: &str) -> Result<Self, InstanceError> {
        validate_name(name)?;
        let dir = instances_root(env).join(name);
        let cfg_path = dir.join(CONFIG_FILE);
        let text = match read_config(&cfg_path) {
            Ok(t) => t,
            Err(InstanceError::Io(_, e)) if e.kind() == io::ErrorKind::NotFound => {
                return Err(InstanceError::NotFound(name.to_owned()));
            }
            Err(e) => return Err(e),
        };
        let config = config::parse(&text)?;
        Ok(Self {
            name: name.to_owned(),
            dir,
            config,
            config_version: config_version(&text),
        })
    }

    /// Names of all instances, sorted. An absent root means no instances.
    pub fn list(env: &Env) -> Result<Vec<String>, InstanceError> {
        list_in(&instances_root(env))
    }

    /// What a run of this instance has to say about its config before it
    /// starts: a node whose meaning changed after the version the file
    /// records asks for a different sandbox now than it did when it was
    /// written. A file recording no version counts as version 1. One
    /// string per migration the file has not been through, since a file
    /// old enough may not have been through either.
    pub fn migration_warning(&self) -> Vec<String> {
        let written = self.config_version.unwrap_or(1);
        let services = &self.config.services;
        let name = &self.name;
        let mut out = Vec::new();
        if written < ISOLATED_NETWORK_VERSION
            && services
                .iter()
                .any(|s| matches!(s, Service::Network(c) if c.is_isolated()))
        {
            out.push(format!(
                "`network` now means an isolated network namespace; run \
                 `bubbler reseed {name}` to write the config again from its profile, or \
                 `bubbler edit {name}` to keep your own edits and record the version, \
                 or write `network \"host\"` to keep the old behaviour"
            ));
        }
        if written < PORTAL_CHILDREN_VERSION
            && services
                .iter()
                .any(|s| matches!(s, Service::Portals { children } if children.is_empty()))
        {
            out.push(format!(
                "a bare `portals` no longer opens ScreenCast, RemoteDesktop, InputCapture, \
                 GlobalShortcuts, Background, DynamicLauncher, Location or Secret: each is \
                 a child written inside the node, such as `portals {{ screencast }}` for \
                 screen sharing, and the others are `remote-desktop`, `global-shortcuts`, \
                 `background`, `location`, `secrets` and `camera`; run \
                 `bubbler reseed {name}` to write the config again from its profile, or \
                 `bubbler edit {name}` to add the children this application needs and \
                 record the version"
            ));
        }
        out
    }

    /// Whether `s` is among the granted services.
    pub fn has_service(&self, s: &Service) -> bool {
        self.config.services.contains(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::BARE_GRANTS as GRANTS;
    use crate::kdl_out;

    #[test]
    fn a_grant_the_config_already_made_keeps_its_properties() {
        // The parser takes one `gamepad` node, so a bare grant on top of
        // a node carrying properties must leave that node alone rather
        // than add a second, narrower one.
        let mut cfg = config::parse("gamepad hidraw=#true").unwrap();
        with_grants(&mut cfg, &["gamepad"]).unwrap();
        assert_eq!(
            cfg.services,
            vec![Service::Gamepad {
                hidraw: true,
                uinput: false
            }]
        );
        assert_eq!(kdl_out::render(&cfg).unwrap(), "gamepad hidraw=#true\n");
    }

    #[test]
    fn a_camera_grant_leaves_a_device_grant_in_the_config_alone() {
        // The parser takes one `camera` node, so a bare grant on top of
        // `nodes=#true` must not narrow what the config already granted.
        let mut cfg = config::parse("dbus\nportals\ncamera nodes=#true").unwrap();
        with_grants(&mut cfg, &["camera"]).unwrap();
        assert_eq!(cfg.services.last(), Some(&Service::Camera { nodes: true }));
        assert!(
            kdl_out::render(&cfg)
                .unwrap()
                .contains("camera nodes=#true\n")
        );
    }

    #[test]
    fn every_listed_grant_names_a_service() {
        // The list is what the error message offers; a name on it that no
        // service answers to would be an offer bubbler cannot keep.
        for g in GRANTS {
            assert!(grant_service(g).is_some(), "{g}");
        }
        // A node that takes an argument is not a grant: `--grant` writes
        // a bare node, and `app-runtime` without its id would name no
        // directory.
        for named in ["home-share", "app-runtime"] {
            assert!(grant_service(named).is_none(), "{named}");
            assert!(!GRANTS.contains(&named), "{named}");
        }
    }

    #[test]
    fn only_the_header_seed_writes_names_a_profile() {
        assert_eq!(
            profile_header("// bubbler profile: ff\nwayland\n"),
            Some("ff")
        );
        assert_eq!(profile_header("// bubbler profile: ff"), Some("ff"));
        assert_eq!(profile_header("// bubbler profile: ff \n"), Some("ff"));
        for bad in [
            "",
            "wayland\n",
            "// bubbler profile:\n",
            "// bubbler profile: \n",
            "//bubbler profile: ff\n",
            "// bubbler profile: ../escape\n",
            "wayland\n// bubbler profile: ff\n",
        ] {
            assert_eq!(profile_header(bad), None, "{bad:?}");
        }
    }
}
