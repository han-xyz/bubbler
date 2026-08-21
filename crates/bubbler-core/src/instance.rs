//! Named instances: a directory with `config.kdl` and a private `home/`.
//! Layout follows bubblejail: `$XDG_DATA_HOME/bubbler/instances/<name>/`.

use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use rustix::fs::Mode;
use rustix::io::Errno;
use rustix::process::{Pid, test_kill_process};

use crate::config::{self, InstanceConfig, NetworkConfig, Service};
use crate::env::Env;
use crate::error::InstanceError;
use crate::kdl_out;
use crate::profile::{self, PROFILE_HEADER};
use crate::{dbus, exec, launcher};

const CONFIG_FILE: &str = "config.kdl";

/// Header line recording which meanings a `config.kdl` was written
/// against. Second line of a seeded file, after the profile header.
pub(crate) const CONFIG_HEADER: &str = "// bubbler config: ";

/// The meanings this bubbler writes. Version 2 is where a bare `network`
/// node became the sandbox's own network namespace; version 1 is every
/// file written before that, which has no header at all.
pub const CONFIG_VERSION: u32 = 2;

/// Where `reseed` keeps the `config.kdl` it replaces.
const BACKUP_FILE: &str = "config.kdl.bak";

/// Where `reseed` builds the new `config.kdl` before it takes the old
/// one's place.
const TEMP_FILE: &str = "config.kdl.new";

/// Service names [`Instance::ephemeral`] accepts as grants: the bare
/// config nodes, which take no arguments. Anything else needs a config
/// file and therefore a real instance.
pub const GRANTS: &[&str] = &[
    "wayland",
    "x11",
    "network",
    "dri",
    "pipewire",
    "pulseaudio",
    "dbus",
    "portals",
    "notify",
    "tray",
    "gamepad",
    "hidraw",
    "camera",
];

/// Directory holding all instances.
pub fn instances_root(env: &Env) -> PathBuf {
    env.data_home.join("bubbler").join("instances")
}

/// Directory holding throwaway instances, one per bubbler pid.
fn try_root(env: &Env) -> PathBuf {
    env.data_home.join("bubbler").join("try")
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

/// Whether `name` is the shape [`Instance::ephemeral`] gives a throwaway
/// sandbox, `try-<pid>`, whose runtime directory is swept once that pid is
/// gone. An instance of that name would have its own swept out from under it.
fn is_try_name(name: &str) -> bool {
    name.strip_prefix("try-")
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

/// The name grammar instances and profiles share: `[A-Za-z0-9._-]+`, not
/// `.` or `..`, and not starting with `-`. Such a name is one path
/// component that cannot traverse out of a directory, and no CLI that
/// takes it reads it as an option.
pub fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn validate_name(name: &str) -> Result<(), InstanceError> {
    if is_plain_name(name) && !is_try_name(name) {
        Ok(())
    } else {
        Err(InstanceError::InvalidName(name.to_owned()))
    }
}

/// Bytes a `sockaddr_un` holds, the terminating NUL among them
/// (`unix(7)`).
const SUN_PATH_MAX: usize = 108;

/// Refuse a name whose runtime sockets would not fit a `sockaddr_un`.
/// The kernel truncates a longer path without saying so, and what the
/// user then sees is a client failing on a path that is not the one
/// bubbler printed. Checked where the instance is created, so the name is
/// still the user's to change.
// Every socket an instance can have, longest first: the proxy binds its
// own in the `dbus/` subdirectory, one level deeper than the path the
// launcher then moves it to, so those are the longest of all.
fn check_socket_paths(env: &Env, name: &str) -> Result<(), InstanceError> {
    let runtime = launcher::instance_runtime_dir(env, name);
    for path in [
        dbus::proxy_bus_path(&runtime, dbus::SYSTEM_SOCKET),
        dbus::proxy_bus_path(&runtime, dbus::SESSION_SOCKET),
        runtime.join(exec::SOCKET_NAME),
        dbus::app_bus_path(&runtime, dbus::SYSTEM_SOCKET),
        dbus::app_bus_path(&runtime, dbus::SESSION_SOCKET),
    ] {
        if path.as_os_str().as_encoded_bytes().len() + 1 > SUN_PATH_MAX {
            return Err(InstanceError::SocketPathTooLong(path));
        }
    }
    Ok(())
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> InstanceError + '_ {
    move |e| InstanceError::Io(path.to_path_buf(), e)
}

/// Put `text` at `path` in one step: it is written to a sibling file and
/// renamed over `path`, and `rename(2)` within one directory replaces the
/// name atomically. A reader therefore sees either the whole old config
/// or the whole new one, never the half-written file a crashed or failing
/// write would leave under a name bubbler treats as a complete config.
fn write_atomic(path: &Path, text: &str) -> Result<(), InstanceError> {
    // Same directory as `path`, which is what makes the rename atomic
    // rather than a copy across filesystems.
    let tmp = path.with_file_name(TEMP_FILE);
    let written = (|| -> io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        // The rename only orders the *name* change; without this the
        // contents may still be unwritten when it happens, so a crash
        // could leave the new name over an empty file.
        f.sync_all()
    })();
    if let Err(e) = written {
        // Cleanup on the way out: the error being reported is the write's,
        // and a leftover temporary file is not part of any sandbox.
        let _ = fs::remove_file(&tmp);
        return Err(InstanceError::Io(tmp, e));
    }
    fs::rename(&tmp, path).map_err(io_err(path))
}

/// Lay out an instance directory: `dir` itself (never overwriting one),
/// a private `home/` and `config.kdl` holding `text`. `name` only names
/// the instance in the "already exists" error.
fn make_dir(dir: &Path, name: &str, text: &str) -> Result<(), InstanceError> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(io_err(parent))?;
    }
    fs::create_dir(dir).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => InstanceError::AlreadyExists(name.to_owned()),
        _ => InstanceError::Io(dir.to_path_buf(), e),
    })?;
    let home = dir.join("home");
    rustix::fs::mkdir(&home, Mode::RWXU).map_err(|e| InstanceError::Io(home.clone(), e.into()))?;
    let cfg_path = dir.join(CONFIG_FILE);
    fs::write(&cfg_path, text).map_err(io_err(&cfg_path))
}

/// The service one [`GRANTS`] name adds.
fn grant_service(name: &str) -> Option<Service> {
    Some(match name {
        "wayland" => Service::Wayland,
        "x11" => Service::X11,
        "network" => Service::Network(NetworkConfig::default()),
        "dri" => Service::Dri,
        "pipewire" => Service::Pipewire,
        "pulseaudio" => Service::Pulseaudio,
        "dbus" => Service::Dbus { rules: Vec::new() },
        "portals" => Service::Portals,
        "notify" => Service::Notify,
        "tray" => Service::Tray,
        "gamepad" => Service::Gamepad {
            hidraw: false,
            uinput: false,
        },
        "hidraw" => Service::Hidraw,
        "camera" => Service::Camera { nodes: false },
        _ => return None,
    })
}

/// Add one bare service node per grant. A grant the config already holds
/// is skipped: the parser rejects a duplicate.
fn with_grants(cfg: &mut InstanceConfig, grants: &[&str]) -> Result<(), InstanceError> {
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
            other => cfg.services.contains(other),
        };
        if !held {
            cfg.services.push(svc);
        }
    }
    Ok(())
}

/// What a `config.kdl` holds when its profile grants nothing: the same
/// examples the `generic` profile is written with. A flattened profile
/// keeps no comments, so without this `bubbler edit` on a fresh instance
/// would open a file holding only its header.
const STARTER: &str = "\
// Baseline sandbox only. Add grants below, e.g.:
//   wayland
//   network
//   home-share \"Downloads\"
// and a default command:
//   command \"foot\"
";

/// The flattened profile as the text a new instance's `config.kdl` holds:
/// a header naming the profile it came from, then the canonical KDL of the
/// merged result plus one bare node per grant. The text is parsed back, so
/// nothing is written that bubbler would then refuse to open.
fn seed(
    env: &Env,
    profile_name: &str,
    grants: &[&str],
) -> Result<(String, InstanceConfig), InstanceError> {
    let mut cfg = profile::Resolver::new(env).resolve(profile_name)?.config;
    with_grants(&mut cfg, grants)?;
    let rendered = kdl_out::render(&cfg)?;
    let body = if rendered.is_empty() {
        STARTER
    } else {
        rendered.as_str()
    };
    // The name passed the profile name grammar to resolve at all, so it
    // holds no newline that could end the header comment early.
    let text = format!("{PROFILE_HEADER}{profile_name}\n{CONFIG_HEADER}{CONFIG_VERSION}\n{body}");
    let config = config::parse(&text)?;
    Ok((text, config))
}

/// The profile name the first line records, if that line is the header
/// [`seed`] writes and what follows it is a profile name. A hand-written
/// config without it names no profile to re-flatten.
fn profile_header(text: &str) -> Option<&str> {
    let name = text
        .lines()
        .next()?
        .strip_prefix(PROFILE_HEADER)?
        .trim_end();
    is_plain_name(name).then_some(name)
}

/// The version the header records, if the file has one. Only the leading
/// comment block is read: a `// bubbler config:` line further down is
/// part of somebody's notes, not a header.
fn config_version(text: &str) -> Option<u32> {
    text.lines()
        .take_while(|l| {
            let l = l.trim_start();
            l.is_empty() || l.starts_with("//")
        })
        .find_map(|l| l.trim_start().strip_prefix(CONFIG_HEADER))
        .and_then(|v| v.trim().parse().ok())
}

/// The pid a sweepable directory is named after: decimal digits only, so
/// `-1`, `+5` and `0` name no process and are left alone.
fn dir_pid(name: &str) -> Option<Pid> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Pid::from_raw(i32::try_from(name.parse::<u32>().ok()?).ok()?)
}

/// Remove every entry of `dir` named `<prefix><pid>` whose pid is not a
/// live process, and nothing else. Best effort: a directory that cannot
/// be removed is reported, never fatal.
fn sweep_dir(dir: &Path, prefix: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(prefix))
            .and_then(dir_pid)
        else {
            continue;
        };
        // `kill(pid, 0)` fails with ESRCH only when no process has that
        // pid; EPERM means it is alive and owned by someone else.
        if test_kill_process(pid) != Err(Errno::SRCH) {
            continue;
        }
        if let Err(e) = fs::remove_dir_all(entry.path()) {
            eprintln!("bubbler: {}: {e}", entry.path().display());
        }
    }
}

/// Remove leftovers of tries whose bubbler is gone: `try/<pid>` and
/// `<runtime>/bubbler/try-<pid>` for every pid no live process has. A
/// name that is not a pid is not swept.
pub fn sweep_stale(env: &Env) {
    sweep_dir(&try_root(env), "");
    sweep_dir(&env.runtime_dir.join("bubbler"), "try-");
}

/// A throwaway instance under `try/<pid>`, removed when this guard drops
/// unless [`Ephemeral::keep_as`] renamed it into a real instance first.
#[derive(Debug)]
pub struct Ephemeral {
    /// The instance itself; the launcher takes it like any other.
    pub instance: Instance,
    /// Instance name to keep the directory under, if any.
    keep: Option<String>,
    // `Drop` runs without an `Env`, so the paths it needs are copied here.
    instances_root: PathBuf,
    runtime: PathBuf,
    /// Whether the runtime directory is this guard's to remove.
    remove_runtime: bool,
}

impl Ephemeral {
    /// Keep the sandbox afterwards as instance `name` instead of removing
    /// it. The name is checked now so a run that cannot be kept never
    /// starts: kept, it is what the next run's sockets are named after,
    /// so it faces the same length limit as a name given to `create`.
    pub fn keep_as(&mut self, env: &Env, name: &str) -> Result<(), InstanceError> {
        validate_name(name)?;
        check_socket_paths(env, name)?;
        fs::create_dir_all(&self.instances_root).map_err(io_err(&self.instances_root))?;
        if fs::symlink_metadata(self.instances_root.join(name)).is_ok() {
            return Err(InstanceError::AlreadyExists(name.to_owned()));
        }
        self.keep = Some(name.to_owned());
        Ok(())
    }

    /// Leave the runtime directory alone on drop, for when it turned out
    /// to belong to something else that is already running there.
    pub fn disarm_runtime(&mut self) {
        self.remove_runtime = false;
    }

    /// Forget the name the sandbox was to be kept under, so it is removed
    /// after all. What `--keep` keeps is a sandbox that ran, never one
    /// whose launch failed.
    pub fn disarm_keep(&mut self) {
        self.keep = None;
    }
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        let dir = &self.instance.dir;
        let kept = match &self.keep {
            Some(name) => fs::rename(dir, self.instances_root.join(name)),
            None => fs::remove_dir_all(dir),
        };
        // A guard cannot propagate: naming the leftover directory is all
        // it can do about a failure here.
        if let Err(e) = kept {
            eprintln!("bubbler: {}: {e}", dir.display());
        }
        if self.remove_runtime
            && let Err(e) = fs::remove_dir_all(&self.runtime)
            && e.kind() != io::ErrorKind::NotFound
        {
            eprintln!("bubbler: {}: {e}", self.runtime.display());
        }
    }
}

impl Instance {
    /// Private home directory on the host, bound to `/home/bubbler` inside.
    pub fn home(&self) -> PathBuf {
        self.dir.join("home")
    }

    /// Path of `config.kdl`.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    /// Create a new instance seeded from a profile, flattened through its
    /// layers. Fails if the directory already exists; never overwrites.
    pub fn create(env: &Env, name: &str, profile_name: &str) -> Result<Self, InstanceError> {
        validate_name(name)?;
        check_socket_paths(env, name)?;
        let (text, config) = seed(env, profile_name, &[])?;
        let dir = instances_root(env).join(name);
        make_dir(&dir, name, &text)?;
        Ok(Self {
            name: name.to_owned(),
            dir,
            config,
            config_version: Some(CONFIG_VERSION),
        })
    }

    /// Create a throwaway instance seeded from a flattened profile plus
    /// one bare node per grant, named `try-<pid>` so its runtime directory
    /// is its own. The guard removes it again when it drops.
    pub fn ephemeral(
        env: &Env,
        profile_name: &str,
        grants: &[&str],
    ) -> Result<Ephemeral, InstanceError> {
        sweep_stale(env);
        let (text, config) = seed(env, profile_name, grants)?;
        let pid = std::process::id();
        let name = format!("try-{pid}");
        check_socket_paths(env, &name)?;
        let dir = try_root(env).join(pid.to_string());
        let runtime = launcher::instance_runtime_dir(env, &name);
        // Only this process can be the live owner of try/<own pid>, so a
        // directory there is a leftover from a bubbler whose pid was reused.
        if let Err(e) = fs::remove_dir_all(&dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(InstanceError::Io(dir, e));
        }
        make_dir(&dir, &name, &text)?;
        Ok(Ephemeral {
            instance: Self {
                name,
                dir,
                config,
                config_version: Some(CONFIG_VERSION),
            },
            keep: None,
            instances_root: instances_root(env),
            runtime,
            remove_runtime: true,
        })
    }

    /// Open an existing instance and parse its config.
    pub fn open(env: &Env, name: &str) -> Result<Self, InstanceError> {
        validate_name(name)?;
        let dir = instances_root(env).join(name);
        let cfg_path = dir.join(CONFIG_FILE);
        let text = match fs::read_to_string(&cfg_path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(InstanceError::NotFound(name.to_owned()));
            }
            Err(e) => return Err(InstanceError::Io(cfg_path, e)),
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
        let root = instances_root(env);
        let entries = match fs::read_dir(&root) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(InstanceError::Io(root, e)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io_err(&root))?;
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

    /// Remove the instance directory, including its private home, and its
    /// runtime directory. Refuses to follow a symlink in place of the
    /// instance directory.
    pub fn delete(env: &Env, name: &str) -> Result<(), InstanceError> {
        validate_name(name)?;
        let dir = instances_root(env).join(name);
        let meta = match fs::symlink_metadata(&dir) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(InstanceError::NotFound(name.to_owned()));
            }
            Err(e) => return Err(InstanceError::Io(dir, e)),
        };
        if meta.file_type().is_symlink() {
            return Err(InstanceError::IsSymlink(dir));
        }
        fs::remove_dir_all(&dir).map_err(io_err(&dir))?;
        let run = env.runtime_dir.join("bubbler").join(name);
        match fs::remove_dir_all(&run) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(InstanceError::Io(run, e)),
        }
    }

    /// Write `config` back to `config.kdl`, keeping the headers the file
    /// carries: the profile it was seeded from, so `reseed` still knows
    /// where to re-flatten it from, and the config version, so no later
    /// run warns about meanings this file has just been written against.
    /// What it replaces is kept beside it as `config.kdl.bak`, and the
    /// rename is atomic, so a reader sees one whole config or the other.
    ///
    /// Comments and layout are not kept: the file is rendered from the
    /// config, which holds the grants and not the text around them.
    pub fn save(&self, config: &InstanceConfig) -> Result<(), InstanceError> {
        let cfg_path = self.config_path();
        let held = fs::read_to_string(&cfg_path).map_err(io_err(&cfg_path))?;
        let mut text = String::new();
        // A profile is only named where the file already named one: a
        // header invented here would send `reseed` to somebody else's
        // profile. The name passed the profile grammar to be read as a
        // header at all, so it holds no newline of its own.
        if let Some(profile_name) = profile_header(&held) {
            text.push_str(&format!("{PROFILE_HEADER}{profile_name}\n"));
        }
        text.push_str(&format!("{CONFIG_HEADER}{CONFIG_VERSION}\n"));
        text.push_str(&kdl_out::render(config)?);
        // Read back before anything is written, the way a seed is: a file
        // the parser would refuse is an instance that cannot be opened
        // again, and the checks across nodes (`camera` needs `portals`)
        // are only made here.
        config::parse(&text)?;
        let backup = self.dir.join(BACKUP_FILE);
        fs::copy(&cfg_path, &backup).map_err(io_err(&backup))?;
        write_atomic(&cfg_path, &text)
    }

    /// Re-flatten the profile named in `config.kdl`'s header into that
    /// file, keeping the private `home/`. What it replaces is kept beside
    /// it as `config.kdl.bak`, overwriting an older backup.
    pub fn reseed(env: &Env, name: &str) -> Result<Self, InstanceError> {
        let cfg_path = config_path_checked(env, name)?;
        // A running sandbox was built from the file as it stands, and
        // bwrap cannot be told about a bind after the fact: rewriting it
        // now would describe grants that sandbox does not have.
        if crate::exec::connect(env, name)
            .map_err(InstanceError::Probe)?
            .is_some()
        {
            return Err(InstanceError::AlreadyRunning(name.to_owned()));
        }
        let text = fs::read_to_string(&cfg_path).map_err(io_err(&cfg_path))?;
        let profile_name = profile_header(&text)
            .ok_or_else(|| InstanceError::NoProfileHeader(cfg_path.clone()))?;
        let (fresh, config) = seed(env, profile_name, &[])?;
        let dir = instances_root(env).join(name);
        let backup = dir.join(BACKUP_FILE);
        fs::copy(&cfg_path, &backup).map_err(io_err(&backup))?;
        write_atomic(&cfg_path, &fresh)?;
        Ok(Self {
            name: name.to_owned(),
            dir,
            config,
            config_version: Some(CONFIG_VERSION),
        })
    }

    /// Record the current version in a config that does not already, by
    /// replacing an older header or writing one after the profile header.
    /// `true` when the file was changed. What it records is that the file
    /// has been read against the current meanings, which is what
    /// [`Instance::migration_warning`] stops warning about.
    pub fn mark_version(env: &Env, name: &str) -> Result<bool, InstanceError> {
        let cfg_path = config_path_checked(env, name)?;
        let text = fs::read_to_string(&cfg_path).map_err(io_err(&cfg_path))?;
        if config_version(&text).is_some_and(|v| v >= CONFIG_VERSION) {
            return Ok(false);
        }
        let header = format!("{CONFIG_HEADER}{CONFIG_VERSION}");
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        // An older header is replaced where it stands; without one the
        // line goes under the profile header, or at the top.
        match lines
            .iter()
            .position(|l| l.trim_start().starts_with(CONFIG_HEADER))
        {
            Some(i) => lines[i] = header,
            None => {
                let at = usize::from(lines.first().is_some_and(|l| l.starts_with(PROFILE_HEADER)));
                lines.insert(at, header);
            }
        }
        let mut marked = lines.join("\n");
        marked.push('\n');
        write_atomic(&cfg_path, &marked)?;
        Ok(true)
    }

    /// What a run of this instance has to say about its config before it
    /// starts, if anything: a file written before version 2 that still
    /// holds a bare `network` node asks for a different sandbox now than
    /// it did when it was written. A file recording any older version
    /// counts the same as one recording none.
    pub fn migration_warning(&self) -> Option<String> {
        let bare = self
            .config
            .services
            .iter()
            .any(|s| matches!(s, Service::Network(c) if c.is_isolated()));
        let old = self.config_version.is_none_or(|v| v < CONFIG_VERSION);
        (old && bare).then(|| {
            format!(
                "`network` now means an isolated network namespace; run \
                 `bubbler reseed {name}` to write the config again from its profile, or \
                 `bubbler edit {name}` to keep your own edits and record the version, \
                 or write `network \"host\"` to keep the old behaviour",
                name = self.name
            )
        })
    }

    /// Whether `s` is among the granted services.
    pub fn has_service(&self, s: &Service) -> bool {
        self.config.services.contains(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(data_home: &Path) -> Env {
        Env {
            home: "/home/han".into(),
            data_home: data_home.to_path_buf(),
            config_home: data_home.join("config"),
            runtime_dir: "/run/user/1000".into(),
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
            profile_dir_override: Some(data_home.join("profiles")),
            proxy_override: None,
            pasta_override: None,
        }
    }

    #[test]
    fn create_open_list_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        assert!(Instance::list(&env).unwrap().is_empty());
        let inst = Instance::create(&env, "ff", "generic").unwrap();
        assert!(inst.home().is_dir());
        assert!(inst.config_path().is_file());
        assert_eq!(inst.config, InstanceConfig::default());
        let opened = Instance::open(&env, "ff").unwrap();
        assert_eq!(opened.dir, inst.dir);
        assert_eq!(Instance::list(&env).unwrap(), vec!["ff".to_string()]);
    }

    #[test]
    fn a_name_whose_runtime_sockets_would_be_truncated_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        // `/run/user/1000/bubbler/`, and the longest path below it is the
        // proxy's own system bus socket.
        let prefix = e.runtime_dir.join("bubbler").join("").as_os_str().len();
        assert_eq!(prefix, 23);
        let longest = |name: &str| {
            dbus::proxy_bus_path(
                &e.runtime_dir.join("bubbler").join(name),
                dbus::SYSTEM_SOCKET,
            )
        };
        let fits = 107 - prefix - "/dbus/system".len();
        let name = "a".repeat(fits);
        assert_eq!(longest(&name).as_os_str().len(), 107);
        assert!(Instance::create(&e, &name, "generic").is_ok(), "{fits}");

        let name = "b".repeat(fits + 1);
        let Err(InstanceError::SocketPathTooLong(path)) = Instance::create(&e, &name, "generic")
        else {
            panic!("a name one byte too long was accepted");
        };
        assert_eq!(path, longest(&name));
        // And nothing was created for it.
        assert!(!instances_root(&e).join(&name).exists());

        // A 74-character name leaves the control socket 107 bytes and the
        // proxy's socket two over, which is how a live proxy came to bind
        // a truncated `.../dbus/syst`.
        let name = "c".repeat(74);
        assert_eq!(
            e.runtime_dir
                .join("bubbler")
                .join(&name)
                .join(exec::SOCKET_NAME)
                .as_os_str()
                .len(),
            107
        );
        let Err(InstanceError::SocketPathTooLong(path)) = Instance::create(&e, &name, "generic")
        else {
            panic!("a name whose proxy socket is truncated was accepted");
        };
        assert_eq!(path, longest(&name));
    }

    #[test]
    fn save_keeps_the_headers_and_the_file_it_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "ff", "firefox").unwrap();
        let seeded = fs::read_to_string(inst.config_path()).unwrap();
        let mut edited = inst.config.clone();
        edited.services.push(Service::X11);
        edited.desktop = Some("firefox.desktop".to_owned());
        inst.save(&edited).unwrap();

        let text = fs::read_to_string(inst.config_path()).unwrap();
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some(format!("{PROFILE_HEADER}firefox").as_str())
        );
        assert_eq!(
            lines.next(),
            Some(format!("{CONFIG_HEADER}{CONFIG_VERSION}").as_str())
        );
        let reopened = Instance::open(&env, "ff").unwrap();
        assert_eq!(reopened.config, edited);
        // The version header is what stops every later run warning about
        // the meanings the file was written against.
        assert_eq!(reopened.config_version, Some(CONFIG_VERSION));
        assert!(reopened.migration_warning().is_none());
        // What it replaced is kept beside it, and the temporary file the
        // rename went through is gone.
        assert_eq!(
            fs::read_to_string(inst.dir.join(BACKUP_FILE)).unwrap(),
            seeded
        );
        assert!(!inst.dir.join(TEMP_FILE).exists());

        // The profile header survived, so the instance can still be
        // re-flattened from the profile it came from.
        let reseeded = Instance::reseed(&env, "ff").unwrap();
        assert_eq!(reseeded.config, inst.config);
        assert!(reseeded.migration_warning().is_none());
    }

    #[test]
    fn save_writes_no_profile_header_where_the_file_named_no_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "hand", "generic").unwrap();
        // A config written by hand, with neither header.
        fs::write(
            inst.config_path(),
            "wayland
",
        )
        .unwrap();
        let inst = Instance::open(&env, "hand").unwrap();
        assert_eq!(inst.config_version, None);
        inst.save(&inst.config).unwrap();
        let text = fs::read_to_string(inst.config_path()).unwrap();
        // No profile is invented for it: there is none to re-flatten from,
        // and a header naming one would send `reseed` to the wrong file.
        assert_eq!(text, format!("{CONFIG_HEADER}{CONFIG_VERSION}\nwayland\n"));
        assert!(matches!(
            Instance::reseed(&env, "hand"),
            Err(InstanceError::NoProfileHeader(_))
        ));
    }

    #[test]
    fn save_refuses_a_config_it_could_not_read_back() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "c", "generic").unwrap();
        let seeded = fs::read_to_string(inst.config_path()).unwrap();
        // `camera` without `portals` renders, and the parser refuses it:
        // saved, the instance could not be opened again.
        let broken = InstanceConfig {
            services: vec![Service::Camera { nodes: false }],
            ..InstanceConfig::default()
        };
        assert!(matches!(
            inst.save(&broken),
            Err(InstanceError::Config(config::ConfigError::BadArgument { ref node, .. }))
                if node == "camera"
        ));
        // Nothing was touched: not the config, and no backup of it either.
        assert_eq!(fs::read_to_string(inst.config_path()).unwrap(), seeded);
        assert!(!inst.dir.join(BACKUP_FILE).exists());
    }

    #[test]
    fn home_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let inst = Instance::create(&env(tmp.path()), "p", "generic").unwrap();
        let mode = std::fs::metadata(inst.home()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn create_twice_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        Instance::create(&env, "a", "generic").unwrap();
        assert!(matches!(
            Instance::create(&env, "a", "generic"),
            Err(InstanceError::AlreadyExists(_))
        ));
    }

    #[test]
    fn create_on_dangling_symlink_is_already_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let root = instances_root(&env);
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("/nonexistent", root.join("dangle")).unwrap();
        assert!(matches!(
            Instance::create(&env, "dangle", "generic"),
            Err(InstanceError::AlreadyExists(_))
        ));
    }

    #[test]
    fn open_missing_and_bad_names() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        assert!(matches!(
            Instance::open(&env, "zz"),
            Err(InstanceError::NotFound(_))
        ));
        // `try-<digits>` is what `bubbler try` names and sweeps its own
        // sandboxes, so it is not a name a user's instance may take.
        for bad in ["", ".", "..", "-x", "a/b", "a b", "é", "try-1", "try-04321"] {
            assert!(
                matches!(
                    Instance::create(&env, bad, "generic"),
                    Err(InstanceError::InvalidName(_))
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            Instance::create(&env, "ok", "nope"),
            Err(InstanceError::Profile(
                crate::error::ProfileError::NotFound(_)
            ))
        ));
        // Only that exact shape is reserved.
        for ok in ["try", "try-", "try-x", "try-1a", "tryout"] {
            assert!(Instance::create(&env, ok, "generic").is_ok(), "{ok:?}");
        }
    }

    /// The header a seeded file carries, and the warning a file written
    /// before there was one earns: `network` grants a different sandbox
    /// now than it did then, and only the bare node changed meaning.
    #[test]
    fn a_config_without_the_version_header_warns_about_a_bare_network() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "e", "generic").unwrap();
        assert_eq!(inst.config_version, Some(CONFIG_VERSION));
        assert_eq!(inst.migration_warning(), None);

        let cases = [
            ("network\n", true),
            ("network \"host\"\n", false),
            ("network \"none\"\n", false),
            ("wayland\n", false),
            ("// bubbler config: 2\nnetwork\n", false),
            (
                "// bubbler profile: generic\n// bubbler config: 2\nnetwork\n",
                false,
            ),
        ];
        for (text, warns) in cases {
            std::fs::write(inst.config_path(), text).unwrap();
            let opened = Instance::open(&env, "e").unwrap();
            let warning = opened.migration_warning();
            assert_eq!(warning.is_some(), warns, "{text:?}");
            if let Some(w) = warning {
                assert!(w.contains("isolated network namespace"), "{w}");
                // Both ways out: one re-flattens the profile over the
                // file, the other keeps what was written by hand.
                assert!(w.contains("bubbler reseed e"), "{w}");
                assert!(w.contains("bubbler edit e"), "{w}");
                assert!(w.contains("network \"host\""), "{w}");
            }
        }
        // A header recording an older version is as old as none at all.
        std::fs::write(inst.config_path(), "// bubbler config: 1\nnetwork\n").unwrap();
        let old = Instance::open(&env, "e").unwrap();
        assert_eq!(old.config_version, Some(1));
        assert!(old.migration_warning().is_some());

        // A header further down is somebody's notes, not a header.
        std::fs::write(inst.config_path(), "network\n// bubbler config: 2\n").unwrap();
        assert!(
            Instance::open(&env, "e")
                .unwrap()
                .migration_warning()
                .is_some()
        );
    }

    #[test]
    fn marking_the_version_writes_one_header_under_the_profile_line() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "e", "generic").unwrap();
        std::fs::write(inst.config_path(), "// bubbler profile: generic\nnetwork\n").unwrap();
        assert!(Instance::mark_version(&env, "e").unwrap());
        assert_eq!(
            std::fs::read_to_string(inst.config_path()).unwrap(),
            "// bubbler profile: generic\n// bubbler config: 2\nnetwork\n"
        );
        // Idempotent: a file that already records a version is left alone.
        assert!(!Instance::mark_version(&env, "e").unwrap());
        assert_eq!(Instance::open(&env, "e").unwrap().migration_warning(), None);

        // Without a profile header the version goes to the top.
        std::fs::write(inst.config_path(), "network\n").unwrap();
        assert!(Instance::mark_version(&env, "e").unwrap());
        assert_eq!(
            std::fs::read_to_string(inst.config_path()).unwrap(),
            "// bubbler config: 2\nnetwork\n"
        );

        // An older header is replaced where it stands, never doubled.
        std::fs::write(
            inst.config_path(),
            "// bubbler profile: generic\n// bubbler config: 1\nnetwork\n",
        )
        .unwrap();
        assert!(Instance::mark_version(&env, "e").unwrap());
        assert_eq!(
            std::fs::read_to_string(inst.config_path()).unwrap(),
            "// bubbler profile: generic\n// bubbler config: 2\nnetwork\n"
        );
    }

    #[test]
    fn open_reads_edited_config() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "e", "generic").unwrap();
        std::fs::write(inst.config_path(), "network\ncommand \"true\"\n").unwrap();
        let inst = Instance::open(&env, "e").unwrap();
        assert_eq!(
            inst.config.services,
            vec![Service::Network(NetworkConfig::default())]
        );
        assert!(Instance::open(&env, "e").is_ok());
        std::fs::write(inst.config_path(), "bogus\n").unwrap();
        assert!(matches!(
            Instance::open(&env, "e"),
            Err(InstanceError::Config(_))
        ));
    }

    #[test]
    fn delete_removes_instance_and_refuses_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        Instance::create(&env, "a", "generic").unwrap();
        std::fs::write(instances_root(&env).join("a/home/file"), b"x").unwrap();
        let run = env.runtime_dir.join("bubbler").join("a");
        std::fs::create_dir_all(&run).unwrap();
        Instance::delete(&env, "a").unwrap();
        assert!(!instances_root(&env).join("a").exists());
        assert!(!run.exists());
        assert!(matches!(
            Instance::delete(&env, "a"),
            Err(InstanceError::NotFound(_))
        ));
        std::fs::create_dir_all(tmp.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(
            tmp.path().join("elsewhere"),
            instances_root(&env).join("lnk"),
        )
        .unwrap();
        assert!(matches!(
            Instance::delete(&env, "lnk"),
            Err(InstanceError::IsSymlink(_))
        ));
        assert!(tmp.path().join("elsewhere").exists());
    }

    #[test]
    fn config_path_checked_validates_name_and_existence() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        assert!(matches!(
            config_path_checked(&env, "-x"),
            Err(InstanceError::InvalidName(_))
        ));
        assert!(matches!(
            config_path_checked(&env, "zz"),
            Err(InstanceError::NotFound(_))
        ));
        let inst = Instance::create(&env, "b", "generic").unwrap();
        std::fs::write(inst.config_path(), "bogus\n").unwrap();
        assert_eq!(config_path_checked(&env, "b").unwrap(), inst.config_path());
        std::fs::remove_file(inst.config_path()).unwrap();
        std::fs::create_dir(inst.config_path()).unwrap();
        assert!(matches!(
            config_path_checked(&env, "b"),
            Err(InstanceError::NotFound(_))
        ));
    }

    #[test]
    fn ephemeral_is_removed_on_drop_and_never_listed() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        let pid = std::process::id();
        let run = env.runtime_dir.join("bubbler").join(format!("try-{pid}"));
        let dir = {
            let eph = Instance::ephemeral(&env, "generic", &["network"]).unwrap();
            assert_eq!(eph.instance.name, format!("try-{pid}"));
            assert_eq!(eph.instance.dir, try_root(&env).join(pid.to_string()));
            assert_eq!(
                eph.instance.config.services,
                vec![Service::Network(NetworkConfig::default())]
            );
            let mode = fs::metadata(eph.instance.home())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
            assert!(eph.instance.config_path().is_file());
            assert!(Instance::list(&env).unwrap().is_empty());
            fs::create_dir_all(&run).unwrap();
            eph.instance.dir.clone()
        };
        assert!(!dir.exists());
        assert!(!run.exists());
    }

    #[test]
    fn keep_as_turns_a_try_into_an_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        {
            let mut eph = Instance::ephemeral(&env, "generic", &[]).unwrap();
            assert!(matches!(
                eph.keep_as(&env, "-x"),
                Err(InstanceError::InvalidName(_))
            ));
            // The kept name is what the next run's sockets are built
            // from, so `--keep` is refused here rather than by the `run`
            // after it.
            assert!(matches!(
                eph.keep_as(&env, &"k".repeat(100)),
                Err(InstanceError::SocketPathTooLong(_))
            ));
            eph.keep_as(&env, "kept").unwrap();
        }
        assert_eq!(Instance::list(&env).unwrap(), vec!["kept".to_string()]);
        assert!(Instance::open(&env, "kept").unwrap().home().is_dir());
        assert!(try_root(&env).read_dir().unwrap().next().is_none());
        let mut eph = Instance::ephemeral(&env, "generic", &[]).unwrap();
        assert!(matches!(
            eph.keep_as(&env, "kept"),
            Err(InstanceError::AlreadyExists(_))
        ));
    }

    #[test]
    fn grants_are_checked_and_deduplicated() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        let err = Instance::ephemeral(&env, "generic", &["bogus"]).unwrap_err();
        assert!(matches!(err, InstanceError::InvalidGrant(_)));
        assert!(err.to_string().contains("wayland"), "{err}");
        let eph = Instance::ephemeral(&env, "firefox", &["dri", "dri", "network"]).unwrap();
        let services = &eph.instance.config.services;
        assert!(services.contains(&Service::Network(NetworkConfig::default())));
        assert_eq!(services.iter().filter(|s| **s == Service::Dri).count(), 1);
        drop(eph);
        let eph = Instance::ephemeral(&env, "generic", &["gamepad", "dbus", "tray"]).unwrap();
        let services = &eph.instance.config.services;
        assert!(services.contains(&Service::Gamepad {
            hidraw: false,
            uinput: false
        }));
        assert!(services.contains(&Service::Tray));
        drop(eph);
        // A bundle grant without `dbus` is rejected by the parser as
        // usual, and nothing is created for a config that cannot run.
        for grant in ["portals", "tray"] {
            assert!(matches!(
                Instance::ephemeral(&env, "generic", &[grant]),
                Err(InstanceError::Config(_))
            ));
        }
        // `camera` is granted the same way, and takes the `portals` that
        // carry it rather than binding a device node of its own.
        assert!(matches!(
            Instance::ephemeral(&env, "generic", &["camera"]),
            Err(InstanceError::Config(_))
        ));
        assert!(matches!(
            Instance::ephemeral(&env, "generic", &["dbus", "camera"]),
            Err(InstanceError::Config(_))
        ));
        let eph = Instance::ephemeral(&env, "generic", &["dbus", "portals", "camera"]).unwrap();
        assert!(
            eph.instance
                .config
                .services
                .contains(&Service::Camera { nodes: false })
        );
        drop(eph);
        assert!(!try_root(&env).exists() || try_root(&env).read_dir().unwrap().next().is_none());
    }

    #[test]
    fn hidraw_is_a_grant_of_its_own_beside_the_gamepad_spelling() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        let eph = Instance::ephemeral(&env, "generic", &["hidraw"]).unwrap();
        assert_eq!(eph.instance.config.services, vec![Service::Hidraw]);
        drop(eph);
        // The older spelling is a different node, so a profile carrying
        // it does not swallow the grant; the launcher binds once.
        let mut cfg = config::parse("gamepad hidraw=#true").unwrap();
        with_grants(&mut cfg, &["hidraw"]).unwrap();
        assert_eq!(
            cfg.services,
            vec![
                Service::Gamepad {
                    hidraw: true,
                    uinput: false
                },
                Service::Hidraw
            ]
        );
    }

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
    fn a_created_config_names_the_profile_it_was_flattened_from() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "ff", "firefox").unwrap();
        let text = fs::read_to_string(inst.config_path()).unwrap();
        assert!(text.starts_with("// bubbler profile: firefox\n"), "{text}");
        assert_eq!(config::parse(&text).unwrap(), inst.config);
        // What was written is what a later `open` sees.
        assert_eq!(Instance::open(&env, "ff").unwrap().config, inst.config);
    }

    #[test]
    fn a_profile_that_grants_nothing_is_seeded_with_the_starter_comments() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        // `generic` flattens to no nodes, so the file would otherwise hold
        // its header and nothing an editor could work from.
        let inst = Instance::create(&env, "g", "generic").unwrap();
        let text = fs::read_to_string(inst.config_path()).unwrap();
        assert!(text.contains("//   home-share \"Downloads\""), "{text}");
        assert_eq!(config::parse(&text).unwrap(), InstanceConfig::default());

        // A profile with a node of its own is written as itself.
        let inst = Instance::create(&env, "ff", "firefox").unwrap();
        let text = fs::read_to_string(inst.config_path()).unwrap();
        assert!(!text.contains("//   home-share"), "{text}");
    }

    #[test]
    fn sweep_stale_removes_only_dead_pids() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let dead = child.id().to_string();
        child.wait().unwrap();
        let live = std::process::id().to_string();
        // `-1` and `+5` parse as numbers but name no process: sweeping
        // them would mean `kill(-1, 0)`, a whole process group.
        let kept = [live.as_str(), "keepme", "-1", "+5", "0"];
        for n in kept.iter().chain([dead.as_str()].iter()) {
            fs::create_dir_all(try_root(&env).join(n)).unwrap();
        }
        let runtime = env.runtime_dir.join("bubbler");
        for n in ["try-", "inst", "try--1"] {
            fs::create_dir_all(runtime.join(format!("{n}{dead}"))).unwrap();
        }
        fs::create_dir_all(runtime.join(format!("try-{live}"))).unwrap();

        sweep_stale(&env);

        assert!(!try_root(&env).join(&dead).exists());
        for n in kept {
            assert!(try_root(&env).join(n).exists(), "{n}");
        }
        assert!(!runtime.join(format!("try-{dead}")).exists());
        for n in ["inst", "try--1"] {
            assert!(runtime.join(format!("{n}{dead}")).exists(), "{n}");
        }
        assert!(runtime.join(format!("try-{live}")).exists());
    }

    #[test]
    fn a_disarmed_guard_leaves_the_runtime_directory_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        let run = env
            .runtime_dir
            .join("bubbler")
            .join(format!("try-{}", std::process::id()));
        let dir = {
            let mut eph = Instance::ephemeral(&env, "generic", &[]).unwrap();
            fs::create_dir_all(&run).unwrap();
            eph.disarm_runtime();
            eph.instance.dir.clone()
        };
        assert!(!dir.exists());
        assert!(run.is_dir());
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

    /// Write `text` as the user layer's profile `name`.
    fn user_profile(env: &Env, name: &str, text: &str) {
        let dir = env.config_home.join("bubbler").join("profiles");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{name}.kdl")), text).unwrap();
    }

    #[test]
    fn reseed_rewrites_from_the_profile_and_keeps_the_old_file() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        user_profile(&env, "app", "wayland\n");
        let inst = Instance::create(&env, "a", "app").unwrap();
        let before = fs::read_to_string(inst.config_path()).unwrap();
        fs::write(inst.home().join("data"), b"kept").unwrap();

        user_profile(&env, "app", "wayland\nnetwork\n");
        let after = Instance::reseed(&env, "a").unwrap();
        assert!(
            after
                .config
                .services
                .contains(&Service::Network(NetworkConfig::default()))
        );
        assert_eq!(
            fs::read_to_string(after.config_path()).unwrap(),
            "// bubbler profile: app\n// bubbler config: 2\nwayland\nnetwork\n"
        );
        assert_eq!(
            fs::read_to_string(after.dir.join(BACKUP_FILE)).unwrap(),
            before
        );
        // The private home is the point of reseeding rather than
        // recreating: nothing in it is touched.
        assert_eq!(
            fs::read_to_string(after.home().join("data")).unwrap(),
            "kept"
        );

        // A second reseed overwrites the backup rather than refusing.
        user_profile(&env, "app", "dri\n");
        let after = Instance::reseed(&env, "a").unwrap();
        assert!(after.config.services.contains(&Service::Dri));
        assert!(
            fs::read_to_string(after.dir.join(BACKUP_FILE))
                .unwrap()
                .contains("network")
        );

        // The new config is renamed into place from a sibling file, which
        // must not still be there afterwards: a `config.kdl.new` left in
        // the instance directory is a config bubbler would never read.
        let mut left: Vec<_> = fs::read_dir(&after.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, [CONFIG_FILE, BACKUP_FILE, "home"]);
    }

    #[test]
    fn reseed_needs_a_header_and_an_instance_that_is_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = env(tmp.path());
        env.runtime_dir = tmp.path().join("run");
        assert!(matches!(
            Instance::reseed(&env, "gone"),
            Err(InstanceError::NotFound(_))
        ));
        let inst = Instance::create(&env, "a", "generic").unwrap();
        fs::write(inst.config_path(), "wayland\n").unwrap();
        assert!(matches!(
            Instance::reseed(&env, "a"),
            Err(InstanceError::NoProfileHeader(p)) if p == inst.config_path()
        ));
        assert!(!inst.dir.join(BACKUP_FILE).exists());

        // Something answering on the control socket is what "running"
        // means to every other subcommand, so it is what is bound here.
        let sock = crate::exec::socket_path(&env, "a");
        fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        fs::write(inst.config_path(), "// bubbler profile: generic\n").unwrap();
        assert!(matches!(
            Instance::reseed(&env, "a"),
            Err(InstanceError::AlreadyRunning(n)) if n == "a"
        ));
        assert_eq!(
            fs::read_to_string(inst.config_path()).unwrap(),
            "// bubbler profile: generic\n"
        );
        assert!(!inst.dir.join(BACKUP_FILE).exists());
    }
}
