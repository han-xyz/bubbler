//! Named instances: a directory with `config.kdl` and a private `home/`.
//! Layout follows bubblejail: `$XDG_DATA_HOME/bubbler/instances/<name>/`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::Mode;
use rustix::io::Errno;
use rustix::process::{Pid, test_kill_process};

use crate::config::{self, InstanceConfig, Service};
use crate::env::Env;
use crate::error::InstanceError;
use crate::profile;

const CONFIG_FILE: &str = "config.kdl";

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
}

/// Whether `name` is the shape [`Instance::ephemeral`] gives a throwaway
/// sandbox, `try-<pid>`, whose runtime directory is swept once that pid is
/// gone. An instance of that name would have its own swept out from under it.
fn is_try_name(name: &str) -> bool {
    name.strip_prefix("try-")
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

// A leading `-` is rejected as well: such a name is a valid directory but
// every CLI that takes it would read it as an option.
fn validate_name(name: &str) -> Result<(), InstanceError> {
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('-')
        && !is_try_name(name)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(InstanceError::InvalidName(name.to_owned()))
    }
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> InstanceError + '_ {
    move |e| InstanceError::Io(path.to_path_buf(), e)
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

/// Profile text plus one bare node per grant. A grant the text already
/// has as a bare line is skipped: the parser rejects duplicates.
fn with_grants(text: &str, grants: &[&str]) -> Result<String, InstanceError> {
    let mut out = text.to_owned();
    for g in grants {
        if !GRANTS.contains(g) {
            return Err(InstanceError::InvalidGrant((*g).to_owned()));
        }
        if out.lines().any(|l| l.trim() == *g) {
            continue;
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(g);
        out.push('\n');
    }
    Ok(out)
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
    /// starts.
    pub fn keep_as(&mut self, name: &str) -> Result<(), InstanceError> {
        validate_name(name)?;
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

    /// Create a new instance seeded from a built-in profile. Fails if the
    /// directory already exists; never overwrites.
    pub fn create(env: &Env, name: &str, profile_name: &str) -> Result<Self, InstanceError> {
        validate_name(name)?;
        let text = profile::lookup(profile_name)
            .ok_or_else(|| InstanceError::UnknownProfile(profile_name.to_owned()))?;
        let config = config::parse(text)?;
        let dir = instances_root(env).join(name);
        make_dir(&dir, name, text)?;
        Ok(Self {
            name: name.to_owned(),
            dir,
            config,
        })
    }

    /// Create a throwaway instance seeded from a profile plus one bare
    /// node per grant, named `try-<pid>` so its runtime directory is its
    /// own. The guard removes it again when it drops.
    pub fn ephemeral(
        env: &Env,
        profile_name: &str,
        grants: &[&str],
    ) -> Result<Ephemeral, InstanceError> {
        sweep_stale(env);
        let text = profile::lookup(profile_name)
            .ok_or_else(|| InstanceError::UnknownProfile(profile_name.to_owned()))?;
        let text = with_grants(text, grants)?;
        let config = config::parse(&text)?;
        let pid = std::process::id();
        let name = format!("try-{pid}");
        let dir = try_root(env).join(pid.to_string());
        let runtime = env.runtime_dir.join("bubbler").join(&name);
        // Only this process can be the live owner of try/<own pid>, so a
        // directory there is a leftover from a bubbler whose pid was reused.
        if let Err(e) = fs::remove_dir_all(&dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(InstanceError::Io(dir, e));
        }
        make_dir(&dir, &name, &text)?;
        Ok(Ephemeral {
            instance: Self { name, dir, config },
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
            runtime_dir: "/run/user/1000".into(),
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
            proxy_override: None,
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
            Err(InstanceError::UnknownProfile(_))
        ));
        // Only that exact shape is reserved.
        for ok in ["try", "try-", "try-x", "try-1a", "tryout"] {
            assert!(Instance::create(&env, ok, "generic").is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn open_reads_edited_config() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env(tmp.path());
        let inst = Instance::create(&env, "e", "generic").unwrap();
        std::fs::write(inst.config_path(), "network\ncommand \"true\"\n").unwrap();
        let inst = Instance::open(&env, "e").unwrap();
        assert_eq!(inst.config.services, vec![Service::Network]);
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
            assert_eq!(eph.instance.config.services, vec![Service::Network]);
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
                eph.keep_as("-x"),
                Err(InstanceError::InvalidName(_))
            ));
            eph.keep_as("kept").unwrap();
        }
        assert_eq!(Instance::list(&env).unwrap(), vec!["kept".to_string()]);
        assert!(Instance::open(&env, "kept").unwrap().home().is_dir());
        assert!(try_root(&env).read_dir().unwrap().next().is_none());
        let mut eph = Instance::ephemeral(&env, "generic", &[]).unwrap();
        assert!(matches!(
            eph.keep_as("kept"),
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
        assert!(services.contains(&Service::Network));
        assert_eq!(services.iter().filter(|s| **s == Service::Dri).count(), 1);
        drop(eph);
        // `portals` without `dbus` is rejected by the parser as usual, and
        // nothing is created for a config that cannot run.
        assert!(matches!(
            Instance::ephemeral(&env, "generic", &["portals"]),
            Err(InstanceError::Config(_))
        ));
        assert!(!try_root(&env).exists() || try_root(&env).read_dir().unwrap().next().is_none());
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
}
