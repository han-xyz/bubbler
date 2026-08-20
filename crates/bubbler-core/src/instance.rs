//! Named instances: a directory with `config.kdl` and a private `home/`.
//! Layout follows bubblejail: `$XDG_DATA_HOME/bubbler/instances/<name>/`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::Mode;

use crate::config::{self, InstanceConfig, Service};
use crate::env::Env;
use crate::error::InstanceError;
use crate::profile;

const CONFIG_FILE: &str = "config.kdl";

/// Directory holding all instances.
pub fn instances_root(env: &Env) -> PathBuf {
    env.data_home.join("bubbler").join("instances")
}

/// Where `name`'s configuration would live, without opening the instance,
/// so a caller can name the file in an error message.
pub fn config_path(env: &Env, name: &str) -> PathBuf {
    instances_root(env).join(name).join(CONFIG_FILE)
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

// A leading `-` is rejected as well: such a name is a valid directory but
// every CLI that takes it would read it as an option.
fn validate_name(name: &str) -> Result<(), InstanceError> {
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('-')
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
        let root = instances_root(env);
        let dir = root.join(name);
        fs::create_dir_all(&root).map_err(io_err(&root))?;
        fs::create_dir(&dir).map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => InstanceError::AlreadyExists(name.to_owned()),
            _ => InstanceError::Io(dir.clone(), e),
        })?;
        let home = dir.join("home");
        rustix::fs::mkdir(&home, Mode::RWXU)
            .map_err(|e| InstanceError::Io(home.clone(), e.into()))?;
        let cfg_path = dir.join(CONFIG_FILE);
        fs::write(&cfg_path, text).map_err(io_err(&cfg_path))?;
        Ok(Self {
            name: name.to_owned(),
            dir,
            config,
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
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
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
        for bad in ["", ".", "..", "-x", "a/b", "a b", "é"] {
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
}
