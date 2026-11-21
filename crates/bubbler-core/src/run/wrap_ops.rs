//! Writes to the shim registry and to `~/.local/bin`: making and
//! removing a shim, under the registry lock.

use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, Mode, OFlags, flock};

use crate::env::Env;
use crate::error::WrapError;
use crate::fsutil;
use crate::instance::Instance;
use crate::wrap::{
    Added, Wrap, check_name, is_ours, is_shim_name, load, registry_path, render, shim_dir,
};

// File whose `flock(2)` serialises a read-modify-write of the registry.
// It exists because the registry is *replaced* by a rename, so a lock
// taken on the registry itself would be a lock on an inode the next
// writer no longer has.
const LOCK_FILE: &str = "wraps.kdl.lock";

/// Create the shim `name` for `instance`, pointing at `bubbler`, and
/// record it. Refuses a reserved name, a name that is not one file name,
/// an instance with no `command` to run, a name another instance already
/// holds, and any existing path that is not a shim of bubbler's. A shim
/// of bubbler's is written again, which is how one deleted or left
/// unregistered by a half-finished `wrap` is repaired.
pub fn add(env: &Env, instance: &str, name: &str, bubbler: &Path) -> Result<Added, WrapError> {
    check_name(name)?;
    let inst = Instance::open(env, instance)?;
    // A shim's whole command line is the instance's `command` plus what
    // the user typed, so an instance without one has nothing to run.
    if inst.config.command.is_none() {
        return Err(WrapError::NoCommand(instance.to_owned()));
    }
    let dir = shim_dir(env);
    let path = dir.join(name);
    // Held across the read and the write: two `wrap`s at once would
    // otherwise each write back a registry missing the other's entry.
    let _lock = lock(env)?;
    let mut wraps = load(env)?;
    let held = wraps.iter().position(|w| w.name == name);
    if let Some(i) = held
        && wraps[i].instance != instance
    {
        return Err(WrapError::NameTaken {
            name: name.to_owned(),
            instance: wraps[i].instance.clone(),
        });
    }
    let mut adopted = false;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(WrapError::Io(path, e)),
        // Ours to replace, whatever the registry says about it: a
        // registered name whose link is a stranger's is refused below,
        // so nothing here can repoint a file bubbler did not make.
        Ok(_) if is_ours(&path, bubbler) => adopted = held.is_none(),
        Ok(_) => return Err(WrapError::Occupied(path)),
    }
    fs::create_dir_all(&dir).map_err(|e| WrapError::Io(dir.clone(), e))?;
    let previous = render(&wraps);
    if held.is_none() {
        wraps.push(Wrap {
            name: name.to_owned(),
            instance: instance.to_owned(),
        });
        wraps.sort_by(|a, b| a.name.cmp(&b.name));
    }
    save(env, &wraps)?;
    // The registry goes first because it is what makes a link ours: a
    // link with no entry behind it reads as a stranger's file to the
    // next `wrap`, which would then refuse to touch bubbler's own.
    if let Err(e) = link(bubbler, &dir, name) {
        // The rollback's own failure is reported instead of `e`: it
        // leaves the registry naming a shim that was never made, which
        // is the state the user has to be told about.
        write(env, &previous)?;
        return Err(e);
    }
    Ok(Added { path, adopted })
}

/// Remove the shim `name` and its registry line. The link is deleted
/// only when it is one of bubbler's: a regular file, or a symlink
/// somebody else aimed somewhere else, is not something bubbler made,
/// and it stays where it is while the entry that no longer describes it
/// goes. `bubbler` is the running binary, as for [`crate::wrap::list`].
pub fn remove(env: &Env, name: &str, bubbler: &Path) -> Result<PathBuf, WrapError> {
    // The reserved list is not applied here: a registry naming one is
    // rejected on read, and undoing something is never the moment to
    // refuse a name for what it would shadow.
    if !is_shim_name(name) {
        return Err(WrapError::InvalidName(name.to_owned()));
    }
    let _lock = lock(env)?;
    let mut wraps = load(env)?;
    let i = wraps
        .iter()
        .position(|w| w.name == name)
        .ok_or_else(|| WrapError::NotWrapped(name.to_owned()))?;
    wraps.remove(i);
    let path = shim_dir(env).join(name);
    if is_ours(&path, bubbler) {
        fs::remove_file(&path).map_err(|e| WrapError::Io(path.clone(), e))?;
    }
    save(env, &wraps)?;
    Ok(path)
}

// Point `dir/name` at `target`: the link is made under a name carrying
// this process's pid and renamed over the shim, since `symlink(2)`
// refuses an existing path and unlinking first would leave the shim
// missing in between. `O_EXCL` semantics come free — `symlink(2)` fails
// with `EEXIST` — so a file already under the temporary name is never
// followed and never removed.
fn link(target: &Path, dir: &Path, name: &str) -> Result<(), WrapError> {
    let tmp = dir.join(format!(".{name}.{}.new", std::process::id()));
    std::os::unix::fs::symlink(target, &tmp).map_err(|e| WrapError::Io(tmp.clone(), e))?;
    let path = dir.join(name);
    if let Err(e) = fs::rename(&tmp, &path) {
        // Deliberate: the rename's error is the one to report, and the
        // link being cleaned up is one this call just made.
        let _ = fs::remove_file(&tmp);
        return Err(WrapError::Io(path, e));
    }
    Ok(())
}

// `flock(2)` is released by the kernel when the descriptor closes, so a
// bubbler killed while holding it leaves nothing to time out, unlike a
// lock whose existence is a file.
struct Lock(#[allow(dead_code)] OwnedFd);

fn lock(env: &Env) -> Result<Lock, WrapError> {
    let path = registry_path(env);
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    fs::create_dir_all(&dir).map_err(|e| WrapError::Io(dir.clone(), e))?;
    let path = dir.join(LOCK_FILE);
    // `NOFOLLOW`: the lock is this file, not whatever a link put there.
    let fd = rustix::fs::open(
        &path,
        OFlags::CREATE | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| WrapError::Io(path.clone(), e.into()))?;
    flock(&fd, FlockOperation::LockExclusive).map_err(|e| WrapError::Io(path, e.into()))?;
    Ok(Lock(fd))
}

// Callers hold [`lock`] across the read this replaces.
fn save(env: &Env, wraps: &[Wrap]) -> Result<(), WrapError> {
    write(env, &render(wraps))
}

fn write(env: &Env, text: &str) -> Result<(), WrapError> {
    let path = registry_path(env);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| WrapError::Io(parent.to_path_buf(), e))?;
    }
    fsutil::write_atomic(&path, text).map_err(|(at, e)| WrapError::Io(at, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    use crate::config::MAX_NESTING;
    use crate::env::Env;
    use crate::error::ConfigError;
    use crate::instance;
    use crate::wrap::{Entry, HEADER, REGISTRY_FILE, RESERVED, State, list, lookup, path_warning};

    /// A test root holding a fake bubbler binary, an instance store and
    /// the config home the registry lives in.
    struct Root {
        tmp: tempfile::TempDir,
        env: Env,
        bubbler: PathBuf,
    }

    fn root() -> Root {
        let tmp = tempfile::tempdir().unwrap();
        let env = Env {
            home: tmp.path().join("home"),
            data_home: tmp.path().join("data"),
            config_home: tmp.path().join("config"),
            config_dirs: Vec::new(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: tmp.path().join("run"),
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
            profile_dir_override: Some(tmp.path().join("profiles")),
            proxy_override: None,
            pasta_override: None,
            pw_dump_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
        };
        // Named `bubbler`, since that is what a shim points at.
        let bubbler = tmp.path().join("bin").join("bubbler");
        fs::create_dir_all(bubbler.parent().unwrap()).unwrap();
        fs::write(&bubbler, b"").unwrap();
        Root { tmp, env, bubbler }
    }

    impl Root {
        /// An instance directory with a `config.kdl` naming a command,
        /// which is what a shim needs to have something to run.
        fn instance(&self, name: &str) {
            self.instance_with(name, "command \"/usr/bin/true\"\n");
        }

        fn instance_with(&self, name: &str, text: &str) {
            let dir = instance::instances_root(&self.env).join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("config.kdl"), text).unwrap();
        }

        fn registry(&self) -> String {
            fs::read_to_string(registry_path(&self.env)).unwrap()
        }

        fn add(&self, instance: &str, name: &str) -> Result<Added, WrapError> {
            add(&self.env, instance, name, &self.bubbler)
        }

        fn list(&self) -> Vec<Entry> {
            list(&self.env, &self.bubbler).unwrap()
        }
    }

    #[test]
    fn a_shim_is_a_symlink_the_registry_names() {
        let r = root();
        r.instance("ff");
        let made = r.add("ff", "ff").unwrap();
        assert_eq!(made.path, r.env.home.join(".local/bin/ff"));
        assert!(!made.adopted);
        assert_eq!(fs::read_link(&made.path).unwrap(), r.bubbler);
        assert_eq!(
            r.registry(),
            "// bubbler wraps: 1\nwrap \"ff\" instance=\"ff\"\n"
        );
        assert_eq!(
            load(&r.env).unwrap(),
            vec![Wrap {
                name: "ff".to_owned(),
                instance: "ff".to_owned()
            }]
        );
        let entries = r.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].state, State::Ok);
        assert_eq!(entries[0].path, made.path);
    }

    #[test]
    fn the_registry_round_trips_every_name_it_holds() {
        let r = root();
        r.instance("ff");
        r.instance("dev");
        r.add("ff", "ff").unwrap();
        r.add("dev", "code").unwrap();
        assert_eq!(
            load(&r.env).unwrap(),
            vec![
                Wrap {
                    name: "code".to_owned(),
                    instance: "dev".to_owned()
                },
                Wrap {
                    name: "ff".to_owned(),
                    instance: "ff".to_owned()
                },
            ]
        );
        assert_eq!(
            lookup(&r.env, "code").unwrap(),
            Some(Wrap {
                name: "code".to_owned(),
                instance: "dev".to_owned()
            })
        );
        assert_eq!(lookup(&r.env, "vim").unwrap(), None);
    }

    #[test]
    fn a_missing_registry_is_an_empty_one() {
        let r = root();
        assert!(load(&r.env).unwrap().is_empty());
        assert!(r.list().is_empty());
        assert_eq!(lookup(&r.env, "ff").unwrap(), None);
    }

    #[test]
    fn names_bubbler_resolves_itself_are_refused() {
        let r = root();
        r.instance("ff");
        assert!(RESERVED.contains(&"xdg-dbus-proxy") && RESERVED.contains(&"pasta"));
        for name in RESERVED {
            let e = r.add("ff", name).unwrap_err();
            assert!(matches!(e, WrapError::Reserved(_)), "{name}: {e}");
        }
        assert!(!r.env.home.join(".local/bin").exists());
    }

    #[test]
    fn a_name_that_is_not_one_plain_file_name_is_refused() {
        let r = root();
        r.instance("ff");
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "/usr/bin/x",
            "sub/",
            "-x",
            "a b",
            "a\tb",
            "a\nb",
            "a\u{7f}b",
            "ff+",
        ] {
            let e = r.add("ff", name).unwrap_err();
            assert!(matches!(e, WrapError::InvalidName(_)), "{name:?}: {e}");
        }
    }

    #[test]
    fn wrapping_needs_an_instance_that_exists_and_has_a_command() {
        let r = root();
        let e = r.add("nope", "nope").unwrap_err();
        assert!(matches!(e, WrapError::Instance(_)), "{e}");

        r.instance_with("bare", "wayland\n");
        let e = r.add("bare", "bare").unwrap_err();
        assert!(matches!(e, WrapError::NoCommand(_)), "{e}");
        assert!(load(&r.env).unwrap().is_empty());
    }

    #[test]
    fn a_file_that_is_not_our_shim_is_never_replaced() {
        let r = root();
        r.instance("ff");
        let dir = r.env.home.join(".local/bin");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ff"), b"#!/bin/sh\n").unwrap();
        let e = r.add("ff", "ff").unwrap_err();
        assert!(matches!(e, WrapError::Occupied(_)), "{e}");
        // Neither the file nor the registry moved.
        assert_eq!(fs::read_to_string(dir.join("ff")).unwrap(), "#!/bin/sh\n");
        assert!(load(&r.env).unwrap().is_empty());
    }

    #[test]
    fn a_symlink_aimed_somewhere_else_is_a_strangers_even_once_registered() {
        let r = root();
        r.instance("ff");
        let path = r.add("ff", "ff").unwrap().path;
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/usr/bin/true", &path).unwrap();
        // Registered, and still not ours: neither repointed nor removed.
        assert_eq!(r.list()[0].state, State::Broken);
        let e = r.add("ff", "ff").unwrap_err();
        assert!(matches!(e, WrapError::Occupied(_)), "{e}");
        assert_eq!(fs::read_link(&path).unwrap(), Path::new("/usr/bin/true"));
    }

    #[test]
    fn unwrap_leaves_a_strangers_symlink_where_it_is() {
        let r = root();
        r.instance("ff");
        let path = r.add("ff", "ff").unwrap().path;
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/usr/bin/true", &path).unwrap();
        assert_eq!(remove(&r.env, "ff", &r.bubbler).unwrap(), path);
        assert_eq!(fs::read_link(&path).unwrap(), Path::new("/usr/bin/true"));
        assert!(load(&r.env).unwrap().is_empty());
    }

    #[test]
    fn a_shim_of_ours_the_registry_lost_is_taken_back_over() {
        let r = root();
        r.instance("ff");
        let path = r.add("ff", "ff").unwrap().path;
        write(&r.env, HEADER).unwrap();
        let made = r.add("ff", "ff").unwrap();
        assert!(made.adopted, "an unregistered shim of ours was not adopted");
        assert_eq!(made.path, path);
        assert_eq!(load(&r.env).unwrap().len(), 1);
        // A link pointing at another bubbler binary is still bubbler's.
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/usr/lib/bubbler/bubbler", &path).unwrap();
        assert!(r.add("ff", "ff").is_ok());
        assert_eq!(fs::read_link(&path).unwrap(), r.bubbler);
    }

    #[test]
    fn a_name_already_pointing_elsewhere_is_refused_and_the_same_one_repaired() {
        let r = root();
        r.instance("ff");
        r.instance("dev");
        let path = r.add("ff", "ff").unwrap().path;
        let e = r.add("dev", "ff").unwrap_err();
        assert!(matches!(e, WrapError::NameTaken { .. }), "{e}");
        assert_eq!(load(&r.env).unwrap().len(), 1);

        // The same mapping again repairs a link that was removed by hand.
        fs::remove_file(&path).unwrap();
        assert_eq!(r.list()[0].state, State::Broken);
        assert!(!r.add("ff", "ff").unwrap().adopted);
        assert_eq!(r.list()[0].state, State::Ok);
        assert_eq!(load(&r.env).unwrap().len(), 1);
    }

    #[test]
    fn a_shim_is_broken_when_its_binary_or_its_instance_is_gone() {
        let r = root();
        r.instance("ff");
        r.add("ff", "ff").unwrap();
        fs::remove_file(&r.bubbler).unwrap();
        assert_eq!(r.list()[0].state, State::Broken);

        fs::write(&r.bubbler, b"").unwrap();
        assert_eq!(r.list()[0].state, State::Ok);
        fs::remove_dir_all(instance::instances_root(&r.env).join("ff")).unwrap();
        assert_eq!(r.list()[0].state, State::Broken);
    }

    #[test]
    fn unwrap_removes_the_link_and_the_line() {
        let r = root();
        r.instance("ff");
        let path = r.add("ff", "ff").unwrap().path;
        assert_eq!(remove(&r.env, "ff", &r.bubbler).unwrap(), path);
        assert!(fs::symlink_metadata(&path).is_err());
        assert!(load(&r.env).unwrap().is_empty());
        let e = remove(&r.env, "ff", &r.bubbler).unwrap_err();
        assert!(matches!(e, WrapError::NotWrapped(_)), "{e}");
    }

    #[test]
    fn unwrap_drops_the_line_but_never_deletes_a_real_file() {
        let r = root();
        r.instance("ff");
        let path = r.add("ff", "ff").unwrap().path;
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"someone else's\n").unwrap();
        assert_eq!(remove(&r.env, "ff", &r.bubbler).unwrap(), path);
        assert!(path.is_file());
        assert!(load(&r.env).unwrap().is_empty());
    }

    #[test]
    fn a_registry_bubbler_did_not_write_is_an_error() {
        let r = root();
        let path = registry_path(&r.env);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        for (text, what) in [
            ("wrap \"ff\"\n", "no instance"),
            ("wrap instance=\"ff\"\n", "no name"),
            ("shim \"ff\" instance=\"ff\"\n", "unknown node"),
            ("wrap \"ff\" instance=\"ff\" x=1\n", "unknown property"),
            (
                "wrap \"ff\" instance=\"a\" instance=\"b\"\n",
                "two instances",
            ),
            ("wrap \"a/b\" instance=\"ff\"\n", "name with a separator"),
            ("wrap \"bwrap\" instance=\"ff\"\n", "a name bubbler needs"),
            (
                "wrap \"ff\" instance=\"../x\"\n",
                "instance with a separator",
            ),
            (
                "wrap \"ff\" instance=\"a\"\nwrap \"ff\" instance=\"b\"\n",
                "duplicate",
            ),
            ("wrap \"ff\" instance=\"ff\" { x; }\n", "children"),
        ] {
            fs::write(&path, text).unwrap();
            let e = load(&r.env).unwrap_err();
            assert!(matches!(e, WrapError::Malformed { .. }), "{what}: {e}");
            assert!(e.to_string().contains("wraps.kdl"), "{what}: {e}");
        }
        fs::write(&path, "wrap \"ff\" instance=\n").unwrap();
        let e = load(&r.env).unwrap_err();
        assert!(matches!(e, WrapError::Parse { .. }), "{e}");
    }

    #[test]
    fn a_registry_nested_past_the_bound_is_an_error_and_not_an_abort() {
        let r = root();
        let path = registry_path(&r.env);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let deep = format!("wrap {}\n", "{".repeat(MAX_NESTING + 1));
        fs::write(&path, &deep).unwrap();
        let e = load(&r.env).unwrap_err();
        assert!(
            matches!(
                e,
                WrapError::Parse {
                    source: ConfigError::TooDeep { max, .. },
                    ..
                } if max == MAX_NESTING
            ),
            "{e}"
        );
    }

    #[test]
    fn the_path_check_names_what_would_run_instead() {
        let r = root();
        let dir = r.env.home.join(".local/bin");
        fs::create_dir_all(&dir).unwrap();
        let usr = r.tmp.path().join("usr-bin");
        fs::create_dir_all(&usr).unwrap();
        let program = |name: &str, mode: u32| {
            let p = usr.join(name);
            fs::write(&p, b"").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        };
        program("firefox", 0o755);
        // Not executable, and a directory: neither shadows anything.
        program("code", 0o644);
        fs::create_dir(usr.join("kitty")).unwrap();

        let warning = path_warning(&dir, "firefox", std::slice::from_ref(&usr)).unwrap();
        assert!(warning.contains("not on"), "{warning}");

        let both = [usr.clone(), dir.clone()];
        let warning = path_warning(&dir, "firefox", &both).unwrap();
        assert!(
            warning.contains(&usr.join("firefox").display().to_string()),
            "{warning}"
        );
        assert_eq!(path_warning(&dir, "code", &both), None);
        assert_eq!(path_warning(&dir, "kitty", &both), None);
        assert_eq!(path_warning(&dir, "ff", &both), None);
        assert_eq!(path_warning(&dir, "firefox", &[dir.clone(), usr]), None);
    }

    #[test]
    fn a_file_sitting_under_the_temporary_name_stops_the_link_and_rolls_back() {
        let r = root();
        r.instance("ff");
        let dir = r.env.home.join(".local/bin");
        fs::create_dir_all(&dir).unwrap();
        // The name `link` builds, planted as a regular file: it must be
        // neither followed nor removed, and `symlink(2)` says so itself.
        let planted = dir.join(format!(".ff.{}.new", std::process::id()));
        fs::write(&planted, b"not ours\n").unwrap();
        let e = r.add("ff", "ff").unwrap_err();
        assert!(
            matches!(&e, WrapError::Io(at, e)
                if at == &planted && e.kind() == io::ErrorKind::AlreadyExists),
            "{e}"
        );
        assert_eq!(fs::read_to_string(&planted).unwrap(), "not ours\n");
        assert!(!dir.join("ff").exists());
        // And the entry written ahead of the link is taken back out.
        assert!(load(&r.env).unwrap().is_empty());
    }

    #[test]
    fn the_registry_is_replaced_in_one_step() {
        let r = root();
        r.instance("ff");
        r.add("ff", "ff").unwrap();
        let dir = registry_path(&r.env);
        let dir = dir.parent().unwrap();
        let mut left: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        // The lock file stays; a half-written registry never appears.
        assert_eq!(left, [REGISTRY_FILE, LOCK_FILE]);
        let bin = r.env.home.join(".local/bin");
        let left: Vec<_> = fs::read_dir(&bin)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, [OsString::from("ff")]);
    }
}
