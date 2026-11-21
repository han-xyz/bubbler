//! Launcher entries on disk: finding the vendor entry to copy, writing
//! and removing bubbler's own, and the desktop tools that check and
//! index them.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::InstanceConfig;
use crate::desktop::{Dirs, command_name, exec_program, head, owner, patch};
use crate::error::DesktopError;
use crate::fsutil;

// Name of the `bubbler` binary as an entry's `Exec` may name it.
const BINARY: &str = "bubbler";

/// The vendor entry an instance's launcher entry is copied from: the
/// `desktop` node if the config has one, else `<command>.desktop`, else
/// the one entry whose `Exec` runs `<command>`.
///
/// Entries bubbler generated are never a source; neither are entries a
/// launcher does not display — a `desktop` node excepted, since that is
/// the user naming the file. Two candidates are an error rather than a
/// guess.
pub fn source(dirs: &Dirs, name: &str, config: &InstanceConfig) -> Result<PathBuf, DesktopError> {
    if let Some(hint) = &config.desktop {
        return find(dirs, OsStr::new(hint), false).ok_or_else(|| DesktopError::HintNotFound {
            name: hint.clone(),
            dirs: dirs.lookup().map(Path::to_path_buf).collect(),
        });
    }
    let command = command_name(config).ok_or_else(|| DesktopError::NoCommand(name.to_owned()))?;
    let mut exact = command.to_os_string();
    exact.push(".desktop");
    if let Some(path) = find(dirs, &exact, true) {
        return Ok(path);
    }
    let mut candidates = scan(dirs, command);
    match candidates.len() {
        0 => Err(DesktopError::NotFound {
            command: command.to_string_lossy().into_owned(),
        }),
        1 => Ok(candidates.remove(0)),
        _ => Err(DesktopError::Ambiguous {
            command: command.to_string_lossy().into_owned(),
            candidates: candidates
                .iter()
                .map(|p| p.file_name().unwrap_or(p.as_os_str()).to_string_lossy())
                .map(std::borrow::Cow::into_owned)
                .collect(),
        }),
    }
}

// The first directory holding `file` as an entry bubbler did not write.
// With `shown`, an entry a launcher does not display is passed over as
// well, which is what the `<command>.desktop` step wants: a name that
// happens to match a MIME-handler-only entry is the same wrong answer
// there as in the scan. A `desktop` hint sets it false, because that is
// the user naming the file they mean.
fn find(dirs: &Dirs, file: &OsStr, shown: bool) -> Option<PathBuf> {
    dirs.lookup().map(|d| d.join(file)).find(|p| {
        std::fs::read_to_string(p).is_ok_and(|t| {
            let head = head(&t);
            head.marker.is_none() && !(shown && head.no_display)
        })
    })
}

// Every entry whose `Exec` runs `command`, in lookup order, one per file
// name: a user's own copy of an entry shadows the system's, the way a
// launcher resolves it.
fn scan(dirs: &Dirs, command: &OsStr) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for dir in dirs.lookup() {
        let mut names: Vec<OsString> = match std::fs::read_dir(dir) {
            Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
            Err(_) => continue,
        };
        names.sort();
        for name in names {
            if Path::new(&name).extension() != Some(OsStr::new("desktop")) {
                continue;
            }
            if found.iter().any(|p| p.file_name() == Some(&name)) {
                continue;
            }
            let path = dir.join(&name);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let head = head(&text);
            if head.marker.is_some() || head.no_display || head.hidden {
                continue;
            }
            let runs = head
                .exec
                .and_then(exec_program)
                .is_some_and(|p| Path::new(&p).file_name() == Some(command));
            if runs {
                found.push(path);
            }
        }
    }
    found
}

/// The generated entry for `instance`, from the vendor file at `source`.
pub fn render(source: &Path, instance: &str, program: &Path) -> Result<String, DesktopError> {
    let text = std::fs::read_to_string(source).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData => DesktopError::NotUtf8(source.to_path_buf()),
        _ => DesktopError::Io(source.to_path_buf(), e),
    })?;
    patch(&text, instance, program)
}

/// Write `text` to `path`, refusing every file that is not this
/// instance's own entry: bubbler never overwrites a file it did not
/// write, and does not guess who wrote one it cannot recognise.
pub fn write(path: &Path, text: &str, instance: &str) -> Result<(), DesktopError> {
    match std::fs::symlink_metadata(path) {
        // A symlink is never bubbler's entry, whatever it points at.
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(DesktopError::Foreign(path.to_path_buf()));
        }
        Ok(_) => match std::fs::read_to_string(path) {
            Ok(held) => match owner(&held) {
                Some(o) if o == instance => {}
                Some(o) => {
                    return Err(DesktopError::OtherInstance {
                        path: path.to_path_buf(),
                        instance: o.to_owned(),
                    });
                }
                None => return Err(DesktopError::Foreign(path.to_path_buf())),
            },
            // A file that is not even UTF-8 is not an entry of bubbler's.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(DesktopError::Foreign(path.to_path_buf()));
            }
            Err(e) => return Err(DesktopError::Io(path.to_path_buf(), e)),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(DesktopError::Io(path.to_path_buf(), e)),
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DesktopError::Io(parent.to_path_buf(), e))?;
    }
    // The sibling it writes through is dot-prefixed and does not end in
    // `.desktop`, so neither a launcher nor `update-desktop-database`
    // reads it as an entry while it is there.
    fsutil::write_atomic(path, text).map_err(|(at, e)| DesktopError::Io(at, e))
}

/// Every entry bubbler generated, as `(path, instance)`, sorted by path.
/// Only the user's directory: it is the only one bubbler writes.
pub fn generated(dirs: &Dirs) -> Vec<(PathBuf, String)> {
    let mut names: Vec<OsString> = match std::fs::read_dir(&dirs.user) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
        Err(_) => return Vec::new(),
    };
    names.sort();
    names
        .into_iter()
        .filter(|n| Path::new(n).extension() == Some(OsStr::new("desktop")))
        .filter_map(|n| {
            let path = dirs.user.join(n);
            let text = std::fs::read_to_string(&path).ok()?;
            Some((path, owner(&text)?.to_owned()))
        })
        .collect()
}

/// Delete this instance's generated entries, and only those: a file
/// without bubbler's marker is left where it is. The paths removed.
pub fn remove(dirs: &Dirs, instance: &str) -> Result<Vec<PathBuf>, DesktopError> {
    let mine: Vec<PathBuf> = generated(dirs)
        .into_iter()
        .filter(|(_, owner)| owner == instance)
        .map(|(path, _)| path)
        .collect();
    if mine.is_empty() {
        return Err(DesktopError::NotGenerated {
            instance: instance.to_owned(),
            dir: dirs.user.clone(),
        });
    }
    for path in &mine {
        std::fs::remove_file(path).map_err(|e| DesktopError::Io(path.clone(), e))?;
    }
    Ok(mine)
}

/// What a generated entry should call to reach this bubbler: the bare
/// name where `PATH` resolves it to this very binary, else the absolute
/// path. A launcher shows no entry at all when it cannot find the
/// program, so a dev build must name itself where it actually is.
pub fn program(exe: &Path, search_path: &[PathBuf]) -> PathBuf {
    let real = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    // Only the first executable of that name counts, because that is
    // where a `PATH` search stops: another bubbler ahead of this one
    // means the bare name would start that binary instead, and one
    // behind it is never reached at all.
    let first = search_path
        .iter()
        .map(|dir| dir.join(BINARY))
        .find(|candidate| executable(candidate))
        .and_then(|candidate| std::fs::canonicalize(candidate).ok());
    match first.is_some_and(|found| found == real) {
        true => PathBuf::from(BINARY),
        false => real,
    }
}

// Whether `path` is a file a `PATH` search would run: a name without an
// execute bit is one the search passes over.
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// What `desktop-file-validate` calls an error in the entry at `path`,
/// empty when it is installed and content with the file, and empty when
/// it is not installed at all. Its hints and warnings are left out: they
/// are about the application's own file, which bubbler copied and is not
/// in a position to fix.
pub fn validate(path: &Path) -> Vec<String> {
    let Ok(out) = Command::new("desktop-file-validate").arg(path).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("error:"))
        .map(str::to_owned)
        .collect()
}

/// Rebuild the launcher's MIME cache for `dir`. `false` when
/// `update-desktop-database` is not installed, which costs the entry its
/// place in "Open With" lists and nothing else.
pub fn update_database(dir: &Path) -> Result<bool, DesktopError> {
    // Its exit status is not read: what it reports about other files in
    // the directory is not this entry's business.
    match Command::new("update-desktop-database")
        .arg(dir)
        .stdout(Stdio::null())
        .status()
    {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(DesktopError::Io(dir.to_path_buf(), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    use crate::desktop::target;
    use crate::desktop::test_support::{FIREFOX, KEEPASSXC, KITTY, KITTY_PATCHED, STEAM, patched};

    fn dirs(root: &Path) -> Dirs {
        Dirs {
            user: root.join("user"),
            system: vec![root.join("system")],
        }
    }

    fn put(dir: &Path, name: &str, text: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    /// A file a `PATH` search would run, or, without an execute bit, one
    /// it would pass over.
    fn put_binary(dir: &Path, name: &str, mode: u32) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn config(command: &str) -> InstanceConfig {
        InstanceConfig {
            command: Some(vec![OsString::from(command)]),
            ..InstanceConfig::default()
        }
    }

    #[test]
    fn a_source_that_is_not_a_desktop_entry_at_all_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("binary.desktop");
        std::fs::write(&path, [0xff, 0xfe, b'\n']).unwrap();
        assert!(matches!(
            render(&path, "i", Path::new("/usr/bin/bubbler")),
            Err(DesktopError::NotUtf8(p)) if p == path
        ));
        let missing = tmp.path().join("gone.desktop");
        assert!(matches!(
            render(&missing, "i", Path::new("/usr/bin/bubbler")),
            Err(DesktopError::Io(p, _)) if p == missing
        ));
        let path = put(tmp.path(), "kitty.desktop", KITTY);
        assert_eq!(
            render(&path, "kt", Path::new("/usr/bin/bubbler")).unwrap(),
            KITTY_PATCHED
        );
    }

    #[test]
    fn a_generated_entry_passes_desktop_file_validate() {
        let tmp = tempfile::tempdir().unwrap();
        let mut checked = 0;
        for (name, text) in [
            ("bubbler-kt.desktop", KITTY),
            ("bubbler-ff.desktop", FIREFOX),
            ("bubbler-kp.desktop", KEEPASSXC),
            ("bubbler-st.desktop", STEAM),
        ] {
            let path = put(tmp.path(), name, &patched(text, "t"));
            let out = match Command::new("desktop-file-validate").arg(&path).output() {
                Ok(out) => out,
                // Not installed here; the generator's own tests are what
                // the goldens above are for.
                Err(_) => return,
            };
            let said = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(!said.contains("error:"), "{name}: {said}");
            checked += 1;
        }
        assert_eq!(checked, 4);
    }

    #[test]
    fn the_source_is_the_hint_then_the_command_name_then_the_one_entry_that_runs_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let system = tmp.path().join("system");
        put(&system, "kitty.desktop", KITTY);
        let by_name = system.join("kitty.desktop");
        assert_eq!(source(&dirs, "kt", &config("kitty")).unwrap(), by_name);
        // A command run from an absolute path is looked up by its
        // basename, the way the entry names it.
        assert_eq!(
            source(&dirs, "kt", &config("/usr/bin/kitty")).unwrap(),
            by_name
        );
        // No `kp.desktop`, one entry whose `Exec` runs `kp`.
        let scanned = put(
            &system,
            "org.example.Kp.desktop",
            "[Desktop Entry]\nExec=kp %f\n",
        );
        assert_eq!(source(&dirs, "i", &config("kp")).unwrap(), scanned);
        // The hint wins over both, and names a file, not a path.
        let cfg = InstanceConfig {
            desktop: Some("org.example.Kp.desktop".to_owned()),
            ..config("kitty")
        };
        assert_eq!(source(&dirs, "i", &cfg).unwrap(), scanned);
        let cfg = InstanceConfig {
            desktop: Some("nothere.desktop".to_owned()),
            ..config("kitty")
        };
        assert!(matches!(
            source(&dirs, "i", &cfg),
            Err(DesktopError::HintNotFound { name, .. }) if name == "nothere.desktop"
        ));
    }

    #[test]
    fn an_entry_a_launcher_hides_is_no_source_unless_the_hint_names_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let system = tmp.path().join("system");
        // The `<command>.desktop` step is a lookup by name rather than a
        // scan, and a MIME-handler-only entry named after the command is
        // the same wrong answer there as it is in the scan.
        put(
            &system,
            "l.desktop",
            "[Desktop Entry]\nExec=l %f\nNoDisplay=true\n",
        );
        let shown = put(
            &system,
            "net.example.L.desktop",
            "[Desktop Entry]\nExec=l %U\n",
        );
        assert_eq!(source(&dirs, "i", &config("l")).unwrap(), shown);
        // A `desktop` node is the user naming the file they mean, so it
        // reaches even the entry nothing would have found on its own.
        let cfg = InstanceConfig {
            desktop: Some("l.desktop".to_owned()),
            ..config("l")
        };
        assert_eq!(source(&dirs, "i", &cfg).unwrap(), system.join("l.desktop"));
    }

    #[test]
    fn a_users_own_entry_shadows_the_systems_and_bubblers_own_is_no_source() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let (user, system) = (tmp.path().join("user"), tmp.path().join("system"));
        put(&system, "kitty.desktop", KITTY);
        let mine = put(
            &user,
            "kitty.desktop",
            "[Desktop Entry]\nExec=kitty --mine\n",
        );
        assert_eq!(source(&dirs, "kt", &config("kitty")).unwrap(), mine);
        // bubbler's own entry for the same file name is skipped, so the
        // vendor's is found again and `--replace` stays idempotent.
        put(&user, "kitty.desktop", &patched(KITTY, "kt"));
        assert_eq!(
            source(&dirs, "kt", &config("kitty")).unwrap(),
            system.join("kitty.desktop")
        );
    }

    #[test]
    fn two_entries_for_one_command_are_listed_rather_than_guessed_between() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let system = tmp.path().join("system");
        put(
            &system,
            "net.example.L.desktop",
            "[Desktop Entry]\nExec=l %U\n",
        );
        put(
            &system,
            "net.example.L1.desktop",
            "[Desktop Entry]\nExec=l --install %f\n",
        );
        let err = source(&dirs, "i", &config("l")).unwrap_err();
        let DesktopError::Ambiguous { candidates, .. } = &err else {
            panic!("{err}");
        };
        assert_eq!(
            candidates,
            &["net.example.L.desktop", "net.example.L1.desktop"]
        );
        assert!(err.to_string().contains("`desktop \"<name>.desktop\"`"));
        // The one a launcher does not show is not a candidate at all.
        put(
            &system,
            "net.example.L1.desktop",
            "[Desktop Entry]\nExec=l --install %f\nNoDisplay=true\n",
        );
        assert_eq!(
            source(&dirs, "i", &config("l")).unwrap(),
            system.join("net.example.L.desktop")
        );
        // And nothing that runs it at all is its own answer.
        assert!(matches!(
            source(&dirs, "i", &config("nothing")),
            Err(DesktopError::NotFound { .. })
        ));
        assert!(matches!(
            source(&dirs, "i", &InstanceConfig::default()),
            Err(DesktopError::NoCommand(i)) if i == "i"
        ));
    }

    #[test]
    fn only_bubblers_own_entry_for_this_instance_is_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let path = target(
            &dirs,
            "kt",
            Path::new("/usr/share/applications/kitty.desktop"),
            false,
        );
        assert_eq!(path, dirs.user.join("bubbler-kt.desktop"));
        assert_eq!(
            target(
                &dirs,
                "kt",
                Path::new("/usr/share/applications/kitty.desktop"),
                true
            ),
            dirs.user.join("kitty.desktop")
        );
        // A directory nothing has created yet is created here.
        write(&path, &patched(KITTY, "kt"), "kt").unwrap();
        assert_eq!(owner(&std::fs::read_to_string(&path).unwrap()), Some("kt"));
        // Ours for this instance: a plain overwrite.
        write(&path, &patched(KEEPASSXC, "kt"), "kt").unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("KeePassXC")
        );
        // Ours for another instance, and a file that is not ours at all.
        assert!(matches!(
            write(&path, "x", "other"),
            Err(DesktopError::OtherInstance { instance, .. }) if instance == "kt"
        ));
        let foreign = put(&dirs.user, "kitty.desktop", KITTY);
        assert!(matches!(
            write(&foreign, "x", "kt"),
            Err(DesktopError::Foreign(p)) if p == foreign
        ));
        assert_eq!(std::fs::read_to_string(&foreign).unwrap(), KITTY);
        // A symlink is never bubbler's, whatever it points at.
        let link = dirs.user.join("bubbler-link.desktop");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            write(&link, "x", "kt"),
            Err(DesktopError::Foreign(_))
        ));
    }

    #[test]
    fn a_symlink_planted_where_the_entry_is_built_is_never_written_through() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        std::fs::create_dir_all(&dirs.user).unwrap();
        let path = dirs.user.join("bubbler-kt.desktop");
        // The sibling `fsutil::write_atomic` builds in, aimed at a file
        // of the user's: it is created with `O_EXCL`, so the write fails
        // rather than following it.
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"mine\n").unwrap();
        let sibling = dirs
            .user
            .join(format!(".bubbler-kt.desktop.{}.new", std::process::id()));
        std::os::unix::fs::symlink(&victim, &sibling).unwrap();
        assert!(matches!(
            write(&path, &patched(KITTY, "kt"), "kt"),
            Err(DesktopError::Io(at, _)) if at == sibling
        ));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "mine\n");
        assert!(!path.exists());
        // The failed attempt takes the name it could not use with it, so
        // the next one writes the entry, and as a regular file.
        assert!(std::fs::symlink_metadata(&sibling).is_err());
        write(&path, &patched(KITTY, "kt"), "kt").unwrap();
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_file()
        );
    }

    #[test]
    fn remove_deletes_this_instances_entries_and_leaves_every_other_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let mine = put(&dirs.user, "bubbler-kt.desktop", &patched(KITTY, "kt"));
        let shadow = put(&dirs.user, "kitty.desktop", &patched(KITTY, "kt"));
        let theirs = put(&dirs.user, "bubbler-ff.desktop", &patched(FIREFOX, "ff"));
        let foreign = put(&dirs.user, "other.desktop", KITTY);
        assert_eq!(
            generated(&dirs),
            vec![
                (theirs.clone(), "ff".to_owned()),
                (mine.clone(), "kt".to_owned()),
                (shadow.clone(), "kt".to_owned()),
            ]
        );
        let mut removed = remove(&dirs, "kt").unwrap();
        removed.sort();
        assert_eq!(removed, vec![mine, shadow]);
        assert!(theirs.is_file() && foreign.is_file());
        assert!(matches!(
            remove(&dirs, "kt"),
            Err(DesktopError::NotGenerated { instance, .. }) if instance == "kt"
        ));
    }

    #[test]
    fn the_entry_names_bubbler_bare_only_where_path_resolves_to_this_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let (bin, other) = (tmp.path().join("bin"), tmp.path().join("other"));
        std::fs::create_dir_all(&other).unwrap();
        let exe = put_binary(&bin, BINARY, 0o755);
        let path = [other.clone(), bin.clone()];
        // Nothing of that name earlier on PATH, so the search reaches
        // this one and the bare name is what a launcher resolves.
        assert_eq!(program(&exe, &path), PathBuf::from(BINARY));
        // A different bubbler earlier on PATH is the one the bare name
        // would start, so this entry has to name its own binary.
        let theirs = put_binary(&other, BINARY, 0o755);
        assert_eq!(program(&exe, &path), exe);
        // One without an execute bit is not what the search finds, so
        // the bare name reaches this binary again.
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(program(&exe, &path), PathBuf::from(BINARY));
        assert_eq!(program(&exe, &[]), exe);
        // A symlink on PATH to this binary is this binary.
        let link = other.join("link");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        assert_eq!(
            program(&link, std::slice::from_ref(&bin)),
            PathBuf::from(BINARY)
        );
    }
}
