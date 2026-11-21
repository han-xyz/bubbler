//! The per-instance runtime directory and the sidecar directories in it: created private, and
//! cleared of what dead runs left without following it.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::config::Service;
use crate::env::Env;
use crate::instance::Instance;
use crate::launch_error::LaunchError;
use crate::paths::{RUNTIME_SUBDIR, instance_runtime_dir};
use crate::service;
use bubbler_plan::plan_error::PlanError;

// ENOSYS (no `CONFIG_KEYS`) is not a failure: there is no keyring to inherit either. rustix
// wraps no keyring call, hence `libc`.
pub(super) fn join_session_keyring() -> io::Result<()> {
    // SAFETY: one syscall taking its arguments by value, allocating
    // nothing and touching no memory of this process — async-signal-safe,
    // which is what a `pre_exec` closure is held to. The null name is
    // what asks for a fresh anonymous keyring rather than a named one.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            u64::from(libc::KEYCTL_JOIN_SESSION_KEYRING),
            0u64,
        )
    };
    if rc >= 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS) => Ok(()),
        _ => Err(err),
    }
}

// For the proxy's `pre_exec`, where `format!` would allocate in a forked child.
pub(super) fn decimal(value: i32, buf: &mut [u8; 10]) -> &[u8] {
    let mut value = value.unsigned_abs();
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 || at == 0 {
            break;
        }
    }
    &buf[at..]
}

pub(super) fn open_dir(path: &Path) -> Result<OwnedFd, LaunchError> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))
}

// An existing directory is reused as is: only the user can create under `$XDG_RUNTIME_DIR`.
pub(super) fn mkdir_private(dir: &Path) -> Result<(), LaunchError> {
    match rustix::fs::mkdir(dir, Mode::RWXU) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(LaunchError::Io(dir.to_path_buf(), e.into())),
    }
}

// Bounds how long clearing dead runs' leftovers delays one start; the next start takes up
// the rest.
const LEFTOVER_BUDGET: usize = 100_000;

// Only after this run's control-socket bind found no live run. Only one start at a time gets
// there, and a run that is ending holds a start back until its teardown is done — except for a
// start that binds in the moment between the sandbox's exit and the ending run taking the lock.
// What is at the name is moved aside and removed best-effort, never followed.
pub(super) fn fresh_sidecar_dir(dir: &Path) -> Result<(), LaunchError> {
    let io_at = |e: Errno| LaunchError::Io(dir.to_path_buf(), e.into());
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        unreachable!("a sidecar directory is named inside the instance's");
    };
    let at = open_dir(parent)?;
    match rustix::fs::statat(&at, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => clear_leftovers(&at, name),
        Err(e) => return Err(io_at(e)),
        Ok(_) => move_aside(&at, parent, name).map_err(io_at)?,
    }
    rustix::fs::mkdirat(&at, name, Mode::RWXU).map_err(io_at)
}

// A rename within bubbler's own directory: no mode or depth refuses it, and a link moves as
// the link.
pub(super) fn move_aside(at: &OwnedFd, dir: &Path, name: &OsStr) -> rustix::io::Result<()> {
    let moved = rename_to_free(at, name, at, &mut 0, |seq| leftover_name(name, seq))?;
    clear_leftovers(at, name);
    if rustix::fs::statat(at, &moved, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
        eprintln!(
            "bubbler: warning: {} is what a sidecar left and could not be removed in full; the next start tries again",
            dir.join(moved).display()
        );
    }
    Ok(())
}

// Only once the sidecar has exited. Not `std::fs::remove_dir_all`: it recurses, and a deep
// enough tree overflows the stack.
pub(super) fn remove_sidecar_dir(dir: &Path) {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        return;
    };
    let Ok(at) = open_dir(parent) else {
        return;
    };
    let _ = remove_tree(&at, name, &mut LEFTOVER_BUDGET.clone());
}

// Only bubbler writes the instance's runtime directory, so the name need not be unguessable.
fn leftover_name(name: &OsStr, seq: u64) -> OsString {
    let mut aside = leftover_prefix(name);
    aside.push(format!("{}.{seq}", std::process::id()));
    aside
}

fn leftover_prefix(name: &OsStr) -> OsString {
    let mut prefix = name.to_owned();
    prefix.push(".leftover.");
    prefix
}

// A failure is left for the next start; the start that moved the tree aside already warned.
fn clear_leftovers(at: &OwnedFd, name: &OsStr) {
    let prefix = leftover_prefix(name);
    let mut budget = LEFTOVER_BUDGET;
    // Only bubbler writes the instance's directory, so its width is not a
    // sidecar's to choose.
    let Ok(names) = entry_names(at, usize::MAX) else {
        return;
    };
    for leftover in names {
        if leftover.as_bytes().starts_with(prefix.as_bytes()) {
            let _ = remove_tree(at, &leftover, &mut budget);
        }
    }
}

// Never replaces an entry; `seq` is left past the name taken.
fn rename_to_free(
    from: &OwnedFd,
    name: &OsStr,
    to: &OwnedFd,
    seq: &mut u64,
    make: impl Fn(u64) -> OsString,
) -> rustix::io::Result<OsString> {
    loop {
        let new = make(*seq);
        *seq += 1;
        match rustix::fs::renameat_with(from, name, to, &new, rustix::fs::RenameFlags::NOREPLACE) {
            Err(Errno::EXIST) => {}
            Err(e) => return Err(e),
            Ok(()) => return Ok(new),
        }
    }
}

// Names read before acting on them, so a directory of any width costs bounded memory.
const READ_BATCH: usize = 1024;

// A fixed number of descriptors at any depth: each pass empties the directories in the top
// one and lifts their contents into it. Work done before `EAGAIN` stays done.
fn remove_tree(at: &OwnedFd, name: &OsStr, budget: &mut usize) -> rustix::io::Result<()> {
    let Some(top) = unlink_or_open(at, name)? else {
        return Ok(());
    };
    let mut lifted = 0;
    loop {
        let names = entry_names(&top, READ_BATCH)?;
        if names.is_empty() {
            break;
        }
        for entry in names {
            spend(budget)?;
            let Some(inner) = unlink_or_open(&top, &entry)? else {
                continue;
            };
            loop {
                let subs = entry_names(&inner, READ_BATCH)?;
                if subs.is_empty() {
                    break;
                }
                for sub in subs {
                    spend(budget)?;
                    if unlink_or_open(&inner, &sub)?.is_some() {
                        rename_to_free(&inner, &sub, &top, &mut lifted, |seq| {
                            OsString::from(seq.to_string())
                        })?;
                    }
                }
            }
            rustix::fs::unlinkat(&top, &entry, AtFlags::REMOVEDIR)?;
        }
    }
    rustix::fs::unlinkat(at, name, AtFlags::REMOVEDIR)
}

fn spend(budget: &mut usize) -> rustix::io::Result<()> {
    *budget = budget.checked_sub(1).ok_or(Errno::AGAIN)?;
    Ok(())
}

// A sidecar can leave a directory no one may read or move; the mode changes on the opened
// directory, never on whatever the path names by then, and no link is followed.
fn unlink_or_open(at: &OwnedFd, name: &OsStr) -> rustix::io::Result<Option<OwnedFd>> {
    let stat = rustix::fs::statat(at, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        rustix::fs::unlinkat(at, name, AtFlags::empty())?;
        return Ok(None);
    }
    let pinned = rustix::fs::openat(
        at,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // `fchmod` refuses an `O_PATH` descriptor, and one opened for reading
    // needs the permission this is restoring.
    rustix::fs::chmod(format!("/proc/self/fd/{}", pinned.as_raw_fd()), Mode::RWXU)?;
    rustix::fs::openat(
        &pinned,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(Some)
}

fn entry_names(dir: &OwnedFd, max: usize) -> rustix::io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir)? {
        if names.len() == max {
            break;
        }
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Create `$XDG_RUNTIME_DIR/bubbler/<name>/` with mode 0700, reusing an existing one. Not a
/// lock: a second start of the instance collides on the control socket in it.
pub fn prepare_runtime_dir(env: &Env, inst: &Instance) -> Result<PathBuf, LaunchError> {
    // Each level is created 0700 outright; a missing `$XDG_RUNTIME_DIR` is created but not its
    // parent, which would mean the session has no runtime dir.
    mkdir_private(&env.runtime_dir)?;
    mkdir_private(&env.runtime_dir.join(RUNTIME_SUBDIR))?;
    let dir = instance_runtime_dir(env, &inst.name);
    mkdir_private(&dir)?;
    Ok(dir)
}

// Only bubbler creates these, never a sandbox: whoever creates `app/<id>` decides what the
// others bind. Why the check-then-bind window is no hole: threat model, app-runtime.
pub(super) fn prepare_app_runtime(env: &Env, services: &[Service]) -> Result<(), LaunchError> {
    let ids: Vec<&str> = services
        .iter()
        .filter_map(|s| match s {
            Service::AppRuntime { id, .. } => Some(id.as_str()),
            _ => None,
        })
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    // Both levels 0700, the way `prepare_runtime_dir` makes its own: the
    // order in the caller is not what should decide whether they are.
    mkdir_private(&env.runtime_dir)?;
    let app = env.runtime_dir.join("app");
    mkdir_private(&app)?;
    let at = open_dir_nofollow(rustix::fs::CWD, &app, &app, "app-runtime")?;
    for id in ids {
        let dir = service::app_runtime_dir(env, id);
        // `mkdir` reports EEXIST for a symlink too, so the probe below is what catches one.
        match rustix::fs::mkdirat(&at, id, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(LaunchError::Io(dir, e.into())),
        }
        open_dir_nofollow(&at, id, &dir, "app-runtime")?;
    }
    Ok(())
}

pub(super) fn open_dir_nofollow<P: rustix::path::Arg>(
    at: impl AsFd,
    path: P,
    named: &Path,
    service: &'static str,
) -> Result<OwnedFd, LaunchError> {
    rustix::fs::openat(
        at,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::NOTDIR => LaunchError::Plan(PlanError::WrongType {
            service,
            path: named.to_path_buf(),
            expected: "a directory",
        }),
        e => LaunchError::Io(named.to_path_buf(), e.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::{leftovers, plant_chain, with_desktop_fd_limit};
    use super::*;
    use crate::config::WaylandMode;
    use crate::sidecar_argv::test_support::*;
    use crate::{dbus, pipewire};

    /// The pid the proxy's `pre_exec` writes into `cgroup.procs`, which
    /// is formatted by hand because a forked child may not allocate. The
    /// ends of the range and the one-digit case, since an off-by-one in
    /// the buffer index would put the wrong process in the one cgroup
    /// the filter accepts.
    #[test]
    fn the_pid_written_into_the_cgroup_is_formatted_exactly() {
        let mut buf = [0u8; 10];
        assert_eq!(decimal(1, &mut buf), b"1");
        assert_eq!(decimal(0, &mut buf), b"0");
        assert_eq!(decimal(4194304, &mut buf), b"4194304");
        // The widest a pid can be, which fills the buffer exactly.
        assert_eq!(decimal(i32::MAX, &mut buf), b"2147483647");
    }

    /// A session keyring is per-thread credentials, so joining one here
    /// changes this thread's keyring and nothing else's. The id before
    /// and after therefore has to differ: that is the whole of what the
    /// sandbox gets — a keyring of its own rather than the login
    /// session's, whatever a profile says about `keyctl`.
    #[test]
    fn joining_a_session_keyring_leaves_the_thread_on_a_new_one() {
        // KEYCTL_GET_KEYRING_ID(KEY_SPEC_SESSION_KEYRING, create=0).
        let id = || -> i64 {
            // SAFETY: `keyctl` takes its arguments by value; this asks
            // for the id of an existing keyring and creates nothing.
            unsafe { libc::syscall(libc::SYS_keyctl, 0u64, -3i64, 0u64) }
        };
        let before = id();
        if before < 0 {
            // A kernel without CONFIG_KEYS has no keyring to inherit, so
            // there is nothing to test rather than something that failed.
            eprintln!("skipping: this host has no session keyring");
            return;
        }
        join_session_keyring().unwrap();
        let after = id();
        assert!(after >= 0, "no keyring after joining one");
        assert_ne!(before, after, "the thread kept the keyring it was given");
    }

    #[test]
    fn runtime_dir_is_created_private_and_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "");
        let d = prepare_runtime_dir(&e, &i).unwrap();
        assert_eq!(d, tmp.path().join("run/bubbler/t"));
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        prepare_runtime_dir(&e, &i).unwrap();
    }

    #[test]
    fn app_runtime_dirs_are_created_once_and_reused_whatever_their_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let svcs = vec![
            Service::AppRuntime {
                id: "org.keepassxc.KeePassXC".to_owned(),
                mode: crate::config::ShareMode::ReadWrite,
            },
            Service::AppRuntime {
                id: "org.example.Other".to_owned(),
                mode: crate::config::ShareMode::ReadOnly,
            },
        ];
        prepare_app_runtime(&e, &svcs).unwrap();
        let one = tmp.path().join("run/app/org.keepassxc.KeePassXC");
        assert!(one.is_dir());
        assert!(tmp.path().join("run/app/org.example.Other").is_dir());
        // A native application creates the directory at 0755 (Qt's
        // `mkpath`), and bubbler reuses it rather than fighting over the
        // mode: `$XDG_RUNTIME_DIR` being 0700 is what keeps it private.
        std::fs::set_permissions(&one, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_app_runtime(&e, &svcs).unwrap();
        assert_eq!(
            std::fs::metadata(&one).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn an_app_runtime_id_that_is_not_a_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        std::fs::create_dir_all(tmp.path().join("run/app")).unwrap();
        // A symlink where the directory belongs would bind whatever it
        // points at, resolved on the host's side of the boundary.
        std::os::unix::fs::symlink("/etc", tmp.path().join("run/app/org.example.App")).unwrap();
        let svcs = vec![Service::AppRuntime {
            id: "org.example.App".to_owned(),
            mode: crate::config::ShareMode::ReadOnly,
        }];
        assert!(matches!(
            prepare_app_runtime(&e, &svcs),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
        std::fs::remove_file(tmp.path().join("run/app/org.example.App")).unwrap();
        std::fs::write(tmp.path().join("run/app/org.example.App"), b"").unwrap();
        assert!(matches!(
            prepare_app_runtime(&e, &svcs),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
    }

    #[test]
    fn an_app_parent_that_is_not_a_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        std::fs::create_dir_all(tmp.path().join("run")).unwrap();
        // `mkdir` reports EEXIST for a plain file too, so the probe of
        // the parent is the only thing between this and an `openat` that
        // would fail somewhere less legible.
        std::fs::write(tmp.path().join("run/app"), b"").unwrap();
        assert!(matches!(
            prepare_app_runtime(
                &e,
                &[Service::AppRuntime {
                    id: "org.example.App".to_owned(),
                    mode: crate::config::ShareMode::ReadOnly,
                }]
            ),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
    }

    #[test]
    fn an_app_parent_that_is_a_symlink_is_refused_before_any_id_is_made() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        std::fs::create_dir_all(tmp.path().join("run")).unwrap();
        std::fs::create_dir_all(tmp.path().join("elsewhere")).unwrap();
        // `app` pointing away would make every id resolve outside the
        // runtime directory while the sandbox binds the path the config
        // named.
        std::os::unix::fs::symlink(tmp.path().join("elsewhere"), tmp.path().join("run/app"))
            .unwrap();
        let svcs = vec![Service::AppRuntime {
            id: "org.example.App".to_owned(),
            mode: crate::config::ShareMode::ReadOnly,
        }];
        assert!(matches!(
            prepare_app_runtime(&e, &svcs),
            Err(LaunchError::Plan(PlanError::WrongType {
                service: "app-runtime",
                ..
            }))
        ));
        assert!(!tmp.path().join("elsewhere/org.example.App").exists());
    }

    #[test]
    fn a_config_without_app_runtime_creates_no_app_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        prepare_app_runtime(&e, &[Service::Wayland(WaylandMode::default())]).unwrap();
        assert!(!tmp.path().join("run/app").exists());
    }

    /// The same for the two other directories a sidecar writes: whatever
    /// a dead run left at their name is replaced by a fresh directory, a
    /// link included, and what it pointed at is left alone.
    #[test]
    fn a_sidecar_directory_is_made_afresh_whatever_is_at_its_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("t");
        std::fs::create_dir(&dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("sentinel"), b"sentinel").unwrap();
        for sidecar in [pipewire::dir(&dir), dbus::socket_dir(&dir)] {
            std::os::unix::fs::symlink(&elsewhere, &sidecar).unwrap();
            fresh_sidecar_dir(&sidecar).unwrap();
            let made = std::fs::symlink_metadata(&sidecar).unwrap();
            assert!(made.is_dir(), "{} is still a link", sidecar.display());
            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);
            assert!(elsewhere.join("sentinel").exists());

            std::fs::write(sidecar.join("left"), b"").unwrap();
            fresh_sidecar_dir(&sidecar).unwrap();
            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);

            std::fs::remove_dir(&sidecar).unwrap();
            std::fs::write(&sidecar, b"").unwrap();
            fresh_sidecar_dir(&sidecar).unwrap();
            assert!(std::fs::symlink_metadata(&sidecar).unwrap().is_dir());
        }
    }

    /// A sidecar can build a tree deeper than any walk holding a
    /// descriptor per level can follow. The start still gets a fresh
    /// directory, and the tree is gone rather than left beside it.
    #[test]
    fn a_tree_deeper_than_the_descriptor_limit_does_not_block_its_start() {
        with_desktop_fd_limit(|| {
            let tmp = tempfile::tempdir().unwrap();
            let sidecar = pipewire::dir(tmp.path());
            plant_chain(&sidecar, 1500);

            fresh_sidecar_dir(&sidecar).unwrap();

            assert!(std::fs::symlink_metadata(&sidecar).unwrap().is_dir());
            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);
            assert_eq!(leftovers(tmp.path(), &sidecar), Vec::<OsString>::new());
        });
    }

    /// What the moved tree links to, at its deepest and behind levels no
    /// one may open, is neither followed, removed nor given new modes.
    #[test]
    fn removing_a_moved_tree_changes_nothing_its_links_name() {
        use std::os::unix::fs::PermissionsExt;
        with_desktop_fd_limit(|| {
            let tmp = tempfile::tempdir().unwrap();
            let elsewhere = tmp.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            let sentinel = elsewhere.join("sentinel");
            std::fs::write(&sentinel, b"sentinel").unwrap();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            let before = (mode(&elsewhere), mode(&sentinel));
            let dir = tmp.path().join("t");
            std::fs::create_dir(&dir).unwrap();
            let sidecar = dbus::socket_dir(&dir);
            let bottom = plant_chain(&sidecar, 600);
            rustix::fs::symlinkat(&sentinel, &bottom, "out").unwrap();
            rustix::fs::symlinkat(&elsewhere, &bottom, "up").unwrap();
            rustix::fs::chmod(
                format!("/proc/self/fd/{}", bottom.as_raw_fd()),
                Mode::empty(),
            )
            .unwrap();
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o000)).unwrap();

            fresh_sidecar_dir(&sidecar).unwrap();

            assert_eq!(std::fs::read_dir(&sidecar).unwrap().count(), 0);
            assert_eq!(leftovers(&dir, &sidecar), Vec::<OsString>::new());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
            assert_eq!((mode(&elsewhere), mode(&sentinel)), before);
        });
    }

    /// A tree with more entries than one pass may touch still shrinks on
    /// every pass, so the starts that follow clear it in the end.
    #[test]
    fn clearing_a_tree_wider_than_the_budget_makes_progress_on_every_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("t");
        std::fs::create_dir(&top).unwrap();
        for i in 0..30 {
            std::fs::write(top.join(format!("f{i}")), b"").unwrap();
        }
        for i in 0..5 {
            let sub = top.join(format!("d{i}"));
            std::fs::create_dir_all(sub.join("deeper")).unwrap();
            std::fs::write(sub.join("deeper").join("f"), b"").unwrap();
            for j in 0..10 {
                std::fs::write(sub.join(format!("f{j}")), b"").unwrap();
            }
        }
        fn count(dir: &Path) -> usize {
            std::fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .map(|e| {
                            let e = e.unwrap();
                            1 + if e.file_type().unwrap().is_dir() {
                                count(&e.path())
                            } else {
                                0
                            }
                        })
                        .sum()
                })
                .unwrap_or(0)
        }
        let at = open_dir(tmp.path()).unwrap();
        let mut left = count(&top);
        let passes = left;
        for _ in 0..passes {
            match remove_tree(&at, OsStr::new("t"), &mut 8) {
                Ok(()) => {
                    assert!(std::fs::symlink_metadata(&top).is_err());
                    return;
                }
                Err(e) => assert_eq!(e, Errno::AGAIN),
            }
            let now = count(&top);
            assert!(now < left, "a pass left {now} of {left} entries");
            left = now;
        }
        panic!("{left} entries are never removed");
    }
}
