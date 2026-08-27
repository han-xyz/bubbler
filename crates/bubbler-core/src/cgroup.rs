//! The two cgroups a run with an `allow-host` needs: the one the sandbox
//! runs in and the one the egress proxy runs in, side by side under a
//! parent of their own.
//!
//! nftables matches a cgroup by path (`socket cgroupv2 level N "<path>"`)
//! but stores the id it resolved, so the proxy's directory has to exist
//! before `nft -f` reads the rule and to live as long as the sandbox: one
//! made afterwards matches nothing, silently.
//!
//! Why two, and why bubbler moves *itself*. bwrap never changes cgroup,
//! so `--unshare-cgroup` makes whatever cgroup bwrap was started in the
//! root of the sandbox's cgroup namespace — and everything under that
//! root is nameable from inside. Measured on this host: with the default
//! `userns "allow"` an application can `unshare(CLONE_NEWUSER |
//! CLONE_NEWCGROUP | CLONE_NEWNS)`, mount cgroup2 (`CAP_SYS_ADMIN` in the
//! user namespace owning its own new cgroup namespace), see a proxy
//! cgroup placed under that root, write its pid into it and have the
//! whole network. So bubbler puts itself in `sandbox/` before it spawns
//! bwrap — bwrap, the supervisor and the application inherit it, and the
//! namespace root becomes `sandbox` — and the proxy goes into `proxy/`,
//! a **sibling outside** that root: unnameable through any cgroupfs the
//! application mounts, and refused by `nsdelegate` even if it were named.
//!
//! The parent holds no process, only the two leaves, so the "no internal
//! processes" rule cannot be reached: it constrains a cgroup that has
//! both processes and controllers enabled for its children, and nothing
//! here writes `cgroup.subtree_control` at all.
//!
//! Both are created under bubbler's own cgroup, which on a systemd user
//! session is a delegated cgroup2 subtree the user may write; without
//! such a subtree there is nothing to create and `allow-host` cannot be
//! served.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::error::LaunchError;
use crate::network;

/// Where the unified hierarchy is mounted. Every path a rule carries is
/// relative to this.
const CGROUP2_ROOT: &str = "/sys/fs/cgroup";

/// The line of `/proc/<pid>/cgroup` that names the unified hierarchy;
/// the others are v1 controllers, which the `socket cgroupv2` match has
/// nothing to do with.
const UNIFIED: &str = "0::";

/// Longest `/proc/self/cgroup` this reads. The file is a handful of
/// lines of the kernel's own making; a bound is here because everything
/// bubbler reads has one.
const MAX_CGROUP_FILE: u64 = 64 * 1024;

/// The leaf bubbler moves itself into, and so the root of the sandbox's
/// cgroup namespace.
const SANDBOX_LEAF: &str = "sandbox";

/// The leaf the egress proxy writes itself into, which is what the
/// ruleset accepts.
const PROXY_LEAF: &str = "proxy";

/// How long the teardown waits for the sandbox's processes to be gone
/// before giving up on removing the directories. bwrap's
/// `--die-with-parent` kills them as it exits, which is not quite
/// instant, and a cgroup with a process left in it cannot be removed.
const RELEASE_WAIT: Duration = Duration::from_secs(2);

/// How often that is retried.
const RELEASE_POLL: Duration = Duration::from_millis(50);

/// One run's cgroups: the parent, its two leaves, an open descriptor for
/// the proxy leaf's `cgroup.procs`, and where bubbler was before it
/// moved itself.
///
/// The descriptor is opened here so the proxy's `pre_exec` — which may
/// allocate nothing and open nothing — has only a `write` left to do.
/// Dropping the handle moves bubbler back and removes all three
/// directories, which the kernel allows only once no process is left in
/// them: the proxy is stopped and the sandbox has exited by then.
#[derive(Debug)]
pub struct SandboxCgroup {
    /// The parent, which holds no process and is removed last.
    dir: PathBuf,
    /// The leaf bubbler and therefore the sandbox are in.
    sandbox: PathBuf,
    /// The leaf the proxy is in.
    proxy: PathBuf,
    /// The proxy leaf's `cgroup.procs`, open for writing.
    procs: OwnedFd,
    /// The cgroup bubbler was in before this, to move back to.
    home: PathBuf,
    /// bubbler's own pid, which is what was moved and what moves back.
    pid: u32,
    /// The proxy leaf as an nftables rule names it.
    spec: network::Cgroup,
    /// How directories are made and removed, which only a test changes.
    ops: Ops,
}

impl SandboxCgroup {
    /// The path and level the nftables rule is written from, which is
    /// the proxy's leaf and never the sandbox's.
    pub fn spec(&self) -> &network::Cgroup {
        &self.spec
    }

    /// The open `cgroup.procs` of the proxy leaf, which the proxy joins
    /// by writing its pid.
    pub fn procs(&self) -> BorrowedFd<'_> {
        self.procs.as_fd()
    }

    /// Move bubbler back where it was and remove the three directories,
    /// in the only order the kernel takes: the leaves have to be empty,
    /// and the parent has to have no children left.
    ///
    /// Every step is best-effort. A move back that fails leaves empty
    /// directories under the user's own subtree, which the next run of
    /// this instance sweeps ([`create`]); ending a run over it would
    /// help nobody.
    fn release(&mut self) {
        let _ = write_pid(&self.home, self.pid);
        // The sandbox's processes go with bwrap, which has exited by the
        // time this runs — but not necessarily *finished* exiting.
        let deadline = Instant::now() + RELEASE_WAIT;
        loop {
            let removed = [&self.proxy, &self.sandbox, &self.dir]
                .iter()
                .all(|d| matches!((self.ops.rmdir)(d), Ok(()) | Err(Errno::NOENT)));
            if removed || Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(RELEASE_POLL);
        }
    }
}

impl Drop for SandboxCgroup {
    fn drop(&mut self) {
        self.release();
    }
}

/// Write `pid` into the `cgroup.procs` of the cgroup directory `dir`,
/// which is how a process is moved into it.
fn write_pid(dir: &Path, pid: u32) -> std::io::Result<()> {
    File::options()
        .write(true)
        .open(dir.join("cgroup.procs"))?
        .write_all(pid.to_string().as_bytes())
}

/// Make this run's cgroups under bubbler's own and move bubbler into the
/// sandbox leaf, so that everything it spawns from here on is in it.
///
/// `pid` is bubbler's own: the name has to be settled before bwrap is
/// spawned, since the sandbox's cgroup namespace root is fixed at the
/// `--unshare-cgroup`, so the sandbox's pid is not yet known.
///
/// Fails the launch rather than warning: the ruleset is written around
/// the proxy leaf, and a run that asked for `allow-host` and got no
/// cgroup would either have no rules at all or rules naming a path that
/// resolves to nothing.
pub fn create(instance: &str, pid: u32) -> Result<SandboxCgroup, LaunchError> {
    create_under(
        Path::new(CGROUP2_ROOT),
        &own_path()?,
        instance,
        pid,
        Ops::KERNEL,
    )
}

/// The two things the kernel does for a cgroup directory that it does
/// not do for a plain one: it fills a new one with `cgroup.procs` and
/// the rest of the interface files, and it takes them away with the
/// directory when that is removed. Nothing in this module creates or
/// deletes an interface file, so a test drives it against a tree of
/// plain directories by doing those two things itself.
#[derive(Debug, Clone, Copy)]
struct Ops {
    mkdir: fn(&Path) -> Result<(), Errno>,
    rmdir: fn(&Path) -> Result<(), Errno>,
}

impl Ops {
    /// What a real cgroup2 filesystem needs, which is nothing beyond the
    /// two system calls.
    const KERNEL: Self = Self {
        mkdir: kernel_mkdir,
        rmdir: kernel_rmdir,
    };
}

/// 0755 like every other cgroup: the directory is the user's own and
/// the kernel makes the files inside it.
fn kernel_mkdir(dir: &Path) -> Result<(), Errno> {
    rustix::fs::mkdir(dir, Mode::from_raw_mode(0o755))
}

/// A cgroup goes away with `rmdir`, interface files and all — but only
/// once it holds neither a process nor a child cgroup.
fn kernel_rmdir(dir: &Path) -> Result<(), Errno> {
    rustix::fs::rmdir(dir)
}

/// [`create`] under one cgroup2 root and one starting cgroup, so a test
/// can name both.
fn create_under(
    root: &Path,
    own: &str,
    instance: &str,
    pid: u32,
    ops: Ops,
) -> Result<SandboxCgroup, LaunchError> {
    let prefix = format!("bubbler-{instance}-");
    let base = match own.is_empty() {
        true => format!("{prefix}{pid}"),
        false => format!("{own}/{prefix}{pid}"),
    };
    let spec = network::Cgroup::new(&format!("{base}/{PROXY_LEAF}")).map_err(|why| {
        LaunchError::Network(format!(
            "the cgroup this run would create is no path a rule could carry ({why}): {base}"
        ))
    })?;
    let home = root.join(own);
    // A bubbler killed with SIGKILL leaves its directories behind, and
    // they are empty: no process outlives the run that was in them. They
    // are swept here rather than at exit because only here is it known
    // that this instance is not running — a live run's directories
    // refuse to be removed anyway, since a cgroup holding a process
    // cannot be.
    sweep(ops, &home, &prefix);
    let dir = root.join(&base);
    let (sandbox, proxy) = (dir.join(SANDBOX_LEAF), dir.join(PROXY_LEAF));
    for d in [&dir, &sandbox, &proxy] {
        if let Err(e) = (ops.mkdir)(d) {
            remove(ops, &[&proxy, &sandbox, &dir]);
            return Err(bad_subtree(e, d));
        }
    }
    // From here the directories are this run's to remove however the
    // rest of the launch goes.
    let procs = match rustix::fs::open(
        proxy.join("cgroup.procs"),
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(procs) => procs,
        Err(e) => {
            remove(ops, &[&proxy, &sandbox, &dir]);
            return Err(LaunchError::Network(format!(
                "opening {}/cgroup.procs: {e}",
                proxy.display()
            )));
        }
    };
    let cgroup = SandboxCgroup {
        dir,
        sandbox,
        proxy,
        procs,
        home,
        pid,
        spec,
        ops,
    };
    // Last, because from here bubbler is somewhere else and the way back
    // is what the handle carries.
    if let Err(e) = write_pid(&cgroup.sandbox, pid) {
        // The handle is not returned, so nothing else will remove them.
        let dirs: Vec<PathBuf> = vec![
            cgroup.proxy.clone(),
            cgroup.sandbox.clone(),
            cgroup.dir.clone(),
        ];
        remove(ops, &dirs.iter().collect::<Vec<_>>());
        return Err(LaunchError::Network(format!(
            "moving bubbler into {}: {e}",
            cgroup.sandbox.display()
        )));
    }
    Ok(cgroup)
}

/// Remove what was made, deepest first, ignoring what is not there.
fn remove(ops: Ops, dirs: &[&PathBuf]) {
    for d in dirs {
        let _ = (ops.rmdir)(d);
    }
}

/// Remove empty cgroups of earlier runs of this instance. A directory
/// still holding a process — a run that is live, whatever the launcher
/// thinks — refuses, which is the check that keeps this from touching
/// anything of another run's.
fn sweep(ops: Ops, home: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(home) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(prefix) {
            continue;
        }
        let dir = entry.path();
        remove(
            ops,
            &[&dir.join(PROXY_LEAF), &dir.join(SANDBOX_LEAF), &dir.clone()],
        );
    }
}

/// Why a cgroup could not be made, in the terms of what the user would
/// have to change. Everything else is reported as it arrived.
fn bad_subtree(e: Errno, dir: &Path) -> LaunchError {
    match e {
        Errno::ACCESS | Errno::PERM | Errno::ROFS | Errno::NOENT => LaunchError::Network(format!(
            "allow-host needs a delegated cgroup2 subtree (a systemd user session provides \
             one): creating {}: {e}",
            dir.display()
        )),
        // The sweep above removes what an earlier run left, so what is
        // left here is a directory holding a process: another bubbler
        // with this instance and this pid, which cannot be, or something
        // else of the user's under the same name.
        Errno::EXIST => LaunchError::Network(format!(
            "{} already exists and is not empty; another process is in it",
            dir.display()
        )),
        _ => LaunchError::Network(format!("creating {}: {e}", dir.display())),
    }
}

/// bubbler's own cgroup, relative to the cgroup2 mount and without the
/// leading `/`. Empty where bubbler is in the root cgroup itself.
///
/// Also what an explanation names its placeholder under, so the block
/// `--explain` prints is the shape a run would install.
pub fn own_path() -> Result<String, LaunchError> {
    let path = PathBuf::from("/proc/self/cgroup");
    // Read with a bound like everything else bubbler reads, and by
    // length rather than by the reported size: a procfs file reports
    // none.
    let mut text = String::new();
    File::open(&path)
        .and_then(|f| f.take(MAX_CGROUP_FILE).read_to_string(&mut text))
        .map_err(|e| LaunchError::Io(path.clone(), e))?;
    unified_of(&text).map(str::to_owned).ok_or_else(|| {
        LaunchError::Network(
            "this process is in no cgroup2 hierarchy, which is what an `allow-host` ruleset \
             matches on"
                .to_owned(),
        )
    })
}

/// The leaf an explanation names, under the cgroup a run of `instance`
/// would create: the sandbox pid is not part of it, and bubbler's own is
/// whatever the run has.
pub fn placeholder(own: &str, instance: &str) -> String {
    let base = match own.is_empty() {
        true => String::new(),
        false => format!("{own}/"),
    };
    format!("{base}bubbler-{instance}-<pid>/{PROXY_LEAF}")
}

/// The unified hierarchy's path out of a `/proc/<pid>/cgroup` file,
/// relative to the cgroup2 mount: the `0::` line with its prefix and
/// leading `/` taken off.
///
/// `None` where there is no such line, which is a host with no cgroup2
/// hierarchy — or one where bubbler is in a v1 controller only, which
/// the `socket cgroupv2` match cannot see either.
fn unified_of(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.strip_prefix(UNIFIED))
        .map(|path| path.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout a systemd user session has, which is where the
    /// delegated subtree is: the `0::` line, whatever v1 controllers sit
    /// above it.
    const SESSION: &str = "\
12:pids:/user.slice/user-1000.slice/user@1000.service/app.slice/app.scope
1:name=systemd:/user.slice/user-1000.slice/user@1000.service/app.slice/app.scope
0::/user.slice/user-1000.slice/user@1000.service/app.slice/app.scope
";

    /// A cgroup2 root of plain directories, with the `cgroup.procs` the
    /// kernel would make in each. Enough for everything this module does
    /// to a real one: create directories, write a pid into a file, read
    /// nothing back.
    fn fake_root(dir: &Path, cgroups: &[&str]) {
        for c in cgroups {
            let mut at = dir.to_path_buf();
            for part in Path::new(c).components() {
                at = at.join(part);
                if !at.exists() {
                    fake_mkdir(&at).expect("a fake cgroup");
                }
            }
        }
    }

    /// What the kernel does for a real cgroup directory, done by hand:
    /// make it with the one interface file this module writes to, and
    /// take that file away with the directory.
    const FAKE: Ops = Ops {
        mkdir: fake_mkdir,
        rmdir: fake_rmdir,
    };

    fn fake_mkdir(dir: &Path) -> Result<(), Errno> {
        kernel_mkdir(dir)?;
        std::fs::write(dir.join("cgroup.procs"), b"").map_err(errno_of)
    }

    fn fake_rmdir(dir: &Path) -> Result<(), Errno> {
        // Only the interface file: anything else in there is a child
        // cgroup or a stray, and a real `rmdir` would refuse too.
        let _ = std::fs::remove_file(dir.join("cgroup.procs"));
        kernel_rmdir(dir)
    }

    fn errno_of(e: std::io::Error) -> Errno {
        Errno::from_raw_os_error(e.raw_os_error().unwrap_or(Errno::IO.raw_os_error()))
    }

    #[test]
    fn the_unified_line_is_the_one_that_is_read() {
        assert_eq!(
            unified_of(SESSION),
            Some("user.slice/user-1000.slice/user@1000.service/app.slice/app.scope")
        );
        // A name systemd escaped stays as it wrote it: nft resolves the
        // path as written, and unescaping would name a directory that
        // does not exist.
        assert_eq!(
            unified_of("0::/user.slice/user\\x2d1000.slice\n"),
            Some("user.slice/user\\x2d1000.slice")
        );
    }

    /// The root cgroup is no path at all, and a host with only v1
    /// controllers has no unified line to find.
    #[test]
    fn a_root_cgroup_is_empty_and_a_v1_only_host_has_none() {
        assert_eq!(unified_of("0::/\n"), Some(""));
        assert_eq!(unified_of("1:name=systemd:/user.slice\n"), None);
        assert_eq!(unified_of(""), None);
    }

    /// What a rule carries is the *proxy* leaf, one level below the run
    /// cgroup and beside the one the sandbox is in — the whole point of
    /// the layout, so it is pinned here and in the explanation.
    #[test]
    fn the_rule_names_the_proxy_leaf_beside_the_sandbox_s() {
        let own = unified_of(SESSION).expect("the unified line");
        let tmp = tempfile::tempdir().expect("a temporary directory");
        fake_root(tmp.path(), &[own]);
        let cgroup = create_under(tmp.path(), own, "t", 1234, FAKE).expect("the run's cgroups");
        assert_eq!(
            cgroup.spec().path(),
            "user.slice/user-1000.slice/user@1000.service/app.slice/app.scope/bubbler-t-1234/proxy"
        );
        assert_eq!(cgroup.spec().level(), 7);
        assert_eq!(
            placeholder(own, "t"),
            "user.slice/user-1000.slice/user@1000.service/app.slice/app.scope/\
             bubbler-t-<pid>/proxy"
        );
        // Both leaves exist, the parent holds neither process nor
        // anything but them, and bubbler moved itself into the sandbox
        // one.
        assert!(cgroup.proxy.is_dir() && cgroup.sandbox.is_dir());
        assert_eq!(
            std::fs::read_to_string(cgroup.sandbox.join("cgroup.procs")).expect("its procs"),
            "1234"
        );
        assert_eq!(
            std::fs::read_to_string(cgroup.dir.join("cgroup.procs")).expect("its procs"),
            "",
            "the parent holds no process, so `no internal processes` is never reached"
        );
    }

    /// Teardown puts bubbler back where it started and leaves nothing
    /// behind — the move first, since a cgroup holding a process cannot
    /// be removed.
    #[test]
    fn the_teardown_moves_bubbler_back_and_removes_every_directory() {
        let own = "user.slice/user-1000.slice/user@1000.service/app.slice/app.scope";
        let tmp = tempfile::tempdir().expect("a temporary directory");
        fake_root(tmp.path(), &[own]);
        let dir = {
            let cgroup = create_under(tmp.path(), own, "t", 4321, FAKE).expect("the run's cgroups");
            cgroup.dir.clone()
        };
        assert!(!dir.exists(), "the run's cgroup is gone");
        assert!(!dir.join(SANDBOX_LEAF).exists());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(own).join("cgroup.procs")).expect("its procs"),
            "4321",
            "bubbler is back in the cgroup it started in"
        );
    }

    /// A bubbler killed before its teardown leaves empty directories;
    /// the next run of that instance removes them rather than failing on
    /// the name.
    #[test]
    fn an_empty_leftover_of_an_earlier_run_is_swept() {
        let own = "user.slice/app.scope";
        let tmp = tempfile::tempdir().expect("a temporary directory");
        fake_root(
            tmp.path(),
            &[
                own,
                &format!("{own}/bubbler-t-11/sandbox"),
                &format!("{own}/bubbler-t-11/proxy"),
                &format!("{own}/bubbler-other-12/proxy"),
            ],
        );
        let cgroup = create_under(tmp.path(), own, "t", 22, FAKE).expect("the run's cgroups");
        assert!(
            !tmp.path().join(own).join("bubbler-t-11").exists(),
            "the leftover of an earlier run of this instance is gone"
        );
        assert!(
            tmp.path().join(own).join("bubbler-other-12").is_dir(),
            "another instance's is not touched"
        );
        assert!(cgroup.proxy.is_dir());
    }

    /// The same instance and pid twice over is the one case the sweep
    /// cannot clear, because a directory holding a process refuses to be
    /// removed. It names what it found rather than reporting a bare
    /// `File exists`.
    #[test]
    fn a_leftover_that_will_not_go_names_itself() {
        let own = "user.slice/app.scope";
        let tmp = tempfile::tempdir().expect("a temporary directory");
        fake_root(tmp.path(), &[own, &format!("{own}/bubbler-t-33/busy")]);
        let refused = create_under(tmp.path(), own, "t", 33, FAKE);
        let Err(LaunchError::Network(why)) = refused else {
            panic!("{refused:?}")
        };
        assert!(why.contains("bubbler-t-33"), "{why}");
        assert!(why.contains("already exists"), "{why}");
    }
}
