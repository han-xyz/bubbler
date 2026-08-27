//! The cgroup a run's egress proxy is put in, which is the whole of
//! what the `allow-host` ruleset accepts.
//!
//! nftables matches a cgroup by path (`socket cgroupv2 level N "<path>"`)
//! but stores the id it resolved, so the directory has to exist before
//! `nft -f` reads the rule and to live as long as the sandbox: one made
//! afterwards matches nothing, silently. It is created under bubbler's
//! own cgroup, which on a systemd user session is a delegated cgroup2
//! subtree the user may write; without such a subtree there is nothing
//! to create and `allow-host` cannot be served at all.
//!
//! The application cannot join it: it has an empty capability set, its
//! own cgroup namespace and no cgroupfs mounted to write through.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;

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

/// One run's cgroup: the directory, an open descriptor for its
/// `cgroup.procs`, and the path as a rule names it.
///
/// The descriptor is opened here so the proxy's `pre_exec` — which may
/// allocate nothing and open nothing — has only a `write` left to do.
/// Dropping the handle removes the directory, which the kernel allows
/// only once no process is left in it: the proxy is stopped first.
#[derive(Debug)]
pub struct SandboxCgroup {
    dir: PathBuf,
    procs: OwnedFd,
    spec: network::Cgroup,
}

impl SandboxCgroup {
    /// The path and level the nftables rule is written from.
    pub fn spec(&self) -> &network::Cgroup {
        &self.spec
    }

    /// The open `cgroup.procs`, which a child joins by writing its pid.
    pub fn procs(&self) -> BorrowedFd<'_> {
        self.procs.as_fd()
    }
}

impl Drop for SandboxCgroup {
    /// Remove the directory. A cgroup still holding a process refuses,
    /// which is why this happens after the proxy has been waited for;
    /// one left behind would be an empty directory under the user's own
    /// subtree, so a failure here is not worth ending a run over.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Make the cgroup this run's egress proxy will join, under bubbler's
/// own. `pid` is the sandbox's, so two runs of one instance never name
/// the same directory.
///
/// Fails the launch rather than warning: the ruleset is written around
/// this cgroup, and a run that asked for `allow-host` and got no cgroup
/// would either have no rules at all or rules naming a path that
/// resolves to nothing.
pub fn create(instance: &str, pid: i32) -> Result<SandboxCgroup, LaunchError> {
    let own = own_path()?;
    let name = format!("bubbler-{instance}-{pid}");
    let relative = match own.is_empty() {
        true => name,
        false => format!("{own}/{name}"),
    };
    let spec = network::Cgroup::new(&relative).map_err(|why| {
        LaunchError::Network(format!(
            "the cgroup this run would create is no path a rule could carry ({why}): {relative}"
        ))
    })?;
    let dir = PathBuf::from(CGROUP2_ROOT).join(&relative);
    // 0755 like every other cgroup: the directory is the user's own and
    // the kernel makes the files inside it.
    rustix::fs::mkdir(&dir, Mode::from_raw_mode(0o755)).map_err(|e| bad_subtree(e, &dir))?;
    // From here the directory is this run's to remove however the rest
    // of the launch goes.
    let procs = rustix::fs::open(
        dir.join("cgroup.procs"),
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    );
    match procs {
        Ok(procs) => Ok(SandboxCgroup { dir, procs, spec }),
        Err(e) => {
            let _ = std::fs::remove_dir(&dir);
            Err(LaunchError::Network(format!(
                "opening {}/cgroup.procs: {e}",
                dir.display()
            )))
        }
    }
}

/// Why a cgroup could not be made, in the terms of what the user would
/// have to change. Everything else is reported as it arrived.
fn bad_subtree(e: Errno, dir: &std::path::Path) -> LaunchError {
    match e {
        Errno::ACCESS | Errno::PERM | Errno::ROFS | Errno::NOENT => LaunchError::Network(format!(
            "allow-host needs a delegated cgroup2 subtree (a systemd user session provides \
             one): creating {}: {e}",
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

    /// What a rule would carry for a session like the one above: the
    /// path bubbler is in, one component more, and the level counted
    /// from it.
    #[test]
    fn the_run_s_cgroup_is_one_component_under_bubbler_s_own() {
        let own = unified_of(SESSION).expect("the unified line");
        let spec = network::Cgroup::new(&format!("{own}/bubbler-t-1234")).expect("a cgroup path");
        assert_eq!(
            spec.path(),
            "user.slice/user-1000.slice/user@1000.service/app.slice/app.scope/bubbler-t-1234"
        );
        assert_eq!(spec.level(), 6);
        assert_eq!(
            spec.to_string(),
            format!("socket cgroupv2 level 6 \"{}\"", spec.path())
        );
    }
}
