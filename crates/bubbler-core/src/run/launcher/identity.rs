//! The portal identity files a run publishes, and the readers of bwrap's sandbox info.

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Instant;

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::fs::Mode;
use rustix::io::Errno;
use rustix::process::Pid;

use crate::env::Env;
use crate::run::launch_error::LaunchError;
use crate::{dbus, init_bin, proc};

use super::POLL;
use super::alloc::RealAlloc;
use super::runtime_dir::mkdir_private;

// Scanned rather than parsed: bwrap adds members over time and only this one matters.
fn parse_child_pid(buf: &[u8]) -> Option<i32> {
    const KEY: &[u8] = b"\"child-pid\"";
    let after = buf.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let rest = &buf[after..];
    let colon = rest.iter().position(|b| *b == b':')?;
    let tail = &rest[colon + 1..];
    let start = tail.iter().position(|b| !b.is_ascii_whitespace())?;
    let end = start
        + tail[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    // Digits running to the end of the buffer may still be half read, so
    // they only count once something follows them.
    if end == start || end == tail.len() {
        return None;
    }
    std::str::from_utf8(&tail[start..end]).ok()?.parse().ok()
}

// Braces counted outside strings: bwrap writes one multi-line document, and portals cannot
// use a truncated one.
fn json_object_end(buf: &[u8]) -> Option<usize> {
    let mut depth = 0u32;
    let mut in_string = false;
    let mut escaped = false;
    for (i, b) in buf.iter().enumerate() {
        match b {
            _ if escaped => escaped = false,
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

// Portals read this same document back out of `bwrapinfo.json`, so it is returned as written.
pub(super) fn read_sandbox_info(
    info: &OwnedFd,
    child: &mut Child,
    deadline: Instant,
) -> Option<(i32, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        if let Some(end) = json_object_end(&buf)
            && let Some(pid) = parse_child_pid(&buf[..end])
        {
            buf.truncate(end);
            return Some((pid, buf));
        }
        if Instant::now() >= deadline || child.try_wait().ok()?.is_some() {
            return None;
        }
        let slice = Timespec {
            tv_sec: POLL.as_secs() as Secs,
            tv_nsec: POLL.subsec_nanos() as Nsecs,
        };
        match poll(&mut [PollFd::new(info, PollFlags::IN)], Some(&slice)) {
            // A signal during startup is acted on by the wait loop, so
            // every interruption here is simply retried until the deadline.
            Ok(0) | Err(_) => continue,
            Ok(_) => {}
        }
        match rustix::io::read(info, &mut chunk) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(Errno::INTR) => {}
            Err(_) => return None,
        }
    }
}

// The reaper's child carries bwrap's name until it execs, and a failed exec leaves another.
fn is_supervisor(pid: Pid) -> bool {
    let comm = format!("/proc/{}/comm", pid.as_raw_nonzero());
    std::fs::read_to_string(comm).is_ok_and(|name| name == format!("{}\n", init_bin::NAME))
}

// The reaper is pid 1 there and ignores outside signals it has no handler for; `bubbler-init`,
// its first child, handles SIGTERM. Only once released: a held sandbox has not forked it.
pub(super) fn supervisor_pid(reaper: i32, child: &mut Child, deadline: Instant) -> Option<Pid> {
    let children = PathBuf::from(format!("/proc/{reaper}/task/{reaper}/children"));
    loop {
        // An empty list or a child not yet exec'd is worth waiting on; a failed read means the
        // sandbox is gone or the kernel has no `children` file, and neither improves.
        let list = std::fs::read_to_string(&children).ok()?;
        if let Some(pid) = list
            .split_ascii_whitespace()
            .next()
            .and_then(|p| p.parse::<i32>().ok())
            .and_then(Pid::from_raw)
            && is_supervisor(pid)
        {
            return Some(pid);
        }
        if Instant::now() >= deadline || child.try_wait().ok()?.is_some() {
            return None;
        }
        std::thread::sleep(POLL);
    }
}

#[derive(Debug)]
pub(super) struct FileGuard(pub(super) PathBuf);

impl Drop for FileGuard {
    fn drop(&mut self) {
        // Nothing to report: a concurrent start may have replaced the
        // socket, and a stale one is detected by connecting to it anyway.
        let _ = std::fs::remove_file(&self.0);
    }
}

// Removes only this run's entry: the `.flatpak` directory above it is shared with flatpak.
pub(super) struct FlatpakGuard(PathBuf);

impl Drop for FlatpakGuard {
    fn drop(&mut self) {
        // Nothing to report: the directory holds this run's identity and
        // nothing else, and a leftover only names a pid that is gone.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Only a directory holding nothing but a `bwrapinfo.json` whose `child-pid` is dead; anything
// else is someone's to keep.
fn sweep_identity(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let names: Vec<OsString> = entries.flatten().map(|e| e.file_name()).collect();
    if names != [OsString::from(dbus::BWRAPINFO)] {
        return;
    }
    let Ok(info) = std::fs::read(dir.join(dbus::BWRAPINFO)) else {
        return;
    };
    let gone = parse_child_pid(&info)
        .and_then(Pid::from_raw)
        .is_some_and(|pid| !proc::pid_alive(pid));
    if gone {
        let _ = std::fs::remove_dir_all(dir);
    }
}

// Created outright, never adopted: a second run of the instance must not publish over the
// first one's identity.
fn publish_bwrapinfo(env: &Env, instance: &str, info: &[u8]) -> Result<FlatpakGuard, LaunchError> {
    mkdir_private(&env.runtime_dir.join(dbus::FLATPAK_DIR))?;
    let dir = dbus::flatpak_instance_dir(env, instance);
    sweep_identity(&dir);
    rustix::fs::mkdir(&dir, Mode::RWXU)
        .map_err(|e| LaunchError::Io(dir.to_path_buf(), e.into()))?;
    let guard = FlatpakGuard(dir.clone());
    // Written and renamed inside the directory, so a portal reading it
    // never sees half a document.
    let tmp = dir.join(format!("{}.new", dbus::BWRAPINFO));
    std::fs::write(&tmp, info).map_err(|e| LaunchError::Io(tmp.clone(), e))?;
    let dest = dir.join(dbus::BWRAPINFO);
    std::fs::rename(&tmp, &dest).map_err(|e| LaunchError::Io(dest, e))?;
    Ok(guard)
}

// Never fatal: an app whose portal calls fail still runs.
pub(super) fn publish_identity(
    env: &Env,
    instance: &str,
    info: Option<&[u8]>,
) -> Option<FlatpakGuard> {
    let Some(info) = info else {
        eprintln!("bubbler: warning: the sandbox reported no pid, so portal operations will fail");
        return None;
    };
    match publish_bwrapinfo(env, instance, info) {
        Ok(guard) => Some(guard),
        Err(e) => {
            // `LaunchError::Io` shows the path; what went wrong is its source.
            let why = std::error::Error::source(&e).map_or_else(String::new, |s| format!(": {s}"));
            eprintln!("bubbler: warning: {e}{why}, so portal operations will fail");
            None
        }
    }
}

// Closing the pipe releases the sandbox as the byte does, so a failed write still starts it.
pub(super) fn release_block(alloc: &mut RealAlloc) {
    if let Some(fd) = alloc.block_write.take() {
        let _ = rustix::io::write(&fd, b"\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar_argv::test_support::*;
    use std::process::Command;

    /// A pid no process has: a child that has already been reaped.
    fn dead_pid() -> u32 {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    fn bwrapinfo(pid: u32) -> Vec<u8> {
        format!("{{\n    \"child-pid\": {pid},\n    \"x\": 1\n}}\n").into_bytes()
    }

    #[test]
    fn a_dead_runs_identity_directory_is_swept_before_the_new_one_is_made() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = dbus::flatpak_instance_dir(&e, "t");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(dbus::BWRAPINFO), bwrapinfo(dead_pid())).unwrap();
        let guard = publish_bwrapinfo(&e, "t", &bwrapinfo(4321)).unwrap();
        assert_eq!(
            std::fs::read(dir.join(dbus::BWRAPINFO)).unwrap(),
            bwrapinfo(4321)
        );
        drop(guard);
        assert!(!dir.exists(), "the identity outlived the run");
    }

    #[test]
    fn an_identity_directory_that_is_not_a_dead_runs_is_never_adopted() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = dbus::flatpak_instance_dir(&e, "t");
        // A live pid: another bubbler is using this instance's identity.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(dbus::BWRAPINFO), bwrapinfo(std::process::id())).unwrap();
        assert!(matches!(
            publish_bwrapinfo(&e, "t", &bwrapinfo(4321)),
            Err(LaunchError::Io(_, _))
        ));
        // Anything else in it is not something bubbler put there.
        std::fs::write(dir.join(dbus::BWRAPINFO), bwrapinfo(dead_pid())).unwrap();
        std::fs::write(dir.join("other"), b"").unwrap();
        assert!(matches!(
            publish_bwrapinfo(&e, "t", &bwrapinfo(4321)),
            Err(LaunchError::Io(_, _))
        ));
        assert!(dir.join("other").is_file(), "a foreign file was removed");
    }

    #[test]
    fn a_json_object_ends_at_its_closing_brace() {
        let doc = b"{\n    \"child-pid\": 7\n}\n";
        assert_eq!(json_object_end(doc), Some(doc.len() - 1));
        assert_eq!(json_object_end(b"{\"a\": {\"b\": 1}}"), Some(15));
        // Braces inside a string do not close the object, and a document
        // still being written has no end yet.
        assert_eq!(json_object_end(b"{\"a\": \"}\", \"b\": 1}"), Some(18));
        assert_eq!(json_object_end(b"{\"a\": \"\\\"}\"}"), Some(12));
        assert_eq!(json_object_end(b"{\n    \"child-pid\": 7"), None);
        assert_eq!(json_object_end(b""), None);
    }

    #[test]
    fn child_pid_is_scanned_out_of_bwraps_json() {
        assert_eq!(
            parse_child_pid(b"{\n    \"child-pid\": 4321,\n    \"net-namespace\": 7\n}"),
            Some(4321)
        );
        assert_eq!(parse_child_pid(b"{\"child-pid\":9}"), Some(9));
        // A pid still being written, no pid, and no member at all.
        assert_eq!(parse_child_pid(b"{\n    \"child-pid\": 43"), None);
        assert_eq!(parse_child_pid(b"{\n    \"child-pid\": }"), None);
        assert_eq!(parse_child_pid(b"{\"cgroup-namespace\": 4026533374}"), None);
        assert_eq!(parse_child_pid(b""), None);
    }

    #[test]
    fn only_a_process_running_the_supervisor_is_signalled() {
        let me = Pid::from_raw(std::process::id() as i32).expect("a live pid");
        assert!(!is_supervisor(me), "this test binary is not the supervisor");
    }
}
