//! The only place that produces bubblewrap arguments. Arguments are kept
//! in fixed phases because `bwrap(1)` applies filesystem operations in
//! command-line order: a later `--tmpfs /run` would silently hide an
//! earlier socket bind underneath it.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

use crate::env::{Env, SANDBOX_HOME};
use crate::error::LaunchError;
use crate::host::Host;

/// One entry of a phase: either a literal argument or a generated file
/// that only becomes arguments once an fd has been allocated for it.
#[derive(Debug, Clone)]
enum Item {
    Arg(OsString),
    /// Content written to an fd by the allocator at `finish` time and
    /// bound read-only at `dest` with `mode`.
    Data {
        content: Vec<u8>,
        dest: PathBuf,
        mode: OsString,
    },
}

/// Ordered, phase-separated bubblewrap arguments.
///
/// Phases: 1 namespaces, 2 filesystem skeleton, 3 runtime dir,
/// 4 service binds, 5 environment, then `--` and the command.
// No `Default`: `baseline` is the only constructor, so a `BwrapArgs`
// without the baseline restrictions cannot be built.
#[derive(Debug, Clone)]
pub struct BwrapArgs {
    namespaces: Vec<Item>,
    skeleton: Vec<Item>,
    runtime_dir: Vec<Item>,
    binds: Vec<Item>,
    env: Vec<Item>,
}

fn push<const N: usize>(v: &mut Vec<Item>, parts: [&OsStr; N]) {
    v.extend(parts.iter().map(|p| Item::Arg(p.to_os_string())));
}

impl BwrapArgs {
    /// The restrictions every sandbox gets: all namespaces unshared, no
    /// network, read-only `/usr` `/etc` `/opt`, empty `/tmp` `/var` `/run`,
    /// a private home at [`SANDBOX_HOME`], an empty `$XDG_RUNTIME_DIR` at
    /// the same path as on the host and mode 0700 (`--perms` applies to the
    /// next operation only, so it must immediately precede `--dir`), cleared
    /// environment with only locale/terminal passthrough. Services relax
    /// this explicitly. `--unshare-all` uses bwrap's `-try` semantics for
    /// the user namespace (`bwrap(1)`), so on a host without unprivileged
    /// user namespaces the sandbox may start without one; to be revisited.
    pub fn baseline(env: &Env, instance_home: &Path, _host: &dyn Host) -> Self {
        let mut a = Self {
            namespaces: Vec::new(),
            skeleton: Vec::new(),
            runtime_dir: Vec::new(),
            binds: Vec::new(),
            env: Vec::new(),
        };
        let o = OsStr::new;
        push(
            &mut a.namespaces,
            [
                o("--unshare-all"),
                o("--die-with-parent"),
                o("--new-session"),
                o("--hostname"),
                o("bubbler"),
            ],
        );

        push(&mut a.skeleton, [o("--ro-bind"), o("/usr"), o("/usr")]);
        for (target, link) in [
            ("usr/bin", "/bin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
            ("usr/bin", "/sbin"),
        ] {
            push(&mut a.skeleton, [o("--symlink"), o(target), o(link)]);
        }
        push(&mut a.skeleton, [o("--ro-bind"), o("/etc"), o("/etc")]);
        push(&mut a.skeleton, [o("--ro-bind-try"), o("/opt"), o("/opt")]);
        push(
            &mut a.skeleton,
            [o("--proc"), o("/proc"), o("--dev"), o("/dev")],
        );
        push(
            &mut a.skeleton,
            [
                o("--tmpfs"),
                o("/tmp"),
                o("--tmpfs"),
                o("/var"),
                o("--tmpfs"),
                o("/run"),
            ],
        );
        push(
            &mut a.skeleton,
            [o("--bind"), instance_home.as_os_str(), o(SANDBOX_HOME)],
        );

        push(
            &mut a.runtime_dir,
            [
                o("--perms"),
                o("0700"),
                o("--dir"),
                env.runtime_dir.as_os_str(),
            ],
        );

        push(&mut a.env, [o("--clearenv")]);
        for (k, v) in &env.passthrough {
            push(&mut a.env, [o("--setenv"), k, v]);
        }
        push(&mut a.env, [o("--setenv"), o("HOME"), o(SANDBOX_HOME)]);
        push(&mut a.env, [o("--setenv"), o("PATH"), o("/usr/bin")]);
        push(
            &mut a.env,
            [
                o("--setenv"),
                o("XDG_RUNTIME_DIR"),
                env.runtime_dir.as_os_str(),
            ],
        );
        a
    }

    /// Keep the host network namespace (`--share-net`). Only the
    /// `network` service calls this. Idempotent: `--share-net` is emitted
    /// once however often this is called, and always directly after
    /// `--unshare-all`, which bwrap requires.
    pub fn share_net(&mut self) {
        let flag = OsStr::new("--share-net");
        if !self
            .namespaces
            .iter()
            .any(|i| matches!(i, Item::Arg(a) if a == flag))
        {
            self.namespaces.insert(1, Item::Arg(flag.to_os_string()));
        }
    }

    /// Read-only bind of a host path (phase 4).
    pub fn ro_bind(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            [OsStr::new("--ro-bind"), src.as_os_str(), dst.as_os_str()],
        );
    }

    /// Read-write bind of a host path (phase 4).
    pub fn bind(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            [OsStr::new("--bind"), src.as_os_str(), dst.as_os_str()],
        );
    }

    /// Bind `content` read-only at `dest` with `mode` (phase 4). The bytes
    /// are handed to the fd allocator in `finish`.
    pub fn ro_bind_data(&mut self, content: Vec<u8>, dest: &Path, mode: &str) {
        self.binds.push(Item::Data {
            content,
            dest: dest.to_path_buf(),
            mode: mode.into(),
        });
    }

    /// Set a variable inside the sandbox (phase 5, after `--clearenv`).
    pub fn setenv(&mut self, key: &OsStr, value: &OsStr) {
        push(&mut self.env, [OsStr::new("--setenv"), key, value]);
    }

    /// Concatenate the phases, resolve data items through `alloc` (which
    /// returns the fd number bwrap should read), append `--` and the
    /// command. The result is the complete argv after the program name.
    pub fn finish(
        self,
        command: &[OsString],
        alloc: &mut dyn FnMut(&[u8]) -> io::Result<OsString>,
    ) -> Result<Vec<OsString>, LaunchError> {
        let mut out = Vec::new();
        for item in [
            self.namespaces,
            self.skeleton,
            self.runtime_dir,
            self.binds,
            self.env,
        ]
        .into_iter()
        .flatten()
        {
            match item {
                Item::Arg(a) => out.push(a),
                Item::Data {
                    content,
                    dest,
                    mode,
                } => {
                    let fd = alloc(&content).map_err(LaunchError::Data)?;
                    // `--perms` applies to the next operation only.
                    out.extend([
                        "--perms".into(),
                        mode,
                        "--ro-bind-data".into(),
                        fd,
                        dest.into_os_string(),
                    ]);
                }
            }
        }
        out.push(OsString::from("--"));
        out.extend_from_slice(command);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use std::path::Path;

    fn env() -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: Some("wayland-1".into()),
            display: Some(":0".into()),
            xauthority: None,
            passthrough: vec![("TERM".into(), "foot".into())],
        }
    }

    fn strs(v: &[OsString]) -> Vec<&str> {
        v.iter().map(|s| s.to_str().unwrap()).collect()
    }

    fn counter() -> impl FnMut(&[u8]) -> std::io::Result<OsString> {
        let mut n = 2;
        move |_| {
            n += 1;
            Ok(OsString::from(n.to_string()))
        }
    }

    #[test]
    fn baseline_argv_is_exact() {
        let args = BwrapArgs::baseline(
            &env(),
            Path::new("/home/han/.local/share/bubbler/instances/t/home"),
            &FakeHost::default(),
        );
        let argv = args
            .finish(&["/usr/bin/true".into()], &mut counter())
            .unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--hostname",
                "bubbler",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/bin",
                "/sbin",
                "--ro-bind",
                "/etc",
                "/etc",
                "--ro-bind-try",
                "/opt",
                "/opt",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/var",
                "--tmpfs",
                "/run",
                "--bind",
                "/home/han/.local/share/bubbler/instances/t/home",
                "/home/bubbler",
                "--perms",
                "0700",
                "--dir",
                "/run/user/1000",
                "--clearenv",
                "--setenv",
                "TERM",
                "foot",
                "--setenv",
                "HOME",
                "/home/bubbler",
                "--setenv",
                "PATH",
                "/usr/bin",
                "--setenv",
                "XDG_RUNTIME_DIR",
                "/run/user/1000",
                "--",
                "/usr/bin/true",
            ]
        );
    }

    #[test]
    fn service_binds_come_after_runtime_dir_and_before_env() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.setenv(OsStr::new("WAYLAND_DISPLAY"), OsStr::new("wayland-1"));
        args.ro_bind(
            Path::new("/run/user/1000/wayland-1"),
            Path::new("/run/user/1000/wayland-1"),
        );
        args.share_net();
        let finished = args.finish(&["sh".into()], &mut counter()).unwrap();
        let argv = strs(&finished);
        let pos = |s: &str| argv.iter().position(|a| *a == s).unwrap();
        assert_eq!(
            pos("--share-net"),
            1,
            "share-net sits in phase 1 right after --unshare-all"
        );
        assert!(pos("/run/user/1000/wayland-1") > pos("--dir"));
        assert!(pos("/run/user/1000/wayland-1") < pos("--clearenv"));
        assert!(pos("WAYLAND_DISPLAY") > pos("--clearenv"));
    }

    #[test]
    fn share_net_is_idempotent() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.share_net();
        args.share_net();
        let finished = args.finish(&["sh".into()], &mut counter()).unwrap();
        let argv = strs(&finished);
        assert_eq!(argv.iter().filter(|a| **a == "--share-net").count(), 1);
    }

    #[test]
    fn data_items_become_ro_bind_data_with_allocated_fds() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ro_bind_data(b"hello".to_vec(), Path::new("/etc/x"), "0644");
        args.ro_bind_data(b"world".to_vec(), Path::new("/etc/y"), "0600");
        let mut seen = Vec::new();
        let argv = args
            .finish(&["sh".into()], &mut |c: &[u8]| {
                seen.push(c.to_vec());
                Ok(OsString::from((seen.len() + 2).to_string()))
            })
            .unwrap();
        let s = strs(&argv);
        assert!(
            s.windows(5)
                .any(|w| w == ["--perms", "0644", "--ro-bind-data", "3", "/etc/x"])
        );
        assert!(
            s.windows(5)
                .any(|w| w == ["--perms", "0600", "--ro-bind-data", "4", "/etc/y"])
        );
        assert_eq!(seen, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn allocator_failure_is_data_error() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ro_bind_data(b"x".to_vec(), Path::new("/etc/x"), "0644");
        let r = args.finish(&["sh".into()], &mut |_| Err(std::io::Error::other("nope")));
        assert!(matches!(r, Err(LaunchError::Data(_))));
    }
}
