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
    /// `--info-fd` with the fd the allocator opens at `finish` time.
    InfoFd,
    /// `--block-fd` with the fd the allocator opens at `finish` time.
    BlockFd,
    /// A compiled seccomp program, read by bwrap from an fd the allocator
    /// opens at `finish` time.
    Seccomp {
        /// cBPF as `struct sock_filter` bytes; bwrap rejects a length that
        /// is not a multiple of eight.
        program: Vec<u8>,
    },
}

/// Where the `bubbler-init` supervisor is bound inside every sandbox.
/// `/run` is a tmpfs this builder creates, so the bind works whether or
/// not bubbler is installed on the host.
// Not under `/usr`: that is a read-only bind of the host `/usr`, and bwrap
// 0.11.2 refuses a destination in it ("Can't mkdir parents for
// /usr/lib/bubbler/bubbler-init: Read-only file system").
pub const INIT_INSIDE: &str = "/run/bubbler-init";

/// Turns generated content and channels into the fd numbers bwrap is told
/// to read them from. `--dry-run` counts, a real run creates the fds.
pub trait FdAllocator {
    /// Fd holding `content`, for a `--ro-bind-data`.
    fn data(&mut self, content: &[u8]) -> io::Result<OsString>;
    /// Fd of the listening control socket `bubbler-init` serves.
    fn init_socket(&mut self) -> io::Result<OsString>;
    /// Fd a sidecar reports readiness on; the allocator keeps the other end.
    fn ready_pipe(&mut self) -> io::Result<OsString>;
    /// Fd bwrap reports the sandbox pid on; the allocator keeps the read end.
    fn info_pipe(&mut self) -> io::Result<OsString>;
    /// Fd the sandbox is held at until released; the allocator keeps the
    /// write end.
    fn block_pipe(&mut self) -> io::Result<OsString>;
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
    /// `--ctty` in the supervisor's own argv, not a bwrap flag.
    ctty: bool,
}

fn push<const N: usize>(v: &mut Vec<Item>, parts: [&OsStr; N]) {
    v.extend(parts.iter().map(|p| Item::Arg(p.to_os_string())));
}

/// Host `/etc` entries bound read-only when they exist. Everything else in
/// `/etc` is hidden by the tmpfs mounted first.
pub const ETC_ALLOWLIST: &[&str] = &[
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "fonts",
    "localtime",
    "machine-id",
    "nsswitch.conf",
    "hosts",
    "host.conf",
    "ssl",
    "ca-certificates",
    "mime.types",
    "xdg",
    "gtk-3.0",
    "gtk-4.0",
    "pulse",
    "pipewire",
    "drirc",
    "vulkan",
    "glvnd",
    "egl",
    "os-release",
];

/// Host `/etc` entries the D-Bus proxy sandbox gets when they exist:
/// what the dynamic loader and name resolution read, and nothing else.
pub const PROXY_ETC: &[&str] = &["ld.so.cache", "ld.so.conf", "ld.so.conf.d", "nsswitch.conf"];

/// `/etc/passwd` for the sandbox: the fixed `bubbler` user plus `nobody`,
/// which is what files owned by other host users map to in the user namespace.
pub fn passwd_content(uid: u32, gid: u32) -> Vec<u8> {
    format!(
        "bubbler:x:{uid}:{gid}:bubbler:{SANDBOX_HOME}:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n"
    )
    .into_bytes()
}

/// `/etc/group` matching [`passwd_content`].
pub fn group_content(gid: u32) -> Vec<u8> {
    format!("bubbler:x:{gid}:\nnobody:x:65534:\n").into_bytes()
}

impl BwrapArgs {
    /// The restrictions every sandbox gets: all namespaces unshared, no
    /// network, read-only `/usr` `/opt`, an `/etc` that is an allowlist
    /// ([`ETC_ALLOWLIST`]) over a tmpfs plus a synthetic passwd and group,
    /// empty `/tmp` `/var` `/run`, a private home at [`SANDBOX_HOME`], an
    /// empty `$XDG_RUNTIME_DIR` at the same path as on the host and mode
    /// 0700 (`--perms` applies to the next operation only, so it must
    /// immediately precede `--dir`), the private home as the working
    /// directory, an `--info-fd` the sandbox pid is reported on, cleared
    /// environment with only locale/terminal
    /// passthrough and the fixed user name. Services relax
    /// this explicitly. `--unshare-all` uses bwrap's `-try` semantics for
    /// the user namespace (`bwrap(1)`), so on a host without unprivileged
    /// user namespaces the sandbox may start without one; to be revisited.
    pub fn baseline(env: &Env, instance_home: &Path, host: &dyn Host) -> Self {
        let mut a = Self {
            namespaces: Vec::new(),
            skeleton: Vec::new(),
            runtime_dir: Vec::new(),
            binds: Vec::new(),
            env: Vec::new(),
            ctty: false,
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
                // bwrap keeps the working directory it was started in when
                // that path also exists inside, so without --chdir a sandbox
                // started from, say, /tmp would run there instead of in the
                // private home.
                o("--chdir"),
                o(SANDBOX_HOME),
            ],
        );
        // bwrap reports the sandbox pid here; the launcher needs it to
        // signal the supervisor, since bwrap forwards no signals itself.
        a.namespaces.push(Item::InfoFd);

        push(&mut a.skeleton, [o("--ro-bind"), o("/usr"), o("/usr")]);
        for (target, link) in [
            ("usr/bin", "/bin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
            ("usr/bin", "/sbin"),
        ] {
            push(&mut a.skeleton, [o("--symlink"), o(target), o(link)]);
        }
        push(&mut a.skeleton, [o("--ro-bind-try"), o("/opt"), o("/opt")]);
        // The tmpfs has to precede the entry binds and the data files, or it
        // would hide them: bwrap applies filesystem operations in argv order.
        push(&mut a.skeleton, [o("--tmpfs"), o("/etc")]);
        for name in ETC_ALLOWLIST {
            let p = Path::new("/etc").join(name);
            if host.file_type(&p).is_some() {
                push(
                    &mut a.skeleton,
                    [o("--ro-bind"), p.as_os_str(), p.as_os_str()],
                );
            }
        }
        a.skeleton.push(Item::Data {
            content: passwd_content(env.uid, env.gid),
            dest: "/etc/passwd".into(),
            mode: "0644".into(),
        });
        a.skeleton.push(Item::Data {
            content: group_content(env.gid),
            dest: "/etc/group".into(),
            mode: "0644".into(),
        });
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
        push(&mut a.env, [o("--setenv"), o("USER"), o("bubbler")]);
        push(&mut a.env, [o("--setenv"), o("LOGNAME"), o("bubbler")]);
        a
    }

    /// The sandbox the D-Bus proxy sidecar runs in: the same namespace
    /// restrictions as [`BwrapArgs::baseline`], a read-only `/usr` and a
    /// minimal `/etc` ([`PROXY_ETC`]) so the proxy binary can start, no
    /// home, no runtime dir of its own, and exactly two paths from the
    /// session: the host bus socket read-only and `socket_dir`
    /// read-write, which is where it creates the filtered socket. The
    /// environment is cleared; the bus address is an argument.
    ///
    /// `socket_dir` is a directory of its own, never the instance's
    /// runtime directory: that one holds the supervisor's control socket,
    /// and a process that reaches it can run commands inside the app.
    pub fn proxy_baseline(host_bus: &Path, socket_dir: &Path, host: &dyn Host) -> Self {
        let mut a = Self {
            namespaces: Vec::new(),
            skeleton: Vec::new(),
            runtime_dir: Vec::new(),
            binds: Vec::new(),
            env: Vec::new(),
            ctty: false,
        };
        let o = OsStr::new;
        push(
            &mut a.namespaces,
            [
                o("--unshare-all"),
                o("--die-with-parent"),
                o("--new-session"),
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
        push(&mut a.skeleton, [o("--tmpfs"), o("/etc")]);
        for name in PROXY_ETC {
            let p = Path::new("/etc").join(name);
            if host.file_type(&p).is_some() {
                push(
                    &mut a.skeleton,
                    [o("--ro-bind"), p.as_os_str(), p.as_os_str()],
                );
            }
        }
        push(
            &mut a.skeleton,
            [
                o("--proc"),
                o("/proc"),
                o("--dev"),
                o("/dev"),
                o("--tmpfs"),
                o("/tmp"),
            ],
        );
        push(
            &mut a.skeleton,
            [o("--ro-bind"), host_bus.as_os_str(), host_bus.as_os_str()],
        );
        // Read-write because the proxy has to create its socket here, and
        // nothing else of the session is in this directory.
        push(
            &mut a.skeleton,
            [o("--bind"), socket_dir.as_os_str(), socket_dir.as_os_str()],
        );
        push(&mut a.env, [o("--clearenv")]);
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

    /// Hold the sandbox at startup until the launcher lets it go
    /// (`bwrap(1)` `--block-fd`, phase 1). Only a sandbox whose identity
    /// bubbler still has to publish waits, and it waits before it execs.
    // After `--info-fd`, which bwrap writes before it reads this one: the
    // identity is built out of that document.
    pub fn block_until_released(&mut self) {
        self.namespaces.push(Item::BlockFd);
    }

    /// Load one compiled seccomp program into the sandbox (`bwrap(1)`
    /// `--add-seccomp-fd`, phase 1). Repeatable: bwrap loads every program
    /// given, in order, which is how one denylist can answer with more
    /// than one error.
    // `bwrap(1)`: all of them "except possibly the last, must allow use of
    // the PR_SET_SECCOMP prctl", which is why the config refuses
    // `deny "prctl"`. Placed after `--info-fd` and `--block-fd` only for
    // readability; bwrap orders seccomp fds among themselves, not against
    // other flags.
    pub fn add_seccomp(&mut self, program: Vec<u8>) {
        self.namespaces.push(Item::Seccomp { program });
    }

    /// Read-only bind of a host path (phase 4).
    pub fn ro_bind(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            [OsStr::new("--ro-bind"), src.as_os_str(), dst.as_os_str()],
        );
    }

    /// Bind a host path "allowing device access" (`bwrap(1)` `--dev-bind`,
    /// phase 4), which device nodes such as `/dev/dri/renderD128` need.
    /// bwrap has no read-only form of it, so the two services that bind
    /// device directories, `dri` and `gamepad`, both grant write access.
    pub fn dev_bind(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            [OsStr::new("--dev-bind"), src.as_os_str(), dst.as_os_str()],
        );
    }

    /// Read-write bind of a host path (phase 4).
    pub fn bind(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            [OsStr::new("--bind"), src.as_os_str(), dst.as_os_str()],
        );
    }

    /// Bind the host `bubbler-init` binary read-only at [`INIT_INSIDE`]
    /// (phase 4), which is the program every sandbox actually starts.
    pub fn bind_init(&mut self, host_path: &Path) {
        self.ro_bind(host_path, Path::new(INIT_INSIDE));
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

    /// Let the command take its stdin as a controlling terminal: `--ctty`
    /// for the supervisor. Only for a pty bubbler allocated and handed to
    /// this sandbox, never for a terminal it inherited from the user.
    pub fn ctty(&mut self) {
        self.ctty = true;
    }

    /// Set a variable inside the sandbox (phase 5, after `--clearenv`).
    pub fn setenv(&mut self, key: &OsStr, value: &OsStr) {
        push(&mut self.env, [OsStr::new("--setenv"), key, value]);
    }

    /// Concatenate the phases, resolve data items through `alloc` (which
    /// returns the fd number bwrap should read), then append `--` and the
    /// command wrapped in [`INIT_INSIDE`], which supervises it and serves
    /// the exec channel. The result is the complete argv after `bwrap`.
    pub fn finish(
        self,
        command: &[OsString],
        alloc: &mut dyn FdAllocator,
    ) -> Result<Vec<OsString>, LaunchError> {
        let ctty = self.ctty;
        let mut out = self.emit(alloc)?;
        let socket = alloc.init_socket().map_err(LaunchError::Data)?;
        out.extend([
            OsString::from("--"),
            INIT_INSIDE.into(),
            "--socket-fd".into(),
            socket,
        ]);
        if ctty {
            out.push("--ctty".into());
        }
        out.push("--".into());
        out.extend_from_slice(command);
        Ok(out)
    }

    /// Like [`BwrapArgs::finish`] but running `command` directly. Only
    /// sidecars use it: they have no exec channel to serve, so there is
    /// nothing for `bubbler-init` to supervise.
    pub fn finish_plain(
        self,
        command: &[OsString],
        alloc: &mut dyn FdAllocator,
    ) -> Result<Vec<OsString>, LaunchError> {
        let mut out = self.emit(alloc)?;
        out.push(OsString::from("--"));
        out.extend_from_slice(command);
        Ok(out)
    }

    fn emit(self, alloc: &mut dyn FdAllocator) -> Result<Vec<OsString>, LaunchError> {
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
                    let fd = alloc.data(&content).map_err(LaunchError::Data)?;
                    // `--perms` applies to the next operation only.
                    out.extend([
                        "--perms".into(),
                        mode,
                        "--ro-bind-data".into(),
                        fd,
                        dest.into_os_string(),
                    ]);
                }
                Item::InfoFd => {
                    let fd = alloc.info_pipe().map_err(LaunchError::Data)?;
                    out.extend(["--info-fd".into(), fd]);
                }
                Item::BlockFd => {
                    let fd = alloc.block_pipe().map_err(LaunchError::Data)?;
                    out.extend(["--block-fd".into(), fd]);
                }
                Item::Seccomp { program } => {
                    let fd = alloc.data(&program).map_err(LaunchError::Data)?;
                    out.extend(["--add-seccomp-fd".into(), fd]);
                }
            }
        }
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
            config_home: "/home/han/.config".into(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: Some("wayland-1".into()),
            display: Some(":0".into()),
            xauthority: None,
            passthrough: vec![("TERM".into(), "foot".into())],
            init_override: None,
            dbus_address: None,
            dbus_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
        }
    }

    fn strs(v: &[OsString]) -> Vec<&str> {
        v.iter().map(|s| s.to_str().unwrap()).collect()
    }

    /// Numbers every fd from 3 like a dry run, so argv assertions are exact.
    struct Counter(u32);

    impl Counter {
        fn new() -> Self {
            Self(2)
        }

        fn bump(&mut self) -> io::Result<OsString> {
            self.0 += 1;
            Ok(OsString::from(self.0.to_string()))
        }
    }

    impl FdAllocator for Counter {
        fn data(&mut self, _content: &[u8]) -> io::Result<OsString> {
            self.bump()
        }
        fn init_socket(&mut self) -> io::Result<OsString> {
            self.bump()
        }
        fn ready_pipe(&mut self) -> io::Result<OsString> {
            self.bump()
        }
        fn info_pipe(&mut self) -> io::Result<OsString> {
            self.bump()
        }
        fn block_pipe(&mut self) -> io::Result<OsString> {
            self.bump()
        }
    }

    /// Counter that also keeps every data payload it was handed.
    struct Recorder {
        seen: Vec<Vec<u8>>,
        next: Counter,
    }

    impl FdAllocator for Recorder {
        fn data(&mut self, content: &[u8]) -> io::Result<OsString> {
            self.seen.push(content.to_vec());
            self.next.bump()
        }
        fn init_socket(&mut self) -> io::Result<OsString> {
            self.next.bump()
        }
        fn ready_pipe(&mut self) -> io::Result<OsString> {
            self.next.bump()
        }
        fn info_pipe(&mut self) -> io::Result<OsString> {
            self.next.bump()
        }
        fn block_pipe(&mut self) -> io::Result<OsString> {
            self.next.bump()
        }
    }

    struct Failing;

    impl FdAllocator for Failing {
        fn data(&mut self, _content: &[u8]) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
        }
        fn init_socket(&mut self) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
        }
        fn ready_pipe(&mut self) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
        }
        fn info_pipe(&mut self) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
        }
        fn block_pipe(&mut self) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
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
            .finish(&["/usr/bin/true".into()], &mut Counter::new())
            .unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--hostname",
                "bubbler",
                "--chdir",
                "/home/bubbler",
                "--info-fd",
                "3",
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
                "--ro-bind-try",
                "/opt",
                "/opt",
                "--tmpfs",
                "/etc",
                "--perms",
                "0644",
                "--ro-bind-data",
                "4",
                "/etc/passwd",
                "--perms",
                "0644",
                "--ro-bind-data",
                "5",
                "/etc/group",
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
                "--setenv",
                "USER",
                "bubbler",
                "--setenv",
                "LOGNAME",
                "bubbler",
                "--",
                "/run/bubbler-init",
                "--socket-fd",
                "6",
                "--",
                "/usr/bin/true",
            ]
        );
    }

    #[test]
    fn proxy_baseline_argv_is_exact() {
        let (f, d, _) = crate::host::fake::types();
        let host = FakeHost::default()
            .with("/etc/ld.so.cache", f)
            .with("/etc/ld.so.conf.d", d)
            .with("/etc/nsswitch.conf", f)
            .with("/etc/hosts", f);
        let argv = BwrapArgs::proxy_baseline(
            Path::new("/run/user/1000/bus"),
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &host,
        )
        .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
        .unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
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
                "--tmpfs",
                "/etc",
                "--ro-bind",
                "/etc/ld.so.cache",
                "/etc/ld.so.cache",
                "--ro-bind",
                "/etc/ld.so.conf.d",
                "/etc/ld.so.conf.d",
                "--ro-bind",
                "/etc/nsswitch.conf",
                "/etc/nsswitch.conf",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/run/user/1000/bus",
                "/run/user/1000/bus",
                "--bind",
                "/run/user/1000/bubbler/t/dbus",
                "/run/user/1000/bubbler/t/dbus",
                "--clearenv",
                "--",
                "xdg-dbus-proxy",
            ],
            "an /etc entry that is not in PROXY_ETC must not appear"
        );
    }

    #[test]
    fn proxy_sandbox_takes_the_flatpak_info_data_file() {
        let mut args = BwrapArgs::proxy_baseline(
            Path::new("/run/user/1000/bus"),
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &FakeHost::default(),
        );
        args.ro_bind_data(
            b"[Application]\n".to_vec(),
            Path::new("/.flatpak-info"),
            "0644",
        );
        let argv = args
            .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        assert!(
            s.windows(5)
                .any(|w| w == ["--perms", "0644", "--ro-bind-data", "3", "/.flatpak-info"]),
            "{s:?}"
        );
        // No supervisor and no control socket: the proxy is not an instance.
        assert!(!s.contains(&INIT_INSIDE));
        assert!(!s.contains(&"--info-fd"));
    }

    #[test]
    fn etc_is_an_allowlist_of_existing_entries() {
        let (f, d, _) = crate::host::fake::types();
        let host = FakeHost::default()
            .with("/etc/hosts", f)
            .with("/etc/fonts", d)
            .with("/etc/shadow", f);
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &host)
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        let pos = |x: &str| s.iter().position(|a| *a == x).unwrap();
        assert!(s.windows(2).any(|w| w == ["--tmpfs", "/etc"]));
        assert!(
            s.windows(3)
                .any(|w| w == ["--ro-bind", "/etc/hosts", "/etc/hosts"])
        );
        assert!(
            s.windows(3)
                .any(|w| w == ["--ro-bind", "/etc/fonts", "/etc/fonts"])
        );
        assert!(!s.contains(&"/etc/shadow"));
        assert!(!s.windows(3).any(|w| w == ["--ro-bind", "/etc", "/etc"]));
        assert!(pos("/etc/hosts") > pos("--tmpfs"));
        assert!(
            s.windows(5)
                .any(|w| w == ["--perms", "0644", "--ro-bind-data", "4", "/etc/passwd"])
        );
        assert!(
            s.windows(5)
                .any(|w| w == ["--perms", "0644", "--ro-bind-data", "5", "/etc/group"])
        );
        assert!(pos("/etc/passwd") < pos("--proc"));
        assert!(s.windows(3).any(|w| w == ["--setenv", "USER", "bubbler"]));
        assert!(
            s.windows(3)
                .any(|w| w == ["--setenv", "LOGNAME", "bubbler"])
        );
    }

    #[test]
    fn passwd_and_group_content() {
        assert_eq!(
            passwd_content(1000, 1000),
            b"bubbler:x:1000:1000:bubbler:/home/bubbler:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n"
                .to_vec()
        );
        assert_eq!(
            group_content(1000),
            b"bubbler:x:1000:\nnobody:x:65534:\n".to_vec()
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
        let finished = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
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
    fn the_sandbox_blocks_only_when_asked_to() {
        let plain = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        assert!(!strs(&plain).contains(&"--block-fd"));

        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.block_until_released();
        let finished = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&finished);
        // Phase 1, and after --info-fd: bwrap writes the info it is blocked
        // for before it reads the block fd.
        assert_eq!(&s[7..11], &["--info-fd", "3", "--block-fd", "4"], "{s:?}");
    }

    #[test]
    fn share_net_is_idempotent() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.share_net();
        args.share_net();
        let finished = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let argv = strs(&finished);
        assert_eq!(argv.iter().filter(|a| **a == "--share-net").count(), 1);
    }

    #[test]
    fn data_items_become_ro_bind_data_with_allocated_fds() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ro_bind_data(b"hello".to_vec(), Path::new("/etc/x"), "0644");
        args.ro_bind_data(b"world".to_vec(), Path::new("/etc/y"), "0600");
        let mut rec = Recorder {
            seen: Vec::new(),
            next: Counter::new(),
        };
        let argv = args.finish(&["sh".into()], &mut rec).unwrap();
        let seen = rec.seen;
        let s = strs(&argv);
        // Fd 3 went to the info pipe, 4 and 5 to the baseline passwd and group.
        assert!(
            s.windows(5)
                .any(|w| w == ["--perms", "0644", "--ro-bind-data", "6", "/etc/x"])
        );
        assert!(
            s.windows(5)
                .any(|w| w == ["--perms", "0600", "--ro-bind-data", "7", "/etc/y"])
        );
        assert_eq!(seen[2..], [b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn allocator_failure_is_data_error() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ro_bind_data(b"x".to_vec(), Path::new("/etc/x"), "0644");
        let r = args.finish(&["sh".into()], &mut Failing);
        assert!(matches!(r, Err(LaunchError::Data(_))));
    }

    #[test]
    fn the_command_runs_under_bubbler_init_on_the_allocated_socket_fd() {
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        // Fd 3 went to the info pipe, 4 and 5 to the baseline passwd and group.
        assert_eq!(
            &s[s.len() - 6..],
            &["--", INIT_INSIDE, "--socket-fd", "6", "--", "sh"]
        );
    }

    #[test]
    fn the_controlling_terminal_switch_reaches_the_supervisor_argv() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ctty();
        let argv = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&argv);
        assert_eq!(
            &s[s.len() - 7..],
            &["--", INIT_INSIDE, "--socket-fd", "6", "--ctty", "--", "sh"]
        );
    }

    #[test]
    fn bind_init_maps_the_host_binary_onto_the_fixed_inside_path() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.bind_init(Path::new("/x/bubbler-init"));
        let finished = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&finished);
        let pos = |x: &str| s.iter().position(|a| *a == x).unwrap();
        assert!(
            s.windows(3)
                .any(|w| w == ["--ro-bind", "/x/bubbler-init", INIT_INSIDE])
        );
        assert!(pos("/x/bubbler-init") > pos("--dir"));
        assert!(pos("/x/bubbler-init") < pos("--clearenv"));
    }

    #[test]
    fn seccomp_programs_follow_the_info_and_block_fds_in_phase_one() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.block_until_released();
        args.add_seccomp(b"12345678".to_vec());
        args.add_seccomp(b"87654321".to_vec());
        let mut rec = Recorder {
            seen: Vec::new(),
            next: Counter::new(),
        };
        let finished = args.finish(&["sh".into()], &mut rec).unwrap();
        let s = strs(&finished);
        assert_eq!(
            &s[7..15],
            &[
                "--info-fd",
                "3",
                "--block-fd",
                "4",
                "--add-seccomp-fd",
                "5",
                "--add-seccomp-fd",
                "6",
            ],
            "{s:?}"
        );
        assert_eq!(
            rec.seen[..2],
            [b"12345678".to_vec(), b"87654321".to_vec()],
            "the programs are the first data the allocator is handed"
        );
    }

    #[test]
    fn a_sandbox_without_a_filter_has_no_seccomp_flag() {
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        assert!(!strs(&argv).contains(&"--add-seccomp-fd"));
    }
}
