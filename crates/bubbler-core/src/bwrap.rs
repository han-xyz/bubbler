//! The only place that produces bubblewrap arguments. Arguments are kept
//! in fixed phases because `bwrap(1)` applies filesystem operations in
//! command-line order: a later `--tmpfs /run` would silently hide an
//! earlier socket bind underneath it.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use crate::env::{Env, SANDBOX_HOME};
use crate::error::LaunchError;
use crate::host::Host;

/// Which decision put an argument in the argv. Rendering one takes the
/// config it indexes into, so it stays a tag here and text elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// [`BwrapArgs::baseline`] or [`BwrapArgs::proxy_baseline`]: what
    /// every sandbox is restricted to before a grant relaxes it.
    Baseline,
    /// A compiled seccomp program.
    Seccomp,
    /// A `userns "disable"` node.
    Userns,
    /// A `tmp size=` node, which moves the cap the baseline put on
    /// `/tmp`.
    Tmp,
    /// An `etc "host"` node, which replaces the tmpfs allowlist with the
    /// host's whole `/etc`.
    Etc,
    /// `--ctty`, decided by the terminal mode rather than by the config.
    Ctty,
    /// The `/.flatpak-info` document that names the sandbox to the proxy.
    Identity,
    /// Index into the instance config's `services`, in file order.
    Service(usize),
    /// Index into the instance config's `shares`: a `--share` flag.
    Share(usize),
    /// Index into the instance config's `env`, in file order.
    Env(usize),
    /// The `bubbler-init` bind and the supervisor's own arguments.
    Init,
    /// The program the sandbox runs, after the final `--`.
    Command,
}

/// One operation of a bwrap argv with the decision that produced it and,
/// for an argument bwrap reads a generated fd from, what is behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explained {
    /// What put these arguments in the argv.
    pub origin: Origin,
    /// The argv elements of this one operation, in order.
    pub args: Vec<OsString>,
    /// What an fd number in `args` refers to, for a reader who cannot
    /// see the pipe or the memfd behind it.
    pub note: Option<String>,
}

/// One entry of a phase with the origin that pushed it.
#[derive(Debug, Clone)]
struct Item {
    origin: Origin,
    kind: Kind,
}

/// Either the literal arguments of one operation or a generated file that
/// only becomes arguments once an fd has been allocated for it.
#[derive(Debug, Clone)]
enum Kind {
    /// The elements of one operation, e.g. `--ro-bind SRC DST`.
    Args(Vec<OsString>),
    /// The same, with what an explanation adds where the paths alone do
    /// not say what the operation is there for.
    Noted { args: Vec<OsString>, note: String },
    /// Content written to a host file by the allocator at `finish` time
    /// and bound read-only at `dest`.
    Data { content: Vec<u8>, dest: PathBuf },
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
        /// The architectures the program answers for, for
        /// [`Explained::note`].
        arches: &'static str,
    },
}

/// Where the `bubbler-init` supervisor is bound inside every sandbox.
/// `/run` is a tmpfs this builder creates, so the bind works whether or
/// not bubbler is installed on the host.
// Not under `/usr`: that is a read-only bind of the host `/usr`, and bwrap
// 0.11.2 refuses a destination in it ("Can't mkdir parents for
// /usr/lib/bubbler/bubbler-init: Read-only file system").
pub const INIT_INSIDE: &str = "/run/bubbler-init";

/// Where the `flatpak-spawn` shim — the same `bubbler-init` binary,
/// which takes that mode from its own `argv[0]` — is bound in a sandbox
/// that carries `/.flatpak-info`.
// Not a free choice: gdk-pixbuf's glycin loaders run the program through
// `env -i`, which leaves glibc's built-in path `/bin:/usr/bin` to find it
// (`getconf PATH`), and `/bin` is a symlink to `usr/bin` here.
pub const FLATPAK_SPAWN_INSIDE: &str = "/usr/bin/flatpak-spawn";

/// Turns generated content and channels into the fd numbers and host
/// paths bwrap is told to read them from. `--dry-run` counts and names,
/// a real run creates the fds and writes the files.
pub trait FdAllocator {
    /// Fd holding `content`, for an `--add-seccomp-fd`.
    fn data(&mut self, content: &[u8]) -> io::Result<OsString>;
    /// Host path of a file holding `content`, for a `--ro-bind` at
    /// `dest`. A file and not bwrap's own `--ro-bind-data`, which binds a
    /// file it has already unlinked: a sandbox that nests one of its own
    /// cannot re-bind such a destination (the nested bwrap resolves its
    /// source through `/proc/self/fd`, and an unlinked dentry there is
    /// ENOENT), which is what kept Steam's runtime from starting.
    fn file(&mut self, dest: &Path, content: &[u8]) -> io::Result<OsString>;
    /// Fd of the listening control socket `bubbler-init` serves.
    fn init_socket(&mut self) -> io::Result<OsString>;
    /// Fd a sidecar reports readiness on; the allocator keeps the other end.
    fn ready_pipe(&mut self) -> io::Result<OsString>;
    /// Fd of a listening socket bubbler bound for a sidecar to accept
    /// the application's connections on.
    fn listener(&mut self) -> io::Result<OsString>;
    /// Fd bwrap reports the sandbox pid on; the allocator keeps the read end.
    fn info_pipe(&mut self) -> io::Result<OsString>;
    /// Fd the sandbox is held at until released; the allocator keeps the
    /// write end.
    fn block_pipe(&mut self) -> io::Result<OsString>;
}

/// Ordered, phase-separated bubblewrap arguments.
///
/// Phases: 1 namespaces, 2 filesystem skeleton, 3 runtime dir,
/// 4 service binds, 4b masks, 5 environment, then `--` and the command.
// No `Default`: `baseline` is the only constructor, so a `BwrapArgs`
// without the baseline restrictions cannot be built.
#[derive(Debug, Clone)]
pub struct BwrapArgs {
    namespaces: Vec<Item>,
    skeleton: Vec<Item>,
    runtime_dir: Vec<Item>,
    binds: Vec<Item>,
    /// What [`BwrapArgs::mask_dir`] covers, emitted after every bind of
    /// phase 4: a mask is only a mask while nothing binds over it, and a
    /// grant whose binds are hoisted to the end of that phase — `gamepad`
    /// with its whole `/sys/devices` — would otherwise reopen what
    /// another grant masked underneath.
    masks: Vec<Item>,
    env: Vec<Item>,
    /// `--ctty` in the supervisor's own argv, not a bwrap flag.
    ctty: bool,
    /// The argv of the nested X server the supervisor starts on the
    /// first X connection, an optional window manager to start with it,
    /// and the node that asked for them. Also not bwrap flags.
    x11: Option<(Origin, Vec<OsString>, Option<OsString>)>,
    /// Tag every following push carries. Set once per phase of work by
    /// [`BwrapArgs::tag`], so the dozens of `ro_bind`/`setenv` call sites
    /// need no origin argument of their own.
    origin: Origin,
}

/// Whether one item is an operation `flag` leads, for the two phase-1
/// flags that must not be emitted twice. Only the head is compared: a
/// value further along could be anything, `--share-net` included.
fn holds(item: &Item, flag: &OsStr) -> bool {
    matches!(&item.kind, Kind::Args(a) if a.first().is_some_and(|p| p == flag))
}

/// One operation: the parts become one line of an explanation and stay
/// separate elements of the argv.
fn push<const N: usize>(v: &mut Vec<Item>, origin: Origin, parts: [&OsStr; N]) {
    v.push(Item {
        origin,
        kind: Kind::Args(parts.iter().map(|p| p.to_os_string()).collect()),
    });
}

/// Cap of the sandbox's `/tmp`, in bytes: 2 GiB. Without one a tmpfs may
/// grow to half of host RAM (`tmpfs(5)`), and a sandbox that fills it
/// takes the session's memory with it. Large enough for a browser's
/// download staging and a build's scratch files; `tmp size="…"` moves it.
pub const TMP_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Cap of every other tmpfs bubbler mounts, in bytes: 64 MiB. `/etc`,
/// `/var` and `/run` hold sockets, generated files and directories, not
/// data, and the runtime directory `--dir` creates inside `/run` shares
/// this cap because it lives on that tmpfs.
pub const TMPFS_SIZE: u64 = 64 * 1024 * 1024;

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
    "alsa",
    "drirc",
    "vulkan",
    "glvnd",
    "egl",
    "vdpau_wrapper.cfg",
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
    /// empty `/tmp` ([`TMP_SIZE`]) `/var` `/run` ([`TMPFS_SIZE`]),
    /// `/dev/ntsync` where the host has that
    /// node, a private home at [`SANDBOX_HOME`], an empty
    /// `$XDG_RUNTIME_DIR` at the same path as on the host and mode 0700
    /// (`--perms` applies to the next operation only, so it must
    /// immediately precede `--dir`), the private home as the working
    /// directory, an `--info-fd` the sandbox pid is reported on, cleared
    /// environment with only locale/terminal passthrough and the fixed
    /// user name. Services relax
    /// this explicitly. `--unshare-all` uses bwrap's `-try` semantics for
    /// the user namespace (`bwrap(1)`), so on a host without unprivileged
    /// user namespaces the sandbox may start without one; to be revisited.
    pub fn baseline(env: &Env, instance_home: &Path, host: &dyn Host) -> Self {
        let mut a = Self {
            namespaces: Vec::new(),
            skeleton: Vec::new(),
            runtime_dir: Vec::new(),
            binds: Vec::new(),
            masks: Vec::new(),
            env: Vec::new(),
            ctty: false,
            x11: None,
            origin: Origin::Baseline,
        };
        let o = OsStr::new;
        let b = Origin::Baseline;
        for flag in [
            o("--unshare-all"),
            o("--die-with-parent"),
            o("--new-session"),
        ] {
            push(&mut a.namespaces, b, [flag]);
        }
        push(&mut a.namespaces, b, [o("--hostname"), o("bubbler")]);
        // bwrap keeps the working directory it was started in when that
        // path also exists inside, so without --chdir a sandbox started
        // from, say, /tmp would run there instead of in the private home.
        push(&mut a.namespaces, b, [o("--chdir"), o(SANDBOX_HOME)]);
        // bwrap reports the sandbox pid here; the launcher needs it to
        // signal the supervisor, since bwrap forwards no signals itself.
        a.namespaces.push(Item {
            origin: b,
            kind: Kind::InfoFd,
        });

        push(&mut a.skeleton, b, [o("--ro-bind"), o("/usr"), o("/usr")]);
        for (target, link) in [
            ("usr/bin", "/bin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
            ("usr/bin", "/sbin"),
        ] {
            push(&mut a.skeleton, b, [o("--symlink"), o(target), o(link)]);
        }
        push(
            &mut a.skeleton,
            b,
            [o("--ro-bind-try"), o("/opt"), o("/opt")],
        );
        // The tmpfs has to precede the entry binds and the data files, or it
        // would hide them: bwrap applies filesystem operations in argv order.
        // `--size` applies to the next operation only (`bwrap(1)`), so
        // it stays part of the same operation as its `--tmpfs`.
        let tmpfs_size = OsString::from(TMPFS_SIZE.to_string());
        let tmp_size = OsString::from(TMP_SIZE.to_string());
        push(
            &mut a.skeleton,
            b,
            [o("--size"), tmpfs_size.as_os_str(), o("--tmpfs"), o("/etc")],
        );
        for name in ETC_ALLOWLIST {
            let p = Path::new("/etc").join(name);
            if host.file_type(&p).is_some() {
                push(
                    &mut a.skeleton,
                    b,
                    [o("--ro-bind"), p.as_os_str(), p.as_os_str()],
                );
            }
        }
        for (content, dest) in [
            (passwd_content(env.uid, env.gid), "/etc/passwd"),
            (group_content(env.gid), "/etc/group"),
        ] {
            a.skeleton.push(Item {
                origin: b,
                kind: Kind::Data {
                    content,
                    dest: dest.into(),
                },
            });
        }
        push(&mut a.skeleton, b, [o("--proc"), o("/proc")]);
        push(&mut a.skeleton, b, [o("--dev"), o("/dev")]);
        // Wine's and Proton's synchronisation primitive, which flatpak binds
        // with no permission of its own: the objects it makes belong to the
        // process that opened it, so there is no host state behind it. The
        // deliberate trade is that every sandbox reaches the ntsync driver's
        // ioctl surface (`drivers/misc/ntsync`, kernel 6.14 and later) rather
        // than Wine falling back to slow sync. The bind follows `--dev`,
        // which would otherwise hide it.
        let ntsync = Path::new("/dev/ntsync");
        if host.file_type(ntsync).is_some_and(|t| t.is_char_device()) {
            push(
                &mut a.skeleton,
                b,
                [o("--dev-bind"), ntsync.as_os_str(), ntsync.as_os_str()],
            );
        }
        for (size, dir) in [
            (tmp_size.as_os_str(), o("/tmp")),
            (tmpfs_size.as_os_str(), o("/var")),
            (tmpfs_size.as_os_str(), o("/run")),
        ] {
            push(&mut a.skeleton, b, [o("--size"), size, o("--tmpfs"), dir]);
        }
        push(
            &mut a.skeleton,
            b,
            [o("--bind"), instance_home.as_os_str(), o(SANDBOX_HOME)],
        );

        // `--perms` applies to the next operation only, so it stays part
        // of the same operation as the `--dir` it sets the mode of.
        push(
            &mut a.runtime_dir,
            b,
            [
                o("--perms"),
                o("0700"),
                o("--dir"),
                env.runtime_dir.as_os_str(),
            ],
        );

        push(&mut a.env, b, [o("--clearenv")]);
        for (k, v) in &env.passthrough {
            push(&mut a.env, b, [o("--setenv"), k, v]);
        }
        push(&mut a.env, b, [o("--setenv"), o("HOME"), o(SANDBOX_HOME)]);
        // Host binaries first: a file an app drops into its own
        // `~/.local/bin` (the Claude Code installer, XDG user binaries)
        // must never shadow `/usr/bin` for a bare command name.
        let path = format!("/usr/bin:{SANDBOX_HOME}/.local/bin");
        push(&mut a.env, b, [o("--setenv"), o("PATH"), o(&path)]);
        push(
            &mut a.env,
            b,
            [
                o("--setenv"),
                o("XDG_RUNTIME_DIR"),
                env.runtime_dir.as_os_str(),
            ],
        );
        push(&mut a.env, b, [o("--setenv"), o("USER"), o("bubbler")]);
        push(&mut a.env, b, [o("--setenv"), o("LOGNAME"), o("bubbler")]);
        a
    }

    /// What every sidecar sandbox starts from: the same namespace
    /// restrictions as [`BwrapArgs::baseline`], a read-only `/usr` and a
    /// minimal `/etc` ([`PROXY_ETC`]) so the sidecar binary can start,
    /// no home and no runtime dir of its own. The environment is
    /// cleared; whatever a sidecar needs to reach is an argument of it.
    ///
    /// Nothing of the session is here. Each sidecar adds the one or two
    /// paths it serves, and nothing else: the instance's runtime
    /// directory in particular holds the supervisor's control socket,
    /// and a process that reaches it can run commands inside the app.
    fn sidecar_baseline(host: &dyn Host) -> Self {
        let mut a = Self {
            namespaces: Vec::new(),
            skeleton: Vec::new(),
            runtime_dir: Vec::new(),
            binds: Vec::new(),
            masks: Vec::new(),
            env: Vec::new(),
            ctty: false,
            x11: None,
            origin: Origin::Baseline,
        };
        let o = OsStr::new;
        let b = Origin::Baseline;
        for flag in [
            o("--unshare-all"),
            o("--die-with-parent"),
            o("--new-session"),
        ] {
            push(&mut a.namespaces, b, [flag]);
        }
        push(&mut a.skeleton, b, [o("--ro-bind"), o("/usr"), o("/usr")]);
        for (target, link) in [
            ("usr/bin", "/bin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
            ("usr/bin", "/sbin"),
        ] {
            push(&mut a.skeleton, b, [o("--symlink"), o(target), o(link)]);
        }
        let tmpfs_size = OsString::from(TMPFS_SIZE.to_string());
        push(
            &mut a.skeleton,
            b,
            [o("--size"), tmpfs_size.as_os_str(), o("--tmpfs"), o("/etc")],
        );
        for name in PROXY_ETC {
            let p = Path::new("/etc").join(name);
            if host.file_type(&p).is_some() {
                push(
                    &mut a.skeleton,
                    b,
                    [o("--ro-bind"), p.as_os_str(), p.as_os_str()],
                );
            }
        }
        push(&mut a.skeleton, b, [o("--proc"), o("/proc")]);
        push(&mut a.skeleton, b, [o("--dev"), o("/dev")]);
        push(
            &mut a.skeleton,
            b,
            [o("--size"), tmpfs_size.as_os_str(), o("--tmpfs"), o("/tmp")],
        );
        push(&mut a.env, b, [o("--clearenv")]);
        a
    }

    /// The sandbox the D-Bus proxy sidecar runs in: the sidecar baseline
    /// plus the host socket of each bus it was asked for, read-only, and
    /// `socket_dir` read-write, which is where it creates the filtered
    /// sockets. The addresses are arguments, not environment.
    ///
    /// `socket_dir` is a directory of its own, never the instance's
    /// runtime directory: that one holds the supervisor's control socket,
    /// and a process that reaches it can run commands inside the app.
    pub fn proxy_baseline(
        host_bus: Option<&Path>,
        host_system_bus: Option<&Path>,
        host_a11y_bus: Option<&Path>,
        socket_dir: &Path,
        host: &dyn Host,
    ) -> Self {
        let mut a = Self::sidecar_baseline(host);
        let o = OsStr::new;
        let b = Origin::Baseline;
        // Only the buses this proxy was asked for: a socket bound here
        // that no section names is a host bus the proxy could still reach.
        for bus in [host_bus, host_system_bus, host_a11y_bus]
            .into_iter()
            .flatten()
        {
            push(
                &mut a.skeleton,
                b,
                [o("--ro-bind"), bus.as_os_str(), bus.as_os_str()],
            );
        }
        // Read-write because the proxy has to create its socket here, and
        // nothing else of the session is in this directory.
        push(
            &mut a.skeleton,
            b,
            [o("--bind"), socket_dir.as_os_str(), socket_dir.as_os_str()],
        );
        a
    }

    /// The sandbox the PipeWire context sidecar runs in: the sidecar
    /// baseline, the session's own `pipewire-0` read-only at its own
    /// path, and `dir` as the whole of `/tmp`.
    ///
    /// That socket is the only thing of the session in here — the
    /// manager socket beside it never is. `/tmp` is bound rather than
    /// left a tmpfs because `pw-container` creates its socket at a
    /// `/tmp` path it chooses itself and takes from no environment
    /// variable, so binding that directory is how bubbler decides where
    /// the socket lands; `dir` is the instance's own, holds nothing but
    /// that socket, and is the only thing this sidecar can write.
    pub fn pw_context_baseline(host_socket: &Path, dir: &Path, host: &dyn Host) -> Self {
        let mut a = Self::sidecar_baseline(host);
        let o = OsStr::new;
        let b = Origin::Baseline;
        push(
            &mut a.skeleton,
            b,
            [
                o("--ro-bind"),
                host_socket.as_os_str(),
                host_socket.as_os_str(),
            ],
        );
        // After the baseline's own `--tmpfs /tmp`, which this replaces:
        // bwrap applies filesystem operations in the order given.
        push(
            &mut a.skeleton,
            b,
            [o("--bind"), dir.as_os_str(), o("/tmp")],
        );
        a
    }

    /// The sandbox the private PulseAudio server of a `pulseaudio` grant
    /// runs in: the sidecar baseline, this run's own context socket
    /// read-only at `inside`, and `dir` as the whole of `/tmp`.
    ///
    /// The session's own `pipewire-0` is not in here at all — this
    /// server is a client of the instance's security context like any
    /// other, so what it may do is what the session manager grants the
    /// instance. `inside` is a path of bubbler's choosing rather than
    /// the socket's own: the sandbox has no runtime directory of the
    /// session's to put it in. `/tmp` is bound for the same reason it is
    /// in [`BwrapArgs::pw_context_baseline`] — it is where the socket
    /// this server listens on lands, and `dir` is the instance's own.
    pub fn pw_pulse_baseline(socket: &Path, inside: &Path, dir: &Path, host: &dyn Host) -> Self {
        let mut a = Self::sidecar_baseline(host);
        let o = OsStr::new;
        let b = Origin::Baseline;
        push(
            &mut a.skeleton,
            b,
            [o("--ro-bind"), socket.as_os_str(), inside.as_os_str()],
        );
        // After the baseline's own `--tmpfs /tmp`, which this replaces:
        // bwrap applies filesystem operations in the order given.
        push(
            &mut a.skeleton,
            b,
            [o("--bind"), dir.as_os_str(), o("/tmp")],
        );
        a
    }

    /// The sandbox the Wayland proxy sidecar runs in: the sidecar
    /// baseline plus `upstream`, the compositor socket it forwards the
    /// application's connection to, read-only and at its own path.
    ///
    /// That socket is the only thing of the session in here. The socket
    /// the proxy accepts the application on is not bound at all: it is
    /// handed over as a descriptor, so the proxy can neither reach the
    /// directory it lives in nor create anything beside it.
    pub fn wl_proxy_baseline(upstream: &Path, host: &dyn Host) -> Self {
        let mut a = Self::sidecar_baseline(host);
        push(
            &mut a.skeleton,
            Origin::Baseline,
            [
                OsStr::new("--ro-bind"),
                upstream.as_os_str(),
                upstream.as_os_str(),
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
        if !self.namespaces.iter().any(|i| holds(i, flag)) {
            self.namespaces.insert(
                1,
                Item {
                    origin: self.origin,
                    kind: Kind::Args(vec![flag.to_os_string()]),
                },
            );
        }
    }

    /// Start the command in `dir` instead of the private home. Replaces
    /// the value of the baseline `--chdir`, so the flag is still emitted
    /// once and in phase 1; the group it explains under stays the
    /// baseline's.
    ///
    /// # Panics
    ///
    /// If the arguments hold no `--chdir`. Only [`BwrapArgs::baseline`]
    /// builds the sandbox this is called on, and it always emits one.
    pub fn chdir(&mut self, dir: &Path) {
        let flag = OsStr::new("--chdir");
        // Silently leaving the working directory where it was would put
        // the sandbox in whatever directory bwrap inherited — a host
        // path — instead of in the share the caller asked for.
        let args = self
            .namespaces
            .iter_mut()
            .find_map(|i| match &mut i.kind {
                Kind::Args(a) if a.first().is_some_and(|p| p == flag) => Some(a),
                _ => None,
            })
            .expect("the baseline emits --chdir once, in phase 1");
        args.truncate(1);
        args.push(dir.as_os_str().to_owned());
    }

    /// Cap the sandbox's `/tmp` at `bytes` instead of [`TMP_SIZE`], and
    /// attribute the operation to the `tmp` node that asked for it.
    /// The value is replaced where it stands, so `/tmp` is still mounted
    /// once and still ahead of anything bound under it.
    ///
    /// # Panics
    ///
    /// If the arguments hold no `--size … --tmpfs /tmp`. Only
    /// [`BwrapArgs::baseline`] builds the sandbox this is called on, and
    /// it always emits one.
    pub fn tmp_size(&mut self, bytes: u64) {
        let item = self
            .skeleton
            .iter_mut()
            .find(|i| {
                matches!(&i.kind, Kind::Args(a)
                    if a.first().is_some_and(|p| p == OsStr::new("--size"))
                        && a.last().is_some_and(|p| p == OsStr::new("/tmp")))
            })
            .expect("the baseline emits `--size … --tmpfs /tmp` once, in phase 2");
        item.origin = self.origin;
        let Kind::Args(args) = &mut item.kind else {
            unreachable!("the item was found by matching on its arguments");
        };
        args[1] = OsString::from(bytes.to_string());
    }

    /// Replace the `/etc` tmpfs and its allowlist with one read-only
    /// bind of the host's whole `/etc` (`etc "host"`, phase 2), and
    /// attribute the bind and the synthetic binds that follow it to the
    /// `etc` node that asked for it. The synthetic `passwd`/`group`
    /// binds are left standing where they are, after the replacement,
    /// and joined by the same synthetic content over `passwd`/`group`'s
    /// `-`/`+` backups and an empty file over `subuid`/`subgid` — each
    /// only where `host` has the mountpoint for it — because those are
    /// the four world-readable files under the allowlist mode's reach
    /// that still name the host account otherwise: the host username
    /// stays hidden whichever mode `/etc` is in.
    ///
    /// # Panics
    ///
    /// If the arguments hold no `--size … --tmpfs /etc` followed by two
    /// data binds. Only [`BwrapArgs::baseline`] builds the sandbox this
    /// is called on, and it always emits both.
    pub fn bind_host_etc(&mut self, host: &dyn Host) {
        let start = self
            .skeleton
            .iter()
            .position(|i| {
                matches!(&i.kind, Kind::Args(a)
                    if a.first().is_some_and(|p| p == OsStr::new("--size"))
                        && a.last().is_some_and(|p| p == OsStr::new("/etc")))
            })
            .expect("the baseline emits `--size … --tmpfs /etc` once, in phase 2");
        let end = self.skeleton[start..]
            .iter()
            .position(|i| matches!(i.kind, Kind::Data { .. }))
            .map(|n| start + n)
            .expect("the baseline emits the synthetic passwd/group binds after the /etc tmpfs");
        for item in &mut self.skeleton[end..end + 2] {
            item.origin = self.origin;
        }
        let (
            Kind::Data {
                content: passwd, ..
            },
            Kind::Data { content: group, .. },
        ) = (&self.skeleton[end].kind, &self.skeleton[end + 1].kind)
        else {
            unreachable!("end holds the synthetic passwd/group binds, matched above");
        };
        let (passwd, group) = (passwd.clone(), group.clone());
        let mut extra = Vec::new();
        for (content, dest) in [
            (passwd.clone(), "/etc/passwd-"),
            (passwd, "/etc/passwd+"),
            (group.clone(), "/etc/group-"),
            (group, "/etc/group+"),
        ] {
            if host.file_type(Path::new(dest)).is_some() {
                extra.push(Item {
                    origin: self.origin,
                    kind: Kind::Data {
                        content,
                        dest: dest.into(),
                    },
                });
            }
        }
        // subuid/subgid carry no per-sandbox identity to synthesise, only
        // the host account to hide, so an empty file is enough to cover
        // the mountpoint.
        for dest in ["/etc/subuid", "/etc/subgid"] {
            if host.file_type(Path::new(dest)).is_some() {
                extra.push(Item {
                    origin: self.origin,
                    kind: Kind::Data {
                        content: Vec::new(),
                        dest: dest.into(),
                    },
                });
            }
        }
        self.skeleton.splice(end + 2..end + 2, extra);
        self.skeleton.splice(
            start..end,
            [Item {
                origin: self.origin,
                kind: Kind::Args(vec![
                    OsString::from("--ro-bind"),
                    OsString::from("/etc"),
                    OsString::from("/etc"),
                ]),
            }],
        );
    }

    /// Tag every argument pushed from here on with `origin`. The caller
    /// stamps it once per phase of work; nothing else has to know.
    pub fn tag(&mut self, origin: Origin) {
        self.origin = origin;
    }

    /// The tag in force, for a service that hands part of its work to
    /// another node's grant and has to put its own back afterwards.
    pub fn origin(&self) -> Origin {
        self.origin
    }

    /// Forbid nested user namespaces (`bwrap(1)` `--disable-userns`,
    /// phase 1). Idempotent, and it emits `--unshare-user` with the flag:
    /// bwrap refuses `--disable-userns` without it, and `--unshare-all`
    /// does not count, since that asks for the user namespace only if the
    /// host has unprivileged ones.
    pub fn disable_userns(&mut self) {
        let flags = [OsStr::new("--unshare-user"), OsStr::new("--disable-userns")];
        // The pair is one operation, and nothing else emits its head, so
        // `--unshare-user` there is what says it has already been added.
        if self.namespaces.iter().any(|i| holds(i, flags[0])) {
            return;
        }
        push(&mut self.namespaces, self.origin, flags);
    }

    /// Hold the sandbox at startup until the launcher lets it go
    /// (`bwrap(1)` `--block-fd`, phase 1). Only a sandbox whose identity
    /// bubbler still has to publish waits, and it waits before it execs.
    // After `--info-fd`, which bwrap writes before it reads this one: the
    // identity is built out of that document.
    pub fn block_until_released(&mut self) {
        self.namespaces.push(Item {
            origin: self.origin,
            kind: Kind::BlockFd,
        });
    }

    /// Load the compiled seccomp program into the sandbox (`bwrap(1)`
    /// `--add-seccomp-fd`, phase 1). One filter answers for every
    /// architecture and every error, so a sandbox needs exactly one call.
    // The config refuses `deny "prctl"` because glibc and Chromium call
    // it for themselves — thread names, `PR_SET_NO_NEW_PRIVS`, the
    // renderer's own seccomp — so denying it breaks the sandbox from the
    // inside. Placed after `--info-fd` and `--block-fd` only for
    // readability; bwrap orders seccomp fds among themselves, not against
    // other flags.
    pub fn add_seccomp(&mut self, program: Vec<u8>, arches: &'static str) {
        self.namespaces.push(Item {
            origin: self.origin,
            kind: Kind::Seccomp { program, arches },
        });
    }

    /// Read-only bind of a host path (phase 4).
    pub fn ro_bind(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            self.origin,
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
            self.origin,
            [OsStr::new("--dev-bind"), src.as_os_str(), dst.as_os_str()],
        );
    }

    /// Like [`BwrapArgs::dev_bind`] but skipped by bwrap when the source
    /// has gone (`bwrap(1)` `--dev-bind-try`). For nodes enumerated while
    /// the argv is built: hardware unplugged in the moment between that
    /// and the exec must not fail the launch.
    pub fn dev_bind_try(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            self.origin,
            [
                OsStr::new("--dev-bind-try"),
                src.as_os_str(),
                dst.as_os_str(),
            ],
        );
    }

    /// Symlink inside the sandbox (phase 4). Used to rebuild sysfs paths
    /// (e.g. `/sys/class/drm` from its constituent symlinks) so render-only
    /// `dri` services can hide GPU card sysfs directories without breaking
    /// device discovery.
    pub fn symlink(&mut self, target: &Path, link: &Path) {
        push(
            &mut self.binds,
            self.origin,
            [
                OsStr::new("--symlink"),
                target.as_os_str(),
                link.as_os_str(),
            ],
        );
    }

    /// Mask a directory with an empty read-only tmpfs. Used to hide GPU
    /// card sysfs directories without breaking device discovery when
    /// render-only `dri` is granted.
    ///
    /// Emitted after every bind of phase 4, whichever grant asked for it
    /// and wherever that grant sits in the file: bind order is
    /// semantics, and a mask a later bind covers is no mask at all.
    pub fn mask_dir(&mut self, dir: &Path) {
        push(
            &mut self.masks,
            self.origin,
            [
                OsStr::new("--size"),
                OsStr::new("4096"),
                OsStr::new("--tmpfs"),
                dir.as_os_str(),
            ],
        );
        push(
            &mut self.masks,
            self.origin,
            [OsStr::new("--remount-ro"), dir.as_os_str()],
        );
    }

    /// Read-write bind of a host path (phase 4).
    pub fn bind(&mut self, src: &Path, dst: &Path) {
        push(
            &mut self.binds,
            self.origin,
            [OsStr::new("--bind"), src.as_os_str(), dst.as_os_str()],
        );
    }

    /// Bind the host `bubbler-init` binary read-only at [`INIT_INSIDE`]
    /// (phase 4), which is the program every sandbox actually starts.
    pub fn bind_init(&mut self, host_path: &Path) {
        self.ro_bind(host_path, Path::new(INIT_INSIDE));
    }

    /// Bind the same `bubbler-init` binary a second time, as
    /// [`FLATPAK_SPAWN_INSIDE`] (phase 4), which is what an image loader
    /// in a sandbox carrying `/.flatpak-info` looks for.
    ///
    /// `/usr` is a read-only bind of the host's, and bwrap cannot create
    /// a mount point in it ("Can't create file at
    /// /usr/bin/flatpak-spawn: Read-only file system"), so `/usr/bin`
    /// becomes an overlay of itself with the writes going to an
    /// invisible tmpfs — and then read-only again, since an overlay left
    /// writable is a `/usr/bin` the sandbox can replace program by
    /// program. Needs unprivileged overlayfs (Linux 5.11 or newer);
    /// where the kernel refuses the mount bwrap says so and the launch
    /// fails.
    pub fn flatpak_spawn_shim(&mut self, host_path: &Path) {
        let o = OsStr::new;
        let bin = o("/usr/bin");
        // `--overlay-src` does nothing on its own and applies to the
        // next overlay option only (`bwrap(1)`), so it stays part of the
        // same operation as its `--tmp-overlay`.
        self.binds.push(Item {
            origin: self.origin,
            kind: Kind::Noted {
                args: vec![
                    o("--overlay-src").into(),
                    bin.into(),
                    o("--tmp-overlay").into(),
                    bin.into(),
                ],
                note: "flatpak-spawn shim (glycin, gdk-pixbuf)".to_owned(),
            },
        });
        self.ro_bind(host_path, Path::new(FLATPAK_SPAWN_INSIDE));
        push(&mut self.binds, self.origin, [o("--remount-ro"), bin]);
    }

    /// Bind `content` read-only at `dest` (phase 4). The bytes are handed
    /// to the allocator in `finish`, which writes them to a host file.
    pub fn ro_bind_data(&mut self, content: Vec<u8>, dest: &Path) {
        self.binds.push(Item {
            origin: self.origin,
            kind: Kind::Data {
                content,
                dest: dest.to_path_buf(),
            },
        });
    }

    /// Let the command take its stdin as a controlling terminal: `--ctty`
    /// for the supervisor. Only for a pty bubbler allocated and handed to
    /// this sandbox, never for a terminal it inherited from the user.
    pub fn ctty(&mut self) {
        self.ctty = true;
    }

    /// Have the supervisor own the display socket and start `argv` on
    /// the first client that connects, with `wm` alongside it:
    /// `--x11 <argv…> --` and `--wm <program>` in `bubbler-init`'s own
    /// arguments, and only there — a sandbox has one display server at
    /// most, and a sidecar has none.
    pub fn x11_server(&mut self, argv: Vec<OsString>, wm: Option<OsString>) {
        // Two servers in one sandbox is a bug in the caller, not a
        // configuration a user can write: the second would replace the
        // first silently, so the first is kept.
        debug_assert!(self.x11.is_none(), "a second X server argv");
        self.x11.get_or_insert((self.origin, argv, wm));
    }

    /// Set a variable inside the sandbox (phase 5, after `--clearenv`).
    pub fn setenv(&mut self, key: &OsStr, value: &OsStr) {
        push(
            &mut self.env,
            self.origin,
            [OsStr::new("--setenv"), key, value],
        );
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
        Ok(flatten(self.finish_explained(command, alloc)?))
    }

    /// [`BwrapArgs::finish`] with every operation kept apart and tagged
    /// with what produced it. Flattening the result is the argv again,
    /// element for element.
    pub fn finish_explained(
        mut self,
        command: &[OsString],
        alloc: &mut dyn FdAllocator,
    ) -> Result<Vec<Explained>, LaunchError> {
        let ctty = self.ctty;
        let x11 = self.x11.take();
        let mut out = self.emit(alloc)?;
        let socket = alloc.init_socket().map_err(LaunchError::Data)?;
        out.push(Explained {
            origin: Origin::Init,
            args: vec![
                OsString::from("--"),
                INIT_INSIDE.into(),
                "--socket-fd".into(),
                socket,
            ],
            note: Some("socket: the exec channel bubbler-init serves".to_owned()),
        });
        if ctty {
            out.push(Explained {
                origin: Origin::Ctty,
                args: vec!["--ctty".into()],
                note: None,
            });
        }
        if let Some((origin, argv, wm)) = x11 {
            let mut args = vec![OsString::from("--x11")];
            args.extend(argv);
            // The supervisor reads the server's argv up to this `--`; the
            // window manager and the command's own argv follow it.
            args.push(OsString::from("--"));
            out.push(Explained {
                origin,
                args,
                note: Some(
                    "nested Xwayland, started by bubbler-init on the first X connection; \
                     -listenfd is added at run time"
                        .to_owned(),
                ),
            });
            if let Some(wm) = wm {
                out.push(Explained {
                    origin,
                    args: vec![OsString::from("--wm"), wm],
                    note: Some(
                        "window manager inside the sandbox, started with the server".to_owned(),
                    ),
                });
            }
        }
        let mut args = vec![OsString::from("--")];
        args.extend_from_slice(command);
        out.push(Explained {
            origin: Origin::Command,
            args,
            note: None,
        });
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
        let mut out = flatten(self.emit(alloc)?);
        out.push(OsString::from("--"));
        out.extend_from_slice(command);
        Ok(out)
    }

    /// [`BwrapArgs::finish_plain`] with every operation kept apart and
    /// tagged, `command` carrying an origin per element: a sidecar's argv
    /// is its rule list, and each rule belongs to the node that asked for
    /// it. Flattening the arguments is [`BwrapArgs::finish_plain`] again.
    pub fn finish_plain_explained(
        self,
        command: &[(OsString, Origin)],
        alloc: &mut dyn FdAllocator,
    ) -> Result<Vec<Explained>, LaunchError> {
        let mut out = self.emit(alloc)?;
        let separator = (OsString::from("--"), Origin::Command);
        for (arg, origin) in std::iter::once(&separator).chain(command) {
            out.push(Explained {
                origin: *origin,
                args: vec![arg.clone()],
                note: None,
            });
        }
        Ok(out)
    }

    fn emit(self, alloc: &mut dyn FdAllocator) -> Result<Vec<Explained>, LaunchError> {
        let mut out = Vec::new();
        for item in [
            self.namespaces,
            self.skeleton,
            self.runtime_dir,
            self.binds,
            self.masks,
            self.env,
        ]
        .into_iter()
        .flatten()
        {
            let (args, note) = match item.kind {
                Kind::Args(a) => (a, None),
                Kind::Noted { args, note } => (args, Some(note)),
                Kind::Data { content, dest } => {
                    let src = alloc.file(&dest, &content).map_err(LaunchError::Data)?;
                    (
                        vec!["--ro-bind".into(), src, dest.into_os_string()],
                        Some(format!("generated file, {} bytes", content.len())),
                    )
                }
                Kind::InfoFd => {
                    let fd = alloc.info_pipe().map_err(LaunchError::Data)?;
                    (
                        vec!["--info-fd".into(), fd],
                        Some("pipe: bwrap reports the sandbox pid on it".to_owned()),
                    )
                }
                Kind::BlockFd => {
                    let fd = alloc.block_pipe().map_err(LaunchError::Data)?;
                    (
                        vec!["--block-fd".into(), fd],
                        Some("pipe: the sandbox waits on it until bubbler lets it go".to_owned()),
                    )
                }
                Kind::Seccomp { program, arches } => {
                    let fd = alloc.data(&program).map_err(LaunchError::Data)?;
                    (
                        vec!["--add-seccomp-fd".into(), fd],
                        Some(format!("filter, {} bytes, {arches}", program.len())),
                    )
                }
            };
            out.push(Explained {
                origin: item.origin,
                args,
                note,
            });
        }
        Ok(out)
    }
}

/// The argv again: the operations concatenated, element for element.
/// Public so a caller that had to look at the operations — the
/// destination sweep does — can still hand bwrap exactly what
/// [`BwrapArgs::finish`] would have.
pub fn flatten(items: Vec<Explained>) -> Vec<OsString> {
    items.into_iter().flat_map(|i| i.args).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use std::path::Path;

    fn env() -> Env {
        Env {
            home: "/home/user".into(),
            data_home: "/home/user/.local/share".into(),
            config_home: "/home/user/.config".into(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: Some("wayland-1".into()),
            display: Some(":0".into()),
            xauthority: None,
            passthrough: vec![("TERM".into(), "foot".into())],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            at_spi_bus_address: None,
            dbus_log: false,
            net_proxy_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
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

    /// Where a run would write its generated files, so an argv assertion
    /// names the same path a dry run of a real instance would.
    const DATA_DIR: &str = "/run/user/1000/bubbler/i";

    fn data_path(dest: &Path) -> OsString {
        Path::new(DATA_DIR)
            .join(crate::launcher::data_name("", dest))
            .into_os_string()
    }

    impl FdAllocator for Counter {
        fn data(&mut self, _content: &[u8]) -> io::Result<OsString> {
            self.bump()
        }
        fn file(&mut self, dest: &Path, _content: &[u8]) -> io::Result<OsString> {
            Ok(data_path(dest))
        }
        fn init_socket(&mut self) -> io::Result<OsString> {
            self.bump()
        }
        fn ready_pipe(&mut self) -> io::Result<OsString> {
            self.bump()
        }
        fn listener(&mut self) -> io::Result<OsString> {
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
        fn file(&mut self, dest: &Path, content: &[u8]) -> io::Result<OsString> {
            self.seen.push(content.to_vec());
            Ok(data_path(dest))
        }
        fn init_socket(&mut self) -> io::Result<OsString> {
            self.next.bump()
        }
        fn ready_pipe(&mut self) -> io::Result<OsString> {
            self.next.bump()
        }
        fn listener(&mut self) -> io::Result<OsString> {
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
        fn file(&mut self, _dest: &Path, _content: &[u8]) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
        }
        fn init_socket(&mut self) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
        }
        fn ready_pipe(&mut self) -> io::Result<OsString> {
            Err(io::Error::other("nope"))
        }
        fn listener(&mut self) -> io::Result<OsString> {
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
            Path::new("/home/user/.local/share/bubbler/instances/t/home"),
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
                "--size",
                "67108864",
                "--tmpfs",
                "/etc",
                "--ro-bind",
                "/run/user/1000/bubbler/i/etc-passwd",
                "/etc/passwd",
                "--ro-bind",
                "/run/user/1000/bubbler/i/etc-group",
                "/etc/group",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                "2147483648",
                "--tmpfs",
                "/tmp",
                "--size",
                "67108864",
                "--tmpfs",
                "/var",
                "--size",
                "67108864",
                "--tmpfs",
                "/run",
                "--bind",
                "/home/user/.local/share/bubbler/instances/t/home",
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
                "/usr/bin:/home/bubbler/.local/bin",
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
                "4",
                "--",
                "/usr/bin/true",
            ]
        );
    }

    #[test]
    fn ntsync_is_bound_only_where_the_host_has_the_node() {
        let host = FakeHost::default().with("/dev/ntsync", crate::host::fake::char_type());
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &host)
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        let dev = s
            .windows(2)
            .position(|w| w == ["--dev", "/dev"])
            .expect("the baseline always mounts /dev");
        assert_eq!(
            &s[dev + 2..dev + 5],
            &["--dev-bind", "/dev/ntsync", "/dev/ntsync"],
            "the bind has to follow the --dev that would otherwise hide it: {s:?}"
        );

        let wrong_type = FakeHost::default().with("/dev/ntsync", crate::host::fake::types().0);
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &wrong_type)
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        assert!(!strs(&argv).contains(&"/dev/ntsync"));
    }

    #[test]
    fn the_proxy_sandbox_gets_no_ntsync() {
        let host = FakeHost::default().with("/dev/ntsync", crate::host::fake::char_type());
        let argv = BwrapArgs::proxy_baseline(
            Some(Path::new("/run/user/1000/bus")),
            None,
            None,
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &host,
        )
        .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
        .unwrap();
        assert!(!strs(&argv).contains(&"/dev/ntsync"));
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
            Some(Path::new("/run/user/1000/bus")),
            None,
            None,
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
                "--size",
                "67108864",
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
                "--size",
                "67108864",
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
        // Without the section there is no bind of the host system bus,
        // and with it the two sockets are bound in argv order.
        assert!(!argv.iter().any(|a| a == "/run/dbus/system_bus_socket"));
        let both = BwrapArgs::proxy_baseline(
            Some(Path::new("/run/user/1000/bus")),
            Some(Path::new("/run/dbus/system_bus_socket")),
            None,
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &host,
        )
        .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
        .unwrap();
        assert!(
            strs(&both).windows(6).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/bus",
                    "/run/user/1000/bus",
                    "--ro-bind",
                    "/run/dbus/system_bus_socket",
                    "/run/dbus/system_bus_socket",
                ]),
            "{:?}",
            strs(&both)
        );
        // A system-only proxy never sees the session bus.
        let system_only = BwrapArgs::proxy_baseline(
            None,
            Some(Path::new("/run/dbus/system_bus_socket")),
            None,
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &host,
        )
        .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
        .unwrap();
        assert!(!system_only.iter().any(|a| a == "/run/user/1000/bus"));
    }

    /// Without a cap a tmpfs grows to half of host RAM, and a sandbox
    /// that fills `/tmp` takes the session down with it. Each `--size`
    /// has to sit directly in front of the `--tmpfs` it applies to:
    /// bwrap(1) says the option affects the next tmpfs only.
    #[test]
    fn every_tmpfs_carries_its_own_size() {
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        for (size, dir) in [
            ("67108864", "/etc"),
            ("2147483648", "/tmp"),
            ("67108864", "/var"),
            ("67108864", "/run"),
        ] {
            assert!(
                s.windows(4).any(|w| w == ["--size", size, "--tmpfs", dir]),
                "{dir} has no cap: {s:?}"
            );
        }
        assert_eq!(
            s.iter().filter(|a| **a == "--tmpfs").count(),
            s.iter().filter(|a| **a == "--size").count(),
            "a tmpfs without a size: {s:?}"
        );

        // The sidecars get the same 64 MiB on both of theirs.
        let argv = BwrapArgs::proxy_baseline(
            Some(Path::new("/run/user/1000/bus")),
            None,
            None,
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &FakeHost::default(),
        )
        .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
        .unwrap();
        let s = strs(&argv);
        for dir in ["/etc", "/tmp"] {
            assert!(
                s.windows(4)
                    .any(|w| w == ["--size", "67108864", "--tmpfs", dir]),
                "{dir} has no cap: {s:?}"
            );
        }
    }

    /// The accessibility bus is one more host socket the proxy connects
    /// to, bound read-only like the other two and only where the plan
    /// holds that bus: a socket bound for a bus no section names is a
    /// host bus the proxy could still reach.
    #[test]
    fn the_a11y_host_socket_is_bound_only_where_that_bus_is_proxied() {
        let argv = BwrapArgs::proxy_baseline(
            Some(Path::new("/run/user/1000/bus")),
            None,
            Some(Path::new("/run/user/1000/at-spi/bus_0")),
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &FakeHost::default(),
        )
        .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
        .unwrap();
        let s = strs(&argv);
        assert!(
            s.windows(6).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/bus",
                    "/run/user/1000/bus",
                    "--ro-bind",
                    "/run/user/1000/at-spi/bus_0",
                    "/run/user/1000/at-spi/bus_0",
                ]),
            "{s:?}"
        );
        // The socket the proxy serves for it is created in the one
        // writable bind, not bound in from the host.
        assert!(!s.iter().any(|a| a.ends_with("/dbus/a11y")), "{s:?}");
        let without = BwrapArgs::proxy_baseline(
            Some(Path::new("/run/user/1000/bus")),
            None,
            None,
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &FakeHost::default(),
        )
        .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
        .unwrap();
        assert!(
            !strs(&without).iter().any(|a| a.contains("at-spi")),
            "{:?}",
            strs(&without)
        );
    }

    #[test]
    fn proxy_sandbox_takes_the_flatpak_info_data_file() {
        let mut args = BwrapArgs::proxy_baseline(
            Some(Path::new("/run/user/1000/bus")),
            None,
            None,
            Path::new("/run/user/1000/bubbler/t/dbus"),
            &FakeHost::default(),
        );
        args.ro_bind_data(b"[Application]\n".to_vec(), Path::new("/.flatpak-info"));
        let argv = args
            .finish_plain(&["xdg-dbus-proxy".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        assert!(
            s.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/bubbler/i/.flatpak-info",
                    "/.flatpak-info"
                ]),
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
            .with("/etc/vdpau_wrapper.cfg", f)
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
        assert!(s.windows(3).any(|w| w
            == [
                "--ro-bind",
                "/etc/vdpau_wrapper.cfg",
                "/etc/vdpau_wrapper.cfg"
            ]));
        assert!(!s.contains(&"/etc/shadow"));
        assert!(!s.windows(3).any(|w| w == ["--ro-bind", "/etc", "/etc"]));
        assert!(pos("/etc/hosts") > pos("--tmpfs"));
        assert!(s.windows(3).any(|w| w
            == [
                "--ro-bind",
                "/run/user/1000/bubbler/i/etc-passwd",
                "/etc/passwd"
            ]));
        assert!(s.windows(3).any(|w| w
            == [
                "--ro-bind",
                "/run/user/1000/bubbler/i/etc-group",
                "/etc/group"
            ]));
        assert!(pos("/etc/passwd") < pos("--proc"));
        assert!(s.windows(3).any(|w| w == ["--setenv", "USER", "bubbler"]));
        assert!(
            s.windows(3)
                .any(|w| w == ["--setenv", "LOGNAME", "bubbler"])
        );
    }

    /// `etc "host"` replaces the tmpfs and its allowlist with one bind
    /// of the host's whole `/etc`; the synthetic `passwd`/`group` binds
    /// still follow it, in the same order, so the host username stays
    /// hidden. So do the shadow-suite backups and `subuid`/`subgid`,
    /// which name the host account the same way `passwd`/`group` do and
    /// are not on the allowlist — but only the ones the host actually
    /// has: `/etc/passwd+` here does not exist, and gets no bind of its
    /// own to point nowhere.
    #[test]
    fn binding_the_hosts_etc_replaces_the_tmpfs_and_allowlist_with_one_bind() {
        let (f, d, _) = crate::host::fake::types();
        let host = FakeHost::default()
            .with("/etc/hosts", f)
            .with("/etc/fonts", d)
            .with("/etc/passwd-", f)
            .with("/etc/group-", f)
            .with("/etc/subuid", f)
            .with("/etc/subgid", f);
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &host);
        args.tag(Origin::Etc);
        args.bind_host_etc(&host);
        let argv = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&argv);
        let pos = |x: &str| s.iter().position(|a| *a == x).unwrap();
        assert!(
            s.windows(3).any(|w| w == ["--ro-bind", "/etc", "/etc"]),
            "{s:?}"
        );
        assert!(!s.windows(2).any(|w| w == ["--tmpfs", "/etc"]), "{s:?}");
        assert!(!s.contains(&"/etc/hosts"), "{s:?}");
        assert!(!s.contains(&"/etc/fonts"), "{s:?}");
        assert!(
            s.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/bubbler/i/etc-passwd",
                    "/etc/passwd"
                ]),
            "{s:?}"
        );
        assert!(
            s.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/bubbler/i/etc-group",
                    "/etc/group"
                ]),
            "{s:?}"
        );
        for (src, dest) in [
            ("etc-passwd-", "/etc/passwd-"),
            ("etc-group-", "/etc/group-"),
            ("etc-subuid", "/etc/subuid"),
            ("etc-subgid", "/etc/subgid"),
        ] {
            assert!(
                s.windows(3).any(|w| w
                    == [
                        "--ro-bind",
                        format!("/run/user/1000/bubbler/i/{src}").as_str(),
                        dest
                    ]),
                "{s:?}"
            );
        }
        assert!(!s.contains(&"/etc/passwd+"), "{s:?}");
        assert!(!s.contains(&"/etc/group+"), "{s:?}");
        assert!(pos("/etc/passwd") > pos("/etc"), "{s:?}");
        assert!(pos("/etc/subgid") < pos("--proc"), "{s:?}");
    }

    /// The bind, the two synthetic files and the shadow-suite overlay
    /// that follows them are all tagged with the `etc` node that asked
    /// for them, not left as baseline: `--explain` groups them together
    /// rather than folding them into the sandbox that would exist
    /// without it.
    #[test]
    fn binding_the_hosts_etc_tags_the_bind_and_the_synthetic_files_with_its_own_origin() {
        let (f, _, _) = crate::host::fake::types();
        let host = FakeHost::default().with("/etc/subuid", f);
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &host);
        args.tag(Origin::Etc);
        args.bind_host_etc(&host);
        let argv = args
            .finish_explained(&["sh".into()], &mut Counter::new())
            .unwrap();
        let etc: Vec<&Explained> = argv.iter().filter(|i| i.origin == Origin::Etc).collect();
        assert_eq!(etc.len(), 4, "{argv:#?}");
        assert_eq!(strs(&etc[0].args), ["--ro-bind", "/etc", "/etc"]);
        assert!(etc[1].args.iter().any(|a| a == "/etc/passwd"), "{etc:#?}");
        assert!(etc[2].args.iter().any(|a| a == "/etc/group"), "{etc:#?}");
        assert!(etc[3].args.iter().any(|a| a == "/etc/subuid"), "{etc:#?}");
    }

    #[test]
    fn the_alsa_configuration_is_in_the_baseline_etc() {
        // alsa-lib reads `/etc/alsa/conf.d`, never `/usr/share/alsa`
        // directly, and pipewire-alsa's `99-pipewire-default.conf` there
        // is what makes `default` the sound server. Without the entry an
        // ALSA client under `pipewire` falls back to the hardware card,
        // whose `/dev/snd` nodes no sandbox has (measured:
        // `cannot find card '0'`).
        let (_, d, _) = crate::host::fake::types();
        let host = FakeHost::default().with("/etc/alsa", d);
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &host)
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        assert!(
            s.windows(3)
                .any(|w| w == ["--ro-bind", "/etc/alsa", "/etc/alsa"]),
            "{s:?}"
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
    fn disabling_user_namespaces_adds_two_phase_one_flags_and_nothing_else() {
        let plain = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.disable_userns();
        args.disable_userns();
        let hardened = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&hardened);
        // Phase 1, and `--unshare-user` with it: bwrap refuses
        // `--disable-userns` on its own, and `--unshare-all` is not enough.
        assert_eq!(&s[9..11], &["--unshare-user", "--disable-userns"], "{s:?}");
        let rest: Vec<&str> = s
            .iter()
            .copied()
            .filter(|a| *a != "--unshare-user" && *a != "--disable-userns")
            .collect();
        assert_eq!(rest, strs(&plain), "nothing else about the sandbox moved");
    }

    /// A per-run share moves the working directory by replacing the
    /// value of the baseline flag, never by adding a second one: bwrap
    /// would take the last, and an explanation would show both.
    #[test]
    fn chdir_replaces_the_baseline_working_directory() {
        let plain = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let plain = strs(&plain);
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.chdir(Path::new("/srv/src"));
        let finished = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&finished);
        assert_eq!(s.iter().filter(|a| **a == "--chdir").count(), 1, "{s:?}");
        let at = s.iter().position(|a| *a == "--chdir").unwrap();
        // Same place in phase 1 the baseline puts it, with only the
        // directory changed.
        assert_eq!(
            plain.iter().position(|a| *a == "--chdir"),
            Some(at),
            "{s:?}"
        );
        assert_eq!(&s[at..at + 2], &["--chdir", "/srv/src"], "{s:?}");
        assert_eq!(
            &plain[at..at + 2],
            &["--chdir", "/home/bubbler"],
            "{plain:?}"
        );
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
    fn data_items_become_read_only_binds_of_written_files() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ro_bind_data(b"hello".to_vec(), Path::new("/etc/x"));
        args.ro_bind_data(b"world".to_vec(), Path::new("/etc/y"));
        let mut rec = Recorder {
            seen: Vec::new(),
            next: Counter::new(),
        };
        let argv = args.finish(&["sh".into()], &mut rec).unwrap();
        let seen = rec.seen;
        let s = strs(&argv);
        assert!(
            s.windows(3)
                .any(|w| w == ["--ro-bind", "/run/user/1000/bubbler/i/etc-x", "/etc/x"])
        );
        assert!(
            s.windows(3)
                .any(|w| w == ["--ro-bind", "/run/user/1000/bubbler/i/etc-y", "/etc/y"])
        );
        // The baseline's passwd and group came through the same call
        // first, so the two written here are the last two seen.
        assert_eq!(seen[2..], [b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn allocator_failure_is_data_error() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ro_bind_data(b"x".to_vec(), Path::new("/etc/x"));
        let r = args.finish(&["sh".into()], &mut Failing);
        assert!(matches!(r, Err(LaunchError::Data(_))));
    }

    #[test]
    fn the_command_runs_under_bubbler_init_on_the_allocated_socket_fd() {
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        let s = strs(&argv);
        // Fd 3 went to the info pipe; the baseline passwd and group are
        // files, not descriptors, so the control socket is next.
        assert_eq!(
            &s[s.len() - 6..],
            &["--", INIT_INSIDE, "--socket-fd", "4", "--", "sh"]
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
            &["--", INIT_INSIDE, "--socket-fd", "4", "--ctty", "--", "sh"]
        );
    }

    /// The server argv is the supervisor's argument, not bwrap's: it
    /// follows the switches of the supervisor, ends with the `--` that
    /// closes it, and keeps the origin of the node that asked for a
    /// display. A sidecar runs no supervisor, so it never carries one.
    #[test]
    fn the_x11_argv_follows_the_supervisor_switches_and_keeps_its_origin() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.ctty();
        args.tag(Origin::Service(2));
        args.x11_server(vec!["/usr/bin/Xwayland".into(), ":0".into()], None);
        args.tag(Origin::Baseline);
        let explained = args
            .clone()
            .finish_explained(&["sh".into()], &mut Counter::new())
            .unwrap();
        let server = &explained[explained.len() - 2];
        assert_eq!(server.origin, Origin::Service(2));
        assert_eq!(
            strs(&server.args),
            ["--x11", "/usr/bin/Xwayland", ":0", "--"]
        );
        assert_eq!(
            server.note.as_deref(),
            Some(
                "nested Xwayland, started by bubbler-init on the first X connection; \
                 -listenfd is added at run time"
            )
        );
        let plain = args
            .finish_plain(&["sh".into()], &mut Counter::new())
            .unwrap();
        assert!(!strs(&plain).contains(&"--x11"), "{plain:?}");
    }

    /// A window manager is one more argument of the supervisor's, after
    /// the `--` that closes the server argv and before the command's
    /// own: the words of the server's command line stay the server's.
    #[test]
    fn a_window_manager_follows_the_server_argv_it_is_not_part_of() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.tag(Origin::Service(2));
        args.x11_server(
            vec!["/usr/bin/Xwayland".into(), ":0".into()],
            Some("openbox".into()),
        );
        args.tag(Origin::Baseline);
        let explained = args
            .finish_explained(&["sh".into()], &mut Counter::new())
            .unwrap();
        let wm = &explained[explained.len() - 2];
        assert_eq!(wm.origin, Origin::Service(2));
        assert_eq!(strs(&wm.args), ["--wm", "openbox"]);
        assert_eq!(
            wm.note.as_deref(),
            Some("window manager inside the sandbox, started with the server")
        );
        let flat = flatten(explained);
        let tail = [
            "--x11",
            "/usr/bin/Xwayland",
            ":0",
            "--",
            "--wm",
            "openbox",
            "--",
            "sh",
        ];
        assert_eq!(strs(&flat[flat.len() - tail.len()..]), tail, "{flat:?}");
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

    /// bwrap cannot make a mount point inside the read-only `/usr`, so
    /// the shim needs a writable `/usr/bin` first and a remount to take
    /// the write back: without the remount the sandbox can replace or
    /// delete anything in it. The three are one sequence in that order,
    /// and all of them after the `/usr` the overlay reads from.
    #[test]
    fn the_flatpak_spawn_shim_is_an_overlay_the_remount_takes_back() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.flatpak_spawn_shim(Path::new("/x/bubbler-init"));
        let explained = args
            .finish_explained(&["sh".into()], &mut Counter::new())
            .unwrap();
        let flat = flatten(explained.clone());
        let s = strs(&flat);
        let pos = |x: &str| s.iter().position(|a| *a == x).unwrap();
        assert!(
            s.windows(4)
                .any(|w| w == ["--overlay-src", "/usr/bin", "--tmp-overlay", "/usr/bin"]),
            "{s:?}"
        );
        assert!(
            s.windows(3)
                .any(|w| w == ["--ro-bind", "/x/bubbler-init", FLATPAK_SPAWN_INSIDE]),
            "{s:?}"
        );
        assert!(pos("--ro-bind") < pos("--overlay-src"), "{s:?}");
        assert!(pos("--overlay-src") < pos(FLATPAK_SPAWN_INSIDE), "{s:?}");
        assert!(pos(FLATPAK_SPAWN_INSIDE) < pos("--remount-ro"), "{s:?}");
        // The overlay is the one operation whose paths do not say what
        // it is there for, so it is the one that carries the note.
        let overlay = explained
            .iter()
            .find(|e| e.args.first().is_some_and(|a| a == "--overlay-src"))
            .expect("the overlay is in the argv");
        assert_eq!(
            overlay.note.as_deref(),
            Some("flatpak-spawn shim (glycin, gdk-pixbuf)")
        );
    }

    #[test]
    fn the_seccomp_program_follows_the_info_and_block_fds_in_phase_one() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.block_until_released();
        args.add_seccomp(b"12345678".to_vec(), "x86_64 + i386");
        let mut rec = Recorder {
            seen: Vec::new(),
            next: Counter::new(),
        };
        let finished = args.finish(&["sh".into()], &mut rec).unwrap();
        let s = strs(&finished);
        assert_eq!(
            &s[7..13],
            &["--info-fd", "3", "--block-fd", "4", "--add-seccomp-fd", "5",],
            "{s:?}"
        );
        assert_eq!(
            rec.seen[..1],
            [b"12345678".to_vec()],
            "the program is the first data the allocator is handed"
        );
    }

    #[test]
    fn a_sandbox_without_a_filter_has_no_seccomp_flag() {
        let argv = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default())
            .finish(&["sh".into()], &mut Counter::new())
            .unwrap();
        assert!(!strs(&argv).contains(&"--add-seccomp-fd"));
    }

    #[test]
    fn symlink_emits_arguments_in_the_service_section() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.tag(Origin::Service(0));
        args.ro_bind(Path::new("/etc"), Path::new("/etc"));
        args.symlink(Path::new("usr/lib"), Path::new("/lib64"));
        let argv = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&argv);
        let ro_bind_pos = s
            .windows(3)
            .position(|w| w == ["--ro-bind", "/etc", "/etc"])
            .expect("ro_bind must appear in argv");
        let symlink_pos = s
            .windows(3)
            .position(|w| w == ["--symlink", "usr/lib", "/lib64"])
            .expect("symlink must appear in argv");
        assert!(
            symlink_pos > ro_bind_pos,
            "symlink must appear after the preceding ro_bind in the service phase: {s:?}"
        );
    }

    #[test]
    fn mask_dir_emits_size_tmpfs_and_remount_ro() {
        let mut args = BwrapArgs::baseline(&env(), Path::new("/i/home"), &FakeHost::default());
        args.tag(Origin::Service(0));
        args.ro_bind(Path::new("/etc"), Path::new("/etc"));
        args.mask_dir(Path::new("/sys/class/drm/card0"));
        let argv = args.finish(&["sh".into()], &mut Counter::new()).unwrap();
        let s = strs(&argv);
        let ro_bind_pos = s
            .windows(3)
            .position(|w| w == ["--ro-bind", "/etc", "/etc"])
            .expect("ro_bind must appear in argv");
        let mask_start = s
            .windows(4)
            .position(|w| {
                w[0] == "--size"
                    && w[1] == "4096"
                    && w[2] == "--tmpfs"
                    && w[3] == "/sys/class/drm/card0"
            })
            .expect("mask_dir must emit --size 4096 --tmpfs <dir>");
        assert!(
            mask_start > ro_bind_pos,
            "mask_dir must appear after the preceding ro_bind in the service phase: {s:?}"
        );
        assert_eq!(
            &s[mask_start + 4..mask_start + 6],
            &["--remount-ro", "/sys/class/drm/card0"],
            "mask_dir must follow with --remount-ro: {s:?}"
        );
    }
}
