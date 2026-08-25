//! Turns granted services into builder calls. Each service touches only
//! phase 4 (binds) and phase 5 (env); `network "host"` is the one
//! exception that edits phase 1 via [`BwrapArgs::share_net`].
//!
//! Paths come from untrusted host environment values, so every source is
//! probed for its file *type*, never for mere existence: binding a
//! directory binds the whole tree under it, so `XAUTHORITY=/` would bind
//! the host root.

use std::ffi::{OsStr, OsString};
use std::fs::FileType;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

use crate::bwrap::{BwrapArgs, Origin};
use crate::config::{RESERVED_ENV, Service, ShareMode};
use crate::dbus;
use crate::env::{Env, SANDBOX_HOME};
use crate::error::LaunchError;
use crate::host::Host;
use crate::network::{self, Mode as NetworkMode, NetworkConfig};

/// What a service needs to know about the instance beyond its config.
#[derive(Debug, Clone)]
pub struct ServiceCtx<'a> {
    /// `$XDG_RUNTIME_DIR/bubbler/<instance>` on the host: where the
    /// launcher's sidecars put the sockets a service binds.
    pub instance_runtime: PathBuf,
    /// The D-Bus plan the launcher carries out, when `dbus` is granted.
    /// `portals` binds the `/.flatpak-info` from it, so the sandbox and
    /// the proxy are handed the very same bytes.
    pub dbus: Option<&'a dbus::Plan>,
}

/// Apply every service to `args`. `host` reports the type of a host path
/// with symlinks followed, so tests run without real sockets. A
/// [`Service::HomeShare`] `path` must be relative and a
/// [`Service::PathShare`] `path` absolute, both normalised, exactly as the
/// parser leaves them.
///
/// Every argument a service adds is tagged with the position of its node
/// in `services`, including the two bound after the loop: the tag is set
/// here, so no service has to carry one.
pub fn apply_all(
    services: &[Service],
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    ctx: &ServiceCtx,
) -> Result<(), LaunchError> {
    let has_x11 = services.contains(&Service::X11);
    let shares = path_shares(services, env, host)?;
    for (i, s) in services.iter().enumerate() {
        args.tag(Origin::Service(i));
        match s {
            // The mode chooses which socket the launcher hands over, and
            // no launcher hands one over yet: both bind the host's.
            Service::Wayland(_) => wayland(env, args, host, !has_x11)?,
            Service::X11 => x11(env, args, host)?,
            Service::Network(cfg) => network(args, host, cfg)?,
            Service::HomeShare { path, mode } => home_share(env, args, host, path, *mode)?,
            Service::Dri => dri(args, host)?,
            Service::Pipewire => pipewire(env, args, host)?,
            Service::Pulseaudio => pulseaudio(env, args, host)?,
            Service::EtcShare { name } => etc_share(args, host, name)?,
            Service::AppRuntime { id, mode } => app_runtime(env, args, id, *mode),
            Service::Dbus { .. } => dbus_socket(env, args, ctx),
            Service::SystemBus { .. } => system_bus_socket(args, ctx),
            Service::Portals => portals(env, args, host, ctx)?,
            Service::Camera { nodes } => camera(services, args, host, *nodes)?,
            // Bound below, once every share has been resolved: two
            // overlapping shares must be refused before either is emitted.
            Service::PathShare { .. } => {}
            // Bound after the loop, so its whole-`/sys/devices` bind always
            // follows the PCI roots `dri` binds under it rather than
            // depending on the order of the two nodes in the file.
            Service::Gamepad { .. } => {}
            // Bound after the loop with `gamepad hidraw=#true`, which is
            // the same grant written the older way: one bind, whether the
            // config holds one node or both.
            Service::Hidraw => {}
            // Rule-only bundles: they reach the sandbox through the proxy
            // the launcher starts, not through bwrap arguments.
            Service::Notify | Service::Tray | Service::Mpris { .. } => {}
        }
    }
    let pad = services.iter().enumerate().find_map(|(i, s)| match s {
        Service::Gamepad { hidraw, uinput } => Some((i, *hidraw, *uinput)),
        _ => None,
    });
    // One grant however it is written, and the name is the node an error
    // points at: the bare one when the config holds both. Its arguments
    // are attributed to that same node.
    let bare = services.iter().position(|s| *s == Service::Hidraw);
    let hidraw_node = match (bare, pad.is_some_and(|(_, h, _)| h)) {
        (Some(i), _) => Some(("hidraw", Origin::Service(i))),
        (None, true) => pad.map(|(i, _, _)| ("gamepad", Origin::Service(i))),
        (None, false) => None,
    };
    match pad {
        Some((i, _, uinput)) => {
            args.tag(Origin::Service(i));
            gamepad(args, host, hidraw_node, uinput)?;
        }
        None => {
            if let Some((node, origin)) = hidraw_node {
                args.tag(origin);
                hidraw(args, host, node)?;
            }
        }
    }
    for (i, dst, src, mode) in shares {
        args.tag(Origin::Service(i));
        match mode {
            ShareMode::ReadOnly => args.ro_bind(&src, dst),
            ShareMode::ReadWrite => args.bind(&src, dst),
        }
    }
    Ok(())
}

fn require(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
    expected: &'static str,
    accept: impl Fn(FileType) -> bool,
) -> Result<PathBuf, LaunchError> {
    match host.file_type(&path) {
        None => Err(LaunchError::MissingResource { service, path }),
        Some(t) if accept(t) => Ok(path),
        Some(_) => Err(LaunchError::WrongType {
            service,
            path,
            expected,
        }),
    }
}

/// The source must be a Unix socket; a directory here would bind a tree.
pub(crate) fn require_socket(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    require(host, service, path, "a socket", |t| t.is_socket())
}

/// The source must be a regular file, e.g. an Xauthority cookie file.
pub(crate) fn require_file(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    require(host, service, path, "a regular file", |t| t.is_file())
}

/// The source must be a directory, e.g. a `/sys` subtree.
fn require_dir(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    require(host, service, path, "a directory", |t| t.is_dir())
}

/// The source must be a tree or a file to bind: a socket or a device node
/// under a shared path is a grant of its own kind, never a side effect of
/// sharing a path.
fn require_dir_or_file(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    require(host, service, path, "a directory or a regular file", |t| {
        t.is_dir() || t.is_file()
    })
}

/// The source may be of any type; only used where the user named the path
/// in the config rather than the environment naming it.
fn require_exists(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    match host.file_type(&path) {
        Some(_) => Ok(path),
        None => Err(LaunchError::MissingResource { service, path }),
    }
}

/// The resolver configuration, and the host's network namespace where
/// the node asked for it. The isolated mode needs nothing of bwrap beyond
/// the baseline's `--unshare-all`; what connects it is the pasta sidecar
/// the launcher starts once bwrap has reported the sandbox pid.
///
/// The bind is phase 4, so it lands inside the phase-2 tmpfs on `/etc`.
/// A generated file rather than the host's, except under `"host"` with no
/// `dns` child: the host's `/etc/resolv.conf` may name a resolver on its
/// own loopback, which a sandbox with its own namespace can never reach.
fn network(args: &mut BwrapArgs, host: &dyn Host, cfg: &NetworkConfig) -> Result<(), LaunchError> {
    if cfg.mode == NetworkMode::Host {
        args.share_net();
    }
    match network::resolv_conf(cfg) {
        Some(content) => args.ro_bind_data(content, Path::new("/etc/resolv.conf"), "0644"),
        None if cfg.mode == NetworkMode::Host => {
            let p = require_file(host, "network", PathBuf::from("/etc/resolv.conf"))?;
            args.ro_bind(&p, &p);
        }
        None => {}
    }
    Ok(())
}

/// Bind `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` at the same path, which must
/// be a plain socket name. Arch wiki (Bubblewrap/Examples) pattern.
/// `XDG_SESSION_TYPE=wayland` only when X11 is not also granted, so
/// toolkits do not get mixed signals.
fn wayland(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    claim_session: bool,
) -> Result<(), LaunchError> {
    let display = env
        .wayland_display
        .as_deref()
        .ok_or(LaunchError::MissingEnv {
            service: "wayland",
            var: "WAYLAND_DISPLAY",
        })?;
    let mut comps = Path::new(display).components();
    if !matches!(
        (comps.next(), comps.next()),
        (Some(Component::Normal(_)), None)
    ) {
        return Err(LaunchError::BadValue {
            service: "wayland",
            reason: format!(
                "cannot use WAYLAND_DISPLAY={}; only a plain socket name is supported",
                display.to_string_lossy()
            ),
        });
    }
    let sock = require_socket(host, "wayland", env.runtime_dir.join(display))?;
    args.ro_bind(&sock, &sock);
    args.setenv(OsStr::new("WAYLAND_DISPLAY"), display);
    if claim_session {
        args.setenv(OsStr::new("XDG_SESSION_TYPE"), OsStr::new("wayland"));
    }
    Ok(())
}

/// Display number from `$DISPLAY`: accepts `:N`, `:N.S`, `unix:N`.
/// Anything with a host part is a TCP display and unsupported.
pub fn x11_display_number(display: &OsStr) -> Option<u32> {
    let s = display.to_str()?;
    let rest = s.strip_prefix(':').or_else(|| s.strip_prefix("unix:"))?;
    let num = rest.split('.').next()?;
    // `u32::from_str` accepts a leading `+`; a display number never has one.
    if num.starts_with('+') {
        return None;
    }
    num.parse().ok()
}

/// Bind the X11 socket at the same path (Arch wiki: binding to a different
/// display number may not work) and any Xauthority file at the fixed inner
/// path `/home/bubbler/.Xauthority`, so the host location stays hidden.
/// The `$HOME/.Xauthority` fallback follows libX11's default, not the wiki,
/// and is used only when it is a regular file.
fn x11(env: &Env, args: &mut BwrapArgs, host: &dyn Host) -> Result<(), LaunchError> {
    let display = env.display.as_deref().ok_or(LaunchError::MissingEnv {
        service: "x11",
        var: "DISPLAY",
    })?;
    let n = x11_display_number(display).ok_or_else(|| LaunchError::BadValue {
        service: "x11",
        reason: format!(
            "cannot use DISPLAY={}; only local displays like :0 are supported",
            display.to_string_lossy()
        ),
    })?;
    let sock = require_socket(host, "x11", PathBuf::from(format!("/tmp/.X11-unix/X{n}")))?;
    args.ro_bind(&sock, &sock);
    args.setenv(OsStr::new("DISPLAY"), OsStr::new(&format!(":{n}")));

    let cookie = match &env.xauthority {
        Some(xa) => Some(require_file(host, "x11", xa.clone())?),
        None => {
            let home = env.home.join(".Xauthority");
            host.file_type(&home)
                .is_some_and(|t| t.is_file())
                .then_some(home)
        }
    };
    if let Some(cookie_path) = cookie {
        let inner = Path::new(SANDBOX_HOME).join(".Xauthority");
        args.ro_bind(&cookie_path, &inner);
        args.setenv(OsStr::new("XAUTHORITY"), inner.as_os_str());
    }
    Ok(())
}

/// GPU access: `/dev/dri` and whichever NVIDIA nodes the host has, bound
/// read-write because bwrap has no read-only device bind, plus the `/sys`
/// paths a userspace driver reads; a PCI root exposes every PCI device's
/// attributes, not only the GPU's.
fn dri(args: &mut BwrapArgs, host: &dyn Host) -> Result<(), LaunchError> {
    // Paths from Arch wiki Bubblewrap/Examples; PCI roots are enumerated so no unrelated
    // `/sys/devices` subtree is exposed.
    let dev = require_dir(host, "dri", PathBuf::from("/dev/dri"))?;
    args.dev_bind(&dev, &dev);
    for p in ["/sys/dev/char", "/sys/devices/system/cpu"] {
        let p = require_dir(host, "dri", PathBuf::from(p))?;
        args.ro_bind(&p, &p);
    }
    let devices = Path::new("/sys/devices");
    let mut found = false;
    for name in host.list_dir(devices) {
        if !name.as_encoded_bytes().starts_with(b"pci") {
            continue;
        }
        let p = devices.join(&name);
        if host.file_type(&p).is_some_and(|t| t.is_dir()) {
            args.ro_bind(&p, &p);
            found = true;
        }
    }
    if !found {
        return Err(LaunchError::MissingResource {
            service: "dri",
            path: devices.join("pci*"),
        });
    }
    // After the PCI roots, whose subtrees every entry in it is a relative
    // symlink into: the only file it adds is `/sys/class/drm/version`.
    // Missing on a host with no DRM driver loaded, which is not an error
    // when `/dev/dri` is there.
    let drm = PathBuf::from("/sys/class/drm");
    if host.file_type(&drm).is_some_and(|t| t.is_dir()) {
        args.ro_bind(&drm, &drm);
    }
    // The NVIDIA nodes are created by the setuid `nvidia-modprobe` a udev
    // rule runs, and a sandbox has `NoNewPrivs` set, so a node missing at
    // launch can never appear later: bind what the host has, fail over
    // nothing. The char-device check keeps the `/dev/nvidia-caps`
    // directory out: those are MIG capability files, and nothing outside
    // MIG reads them.
    // `file_type` follows symlinks, but `/dev` and `/sys/module` are
    // root-owned, so a `nvidia*` symlink there is the host's decision.
    let dev_dir = Path::new("/dev");
    for name in host.list_dir(dev_dir) {
        if !name.as_encoded_bytes().starts_with(b"nvidia") {
            continue;
        }
        let p = dev_dir.join(&name);
        if host.file_type(&p).is_some_and(|t| t.is_char_device()) {
            args.dev_bind(&p, &p);
        }
    }
    // libnvidia-glvnd and NVML read `/sys/module/nvidia/initstate` and fall
    // back to Mesa when it is missing (verified on driver 610). The other
    // `nvidia_*` module directories cost nothing and cover CUDA.
    let modules = Path::new("/sys/module");
    for name in host.list_dir(modules) {
        if !name.as_encoded_bytes().starts_with(b"nvidia") {
            continue;
        }
        let p = modules.join(&name);
        if host.file_type(&p).is_some_and(|t| t.is_dir()) {
            args.ro_bind(&p, &p);
        }
    }
    Ok(())
}

/// Game controllers: `/dev/input` with device access, plus the `/sys`
/// entries that identify a device and the udev database where the host
/// has one. `/dev/input` is every input device, keyboards included.
/// `hidraw` names the node the raw HID devices were granted by, when they
/// were; `uinput` adds the injection node.
fn gamepad(
    args: &mut BwrapArgs,
    host: &dyn Host,
    hidraw: Option<(&'static str, Origin)>,
    uinput: bool,
) -> Result<(), LaunchError> {
    // The `hidraw` binds may belong to a `hidraw` node of its own, so the
    // tag this was called with is put back before the rest of the grant.
    let pad = args.origin();
    // The directory, not the nodes it holds today, exactly as flatpak's
    // `--device=input`: a node bound one by one freezes the device list at
    // start, while the directory shows a controller plugged in later.
    let dev = require_dir(host, "gamepad", PathBuf::from("/dev/input"))?;
    args.dev_bind(&dev, &dev);
    // `/sys/class/input` entries are symlinks into `/sys/devices`, and a
    // bluetooth or virtual controller lives outside the PCI roots `dri`
    // exposes, so the whole tree is bound read-only.
    for p in ["/sys/class/input", "/sys/devices"] {
        let p = require_dir(host, "gamepad", PathBuf::from(p))?;
        args.ro_bind(&p, &p);
    }
    // Identification only: the udev monitor is a netlink socket, which
    // delivers no uevents in the sandbox's own network namespace.
    let udev = PathBuf::from("/run/udev");
    match host.file_type(&udev) {
        // A host with no udev database is not an error; libudev and SDL
        // both fall back to reading the device directory itself.
        None => {}
        Some(t) if t.is_dir() => args.ro_bind(&udev, &udev),
        Some(_) => {
            return Err(LaunchError::WrongType {
                service: "gamepad",
                path: udev,
                expected: "a directory",
            });
        }
    }
    if let Some((node, origin)) = hidraw {
        args.tag(origin);
        self::hidraw(args, host, node)?;
        args.tag(pad);
    }
    if uinput {
        gamepad_uinput(args, host)?;
    }
    Ok(())
}

/// The `/dev/hidraw*` nodes the host has right now, plus the sysfs class
/// directory that names them. `service` is the node this was granted
/// by — `hidraw` or the older `gamepad hidraw=#true` — so an error
/// names the line the user wrote.
// There is no `/dev/hidraw` directory to bind instead, so the list is
// whatever is plugged in when the sandbox starts: a device connected
// later has no node inside. Nothing is refused when there are none —
// hidraw nodes come and go with the hardware, and every one of them is a
// HID device, not only a controller.
fn hidraw(args: &mut BwrapArgs, host: &dyn Host, service: &'static str) -> Result<(), LaunchError> {
    let dev = Path::new("/dev");
    for name in host.list_dir(dev) {
        if !name.as_encoded_bytes().starts_with(b"hidraw") {
            continue;
        }
        let p = dev.join(&name);
        // A name is not a node: only the character devices are bound.
        if host.file_type(&p).is_some_and(|t| t.is_char_device()) {
            // `-try`: the node is one this loop found a moment ago, and a
            // device unplugged before the exec must not fail the launch.
            args.dev_bind_try(&p, &p);
        }
    }
    let class = PathBuf::from("/sys/class/hidraw");
    match host.file_type(&class) {
        // A missing class directory is tolerated, like `/run/udev`: the
        // nodes above are what a device is opened through.
        None => Ok(()),
        Some(t) if t.is_dir() => {
            args.ro_bind(&class, &class);
            Ok(())
        }
        Some(_) => Err(LaunchError::WrongType {
            service,
            path: class,
            expected: "a directory",
        }),
    }
}

/// Cameras. The bare grant reaches the sandbox through the portal on the
/// bus and produces no argument at all; `nodes` adds the device half.
///
/// Without `portals` there is no `/.flatpak-info`, so the portal reads
/// the sandbox as an ordinary process of the user and the permission it
/// would store is the blanket one every unsandboxed process shares. The
/// grant is refused here rather than quietly downgraded; the parser
/// rejects that config already.
fn camera(
    services: &[Service],
    args: &mut BwrapArgs,
    host: &dyn Host,
    nodes: bool,
) -> Result<(), LaunchError> {
    if !services.contains(&Service::Portals) {
        return Err(LaunchError::BadValue {
            service: "camera",
            reason: "requires portals".to_owned(),
        });
    }
    if nodes {
        // `gamepad` binds `/run/udev` too, and after this: emitting it
        // twice would mount it twice for one database.
        let udev = !services
            .iter()
            .any(|s| matches!(s, Service::Gamepad { .. }));
        camera_nodes(args, host, udev)?;
    }
    Ok(())
}

/// The V4L2 device nodes for a `camera nodes=#true`, plus the sysfs
/// directories that name them and the udev database that identifies
/// them. `udev` is false where another grant binds `/run/udev` already.
/// Every one is emitted only where the host has it: a machine with no
/// camera has none of them, and the portal half of the grant works
/// either way, so a missing node is not a failed launch.
// `/dev/media*` is bound beside `/dev/video*` because a UVC camera's
// controls are a media controller device, not a V4L2 one.
//
// `/dev/v4l/by-id` and `by-path` hold relative symlinks (`../../video0`,
// as udev writes them) onto the nodes bound above, so they resolve
// inside. The `/sys` entries do not: `/sys/class/video4linux/videoN` and
// `/sys/bus/media/devices/*` point into `/sys/devices`, which this grant
// deliberately does not bind, so sysfs enumeration finds nothing. What
// works inside is opening `/dev/videoN` directly.
fn camera_nodes(args: &mut BwrapArgs, host: &dyn Host, udev: bool) -> Result<(), LaunchError> {
    let dev = Path::new("/dev");
    for name in host.list_dir(dev) {
        let bytes = name.as_encoded_bytes();
        if !bytes.starts_with(b"video") && !bytes.starts_with(b"media") {
            continue;
        }
        let p = dev.join(&name);
        // A name is not a node: only the character devices are bound.
        if host.file_type(&p).is_some_and(|t| t.is_char_device()) {
            // `-try`: the node is one this loop found a moment ago, and a
            // camera unplugged before the exec must not fail the launch.
            args.dev_bind_try(&p, &p);
        }
    }
    // Identification only. `/run/udev/data` is a database read at
    // enumeration time; the udev monitor behind it is a netlink socket,
    // which delivers no uevents in the sandbox's own network namespace.
    let dirs: &[&str] = match udev {
        true => &[
            "/dev/v4l",
            "/sys/class/video4linux",
            "/sys/bus/media",
            "/run/udev",
        ],
        false => &["/dev/v4l", "/sys/class/video4linux", "/sys/bus/media"],
    };
    for p in dirs {
        let p = PathBuf::from(*p);
        match host.file_type(&p) {
            // A host with none of them is a host with no camera, which
            // the portal half of the grant does not need.
            None => {}
            Some(t) if t.is_dir() => args.ro_bind(&p, &p),
            Some(_) => {
                return Err(LaunchError::WrongType {
                    service: "camera",
                    path: p,
                    expected: "a directory",
                });
            }
        }
    }
    Ok(())
}

/// `/dev/uinput`, which is how a process creates input devices for the
/// whole session. Warned about on every launch: the grant reaches out of
/// the sandbox, so it is never a quiet one.
fn gamepad_uinput(args: &mut BwrapArgs, host: &dyn Host) -> Result<(), LaunchError> {
    let p = require(
        host,
        "gamepad",
        PathBuf::from("/dev/uinput"),
        "a character device",
        |t| t.is_char_device(),
    )?;
    args.dev_bind(&p, &p);
    eprintln!(
        "bubbler: warning: gamepad uinput=#true: the sandbox can create \
         virtual input devices and type into your session"
    );
    Ok(())
}

/// Bind the PipeWire socket at the same path; clients find it through
/// `$XDG_RUNTIME_DIR`, so no variable is needed.
fn pipewire(env: &Env, args: &mut BwrapArgs, host: &dyn Host) -> Result<(), LaunchError> {
    let p = require_socket(host, "pipewire", env.runtime_dir.join("pipewire-0"))?;
    args.ro_bind(&p, &p);
    Ok(())
}

/// Bind the PulseAudio native socket at the same path and set
/// `PULSE_SERVER` to it so clients find the socket.
fn pulseaudio(env: &Env, args: &mut BwrapArgs, host: &dyn Host) -> Result<(), LaunchError> {
    let p = require_socket(host, "pulseaudio", env.runtime_dir.join("pulse/native"))?;
    args.ro_bind(&p, &p);
    let mut value = OsString::from("unix:");
    value.push(p.as_os_str());
    args.setenv(OsStr::new("PULSE_SERVER"), &value);
    Ok(())
}

/// Bind the socket the launcher's `xdg-dbus-proxy` serves at the usual
/// `$XDG_RUNTIME_DIR/bus` and point clients at it. The host bus is never
/// bound; only the filtered socket is.
///
/// The source is not probed here, unlike every other bind: it exists only
/// once the launcher has checked the proxy's socket and moved it out of
/// the directory the proxy can write to. A `--dry-run` builds the same
/// argv with no proxy running at all.
fn dbus_socket(env: &Env, args: &mut BwrapArgs, ctx: &ServiceCtx) {
    let inside = env.runtime_dir.join("bus");
    args.ro_bind(
        &dbus::app_bus_path(&ctx.instance_runtime, dbus::SESSION_SOCKET),
        &inside,
    );
    let mut address = OsString::from("unix:path=");
    address.push(inside.as_os_str());
    args.setenv(OsStr::new("DBUS_SESSION_BUS_ADDRESS"), &address);
}

/// Bind the socket the same proxy serves for the system bus at the path
/// every client library compiles in, so no environment variable points at
/// it. `/run` is a tmpfs this builder creates and the bind comes after it.
///
/// The source is not probed here for the same reason [`dbus_socket`]'s is
/// not: it exists only once the launcher has moved the proxy's socket out
/// of the proxy's reach.
fn system_bus_socket(args: &mut BwrapArgs, ctx: &ServiceCtx) {
    args.ro_bind(
        &dbus::app_bus_path(&ctx.instance_runtime, dbus::SYSTEM_SOCKET),
        Path::new(dbus::SYSTEM_BUS_PATH),
    );
}

/// Bind `/.flatpak-info` so portals know the sandbox, and this instance's
/// own view of the document portal — `$XDG_RUNTIME_DIR/doc/by-app/<app id>`
/// on the host — at `$XDG_RUNTIME_DIR/doc`, the path the portal hands back
/// for a picked file. Read-write: the portal strips write permission from
/// every document it did not grant WRITE, so the bind adds no policy. Only
/// the per-app subtree is bound; the mount root holds every app's
/// documents. Without a mount there (no xdg-document-portal) the launch
/// warns and runs with the identity file alone.
///
/// The bytes of `/.flatpak-info` come from the launcher's plan, which
/// hands the proxy the same file. Without a plan there is no proxy and no
/// bus, so the grant is refused rather than quietly dropped; the parser
/// rejects that config already.
fn portals(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    ctx: &ServiceCtx,
) -> Result<(), LaunchError> {
    let plan = ctx
        .dbus
        .filter(|p| p.session.is_some())
        .ok_or(LaunchError::BadValue {
            service: "portals",
            reason: "requires dbus".to_owned(),
        })?;
    args.ro_bind_data(
        plan.flatpak_info.clone(),
        Path::new(dbus::FLATPAK_INFO),
        "0644",
    );
    let doc = env.runtime_dir.join("doc");
    // `by-app/<app id>` itself is never probed: the FUSE creates it on
    // the first lookup for any valid app id (xdg-desktop-portal,
    // document-portal/document-portal-fuse.c, `ensure_by_app_inode`), so
    // it is absent until something asks for it.
    let mounted =
        host.file_type(&doc).is_some_and(|t| t.is_dir()) && host.is_mountpoint(&doc) == Some(true);
    if mounted {
        args.bind(&doc.join("by-app").join(&plan.app_id), &doc);
    } else {
        eprintln!(
            "bubbler: warning: portals: no document portal at {}, so a file \
             picked in a portal dialog cannot be opened inside",
            doc.display()
        );
    }
    Ok(())
}

/// Emit profile/instance `env` pairs after all service variables, so a
/// profile can layer toolkit settings on top. A [`RESERVED_ENV`] key is
/// refused here as well as in the parser, so a caller building an
/// [`crate::config::InstanceConfig`] by hand cannot override what the
/// sandbox sets.
pub fn apply_env(pairs: &[(String, String)], args: &mut BwrapArgs) -> Result<(), LaunchError> {
    for (i, (k, v)) in pairs.iter().enumerate() {
        args.tag(Origin::Env(i));
        if RESERVED_ENV.contains(&k.as_str()) {
            return Err(LaunchError::BadValue {
                service: "env",
                reason: format!("{k} is set by bubbler and cannot be overridden"),
            });
        }
        args.setenv(OsStr::new(k), OsStr::new(v));
    }
    Ok(())
}

/// The canonical form of a host path a config named, accepted only if
/// `probe` allows its type. Canonical is what the caller must bind:
/// binding the path as written would mount whatever a symlink on it
/// points at instead, and it is also the only form a policy check can be
/// made on.
fn resolve_source(
    host: &dyn Host,
    service: &'static str,
    src: &Path,
    probe: fn(&dyn Host, &'static str, PathBuf) -> Result<PathBuf, LaunchError>,
) -> Result<PathBuf, LaunchError> {
    let Some(real) = host.canonicalize(src) else {
        return Err(LaunchError::MissingResource {
            service,
            path: src.to_path_buf(),
        });
    };
    probe(host, service, real)
}

/// Resolve `src` and require that it stays under `root`; both are
/// canonicalised, so a symlink cannot turn a grant inside `root` into a
/// bind of something outside it. Returns the canonical source.
fn confine(
    host: &dyn Host,
    service: &'static str,
    root: &Path,
    src: &Path,
    outside: &str,
) -> Result<PathBuf, LaunchError> {
    let root = host
        .canonicalize(root)
        .ok_or_else(|| LaunchError::MissingResource {
            service,
            path: root.to_path_buf(),
        })?;
    let real = resolve_source(host, service, src, require_exists)?;
    if !real.starts_with(&root) {
        return Err(LaunchError::BadValue {
            service,
            reason: format!("{} resolves outside {outside}", src.display()),
        });
    }
    Ok(real)
}

/// Host roots `path-share` never binds, whatever the config says. The
/// baseline owns `/proc`, `/dev`, `/etc`, `/tmp`, `/var` and `/run`;
/// `/usr` and `/opt` are already read-only mounts a phase-4 bind cannot
/// nest inside; `/home` is what the private home replaces. flatpak
/// refuses the same set in `dont_export_in` (`flatpak-exports.c`), and
/// for the same reason: a share of one of these takes the sandbox apart.
const DENIED_ROOTS: &[&str] = &[
    "/proc", "/sys", "/dev", "/etc", "/usr", "/opt", "/home", "/tmp", "/var", "/run",
];

/// Removable media, mounted here by udisks, is a real share target, so it
/// is carved out of the `/run` denial. flatpak exposes the same path
/// (`flatpak-context.c`).
const MEDIA_ROOT: &str = "/run/media";

/// Which end of a share met a reserved root: the host path it resolves
/// to, or the path inside the sandbox it would be bound at.
#[derive(Clone, Copy)]
enum End {
    /// The canonical source.
    Source,
    /// The path as written, which is where the bind lands.
    Destination,
}

/// The roots the environment names, each in resolved form as well: with a
/// symlink anywhere on the way to one of them, only the resolved form
/// matches the canonical source of a share, and only the written form
/// matches its destination. The instance store and the profile layer are
/// resolved on their own as well as under a resolved `$XDG_DATA_HOME` or
/// `$XDG_CONFIG_HOME`, since either link alone moves them. A root that
/// does not resolve is kept as written.
fn env_roots(host: &dyn Host, env: &Env) -> Vec<PathBuf> {
    let under = |dir: &Path| {
        host.canonicalize(dir)
            .unwrap_or_else(|| dir.to_path_buf())
            .join("bubbler")
    };
    let named = [
        env.home.clone(),
        env.runtime_dir.clone(),
        env.data_home.join("bubbler"),
        under(&env.data_home),
        // The user's profile layer. A sandbox that can write a profile
        // there writes the config of every instance seeded from it
        // afterwards, which is the break the instance store is denied for.
        env.config_home.join("bubbler"),
        under(&env.config_home),
    ];
    let resolved: Vec<PathBuf> = named.iter().filter_map(|p| host.canonicalize(p)).collect();
    named.into_iter().chain(resolved).collect()
}

/// The reserved root a share meets, at either end: the path is that root,
/// is inside it, or is one of its ancestors. An ancestor is refused
/// because binding it would cover the root with a mount of its own. The
/// roots the environment names are checked first and on both ends, so
/// neither the `/run/media` carve-out nor the test hook can lift them.
fn denied_root(
    host: &dyn Host,
    env: &Env,
    canonical: &Path,
    written: &Path,
) -> Option<(PathBuf, End)> {
    // Sharing the root itself is refused before anything else, so that
    // the message names `/` rather than whichever root lies under it.
    if canonical == Path::new("/") || written == Path::new("/") {
        return Some((PathBuf::from("/"), End::Source));
    }
    let roots = env_roots(host, env);
    for (path, end) in [(canonical, End::Source), (written, End::Destination)] {
        if let Some(root) = roots.iter().find(|root| nested(path, root)) {
            return Some((root.clone(), end));
        }
    }
    // A bind landing on the private home would cover what the instance
    // keeps there, whatever the host path it came from.
    if nested(written, Path::new(SANDBOX_HOME)) {
        return Some((PathBuf::from(SANDBOX_HOME), End::Destination));
    }
    fixed_root(canonical, env)
        .map(|root| (root, End::Source))
        .or_else(|| fixed_root(written, env).map(|root| (root, End::Destination)))
}

/// The fixed reserved root a path meets. `$BUBBLER_TEST_ALLOW_PATH` lifts
/// all of them for one subtree, and `/run/media` is carved out of `/run`
/// alone.
fn fixed_root(path: &Path, env: &Env) -> Option<PathBuf> {
    if let Some(allow) = env.test_allow_path.as_deref()
        && path.starts_with(allow)
    {
        return None;
    }
    // `/` is an ancestor of every root and every path is inside it, so
    // only sharing `/` itself is what the entry can mean. `denied_root`
    // already refused it; the check stays so this function stands alone.
    if path == Path::new("/") {
        return Some(PathBuf::from("/"));
    }
    let on_media = path.starts_with(MEDIA_ROOT);
    DENIED_ROOTS
        .iter()
        .map(PathBuf::from)
        .find(|root| nested(path, root) && !(on_media && root.as_path() == Path::new("/run")))
}

/// Why `path-share "<written>"` would be refused for meeting a reserved
/// root, if it would. The launcher raises the same sentence as an error
/// when it builds the argv; the linter reports it against the node, on a
/// source that need not exist yet.
pub(crate) fn reserved_reason(host: &dyn Host, env: &Env, written: &Path) -> Option<String> {
    let src = host
        .canonicalize(written)
        .unwrap_or_else(|| written.to_path_buf());
    let (root, end) = denied_root(host, env, &src, written)?;
    Some(denied_reason(written, &src, &root, end))
}

/// Why a share was refused, naming the end that met the root.
fn denied_reason(written: &Path, src: &Path, root: &Path, end: End) -> String {
    match end {
        End::Destination => format!(
            "{} would be bound over {}, which bubbler never shares",
            written.display(),
            root.display()
        ),
        End::Source => {
            let target = if src == root {
                root.display().to_string()
            } else {
                format!("{}, which overlaps {}", src.display(), root.display())
            };
            if src == written {
                format!("bubbler never shares {target}")
            } else {
                format!(
                    "{} resolves to {target}, which bubbler never shares",
                    written.display()
                )
            }
        }
    }
}

/// Whether two paths are the same or one contains the other, compared
/// component-wise so `/kioxiaa` is not inside `/kioxia`.
fn nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Every `path-share` as (position in `services`, written destination,
/// canonical source, mode), with the reserved roots and the overlap rule
/// applied. bwrap applies binds in the order given, so two shares whose
/// destinations nest would either fail (a read-only parent bound first)
/// or silently hide one another; sharing one host tree twice is refused
/// with them, so that file order stays irrelevant either way.
fn path_shares<'a>(
    services: &'a [Service],
    env: &Env,
    host: &dyn Host,
) -> Result<Vec<(usize, &'a Path, PathBuf, ShareMode)>, LaunchError> {
    let mut shares: Vec<(usize, &Path, PathBuf, ShareMode)> = Vec::new();
    for (i, s) in services.iter().enumerate() {
        let Service::PathShare { path, mode } = s else {
            continue;
        };
        let src = resolve_source(host, "path-share", path, require_dir_or_file)?;
        if let Some((root, end)) = denied_root(host, env, &src, path) {
            return Err(LaunchError::BadValue {
                service: "path-share",
                reason: denied_reason(path, &src, &root, end),
            });
        }
        shares.push((i, path.as_path(), src, *mode));
    }
    for (i, (_, a_dst, a_src, _)) in shares.iter().enumerate() {
        for (_, b_dst, b_src, _) in &shares[i + 1..] {
            let destinations = nested(a_dst, b_dst);
            if !destinations && !nested(a_src, b_src) {
                continue;
            }
            let where_ = if destinations {
                String::new()
            } else {
                format!(
                    " (they resolve to {} and {})",
                    a_src.display(),
                    b_src.display()
                )
            };
            return Err(LaunchError::BadValue {
                service: "path-share",
                reason: format!(
                    "{} and {} overlap{where_}; one share cannot contain another",
                    a_dst.display(),
                    b_dst.display()
                ),
            });
        }
    }
    Ok(shares)
}

/// Bind `$HOME/<path>` to `/home/bubbler/<path>`. The host path must exist,
/// may be of any type and must resolve inside the real home; bubbler never
/// creates directories in the real home. Resolving and binding both happen
/// by path, so a symlink swapped in between the two is not detected; that
/// is inherent to bwrap path binds.
fn home_share(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    rel: &Path,
    mode: ShareMode,
) -> Result<(), LaunchError> {
    let src = confine(
        host,
        "home-share",
        &env.home,
        &env.home.join(rel),
        "the home directory",
    )?;
    let dst = Path::new(SANDBOX_HOME).join(rel);
    match mode {
        ShareMode::ReadOnly => args.ro_bind(&src, &dst),
        ShareMode::ReadWrite => args.bind(&src, &dst),
    }
    Ok(())
}

/// Bind one host `/etc` entry read-only at `/etc/<name>`, on top of the
/// baseline allowlist. The entry must resolve inside `/etc`, so a symlink
/// there cannot pull an unrelated part of the host into the sandbox; the
/// names the sandbox generates itself were rejected by the parser.
fn etc_share(args: &mut BwrapArgs, host: &dyn Host, name: &OsStr) -> Result<(), LaunchError> {
    let etc = Path::new("/etc");
    let dst = etc.join(name);
    let src = confine(host, "etc-share", etc, &dst, "/etc")?;
    args.ro_bind(&src, &dst);
    Ok(())
}

/// Where one `app-runtime` id's directory lives, on the host and inside
/// the sandbox alike. The same path on both sides is the whole point:
/// KeePassXC, and every other user of the convention, computes
/// `$XDG_RUNTIME_DIR/app/<id>` from its own environment and would look
/// somewhere else if bubbler moved it.
pub(crate) fn app_runtime_dir(env: &Env, id: &str) -> PathBuf {
    env.runtime_dir.join("app").join(id)
}

/// Bind the shared directory of one application id at that same path.
/// Only the leaf is bound, never `app/` and never the runtime directory,
/// so no id reaches another one's directory or `bubbler/`, where every
/// instance's control socket is.
///
/// The source is not probed here: the launcher creates it and checks it
/// with `O_NOFOLLOW` right before the sandbox starts, which is the only
/// order in which the check means anything. Nothing is probed on a
/// `--dry-run` either, where no directory has been created.
fn app_runtime(env: &Env, args: &mut BwrapArgs, id: &str, mode: ShareMode) {
    let dir = app_runtime_dir(env, id);
    match mode {
        ShareMode::ReadOnly => args.ro_bind(&dir, &dir),
        ShareMode::ReadWrite => args.bind(&dir, &dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WaylandMode;
    use crate::host::fake::{self, FakeHost};
    use std::ffi::OsString;

    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Sock,
        File,
        Dir,
        Char,
        /// A directory another filesystem is mounted on.
        Mount,
    }

    use Kind::{Char, Dir, File, Mount, Sock};

    fn env() -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            config_home: "/home/han/.config".into(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: Some("wayland-1".into()),
            display: Some(":0".into()),
            xauthority: Some("/run/user/1000/Xauthority".into()),
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            dbus_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
        }
    }

    fn argv(
        services: &[Service],
        env: &Env,
        existing: &[(&str, Kind)],
    ) -> Result<Vec<String>, LaunchError> {
        argv_linked(services, env, existing, &[])
    }

    /// Services are applied with the plan the launcher would build, so a
    /// test sees the same `/.flatpak-info` the proxy would.
    fn argv_ctx<'a>(plan: &'a Option<dbus::Plan>) -> ServiceCtx<'a> {
        ServiceCtx {
            instance_runtime: "/run/user/1000/bubbler/t".into(),
            dbus: plan.as_ref(),
        }
    }

    fn argv_linked(
        services: &[Service],
        env: &Env,
        existing: &[(&str, Kind)],
        links: &[(&str, &str)],
    ) -> Result<Vec<String>, LaunchError> {
        let (file, dir, sock) = fake::types();
        let mut host = FakeHost::default();
        for (p, k) in existing {
            host = match k {
                Sock => host.with(p, sock),
                File => host.with(p, file),
                Dir => host.with(p, dir),
                Char => host.with(p, fake::char_type()),
                Mount => host.with(p, dir).mount(p),
            };
        }
        for (from, to) in links {
            host = host.link(from, to);
        }
        let plan = dbus::plan(services, "t");
        let mut args = BwrapArgs::baseline(env, Path::new("/i/home"), &host);
        apply_all(services, env, &mut args, &host, &argv_ctx(&plan))?;
        Ok(strs(&args.finish(
            &[OsString::from("x")],
            &mut crate::launcher::DryRunAlloc::default(),
        )?))
    }

    fn strs(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn has_seq(argv: &[String], seq: &[&str]) -> bool {
        argv.windows(seq.len())
            .any(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
    }

    /// The service binds alone (phase 4): what lies between the runtime
    /// directory of phase 3 and the `--clearenv` that opens phase 5.
    fn binds(argv: &[String]) -> Vec<&str> {
        let dir = argv
            .iter()
            .position(|a| a == "--dir")
            .expect("phase 3 always emits --dir");
        let env = argv
            .iter()
            .position(|a| a == "--clearenv")
            .expect("phase 5 always opens with --clearenv");
        argv[dir + 2..env].iter().map(String::as_str).collect()
    }

    #[test]
    fn wayland_binds_socket_and_sets_env() {
        let a = argv(
            &[Service::Wayland(WaylandMode::Sandboxed)],
            &env(),
            &[("/run/user/1000/wayland-1", Sock)],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/wayland-1",
                "/run/user/1000/wayland-1"
            ]
        ));
        assert!(has_seq(&a, &["--setenv", "WAYLAND_DISPLAY", "wayland-1"]));
        assert!(has_seq(&a, &["--setenv", "XDG_SESSION_TYPE", "wayland"]));
    }

    #[test]
    fn wayland_missing_socket_or_env_fails() {
        assert!(matches!(
            argv(&[Service::Wayland(WaylandMode::Sandboxed)], &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "wayland",
                ..
            })
        ));
        let mut e = env();
        e.wayland_display = None;
        assert!(matches!(
            argv(&[Service::Wayland(WaylandMode::Sandboxed)], &e, &[]),
            Err(LaunchError::MissingEnv {
                service: "wayland",
                var: "WAYLAND_DISPLAY"
            })
        ));
    }

    #[test]
    fn wayland_socket_path_of_the_wrong_type_fails() {
        for kind in [File, Dir] {
            assert!(matches!(
                argv(
                    &[Service::Wayland(WaylandMode::Sandboxed)],
                    &env(),
                    &[("/run/user/1000/wayland-1", kind)]
                ),
                Err(LaunchError::WrongType {
                    service: "wayland",
                    expected: "a socket",
                    ..
                })
            ));
        }
    }

    #[test]
    fn x11_binds_socket_and_xauthority() {
        let a = argv(
            &[Service::X11],
            &env(),
            &[
                ("/tmp/.X11-unix/X0", Sock),
                ("/run/user/1000/Xauthority", File),
            ],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &["--ro-bind", "/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0"]
        ));
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/Xauthority",
                "/home/bubbler/.Xauthority"
            ]
        ));
        assert!(has_seq(&a, &["--setenv", "DISPLAY", ":0"]));
        assert!(has_seq(
            &a,
            &["--setenv", "XAUTHORITY", "/home/bubbler/.Xauthority"]
        ));
        assert_eq!(
            a.iter()
                .filter(|s| *s == "/run/user/1000/Xauthority")
                .count(),
            1,
            "the host path is a bind source only, never visible inside"
        );
        assert!(!a.contains(&"XDG_SESSION_TYPE".to_string()));
    }

    #[test]
    fn x11_falls_back_to_home_xauthority_or_none() {
        let mut e = env();
        e.xauthority = None;
        let a = argv(
            &[Service::X11],
            &e,
            &[("/tmp/.X11-unix/X0", Sock), ("/home/han/.Xauthority", File)],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/home/han/.Xauthority",
                "/home/bubbler/.Xauthority"
            ]
        ));
        assert!(has_seq(
            &a,
            &["--setenv", "XAUTHORITY", "/home/bubbler/.Xauthority"]
        ));
        let a = argv(&[Service::X11], &e, &[("/tmp/.X11-unix/X0", Sock)]).unwrap();
        assert!(!a.contains(&"XAUTHORITY".to_string()));
    }

    #[test]
    fn x11_fallback_xauthority_that_is_a_directory_is_skipped() {
        let mut e = env();
        e.xauthority = None;
        let a = argv(
            &[Service::X11],
            &e,
            &[("/tmp/.X11-unix/X0", Sock), ("/home/han/.Xauthority", Dir)],
        )
        .unwrap();
        assert!(!a.contains(&"XAUTHORITY".to_string()));
        assert!(!a.contains(&"/home/han/.Xauthority".to_string()));
    }

    #[test]
    fn x11_set_but_missing_xauthority_fails() {
        assert!(matches!(
            argv(&[Service::X11], &env(), &[("/tmp/.X11-unix/X0", Sock)]),
            Err(LaunchError::MissingResource { service: "x11", .. })
        ));
    }

    #[test]
    fn x11_xauthority_at_a_directory_fails() {
        let mut e = env();
        e.xauthority = Some("/".into());
        assert!(matches!(
            argv(
                &[Service::X11],
                &e,
                &[("/tmp/.X11-unix/X0", Sock), ("/", Dir)]
            ),
            Err(LaunchError::WrongType {
                service: "x11",
                expected: "a regular file",
                ..
            })
        ));
    }

    #[test]
    fn x11_socket_that_is_not_a_socket_fails() {
        assert!(matches!(
            argv(&[Service::X11], &env(), &[("/tmp/.X11-unix/X0", File)]),
            Err(LaunchError::WrongType {
                service: "x11",
                expected: "a socket",
                ..
            })
        ));
    }

    #[test]
    fn wayland_display_with_a_path_is_rejected() {
        let mut e = env();
        e.wayland_display = Some("/run/user/1000/wayland-1".into());
        assert!(matches!(
            argv(
                &[Service::Wayland(WaylandMode::Sandboxed)],
                &e,
                &[("/run/user/1000/wayland-1", Sock)]
            ),
            Err(LaunchError::BadValue {
                service: "wayland",
                ..
            })
        ));
        e.wayland_display = Some("nested/wayland-1".into());
        assert!(matches!(
            argv(
                &[Service::Wayland(WaylandMode::Sandboxed)],
                &e,
                &[("/run/user/1000/nested/wayland-1", Sock)]
            ),
            Err(LaunchError::BadValue {
                service: "wayland",
                ..
            })
        ));
    }

    #[test]
    fn wayland_display_that_is_not_one_component_is_rejected() {
        for bad in [".", "..", "wayland-1/..", ""] {
            let mut e = env();
            e.wayland_display = Some(bad.into());
            assert!(
                matches!(
                    argv(
                        &[Service::Wayland(WaylandMode::Sandboxed)],
                        &e,
                        &[
                            ("/run/user/1000", Dir),
                            ("/run/user/1000/.", Dir),
                            ("/run/user/1000/..", Dir),
                        ]
                    ),
                    Err(LaunchError::BadValue {
                        service: "wayland",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn wayland_display_naming_a_directory_is_rejected() {
        let mut e = env();
        e.wayland_display = Some("dconf".into());
        assert!(matches!(
            argv(
                &[Service::Wayland(WaylandMode::Sandboxed)],
                &e,
                &[("/run/user/1000/dconf", Dir)]
            ),
            Err(LaunchError::WrongType {
                service: "wayland",
                expected: "a socket",
                ..
            })
        ));
    }

    #[test]
    fn x11_display_parsing() {
        assert_eq!(x11_display_number(OsStr::new(":0")), Some(0));
        assert_eq!(x11_display_number(OsStr::new(":10.1")), Some(10));
        assert_eq!(x11_display_number(OsStr::new("unix:2")), Some(2));
        assert_eq!(x11_display_number(OsStr::new("host:0")), None);
        assert_eq!(x11_display_number(OsStr::new(":+1")), None);
        assert_eq!(x11_display_number(OsStr::new("")), None);
        let mut e = env();
        e.display = None;
        assert!(matches!(
            argv(&[Service::X11], &e, &[]),
            Err(LaunchError::MissingEnv {
                service: "x11",
                var: "DISPLAY"
            })
        ));
    }

    #[test]
    fn wayland_and_x11_together_do_not_claim_wayland_session() {
        let a = argv(
            &[Service::Wayland(WaylandMode::Sandboxed), Service::X11],
            &env(),
            &[
                ("/run/user/1000/wayland-1", Sock),
                ("/tmp/.X11-unix/X0", Sock),
                ("/run/user/1000/Xauthority", File),
            ],
        )
        .unwrap();
        assert!(!a.contains(&"XDG_SESSION_TYPE".to_string()));
    }

    /// The one mode that keeps the host's namespace, and the one that
    /// binds the host's resolver file. Both are what `network` emitted
    /// before the isolated mode became the default, unchanged.
    #[test]
    fn network_host_shares_net_and_binds_resolv_conf() {
        let host = Service::Network(NetworkConfig {
            mode: NetworkMode::Host,
            ..NetworkConfig::default()
        });
        let a = argv(
            std::slice::from_ref(&host),
            &env(),
            &[("/etc/resolv.conf", File)],
        )
        .unwrap();
        assert_eq!(a[1], "--share-net");
        assert!(has_seq(
            &a,
            &["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]
        ));
        assert!(matches!(
            argv(std::slice::from_ref(&host), &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "network",
                ..
            })
        ));
    }

    /// The isolated mode is the baseline's own namespace: nothing of
    /// bwrap beyond a resolver file, and no host path to depend on.
    #[test]
    fn isolated_network_generates_a_resolver_and_shares_nothing() {
        let a = argv(
            &[Service::Network(NetworkConfig::default())],
            &env(),
            &[("/etc/resolv.conf", File)],
        )
        .unwrap();
        assert!(!a.contains(&"--share-net".to_string()), "{a:?}");
        assert!(
            !has_seq(&a, &["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]),
            "{a:?}"
        );
        assert!(has_seq(&a, &["--perms", "0644", "--ro-bind-data"]), "{a:?}");
        // And it needs nothing of the host: an empty host tree is enough.
        assert!(argv(&[Service::Network(NetworkConfig::default())], &env(), &[]).is_ok());
    }

    /// `dns` replaces the resolver file in every mode, so a sandbox on
    /// the host's namespace never sees the host's own resolver either.
    #[test]
    fn dns_children_replace_the_resolver_file_under_host_too() {
        let svc = Service::Network(NetworkConfig {
            mode: NetworkMode::Host,
            dns: vec![std::net::IpAddr::from([1, 1, 1, 1])],
            ..NetworkConfig::default()
        });
        let a = argv(std::slice::from_ref(&svc), &env(), &[]).unwrap();
        assert!(a.contains(&"--share-net".to_string()), "{a:?}");
        assert!(has_seq(&a, &["--perms", "0644", "--ro-bind-data"]), "{a:?}");
        assert!(
            !has_seq(&a, &["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]),
            "{a:?}"
        );
    }

    /// `none` is the baseline as it stands: the node grants nothing, and
    /// emits nothing.
    #[test]
    fn network_none_emits_nothing() {
        let plain = argv(&[], &env(), &[]).unwrap();
        let none = argv(
            &[Service::Network(NetworkConfig {
                mode: NetworkMode::None,
                ..NetworkConfig::default()
            })],
            &env(),
            &[],
        )
        .unwrap();
        assert_eq!(plain, none);
    }

    #[test]
    fn home_share_maps_into_sandbox_home() {
        let svcs = [
            Service::HomeShare {
                path: "Downloads".into(),
                mode: ShareMode::ReadOnly,
            },
            Service::HomeShare {
                path: "Projects/x".into(),
                mode: ShareMode::ReadWrite,
            },
        ];
        let a = argv(
            &svcs,
            &env(),
            &[("/home/han/Downloads", Dir), ("/home/han/Projects/x", Dir)],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/home/han/Downloads",
                "/home/bubbler/Downloads"
            ]
        ));
        assert!(has_seq(
            &a,
            &["--bind", "/home/han/Projects/x", "/home/bubbler/Projects/x"]
        ));
    }

    #[test]
    fn home_share_accepts_any_type_but_needs_the_source() {
        let svcs = [Service::HomeShare {
            path: "notes.txt".into(),
            mode: ShareMode::ReadOnly,
        }];
        let a = argv(&svcs, &env(), &[("/home/han/notes.txt", File)]).unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/home/han/notes.txt",
                "/home/bubbler/notes.txt"
            ]
        ));
    }

    #[test]
    fn home_share_missing_source_fails() {
        let svcs = [Service::HomeShare {
            path: "Nope".into(),
            mode: ShareMode::ReadOnly,
        }];
        assert!(matches!(
            argv(&svcs, &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "home-share",
                ..
            })
        ));
    }

    #[test]
    fn home_share_through_a_symlink_out_of_the_home_is_refused() {
        let svcs = [Service::HomeShare {
            path: "RootLink".into(),
            mode: ShareMode::ReadWrite,
        }];
        let r = argv_linked(
            &svcs,
            &env(),
            &[("/home/han/RootLink", Dir), ("/", Dir)],
            &[("/home/han/RootLink", "/")],
        );
        assert!(
            matches!(&r, Err(LaunchError::BadValue { service: "home-share", reason }) if reason.contains("outside the home directory")),
            "{r:?}"
        );
    }

    #[test]
    fn home_share_through_a_symlink_inside_the_home_binds_the_target() {
        let svcs = [Service::HomeShare {
            path: "Downloads".into(),
            mode: ShareMode::ReadOnly,
        }];
        let a = argv_linked(
            &svcs,
            &env(),
            &[("/home/han/Downloads", Dir), ("/home/han/dl", Dir)],
            &[("/home/han/Downloads", "/home/han/dl")],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &["--ro-bind", "/home/han/dl", "/home/bubbler/Downloads"]
        ));
    }

    #[test]
    fn home_share_needs_a_home_that_resolves() {
        let svcs = [Service::HomeShare {
            path: "Downloads".into(),
            mode: ShareMode::ReadOnly,
        }];
        let (_, dir, _) = fake::types();
        let host = FakeHost::default().with("/home/han/Downloads", dir);
        struct NoHome(FakeHost);
        impl Host for NoHome {
            fn file_type(&self, p: &Path) -> Option<FileType> {
                self.0.file_type(p)
            }
            fn list_dir(&self, p: &Path) -> Vec<OsString> {
                self.0.list_dir(p)
            }
            fn canonicalize(&self, _: &Path) -> Option<PathBuf> {
                None
            }
            fn is_mountpoint(&self, p: &Path) -> Option<bool> {
                self.0.is_mountpoint(p)
            }
        }
        let e = env();
        let mut args = BwrapArgs::baseline(&e, Path::new("/i/home"), &host);
        assert!(matches!(
            apply_all(&svcs, &e, &mut args, &NoHome(host), &argv_ctx(&None)),
            Err(LaunchError::MissingResource {
                service: "home-share",
                ..
            })
        ));
    }

    fn share(path: &str, mode: ShareMode) -> Service {
        Service::PathShare {
            path: path.into(),
            mode,
        }
    }

    #[test]
    fn path_share_refuses_every_reserved_root() {
        let mut e = env();
        // Off the home so the ancestors of the instance store are denied
        // by that root alone, not by `/home`.
        e.data_home = "/kioxia/xdg".into();
        // Each row is (share, the root that must stop it): a fixed root, or
        // the more specific one the environment names where there is one.
        let cases: &[(&str, &str)] = &[
            ("/", "/"),
            ("/proc", "/proc"),
            ("/proc/1", "/proc"),
            ("/sys", "/sys"),
            ("/sys/class", "/sys"),
            ("/dev", "/dev"),
            ("/dev/dri", "/dev"),
            ("/etc", "/etc"),
            ("/etc/ssl", "/etc"),
            ("/usr", "/usr"),
            ("/usr/share", "/usr"),
            ("/opt", "/opt"),
            ("/opt/thing", "/opt"),
            ("/home", "/home/han"),
            ("/home/other", "/home"),
            ("/home/han", "/home/han"),
            ("/home/han/Downloads", "/home/han"),
            ("/tmp", "/tmp"),
            ("/tmp/x", "/tmp"),
            ("/var", "/var"),
            ("/var/lib", "/var"),
            ("/run", "/run/user/1000"),
            ("/run/user", "/run/user/1000"),
            ("/run/user/1000", "/run/user/1000"),
            ("/run/user/1000/bus", "/run/user/1000"),
            ("/kioxia", "/kioxia/xdg/bubbler"),
            ("/kioxia/xdg", "/kioxia/xdg/bubbler"),
            ("/kioxia/xdg/bubbler", "/kioxia/xdg/bubbler"),
            ("/kioxia/xdg/bubbler/instances/t", "/kioxia/xdg/bubbler"),
        ];
        for (path, root) in cases {
            let want = if path == root {
                format!("bubbler never shares {root}")
            } else {
                format!("bubbler never shares {path}, which overlaps {root}")
            };
            let r = argv(&[share(path, ShareMode::ReadOnly)], &e, &[(path, Dir)]);
            assert!(
                matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                    if *reason == want),
                "{path} should be refused with `{want}`, got {r:?}"
            );
        }
    }

    #[test]
    fn path_share_resolves_the_instance_store_itself() {
        for path in ["/kioxia", "/kioxia/bubbler", "/kioxia/bubbler/instances"] {
            let r = argv_linked(
                &[share(path, ShareMode::ReadWrite)],
                &env(),
                &[(path, Dir)],
                &[("/home/han/.local/share/bubbler", "/kioxia/bubbler")],
            );
            assert!(
                matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                    if reason.contains("/kioxia/bubbler")),
                "{path}: {r:?}"
            );
        }
    }

    #[test]
    fn path_share_allows_mountpoints_and_removable_media() {
        for path in [
            "/kioxia/Steam",
            "/kioxia",
            "/mnt/x",
            "/media/x",
            "/srv/x",
            "/run/media",
            "/run/media/han/usb",
        ] {
            let a = argv(&[share(path, ShareMode::ReadOnly)], &env(), &[(path, Dir)])
                .unwrap_or_else(|e| panic!("{path} should be allowed, got {e:?}"));
            assert!(has_seq(&a, &["--ro-bind", path, path]), "{path}: {a:?}");
        }
    }

    #[test]
    fn path_share_binds_the_canonical_source_at_the_written_path() {
        let a = argv_linked(
            &[share("/kioxia/Steam", ShareMode::ReadWrite)],
            &env(),
            &[("/kioxia/Steam", Dir), ("/mnt/big/steam", Dir)],
            &[("/kioxia/Steam", "/mnt/big/steam")],
        )
        .unwrap();
        assert!(has_seq(&a, &["--bind", "/mnt/big/steam", "/kioxia/Steam"]));
    }

    #[test]
    fn path_share_through_a_symlink_into_a_reserved_root_is_refused() {
        let r = argv_linked(
            &[share("/kioxia/link", ShareMode::ReadOnly)],
            &env(),
            &[("/kioxia/link", Dir), ("/etc", Dir)],
            &[("/kioxia/link", "/etc")],
        );
        assert!(
            matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                if reason.contains("/etc")),
            "{r:?}"
        );
    }

    #[test]
    fn path_share_missing_source_fails() {
        assert!(matches!(
            argv(&[share("/kioxia/Steam", ShareMode::ReadOnly)], &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "path-share",
                ..
            })
        ));
    }

    #[test]
    fn path_share_accepts_a_regular_file() {
        let a = argv(
            &[share("/kioxia/notes.txt", ShareMode::ReadOnly)],
            &env(),
            &[("/kioxia/notes.txt", File)],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &["--ro-bind", "/kioxia/notes.txt", "/kioxia/notes.txt"]
        ));
    }

    #[test]
    fn path_share_compares_the_environment_roots_resolved() {
        let mut e = env();
        e.home = "/link/home".into();
        e.data_home = "/link/xdg".into();
        for path in ["/real/home", "/real/home/Downloads", "/real/xdg/bubbler"] {
            let r = argv_linked(
                &[share(path, ShareMode::ReadWrite)],
                &e,
                &[(path, Dir)],
                &[("/link/home", "/real/home"), ("/link/xdg", "/real/xdg")],
            );
            assert!(
                matches!(
                    &r,
                    Err(LaunchError::BadValue {
                        service: "path-share",
                        ..
                    })
                ),
                "{path}: {r:?}"
            );
        }
    }

    /// The user's profile layer lives in `$XDG_CONFIG_HOME/bubbler`, and
    /// a sandbox that can write a profile there writes the config of
    /// every instance seeded from it afterwards — the same total break
    /// as reaching the instance store. Denied wherever the environment
    /// puts it, as written and as resolved.
    #[test]
    fn path_share_refuses_the_profile_layer_under_a_relocated_config_home() {
        let mut e = env();
        // Outside the home, so `/home/han` is not what stops these.
        e.config_home = "/kioxia/cfg".into();
        let cases: &[(&str, Kind)] = &[
            ("/kioxia", Dir),
            ("/kioxia/cfg", Dir),
            ("/kioxia/cfg/bubbler", Dir),
            ("/kioxia/cfg/bubbler/profiles/firefox.kdl", File),
        ];
        for (path, kind) in cases {
            let r = argv(&[share(path, ShareMode::ReadOnly)], &e, &[(path, *kind)]);
            assert!(
                matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                    if reason.contains("/kioxia/cfg/bubbler")),
                "{path}: {r:?}"
            );
        }
        // A neighbour of the layer is still shareable: the root is the
        // layer, not the directory the environment happens to name.
        let a = argv(
            &[share("/kioxia/cfg/notes", ShareMode::ReadOnly)],
            &e,
            &[("/kioxia/cfg/notes", Dir)],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &["--ro-bind", "/kioxia/cfg/notes", "/kioxia/cfg/notes"]
        ));

        // And with a symlink on the way to it, the resolved source is
        // compared too, the way the instance store is.
        e.config_home = "/link/cfg".into();
        let r = argv_linked(
            &[share("/real/cfg/bubbler", ShareMode::ReadWrite)],
            &e,
            &[("/real/cfg/bubbler", Dir)],
            &[("/link/cfg", "/real/cfg")],
        );
        assert!(
            matches!(
                &r,
                Err(LaunchError::BadValue {
                    service: "path-share",
                    ..
                })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn path_share_environment_roots_outlast_the_carve_out_and_the_hook() {
        let mut e = env();
        e.data_home = "/run/media/disk/xdg".into();
        for hook in [None, Some(PathBuf::from("/run/media/disk"))] {
            e.test_allow_path = hook.clone();
            let r = argv(
                &[share("/run/media/disk", ShareMode::ReadWrite)],
                &e,
                &[("/run/media/disk", Dir)],
            );
            assert!(
                matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                    if reason.contains("/run/media/disk/xdg/bubbler")),
                "hook {hook:?}: {r:?}"
            );
        }
        e.test_allow_path = None;
        let a = argv(
            &[share("/run/media/other", ShareMode::ReadOnly)],
            &e,
            &[("/run/media/other", Dir)],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &["--ro-bind", "/run/media/other", "/run/media/other"]
        ));
    }

    #[test]
    fn path_share_refuses_a_destination_on_a_reserved_root() {
        let mut e = env();
        // The hook lifts the fixed roots for `/home`, so what is left to
        // refuse these is the destination check itself.
        e.test_allow_path = Some("/home".into());
        for dst in ["/home/bubbler/x", "/home/han/x"] {
            let r = argv_linked(
                &[share(dst, ShareMode::ReadWrite)],
                &e,
                &[(dst, Dir), ("/kioxia/data", Dir)],
                &[(dst, "/kioxia/data")],
            );
            assert!(
                matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                    if reason.contains(dst)),
                "{dst}: {r:?}"
            );
        }
    }

    #[test]
    fn path_share_refuses_a_source_that_is_not_a_tree_or_a_file() {
        let r = argv(
            &[share("/kioxia/sock", ShareMode::ReadOnly)],
            &env(),
            &[("/kioxia/sock", Sock)],
        );
        assert!(
            matches!(
                &r,
                Err(LaunchError::WrongType {
                    service: "path-share",
                    expected: "a directory or a regular file",
                    ..
                })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn path_share_test_hook_allows_exactly_one_extra_root() {
        let mut e = env();
        e.test_allow_path = Some("/tmp/bubbler-test".into());
        for path in ["/tmp/bubbler-test", "/tmp/bubbler-test/data"] {
            let a = argv(&[share(path, ShareMode::ReadWrite)], &e, &[(path, Dir)])
                .unwrap_or_else(|err| panic!("{path} should be allowed, got {err:?}"));
            assert!(has_seq(&a, &["--bind", path, path]), "{path}: {a:?}");
        }
        for path in ["/tmp/other", "/tmp", "/etc"] {
            let r = argv(&[share(path, ShareMode::ReadOnly)], &e, &[(path, Dir)]);
            assert!(
                matches!(&r, Err(LaunchError::BadValue { .. })),
                "{path}: {r:?}"
            );
        }
    }

    #[test]
    fn path_share_overlapping_shares_are_refused() {
        let both = |a: &str, b: &str| {
            argv(
                &[
                    share(a, ShareMode::ReadOnly),
                    share(b, ShareMode::ReadWrite),
                ],
                &env(),
                &[(a, Dir), (b, Dir)],
            )
        };
        for (a, b) in [
            ("/kioxia/Steam", "/kioxia/Steam"),
            ("/kioxia", "/kioxia/Steam"),
            ("/kioxia/Steam", "/kioxia"),
        ] {
            let r = both(a, b);
            assert!(
                matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                    if reason.contains(a) && reason.contains(b)),
                "{a} and {b}: {r:?}"
            );
        }
        assert!(both("/kioxia/a", "/kioxia/b").is_ok());
        assert!(both("/kioxia/a", "/kioxiaa").is_ok());
    }

    #[test]
    fn path_share_overlap_is_checked_on_the_resolved_source_too() {
        let r = argv_linked(
            &[
                share("/mnt/link", ShareMode::ReadOnly),
                share("/kioxia/Steam", ShareMode::ReadOnly),
            ],
            &env(),
            &[("/mnt/link", Dir), ("/kioxia/Steam", Dir)],
            &[("/mnt/link", "/kioxia/Steam")],
        );
        assert!(
            matches!(&r, Err(LaunchError::BadValue { service: "path-share", reason })
                if reason.contains("/mnt/link") && reason.contains("/kioxia/Steam")),
            "{r:?}"
        );
    }

    #[test]
    fn etc_share_through_a_symlink_out_of_etc_is_refused() {
        let r = argv_linked(
            &[Service::EtcShare {
                name: "escape".into(),
            }],
            &env(),
            &[("/etc/escape", Dir), ("/home/han", Dir)],
            &[("/etc/escape", "/home/han")],
        );
        assert!(
            matches!(&r, Err(LaunchError::BadValue { service: "etc-share", reason }) if reason.contains("outside")),
            "{r:?}"
        );
    }

    #[test]
    fn etc_share_through_a_symlink_inside_etc_binds_the_target() {
        let a = argv_linked(
            &[Service::EtcShare { name: "foo".into() }],
            &env(),
            &[("/etc/foo", Dir), ("/etc/bar", Dir)],
            &[("/etc/foo", "/etc/bar")],
        )
        .unwrap();
        assert!(has_seq(&a, &["--ro-bind", "/etc/bar", "/etc/foo"]));
    }

    #[test]
    fn dri_binds_devices_and_pci_roots() {
        let a = argv(
            &[Service::Dri],
            &env(),
            &[
                ("/dev/dri", Dir),
                ("/sys/dev/char", Dir),
                ("/sys/devices/system/cpu", Dir),
                ("/sys/devices/pci0000:00", Dir),
                ("/sys/devices/pci0000:40", Dir),
                ("/sys/devices/virtual", Dir),
            ],
        )
        .unwrap();
        assert!(has_seq(&a, &["--dev-bind", "/dev/dri", "/dev/dri"]));
        assert!(has_seq(
            &a,
            &["--ro-bind", "/sys/dev/char", "/sys/dev/char"]
        ));
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/sys/devices/system/cpu",
                "/sys/devices/system/cpu"
            ]
        ));
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/sys/devices/pci0000:00",
                "/sys/devices/pci0000:00"
            ]
        ));
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/sys/devices/pci0000:40",
                "/sys/devices/pci0000:40"
            ]
        ));
        assert!(!a.contains(&"/sys/devices/virtual".to_string()));
        assert!(!a.contains(&"/sys/devices".to_string()));
    }

    #[test]
    fn dri_binds_the_drm_class_directory_after_the_pci_roots() {
        let host = &[
            ("/dev/dri", Dir),
            ("/sys/dev/char", Dir),
            ("/sys/devices/system/cpu", Dir),
            ("/sys/devices/pci0000:00", Dir),
            ("/sys/class/drm", Dir),
        ];
        let a = argv(&[Service::Dri], &env(), host).unwrap();
        // Its entries are relative symlinks into the PCI roots, so it has
        // to come after them for bwrap to resolve them.
        let pci = seq_at(
            &a,
            &[
                "--ro-bind",
                "/sys/devices/pci0000:00",
                "/sys/devices/pci0000:00",
            ],
        )
        .expect("dri binds the PCI root");
        let drm = seq_at(&a, &["--ro-bind", "/sys/class/drm", "/sys/class/drm"])
            .expect("dri binds the drm class directory");
        assert!(pci < drm, "{a:?}");

        // A host without it is not an error: the class directory holds
        // nothing but those symlinks and `version`.
        let without = argv(&[Service::Dri], &env(), &host[..4]).unwrap();
        assert!(
            !without.contains(&"/sys/class/drm".to_string()),
            "{without:?}"
        );
    }

    #[test]
    fn dri_binds_the_nvidia_nodes_and_the_module_directories() {
        let a = argv(
            &[Service::Dri],
            &env(),
            &[
                ("/dev/dri", Dir),
                ("/sys/dev/char", Dir),
                ("/sys/devices/system/cpu", Dir),
                ("/sys/devices/pci0000:00", Dir),
                ("/dev/nvidia0", Char),
                ("/dev/nvidiactl", Char),
                ("/dev/nvidia-modeset", Char),
                ("/dev/nvidia-uvm", Char),
                ("/dev/nvidia-uvm-tools", Char),
                ("/dev/nvidia-caps", Dir),
                ("/sys/module/nvidia", Dir),
                ("/sys/module/nvidia_drm", Dir),
                ("/sys/module/nvidia_uvm", Dir),
                ("/sys/module/amdgpu", Dir),
            ],
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            vec![
                "--dev-bind",
                "/dev/dri",
                "/dev/dri",
                "--ro-bind",
                "/sys/dev/char",
                "/sys/dev/char",
                "--ro-bind",
                "/sys/devices/system/cpu",
                "/sys/devices/system/cpu",
                "--ro-bind",
                "/sys/devices/pci0000:00",
                "/sys/devices/pci0000:00",
                "--dev-bind",
                "/dev/nvidia-modeset",
                "/dev/nvidia-modeset",
                "--dev-bind",
                "/dev/nvidia-uvm",
                "/dev/nvidia-uvm",
                "--dev-bind",
                "/dev/nvidia-uvm-tools",
                "/dev/nvidia-uvm-tools",
                "--dev-bind",
                "/dev/nvidia0",
                "/dev/nvidia0",
                "--dev-bind",
                "/dev/nvidiactl",
                "/dev/nvidiactl",
                "--ro-bind",
                "/sys/module/nvidia",
                "/sys/module/nvidia",
                "--ro-bind",
                "/sys/module/nvidia_drm",
                "/sys/module/nvidia_drm",
                "--ro-bind",
                "/sys/module/nvidia_uvm",
                "/sys/module/nvidia_uvm",
            ],
            "the /dev/nvidia-caps directory and unrelated module directories stay out"
        );
    }

    #[test]
    fn dri_adds_nothing_on_a_host_without_the_nvidia_stack() {
        let a = argv(
            &[Service::Dri],
            &env(),
            &[
                ("/dev/dri", Dir),
                ("/sys/dev/char", Dir),
                ("/sys/devices/system/cpu", Dir),
                ("/sys/devices/pci0000:00", Dir),
                ("/sys/module/amdgpu", Dir),
                // A directory named like a node is not one.
                ("/dev/nvidia-caps", Dir),
            ],
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            vec![
                "--dev-bind",
                "/dev/dri",
                "/dev/dri",
                "--ro-bind",
                "/sys/dev/char",
                "/sys/dev/char",
                "--ro-bind",
                "/sys/devices/system/cpu",
                "/sys/devices/system/cpu",
                "--ro-bind",
                "/sys/devices/pci0000:00",
                "/sys/devices/pci0000:00",
            ]
        );
    }

    #[test]
    fn dri_requires_dev_dri_directory_and_a_pci_root() {
        assert!(matches!(
            argv(&[Service::Dri], &env(), &[("/dev/dri", File)]),
            Err(LaunchError::WrongType {
                service: "dri",
                expected: "a directory",
                ..
            })
        ));
        assert!(matches!(
            argv(
                &[Service::Dri],
                &env(),
                &[
                    ("/dev/dri", Dir),
                    ("/sys/dev/char", Dir),
                    ("/sys/devices/system/cpu", Dir),
                    ("/sys/devices/pci0000:00", File),
                ]
            ),
            Err(LaunchError::MissingResource { service: "dri", .. })
        ));
    }

    /// A host with two cameras: the V4L2 nodes, the media controller
    /// that comes with a UVC device, the persistent-name directory udev
    /// fills, and the two `/sys` entries that name them.
    fn camera_host() -> Vec<(&'static str, Kind)> {
        vec![
            ("/dev/media0", Char),
            ("/dev/video0", Char),
            ("/dev/video1", Char),
            // A name is not a node, and neither of these is bound.
            ("/dev/videodev", Dir),
            ("/dev/mediahub", File),
            ("/dev/v4l", Dir),
            ("/sys/class/video4linux", Dir),
            ("/sys/bus/media", Dir),
            ("/run/udev", Dir),
        ]
    }

    /// The `dbus` and `portals` a `camera` grant requires.
    fn camera_base() -> Vec<Service> {
        vec![Service::Dbus { rules: vec![] }, Service::Portals]
    }

    /// The binds a `camera` node adds on top of the grants it requires,
    /// so a test names what that node emitted and nothing else.
    fn camera_binds(nodes: bool, existing: &[(&str, Kind)]) -> Result<Vec<String>, LaunchError> {
        let base_argv = argv(&camera_base(), &env(), existing)?;
        let mut with = camera_base();
        with.push(Service::Camera { nodes });
        let full_argv = argv(&with, &env(), existing)?;
        let base = binds(&base_argv);
        let full = binds(&full_argv);
        assert!(
            full.starts_with(&base),
            "a camera bind landed before the grants it requires: {full:?}"
        );
        Ok(full[base.len()..].iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn camera_nodes_bind_the_device_nodes_and_the_sysfs_that_names_them() {
        assert_eq!(
            camera_binds(true, &camera_host()).unwrap(),
            [
                "--dev-bind-try",
                "/dev/media0",
                "/dev/media0",
                "--dev-bind-try",
                "/dev/video0",
                "/dev/video0",
                "--dev-bind-try",
                "/dev/video1",
                "/dev/video1",
                // Relative symlinks onto the nodes above, so this comes
                // after them rather than before.
                "--ro-bind",
                "/dev/v4l",
                "/dev/v4l",
                "--ro-bind",
                "/sys/class/video4linux",
                "/sys/class/video4linux",
                "--ro-bind",
                "/sys/bus/media",
                "/sys/bus/media",
                "--ro-bind",
                "/run/udev",
                "/run/udev",
            ]
        );
    }

    #[test]
    fn a_bare_camera_binds_nothing_even_where_the_host_has_a_camera() {
        // The whole grant is the portal on the bus, which is rules and
        // not arguments: the sandbox never sees a device node.
        assert!(
            camera_binds(false, &camera_host()).unwrap().is_empty(),
            "a bare camera grant reached the filesystem"
        );
    }

    #[test]
    fn camera_nodes_on_a_host_with_no_camera_is_not_a_failed_launch() {
        // Emit-when-present: a host with no camera has no node, no class
        // directory and, without systemd-udevd, no database either.
        assert!(camera_binds(true, &[]).unwrap().is_empty());
        // The directories the host does have are still bound.
        assert_eq!(
            camera_binds(true, &[("/sys/bus/media", Dir), ("/run/udev", Dir)]).unwrap(),
            [
                "--ro-bind",
                "/sys/bus/media",
                "/sys/bus/media",
                "--ro-bind",
                "/run/udev",
                "/run/udev",
            ]
        );
    }

    #[test]
    fn camera_refuses_a_path_that_is_not_a_directory() {
        for path in [
            "/dev/v4l",
            "/sys/class/video4linux",
            "/sys/bus/media",
            "/run/udev",
        ] {
            assert!(
                matches!(
                    camera_binds(true, &[(path, File)]),
                    Err(LaunchError::WrongType {
                        service: "camera",
                        expected: "a directory",
                        ..
                    })
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn camera_without_portals_is_refused_rather_than_downgraded() {
        // The parser refuses that config, so this is the backstop for a
        // caller building an `InstanceConfig` by hand: without
        // `/.flatpak-info` the portal reads the sandbox as an ordinary
        // process and the permission it stores is everyone's.
        for nodes in [false, true] {
            assert!(
                matches!(
                    argv(&[Service::Camera { nodes }], &env(), &camera_host()),
                    Err(LaunchError::BadValue {
                        service: "camera",
                        ..
                    })
                ),
                "nodes={nodes}"
            );
        }
    }

    #[test]
    fn camera_leaves_the_udev_database_to_gamepad_where_both_are_granted() {
        let mut services = camera_base();
        services.push(Service::Gamepad {
            hidraw: false,
            uinput: false,
        });
        services.push(Service::Camera { nodes: true });
        let mut host = camera_host();
        host.extend(gamepad_host());
        let a = argv(&services, &env(), &host).unwrap();
        // One database, one mount: `gamepad` binds it after the loop, so
        // `camera` leaves it to that node rather than mounting it twice.
        assert_eq!(
            binds(&a).iter().filter(|b| **b == "/run/udev").count(),
            2,
            "{:?}",
            binds(&a)
        );
        assert!(has_seq(&a, &["--ro-bind", "/dev/v4l", "/dev/v4l"]));
    }

    /// Where `seq` starts in `argv`, for the tests that care which of two
    /// binds bwrap applies first.
    fn seq_at(argv: &[String], seq: &[&str]) -> Option<usize> {
        argv.windows(seq.len())
            .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
    }

    /// A `gamepad` grant with the two device-class properties as given.
    fn pad(hidraw: bool, uinput: bool) -> Service {
        Service::Gamepad { hidraw, uinput }
    }

    fn gamepad_host() -> Vec<(&'static str, Kind)> {
        vec![
            ("/dev/input", Dir),
            ("/sys/class/input", Dir),
            ("/sys/devices", Dir),
            ("/run/udev", Dir),
        ]
    }

    #[test]
    fn gamepad_binds_the_input_directory_and_the_sysfs_around_it() {
        let a = argv(&[pad(false, false)], &env(), &gamepad_host()).unwrap();
        assert!(has_seq(&a, &["--dev-bind", "/dev/input", "/dev/input"]));
        assert!(has_seq(
            &a,
            &["--ro-bind", "/sys/class/input", "/sys/class/input"]
        ));
        assert!(has_seq(&a, &["--ro-bind", "/sys/devices", "/sys/devices"]));
        assert!(has_seq(&a, &["--ro-bind", "/run/udev", "/run/udev"]));
        // Writing to `/dev/uinput` is synthetic input into the host session.
        assert!(!a.iter().any(|s| s.contains("uinput")), "{a:?}");
    }

    #[test]
    fn gamepad_without_a_udev_database_still_builds() {
        let host: Vec<_> = gamepad_host()
            .into_iter()
            .filter(|(p, _)| *p != "/run/udev")
            .collect();
        let a = argv(&[pad(false, false)], &env(), &host).unwrap();
        assert!(has_seq(&a, &["--dev-bind", "/dev/input", "/dev/input"]));
        assert!(!a.iter().any(|s| s.contains("udev")), "{a:?}");
    }

    #[test]
    fn gamepad_refuses_a_source_that_is_not_a_directory() {
        for wrong in [
            "/dev/input",
            "/sys/class/input",
            "/sys/devices",
            "/run/udev",
        ] {
            let host: Vec<_> = gamepad_host()
                .into_iter()
                .map(|(p, k)| if p == wrong { (p, File) } else { (p, k) })
                .collect();
            assert!(
                matches!(
                    argv(&[pad(false, false)], &env(), &host),
                    Err(LaunchError::WrongType {
                        service: "gamepad",
                        expected: "a directory",
                        ..
                    })
                ),
                "{wrong}"
            );
        }
        let host: Vec<_> = gamepad_host()
            .into_iter()
            .filter(|(p, _)| *p != "/sys/class/input")
            .collect();
        assert!(matches!(
            argv(&[pad(false, false)], &env(), &host),
            Err(LaunchError::MissingResource {
                service: "gamepad",
                ..
            })
        ));
    }

    #[test]
    fn gamepad_hidraw_binds_the_character_nodes_it_finds_in_order() {
        let mut host = gamepad_host();
        host.extend([
            ("/dev/hidraw3", Char),
            ("/dev/hidraw0", Char),
            ("/dev/hidraw7", Char),
            // Neither is a device node, however the name reads.
            ("/dev/hidrawdir", Dir),
            ("/dev/hidraw-note", File),
            ("/sys/class/hidraw", Dir),
        ]);
        let a = argv(&[pad(true, false)], &env(), &host).unwrap();
        let at = |n: &str| {
            seq_at(&a, &["--dev-bind-try", n, n])
                .unwrap_or_else(|| panic!("{n} is not bound: {a:?}"))
        };
        assert!(at("/dev/hidraw0") < at("/dev/hidraw3"), "{a:?}");
        assert!(at("/dev/hidraw3") < at("/dev/hidraw7"), "{a:?}");
        assert!(has_seq(
            &a,
            &["--ro-bind", "/sys/class/hidraw", "/sys/class/hidraw"]
        ));
        assert!(!a.iter().any(|s| s.contains("hidrawdir")), "{a:?}");
        assert!(!a.iter().any(|s| s.contains("hidraw-note")), "{a:?}");
        assert!(!a.iter().any(|s| s.contains("uinput")), "{a:?}");
        // The property is what adds them: the bare grant on this same
        // host binds no hidraw node at all.
        let bare = argv(&[pad(false, false)], &env(), &host).unwrap();
        assert!(!bare.iter().any(|s| s.contains("hidraw")), "{bare:?}");
    }

    #[test]
    fn gamepad_hidraw_on_a_host_with_no_hid_devices_still_builds() {
        // Nodes come and go with the hardware, so an empty glob is a host
        // with nothing plugged in, not a broken config.
        let a = argv(&[pad(true, false)], &env(), &gamepad_host()).unwrap();
        assert!(!a.iter().any(|s| s.contains("hidraw")), "{a:?}");
        let mut host = gamepad_host();
        host.push(("/sys/class/hidraw", File));
        assert!(matches!(
            argv(&[pad(true, false)], &env(), &host),
            Err(LaunchError::WrongType {
                service: "gamepad",
                expected: "a directory",
                ..
            })
        ));
    }

    /// The `/dev/hidraw*` nodes a host with HID devices has.
    fn hidraw_host() -> Vec<(&'static str, Kind)> {
        vec![
            ("/dev/hidraw3", Char),
            ("/dev/hidraw0", Char),
            ("/sys/class/hidraw", Dir),
        ]
    }

    #[test]
    fn the_bare_hidraw_grant_binds_the_nodes_without_the_input_tree() {
        let a = argv(&[Service::Hidraw], &env(), &hidraw_host()).unwrap();
        assert!(has_seq(
            &a,
            &["--dev-bind-try", "/dev/hidraw0", "/dev/hidraw0"]
        ));
        assert!(has_seq(
            &a,
            &["--dev-bind-try", "/dev/hidraw3", "/dev/hidraw3"]
        ));
        assert!(has_seq(
            &a,
            &["--ro-bind", "/sys/class/hidraw", "/sys/class/hidraw"]
        ));
        // The whole point of the grant: no keyboards, no `/sys/devices`.
        assert!(!a.iter().any(|s| s.contains("/dev/input")), "{a:?}");
        assert!(!a.iter().any(|s| s.contains("/sys/devices")), "{a:?}");
    }

    #[test]
    fn hidraw_and_the_gamepad_property_are_the_same_grant_bound_once() {
        let mut host = gamepad_host();
        host.extend(hidraw_host());
        let bare = argv(&[pad(false, false), Service::Hidraw], &env(), &host).unwrap();
        let prop = argv(&[pad(true, false)], &env(), &host).unwrap();
        assert_eq!(bare, prop);
        // Written both ways in one config the nodes are bound once, not
        // twice: two `--dev-bind-try` of one node would be a second
        // mount over the first.
        let both = argv(&[pad(true, false), Service::Hidraw], &env(), &host).unwrap();
        assert_eq!(both, prop);
        assert_eq!(
            both.iter().filter(|s| *s == "/dev/hidraw0").count(),
            2,
            "{both:?}"
        );
    }

    #[test]
    fn the_bare_hidraw_grant_names_itself_when_the_sysfs_class_is_wrong() {
        // The error names the node the user wrote, so `hidraw` and
        // `gamepad hidraw=#true` each point at their own line.
        assert!(matches!(
            argv(&[Service::Hidraw], &env(), &[("/sys/class/hidraw", File)]),
            Err(LaunchError::WrongType {
                service: "hidraw",
                expected: "a directory",
                ..
            })
        ));
    }

    #[test]
    fn gamepad_uinput_binds_the_injection_node_only_when_asked_for() {
        let mut host = gamepad_host();
        host.push(("/dev/uinput", Char));
        let a = argv(&[pad(false, true)], &env(), &host).unwrap();
        assert!(has_seq(&a, &["--dev-bind", "/dev/uinput", "/dev/uinput"]));
        let bare = argv(&[pad(false, false)], &env(), &host).unwrap();
        assert!(!bare.iter().any(|s| s.contains("uinput")), "{bare:?}");
    }

    #[test]
    fn gamepad_uinput_refuses_a_node_that_is_missing_or_not_a_device() {
        // The grant is explicit, so a host that cannot honour it is an
        // error rather than a sandbox quietly without the node.
        assert!(matches!(
            argv(&[pad(false, true)], &env(), &gamepad_host()),
            Err(LaunchError::MissingResource {
                service: "gamepad",
                ..
            })
        ));
        let mut host = gamepad_host();
        host.push(("/dev/uinput", File));
        assert!(matches!(
            argv(&[pad(false, true)], &env(), &host),
            Err(LaunchError::WrongType {
                service: "gamepad",
                expected: "a character device",
                ..
            })
        ));
    }

    #[test]
    fn gamepad_binds_sysfs_devices_after_the_pci_roots_whatever_the_file_order() {
        let mut host = gamepad_host();
        host.extend([
            ("/dev/dri", Dir),
            ("/sys/dev/char", Dir),
            ("/sys/devices/system/cpu", Dir),
            ("/sys/devices/pci0000:00", Dir),
        ]);
        for order in [
            [Service::Dri, pad(false, false)],
            [pad(false, false), Service::Dri],
        ] {
            let a = argv(&order, &env(), &host).unwrap();
            let pci = seq_at(
                &a,
                &[
                    "--ro-bind",
                    "/sys/devices/pci0000:00",
                    "/sys/devices/pci0000:00",
                ],
            )
            .expect("dri binds the PCI root");
            let all = seq_at(&a, &["--ro-bind", "/sys/devices", "/sys/devices"])
                .expect("gamepad binds the device tree");
            assert!(pci < all, "{order:?}: {a:?}");
        }
    }

    #[test]
    fn tray_adds_no_bwrap_arguments() {
        let bare = argv(&[Service::Dbus { rules: vec![] }], &env(), &[]).unwrap();
        let with_tray = argv(
            &[Service::Dbus { rules: vec![] }, Service::Tray],
            &env(),
            &[],
        )
        .unwrap();
        assert_eq!(bare, with_tray);
    }

    #[test]
    fn pipewire_and_pulseaudio_bind_sockets() {
        let a = argv(
            &[Service::Pipewire, Service::Pulseaudio],
            &env(),
            &[
                ("/run/user/1000/pipewire-0", Sock),
                ("/run/user/1000/pulse/native", Sock),
            ],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/pipewire-0",
                "/run/user/1000/pipewire-0"
            ]
        ));
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1000/pulse/native",
                "/run/user/1000/pulse/native"
            ]
        ));
        assert!(has_seq(
            &a,
            &[
                "--setenv",
                "PULSE_SERVER",
                "unix:/run/user/1000/pulse/native"
            ]
        ));
        assert!(matches!(
            argv(
                &[Service::Pipewire],
                &env(),
                &[("/run/user/1000/pipewire-0", File)]
            ),
            Err(LaunchError::WrongType {
                service: "pipewire",
                expected: "a socket",
                ..
            })
        ));
        assert!(matches!(
            argv(&[Service::Pulseaudio], &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "pulseaudio",
                ..
            })
        ));
    }

    #[test]
    fn etc_share_binds_an_existing_entry() {
        let a = argv(
            &[Service::EtcShare {
                name: "java".into(),
            }],
            &env(),
            &[("/etc/java", Dir)],
        )
        .unwrap();
        assert!(has_seq(&a, &["--ro-bind", "/etc/java", "/etc/java"]));
        assert!(matches!(
            argv(
                &[Service::EtcShare {
                    name: "nope".into()
                }],
                &env(),
                &[("/etc/java", Dir)]
            ),
            Err(LaunchError::MissingResource {
                service: "etc-share",
                ..
            })
        ));
    }

    #[test]
    fn dbus_binds_the_proxied_socket_and_points_clients_at_it() {
        let a = argv(&[Service::Dbus { rules: vec![] }], &env(), &[]).unwrap();
        // The instance directory, not the proxy's `dbus/` subdirectory:
        // the launcher moves the socket there once it has proved it is one.
        assert!(
            has_seq(
                &a,
                &[
                    "--ro-bind",
                    "/run/user/1000/bubbler/t/bus",
                    "/run/user/1000/bus"
                ]
            ),
            "{a:?}"
        );
        assert!(
            !a.iter().any(|s| s == "/run/user/1000/bubbler/t/dbus/bus"),
            "the sandbox binds a path the proxy can still write to: {a:?}"
        );
        assert!(
            has_seq(
                &a,
                &[
                    "--setenv",
                    "DBUS_SESSION_BUS_ADDRESS",
                    "unix:path=/run/user/1000/bus"
                ]
            ),
            "{a:?}"
        );
        // Only as the bind source: the sandbox sees the socket at the
        // usual runtime path, not at the instance's directory.
        assert_eq!(
            a.iter()
                .filter(|s| *s == "/run/user/1000/bubbler/t/bus")
                .count(),
            1
        );
    }

    #[test]
    fn the_system_bus_is_bound_where_every_client_library_looks() {
        let a = argv(
            &[Service::SystemBus {
                rules: vec![crate::config::BusRule::Talk(
                    "org.freedesktop.UPower".into(),
                )],
            }],
            &env(),
            &[],
        )
        .unwrap();
        // The instance directory, not the proxy's `dbus/` subdirectory:
        // the launcher moves the socket there once it has proved it is one.
        assert!(
            has_seq(
                &a,
                &[
                    "--ro-bind",
                    "/run/user/1000/bubbler/t/system",
                    "/run/dbus/system_bus_socket"
                ]
            ),
            "{a:?}"
        );
        assert!(
            !a.iter()
                .any(|s| s == "/run/user/1000/bubbler/t/dbus/system"),
            "the sandbox binds a path the proxy can still write to: {a:?}"
        );
        // No environment variable: libdbus and libsystemd compile that
        // path in, and a variable a profile could see would name the
        // unfiltered host bus just as well.
        assert!(!a.iter().any(|s| s == "DBUS_SYSTEM_BUS_ADDRESS"), "{a:?}");
        // Nothing of the session bus comes with it.
        assert!(
            !a.iter().any(|s| s == "/run/user/1000/bubbler/t/bus"),
            "{a:?}"
        );
        assert!(!a.iter().any(|s| s == "DBUS_SESSION_BUS_ADDRESS"), "{a:?}");
        // The bind comes after the `--tmpfs /run` that would hide it.
        let tmpfs = a
            .windows(2)
            .position(|w| w == ["--tmpfs", "/run"])
            .expect("the baseline puts a tmpfs over /run");
        let bind = a
            .iter()
            .position(|s| s == "/run/dbus/system_bus_socket")
            .expect("checked above");
        assert!(tmpfs < bind, "{a:?}");
        // Without the node nothing is bound there at all.
        let bare = argv(&[Service::Dbus { rules: vec![] }], &env(), &[]).unwrap();
        assert!(
            !bare.iter().any(|s| s == "/run/dbus/system_bus_socket"),
            "{bare:?}"
        );
    }

    #[test]
    fn portals_adds_the_flatpak_info_file() {
        let a = argv(
            &[Service::Dbus { rules: vec![] }, Service::Portals],
            &env(),
            &[],
        )
        .unwrap();
        // Fd 3 is the info pipe, 4 and 5 the baseline passwd and group.
        assert!(
            has_seq(
                &a,
                &["--perms", "0644", "--ro-bind-data", "6", "/.flatpak-info"]
            ),
            "{a:?}"
        );
    }

    #[test]
    fn portals_binds_this_instances_document_portal_view_read_write() {
        let a = argv(
            &[Service::Dbus { rules: vec![] }, Service::Portals],
            &env(),
            &[("/run/user/1000/doc", Mount)],
        )
        .unwrap();
        assert!(
            has_seq(
                &a,
                &[
                    "--bind",
                    "/run/user/1000/doc/by-app/org.bubbler.t",
                    "/run/user/1000/doc",
                ]
            ),
            "{a:?}"
        );
        // Only the by-app view: the whole mount would show every app's documents.
        assert!(
            !has_seq(&a, &["--bind", "/run/user/1000/doc", "/run/user/1000/doc"]),
            "{a:?}"
        );
    }

    #[test]
    fn portals_without_a_document_portal_mount_binds_nothing_there() {
        for existing in [&[][..], &[("/run/user/1000/doc", Dir)][..]] {
            let a = argv(
                &[Service::Dbus { rules: vec![] }, Service::Portals],
                &env(),
                existing,
            )
            .unwrap();
            assert!(
                !a.iter().any(|s| s == "/run/user/1000/doc"),
                "{existing:?}: {a:?}"
            );
        }
    }

    #[test]
    fn dbus_alone_never_binds_the_document_portal() {
        let a = argv(
            &[Service::Dbus { rules: vec![] }],
            &env(),
            &[("/run/user/1000/doc", Mount)],
        )
        .unwrap();
        assert!(!a.iter().any(|s| s == "/run/user/1000/doc"), "{a:?}");
    }

    #[test]
    fn app_runtime_binds_one_leaf_at_the_same_path_in_and_out() {
        // No host entry in the fake tree: the launcher creates the
        // directory, so nothing here probes for it.
        let a = argv(
            &[
                Service::AppRuntime {
                    id: "org.keepassxc.KeePassXC".to_owned(),
                    mode: ShareMode::ReadOnly,
                },
                Service::AppRuntime {
                    id: "com.discordapp.Discord".to_owned(),
                    mode: ShareMode::ReadWrite,
                },
            ],
            &env(),
            &[],
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            [
                "--ro-bind",
                "/run/user/1000/app/org.keepassxc.KeePassXC",
                "/run/user/1000/app/org.keepassxc.KeePassXC",
                "--bind",
                "/run/user/1000/app/com.discordapp.Discord",
                "/run/user/1000/app/com.discordapp.Discord",
            ]
        );
        // Never the parent and never the runtime directory: `app/` holds
        // every other id, and `bubbler/` under the runtime dir holds each
        // instance's control socket.
        for whole in ["/run/user/1000/app", "/run/user/1000"] {
            assert!(
                !has_seq(&a, &["--ro-bind", whole, whole])
                    && !has_seq(&a, &["--bind", whole, whole]),
                "{a:?}"
            );
        }
    }

    #[test]
    fn app_runtime_follows_the_runtime_directory_the_environment_names() {
        let mut e = env();
        e.runtime_dir = "/run/user/1001".into();
        let a = argv(
            &[Service::AppRuntime {
                id: "org.example.App".to_owned(),
                mode: ShareMode::ReadOnly,
            }],
            &e,
            &[],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/run/user/1001/app/org.example.App",
                "/run/user/1001/app/org.example.App"
            ]
        ));
    }

    #[test]
    fn notify_and_mpris_add_no_bwrap_arguments() {
        let bare = argv(&[Service::Dbus { rules: vec![] }], &env(), &[]).unwrap();
        let bundled = argv(
            &[
                Service::Dbus { rules: vec![] },
                Service::Notify,
                Service::Mpris {
                    name: "firefox.*".into(),
                },
            ],
            &env(),
            &[],
        )
        .unwrap();
        assert_eq!(bare, bundled);
    }

    #[test]
    fn env_pairs_are_emitted_after_service_env() {
        let (_, _, sock) = fake::types();
        let host = FakeHost::default().with("/run/user/1000/wayland-1", sock);
        let e = env();
        let mut args = BwrapArgs::baseline(&e, Path::new("/i/home"), &host);
        apply_all(
            &[Service::Wayland(WaylandMode::Sandboxed)],
            &e,
            &mut args,
            &host,
            &argv_ctx(&None),
        )
        .unwrap();
        apply_env(&[("MOZ_ENABLE_WAYLAND".into(), "1".into())], &mut args).unwrap();
        let a = strs(
            &args
                .finish(
                    &[OsString::from("x")],
                    &mut crate::launcher::DryRunAlloc::default(),
                )
                .unwrap(),
        );
        let pos = |x: &str| a.iter().position(|v| v == x).unwrap();
        assert!(pos("MOZ_ENABLE_WAYLAND") > pos("WAYLAND_DISPLAY"));
    }

    #[test]
    fn env_pairs_may_not_set_a_variable_the_sandbox_owns() {
        let e = env();
        let host = FakeHost::default();
        for key in crate::config::RESERVED_ENV {
            let mut args = BwrapArgs::baseline(&e, Path::new("/i/home"), &host);
            assert!(
                matches!(
                    apply_env(&[((*key).to_owned(), "x".into())], &mut args),
                    Err(LaunchError::BadValue { service: "env", .. })
                ),
                "{key}"
            );
        }
    }
}
