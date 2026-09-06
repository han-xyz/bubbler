//! Turns granted services into builder calls. Each service touches only
//! phase 4 (binds) and phase 5 (env); `network "host"` is the one
//! exception that edits phase 1 via [`BwrapArgs::share_net`].
//!
//! Paths come from untrusted host environment values, so every source is
//! probed for its file *type*, never for mere existence: binding a
//! directory binds the whole tree under it, so `XAUTHORITY=/` would bind
//! the host root.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::FileType;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

use crate::bwrap::{BwrapArgs, Explained, Origin};
use crate::config::{self, RESERVED_ENV, Service, Share, ShareMode, X11Mode};
use crate::dbus;
use crate::env::{Env, SANDBOX_HOME};
use crate::error::LaunchError;
use crate::host::Host;
use crate::network::{self, Mode as NetworkMode, NetworkConfig};
use crate::wayland::WaylandPlan;

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
    /// How `wayland` is served this run; `None` without the grant.
    pub wayland: Option<&'a WaylandPlan>,
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
    let has_x11 = services.iter().any(|s| matches!(s, Service::X11(_)));
    let shares = path_shares(services, env, host)?;
    for (i, s) in services.iter().enumerate() {
        args.tag(Origin::Service(i));
        match s {
            Service::Wayland(_) => wayland(env, args, host, !has_x11, ctx.wayland)?,
            Service::X11(mode) => x11(env, args, host, mode)?,
            Service::Network(cfg) => network(env, args, host, cfg)?,
            Service::HomeShare {
                path,
                mode,
                optional,
            } => home_share(env, args, host, path, *mode, *optional)?,
            Service::Dri { kms } => dri(args, host, *kms)?,
            Service::Pipewire => pipewire(env, args, host)?,
            Service::Pulseaudio => pulseaudio(env, args, host)?,
            Service::EtcShare { name } => etc_share(args, host, name)?,
            Service::AppRuntime { id, mode } => app_runtime(env, args, id, *mode),
            Service::Dbus { .. } => dbus_socket(env, args, ctx),
            Service::SystemBus { .. } => system_bus_socket(args, ctx),
            Service::Portals { .. } => portals(env, args, host, ctx)?,
            Service::Camera { nodes } => camera(services, args, host, *nodes)?,
            // Bound below, once every share has been resolved: two
            // overlapping shares must be refused before either is emitted.
            Service::PathShare { .. } => {}
            // Bound after the loop, so its whole-`/sys/devices` bind always
            // follows the device directories `dri` binds under it rather
            // than depending on the order of the two nodes in the file.
            // The masks `dri` lays over the card directories are emitted
            // after this bind again, in the builder's own late section.
            Service::Gamepad { .. } => {}
            // Bound after the loop with `gamepad hidraw=#true`, which is
            // the same grant written the older way: one bind, whether the
            // config holds one node or both.
            Service::Hidraw => {}
            // Rule-only bundles: they reach the sandbox through the proxy
            // the launcher starts, not through bwrap arguments.
            Service::Notify | Service::Tray | Service::Mpris { .. } => {}
            Service::A11y => a11y(env, args, ctx)?,
            Service::InputMethod => input_method(args),
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
///
/// An `allow-host` adds the two halves of the egress proxy that belong
/// to the sandbox's own argv: the binary, bound where the sidecar execs
/// it from after joining this mount namespace, and the seven variables
/// that tell the application where it listens. The proxy process itself
/// is the launcher's, like pasta.
fn network(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    cfg: &NetworkConfig,
) -> Result<(), LaunchError> {
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
    if !cfg.allow_hosts.is_empty() {
        // Bound whatever it is and wherever it was found: the installed
        // path is visible in here anyway, and one path for every build
        // keeps the argv the launcher execs and the argv `--explain`
        // prints the same. A missing binary fails the launch here,
        // before a sandbox is started that would be pointed at a proxy
        // nothing runs.
        let (program, _) = network::net_proxy_program(env, host)?;
        args.ro_bind(&program, Path::new(network::NET_PROXY_INSIDE));
        // The port is fixed ([`network::PROXY_PORT`]), so these are
        // exact in a `--dry-run` that starts nothing.
        for (name, value) in network::proxy_env(network::PROXY_PORT) {
            args.setenv(OsStr::new(&name), OsStr::new(&value));
        }
    }
    Ok(())
}

/// A compositor socket's name, refused unless it is exactly one path
/// component: `$WAYLAND_DISPLAY` is untrusted host input, and an
/// absolute or `..` name would otherwise decide what a bind mounts, or
/// what endpoint the launcher hands its listening socket to. Everything
/// that uses the value goes through here first.
pub(crate) fn check_wayland_display(value: Option<&OsStr>) -> Result<&OsStr, LaunchError> {
    let display = value.ok_or(LaunchError::MissingEnv {
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
    Ok(display)
}

/// [`check_wayland_display`] on the run's [`Env`], the value every bind
/// takes the socket name from. The launcher checks the process
/// environment's own value separately: the Wayland client reads that one
/// itself, and the two need not be the same string.
pub(crate) fn wayland_display(env: &Env) -> Result<&OsStr, LaunchError> {
    check_wayland_display(env.wayland_display.as_deref())
}

/// Bind a Wayland socket at `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`, which
/// must be a plain socket name: the socket bubbler's own proxy accepts
/// on for a sandboxed grant, the session's own socket for
/// `wayland "host"`. Arch wiki (Bubblewrap/Examples) pattern.
/// `XDG_SESSION_TYPE=wayland` only when X11 is not also granted, so
/// toolkits do not get mixed signals.
fn wayland(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    claim_session: bool,
    plan: Option<&WaylandPlan>,
) -> Result<(), LaunchError> {
    let display = wayland_display(env)?;
    let inside = env.runtime_dir.join(display);
    match plan {
        // The launcher creates this one after the argv is built, like the
        // proxied bus socket, so there is nothing here to probe.
        Some(WaylandPlan::Proxy { socket }) => args.ro_bind(socket, &inside),
        // A missing plan is read as the session's socket: a caller that
        // built the context by hand must not get a bind of a socket
        // nobody is going to create.
        _ => {
            let sock = require_socket(host, "wayland", inside)?;
            args.ro_bind(&sock, &sock);
        }
    }
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

/// `x11 "host"` binds the session's X11 socket at the same path (Arch
/// wiki: binding to a different display number may not work) and any
/// Xauthority file at the fixed inner path `/home/bubbler/.Xauthority`,
/// so the host location stays hidden. The `$HOME/.Xauthority` fallback
/// follows libX11's default, not the wiki, and is used only when it is a
/// regular file. The nested mode binds nothing of the host's: the server
/// is started inside the sandbox and `DISPLAY` names it.
fn x11(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    mode: &X11Mode,
) -> Result<(), LaunchError> {
    if let X11Mode::Nested(nested) = mode {
        // Probed on the host because that is where the binary is read
        // from: `/usr` is bound read-only, so a sandbox without
        // `xorg-xwayland` installed outside has no server to start, and
        // failing here beats a `DISPLAY` that names nothing.
        require_file(host, "x11", PathBuf::from(config::XWAYLAND))?;
        // The display number is fixed: the server is the only one in
        // this sandbox, and `exec` children take the variable from the
        // supervisor that started it. Nothing is bound and no cookie is
        // handed over — an X client inside reaches no other display.
        args.setenv(OsStr::new("DISPLAY"), OsStr::new(":0"));
        // The window manager is not probed on the host: the supervisor
        // resolves it on the sandbox's own `PATH`, and a name that
        // resolves to nothing there is a line in its log rather than a
        // launch that fails.
        args.x11_server(
            nested.xwayland_argv(),
            nested.wm.as_deref().map(OsString::from),
        );
        return Ok(());
    }
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

/// Where the kernel puts the DRM device nodes. A `dri` grant binds the
/// nodes it needs one by one, never this directory.
const DRI_DEV: &str = "/dev/dri";

/// Where the kernel publishes the DRM class: one entry per node, plus
/// the connector directories that carry a monitor's EDID.
const DRM_CLASS: &str = "/sys/class/drm";

/// GPU access: the render node of every GPU the host has, bound
/// read-write because bwrap has no read-only device bind, plus each GPU's
/// own `/sys/devices` directory and whichever NVIDIA nodes are there.
/// `kms` adds the primary (`card*`) nodes and leaves the sysfs behind
/// them readable, which is mode setting and everything that comes with
/// it: DRM master on a virtual terminal switch, the monitors' EDID, the
/// framebuffer geometry, every other client's flink names.
fn dri(args: &mut BwrapArgs, host: &dyn Host, kms: bool) -> Result<(), LaunchError> {
    let dev = require_dir(host, "dri", PathBuf::from(DRI_DEV))?;
    // udev's `by-path` links are the only discovery path: a node's name
    // says nothing about which kind it is, and `/dev/dri` bound whole is
    // what this grant no longer does. The directory itself is not bound.
    let by_path = dev.join("by-path");
    let (render, card) = dri_nodes(host, &by_path);
    if render.is_empty() {
        return Err(LaunchError::MissingResource {
            service: "dri",
            path: by_path,
        });
    }
    for name in &render {
        let node = dev.join(name);
        args.dev_bind(&node, &node);
    }
    if kms {
        for name in &card {
            let node = dev.join(name);
            args.dev_bind(&node, &node);
        }
    }
    // Paths from Arch wiki Bubblewrap/Examples. `/sys/dev/char` is the
    // symlinks a driver maps a device number through; they lead into the
    // directories bound below.
    for p in ["/sys/dev/char", "/sys/devices/system/cpu"] {
        let p = require_dir(host, "dri", PathBuf::from(p))?;
        args.ro_bind(&p, &p);
    }
    for name in &render {
        dri_sysfs(args, host, name, kms)?;
    }
    // `/sys/class/drm` is rebuilt from the symlinks above rather than
    // bound, since its own entries are the primary nodes and their
    // connectors; `version` is the only file left of it. Missing on a
    // host with no DRM driver loaded, which is not an error when the
    // render node is there.
    let version = Path::new(DRM_CLASS).join("version");
    if host.file_type(&version).is_some_and(|t| t.is_file()) {
        args.ro_bind(&version, &version);
    }
    // The NVIDIA nodes are created by the setuid `nvidia-modprobe` a udev
    // rule runs, and a sandbox has `NoNewPrivs` set, so a node missing at
    // launch can never appear later: bind what the host has, fail over
    // nothing. The char-device check keeps the `/dev/nvidia-caps`
    // directory out: those are MIG capability files, and nothing outside
    // MIG reads them. They have no render/primary split of their own, so
    // `kms` says nothing about them.
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

/// The names of the render and the primary nodes `by_path` points at,
/// each once and in name order. udev writes those links as `../<node>`,
/// and a link of any other shape names nothing: what it points at is
/// then outside the device directory this grant is confined to. A link
/// that cannot be read is one GPU fewer, never one more; a host where
/// that leaves no render node at all fails in the caller.
fn dri_nodes(host: &dyn Host, by_path: &Path) -> (BTreeSet<OsString>, BTreeSet<OsString>) {
    let (mut render, mut card) = (BTreeSet::new(), BTreeSet::new());
    for entry in host.list_dir(by_path) {
        let kind = match entry.as_encoded_bytes() {
            b if b.ends_with(b"-render") => &mut render,
            b if b.ends_with(b"-card") => &mut card,
            _ => continue,
        };
        let Ok(Some(target)) = host.read_link(&by_path.join(&entry)) else {
            continue;
        };
        let mut parts = target.components();
        if let (Some(Component::ParentDir), Some(Component::Normal(node)), None) =
            (parts.next(), parts.next(), parts.next())
        {
            kind.insert(node.to_os_string());
        }
    }
    (render, card)
}

/// Whether a bare `dri` on this host binds a primary node as well as the
/// render nodes, which it does for a GPU on the proprietary NVIDIA
/// driver. The linter asks, so a config that says nothing about that
/// node can still tell the reader what the run opens.
pub(crate) fn dri_binds_a_primary_node(host: &dyn Host) -> bool {
    let (render, _) = dri_nodes(host, &Path::new(DRI_DEV).join("by-path"));
    render.iter().any(|name| {
        host.canonicalize(&Path::new(DRM_CLASS).join(name).join("device"))
            .and_then(|dir| dri_driver(host, &dir))
            .is_some_and(|driver| driver == "nvidia")
    })
}

/// The name of the kernel driver bound to the device at `dir`, from the
/// link its bus keeps beside it (`.../0000:01:00.0/driver` ->
/// `../../../../bus/pci/drivers/nvidia`). `None` where the device has no
/// driver or the link cannot be read.
fn dri_driver(host: &dyn Host, dir: &Path) -> Option<OsString> {
    let target = host.read_link(&dir.join("driver")).ok().flatten()?;
    target.file_name().map(OsStr::to_os_string)
}

/// The sysfs one render node needs: the GPU's own directory under
/// `/sys/devices`, with the primary nodes under it masked by an empty
/// read-only tmpfs unless `kms`, and `/sys/class/drm/<node>` as the
/// relative symlink the host has there, so a driver that walks the class
/// directory finds the device without the rest of the class being bound.
/// A GPU on the proprietary NVIDIA driver also keeps its primary node,
/// which is the one thing its EGL will not drive a Wayland display
/// without.
fn dri_sysfs(
    args: &mut BwrapArgs,
    host: &dyn Host,
    name: &OsStr,
    kms: bool,
) -> Result<(), LaunchError> {
    let class = Path::new(DRM_CLASS).join(name);
    let link = class.join("device");
    let devices = Path::new("/sys/devices");
    let Some(dir) = host.canonicalize(&link) else {
        return Err(LaunchError::MissingResource {
            service: "dri",
            path: link,
        });
    };
    // Every GPU's directory is under `/sys/devices`, and one that
    // resolves elsewhere is not a device this grant can hand over
    // without binding a tree it knows nothing about.
    let Ok(rel) = dir.strip_prefix(devices) else {
        return Err(LaunchError::BadValue {
            service: "dri",
            reason: format!(
                "`{}` resolves to `{}`, outside /sys/devices",
                link.display(),
                dir.display()
            ),
        });
    };
    args.ro_bind(&dir, &dir);
    let drm = dir.join("drm");
    if !kms {
        // NVIDIA's proprietary stack has no render/primary split, and its
        // EGL declines a Wayland display without the primary node:
        // measured on driver 610, a client inside falls back to llvmpipe
        // and Mesa reports `pci id 10de:…, driver (null)`. Only the node
        // is needed — with it bound and the sysfs below still masked, the
        // same client gets the GPU back.
        let nvidia = dri_driver(host, &dir).is_some_and(|d| d == "nvidia");
        for entry in host.list_dir(&drm) {
            let card = drm.join(&entry);
            if !entry.as_encoded_bytes().starts_with(b"card")
                || !host.file_type(&card).is_some_and(|t| t.is_dir())
            {
                continue;
            }
            if nvidia {
                let node = Path::new(DRI_DEV).join(&entry);
                args.dev_bind(&node, &node);
            }
            // The primary node's directory holds the connectors, and each
            // of those holds the monitor's EDID; the node's own
            // attributes carry the framebuffer geometry.
            args.mask_dir(&card);
        }
    }
    // Relative, as the host writes it: a driver comparing the link with
    // the one it read on the host sees the same text.
    args.symlink(
        &Path::new("../../devices").join(rel).join("drm").join(name),
        &class,
    );
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
    // bluetooth or virtual controller lives outside the GPU directories
    // `dri` exposes, so the whole tree is bound read-only.
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
    if !services
        .iter()
        .any(|s| matches!(s, Service::Portals { .. }))
    {
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

/// Bind the socket the same proxy serves for the accessibility bus at
/// `$XDG_RUNTIME_DIR/at-spi/bus` and name it in `AT_SPI_BUS_ADDRESS`,
/// which is where at-spi2's own clients look before they ask any bus for
/// an address (`atspi-misc.c`). The host's accessibility socket is never
/// bound; only the filtered one is, and what it filters is the fixed
/// [`dbus::A11Y_RULES`].
///
/// The source is not probed here for the same reason [`dbus_socket`]'s is
/// not: it exists only once the launcher has moved the proxy's socket out
/// of the proxy's reach.
///
/// Without a plan holding that bus nothing ever creates the socket, so
/// the grant is refused rather than quietly dropped; the parser rejects
/// that config already.
fn a11y(env: &Env, args: &mut BwrapArgs, ctx: &ServiceCtx) -> Result<(), LaunchError> {
    if !ctx.dbus.is_some_and(|p| p.a11y.is_some()) {
        return Err(LaunchError::BadValue {
            service: dbus::A11Y_NODE,
            reason: "requires dbus".to_owned(),
        });
    }
    let inside = env.runtime_dir.join("at-spi").join("bus");
    args.ro_bind(
        &dbus::app_bus_path(&ctx.instance_runtime, dbus::A11Y_SOCKET),
        &inside,
    );
    let mut address = OsString::from("unix:path=");
    address.push(inside.as_os_str());
    args.setenv(OsStr::new("AT_SPI_BUS_ADDRESS"), &address);
    Ok(())
}

/// Point the IBus client library at the sandboxed portal name instead of
/// the daemon's own; fcitx5's Qt and GTK clients watch for their portal
/// name by themselves. The rules that make either name reachable are the
/// plan's, and neither daemon's main name — which carries `Exit`,
/// `SetConfig` and their kin — is among them.
// `ibusbus.c`: the library uses the portal when `IBUS_USE_PORTAL` is set
// or `/.flatpak-info` exists. bubbler sets no IM module variable: the
// toolkits pick the Wayland text-input protocol by themselves, and an
// Xwayland application needs a profile's `env` to say which module.
fn input_method(args: &mut BwrapArgs) {
    args.setenv(OsStr::new("IBUS_USE_PORTAL"), OsStr::new("1"));
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
/// matches its destination. The instance store and the profile layers are
/// resolved on their own as well as under a resolved `$XDG_DATA_HOME` or
/// `$XDG_CONFIG_HOME`, since either link alone moves them. A root that
/// does not resolve is kept as written.
fn env_roots(host: &dyn Host, env: &Env) -> Vec<PathBuf> {
    let under = |dir: &Path| {
        host.canonicalize(dir)
            .unwrap_or_else(|| dir.to_path_buf())
            .join("bubbler")
    };
    let mut named = vec![
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
    // The system profile layer wherever `$BUBBLER_PROFILE_DIR` moved it:
    // it is read as a layer at that path, so it is the same break as the
    // user's own. The default `/usr/share/bubbler/profiles` needs no
    // entry of its own — `/usr` is a fixed root, and read-only besides.
    named.extend(env.profile_dir_override.clone());
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
        let Service::PathShare {
            path,
            mode,
            optional,
        } = s
        else {
            continue;
        };
        let src = match resolve_source(host, "path-share", path, require_dir_or_file) {
            // A missing optional source is a silent no-op rather than the
            // launch error below: `--explain` is where the skip is
            // reported. Matched on the missing path itself, the same way
            // `home_share` is, so a source that fails to resolve for a
            // reason other than "not there" still refuses the launch.
            Err(LaunchError::MissingResource { path: p, .. }) if *optional && p == *path => {
                continue;
            }
            result => result?,
        };
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
/// creates directories in the real home. The roots bubbler keeps inside
/// the home — the instance store and the profile layer — are refused in
/// both modes, as they are for `path-share` and `--share`. Resolving and
/// binding both happen by path, so a symlink swapped in between the two
/// is not detected; that is inherent to bwrap path binds.
///
/// `optional` turns a missing source into a silent no-op rather than the
/// launch error every other absent resource is: a profile can name a path
/// only some installs of an app have, and `--explain` is where the skip
/// is reported.
fn home_share(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    rel: &Path,
    mode: ShareMode,
    optional: bool,
) -> Result<(), LaunchError> {
    let written = env.home.join(rel);
    let src = match confine(
        host,
        "home-share",
        &env.home,
        &written,
        "the home directory",
    ) {
        // Matched on the missing path itself, not just the error kind: a
        // `home-share` that cannot resolve because `$HOME` is gone is a
        // much bigger problem than one absent optional entry, and stays
        // the launch error it always was.
        Err(LaunchError::MissingResource { path, .. }) if optional && path == written => {
            return Ok(());
        }
        result => result?,
    };
    let dst = Path::new(SANDBOX_HOME).join(rel);
    deny_reserved_in_home(host, env, "home-share", &written, &src, &dst)?;
    match mode {
        ShareMode::ReadOnly => args.ro_bind(&src, &dst),
        ShareMode::ReadWrite => args.bind(&src, &dst),
    }
    Ok(())
}

/// Bind every `--share` after the config's own services, each tagged with
/// its position. A path under the real home lands at the same relative
/// path in the private home, any other at its own path, and both under
/// the reserved roots `path-share` is held to. The first share that is a
/// directory
/// becomes the working directory. A share the config already makes, one
/// given twice, and one that contains or sits inside another share are
/// all errors rather than a second bind of the same place.
pub fn apply_shares(
    services: &[Service],
    shares: &[Share],
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
) -> Result<(), LaunchError> {
    // Without a flag there is nothing to check, and `share_plan` would
    // resolve the config's own shares a second time only to compare them
    // against nothing.
    if shares.is_empty() {
        return Ok(());
    }
    let mut cwd: Option<PathBuf> = None;
    for (i, (s, (src, dst))) in shares
        .iter()
        .zip(share_plan(services, shares, env, host)?)
        .enumerate()
    {
        args.tag(Origin::Share(i));
        match s.mode {
            ShareMode::ReadOnly => args.ro_bind(&src, &dst),
            ShareMode::ReadWrite => args.bind(&src, &dst),
        }
        if cwd.is_none() && host.file_type(&src).is_some_and(|t| t.is_dir()) {
            cwd = Some(dst);
        }
    }
    if let Some(dir) = cwd {
        args.chdir(&dir);
    }
    Ok(())
}

/// Every `--share` as (canonical source, destination), in the order the
/// flags were given, once all of them have passed the checks the config
/// nodes get. Nothing is bound until the last one has: a run refused
/// halfway would otherwise be a sandbox built from the shares before the
/// error.
fn share_plan(
    services: &[Service],
    shares: &[Share],
    env: &Env,
    host: &dyn Host,
) -> Result<Vec<(PathBuf, PathBuf)>, LaunchError> {
    let config = config_shares(services, env, host)?;
    let mut out: Vec<(PathBuf, PathBuf)> = Vec::new();
    for s in shares {
        let (src, dst) = share_paths(env, host, &s.path)?;
        // The exact cases first: naming the same place twice is a
        // mistake worth its own sentence, and the overlap rule below
        // would otherwise answer for it in the general terms of two
        // shares that contain one another.
        if config.iter().any(|(_, d)| *d == dst) {
            return Err(LaunchError::BadValue {
                service: "--share",
                reason: format!("{} already shared by config.kdl", s.path.display()),
            });
        }
        if out.iter().any(|(_, d)| *d == dst) {
            return Err(LaunchError::BadValue {
                service: "--share",
                reason: format!("{} given twice", s.path.display()),
            });
        }
        let against = config
            .iter()
            .map(|(o_src, o_dst)| (o_src.as_deref(), o_dst.as_path()))
            .chain(
                out.iter()
                    .map(|(o_src, o_dst)| (Some(o_src.as_path()), o_dst.as_path())),
            );
        for (o_src, o_dst) in against {
            if let Some(reason) = overlap(&src, &dst, o_src, o_dst) {
                return Err(LaunchError::BadValue {
                    service: "--share",
                    reason,
                });
            }
        }
        out.push((src, dst));
    }
    Ok(out)
}

/// Every share the config makes, as (canonical source, destination),
/// each resolved the way the service that binds it resolves it: a
/// symlink in the home makes the two sides of a `home-share` different
/// paths, and the source is the side a `--share` of that symlink meets.
// Only the two share nodes are listed. Another service that binds under
// a share's destination is invisible to the overlap rule: today that is
// `x11`, whose cookie lands at `/home/bubbler/.Xauthority`.
fn config_shares(
    services: &[Service],
    env: &Env,
    host: &dyn Host,
) -> Result<Vec<(Option<PathBuf>, PathBuf)>, LaunchError> {
    let mut out: Vec<(Option<PathBuf>, PathBuf)> = Vec::new();
    for s in services {
        let Service::HomeShare { path, optional, .. } = s else {
            continue;
        };
        // The name of the node that would be at fault, not of the flag:
        // `apply_all` resolved this same path before us, so a failure
        // here is the config's, not the caller's.
        let written = env.home.join(path);
        let src = match confine(
            host,
            "home-share",
            &env.home,
            &written,
            "the home directory",
        ) {
            // A missing optional source binds nothing, so it is not a
            // share to check `--share` against either; `apply_all`'s
            // `home_share` makes the same skip.
            Err(LaunchError::MissingResource { path: p, .. }) if *optional && p == written => {
                continue;
            }
            result => result?,
        };
        out.push((Some(src), Path::new(SANDBOX_HOME).join(path)));
    }
    for (_, dst, src, _) in path_shares(services, env, host)? {
        out.push((Some(src), dst.to_path_buf()));
    }
    Ok(out)
}

/// Why one `--share` overlaps another share, if it does: the same rule
/// two `path-share` nodes are held to, in the same words. `None` where
/// the two are unrelated, and where a share the config makes has no
/// source to compare against.
fn overlap(src: &Path, dst: &Path, other_src: Option<&Path>, other_dst: &Path) -> Option<String> {
    let where_ = if nested(dst, other_dst) {
        String::new()
    } else {
        let other = other_src.filter(|o| nested(src, o))?;
        format!(
            " (they resolve to {} and {})",
            src.display(),
            other.display()
        )
    };
    Some(format!(
        "{} and {} overlap{where_}; one share cannot contain another",
        dst.display(),
        other_dst.display()
    ))
}

/// Source and destination of one `--share`: the source resolved and
/// type-checked as `path-share` does, the destination by where the written
/// path lies, and either way under the reserved roots the config nodes
/// are held to. The path must be absolute and free of `.` and `..`, which
/// is what the parser guarantees for a node and nothing guarantees for a
/// flag; a path that is neither is refused rather than repaired here.
fn share_paths(
    env: &Env,
    host: &dyn Host,
    written: &Path,
) -> Result<(PathBuf, PathBuf), LaunchError> {
    let mut comps = written.components();
    if comps.next() != Some(Component::RootDir) {
        return Err(LaunchError::BadValue {
            service: "--share",
            reason: format!("{} is not absolute", written.display()),
        });
    }
    // The config nodes are normalised at parse time; a flag is checked
    // here instead. A `..` left in the path would walk out of every
    // comparison below — the destination it is bound at is built from the
    // path as written, so `$HOME/x/..` maps over the private home while
    // comparing equal to nothing.
    if !comps.all(|c| matches!(c, Component::Normal(_))) {
        return Err(LaunchError::BadValue {
            service: "--share",
            reason: format!(
                "{} contains `.` or `..`; give the path without them",
                written.display()
            ),
        });
    }
    if let Ok(rel) = written.strip_prefix(&env.home) {
        let src = confine(host, "--share", &env.home, written, "the home directory")?;
        let src = require_dir_or_file(host, "--share", src)?;
        let dst = Path::new(SANDBOX_HOME).join(rel);
        deny_reserved_in_home(host, env, "--share", written, &src, &dst)?;
        return Ok((src, dst));
    }
    let src = resolve_source(host, "--share", written, require_dir_or_file)?;
    if let Some((root, end)) = denied_root(host, env, &src, written) {
        return Err(LaunchError::BadValue {
            service: "--share",
            reason: denied_reason(written, &src, &root, end),
        });
    }
    Ok((src, written.components().collect()))
}

/// Refuse a share that maps into the private home and meets one of the
/// roots bubbler keeps for itself there. `home-share` and a `--share` of
/// a path under the real home land in the same place and are held to the
/// same roots, so both come through here; `written` is the host path the
/// entry names, which is what the message quotes back.
fn deny_reserved_in_home(
    host: &dyn Host,
    env: &Env,
    service: &'static str,
    written: &Path,
    src: &Path,
    dst: &Path,
) -> Result<(), LaunchError> {
    match denied_root_in_home(host, env, src, dst) {
        Some((root, end)) => Err(LaunchError::BadValue {
            service,
            reason: denied_reason(written, src, &root, end),
        }),
        None => Ok(()),
    }
}

/// Why `home-share "<rel>"` would be refused for meeting one of the
/// roots bubbler keeps inside the home, if it would. The launcher raises
/// the same sentence as an error when it builds the argv; the linter
/// reports it against the node, on a source that need not exist yet.
pub(crate) fn reserved_in_home_reason(host: &dyn Host, env: &Env, rel: &Path) -> Option<String> {
    let written = env.home.join(rel);
    let src = host
        .canonicalize(&written)
        .unwrap_or_else(|| written.clone());
    let dst = Path::new(SANDBOX_HOME).join(rel);
    let (root, end) = denied_root_in_home(host, env, &src, &dst)?;
    Some(denied_reason(&written, &src, &root, end))
}

/// The reserved root a share that maps into the private home meets.
/// [`denied_root`] cannot answer for one: the real home is a root of its
/// own there and every path inside it is nested with it, so what is left
/// to check is the roots that lie *within* the home — the instance store
/// and the profile layer, wherever XDG puts them — and the private home
/// itself as a destination. Ancestors count, as they do for `path-share`:
/// binding one covers the root beneath it.
fn denied_root_in_home(
    host: &dyn Host,
    env: &Env,
    canonical: &Path,
    dst: &Path,
) -> Option<(PathBuf, End)> {
    // The private home first, so that a share of the whole real home is
    // named by what it would cover rather than by whichever root inside
    // it happens to be found first.
    if dst == Path::new(SANDBOX_HOME) {
        return Some((PathBuf::from(SANDBOX_HOME), End::Destination));
    }
    let home = [Some(env.home.clone()), host.canonicalize(&env.home)];
    env_roots(host, env)
        .into_iter()
        .filter(|root| !home.iter().flatten().any(|h| h == root))
        .find(|root| nested(canonical, root))
        .map(|root| (root, End::Source))
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

/// bwrap operations that create a path inside the sandbox, and how many
/// arguments stand between the flag and that path. `--perms` and
/// `--size` may precede the flag inside one operation, so the flag is
/// looked for rather than assumed to be first. The overlay family is
/// here for completeness though the builder never emits it; a test
/// holds every flag the builder can emit to either this list or the
/// one of flags that create nothing.
const CREATES: &[(&str, usize)] = &[
    ("--bind", 2),
    ("--bind-try", 2),
    ("--ro-bind", 2),
    ("--ro-bind-try", 2),
    ("--dev-bind", 2),
    ("--dev-bind-try", 2),
    ("--symlink", 2),
    ("--bind-data", 2),
    ("--ro-bind-data", 2),
    ("--file", 2),
    ("--dir", 1),
    ("--tmpfs", 1),
    ("--proc", 1),
    ("--dev", 1),
    ("--mqueue", 1),
    ("--overlay", 3),
    ("--tmp-overlay", 1),
    ("--ro-overlay", 1),
];

/// The path one operation creates inside the sandbox, or `None` for an
/// operation that creates none.
fn destination(op: &Explained) -> Option<&OsStr> {
    for (i, arg) in op.args.iter().enumerate() {
        if let Some((_, at)) = CREATES.iter().find(|(flag, _)| arg == OsStr::new(flag)) {
            return op.args.get(i + at).map(OsString::as_os_str);
        }
    }
    None
}

/// The trees an application inside the sandbox may write, read off the
/// argv itself: each is a bind whose destination the sandbox can create
/// files in, paired with the host directory behind it. Read-only binds
/// are here too — one id's `app-runtime` directory is writable by
/// whichever other instance names the same id, and a link planted there
/// is planted for this run as well.
fn writable_trees(ops: &[Explained], env: &Env) -> Vec<(PathBuf, PathBuf, &'static str)> {
    let app = env.runtime_dir.join("app");
    let doc = env.runtime_dir.join("doc");
    let mut out = Vec::new();
    for op in ops {
        // The flag is looked for rather than assumed first: the builder
        // emits prefixed operations — `--perms 0700 --bind src dst` — and
        // a tree read off only the bare three-element shape would be
        // dropped silently, taking the sweep of everything under it with
        // it. [`destination`] reads an operation the same way.
        let Some(i) = op
            .args
            .iter()
            .position(|a| a == OsStr::new("--bind") || a == OsStr::new("--ro-bind"))
        else {
            continue;
        };
        let (Some(src), Some(dst)) = (op.args.get(i + 1), op.args.get(i + 2)) else {
            continue;
        };
        let dst = Path::new(dst);
        let tree = if dst == Path::new(SANDBOX_HOME) {
            "the instance home"
        } else if dst.parent() == Some(app.as_path()) {
            "the app-runtime directory"
        } else if dst == doc.as_path() {
            "the document view"
        } else {
            continue;
        };
        out.push((PathBuf::from(src), dst.to_path_buf(), tree));
    }
    out
}

/// Refuse the launch when a path the argv has bwrap create sits behind a
/// symlink inside a tree the application can write.
///
/// bubblewrap below 0.12.0 creates the parents of a destination without
/// checking for links on the way, so an application that plants
/// `Downloads -> /oldroot/<victim>` in its own home has the next launch
/// write into `<victim>` outside the sandbox (GHSA-pxhw-h44j-8pfx,
/// reproduced on 0.11.2). The sweep runs whatever version the host has:
/// it costs one `lstat` per component and it is the mitigation the
/// warning points at.
///
/// Every component of the destination's path relative to its tree is
/// `lstat`ed at the tree's real location on the host, the last one
/// included — the destination itself is what bwrap creates. A component
/// that cannot be `lstat`ed refuses the run as well: bwrap creates the
/// destination as root of its user namespace, past a mode that stops
/// bubbler, so an unreadable directory is not a clean one. Nothing is
/// deleted: what planted the link is what the user has to see.
///
/// No lock keeps a concurrently running instance of the same sandbox
/// from planting a link between this check and bwrap's own `mkdir`;
/// only bwrap 0.12.0 and later closes that window, which is what the
/// version warning points at.
pub fn sweep_destinations(
    ops: &[Explained],
    env: &Env,
    host: &dyn Host,
) -> Result<(), LaunchError> {
    let trees = writable_trees(ops, env);
    // bwrap reads options up to the first `--`; everything after it is
    // bubbler-init's argv, whatever flags it spells.
    let bwrap_ops = ops
        .iter()
        .take_while(|op| op.args.first().map(OsString::as_os_str) != Some(OsStr::new("--")));
    for op in bwrap_ops {
        let Some(dst) = destination(op) else {
            continue;
        };
        let dst = Path::new(dst);
        for (host_root, inside_root, tree) in &trees {
            let Ok(rel) = dst.strip_prefix(inside_root) else {
                continue;
            };
            let mut on_host = host_root.clone();
            let mut inside = inside_root.clone();
            for part in rel.components() {
                let Component::Normal(name) = part else {
                    return Err(LaunchError::UnwalkableDestination(dst.to_path_buf()));
                };
                on_host.push(name);
                inside.push(name);
                match host.read_link(&on_host) {
                    Ok(None) => {}
                    Ok(Some(target)) => {
                        return Err(LaunchError::PlantedSymlink {
                            inside,
                            tree,
                            target,
                            host: host_root.clone(),
                        });
                    }
                    Err(source) => {
                        return Err(LaunchError::UncheckedDestination {
                            inside,
                            tree,
                            host: on_host,
                            source,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NestedX11, WaylandMode};
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
            xauthority: Some("/run/user/1000/Xauthority".into()),
            passthrough: vec![],
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

    /// One operation of an argv, as [`crate::bwrap::Explained`] carries it.
    fn op(args: &[&str]) -> crate::bwrap::Explained {
        crate::bwrap::Explained {
            origin: Origin::Baseline,
            args: args.iter().map(OsString::from).collect(),
            note: None,
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
            wayland: None,
        }
    }

    /// The `wayland` grant applied with the plan the launcher would have
    /// built for it, which is what decides the socket it binds.
    fn argv_wayland(
        plan: &WaylandPlan,
        env: &Env,
        existing: &[(&str, Kind)],
    ) -> Result<Vec<String>, LaunchError> {
        argv_planned(
            &[Service::Wayland(WaylandMode::default())],
            env,
            existing,
            &[],
            Some(plan),
        )
    }

    fn argv_linked(
        services: &[Service],
        env: &Env,
        existing: &[(&str, Kind)],
        links: &[(&str, &str)],
    ) -> Result<Vec<String>, LaunchError> {
        argv_planned(services, env, existing, links, None)
    }

    /// The host tree a test names, with the type the fake reports for
    /// each entry and the symlinks laid over them.
    fn fake_host(existing: &[(&str, Kind)], links: &[(&str, &str)]) -> FakeHost {
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
        host
    }

    fn argv_planned(
        services: &[Service],
        env: &Env,
        existing: &[(&str, Kind)],
        links: &[(&str, &str)],
        wayland: Option<&WaylandPlan>,
    ) -> Result<Vec<String>, LaunchError> {
        let host = fake_host(existing, links);
        let plan = dbus::plan(services, "t");
        let ctx = ServiceCtx {
            wayland,
            ..argv_ctx(&plan)
        };
        let mut args = BwrapArgs::baseline(env, Path::new("/i/home"), &host);
        apply_all(services, env, &mut args, &host, &ctx)?;
        Ok(strs(&args.finish(
            &[OsString::from("x")],
            &mut crate::launcher::DryRunAlloc::default(),
        )?))
    }

    /// `argv` with the per-run shares bound on top of the services, in
    /// the one order the launcher uses: the config's own grants first.
    fn argv_shared(
        services: &[Service],
        shares: &[Share],
        existing: &[(&str, Kind)],
    ) -> Result<Vec<String>, LaunchError> {
        argv_shared_linked(services, shares, existing, &[])
    }

    fn argv_shared_linked(
        services: &[Service],
        shares: &[Share],
        existing: &[(&str, Kind)],
        links: &[(&str, &str)],
    ) -> Result<Vec<String>, LaunchError> {
        let env = env();
        let host = fake_host(existing, links);
        let plan = dbus::plan(services, "t");
        let mut args = BwrapArgs::baseline(&env, Path::new("/i/home"), &host);
        apply_all(services, &env, &mut args, &host, &argv_ctx(&plan))?;
        apply_shares(services, shares, &env, &mut args, &host)?;
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
            &[Service::Wayland(WaylandMode::default())],
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

    /// The shape check is the value's, not the bind's: the launcher runs
    /// the process environment's own `$WAYLAND_DISPLAY` through it before
    /// it connects to the compositor, so it has to refuse on a bare
    /// string with no [`Env`] around it.
    #[test]
    fn wayland_display_is_a_socket_name_or_nothing() {
        assert_eq!(
            check_wayland_display(Some(OsStr::new("wayland-1"))).unwrap(),
            OsStr::new("wayland-1")
        );
        for bad in [
            "/run/user/1000/wayland-1",
            "../wayland-1",
            "a/b",
            ".",
            "..",
            "",
        ] {
            let err = check_wayland_display(Some(OsStr::new(bad))).expect_err(bad);
            assert!(
                matches!(
                    err,
                    LaunchError::BadValue {
                        service: "wayland",
                        ..
                    }
                ),
                "{bad}: {err:?}"
            );
        }
        assert!(matches!(
            check_wayland_display(None),
            Err(LaunchError::MissingEnv {
                service: "wayland",
                var: "WAYLAND_DISPLAY"
            })
        ));
        // The wrapper is the same check on the value the bind uses.
        let mut e = env();
        assert_eq!(wayland_display(&e).unwrap(), OsStr::new("wayland-1"));
        e.wayland_display = Some("../wayland-1".into());
        assert!(wayland_display(&e).is_err());
        e.wayland_display = None;
        assert!(wayland_display(&e).is_err());
    }

    /// The proxy's own socket is bound at the host socket's name, and is
    /// not probed: it is created after the argv is built. The name is
    /// still validated, so a plan cannot smuggle a path past that check.
    #[test]
    fn wayland_context_binds_bubblers_socket_at_the_host_name() {
        let plan = WaylandPlan::Proxy {
            socket: "/run/user/1000/bubbler/t/wayland".into(),
        };
        let a = argv_wayland(&plan, &env(), &[]).unwrap();
        assert!(
            has_seq(
                &a,
                &[
                    "--ro-bind",
                    "/run/user/1000/bubbler/t/wayland",
                    "/run/user/1000/wayland-1"
                ]
            ),
            "{a:?}"
        );
        assert!(
            has_seq(&a, &["--setenv", "WAYLAND_DISPLAY", "wayland-1"]),
            "{a:?}"
        );
        let mut e = env();
        e.wayland_display = Some("nested/wayland-1".into());
        assert!(matches!(
            argv_wayland(&plan, &e, &[]),
            Err(LaunchError::BadValue {
                service: "wayland",
                ..
            })
        ));
    }

    /// `wayland "host"` binds the session's own socket, and still
    /// requires it to be there and to be a socket.
    #[test]
    fn wayland_host_binds_the_session_socket() {
        let plan = WaylandPlan::Host;
        let a = argv_wayland(&plan, &env(), &[("/run/user/1000/wayland-1", Sock)]).unwrap();
        assert!(
            has_seq(
                &a,
                &[
                    "--ro-bind",
                    "/run/user/1000/wayland-1",
                    "/run/user/1000/wayland-1"
                ]
            ),
            "{a:?}"
        );
        assert!(
            argv_wayland(&plan, &env(), &[]).is_err(),
            "the host socket is still required to be there"
        );
    }

    #[test]
    fn wayland_missing_socket_or_env_fails() {
        assert!(matches!(
            argv(&[Service::Wayland(WaylandMode::default())], &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "wayland",
                ..
            })
        ));
        let mut e = env();
        e.wayland_display = None;
        assert!(matches!(
            argv(&[Service::Wayland(WaylandMode::default())], &e, &[]),
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
                    &[Service::Wayland(WaylandMode::default())],
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
            &[Service::X11(X11Mode::Host)],
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

    /// The nested server runs inside the sandbox, so nothing of the
    /// host's display is bound for it and no cookie is handed over:
    /// `DISPLAY` and the server's own argv are the whole of what the
    /// grant emits, and they hold even where the session has no X server
    /// at all.
    #[test]
    fn nested_x11_binds_nothing_and_only_names_the_display() {
        let mut e = env();
        e.display = None;
        let a = argv(
            &[Service::X11(X11Mode::default())],
            &e,
            &[
                ("/usr/bin/Xwayland", File),
                ("/tmp/.X11-unix/X0", Sock),
                ("/run/user/1000/Xauthority", File),
            ],
        )
        .unwrap();
        assert!(has_seq(&a, &["--setenv", "DISPLAY", ":0"]));
        assert!(!a.iter().any(|w| w.contains(".X11-unix")), "{a:?}");
        assert!(!a.contains(&"XAUTHORITY".to_owned()), "{a:?}");
        assert!(
            !a.contains(&"/run/user/1000/Xauthority".to_owned()),
            "{a:?}"
        );
    }

    /// The supervisor is handed the server's command line, ended by a
    /// `--` of its own so the sandbox's command still follows it: these
    /// words are the argv `bubbler-init` runs, `-listenfd` aside. A
    /// window manager the node names follows that `--` as an argument
    /// of the supervisor's, never as a flag of the server's.
    #[test]
    fn nested_x11_hands_the_supervisor_the_server_argv() {
        let a = argv(
            &[Service::X11(X11Mode::default())],
            &env(),
            &[("/usr/bin/Xwayland", File)],
        )
        .unwrap();
        let tail = [
            "--x11",
            "/usr/bin/Xwayland",
            ":0",
            "-noreset",
            "-nolisten",
            "tcp",
            "-nolisten",
            "local",
            "-nolisten",
            "unix",
            "-ac",
            "-hidpi",
            "-decorate",
            "-geometry",
            "1280x720",
            "--",
            "--",
            "x",
        ];
        assert_eq!(a[a.len() - tail.len()..], tail, "{a:?}");
        let wm = argv(
            &[Service::X11(X11Mode::Nested(NestedX11 {
                wm: Some("openbox".to_owned()),
                ..NestedX11::default()
            }))],
            &env(),
            &[("/usr/bin/Xwayland", File)],
        )
        .unwrap();
        assert_eq!(wm[wm.len() - 4..], ["--wm", "openbox", "--", "x"], "{wm:?}");
        // The name is the supervisor's argument alone; the server argv
        // ends before it, at its own `--`.
        assert_eq!(wm[wm.len() - 5], "--", "{wm:?}");
        assert!(!wm.contains(&"-wm".to_owned()), "{wm:?}");
    }

    /// A host without `xorg-xwayland` has no server to nest, and the run
    /// is refused before it starts rather than leaving the sandbox with a
    /// `DISPLAY` that names nothing.
    #[test]
    fn nested_x11_without_xwayland_on_the_host_fails() {
        assert!(matches!(
            argv(&[Service::X11(X11Mode::default())], &env(), &[]),
            Err(LaunchError::MissingResource { service: "x11", .. })
        ));
    }

    #[test]
    fn x11_falls_back_to_home_xauthority_or_none() {
        let mut e = env();
        e.xauthority = None;
        let a = argv(
            &[Service::X11(X11Mode::Host)],
            &e,
            &[
                ("/tmp/.X11-unix/X0", Sock),
                ("/home/user/.Xauthority", File),
            ],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/home/user/.Xauthority",
                "/home/bubbler/.Xauthority"
            ]
        ));
        assert!(has_seq(
            &a,
            &["--setenv", "XAUTHORITY", "/home/bubbler/.Xauthority"]
        ));
        let a = argv(
            &[Service::X11(X11Mode::Host)],
            &e,
            &[("/tmp/.X11-unix/X0", Sock)],
        )
        .unwrap();
        assert!(!a.contains(&"XAUTHORITY".to_string()));
    }

    #[test]
    fn x11_fallback_xauthority_that_is_a_directory_is_skipped() {
        let mut e = env();
        e.xauthority = None;
        let a = argv(
            &[Service::X11(X11Mode::Host)],
            &e,
            &[("/tmp/.X11-unix/X0", Sock), ("/home/user/.Xauthority", Dir)],
        )
        .unwrap();
        assert!(!a.contains(&"XAUTHORITY".to_string()));
        assert!(!a.contains(&"/home/user/.Xauthority".to_string()));
    }

    #[test]
    fn x11_set_but_missing_xauthority_fails() {
        assert!(matches!(
            argv(
                &[Service::X11(X11Mode::Host)],
                &env(),
                &[("/tmp/.X11-unix/X0", Sock)]
            ),
            Err(LaunchError::MissingResource { service: "x11", .. })
        ));
    }

    #[test]
    fn x11_xauthority_at_a_directory_fails() {
        let mut e = env();
        e.xauthority = Some("/".into());
        assert!(matches!(
            argv(
                &[Service::X11(X11Mode::Host)],
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
            argv(
                &[Service::X11(X11Mode::Host)],
                &env(),
                &[("/tmp/.X11-unix/X0", File)]
            ),
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
                &[Service::Wayland(WaylandMode::default())],
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
                &[Service::Wayland(WaylandMode::default())],
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
                        &[Service::Wayland(WaylandMode::default())],
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
                &[Service::Wayland(WaylandMode::default())],
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
            argv(&[Service::X11(X11Mode::Host)], &e, &[]),
            Err(LaunchError::MissingEnv {
                service: "x11",
                var: "DISPLAY"
            })
        ));
    }

    #[test]
    fn wayland_and_x11_together_do_not_claim_wayland_session() {
        let a = argv(
            &[
                Service::Wayland(WaylandMode::default()),
                Service::X11(X11Mode::Host),
            ],
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
                optional: false,
            },
            Service::HomeShare {
                path: "Projects/x".into(),
                mode: ShareMode::ReadWrite,
                optional: false,
            },
        ];
        let a = argv(
            &svcs,
            &env(),
            &[
                ("/home/user/Downloads", Dir),
                ("/home/user/Projects/x", Dir),
            ],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/home/user/Downloads",
                "/home/bubbler/Downloads"
            ]
        ));
        assert!(has_seq(
            &a,
            &[
                "--bind",
                "/home/user/Projects/x",
                "/home/bubbler/Projects/x"
            ]
        ));
    }

    #[test]
    fn home_share_accepts_any_type_but_needs_the_source() {
        let svcs = [Service::HomeShare {
            path: "notes.txt".into(),
            mode: ShareMode::ReadOnly,
            optional: false,
        }];
        let a = argv(&svcs, &env(), &[("/home/user/notes.txt", File)]).unwrap();
        assert!(has_seq(
            &a,
            &[
                "--ro-bind",
                "/home/user/notes.txt",
                "/home/bubbler/notes.txt"
            ]
        ));
    }

    #[test]
    fn home_share_missing_source_fails() {
        let svcs = [Service::HomeShare {
            path: "Nope".into(),
            mode: ShareMode::ReadOnly,
            optional: false,
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
    fn home_share_optional_and_absent_binds_nothing_and_does_not_fail() {
        let svcs = [Service::HomeShare {
            path: "Nope".into(),
            mode: ShareMode::ReadOnly,
            optional: true,
        }];
        let a = argv(&svcs, &env(), &[]).unwrap();
        assert!(!a.iter().any(|s| s.contains("Nope")), "{a:?}");
    }

    #[test]
    fn home_share_optional_and_present_binds_exactly_as_a_required_one_would() {
        let present = |optional| {
            argv(
                &[Service::HomeShare {
                    path: "Downloads".into(),
                    mode: ShareMode::ReadOnly,
                    optional,
                }],
                &env(),
                &[("/home/user/Downloads", Dir)],
            )
            .unwrap()
        };
        assert_eq!(present(true), present(false));
    }

    #[test]
    fn home_share_through_a_symlink_out_of_the_home_is_refused() {
        let svcs = [Service::HomeShare {
            path: "RootLink".into(),
            mode: ShareMode::ReadWrite,
            optional: false,
        }];
        let r = argv_linked(
            &svcs,
            &env(),
            &[("/home/user/RootLink", Dir), ("/", Dir)],
            &[("/home/user/RootLink", "/")],
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
            optional: false,
        }];
        let a = argv_linked(
            &svcs,
            &env(),
            &[("/home/user/Downloads", Dir), ("/home/user/dl", Dir)],
            &[("/home/user/Downloads", "/home/user/dl")],
        )
        .unwrap();
        assert!(has_seq(
            &a,
            &["--ro-bind", "/home/user/dl", "/home/bubbler/Downloads"]
        ));
    }

    #[test]
    fn home_share_needs_a_home_that_resolves() {
        let svcs = [Service::HomeShare {
            path: "Downloads".into(),
            mode: ShareMode::ReadOnly,
            optional: false,
        }];
        let (_, dir, _) = fake::types();
        let host = FakeHost::default().with("/home/user/Downloads", dir);
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
            fn writable(&self, p: &Path) -> bool {
                Host::writable(&self.0, p)
            }
            fn read_link(&self, p: &Path) -> std::io::Result<Option<PathBuf>> {
                self.0.read_link(p)
            }
            fn read_text(&self, p: &Path, limit: u64) -> Option<String> {
                self.0.read_text(p, limit)
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

    /// `$BUBBLER_PROFILE_DIR` moves the system profile layer, and the
    /// layer is reserved wherever it is: a sandbox that can write a
    /// profile there writes the config of every instance seeded from it
    /// afterwards. Under the home it is reachable by a relative path.
    #[test]
    fn home_share_of_the_profile_dir_override_is_refused() {
        let mut e = env();
        let dir = home("myprofiles");
        e.profile_dir_override = Some(PathBuf::from(&dir));
        let svcs = [Service::HomeShare {
            path: "myprofiles".into(),
            mode: ShareMode::ReadWrite,
            optional: false,
        }];
        let err = argv(&svcs, &e, &[(&dir, Dir)]).unwrap_err();
        assert!(
            matches!(&err, LaunchError::BadValue { service: "home-share", reason }
                if reason == &format!("bubbler never shares {dir}")),
            "{err}"
        );
    }

    /// And outside the home, where `path-share` is what reaches it —
    /// the directory itself and anything containing it.
    #[test]
    fn path_share_of_the_profile_dir_override_is_refused() {
        let mut e = env();
        e.profile_dir_override = Some(PathBuf::from("/kioxia/profiles"));
        for (path, want) in [
            (
                "/kioxia/profiles",
                "bubbler never shares /kioxia/profiles".to_owned(),
            ),
            (
                "/kioxia",
                "bubbler never shares /kioxia, which overlaps /kioxia/profiles".to_owned(),
            ),
        ] {
            let svcs = [Service::PathShare {
                path: path.into(),
                mode: ShareMode::ReadWrite,
                optional: false,
            }];
            let err = argv(&svcs, &e, &[(path, Dir), ("/kioxia/profiles", Dir)]).unwrap_err();
            assert!(
                matches!(&err, LaunchError::BadValue { service: "path-share", reason }
                    if reason == &want),
                "{path}: {err}"
            );
        }
    }

    /// The home of [`env`], as a test writes host paths out.
    fn home(rel: &str) -> String {
        env().home.join(rel).to_string_lossy().into_owned()
    }

    /// The instance store is bubbler's own directory: read-write the
    /// sandbox rewrites the `config.kdl` it was launched from and grants
    /// itself anything on the next run, and read-only it reads every
    /// other instance's config and private home. Both modes are refused,
    /// as they are for `path-share` and `--share`.
    #[test]
    fn home_share_of_the_instance_store_is_refused() {
        let store = home(".local/share/bubbler");
        for mode in [ShareMode::ReadWrite, ShareMode::ReadOnly] {
            let svcs = [Service::HomeShare {
                path: ".local/share/bubbler".into(),
                mode,
                optional: false,
            }];
            let e = argv(&svcs, &env(), &[(&store, Dir)]).unwrap_err();
            assert!(
                matches!(&e, LaunchError::BadValue { service: "home-share", reason }
                    if reason == &format!("bubbler never shares {store}")),
                "{mode:?}: {e}"
            );
        }
    }

    /// The user's profile layer, for the same reason: a sandbox that can
    /// write a profile there writes the config of every instance seeded
    /// from it afterwards.
    #[test]
    fn home_share_of_the_profile_layer_is_refused() {
        let layer = home(".config/bubbler");
        let svcs = [Service::HomeShare {
            path: ".config/bubbler".into(),
            mode: ShareMode::ReadOnly,
            optional: false,
        }];
        let e = argv(&svcs, &env(), &[(&layer, Dir)]).unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "home-share", reason }
                if reason == &format!("bubbler never shares {layer}")),
            "{e}"
        );
    }

    /// An ancestor is refused with them: a bind of `.local/share` covers
    /// the store under it, so the share reaches it either way.
    #[test]
    fn home_share_of_an_ancestor_of_the_instance_store_is_refused() {
        let above = home(".local/share");
        let store = home(".local/share/bubbler");
        let svcs = [Service::HomeShare {
            path: ".local/share".into(),
            mode: ShareMode::ReadOnly,
            optional: false,
        }];
        let e = argv(&svcs, &env(), &[(&above, Dir)]).unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "home-share", reason }
                if reason == &format!("bubbler never shares {above}, which overlaps {store}")),
            "{e}"
        );
    }

    /// A directory beside the store is nothing of bubbler's, and the
    /// check does not widen to the parent it shares with it.
    #[test]
    fn home_share_beside_the_instance_store_still_binds() {
        let other = home(".local/share/Other");
        let svcs = [Service::HomeShare {
            path: ".local/share/Other".into(),
            mode: ShareMode::ReadOnly,
            optional: false,
        }];
        let a = argv(&svcs, &env(), &[(&other, Dir)]).unwrap();
        assert!(
            has_seq(
                &a,
                &["--ro-bind", &other, "/home/bubbler/.local/share/Other"]
            ),
            "{a:?}"
        );
    }

    #[test]
    fn a_share_under_the_home_lands_in_the_private_home_read_write() {
        let src = home("Projects/app");
        let a = argv_shared(
            &[],
            &[Share {
                path: PathBuf::from(&src),
                mode: ShareMode::ReadWrite,
            }],
            &[(&src, Dir)],
        )
        .unwrap();
        assert!(
            has_seq(&a, &["--bind", &src, "/home/bubbler/Projects/app"]),
            "{a:?}"
        );
        assert!(
            has_seq(&a, &["--chdir", "/home/bubbler/Projects/app"]),
            "{a:?}"
        );
        assert!(!has_seq(&a, &["--chdir", "/home/bubbler"]), "{a:?}");
    }

    #[test]
    fn a_share_outside_the_home_keeps_its_path_and_a_file_share_moves_no_cwd() {
        let a = argv_shared(
            &[],
            &[
                Share {
                    path: PathBuf::from("/srv/notes.txt"),
                    mode: ShareMode::ReadOnly,
                },
                Share {
                    path: PathBuf::from("/srv/src"),
                    mode: ShareMode::ReadWrite,
                },
            ],
            &[("/srv/notes.txt", File), ("/srv/src", Dir)],
        )
        .unwrap();
        assert!(
            has_seq(&a, &["--ro-bind", "/srv/notes.txt", "/srv/notes.txt"]),
            "{a:?}"
        );
        assert!(has_seq(&a, &["--bind", "/srv/src", "/srv/src"]), "{a:?}");
        // The first *directory* share is the cwd, not the first share.
        assert!(has_seq(&a, &["--chdir", "/srv/src"]), "{a:?}");
    }

    #[test]
    fn a_share_is_refused_where_the_config_nodes_would_refuse_it() {
        // Missing source.
        let e = argv_shared(
            &[],
            &[Share {
                path: PathBuf::from("/srv/none"),
                mode: ShareMode::ReadWrite,
            }],
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(
                e,
                LaunchError::MissingResource {
                    service: "--share",
                    ..
                }
            ),
            "{e}"
        );
        // A reserved root.
        let e = argv_shared(
            &[],
            &[Share {
                path: PathBuf::from("/etc"),
                mode: ShareMode::ReadOnly,
            }],
            &[("/etc", Dir)],
        )
        .unwrap_err();
        assert!(
            matches!(
                e,
                LaunchError::BadValue {
                    service: "--share",
                    ..
                }
            ),
            "{e}"
        );
        // Already shared by the config.
        let src = home("Projects/app");
        let e = argv_shared(
            &[Service::HomeShare {
                path: PathBuf::from("Projects/app"),
                mode: ShareMode::ReadOnly,
                optional: false,
            }],
            &[Share {
                path: PathBuf::from(&src),
                mode: ShareMode::ReadWrite,
            }],
            &[(&src, Dir)],
        )
        .unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "--share", reason } if reason.contains("already shared by config.kdl")),
            "{e}"
        );
        // Given twice.
        let s = Share {
            path: PathBuf::from("/srv/src"),
            mode: ShareMode::ReadWrite,
        };
        let e = argv_shared(&[], &[s.clone(), s], &[("/srv/src", Dir)]).unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "--share", reason } if reason.contains("given twice")),
            "{e}"
        );
    }

    /// The roots that live under the real home — the instance store and
    /// the profile layer — are the ones only this branch can reach, and
    /// a sandbox that can write either one writes the config of every
    /// instance seeded afterwards.
    #[test]
    fn a_share_of_a_reserved_root_under_the_home_is_refused() {
        let store = home(".local/share/bubbler");
        let e = argv_shared(
            &[],
            &[Share {
                path: PathBuf::from(&store),
                mode: ShareMode::ReadWrite,
            }],
            &[(&store, Dir)],
        )
        .unwrap_err();
        let LaunchError::BadValue { service, reason } = &e else {
            panic!("{e}");
        };
        assert_eq!(*service, "--share");
        assert_eq!(reason, &format!("bubbler never shares {store}"));
        // And its ancestors with it: a bind of one covers the root under
        // it, which is why `path-share` refuses both ends.
        let above = home(".local/share");
        let e = argv_shared(
            &[],
            &[Share {
                path: PathBuf::from(&above),
                mode: ShareMode::ReadWrite,
            }],
            &[(&above, Dir)],
        )
        .unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "--share", reason }
                if reason == &format!("bubbler never shares {above}, which overlaps {store}")),
            "{e}"
        );
    }

    /// The config nodes are normalised by the parser; a flag is checked
    /// here. A `..` would be a component of the destination as well, so
    /// every comparison below it — the private home, the duplicates, the
    /// overlaps — would compare a path that is not the one bwrap mounts.
    #[test]
    fn a_share_with_a_dot_component_or_no_root_is_refused() {
        let dots = [PathBuf::from("/srv/a/../b"), env().home.join("Projects/..")];
        for path in dots {
            let e = argv_shared(
                &[],
                &[Share {
                    path: path.clone(),
                    mode: ShareMode::ReadWrite,
                }],
                &[("/srv/a", Dir), ("/srv/b", Dir), (&home("Projects"), Dir)],
            )
            .unwrap_err();
            assert!(
                matches!(&e, LaunchError::BadValue { service: "--share", reason }
                    if reason == &format!("{} contains `.` or `..`; give the path without them", path.display())),
                "{e}"
            );
        }
        // The CLI joins the caller's cwd, so a relative path here is a
        // caller that did not; it is refused rather than joined to
        // anything of bubbler's own.
        let e = argv_shared(
            &[],
            &[Share {
                path: PathBuf::from("srv/a"),
                mode: ShareMode::ReadWrite,
            }],
            &[("/srv/a", Dir)],
        )
        .unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "--share", reason }
                if reason == "srv/a is not absolute"),
            "{e}"
        );
    }

    /// A `home-share` binds the path its source resolves to, so a
    /// symlink in the home makes the node's two sides different paths.
    /// The flag names the symlink, lands somewhere else inside the
    /// sandbox, and would bind the same host tree a second time.
    #[test]
    fn a_share_through_a_symlink_onto_a_config_share_is_refused() {
        let e = argv_shared_linked(
            &[Service::HomeShare {
                path: PathBuf::from("Projects/app"),
                mode: ShareMode::ReadOnly,
                optional: false,
            }],
            &[Share {
                path: PathBuf::from(home("app")),
                mode: ShareMode::ReadWrite,
            }],
            &[(&home("Projects/app"), Dir)],
            &[(&home("app"), &home("Projects/app"))],
        )
        .unwrap_err();
        let LaunchError::BadValue { service, reason } = &e else {
            panic!("{e}");
        };
        assert_eq!(*service, "--share");
        assert_eq!(
            reason,
            &format!(
                "/home/bubbler/app and /home/bubbler/Projects/app overlap \
                 (they resolve to {0} and {0}); one share cannot contain another",
                home("Projects/app")
            )
        );
    }

    /// Shares are bound after the config's own grants, which is what the
    /// overlap rule rests on: bwrap applies binds in the order it is
    /// given them.
    #[test]
    fn a_share_is_bound_after_the_config_binds() {
        let a = argv_shared(
            &[Service::HomeShare {
                path: PathBuf::from("Downloads"),
                mode: ShareMode::ReadOnly,
                optional: false,
            }],
            &[Share {
                path: PathBuf::from(home("Projects/app")),
                mode: ShareMode::ReadWrite,
            }],
            &[(&home("Downloads"), Dir), (&home("Projects/app"), Dir)],
        )
        .unwrap();
        let at = |p: String| a.iter().position(|x| *x == p);
        assert!(at(home("Downloads")) < at(home("Projects/app")), "{a:?}");
    }

    /// The overlap rule two `path-share` nodes are held to, applied to
    /// the flags: bwrap binds in the order it is given, so one share
    /// inside another either fails or hides it, depending on which was
    /// written first.
    #[test]
    fn a_share_that_contains_another_share_is_refused() {
        let e = argv_shared(
            &[],
            &[
                Share {
                    path: PathBuf::from("/srv/a"),
                    mode: ShareMode::ReadWrite,
                },
                Share {
                    path: PathBuf::from("/srv/a/b"),
                    mode: ShareMode::ReadWrite,
                },
            ],
            &[("/srv/a", Dir), ("/srv/a/b", Dir)],
        )
        .unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "--share", reason }
                if reason == "/srv/a/b and /srv/a overlap; one share cannot contain another"),
            "{e}"
        );
    }

    /// The same rule against the config's own shares, on the mapped
    /// destinations: the flag names a host path, the node a relative one,
    /// and only inside the sandbox are the two comparable.
    #[test]
    fn a_share_inside_a_config_share_is_refused() {
        let e = argv_shared(
            &[Service::HomeShare {
                path: PathBuf::from("Projects/app"),
                mode: ShareMode::ReadOnly,
                optional: false,
            }],
            &[Share {
                path: PathBuf::from(home("Projects/app/sub")),
                mode: ShareMode::ReadWrite,
            }],
            &[
                (&home("Projects/app"), Dir),
                (&home("Projects/app/sub"), Dir),
            ],
        )
        .unwrap_err();
        let LaunchError::BadValue { service, reason } = &e else {
            panic!("{e}");
        };
        assert_eq!(*service, "--share");
        assert_eq!(
            reason,
            "/home/bubbler/Projects/app/sub and /home/bubbler/Projects/app overlap; \
             one share cannot contain another"
        );
    }

    /// The real home over the private one is the one mapping that takes
    /// the sandbox apart, and it is the destination rule `path-share`
    /// already has, applied to the branch that maps into the home.
    #[test]
    fn a_share_of_the_home_itself_is_refused() {
        let src = env().home;
        let e = argv_shared(
            &[],
            &[Share {
                path: src.clone(),
                mode: ShareMode::ReadWrite,
            }],
            &[(&src.to_string_lossy(), Dir)],
        )
        .unwrap_err();
        assert!(
            matches!(&e, LaunchError::BadValue { service: "--share", reason } if reason.contains("/home/bubbler")),
            "{e}"
        );
    }

    fn share(path: &str, mode: ShareMode) -> Service {
        Service::PathShare {
            path: path.into(),
            mode,
            optional: false,
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
            ("/home", "/home/user"),
            ("/home/other", "/home"),
            ("/home/user", "/home/user"),
            ("/home/user/Downloads", "/home/user"),
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
                &[("/home/user/.local/share/bubbler", "/kioxia/bubbler")],
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
    fn path_share_optional_and_absent_binds_nothing_and_does_not_fail() {
        let svcs = [Service::PathShare {
            path: "/kioxia/Steam".into(),
            mode: ShareMode::ReadOnly,
            optional: true,
        }];
        let a = argv(&svcs, &env(), &[]).unwrap();
        assert!(!a.iter().any(|s| s.contains("Steam")), "{a:?}");
    }

    #[test]
    fn path_share_optional_and_present_binds_exactly_as_a_required_one_would() {
        let present = |optional| {
            argv(
                &[Service::PathShare {
                    path: "/kioxia/Steam".into(),
                    mode: ShareMode::ReadOnly,
                    optional,
                }],
                &env(),
                &[("/kioxia/Steam", Dir)],
            )
            .unwrap()
        };
        assert_eq!(present(true), present(false));
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
        // Outside the home, so `/home/user` is not what stops these.
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
        for dst in ["/home/bubbler/x", "/home/user/x"] {
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
            &[("/etc/escape", Dir), ("/home/user", Dir)],
            &[("/etc/escape", "/home/user")],
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

    /// The two GPUs of a hybrid desktop, laid out the way the host lays
    /// them out: a `by-path` entry per node, a primary and a render node
    /// each, and each GPU's own directory under `/sys/devices` holding
    /// the `drm/` children the kernel puts there.
    const GPU_A: &str = "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0";
    const GPU_B: &str = "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0";

    fn two_gpu_host() -> Vec<(&'static str, Kind)> {
        vec![
            ("/dev/dri", Dir),
            ("/dev/dri/by-path", Dir),
            ("/dev/dri/by-path/pci-0000:01:00.0-card", Char),
            ("/dev/dri/by-path/pci-0000:01:00.0-render", Char),
            ("/dev/dri/by-path/pci-0000:0c:00.0-card", Char),
            ("/dev/dri/by-path/pci-0000:0c:00.0-render", Char),
            ("/dev/dri/card0", Char),
            ("/dev/dri/card1", Char),
            ("/dev/dri/renderD128", Char),
            ("/dev/dri/renderD129", Char),
            ("/sys/dev/char", Dir),
            ("/sys/devices/system/cpu", Dir),
            ("/sys/class/drm/version", File),
            (GPU_A, Dir),
            ("/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm", Dir),
            (
                "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1",
                Dir,
            ),
            (
                "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/controlD65",
                Dir,
            ),
            (
                "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/renderD128",
                Dir,
            ),
            (GPU_B, Dir),
            ("/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm", Dir),
            (
                "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/card0",
                Dir,
            ),
            (
                "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/controlD64",
                Dir,
            ),
            (
                "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/renderD129",
                Dir,
            ),
        ]
    }

    fn two_gpu_links() -> Vec<(&'static str, &'static str)> {
        vec![
            ("/dev/dri/by-path/pci-0000:01:00.0-card", "../card1"),
            ("/dev/dri/by-path/pci-0000:01:00.0-render", "../renderD128"),
            ("/dev/dri/by-path/pci-0000:0c:00.0-card", "../card0"),
            ("/dev/dri/by-path/pci-0000:0c:00.0-render", "../renderD129"),
            ("/sys/class/drm/renderD128/device", GPU_A),
            ("/sys/class/drm/renderD129/device", GPU_B),
            (
                "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/driver",
                "../../../../bus/pci/drivers/amdgpu",
            ),
            (
                "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/driver",
                "../../../../bus/pci/drivers/amdgpu",
            ),
        ]
    }

    /// [`two_gpu_links`] with the first GPU driven by the proprietary
    /// NVIDIA driver, as this desktop has it.
    fn nvidia_gpu_links() -> Vec<(&'static str, &'static str)> {
        two_gpu_links()
            .into_iter()
            .map(|(from, to)| match from {
                "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/driver" => {
                    (from, "../../../../bus/pci/drivers/nvidia")
                }
                _ => (from, to),
            })
            .collect()
    }

    /// What a bare `dri` binds on [`two_gpu_host`]. The masks it also
    /// emits are [`two_gpu_masks`], which every grant's binds come
    /// before.
    fn two_gpu_binds() -> Vec<&'static str> {
        vec![
            "--dev-bind",
            "/dev/dri/renderD128",
            "/dev/dri/renderD128",
            "--dev-bind",
            "/dev/dri/renderD129",
            "/dev/dri/renderD129",
            "--ro-bind",
            "/sys/dev/char",
            "/sys/dev/char",
            "--ro-bind",
            "/sys/devices/system/cpu",
            "/sys/devices/system/cpu",
            "--ro-bind",
            GPU_A,
            GPU_A,
            "--symlink",
            "../../devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/renderD128",
            "/sys/class/drm/renderD128",
            "--ro-bind",
            GPU_B,
            GPU_B,
            "--symlink",
            "../../devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/renderD129",
            "/sys/class/drm/renderD129",
            "--ro-bind",
            "/sys/class/drm/version",
            "/sys/class/drm/version",
        ]
    }

    /// The card directories a bare `dri` covers on [`two_gpu_host`], in
    /// the place the builder emits every mask: after the binds.
    fn two_gpu_masks() -> Vec<&'static str> {
        vec![
            "--size",
            "4096",
            "--tmpfs",
            "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1",
            "--remount-ro",
            "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1",
            "--size",
            "4096",
            "--tmpfs",
            "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/card0",
            "--remount-ro",
            "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/card0",
        ]
    }

    #[test]
    fn dri_binds_the_render_nodes_and_each_gpus_own_sysfs() {
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &two_gpu_host(),
            &two_gpu_links(),
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            [two_gpu_binds(), two_gpu_masks()].concat(),
            "no card node, no `/dev/dri` itself, no `by-path`, no PCI root and no \
             `/sys/class/drm` around the two symlinks"
        );
    }

    #[test]
    fn dri_binds_the_primary_node_of_an_nvidia_gpu_and_of_no_other() {
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &two_gpu_host(),
            &nvidia_gpu_links(),
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            [
                vec![
                    "--dev-bind",
                    "/dev/dri/renderD128",
                    "/dev/dri/renderD128",
                    "--dev-bind",
                    "/dev/dri/renderD129",
                    "/dev/dri/renderD129",
                    "--ro-bind",
                    "/sys/dev/char",
                    "/sys/dev/char",
                    "--ro-bind",
                    "/sys/devices/system/cpu",
                    "/sys/devices/system/cpu",
                    "--ro-bind",
                    GPU_A,
                    GPU_A,
                    "--dev-bind",
                    "/dev/dri/card1",
                    "/dev/dri/card1",
                    "--symlink",
                    "../../devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/renderD128",
                    "/sys/class/drm/renderD128",
                    "--ro-bind",
                    GPU_B,
                    GPU_B,
                    "--symlink",
                    "../../devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/renderD129",
                    "/sys/class/drm/renderD129",
                    "--ro-bind",
                    "/sys/class/drm/version",
                    "/sys/class/drm/version",
                ],
                two_gpu_masks(),
            ]
            .concat(),
            "the Mesa-driven GPU keeps its primary node out, and both card \
             directories stay masked"
        );
    }

    #[test]
    fn dri_kms_adds_the_card_nodes_and_leaves_their_sysfs_readable() {
        let a = argv_linked(
            &[Service::Dri { kms: true }],
            &env(),
            &two_gpu_host(),
            &two_gpu_links(),
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            vec![
                "--dev-bind",
                "/dev/dri/renderD128",
                "/dev/dri/renderD128",
                "--dev-bind",
                "/dev/dri/renderD129",
                "/dev/dri/renderD129",
                "--dev-bind",
                "/dev/dri/card0",
                "/dev/dri/card0",
                "--dev-bind",
                "/dev/dri/card1",
                "/dev/dri/card1",
                "--ro-bind",
                "/sys/dev/char",
                "/sys/dev/char",
                "--ro-bind",
                "/sys/devices/system/cpu",
                "/sys/devices/system/cpu",
                "--ro-bind",
                GPU_A,
                GPU_A,
                "--symlink",
                "../../devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/renderD128",
                "/sys/class/drm/renderD128",
                "--ro-bind",
                GPU_B,
                GPU_B,
                "--symlink",
                "../../devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/renderD129",
                "/sys/class/drm/renderD129",
                "--ro-bind",
                "/sys/class/drm/version",
                "/sys/class/drm/version",
            ]
        );
    }

    #[test]
    fn dris_card_masks_survive_a_gamepads_whole_device_tree() {
        let card_a = "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1";
        let mut host = gamepad_host();
        host.extend(two_gpu_host());
        for order in [
            [Service::Dri { kms: false }, pad(false, false)],
            [pad(false, false), Service::Dri { kms: false }],
        ] {
            let a = argv_linked(&order, &env(), &host, &two_gpu_links()).unwrap();
            let tree = seq_at(&a, &["--ro-bind", "/sys/devices", "/sys/devices"])
                .expect("gamepad binds the device tree");
            let mask = seq_at(&a, &["--size", "4096", "--tmpfs", card_a])
                .expect("dri masks the card directory");
            // A bind of the tree over a mask already laid would hand the
            // card sysfs back, so the masks are emitted last of all.
            assert!(tree < mask, "{order:?}: {a:?}");
            assert!(has_seq(&a, &["--remount-ro", card_a]), "{a:?}");
        }
        let kms = argv_linked(
            &[Service::Dri { kms: true }, pad(false, false)],
            &env(),
            &host,
            &two_gpu_links(),
        )
        .unwrap();
        assert!(
            !has_seq(&kms, &["--size", "4096", "--tmpfs", card_a]),
            "{kms:?}"
        );
    }

    #[test]
    fn dri_without_a_render_node_under_by_path_is_an_error() {
        // `by-path` is the only place a render node is discovered, so a
        // host that has none there fails rather than falling back to a
        // wider bind of `/dev/dri`.
        let host: Vec<(&str, Kind)> = two_gpu_host()
            .into_iter()
            .filter(|(p, _)| !p.ends_with("-render"))
            .collect();
        let links: Vec<(&str, &str)> = two_gpu_links()
            .into_iter()
            .filter(|(from, _)| !from.ends_with("-render"))
            .collect();
        assert!(matches!(
            argv_linked(&[Service::Dri { kms: false }], &env(), &host, &links),
            Err(LaunchError::MissingResource { service: "dri", path })
                if path == Path::new("/dev/dri/by-path")
        ));
    }

    #[test]
    fn dri_refuses_a_render_node_whose_sysfs_leaves_the_device_tree() {
        let links: Vec<(&str, &str)> = two_gpu_links()
            .into_iter()
            .map(|(from, to)| match from {
                "/sys/class/drm/renderD128/device" => (from, "/sys/class/misc"),
                _ => (from, to),
            })
            .collect();
        let r = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &two_gpu_host(),
            &links,
        );
        assert!(
            matches!(&r, Err(LaunchError::BadValue { service: "dri", reason })
                if reason.contains("/sys/devices")),
            "{r:?}"
        );
    }

    #[test]
    fn dri_binds_the_nvidia_nodes_and_the_module_directories() {
        let mut host = two_gpu_host();
        host.extend([
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
        ]);
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &host,
            &two_gpu_links(),
        )
        .unwrap();
        let mut expected = two_gpu_binds();
        expected.extend([
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
        ]);
        expected.extend(two_gpu_masks());
        assert_eq!(
            binds(&a),
            expected,
            "the /dev/nvidia-caps directory and unrelated module directories stay out, \
             and the card masks follow every bind"
        );
    }

    #[test]
    fn dri_adds_nothing_on_a_host_without_the_nvidia_stack() {
        let mut host = two_gpu_host();
        host.extend([
            ("/sys/module/amdgpu", Dir),
            // A directory named like a node is not one.
            ("/dev/nvidia-caps", Dir),
        ]);
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &host,
            &two_gpu_links(),
        )
        .unwrap();
        assert_eq!(binds(&a), [two_gpu_binds(), two_gpu_masks()].concat());
    }

    #[test]
    fn dri_requires_dev_dri_to_be_a_directory() {
        assert!(matches!(
            argv(
                &[Service::Dri { kms: false }],
                &env(),
                &[("/dev/dri", File)]
            ),
            Err(LaunchError::WrongType {
                service: "dri",
                expected: "a directory",
                ..
            })
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
        vec![
            Service::Dbus { rules: vec![] },
            Service::Portals {
                children: Vec::new(),
            },
        ]
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
    fn gamepad_binds_sysfs_devices_after_dris_gpu_directories_whatever_the_file_order() {
        let mut host = gamepad_host();
        host.extend(two_gpu_host());
        for order in [
            [Service::Dri { kms: false }, pad(false, false)],
            [pad(false, false), Service::Dri { kms: false }],
        ] {
            let a = argv_linked(&order, &env(), &host, &two_gpu_links()).unwrap();
            let gpu = seq_at(&a, &["--ro-bind", GPU_A, GPU_A]).expect("dri binds the GPU");
            let all = seq_at(&a, &["--ro-bind", "/sys/devices", "/sys/devices"])
                .expect("gamepad binds the device tree");
            assert!(gpu < all, "{order:?}: {a:?}");
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
    fn a11y_binds_the_proxied_bus_where_at_spi_clients_look_for_it() {
        let a = argv(
            &[Service::Dbus { rules: vec![] }, Service::A11y],
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
                    "/run/user/1000/bubbler/t/a11y",
                    "/run/user/1000/at-spi/bus"
                ]
            ),
            "{a:?}"
        );
        assert!(
            !a.iter().any(|s| s == "/run/user/1000/bubbler/t/dbus/a11y"),
            "the sandbox binds a path the proxy can still write to: {a:?}"
        );
        // What every at-spi2 client reads before it asks a bus anything,
        // pointed at the filtered socket rather than the session's.
        assert!(
            has_seq(
                &a,
                &[
                    "--setenv",
                    "AT_SPI_BUS_ADDRESS",
                    "unix:path=/run/user/1000/at-spi/bus"
                ]
            ),
            "{a:?}"
        );
        // Without the node neither the bind nor the variable is there.
        let bare = argv(&[Service::Dbus { rules: vec![] }], &env(), &[]).unwrap();
        assert!(!bare.iter().any(|s| s == "AT_SPI_BUS_ADDRESS"), "{bare:?}");
        assert!(!bare.iter().any(|s| s.contains("at-spi")), "{bare:?}");
    }

    #[test]
    fn a11y_without_a_bus_is_refused_rather_than_downgraded() {
        // The parser refuses that config, so this is the backstop for a
        // caller building an `InstanceConfig` by hand: no plan means no
        // proxy, and the bind would name a socket nothing ever creates.
        assert!(
            matches!(
                argv(&[Service::A11y], &env(), &[]),
                Err(LaunchError::BadValue {
                    service: "a11y",
                    ..
                })
            ),
            "a11y without dbus is a grant that reaches nothing"
        );
    }

    #[test]
    fn input_method_is_the_portal_variable_and_no_bind_at_all() {
        let a = argv(
            &[Service::Dbus { rules: vec![] }, Service::InputMethod],
            &env(),
            &[],
        )
        .unwrap();
        // The client libraries take the sandboxed portal name from this;
        // the rules that make that name reachable are the plan's.
        assert!(has_seq(&a, &["--setenv", "IBUS_USE_PORTAL", "1"]), "{a:?}");
        let bare = argv(&[Service::Dbus { rules: vec![] }], &env(), &[]).unwrap();
        assert!(!bare.iter().any(|s| s == "IBUS_USE_PORTAL"), "{bare:?}");
        assert_eq!(binds(&a), binds(&bare), "{a:?}");
    }

    #[test]
    fn portals_adds_the_flatpak_info_file() {
        let a = argv(
            &[
                Service::Dbus { rules: vec![] },
                Service::Portals {
                    children: Vec::new(),
                },
            ],
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
            &[
                Service::Dbus { rules: vec![] },
                Service::Portals {
                    children: Vec::new(),
                },
            ],
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
                &[
                    Service::Dbus { rules: vec![] },
                    Service::Portals {
                        children: Vec::new(),
                    },
                ],
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
            &[Service::Wayland(WaylandMode::default())],
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

    /// The reproduced attack: an application inside the sandbox plants
    /// `Downloads -> /oldroot/<victim>` in its own home, and the next
    /// launch has bwrap create the bind destination there. bubblewrap
    /// below 0.12.0 follows it and writes outside the sandbox, so the
    /// launch is refused before bwrap is ever started.
    #[test]
    fn a_bind_destination_behind_a_planted_symlink_refuses_the_launch() {
        let e = env();
        let inside = Path::new(SANDBOX_HOME);
        let home = Path::new("/home/user/.local/share/bubbler/instances/t/home");
        let ops = vec![
            op(&["--bind", &home.display().to_string(), SANDBOX_HOME]),
            op(&[
                "--ro-bind",
                "/home/user/Downloads",
                &inside.join("Downloads").display().to_string(),
            ]),
        ];
        let host = FakeHost::default().link(
            "/home/user/.local/share/bubbler/instances/t/home/Downloads",
            "/oldroot/home/user/.config",
        );
        let err = sweep_destinations(&ops, &e, &host).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("refusing to start"), "{text}");
        assert!(
            text.contains("/home/bubbler/Downloads is a symlink"),
            "{text}"
        );
        assert!(text.contains("in the instance home"), "{text}");
        assert!(text.contains("-> /oldroot/home/user/.config"), "{text}");
        assert!(text.contains("an app may have planted it"), "{text}");
        assert!(text.contains(&home.display().to_string()), "{text}");

        // A plain directory in the same place is what the sandbox is for.
        let (_, dir, _) = fake::types();
        let plain = FakeHost::default().with(
            "/home/user/.local/share/bubbler/instances/t/home/Downloads",
            dir,
        );
        assert!(sweep_destinations(&ops, &e, &plain).is_ok());
    }

    /// The tree a destination is measured against is read off a bind
    /// wherever its flag sits in the operation: the builder emits
    /// `--perms NNNN --bind src dst` as one operation too, and a tree
    /// missed there takes every destination under it out of the sweep.
    #[test]
    fn a_prefixed_bind_still_contributes_its_tree() {
        let e = env();
        let home = "/home/user/.local/share/bubbler/instances/t/home";
        let ops = vec![
            op(&["--perms", "0700", "--bind", home, SANDBOX_HOME]),
            op(&[
                "--ro-bind",
                "/home/user/Downloads",
                "/home/bubbler/Downloads",
            ]),
        ];
        let host =
            FakeHost::default().link(&format!("{home}/Downloads"), "/oldroot/home/user/.config");
        let err = sweep_destinations(&ops, &e, &host).unwrap_err();
        assert!(err.to_string().contains("in the instance home"), "{err}");
    }

    /// Every component of the path is checked, not only the last: a link
    /// one level up carries the destination out of the sandbox just as
    /// well. And the cookie `x11 "host"` writes is a destination too.
    #[test]
    fn the_sweep_walks_every_component_and_every_kind_of_destination() {
        let e = env();
        let home = "/home/user/.local/share/bubbler/instances/t/home";
        let base = op(&["--bind", home, SANDBOX_HOME]);

        let deep = vec![
            base.clone(),
            op(&["--ro-bind", "/etc/hosts", "/home/bubbler/a/b/hosts"]),
        ];
        let host = FakeHost::default().link(&format!("{home}/a"), "/oldroot/etc");
        let err = sweep_destinations(&deep, &e, &host).unwrap_err();
        assert!(
            err.to_string().contains("/home/bubbler/a is a symlink"),
            "{err}"
        );

        let cookie = vec![
            base.clone(),
            op(&[
                "--ro-bind",
                "/run/user/1000/Xauthority",
                "/home/bubbler/.Xauthority",
            ]),
        ];
        let host = FakeHost::default().link(&format!("{home}/.Xauthority"), "/oldroot/xauth");
        assert!(sweep_destinations(&cookie, &e, &host).is_err());

        // A `--symlink` and a `--ro-bind-data` create a destination too;
        // `--perms` sits in front of the data one, so the flag is looked
        // for rather than assumed first.
        let others = vec![
            base.clone(),
            op(&["--symlink", "/usr/bin/sh", "/home/bubbler/sh"]),
            op(&[
                "--perms",
                "0644",
                "--ro-bind-data",
                "7",
                "/home/bubbler/.config/x",
            ]),
            op(&["--perms", "0700", "--dir", "/home/bubbler/state"]),
        ];
        for planted in [".config", "sh", "state"] {
            let host = FakeHost::default().link(&format!("{home}/{planted}"), "/oldroot/x");
            assert!(
                sweep_destinations(&others, &e, &host).is_err(),
                "a planted `{planted}` was not caught"
            );
        }
    }

    /// The app-runtime leaf and the document view are the other two trees
    /// the application can write; nothing outside the three is swept, so
    /// a symlink on the host's own `/etc` is not bubbler's business.
    #[test]
    fn the_app_runtime_leaf_and_the_document_view_are_swept_and_nothing_else_is() {
        let e = env();
        let ops = vec![
            op(&["--bind", "/i/home", SANDBOX_HOME]),
            op(&[
                "--bind",
                "/run/user/1000/app/org.example.App",
                "/run/user/1000/app/org.example.App",
            ]),
            op(&[
                "--bind",
                "/run/user/1000/doc/by-app/org.bubbler.t",
                "/run/user/1000/doc",
            ]),
            op(&["--ro-bind", "/etc/hosts", "/etc/hosts"]),
        ];
        let host =
            FakeHost::default().link("/run/user/1000/app/org.example.App/sock", "/oldroot/x");
        let more = {
            let mut v = ops.clone();
            v.push(op(&[
                "--ro-bind",
                "/tmp/s",
                "/run/user/1000/app/org.example.App/sock",
            ]));
            v
        };
        let err = sweep_destinations(&more, &e, &host).unwrap_err();
        assert!(
            err.to_string().contains("the app-runtime directory"),
            "{err}"
        );

        let host =
            FakeHost::default().link("/run/user/1000/doc/by-app/org.bubbler.t/f", "/oldroot/x");
        let mut docs = ops.clone();
        docs.push(op(&["--ro-bind", "/tmp/f", "/run/user/1000/doc/f"]));
        let err = sweep_destinations(&docs, &e, &host).unwrap_err();
        assert!(err.to_string().contains("the document view"), "{err}");

        // A link on a host path no tree covers is not swept.
        let host = FakeHost::default().link("/etc/hosts", "/oldroot/etc/hosts");
        assert!(sweep_destinations(&ops, &e, &host).is_ok());
    }

    /// A directory the app `chmod 000`'d hides what is under it from
    /// bubbler's `lstat` and from nothing bwrap does as root of its user
    /// namespace, so a component that cannot be checked refuses the run
    /// the same as a link would, naming the host path to make readable.
    #[test]
    fn a_destination_component_that_cannot_be_checked_refuses_the_launch() {
        let e = env();
        let home = "/home/user/.local/share/bubbler/instances/t/home";
        let ops = vec![
            op(&["--bind", home, SANDBOX_HOME]),
            op(&["--ro-bind", "/home/user/a/b/c", "/home/bubbler/a/b/c"]),
        ];
        let host = FakeHost::default()
            .unreadable(&format!("{home}/a/b"))
            .link(&format!("{home}/a/b"), "/oldroot/x");
        let err = sweep_destinations(&ops, &e, &host).unwrap_err();
        assert!(
            matches!(err, LaunchError::UncheckedDestination { .. }),
            "{err}"
        );
        let text = err.to_string();
        assert!(text.contains("refusing to start"), "{text}");
        assert!(
            text.contains(
                "cannot check whether /home/bubbler/a/b is a symlink in the instance home"
            ),
            "{text}"
        );
        assert!(text.contains(&format!("({home}/a/b: ")), "{text}");
        assert!(text.contains("make it readable or remove it"), "{text}");
    }

    /// bubbler builds every destination, so one with `..` in it is a
    /// builder bug; the sweep refuses it rather than walk it into a path
    /// it did not check.
    #[test]
    fn a_destination_with_a_parent_component_is_refused_as_unwalkable() {
        let e = env();
        let home = "/home/user/.local/share/bubbler/instances/t/home";
        let ops = vec![
            op(&["--bind", home, SANDBOX_HOME]),
            op(&["--ro-bind", "/etc/hosts", "/home/bubbler/../etc/hosts"]),
        ];
        let err = sweep_destinations(&ops, &e, &FakeHost::default()).unwrap_err();
        assert!(
            matches!(err, LaunchError::UnwalkableDestination(_)),
            "{err}"
        );
    }

    /// Options end at bwrap's `--`; the argv bubbler-init and the command
    /// get after it is not swept, whatever flag names it happens to use.
    #[test]
    fn the_sweep_stops_at_the_command_separator() {
        let e = env();
        let home = "/home/user/.local/share/bubbler/instances/t/home";
        let ops = vec![
            op(&["--bind", home, SANDBOX_HOME]),
            op(&["--", "/init", "--socket-fd", "7"]),
            op(&["--", "prog", "--dir", "/home/bubbler/x"]),
        ];
        let host = FakeHost::default().link(&format!("{home}/x"), "/oldroot/x");
        assert!(sweep_destinations(&ops, &e, &host).is_ok());
    }

    /// Every flag the builder can emit is either one the sweep knows
    /// creates a destination or one on the list here of flags that create
    /// none, so a flag added to the builder without that decision fails
    /// this test instead of leaving a destination unswept. The builder
    /// is the one place a bwrap flag is spelled, which is what makes its
    /// source the list to check against.
    #[test]
    fn every_flag_the_builder_emits_is_classified_for_the_sweep() {
        const CREATES_NOTHING: &[&str] = &[
            "--",
            "--add-seccomp-fd",
            "--block-fd",
            "--chdir",
            "--clearenv",
            "--ctty",
            "--die-with-parent",
            "--disable-userns",
            "--hostname",
            "--info-fd",
            "--new-session",
            "--perms",
            "--remount-ro",
            "--setenv",
            "--share-net",
            "--size",
            "--socket-fd",
            "--unshare-all",
            "--unshare-user",
            "--wm",
            "--x11",
        ];
        let source = include_str!("bwrap.rs");
        let mut seen = std::collections::BTreeSet::new();
        for (i, _) in source.match_indices("\"--") {
            let rest = &source[i + 1..];
            let flag = &rest[..rest.find('"').unwrap()];
            if flag
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                seen.insert(flag);
            }
        }
        assert!(
            seen.contains("--ro-bind"),
            "the scan found nothing: {seen:?}"
        );
        for flag in seen {
            assert!(
                CREATES.iter().any(|(f, _)| *f == flag) || CREATES_NOTHING.contains(&flag),
                "`{flag}` is emitted by the builder but the sweep has no ruling on it"
            );
        }
    }
}
