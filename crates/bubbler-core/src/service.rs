//! Turns granted services into builder calls. Each service touches only
//! phase 4 (binds) and phase 5 (env); `network` is the one exception that
//! edits phase 1 via [`BwrapArgs::share_net`].
//!
//! Paths come from untrusted host environment values, so every source is
//! probed for its file *type*, never for mere existence: binding a
//! directory binds the whole tree under it, so `XAUTHORITY=/` would bind
//! the host root.

use std::ffi::{OsStr, OsString};
use std::fs::FileType;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

use crate::bwrap::BwrapArgs;
use crate::config::{RESERVED_ENV, Service, ShareMode};
use crate::dbus;
use crate::env::{Env, SANDBOX_HOME};
use crate::error::LaunchError;
use crate::host::Host;

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
/// [`Service::HomeShare`] `path` must be relative and normalised, exactly
/// as the parser leaves it.
pub fn apply_all(
    services: &[Service],
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    ctx: &ServiceCtx,
) -> Result<(), LaunchError> {
    let has_x11 = services.contains(&Service::X11);
    for s in services {
        match s {
            Service::Wayland => wayland(env, args, host, !has_x11)?,
            Service::X11 => x11(env, args, host)?,
            Service::Network => network(args, host)?,
            Service::HomeShare { path, mode } => home_share(env, args, host, path, *mode)?,
            Service::Dri => dri(args, host)?,
            Service::Pipewire => pipewire(env, args, host)?,
            Service::Pulseaudio => pulseaudio(env, args, host)?,
            Service::EtcShare { name } => etc_share(args, host, name)?,
            Service::Dbus { .. } => dbus_socket(env, args, ctx),
            Service::Portals => portals(args, ctx)?,
            // Rule-only bundles: they reach the sandbox through the proxy
            // the launcher starts, not through bwrap arguments.
            Service::Notify | Service::Mpris { .. } => {}
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

/// Keep the host network namespace and bind the resolver configuration,
/// without which names cannot be resolved inside the sandbox. The bind is
/// phase 4, so it lands inside the phase-2 tmpfs on `/etc`.
fn network(args: &mut BwrapArgs, host: &dyn Host) -> Result<(), LaunchError> {
    args.share_net();
    let p = require_file(host, "network", PathBuf::from("/etc/resolv.conf"))?;
    args.ro_bind(&p, &p);
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

/// GPU access: `/dev/dri`, bound read-write because bwrap has no
/// read-only device bind, plus the `/sys` paths a userspace driver reads;
/// a PCI root exposes every PCI device's attributes, not only the GPU's.
fn dri(args: &mut BwrapArgs, host: &dyn Host) -> Result<(), LaunchError> {
    // Paths from Arch wiki Bubblewrap/Examples and bubblejail
    // `direct_rendering`; PCI roots are enumerated so no unrelated
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
    args.ro_bind(&dbus::app_bus_path(&ctx.instance_runtime), &inside);
    let mut address = OsString::from("unix:path=");
    address.push(inside.as_os_str());
    args.setenv(OsStr::new("DBUS_SESSION_BUS_ADDRESS"), &address);
}

/// Bind the `/.flatpak-info` portals identify the sandbox by. The bytes
/// come from the launcher's plan, which hands the proxy the same file.
/// Without a plan there is no proxy and no bus, so the grant is refused
/// rather than quietly dropped; the parser rejects that config already.
fn portals(args: &mut BwrapArgs, ctx: &ServiceCtx) -> Result<(), LaunchError> {
    let plan = ctx.dbus.ok_or(LaunchError::BadValue {
        service: "portals",
        reason: "requires dbus".to_owned(),
    })?;
    args.ro_bind_data(
        plan.flatpak_info.clone(),
        Path::new(dbus::FLATPAK_INFO),
        "0644",
    );
    Ok(())
}

/// Emit profile/instance `env` pairs after all service variables, so a
/// profile can layer toolkit settings on top. A [`RESERVED_ENV`] key is
/// refused here as well as in the parser, so a caller building an
/// [`crate::config::InstanceConfig`] by hand cannot override what the
/// sandbox sets.
pub fn apply_env(pairs: &[(String, String)], args: &mut BwrapArgs) -> Result<(), LaunchError> {
    for (k, v) in pairs {
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

/// Resolve `src` and require that it stays under `root`; both are
/// canonicalised, so a symlink cannot turn a grant inside `root` into a
/// bind of something outside it. Returns the canonical source, which is
/// what the caller must bind: binding the path as written would mount
/// whatever the symlink points at instead.
fn confine(
    host: &dyn Host,
    service: &'static str,
    root: &Path,
    src: PathBuf,
    outside: &str,
) -> Result<PathBuf, LaunchError> {
    let root = host
        .canonicalize(root)
        .ok_or_else(|| LaunchError::MissingResource {
            service,
            path: root.to_path_buf(),
        })?;
    let Some(real) = host.canonicalize(&src) else {
        return Err(LaunchError::MissingResource { service, path: src });
    };
    if !real.starts_with(&root) {
        return Err(LaunchError::BadValue {
            service,
            reason: format!("{} resolves outside {outside}", src.display()),
        });
    }
    require_exists(host, service, real)
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
        env.home.join(rel),
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
    let src = confine(host, "etc-share", etc, dst.clone(), "/etc")?;
    args.ro_bind(&src, &dst);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::{self, FakeHost};
    use std::ffi::OsString;

    #[derive(Clone, Copy)]
    enum Kind {
        Sock,
        File,
        Dir,
    }

    use Kind::{Dir, File, Sock};

    fn env() -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: Some("wayland-1".into()),
            display: Some(":0".into()),
            xauthority: Some("/run/user/1000/Xauthority".into()),
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_log: false,
            seccomp_log: false,
            proxy_override: None,
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
            host = host.with(
                p,
                match k {
                    Sock => sock,
                    File => file,
                    Dir => dir,
                },
            );
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

    #[test]
    fn wayland_binds_socket_and_sets_env() {
        let a = argv(
            &[Service::Wayland],
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
            argv(&[Service::Wayland], &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "wayland",
                ..
            })
        ));
        let mut e = env();
        e.wayland_display = None;
        assert!(matches!(
            argv(&[Service::Wayland], &e, &[]),
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
                    &[Service::Wayland],
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
                &[Service::Wayland],
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
                &[Service::Wayland],
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
                        &[Service::Wayland],
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
            argv(&[Service::Wayland], &e, &[("/run/user/1000/dconf", Dir)]),
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
            &[Service::Wayland, Service::X11],
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

    #[test]
    fn network_shares_net_and_binds_resolv_conf() {
        let a = argv(&[Service::Network], &env(), &[("/etc/resolv.conf", File)]).unwrap();
        assert_eq!(a[1], "--share-net");
        assert!(has_seq(
            &a,
            &["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]
        ));
        assert!(matches!(
            argv(&[Service::Network], &env(), &[]),
            Err(LaunchError::MissingResource {
                service: "network",
                ..
            })
        ));
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
        apply_all(&[Service::Wayland], &e, &mut args, &host, &argv_ctx(&None)).unwrap();
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
