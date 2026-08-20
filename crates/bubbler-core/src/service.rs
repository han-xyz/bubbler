//! Turns granted services into builder calls. Each service touches only
//! phase 4 (binds) and phase 5 (env); `network` is the one exception that
//! edits phase 1 via [`BwrapArgs::share_net`].
//!
//! Paths come from untrusted host environment values, so every source is
//! probed for its file *type*, never for mere existence: binding a
//! directory binds the whole tree under it, so `XAUTHORITY=/` would bind
//! the host root.

use std::ffi::OsStr;
use std::fs::FileType;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

use crate::bwrap::BwrapArgs;
use crate::config::{Service, ShareMode};
use crate::env::{Env, SANDBOX_HOME};
use crate::error::LaunchError;
use crate::host::Host;

/// Apply every service to `args`. `host` reports the type of a host path
/// with symlinks followed, so tests run without real sockets. A
/// [`Service::HomeShare`] `path` must be relative and normalised, exactly
/// as the parser leaves it.
pub fn apply_all(
    services: &[Service],
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
) -> Result<(), LaunchError> {
    let has_x11 = services.contains(&Service::X11);
    for s in services {
        match s {
            Service::Wayland => wayland(env, args, host, !has_x11)?,
            Service::X11 => x11(env, args, host)?,
            Service::Network => args.share_net(),
            Service::HomeShare { path, mode } => home_share(env, args, host, path, *mode)?,
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
fn require_socket(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    require(host, service, path, "a socket", |t| t.is_socket())
}

/// The source must be a regular file, e.g. an Xauthority cookie file.
fn require_file(
    host: &dyn Host,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    require(host, service, path, "a regular file", |t| t.is_file())
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
    if let Some(host) = cookie {
        let inner = Path::new(SANDBOX_HOME).join(".Xauthority");
        args.ro_bind(&host, &inner);
        args.setenv(OsStr::new("XAUTHORITY"), inner.as_os_str());
    }
    Ok(())
}

/// Bind `$HOME/<path>` to `/home/bubbler/<path>`. The host path must exist
/// and may be of any type; bubbler never creates directories in the real
/// home. Probing and binding both happen by path, so a symlink swapped in
/// between the two is not detected; that is inherent to bwrap path binds.
fn home_share(
    env: &Env,
    args: &mut BwrapArgs,
    host: &dyn Host,
    rel: &Path,
    mode: ShareMode,
) -> Result<(), LaunchError> {
    let src = require_exists(host, "home-share", env.home.join(rel))?;
    let dst = Path::new(SANDBOX_HOME).join(rel);
    match mode {
        ShareMode::ReadOnly => args.ro_bind(&src, &dst),
        ShareMode::ReadWrite => args.bind(&src, &dst),
    }
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
        }
    }

    fn counter() -> impl FnMut(&[u8]) -> std::io::Result<OsString> {
        let mut n = 2;
        move |_| {
            n += 1;
            Ok(OsString::from(n.to_string()))
        }
    }

    fn argv(
        services: &[Service],
        env: &Env,
        existing: &[(&str, Kind)],
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
        let mut args = BwrapArgs::baseline(env, Path::new("/i/home"), &host);
        apply_all(services, env, &mut args, &host)?;
        Ok(args
            .finish(&[OsString::from("x")], &mut counter())?
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect())
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
    fn network_shares_net() {
        let a = argv(&[Service::Network], &env(), &[]).unwrap();
        assert_eq!(a[1], "--share-net");
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
}
