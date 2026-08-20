//! Turns granted services into builder calls. Each service touches only
//! phase 4 (binds) and phase 5 (env); `network` is the one exception that
//! edits phase 1 via [`BwrapArgs::share_net`].

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::bwrap::BwrapArgs;
use crate::config::{Service, ShareMode};
use crate::env::{Env, SANDBOX_HOME};
use crate::error::LaunchError;

/// Apply every service to `args`. `probe` reports whether a host path
/// exists; it is a parameter so tests run without real sockets.
pub fn apply_all(
    services: &[Service],
    env: &Env,
    args: &mut BwrapArgs,
    probe: &dyn Fn(&Path) -> bool,
) -> Result<(), LaunchError> {
    let has_x11 = services.contains(&Service::X11);
    for s in services {
        match s {
            Service::Wayland => wayland(env, args, probe, !has_x11)?,
            Service::X11 => x11(env, args, probe)?,
            Service::Network => args.share_net(),
            Service::HomeShare { path, mode } => home_share(env, args, probe, path, *mode)?,
        }
    }
    Ok(())
}

fn require(
    probe: &dyn Fn(&Path) -> bool,
    service: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    if probe(&path) {
        Ok(path)
    } else {
        Err(LaunchError::MissingResource { service, path })
    }
}

/// Bind `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` at the same path. Arch wiki
/// (Bubblewrap/Examples) pattern. `XDG_SESSION_TYPE=wayland` only when
/// X11 is not also granted, so toolkits do not get mixed signals.
fn wayland(
    env: &Env,
    args: &mut BwrapArgs,
    probe: &dyn Fn(&Path) -> bool,
    claim_session: bool,
) -> Result<(), LaunchError> {
    let display = env
        .wayland_display
        .as_deref()
        .ok_or(LaunchError::MissingEnv {
            service: "wayland",
            var: "WAYLAND_DISPLAY",
        })?;
    let sock = require(probe, "wayland", env.runtime_dir.join(display))?;
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
    num.parse().ok()
}

/// Bind the X11 socket at the same path (Arch wiki: binding to a different
/// display number may not work) and an Xauthority file if one is found.
/// Xauthority fallback to `$HOME/.Xauthority` follows libX11's default
/// and is not covered by the wiki.
fn x11(env: &Env, args: &mut BwrapArgs, probe: &dyn Fn(&Path) -> bool) -> Result<(), LaunchError> {
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
    let sock = require(probe, "x11", PathBuf::from(format!("/tmp/.X11-unix/X{n}")))?;
    args.ro_bind(&sock, &sock);
    args.setenv(OsStr::new("DISPLAY"), OsStr::new(&format!(":{n}")));

    if let Some(xa) = &env.xauthority {
        let xa = require(probe, "x11", xa.clone())?;
        args.ro_bind(&xa, &xa);
        args.setenv(OsStr::new("XAUTHORITY"), xa.as_os_str());
    } else {
        let host = env.home.join(".Xauthority");
        if probe(&host) {
            let inner = Path::new(SANDBOX_HOME).join(".Xauthority");
            args.ro_bind(&host, &inner);
            args.setenv(OsStr::new("XAUTHORITY"), inner.as_os_str());
        }
    }
    Ok(())
}

/// Bind `$HOME/<path>` to `/home/bubbler/<path>`. The host path must exist;
/// bubbler never creates directories in the real home.
fn home_share(
    env: &Env,
    args: &mut BwrapArgs,
    probe: &dyn Fn(&Path) -> bool,
    rel: &Path,
    mode: ShareMode,
) -> Result<(), LaunchError> {
    let src = require(probe, "home-share", env.home.join(rel))?;
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
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn env() -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            runtime_dir: "/run/user/1000".into(),
            wayland_display: Some("wayland-1".into()),
            display: Some(":0".into()),
            xauthority: Some("/run/user/1000/Xauthority".into()),
            passthrough: vec![],
        }
    }

    fn argv(
        services: &[Service],
        env: &Env,
        existing: &[&str],
    ) -> Result<Vec<String>, LaunchError> {
        let set: HashSet<PathBuf> = existing.iter().map(PathBuf::from).collect();
        let mut args = BwrapArgs::baseline(env, Path::new("/i/home"));
        apply_all(services, env, &mut args, &|p| set.contains(p))?;
        Ok(args
            .finish(&[OsString::from("x")])
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
        let a = argv(&[Service::Wayland], &env(), &["/run/user/1000/wayland-1"]).unwrap();
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
    fn x11_binds_socket_and_xauthority() {
        let a = argv(
            &[Service::X11],
            &env(),
            &["/tmp/.X11-unix/X0", "/run/user/1000/Xauthority"],
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
                "/run/user/1000/Xauthority"
            ]
        ));
        assert!(has_seq(&a, &["--setenv", "DISPLAY", ":0"]));
        assert!(has_seq(
            &a,
            &["--setenv", "XAUTHORITY", "/run/user/1000/Xauthority"]
        ));
        assert!(!a.contains(&"XDG_SESSION_TYPE".to_string()));
    }

    #[test]
    fn x11_falls_back_to_home_xauthority_or_none() {
        let mut e = env();
        e.xauthority = None;
        let a = argv(
            &[Service::X11],
            &e,
            &["/tmp/.X11-unix/X0", "/home/han/.Xauthority"],
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
        let a = argv(&[Service::X11], &e, &["/tmp/.X11-unix/X0"]).unwrap();
        assert!(!a.contains(&"XAUTHORITY".to_string()));
    }

    #[test]
    fn x11_display_parsing() {
        assert_eq!(x11_display_number(OsStr::new(":0")), Some(0));
        assert_eq!(x11_display_number(OsStr::new(":10.1")), Some(10));
        assert_eq!(x11_display_number(OsStr::new("unix:2")), Some(2));
        assert_eq!(x11_display_number(OsStr::new("host:0")), None);
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
                "/run/user/1000/wayland-1",
                "/tmp/.X11-unix/X0",
                "/run/user/1000/Xauthority",
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
            &["/home/han/Downloads", "/home/han/Projects/x"],
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
