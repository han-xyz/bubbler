//! Where the host copy of `bubbler-init` is. Every sandbox runs under it,
//! so a run that cannot find it fails before bwrap is spawned.

use std::path::{Path, PathBuf};

use crate::env::Env;
use crate::error::LaunchError;

/// File name of the supervisor binary.
pub const NAME: &str = "bubbler-init";

/// Where a packaged bubbler installs the supervisor.
pub const INSTALLED: &str = "/usr/lib/bubbler/bubbler-init";

fn is_regular_file(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file())
}

fn missing(path: PathBuf) -> LaunchError {
    LaunchError::MissingResource {
        service: "init",
        path,
    }
}

/// Host path of `bubbler-init`: [`Env::init_override`] (`$BUBBLER_INIT`),
/// else next to the running executable, else [`INSTALLED`]. Must be a
/// regular file; an override that is not one is an error, never a
/// silent fallback to another binary.
pub fn locate(env: &Env) -> Result<PathBuf, LaunchError> {
    if let Some(p) = &env.init_override {
        return if is_regular_file(p) {
            Ok(p.clone())
        } else {
            Err(missing(p.clone()))
        };
    }
    if let Some(sibling) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(NAME)))
        && is_regular_file(&sibling)
    {
        return Ok(sibling);
    }
    let installed = PathBuf::from(INSTALLED);
    if is_regular_file(&installed) {
        Ok(installed)
    } else {
        Err(missing(installed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(init_override: Option<PathBuf>) -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override,
        }
    }

    #[test]
    fn an_override_wins_and_must_be_a_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join(NAME);
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        assert_eq!(locate(&env(Some(bin.clone()))).unwrap(), bin);

        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        assert!(matches!(
            locate(&env(Some(dir.clone()))),
            Err(LaunchError::MissingResource { service: "init", path }) if path == dir
        ));
        assert!(matches!(
            locate(&env(Some(tmp.path().join("nope")))),
            Err(LaunchError::MissingResource {
                service: "init",
                ..
            })
        ));
    }

    #[test]
    fn without_an_override_the_sibling_of_the_test_binary_is_searched_first() {
        // The test binary lives in `target/debug/deps/`, so this is the
        // same rule the installed `bubbler` uses for its own directory.
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join(NAME)));
        match locate(&env(None)) {
            Ok(p) => assert!(Some(&p) == sibling.as_ref() || p == Path::new(INSTALLED)),
            Err(LaunchError::MissingResource { path, .. }) => {
                assert_eq!(path, Path::new(INSTALLED));
                assert!(sibling.is_none_or(|s| !is_regular_file(&s)));
            }
            Err(e) => panic!("{e}"),
        }
    }
}
