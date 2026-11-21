//! The host tools' versions, asked for once per process.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::dbus::{self, PROXY_BIN};
use crate::env::Env;
use crate::version::{BWRAP_NAME, Version, parse};

/// Ask `program` for its version. Nothing about the answer is trusted
/// beyond its shape, and every failure is [`Version::Unknown`] rather
/// than an error: a version check must never be what stops a run.
pub fn probe(program: &Path, name: &str) -> Version {
    // No stdin and no stderr: this runs before the descriptor sweep a
    // spawn makes, and the answer is one line on stdout.
    let Ok(out) = Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Version::Unknown;
    };
    if !out.status.success() {
        return Version::Unknown;
    }
    match std::str::from_utf8(&out.stdout) {
        Ok(text) => parse(name, text),
        Err(_) => Version::Unknown,
    }
}

/// The host `bwrap`'s version, asked for once however many sandboxes a
/// process builds.
pub fn bwrap() -> Version {
    static SEEN: OnceLock<Version> = OnceLock::new();
    *SEEN.get_or_init(|| probe(Path::new("bwrap"), BWRAP_NAME))
}

/// The host `xdg-dbus-proxy`'s version, asked for once per process. The
/// binary is the one a run would start, `$BUBBLER_DBUS_PROXY` included.
pub fn proxy(env: &Env) -> Version {
    static SEEN: OnceLock<Version> = OnceLock::new();
    *SEEN.get_or_init(|| probe(&dbus::proxy_program(env), PROXY_BIN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// A stand-in for the tool: a program that prints one version line is
    /// read, and one that fails, prints nothing bubbler recognises, or is
    /// not there at all is unknown rather than an error.
    fn fake(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn probing_reads_a_tool_that_answers_and_says_unknown_for_one_that_does_not() {
        let tmp = tempfile::tempdir().unwrap();
        let good = fake(tmp.path(), "good", "#!/bin/sh\necho 'bubblewrap 0.11.2'\n");
        assert_eq!(probe(&good, BWRAP_NAME), Version::Known(0, 11, 2));

        let failing = fake(
            tmp.path(),
            "failing",
            "#!/bin/sh\necho 'bubblewrap 9.9.9'\nexit 1\n",
        );
        assert_eq!(probe(&failing, BWRAP_NAME), Version::Unknown);

        let quiet = fake(tmp.path(), "quiet", "#!/bin/sh\nexit 0\n");
        assert_eq!(probe(&quiet, BWRAP_NAME), Version::Unknown);

        assert_eq!(
            probe(&tmp.path().join("absent"), BWRAP_NAME),
            Version::Unknown
        );
    }
}
