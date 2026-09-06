//! Versions of the two host tools a sandbox is built out of, asked for
//! once per process. Both floors exist because the older tool breaks a
//! confinement bubbler otherwise has: bubblewrap below 0.12.0 follows a
//! symlink an application planted at a destination it creates, and
//! xdg-dbus-proxy below 0.1.8 lets a filtered client past its own filter.
//!
//! A version that cannot be read is treated as below every floor. The
//! gate exists for a tool that is too old, and one that will not say
//! which it is has to be assumed to be one.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::config::Service;
use crate::dbus::{self, PROXY_BIN};
use crate::env::Env;

/// What `bwrap --version` calls itself: the package name, not the binary.
pub const BWRAP_NAME: &str = "bubblewrap";

/// First bubblewrap that does not follow a symlink planted at a
/// destination it creates (GHSA-pxhw-h44j-8pfx).
pub const BWRAP_FLOOR: (u32, u32, u32) = (0, 12, 0);

/// First xdg-dbus-proxy that closes the eavesdrop and accessibility
/// broadcast bypasses (CVE-2026-34080, GHSA-r7hp-698j-2h6c).
pub const PROXY_FLOOR: (u32, u32, u32) = (0, 1, 8);

/// A host tool's version as it reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// `X.Y.Z`, exactly as the tool printed it.
    Known(u32, u32, u32),
    /// The tool could not be run, exited non-zero, or printed something
    /// that is not `<name> X.Y.Z`.
    Unknown,
}

impl Version {
    /// Whether this is older than `floor`. [`Version::Unknown`] is: a
    /// tool that will not say which version it is cannot be trusted to
    /// be the one that carries the fix.
    pub fn below(self, floor: (u32, u32, u32)) -> bool {
        match self {
            Self::Unknown => true,
            Self::Known(a, b, c) => (a, b, c) < floor,
        }
    }

    /// How a warning and `--explain` name it.
    pub fn text(self) -> String {
        match self {
            Self::Known(a, b, c) => format!("{a}.{b}.{c}"),
            Self::Unknown => "unknown".to_owned(),
        }
    }
}

/// The version in `<name> X.Y.Z` on the first line of `output`, or
/// [`Version::Unknown`] for anything else. The tool's own name must
/// match: a `bwrap` on `PATH` that is a wrapper printing its own
/// version is not the bubblewrap this floor is about.
pub fn parse(name: &str, output: &str) -> Version {
    let Some(rest) = output
        .lines()
        .next()
        .and_then(|l| l.strip_prefix(name))
        .and_then(|r| r.strip_prefix(' '))
    else {
        return Version::Unknown;
    };
    let parts: Vec<&str> = rest.trim().split('.').collect();
    let [a, b, c] = parts.as_slice() else {
        return Version::Unknown;
    };
    // `u32::from_str` accepts a leading `+`; a version number has none.
    if [a, b, c].iter().any(|p| p.starts_with('+')) {
        return Version::Unknown;
    }
    match (a.parse(), b.parse(), c.parse()) {
        (Ok(a), Ok(b), Ok(c)) => Version::Known(a, b, c),
        _ => Version::Unknown,
    }
}

/// Ask `program` for its version. Nothing about the answer is trusted
/// beyond its shape, and every failure — a missing binary, a non-zero
/// exit, output that is not UTF-8 — is [`Version::Unknown`] rather than
/// an error: a version check must never be what stops a run.
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

/// The advisory lines a launch prints on stderr, in the order it prints
/// them. Nothing silences them: the whole point of the bwrap line is
/// that the host tool cannot enforce what bubbler configured, and a
/// configuration that could turn it off would be one nobody reads.
///
/// The proxy line is printed only for a config that starts the proxy —
/// `dbus`, `portals`, `a11y` or `system-bus` — since a sandbox with no
/// bus is not exposed to what its advisories describe.
pub fn warnings(bwrap: Version, proxy: Version, services: &[Service]) -> Vec<String> {
    let mut out = Vec::new();
    if bwrap.below(BWRAP_FLOOR) {
        out.push(format!(
            "bwrap {} creates a file or directory under the instance home by following a \
             symlink an application planted there, which writes outside the sandbox \
             (GHSA-pxhw-h44j-8pfx); upgrade to 0.12.0. bubbler refuses a run whose \
             destinations sit behind one, and nothing turns this warning off.",
            bwrap.text()
        ));
    }
    let bus = services.iter().any(|s| {
        matches!(
            s,
            Service::Dbus { .. }
                | Service::SystemBus { .. }
                | Service::Portals { .. }
                | Service::A11y
        )
    });
    if bus && proxy.below(PROXY_FLOOR) {
        out.push(format!(
            "xdg-dbus-proxy {} lets a filtered client eavesdrop on the bus and receive \
             accessibility broadcasts it was not granted (CVE-2026-34080, \
             GHSA-r7hp-698j-2h6c); upgrade to 0.1.8.",
            proxy.text()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Service;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    #[test]
    fn a_version_line_is_the_tool_s_own_name_and_three_numbers() {
        assert_eq!(
            parse(BWRAP_NAME, "bubblewrap 0.11.2\n"),
            Version::Known(0, 11, 2)
        );
        assert_eq!(
            parse(crate::dbus::PROXY_BIN, "xdg-dbus-proxy 0.1.8\n"),
            Version::Known(0, 1, 8)
        );
        // Anything else at all is unknown, and unknown is treated as old.
        for other in [
            "",
            "\n",
            "bubblewrap\n",
            "bubblewrap 0.11\n",
            "bubblewrap 0.11.2.1\n",
            "bubblewrap 0.11.x\n",
            "bubblewrap +0.11.2\n",
            "bwrap 0.11.2\n",
            "  bubblewrap 0.11.2\n",
        ] {
            assert_eq!(parse(BWRAP_NAME, other), Version::Unknown, "{other:?}");
        }
    }

    #[test]
    fn unknown_is_below_every_floor_and_a_known_version_compares_by_number() {
        assert!(Version::Unknown.below(BWRAP_FLOOR));
        assert!(Version::Known(0, 11, 2).below(BWRAP_FLOOR));
        assert!(!Version::Known(0, 12, 0).below(BWRAP_FLOOR));
        assert!(!Version::Known(1, 0, 0).below(BWRAP_FLOOR));
        assert!(Version::Known(0, 1, 7).below(PROXY_FLOOR));
        assert!(!Version::Known(0, 1, 8).below(PROXY_FLOOR));
        assert_eq!(Version::Known(0, 11, 2).text(), "0.11.2");
        assert_eq!(Version::Unknown.text(), "unknown");
    }

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

    #[test]
    fn an_old_bwrap_always_warns_and_an_old_proxy_only_where_a_bus_is_granted() {
        let old = Version::Known(0, 11, 2);
        let new = Version::Known(0, 12, 0);
        let proxy_old = Version::Known(0, 1, 7);
        let proxy_new = Version::Known(0, 1, 8);

        let w = warnings(old, proxy_new, &[]);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("bwrap 0.11.2"), "{w:?}");
        assert!(w[0].contains("GHSA-pxhw-h44j-8pfx"), "{w:?}");
        assert!(w[0].contains("upgrade to 0.12.0"), "{w:?}");

        // Current tools, nothing to say.
        assert!(
            warnings(
                new,
                proxy_new,
                &[Service::Portals {
                    children: Vec::new()
                }]
            )
            .is_empty()
        );

        // The proxy gate needs a node that starts the proxy.
        assert!(warnings(new, proxy_old, &[Service::Dri { kms: false }]).is_empty());
        for node in [
            Service::Dbus { rules: Vec::new() },
            Service::Portals {
                children: Vec::new(),
            },
            Service::A11y,
            Service::SystemBus { rules: Vec::new() },
        ] {
            let w = warnings(new, proxy_old, std::slice::from_ref(&node));
            assert_eq!(w.len(), 1, "{node:?}: {w:?}");
            assert!(w[0].contains("xdg-dbus-proxy 0.1.7"), "{w:?}");
            assert!(w[0].contains("CVE-2026-34080"), "{w:?}");
            assert!(w[0].contains("GHSA-r7hp-698j-2h6c"), "{w:?}");
            assert!(w[0].contains("upgrade to 0.1.8"), "{w:?}");
        }

        // A version that could not be read is old, and says so.
        let w = warnings(Version::Unknown, proxy_new, &[]);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("bwrap unknown"), "{w:?}");

        // Both at once, bwrap first.
        let w = warnings(old, proxy_old, &[Service::Dbus { rules: Vec::new() }]);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].starts_with("bwrap "), "{w:?}");
        assert!(w[1].starts_with("xdg-dbus-proxy "), "{w:?}");
    }
}
