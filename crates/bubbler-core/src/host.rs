//! Host filesystem inspection behind a trait so builder and services can
//! be tested against a fake tree.

use std::ffi::OsString;
use std::fs::{self, FileType};
use std::path::{Path, PathBuf};

/// Read-only view of the host filesystem used to decide what to bind.
pub trait Host {
    /// Type of `p` with symlinks followed; `None` if it does not exist.
    fn file_type(&self, p: &Path) -> Option<FileType>;
    /// Entry names directly under `p`; empty if unreadable or not a dir.
    fn list_dir(&self, p: &Path) -> Vec<OsString>;
    /// Absolute path of `p` with every symlink and `..` resolved; `None`
    /// if it does not exist. Services compare the result against the root
    /// a grant is confined to.
    fn canonicalize(&self, p: &Path) -> Option<PathBuf>;
    /// Whether `p` is where a filesystem is mounted. `None` when that
    /// cannot be told here, so a caller reports nothing rather than
    /// guessing.
    fn is_mountpoint(&self, p: &Path) -> Option<bool>;
}

/// The real filesystem.
pub struct RealHost;

impl Host for RealHost {
    fn file_type(&self, p: &Path) -> Option<FileType> {
        fs::metadata(p).ok().map(|m| m.file_type())
    }

    fn canonicalize(&self, p: &Path) -> Option<PathBuf> {
        fs::canonicalize(p).ok()
    }

    /// A mount point holds a different device number than the directory
    /// it is mounted over, and `/` has no parent to differ from. A bind
    /// mount of the same filesystem shares the device number and is
    /// therefore not reported.
    fn is_mountpoint(&self, p: &Path) -> Option<bool> {
        use std::os::unix::fs::MetadataExt;
        let here = fs::metadata(p).ok()?;
        let Some(parent) = p.parent() else {
            return Some(true);
        };
        Some(here.dev() != fs::metadata(parent).ok()?.dev())
    }

    /// A directory that cannot be read yields an empty list, so a caller
    /// that needs an entry from it reports the entry missing rather than
    /// the I/O error: `dri` fails with `MissingResource`, never silently.
    fn list_dir(&self, p: &Path) -> Vec<OsString> {
        let mut names: Vec<OsString> = match fs::read_dir(p) {
            Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    /// In-memory tree for tests: maps absolute paths to a type tag, plus
    /// symlinks as a path-prefix rewrite.
    #[derive(Default)]
    pub struct FakeHost {
        pub entries: BTreeMap<PathBuf, FileType>,
        pub links: BTreeMap<PathBuf, PathBuf>,
        pub mounts: BTreeSet<PathBuf>,
    }

    impl FakeHost {
        pub fn with(mut self, p: &str, t: FileType) -> Self {
            self.entries.insert(PathBuf::from(p), t);
            self
        }

        pub fn link(mut self, from: &str, to: &str) -> Self {
            self.links.insert(PathBuf::from(from), PathBuf::from(to));
            self
        }

        pub fn mount(mut self, p: &str) -> Self {
            self.mounts.insert(PathBuf::from(p));
            self
        }
    }

    impl Host for FakeHost {
        fn file_type(&self, p: &Path) -> Option<FileType> {
            self.entries.get(p).copied()
        }
        /// Longest matching link prefix is replaced once; a path no link
        /// covers is its own canonical form.
        fn canonicalize(&self, p: &Path) -> Option<PathBuf> {
            let hit = self
                .links
                .iter()
                .filter(|(from, _)| p.starts_with(from))
                .max_by_key(|(from, _)| from.components().count());
            match hit {
                // Collected component-wise: joining an empty remainder
                // would leave a trailing separator.
                Some((from, to)) => {
                    let rest = p.strip_prefix(from).ok()?;
                    Some(to.components().chain(rest.components()).collect())
                }
                None => Some(p.to_path_buf()),
            }
        }
        /// A path the tree does not hold has no answer, the same way the
        /// real host has none for a path it cannot stat.
        fn is_mountpoint(&self, p: &Path) -> Option<bool> {
            self.entries
                .contains_key(p)
                .then(|| self.mounts.contains(p))
        }
        fn list_dir(&self, p: &Path) -> Vec<OsString> {
            let mut v: Vec<OsString> = self
                .entries
                .keys()
                .filter(|k| k.parent() == Some(p))
                .filter_map(|k| k.file_name().map(|n| n.to_os_string()))
                .collect();
            v.sort();
            v
        }
    }

    /// A character device `FileType`. `mknod` needs privileges the tests
    /// do not have, so it is read from `/dev/null`.
    pub fn char_type() -> FileType {
        std::fs::metadata("/dev/null")
            .expect("/dev/null exists wherever these tests can run")
            .file_type()
    }

    /// Real `FileType` values (there is no constructor), obtained once from a temp dir.
    pub fn types() -> (FileType, FileType, FileType) {
        let (f, d, s, _) = every_type();
        (f, d, s)
    }

    /// The four types a share source can have: regular file, directory,
    /// socket and named pipe. A pipe needs no privilege to make, unlike
    /// the device nodes [`char_type`] borrows from `/dev/null`.
    pub fn every_type() -> (FileType, FileType, FileType, FileType) {
        use std::os::unix::net::UnixListener;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"").unwrap();
        std::fs::create_dir(tmp.path().join("d")).unwrap();
        let _l = UnixListener::bind(tmp.path().join("s")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            tmp.path().join("p"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let t = |n: &str| std::fs::metadata(tmp.path().join(n)).unwrap().file_type();
        (t("f"), t("d"), t("s"), t("p"))
    }
}
