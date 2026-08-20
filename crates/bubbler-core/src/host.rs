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
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// In-memory tree for tests: maps absolute paths to a type tag, plus
    /// symlinks as a path-prefix rewrite.
    #[derive(Default)]
    pub struct FakeHost {
        pub entries: BTreeMap<PathBuf, FileType>,
        pub links: BTreeMap<PathBuf, PathBuf>,
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

    /// Real `FileType` values (there is no constructor), obtained once from a temp dir.
    pub fn types() -> (FileType, FileType, FileType) {
        use std::os::unix::net::UnixListener;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"").unwrap();
        std::fs::create_dir(tmp.path().join("d")).unwrap();
        let _l = UnixListener::bind(tmp.path().join("s")).unwrap();
        let t = |n: &str| std::fs::metadata(tmp.path().join(n)).unwrap().file_type();
        (t("f"), t("d"), t("s"))
    }
}
