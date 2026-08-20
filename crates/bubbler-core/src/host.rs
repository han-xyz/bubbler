//! Host filesystem inspection behind a trait so builder and services can
//! be tested against a fake tree.

use std::ffi::OsString;
use std::fs::{self, FileType};
use std::path::Path;

/// Read-only view of the host filesystem used to decide what to bind.
pub trait Host {
    /// Type of `p` with symlinks followed; `None` if it does not exist.
    fn file_type(&self, p: &Path) -> Option<FileType>;
    /// Entry names directly under `p`; empty if unreadable or not a dir.
    fn list_dir(&self, p: &Path) -> Vec<OsString>;
}

/// The real filesystem.
pub struct RealHost;

impl Host for RealHost {
    fn file_type(&self, p: &Path) -> Option<FileType> {
        fs::metadata(p).ok().map(|m| m.file_type())
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

    /// In-memory tree for tests: maps absolute paths to a type tag.
    #[derive(Default)]
    pub struct FakeHost {
        pub entries: BTreeMap<PathBuf, FileType>,
    }

    impl FakeHost {
        pub fn with(mut self, p: &str, t: FileType) -> Self {
            self.entries.insert(PathBuf::from(p), t);
            self
        }
    }

    impl Host for FakeHost {
        fn file_type(&self, p: &Path) -> Option<FileType> {
            self.entries.get(p).copied()
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
