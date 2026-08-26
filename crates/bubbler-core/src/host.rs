//! Host filesystem inspection behind a trait so builder and services can
//! be tested against a fake tree.

use std::ffi::OsString;
use std::fs::{self, FileType};
use std::io::Read;
use std::path::{Path, PathBuf};

/// How much of a file [`Host::read_small`] is willing to hold. A sysfs
/// attribute is one page at most, and nothing bigger describes a device.
pub const SMALL_READ: usize = 4096;

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
    /// Whether the user may write `p`, with symlinks followed. A file the
    /// user cannot write is forwarded to the document portal read-only,
    /// so this decides what a sandbox is granted, not what it is told.
    fn writable(&self, p: &Path) -> bool;
    /// The bytes of `p` when there are at most [`SMALL_READ`] of them;
    /// `None` when it cannot be read or holds more. For the sysfs
    /// attributes a grant matches a device by, never for content the
    /// sandbox is handed.
    fn read_small(&self, p: &Path) -> Option<Vec<u8>>;
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

    /// `access(2)` tests the real uid and gid; bubbler is never setuid,
    /// so those are the ids it would write the file with anyway.
    fn writable(&self, p: &Path) -> bool {
        rustix::fs::access(p, rustix::fs::Access::WRITE_OK).is_ok()
    }

    /// One byte over the cap is refused rather than truncated: a
    /// truncated `idVendor` is a device id that matches the wrong
    /// device. Sysfs reports every attribute as one page long and
    /// answers with fewer bytes, so the size is read, not stat'd.
    fn read_small(&self, p: &Path) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        fs::File::open(p)
            .ok()?
            .take(SMALL_READ as u64 + 1)
            .read_to_end(&mut buf)
            .ok()?;
        (buf.len() <= SMALL_READ).then_some(buf)
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
        pub writable: BTreeSet<PathBuf>,
        pub unresolved: BTreeSet<PathBuf>,
        pub files: BTreeMap<PathBuf, Vec<u8>>,
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

        /// Mark `p` writable by the user; every other path is read-only.
        pub fn rw(mut self, p: &str) -> Self {
            self.writable.insert(PathBuf::from(p));
            self
        }

        /// Give `p` the bytes [`Host::read_small`] answers with; a path
        /// with none reads as unreadable.
        pub fn contents(mut self, p: &str, bytes: &[u8]) -> Self {
            self.files.insert(PathBuf::from(p), bytes.to_vec());
            self
        }

        /// Make `canonicalize` answer `None` for `p` and everything
        /// under it, the way the real host answers for a path that is
        /// not there.
        pub fn unresolved(mut self, p: &str) -> Self {
            self.unresolved.insert(PathBuf::from(p));
            self
        }
    }

    impl Host for FakeHost {
        fn file_type(&self, p: &Path) -> Option<FileType> {
            self.entries.get(p).copied()
        }
        /// Longest matching link prefix is replaced once; a path no link
        /// covers is its own canonical form, and one [`FakeHost::unresolved`]
        /// covers has none at all.
        fn canonicalize(&self, p: &Path) -> Option<PathBuf> {
            if self.unresolved.iter().any(|gone| p.starts_with(gone)) {
                return None;
            }
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
        /// Only what [`FakeHost::rw`] named; the tests never touch the
        /// permissions of a real file.
        fn writable(&self, p: &Path) -> bool {
            self.writable.contains(p)
        }
        /// The cap is applied here too, so a test can pin what a file
        /// too big to hold does.
        fn read_small(&self, p: &Path) -> Option<Vec<u8>> {
            self.files.get(p).filter(|b| b.len() <= SMALL_READ).cloned()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_file_is_read_whole_and_a_bigger_one_not_at_all() {
        let tmp = tempfile::tempdir().expect("a temp dir wherever these tests run");
        let write = |name: &str, bytes: Vec<u8>| {
            let p = tmp.path().join(name);
            std::fs::write(&p, bytes).expect("the temp dir is writable");
            p
        };
        let id = write("idVendor", b"0bb4\n".to_vec());
        assert_eq!(RealHost.read_small(&id).as_deref(), Some(&b"0bb4\n"[..]));
        // The cap is a limit, not a threshold: a file exactly that long
        // is still read.
        let edge = write("edge", vec![b'x'; SMALL_READ]);
        assert_eq!(
            RealHost.read_small(&edge).map(|b| b.len()),
            Some(SMALL_READ)
        );
        // One byte over is refused rather than cut short, so no caller
        // can compare against half a value.
        let over = write("over", vec![b'x'; SMALL_READ + 1]);
        assert_eq!(RealHost.read_small(&over), None);
        assert_eq!(RealHost.read_small(&tmp.path().join("gone")), None);
        // A directory opens and then refuses to be read.
        assert_eq!(RealHost.read_small(tmp.path()), None);
    }

    #[test]
    fn the_fake_host_holds_the_same_cap_as_the_real_one() {
        let host = fake::FakeHost::default()
            .contents("/sys/small", b"1\n")
            .contents("/sys/over", &vec![b'x'; SMALL_READ + 1]);
        assert_eq!(
            host.read_small(Path::new("/sys/small")).as_deref(),
            Some(&b"1\n"[..])
        );
        assert_eq!(host.read_small(Path::new("/sys/over")), None);
        assert_eq!(host.read_small(Path::new("/sys/absent")), None);
    }
}
