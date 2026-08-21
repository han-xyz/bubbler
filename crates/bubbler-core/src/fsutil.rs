//! One way to replace a file, shared by every module that keeps user
//! state on disk.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Put `text` at `path` in one step: it is written to a sibling file and
/// renamed over `path`, and `rename(2)` within one directory replaces the
/// name atomically. A reader therefore sees either the whole old file or
/// the whole new one, never the half-written file a crashed or failing
/// write would leave under a name bubbler treats as complete.
///
/// The sibling is created with `O_EXCL` and carries this process's pid,
/// so a file already sitting under that name — a symlink aimed somewhere
/// else among them — is never opened or followed, and two bubblers
/// writing at once never share one.
///
/// The returned path is where it went wrong: the sibling for a failed
/// write, `path` itself for a failed rename.
pub fn write_atomic(path: &Path, text: &str) -> Result<(), (PathBuf, io::Error)> {
    let Some(name) = path.file_name() else {
        let e = io::Error::new(io::ErrorKind::InvalidInput, "not a file path");
        return Err((path.to_path_buf(), e));
    };
    // Same directory as `path`, which is what makes the rename atomic
    // rather than a copy across filesystems.
    let mut tmp = OsString::from(".");
    tmp.push(name);
    tmp.push(format!(".{}.new", std::process::id()));
    let tmp = path.with_file_name(tmp);
    let written = (|| -> io::Result<()> {
        // `create_new` is `O_EXCL`: an existing path of that name fails
        // here rather than being written through.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        // The rename only orders the *name* change; without this the
        // contents may still be unwritten when it happens, so a crash
        // could leave the new name over an empty file.
        f.sync_all()
    })();
    // Deliberate: the error to report is the write's or the rename's own.
    // A cleanup that also failed leaves a stray sibling, which no caller
    // reads; reporting it instead would hide what actually went wrong.
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err((tmp, e));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err((path.to_path_buf(), e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_replacement_leaves_no_sibling_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f.kdl");
        write_atomic(&path, "one\n").unwrap();
        write_atomic(&path, "two\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        let left: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, [OsString::from("f.kdl")]);
    }

    #[test]
    fn a_planted_sibling_is_never_written_through() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f.kdl");
        let sibling = tmp
            .path()
            .join(format!(".f.kdl.{}.new", std::process::id()));
        let elsewhere = tmp.path().join("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &sibling).unwrap();
        let (at, e) = write_atomic(&path, "one\n").unwrap_err();
        assert_eq!(at, sibling);
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert!(!elsewhere.exists());
        assert!(!path.exists());
    }

    #[test]
    fn a_path_that_names_no_file_is_an_error_rather_than_a_panic() {
        let (at, e) = write_atomic(Path::new("/"), "x").unwrap_err();
        assert_eq!(at, Path::new("/"));
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }
}
