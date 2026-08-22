//! The `bubbler` binary, and the three ways this editor runs it.
//!
//! Every action is that command line with one argument per element and no
//! shell anywhere: the editor knows which subcommand to call, and the CLI
//! stays the one place that decides what a subcommand does.

use std::ffi::OsString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

/// File name of the command line binary this editor drives.
pub const BINARY: &str = "bubbler";

/// Whether `path` is a file a `PATH` search would run.
fn executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Host path of the `bubbler` binary: beside this one first, so a pair
/// built or unpacked together stay a pair, then the first on `$PATH`.
pub fn locate(search_path: &[PathBuf]) -> Option<PathBuf> {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(BINARY)));
    if let Some(sibling) = sibling.filter(|p| executable(p)) {
        return Some(sibling);
    }
    search_path
        .iter()
        .map(|dir| dir.join(BINARY))
        .find(|candidate| executable(candidate))
}

/// The `bubbler` binary this editor drives.
#[derive(Debug, Clone)]
pub struct Cli {
    path: PathBuf,
}

impl Cli {
    /// Drive the binary at `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn command(&self, args: &[OsString]) -> Command {
        let mut cmd = Command::new(&self.path);
        cmd.args(args);
        cmd
    }

    /// Start a sandbox and come straight back to the editor: a process
    /// group of its own, so a signal the terminal sends to the editor's
    /// foreground group does not reach it, and `/dev/null` for stdio, so
    /// it holds no descriptor of this terminal. It stays in this session
    /// and this session's controlling terminal is still its own; it is
    /// not `setsid(2)`, and a hangup on the terminal is still delivered.
    pub fn detached(&self, args: &[OsString]) -> io::Result<Child> {
        self.command(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // A new process group, not a new session: it is what keeps
            // `^C` in the editor off the sandbox, and it is asked for
            // without a `pre_exec` closure and so without an unsafe block.
            .process_group(0)
            .spawn()
    }

    /// Hand the terminal over and wait: the caller has already left the
    /// alternate screen and raw mode, so the command owns the terminal
    /// exactly as it would from a shell.
    pub fn attached(&self, args: &[OsString]) -> io::Result<ExitStatus> {
        self.command(args).status()
    }

    /// Run and collect what it printed, for the commands whose whole
    /// answer is their output: the explanation, a lint report, a profile.
    /// stdout and stderr are kept apart, so a warning cannot be read as
    /// part of the report.
    pub fn captured(&self, args: &[OsString]) -> io::Result<Output> {
        let out = self.command(args).stdin(Stdio::null()).output()?;
        Ok(Output {
            status: out.status,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// What a captured run printed. Lossy text, because it is on its way to a
/// terminal buffer and not to a file: bubbler's own output is UTF-8, and
/// a path that is not is better shown with a replacement character than
/// not at all.
#[derive(Debug, Clone)]
pub struct Output {
    /// How the command ended.
    pub status: ExitStatus,
    /// The report itself.
    pub stdout: String,
    /// Warnings and errors, which bubbler keeps off stdout.
    pub stderr: String,
}

impl Output {
    /// The lines a viewer shows: the report, then anything the command
    /// warned about under it.
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self.stdout.lines().map(str::to_owned).collect();
        if !self.stderr.trim().is_empty() {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.extend(self.stderr.lines().map(str::to_owned));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn executable_file(path: &Path) {
        fs::write(path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn the_binary_is_looked_for_on_the_path_when_no_sibling_has_the_bit() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("bin");
        fs::create_dir(&dir).unwrap();
        assert_eq!(locate(std::slice::from_ref(&dir)), None);
        let bin = dir.join(BINARY);
        fs::write(&bin, "not executable").unwrap();
        assert_eq!(
            locate(std::slice::from_ref(&dir)),
            None,
            "a file with no execute bit"
        );
        executable_file(&bin);
        assert_eq!(locate(&[dir]), Some(bin));
    }

    #[test]
    fn captured_output_reads_as_the_report_then_the_warnings() {
        let out = Output {
            status: std::process::Command::new("/bin/true").status().unwrap(),
            stdout: "one\ntwo\n".to_owned(),
            stderr: "bubbler: warning: three\n".to_owned(),
        };
        assert_eq!(out.lines(), ["one", "two", "", "bubbler: warning: three"]);
        let quiet = Output {
            stderr: String::new(),
            ..out
        };
        assert_eq!(quiet.lines(), ["one", "two"]);
    }
}
