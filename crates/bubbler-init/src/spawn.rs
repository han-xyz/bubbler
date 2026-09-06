//! The `flatpak-spawn` a sandboxed image loader looks for, as a mode of
//! the supervisor binary: it runs the command it is given right here,
//! inside the sandbox it was called in, instead of asking a host portal
//! to run it outside.
//!
//! gdk-pixbuf's glycin loaders pick their sandbox by looking for
//! `/.flatpak-info`, and a sandbox that carries one (bubbler's `portals`
//! grant writes it) is expected to have `flatpak-spawn` on the default
//! path — without it GTK's icon loading fails an assertion and takes the
//! application down. Running the loader here is the trust level glycin's
//! own no-sandbox fallback would have given it, and nothing in this mode
//! ever reaches the host bus.

use std::ffi::{OsStr, OsString};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

/// The file name bwrap binds this binary at, and the `argv[0]` basename
/// that selects this mode.
pub const NAME: &str = "flatpak-spawn";

/// What one `flatpak-spawn` command line asks for, once the options a
/// sandbox of bubbler's own can answer have been read off it.
#[derive(Debug, Default, PartialEq, Eq)]
struct Spawn {
    /// `--directory=DIR`: the working directory of the command.
    directory: Option<PathBuf>,
    /// `--env=K=V` pairs, in the order they were given.
    env: Vec<(OsString, OsString)>,
    /// `--clear-env`: start the command from an empty environment.
    clear_env: bool,
    /// `--forward-fd=N`: descriptors the caller passed and the command
    /// is to keep.
    forward: Vec<i32>,
    /// The command and its own arguments.
    argv: Vec<OsString>,
}

/// Options a real `flatpak-spawn` would answer by building a sub-sandbox
/// on the host. There is no host side here and no sub-sandbox to build,
/// so each one is read and dropped; the command still runs, inside this
/// sandbox, which is what the caller wanted the loader for.
const IGNORED: &[&[u8]] = &[
    b"--sandbox",
    b"--watch-bus",
    b"--latest-version",
    b"--no-network",
];

/// Prefixes of the same kind, each carrying a value: what the host would
/// have exposed to the sub-sandbox, and the flags it would have set.
const IGNORED_PREFIXES: &[&[u8]] = &[b"--sandbox-expose", b"--sandbox-flag"];

/// Options there is no sub-sandbox here to honour either, but which
/// widen what the command may reach rather than narrow it: the host
/// itself, a bus name to hold, another `/app` or `/usr` over the one it
/// has, the caller's pid namespace. Refused by name rather than dropped,
/// since a caller told its command has one of these and silently given
/// none would go on believing it.
const HOST_ONLY: &[&[u8]] = &[
    b"--host",
    b"--talk-name",
    b"--app-path",
    b"--usr-path",
    b"--expose-pids",
];

/// Read one `flatpak-spawn` command line. The first word that is not an
/// option ends the options: the rest belongs to the command, whose own
/// arguments (`prlimit --as=…`) must not be read as this shim's.
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Spawn, String> {
    let mut s = Spawn::default();
    let mut it = args.into_iter();
    while let Some(word) = it.next() {
        let bytes = word.as_bytes();
        if bytes == b"--" {
            s.argv.extend(it.by_ref());
            break;
        }
        if !bytes.starts_with(b"--") {
            s.argv.push(word);
            s.argv.extend(it.by_ref());
            break;
        }
        let (name, value) = match bytes.iter().position(|b| *b == b'=') {
            Some(i) => (&bytes[..i], Some(OsStr::from_bytes(&bytes[i + 1..]))),
            None => (bytes, None),
        };
        let named = || String::from_utf8_lossy(name).into_owned();
        if HOST_ONLY.contains(&name) {
            return Err(format!(
                "{} is not available inside a bubbler sandbox",
                named()
            ));
        }
        if IGNORED.contains(&name) || IGNORED_PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        match name {
            b"--directory" => s.directory = Some(PathBuf::from(value_of(&word, value)?)),
            b"--clear-env" => s.clear_env = true,
            b"--env" => {
                let pair = value_of(&word, value)?;
                let bytes = pair.as_bytes();
                let at = bytes
                    .iter()
                    .position(|b| *b == b'=')
                    .ok_or_else(|| format!("{}: not KEY=VALUE", word.to_string_lossy()))?;
                s.env.push((
                    OsStr::from_bytes(&bytes[..at]).to_os_string(),
                    OsStr::from_bytes(&bytes[at + 1..]).to_os_string(),
                ));
            }
            b"--forward-fd" => {
                let fd = value_of(&word, value)?
                    .to_str()
                    .and_then(|v| v.parse::<i32>().ok())
                    .filter(|n| *n >= 0)
                    .ok_or_else(|| {
                        format!("{}: not a descriptor number", word.to_string_lossy())
                    })?;
                s.forward.push(fd);
            }
            _ => return Err(format!("unknown option {}", word.to_string_lossy())),
        }
    }
    if s.argv.is_empty() {
        return Err("no command to run".to_owned());
    }
    Ok(s)
}

/// The `=VALUE` half of an option that takes one, or an error naming the
/// whole word: this grammar has no form where the value is a word of its
/// own, since a value taken from the next word would swallow a command.
fn value_of<'a>(word: &OsString, value: Option<&'a OsStr>) -> Result<&'a OsStr, String> {
    value.ok_or_else(|| format!("{}: needs a =VALUE", word.to_string_lossy()))
}

/// Parse this argv and become the command it names. Returns only when
/// the command line was refused or the command could not be run at all.
pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let spawn = match parse(args) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("{NAME}: {why}");
            return ExitCode::from(1);
        }
    };
    for fd in &spawn.forward {
        // SAFETY: `borrow_raw` only names the descriptor and never closes
        // it, so a number that is open stays owned by whoever passed it
        // in, and one that is not open fails the `fcntl` with EBADF
        // instead of being adopted. Nothing else in this process holds a
        // handle to it: the shim opens nothing before this point.
        let borrowed = unsafe { BorrowedFd::borrow_raw(*fd) };
        // The command inherits every descriptor that is not CLOEXEC, and
        // `execvp` below keeps this process, so clearing the flag is the
        // whole of forwarding one.
        if let Err(e) =
            fcntl_getfd(borrowed).and_then(|flags| fcntl_setfd(borrowed, flags - FdFlags::CLOEXEC))
        {
            eprintln!("{NAME}: --forward-fd={fd}: {e}");
            return ExitCode::from(1);
        }
    }
    let (program, rest) = spawn
        .argv
        .split_first()
        .expect("parse refuses a command line with no command");
    let mut command = Command::new(program);
    command.args(rest);
    if let Some(dir) = &spawn.directory {
        command.current_dir(dir);
    }
    if spawn.clear_env {
        command.env_clear();
    }
    for (k, v) in &spawn.env {
        command.env(k, v);
    }
    // In place, with no fork: the caller waits on this pid for the
    // command's own status, the way it would for a real flatpak-spawn.
    let e = command.exec();
    eprintln!("{NAME}: {}: {e}", program.to_string_lossy());
    ExitCode::from(127)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(words: &[&str]) -> Result<Spawn, String> {
        parse(words.iter().map(OsString::from))
    }

    /// The command line glycin builds for its SVG loader, word for word
    /// (glycin 2.1.5): everything after the first non-option word is the
    /// loader's own argv, `--as=…` and `--dbus-fd` included.
    #[test]
    fn the_glycin_loader_command_line_runs_here() {
        let s = parsed(&[
            "--sandbox",
            "--watch-bus",
            "--directory=/",
            "--forward-fd=95",
            "prlimit",
            "--as=17012097024",
            "/usr/lib/glycin-loaders/2+/glycin-svg",
            "--dbus-fd",
            "95",
        ])
        .unwrap();
        assert_eq!(s.directory, Some(PathBuf::from("/")));
        assert_eq!(s.forward, [95]);
        assert_eq!(
            s.argv,
            [
                "prlimit",
                "--as=17012097024",
                "/usr/lib/glycin-loaders/2+/glycin-svg",
                "--dbus-fd",
                "95"
            ]
        );
    }

    /// What a real portal would have used to build a sub-sandbox says
    /// nothing about one that is already inside bubbler's.
    #[test]
    fn the_sub_sandbox_options_are_ignored() {
        let s = parsed(&[
            "--sandbox",
            "--watch-bus",
            "--latest-version",
            "--no-network",
            "--sandbox-expose=xdg-run/foo",
            "--sandbox-expose-ro=xdg-run/bar",
            "--sandbox-expose-path=/opt/x",
            "--sandbox-flag=1",
            "/usr/bin/true",
        ])
        .unwrap();
        assert_eq!(
            s,
            Spawn {
                argv: vec![OsString::from("/usr/bin/true")],
                ..Spawn::default()
            }
        );
    }

    #[test]
    fn an_environment_pair_keeps_the_value_whole() {
        let s = parsed(&["--env=A=b=c", "--env=D=", "/usr/bin/true"]).unwrap();
        assert_eq!(
            s.env,
            [
                (OsString::from("A"), OsString::from("b=c")),
                (OsString::from("D"), OsString::new()),
            ]
        );
        assert!(!s.clear_env);
    }

    #[test]
    fn clear_env_is_remembered() {
        assert!(parsed(&["--clear-env", "/usr/bin/true"]).unwrap().clear_env);
    }

    #[test]
    fn an_environment_pair_without_a_value_is_refused() {
        let e = parsed(&["--env=A", "/usr/bin/true"]).unwrap_err();
        assert!(e.contains("--env=A"), "{e}");
    }

    #[test]
    fn a_double_dash_ends_the_options() {
        let s = parsed(&["--sandbox", "--", "--directory=/tmp", "x"]).unwrap();
        assert_eq!(s.directory, None);
        assert_eq!(s.argv, ["--directory=/tmp", "x"]);
    }

    #[test]
    fn the_host_is_refused_by_name() {
        let e = parsed(&["--host", "/usr/bin/true"]).unwrap_err();
        assert_eq!(e, "--host is not available inside a bubbler sandbox");
    }

    #[test]
    fn a_bus_name_to_talk_to_is_refused_by_name() {
        let e = parsed(&["--talk-name=org.gnome.Shell", "/usr/bin/true"]).unwrap_err();
        assert_eq!(e, "--talk-name is not available inside a bubbler sandbox");
    }

    /// Named, not ignored: an option this shim drops silently is one
    /// whose effect the caller still believes it asked for.
    #[test]
    fn an_unknown_option_is_named() {
        let e = parsed(&["--unset-env=SECRET", "/usr/bin/true"]).unwrap_err();
        assert!(e.contains("--unset-env=SECRET"), "{e}");
    }

    #[test]
    fn a_forward_fd_that_is_not_a_descriptor_is_refused() {
        let e = parsed(&["--forward-fd=x", "/usr/bin/true"]).unwrap_err();
        assert!(e.contains("--forward-fd=x"), "{e}");
        let e = parsed(&["--forward-fd=-1", "/usr/bin/true"]).unwrap_err();
        assert!(e.contains("--forward-fd=-1"), "{e}");
    }

    #[test]
    fn a_command_line_without_a_command_is_a_usage_error() {
        let e = parsed(&["--sandbox"]).unwrap_err();
        assert!(e.contains("command"), "{e}");
    }

    /// Paths and argv are bytes: a word that is not UTF-8 is a command,
    /// not a option the parser failed to recognise.
    #[test]
    fn a_command_that_is_not_utf8_is_still_a_command() {
        let s = parse([
            OsString::from("--sandbox"),
            OsStr::from_bytes(b"/usr/bin/\xff").to_os_string(),
        ])
        .unwrap();
        assert_eq!(s.argv, [OsStr::from_bytes(b"/usr/bin/\xff")]);
    }
}
