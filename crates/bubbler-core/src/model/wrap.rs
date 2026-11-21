//! PATH shims: a symlink in `~/.local/bin` that runs bubbler under
//! another name, plus the registry saying which instance each name opens.
//!
//! `argv[0]` is the only place the name survives — `current_exe()`
//! resolves the symlink to the real binary — and it is caller-controlled,
//! so dispatch is a lookup in a file bubbler wrote, never a name turned
//! into an instance.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::config;
use crate::env::Env;
use crate::error::{ReadError, WrapError};
use crate::instance;
use crate::kdl_out::quote;
use crate::names::{INIT_BIN, PASTA_BIN, PROXY_BIN};

pub(crate) const REGISTRY_FILE: &str = "wraps.kdl";

// First line of the registry. Informational only — nothing reads it
// back — so that a person opening the file can see what wrote it.
pub(crate) const HEADER: &str = "// bubbler wraps: 1\n";

// Directory the shims go in, relative to `$HOME`. The only directory a
// user can add to their own `PATH` without a password.
const SHIM_DIR: &str = ".local/bin";

// File name of the bubbler binary, which is what a shim points at.
const BUBBLER_BIN: &str = "bubbler";

/// Names a shim may not take: bubbler resolves each of them through
/// `PATH` itself, so a shim of that name would shadow the real program —
/// `bubbler` into a loop, the rest into every sandbox failing to start.
pub const RESERVED: &[&str] = &[
    BUBBLER_BIN,
    INIT_BIN,
    "bwrap",
    PROXY_BIN,
    PASTA_BIN,
    // The package `pasta` ships in, and the other name it answers to.
    "passt",
];

/// One registry entry: the name on `PATH` and the instance it opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrap {
    /// Name the shim was created under, one file name.
    pub name: String,
    /// Instance `bubbler open` is called with.
    pub instance: String,
}

/// Whether a registered shim would run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// A symlink of bubbler's own, leading to a binary that is there,
    /// for an instance that still exists.
    Ok,
    /// Anything else: nothing at that path, a file that is not one of
    /// bubbler's symlinks, a binary that has moved, or an instance that
    /// has been deleted.
    Broken,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ok => "ok",
            Self::Broken => "broken",
        })
    }
}

/// A registry entry together with the shim path it names and whether
/// that path would run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The registry line.
    pub wrap: Wrap,
    /// `~/.local/bin/<name>`.
    pub path: PathBuf,
    /// What is at that path now.
    pub state: State,
}

/// The shim `wrap_ops::add` wrote and what it found there first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    /// `~/.local/bin/<name>`.
    pub path: PathBuf,
    /// A shim of bubbler's was already there that the registry did not
    /// name, and this call took it over.
    pub adopted: bool,
}

/// `$XDG_CONFIG_HOME/bubbler/wraps.kdl`.
pub fn registry_path(env: &Env) -> PathBuf {
    env.config_home.join("bubbler").join(REGISTRY_FILE)
}

/// `~/.local/bin`, where every shim is written.
pub fn shim_dir(env: &Env) -> PathBuf {
    env.home.join(SHIM_DIR)
}

/// Whether `name` may be a shim. Deliberately the instance name grammar
/// (`[A-Za-z0-9._-]`, not leading `-`, not `.` or `..`): a shim is
/// created inside [`shim_dir`], so a name holding `/` would name a path
/// outside it, and control characters or spaces in a name make a command
/// nobody can type and a registry line nobody can read.
pub fn is_shim_name(name: &str) -> bool {
    instance::is_plain_name(name)
}

pub(crate) fn check_name(name: &str) -> Result<(), WrapError> {
    if !is_shim_name(name) {
        return Err(WrapError::InvalidName(name.to_owned()));
    }
    if RESERVED.contains(&name) {
        return Err(WrapError::Reserved(name.to_owned()));
    }
    Ok(())
}

/// The shim name this process was called by, or `None` when it was
/// called as bubbler itself. `bubbler-<something>` is left alone too, so
/// `cargo run` and the test binaries never dispatch. Compared on the
/// file name only: a shell passes the bare word it found on `PATH`, an
/// explicit invocation passes the whole path.
pub fn shim_name(argv0: Option<&OsStr>) -> Option<String> {
    let name = Path::new(argv0?).file_name()?.to_str()?;
    if name == BUBBLER_BIN || name.starts_with("bubbler-") {
        return None;
    }
    is_shim_name(name).then(|| name.to_owned())
}

/// The command line a shim stands for: `bubbler open <instance> --
/// <args>`, ready for the argument parser to read as if it had been
/// typed. `args` is the whole command to run inside, the instance's own
/// `command` first, since `open` would otherwise take the shim's
/// arguments *as* the command.
pub fn open_argv(instance: &str, args: &[OsString]) -> Vec<OsString> {
    let mut argv = vec![
        OsString::from(BUBBLER_BIN),
        OsString::from("open"),
        OsString::from(instance),
        OsString::from("--"),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// Every registered shim, sorted by name. A registry that is not there
/// is an empty one; a registry bubbler did not write is an error, since
/// dispatch turns what it says into an instance name.
pub fn load(env: &Env) -> Result<Vec<Wrap>, WrapError> {
    let path = registry_path(env);
    let text = match config::read_bounded(&path) {
        Ok(text) => text,
        // The same refusal `parse` below makes, named the same way:
        // the registry is read on every start under a shim name.
        Err(ReadError::TooLarge(source)) => return Err(WrapError::Parse { path, source }),
        Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(ReadError::Io(e)) => return Err(WrapError::Io(path, e)),
    };
    parse(&path, &text)
}

/// The instance `name` opens, or `None` when no shim has that name.
pub fn lookup(env: &Env, name: &str) -> Result<Option<Wrap>, WrapError> {
    Ok(load(env)?.into_iter().find(|w| w.name == name))
}

/// Every registered shim with the path it names and whether that path
/// would still run. `bubbler` is the running binary, which is what a
/// working shim points at.
pub fn list(env: &Env, bubbler: &Path) -> Result<Vec<Entry>, WrapError> {
    let dir = shim_dir(env);
    Ok(load(env)?
        .into_iter()
        .map(|wrap| {
            let path = dir.join(&wrap.name);
            let state = state_of(env, &wrap, &path, bubbler);
            Entry { wrap, path, state }
        })
        .collect())
}

// A shim runs only if all three hold: the path is one of bubbler's
// symlinks, the binary it names is there, and the instance it opens
// still exists.
fn state_of(env: &Env, wrap: &Wrap, path: &Path, bubbler: &Path) -> State {
    let runs = is_ours(path, bubbler) && fs::metadata(path).is_ok_and(|m| m.is_file());
    let instance = instance::config_path_checked(env, &wrap.instance).is_ok();
    match runs && instance {
        true => State::Ok,
        false => State::Broken,
    }
}

// Whether `path` is a shim bubbler made: a symlink at the running
// binary, or at some other file named `bubbler` — a package upgrade or
// a dev build changes the path, and the shim is still bubbler's own.
// Never true of a regular file or of a link pointing anywhere else, so
// nothing bubbler did not create is ever repointed or removed.
pub(crate) fn is_ours(path: &Path, bubbler: &Path) -> bool {
    let Ok(target) = fs::read_link(path) else {
        return false;
    };
    target == bubbler || target.file_name() == Some(OsStr::new(BUBBLER_BIN))
}

/// What is wrong with reaching `dir/name` through `search_path`, if
/// anything: `~/.local/bin` is not on Arch's default `PATH` at all, and
/// a shim behind the directory the real program is in never runs.
pub fn path_warning(dir: &Path, name: &str, search_path: &[PathBuf]) -> Option<String> {
    let dir_key = canonical(dir);
    let Some(here) = search_path.iter().position(|p| canonical(p) == dir_key) else {
        return Some(format!(
            "{} is not on your PATH, so `{name}` will not be found; \
             add it in your shell's startup file",
            dir.display()
        ));
    };
    search_path[..here].iter().find_map(|earlier| {
        let other = earlier.join(name);
        // Only something the shell would actually run: a directory or an
        // unreadable stub of that name shadows nothing.
        is_executable(&other).then(|| {
            format!(
                "{} comes first on your PATH, so `{name}` still runs that",
                other.display()
            )
        })
    })
}

// Whether `p` is a regular file with an execute bit anyone holds, which
// is what a `PATH` search stops at.
fn is_executable(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

// `p` with symlinks resolved where that is possible, so two spellings
// of the same directory compare equal. A path that cannot be resolved
// compares as written.
fn canonical(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

// The registry as KDL: the header, then one `wrap` node per shim in
// name order, so the file does not churn between writes.
pub(crate) fn render(wraps: &[Wrap]) -> String {
    let mut out = String::from(HEADER);
    for w in wraps {
        out.push_str(&format!(
            "wrap {} instance={}\n",
            quote(&w.name),
            quote(&w.instance)
        ));
    }
    out
}

// Every deviation is an error: a name bubbler would not have written is
// a file somebody else edited, and dispatch builds an instance path out
// of what it says.
//
// Through [`config::parse_document`], because this is the same recursive
// KDL parser every other configuration goes through, and it is read on
// every start under a shim name.
fn parse(path: &Path, text: &str) -> Result<Vec<Wrap>, WrapError> {
    let doc = config::parse_document(text).map_err(|source| WrapError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let bad = |reason: String| WrapError::Malformed {
        path: path.to_path_buf(),
        reason,
    };
    let mut out: Vec<Wrap> = Vec::new();
    for node in doc.nodes() {
        if node.name().value() != "wrap" {
            return Err(bad(format!("unknown node `{}`", node.name().value())));
        }
        if node.ty().is_some() || node.entries().iter().any(|e| e.ty().is_some()) {
            return Err(bad("type annotations are not supported".to_owned()));
        }
        if node.children().is_some() {
            return Err(bad("`wrap` takes no children".to_owned()));
        }
        let mut name: Option<&str> = None;
        let mut instance: Option<&str> = None;
        for e in node.entries() {
            match e.name().map(|n| n.value()) {
                None => {
                    if name.is_some() {
                        return Err(bad("`wrap` takes exactly one name".to_owned()));
                    }
                    name = Some(
                        e.value()
                            .as_string()
                            .ok_or_else(|| bad("a shim name must be a string".to_owned()))?,
                    );
                }
                Some("instance") => {
                    if instance.is_some() {
                        return Err(bad("`wrap` takes one `instance`".to_owned()));
                    }
                    instance = Some(
                        e.value()
                            .as_string()
                            .ok_or_else(|| bad("`instance` must be a string".to_owned()))?,
                    );
                }
                Some(p) => return Err(bad(format!("`wrap` does not accept property `{p}`"))),
            }
        }
        let name = name.ok_or_else(|| bad("`wrap` takes exactly one name".to_owned()))?;
        let instance =
            instance.ok_or_else(|| bad(format!("`wrap \"{name}\"` names no instance")))?;
        // The same refusals `wrap` makes, applied to a file that may have
        // been edited since: a shim named `bwrap` would break every
        // sandbox on the machine whoever wrote the line.
        match check_name(name) {
            Ok(()) => {}
            Err(WrapError::Reserved(_)) => {
                return Err(bad(format!("`{name}` is a name bubbler resolves itself")));
            }
            Err(_) => return Err(bad(format!("`{name}` is not a shim name"))),
        }
        if !instance::is_plain_name(instance) {
            return Err(bad(format!("`{instance}` is not an instance name")));
        }
        if out.iter().any(|w| w.name == name) {
            return Err(bad(format!("`{name}` is named more than once")));
        }
        out.push(Wrap {
            name: name.to_owned(),
            instance: instance.to_owned(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dispatched_argv_is_an_open_with_the_command_after_it() {
        let argv = open_argv(
            "ff",
            &[OsString::from("firefox"), OsString::from("https://x")],
        );
        let want: Vec<OsString> = ["bubbler", "open", "ff", "--", "firefox", "https://x"]
            .iter()
            .map(OsString::from)
            .collect();
        assert_eq!(argv, want);
    }

    #[test]
    fn only_a_name_that_is_not_bubblers_own_dispatches() {
        for own in [
            "bubbler",
            "/usr/bin/bubbler",
            "bubbler-init",
            "bubbler-tui",
            "",
            "/",
            "-x",
        ] {
            assert_eq!(shim_name(Some(OsStr::new(own))), None, "{own}");
        }
        assert_eq!(shim_name(None), None);
        assert_eq!(
            shim_name(Some(OsStr::new("firefox"))),
            Some("firefox".into())
        );
        assert_eq!(
            shim_name(Some(OsStr::new("/home/h/.local/bin/ff"))),
            Some("ff".into())
        );
    }
}
