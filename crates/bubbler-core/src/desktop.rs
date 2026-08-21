//! Launcher entries: copy an application's own `.desktop` file and patch
//! the few keys that make it start through bubbler.
//!
//! The vendor file is copied verbatim — every group, every key, every
//! locale — and only `Name`, `Exec`, `TryExec`, `DBusActivatable` and
//! bubbler's own marker key are rewritten. Nothing is dropped: the spec's
//! "MUST not remove any fields" rule is about rewriting a file in place,
//! and while this authors a new entry derived from one, a key nobody here
//! understands is exactly the key that must not be lost.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::InstanceConfig;
use crate::env::Env;
use crate::error::DesktopError;
use crate::fsutil;

/// Appended to `Name` and every `Name[xx]` of the generated entry. The
/// only mark a user sees in a menu: an icon badge would mean shipping
/// icon files and a theme cache, and every localized name carries this
/// one, so the entry is marked in every locale rather than in English.
pub const SUFFIX: &str = " (Bubbler)";

/// Key naming the instance an entry was generated for. `X-` because a
/// desktop entry may only be extended with `X-` keys, and the instance
/// name because that is what makes `--remove` and a refusal to overwrite
/// safe: an entry without it was written by somebody else.
pub const MARKER: &str = "X-Bubbler-Instance";

/// Name of the `bubbler` binary as an entry's `Exec` may name it.
const BINARY: &str = "bubbler";

/// Subdirectory of a data directory that holds desktop entries.
const APPLICATIONS: &str = "applications";

/// Where entries are read from and written to. Read order is user first,
/// which is the precedence the XDG base directory specification gives
/// `$XDG_DATA_HOME` over `$XDG_DATA_DIRS`.
#[derive(Debug, Clone)]
pub struct Dirs {
    /// `$XDG_DATA_HOME/applications`: the only directory bubbler writes.
    pub user: PathBuf,
    /// System entry directories, in precedence order.
    pub system: Vec<PathBuf>,
}

impl Dirs {
    /// The `applications` directory of `$XDG_DATA_HOME` and of every
    /// `$XDG_DATA_DIRS` entry, which is exactly where a launcher looks —
    /// a host that puts entries elsewhere (a Nix profile, a flatpak
    /// export) says so in that variable and bubbler follows it.
    pub fn from_env(env: &Env) -> Self {
        Self {
            user: env.data_home.join(APPLICATIONS),
            system: env.data_dirs.iter().map(|d| d.join(APPLICATIONS)).collect(),
        }
    }

    /// Every directory an entry may be read from, in lookup order.
    pub fn lookup(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.user.as_path()).chain(self.system.iter().map(PathBuf::as_path))
    }
}

/// The `[Desktop Entry]` keys a lookup decides on, read without parsing
/// the rest of the file.
struct Head<'a> {
    exec: Option<&'a str>,
    marker: Option<&'a str>,
    /// `NoDisplay=true`: an entry a launcher does not show, which is what
    /// an application's MIME-handler-only entries are. Never the one a
    /// user means by the application's name.
    no_display: bool,
    /// `Hidden=true`, which the specification calls "strictly equivalent
    /// to the .desktop file not existing at all".
    hidden: bool,
}

/// Read the `[Desktop Entry]` group of `text`, ignoring every other
/// group: only the main group decides what an entry is and what it runs.
fn head(text: &str) -> Head<'_> {
    let mut found = Head {
        exec: None,
        marker: None,
        no_display: false,
        hidden: false,
    };
    for line in group_lines(text, "Desktop Entry") {
        let Some((key, value)) = split_key(line) else {
            continue;
        };
        match key {
            "Exec" if found.exec.is_none() => found.exec = Some(value),
            MARKER if found.marker.is_none() => found.marker = Some(value),
            "NoDisplay" => found.no_display |= value == "true",
            "Hidden" => found.hidden |= value == "true",
            _ => {}
        }
    }
    found
}

/// The lines of one group, without its header.
fn group_lines<'a>(text: &'a str, group: &'a str) -> impl Iterator<Item = &'a str> {
    text.lines()
        .skip_while(move |l| header(l) != Some(group))
        .skip(1)
        .take_while(|l| header(l).is_none())
}

/// The group a `[name]` line names, or `None` for any other line.
fn header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

/// `key=value` split with the space the specification allows around the
/// `=` removed. Comments and blank lines have no `=` and fall out here.
fn split_key(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim_end(), value.trim_start()))
}

/// The part of a key before its `[locale]` suffix.
fn base_key(key: &str) -> &str {
    key.split('[').next().unwrap_or(key)
}

/// The instance an entry was generated for, if bubbler generated it.
pub fn owner(text: &str) -> Option<&str> {
    head(text).marker
}

/// The program an `Exec` value runs, unquoted. Only the first argument is
/// read, which is the one a launcher has to find on `PATH` before it will
/// show the entry at all.
fn exec_program(value: &str) -> Option<String> {
    let value = value.trim_start();
    if let Some(quoted) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut escaped = false;
        for c in quoted.chars() {
            match (escaped, c) {
                (false, '\\') => escaped = true,
                (false, '"') => return Some(out),
                (_, c) => {
                    out.push(c);
                    escaped = false;
                }
            }
        }
        // An unterminated quote is not a command line anything can run.
        return None;
    }
    let word = value.split_ascii_whitespace().next()?;
    Some(word.to_owned())
}

/// `value` as one argument of an `Exec` value: quoted only where it holds
/// a character the specification reserves, since a quoted argument is
/// also where a field code would stop expanding.
fn exec_quote(value: &str) -> String {
    const RESERVED: &[char] = &[
        ' ', '\t', '\n', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(',
        ')', '`',
    ];
    // A literal percent is written `%%`; a single one is the start of a
    // field code, and a launcher would expand or drop it.
    let value = value.replace('%', "%%");
    if !value.contains(RESERVED) {
        return value;
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// The command basename an entry is looked up by: the first word of the
/// instance's `command`, without its directory.
fn command_name(config: &InstanceConfig) -> Option<&OsStr> {
    Path::new(config.command.as_ref()?.first()?).file_name()
}

/// The vendor entry an instance's launcher entry is copied from: the
/// `desktop` node if the config has one, else `<command>.desktop`, else
/// the one entry whose `Exec` runs `<command>`.
///
/// Entries bubbler generated are never a source; neither are entries a
/// launcher does not display, which is what an application's
/// MIME-handler-only entries are. Two candidates are an error rather than
/// a guess: `lutris` matches its own entry and its URL handler, and only
/// the user knows which one the instance is for.
pub fn source(dirs: &Dirs, name: &str, config: &InstanceConfig) -> Result<PathBuf, DesktopError> {
    if let Some(hint) = &config.desktop {
        return find(dirs, OsStr::new(hint)).ok_or_else(|| DesktopError::HintNotFound {
            name: hint.clone(),
            dirs: dirs.lookup().map(Path::to_path_buf).collect(),
        });
    }
    let command = command_name(config).ok_or_else(|| DesktopError::NoCommand(name.to_owned()))?;
    let mut exact = command.to_os_string();
    exact.push(".desktop");
    if let Some(path) = find(dirs, &exact) {
        return Ok(path);
    }
    let mut candidates = scan(dirs, command);
    match candidates.len() {
        0 => Err(DesktopError::NotFound {
            command: command.to_string_lossy().into_owned(),
        }),
        1 => Ok(candidates.remove(0)),
        _ => Err(DesktopError::Ambiguous {
            command: command.to_string_lossy().into_owned(),
            candidates: candidates
                .iter()
                .map(|p| p.file_name().unwrap_or(p.as_os_str()).to_string_lossy())
                .map(std::borrow::Cow::into_owned)
                .collect(),
        }),
    }
}

/// The first directory holding `file` as an entry bubbler did not write.
fn find(dirs: &Dirs, file: &OsStr) -> Option<PathBuf> {
    dirs.lookup()
        .map(|d| d.join(file))
        .find(|p| std::fs::read_to_string(p).is_ok_and(|t| owner(&t).is_none()))
}

/// Every entry whose `Exec` runs `command`, in lookup order, one per file
/// name: a user's own copy of an entry shadows the system's, the way a
/// launcher resolves it.
fn scan(dirs: &Dirs, command: &OsStr) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for dir in dirs.lookup() {
        let mut names: Vec<OsString> = match std::fs::read_dir(dir) {
            Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
            Err(_) => continue,
        };
        names.sort();
        for name in names {
            if Path::new(&name).extension() != Some(OsStr::new("desktop")) {
                continue;
            }
            if found.iter().any(|p| p.file_name() == Some(&name)) {
                continue;
            }
            let path = dir.join(&name);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let head = head(&text);
            if head.marker.is_some() || head.no_display || head.hidden {
                continue;
            }
            let runs = head
                .exec
                .and_then(exec_program)
                .is_some_and(|p| Path::new(&p).file_name() == Some(command));
            if runs {
                found.push(path);
            }
        }
    }
    found
}

/// Which of the keys bubbler owns the source's `[Desktop Entry]` group
/// already carries, and therefore which are rewritten rather than added.
#[derive(Default)]
struct Present {
    try_exec: bool,
    dbus_activatable: bool,
}

/// The generated entry's text: `text` with `Name`, `Exec`, `TryExec`,
/// `DBusActivatable` and the marker key changed and nothing else touched.
///
/// `program` is what the entry calls to reach bubbler. Every `Exec`,
/// including each `[Desktop Action]`'s, becomes `<program> open
/// <instance> -- <the vendor's own command line>`, so field codes stay
/// where the vendor put them: they expand at the tail, which is where
/// `bubbler open` collects the command.
pub fn patch(text: &str, instance: &str, program: &Path) -> Result<String, DesktopError> {
    if let Some(owner) = owner(text) {
        return Err(DesktopError::Generated(owner.to_owned()));
    }
    let program = program.to_str().ok_or(DesktopError::ProgramNotUtf8)?;
    let head = head(text);
    if !text.lines().any(|l| header(l) == Some("Desktop Entry")) {
        return Err(DesktopError::NoEntryGroup);
    }
    if head.exec.is_none() {
        return Err(DesktopError::NoExec);
    }
    if head.hidden {
        return Err(DesktopError::Hidden);
    }
    let launch = format!("{} open {instance} -- ", exec_quote(program));
    // Keys bubbler adds end their lines the way the file it copies ends
    // its own, so a CRLF entry stays one file rather than two styles.
    let eol = match text.contains("\r\n") {
        true => "\r",
        false => "",
    };
    let mut out: Vec<String> = Vec::new();
    let mut group: Option<String> = None;
    let mut present = Present::default();
    let mut lines: Vec<&str> = text.split('\n').collect();
    let trailing = text.ends_with('\n');
    if trailing {
        lines.pop();
    }
    for line in lines {
        // A carriage return belongs to the line ending, not to the value,
        // and is put back on a line that is rewritten.
        let (body, cr) = match line.strip_suffix('\r') {
            Some(body) => (body, "\r"),
            None => (line, ""),
        };
        if let Some(name) = header(body) {
            if group.as_deref() == Some("Desktop Entry") {
                out.extend(added(&present, instance, program, eol));
            }
            group = Some(name.to_owned());
            out.push(line.to_owned());
            continue;
        }
        let entry = group.as_deref() == Some("Desktop Entry");
        let Some((key, value)) = split_key(body) else {
            out.push(line.to_owned());
            continue;
        };
        let rewritten = match (entry, key, base_key(key)) {
            (true, _, "Name") => Some(format!("{key}={value}{SUFFIX}")),
            (_, "Exec", _) => Some(format!("{key}={launch}{value}")),
            (true, "TryExec", _) => {
                present.try_exec = true;
                Some(format!("{key}={program}"))
            }
            (true, "DBusActivatable", _) => {
                present.dbus_activatable = true;
                Some(format!("{key}=false"))
            }
            _ => None,
        };
        match rewritten {
            Some(new) => out.push(new + cr),
            None => out.push(line.to_owned()),
        }
    }
    if group.as_deref() == Some("Desktop Entry") {
        out.extend(added(&present, instance, program, eol));
    }
    let mut text = out.join("\n");
    if trailing {
        text.push('\n');
    }
    Ok(text)
}

/// The keys the source did not carry, written at the end of its
/// `[Desktop Entry]` group.
///
/// `DBusActivatable=true` is set to `false` rather than dropped, and
/// added where it was absent, because a launcher that understands the key
/// ignores `Exec` entirely and asks the session bus to start the
/// application — outside the sandbox, with nothing printed anywhere.
fn added(present: &Present, instance: &str, program: &str, eol: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if !present.try_exec {
        lines.push(format!("TryExec={program}"));
    }
    if !present.dbus_activatable {
        lines.push("DBusActivatable=false".to_owned());
    }
    lines.push(format!("{MARKER}={instance}"));
    lines.iter().map(|l| format!("{l}{eol}")).collect()
}

/// The generated entry for `instance`, from the vendor file at `source`.
pub fn render(source: &Path, instance: &str, program: &Path) -> Result<String, DesktopError> {
    let text = std::fs::read_to_string(source).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData => DesktopError::NotUtf8(source.to_path_buf()),
        _ => DesktopError::Io(source.to_path_buf(), e),
    })?;
    patch(&text, instance, program)
}

/// Where an instance's entry is written: its own file name, or the
/// vendor's under `--replace`, which shadows the application's entry
/// because a user entry of the same file name wins over a system one.
pub fn target(dirs: &Dirs, instance: &str, source: &Path, replace: bool) -> PathBuf {
    let name = match replace {
        true => source
            .file_name()
            .map_or_else(|| OsString::from("bubbler.desktop"), OsStr::to_os_string),
        false => OsString::from(format!("bubbler-{instance}.desktop")),
    };
    dirs.user.join(name)
}

/// Write `text` to `path`, refusing every file that is not this
/// instance's own entry: bubbler never overwrites a file it did not
/// write, and does not guess who wrote one it cannot recognise.
pub fn write(path: &Path, text: &str, instance: &str) -> Result<(), DesktopError> {
    match std::fs::symlink_metadata(path) {
        // A symlink is never bubbler's entry, whatever it points at.
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(DesktopError::Foreign(path.to_path_buf()));
        }
        Ok(_) => match std::fs::read_to_string(path) {
            Ok(held) => match owner(&held) {
                Some(o) if o == instance => {}
                Some(o) => {
                    return Err(DesktopError::OtherInstance {
                        path: path.to_path_buf(),
                        instance: o.to_owned(),
                    });
                }
                None => return Err(DesktopError::Foreign(path.to_path_buf())),
            },
            // A file that is not even UTF-8 is not an entry of bubbler's.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(DesktopError::Foreign(path.to_path_buf()));
            }
            Err(e) => return Err(DesktopError::Io(path.to_path_buf(), e)),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(DesktopError::Io(path.to_path_buf(), e)),
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DesktopError::Io(parent.to_path_buf(), e))?;
    }
    // The sibling it writes through is dot-prefixed and does not end in
    // `.desktop`, so neither a launcher nor `update-desktop-database`
    // reads it as an entry while it is there.
    fsutil::write_atomic(path, text).map_err(|(at, e)| DesktopError::Io(at, e))
}

/// Every entry bubbler generated, as `(path, instance)`, sorted by path.
/// Only the user's directory: it is the only one bubbler writes.
pub fn generated(dirs: &Dirs) -> Vec<(PathBuf, String)> {
    let mut names: Vec<OsString> = match std::fs::read_dir(&dirs.user) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
        Err(_) => return Vec::new(),
    };
    names.sort();
    names
        .into_iter()
        .filter(|n| Path::new(n).extension() == Some(OsStr::new("desktop")))
        .filter_map(|n| {
            let path = dirs.user.join(n);
            let text = std::fs::read_to_string(&path).ok()?;
            Some((path, owner(&text)?.to_owned()))
        })
        .collect()
}

/// Delete this instance's generated entries, and only those: a file
/// without bubbler's marker is left where it is. The paths removed.
pub fn remove(dirs: &Dirs, instance: &str) -> Result<Vec<PathBuf>, DesktopError> {
    let mine: Vec<PathBuf> = generated(dirs)
        .into_iter()
        .filter(|(_, owner)| owner == instance)
        .map(|(path, _)| path)
        .collect();
    if mine.is_empty() {
        return Err(DesktopError::NotGenerated {
            instance: instance.to_owned(),
            dir: dirs.user.clone(),
        });
    }
    for path in &mine {
        std::fs::remove_file(path).map_err(|e| DesktopError::Io(path.clone(), e))?;
    }
    Ok(mine)
}

/// What a generated entry should call to reach this bubbler: the bare
/// name where `PATH` resolves it to this very binary, else the absolute
/// path. A launcher shows no entry at all when it cannot find the
/// program, so a dev build must name itself where it actually is.
pub fn program(exe: &Path, search_path: &[PathBuf]) -> PathBuf {
    let real = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    // Only the first executable of that name counts, because that is
    // where a `PATH` search stops: another bubbler ahead of this one
    // means the bare name would start that binary instead, and one
    // behind it is never reached at all.
    let first = search_path
        .iter()
        .map(|dir| dir.join(BINARY))
        .find(|candidate| executable(candidate))
        .and_then(|candidate| std::fs::canonicalize(candidate).ok());
    match first.is_some_and(|found| found == real) {
        true => PathBuf::from(BINARY),
        false => real,
    }
}

/// Whether `path` is a file a `PATH` search would run: a name without an
/// execute bit is one the search passes over.
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// What `desktop-file-validate` calls an error in the entry at `path`,
/// empty when it is installed and content with the file, and empty when
/// it is not installed at all. Its hints and warnings are left out: they
/// are about the application's own file, which bubbler copied and is not
/// in a position to fix.
pub fn validate(path: &Path) -> Vec<String> {
    let Ok(out) = Command::new("desktop-file-validate").arg(path).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("error:"))
        .map(str::to_owned)
        .collect()
}

/// Rebuild the launcher's MIME cache for `dir`. `false` when
/// `update-desktop-database` is not installed, which costs the entry its
/// place in "Open With" lists and nothing else.
pub fn update_database(dir: &Path) -> Result<bool, DesktopError> {
    // Its exit status is not read: what it reports about other files in
    // the directory is not this entry's business.
    match Command::new("update-desktop-database")
        .arg(dir)
        .stdout(Stdio::null())
        .status()
    {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(DesktopError::Io(dir.to_path_buf(), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    const KITTY: &str = include_str!("../fixtures/kitty.desktop");
    const FIREFOX: &str = include_str!("../fixtures/firefox.desktop");
    const KEEPASSXC: &str = include_str!("../fixtures/org.keepassxc.KeePassXC.desktop");
    const STEAM: &str = include_str!("../fixtures/steam.desktop");

    /// The whole generated entry for the smallest real vendor file, so
    /// what is copied and what is changed is one comparison.
    const KITTY_PATCHED: &str = "\
[Desktop Entry]
Version=1.0
Type=Application
Name=kitty (Bubbler)
GenericName=Terminal emulator
Comment=Fast, feature-rich, GPU based terminal
TryExec=/usr/bin/bubbler
StartupNotify=true
Exec=/usr/bin/bubbler open kt -- kitty
Icon=kitty
Categories=System;TerminalEmulator;
X-TerminalArgExec=--
X-TerminalArgTitle=--title
X-TerminalArgAppId=--class
X-TerminalArgDir=--working-directory
X-TerminalArgHold=--hold
DBusActivatable=false
X-Bubbler-Instance=kt
";

    fn patched(text: &str, instance: &str) -> String {
        patch(text, instance, Path::new("/usr/bin/bubbler")).unwrap()
    }

    fn dirs(root: &Path) -> Dirs {
        Dirs {
            user: root.join("user"),
            system: vec![root.join("system")],
        }
    }

    fn put(dir: &Path, name: &str, text: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    /// A file a `PATH` search would run, or, without an execute bit, one
    /// it would pass over.
    fn put_binary(dir: &Path, name: &str, mode: u32) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn config(command: &str) -> InstanceConfig {
        InstanceConfig {
            command: Some(vec![OsString::from(command)]),
            ..InstanceConfig::default()
        }
    }

    #[test]
    fn a_vendor_entry_is_copied_with_only_the_owned_keys_changed() {
        assert_eq!(patched(KITTY, "kt"), KITTY_PATCHED);
    }

    #[test]
    fn every_action_is_rewritten_and_every_localized_name_is_marked() {
        let out = patched(FIREFOX, "ff");
        for exec in [
            "Exec=/usr/bin/bubbler open ff -- /usr/lib/firefox/firefox %u",
            "Exec=/usr/bin/bubbler open ff -- /usr/lib/firefox/firefox --new-window %u",
            "Exec=/usr/bin/bubbler open ff -- /usr/lib/firefox/firefox --private-window %u",
            "Exec=/usr/bin/bubbler open ff -- /usr/lib/firefox/firefox --ProfileManager",
        ] {
            assert!(out.contains(exec), "{exec}\n{out}");
        }
        for name in ["Name=Firefox (Bubbler)", "Name[de]=Firefox (Bubbler)"] {
            assert!(out.contains(name), "{name}");
        }
        // An action's own name is the quicklist label under an entry that
        // is already marked; marking it again would only be noise.
        assert!(out.contains("\nName=New Window\n"), "{out}");
        assert!(out.contains("\nName[fr]=Nouvelle fenêtre\n"), "{out}");
        // Everything else survives, including the comment lines, the
        // group headers and the blank lines between the actions.
        assert!(out.starts_with("# Excerpt of Arch firefox"), "{out}");
        assert!(out.contains("\nMimeType=application/json;"), "{out}");
        assert!(
            out.contains("\n\n[Desktop Action new-private-window]\n"),
            "{out}"
        );
        assert_eq!(out.lines().count(), FIREFOX.lines().count() + 2);
        assert!(out.ends_with("gestionnaire de profils\n"), "{out}");
    }

    #[test]
    fn the_keys_that_bypass_the_sandbox_are_forced_even_where_they_are_absent() {
        // Neither key is in the source; both are written at the end of
        // the group it belongs to, ahead of the first action group.
        let out = patched(FIREFOX, "ff");
        let head = out.split("[Desktop Action").next().unwrap();
        assert!(head.contains("\nTryExec=/usr/bin/bubbler\n"), "{head}");
        assert!(head.contains("\nX-Bubbler-Instance=ff\n"), "{head}");
        assert_eq!(out.matches("DBusActivatable=false").count(), 1, "{out}");
        assert_eq!(owner(&out), Some("ff"));
        // The source's own `TryExec` is rewritten where it stands.
        let out = patched(KEEPASSXC, "kp");
        assert!(out.contains("\nTryExec=/usr/bin/bubbler\n"), "{out}");
        assert_eq!(out.matches("TryExec=").count(), 1, "{out}");
        assert!(out.contains("DBusActivatable=false"), "{out}");
    }

    #[test]
    fn every_one_of_a_nine_action_entry_s_command_lines_is_rewritten() {
        let out = patched(STEAM, "st");
        // Ten `Exec` lines, ten rewrites: a quicklist entry that was
        // missed would start Steam outside the sandbox from the menu.
        assert_eq!(out.matches("Exec=").count(), 11);
        assert_eq!(out.matches("open st -- ").count(), 10);
        assert!(
            out.contains("Exec=/usr/bin/bubbler open st -- /usr/bin/steam steam://store"),
            "{out}"
        );
        assert_eq!(out.matches("\n[Desktop Action ").count(), 9);
        assert!(out.contains("\nActions=Store;Community;"), "{out}");
        assert_eq!(out.matches("Name=Steam (Bubbler)").count(), 1, "{out}");
        assert!(out.contains("\nName=Store\n"), "{out}");
        // Keys nothing here understands ride through untouched.
        for kept in [
            "\nPrefersNonDefaultGPU=true\n",
            "\nX-KDE-RunOnDiscreteGpu=true\n",
        ] {
            assert!(out.contains(kept), "{kept}");
        }
        assert_eq!(out.lines().count(), STEAM.lines().count() + 3);
    }

    #[test]
    fn a_crlf_entry_keeps_its_line_endings_in_the_keys_that_are_added() {
        let source = "[Desktop Entry]\r\nType=Application\r\nName=A\r\nExec=a %u\r\n";
        let out = patched(source, "i");
        assert_eq!(
            out,
            "[Desktop Entry]\r\nType=Application\r\nName=A (Bubbler)\r\n\
             Exec=/usr/bin/bubbler open i -- a %u\r\nTryExec=/usr/bin/bubbler\r\n\
             DBusActivatable=false\r\nX-Bubbler-Instance=i\r\n"
        );
    }

    #[test]
    fn an_entry_a_launcher_is_told_to_ignore_is_refused() {
        // `Hidden=true` is "strictly equivalent to the .desktop file not
        // existing at all", so a copy of one would be an entry that is
        // there and does nothing.
        let source = "[Desktop Entry]\nType=Application\nName=A\nExec=a\nHidden=true\n";
        assert!(matches!(
            patch(source, "i", Path::new("/usr/bin/bubbler")),
            Err(DesktopError::Hidden)
        ));
        // Not displayed is a different thing: it is still a working entry,
        // and only the scan passes over it.
        let source = "[Desktop Entry]\nType=Application\nName=A\nExec=a\nNoDisplay=true\n";
        assert!(patch(source, "i", Path::new("/usr/bin/bubbler")).is_ok());
    }

    #[test]
    fn a_field_code_reaches_the_command_unchanged() {
        let out = patched(KEEPASSXC, "kp");
        assert!(
            out.contains("Exec=/usr/bin/bubbler open kp -- keepassxc %f"),
            "{out}"
        );
    }

    #[test]
    fn a_program_path_that_needs_quoting_is_quoted_once() {
        let out = patch(KITTY, "kt", Path::new("/opt/my apps/bubbler")).unwrap();
        assert!(
            out.contains("Exec=\"/opt/my apps/bubbler\" open kt -- kitty"),
            "{out}"
        );
        assert!(out.contains("TryExec=/opt/my apps/bubbler"), "{out}");
        // A percent in the path is a literal one, which an `Exec` value
        // writes `%%`; a single one would read as a field code. `TryExec`
        // takes no field codes and is written as it is.
        let out = patch(KITTY, "kt", Path::new("/opt/100%/bubbler")).unwrap();
        assert!(
            out.contains("Exec=/opt/100%%/bubbler open kt -- kitty"),
            "{out}"
        );
        assert!(out.contains("TryExec=/opt/100%/bubbler"), "{out}");
    }

    #[test]
    fn what_is_not_an_application_entry_is_refused() {
        let generated = patched(KITTY, "kt");
        assert!(matches!(
            patch(&generated, "kt", Path::new("/usr/bin/bubbler")),
            Err(DesktopError::Generated(i)) if i == "kt"
        ));
        assert!(matches!(
            patch(
                "[Desktop Entry]\nType=Link\nURL=https://a\n",
                "kt",
                Path::new("/b")
            ),
            Err(DesktopError::NoExec)
        ));
        assert!(matches!(
            patch("Exec=kitty\n", "kt", Path::new("/b")),
            Err(DesktopError::NoEntryGroup)
        ));
    }

    #[test]
    fn a_source_that_is_not_a_desktop_entry_at_all_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("binary.desktop");
        std::fs::write(&path, [0xff, 0xfe, b'\n']).unwrap();
        assert!(matches!(
            render(&path, "i", Path::new("/usr/bin/bubbler")),
            Err(DesktopError::NotUtf8(p)) if p == path
        ));
        let missing = tmp.path().join("gone.desktop");
        assert!(matches!(
            render(&missing, "i", Path::new("/usr/bin/bubbler")),
            Err(DesktopError::Io(p, _)) if p == missing
        ));
        let path = put(tmp.path(), "kitty.desktop", KITTY);
        assert_eq!(
            render(&path, "kt", Path::new("/usr/bin/bubbler")).unwrap(),
            KITTY_PATCHED
        );
    }

    #[test]
    fn a_generated_entry_passes_desktop_file_validate() {
        let tmp = tempfile::tempdir().unwrap();
        let mut checked = 0;
        for (name, text) in [
            ("bubbler-kt.desktop", KITTY),
            ("bubbler-ff.desktop", FIREFOX),
            ("bubbler-kp.desktop", KEEPASSXC),
            ("bubbler-st.desktop", STEAM),
        ] {
            let path = put(tmp.path(), name, &patched(text, "t"));
            let out = match Command::new("desktop-file-validate").arg(&path).output() {
                Ok(out) => out,
                // Not installed here; the generator's own tests are what
                // the goldens above are for.
                Err(_) => return,
            };
            let said = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(!said.contains("error:"), "{name}: {said}");
            checked += 1;
        }
        assert_eq!(checked, 4);
    }

    #[test]
    fn the_source_is_the_hint_then_the_command_name_then_the_one_entry_that_runs_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let system = tmp.path().join("system");
        put(&system, "kitty.desktop", KITTY);
        let by_name = system.join("kitty.desktop");
        assert_eq!(source(&dirs, "kt", &config("kitty")).unwrap(), by_name);
        // A command run from an absolute path is looked up by its
        // basename, the way the entry names it.
        assert_eq!(
            source(&dirs, "kt", &config("/usr/bin/kitty")).unwrap(),
            by_name
        );
        // No `kp.desktop`, one entry whose `Exec` runs `kp`.
        let scanned = put(
            &system,
            "org.example.Kp.desktop",
            "[Desktop Entry]\nExec=kp %f\n",
        );
        assert_eq!(source(&dirs, "i", &config("kp")).unwrap(), scanned);
        // The hint wins over both, and names a file, not a path.
        let cfg = InstanceConfig {
            desktop: Some("org.example.Kp.desktop".to_owned()),
            ..config("kitty")
        };
        assert_eq!(source(&dirs, "i", &cfg).unwrap(), scanned);
        let cfg = InstanceConfig {
            desktop: Some("nothere.desktop".to_owned()),
            ..config("kitty")
        };
        assert!(matches!(
            source(&dirs, "i", &cfg),
            Err(DesktopError::HintNotFound { name, .. }) if name == "nothere.desktop"
        ));
    }

    #[test]
    fn a_users_own_entry_shadows_the_systems_and_bubblers_own_is_no_source() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let (user, system) = (tmp.path().join("user"), tmp.path().join("system"));
        put(&system, "kitty.desktop", KITTY);
        let mine = put(
            &user,
            "kitty.desktop",
            "[Desktop Entry]\nExec=kitty --mine\n",
        );
        assert_eq!(source(&dirs, "kt", &config("kitty")).unwrap(), mine);
        // bubbler's own entry for the same file name is skipped, so the
        // vendor's is found again and `--replace` stays idempotent.
        put(&user, "kitty.desktop", &patched(KITTY, "kt"));
        assert_eq!(
            source(&dirs, "kt", &config("kitty")).unwrap(),
            system.join("kitty.desktop")
        );
    }

    #[test]
    fn two_entries_for_one_command_are_listed_rather_than_guessed_between() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let system = tmp.path().join("system");
        put(
            &system,
            "net.example.L.desktop",
            "[Desktop Entry]\nExec=l %U\n",
        );
        put(
            &system,
            "net.example.L1.desktop",
            "[Desktop Entry]\nExec=l --install %f\n",
        );
        let err = source(&dirs, "i", &config("l")).unwrap_err();
        let DesktopError::Ambiguous { candidates, .. } = &err else {
            panic!("{err}");
        };
        assert_eq!(
            candidates,
            &["net.example.L.desktop", "net.example.L1.desktop"]
        );
        assert!(err.to_string().contains("`desktop \"<name>.desktop\"`"));
        // The one a launcher does not show is not a candidate at all.
        put(
            &system,
            "net.example.L1.desktop",
            "[Desktop Entry]\nExec=l --install %f\nNoDisplay=true\n",
        );
        assert_eq!(
            source(&dirs, "i", &config("l")).unwrap(),
            system.join("net.example.L.desktop")
        );
        // And nothing that runs it at all is its own answer.
        assert!(matches!(
            source(&dirs, "i", &config("nothing")),
            Err(DesktopError::NotFound { .. })
        ));
        assert!(matches!(
            source(&dirs, "i", &InstanceConfig::default()),
            Err(DesktopError::NoCommand(i)) if i == "i"
        ));
    }

    #[test]
    fn only_bubblers_own_entry_for_this_instance_is_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let path = target(
            &dirs,
            "kt",
            Path::new("/usr/share/applications/kitty.desktop"),
            false,
        );
        assert_eq!(path, dirs.user.join("bubbler-kt.desktop"));
        assert_eq!(
            target(
                &dirs,
                "kt",
                Path::new("/usr/share/applications/kitty.desktop"),
                true
            ),
            dirs.user.join("kitty.desktop")
        );
        // A directory nothing has created yet is created here.
        write(&path, &patched(KITTY, "kt"), "kt").unwrap();
        assert_eq!(owner(&std::fs::read_to_string(&path).unwrap()), Some("kt"));
        // Ours for this instance: a plain overwrite.
        write(&path, &patched(KEEPASSXC, "kt"), "kt").unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("KeePassXC")
        );
        // Ours for another instance, and a file that is not ours at all.
        assert!(matches!(
            write(&path, "x", "other"),
            Err(DesktopError::OtherInstance { instance, .. }) if instance == "kt"
        ));
        let foreign = put(&dirs.user, "kitty.desktop", KITTY);
        assert!(matches!(
            write(&foreign, "x", "kt"),
            Err(DesktopError::Foreign(p)) if p == foreign
        ));
        assert_eq!(std::fs::read_to_string(&foreign).unwrap(), KITTY);
        // A symlink is never bubbler's, whatever it points at.
        let link = dirs.user.join("bubbler-link.desktop");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            write(&link, "x", "kt"),
            Err(DesktopError::Foreign(_))
        ));
    }

    #[test]
    fn a_symlink_planted_where_the_entry_is_built_is_never_written_through() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        std::fs::create_dir_all(&dirs.user).unwrap();
        let path = dirs.user.join("bubbler-kt.desktop");
        // The sibling `fsutil::write_atomic` builds in, aimed at a file
        // of the user's: it is created with `O_EXCL`, so the write fails
        // rather than following it.
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"mine\n").unwrap();
        let sibling = dirs
            .user
            .join(format!(".bubbler-kt.desktop.{}.new", std::process::id()));
        std::os::unix::fs::symlink(&victim, &sibling).unwrap();
        assert!(matches!(
            write(&path, &patched(KITTY, "kt"), "kt"),
            Err(DesktopError::Io(at, _)) if at == sibling
        ));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "mine\n");
        assert!(!path.exists());
        // The failed attempt takes the name it could not use with it, so
        // the next one writes the entry, and as a regular file.
        assert!(std::fs::symlink_metadata(&sibling).is_err());
        write(&path, &patched(KITTY, "kt"), "kt").unwrap();
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_file()
        );
    }

    #[test]
    fn remove_deletes_this_instances_entries_and_leaves_every_other_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = dirs(tmp.path());
        let mine = put(&dirs.user, "bubbler-kt.desktop", &patched(KITTY, "kt"));
        let shadow = put(&dirs.user, "kitty.desktop", &patched(KITTY, "kt"));
        let theirs = put(&dirs.user, "bubbler-ff.desktop", &patched(FIREFOX, "ff"));
        let foreign = put(&dirs.user, "other.desktop", KITTY);
        assert_eq!(
            generated(&dirs),
            vec![
                (theirs.clone(), "ff".to_owned()),
                (mine.clone(), "kt".to_owned()),
                (shadow.clone(), "kt".to_owned()),
            ]
        );
        let mut removed = remove(&dirs, "kt").unwrap();
        removed.sort();
        assert_eq!(removed, vec![mine, shadow]);
        assert!(theirs.is_file() && foreign.is_file());
        assert!(matches!(
            remove(&dirs, "kt"),
            Err(DesktopError::NotGenerated { instance, .. }) if instance == "kt"
        ));
    }

    #[test]
    fn the_entry_names_bubbler_bare_only_where_path_resolves_to_this_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let (bin, other) = (tmp.path().join("bin"), tmp.path().join("other"));
        std::fs::create_dir_all(&other).unwrap();
        let exe = put_binary(&bin, BINARY, 0o755);
        let path = [other.clone(), bin.clone()];
        // Nothing of that name earlier on PATH, so the search reaches
        // this one and the bare name is what a launcher resolves.
        assert_eq!(program(&exe, &path), PathBuf::from(BINARY));
        // A different bubbler earlier on PATH is the one the bare name
        // would start, so this entry has to name its own binary.
        let theirs = put_binary(&other, BINARY, 0o755);
        assert_eq!(program(&exe, &path), exe);
        // One without an execute bit is not what the search finds, so
        // the bare name reaches this binary again.
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(program(&exe, &path), PathBuf::from(BINARY));
        assert_eq!(program(&exe, &[]), exe);
        // A symlink on PATH to this binary is this binary.
        let link = other.join("link");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        assert_eq!(
            program(&link, std::slice::from_ref(&bin)),
            PathBuf::from(BINARY)
        );
    }
}
