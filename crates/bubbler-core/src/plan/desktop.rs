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
use std::path::{Path, PathBuf};

use crate::config::InstanceConfig;
use crate::env::Env;
use crate::error::DesktopError;

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
    /// `$XDG_DATA_DIRS` entry, which is exactly where a launcher looks.
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

// The `[Desktop Entry]` keys a lookup decides on, read without parsing
// the rest of the file.
pub(crate) struct Head<'a> {
    pub(crate) exec: Option<&'a str>,
    pub(crate) marker: Option<&'a str>,
    // `NoDisplay=true`: an entry a launcher does not show, which is what
    // an application's MIME-handler-only entries are.
    pub(crate) no_display: bool,
    // `Hidden=true`, which the specification calls "strictly equivalent
    // to the .desktop file not existing at all".
    pub(crate) hidden: bool,
}

// Read the `[Desktop Entry]` group of `text`, ignoring every other
// group: only the main group decides what an entry is and what it runs.
pub(crate) fn head(text: &str) -> Head<'_> {
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

fn group_lines<'a>(text: &'a str, group: &'a str) -> impl Iterator<Item = &'a str> {
    text.lines()
        .skip_while(move |l| header(l) != Some(group))
        .skip(1)
        .take_while(|l| header(l).is_none())
}

fn header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

// `key=value` split with the space the specification allows around the
// `=` removed. Comments and blank lines have no `=` and fall out here.
fn split_key(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim_end(), value.trim_start()))
}

fn base_key(key: &str) -> &str {
    key.split('[').next().unwrap_or(key)
}

/// The instance an entry was generated for, if bubbler generated it.
pub fn owner(text: &str) -> Option<&str> {
    head(text).marker
}

// Only the first argument is read, which is the one a launcher has to
// find on `PATH` before it will show the entry at all.
pub(crate) fn exec_program(value: &str) -> Option<String> {
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

// `value` as one argument of an `Exec` value: quoted only where it holds
// a character the specification reserves, since a quoted argument is
// also where a field code would stop expanding.
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

// The command basename an entry is looked up by: the first word of the
// instance's `command`, without its directory.
pub(crate) fn command_name(config: &InstanceConfig) -> Option<&OsStr> {
    Path::new(config.command.as_ref()?.first()?).file_name()
}

// Which of the keys bubbler owns the source's `[Desktop Entry]` group
// already carries, and therefore which are rewritten rather than added.
#[derive(Default)]
struct Present {
    try_exec: bool,
    dbus_activatable: bool,
}

/// The generated entry's text: `text` with `Name`, `Exec`, `TryExec`,
/// `DBusActivatable` and the marker key changed and nothing else touched.
///
/// `program` is what the entry calls to reach bubbler.
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
                push_added(&mut out, &present, instance, program, eol);
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
        push_added(&mut out, &present, instance, program, eol);
    }
    let mut text = out.join("\n");
    if trailing {
        text.push('\n');
    }
    Ok(text)
}

// Put the keys bubbler adds at the end of the `[Desktop Entry]` group's
// own lines, before the blank lines the vendor left between it and what
// follows: a key written after that separator reads as the next group's.
fn push_added(out: &mut Vec<String>, present: &Present, instance: &str, program: &str, eol: &str) {
    let at = out
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(0, |i| i + 1);
    out.splice(at..at, added(present, instance, program, eol));
}

// `DBusActivatable=true` is set to `false` rather than dropped, and
// added where it was absent, because a launcher that understands the key
// ignores `Exec` entirely and asks the session bus to start the
// application — outside the sandbox, with nothing printed anywhere.
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const KITTY: &str = include_str!("../../fixtures/kitty.desktop");
    pub(crate) const FIREFOX: &str = include_str!("../../fixtures/firefox.desktop");
    pub(crate) const KEEPASSXC: &str =
        include_str!("../../fixtures/org.keepassxc.KeePassXC.desktop");
    pub(crate) const STEAM: &str = include_str!("../../fixtures/steam.desktop");

    /// The whole generated entry for the smallest real vendor file, so
    /// what is copied and what is changed is one comparison.
    pub(crate) const KITTY_PATCHED: &str = "\
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

    pub(crate) fn patched(text: &str, instance: &str) -> String {
        patch(text, instance, Path::new("/usr/bin/bubbler")).unwrap()
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
    fn the_keys_bubbler_adds_land_inside_the_group_and_not_after_it() {
        // A blank line separates one group from the next, so a key put
        // after it reads as the next group's — and a key of the entry
        // group written under `[Desktop Action new]` is not the entry's.
        let source = "[Desktop Entry]\nType=Application\nName=A\nExec=a\n\n\
                      [Desktop Action new]\nName=New\nExec=a --new\n";
        let out = patch(source, "i", Path::new("/usr/bin/bubbler")).unwrap();
        assert_eq!(
            out,
            "[Desktop Entry]\nType=Application\nName=A (Bubbler)\n\
             Exec=/usr/bin/bubbler open i -- a\nTryExec=/usr/bin/bubbler\n\
             DBusActivatable=false\nX-Bubbler-Instance=i\n\n\
             [Desktop Action new]\nName=New\nExec=/usr/bin/bubbler open i -- a --new\n"
        );
        // At the end of the file the blank lines separate the group from
        // nothing, and they stay where the vendor left them all the same.
        let source = "[Desktop Entry]\nType=Application\nName=A\nExec=a\n\n\n";
        let out = patch(source, "i", Path::new("/usr/bin/bubbler")).unwrap();
        assert!(out.ends_with("X-Bubbler-Instance=i\n\n\n"), "{out:?}");
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
}
