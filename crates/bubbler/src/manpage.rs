//! The two pages `bubbler man` prints: `bubbler(1)`, rendered from the
//! clap command tree, and `bubbler-config(5)`, rendered from the grant
//! catalogue and the lint table. Both are generated from what the binary
//! actually takes, so a page cannot promise a flag or a node that is not
//! there.

use std::ffi::OsString;

use bubbler_core::catalogue::GRANTS;
use bubbler_core::lint::CHECKS;
use clap::Command;
use clap_mangen::Man;
use clap_mangen::roff::{Roff, bold, roman};

/// The `.TH` manual name both pages carry.
const MANUAL: &str = "bubbler manual";

/// The `.TH` line, written here rather than through `roff`, which drops
/// an empty argument instead of quoting it: an empty date has to keep
/// its place or the source and the manual are read as the two fields
/// before them.
///
/// The date is left empty on purpose. A page generated at package time
/// carries whatever day that was, so a date would be the one field that
/// differs between two builds of the same source; man(1) simply prints
/// nothing in its place.
fn title(name: &str, section: &str, version: &str) -> String {
    format!(".TH {name} {section} \"\" \"{version}\" \"{MANUAL}\"")
}

/// The two lines `roff` writes above every render to define an
/// apostrophe that survives every roff implementation. A page carries
/// them once, and each section is rendered separately here, so they are
/// dropped from the sections and written at the top by hand.
const PREAMBLE: [&str; 2] = [r".ie \n(.g .ds Aq \(aq", r".el .ds Aq '"];

/// Paths a run reads or writes, as the `FILES` section lists them.
const FILES: &[(&str, &str)] = &[
    (
        "$XDG_DATA_HOME/bubbler/instances/<name>/config.kdl",
        "What the instance grants. bubbler-config(5) is the page for it.",
    ),
    (
        "$XDG_DATA_HOME/bubbler/instances/<name>/config.kdl.bak",
        "That config as it stood before whatever last replaced it: a `reseed`, or a save \
         from `bubbler ui`. Written beside the fresh one, over the backup an earlier \
         replacement left.",
    ),
    (
        "$XDG_DATA_HOME/bubbler/instances/<name>/home/",
        "The instance's private home, bound over /home/bubbler inside the sandbox.",
    ),
    (
        "$XDG_DATA_HOME/bubbler/instances/<name>/last-run.log",
        "What the last run with no terminal wrote to stderr: bubbler's warnings, its \
         sidecars' and the application's. Mode 0600, never over a mebibyte, and printed by \
         `bubbler log`.",
    ),
    (
        "$XDG_DATA_HOME/applications/",
        "Where `bubbler desktop` writes launcher entries, as bubbler-<name>.desktop or, with \
         --replace, under the application's own file name.",
    ),
    (
        "$XDG_DATA_HOME/bubbler/try/<pid>/",
        "A throwaway sandbox. Removed when the command exits, and swept by pid on the next try.",
    ),
    (
        "$XDG_CONFIG_HOME/bubbler/profiles/<name>.kdl",
        "Your profile layer, which overrides the two below it.",
    ),
    (
        "$XDG_CONFIG_HOME/bubbler/wraps.kdl",
        "The shim registry `wrap` writes: which instance each name in the shim directory \
         opens.",
    ),
    (
        "~/.local/bin/<name>",
        "A shim: a symlink to the bubbler binary that opens the instance the registry maps \
         that name to.",
    ),
    (
        "/usr/share/bubbler/profiles/<name>.kdl",
        "The system profile layer, or wherever $BUBBLER_PROFILE_DIR points. bubbler ships \
         nothing here: the profile library is compiled into the binary, and this directory \
         is the administrator's.",
    ),
    (
        "$XDG_RUNTIME_DIR/bubbler/<name>/",
        "Runtime state of a running instance, mode 0700: the supervisor's init.sock, and the \
         D-Bus proxy's sockets where a bus is granted. Every socket in it goes when the run \
         ends; the directory itself is left for the next run to reuse.",
    ),
    (
        "$XDG_RUNTIME_DIR/.flatpak/bubbler-<name>/",
        "Where a `portals` grant writes the bwrapinfo.json the portal daemon reads to \
         identify the sandbox; `.flatpak/` is created if the session has none.",
    ),
    (
        "/usr/lib/bubbler/bubbler-init",
        "The supervisor that runs as pid 2 in every sandbox, bound in at /run/bubbler-init.",
    ),
];

/// Variables bubbler reads, as the `ENVIRONMENT` section lists them.
const ENVIRONMENT: &[(&str, &str)] = &[
    (
        "HOME, XDG_RUNTIME_DIR",
        "Must be set and non-empty; bubbler refuses to run otherwise.",
    ),
    (
        "XDG_DATA_HOME, XDG_CONFIG_HOME",
        "Where instances and your profile layer live; the XDG defaults apply. \
         XDG_DATA_HOME also holds the applications directory `desktop` writes entries to.",
    ),
    (
        "XDG_DATA_DIRS",
        "Where `desktop` looks for the application's own entry, under XDG_DATA_HOME's copy \
         of the same name; /usr/local/share:/usr/share when it is unset. A relative entry \
         is ignored, as the XDG base directory specification asks.",
    ),
    (
        "WAYLAND_DISPLAY, DISPLAY, XAUTHORITY",
        "Which session sockets the `wayland` and `x11 \"host\"` grants bind; a bare `x11` \
         reads neither DISPLAY nor XAUTHORITY, the server being its own. These are \
         untrusted input: WAYLAND_DISPLAY must be a single path component under \
         XDG_RUNTIME_DIR and must be a socket, DISPLAY must be a local display like `:0`, \
         and XAUTHORITY must be a regular file, $HOME/.Xauthority being the default. The \
         file type is probed, never mere existence, so a variable naming a directory is \
         refused rather than bound.",
    ),
    (
        "DBUS_SESSION_BUS_ADDRESS, DBUS_SYSTEM_BUS_ADDRESS",
        "The buses the proxy connects to, defaulting to $XDG_RUNTIME_DIR/bus and \
         /run/dbus/system_bus_socket. Both must resolve to a socket, and an address \
         bubbler cannot bind (`tcp:`, `unix:abstract=`) fails the run naming the variable \
         rather than falling back to a bus the session is not on. An address that \
         resolves under $XDG_RUNTIME_DIR/bubbler/ is refused as well: that directory \
         holds an instance's control socket and the socket the proxy itself serves, and \
         neither is a host bus.",
    ),
    (
        "AT_SPI_BUS_ADDRESS",
        "Where the accessibility bus the `a11y` grant proxies is, read before anything is \
         asked of the session: when it is unset, bubbler asks org.a11y.Bus for the address \
         with dbus-send, from the `dbus` package. It is untrusted like the D-Bus \
         addresses, must be a `unix:path=` address, and a bus that cannot be found fails \
         the run rather than dropping the grant.",
    ),
    (
        "TERM, LANG, LANGUAGE, COLORTERM, TZ, LC_*",
        "The only variables of yours a sandbox is given: the environment inside is cleared, \
         and everything else in yours stops at the boundary.",
    ),
    (
        "PATH",
        "Where the `command-not-found` check looks for a profile's command. Unset or empty \
         searches nothing rather than the working directory.",
    ),
    (
        "VISUAL, EDITOR",
        "What `edit` and `profile edit` run, split into an argv without a shell, so quotes \
         and $VAR in them are not expanded. VISUAL wins.",
    ),
    (
        "BUBBLER_INIT, BUBBLER_DBUS_PROXY, BUBBLER_PASTA",
        "Replace the bubbler-init, xdg-dbus-proxy and pasta binaries a run uses; each must \
         name a regular file. For tests and debugging.",
    ),
    (
        "BUBBLER_PROFILE_DIR",
        "Replaces /usr/share/bubbler/profiles as the system profile layer.",
    ),
    (
        "BUBBLER_DBUS_LOG, BUBBLER_SECCOMP_LOG",
        "=1 runs the D-Bus proxy with --log, and compiles the seccomp filter to log what it \
         would have denied instead of denying it. Both are debugging aids and both weaken \
         nothing on their own.",
    ),
    (
        "BUBBLER_TEST_ALLOW_PATH",
        "One extra absolute root `path-share` accepts, for the test suite.",
    ),
];

/// The pages and programs a reader goes to next.
const SEE_ALSO: &str = "bubbler-config(5), bwrap(1), xdg-dbus-proxy(1), pasta(1)";

/// What `config.kdl` is, before the node-by-node list.
const CONFIG_DESCRIPTION: &[&str] = &[
    "An instance's config.kdl, and the profile it was seeded from, are the same KDL. \
     Every node in it is a grant: a sandbox starts with nothing but the baseline \
     (a private home, no network, no display, a fresh /proc, /dev, /tmp and /run, \
     a seccomp filter) and each node widens it by exactly one resource.",
    "A node bubbler does not know, a property it does not take on a node it does, \
     or a type annotation anywhere is an error, not a node that is ignored: a grant \
     that was silently dropped is a sandbox that does not do what its file says. \
     The same file read by an older bubbler is why `// bubbler config: <n>` is \
     written at the top.",
    "A profile may `include` another, and the layers — yours, the system's, the \
     built-in library — are flattened before any of this is read. `bubbler profile \
     show <name>` prints the result with every node under the layer it came from.",
    "`bubbler lint` measures a file against the checks under LINT CHECKS below; a \
     warning or a note is accepted with `lint-allow \"<id>\" reason=\"...\"`, and an \
     id no check has is a parse error.",
];

/// One line per lint check, keyed by its id. Kept beside the page rather
/// than in the table itself: `lint::Check` is what the linter matches on,
/// and a test here holds the two lists together.
const CHECK_LINES: &[(&str, &str)] = &[
    (
        "app-runtime-rw",
        "An `app-runtime` shared mode=rw, so the sandbox can replace the sockets every \
         other instance naming that id connects to.",
    ),
    (
        "bundle-without-dbus",
        "A `portals`, `notify`, `tray`, `mpris`, `a11y` or `input-method` grant that no \
         layer gives a `dbus` to carry its rules.",
    ),
    (
        "camera-nodes-none-present",
        "`camera nodes=#true` on a host with no /dev/video* or /dev/media* node, so that \
         half of the grant binds nothing.",
    ),
    (
        "camera-nodes-no-hotplug",
        "`camera nodes=#true` binds the nodes the host has at launch: a camera plugged in \
         later has no node inside.",
    ),
    (
        "camera-without-portals",
        "A `camera` grant no layer gives a `portals` to carry, so the sandbox has no \
         /.flatpak-info and the portal reads it as an ordinary process of yours.",
    ),
    (
        "command-not-found",
        "The `command` node names a program that is not on this host's PATH.",
    ),
    (
        "desktop-entry-missing",
        "The `desktop` node names an entry no application directory on this host holds, so \
         `bubbler desktop` has nothing to copy.",
    ),
    (
        "dbus-without-rules",
        "`dbus` names nothing and no layer adds a bundle, so the proxy it starts answers \
         nothing.",
    ),
    (
        "dup-name-policy",
        "One bus name given two policies by two layers; one name takes one policy.",
    ),
    (
        "env-looks-secret",
        "An `env` name or value that looks like a credential, in a file people share.",
    ),
    (
        "home-share-sensitive",
        "A `home-share` of a directory holding your keys, sessions or another \
         application's configuration.",
    ),
    (
        "lint-allow-unused",
        "A `lint-allow` node that accepts nothing: a suppression outliving what it was \
         written for.",
    ),
    (
        "mpris-wildcard",
        "`mpris name=\"*\"` owns every media player name on the bus.",
    ),
    (
        "network-host",
        "`network \"host\"`, the one mode that puts the sandbox on the host's network \
         stack, loopback services and abstract sockets included.",
    ),
    (
        "outbound-deny",
        "`outbound \"deny\"` filters the sandbox's own network namespace by address: a \
         name that resolves to an address no `allow-out` covers is refused.",
    ),
    (
        "own-on-system-bus",
        "An `own` rule on the system bus, where the bus sees the proxy's credentials, so \
         the name would be owned as you.",
    ),
    (
        "own-too-wide",
        "An `own` ending in `*` with fewer than three name elements before it, which \
         claims every well-known name under that prefix.",
    ),
    (
        "ozone-hint-unnecessary",
        "`env ELECTRON_OZONE_PLATFORM_HINT`, measured to change nothing: an Electron app \
         picks Wayland up from the socket alone.",
    ),
    (
        "path-share-mountpoint",
        "A `path-share mode=rw` of a whole mounted filesystem.",
    ),
    (
        "path-share-reserved",
        "A `path-share` of a root bubbler never shares; the launcher refuses it.",
    ),
    (
        "path-share-socket",
        "A `path-share` of a socket, of a path named like one (`.sock`, `.socket`) \
         whatever it turns out to be, or of a directory holding one: a shared control \
         socket is command execution across the boundary.",
    ),
    (
        "portal-talk-without-portals",
        "A portal name in the bus rules without `portals`, so the call is refused rather \
         than answered.",
    ),
    (
        "seccomp-disabled",
        "`seccomp { disable }` leaves the sandbox with no syscall filter at all.",
    ),
    (
        "secrets-access",
        "A `talk` or `own` of org.freedesktop.secrets: the whole login keyring, which the \
         Secret Service API partitions between no applications.",
    ),
    (
        "share-source-missing",
        "A share whose source this host does not have, or has as something other than a \
         directory or a regular file; the launcher refuses the run rather than skipping \
         the bind.",
    ),
    (
        "system-bus-polkit-name",
        "A `talk` on a system service whose privileged actions polkit judges as you.",
    ),
    (
        "tty-passthrough",
        "`tty \"passthrough\"` hands the sandbox this terminal's own descriptors.",
    ),
    (
        "userns-disabled-with-nested-sandbox",
        "`userns \"disable\"` under a command known to start a sandbox of its own; the \
         list of such commands is a heuristic.",
    ),
    (
        "wayland-host",
        "`wayland \"host\"` binds the session's own socket, so the compositor cannot tell \
         the sandbox from your session and its privileged globals stay reachable.",
    ),
    (
        "x11-nested-no-wm",
        "A nested `x11` server with neither `fullscreen=#true` nor `wm=`, which has no \
         window manager: the X windows inside are undecorated and unmanaged in the one \
         compositor window the server draws.",
    ),
    (
        "x11-without-reason",
        "An `x11 \"host\"` grant with no `lint-allow` reason: the session's X clients are \
         not isolated from one another.",
    ),
];

/// One line of `id`'s check, or the id itself when the tables have
/// drifted; a page is not the place to fail a run over its own prose,
/// and the unit test below is what keeps the two lists together.
fn check_line(id: &str) -> &str {
    CHECK_LINES
        .iter()
        .find(|(check, _)| *check == id)
        .map_or(id, |(_, line)| *line)
}

/// The one non-ASCII character bubbler's prose uses, written as the
/// escape every roff understands: a page rendered by `nroff` without
/// `preconv` in front of it reads a UTF-8 em dash as three bytes of
/// noise, and a man page is not always read through man(1).
fn roff_ascii(line: String) -> String {
    line.replace('\u{2014}', r"\(em")
}

/// A rendered chunk as lines, without the preamble [`PREAMBLE`] repeats
/// at the top of every render.
fn body(chunk: &str) -> impl Iterator<Item = &str> {
    chunk.lines().filter(|l| !PREAMBLE.contains(l))
}

/// A rendered chunk as lines, without its `.SH` headings: the sections
/// of a subcommand sit under one `.SS` of their own here, and a second
/// level of headings inside it would read as a page of its own. Only a
/// control line can start with `.SH ` — `roff` writes `\&` in front of a
/// text line that would.
fn headless(chunk: &str) -> impl Iterator<Item = &str> {
    body(chunk).filter(|l| !l.starts_with(".SH "))
}

/// Render one section through `f` and return it as roff lines.
fn section(f: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
    let mut buf = Vec::new();
    f(&mut buf).expect("writing roff into a Vec cannot fail");
    String::from_utf8(buf).expect("clap help text and roff output are UTF-8")
}

/// Every subcommand under `cmd`, depth first and in declaration order,
/// each paired with the full command line it is invoked as. Hidden ones
/// are left out, as they are left out of `--help`.
fn subcommands(cmd: &Command, path: &str) -> Vec<(String, Command)> {
    let mut out = Vec::new();
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        let full = format!("{path} {}", sub.get_name());
        out.push((
            full.clone(),
            sub.clone()
                .bin_name(full.clone())
                .display_name(full.clone()),
        ));
        out.extend(subcommands(sub, &full));
    }
    out
}

/// `bubbler(1)`: the top page, a subsection for every subcommand with
/// its own synopsis and options, and the sections clap knows nothing
/// about. One page rather than the one per subcommand
/// `clap_mangen::generate_to` writes, since `man bubbler` is where a
/// reader looks and a cross-reference to a page nobody installed is
/// worse than no heading at all.
pub fn page(cmd: Command, version: &str) -> Vec<OsString> {
    // As `clap_mangen` does: `bubbler help <cmd>` prints what `--help`
    // prints and is not a command to document beside the real ones.
    let mut cmd = cmd.disable_help_subcommand(true);
    cmd.build();
    // Only the section renderers below are used, so the title, section
    // and manual `Man` would carry are never rendered from it.
    let man = Man::new(cmd.clone());
    let mut lines: Vec<String> = PREAMBLE.iter().map(|l| (*l).to_owned()).collect();
    lines.push(title("BUBBLER", "1", version));
    for chunk in [
        section(|w| man.render_name_section(w)),
        section(|w| man.render_synopsis_section(w)),
        section(|w| man.render_description_section(w)),
        section(|w| man.render_options_section(w)),
    ] {
        lines.extend(body(&chunk).map(str::to_owned));
    }
    lines.push(".SH COMMANDS".to_owned());
    for (path, sub) in subcommands(&cmd, cmd.get_name()) {
        let man = Man::new(sub);
        lines.push(format!(".SS {path}"));
        lines.extend(headless(&section(|w| man.render_synopsis_section(w))).map(str::to_owned));
        // Without it the synopsis and the first line of the description
        // are filled into one paragraph.
        lines.push(".PP".to_owned());
        for chunk in [
            section(|w| man.render_description_section(w)),
            section(|w| man.render_options_section(w)),
        ] {
            lines.extend(headless(&chunk).map(str::to_owned));
        }
    }
    let mut extra = Roff::default();
    extra.control("SH", ["FILES"]);
    for (path, what) in FILES {
        extra.control("TP", []);
        extra.text([bold(*path)]);
        extra.text([roman(*what)]);
    }
    extra.control("SH", ["ENVIRONMENT"]);
    for (name, what) in ENVIRONMENT {
        extra.control("TP", []);
        extra.text([bold(*name)]);
        extra.text([roman(*what)]);
    }
    extra.control("SH", ["SEE ALSO"]);
    extra.text([roman(SEE_ALSO)]);
    lines.extend(body(&section(|w| extra.to_writer(w))).map(str::to_owned));
    lines.extend(body(&section(|w| man.render_version_section(w))).map(str::to_owned));
    lines
        .into_iter()
        .map(roff_ascii)
        .map(OsString::from)
        .collect()
}

/// `bubbler-config(5)`: every node a config may hold, written from the
/// same catalogue the rest of bubbler explains grants from, and every
/// lint check by id, so the page and the binary cannot disagree about
/// what a config takes.
pub fn config_page(version: &str) -> Vec<OsString> {
    let mut roff = Roff::default();
    roff.control("SH", ["NAME"]);
    roff.text([roman(
        "bubbler-config - the KDL a bubbler instance or profile is written in",
    )]);
    roff.control("SH", ["DESCRIPTION"]);
    for (i, para) in CONFIG_DESCRIPTION.iter().enumerate() {
        if i > 0 {
            roff.control("PP", []);
        }
        roff.text([roman(*para)]);
    }
    roff.control("SH", ["GRANTS"]);
    roff.text([roman(
        "Each node below is one grant. `Risk` is the widest thing the node can be written \
         to mean, not what one config asks for.",
    )]);
    for grant in GRANTS {
        roff.control("SS", [grant.node]);
        // Unfilled: a grammar line is syntax, and justification would put
        // spaces inside it wherever the line needed stretching.
        roff.control("EX", []);
        roff.text([roman(grant.grammar)]);
        roff.control("EE", []);
        roff.control("PP", []);
        roff.text([roman(grant.summary)]);
        roff.control("PP", []);
        roff.text([roman(grant.cost)]);
        roff.control("PP", []);
        roff.text([roman(format!("Risk: {}.", grant.risk))]);
    }
    roff.control("SH", ["LINT CHECKS"]);
    roff.text([roman(
        "What `bubbler lint` and `bubbler profile lint` report. An error says the file will \
         not do what it says and is never suppressible; a warning says it grants more than \
         it probably means to; a note is information and fails nothing.",
    )]);
    for check in CHECKS {
        roff.control("TP", []);
        roff.text([bold(check.id), roman(format!(" ({})", check.severity))]);
        roff.text([roman(check_line(check.id))]);
    }
    roff.control("SH", ["SEE ALSO"]);
    roff.text([roman("bubbler(1)")]);
    let rendered = section(|w| roff.to_writer(w));
    let mut lines: Vec<String> = PREAMBLE.iter().map(|l| (*l).to_owned()).collect();
    lines.push(title("BUBBLER-CONFIG", "5", version));
    lines.extend(body(&rendered).map(str::to_owned));
    lines
        .into_iter()
        .map(roff_ascii)
        .map(OsString::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A check with no line of its own would print its bare id, which is
    /// the drift this catches: the page documents the table, and the
    /// table is what the linter reports from.
    #[test]
    fn every_lint_check_has_a_line_and_no_line_is_orphaned() {
        for check in CHECKS {
            assert_ne!(check_line(check.id), check.id, "no line for {}", check.id);
        }
        for (id, _) in CHECK_LINES {
            assert!(
                CHECKS.iter().any(|c| c.id == *id),
                "{id} is no check the linter runs"
            );
        }
    }

    /// Every name the environment section has to carry, read off the
    /// source that reads them rather than off a list kept beside it:
    /// `var_os("X")` in `host_env.rs`, every `BUBBLER_*` the same file
    /// names in a message, and the passthrough set core exports.
    fn variables_read() -> Vec<String> {
        let source = include_str!("host_env.rs");
        let by_name = source
            .split("var_os(\"")
            .skip(1)
            .filter_map(|r| r.split('"').next());
        let bubbler = source.split("BUBBLER_").skip(1).map(|r| {
            let tail: String = r
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                .collect();
            format!("BUBBLER_{tail}")
        });
        let mut names: Vec<String> = by_name
            .map(str::to_owned)
            .chain(bubbler)
            .chain(
                bubbler_core::env::PASSTHROUGH_VARS
                    .iter()
                    .map(|v| (*v).to_string()),
            )
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// The backup is written from two places, and a reader who finds one
    /// of them there has no reason to look for the other: the page is
    /// where both are named.
    #[test]
    fn the_backup_file_names_everything_that_writes_it() {
        let (_, what) = FILES
            .iter()
            .find(|(path, _)| path.ends_with("config.kdl.bak"))
            .expect("the backup has a FILES entry");
        assert!(what.contains("reseed"), "{what}");
        assert!(what.contains("bubbler ui"), "{what}");
    }

    /// The page promises what bubbler reads from the environment, and
    /// what it reads is in one file, so the two can be held together
    /// rather than trusted to stay together.
    #[test]
    fn the_environment_section_names_every_variable_the_binary_reads() {
        let names = variables_read();
        // A scan that matched nothing would pass every assertion below.
        assert!(names.len() > 15, "the scan found only {names:?}");
        let cmd = <crate::Cli as clap::CommandFactory>::command();
        let page = page(cmd, "bubbler 0.0.0").join(&OsString::from("\n"));
        // The font escapes are glued to the word they open, so they are
        // taken off before the page is cut into words.
        let page = page
            .to_string_lossy()
            .replace(r"\fB", " ")
            .replace(r"\fI", " ")
            .replace(r"\fR", " ");
        let words: std::collections::HashSet<&str> = page
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .collect();
        for name in &names {
            assert!(
                words.contains(name.as_str()),
                "the page never names ${name}"
            );
        }
    }

    /// A page is bytes a roff has to read the same way everywhere, and
    /// the prose it is built from is not written under that constraint.
    #[test]
    fn neither_page_carries_a_byte_roff_has_to_guess_at() {
        let cmd = <crate::Cli as clap::CommandFactory>::command();
        for page in [page(cmd, "bubbler 0.0.0"), config_page("bubbler 0.0.0")] {
            for line in page {
                let line = line.to_string_lossy().into_owned();
                assert!(line.is_ascii(), "not ASCII: {line}");
            }
        }
    }

    /// The apostrophe preamble is dropped by matching two exact lines, so
    /// a `roff` that changes them must be noticed here rather than in a
    /// page with forty copies of them in it.
    #[test]
    fn the_preamble_is_written_once() {
        let cmd = <crate::Cli as clap::CommandFactory>::command();
        for page in [page(cmd, "bubbler 0.0.0"), config_page("bubbler 0.0.0")] {
            let count = page
                .iter()
                .filter(|l| PREAMBLE.contains(&&*l.to_string_lossy()))
                .count();
            assert_eq!(count, PREAMBLE.len(), "the preamble is not what it was");
        }
    }
}
