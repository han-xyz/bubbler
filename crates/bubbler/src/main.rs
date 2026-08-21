//! bubbler command line: create, run, edit, delete and list sandbox instances.

mod host_env;
mod manpage;

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bubbler_core::config::{self, Service};
use bubbler_core::desktop;
use bubbler_core::env::Env;
use bubbler_core::error::{ConfigError, LaunchError};
use bubbler_core::exec;
use bubbler_core::explain;
use bubbler_core::host::RealHost;
use bubbler_core::instance::{self, Instance};
use bubbler_core::launcher;
use bubbler_core::lint;
use bubbler_core::profile;
use bubbler_core::run_log;
use bubbler_core::tty::{self, TtyMode};
use bubbler_core::wrap;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

/// `--tty` takes the names the config's `tty` node takes; clap already
/// says which value was rejected, so only the reason is passed on.
fn tty_mode(s: &str) -> Result<TtyMode, String> {
    TtyMode::from_str(s).map_err(|e| match e {
        ConfigError::BadArgument { reason, .. } => reason,
        other => other.to_string(),
    })
}

/// How much of the argv `--explain` prints.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Explain {
    /// Every group, with the baseline summed up after its first
    /// arguments. The default.
    Groups,
    /// Every argument, the baseline included.
    Full,
}

/// How `--explain` writes what it found.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Groups for reading, in emit order.
    Text,
    /// One object per operation, nothing elided.
    Json,
}

/// The `--explain` flags `run` and `try` share.
struct Explaining {
    mode: Explain,
    format: Format,
    proxy: bool,
}

/// bubblewrap-based application sandbox.
#[derive(Parser)]
#[command(name = "bubbler", version, about)]
#[command(long_about = "\
bubbler runs an application inside a bubblewrap sandbox that starts with
nothing and is widened one grant at a time. An instance is a named sandbox
with its own private home and its own config.kdl; a profile seeds that config
once and never edits it again. Every grant is a node in that file, and every
node is documented in bubbler-config(5), which `bubbler man --config` prints.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new instance from a profile (user, system or built-in layers).
    #[command(long_about = "\
Create a new instance: a directory holding a config.kdl seeded from the
profile, flattened through the user, system and built-in layers, and an empty
private home. The directory it made is printed. Editing the instance never
edits the profile it came from, and `reseed` is the way back to it.")]
    Create {
        /// Instance name: letters, digits, `.`, `_`, `-`; not `.`, `..`
        /// or a name starting with `-`.
        name: String,
        /// Profile to seed config.kdl from, flattened through its layers.
        #[arg(long, default_value = "generic")]
        profile: String,
    },
    /// Run a command inside an instance's sandbox.
    #[command(long_about = "\
Run the instance's `command`, or the command given after `--`, inside its
sandbox. An instance that is already running is not started a second time: the
command is executed inside the running sandbox instead, with the grants that
sandbox was started with, and configuration changes apply on the next start.
`--dry-run` prints the bwrap argv and launches nothing; `--explain` prints
that same argv grouped under the config node each argument came from.")]
    Run {
        /// Instance name.
        name: String,
        /// Print the bwrap argv, one element per line, instead of running.
        #[arg(long)]
        dry_run: bool,
        /// Print the argv grouped under the node each argument came
        /// from, instead of running; `full` also lists the baseline.
        #[arg(long, value_name = "MODE", value_enum, num_args = 0..=1,
              default_missing_value = "groups")]
        explain: Option<Explain>,
        /// With `--explain`: explain the D-Bus proxy sidecar's argv
        /// instead of the sandbox's.
        #[arg(long, requires = "explain")]
        proxy: bool,
        /// With `--explain`: `text` to read, `json` for tooling.
        #[arg(
            long,
            value_name = "FORMAT",
            value_enum,
            default_value = "text",
            requires = "explain"
        )]
        format: Format,
        /// Terminal the sandbox gets: `pty`, `passthrough` or `none`;
        /// overrides the instance's `tty` node.
        #[arg(long, value_name = "MODE", value_parser = tty_mode)]
        tty: Option<TtyMode>,
        /// Command to run; replaces the config's `command`.
        #[arg(last = true)]
        command: Vec<OsString>,
    },
    /// Run a command in a throwaway sandbox, without creating an instance.
    #[command(long_about = "\
Run one command in a sandbox that is thrown away afterwards. Its config is the
flattened profile plus one bare node per `--grant`, checked the way a config
file is, so a bundle without the `dbus` that carries it is refused rather than
quietly dropped. The sandbox lives under $XDG_DATA_HOME/bubbler/try/<pid>,
never appears in `list`, and is removed when the command exits whatever its
status; `--keep <name>` renames it into an instance instead.")]
    Try {
        /// Profile to seed the throwaway config from.
        #[arg(long, default_value = "generic")]
        profile: String,
        /// Grant one service on top of the profile; repeatable.
        #[arg(long = "grant", value_name = "SERVICE")]
        grants: Vec<String>,
        /// Keep the sandbox afterwards as an instance with this name.
        // Nothing runs under `--explain`, so there is nothing to keep.
        #[arg(long, value_name = "NAME", conflicts_with = "explain")]
        keep: Option<String>,
        /// Print the argv grouped under the node each argument came
        /// from, instead of running; `full` also lists the baseline.
        #[arg(long, value_name = "MODE", value_enum, num_args = 0..=1,
              default_missing_value = "groups")]
        explain: Option<Explain>,
        /// With `--explain`: explain the D-Bus proxy sidecar's argv
        /// instead of the sandbox's.
        #[arg(long, requires = "explain")]
        proxy: bool,
        /// With `--explain`: `text` to read, `json` for tooling.
        #[arg(
            long,
            value_name = "FORMAT",
            value_enum,
            default_value = "text",
            requires = "explain"
        )]
        format: Format,
        /// Terminal the sandbox gets: `pty`, `passthrough` or `none`;
        /// overrides the profile's `tty` node.
        #[arg(long, value_name = "MODE", value_parser = tty_mode)]
        tty: Option<TtyMode>,
        /// Command to run; replaces the profile's `command`.
        #[arg(last = true)]
        command: Vec<OsString>,
    },
    /// Run a command inside an already running instance.
    #[command(long_about = "\
Run a command inside a sandbox that is already running, through the control
socket of the `bubbler-init` supervisor in it. The command joins that sandbox
as it was started, so what it may reach is what the sandbox was given, not
what its config.kdl says now. Descriptors handed to an exec'd command are
reachable by the sandboxed application through /proc, so exec is a convenience
channel and not a boundary.")]
    Exec {
        /// Instance name.
        name: String,
        /// Terminal the command gets: `pty`, `passthrough` or `none`;
        /// overrides the instance's `tty` node.
        #[arg(long, value_name = "MODE", value_parser = tty_mode)]
        tty: Option<TtyMode>,
        /// Command to run inside it, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Run a command in an instance, the way shims and desktop entries do.
    #[command(long_about = "\
Run a command in an instance, starting the sandbox when it is not running and
executing into it when it is, which is what a desktop entry and a PATH shim
call. A URL or a file handed to a running application therefore reaches the
window that is already open. The command replaces the config's `command`; with
no terminal anywhere, the sandbox is given none either (`tty \"none\"`) and
bubbler's own stderr, the sidecars' and the application's go to the instance's
last-run.log, which `bubbler log` prints.")]
    Open {
        /// Instance name.
        name: String,
        /// Command to run; replaces the config's `command`.
        #[arg(last = true)]
        command: Vec<OsString>,
    },
    /// Print what the instance's last run without a terminal wrote.
    #[command(long_about = "\
Print the instance's last-run.log, byte for byte: what bubbler, its sidecars
and the application wrote to stderr during the last run that had no terminal
to write to. Such a run empties it first and one that executes into a running
instance adds to it; it is never larger than a mebibyte, and mode 0600. An
instance that has only ever been run from a terminal has none.")]
    Log {
        /// Instance name.
        name: String,
    },
    /// Write, print or remove an instance's launcher entry.
    #[command(long_about = "\
Write a launcher entry that starts the instance, copied from the application's
own .desktop file and patched only where it has to be: the names gain a
` (Bubbler)` suffix, every Exec (the main one and each action's) runs `bubbler
open <instance>` around the application's own command line, TryExec names this
binary, DBusActivatable is forced false so no launcher can bypass Exec through
the session bus, and X-Bubbler-Instance records whose entry it is. Everything
else is copied through. Which file is copied comes from the config's `desktop`
node, else <command>.desktop, else the one entry whose Exec runs the command.
A file bubbler did not write is never written over.")]
    Desktop {
        /// Instance name; leave it out with `--refresh`.
        #[arg(required_unless_present = "refresh")]
        name: Option<String>,
        /// Take over the application's own entry, by writing one of the
        /// same file name: a user entry shadows the system's, so the
        /// menu keeps one entry and it is the sandboxed one.
        #[arg(long, conflicts_with_all = ["remove", "refresh"])]
        replace: bool,
        /// Delete the entries written for this instance, and nothing else.
        #[arg(long, conflicts_with_all = ["print", "refresh"])]
        remove: bool,
        /// Write the entry to stdout and touch no file.
        #[arg(long, conflicts_with = "refresh")]
        print: bool,
        /// Rewrite every entry bubbler has written, for every instance:
        /// re-copies each application's file and re-resolves this binary.
        #[arg(long, conflicts_with = "name")]
        refresh: bool,
    },
    /// List instances.
    #[command(long_about = "\
Print the name of every instance, one per line, sorted by name. A directory
without a config.kdl in it, or under a name bubbler would not have created, is
passed over rather than listed. The throwaway sandboxes `try` makes never
appear here.")]
    List,
    /// List profiles from every layer: user, system and built-in.
    #[command(long_about = "\
Print the name of every profile any layer holds — yours, the system's, and the
built-in library — one per line, each name once however many layers carry it.
`--origin` adds the layer a name resolves to and the file it is read from, tab
separated, with `-` for a built-in, which has no file.")]
    Profiles {
        /// Also print the layer each name resolves to and the file it is
        /// read from, tab separated; `-` for a built-in.
        #[arg(long)]
        origin: bool,
    },
    /// Delete an instance and its private home. Irreversible.
    #[command(long_about = "\
Delete an instance: its config.kdl, its private home and any runtime directory
left behind. This is irreversible, so it does nothing without `--yes`. An
instance path that is a symlink is refused outright rather than followed.")]
    Delete {
        /// Instance name.
        name: String,
        /// Required: confirms deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Open an instance's config.kdl in $VISUAL or $EDITOR, then re-check it.
    #[command(long_about = "\
Open the instance's config.kdl in $VISUAL, else $EDITOR, split into an argv
with no shell in between, so quotes and $VAR in those variables are not
expanded. A non-zero editor exit is propagated and the file is left alone.
Afterwards the file is parsed again and any error printed; the file is kept
either way, since only its author knows what it was meant to say. A config
that parses is then linted, a hand-edited file being where a grant wider than
it means tends to appear.")]
    Edit {
        /// Instance name.
        name: String,
    },
    /// Show, edit or lint one profile.
    #[command(long_about = "\
Show, edit or lint one profile. Profiles come in three layers — yours under
$XDG_CONFIG_HOME/bubbler/profiles, the system's, and the library built into
the binary — and compose with `include`, which resolves at the next layer
down. A profile only ever seeds an instance: changing one never changes an
instance already created from it.")]
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Re-seed an instance's config.kdl from its profile, keeping `home/`.
    #[command(long_about = "\
Flatten the instance's profile again and write it over the instance's
config.kdl, keeping the private home as it is. Edits made to that config are
lost, which is the point: this is how an instance picks up a profile that has
changed. The file it replaces is copied to config.kdl.bak first, and the fresh
one is linted afterwards. An instance that is running is refused: bwrap cannot
be told about a bind after the fact, so a rewritten config would describe
grants that sandbox does not have.")]
    Reseed {
        /// Instance name.
        name: String,
    },
    /// Check an instance's config.kdl for grants wider than it likely means.
    #[command(long_about = "\
Measure an instance's config.kdl against what a sandbox is meant to give away.
Nothing is launched and no file is edited. Findings name the file and line
that has to change and carry an indented `help:` line with the fix. Exit 0
clean (notes fail nothing), 1 warnings, 2 errors, 3 when the run could not be
made at all — a file that does not parse is deliberately a different answer
from a file that grants too much. The checks are listed in bubbler-config(5).")]
    Lint {
        /// Instance name.
        name: String,
        #[command(flatten)]
        opts: LintOpts,
    },
    /// Put a shim for an instance on `PATH`, in ~/.local/bin.
    Wrap {
        /// Instance the shim opens; leave it out with `--list`.
        #[arg(required_unless_present = "list")]
        name: Option<String>,
        /// Name the shim takes, instead of the instance's own. It
        /// intercepts every use of that name resolved through `PATH`.
        #[arg(long = "as", value_name = "NAME", conflicts_with = "list")]
        as_name: Option<String>,
        /// Print every shim: name, instance, path and `ok` or `broken`.
        #[arg(long, conflicts_with = "name")]
        list: bool,
    },
    /// Remove a shim and the registry line naming it.
    Unwrap {
        /// Shim name, as `wrap --list` prints it.
        name: String,
    },
    /// Print bubbler's manual pages in roff.
    #[command(long_about = "\
Print bubbler's own manual page, bubbler(1), as roff on stdout: the synopsis
and options of every subcommand, the files a run reads and writes, and the
environment it honours, all rendered from the command tree this binary was
built with. `--config` prints bubbler-config(5) instead — every config node
with its grammar, what it grants and what granting it costs, and every lint
check by id — generated from the same catalogue the rest of bubbler explains
grants from. A packager writes `bubbler man > bubbler.1` and `bubbler man
--config > bubbler-config.5` against the binary it is installing beside them.")]
    Man {
        /// Print `bubbler-config(5)`, the config.kdl page, instead of
        /// `bubbler(1)`.
        #[arg(long)]
        config: bool,
    },
}

/// How a lint run reports and what it makes of a warning. Shared by
/// `bubbler lint` and `bubbler profile lint`.
#[derive(clap::Args)]
struct LintOpts {
    /// Print findings as JSON, one object per finding plus a summary.
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    format: Option<String>,
    /// Exit 2 rather than 1 when the run found only warnings.
    #[arg(long, value_name = "WHAT", value_parser = ["warnings"])]
    deny: Option<String>,
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Print the profile flattened through its layers, each node under
    /// the layer it came from.
    #[command(long_about = "\
Print the profile as bubbler reads it: flattened through its layers, with
every node under the layer it came from, so an `include` and an override are
visible as such rather than as one merged file.")]
    Show {
        /// Profile name.
        name: String,
    },
    /// Open your layer's copy in $VISUAL or $EDITOR, then re-resolve it.
    /// A name you do not have yet is written with a starting point first.
    #[command(long_about = "\
Open your layer's copy of the profile in $VISUAL, else $EDITOR, and resolve it
again afterwards. A name your layer does not hold yet is written first with a
starting point in it, so overriding a built-in profile means writing a profile
of your own rather than changing one in place. A profile that parses is linted
afterwards, as an instance config is after `edit`.")]
    Edit {
        /// Profile name.
        name: String,
    },
    /// Check a profile, flattened through its layers, for grants wider
    /// than it likely means.
    #[command(long_about = "\
Measure a profile, flattened through its layers, against what a sandbox is
meant to give away. Spans come from the file rather than from the flattened
result, so a finding names the layer that has to change even when the grant is
three `include`s deep. `--all` lints every name any layer holds and is the CI
entry point: one layer that cannot be read stops the run rather than counting
as clean. The checks are listed in bubbler-config(5).")]
    Lint {
        /// Profile name; leave it out with `--all`.
        #[arg(required_unless_present = "all")]
        name: Option<String>,
        /// Lint every profile name any layer holds.
        #[arg(long, conflicts_with = "name")]
        all: bool,
        #[command(flatten)]
        opts: LintOpts,
    },
}

fn main() -> ExitCode {
    // The guard lives here and not inside the run so that the error a
    // failed run ends with is written to the log as well; `open` is the
    // only subcommand that ever fills it in.
    let mut log = None;
    let code = match real_main(&mut log) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("bubbler: {e:#}");
            ExitCode::from(1)
        }
    };
    drop(log);
    code
}

fn write_lines(out: &mut dyn Write, lines: &[&OsStr]) -> io::Result<()> {
    for l in lines {
        out.write_all(l.as_bytes())?;
        out.write_all(b"\n")?;
    }
    out.flush()
}

/// Print one line per element, byte for byte: argv and paths are not UTF-8
/// and a lossy rendering would not be the audit trail it claims to be. A
/// reader that closed the pipe early (`| head`) is a normal end, not a
/// failure.
fn print_lines(lines: &[&OsStr], what: &str) -> Result<i32> {
    match write_lines(&mut io::stdout().lock(), lines) {
        Ok(()) => Ok(0),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Err(e) => Err(e).with_context(|| format!("writing {what}")),
    }
}

/// Print bytes as they are: a log and a desktop entry are files, and
/// what is in them is not this command's to reword. A reader that left
/// early (`| head`) is a normal end here too.
fn print_bytes(bytes: &[u8], what: &str) -> Result<i32> {
    let mut out = io::stdout().lock();
    let written = out.write_all(bytes).and_then(|()| out.flush());
    match written {
        Ok(()) => Ok(0),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Err(e) => Err(e).with_context(|| format!("writing {what}")),
    }
}

/// Print the argv of `inst` with every argument under the node it came
/// from, or, with `--proxy`, the argv of its D-Bus proxy sidecar. Nothing
/// is started: `--explain` is a `--dry-run` with a different framing.
fn explain(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    ctty: bool,
    opts: &Explaining,
) -> Result<i32> {
    let (title, items) = match opts.proxy {
        true => (
            "bwrap  (the D-Bus proxy sidecar)",
            launcher::explain_proxy(env, inst)
                .context("building the proxy's bwrap arguments")?
                .with_context(|| {
                    format!(
                        "instance `{}` grants no bus, so it starts no proxy sidecar",
                        inst.name
                    )
                })?,
        ),
        false => (
            "bwrap",
            launcher::explain(env, inst, command, ctty).context("building bwrap arguments")?,
        ),
    };
    let path = inst.config_path();
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut lines = config::node_lines(&text)
        .with_context(|| format!("locating the nodes of {}", path.display()))?;
    // The file is read a second time here, so a config edited in between
    // is reported without line numbers rather than with wrong ones.
    if lines.services.len() != inst.config.services.len()
        || lines.env.len() != inst.config.env.len()
    {
        lines = config::Lines::default();
    }
    let rules = explain::rules(&inst.config, &inst.name);
    let view = explain::View {
        title,
        cfg: &inst.config,
        source: explain::Source {
            file: "config.kdl",
            lines: &lines,
        },
        rules: &rules,
        proxy: opts.proxy,
        full: opts.mode == Explain::Full,
    };
    let rendered = match opts.format {
        Format::Text => explain::render(&items, &view),
        Format::Json => explain::render_json(&items, &view).map(|j| vec![j]),
    }
    .context("rendering the explanation")?;
    let lines: Vec<&OsStr> = rendered.iter().map(OsStr::new).collect();
    print_lines(&lines, "the explanation")
}

/// The entry an instance's launcher entry is generated from, and where
/// it goes. Split out because `--refresh` builds the same thing for an
/// entry whose path is already decided.
fn build_entry(
    dirs: &desktop::Dirs,
    inst: &Instance,
    program: &Path,
    replace: bool,
) -> Result<(PathBuf, String)> {
    let source = desktop::source(dirs, &inst.name, &inst.config)
        .with_context(|| format!("finding the desktop entry instance `{}` is for", inst.name))?;
    let entry = desktop::render(&source, &inst.name, program)
        .with_context(|| format!("reading {}", source.display()))?;
    Ok((desktop::target(dirs, &inst.name, &source, replace), entry))
}

/// Re-generate every entry bubbler has written: a new bubbler path, a
/// changed config or an updated application file all reach the menu
/// through this. Each entry is rewritten where it already is, so an entry
/// written with `--replace` keeps shadowing the application's.
fn refresh_entries(env: &Env, dirs: &desktop::Dirs, program: &Path) -> Result<i32> {
    let entries = desktop::generated(dirs);
    if entries.is_empty() {
        eprintln!(
            "bubbler: no entry of bubbler's in {}; `bubbler desktop <instance>` writes one",
            dirs.user.display()
        );
        return Ok(0);
    }
    let mut written = Vec::new();
    let mut failed = 0;
    for (path, name) in entries {
        let done = Instance::open(env, &name)
            .with_context(|| format!("opening instance `{name}`"))
            .and_then(|inst| {
                // The file name stays as it is: whether this entry
                // shadows the application's was decided when it was
                // written, and a refresh is not the place to change it.
                let (_, entry) = build_entry(dirs, &inst, program, false)?;
                desktop::write(&path, &entry, &name)
                    .with_context(|| format!("writing {}", path.display()))?;
                warn_invalid(&path);
                Ok(())
            });
        match done {
            Ok(()) => written.push(path),
            Err(e) => {
                failed += 1;
                let e = e.context(format!("refreshing {}", path.display()));
                eprintln!("bubbler: {e:#}");
            }
        }
    }
    update_desktop_db(&dirs.user);
    let lines: Vec<&OsStr> = written.iter().map(|p| p.as_os_str()).collect();
    print_lines(&lines, "the refreshed entries")?;
    Ok(i32::from(failed > 0))
}

/// The log a run without a terminal writes, or `None` after saying why
/// there is none: a log that cannot be opened — a symlink where the file
/// belongs, a full disk — is a lost record, and losing the record is not
/// a reason to refuse the sandbox the user asked for.
fn open_log(path: &Path, truncate: bool) -> Option<run_log::Redirect> {
    match run_log::redirect(path, truncate) {
        Ok(guard) => Some(guard),
        Err(e) => {
            let e = anyhow::Error::new(e);
            eprintln!("bubbler: warning: no log for this run: {e:#}");
            None
        }
    }
}

/// What `desktop-file-validate` rejects about an entry just written, as
/// warnings: the file is on disk either way, since what it says about an
/// application's own copied keys is not bubbler's to correct.
fn warn_invalid(path: &Path) {
    for line in desktop::validate(path) {
        eprintln!("bubbler: warning: {line}");
    }
}

/// Rebuild the launcher's MIME cache after the applications directory has
/// changed. A missing tool is a warning: it costs the entry its place in
/// "Open With" lists, and nothing else about it.
fn update_desktop_db(dir: &Path) {
    match desktop::update_database(dir) {
        Ok(true) => {}
        Ok(false) => eprintln!(
            "bubbler: warning: update-desktop-database is not installed \
             (package desktop-file-utils), so the entry may not be offered \
             as a handler for the file types it claims"
        ),
        Err(e) => eprintln!("bubbler: warning: {e}"),
    }
}

/// Program and arguments from `$VISUAL`, else `$EDITOR`. The value is
/// split into argv and never passed to a shell, so quotes and `$VAR` in
/// it are not expanded. Resolved before anything is opened or written:
/// `profile edit` creates the file it is about to edit, and a host with
/// no editor set must be told so rather than left with a new profile.
fn editor_argv() -> Result<(OsString, Vec<OsString>)> {
    let editor = host_env::editor().context("neither VISUAL nor EDITOR is set")?;
    let mut parts = editor
        .as_bytes()
        .split(u8::is_ascii_whitespace)
        .filter(|p| !p.is_empty())
        .map(|p| OsStr::from_bytes(p).to_owned());
    let program = parts.next().context("VISUAL or EDITOR is blank")?;
    Ok((program, parts.collect()))
}

/// Open `path` in the editor [`editor_argv`] resolved and wait.
/// `Some(code)` is a non-zero editor exit to propagate as bubbler's own.
fn run_editor(program: &OsStr, args: &[OsString], path: &Path) -> Result<Option<i32>> {
    let status = Command::new(program)
        .args(args)
        .arg(path)
        .status()
        .with_context(|| format!("running editor {}", program.to_string_lossy()))?;
    Ok((!status.success()).then(|| launcher::exit_code(status)))
}

/// Exit code for a file the editor has just left: 0 when it parses again,
/// 1 after naming what is still wrong with it. The file is kept either
/// way, since only its author knows what it was meant to say.
fn recheck<T, E>(path: &Path, result: Result<T, E>) -> i32
where
    E: std::error::Error + Send + Sync + 'static,
{
    match result {
        Ok(_) => 0,
        Err(e) => {
            let e = anyhow::Error::new(e).context(format!("{} still has errors", path.display()));
            eprintln!("bubbler: {e:#}");
            1
        }
    }
}

/// Print a report and return the exit code it earns. The text form goes
/// out byte for byte, since a profile path need not be UTF-8.
fn report(report: &lint::Report, opts: &LintOpts) -> Result<i32> {
    let code = lint::exit_code(report, opts.deny.as_deref() == Some("warnings"));
    if opts.format.as_deref() == Some("json") {
        // Through the same writer as everything else, so a reader that
        // leaves early (`| head`) is a normal end here too.
        let json = lint::render_json(report);
        let lines: Vec<&OsStr> = json.lines().map(OsStr::new).collect();
        print_lines(&lines, "the lint report")?;
        return Ok(code);
    }
    let lines = lint::render_text(report);
    let lines: Vec<&OsStr> = lines.iter().map(OsString::as_os_str).collect();
    print_lines(&lines, "the lint report")?;
    Ok(code)
}

/// The errors and warnings of a lint run on stderr, prefixed so they are
/// plainly bubbler's and plainly not the command's own output. Notes are
/// left out, the exit code is untouched, and a run that could not be made
/// at all says nothing: this rides along with another command, and must
/// never be what fails it.
fn warn_lint(result: Result<lint::Report, bubbler_core::error::LintError>) {
    let Ok(report) = result else {
        return;
    };
    for finding in &report.findings {
        if finding.severity == lint::Severity::Note {
            continue;
        }
        for line in lint::render_finding(finding) {
            eprintln!("bubbler: lint: {}", line.to_string_lossy());
        }
    }
}

/// What a config written before the current version has to say about
/// itself, on stderr and before the run it applies to.
fn warn_migration(inst: &Instance) {
    if let Some(text) = inst.migration_warning() {
        eprintln!("bubbler: warning: {text}");
    }
}

/// The `bubbler open` command line this process stands for, when it was
/// started through a PATH shim. `argv[0]` is the only place the name it
/// was called by survives — `current_exe()` reads `/proc/self/exe` and so
/// resolves the symlink — and it is caller-controlled, so the name is a
/// key into the registry bubbler wrote and never an instance name in its
/// own right. A name the registry does not hold is not a shim, and the
/// ordinary CLI runs.
fn shim_dispatch(argv: &[OsString]) -> Result<Option<Vec<OsString>>> {
    let Some(name) = wrap::shim_name(argv.first().map(OsString::as_os_str)) else {
        return Ok(None);
    };
    // Read here rather than in `real_main`, so `bubbler --help` on a host
    // without `$XDG_RUNTIME_DIR` still answers.
    let env = host_env::from_process()?;
    let Some(found) = wrap::lookup(&env, &name).context("reading the shim registry")? else {
        return Ok(None);
    };
    let inst = Instance::open(&env, &found.instance)
        .with_context(|| format!("opening instance `{}` for shim `{name}`", found.instance))?;
    // The instance's own command first: `open` reads what follows `--` as
    // the whole command, so passing only the shim's arguments would run
    // the URL as a program.
    let mut args = launcher::resolve_command(&inst, None)
        .with_context(|| format!("shim `{name}`"))?
        .to_vec();
    args.extend(argv.iter().skip(1).cloned());
    Ok(Some(wrap::open_argv(&found.instance, &args)))
}

fn real_main(log: &mut Option<run_log::Redirect>) -> Result<i32> {
    // Before anything else opens a descriptor.
    host_env::fill_closed_stdio()?;
    // Before the parser: clap ignores `argv[0]`, so a shim named after a
    // subcommand would otherwise be read as that subcommand.
    let argv: Vec<OsString> = std::env::args_os().collect();
    let shim = shim_dispatch(&argv)?;
    let cli = match &shim {
        Some(argv) => {
            // The one hook the shim tests have: what a shim resolved to,
            // without starting the sandbox it names.
            if std::env::var_os("BUBBLER_WRAP_DRY_RUN").is_some_and(|v| v == "1") {
                let lines: Vec<&OsStr> = argv.iter().map(OsString::as_os_str).collect();
                return print_lines(&lines, "the shim command line");
            }
            Cli::parse_from(argv)
        }
        None => Cli::parse(),
    };
    let env = host_env::from_process()?;
    match cli.cmd {
        Cmd::Create { name, profile } => {
            let inst = Instance::create(&env, &name, &profile)
                .with_context(|| format!("creating instance `{name}`"))?;
            let path = host_env::search_path();
            let ctx = lint::Context {
                env: &env,
                host: &RealHost,
                search_path: &path,
            };
            warn_lint(lint::lint_config(&ctx, &inst.config_path()));
            print_lines(&[inst.dir.as_os_str()], "the instance directory")
        }
        Cmd::Run {
            name,
            dry_run,
            explain: explain_mode,
            proxy,
            format,
            tty,
            command,
        } => {
            let inst = Instance::open(&env, &name).with_context(|| {
                format!(
                    "opening instance `{name}` ({})",
                    instance::config_path(&env, &name).display()
                )
            })?;
            // Before the dry run and the explanation too: both describe
            // the sandbox this config asks for, and what it asks for is
            // exactly what changed meaning.
            warn_migration(&inst);
            let command = (!command.is_empty()).then_some(command.as_slice());
            let mode = tty.unwrap_or(inst.config.tty);
            // A dry run and an explanation both describe a fresh start
            // and never touch a live instance, so the liveness check is
            // skipped for both. The argv still depends on this terminal:
            // `--ctty` is there exactly when a real run would allocate a
            // pty for the sandbox's stdin.
            let ctty = tty::plan(mode, tty::host_is_tty()).ctty();
            if let Some(mode) = explain_mode {
                return explain(
                    &env,
                    &inst,
                    command,
                    ctty,
                    &Explaining {
                        mode,
                        format,
                        proxy,
                    },
                );
            }
            if dry_run {
                let argv = launcher::build_argv(
                    &env,
                    &inst,
                    command,
                    &mut launcher::DryRunAlloc::default(),
                    ctty,
                )
                .context("building bwrap arguments")?;
                let mut lines = vec![OsStr::new("bwrap")];
                lines.extend(argv.iter().map(OsString::as_os_str));
                return print_lines(&lines, "the bwrap argv");
            }
            if let Some(stream) = exec::connect(&env, &name)
                .with_context(|| format!("connecting to instance `{name}`"))?
            {
                eprintln!(
                    "bubbler: instance `{name}` is running; executing inside it \
                     (config changes apply after restart)"
                );
                let command = launcher::resolve_command(&inst, command)?;
                return exec::run_in(&stream, command, mode)
                    .with_context(|| format!("executing in instance `{name}`"));
            }
            if inst.has_service(&Service::X11) {
                eprintln!("bubbler: warning: x11 grants no isolation between X clients");
            }
            launcher::run(&env, &inst, command, mode)
                .with_context(|| format!("running instance `{name}`"))
        }
        Cmd::Try {
            profile,
            grants,
            keep,
            explain: explain_mode,
            proxy,
            format,
            tty,
            command,
        } => {
            let grants: Vec<&str> = grants.iter().map(String::as_str).collect();
            let mut eph = Instance::ephemeral(&env, &profile, &grants)
                .context("creating a throwaway sandbox")?;
            if let Some(mode) = explain_mode {
                let command = (!command.is_empty()).then_some(command.as_slice());
                let tty_mode = tty.unwrap_or(eph.instance.config.tty);
                let ctty = tty::plan(tty_mode, tty::host_is_tty()).ctty();
                let code = explain(
                    &env,
                    &eph.instance,
                    command,
                    ctty,
                    &Explaining {
                        mode,
                        format,
                        proxy,
                    },
                );
                // The sandbox directory must outlive the explanation:
                // dropping the guard is what removes it.
                drop(eph);
                return code;
            }
            if let Some(name) = &keep {
                eph.keep_as(&env, name)
                    .with_context(|| format!("keeping the sandbox as instance `{name}`"))?;
            }
            if eph.instance.has_service(&Service::X11) {
                eprintln!("bubbler: warning: x11 grants no isolation between X clients");
            }
            let command = (!command.is_empty()).then_some(command.as_slice());
            let mode = tty.unwrap_or(eph.instance.config.tty);
            let code = launcher::run(&env, &eph.instance, command, mode);
            // Something else already answers on this pid's control socket,
            // so that runtime directory is not this run's to remove.
            if matches!(code, Err(LaunchError::AlreadyRunning(_))) {
                eph.disarm_runtime();
            }
            // A sandbox that never started is not one to keep, whatever
            // `--keep` said.
            if code.is_err() {
                eph.disarm_keep();
            }
            let code = code.context("running a throwaway sandbox");
            // The sandbox directory must outlive the run: dropping the
            // guard is what removes or keeps it.
            drop(eph);
            code
        }
        Cmd::Exec { name, tty, command } => {
            // Checked, not opened: a running instance can be reached even
            // while its config.kdl is mid-edit and would not parse.
            instance::config_path_checked(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            // Which is also why a config that does not parse only costs
            // the terminal mode its default, and its warning, here rather
            // than the exec.
            let opened = Instance::open(&env, &name).ok();
            if let Some(inst) = &opened {
                warn_migration(inst);
            }
            let mode =
                tty.unwrap_or_else(|| opened.map_or_else(TtyMode::default, |i| i.config.tty));
            launcher::exec(&env, &name, &command, mode)
                .with_context(|| format!("executing in instance `{name}`"))
        }
        Cmd::Open { name, command } => {
            // The instance directory is found before its config is read,
            // because a config that does not parse is exactly the failure
            // a run nobody is watching has to leave a record of.
            let config = instance::config_path_checked(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            // Before the log is opened, so a stale socket is cleared and
            // the answer decides whether this run empties the log or adds
            // to what the run it is executing into wrote.
            let stream = exec::connect(&env, &name)
                .with_context(|| format!("connecting to instance `{name}`"))?;
            let is_tty = tty::host_is_tty();
            if !is_tty[2] {
                *log = open_log(&config.with_file_name(run_log::LOG_FILE), stream.is_none());
            }
            let inst = Instance::open(&env, &name).with_context(|| {
                format!(
                    "opening instance `{name}` ({})",
                    instance::config_path(&env, &name).display()
                )
            })?;
            warn_migration(&inst);
            let command = (!command.is_empty()).then_some(command.as_slice());
            // A launcher starts its children with no terminal at all, so
            // there is none to hand over or to stand in for; the sandbox
            // gets pipes bubbler reads, which is what puts the
            // application's own stderr in the log.
            let mode = match is_tty.iter().any(|t| *t) {
                true => inst.config.tty,
                false => TtyMode::None,
            };
            if let Some(stream) = stream {
                eprintln!(
                    "bubbler: instance `{name}` is running; executing inside it \
                     (config changes apply after restart)"
                );
                let command = launcher::resolve_command(&inst, command)?;
                return exec::run_in(&stream, command, mode)
                    .with_context(|| format!("executing in instance `{name}`"));
            }
            if inst.has_service(&Service::X11) {
                eprintln!("bubbler: warning: x11 grants no isolation between X clients");
            }
            launcher::run(&env, &inst, command, mode)
                .with_context(|| format!("running instance `{name}`"))
        }
        Cmd::Log { name } => {
            let config = instance::config_path_checked(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            let path = config.with_file_name(run_log::LOG_FILE);
            let text = run_log::read(&path)
                .with_context(|| format!("reading {}", path.display()))?
                .with_context(|| {
                    format!(
                        "instance `{name}` has no {}: it is written by a run with no \
                         terminal, which is how a desktop entry or a shim starts one",
                        run_log::LOG_FILE
                    )
                })?;
            print_bytes(&text, "the log")
        }
        Cmd::Desktop {
            name,
            replace,
            remove,
            print,
            refresh,
        } => {
            let dirs = desktop::Dirs::from_env(&env);
            let exe = std::env::current_exe().context("finding this bubbler binary")?;
            let program = desktop::program(&exe, &host_env::search_path());
            if refresh {
                return refresh_entries(&env, &dirs, &program);
            }
            // clap requires a name without `--refresh` and refuses one
            // with it, so this is out of reach from the command line.
            let name = name.context("`desktop` takes an instance name or `--refresh`")?;
            if remove {
                let gone = desktop::remove(&dirs, &name)
                    .with_context(|| format!("removing the desktop entry of `{name}`"))?;
                update_desktop_db(&dirs.user);
                let lines: Vec<&OsStr> = gone.iter().map(|p| p.as_os_str()).collect();
                return print_lines(&lines, "the removed entries");
            }
            let inst = Instance::open(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            let (target, entry) = build_entry(&dirs, &inst, &program, replace)?;
            if print {
                return print_bytes(entry.as_bytes(), "the desktop entry");
            }
            desktop::write(&target, &entry, &name)
                .with_context(|| format!("writing {}", target.display()))?;
            warn_invalid(&target);
            update_desktop_db(&dirs.user);
            print_lines(&[target.as_os_str()], "the entry path")
        }
        Cmd::List => {
            let names = Instance::list(&env).context("listing instances")?;
            let lines: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
            print_lines(&lines, "the instance list")
        }
        Cmd::Profiles { origin } => {
            let entries = profile::Resolver::new(&env)
                .list()
                .context("listing profiles")?;
            // Paths are not UTF-8, so the origin line is built as bytes
            // rather than formatted into a String.
            let lines: Vec<OsString> = entries
                .iter()
                .map(|e| {
                    if !origin {
                        return OsString::from(&e.name);
                    }
                    let mut line = OsString::from(format!("{}\t{}\t", e.name, e.origin));
                    line.push(e.path.as_deref().map_or(Path::new("-"), |p| p));
                    line
                })
                .collect();
            let lines: Vec<&OsStr> = lines.iter().map(OsString::as_os_str).collect();
            print_lines(&lines, "the profile list")
        }
        Cmd::Delete { name, yes } => {
            if !yes {
                bail!("refusing to delete `{name}` without --yes (this removes its private home)");
            }
            Instance::delete(&env, &name).with_context(|| format!("deleting instance `{name}`"))?;
            // Named, not removed: a shim is a file on the user's `PATH`,
            // and `delete` taking one away is a surprise `unwrap` is for.
            match wrap::load(&env) {
                Ok(wraps) => {
                    for w in wraps.iter().filter(|w| w.instance == name) {
                        eprintln!(
                            "bubbler: note: shim `{shim}` still opens `{name}`; \
                             `bubbler unwrap {shim}` removes it",
                            shim = w.name
                        );
                    }
                }
                Err(e) => eprintln!("bubbler: warning: reading the shim registry: {e}"),
            }
            Ok(0)
        }
        Cmd::Edit { name } => {
            let (program, args) = editor_argv()?;
            let path = instance::config_path_checked(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            if let Some(code) = run_editor(&program, &args, &path)? {
                return Ok(code);
            }
            let opened = Instance::open(&env, &name);
            // Before the header is written, never after: stamping the
            // file is what stops the warning, and a warning the user
            // never saw would be one the edit quietly erased.
            if let Ok(inst) = &opened {
                warn_migration(inst);
            }
            let code = recheck(&path, opened);
            // A file the user has just read through is a file whose
            // grants mean what this bubbler says they mean, so the
            // version header goes in and the warning above is the last.
            if code == 0 {
                Instance::mark_version(&env, &name)
                    .with_context(|| format!("recording the config version of `{name}`"))?;
            }
            // A config edited by hand is the likeliest place for an `x11`
            // or a share of `.ssh`, so it is linted like a profile is.
            if code == 0 {
                let search = host_env::search_path();
                let ctx = lint::Context {
                    env: &env,
                    host: &RealHost,
                    search_path: &search,
                };
                warn_lint(lint::lint_config(&ctx, &path));
            }
            Ok(code)
        }
        Cmd::Profile { cmd } => match cmd {
            ProfileCmd::Show { name } => {
                let resolved = profile::Resolver::new(&env)
                    .resolve(&name)
                    .with_context(|| format!("resolving profile `{name}`"))?;
                let lines = profile::show(&name, &resolved);
                let lines: Vec<&OsStr> = lines.iter().map(OsString::as_os_str).collect();
                print_lines(&lines, "the profile")
            }
            ProfileCmd::Edit { name } => {
                // Before `edit_path`, which writes a starting point for a
                // profile the user layer does not hold yet: an editor that
                // cannot be resolved must leave nothing behind.
                let (program, args) = editor_argv()?;
                let profiles = profile::Resolver::new(&env);
                let path = profiles
                    .edit_path(&name)
                    .with_context(|| format!("opening profile `{name}`"))?;
                if let Some(code) = run_editor(&program, &args, &path)? {
                    return Ok(code);
                }
                let code = recheck(&path, profiles.resolve(&name));
                if code == 0 {
                    let search = host_env::search_path();
                    let ctx = lint::Context {
                        env: &env,
                        host: &RealHost,
                        search_path: &search,
                    };
                    warn_lint(lint::lint_profile(&ctx, &profiles, &name));
                }
                Ok(code)
            }
            ProfileCmd::Lint { name, all, opts } => {
                let profiles = profile::Resolver::new(&env);
                let search = host_env::search_path();
                let ctx = lint::Context {
                    env: &env,
                    host: &RealHost,
                    search_path: &search,
                };
                let found = match (name.as_deref(), all) {
                    (Some(name), false) => lint::lint_profile(&ctx, &profiles, name),
                    // `--all` is the CI entry point, so one profile that
                    // cannot be read stops the whole run rather than
                    // being counted as clean.
                    (None, true) => lint::lint_all(&ctx, &profiles),
                    // clap refuses a name together with `--all` and
                    // refuses neither, so this is out of reach from the
                    // command line.
                    _ => bail!("`profile lint` takes a profile name or `--all`, not both"),
                };
                let found = match found {
                    Ok(found) => found,
                    Err(e) => {
                        let what = name.as_deref().unwrap_or("every profile");
                        let e = anyhow::Error::new(e).context(format!("linting {what}"));
                        eprintln!("bubbler: {e:#}");
                        return Ok(3);
                    }
                };
                report(&found, &opts)
            }
        },
        Cmd::Reseed { name } => {
            let inst = Instance::reseed(&env, &name)
                .with_context(|| format!("reseeding instance `{name}`"))?;
            let config = inst.config_path();
            let path = host_env::search_path();
            let ctx = lint::Context {
                env: &env,
                host: &RealHost,
                search_path: &path,
            };
            warn_lint(lint::lint_config(&ctx, &config));
            print_lines(&[config.as_os_str()], "the config path")
        }
        Cmd::Man { config } => {
            let version = format!("bubbler {}", env!("CARGO_PKG_VERSION"));
            let lines = match config {
                true => manpage::config_page(&version),
                false => manpage::page(Cli::command(), &version),
            };
            let lines: Vec<&OsStr> = lines.iter().map(OsString::as_os_str).collect();
            print_lines(&lines, "the man page")
        }
        Cmd::Lint { name, opts } => {
            let path = host_env::search_path();
            let ctx = lint::Context {
                env: &env,
                host: &RealHost,
                search_path: &path,
            };
            // Every way the run itself can fail is exit 3: "this file is
            // not one bubbler reads" is a different answer from "this
            // config grants too much", and CI has to tell them apart.
            let found = instance::config_path_checked(&env, &name)
                .map_err(anyhow::Error::new)
                .and_then(|config| Ok(lint::lint_config(&ctx, &config)?));
            match found {
                Ok(found) => report(&found, &opts),
                Err(e) => {
                    let e = e.context(format!("linting instance `{name}`"));
                    eprintln!("bubbler: {e:#}");
                    Ok(3)
                }
            }
        }
        Cmd::Wrap {
            name,
            as_name,
            list,
        } => {
            // The symlink target and the yardstick for "is this ours":
            // `current_exe` resolves through any shim this was itself
            // started by, so it always names the real binary.
            let bubbler = std::env::current_exe().context("locating the bubbler binary")?;
            if list {
                let entries = wrap::list(&env, &bubbler).context("listing shims")?;
                // Built as bytes rather than formatted into a String: the
                // shim path need not be UTF-8.
                let lines: Vec<OsString> = entries
                    .iter()
                    .map(|e| {
                        let mut line =
                            OsString::from(format!("{}\t{}\t", e.wrap.name, e.wrap.instance));
                        line.push(&e.path);
                        line.push(format!("\t{}", e.state));
                        line
                    })
                    .collect();
                let lines: Vec<&OsStr> = lines.iter().map(OsString::as_os_str).collect();
                return print_lines(&lines, "the shim list");
            }
            // clap requires one of the two, so this is out of reach from
            // the command line.
            let name = name.context("`wrap` takes an instance name or `--list`")?;
            let shim = as_name.clone().unwrap_or_else(|| name.clone());
            let made = wrap::add(&env, &name, &shim, &bubbler)
                .with_context(|| format!("wrapping instance `{name}` as `{shim}`"))?;
            if made.adopted {
                eprintln!(
                    "bubbler: note: {} was already a bubbler shim the registry did not \
                     name; it opens `{name}` from now on",
                    made.path.display()
                );
            }
            // Only for a name the user chose: a shim named after the
            // instance shadows nothing, which is why it is the default.
            if as_name.is_some() {
                eprintln!(
                    "bubbler: note: `{shim}` now starts this sandbox wherever PATH resolves it, \
                     the bare-name `Exec=` lines of desktop entries included"
                );
            }
            if let Some(warning) =
                wrap::path_warning(&wrap::shim_dir(&env), &shim, &host_env::search_path())
            {
                eprintln!("bubbler: warning: {warning}");
            }
            print_lines(&[made.path.as_os_str()], "the shim path")
        }
        Cmd::Unwrap { name } => {
            let bubbler = std::env::current_exe().context("locating the bubbler binary")?;
            let path = wrap::remove(&env, &name, &bubbler)
                .with_context(|| format!("removing shim `{name}`"))?;
            print_lines(&[path.as_os_str()], "the shim path")
        }
    }
}
