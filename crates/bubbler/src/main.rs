//! bubbler command line: create, run, edit, delete and list sandbox instances.

mod host_env;

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bubbler_core::config::{self, Service};
use bubbler_core::env::Env;
use bubbler_core::error::{ConfigError, LaunchError};
use bubbler_core::exec;
use bubbler_core::explain;
use bubbler_core::host::RealHost;
use bubbler_core::instance::{self, Instance};
use bubbler_core::launcher;
use bubbler_core::lint;
use bubbler_core::profile;
use bubbler_core::tty::{self, TtyMode};
use clap::{Parser, Subcommand, ValueEnum};

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
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new instance from a profile (user, system or built-in layers).
    Create {
        /// Instance name: letters, digits, `.`, `_`, `-`; not `.`, `..`
        /// or a name starting with `-`.
        name: String,
        /// Profile to seed config.kdl from, flattened through its layers.
        #[arg(long, default_value = "generic")]
        profile: String,
    },
    /// Run a command inside an instance's sandbox.
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
    /// List instances.
    List,
    /// List profiles from every layer: user, system and built-in.
    Profiles {
        /// Also print the layer each name resolves to and the file it is
        /// read from, tab separated; `-` for a built-in.
        #[arg(long)]
        origin: bool,
    },
    /// Delete an instance and its private home. Irreversible.
    Delete {
        /// Instance name.
        name: String,
        /// Required: confirms deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Open an instance's config.kdl in $VISUAL or $EDITOR, then re-check it.
    Edit {
        /// Instance name.
        name: String,
    },
    /// Show, edit or lint one profile.
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Re-seed an instance's config.kdl from its profile, keeping `home/`.
    Reseed {
        /// Instance name.
        name: String,
    },
    /// Check an instance's config.kdl for grants wider than it likely means.
    Lint {
        /// Instance name.
        name: String,
        #[command(flatten)]
        opts: LintOpts,
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
    Show {
        /// Profile name.
        name: String,
    },
    /// Open your layer's copy in $VISUAL or $EDITOR, then re-resolve it.
    /// A name you do not have yet is written with a starting point first.
    Edit {
        /// Profile name.
        name: String,
    },
    /// Check a profile, flattened through its layers, for grants wider
    /// than it likely means.
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
    match real_main() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("bubbler: {e:#}");
            ExitCode::from(1)
        }
    }
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

fn real_main() -> Result<i32> {
    // Before anything else opens a descriptor.
    host_env::fill_closed_stdio()?;
    let cli = Cli::parse();
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
            // the terminal mode its default here, rather than the exec.
            let mode = tty.unwrap_or_else(|| {
                Instance::open(&env, &name).map_or_else(|_| TtyMode::default(), |i| i.config.tty)
            });
            launcher::exec(&env, &name, &command, mode)
                .with_context(|| format!("executing in instance `{name}`"))
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
            Ok(0)
        }
        Cmd::Edit { name } => {
            let (program, args) = editor_argv()?;
            let path = instance::config_path_checked(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            if let Some(code) = run_editor(&program, &args, &path)? {
                return Ok(code);
            }
            let code = recheck(&path, Instance::open(&env, &name));
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
    }
}
