//! bubbler command line: create, run, edit, delete and list sandbox instances.

mod host_env;

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bubbler_core::config::Service;
use bubbler_core::error::{ConfigError, LaunchError};
use bubbler_core::exec;
use bubbler_core::instance::{self, Instance};
use bubbler_core::launcher;
use bubbler_core::profile;
use bubbler_core::tty::{self, TtyMode};
use clap::{Parser, Subcommand};

/// `--tty` takes the names the config's `tty` node takes; clap already
/// says which value was rejected, so only the reason is passed on.
fn tty_mode(s: &str) -> Result<TtyMode, String> {
    TtyMode::from_str(s).map_err(|e| match e {
        ConfigError::BadArgument { reason, .. } => reason,
        other => other.to_string(),
    })
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
        #[arg(long, value_name = "NAME")]
        keep: Option<String>,
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
    /// Show or edit one profile.
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Re-seed an instance's config.kdl from its profile, keeping `home/`.
    Reseed {
        /// Instance name.
        name: String,
    },
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

fn real_main() -> Result<i32> {
    // Before anything else opens a descriptor.
    host_env::fill_closed_stdio()?;
    let cli = Cli::parse();
    let env = host_env::from_process()?;
    match cli.cmd {
        Cmd::Create { name, profile } => {
            let inst = Instance::create(&env, &name, &profile)
                .with_context(|| format!("creating instance `{name}`"))?;
            print_lines(&[inst.dir.as_os_str()], "the instance directory")
        }
        Cmd::Run {
            name,
            dry_run,
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
            if dry_run {
                // A dry run describes a fresh start and never touches a
                // live instance, so the liveness check is skipped here.
                // The argv still depends on this terminal: `--ctty` is
                // there exactly when a real run would allocate a pty for
                // the sandbox's stdin.
                let ctty = tty::plan(mode, tty::host_is_tty()).ctty();
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
            tty,
            command,
        } => {
            let grants: Vec<&str> = grants.iter().map(String::as_str).collect();
            let mut eph = Instance::ephemeral(&env, &profile, &grants)
                .context("creating a throwaway sandbox")?;
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
            Ok(recheck(&path, Instance::open(&env, &name)))
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
                Ok(recheck(&path, profiles.resolve(&name)))
            }
        },
        Cmd::Reseed { name } => {
            let inst = Instance::reseed(&env, &name)
                .with_context(|| format!("reseeding instance `{name}`"))?;
            let path = inst.config_path();
            print_lines(&[path.as_os_str()], "the config path")
        }
    }
}
