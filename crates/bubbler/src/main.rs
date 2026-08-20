//! bubbler command line: create, run, edit, delete and list sandbox instances.

mod host_env;

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use bubbler_core::config::Service;
use bubbler_core::error::LaunchError;
use bubbler_core::exec;
use bubbler_core::instance::{self, Instance};
use bubbler_core::launcher;
use bubbler_core::profile;
use clap::{Parser, Subcommand};

/// bubblewrap-based application sandbox.
#[derive(Parser)]
#[command(name = "bubbler", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new instance from a built-in profile.
    Create {
        /// Instance name: letters, digits, `.`, `_`, `-`; not `.`, `..`
        /// or a name starting with `-`.
        name: String,
        /// Built-in profile to seed config.kdl from.
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
        /// Command to run; replaces the config's `command`.
        #[arg(last = true)]
        command: Vec<OsString>,
    },
    /// Run a command in a throwaway sandbox, without creating an instance.
    Try {
        /// Built-in profile to seed the throwaway config from.
        #[arg(long, default_value = "generic")]
        profile: String,
        /// Grant one service on top of the profile; repeatable.
        #[arg(long = "grant", value_name = "SERVICE")]
        grants: Vec<String>,
        /// Keep the sandbox afterwards as an instance with this name.
        #[arg(long, value_name = "NAME")]
        keep: Option<String>,
        /// Command to run; replaces the profile's `command`.
        #[arg(last = true)]
        command: Vec<OsString>,
    },
    /// Run a command inside an already running instance.
    Exec {
        /// Instance name.
        name: String,
        /// Command to run inside it, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// List instances.
    List,
    /// List built-in profiles.
    Profiles,
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

fn real_main() -> Result<i32> {
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
            command,
        } => {
            let inst = Instance::open(&env, &name).with_context(|| {
                format!(
                    "opening instance `{name}` ({})",
                    instance::config_path(&env, &name).display()
                )
            })?;
            let command = (!command.is_empty()).then_some(command.as_slice());
            if dry_run {
                // A dry run describes a fresh start and never touches a
                // live instance, so the liveness check is skipped here.
                let argv = launcher::build_argv(
                    &env,
                    &inst,
                    command,
                    &mut launcher::DryRunAlloc::default(),
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
                return exec::run_in(&stream, command)
                    .with_context(|| format!("executing in instance `{name}`"));
            }
            if inst.has_service(&Service::X11) {
                eprintln!("bubbler: warning: x11 grants no isolation between X clients");
            }
            launcher::run(&env, &inst, command)
                .with_context(|| format!("running instance `{name}`"))
        }
        Cmd::Try {
            profile,
            grants,
            keep,
            command,
        } => {
            let grants: Vec<&str> = grants.iter().map(String::as_str).collect();
            let mut eph = Instance::ephemeral(&env, &profile, &grants)
                .context("creating a throwaway sandbox")?;
            if let Some(name) = &keep {
                eph.keep_as(name)
                    .with_context(|| format!("keeping the sandbox as instance `{name}`"))?;
            }
            if eph.instance.has_service(&Service::X11) {
                eprintln!("bubbler: warning: x11 grants no isolation between X clients");
            }
            let command = (!command.is_empty()).then_some(command.as_slice());
            let code = launcher::run(&env, &eph.instance, command);
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
        Cmd::Exec { name, command } => {
            // Checked, not opened: a running instance can be reached even
            // while its config.kdl is mid-edit and would not parse.
            instance::config_path_checked(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            launcher::exec(&env, &name, &command)
                .with_context(|| format!("executing in instance `{name}`"))
        }
        Cmd::List => {
            let names = Instance::list(&env).context("listing instances")?;
            let lines: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
            print_lines(&lines, "the instance list")
        }
        Cmd::Profiles => {
            let lines: Vec<&OsStr> = profile::NAMES.iter().map(OsStr::new).collect();
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
            let path = instance::config_path_checked(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            let editor = host_env::editor().context("neither VISUAL nor EDITOR is set")?;
            // $VISUAL/$EDITOR is split into argv, never passed to a shell.
            let mut parts = editor
                .as_bytes()
                .split(u8::is_ascii_whitespace)
                .filter(|p| !p.is_empty());
            let program = parts.next().context("VISUAL or EDITOR is blank")?;
            let status = Command::new(OsStr::from_bytes(program))
                .args(parts.map(OsStr::from_bytes))
                .arg(&path)
                .status()
                .with_context(|| format!("running editor {}", String::from_utf8_lossy(program)))?;
            if !status.success() {
                return Ok(launcher::exit_code(status));
            }
            match Instance::open(&env, &name) {
                Ok(_) => Ok(0),
                Err(e) => {
                    let e = anyhow::Error::new(e)
                        .context(format!("{} still has errors", path.display()));
                    eprintln!("bubbler: {e:#}");
                    Ok(1)
                }
            }
        }
    }
}
