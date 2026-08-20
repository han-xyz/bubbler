//! bubbler command line: create, run and list sandbox instances.

mod host_env;

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use anyhow::{Context, Result};
use bubbler_core::config::Service;
use bubbler_core::instance::Instance;
use bubbler_core::launcher;
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
        /// Instance name: letters, digits, `.`, `_`, `-`.
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
    /// List instances.
    List,
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

fn write_argv(out: &mut dyn Write, argv: &[OsString]) -> io::Result<()> {
    out.write_all(b"bwrap\n")?;
    for a in argv {
        out.write_all(a.as_bytes())?;
        out.write_all(b"\n")?;
    }
    out.flush()
}

/// Print the argv one element per line, byte for byte: argv is not UTF-8
/// and a lossy rendering would not be the audit trail it claims to be. A
/// reader that closed the pipe early (`| head`) is a normal end, not a
/// failure.
fn print_argv(argv: &[OsString]) -> Result<i32> {
    match write_argv(&mut io::stdout().lock(), argv) {
        Ok(()) => Ok(0),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Err(e) => Err(e).context("writing the bwrap argv"),
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    let env = host_env::from_process()?;
    match cli.cmd {
        Cmd::Create { name, profile } => {
            let inst = Instance::create(&env, &name, &profile)
                .with_context(|| format!("creating instance `{name}`"))?;
            println!("{}", inst.dir.display());
            Ok(0)
        }
        Cmd::Run {
            name,
            dry_run,
            command,
        } => {
            let inst = Instance::open(&env, &name)
                .with_context(|| format!("opening instance `{name}`"))?;
            let command = (!command.is_empty()).then_some(command.as_slice());
            if dry_run {
                let argv = launcher::build_argv(&env, &inst, command)
                    .context("building bwrap arguments")?;
                return print_argv(&argv);
            }
            if inst.has_service(&Service::X11) {
                eprintln!("bubbler: warning: x11 grants no isolation between X clients");
            }
            launcher::run(&env, &inst, command)
                .with_context(|| format!("running instance `{name}`"))
        }
        Cmd::List => {
            for n in Instance::list(&env).context("listing instances")? {
                println!("{n}");
            }
            Ok(0)
        }
    }
}
