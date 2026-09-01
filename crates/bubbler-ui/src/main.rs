//! bubbler-ui: the terminal editor for bubbler instances.
//!
//! It shows what a grant costs next to the toggle that gives it, which is
//! the one thing a config file cannot do, and hands every action — every
//! launch, every deletion, every editor — to the `bubbler` binary. So the
//! CLI stays the only thing that starts a sandbox, and this program is
//! what reads the store and draws it.

mod app;
mod cli;
mod detail;
mod draw;
mod env;
mod input;
mod store;
mod term;

#[cfg(test)]
mod fixture;

use std::io::{IsTerminal, Write};
use std::process::{Child, ExitCode};
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bubbler_core::safe_text;
use ratatui::crossterm::event;

use crate::app::{Action, App};
use crate::cli::Cli;
use crate::store::Store;
use crate::term::Term;

/// How long the loop waits for a key before looking at the world again.
/// One second, because the only thing a tick does is probe each
/// instance's control socket, and a running sandbox is not news that
/// needs to arrive faster.
const TICK: Duration = Duration::from_secs(1);

/// What `--help` prints. `bubbler-ui` takes no options of its own: the
/// editor is the interface.
const USAGE: &str = "\
bubbler-ui — edit bubbler instances, with what each grant costs beside it

usage: bubbler-ui [--help] [--version]

Started by `bubbler ui`, and on its own from a terminal. It reads the
instance store and runs the `bubbler` binary beside it for every action:
`?` in the editor lists the keys.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The error quotes the store it read: an instance name, a
            // config value, a path — none of them this program's own.
            let mut err = std::io::stderr().lock();
            let text = format!("bubbler-ui: {e:#}\n");
            let bytes = match err.is_terminal() {
                true => safe_text::render(text.as_bytes()),
                false => text.into_bytes(),
            };
            let _ = err.write_all(&bytes);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    // Read rather than parsed: the editor is the interface, and the two
    // options here are the ones every binary answers.
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("bubbler-ui {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(other) => bail!("unknown argument `{other}`; bubbler-ui takes none"),
    }
    let env = env::from_process()?;
    let bubbler = cli::locate(&env::search_path()).with_context(|| {
        format!(
            "no `{}` binary beside this one or on PATH; the editor runs it for every action",
            cli::BINARY
        )
    })?;
    let store = Store::load(&env).context("reading the instance store")?;
    let mut app = App::new(env, store);
    app.say(format!("driving {}", bubbler.display()));
    let cli = Cli::new(bubbler);
    // Before the terminal is taken, and before ratatui's own hook would
    // be installed by anything: a panic must find the terminal restored.
    term::install_panic_hook();
    let stop = term::stop_flag().context("registering the signal handlers")?;
    let mut terminal = term::enter().context("taking the terminal")?;
    let ended = event_loop(&mut terminal, &mut app, &cli, &stop);
    // Whatever ended it, the terminal goes back before the error does.
    let restored = term::leave();
    ended?;
    restored.context("restoring the terminal")
}

/// Draw, wait for a key or a tick, act. No threads: `poll` is the whole
/// scheduler, and the only thing that happens without a key is the
/// liveness probe.
fn event_loop(
    terminal: &mut Term,
    app: &mut App,
    cli: &Cli,
    stop: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    let mut started: Vec<Child> = Vec::new();
    while !app.quit {
        // What a page is, for the viewer: the body between the header,
        // the footer and the viewer's own border.
        let height = terminal
            .size()
            .context("asking the terminal its size")?
            .height;
        app.page = usize::from(height.saturating_sub(4)).max(1);
        terminal
            .draw(|frame| {
                frame.render_widget(&*app, frame.area());
                if let Some(at) = draw::cursor(app, frame.area()) {
                    frame.set_cursor_position(at);
                }
            })
            .context("drawing")?;
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // A sandbox started from here is nobody's to wait for, but its
        // exit status is this process's to collect.
        started.retain_mut(|child| !matches!(child.try_wait(), Ok(Some(_))));
        let ready = match event::poll(TICK) {
            Ok(ready) => ready,
            // A signal interrupted the wait; the flag above says whether
            // it was one that ends the editor.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("waiting for a key"),
        };
        if !ready {
            app.tick();
            continue;
        }
        let event = event::read().context("reading a key")?;
        // Presses only: a terminal that has negotiated the Kitty keyboard
        // protocol — kitty and foot do — also reports releases and
        // repeats, and every key would otherwise act twice.
        let Some(key) = event.as_key_press_event() else {
            continue;
        };
        if let Some(action) = app.on_key(key) {
            perform(terminal, app, cli, action, &mut started)?;
        }
    }
    Ok(())
}

/// Spend what a keystroke asked for.
fn perform(
    terminal: &mut Term,
    app: &mut App,
    cli: &Cli,
    action: Action,
    started: &mut Vec<Child>,
) -> Result<()> {
    match action {
        Action::Quit => app.quit = true,
        Action::Reload => {
            app.reload();
            app.say("read the store again");
        }
        Action::Detached(args) => match cli.detached(&args) {
            Ok(child) => started.push(child),
            Err(e) => app.say(format!("could not start it: {e}")),
        },
        Action::Attached(args) => {
            // The editor's raw mode has to be off before the command's
            // own terminal handling goes on, or two owners fight over the
            // same termios.
            term::leave().context("giving the terminal to the command")?;
            let ended = cli.attached(&args);
            // A fresh terminal draws the whole screen on the next frame,
            // so there is nothing to clear. `Terminal::clear` would ask
            // the terminal where its cursor is and wait for the answer,
            // which never comes when the editor is being driven by a
            // script rather than typed at.
            *terminal = term::enter().context("taking the terminal back")?;
            match ended {
                Ok(status) if status.success() => app.say("done"),
                Ok(status) => app.say(match status.code() {
                    Some(code) => format!("it exited {code}"),
                    None => "it was killed by a signal".to_owned(),
                }),
                Err(e) => app.say(format!("could not run it: {e}")),
            }
            app.reload();
        }
        Action::Capture {
            title,
            args,
            explain,
        } => match cli.captured(&args) {
            Ok(out) => {
                let mut lines = out.lines();
                if !out.status.success() && lines.is_empty() {
                    lines.push(match out.status.code() {
                        Some(code) => format!("it exited {code}"),
                        None => "it was killed by a signal".to_owned(),
                    });
                }
                // A one-line answer — a path written, an instance gone —
                // is the status line's, not a screen of its own.
                match (lines.len() > 1, explain) {
                    (false, None) => app.say(lines.first().cloned().unwrap_or(title)),
                    (_, explain) => app.show(title, lines, explain),
                }
                app.reload();
            }
            Err(e) => app.say(format!("could not run it: {e}")),
        },
    }
    Ok(())
}
