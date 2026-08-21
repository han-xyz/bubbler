//! Taking the terminal and giving it back.
//!
//! Three ways out and all of them restore it: the ordinary one, a panic,
//! and a signal. The signal path is a flag the loop reads rather than a
//! handler that writes to the terminal, because almost nothing is safe to
//! call from a signal handler and restoring a terminal is not among it.

use std::io::{self, Stdout, stdout};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::ExecutableCommand;
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

/// The terminal the editor draws on.
pub type Term = Terminal<CrosstermBackend<Stdout>>;

/// The signals that end the editor. Caught rather than fatal because the
/// terminal is the editor's to give back: killed in raw mode, it would
/// leave the user without an echo.
const STOP_SIGNALS: [i32; 3] = [SIGINT, SIGTERM, SIGHUP];

/// Raw mode and the alternate screen, and a terminal drawing on them.
pub fn enter() -> io::Result<Term> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout()))
}

/// Give the terminal back. Raw mode goes first: it has more side effects
/// than the alternate screen, so it is the one that must not be left on
/// if a later step fails. The cursor is shown again before the screen is
/// left, because a frame with a dialog on it hid the cursor, and a shell
/// with no cursor is what the user would be handed otherwise. Idempotent,
/// so the panic hook and the signal path can call it and the ordinary
/// path still runs.
pub fn leave() -> io::Result<()> {
    let raw = disable_raw_mode();
    let shown = stdout().execute(Show).map(|_| ());
    stdout().execute(LeaveAlternateScreen)?;
    raw.and(shown)
}

/// Restore the terminal before anything else a panic does, so the message
/// is printed on a terminal that echoes and scrolls.
pub fn install_panic_hook() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = leave();
        hook(info);
    }));
}

/// A flag the loop reads: set once one of [`STOP_SIGNALS`] arrives, so
/// the editor leaves by its own path — within one tick, which is the poll
/// timeout — rather than dying in raw mode.
pub fn stop_flag() -> io::Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    for signal in STOP_SIGNALS {
        signal_hook::flag::register(signal, Arc::clone(&stop))?;
    }
    Ok(stop)
}
