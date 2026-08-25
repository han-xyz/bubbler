//! Wayland wire proxy: sits between a sandboxed client and the socket bubbler
//! gives it, so a clipboard read can be tied to recent user input and an
//! interface the tables do not describe can be kept out of the registry.
//!
//! The relay and its argv parser arrive with the next step; until then the
//! binary refuses to run rather than pretending to proxy anything.

#![forbid(unsafe_code)]

use std::process::ExitCode;

/// The one usage line, so a grammar error always names the whole grammar.
const USAGE: &str = "bubbler-wl-proxy: usage: --listen-fd N --upstream PATH \
                     [--gate paste|open] [--fallback-deny] [--log-fd N]";

fn main() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}
