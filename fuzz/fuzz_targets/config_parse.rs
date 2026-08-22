//! `config.kdl` and profile-layer text, straight from the fuzzer.
//!
//! The parser decides what a sandbox grants, and it reads files a
//! distro ships as well as ones the user wrote. It has to answer on
//! anything, which is what this target checks: an error is a pass, a
//! panic or an abort is not.

#![no_main]

use bubbler_core::config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Both entry points: an instance config refuses `include`, a profile
    // layer takes it, so the two walk different arms of the same parser.
    let _ = config::parse(text);
    let _ = config::parse_profile(text);
    // `--explain` names the line a grant came from, and asks for the
    // spans of the very same text.
    let _ = config::node_lines(text);
});
