//! Syscall names from a `seccomp` node, through to a compiled filter.
//!
//! This is the one bubbler path that crosses into C: the names reach
//! `libseccomp`, which resolves them per architecture and emits the
//! cBPF that bwrap installs. A name the table does not hold must be a
//! refusal, and a filter that compiles must be a length bwrap accepts.

#![no_main]

use bubbler_core::seccomp::{self, Errno, RuleSet, SeccompConfig};
use libfuzzer_sys::fuzz_target;

/// Names per run. Compiling crosses into `libseccomp` for each of them
/// on every architecture in the filter, so the list is kept short
/// enough that the fuzzer measures the parser and not the assembler.
const MAX_NAMES: usize = 16;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let names: Vec<&str> = text.split_whitespace().take(MAX_NAMES).collect();
    let mut cfg = SeccompConfig::default();
    for (i, name) in names.iter().enumerate() {
        if seccomp::syscall_number(name).is_none() {
            continue;
        }
        // Alternating: `allow` takes names out of the default denylist
        // and `deny` puts them back with an errno, and the two lists are
        // applied in that order.
        match i % 2 {
            0 => cfg.allow.push((*name).to_owned()),
            _ => cfg.deny.push(((*name).to_owned(), Errno::Enosys)),
        }
    }
    let Some(set) = RuleSet::with(&cfg) else {
        return;
    };
    let Ok(Some(program)) = seccomp::compile(&set, false) else {
        return;
    };
    // bwrap rejects a filter whose length is not a whole number of
    // `struct sock_filter`, and a filter it rejects is a sandbox that
    // never starts.
    assert_eq!(program.bytes.len() % 8, 0, "filter is not a whole program");
});
