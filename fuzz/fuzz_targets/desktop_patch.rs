//! The desktop-entry patcher, over `.desktop` files from the fuzzer.
//!
//! `bubbler desktop` reads an entry a packager wrote and rewrites its
//! `Exec` lines to go through the sandbox. The marker key it adds is
//! what stops the result from being patched a second time, and a second
//! patch would mean a launcher entry starting a sandbox inside a
//! sandbox.

#![no_main]

use std::path::Path;

use bubbler_core::desktop;
use bubbler_core::error::DesktopError;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let program = Path::new("/usr/bin/bubbler");
    let Ok(out) = desktop::patch(text, "inst", program) else {
        return;
    };
    assert_eq!(desktop::owner(&out), Some("inst"), "no marker key written");
    assert!(
        matches!(desktop::patch(&out, "inst", program), Err(DesktopError::Generated(o)) if o == "inst"),
        "a generated entry was patched a second time"
    );
});
