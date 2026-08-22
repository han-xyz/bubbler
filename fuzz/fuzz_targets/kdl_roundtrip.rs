//! `parse` -> `render` -> `parse` over fuzzer-grown configuration text.
//!
//! The property this holds is the one nothing else detects: a config
//! whose canonical form parses back as *different* grants is a sandbox
//! that differs from the file describing it. A profile is flattened
//! through exactly this path before an instance is seeded from it.

#![no_main]

use bubbler_core::{config, kdl_out};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(cfg) = config::parse(text) else {
        return;
    };
    let rendered = kdl_out::render(&cfg).expect("a parsed config renders");
    let back = config::parse(&rendered).expect("the canonical form parses");
    assert_eq!(back, cfg, "round trip changed the grants:\n{rendered}");
    // Rendering is a fixed point after the first pass: the second
    // rendering of the same grants is the same text.
    let again = kdl_out::render(&back).expect("a parsed config renders");
    assert_eq!(again, rendered, "rendering is not stable");
});
