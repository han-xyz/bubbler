//! The exec request decoder inside the sandbox.
//!
//! `bubbler-init` reads this off a socket the launcher passed it. The
//! socket is bound on the host and never appears inside, so this is not
//! an attacker-facing decoder — it is fuzzed because a decoder that
//! walks a length field is worth a few million executions either way.

#![no_main]

use bubbler_init::proto;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(req) = proto::decode_request(data) else {
        return;
    };
    // Decoding and encoding are one bijection: re-encoding what was
    // decoded gives the bytes back, so no argument was dropped or
    // silently merged into its neighbour.
    let argv: Vec<&std::ffi::OsStr> = req.argv.iter().map(std::ffi::OsString::as_os_str).collect();
    let again = proto::encode_request(&argv, req.flags);
    assert_eq!(again.as_slice(), data, "decode/encode is not a bijection");
});
