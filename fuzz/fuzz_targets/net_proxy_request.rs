//! The `CONNECT` request parser of `bubbler-net-proxy`.
//!
//! These bytes come off a socket the sandboxed application connects to,
//! and this parser is the whole of what stands between them and a
//! tunnel out of the network namespace. A panic here is a proxy that
//! stops serving; a wrong answer is an egress filter that let the wrong
//! name through.

#![no_main]

use bubbler_net_proxy::connect;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = connect::parse(data) else {
        return;
    };
    // The offset the tunnel starts at is an offset into these bytes,
    // and the caller hands everything past it upstream unread.
    assert!(request.consumed <= data.len(), "consumed past the buffer");
    assert!(!request.host.is_empty(), "an empty name was accepted");
    assert!(request.port > 0, "port 0 was accepted");
    assert_eq!(
        request.host,
        request.host.to_ascii_lowercase(),
        "the name was not folded"
    );
    // Nothing behind the blank line changes the decision: the same
    // request without its tunnel bytes parses to the same target.
    let again = connect::parse(&data[..request.consumed]).expect("the request on its own");
    assert_eq!(again, request, "the tunnel bytes changed the answer");
});
