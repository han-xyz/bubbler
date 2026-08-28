//! The DNS answer parser of `bubbler-net-proxy`.
//!
//! The proxy carries its own resolver because NSS inside the sandbox's
//! mount namespace is the application's to answer. What that buys is a
//! parser walking compression pointers and length fields through a
//! message this process did not write, on the one thread that decides
//! where a tunnel goes — so it is fuzzed like the request parser beside
//! it.

#![no_main]

use bubbler_net_proxy::dns;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(reply) = dns::parse(data) else {
        return;
    };
    // Every address came from a record, and the records are capped.
    assert!(
        reply.addresses.len() <= dns::MAX_RECORDS,
        "more addresses than records were read"
    );
    // Names are decompressed into a bound, whatever the pointers said.
    assert!(reply.question.0.len() <= 2 * 255, "a name past the bound");
    assert_eq!(
        reply.question.0,
        reply.question.0.to_ascii_lowercase(),
        "the name was not folded"
    );
    // One message, one answer: nothing here depends on how often it is
    // read.
    let again = dns::parse(data).expect("the same bytes parse again");
    assert_eq!(again, reply, "the same message gave two answers");
});
