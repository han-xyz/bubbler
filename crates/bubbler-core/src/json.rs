//! JSON literals for the commands that speak it: `lint --format json` and
//! `--explain --format json`. Both write their objects by hand — the
//! shapes are fixed and small — and both need the same string escaping,
//! which is the one thing in a hand-written encoder that is easy to get
//! subtly wrong.

/// `s` as a JSON string literal.
///
/// Every control character is escaped, `DEL` and the C1 range included:
/// a value out of a config bubbler did not write reaches a terminal
/// through the reader of this JSON, and U+009B is a one-character CSI
/// that a terminal acts on exactly as `ESC [` would.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_control_character_is_escaped_not_only_the_low_ones() {
        assert_eq!(string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(string("a\nb\tc\rd"), "\"a\\nb\\tc\\rd\"");
        // `DEL` and the C1 controls are what a `c < 0x20` test misses;
        // U+009B is a CSI on its own.
        assert_eq!(string("a\u{7f}b"), "\"a\\u007fb\"");
        assert_eq!(string("a\u{9b}31mb"), "\"a\\u009b31mb\"");
        assert_eq!(string("a\u{1b}[31mb"), "\"a\\u001b[31mb\"");
        // Ordinary text, including text outside ASCII, is left as it is.
        assert_eq!(string("héllo →"), "\"héllo →\"");
    }
}
