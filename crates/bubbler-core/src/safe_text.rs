//! Bytes bubbler did not write, made safe to put on a terminal.
//!
//! A log is the sandbox's own output and an explanation echoes the
//! values a config holds, and a terminal *acts* on the control sequences
//! in either: an OSC 52 in `last-run.log` writes the reader's clipboard,
//! a `\x1b[2J` clears the screen the log was asked for, and a title
//! sequence renames the window. Reading a record is not replaying it, so
//! the control characters are shown rather than sent.
//!
//! Only what reaches a terminal is rendered; the caller decides. A pipe
//! is a tool on the other end and gets the bytes as they are.

/// Render the control characters in `bytes` so a terminal shows them
/// instead of acting on them: C0 and `DEL` in caret notation (`ESC` is
/// `^[`), C1 controls and bytes that are not UTF-8 as `\xNN`, everything
/// else unchanged. `\n` and `\t` are left alone — they are what a log is
/// laid out with, and a terminal that acts on them is doing what the
/// reader wants.
///
/// C1 is decoded rather than matched byte for byte: `U+0080`–`U+009F` are
/// the controls, while the same byte values inside a longer sequence are
/// ordinary text (`\u{201c}` is `e2 80 9c`), and escaping those would
/// mangle every quotation mark a log holds.
///
/// The rendering is not reversible: a log that held the two characters
/// `^` and `[` reads the same as one that held an `ESC`. That is
/// `cat -v`'s bargain, and the reason the raw bytes still go to a pipe.
pub fn render(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        let (text, raw) = match std::str::from_utf8(rest) {
            Ok(text) => (text, 0),
            Err(e) => {
                let text = std::str::from_utf8(&rest[..e.valid_up_to()])
                    .expect("valid_up_to names a prefix that decoded");
                // A sequence cut short by the end of the input is as
                // unreadable as an invalid one: the bytes are all there is.
                let raw = e.error_len().unwrap_or(rest.len() - e.valid_up_to());
                (text, raw)
            }
        };
        for c in text.chars() {
            push_char(&mut out, c);
        }
        let end = text.len() + raw;
        for b in &rest[text.len()..end] {
            push_hex(&mut out, *b);
        }
        rest = &rest[end..];
    }
    out
}

/// One character as a terminal may see it.
fn push_char(out: &mut Vec<u8>, c: char) {
    match c {
        '\n' | '\t' => out.push(c as u8),
        // Caret notation, as `cat -v` writes it: the control's own bit 6
        // flipped, which turns `ESC` into `[` and `DEL` into `?`.
        '\0'..='\x1f' | '\x7f' => out.extend_from_slice(&[b'^', (c as u8) ^ 0x40]),
        // C1 has no caret notation, and a terminal acts on these too:
        // `\u{9b}` is the one-character CSI.
        '\u{80}'..='\u{9f}' => push_hex(out, c as u8),
        c => out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
    }
}

/// One byte as `\xNN`, lowercase, so it reads as the escape a shell or a
/// Rust literal would spell the same way.
fn push_hex(out: &mut Vec<u8>, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(&[
        b'\\',
        b'x',
        HEX[usize::from(b >> 4)],
        HEX[usize::from(b & 0xf)],
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(bytes: &[u8]) -> String {
        String::from_utf8(render(bytes)).expect("the rendering is text")
    }

    #[test]
    fn a_terminal_is_shown_the_control_characters_instead_of_acting_on_them() {
        // The sequence this exists for: OSC 52 writes the clipboard of
        // whoever reads the log.
        assert_eq!(rendered(b"\x1b]52;c;aGk=\x07"), "^[]52;c;aGk=^G");
        // Every C0, and DEL, in caret notation.
        assert_eq!(rendered(b"\0\x01\x1b\x1f\x7f"), "^@^A^[^_^?");
        // The two a log is laid out with are left alone; a carriage
        // return is not one of them, since it overwrites what it follows.
        assert_eq!(rendered(b"a\tb\nc\rd"), "a\tb\nc^Md");
    }

    #[test]
    fn text_is_passed_through_and_only_the_c1_controls_are_escaped() {
        // Curly quotes are `e2 80 9c` and `e2 80 9d`: bytes in the C1
        // range that are not C1 controls, and mangling them would make
        // the rendering worse than useless on ordinary output.
        assert_eq!(
            rendered("a “quoted” café ☃".as_bytes()),
            "a “quoted” café ☃"
        );
        // The C1 controls themselves, as UTF-8: CSI and OSC.
        assert_eq!(rendered("\u{9b}31m\u{9d}".as_bytes()), "\\x9b31m\\x9d");
        // And as the bare bytes a latin-1 log holds, which are not UTF-8
        // at all. So is every other byte no sequence can start.
        assert_eq!(rendered(b"\x9b31m"), "\\x9b31m");
        assert_eq!(rendered(b"\xff\xfe"), "\\xff\\xfe");
    }

    #[test]
    fn a_sequence_the_log_stops_in_the_middle_of_is_shown_as_its_bytes() {
        // The cap in `run_log` cuts the output at a byte, so the last
        // character of a full log is regularly half of one.
        assert_eq!(rendered("caf\u{e9}".as_bytes()), "café");
        assert_eq!(rendered(b"caf\xc3"), "caf\\xc3");
        // Text on both sides of the damage is still text.
        assert_eq!(rendered(b"caf\xc3 au lait"), "caf\\xc3 au lait");
        assert!(render(b"").is_empty());
    }
}
