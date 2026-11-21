//! Bytes bubbler did not write, made safe to put on a terminal.
//!
//! Reading a record is not replaying it, so the control characters are
//! shown rather than sent.
//!
//! Only what reaches a terminal is rendered; the caller decides. A pipe
//! is a tool on the other end and gets the bytes as they are.

use std::borrow::Cow;

/// Render the control characters in `bytes` so a terminal shows them
/// instead of acting on them: C0 and `DEL` in caret notation (`ESC` is
/// `^[`), C1 controls and bytes that are not UTF-8 as `\xNN`, everything
/// else unchanged. `\n` and `\t` are left alone — they are what a log is
/// laid out with, and a terminal that acts on them is doing what the
/// reader wants.
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

// One byte as `\xNN`, lowercase, so it reads as the escape a shell or a
// Rust literal would spell the same way.
fn push_hex(out: &mut Vec<u8>, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(&[
        b'\\',
        b'x',
        HEX[usize::from(b >> 4)],
        HEX[usize::from(b & 0xf)],
    ]);
}

/// `s` with everything a terminal would act on replaced by `?`: every C0
/// control but `\n` and `\t`, `DEL`, the C1 controls, and any sequence an
/// `ESC` introduces — a CSI, an OSC up to its `BEL` or string
/// terminator, an APC, and a lone `ESC` — each whole sequence becoming
/// one `?`. Text that holds nothing to replace is borrowed rather than
/// rebuilt.
pub fn sanitize(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_replacing) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' | '\t' => out.push(c),
            '\x1b' => {
                out.push('?');
                skip_sequence(&mut chars);
            }
            c if needs_replacing(c) => out.push('?'),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

fn needs_replacing(c: char) -> bool {
    match c {
        '\n' | '\t' => false,
        '\0'..='\x1f' | '\x7f' | '\u{80}'..='\u{9f}' => true,
        _ => false,
    }
}

// Step past the rest of the sequence an `ESC` opened, so the whole of it
// is the one `?` already written. A CSI ends at its final byte
// (`0x40`–`0x7e`), an OSC, APC, PM or DCS at `BEL` or at the string
// terminator `ESC \`, and anything else is a two-character escape whose
// second character is ordinary text.
fn skip_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.peek() {
        Some('[') => {
            chars.next();
            while let Some(c) = chars.peek() {
                let end = ('\u{40}'..='\u{7e}').contains(c);
                chars.next();
                if end {
                    return;
                }
            }
        }
        Some(']' | '_' | '^' | 'P') => {
            chars.next();
            while let Some(c) = chars.next() {
                if c == '\x07' {
                    return;
                }
                if c == '\x1b' && chars.peek() == Some(&'\\') {
                    chars.next();
                    return;
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(bytes: &[u8]) -> String {
        String::from_utf8(render(bytes)).expect("the rendering is text")
    }

    #[test]
    fn a_terminal_sequence_becomes_one_question_mark() {
        // The shape CVE-2023-28101 is about: a control sequence carried
        // in a name that something else prints.
        assert_eq!(sanitize("a\x1b[2Jb"), "a?b");
        assert_eq!(sanitize("\x1b]0;retitled\x07x"), "?x");
        assert_eq!(sanitize("\x1b]52;c;cGF5bG9hZA==\x1b\\"), "?");
        assert_eq!(sanitize("\x1b_apc\x1b\\"), "?");
        // An ESC that begins nothing is still not sent on.
        assert_eq!(sanitize("\x1b"), "?");
        assert_eq!(sanitize("\x1bZ"), "?Z");
    }

    #[test]
    fn the_control_characters_a_reader_wants_are_left_alone() {
        assert_eq!(sanitize("one\ntwo\tthree"), "one\ntwo\tthree");
        assert_eq!(sanitize("a\rb\x00c\x7fd"), "a?b?c?d");
        // C1 is a control too: `\u{9b}` is a one-character CSI.
        assert_eq!(sanitize("a\u{9b}2Jb"), "a?2Jb");
        // And ordinary text is borrowed, not rebuilt.
        assert!(matches!(sanitize("plain 文字"), Cow::Borrowed(_)));
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
