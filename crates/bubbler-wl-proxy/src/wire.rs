//! The Wayland wire format: an 8-byte header, then arguments laid out by the
//! message's signature.
//!
//! The wire is native-endian: libwayland and every Rust client read and write
//! machine order, and the socket never leaves the machine.
//!
//! The size field is 16 bits and a message is a whole number of 4-byte words,
//! so one message declares at most 65532 bytes. A relay's read buffer has to
//! hold a maximal message, or a message that large can never be completed.
//!
//! Everything here is byte-exact on purpose. The relay decodes a message,
//! decides what to do with it, and re-encodes it; if the two halves disagreed
//! by a byte the compositor and the client would see different messages.

use std::ffi::CString;

use crate::tables::ArgKind;

/// Bytes of the fixed message header: object id, then opcode and size.
pub const HEADER: usize = 8;

/// What went wrong reading or writing a message. Every variant is a reason to
/// stop relaying that connection rather than to guess.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// The buffer holds only part of the message; read more and retry.
    #[error("the buffer holds only part of the message")]
    NeedMore,
    /// The header's size field is under 8 bytes or not a whole number of words.
    #[error("message size {0} is not a whole number of 4-byte words of at least {HEADER}")]
    BadSize(u16),
    /// An argument runs past the end of the message the header declared.
    #[error("an argument runs past the end of the message")]
    Truncated,
    /// The signature left bytes unread: the sender's idea of the message and
    /// the tables' disagree, which is exactly what must never be forwarded.
    #[error("{0} bytes left over after the arguments")]
    Trailing(usize),
    /// A string argument is not NUL-terminated, or hides a NUL in the middle
    /// where a C reader would stop early and see a different string.
    #[error("a string argument is not NUL-terminated or has an embedded NUL")]
    BadString,
    /// The encoded message does not fit the 16-bit size field.
    #[error("a message of {0} bytes does not fit the 16-bit size field")]
    TooLarge(usize),
}

/// The header of one message: which object it is for, which message of that
/// object it is, and how many bytes the whole message takes including this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Id of the object the message addresses.
    pub object: u32,
    /// Index of the message in the object's request or event list.
    pub opcode: u16,
    /// Total length in bytes, header included; always a multiple of 4.
    pub size: u16,
}

/// One decoded argument. `Fd` carries no value: the descriptor travels in the
/// socket's ancillary data, and only its position in the message is on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// Signed 32-bit integer.
    Int(i32),
    /// Unsigned 32-bit integer, and every enum value.
    Uint(u32),
    /// Signed 24.8 fixed-point number, kept in its raw form.
    Fixed(i32),
    /// String without its NUL, or `None` for the null string, which is a
    /// distinct value on the wire and must be re-encoded as one.
    String(Option<CString>),
    /// Object id; 0 is the null object.
    Object(u32),
    /// Id of the object the message creates.
    NewId(u32),
    /// Byte array, without the padding.
    Array(Vec<u8>),
    /// A file descriptor travels with this message.
    Fd,
}

impl Header {
    /// Read a header from the front of `buf`.
    ///
    /// Fails with [`WireError::NeedMore`] before the 8 bytes are there, and
    /// with [`WireError::BadSize`] for a size no message can have.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let Some(head) = buf.get(..HEADER) else {
            return Err(WireError::NeedMore);
        };
        let object = u32::from_ne_bytes([head[0], head[1], head[2], head[3]]);
        let word = u32::from_ne_bytes([head[4], head[5], head[6], head[7]]);
        let opcode = (word & 0xFFFF) as u16;
        let size = (word >> 16) as u16;
        if usize::from(size) < HEADER || !size.is_multiple_of(4) {
            return Err(WireError::BadSize(size));
        }
        Ok(Self {
            object,
            opcode,
            size,
        })
    }

    /// The 8 bytes of this header.
    pub fn encode(&self) -> [u8; HEADER] {
        let object = self.object.to_ne_bytes();
        let word = ((u32::from(self.size) << 16) | u32::from(self.opcode)).to_ne_bytes();
        [
            object[0], object[1], object[2], object[3], word[0], word[1], word[2], word[3],
        ]
    }
}

/// Read the next 4-byte word of `body` and step `at` past it.
fn take_word(body: &[u8], at: &mut usize) -> Result<u32, WireError> {
    let end = at.checked_add(4).ok_or(WireError::Truncated)?;
    let word = body.get(*at..end).ok_or(WireError::Truncated)?;
    *at = end;
    Ok(u32::from_ne_bytes([word[0], word[1], word[2], word[3]]))
}

/// Read `len` bytes of `body` and step `at` past them and their padding.
fn take_bytes<'a>(body: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8], WireError> {
    let padded = len
        .checked_next_multiple_of(4)
        .ok_or(WireError::Truncated)?;
    let end = at.checked_add(len).ok_or(WireError::Truncated)?;
    let past = at.checked_add(padded).ok_or(WireError::Truncated)?;
    if past > body.len() {
        return Err(WireError::Truncated);
    }
    let bytes = body.get(*at..end).ok_or(WireError::Truncated)?;
    *at = past;
    Ok(bytes)
}

/// Append a length prefix and the bytes it counts, padded to a whole word.
fn put_bytes(body: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let len = u32::try_from(bytes.len()).map_err(|_| WireError::TooLarge(bytes.len()))?;
    body.extend_from_slice(&len.to_ne_bytes());
    body.extend_from_slice(bytes);
    let pad = (4 - bytes.len() % 4) % 4;
    body.resize(body.len() + pad, 0);
    Ok(())
}

/// Decode one whole message from the front of `buf` using `sig`.
///
/// Returns the arguments and the number of bytes consumed, which is the
/// message's own size, so the caller can drain exactly that much. The
/// arguments must account for every byte the header declared.
pub fn decode(buf: &[u8], sig: &[ArgKind]) -> Result<(Vec<Arg>, usize), WireError> {
    let header = Header::decode(buf)?;
    let size = usize::from(header.size);
    let Some(body) = buf.get(HEADER..size) else {
        return Err(WireError::NeedMore);
    };
    let mut args = Vec::with_capacity(sig.len());
    let mut at = 0;
    for kind in sig {
        let arg = match kind {
            ArgKind::Int => Arg::Int(take_word(body, &mut at)? as i32),
            ArgKind::Uint => Arg::Uint(take_word(body, &mut at)?),
            ArgKind::Fixed => Arg::Fixed(take_word(body, &mut at)? as i32),
            ArgKind::Object => Arg::Object(take_word(body, &mut at)?),
            ArgKind::NewId => Arg::NewId(take_word(body, &mut at)?),
            // A zero length is the null string, which is not the same value as
            // an empty one; anything else ends in a NUL and holds none.
            ArgKind::String => match take_word(body, &mut at)? as usize {
                0 => Arg::String(None),
                len => {
                    let bytes = take_bytes(body, &mut at, len)?;
                    let Some((last, text)) = bytes.split_last() else {
                        return Err(WireError::BadString);
                    };
                    if *last != 0 {
                        return Err(WireError::BadString);
                    }
                    Arg::String(Some(CString::new(text).map_err(|_| WireError::BadString)?))
                }
            },
            ArgKind::Array => {
                let len = take_word(body, &mut at)? as usize;
                Arg::Array(take_bytes(body, &mut at, len)?.to_vec())
            }
            ArgKind::Fd => Arg::Fd,
        };
        args.push(arg);
    }
    if at != body.len() {
        return Err(WireError::Trailing(body.len() - at));
    }
    Ok((args, size))
}

/// Encode one message. The size field is computed from the arguments, so a
/// re-encoded message is as long as its content, not as long as it arrived.
pub fn encode(object: u32, opcode: u16, args: &[Arg]) -> Result<Vec<u8>, WireError> {
    let mut body = Vec::new();
    for arg in args {
        match arg {
            Arg::Int(value) | Arg::Fixed(value) => body.extend_from_slice(&value.to_ne_bytes()),
            Arg::Uint(value) | Arg::Object(value) | Arg::NewId(value) => {
                body.extend_from_slice(&value.to_ne_bytes());
            }
            Arg::String(None) => body.extend_from_slice(&0u32.to_ne_bytes()),
            Arg::String(Some(text)) => put_bytes(&mut body, text.as_bytes_with_nul())?,
            Arg::Array(bytes) => put_bytes(&mut body, bytes)?,
            Arg::Fd => {}
        }
    }
    let len = HEADER + body.len();
    let size = u16::try_from(len).map_err(|_| WireError::TooLarge(len))?;
    let header = Header {
        object,
        opcode,
        size,
    };
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&body);
    Ok(out)
}

/// How many file descriptors a message with this signature owns. The relay
/// needs this to take the right number off the socket's fd queue.
pub fn fd_count(sig: &[ArgKind]) -> usize {
    sig.iter().filter(|kind| **kind == ArgKind::Fd).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables;

    fn cstr(s: &str) -> Option<CString> {
        Some(CString::new(s).expect("no NUL in the test string"))
    }

    const ALL: &[ArgKind] = &[
        ArgKind::Int,
        ArgKind::Uint,
        ArgKind::Fixed,
        ArgKind::String,
        ArgKind::Object,
        ArgKind::NewId,
        ArgKind::Array,
        ArgKind::Fd,
    ];

    fn all_args() -> Vec<Arg> {
        vec![
            Arg::Int(-7),
            Arg::Uint(0xDEAD_BEEF),
            Arg::Fixed(256),
            Arg::String(cstr("text/plain;charset=utf-8")),
            Arg::Object(42),
            Arg::NewId(43),
            Arg::Array(vec![1, 2, 3, 4, 5]),
            Arg::Fd,
        ]
    }

    #[test]
    fn every_argument_kind_survives_a_round_trip() {
        let args = all_args();
        let bytes = encode(7, 3, &args).expect("encodes");
        let header = Header::decode(&bytes).expect("a header");
        assert_eq!(header.object, 7);
        assert_eq!(header.opcode, 3);
        assert_eq!(usize::from(header.size), bytes.len());
        let (got, used) = decode(&bytes, ALL).expect("decodes");
        assert_eq!(got, args);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn a_header_round_trips_through_its_bytes() {
        let header = Header {
            object: 0xFF00_0001,
            opcode: 2,
            size: 12,
        };
        assert_eq!(Header::decode(&header.encode()), Ok(header));
    }

    #[test]
    fn a_string_is_nul_terminated_and_padded_to_a_word() {
        let three = encode(1, 0, &[Arg::String(cstr("abc"))]).expect("encodes");
        assert_eq!(&three[HEADER..], &[4, 0, 0, 0, b'a', b'b', b'c', 0]);
        let four = encode(1, 0, &[Arg::String(cstr("abcd"))]).expect("encodes");
        assert_eq!(
            &four[HEADER..],
            &[5, 0, 0, 0, b'a', b'b', b'c', b'd', 0, 0, 0, 0]
        );
        assert_eq!(
            decode(&four, &[ArgKind::String]).expect("decodes").0,
            vec![Arg::String(cstr("abcd"))]
        );
    }

    #[test]
    fn a_null_string_and_an_empty_array_are_a_bare_length() {
        let null = encode(1, 0, &[Arg::String(None)]).expect("encodes");
        assert_eq!(&null[HEADER..], &[0, 0, 0, 0]);
        assert_eq!(
            decode(&null, &[ArgKind::String]).expect("decodes").0,
            vec![Arg::String(None)]
        );
        let empty = encode(1, 0, &[Arg::Array(Vec::new())]).expect("encodes");
        assert_eq!(&empty[HEADER..], &[0, 0, 0, 0]);
        assert_eq!(
            decode(&empty, &[ArgKind::Array]).expect("decodes").0,
            vec![Arg::Array(Vec::new())]
        );
    }

    #[test]
    fn an_array_is_padded_but_keeps_its_length() {
        let odd = encode(1, 0, &[Arg::Array(vec![9, 8, 7])]).expect("encodes");
        assert_eq!(&odd[HEADER..], &[3, 0, 0, 0, 9, 8, 7, 0]);
        assert_eq!(
            decode(&odd, &[ArgKind::Array]).expect("decodes").0,
            vec![Arg::Array(vec![9, 8, 7])]
        );
    }

    #[test]
    fn a_message_split_across_two_reads_asks_for_more() {
        let whole = encode(2, 1, &all_args()).expect("encodes");
        for cut in [0, 1, HEADER - 1, HEADER, HEADER + 4, whole.len() - 1] {
            assert_eq!(
                decode(&whole[..cut], ALL),
                Err(WireError::NeedMore),
                "cut at {cut}"
            );
        }
        let (args, used) = decode(&whole, ALL).expect("decodes once whole");
        assert_eq!(args, all_args());
        assert_eq!(used, whole.len());
    }

    #[test]
    fn two_messages_in_one_buffer_are_consumed_one_at_a_time() {
        let mut buf = encode(1, 0, &[Arg::Uint(1)]).expect("encodes");
        let second = encode(2, 1, &[Arg::Uint(2)]).expect("encodes");
        buf.extend_from_slice(&second);
        let (first, used) = decode(&buf, &[ArgKind::Uint]).expect("decodes");
        assert_eq!(first, vec![Arg::Uint(1)]);
        assert_eq!(used, HEADER + 4);
        let (rest, used) = decode(&buf[used..], &[ArgKind::Uint]).expect("decodes");
        assert_eq!(rest, vec![Arg::Uint(2)]);
        assert_eq!(used, second.len());
    }

    #[test]
    fn a_size_no_message_can_have_is_refused() {
        for size in [0u16, 4, 7, 9, 10] {
            let mut buf = vec![1, 0, 0, 0];
            buf.extend_from_slice(&((u32::from(size) << 16) | 3).to_ne_bytes());
            buf.resize(64, 0);
            assert_eq!(Header::decode(&buf), Err(WireError::BadSize(size)));
            assert_eq!(decode(&buf, &[]), Err(WireError::BadSize(size)));
        }
    }

    #[test]
    fn a_signature_that_does_not_fit_the_message_is_refused() {
        let short = encode(1, 0, &[Arg::Uint(1)]).expect("encodes");
        assert_eq!(
            decode(&short, &[ArgKind::Uint, ArgKind::Uint]),
            Err(WireError::Truncated)
        );
        assert_eq!(decode(&short, &[]), Err(WireError::Trailing(4)));
    }

    #[test]
    fn a_string_that_a_c_reader_would_read_differently_is_refused() {
        let mut buf = encode(1, 0, &[Arg::String(cstr("abc"))]).expect("encodes");
        let last = buf.len() - 1;
        buf[last] = b'd';
        assert_eq!(decode(&buf, &[ArgKind::String]), Err(WireError::BadString));
        let mut buf = encode(1, 0, &[Arg::String(cstr("abc"))]).expect("encodes");
        buf[HEADER + 5] = 0;
        assert_eq!(decode(&buf, &[ArgKind::String]), Err(WireError::BadString));
    }

    #[test]
    fn a_message_too_long_for_the_size_field_is_refused() {
        let huge = Arg::Array(vec![0; usize::from(u16::MAX)]);
        assert!(matches!(encode(1, 0, &[huge]), Err(WireError::TooLarge(_))));
    }

    #[test]
    fn a_pool_carries_its_fd_beside_the_message_and_not_in_it() {
        let shm = tables::lookup("wl_shm").expect("the table has it");
        let create_pool = shm.request(0).expect("wl_shm.create_pool");
        assert_eq!(create_pool.name, "create_pool");
        assert_eq!(
            create_pool.args,
            &[ArgKind::NewId, ArgKind::Fd, ArgKind::Int]
        );
        let args = vec![Arg::NewId(3), Arg::Fd, Arg::Int(4096)];
        let bytes = encode(2, 0, &args).expect("encodes");
        // Header, then the new id and the size: the fd takes no wire bytes.
        assert_eq!(bytes.len(), HEADER + 8);
        assert_eq!(
            bytes,
            vec![2, 0, 0, 0, 0, 0, 16, 0, 3, 0, 0, 0, 0, 16, 0, 0]
        );
        let (got, used) = decode(&bytes, create_pool.args).expect("decodes");
        assert_eq!(got, args);
        assert_eq!(used, bytes.len());
        assert_eq!(fd_count(create_pool.args), 1);
    }

    #[test]
    fn a_signature_owns_one_fd_per_fd_argument() {
        assert_eq!(fd_count(&[]), 0);
        assert_eq!(fd_count(ALL), 1);
        assert_eq!(fd_count(&[ArgKind::Fd, ArgKind::Uint, ArgKind::Fd]), 2);
        let ctx = tables::lookup("wp_security_context_manager_v1").expect("the table has it");
        let listener = ctx.request(1).expect("create_listener");
        assert_eq!(fd_count(listener.args), 2);
    }

    #[test]
    fn a_bind_encoded_from_the_table_decodes_back() {
        let registry = tables::lookup("wl_registry").expect("the table has it");
        let bind = registry.request(0).expect("wl_registry.bind");
        let args = vec![
            Arg::Uint(42),
            Arg::String(cstr("wl_compositor")),
            Arg::Uint(6),
            Arg::NewId(3),
        ];
        let bytes = encode(2, 0, &args).expect("encodes");
        let (got, used) = decode(&bytes, bind.args).expect("decodes");
        assert_eq!(got, args);
        assert_eq!(used, bytes.len());
    }
}
