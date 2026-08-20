//! Wire format of the exec channel. Length-prefixed raw bytes so argv
//! never needs to be UTF-8. One request per connection.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// Upper bound on an encoded request; larger is a protocol violation.
pub const MAX_REQUEST: usize = 1 << 20;

/// Request flag: the command may take the terminal on fd 0 as its
/// controlling terminal. bubbler sets it only for a pty it allocated.
pub const FLAG_CTTY: u32 = 1;

/// Every flag bit this version knows; the rest must be zero, so an
/// unrecognised request is refused rather than half honoured.
const KNOWN_FLAGS: u32 = FLAG_CTTY;

/// Malformed request bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Fewer bytes than the declared lengths require.
    Truncated,
    /// Zero arguments, or more than the size cap allows.
    BadCount,
    /// Total size above [`MAX_REQUEST`].
    TooLarge,
    /// A flag bit this version does not know.
    BadFlags,
}

/// One request: what the client asked for, and the argv to run.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// Bitmask of [`FLAG_CTTY`].
    pub flags: u32,
    /// Program and arguments; never empty.
    pub argv: Vec<OsString>,
}

impl Request {
    /// Whether the client asked for the terminal on fd 0 to become the
    /// command's controlling terminal.
    pub fn ctty(&self) -> bool {
        self.flags & FLAG_CTTY != 0
    }
}

/// `u32 flags`, `u32 argc`, then `argc` x (`u32 len`, bytes), little-endian.
pub fn encode_request(argv: &[&OsStr], flags: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(argv.len() as u32).to_le_bytes());
    for a in argv {
        let b = a.as_bytes();
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// Inverse of [`encode_request`]; rejects empty argv, unknown flags and
/// oversize input.
pub fn decode_request(buf: &[u8]) -> Result<Request, ProtoError> {
    if buf.len() > MAX_REQUEST {
        return Err(ProtoError::TooLarge);
    }
    let mut pos = 0usize;
    let take4 = |pos: &mut usize| -> Result<u32, ProtoError> {
        let end = pos.checked_add(4).ok_or(ProtoError::Truncated)?;
        let b = buf.get(*pos..end).ok_or(ProtoError::Truncated)?;
        *pos = end;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let flags = take4(&mut pos)?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(ProtoError::BadFlags);
    }
    let argc = take4(&mut pos)? as usize;
    if argc == 0 || argc > MAX_REQUEST / 4 {
        return Err(ProtoError::BadCount);
    }
    let mut argv = Vec::with_capacity(argc.min(64));
    for _ in 0..argc {
        let len = take4(&mut pos)? as usize;
        let end = pos.checked_add(len).ok_or(ProtoError::Truncated)?;
        let b = buf.get(pos..end).ok_or(ProtoError::Truncated)?;
        argv.push(OsString::from_vec(b.to_vec()));
        pos = end;
    }
    if pos != buf.len() {
        return Err(ProtoError::Truncated);
    }
    Ok(Request { flags, argv })
}

/// Raw `waitpid` status, little-endian.
pub fn encode_status(status: i32) -> [u8; 4] {
    status.to_le_bytes()
}

/// Inverse of [`encode_status`].
pub fn decode_status(b: &[u8; 4]) -> i32 {
    i32::from_le_bytes(*b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_including_non_utf8() {
        let a: Vec<OsString> = vec![
            "sh".into(),
            "-c".into(),
            OsString::from_vec(vec![0xff, 0x20, b'x']),
        ];
        let refs: Vec<&OsStr> = a.iter().map(|s| s.as_os_str()).collect();
        let got = decode_request(&encode_request(&refs, 0)).unwrap();
        assert_eq!(got.argv, a);
        assert!(!got.ctty(), "no flag was sent");
    }

    #[test]
    fn the_controlling_terminal_flag_rides_with_the_argv() {
        let enc = encode_request(&[OsStr::new("sh")], FLAG_CTTY);
        let got = decode_request(&enc).unwrap();
        assert_eq!(got.flags, FLAG_CTTY);
        assert!(got.ctty());
        // The flags come first, so the argv still decodes byte for byte.
        assert_eq!(got.argv, vec![OsString::from("sh")]);
    }

    #[test]
    fn a_flag_this_version_does_not_know_is_refused() {
        // Honouring an unknown bit by ignoring it would let a future
        // client believe a request was served the way it asked.
        let enc = encode_request(&[OsStr::new("sh")], FLAG_CTTY | 0x8000_0000);
        assert_eq!(decode_request(&enc), Err(ProtoError::BadFlags));
    }

    #[test]
    fn rejects_empty_truncated_and_oversize() {
        assert_eq!(
            decode_request(&encode_request(&[], 0)),
            Err(ProtoError::BadCount)
        );
        let mut enc = encode_request(&[OsStr::new("abc")], 0);
        enc.truncate(enc.len() - 1);
        assert_eq!(decode_request(&enc), Err(ProtoError::Truncated));
        assert_eq!(decode_request(&[]), Err(ProtoError::Truncated));
        assert_eq!(decode_request(&[0u8; 4]), Err(ProtoError::Truncated));
        assert_eq!(
            decode_request(&vec![0u8; MAX_REQUEST + 1]),
            Err(ProtoError::TooLarge)
        );
        let mut trailing = encode_request(&[OsStr::new("a")], 0);
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(ProtoError::Truncated));
    }

    #[test]
    fn status_roundtrip() {
        assert_eq!(decode_status(&encode_status(-1)), -1);
        assert_eq!(decode_status(&encode_status(3 << 8)), 3 << 8);
    }
}
