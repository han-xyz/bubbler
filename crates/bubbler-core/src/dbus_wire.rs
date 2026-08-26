//! A minimal D-Bus client for the session bus: the few calls bubbler
//! makes on the user's own bus, with file descriptors attached.
//!
//! The document portal takes `O_PATH` descriptors, and no command-line
//! tool passes one on our behalf, so bubbler speaks the protocol itself
//! instead of spawning `dbus-send`. Only what those calls need is here:
//! `EXTERNAL` authentication over a Unix socket, one method call at a
//! time, replies matched by serial. This is host-side code talking to
//! the user's own bus as the user; nothing in a sandbox reaches it.
//!
//! Every wire fact is from the D-Bus specification
//! (<https://dbus.freedesktop.org/doc/dbus-specification.html>),
//! sections "Type System", "Message Format" and "Authentication
//! Protocol"; each rule is cited where it is applied. The decoder is
//! strict on purpose: a reply is input from another process, and a
//! length, an alignment or a padding byte that does not match the
//! specification is a reason to fail the call, never to guess.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::event::{Nsecs, PollFd, PollFlags, Secs, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType, recvmsg, sendmsg,
    socket_with,
};

/// Longest a call waits for its reply, and the whole of what a connect
/// and its authentication may take. A bus that has not answered within
/// it is not going to; bubbler's callers have a user waiting.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Major protocol version of every message ("Message Format": the
/// version for this specification is 1, and a mismatch means the two
/// sides cannot talk at all).
const PROTOCOL_VERSION: u8 = 1;

/// Bytes of the fixed part of a header: the four bytes, the body length,
/// the serial and the length of the header-field array.
const FIXED_HEADER: usize = 16;

/// "Arrays have a maximum length defined to be 2 to the 26th power or
/// 67108864 (64 MiB). Implementations must not send or accept arrays
/// exceeding this length."
const MAX_ARRAY: usize = 1 << 26;

/// "The maximum length of a message, including header, header alignment
/// padding, and body is 2 to the 27th power or 134217728 (128 MiB)."
const MAX_MESSAGE: usize = 1 << 27;

/// "The maximum length of a signature is 255."
const MAX_SIGNATURE: usize = 255;

/// "The maximum depth of container type nesting is 32 array type codes
/// and 32 open parentheses", so 64 in total. Counted across variants
/// too: a variant's signature is read from the message, and without a
/// running total a reply could nest them until the decoder's recursion
/// ran out of stack.
const MAX_DEPTH: usize = 64;

/// Nesting of one kind — arrays, or structs and dict entries — the
/// specification allows.
const MAX_CONTAINER_DEPTH: usize = 32;

/// Descriptors one message may carry: Linux caps `SCM_RIGHTS` at 253 per
/// message, so a longer list could never leave in one piece.
const MAX_CALL_FDS: usize = 253;

/// Descriptors a reply is given room to carry. Nothing bubbler calls
/// answers with one; the room exists so a peer that sends some cannot
/// leave them queued, and every one that arrives is closed at once.
const MAX_REPLY_FDS: usize = 4;

/// Longest authentication line accepted, so a peer that never sends
/// `\r\n` cannot grow the buffer without bound. The lines in use are a
/// few dozen bytes.
const MAX_AUTH_LINE: usize = 4096;

/// Message types ("Message Format"): a call, its reply, an error reply,
/// a signal.
const MSG_METHOD_CALL: u8 = 1;
const MSG_METHOD_RETURN: u8 = 2;
const MSG_ERROR: u8 = 3;

/// Header field codes ("Header Fields").
const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SENDER: u8 = 7;
const FIELD_SIGNATURE: u8 = 8;
const FIELD_UNIX_FDS: u8 = 9;

/// The bus's own name, object and interface: where `Hello` and `GetId`
/// live.
const BUS_NAME: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const BUS_INTERFACE: &str = "org.freedesktop.DBus";

/// What went wrong on the bus or on the wire. Everything but
/// [`WireError::Remote`] leaves the connection in a state bubbler cannot
/// reason about, so the session is to be dropped rather than reused.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The bus socket could not be opened or connected to.
    #[error("connecting to the bus socket {}", .path.display())]
    Connect {
        /// Socket the connection was attempted on.
        path: PathBuf,
        /// What the kernel said.
        #[source]
        source: io::Error,
    },
    /// Reading from or writing to a connected bus failed.
    #[error("talking to the bus: {0}")]
    Io(#[source] io::Error),
    /// The bus closed the connection.
    #[error("the bus closed the connection")]
    Closed,
    /// The bus did not answer inside [`CALL_TIMEOUT`].
    #[error("the bus did not answer within {}s", CALL_TIMEOUT.as_secs())]
    Timeout,
    /// The bus answered the authentication handshake with something the
    /// protocol does not allow there.
    #[error("the bus answered the authentication handshake with {0:?}")]
    Auth(String),
    /// The bus refused `EXTERNAL` authentication; the payload is the
    /// mechanism list it offered instead, which may be empty.
    #[error("the bus refused EXTERNAL authentication (it offers {0:?})")]
    AuthRejected(String),
    /// The bus did not agree to descriptor passing, so a call carrying
    /// descriptors cannot be made on this connection.
    #[error("the bus does not pass file descriptors on this connection")]
    NoFdPassing,
    /// More descriptors than one message may carry.
    #[error("{0} file descriptors is more than one message may carry")]
    TooManyFds(usize),
    /// The method call reached the far side and failed there.
    #[error("{name}: {message}")]
    Remote {
        /// D-Bus error name, e.g. `org.freedesktop.DBus.Error.AccessDenied`.
        name: String,
        /// Human-readable text the far side attached, empty if it sent none.
        message: String,
    },
    /// A type signature is not a list of single complete types.
    #[error("{0:?} is not a valid type signature")]
    BadSignature(String),
    /// A signature and a list of values disagree on how many values there are.
    #[error("the signature describes {expected} values and {got} were given")]
    Arity {
        /// Values the signature describes.
        expected: usize,
        /// Values that were given.
        got: usize,
    },
    /// A value does not have the type its signature gives it.
    #[error("the signature says {expected:?} and {got} was given")]
    TypeMismatch {
        /// Type code the signature asks for.
        expected: char,
        /// What was given instead.
        got: &'static str,
    },
    /// A shape the specification allows that this client does not model.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// A value runs past the end of the block it is in.
    #[error("a value runs past the end of the message")]
    Truncated,
    /// Alignment padding that is not nul. "The alignment padding must
    /// not be left uninitialized (it can't contain garbage)", so bytes
    /// there are a sender disagreeing with us about the layout.
    #[error("alignment padding that is not nul")]
    Padding,
    /// The signature left bytes unread: the sender's idea of the message
    /// and ours differ, which is not something to interpret.
    #[error("{0} bytes left over after the values")]
    Trailing(usize),
    /// An array declares more bytes than the specification allows.
    #[error("an array of {0} bytes is longer than the specification allows")]
    ArrayTooLong(usize),
    /// A message is longer than the specification allows.
    #[error("a message of {0} bytes is longer than the specification allows")]
    MessageTooLong(usize),
    /// A string is not nul-terminated, hides a nul where a C reader would
    /// stop early, or is not UTF-8.
    #[error("a string is not nul-terminated, holds a nul, or is not UTF-8")]
    BadString,
    /// An object path does not meet the rules in "Valid Object Paths".
    #[error("{0:?} is not a valid object path")]
    BadObjectPath(String),
    /// A boolean other than 0 or 1: "everything else is invalid".
    #[error("{0} is not a boolean")]
    BadBool(u32),
    /// Containers nested deeper than the specification allows.
    #[error("containers nested deeper than the specification allows")]
    Depth,
    /// A message in an endianness this client does not read. bubbler and
    /// its bus are the same machine, so a reply that is not
    /// little-endian is refused rather than byte-swapped untested.
    #[error("a message with endianness flag {0:?}, which this client does not read")]
    Endianness(u8),
    /// A message that is malformed in a way of its own.
    #[error("the bus sent {0}")]
    BadMessage(&'static str),
    /// A `Fd` value names a descriptor that was not handed to the call.
    #[error("a value names file descriptor {0}, which was not given to the call")]
    FdIndex(u32),
    /// A call with no destination. Every message on a bus is addressed,
    /// and a reply that could not be attributed to a name's owner is one
    /// anybody on the bus could have forged.
    #[error("a call with no destination")]
    NoDestination,
}

/// One value on the wire. The model covers the whole D-Bus type system
/// except dict keys that are not strings, which nothing bubbler talks to
/// uses; see [`WireError::Unsupported`].
///
/// `Fd` carries no descriptor: on the wire a `h` is only an index into
/// the descriptors that travel beside the message, and the descriptors
/// themselves are passed to [`Session::call`].
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `y`: unsigned 8-bit integer.
    Byte(u8),
    /// `b`: boolean, marshalled as 32 bits holding 0 or 1.
    Bool(bool),
    /// `n`: signed 16-bit integer.
    Int16(i16),
    /// `q`: unsigned 16-bit integer.
    Uint16(u16),
    /// `i`: signed 32-bit integer.
    Int32(i32),
    /// `u`: unsigned 32-bit integer.
    Uint32(u32),
    /// `x`: signed 64-bit integer.
    Int64(i64),
    /// `t`: unsigned 64-bit integer.
    Uint64(u64),
    /// `d`: IEEE 754 double.
    Double(f64),
    /// `s`: UTF-8 string with no nul in it.
    Str(String),
    /// `o`: object path, e.g. `/org/freedesktop/portal/documents`.
    ObjectPath(String),
    /// `g`: a type signature carried as a value.
    Signature(String),
    /// `h`: index into the descriptors sent with the message.
    Fd(u32),
    /// `ay`: array of bytes, kept as bytes rather than as a value each.
    ByteArray(Vec<u8>),
    /// `a<type>`: array of values that all have the element type.
    Array(Vec<Value>),
    /// `(...)`: struct, one value per field.
    Struct(Vec<Value>),
    /// `a{s<type>}`: array of dict entries with string keys.
    Dict(Vec<(String, Value)>),
    /// `v`: a value that carries its own type.
    Variant(Box<Value>),
}

impl Value {
    /// What this value is, for an error that has to name it.
    fn kind(&self) -> &'static str {
        match self {
            Value::Byte(_) => "a byte",
            Value::Bool(_) => "a boolean",
            Value::Int16(_) => "an int16",
            Value::Uint16(_) => "a uint16",
            Value::Int32(_) => "an int32",
            Value::Uint32(_) => "a uint32",
            Value::Int64(_) => "an int64",
            Value::Uint64(_) => "a uint64",
            Value::Double(_) => "a double",
            Value::Str(_) => "a string",
            Value::ObjectPath(_) => "an object path",
            Value::Signature(_) => "a signature",
            Value::Fd(_) => "a file descriptor index",
            Value::ByteArray(_) => "a byte array",
            Value::Array(_) => "an array",
            Value::Struct(_) => "a struct",
            Value::Dict(_) => "a dict",
            Value::Variant(_) => "a variant",
        }
    }
}

/// One single complete type, parsed out of a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Type {
    Byte,
    Bool,
    Int16,
    Uint16,
    Int32,
    Uint32,
    Int64,
    Uint64,
    Double,
    Str,
    ObjectPath,
    Signature,
    Fd,
    Array(Box<Type>),
    Struct(Vec<Type>),
    DictEntry(Box<Type>, Box<Type>),
    Variant,
}

impl Type {
    /// Alignment in bytes, from "Summary of D-Bus marshalling". Arrays
    /// align like the length that starts them, structs and dict entries
    /// to 8 whatever they hold, and a variant like the signature that
    /// starts it, which needs no padding at all.
    fn alignment(&self) -> usize {
        match self {
            Type::Byte | Type::Signature | Type::Variant => 1,
            Type::Int16 | Type::Uint16 => 2,
            Type::Bool
            | Type::Int32
            | Type::Uint32
            | Type::Fd
            | Type::Str
            | Type::ObjectPath
            | Type::Array(_) => 4,
            Type::Int64 | Type::Uint64 | Type::Double | Type::Struct(_) | Type::DictEntry(..) => 8,
        }
    }

    /// The type code that opens this type, for an error that has to name it.
    fn code(&self) -> char {
        match self {
            Type::Byte => 'y',
            Type::Bool => 'b',
            Type::Int16 => 'n',
            Type::Uint16 => 'q',
            Type::Int32 => 'i',
            Type::Uint32 => 'u',
            Type::Int64 => 'x',
            Type::Uint64 => 't',
            Type::Double => 'd',
            Type::Str => 's',
            Type::ObjectPath => 'o',
            Type::Signature => 'g',
            Type::Fd => 'h',
            Type::Array(_) => 'a',
            Type::Struct(_) => '(',
            Type::DictEntry(..) => '{',
            Type::Variant => 'v',
        }
    }

    /// Whether this is a basic type, which is all a dict entry's key may be.
    fn is_basic(&self) -> bool {
        !matches!(
            self,
            Type::Array(_) | Type::Struct(_) | Type::DictEntry(..) | Type::Variant
        )
    }
}

/// Parse a signature into the single complete types it lists.
///
/// Rejects everything "Valid Signatures" rejects: an array with no
/// element type, unbalanced parentheses, an empty struct, a dict entry
/// outside an array or with other than two fields or a container key,
/// nesting past the limits, and a signature over 255 bytes.
fn parse_signature(sig: &str) -> Result<Vec<Type>, WireError> {
    let bad = || WireError::BadSignature(sig.to_owned());
    if sig.len() > MAX_SIGNATURE {
        return Err(bad());
    }
    let bytes = sig.as_bytes();
    let mut at = 0;
    let mut out = Vec::new();
    while at < bytes.len() {
        out.push(parse_type(bytes, &mut at, 0, 0).map_err(|_| bad())?);
    }
    Ok(out)
}

/// Parse one single complete type at `at`, tracking how deep in arrays
/// and in structs it already is.
fn parse_type(
    bytes: &[u8],
    at: &mut usize,
    arrays: usize,
    structs: usize,
) -> Result<Type, WireError> {
    let bad = || WireError::BadSignature(String::new());
    let Some(&code) = bytes.get(*at) else {
        return Err(bad());
    };
    *at += 1;
    Ok(match code {
        b'y' => Type::Byte,
        b'b' => Type::Bool,
        b'n' => Type::Int16,
        b'q' => Type::Uint16,
        b'i' => Type::Int32,
        b'u' => Type::Uint32,
        b'x' => Type::Int64,
        b't' => Type::Uint64,
        b'd' => Type::Double,
        b's' => Type::Str,
        b'o' => Type::ObjectPath,
        b'g' => Type::Signature,
        b'h' => Type::Fd,
        b'v' => Type::Variant,
        b'a' => {
            if arrays >= MAX_CONTAINER_DEPTH {
                return Err(bad());
            }
            // A dict entry is only ever an array's element type, so it is
            // read here and nowhere else.
            if bytes.get(*at) == Some(&b'{') {
                if structs >= MAX_CONTAINER_DEPTH {
                    return Err(bad());
                }
                *at += 1;
                let key = parse_type(bytes, at, arrays + 1, structs + 1)?;
                if !key.is_basic() {
                    return Err(bad());
                }
                let value = parse_type(bytes, at, arrays + 1, structs + 1)?;
                if bytes.get(*at) != Some(&b'}') {
                    return Err(bad());
                }
                *at += 1;
                Type::Array(Box::new(Type::DictEntry(Box::new(key), Box::new(value))))
            } else {
                Type::Array(Box::new(parse_type(bytes, at, arrays + 1, structs)?))
            }
        }
        b'(' => {
            if structs >= MAX_CONTAINER_DEPTH {
                return Err(bad());
            }
            let mut fields = Vec::new();
            loop {
                match bytes.get(*at) {
                    Some(b')') => break,
                    Some(_) => fields.push(parse_type(bytes, at, arrays, structs + 1)?),
                    None => return Err(bad()),
                }
            }
            *at += 1;
            if fields.is_empty() {
                return Err(bad());
            }
            Type::Struct(fields)
        }
        _ => return Err(bad()),
    })
}

/// Whether `path` meets "Valid Object Paths": it begins with `/`, its
/// elements hold only `[A-Za-z0-9_]`, none is empty, and only the root
/// path ends in `/`.
fn valid_object_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest.split('/').all(|element| {
            !element.is_empty()
                && element
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// Grow `out` with nul bytes until its length is a multiple of `align`.
fn pad(out: &mut Vec<u8>, align: usize) {
    let over = out.len() % align;
    if over != 0 {
        out.resize(out.len() + align - over, 0);
    }
}

/// `n` rounded up to a multiple of `align`.
fn align_up(n: usize, align: usize) -> usize {
    n.div_ceil(align) * align
}

/// Marshal `values` against `sig`, little-endian.
///
/// Offset 0 of the result is taken to be a multiple of 8 from the start
/// of the message, which is what both blocks a message has are:
/// alignment is "calculated globally, with respect to the first byte in
/// the message", and a body begins on an 8-byte boundary.
pub fn encode(sig: &str, values: &[Value]) -> Result<Vec<u8>, WireError> {
    let types = parse_signature(sig)?;
    if types.len() != values.len() {
        return Err(WireError::Arity {
            expected: types.len(),
            got: values.len(),
        });
    }
    let mut out = Vec::new();
    for (ty, value) in types.iter().zip(values) {
        encode_value(&mut out, ty, value, 0)?;
    }
    Ok(out)
}

/// Marshal one value of type `ty`, padding to its alignment first.
fn encode_value(
    out: &mut Vec<u8>,
    ty: &Type,
    value: &Value,
    depth: usize,
) -> Result<(), WireError> {
    if depth > MAX_DEPTH {
        return Err(WireError::Depth);
    }
    let mismatch = || WireError::TypeMismatch {
        expected: ty.code(),
        got: value.kind(),
    };
    pad(out, ty.alignment());
    match (ty, value) {
        (Type::Byte, Value::Byte(v)) => out.push(*v),
        (Type::Bool, Value::Bool(v)) => out.extend_from_slice(&u32::from(*v).to_le_bytes()),
        (Type::Int16, Value::Int16(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Uint16, Value::Uint16(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Int32, Value::Int32(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Uint32, Value::Uint32(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Int64, Value::Int64(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Uint64, Value::Uint64(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Double, Value::Double(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Fd, Value::Fd(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (Type::Str, Value::Str(v)) => encode_str(out, v)?,
        (Type::ObjectPath, Value::ObjectPath(v)) => {
            if !valid_object_path(v) {
                return Err(WireError::BadObjectPath(v.clone()));
            }
            encode_str(out, v)?;
        }
        (Type::Signature, Value::Signature(v)) => {
            parse_signature(v)?;
            encode_signature(out, v);
        }
        (Type::Array(element), _) => encode_array(out, element, value, depth)?,
        (Type::Struct(fields), Value::Struct(given)) => {
            if fields.len() != given.len() {
                return Err(WireError::Arity {
                    expected: fields.len(),
                    got: given.len(),
                });
            }
            for (field, value) in fields.iter().zip(given) {
                encode_value(out, field, value, depth + 1)?;
            }
        }
        (Type::Variant, Value::Variant(inner)) => {
            // "Variants are marshalled as the SIGNATURE of the contents
            // (which must be a single complete type), followed by a
            // marshalled value with the type given by that signature."
            let sig = signature_of(inner, 0)?;
            let types = parse_signature(&sig)?;
            let [inner_type] = types.as_slice() else {
                return Err(WireError::BadSignature(sig));
            };
            encode_signature(out, &sig);
            encode_value(out, inner_type, inner, depth + 1)?;
        }
        // A dict entry is reached through its array and never directly.
        _ => return Err(mismatch()),
    }
    Ok(())
}

/// A `s`/`o` string: a UINT32 length, the text, a trailing nul. The
/// caller has padded to 4 already.
fn encode_str(out: &mut Vec<u8>, text: &str) -> Result<(), WireError> {
    if text.as_bytes().contains(&0) {
        return Err(WireError::BadString);
    }
    let len = u32::try_from(text.len()).map_err(|_| WireError::ArrayTooLong(text.len()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    Ok(())
}

/// A `g` signature: a single-byte length, the text, a trailing nul. Its
/// alignment is 1, so no padding is ever needed before it, and its
/// length has been checked to fit a byte by [`parse_signature`].
fn encode_signature(out: &mut Vec<u8>, sig: &str) {
    out.push(sig.len() as u8);
    out.extend_from_slice(sig.as_bytes());
    out.push(0);
}

/// An array: a UINT32 of the element bytes, padding to the element's
/// alignment which the length does not count, then the elements.
fn encode_array(
    out: &mut Vec<u8>,
    element: &Type,
    value: &Value,
    depth: usize,
) -> Result<(), WireError> {
    if depth >= MAX_DEPTH {
        return Err(WireError::Depth);
    }
    let mismatch = || WireError::TypeMismatch {
        expected: 'a',
        got: value.kind(),
    };
    let length_at = out.len();
    out.extend_from_slice(&0u32.to_le_bytes());
    // "the alignment padding for the first element is required even if
    // there is no first element".
    pad(out, element.alignment());
    let start = out.len();
    match (element, value) {
        (Type::Byte, Value::ByteArray(bytes)) => out.extend_from_slice(bytes),
        (Type::Byte, _) => return Err(mismatch()),
        (Type::DictEntry(key, entry), Value::Dict(entries)) => {
            if **key != Type::Str {
                return Err(WireError::Unsupported("dict keys that are not strings"));
            }
            for (key, value) in entries {
                pad(out, 8);
                encode_str(out, key)?;
                encode_value(out, entry, value, depth + 1)?;
            }
        }
        (Type::DictEntry(..), _) => return Err(mismatch()),
        (_, Value::Array(items)) => {
            for item in items {
                encode_value(out, element, item, depth + 1)?;
            }
        }
        _ => return Err(mismatch()),
    }
    let length = out.len() - start;
    if length > MAX_ARRAY {
        return Err(WireError::ArrayTooLong(length));
    }
    out[length_at..length_at + 4].copy_from_slice(&(length as u32).to_le_bytes());
    Ok(())
}

/// The signature of a value, for the variant that has to carry one.
///
/// An empty array or dict has no element type to read off its contents,
/// so one cannot go in a variant; nothing bubbler sends does. `depth`
/// bounds the walk: this runs before the encoder has recursed at all, so
/// without it a deep enough value would overflow the stack here rather
/// than come back as an error.
fn signature_of(value: &Value, depth: usize) -> Result<String, WireError> {
    if depth > MAX_DEPTH {
        return Err(WireError::Depth);
    }
    Ok(match value {
        Value::Byte(_) => "y".to_owned(),
        Value::Bool(_) => "b".to_owned(),
        Value::Int16(_) => "n".to_owned(),
        Value::Uint16(_) => "q".to_owned(),
        Value::Int32(_) => "i".to_owned(),
        Value::Uint32(_) => "u".to_owned(),
        Value::Int64(_) => "x".to_owned(),
        Value::Uint64(_) => "t".to_owned(),
        Value::Double(_) => "d".to_owned(),
        Value::Str(_) => "s".to_owned(),
        Value::ObjectPath(_) => "o".to_owned(),
        Value::Signature(_) => "g".to_owned(),
        Value::Fd(_) => "h".to_owned(),
        Value::ByteArray(_) => "ay".to_owned(),
        Value::Variant(_) => "v".to_owned(),
        Value::Array(items) => {
            let first = items
                .first()
                .ok_or(WireError::Unsupported("an empty array inside a variant"))?;
            format!("a{}", signature_of(first, depth + 1)?)
        }
        Value::Dict(entries) => {
            let first = entries
                .first()
                .ok_or(WireError::Unsupported("an empty dict inside a variant"))?;
            format!("a{{s{}}}", signature_of(&first.1, depth + 1)?)
        }
        Value::Struct(fields) => {
            let mut sig = String::from("(");
            for field in fields {
                sig.push_str(&signature_of(field, depth + 1)?);
            }
            sig.push(')');
            sig
        }
    })
}

/// A cursor over a marshalled block, refusing everything the
/// specification does not allow rather than reading on.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    /// Step over the padding before a value of alignment `align`,
    /// refusing padding that is not nul.
    fn align(&mut self, align: usize) -> Result<(), WireError> {
        let over = self.at % align;
        let padding = if over == 0 { 0 } else { align - over };
        if self.take(padding)?.iter().any(|b| *b != 0) {
            return Err(WireError::Padding);
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError::Truncated)?;
        let bytes = self.buf.get(self.at..end).ok_or(WireError::Truncated)?;
        self.at = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn uint32(&mut self) -> Result<u32, WireError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// `len` bytes of text and the nul after them. "The value of any
    /// string-like type is conceptually 0 or more Unicode codepoints
    /// encoded in UTF-8, none of which may be U+0000."
    fn text(&mut self, len: usize) -> Result<String, WireError> {
        let bytes = self.take(len)?;
        if bytes.contains(&0) || self.byte()? != 0 {
            return Err(WireError::BadString);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| WireError::BadString)?;
        Ok(text.to_owned())
    }
}

/// Unmarshal `body` against `sig`, little-endian, with offset 0 taken to
/// be a multiple of 8 from the start of the message.
///
/// Strict: a value that runs past the end, padding that is not nul, an
/// array over the length limit, a string that is not nul-terminated
/// UTF-8, a boolean that is not 0 or 1, an object path the rules forbid
/// and bytes left over at the end are all errors.
pub fn decode(sig: &str, body: &[u8]) -> Result<Vec<Value>, WireError> {
    let types = parse_signature(sig)?;
    let mut reader = Reader::new(body);
    let mut out = Vec::with_capacity(types.len());
    for ty in &types {
        out.push(decode_value(&mut reader, ty, 0)?);
    }
    if reader.at != body.len() {
        return Err(WireError::Trailing(body.len() - reader.at));
    }
    Ok(out)
}

/// Unmarshal one value of type `ty`, stepping over its padding first.
fn decode_value(reader: &mut Reader<'_>, ty: &Type, depth: usize) -> Result<Value, WireError> {
    if depth > MAX_DEPTH {
        return Err(WireError::Depth);
    }
    reader.align(ty.alignment())?;
    Ok(match ty {
        Type::Byte => Value::Byte(reader.byte()?),
        Type::Bool => match reader.uint32()? {
            0 => Value::Bool(false),
            1 => Value::Bool(true),
            other => return Err(WireError::BadBool(other)),
        },
        Type::Int16 => {
            let b = reader.take(2)?;
            Value::Int16(i16::from_le_bytes([b[0], b[1]]))
        }
        Type::Uint16 => {
            let b = reader.take(2)?;
            Value::Uint16(u16::from_le_bytes([b[0], b[1]]))
        }
        Type::Int32 => {
            let b = reader.take(4)?;
            Value::Int32(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }
        Type::Uint32 => Value::Uint32(reader.uint32()?),
        Type::Int64 => {
            let b = reader.take(8)?;
            Value::Int64(i64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
        Type::Uint64 => {
            let b = reader.take(8)?;
            Value::Uint64(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
        Type::Double => {
            let b = reader.take(8)?;
            Value::Double(f64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
        Type::Fd => Value::Fd(reader.uint32()?),
        Type::Str => {
            let len = reader.uint32()? as usize;
            Value::Str(reader.text(len)?)
        }
        Type::ObjectPath => {
            let len = reader.uint32()? as usize;
            let path = reader.text(len)?;
            if !valid_object_path(&path) {
                return Err(WireError::BadObjectPath(path));
            }
            Value::ObjectPath(path)
        }
        Type::Signature => {
            let len = usize::from(reader.byte()?);
            let sig = reader.text(len)?;
            parse_signature(&sig)?;
            Value::Signature(sig)
        }
        Type::Variant => {
            let len = usize::from(reader.byte()?);
            let sig = reader.text(len)?;
            let types = parse_signature(&sig)?;
            let [inner] = types.as_slice() else {
                return Err(WireError::BadSignature(sig));
            };
            Value::Variant(Box::new(decode_value(reader, inner, depth + 1)?))
        }
        Type::Array(element) => decode_array(reader, element, depth)?,
        Type::Struct(fields) => {
            let mut values = Vec::with_capacity(fields.len());
            for field in fields {
                values.push(decode_value(reader, field, depth + 1)?);
            }
            Value::Struct(values)
        }
        // A dict entry is reached through its array and never directly.
        Type::DictEntry(..) => return Err(WireError::Unsupported("a dict entry outside an array")),
    })
}

/// Unmarshal an array: the byte count, the element padding the count
/// does not include, then elements until exactly that many bytes are
/// read. An element that ends anywhere else is a disagreement about the
/// layout, not something to read on from.
fn decode_array(reader: &mut Reader<'_>, element: &Type, depth: usize) -> Result<Value, WireError> {
    if depth >= MAX_DEPTH {
        return Err(WireError::Depth);
    }
    let length = reader.uint32()? as usize;
    if length > MAX_ARRAY {
        return Err(WireError::ArrayTooLong(length));
    }
    reader.align(element.alignment())?;
    let end = reader.at.checked_add(length).ok_or(WireError::Truncated)?;
    if end > reader.buf.len() {
        return Err(WireError::Truncated);
    }
    let value = match element {
        Type::Byte => Value::ByteArray(reader.take(length)?.to_vec()),
        Type::DictEntry(key, entry) => {
            if **key != Type::Str {
                return Err(WireError::Unsupported("dict keys that are not strings"));
            }
            let mut entries = Vec::new();
            while reader.at < end {
                reader.align(8)?;
                let len = reader.uint32()? as usize;
                let key = reader.text(len)?;
                entries.push((key, decode_value(reader, entry, depth + 1)?));
                if reader.at > end {
                    return Err(WireError::Truncated);
                }
            }
            Value::Dict(entries)
        }
        _ => {
            let mut items = Vec::new();
            while reader.at < end {
                items.push(decode_value(reader, element, depth + 1)?);
                if reader.at > end {
                    return Err(WireError::Truncated);
                }
            }
            Value::Array(items)
        }
    };
    if reader.at != end {
        return Err(WireError::Truncated);
    }
    Ok(value)
}

/// One message off the wire, with its body still marshalled: the body's
/// signature is a header field, so it is known only once the header is.
#[derive(Debug)]
struct Message {
    kind: u8,
    reply_serial: Option<u32>,
    error_name: Option<String>,
    /// Unique name of the sender, which on a bus the bus itself fills in
    /// and a client cannot forge.
    sender: Option<String>,
    signature: String,
    /// What `UNIX_FDS` declared, which must match what arrived.
    unix_fds: u32,
    body: Vec<u8>,
}

/// Marshal one message: the fixed header, the header fields, padding to
/// 8, then the body. "The length of the header must be a multiple of 8,
/// allowing the body to begin on an 8-byte boundary."
fn encode_message(
    kind: u8,
    flags: u8,
    serial: u32,
    fields: &[(u8, Value)],
    body: &[u8],
) -> Result<Vec<u8>, WireError> {
    if body.len() > MAX_MESSAGE {
        return Err(WireError::MessageTooLong(body.len()));
    }
    let fields: Vec<Value> = fields
        .iter()
        .map(|(code, value)| {
            Value::Struct(vec![
                Value::Byte(*code),
                Value::Variant(Box::new(value.clone())),
            ])
        })
        .collect();
    let mut message = encode(
        "yyyyuua(yv)",
        &[
            Value::Byte(b'l'),
            Value::Byte(kind),
            Value::Byte(flags),
            Value::Byte(PROTOCOL_VERSION),
            Value::Uint32(body.len() as u32),
            Value::Uint32(serial),
            Value::Array(fields),
        ],
    )?;
    pad(&mut message, 8);
    message.extend_from_slice(body);
    if message.len() > MAX_MESSAGE {
        return Err(WireError::MessageTooLong(message.len()));
    }
    Ok(message)
}

/// Where the body of the message starting at `head` begins and how long
/// it is, read from the fixed header alone. The header-field array's
/// length is the UINT32 at offset 12, the last of the fixed part.
fn frame(head: &[u8]) -> Result<(usize, usize), WireError> {
    let head = head.get(..FIXED_HEADER).ok_or(WireError::Truncated)?;
    if head[0] != b'l' {
        return Err(WireError::Endianness(head[0]));
    }
    if head[3] != PROTOCOL_VERSION {
        return Err(WireError::BadMessage("a message of an unknown version"));
    }
    let body_len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
    let fields_len = u32::from_le_bytes([head[12], head[13], head[14], head[15]]) as usize;
    if fields_len > MAX_ARRAY {
        return Err(WireError::ArrayTooLong(fields_len));
    }
    if body_len > MAX_MESSAGE {
        return Err(WireError::MessageTooLong(body_len));
    }
    let body_at = align_up(FIXED_HEADER + fields_len, 8);
    let total = body_at
        .checked_add(body_len)
        .ok_or(WireError::MessageTooLong(body_len))?;
    if total > MAX_MESSAGE {
        return Err(WireError::MessageTooLong(total));
    }
    Ok((body_at, body_len))
}

/// Unmarshal one whole message. Header fields whose code is known must
/// have the type the specification gives them; unknown codes are
/// ignored, which is what "Header Fields" requires of a client meeting a
/// newer bus. A code that appears twice is refused: the specification
/// gives no rule for which copy wins, and two readers picking different
/// ones is how a message means two things at once.
fn decode_message(message: &[u8]) -> Result<Message, WireError> {
    let (body_at, body_len) = frame(message)?;
    let fields_end = FIXED_HEADER
        + u32::from_le_bytes([message[12], message[13], message[14], message[15]]) as usize;
    let header = message.get(..fields_end).ok_or(WireError::Truncated)?;
    let values = decode("yyyyuua(yv)", header)?;
    let [_, Value::Byte(kind), _, _, _, _, Value::Array(fields)] = values.as_slice() else {
        return Err(WireError::BadMessage("a header it could not read"));
    };
    // The padding between the header and the body is part of neither, so
    // it is checked here rather than by the decoder.
    let padding = message
        .get(fields_end..body_at)
        .ok_or(WireError::Truncated)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(WireError::Padding);
    }
    let body = message
        .get(body_at..body_at + body_len)
        .ok_or(WireError::Truncated)?
        .to_vec();

    let mut reply_serial = None;
    let mut error_name = None;
    let mut sender = None;
    let mut signature = String::new();
    let mut unix_fds = 0;
    let mut seen: Vec<u8> = Vec::new();
    for field in fields {
        let Value::Struct(pair) = field else {
            return Err(WireError::BadMessage("a header field it could not read"));
        };
        let [Value::Byte(code), Value::Variant(value)] = pair.as_slice() else {
            return Err(WireError::BadMessage("a header field it could not read"));
        };
        let wrong = || WireError::BadMessage("a header field of the wrong type");
        if seen.contains(code) {
            return Err(WireError::BadMessage("a header field twice"));
        }
        seen.push(*code);
        match (*code, value.as_ref()) {
            (FIELD_REPLY_SERIAL, Value::Uint32(v)) => reply_serial = Some(*v),
            (FIELD_ERROR_NAME, Value::Str(v)) => error_name = Some(v.clone()),
            (FIELD_SENDER, Value::Str(v)) => sender = Some(v.clone()),
            (FIELD_SIGNATURE, Value::Signature(v)) => signature = v.clone(),
            (FIELD_UNIX_FDS, Value::Uint32(v)) => unix_fds = *v,
            (FIELD_PATH, Value::ObjectPath(_)) => {}
            (FIELD_INTERFACE | FIELD_MEMBER | FIELD_DESTINATION, Value::Str(_)) => {}
            (
                FIELD_PATH | FIELD_INTERFACE | FIELD_MEMBER | FIELD_ERROR_NAME | FIELD_REPLY_SERIAL
                | FIELD_DESTINATION | FIELD_SENDER | FIELD_SIGNATURE | FIELD_UNIX_FDS,
                _,
            ) => return Err(wrong()),
            // A field code from a newer specification: accept and ignore.
            _ => {}
        }
    }
    if signature.is_empty() && !body.is_empty() {
        return Err(WireError::BadMessage("a body with no signature"));
    }
    Ok(Message {
        kind: *kind,
        reply_serial,
        error_name,
        sender,
        signature,
        unix_fds,
        body,
    })
}

/// The ASCII decimal digits of `uid`, each byte written as two hex
/// digits: what `AUTH EXTERNAL` takes. "31303030 is ASCII decimal
/// \"1000\" represented in hex, so the client is authenticating as Unix
/// uid 1000".
fn uid_hex(uid: u32) -> String {
    const DIGITS: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::new();
    for byte in uid.to_string().into_bytes() {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

/// `Timespec` for `poll`, which takes no `Duration`.
fn timespec(d: Duration) -> Timespec {
    Timespec {
        tv_sec: d.as_secs() as Secs,
        tv_nsec: d.subsec_nanos() as Nsecs,
    }
}

/// Park until `fd` is ready for `events`, or until `deadline`.
fn wait(fd: BorrowedFd<'_>, events: PollFlags, deadline: Instant) -> Result<(), WireError> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(WireError::Timeout);
        }
        let mut fds = [PollFd::from_borrowed_fd(fd, events)];
        match poll(&mut fds, Some(&timespec(left))) {
            Ok(0) => return Err(WireError::Timeout),
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => {}
            Err(e) => return Err(WireError::Io(e.into())),
        }
    }
}

/// A connected, authenticated session-bus client that has been given its
/// unique name.
///
/// One call at a time, each with its own deadline. Anything but a
/// [`WireError::Remote`] leaves the connection half-read, so the caller
/// drops the session rather than calling again.
#[derive(Debug)]
pub struct Session {
    socket: OwnedFd,
    /// Unique names already looked up for well-known destinations, so a
    /// second call to the same name costs no round trip. An owner that
    /// changes mid-session makes the next call fail rather than accept a
    /// reply from the wrong sender.
    owners: Vec<(String, String)>,
    /// Descriptors received and closed since the last whole message, to
    /// be checked against what that message declares.
    fds_seen: usize,
    /// Serial of the last message sent; "must not be zero", so the first
    /// call sends 1.
    serial: u32,
    unique_name: String,
    fd_passing: bool,
    /// Bytes read from the socket that no message has claimed yet.
    buf: Vec<u8>,
}

impl Session {
    /// Connect to the bus socket at `path`, authenticate as this uid with
    /// `EXTERNAL`, negotiate descriptor passing and say `Hello`.
    ///
    /// The whole opening — connect, authenticate, `Hello` — shares one
    /// [`CALL_TIMEOUT`], so a bus that answers each step just inside the
    /// deadline cannot hold the caller for a multiple of it.
    ///
    /// A bus that answers `NEGOTIATE_UNIX_FD` with `ERROR` is used
    /// anyway; only a call that carries descriptors then fails, with
    /// [`WireError::NoFdPassing`].
    pub fn connect(path: &Path) -> Result<Self, WireError> {
        let deadline = Instant::now() + CALL_TIMEOUT;
        let failed = |source: Errno| WireError::Connect {
            path: path.to_owned(),
            source: source.into(),
        };
        let addr = SocketAddrUnix::new(path).map_err(failed)?;
        // CLOEXEC: nothing bubbler spawns has any business on the bus
        // connection. NONBLOCK: every wait here has a deadline.
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(failed)?;
        match rustix::net::connect(&socket, &addr) {
            Ok(()) => {}
            Err(Errno::INPROGRESS) => {
                wait(socket.as_fd(), PollFlags::OUT, deadline)?;
                match rustix::net::sockopt::socket_error(&socket) {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) | Err(e) => return Err(failed(e)),
                }
            }
            Err(e) => return Err(failed(e)),
        }
        let mut session = Self {
            socket,
            owners: Vec::new(),
            fds_seen: 0,
            serial: 0,
            unique_name: String::new(),
            fd_passing: false,
            buf: Vec::new(),
        };
        session.authenticate(deadline)?;
        session.unique_name = session.hello(deadline)?;
        Ok(session)
    }

    /// The unique name the bus gave this connection, e.g. `:1.42`.
    pub fn unique_name(&self) -> &str {
        &self.unique_name
    }

    /// Whether the bus agreed to descriptor passing on this connection.
    pub fn passes_fds(&self) -> bool {
        self.fd_passing
    }

    /// Call `member` on `iface` of `path` at `dest`, with a body of
    /// `body` marshalled against `sig` and `fds` travelling beside it,
    /// and return the reply's values.
    ///
    /// The reply is the one whose `REPLY_SERIAL` is this call's, whose
    /// type is `METHOD_RETURN` or `ERROR`, and whose `SENDER` is the
    /// unique name that owns `dest`. Everything else that arrives
    /// meanwhile is dropped, as are any descriptors it carries — nothing
    /// bubbler calls answers with one. An `ERROR` reply becomes
    /// [`WireError::Remote`], which leaves the session usable; every
    /// other failure does not.
    ///
    /// Waits [`CALL_TIMEOUT`] in total: the owner lookup, the sending
    /// and every message skipped on the way to the reply.
    // A destination, an object, an interface, a member, a signature, a
    // body and its descriptors is what a D-Bus method call is; a struct
    // of the names would only move the same list one line up.
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &mut self,
        dest: &str,
        path: &str,
        iface: &str,
        member: &str,
        sig: &str,
        body: &[Value],
        fds: &[BorrowedFd<'_>],
    ) -> Result<Vec<Value>, WireError> {
        let deadline = Instant::now() + CALL_TIMEOUT;
        self.call_by(dest, path, iface, member, sig, body, fds, deadline)
    }

    /// [`Session::call`] against a deadline the caller owns, so the
    /// opening handshake and an owner lookup share the call's.
    #[allow(clippy::too_many_arguments)]
    fn call_by(
        &mut self,
        dest: &str,
        path: &str,
        iface: &str,
        member: &str,
        sig: &str,
        body: &[Value],
        fds: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<Vec<Value>, WireError> {
        if dest.is_empty() {
            return Err(WireError::NoDestination);
        }
        if !fds.is_empty() && !self.fd_passing {
            return Err(WireError::NoFdPassing);
        }
        if fds.len() > MAX_CALL_FDS {
            return Err(WireError::TooManyFds(fds.len()));
        }
        let count = u32::try_from(fds.len()).map_err(|_| WireError::TooManyFds(fds.len()))?;
        for value in body {
            check_fd_indices(value, count)?;
        }

        // Before anything is sent, so the reply has a sender to be held
        // to; the lookup is itself a call, to a name that needs none.
        let owner = self.owner_of(dest, deadline)?;
        let body = encode(sig, body)?;
        let mut fields = vec![
            (FIELD_PATH, Value::ObjectPath(path.to_owned())),
            (FIELD_DESTINATION, Value::Str(dest.to_owned())),
        ];
        // An empty interface is no interface: the member is left to be
        // resolved by the callee, which the specification allows for a
        // method call.
        if !iface.is_empty() {
            fields.push((FIELD_INTERFACE, Value::Str(iface.to_owned())));
        }
        fields.push((FIELD_MEMBER, Value::Str(member.to_owned())));
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        if count > 0 {
            fields.push((FIELD_UNIX_FDS, Value::Uint32(count)));
        }
        self.serial = self.serial.wrapping_add(1).max(1);
        let serial = self.serial;
        let message = encode_message(MSG_METHOD_CALL, 0, serial, &fields, &body)?;
        self.send(&message, fds, deadline)?;

        loop {
            // Checked here as well as inside the read: a peer that keeps
            // sending messages to skip never blocks the reader, so
            // without this the deadline would only bound an idle bus.
            if Instant::now() >= deadline {
                return Err(WireError::Timeout);
            }
            let reply = self.receive(deadline)?;
            if reply.reply_serial != Some(serial) {
                continue;
            }
            // "if a signal has a reply serial it must be ignored even
            // though it has no meaning as of this version of the spec",
            // and an unknown message type "must be ignored" as well:
            // only the two reply types may answer a call.
            if reply.kind != MSG_METHOD_RETURN && reply.kind != MSG_ERROR {
                continue;
            }
            // Serials are guessable, so a reply is only a reply if it
            // came from the name's owner. Anyone else on the bus — a
            // sandboxed instance with the `dbus` grant included — could
            // otherwise answer first and choose what bubbler believes.
            match reply.sender.as_deref() {
                Some(sender) if sender == owner => {}
                Some(_) => continue,
                None => return Err(WireError::BadMessage("a reply with no sender")),
            }
            return match reply.kind {
                MSG_METHOD_RETURN => decode(&reply.signature, &reply.body),
                MSG_ERROR => {
                    let Some(name) = reply.error_name else {
                        return Err(WireError::BadMessage("an error reply with no error name"));
                    };
                    Err(WireError::Remote {
                        name,
                        // "If the first argument exists and is a string,
                        // it is an error message." The name is the half
                        // that matters, so a body that will not decode
                        // leaves the refusal a refusal rather than a
                        // wire failure.
                        message: match decode(&reply.signature, &reply.body) {
                            Ok(values) => match values.first() {
                                Some(Value::Str(text)) => text.clone(),
                                _ => String::new(),
                            },
                            Err(_) => String::new(),
                        },
                    })
                }
                _ => Err(WireError::BadMessage("a reply that is not a reply")),
            };
        }
    }

    /// The unique name that may answer a call to `dest`.
    ///
    /// A unique name owns itself and the bus answers for its own name,
    /// so neither needs asking; every other destination is a well-known
    /// name whose owner the bus is asked for once per session.
    fn owner_of(&mut self, dest: &str, deadline: Instant) -> Result<String, WireError> {
        if dest == BUS_NAME || dest.starts_with(':') {
            return Ok(dest.to_owned());
        }
        if let Some((_, owner)) = self.owners.iter().find(|(name, _)| name == dest) {
            return Ok(owner.clone());
        }
        let reply = self.call_by(
            BUS_NAME,
            BUS_PATH,
            BUS_INTERFACE,
            "GetNameOwner",
            "s",
            &[Value::Str(dest.to_owned())],
            &[],
            deadline,
        )?;
        let [Value::Str(owner)] = reply.as_slice() else {
            return Err(WireError::BadMessage(
                "a GetNameOwner reply that is not one name",
            ));
        };
        if !owner.starts_with(':') {
            return Err(WireError::BadMessage("a name owner that is not unique"));
        }
        self.owners.push((dest.to_owned(), owner.clone()));
        Ok(owner.clone())
    }

    /// The authentication handshake: the credentials nul byte and
    /// `AUTH EXTERNAL <uid in hex>`, then `NEGOTIATE_UNIX_FD`, then
    /// `BEGIN`, after which the socket carries messages only.
    fn authenticate(&mut self, deadline: Instant) -> Result<(), WireError> {
        let uid = rustix::process::getuid().as_raw();
        // "Immediately after connecting to the server, the client must
        // send a single nul byte", which may carry credentials with it.
        let hello = format!("\0AUTH EXTERNAL {}\r\n", uid_hex(uid));
        self.send(hello.as_bytes(), &[], deadline)?;
        let line = self.line(deadline)?;
        if let Some(rest) = line.strip_prefix("REJECTED") {
            return Err(WireError::AuthRejected(rest.trim().to_owned()));
        }
        if !line.starts_with("OK ") {
            return Err(WireError::Auth(line));
        }
        self.send(b"NEGOTIATE_UNIX_FD\r\n", &[], deadline)?;
        let line = self.line(deadline)?;
        if line == "AGREE_UNIX_FD" {
            self.fd_passing = true;
        } else if !line.starts_with("ERROR") {
            return Err(WireError::Auth(line));
        }
        // "The server does not reply" to BEGIN.
        self.send(b"BEGIN\r\n", &[], deadline)?;
        Ok(())
    }

    /// The unique name, from the `Hello` every connection owes the bus
    /// before it may send anything else.
    ///
    /// "Unique connection names must begin with the character ':'": a
    /// name that does not is not one the bus assigned.
    fn hello(&mut self, deadline: Instant) -> Result<String, WireError> {
        let reply = self.call_by(
            BUS_NAME,
            BUS_PATH,
            BUS_INTERFACE,
            "Hello",
            "",
            &[],
            &[],
            deadline,
        )?;
        let [Value::Str(name)] = reply.as_slice() else {
            return Err(WireError::BadMessage("a Hello reply that is not one name"));
        };
        if !name.starts_with(':') {
            return Err(WireError::BadMessage(
                "a Hello reply that is not a unique name",
            ));
        }
        Ok(name.clone())
    }

    /// One `\r\n`-terminated authentication line, without its ending.
    /// "All bytes must be in the ASCII character set."
    fn line(&mut self, deadline: Instant) -> Result<String, WireError> {
        loop {
            if let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..end + 2).take(end).collect();
                if !line.is_ascii() {
                    return Err(WireError::Auth(String::from_utf8_lossy(&line).into_owned()));
                }
                return String::from_utf8(line).map_err(|_| WireError::BadString);
            }
            if self.buf.len() > MAX_AUTH_LINE {
                return Err(WireError::Auth("a line with no end".to_owned()));
            }
            self.fill(deadline)?;
        }
    }

    /// Write every byte, with `fds` attached to the first `sendmsg` so
    /// they travel with the message they belong to: descriptors "may not
    /// be sent before the first byte of the message itself is
    /// transferred or after the last byte".
    fn send(
        &self,
        bytes: &[u8],
        fds: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<(), WireError> {
        let mut sent = 0;
        let mut carried = fds;
        while sent < bytes.len() {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_CALL_FDS))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            if !carried.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(carried)) {
                return Err(WireError::TooManyFds(carried.len()));
            }
            // NOSIGNAL: a bus that goes away is an error to return, not a
            // signal that kills bubbler.
            match sendmsg(
                &self.socket,
                &[IoSlice::new(&bytes[sent..])],
                &mut ancillary,
                SendFlags::NOSIGNAL,
            ) {
                Ok(0) => return Err(WireError::Closed),
                Ok(n) => {
                    sent += n;
                    // Sent once, with the first bytes; the rest of the
                    // message carries none.
                    carried = &[];
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    wait(self.socket.as_fd(), PollFlags::OUT, deadline)?;
                }
                Err(e) => return Err(WireError::Io(e.into())),
            }
        }
        Ok(())
    }

    /// Read whatever the socket has into the buffer, waiting for it if
    /// there is nothing yet. Any descriptor that arrives is closed at
    /// once: no call bubbler makes expects one back, and one left open
    /// would be a descriptor the bus chose for us to hold.
    fn fill(&mut self, deadline: Instant) -> Result<(), WireError> {
        let mut chunk = [0u8; 4096];
        loop {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_REPLY_FDS))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            match recvmsg(
                &self.socket,
                &mut [IoSliceMut::new(&mut chunk)],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            ) {
                Ok(got) => {
                    for message in ancillary.drain() {
                        if let RecvAncillaryMessage::ScmRights(fds) = message {
                            for fd in fds {
                                self.fds_seen += 1;
                                drop(fd);
                            }
                        }
                    }
                    if got.bytes == 0 {
                        return Err(WireError::Closed);
                    }
                    self.buf.extend_from_slice(&chunk[..got.bytes]);
                    return Ok(());
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    wait(self.socket.as_fd(), PollFlags::IN, deadline)?;
                }
                Err(e) => return Err(WireError::Io(e.into())),
            }
        }
    }

    /// The next whole message, read and taken off the buffer.
    ///
    /// The descriptors that arrived while it was being read are its own:
    /// they "may not be sent before the first byte of the message itself
    /// is transferred or after the last byte", and the kernel hands back
    /// the data of one `sendmsg` with the descriptors that came with it.
    /// A message that declares a different number than arrived is
    /// refused rather than read.
    fn receive(&mut self, deadline: Instant) -> Result<Message, WireError> {
        loop {
            // First, so that a peer sending whole messages as fast as
            // the socket takes them still runs out of deadline: nothing
            // below ever blocks while there is something to read.
            if Instant::now() >= deadline {
                return Err(WireError::Timeout);
            }
            if self.buf.len() >= FIXED_HEADER {
                let (body_at, body_len) = frame(&self.buf)?;
                let total = body_at + body_len;
                if self.buf.len() >= total {
                    let bytes: Vec<u8> = self.buf.drain(..total).collect();
                    let message = decode_message(&bytes)?;
                    let arrived = std::mem::take(&mut self.fds_seen);
                    if arrived != message.unix_fds as usize {
                        return Err(WireError::BadMessage(
                            "a message with fewer or more descriptors than it declares",
                        ));
                    }
                    return Ok(message);
                }
            }
            self.fill(deadline)?;
        }
    }
}

/// Refuse a body naming a descriptor the call was not given: an index
/// past the end would have the far side `fstat` whatever happened to be
/// at that position instead.
fn check_fd_indices(value: &Value, count: u32) -> Result<(), WireError> {
    match value {
        Value::Fd(index) => {
            if *index >= count {
                return Err(WireError::FdIndex(*index));
            }
        }
        Value::Array(items) | Value::Struct(items) => {
            for item in items {
                check_fd_indices(item, count)?;
            }
        }
        Value::Dict(entries) => {
            for (_, item) in entries {
                check_fd_indices(item, count)?;
            }
        }
        Value::Variant(inner) => check_fd_indices(inner, count)?,
        _ => {}
    }
    Ok(())
}

/// The fake bus every module's tests script: one connection, the
/// `EXTERNAL` handshake, and replies written from the bus's side.
///
/// It lives here because the client under it does: a second copy of this
/// harness is a second idea of what a bus sends, and the first thing to
/// go out of step is the `SENDER` the client checks.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread::JoinHandle;

    use super::*;

    /// The header field codes and message types a script names, bound to
    /// the encoder's own so a test cannot assert on a number the wire
    /// does not use.
    pub(crate) const BUS_NAME: &str = super::BUS_NAME;
    pub(crate) const FIELD_PATH: u8 = super::FIELD_PATH;
    pub(crate) const FIELD_INTERFACE: u8 = super::FIELD_INTERFACE;
    pub(crate) const FIELD_MEMBER: u8 = super::FIELD_MEMBER;
    pub(crate) const FIELD_ERROR_NAME: u8 = super::FIELD_ERROR_NAME;
    pub(crate) const FIELD_REPLY_SERIAL: u8 = super::FIELD_REPLY_SERIAL;
    pub(crate) const FIELD_DESTINATION: u8 = super::FIELD_DESTINATION;
    pub(crate) const FIELD_SENDER: u8 = super::FIELD_SENDER;
    pub(crate) const FIELD_SIGNATURE: u8 = super::FIELD_SIGNATURE;
    pub(crate) const MSG_METHOD_RETURN: u8 = super::MSG_METHOD_RETURN;
    pub(crate) const MSG_ERROR: u8 = super::MSG_ERROR;

    /// Longest a script waits for the client, and the client for a
    /// connection: a test that stops talking fails its join rather than
    /// hanging the run.
    pub(crate) const SCRIPT_TIMEOUT: Duration = Duration::from_secs(20);

    /// One method call as the bus saw it.
    pub(crate) struct Call {
        /// Header fields in the order the client wrote them.
        pub(crate) fields: Vec<(u8, Value)>,
        /// Signature of the body, empty when there is none.
        pub(crate) signature: String,
        /// The body, decoded against that signature.
        pub(crate) body: Vec<Value>,
        /// Serial the reply must name.
        pub(crate) serial: u32,
        /// Descriptors the call carried.
        pub(crate) fds: Vec<OwnedFd>,
    }

    impl Call {
        /// The text of a header field, e.g. the member name.
        pub(crate) fn text(&self, code: u8) -> String {
            match self.fields.iter().find(|(c, _)| *c == code) {
                Some((_, Value::Str(text) | Value::ObjectPath(text))) => text.clone(),
                other => panic!("header field {code} is {other:?}"),
            }
        }

        /// Every textual header field, in the order it was written: what
        /// the client asked, and of whom.
        pub(crate) fn texts(&self) -> Vec<(u8, String)> {
            self.fields
                .iter()
                .map(|(code, value)| {
                    let text = match value {
                        Value::Str(s) | Value::ObjectPath(s) | Value::Signature(s) => s.clone(),
                        other => format!("{other:?}"),
                    };
                    (*code, text)
                })
                .collect()
        }
    }

    /// The serial of a message: the second UINT32 of its header.
    pub(crate) fn serial_of(message: &[u8]) -> u32 {
        u32::from_le_bytes([message[8], message[9], message[10], message[11]])
    }

    /// A bus on a socket under `dir` that runs `script` on the one
    /// connection it accepts.
    pub(crate) fn fake_bus<F>(dir: &Path, script: F) -> (PathBuf, JoinHandle<()>)
    where
        F: FnOnce(UnixStream) + Send + 'static,
    {
        let path = dir.join("bus");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            // Both waits are bounded before either happens: a client
            // that never connects, or one that stops mid-message, fails
            // the join instead of hanging the run.
            wait(
                listener.as_fd(),
                PollFlags::IN,
                Instant::now() + SCRIPT_TIMEOUT,
            )
            .expect("a client connected");
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(SCRIPT_TIMEOUT)).unwrap();
            script(stream);
        });
        (path, handle)
    }

    /// One `\r\n` line from the client, read a byte at a time so none of
    /// the message stream that follows `BEGIN` is swallowed.
    pub(crate) fn server_line(stream: &UnixStream) -> String {
        let mut out = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            (&*stream).read_exact(&mut byte).unwrap();
            out.push(byte[0]);
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
                return String::from_utf8(out).unwrap();
            }
        }
    }

    /// The `EXTERNAL` handshake from the bus's side, as the
    /// specification's Figure 7 (or Figure 8 with `agree` false) has it.
    pub(crate) fn server_auth(stream: &UnixStream, agree: bool) {
        let uid = rustix::process::getuid().as_raw();
        assert_eq!(
            server_line(stream),
            format!("\0AUTH EXTERNAL {}", uid_hex(uid))
        );
        (&*stream).write_all(b"OK 1234deadbeef\r\n").unwrap();
        assert_eq!(server_line(stream), "NEGOTIATE_UNIX_FD");
        let reply: &[u8] = if agree {
            b"AGREE_UNIX_FD\r\n"
        } else {
            b"ERROR not on this transport\r\n"
        };
        (&*stream).write_all(reply).unwrap();
        assert_eq!(server_line(stream), "BEGIN");
    }

    /// One whole message from the client, with any descriptors it carried.
    pub(crate) fn server_message(stream: &UnixStream) -> (Vec<u8>, Vec<OwnedFd>) {
        let mut buf: Vec<u8> = Vec::new();
        let mut fds = Vec::new();
        loop {
            if buf.len() >= FIXED_HEADER {
                let (body_at, body_len) = frame(&buf).unwrap();
                if buf.len() >= body_at + body_len {
                    buf.truncate(body_at + body_len);
                    return (buf, fds);
                }
            }
            let mut chunk = [0u8; 4096];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let got = recvmsg(
                stream.as_fd(),
                &mut [IoSliceMut::new(&mut chunk)],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            )
            .unwrap();
            for message in ancillary.drain() {
                if let RecvAncillaryMessage::ScmRights(received) = message {
                    fds.extend(received);
                }
            }
            assert!(got.bytes > 0, "the client hung up mid-message");
            buf.extend_from_slice(&chunk[..got.bytes]);
        }
    }

    /// Send one message from the bus's side.
    pub(crate) fn server_send(
        stream: &UnixStream,
        kind: u8,
        serial: u32,
        fields: &[(u8, Value)],
        sig: &str,
        body: &[Value],
    ) {
        let mut fields = fields.to_vec();
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        let body = encode(sig, body).unwrap();
        let message = encode_message(kind, 0, serial, &fields, &body).unwrap();
        (&*stream).write_all(&message).unwrap();
    }

    /// A `METHOD_RETURN` to the call with serial `reply_to`, from
    /// `sender` — the bus fills that field in, so every reply has one.
    pub(crate) fn server_reply(
        stream: &UnixStream,
        serial: u32,
        reply_to: u32,
        sender: &str,
        sig: &str,
        body: &[Value],
    ) {
        server_send(
            stream,
            MSG_METHOD_RETURN,
            serial,
            &[
                (FIELD_REPLY_SERIAL, Value::Uint32(reply_to)),
                (FIELD_SENDER, Value::Str(sender.to_owned())),
            ],
            sig,
            body,
        );
    }

    /// The bytes of a `METHOD_RETURN`, for a test that writes them itself.
    pub(crate) fn reply_bytes(
        serial: u32,
        reply_to: u32,
        sender: &str,
        sig: &str,
        body: &[Value],
    ) -> Vec<u8> {
        let mut fields = vec![
            (FIELD_REPLY_SERIAL, Value::Uint32(reply_to)),
            (FIELD_SENDER, Value::Str(sender.to_owned())),
        ];
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        let body = encode(sig, body).unwrap();
        encode_message(MSG_METHOD_RETURN, 0, serial, &fields, &body).unwrap()
    }

    /// A signal, which a pending call must skip whatever it carries.
    pub(crate) fn signal_bytes(serial: u32, reply_serial: Option<u32>) -> Vec<u8> {
        let mut fields = vec![
            (FIELD_PATH, Value::ObjectPath("/org/a".to_owned())),
            (FIELD_INTERFACE, Value::Str("org.a".to_owned())),
            (FIELD_MEMBER, Value::Str("Changed".to_owned())),
            (FIELD_SENDER, Value::Str(":1.5".to_owned())),
            (FIELD_SIGNATURE, Value::Signature("s".to_owned())),
        ];
        if let Some(reply_serial) = reply_serial {
            fields.push((FIELD_REPLY_SERIAL, Value::Uint32(reply_serial)));
        }
        let body = encode("s", &[Value::Str("ignore me".to_owned())]).unwrap();
        encode_message(4, 0, serial, &fields, &body).unwrap()
    }

    /// Answer the `Hello` every connection opens with, and return the
    /// bytes of the call so a test can look at them.
    pub(crate) fn server_hello(stream: &UnixStream, name: &str) -> Vec<u8> {
        let (bytes, fds) = server_message(stream);
        assert!(fds.is_empty());
        server_reply(
            stream,
            1,
            serial_of(&bytes),
            BUS_NAME,
            "s",
            &[Value::Str(name.to_owned())],
        );
        bytes
    }

    /// The `EXTERNAL` handshake and the `Hello` every connection opens
    /// with, from the bus's side.
    pub(crate) fn server_start(stream: &UnixStream) {
        server_auth(stream, true);
        server_hello(stream, ":1.5");
    }

    /// One whole method call from the client, decoded.
    pub(crate) fn server_call(stream: &UnixStream) -> Call {
        let (bytes, fds) = server_message(stream);
        let fields_len = u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .expect("a header the framing accepted"),
        ) as usize;
        let header = decode("yyyyuua(yv)", &bytes[..FIXED_HEADER + fields_len]).unwrap();
        let (Value::Uint32(serial), Value::Array(raw)) = (&header[5], &header[6]) else {
            panic!("a header that is not a header: {header:?}");
        };
        let fields: Vec<(u8, Value)> = raw
            .iter()
            .map(|field| match field {
                Value::Struct(pair) => match pair.as_slice() {
                    [Value::Byte(code), Value::Variant(value)] => (*code, (**value).clone()),
                    other => panic!("a header field that is not one: {other:?}"),
                },
                other => panic!("a header field that is not one: {other:?}"),
            })
            .collect();
        let signature = match fields.iter().find(|(code, _)| *code == FIELD_SIGNATURE) {
            Some((_, Value::Signature(sig))) => sig.clone(),
            _ => String::new(),
        };
        let body = decode(&signature, &bytes[align_up(FIXED_HEADER + fields_len, 8)..]).unwrap();
        Call {
            fields,
            signature,
            body,
            serial: *serial,
            fds,
        }
    }

    /// The next call to `member` the client makes. A lookup of who owns
    /// the destination is answered with `owner` on the way, since the
    /// client holds the reply to the unique name the bus names here.
    pub(crate) fn server_awaiting(stream: &UnixStream, member: &str, owner: &str) -> Call {
        loop {
            let call = server_call(stream);
            let asked = call.text(FIELD_MEMBER);
            if asked == member {
                return call;
            }
            assert_eq!(asked, "GetNameOwner", "the client called {asked}");
            server_reply(
                stream,
                1,
                call.serial,
                BUS_NAME,
                "s",
                &[Value::Str(owner.to_owned())],
            );
        }
    }

    /// An `ERROR` reply from `sender` to the call with serial `reply_to`.
    pub(crate) fn server_error(
        stream: &UnixStream,
        reply_to: u32,
        sender: &str,
        name: &str,
        message: &str,
    ) {
        server_send(
            stream,
            MSG_ERROR,
            1,
            &[
                (FIELD_REPLY_SERIAL, Value::Uint32(reply_to)),
                (FIELD_SENDER, Value::Str(sender.to_owned())),
                (FIELD_ERROR_NAME, Value::Str(name.to_owned())),
            ],
            "s",
            &[Value::Str(message.to_owned())],
        );
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;

    use super::testing::{
        fake_bus, reply_bytes, serial_of, server_auth, server_hello, server_line, server_message,
        server_reply, server_send, signal_bytes,
    };
    use super::*;

    /// The `Hello` call bubbler opens every connection with, byte for
    /// byte, laid out by hand from "Message Format": the four bytes, the
    /// body length, the serial, then the header-field array, whose
    /// `(yv)` elements each start on an 8-byte boundary.
    const HELLO_FRAME: [u8; 128] = [
        // little-endian, METHOD_CALL, no flags, protocol version 1
        b'l', 1, 0, 1, // body length 0
        0, 0, 0, 0, // serial 1
        1, 0, 0, 0, // the header fields take 110 bytes
        0x6e, 0, 0, 0, // PATH, a variant of signature "o", 21 bytes of text
        1, 1, b'o', 0, 21, 0, 0, 0, b'/', b'o', b'r', b'g', b'/', b'f', b'r', b'e', b'e', b'd',
        b'e', b's', b'k', b't', b'o', b'p', b'/', b'D', b'B', b'u', b's', 0,
        // padding to the next 8-byte boundary
        0, 0, // DESTINATION, a variant of signature "s", 20 bytes of text
        6, 1, b's', 0, 20, 0, 0, 0, b'o', b'r', b'g', b'.', b'f', b'r', b'e', b'e', b'd', b'e',
        b's', b'k', b't', b'o', b'p', b'.', b'D', b'B', b'u', b's', 0, 0, 0, 0,
        // INTERFACE, the same name again
        2, 1, b's', 0, 20, 0, 0, 0, b'o', b'r', b'g', b'.', b'f', b'r', b'e', b'e', b'd', b'e',
        b's', b'k', b't', b'o', b'p', b'.', b'D', b'B', b'u', b's', 0, 0, 0, 0,
        // MEMBER "Hello"
        3, 1, b's', 0, 5, 0, 0, 0, b'H', b'e', b'l', b'l', b'o', 0,
        // padding to the 8-byte boundary the body would start on
        0, 0,
    ];

    /// The header fields of the `Hello` call, in the order [`Session::call`]
    /// writes them.
    fn hello_fields() -> Vec<(u8, Value)> {
        vec![
            (FIELD_PATH, Value::ObjectPath(BUS_PATH.to_owned())),
            (FIELD_DESTINATION, Value::Str(BUS_NAME.to_owned())),
            (FIELD_INTERFACE, Value::Str(BUS_INTERFACE.to_owned())),
            (FIELD_MEMBER, Value::Str("Hello".to_owned())),
        ]
    }

    #[test]
    fn the_hello_call_is_marshalled_byte_for_byte() {
        let message = encode_message(MSG_METHOD_CALL, 0, 1, &hello_fields(), &[]).unwrap();
        assert_eq!(message, HELLO_FRAME);
        let back = decode_message(&HELLO_FRAME).unwrap();
        assert_eq!(back.kind, MSG_METHOD_CALL);
        assert_eq!(back.reply_serial, None);
        assert!(back.body.is_empty());
        assert_eq!(back.signature, "");
    }

    #[test]
    fn the_specification_string_example_marshals_as_printed() {
        // "if the current position is a multiple of 8 bytes from the
        // beginning of a little-endian message, strings 'foo', '+' and
        // 'bar' would be serialized in sequence as follows".
        let values = vec![
            Value::Str("foo".to_owned()),
            Value::Str("+".to_owned()),
            Value::Str("bar".to_owned()),
        ];
        let bytes = encode("sss", &values).unwrap();
        assert_eq!(
            bytes,
            [
                0x03, 0x00, 0x00, 0x00, b'f', b'o', b'o', 0x00, 0x01, 0x00, 0x00, 0x00, b'+', 0x00,
                // two bytes of padding to reach the next multiple of 4
                0x00, 0x00, 0x03, 0x00, 0x00, 0x00, b'b', b'a', b'r', 0x00,
            ]
        );
        assert_eq!(decode("sss", &bytes).unwrap(), values);
    }

    #[test]
    fn an_array_pads_to_its_element_even_when_it_is_empty() {
        // "an array containing only the 64-bit integer 5": the length,
        // then padding to the element's 8-byte boundary that the length
        // does not count, then the element.
        assert_eq!(
            encode("at", &[Value::Array(vec![Value::Uint64(5)])]).unwrap(),
            [8, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]
        );
        // "the alignment padding for the first element is required even
        // if there is no first element".
        assert_eq!(
            encode("at", &[Value::Array(Vec::new())]).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_variant_carries_the_signature_of_what_is_in_it() {
        // "a variant containing a 64-bit integer 5": the signature, then
        // padding to the contained value's own alignment.
        assert_eq!(
            encode("v", &[Value::Variant(Box::new(Value::Uint64(5)))]).unwrap(),
            [0x01, b't', 0x00, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_value_is_padded_to_its_own_alignment() {
        assert_eq!(
            encode("yu", &[Value::Byte(1), Value::Uint32(2)]).unwrap(),
            [1, 0, 0, 0, 2, 0, 0, 0]
        );
        assert_eq!(
            encode("yt", &[Value::Byte(1), Value::Uint64(2)]).unwrap(),
            [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn every_type_round_trips() {
        let cases: Vec<(&str, Vec<Value>)> = vec![
            ("y", vec![Value::Byte(0xab)]),
            ("b", vec![Value::Bool(true)]),
            ("b", vec![Value::Bool(false)]),
            ("n", vec![Value::Int16(-2)]),
            ("q", vec![Value::Uint16(7)]),
            ("i", vec![Value::Int32(-70_000)]),
            ("u", vec![Value::Uint32(70_000)]),
            ("x", vec![Value::Int64(-5_000_000_000)]),
            ("t", vec![Value::Uint64(5_000_000_000)]),
            ("d", vec![Value::Double(0.5)]),
            ("s", vec![Value::Str("héllo".to_owned())]),
            ("s", vec![Value::Str(String::new())]),
            (
                "o",
                vec![Value::ObjectPath(
                    "/org/freedesktop/portal/documents".to_owned(),
                )],
            ),
            ("g", vec![Value::Signature("a{sv}".to_owned())]),
            ("h", vec![Value::Fd(3)]),
            ("ay", vec![Value::ByteArray(vec![1, 2, 3])]),
            ("ay", vec![Value::ByteArray(Vec::new())]),
            (
                "as",
                vec![Value::Array(vec![
                    Value::Str("read".to_owned()),
                    Value::Str("write".to_owned()),
                ])],
            ),
            ("ah", vec![Value::Array(vec![Value::Fd(0), Value::Fd(1)])]),
            (
                "a{sv}",
                vec![Value::Dict(vec![
                    (
                        "mountpoint".to_owned(),
                        Value::Variant(Box::new(Value::ByteArray(b"/run/user/1000/doc".to_vec()))),
                    ),
                    (
                        "count".to_owned(),
                        Value::Variant(Box::new(Value::Uint32(2))),
                    ),
                ])],
            ),
            ("a{sv}", vec![Value::Dict(Vec::new())]),
            (
                "(is)",
                vec![Value::Struct(vec![
                    Value::Int32(1),
                    Value::Str("x".to_owned()),
                ])],
            ),
            (
                "a(yv)",
                vec![Value::Array(vec![Value::Struct(vec![
                    Value::Byte(9),
                    Value::Variant(Box::new(Value::Uint32(1))),
                ])])],
            ),
            (
                "v",
                vec![Value::Variant(Box::new(Value::Str("v".to_owned())))],
            ),
            // The shape of the `AddFull` call and of its reply.
            (
                "ahusas",
                vec![
                    Value::Array(vec![Value::Fd(0), Value::Fd(1)]),
                    Value::Uint32(1),
                    Value::Str("org.bubbler.pdf".to_owned()),
                    Value::Array(vec![
                        Value::Str("read".to_owned()),
                        Value::Str("write".to_owned()),
                    ]),
                ],
            ),
            (
                "asa{sv}",
                vec![
                    Value::Array(vec![Value::Str("1a2b".to_owned())]),
                    Value::Dict(Vec::new()),
                ],
            ),
        ];
        for (sig, values) in cases {
            let bytes = encode(sig, &values).unwrap();
            assert_eq!(decode(sig, &bytes).unwrap(), values, "signature {sig:?}");
        }
    }

    #[test]
    fn padding_that_is_not_nul_is_refused() {
        let mut bytes = encode("yu", &[Value::Byte(1), Value::Uint32(2)]).unwrap();
        bytes[2] = 0xff;
        assert!(matches!(decode("yu", &bytes), Err(WireError::Padding)));
    }

    #[test]
    fn a_truncated_value_is_refused() {
        let mut bytes = encode("as", &[Value::Array(vec![Value::Str("read".to_owned())])]).unwrap();
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(decode("as", &bytes), Err(WireError::Truncated)));
        assert!(matches!(decode("u", &[1, 2, 3]), Err(WireError::Truncated)));
    }

    #[test]
    fn an_array_whose_elements_do_not_fill_it_is_refused() {
        let mut bytes = encode("ay", &[Value::ByteArray(vec![1, 2, 3, 4])]).unwrap();
        // One byte fewer than the elements that follow: the sender and
        // the reader disagree about where the array ends.
        bytes[..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(decode("ay", &bytes), Err(WireError::Trailing(1))));
        let mut bytes = encode("au", &[Value::Array(vec![Value::Uint32(1)])]).unwrap();
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(decode("au", &bytes), Err(WireError::Truncated)));
    }

    #[test]
    fn an_array_longer_than_the_specification_allows_is_refused() {
        let mut bytes = encode("ay", &[Value::ByteArray(vec![1])]).unwrap();
        bytes[..4].copy_from_slice(&(MAX_ARRAY as u32 + 1).to_le_bytes());
        assert!(matches!(
            decode("ay", &bytes),
            Err(WireError::ArrayTooLong(_))
        ));
        // And one that would be believed if the length were not checked
        // against what is there.
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decode("ay", &bytes),
            Err(WireError::ArrayTooLong(_))
        ));
    }

    #[test]
    fn a_string_with_a_nul_in_it_is_refused() {
        assert!(matches!(
            encode("s", &[Value::Str("a\0b".to_owned())]),
            Err(WireError::BadString)
        ));
        let mut bytes = encode("s", &[Value::Str("ab".to_owned())]).unwrap();
        // "a\0", where a C reader would stop early and see "a".
        bytes[5] = 0;
        assert!(matches!(decode("s", &bytes), Err(WireError::BadString)));
    }

    #[test]
    fn a_string_that_does_not_end_in_a_nul_is_refused() {
        let mut bytes = encode("s", &[Value::Str("ab".to_owned())]).unwrap();
        let last = bytes.len() - 1;
        bytes[last] = b'c';
        assert!(matches!(decode("s", &bytes), Err(WireError::BadString)));
    }

    #[test]
    fn a_string_that_is_not_utf8_is_refused() {
        let bytes = [1, 0, 0, 0, 0xff, 0];
        assert!(matches!(decode("s", &bytes), Err(WireError::BadString)));
    }

    #[test]
    fn bytes_left_over_are_refused() {
        let mut bytes = encode("u", &[Value::Uint32(1)]).unwrap();
        bytes.push(0);
        assert!(matches!(decode("u", &bytes), Err(WireError::Trailing(1))));
    }

    #[test]
    fn a_boolean_that_is_not_zero_or_one_is_refused() {
        assert!(matches!(
            decode("b", &2u32.to_le_bytes()),
            Err(WireError::BadBool(2))
        ));
    }

    #[test]
    fn object_paths_follow_the_rules_in_the_specification() {
        for good in ["/", "/a", "/org/freedesktop/portal/documents", "/a_1/B9"] {
            assert!(valid_object_path(good), "{good:?}");
        }
        for bad in ["", "a", "/a/", "//a", "/a//b", "/a.b", "/a-b", "/a b"] {
            assert!(!valid_object_path(bad), "{bad:?}");
        }
        assert!(matches!(
            encode("o", &[Value::ObjectPath("a.b".to_owned())]),
            Err(WireError::BadObjectPath(_))
        ));
        let mut bytes = encode("o", &[Value::ObjectPath("/ab".to_owned())]).unwrap();
        bytes[4] = b'.';
        assert!(matches!(
            decode("o", &bytes),
            Err(WireError::BadObjectPath(_))
        ));
    }

    #[test]
    fn signatures_that_are_not_single_complete_types_are_refused() {
        for bad in [
            "aa", "(ii", "ii)", "a", "()", "{sv}", "a{vs}", "a{s}", "a{svv}", "r", "e", "*", "?",
            "m", "@",
        ] {
            assert!(parse_signature(bad).is_err(), "{bad:?}");
        }
        for good in [
            "", "i", "ii", "aiai", "(ii)(ii)", "a{sv}", "a(ii)", "v", "ay", "(i(ii))", "aay",
        ] {
            assert!(parse_signature(good).is_ok(), "{good:?}");
        }
        assert!(parse_signature(&"y".repeat(MAX_SIGNATURE)).is_ok());
        assert!(parse_signature(&"y".repeat(MAX_SIGNATURE + 1)).is_err());
    }

    #[test]
    fn nesting_past_the_limit_is_refused() {
        assert!(parse_signature(&format!("{}y", "a".repeat(MAX_CONTAINER_DEPTH))).is_ok());
        assert!(parse_signature(&format!("{}y", "a".repeat(MAX_CONTAINER_DEPTH + 1))).is_err());
        // Variants carry their own signature, so without a running total
        // a reply could nest them until the decoder ran out of stack.
        let mut bytes = Vec::new();
        for _ in 0..MAX_DEPTH + 2 {
            bytes.extend_from_slice(&[1, b'v', 0]);
        }
        bytes.extend_from_slice(&[1, b'y', 0, 0]);
        assert!(matches!(decode("v", &bytes), Err(WireError::Depth)));
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused() {
        assert!(matches!(
            encode("s", &[Value::Uint32(1)]),
            Err(WireError::TypeMismatch { expected: 's', .. })
        ));
        assert!(matches!(
            encode("ay", &[Value::Array(vec![Value::Byte(1)])]),
            Err(WireError::TypeMismatch { .. })
        ));
        assert!(matches!(
            encode("ss", &[Value::Str("a".to_owned())]),
            Err(WireError::Arity {
                expected: 2,
                got: 1
            })
        ));
        assert!(matches!(
            encode(
                "(ii)",
                &[Value::Struct(vec![
                    Value::Int32(1),
                    Value::Int32(2),
                    Value::Int32(3)
                ])]
            ),
            Err(WireError::Arity { .. })
        ));
    }

    #[test]
    fn a_dict_key_that_is_not_a_string_is_refused_rather_than_guessed() {
        let bytes = encode("a{us}", &[Value::Dict(Vec::new())]);
        assert!(matches!(bytes, Err(WireError::Unsupported(_))));
        assert!(matches!(
            decode("a{us}", &[0, 0, 0, 0, 0, 0, 0, 0]),
            Err(WireError::Unsupported(_))
        ));
    }

    #[test]
    fn a_big_endian_message_is_refused_rather_than_guessed() {
        let mut message = HELLO_FRAME;
        message[0] = b'B';
        assert!(matches!(
            decode_message(&message),
            Err(WireError::Endianness(b'B'))
        ));
        message[0] = b'l';
        message[3] = 2;
        assert!(matches!(
            decode_message(&message),
            Err(WireError::BadMessage(_))
        ));
    }

    #[test]
    fn a_header_field_of_the_wrong_type_is_refused() {
        // "implementations must not send or accept known header fields
        // with the wrong type stored in the field value".
        let message = encode_message(
            MSG_METHOD_RETURN,
            0,
            1,
            &[(FIELD_REPLY_SERIAL, Value::Str("1".to_owned()))],
            &[],
        )
        .unwrap();
        assert!(matches!(
            decode_message(&message),
            Err(WireError::BadMessage(_))
        ));
    }

    #[test]
    fn a_header_field_from_a_newer_specification_is_accepted_and_ignored() {
        let message = encode_message(
            MSG_METHOD_RETURN,
            0,
            1,
            &[
                (FIELD_REPLY_SERIAL, Value::Uint32(7)),
                (200, Value::Uint64(1)),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(decode_message(&message).unwrap().reply_serial, Some(7));
    }

    #[test]
    fn a_body_with_no_signature_is_refused() {
        let message = encode_message(
            MSG_METHOD_RETURN,
            0,
            1,
            &[(FIELD_REPLY_SERIAL, Value::Uint32(1))],
            &[1, 2, 3, 4],
        )
        .unwrap();
        assert!(matches!(
            decode_message(&message),
            Err(WireError::BadMessage(_))
        ));
    }

    #[test]
    fn the_uid_goes_out_as_hex_of_its_decimal_digits() {
        // "31303030 is ASCII decimal "1000" represented in hex, so the
        // client is authenticating as Unix uid 1000".
        assert_eq!(uid_hex(1000), "31303030");
        assert_eq!(uid_hex(0), "30");
        assert_eq!(uid_hex(4_294_967_295), "34323934393637323935");
    }

    #[test]
    fn a_session_authenticates_says_hello_and_makes_a_call() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            // What goes out first is the frame pinned above, unchanged.
            assert_eq!(server_hello(&stream, ":1.42"), HELLO_FRAME);
            let (bytes, _) = server_message(&stream);
            let call = decode_message(&bytes).unwrap();
            assert_eq!(call.kind, MSG_METHOD_CALL);
            server_reply(
                &stream,
                2,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str("deadbeef".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        assert_eq!(session.unique_name(), ":1.42");
        assert!(session.passes_fds());
        let reply = session
            .call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("deadbeef".to_owned())]);
        // Nothing is sent for a call that names nobody: a reply to it
        // could not be attributed to an owner.
        let err = session
            .call("", BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::NoDestination), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn signals_and_replies_to_other_calls_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.9");
            let (bytes, _) = server_message(&stream);
            // A signal with no reply serial at all, then a reply to a
            // call this connection never made.
            (&stream).write_all(&signal_bytes(7, None)).unwrap();
            server_reply(
                &stream,
                8,
                999,
                BUS_NAME,
                "s",
                &[Value::Str("not yours".to_owned())],
            );
            // A signal that carries the pending serial: "if a signal has
            // a reply serial it must be ignored".
            (&stream)
                .write_all(&signal_bytes(10, Some(serial_of(&bytes))))
                .unwrap();
            server_reply(
                &stream,
                9,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str("yours".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("yours".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn an_error_reply_names_the_error_and_leaves_the_session_usable() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.10");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_ERROR,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (
                        FIELD_ERROR_NAME,
                        Value::Str("org.freedesktop.portal.Error.NotAllowed".to_owned()),
                    ),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                ],
                "s",
                &[Value::Str("no".to_owned())],
            );
            let (bytes, _) = server_message(&stream);
            server_reply(
                &stream,
                3,
                serial_of(&bytes),
                ":1.5",
                "u",
                &[Value::Uint32(1)],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Denied", "", &[], &[])
            .unwrap_err();
        match err {
            WireError::Remote { name, message } => {
                assert_eq!(name, "org.freedesktop.portal.Error.NotAllowed");
                assert_eq!(message, "no");
            }
            other => panic!("{other:?}"),
        }
        // The connection is still good: an error is an answer.
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Allowed", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Uint32(1)]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_refused_mechanism_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_line(&stream);
            (&stream)
                .write_all(b"REJECTED DBUS_COOKIE_SHA1 ANONYMOUS\r\n")
                .unwrap();
        });
        let err = Session::connect(&path).unwrap_err();
        assert!(
            matches!(&err, WireError::AuthRejected(m) if m == "DBUS_COOKIE_SHA1 ANONYMOUS"),
            "{err:?}"
        );
        server.join().unwrap();
    }

    #[test]
    fn a_bus_that_will_not_pass_descriptors_refuses_a_call_that_carries_one() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, false);
            server_hello(&stream, ":1.11");
        });
        let mut session = Session::connect(&path).unwrap();
        assert!(!session.passes_fds());
        let file = std::fs::File::open(tmp.path()).unwrap();
        let err = session
            .call(
                ":1.5",
                "/org/a",
                "org.a",
                "Take",
                "h",
                &[Value::Fd(0)],
                &[file.as_fd()],
            )
            .unwrap_err();
        assert!(matches!(err, WireError::NoFdPassing), "{err:?}");
        // A call carrying nothing still works on such a connection.
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_descriptor_reaches_the_far_side_of_the_bus() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("doc");
        std::fs::write(&file_path, b"twelve bytes").unwrap();
        let want = rustix::fs::stat(&file_path).unwrap();
        let (path, server) = fake_bus(tmp.path(), move |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.12");
            let (bytes, fds) = server_message(&stream);
            let call = decode_message(&bytes).unwrap();
            assert_eq!(call.signature, "ahs");
            assert_eq!(
                decode(&call.signature, &call.body).unwrap(),
                vec![
                    Value::Array(vec![Value::Fd(0)]),
                    Value::Str("read".to_owned())
                ]
            );
            assert_eq!(fds.len(), 1);
            // The descriptor names the same file, not a copy of a path.
            let got = rustix::fs::fstat(&fds[0]).unwrap();
            assert_eq!(
                (got.st_dev, got.st_ino, got.st_size),
                (want.st_dev, want.st_ino, want.st_size)
            );
            server_reply(
                &stream,
                2,
                serial_of(&bytes),
                ":1.5",
                "as",
                &[Value::Array(vec![Value::Str("1a2b".to_owned())])],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let file = std::fs::File::open(&file_path).unwrap();
        // A body naming a descriptor the call was not given never leaves.
        let err = session
            .call(
                ":1.5",
                "/org/a",
                "org.a",
                "AddFull",
                "ahs",
                &[
                    Value::Array(vec![Value::Fd(3)]),
                    Value::Str("read".to_owned()),
                ],
                &[file.as_fd()],
            )
            .unwrap_err();
        assert!(matches!(err, WireError::FdIndex(3)), "{err:?}");
        let reply = session
            .call(
                ":1.5",
                "/org/a",
                "org.a",
                "AddFull",
                "ahs",
                &[
                    Value::Array(vec![Value::Fd(0)]),
                    Value::Str("read".to_owned()),
                ],
                &[file.as_fd()],
            )
            .unwrap();
        assert_eq!(
            reply,
            vec![Value::Array(vec![Value::Str("1a2b".to_owned())])]
        );
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_bus_that_says_nothing_times_the_call_out() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            // Accept the connection and never answer: the client must
            // give up on its own deadline rather than park forever.
            server_line(&stream);
            std::thread::sleep(CALL_TIMEOUT + Duration::from_secs(1));
        });
        let started = Instant::now();
        let err = Session::connect(&path).unwrap_err();
        assert!(matches!(err, WireError::Timeout), "{err:?}");
        assert!(started.elapsed() >= CALL_TIMEOUT);
        server.join().unwrap();
    }

    /// Send one message with descriptors attached, the way a reply that
    /// carries them would arrive.
    fn server_send_fds(stream: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(fds)));
        let sent = sendmsg(
            stream.as_fd(),
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert_eq!(sent, bytes.len());
    }

    #[test]
    fn a_reply_from_anyone_but_the_owner_of_the_name_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.15");
            // A call to a well-known name asks the bus who owns it first.
            let (bytes, _) = server_message(&stream);
            assert_eq!(
                decode("s", &decode_message(&bytes).unwrap().body).unwrap(),
                vec![Value::Str("org.freedesktop.portal.Documents".to_owned())]
            );
            server_reply(
                &stream,
                2,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str(":1.77".to_owned())],
            );
            let (bytes, _) = server_message(&stream);
            // Another peer on the bus guesses the serial and answers
            // first, choosing the path bubbler would go on to use.
            server_reply(
                &stream,
                3,
                serial_of(&bytes),
                ":1.99",
                "s",
                &[Value::Str("/forged".to_owned())],
            );
            server_reply(
                &stream,
                4,
                serial_of(&bytes),
                ":1.77",
                "s",
                &[Value::Str("/genuine".to_owned())],
            );
            // The owner is remembered, so the second call asks nothing.
            let (bytes, _) = server_message(&stream);
            server_reply(
                &stream,
                5,
                serial_of(&bytes),
                ":1.77",
                "s",
                &[Value::Str("/again".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        for want in ["/genuine", "/again"] {
            let reply = session
                .call(
                    "org.freedesktop.portal.Documents",
                    "/org/freedesktop/portal/documents",
                    "org.freedesktop.portal.Documents",
                    "GetMountPoint",
                    "",
                    &[],
                    &[],
                )
                .unwrap();
            assert_eq!(reply, vec![Value::Str(want.to_owned())]);
        }
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_reply_with_no_sender_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.16");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_METHOD_RETURN,
                2,
                &[(FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes)))],
                "s",
                &[Value::Str("from nobody".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_hello_reply_that_is_not_a_unique_name_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            let (bytes, _) = server_message(&stream);
            server_reply(
                &stream,
                1,
                serial_of(&bytes),
                BUS_NAME,
                "s",
                &[Value::Str("org.not.unique".to_owned())],
            );
        });
        let err = Session::connect(&path).unwrap_err();
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        server.join().unwrap();
    }

    #[test]
    fn an_error_reply_with_no_name_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.17");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_ERROR,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                ],
                "s",
                &[Value::Str("nameless".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        // Never an invented name: a refusal bubbler cannot name is a
        // failure, not `org.freedesktop.DBus.Error.Failed`.
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_flood_of_messages_to_skip_does_not_outlast_the_deadline() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.18");
            let (bytes, _) = server_message(&stream);
            // Never the reply: always one more message to skip, so the
            // reader never waits and the deadline is all that ends it.
            let signal = signal_bytes(7, Some(serial_of(&bytes)));
            while (&stream).write_all(&signal).is_ok() {}
        });
        let mut session = Session::connect(&path).unwrap();
        let started = Instant::now();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Wait", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::Timeout), "{err:?}");
        assert!(started.elapsed() >= CALL_TIMEOUT, "{:?}", started.elapsed());
        assert!(
            started.elapsed() < CALL_TIMEOUT * 3,
            "{:?}",
            started.elapsed()
        );
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_reply_delivered_one_byte_at_a_time_is_assembled() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.19");
            let (bytes, _) = server_message(&stream);
            let reply = reply_bytes(
                2,
                serial_of(&bytes),
                ":1.5",
                "s",
                &[Value::Str("assembled".to_owned())],
            );
            for byte in reply {
                (&stream).write_all(&[byte]).unwrap();
            }
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("assembled".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn two_messages_in_one_write_are_read_one_at_a_time() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.20");
            let (bytes, _) = server_message(&stream);
            let mut both = signal_bytes(7, None);
            both.extend_from_slice(&reply_bytes(
                8,
                serial_of(&bytes),
                ":1.5",
                "s",
                &[Value::Str("second".to_owned())],
            ));
            (&stream).write_all(&both).unwrap();
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("second".to_owned())]);
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn descriptors_a_reply_carries_are_closed() {
        let tmp = tempfile::tempdir().unwrap();
        // Three copies of a pipe's write end: once every copy is closed
        // the read end reports end of file, and nothing else can.
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (path, server) = fake_bus(tmp.path(), move |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.21");
            let (bytes, _) = server_message(&stream);
            let body = encode("s", &[Value::Str("ok".to_owned())]).unwrap();
            let message = encode_message(
                MSG_METHOD_RETURN,
                0,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                    (FIELD_SIGNATURE, Value::Signature("s".to_owned())),
                    (FIELD_UNIX_FDS, Value::Uint32(3)),
                ],
                &body,
            )
            .unwrap();
            let carried = [write.as_fd(), write.as_fd(), write.as_fd()];
            server_send_fds(&stream, &message, &carried);
            drop(write);
        });
        let mut session = Session::connect(&path).unwrap();
        let reply = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap();
        assert_eq!(reply, vec![Value::Str("ok".to_owned())]);
        server.join().unwrap();
        let mut fds = [PollFd::from_borrowed_fd(read.as_fd(), PollFlags::IN)];
        assert_eq!(
            poll(&mut fds, Some(&timespec(Duration::from_secs(5)))).unwrap(),
            1,
            "the pipe never hung up, so a copy of the descriptor is still open"
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            std::fs::File::from(read).read(&mut byte).unwrap(),
            0,
            "the pipe still has a writer, so a received descriptor was kept"
        );
        drop(session);
    }

    #[test]
    fn a_message_that_declares_descriptors_it_did_not_send_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, server) = fake_bus(tmp.path(), |stream| {
            server_auth(&stream, true);
            server_hello(&stream, ":1.22");
            let (bytes, _) = server_message(&stream);
            server_send(
                &stream,
                MSG_METHOD_RETURN,
                2,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(serial_of(&bytes))),
                    (FIELD_SENDER, Value::Str(":1.5".to_owned())),
                    (FIELD_UNIX_FDS, Value::Uint32(3)),
                ],
                "s",
                &[Value::Str("three, honest".to_owned())],
            );
        });
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(":1.5", "/org/a", "org.a", "Ask", "", &[], &[])
            .unwrap_err();
        assert!(matches!(err, WireError::BadMessage(_)), "{err:?}");
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_header_field_that_appears_twice_is_refused() {
        let message = encode_message(
            MSG_METHOD_RETURN,
            0,
            1,
            &[
                (FIELD_REPLY_SERIAL, Value::Uint32(1)),
                (FIELD_REPLY_SERIAL, Value::Uint32(2)),
            ],
            &[],
        )
        .unwrap();
        assert!(matches!(
            decode_message(&message),
            Err(WireError::BadMessage(_))
        ));
    }

    #[test]
    fn a_value_too_deep_to_name_is_refused_before_the_stack_runs_out() {
        // The signature of what goes in a variant is worked out before
        // the encoder has recursed at all, so the guard has to be there
        // as well as in the encoder.
        let mut value = Value::Byte(1);
        for _ in 0..200 {
            value = Value::Array(vec![value]);
        }
        let err = encode("v", &[Value::Variant(Box::new(value))]).unwrap_err();
        assert!(matches!(err, WireError::Depth), "{err:?}");
    }

    /// `depth` nested arrays around a variant holding `inner_depth`
    /// nested arrays around one byte, for a block starting on an 8-byte
    /// boundary. Every array holds exactly one element, so a decoder
    /// walks the whole chain.
    fn arrays_around_a_variant(depth: usize, inner_depth: usize) -> (String, Vec<u8>) {
        let inner_sig = format!("{}y", "a".repeat(inner_depth));
        let mut inner = vec![0x7f];
        for _ in 0..inner_depth {
            let mut wrapped = (inner.len() as u32).to_le_bytes().to_vec();
            wrapped.extend_from_slice(&inner);
            inner = wrapped;
        }
        // One 4-byte length per enclosing array stands before the variant.
        let at = depth * 4;
        let mut bytes = vec![inner_sig.len() as u8];
        bytes.extend_from_slice(inner_sig.as_bytes());
        bytes.push(0);
        while !(at + bytes.len()).is_multiple_of(4) {
            bytes.push(0);
        }
        bytes.extend_from_slice(&inner);
        for _ in 0..depth {
            let mut wrapped = (bytes.len() as u32).to_le_bytes().to_vec();
            wrapped.extend_from_slice(&bytes);
            bytes = wrapped;
        }
        (format!("{}v", "a".repeat(depth)), bytes)
    }

    #[test]
    fn containers_that_cross_a_variant_boundary_count_toward_one_limit() {
        let (sig, bytes) = arrays_around_a_variant(10, 10);
        assert!(decode(&sig, &bytes).is_ok());
        // Each half is inside the specification's limit of 32 arrays and
        // the two together are past the total depth of 64.
        let (sig, bytes) = arrays_around_a_variant(32, 32);
        assert!(matches!(decode(&sig, &bytes), Err(WireError::Depth)));
    }

    /// The session bus socket: `DBUS_SESSION_BUS_ADDRESS` when it names a
    /// `unix:path=` one, else `$XDG_RUNTIME_DIR/bus`, and only when what
    /// is there is a socket.
    fn session_bus_socket() -> Option<PathBuf> {
        let from_env = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").and_then(|address| {
            address.as_bytes().split(|b| *b == b';').find_map(|entry| {
                entry
                    .strip_prefix(b"unix:".as_slice())?
                    .split(|b| *b == b',')
                    .find_map(|pair| {
                        Some(PathBuf::from(OsStr::from_bytes(
                            pair.strip_prefix(b"path=".as_slice())?,
                        )))
                    })
            })
        });
        let path = match from_env {
            Some(path) => path,
            None => PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?).join("bus"),
        };
        std::fs::metadata(&path)
            .ok()
            .filter(|m| m.file_type().is_socket())
            .map(|_| path)
    }

    #[test]
    fn the_real_session_bus_answers_get_id() {
        let Some(path) = session_bus_socket() else {
            println!("skipping: no session bus socket to talk to");
            return;
        };
        let mut session = Session::connect(&path).unwrap();
        assert!(
            session.unique_name().starts_with(':'),
            "{:?}",
            session.unique_name()
        );
        let reply = session
            .call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "GetId", "", &[], &[])
            .unwrap();
        let [Value::Str(id)] = reply.as_slice() else {
            panic!("GetId answered {reply:?}")
        };
        // "UUIDs": 16 bytes, printed as 32 hex digits.
        assert_eq!(id.len(), 32, "{id:?}");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id:?}");
    }

    #[test]
    fn the_real_session_bus_refuses_a_method_that_is_not_there() {
        let Some(path) = session_bus_socket() else {
            println!("skipping: no session bus socket to talk to");
            return;
        };
        let mut session = Session::connect(&path).unwrap();
        let err = session
            .call(
                BUS_NAME,
                BUS_PATH,
                BUS_INTERFACE,
                "NoSuchMethod",
                "",
                &[],
                &[],
            )
            .unwrap_err();
        assert!(
            matches!(&err, WireError::Remote { name, .. } if name.starts_with("org.freedesktop.DBus.Error.")),
            "{err:?}"
        );
    }
}
