//! The D-Bus wire format: the values, signatures and messages the
//! session-bus client in `dbus_session` puts on the socket and reads back.
//!
//! Every wire fact is from the D-Bus specification
//! (<https://dbus.freedesktop.org/doc/dbus-specification.html>). The decoder is
//! strict on purpose: a reply is input from another process, and a
//! length, an alignment or a padding byte that does not match the
//! specification is a reason to fail the call, never to guess.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Longest a call waits for its reply, and the whole of what a connect
/// and its authentication may take. A bus that has not answered within
/// it is not going to; bubbler's callers have a user waiting.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) const PROTOCOL_VERSION: u8 = 1;

pub(crate) const FIXED_HEADER: usize = 16;

// The specification's maximum array length, 64 MiB.
const MAX_ARRAY: usize = 1 << 26;

// The specification's maximum message length. This is the limit on what may be *sent*:
// a message the encoder produces has to stay inside it or no conforming peer would read it.
pub(crate) const MAX_MESSAGE: usize = 1 << 27;

// The limit on what is *read*, bubbler's own: the largest reply it reads (the doc-id list
// `AddFull` answers with) is four orders of magnitude smaller, and a hostile peer gets no more.
pub(crate) const MAX_INCOMING: usize = 16 << 20;
// A reply this client reads must always fit what it may send.
const _: () = assert!(MAX_INCOMING < MAX_MESSAGE);

// `MAX_ARRAY` bounds an array's bytes, not what reading it costs, so the count is bounded too.
// The replies bubbler reads hold a handful of values; a million is a bound on a hostile peer.
pub(crate) const MAX_VALUES: usize = 1 << 20;

// The specification's maximum signature length.
const MAX_SIGNATURE: usize = 255;

// 32 array type codes and 32 open parentheses. Counted across variants too: without a
// running total a reply could nest them until the decoder's recursion ran out of stack.
const MAX_DEPTH: usize = 64;

// The specification's limit for one kind: 32 arrays, or 32 structs and dict entries.
const MAX_CONTAINER_DEPTH: usize = 32;

// Linux caps `SCM_RIGHTS` at 253 per message, so a longer list could never leave in
// one piece.
pub(crate) const MAX_CALL_FDS: usize = 253;

// Nothing bubbler calls answers with one; the room exists so a peer that sends some cannot
// leave them queued. `Session::call` refuses a reply that declares more than this.
pub(crate) const MAX_REPLY_FDS: usize = 4;

// Longest authentication line accepted, so a peer that never sends `\r\n` cannot grow the
// buffer without bound. The lines in use are a few dozen bytes.
pub(crate) const MAX_AUTH_LINE: usize = 4096;

pub(crate) const MSG_METHOD_CALL: u8 = 1;
pub(crate) const MSG_METHOD_RETURN: u8 = 2;
pub(crate) const MSG_ERROR: u8 = 3;

pub(crate) const FIELD_PATH: u8 = 1;
pub(crate) const FIELD_INTERFACE: u8 = 2;
pub(crate) const FIELD_MEMBER: u8 = 3;
pub(crate) const FIELD_ERROR_NAME: u8 = 4;
pub(crate) const FIELD_REPLY_SERIAL: u8 = 5;
pub(crate) const FIELD_DESTINATION: u8 = 6;
pub(crate) const FIELD_SENDER: u8 = 7;
pub(crate) const FIELD_SIGNATURE: u8 = 8;
pub(crate) const FIELD_UNIX_FDS: u8 = 9;

// `GetNameOwner`'s answer when nobody holds the name; for an activatable name that only
// means it has not been started yet.
pub(crate) const ERROR_NO_OWNER: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";

pub(crate) const ERROR_SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";

pub(crate) const BUS_NAME: &str = "org.freedesktop.DBus";
pub(crate) const BUS_PATH: &str = "/org/freedesktop/DBus";
pub(crate) const BUS_INTERFACE: &str = "org.freedesktop.DBus";

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
    /// A message is longer than this client sends or accepts.
    #[error("a message of {0} bytes is longer than this client sends or accepts")]
    MessageTooLong(usize),
    /// One block holds more values than this client reads, however few
    /// bytes they came in.
    #[error(
        "a message holding more than the {} values this client reads",
        MAX_VALUES
    )]
    TooManyValues,
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
    // From "Summary of D-Bus marshalling": a variant aligns like the signature
    // that starts it, which needs no padding at all.
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

    fn is_basic(&self) -> bool {
        !matches!(
            self,
            Type::Array(_) | Type::Struct(_) | Type::DictEntry(..) | Type::Variant
        )
    }
}

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

fn pad(out: &mut Vec<u8>, align: usize) {
    let over = out.len() % align;
    if over != 0 {
        out.resize(out.len() + align - over, 0);
    }
}

pub(crate) fn align_up(n: usize, align: usize) -> usize {
    n.div_ceil(align) * align
}

/// Marshal `values` against `sig`, little-endian. Offset 0 of the result is
/// taken to be a multiple of 8 from the start of the message.
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

// The caller has padded to 4 already.
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

// Its alignment is 1, so no padding is ever needed before it, and its
// length has been checked to fit a byte by `parse_signature`.
fn encode_signature(out: &mut Vec<u8>, sig: &str) {
    out.push(sig.len() as u8);
    out.extend_from_slice(sig.as_bytes());
    out.push(0);
}

// The length does not count the padding to the element's alignment.
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

// `depth` bounds the walk: this runs before the encoder has recursed at all, so without
// it a deep enough value would overflow the stack here rather than come back as an error.
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

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
    // Counted across every container: the budget belongs to the block,
    // not to one array inside it.
    values: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            at: 0,
            values: 0,
        }
    }

    // Bytes of a byte array are not counted: they stay bytes, and cost what they weigh.
    fn value(&mut self) -> Result<(), WireError> {
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(WireError::TooManyValues);
        }
        Ok(())
    }

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

fn decode_value(reader: &mut Reader<'_>, ty: &Type, depth: usize) -> Result<Value, WireError> {
    if depth > MAX_DEPTH {
        return Err(WireError::Depth);
    }
    reader.value()?;
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
                // The key is a string rather than a `Value`, so the
                // entry it makes is counted here and not by the decoder.
                reader.value()?;
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

// One message off the wire, with its body still marshalled: the body's
// signature is a header field, so it is known only once the header is.
#[derive(Debug)]
pub(crate) struct Message {
    pub(crate) kind: u8,
    pub(crate) reply_serial: Option<u32>,
    pub(crate) error_name: Option<String>,
    // On a bus the bus itself fills this in, and a client cannot forge it.
    pub(crate) sender: Option<String>,
    pub(crate) signature: String,
    pub(crate) unix_fds: u32,
    pub(crate) fds_arrived: usize,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn encode_message(
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

// Bounded by the specification's maximum, past which no length can be trusted to find the
// next message; whether a message this long is read into memory is `MAX_INCOMING`'s to decide.
pub(crate) fn frame(head: &[u8]) -> Result<(usize, usize), WireError> {
    let head = head.get(..FIXED_HEADER).ok_or(WireError::Truncated)?;
    let uint32 = |at: usize| {
        let bytes = [head[at], head[at + 1], head[at + 2], head[at + 3]];
        match head[0] {
            b'l' => Ok(u32::from_le_bytes(bytes) as usize),
            b'B' => Ok(u32::from_be_bytes(bytes) as usize),
            other => Err(WireError::Endianness(other)),
        }
    };
    if head[3] != PROTOCOL_VERSION {
        return Err(WireError::BadMessage("a message of an unknown version"));
    }
    let body_len = uint32(4)?;
    let fields_len = uint32(12)?;
    if fields_len > MAX_ARRAY {
        return Err(WireError::ArrayTooLong(fields_len));
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

// A code that appears twice is refused: the specification gives no rule for which copy
// wins, and two readers picking different ones is how a message means two things at once.
pub(crate) fn decode_message(message: &[u8]) -> Result<Message, WireError> {
    if message.first().is_some_and(|b| *b != b'l') {
        return Err(WireError::Endianness(message[0]));
    }
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
        fds_arrived: 0,
        body,
    })
}

/// The ASCII decimal digits of `uid`, each byte written as two hex digits: what `AUTH EXTERNAL`
/// takes. "31303030 is ASCII decimal \"1000\" represented in hex, so the client is authenticating
/// as Unix uid 1000".
pub(crate) fn uid_hex(uid: u32) -> String {
    const DIGITS: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::new();
    for byte in uid.to_string().into_bytes() {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

// An index past the end would have the far side `fstat` whatever happened to be
// at that position instead.
pub(crate) fn check_fd_indices(value: &Value, count: u32) -> Result<(), WireError> {
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

/// The `Hello` call bubbler opens every connection with, byte for
/// byte, laid out by hand from "Message Format": the four bytes, the
/// body length, the serial, then the header-field array, whose
/// `(yv)` elements each start on an 8-byte boundary.
#[cfg(test)]
pub(crate) const HELLO_FRAME: [u8; 128] = [
    // little-endian, METHOD_CALL, no flags, protocol version 1
    b'l', 1, 0, 1, // body length 0
    0, 0, 0, 0, // serial 1
    1, 0, 0, 0, // the header fields take 110 bytes
    0x6e, 0, 0, 0, // PATH, a variant of signature "o", 21 bytes of text
    1, 1, b'o', 0, 21, 0, 0, 0, b'/', b'o', b'r', b'g', b'/', b'f', b'r', b'e', b'e', b'd', b'e',
    b's', b'k', b't', b'o', b'p', b'/', b'D', b'B', b'u', b's', 0,
    // padding to the next 8-byte boundary
    0, 0, // DESTINATION, a variant of signature "s", 20 bytes of text
    6, 1, b's', 0, 20, 0, 0, 0, b'o', b'r', b'g', b'.', b'f', b'r', b'e', b'e', b'd', b'e', b's',
    b'k', b't', b'o', b'p', b'.', b'D', b'B', b'u', b's', 0, 0, 0, 0,
    // INTERFACE, the same name again
    2, 1, b's', 0, 20, 0, 0, 0, b'o', b'r', b'g', b'.', b'f', b'r', b'e', b'e', b'd', b'e', b's',
    b'k', b't', b'o', b'p', b'.', b'D', b'B', b'u', b's', 0, 0, 0, 0, // MEMBER "Hello"
    3, 1, b's', 0, 5, 0, 0, 0, b'H', b'e', b'l', b'l', b'o', 0,
    // padding to the 8-byte boundary the body would start on
    0, 0,
];

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_block_holding_more_values_than_the_client_reads_is_refused() {
        // Two bytes on the wire for a value tens of bytes wide: the
        // array's length is inside every limit the specification states
        // and reading it would still cost hundreds of megabytes.
        let count = MAX_VALUES + 1;
        let mut bytes = ((count * 2) as u32).to_le_bytes().to_vec();
        bytes.resize(4 + count * 2, 0);
        assert!(matches!(
            decode("aq", &bytes),
            Err(WireError::TooManyValues)
        ));

        // The budget is the block's, not one array's: a thousand arrays
        // of a thousand are each unremarkable and together are not.
        let (rows, columns) = (1024, 1024);
        let mut bytes = Vec::new();
        let mut rows_bytes = Vec::new();
        for _ in 0..rows {
            rows_bytes.extend_from_slice(&((columns * 2) as u32).to_le_bytes());
            rows_bytes.resize(rows_bytes.len() + columns * 2, 0);
        }
        bytes.extend_from_slice(&(rows_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&rows_bytes);
        assert!(rows * (columns + 1) + 1 > MAX_VALUES);
        assert!(matches!(
            decode("aaq", &bytes),
            Err(WireError::TooManyValues)
        ));

        // A reply of the size bubbler actually reads is untouched by it.
        let ids: Vec<Value> = (0..64).map(|n| Value::Str(format!("id{n}"))).collect();
        let body = encode("as", &[Value::Array(ids.clone())]).unwrap();
        assert_eq!(
            decode("as", &body).unwrap(),
            vec![Value::Array(ids)],
            "a doc-id list is nowhere near the bound"
        );
    }

    #[test]
    fn a_frame_longer_than_the_specification_allows_is_refused() {
        assert_eq!(MAX_MESSAGE, 1 << 27);
        let mut head = [0u8; FIXED_HEADER];
        head[0] = b'l';
        head[1] = MSG_METHOD_RETURN;
        head[3] = PROTOCOL_VERSION;
        head[4..8].copy_from_slice(&((MAX_MESSAGE - FIXED_HEADER + 1) as u32).to_le_bytes());
        assert!(matches!(frame(&head), Err(WireError::MessageTooLong(_))));
        // Longer than this client holds, but a length it can skip by.
        head[4..8].copy_from_slice(&((MAX_INCOMING + 1) as u32).to_le_bytes());
        assert_eq!(frame(&head).unwrap(), (FIXED_HEADER, MAX_INCOMING + 1));
        head[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(frame(&head).unwrap(), (FIXED_HEADER, 8));
    }
}
