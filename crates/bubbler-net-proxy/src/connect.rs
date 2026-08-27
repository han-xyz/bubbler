//! The one request this proxy understands: `CONNECT host:port`.
//!
//! A tunnel is opened on the strength of the request-target and of
//! nothing else. `Host` must be there — RFC 9110 §9.3.6 requires a
//! client to send it — but it is never what the target is taken from:
//! the two may legitimately differ (the RFC's own example pairs a
//! port-less `Host` with an authority carrying one), and authorising on
//! a header a client also chooses would let one spelling pass the
//! allowlist and another be dialled.
//!
//! The parser is a pure function over the bytes read so far. It
//! allocates the host string and nothing else, forwards no header
//! onward — a `CONNECT` carries none — and tells the caller where the
//! request ended, because whatever follows the blank line is already
//! tunnel data (RFC 9110 §9.3.6: the tunnel "commences immediately
//! following the blank line") and must be handed upstream, not read as
//! a second request.

use std::str;

use crate::allow::HostPattern;

/// Longest request-line accepted, terminator included. RFC 9112 §3
/// recommends 8000 octets for a general server; an authority-form
/// target is at most 253 + 1 + 5 characters, so the whole line has no
/// business being this long either.
pub const MAX_REQUEST_LINE: usize = 512;

/// Longest request-target accepted: a name at its DNS limit, the colon,
/// and five digits of port.
pub const MAX_TARGET: usize = 259;

/// Bytes the header block may take, the request-line included. What a
/// `CONNECT` needs is one `Host`; the rest is read only to find the
/// blank line.
pub const MAX_HEADERS: usize = 8 << 10;

/// Header fields one request may carry.
pub const MAX_HEADER_COUNT: usize = 64;

/// The response the proxy sends once the tunnel is up. No body and no
/// framing headers: RFC 9110 §9.3.6 forbids both in a 2xx answer to a
/// `CONNECT`.
pub const ESTABLISHED: &str = "HTTP/1.1 200 Connection established\r\n\r\n";

/// A target the sandbox asked for, and where its request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The name from the request-target, lower case and without a
    /// trailing root dot, ready to be matched and resolved.
    pub host: String,
    /// The port from the request-target.
    pub port: u16,
    /// Bytes the request took. Everything after this in the buffer is
    /// tunnel data the client pipelined and belongs upstream.
    pub consumed: usize,
}

/// Why a request was refused, as the status line says it.
///
/// Code `0` is not a status at all: it is the sentinel for "the bytes
/// so far are no whole request yet", and the answer to one is to read
/// more, never to write a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{code} {reason}")]
pub struct Status {
    /// The HTTP status code, or `0` for a request that is not complete.
    pub code: u16,
    /// The reason phrase that goes with it.
    pub reason: &'static str,
    /// Whether the response carries `Allow: CONNECT`, which RFC 9110
    /// requires of a 405.
    pub allow_header: bool,
}

impl Status {
    /// Not a whole request yet. Read more; write nothing.
    pub const INCOMPLETE: Self = Self::new(0, "Incomplete");
    /// Syntax this parser will not guess at.
    pub const BAD_REQUEST: Self = Self::new(400, "Bad Request");
    /// A target no `allow-host` covers, or an address where a name
    /// belongs.
    pub const FORBIDDEN: Self = Self::new(403, "Forbidden");
    /// Any method but `CONNECT`. This is not a general-purpose proxy.
    pub const METHOD_NOT_ALLOWED: Self = Self {
        code: 405,
        reason: "Method Not Allowed",
        allow_header: true,
    };
    /// A request-line or target longer than anything a name can need.
    pub const URI_TOO_LONG: Self = Self::new(414, "URI Too Long");
    /// More tunnels than this proxy serves at once.
    pub const SERVICE_UNAVAILABLE: Self = Self::new(503, "Service Unavailable");
    /// The name does not resolve, or the connection was refused.
    pub const BAD_GATEWAY: Self = Self::new(502, "Bad Gateway");
    /// The upstream never answered inside the connect budget.
    pub const GATEWAY_TIMEOUT: Self = Self::new(504, "Gateway Timeout");

    /// One status without the `Allow` header.
    const fn new(code: u16, reason: &'static str) -> Self {
        Self {
            code,
            reason,
            allow_header: false,
        }
    }

    /// The whole response for this status: a status line, no body, and
    /// the connection closed after it.
    ///
    /// `Content-Length: 0` is there so a client never waits for a body
    /// that is not coming, and `Connection: close` because a refused
    /// request is the end of this connection either way.
    pub fn response(&self) -> String {
        let allow = if self.allow_header {
            "Allow: CONNECT\r\n"
        } else {
            ""
        };
        format!(
            "HTTP/1.1 {} {}\r\n{allow}Content-Length: 0\r\nConnection: close\r\n\r\n",
            self.code, self.reason
        )
    }
}

/// Read a `CONNECT` request out of `buf`.
///
/// Returns [`Status::INCOMPLETE`] while the blank line has not arrived,
/// a status to answer with when the request is one this proxy refuses,
/// and otherwise the target plus the offset the tunnel's own bytes
/// start at.
pub fn parse(buf: &[u8]) -> Result<Request, Status> {
    let (line, mut at) = split_line(buf, 0, MAX_REQUEST_LINE, Status::URI_TOO_LONG)?;
    let (host, port) = request_line(line)?;
    let mut hosts = 0usize;
    let mut fields = 0usize;
    loop {
        if at >= MAX_HEADERS {
            return Err(Status::BAD_REQUEST);
        }
        let (line, next) = split_line(buf, at, MAX_HEADERS - at, Status::BAD_REQUEST)?;
        at = next;
        if line.is_empty() {
            break;
        }
        fields += 1;
        if fields > MAX_HEADER_COUNT {
            return Err(Status::BAD_REQUEST);
        }
        if field(line)? {
            hosts += 1;
        }
    }
    // RFC 9110 §9.3.6 requires the field; more than one of it is a
    // request two recipients could read differently, which is what a
    // proxy must never pass on.
    if hosts != 1 {
        return Err(Status::BAD_REQUEST);
    }
    Ok(Request {
        host,
        port,
        consumed: at,
    })
}

/// One line from `from` on, without its terminator, and the offset just
/// past that terminator.
///
/// A bare LF ends a line as well as CRLF: tolerated on the way in, never
/// written on the way out. `over` is the answer when the line is longer
/// than `window` — too long a request-line is a 414, too long a header
/// is not.
fn split_line(
    buf: &[u8],
    from: usize,
    window: usize,
    over: Status,
) -> Result<(&[u8], usize), Status> {
    let rest = buf.get(from..).unwrap_or(&[]);
    let limit = rest.len().min(window);
    match rest[..limit].iter().position(|&b| b == b'\n') {
        Some(at) => {
            let line = &rest[..at];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            Ok((line, from + at + 1))
        }
        None if rest.len() > window => Err(over),
        None => Err(Status::INCOMPLETE),
    }
}

/// The request-line: a method, an authority-form target and a version,
/// one space apart.
///
/// The method is judged before anything else about the line, so a
/// browser pointed at this port is told what the proxy does rather than
/// what is wrong with its URI.
fn request_line(line: &[u8]) -> Result<(String, u16), Status> {
    if !line
        .iter()
        .all(|&b| b == b' ' || (0x21..=0x7e).contains(&b))
    {
        return Err(Status::BAD_REQUEST);
    }
    let words: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
    let [method, target, version] = words[..] else {
        return Err(Status::BAD_REQUEST);
    };
    if method != b"CONNECT" {
        return Err(Status::METHOD_NOT_ALLOWED);
    }
    // HTTP/2 and HTTP/3 spell a tunnel differently; a client that asked
    // for one of them would be answered in a framing this proxy does
    // not write.
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(Status::BAD_REQUEST);
    }
    target_of(target)
}

/// The authority-form target: a name, a colon, and a port.
///
/// An address is refused rather than dialled, whichever notation it is
/// in: names are what an `allow-host` grants, and `93.184.216.34:443`
/// would otherwise be a way past every one of them.
fn target_of(target: &[u8]) -> Result<(String, u16), Status> {
    if target.len() > MAX_TARGET {
        return Err(Status::URI_TOO_LONG);
    }
    // The request-line check above leaves only visible ASCII here.
    let text = str::from_utf8(target).map_err(|_| Status::BAD_REQUEST)?;
    let (host, port) = text.rsplit_once(':').ok_or(Status::BAD_REQUEST)?;
    // RFC 3986 §3.2.2 brackets an IP literal, and this is the one shape
    // that says "address" before it says anything else.
    if host.starts_with('[') {
        return Err(Status::FORBIDDEN);
    }
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Status::BAD_REQUEST);
    }
    let port = match port.parse::<u16>() {
        Ok(0) | Err(_) => return Err(Status::BAD_REQUEST),
        Ok(port) => port,
    };
    let name = host.strip_suffix('.').unwrap_or(host);
    let labels: Vec<&str> = name.split('.').collect();
    // RFC 1123 §2.1: a valid host name can never have the dotted-decimal
    // form, since the highest-level label is alphabetic.
    if labels
        .last()
        .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(Status::FORBIDDEN);
    }
    if !labels.iter().all(|l| HostPattern::check_label(l).is_ok()) {
        return Err(Status::BAD_REQUEST);
    }
    Ok((name.to_ascii_lowercase(), port))
}

/// One header field, and whether it was `Host`.
///
/// Nothing is kept: a `CONNECT` forwards no header, so the fields are
/// read only far enough to know the request is well formed and to count
/// the one field it must carry.
fn field(line: &[u8]) -> Result<bool, Status> {
    // Obsolete line folding: RFC 9112 leaves a proxy that is not a
    // message/http translator the choice of rejecting a folded field or
    // flattening it, and a filter takes the reading with one answer.
    if line.starts_with(b" ") || line.starts_with(b"\t") {
        return Err(Status::BAD_REQUEST);
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(Status::BAD_REQUEST)?;
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    if name.is_empty() || !name.iter().all(|&b| is_token(b)) {
        return Err(Status::BAD_REQUEST);
    }
    if !value
        .iter()
        .all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b))
    {
        return Err(Status::BAD_REQUEST);
    }
    Ok(name.eq_ignore_ascii_case(b"host"))
}

/// Whether `b` is a `tchar`, the only thing a field name is made of.
fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connect_request_parses_to_its_target() {
        let raw = b"CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\n\x16\x03\x01";
        let r = parse(raw).expect("a whole request");
        assert_eq!((r.host.as_str(), r.port), ("api.example", 443));
        // The bytes after the blank line are the client's first TLS
        // record, and they belong upstream rather than to this parser.
        assert_eq!(r.consumed, 59);
        assert_eq!(&raw[r.consumed..], b"\x16\x03\x01");
    }

    #[test]
    fn the_request_target_wins_over_the_host_header() {
        let r = parse(b"CONNECT a.example:443 HTTP/1.1\r\nHost: b.example:443\r\n\r\n")
            .expect("a whole request");
        assert_eq!(r.host, "a.example");
    }

    #[test]
    fn refusals_carry_the_right_status() {
        let code = |b: &[u8]| parse(b).expect_err("refused").code;
        assert_eq!(
            code(b"GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n"),
            405
        );
        assert_eq!(
            code(b"CONNECT a.example HTTP/1.1\r\nHost: a.example\r\n\r\n"),
            400
        );
        assert_eq!(
            code(b"CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"),
            403
        );
        assert_eq!(
            code(b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]\r\n\r\n"),
            403
        );
        assert_eq!(code(b"CONNECT a.example:443 HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(
            code(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n x\r\n\r\n"),
            400
        );
        assert_eq!(
            code(b"CONNECT a.example:443 HTTP/1.1\r\nHost: \xff\r\n\r\n"),
            400
        );
        let long = format!(
            "CONNECT {}:443 HTTP/1.1\r\nHost: a\r\n\r\n",
            "a".repeat(600)
        );
        assert_eq!(code(long.as_bytes()), 414);
    }

    #[test]
    fn an_incomplete_request_asks_for_more() {
        assert!(matches!(
            parse(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a"),
            Err(Status { code: 0, .. })
        ));
        assert_eq!(parse(b""), Err(Status::INCOMPLETE));
        assert_eq!(parse(b"CONN"), Err(Status::INCOMPLETE));
        assert_eq!(
            parse(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n"),
            Err(Status::INCOMPLETE)
        );
    }

    #[test]
    fn a_bare_lf_ends_a_line_too() {
        let r = parse(b"CONNECT a.example:443 HTTP/1.1\nHost: a.example\n\nx").expect("a request");
        assert_eq!((r.host.as_str(), r.port), ("a.example", 443));
        assert_eq!(r.consumed, 48);
        assert_eq!(
            &b"CONNECT a.example:443 HTTP/1.1\nHost: a.example\n\nx"[r.consumed..],
            b"x"
        );
    }

    #[test]
    fn a_target_is_a_name_and_a_port_and_nothing_else() {
        let code = |s: &str| {
            parse(format!("CONNECT {s} HTTP/1.1\r\nHost: a.example\r\n\r\n").as_bytes())
                .expect_err("refused")
                .code
        };
        assert_eq!(code("a.example:0"), 400);
        assert_eq!(code("a.example:65536"), 400);
        assert_eq!(code("a.example:+443"), 400);
        assert_eq!(code("a.example:44 3"), 400);
        assert_eq!(code(":443"), 400);
        assert_eq!(code("http://a.example:443"), 400);
        assert_eq!(code("user@a.example:443"), 400);
        assert_eq!(code("a.example:443/x"), 400);
        assert_eq!(code("a_b.example:443"), 400);
        assert_eq!(code("a..example:443"), 400);
        assert_eq!(code(&format!("{}:443", "a".repeat(300))), 414);
        // An address is never a name, whatever notation it is in.
        assert_eq!(code("127.0.0.1:443"), 403);
        assert_eq!(code("[fe80::1]:443"), 403);
        // Case and the root dot are the two spellings a name has.
        let r = parse(b"CONNECT API.Example.:443 HTTP/1.1\r\nHost: x\r\n\r\n").expect("a request");
        assert_eq!(r.host, "api.example");
    }

    #[test]
    fn a_version_this_proxy_does_not_speak_is_refused() {
        for line in [
            "CONNECT a.example:443",
            "CONNECT a.example:443 HTTP/2",
            "CONNECT a.example:443 HTTP/1.1 extra",
            "CONNECT  a.example:443 HTTP/1.1",
            "connect a.example:443 HTTP/1.1",
        ] {
            let raw = format!("{line}\r\nHost: a.example\r\n\r\n");
            assert!(parse(raw.as_bytes()).is_err(), "{line}");
        }
        assert!(parse(b"CONNECT a.example:443 HTTP/1.0\r\nHost: a.example\r\n\r\n").is_ok());
    }

    #[test]
    fn one_host_header_is_required_and_two_are_refused() {
        let two = b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\nhost: b.example\r\n\r\n";
        assert_eq!(parse(two).expect_err("refused").code, 400);
        let named = b"CONNECT a.example:443 HTTP/1.1\r\nHOST: a.example\r\n\r\n";
        assert!(parse(named).is_ok(), "the field name is case-insensitive");
        let broken = b"CONNECT a.example:443 HTTP/1.1\r\nHost a.example\r\n\r\n";
        assert_eq!(parse(broken).expect_err("refused").code, 400);
    }

    #[test]
    fn a_header_block_past_the_bounds_is_refused() {
        let mut raw = String::from("CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n");
        for i in 0..MAX_HEADER_COUNT {
            raw.push_str(&format!("X-Pad-{i}: 1\r\n"));
        }
        raw.push_str("\r\n");
        assert_eq!(parse(raw.as_bytes()).expect_err("refused").code, 400);

        let mut raw = String::from("CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n");
        raw.push_str(&format!("X-Pad: {}\r\n\r\n", "p".repeat(MAX_HEADERS)));
        assert_eq!(parse(raw.as_bytes()).expect_err("refused").code, 400);
    }

    #[test]
    fn a_status_writes_one_response_with_no_body() {
        assert_eq!(
            Status::FORBIDDEN.response(),
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            Status::METHOD_NOT_ALLOWED.response(),
            "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        assert_eq!(Status::BAD_GATEWAY.to_string(), "502 Bad Gateway");
    }
}
