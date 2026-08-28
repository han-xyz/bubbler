//! The proxy's own DNS client: A and AAAA over UDP, TCP on truncation,
//! to the resolver addresses bubbler passes as `--dns`.
//!
//! The proxy does not call `getaddrinfo`, and this module is why. It
//! runs inside the sandbox's mount namespace, where `/run` and `/etc`
//! are tmpfs the application writes; the host's `nsswitch.conf` there
//! names `resolve` and `mymachines` before `dns`, and those modules
//! dial sockets by path. Measured 2026-08-28: an application that binds
//! `/run/systemd/resolve/io.systemd.Resolve` answers the proxy's
//! lookups itself, so a `CONNECT` to a listed name reached an address
//! the application chose. Name policy enforced by a resolver the
//! attacker answers is no policy at all.
//!
//! What is left is a resolver the application cannot reach: only the
//! proxy's cgroup may send to port 53 (`network::ruleset`), and the
//! forwarder address is not local to the namespace. So this speaks the
//! wire format itself — the smallest client that can ask two questions
//! and read the answers — and reads nothing off the filesystem at all.
//!
//! The parser is bounded everywhere and trusts nothing: names are
//! decompressed with strictly backwards pointers only, records are
//! capped, `CNAME` chains are capped, and every field is read through a
//! cursor that cannot leave the message.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use rustix::rand::{GetRandomFlags, getrandom};

/// Where a resolver listens.
pub const PORT: u16 = 53;

/// How long one question waits for one answer.
pub const TIMEOUT: Duration = Duration::from_secs(2);

/// Tries per resolver: the first and two retries. A datagram that is
/// lost is the ordinary failure here, and a resolver that is down is
/// the next one's turn.
pub const TRIES: u32 = 3;

/// How long a whole resolution may take, across both questions, every
/// resolver and every retry. Bounded because a tunnel slot is held for
/// all of it.
pub const BUDGET: Duration = Duration::from_secs(10);

/// Bytes read from one datagram. A server that was not asked for EDNS
/// must answer in 512 or set `TC`; the slack is for one that does not.
const MAX_UDP: usize = 4096;

/// Bytes read from one TCP answer.
const MAX_TCP: usize = 8192;

/// Longest name, from DNS.
const MAX_NAME: usize = 255;

/// Longest label, from DNS.
const MAX_LABEL: usize = 63;

/// Compression pointers one name may follow. Pointers must already
/// point backwards, so this only bounds the work.
const MAX_JUMPS: usize = 16;

/// Answer records read from one message. Everything past this is
/// ignored rather than refused: a long answer is a working name.
pub const MAX_RECORDS: usize = 32;

/// `CNAME` hops followed inside one answer.
pub const MAX_CNAMES: usize = 8;

/// `A`, an IPv4 address.
const TYPE_A: u16 = 1;
/// `CNAME`, another name to look under.
const TYPE_CNAME: u16 = 5;
/// `AAAA`, an IPv6 address.
const TYPE_AAAA: u16 = 28;
/// Class `IN`, the only class this asks about.
const CLASS_IN: u16 = 1;

/// Why an answer could not be read.
///
/// Every one of these ends the answer, never the process: the next
/// resolver, or the next try, is what follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    /// The message ends in the middle of a field.
    #[error("the answer ends in the middle of a field")]
    Short,
    /// A name is longer than DNS allows, or holds a label that is.
    #[error("a name or a label is longer than DNS allows")]
    Name,
    /// A compression pointer that does not point backwards, or too many
    /// of them.
    #[error("a compression pointer does not point backwards")]
    Pointer,
    /// A label type this parser does not have.
    #[error("a label type this parser does not have")]
    LabelType,
    /// The message is a question, not an answer.
    #[error("the message is not an answer")]
    NotAnAnswer,
    /// The message carries no question, or more than one.
    #[error("the answer does not carry exactly one question")]
    Question,
    /// The question is not one this client asks.
    #[error("the answer is to a question of another class")]
    Class,
}

/// One answer, as much of it as this proxy reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The id the question carried, for the caller to match.
    pub id: u16,
    /// The server had more to say than the datagram held.
    pub truncated: bool,
    /// The response code: `0` is an answer, `3` is "no such name".
    pub rcode: u8,
    /// The question echoed back: the name, lower case and without the
    /// root dot, and the type.
    pub question: (String, u16),
    /// The addresses the answer section holds for the question's name,
    /// through its `CNAME`s, in the order they were written.
    pub addresses: Vec<IpAddr>,
}

/// Read one DNS answer message.
///
/// Reads the header, the one question and the answer section, and
/// nothing else: authority and additional records are where a resolver
/// would offer addresses nobody asked about.
pub fn parse(msg: &[u8]) -> Result<Reply, DnsError> {
    let mut r = Reader::new(msg);
    let id = r.u16()?;
    let flags = r.u16()?;
    let questions = r.u16()?;
    let answers = r.u16()?;
    let _authority = r.u16()?;
    let _additional = r.u16()?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::NotAnAnswer);
    }
    if questions != 1 {
        return Err(DnsError::Question);
    }
    let name = r.name()?;
    let qtype = r.u16()?;
    if r.u16()? != CLASS_IN {
        return Err(DnsError::Class);
    }
    let mut records = Vec::new();
    for _ in 0..answers.min(as_u16(MAX_RECORDS)) {
        records.push(r.record()?);
    }
    let addresses = chain(&name, &records);
    Ok(Reply {
        id,
        truncated: flags & 0x0200 != 0,
        rcode: (flags & 0x000f) as u8,
        question: (name, qtype),
        addresses,
    })
}

/// A bound as the wire counts things. The constants are small; the
/// saturation is only so this is a `const`-free expression with no cast
/// that could wrap.
fn as_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Resolve `name` to addresses on `port`, asking each of `servers` on
/// [`PORT`] in turn.
///
/// Both questions are asked: the `A` answer's addresses come first,
/// then the `AAAA` answer's, which is the order they are dialled in.
pub fn resolve(name: &str, port: u16, servers: &[IpAddr]) -> io::Result<Vec<SocketAddr>> {
    let at: Vec<SocketAddr> = servers
        .iter()
        .map(|ip| SocketAddr::new(*ip, PORT))
        .collect();
    resolve_at(name, port, &at)
}

/// [`resolve`], with the resolvers named by address *and* port, which
/// is how a test points it at a server of its own.
pub fn resolve_at(name: &str, port: u16, servers: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
    if servers.is_empty() {
        return Err(io::Error::other("no resolver address was given"));
    }
    let deadline = Instant::now() + BUDGET;
    let mut addresses = Vec::new();
    let mut answered = false;
    let mut last = io::Error::other("no resolver answered");
    for qtype in [TYPE_A, TYPE_AAAA] {
        match ask(name, qtype, servers, deadline) {
            Ok(found) => {
                answered = true;
                addresses.extend(found);
            }
            Err(err) => last = err,
        }
    }
    if !answered {
        return Err(last);
    }
    Ok(addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// Ask one question of every resolver until one answers it.
fn ask(
    name: &str,
    qtype: u16,
    servers: &[SocketAddr],
    deadline: Instant,
) -> io::Result<Vec<IpAddr>> {
    let mut last = io::Error::other("no resolver answered");
    for server in servers {
        for _ in 0..TRIES {
            if Instant::now() >= deadline {
                return Err(io::Error::other(
                    "the resolvers took longer than the budget",
                ));
            }
            match once(name, qtype, server) {
                Ok(reply) => return Ok(reply.addresses),
                Err(err) => last = err,
            }
        }
    }
    Err(last)
}

/// One question to one resolver, over UDP and then over TCP if the
/// answer was truncated.
fn once(name: &str, qtype: u16, server: &SocketAddr) -> io::Result<Reply> {
    let id = query_id();
    let question = question(name, qtype, id)?;
    let reply = checked(&over_udp(server, &question)?, id, name, qtype)?;
    if !reply.truncated {
        return Ok(reply);
    }
    checked(&over_tcp(server, &question)?, id, name, qtype)
}

/// Parse one answer and hold it to the question that was asked.
///
/// The id and the echoed question are what tell this answer from one
/// that arrived by chance; `rcode` 3 is "no such name", which is an
/// answer with no addresses and not a reason to ask again.
fn checked(msg: &[u8], id: u16, name: &str, qtype: u16) -> io::Result<Reply> {
    let reply = parse(msg).map_err(io::Error::other)?;
    if reply.id != id {
        return Err(io::Error::other("an answer carrying another id"));
    }
    let asked = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if reply.question != (asked, qtype) {
        return Err(io::Error::other("an answer to another question"));
    }
    match reply.rcode {
        0 | 3 => Ok(reply),
        code => Err(io::Error::other(format!(
            "the resolver answered with rcode {code}"
        ))),
    }
}

/// Send one question and take one datagram back.
fn over_udp(server: &SocketAddr, question: &[u8]) -> io::Result<Vec<u8>> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(local)?;
    // Connected, so the kernel drops every datagram that is not from
    // the resolver: an answer of anyone else's needs the source address
    // as well as the id.
    socket.connect(server)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.send(question)?;
    let mut buf = vec![0u8; MAX_UDP];
    let n = socket.recv(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Ask the same question over TCP, which is what a truncated answer
/// asks for.
fn over_tcp(server: &SocketAddr, question: &[u8]) -> io::Result<Vec<u8>> {
    let mut socket = TcpStream::connect_timeout(server, TIMEOUT)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    let len = u16::try_from(question.len())
        .map_err(|_| io::Error::other("the question is longer than a message"))?;
    socket.write_all(&len.to_be_bytes())?;
    socket.write_all(question)?;
    let mut head = [0u8; 2];
    socket.read_exact(&mut head)?;
    let len = usize::from(u16::from_be_bytes(head));
    if len > MAX_TCP {
        return Err(io::Error::other("an answer longer than this client reads"));
    }
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf)?;
    Ok(buf)
}

/// One question message: the header, the name, the type and class `IN`.
///
/// `RD` is the only flag set — these resolvers are recursive, and this
/// client follows nothing but the `CNAME`s an answer already holds.
fn question(name: &str, qtype: u16, id: u16) -> io::Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(name.len() + 18);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    encode_name(name, &mut msg)?;
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(msg)
}

/// Write `name` as DNS labels. The name is one a `CONNECT` target
/// already passed the LDH rules, so a failure here is a bug rather than
/// a client's doing.
fn encode_name(name: &str, out: &mut Vec<u8>) -> io::Result<()> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(io::Error::other("a name of no length DNS carries"));
    }
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|n| *n > 0 && usize::from(*n) <= MAX_LABEL)
            .ok_or_else(|| io::Error::other("a label of no length DNS carries"))?;
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// A fresh 16-bit id for one question.
///
/// Never a fixed one: with the id and the ephemeral port, an answer
/// nobody asked for has to guess both, on top of coming from the
/// resolver's own address.
fn query_id() -> u16 {
    let mut bytes = [0u8; 2];
    let mut got = 0;
    while got < bytes.len() {
        match getrandom(&mut bytes[got..], GetRandomFlags::empty()) {
            Ok(filled) if filled > 0 => got += filled,
            // A kernel without `getrandom(2)`. The clock's low bits are
            // worse and are all that is left; the ruleset is what keeps
            // an off-path answer out either way.
            _ => return fallback_id(),
        }
    }
    u16::from_be_bytes(bytes)
}

/// The id when the kernel will not give one: the clock's nanoseconds,
/// which no other process here shares.
fn fallback_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    (nanos & 0xffff) as u16
}

/// One answer record, reduced to what a dial can use.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    /// The owner name, lower case and without the root dot.
    name: String,
    /// What it holds.
    data: Data,
}

/// The record types this client reads.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Data {
    /// An `A` record.
    V4(Ipv4Addr),
    /// An `AAAA` record.
    V6(Ipv6Addr),
    /// A `CNAME`, and the name it points at.
    Cname(String),
    /// Anything else, which this client passes over.
    Other,
}

/// The addresses an answer holds for `name`, following its `CNAME`s.
///
/// Records whose owner is not the name being looked up are ignored, so
/// a resolver cannot slip an address for a name nobody asked about into
/// the same answer.
fn chain(name: &str, records: &[Record]) -> Vec<IpAddr> {
    let mut target = name.to_owned();
    let mut out = Vec::new();
    for _ in 0..MAX_CNAMES {
        let mut next = None;
        for record in records {
            if record.name != target {
                continue;
            }
            match &record.data {
                Data::V4(a) => out.push(IpAddr::V4(*a)),
                Data::V6(a) => out.push(IpAddr::V6(*a)),
                Data::Cname(to) if next.is_none() => next = Some(to.clone()),
                _ => {}
            }
        }
        if !out.is_empty() {
            break;
        }
        match next {
            Some(to) => target = to,
            None => break,
        }
    }
    out
}

/// A cursor over one message that cannot leave it.
struct Reader<'a> {
    /// The whole message, which a compression pointer may reach into.
    msg: &'a [u8],
    /// Where the next field begins.
    at: usize,
}

impl<'a> Reader<'a> {
    /// Read `msg` from its first byte.
    fn new(msg: &'a [u8]) -> Self {
        Self { msg, at: 0 }
    }

    /// One byte.
    fn u8(&mut self) -> Result<u8, DnsError> {
        let b = *self.msg.get(self.at).ok_or(DnsError::Short)?;
        self.at += 1;
        Ok(b)
    }

    /// Two bytes, big-endian, as the wire writes every number.
    fn u16(&mut self) -> Result<u16, DnsError> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }

    /// Four bytes, big-endian.
    fn u32(&mut self) -> Result<u32, DnsError> {
        Ok(u32::from_be_bytes([
            self.u8()?,
            self.u8()?,
            self.u8()?,
            self.u8()?,
        ]))
    }

    /// Move to `to`, which must be inside the message.
    fn seek(&mut self, to: usize) -> Result<(), DnsError> {
        if to > self.msg.len() {
            return Err(DnsError::Short);
        }
        self.at = to;
        Ok(())
    }

    /// One name, decompressed, lower case and without the root dot.
    ///
    /// A pointer must point strictly backwards, which is what makes a
    /// loop impossible rather than merely bounded; the jump count is
    /// there so a chain of legal pointers cannot cost more than the
    /// message is long.
    fn name(&mut self) -> Result<String, DnsError> {
        let mut out = String::new();
        let mut at = self.at;
        let mut jumps = 0usize;
        let mut end = None;
        loop {
            let len = *self.msg.get(at).ok_or(DnsError::Short)?;
            match len & 0xc0 {
                0x00 => {
                    let n = usize::from(len);
                    at += 1;
                    if n == 0 {
                        end = end.or(Some(at));
                        break;
                    }
                    let label = self.msg.get(at..at + n).ok_or(DnsError::Short)?;
                    if out.len() + n + 1 > MAX_NAME {
                        return Err(DnsError::Name);
                    }
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
                    at += n;
                }
                0xc0 => {
                    let hi = usize::from(len & 0x3f);
                    let lo = usize::from(*self.msg.get(at + 1).ok_or(DnsError::Short)?);
                    let to = (hi << 8) | lo;
                    end = end.or(Some(at + 2));
                    if to >= at {
                        return Err(DnsError::Pointer);
                    }
                    jumps += 1;
                    if jumps > MAX_JUMPS {
                        return Err(DnsError::Pointer);
                    }
                    at = to;
                }
                _ => return Err(DnsError::LabelType),
            }
        }
        self.at = end.unwrap_or(at);
        Ok(out)
    }

    /// One answer record. `rdlength` is what says where the next one
    /// begins, whatever the record itself turned out to hold.
    fn record(&mut self) -> Result<Record, DnsError> {
        let name = self.name()?;
        let rtype = self.u16()?;
        let class = self.u16()?;
        let _ttl = self.u32()?;
        let len = usize::from(self.u16()?);
        let from = self.at;
        let end = from.checked_add(len).ok_or(DnsError::Short)?;
        if end > self.msg.len() {
            return Err(DnsError::Short);
        }
        let data = match (class, rtype) {
            (CLASS_IN, TYPE_A) if len == 4 => {
                let b = &self.msg[from..end];
                Data::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            (CLASS_IN, TYPE_AAAA) if len == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&self.msg[from..end]);
                Data::V6(Ipv6Addr::from(b))
            }
            (CLASS_IN, TYPE_CNAME) => {
                let mut sub = Reader {
                    msg: self.msg,
                    at: from,
                };
                Data::Cname(sub.name()?)
            }
            _ => Data::Other,
        };
        self.seek(end)?;
        Ok(Record { name, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// The flags an ordinary answer carries: `QR`, `RD` and `RA`.
    const ANSWER: u16 = 0x8180;

    /// One name as labels.
    fn labels(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_name(name, &mut out).expect("a name DNS carries");
        out
    }

    /// One resource record: owner, type, and its data.
    fn record(owner: &[u8], rtype: u16, data: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&as_u16(data.len()).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// One whole message: header, one question, and the records.
    fn message(id: u16, flags: u16, question: (&str, u16), records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&as_u16(records.len()).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&labels(question.0));
        out.extend_from_slice(&question.1.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    fn v4(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
    }

    #[test]
    fn an_answer_gives_its_addresses_in_the_order_they_were_written() {
        let msg = message(
            0x1234,
            ANSWER,
            ("api.example", TYPE_A),
            &[
                record(&labels("api.example"), TYPE_A, &[1, 2, 3, 4]),
                record(&labels("API.Example"), TYPE_A, &[5, 6, 7, 8]),
            ],
        );
        let reply = parse(&msg).expect("an answer");
        assert_eq!(reply.id, 0x1234);
        assert_eq!(reply.rcode, 0);
        assert!(!reply.truncated);
        assert_eq!(reply.question, ("api.example".to_owned(), TYPE_A));
        assert_eq!(reply.addresses, vec![v4([1, 2, 3, 4]), v4([5, 6, 7, 8])]);
    }

    #[test]
    fn an_aaaa_answer_reads_the_sixteen_bytes() {
        let addr = "2606:4700::1111".parse::<Ipv6Addr>().expect("an address");
        let msg = message(
            1,
            ANSWER,
            ("api.example", TYPE_AAAA),
            &[record(&labels("api.example"), TYPE_AAAA, &addr.octets())],
        );
        let reply = parse(&msg).expect("an answer");
        assert_eq!(reply.addresses, vec![IpAddr::V6(addr)]);
    }

    #[test]
    fn a_cname_is_followed_to_the_address_behind_it() {
        let msg = message(
            1,
            ANSWER,
            ("www.example", TYPE_A),
            &[
                record(&labels("www.example"), TYPE_CNAME, &labels("edge.example")),
                record(&labels("edge.example"), TYPE_A, &[9, 9, 9, 9]),
                // Not on the chain, and so not dialled.
                record(&labels("other.example"), TYPE_A, &[10, 0, 0, 1]),
            ],
        );
        let reply = parse(&msg).expect("an answer");
        assert_eq!(reply.addresses, vec![v4([9, 9, 9, 9])]);
    }

    #[test]
    fn a_record_for_a_name_nobody_asked_about_is_ignored() {
        let msg = message(
            1,
            ANSWER,
            ("api.example", TYPE_A),
            &[record(&labels("evil.example"), TYPE_A, &[10, 0, 0, 1])],
        );
        assert!(parse(&msg).expect("an answer").addresses.is_empty());
    }

    #[test]
    fn a_cname_loop_ends_at_the_bound() {
        let msg = message(
            1,
            ANSWER,
            ("a.example", TYPE_A),
            &[
                record(&labels("a.example"), TYPE_CNAME, &labels("b.example")),
                record(&labels("b.example"), TYPE_CNAME, &labels("a.example")),
            ],
        );
        assert!(parse(&msg).expect("an answer").addresses.is_empty());
    }

    #[test]
    fn a_name_that_does_not_exist_is_an_answer_with_nothing_in_it() {
        let msg = message(7, ANSWER | 3, ("api.example", TYPE_A), &[]);
        let reply = parse(&msg).expect("an answer");
        assert_eq!(reply.rcode, 3);
        assert!(reply.addresses.is_empty());
        checked(&msg, 7, "api.example", TYPE_A).expect("no such name is still an answer");
    }

    #[test]
    fn a_truncated_answer_says_so() {
        let msg = message(1, ANSWER | 0x0200, ("api.example", TYPE_A), &[]);
        assert!(parse(&msg).expect("an answer").truncated);
    }

    #[test]
    fn an_answer_to_another_question_is_refused() {
        let msg = message(9, ANSWER, ("api.example", TYPE_A), &[]);
        assert!(checked(&msg, 8, "api.example", TYPE_A).is_err(), "the id");
        assert!(
            checked(&msg, 9, "other.example", TYPE_A).is_err(),
            "the name"
        );
        assert!(
            checked(&msg, 9, "api.example", TYPE_AAAA).is_err(),
            "the type"
        );
        checked(&msg, 9, "API.Example.", TYPE_A).expect("case and the root dot are the same name");
        let refused = message(9, ANSWER | 2, ("api.example", TYPE_A), &[]);
        assert!(
            checked(&refused, 9, "api.example", TYPE_A).is_err(),
            "rcode 2"
        );
    }

    #[test]
    fn a_message_that_is_not_an_answer_is_refused() {
        let msg = message(1, 0x0100, ("api.example", TYPE_A), &[]);
        assert_eq!(parse(&msg), Err(DnsError::NotAnAnswer));
    }

    #[test]
    fn a_message_that_stops_early_is_refused() {
        let msg = message(1, ANSWER, ("api.example", TYPE_A), &[]);
        for cut in 0..msg.len() {
            assert!(parse(&msg[..cut]).is_err(), "cut at {cut}");
        }
        // An `rdlength` that runs past the message is the same failure.
        let mut long = message(
            1,
            ANSWER,
            ("api.example", TYPE_A),
            &[record(&labels("api.example"), TYPE_A, &[1, 2, 3, 4])],
        );
        let at = long.len() - 6;
        long[at..at + 2].copy_from_slice(&0x0400u16.to_be_bytes());
        assert_eq!(parse(&long), Err(DnsError::Short));
    }

    #[test]
    fn a_label_type_this_parser_does_not_have_is_refused() {
        let mut msg = message(1, ANSWER, ("api.example", TYPE_A), &[]);
        msg[12] = 0x80;
        assert_eq!(parse(&msg), Err(DnsError::LabelType));
    }

    #[test]
    fn a_compression_pointer_must_point_backwards() {
        // A pointer at the question name to itself, which is the shape
        // a loop would have.
        let mut msg = message(1, ANSWER, ("api.example", TYPE_A), &[]);
        msg[12] = 0xc0;
        msg[13] = 12;
        assert_eq!(parse(&msg), Err(DnsError::Pointer));
        // And one pointing forwards, which is the same refusal.
        let mut msg = message(1, ANSWER, ("api.example", TYPE_A), &[]);
        msg[12] = 0xc0;
        msg[13] = 20;
        assert_eq!(parse(&msg), Err(DnsError::Pointer));
    }

    #[test]
    fn a_compressed_owner_name_is_read_as_the_name_it_points_at() {
        // 12 is where the question's name begins in every message.
        let msg = message(
            1,
            ANSWER,
            ("api.example", TYPE_A),
            &[record(&[0xc0, 12], TYPE_A, &[1, 2, 3, 4])],
        );
        assert_eq!(
            parse(&msg).expect("an answer").addresses,
            vec![v4([1, 2, 3, 4])]
        );
    }

    #[test]
    fn a_name_longer_than_dns_carries_is_refused() {
        let long = format!("{}.example", "a".repeat(64));
        let mut out = Vec::new();
        assert!(encode_name(&long, &mut out).is_err());
        assert!(encode_name("", &mut out).is_err());
        assert!(encode_name("a..b", &mut out).is_err());
    }

    /// A resolver of the test's own: one datagram in, one out.
    ///
    /// It answers an `A` question with `1.2.3.4` and every other
    /// question with nothing, which is what a name with no `AAAA`
    /// looks like.
    fn stub(truncate: bool) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let socket =
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a resolver socket");
        let at = socket.local_addr().expect("its address");
        let joined = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    return;
                };
                let reply = stub_answer(&buf[..n], truncate);
                let _ = socket.send_to(&reply, from);
            }
        });
        (at, joined)
    }

    /// The answer the stub writes for whatever question it was sent.
    fn stub_answer(query: &[u8], truncate: bool) -> Vec<u8> {
        let id = u16::from_be_bytes([query[0], query[1]]);
        // The question ends at its root label, then four bytes of type
        // and class.
        let mut at = 12;
        while query[at] != 0 {
            at += 1 + usize::from(query[at]);
        }
        let question = &query[12..at + 5];
        let qtype = u16::from_be_bytes([query[at + 1], query[at + 2]]);
        let records: Vec<Vec<u8>> = if qtype == TYPE_A && !truncate {
            vec![record(&[0xc0, 12], TYPE_A, &[1, 2, 3, 4])]
        } else {
            Vec::new()
        };
        let flags = if truncate { ANSWER | 0x0200 } else { ANSWER };
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&as_u16(records.len()).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(question);
        for r in records {
            out.extend_from_slice(&r);
        }
        out
    }

    #[test]
    fn a_question_goes_out_and_the_answer_comes_back() {
        let (at, joined) = stub(false);
        let got = resolve_at("api.example", 443, &[at]).expect("the stub answers");
        assert_eq!(
            got,
            vec![SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 443))]
        );
        joined.join().expect("the stub ends");
    }

    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp() {
        let (at, joined) = stub(true);
        let listener = TcpListener::bind(at).expect("the same port over TCP");
        let over_tcp = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                let mut head = [0u8; 2];
                if socket.read_exact(&mut head).is_err() {
                    return;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(head))];
                if socket.read_exact(&mut query).is_err() {
                    return;
                }
                let answer = stub_answer(&query, false);
                let _ = socket.write_all(&as_u16(answer.len()).to_be_bytes());
                let _ = socket.write_all(&answer);
            }
        });
        let got = resolve_at("api.example", 443, &[at]).expect("the stub answers");
        assert_eq!(
            got,
            vec![SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 443))]
        );
        joined.join().expect("the stub ends");
        over_tcp.join().expect("the TCP half ends");
    }

    #[test]
    fn a_resolver_that_is_not_there_is_an_error_and_not_a_wait() {
        assert!(resolve("api.example", 443, &[]).is_err());
        // Nothing listens there, so every try is answered with
        // `ECONNREFUSED` at once rather than waited out.
        let dead = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let start = Instant::now();
        assert!(resolve_at("api.example", 443, &[dead]).is_err());
        assert!(start.elapsed() < BUDGET, "waited {:?}", start.elapsed());
    }

    #[test]
    fn every_query_carries_an_id_of_its_own() {
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| query_id()).collect();
        assert!(ids.len() > 32, "only {} ids in 64 draws", ids.len());
    }
}
