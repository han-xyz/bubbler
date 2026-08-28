//! The egress proxy bubbler puts in the sandbox's network namespace.
//!
//! bubbler joins this process to the sandbox's user, network and mount
//! namespaces with no capability of its own and writes it into a cgroup
//! the nftables ruleset accepts. That is the whole of its privilege: it
//! is on the inside, in the one cgroup the filter lets out, and the
//! application beside it is not.
//!
//! So it binds `127.0.0.1:<--port>` itself — after the namespaces are
//! joined, or the socket would be the host's loopback — reports on
//! `--ready-fd` that it is listening, and from then on answers `CONNECT`
//! and nothing else. The port is the launcher's to choose because the
//! sandbox is told it in an environment variable of bwrap's argv, which
//! is fixed before the namespace this binds in exists. Names come from
//! argv; the sandbox never gets to add one.
//!
//! The mount namespace it joins is the sandbox's, which is why names
//! are resolved by [`dns`] against the `--dns` addresses and never by
//! `getaddrinfo`: NSS inside that namespace is the application's to
//! answer.

// The library — the parser, the allowlist and the relay — forbids
// `unsafe`. The binary cannot: taking over a descriptor the launcher
// passed by number is the one thing safe Rust has no wrapper for, and
// it happens once, here, before anything else runs.
#![deny(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

use bubbler_net_proxy::allow::Allowlist;
use bubbler_net_proxy::connect::{self, Status};
use bubbler_net_proxy::dns;
use bubbler_net_proxy::relay;

/// The one usage line, so a grammar error always names the whole
/// grammar.
const USAGE: &str = "bubbler-net-proxy: usage: --allow NAME:PORT [--allow NAME:PORT ...] \
--dns IP [--dns IP ...] --port N --ready-fd N [--log-fd N] [--log-tunnels]";

/// Tunnels one proxy carries at a time. Past this a connection is
/// answered `503` and closed: a sandbox that opens sockets without
/// bound must not cost the host a thread apiece.
const MAX_TUNNELS: usize = 64;

/// How long a client has to finish its request line and headers,
/// counted once from the connection and not once per read. A client
/// that dribbles one byte at a time holds a thread and one of the
/// tunnel slots otherwise.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the whole dial has, however many addresses the name
/// resolved to. Per address it would be this times the length of the
/// answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a write that is not the relay's may block: the `200`, the
/// bytes that came behind it, and every refusal. The relay does its own
/// waiting; a peer that will not read is not owed a thread.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a refusal written from the accept loop may block. Short,
/// because the thread it holds is the one that takes every other
/// connection: a client that never reads its `503` must not be able to
/// stop the proxy from accepting.
const REFUSE_TIMEOUT: Duration = Duration::from_secs(1);

/// How long to wait after an `accept` that failed for a reason of its
/// own. Retrying at once would spin against whatever is exhausted, one
/// log line to a turn.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Lines the log takes in one [`LOG_WINDOW`]. Every line is about
/// something the sandbox did, so without a budget a client opening
/// refused connections in a loop writes the whole of the instance's
/// record and pushes everything else out of it.
const LOG_BUDGET: u32 = 20;

/// The window [`LOG_BUDGET`] is counted over.
const LOG_WINDOW: Duration = Duration::from_secs(1);

/// Bytes taken from the client in one read while the request is being
/// assembled.
const READ_CHUNK: usize = 1024;

/// What goes down `--ready-fd` once the listener is up. Its value says
/// nothing; that it arrives at all is the whole message.
const READY: u8 = 1;

/// What the launcher asked for.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    /// The `name:port` targets a tunnel may be opened to, as written.
    allow: Vec<String>,
    /// The resolvers to ask, in order. The ruleset lets this process
    /// reach them and lets the application reach nothing on port 53.
    dns: Vec<IpAddr>,
    /// The loopback port to listen on, inside the namespace the
    /// launcher joined this process to.
    port: u16,
    /// Written one byte once the listener is up, and closed. The
    /// launcher waits on it before it starts the application, so the
    /// proxy variables it set name a port that already answers.
    ready_fd: i32,
    /// Where the log goes; stderr when the launcher named nothing.
    log_fd: Option<i32>,
    /// Whether the lines about what the proxy carried — the listener it
    /// opened and every tunnel through it — are written at all. Off,
    /// because that log shares a terminal with whatever the sandbox is
    /// running and a full-screen application redraws over it; the
    /// refusals are written either way, since those are what a user has
    /// to notice.
    log_tunnels: bool,
}

fn main() -> ExitCode {
    let Some(args) = parse_from(std::env::args_os().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let list = match Allowlist::parse(&args.allow) {
        Ok(list) => list,
        Err(why) => {
            eprintln!("bubbler-net-proxy: {why}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    // The log is opened first, so every failure after this point
    // reaches the launcher's own record and not a stderr it may not be
    // reading.
    let log = match args.log_fd.map(adopt).transpose() {
        Ok(Some(fd)) => Arc::new(Log::to_fd(fd, args.log_tunnels)),
        Ok(None) => Arc::new(Log::to_stderr(args.log_tunnels)),
        Err(err) => {
            eprintln!("bubbler-net-proxy: {err}");
            return ExitCode::from(1);
        }
    };
    let dns: Vec<SocketAddr> = args
        .dns
        .iter()
        .map(|ip| SocketAddr::new(*ip, dns::PORT))
        .collect();
    match serve(list, dns, args.port, args.ready_fd, &log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log.line(&format!("stopped: {err}"));
            ExitCode::from(1)
        }
    }
}

/// Parse the grammar over any argv but this process's own.
///
/// `--allow` and `--dns` repeat and must each appear at least once — a
/// proxy with an empty allowlist would answer `403` to everything and
/// one with no resolver `502`, and both are launcher bugs worth failing
/// on. The other options appear once, `--log-tunnels` included, and no
/// two may name the same descriptor: a number adopted twice would be
/// closed twice.
fn parse_from(mut it: impl Iterator<Item = OsString>) -> Option<Args> {
    let mut allow: Vec<String> = Vec::new();
    let mut dns: Vec<IpAddr> = Vec::new();
    let mut port = None;
    let mut ready_fd = None;
    let mut log_fd = None;
    let mut log_tunnels = false;
    while let Some(word) = it.next() {
        match word.to_str() {
            Some("--allow") => allow.push(it.next()?.to_str()?.to_owned()),
            Some("--dns") => dns.push(it.next()?.to_str()?.parse().ok()?),
            Some("--port") if port.is_none() => port = Some(listen_port(it.next()?)?),
            Some("--ready-fd") if ready_fd.is_none() => ready_fd = Some(number(it.next()?)?),
            Some("--log-fd") if log_fd.is_none() => log_fd = Some(number(it.next()?)?),
            Some("--log-tunnels") if !log_tunnels => log_tunnels = true,
            _ => return None,
        }
    }
    if allow.is_empty() || dns.is_empty() {
        return None;
    }
    let args = Args {
        allow,
        dns,
        port: port?,
        ready_fd: ready_fd?,
        log_fd,
        log_tunnels,
    };
    if Some(args.ready_fd) == args.log_fd {
        return None;
    }
    Some(args)
}

/// One port number a socket can be bound to: `0` would let the kernel
/// choose, and a port nobody chose is one the launcher could not have
/// put in the sandbox's environment.
fn listen_port(word: OsString) -> Option<u16> {
    match word.to_str()?.parse::<u16>() {
        Ok(port) if port > 0 => Some(port),
        _ => None,
    }
}

/// One non-negative descriptor number.
fn number(word: OsString) -> Option<i32> {
    match word.to_str()?.parse::<i32>() {
        Ok(fd) if fd >= 0 => Some(fd),
        _ => None,
    }
}

/// Bind the loopback listener, tell the launcher it is up, and serve
/// until the process is stopped.
///
/// The byte goes out only once the listener is up, so the launcher never
/// releases an application whose proxy address answers nothing. The
/// namespace is the sandbox's own and nothing else has run in it, so a
/// port the launcher picked is free; a bind that fails anyway ends the
/// process, and the launcher's wait ends with it.
fn serve(
    list: Allowlist,
    dns: Vec<SocketAddr>,
    port: u16,
    ready_fd: i32,
    log: &Arc<Log>,
) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    let ready = adopt(ready_fd)?;
    File::from(ready).write_all(&[READY])?;
    log.if_verbose(&format!(
        "listening on 127.0.0.1:{port} for {} allowed targets",
        list.len()
    ));

    let list = Arc::new(list);
    let dns = Arc::new(dns);
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                log.line(&format!("accept failed: {err}"));
                std::thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
        };
        if live.load(Ordering::SeqCst) >= MAX_TUNNELS {
            note_refusal(log, Status::SERVICE_UNAVAILABLE);
            refuse(client, Status::SERVICE_UNAVAILABLE, REFUSE_TIMEOUT, log);
            continue;
        }
        let held = Live::take(&live);
        let list = Arc::clone(&list);
        let dns = Arc::clone(&dns);
        let thread_log = Arc::clone(log);
        let spawned = std::thread::Builder::new().spawn(move || {
            tunnel(client, &list, &dns, &thread_log);
            drop(held);
        });
        if let Err(err) = spawned {
            log.line(&format!("no thread for a tunnel: {err}"));
        }
    }
}

/// One tunnel's worth of the count, given back when the thread ends.
struct Live(Arc<AtomicUsize>);

impl Live {
    /// Count one more tunnel.
    fn take(live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(live))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve one connection: read its request, judge it, and either relay
/// or refuse.
fn tunnel(mut client: TcpStream, list: &Allowlist, dns: &[SocketAddr], log: &Log) {
    // One deadline for the whole header phase. A request arriving in
    // pieces is ordinary and must still be served; a request that never
    // ends must not be able to keep a slot by writing a byte now and
    // then.
    let deadline = Instant::now() + HEADER_TIMEOUT;
    let (request, buffered) = match read_request(&mut client, deadline) {
        Ok(pair) => pair,
        Err(Some(status)) => {
            note_refusal(log, status);
            return refuse(client, status, WRITE_TIMEOUT, log);
        }
        Err(None) => return,
    };
    if !list.matches(&request.host, request.port) {
        log.line(&format!(
            "denied {}:{}: no allow-host covers it",
            request.host, request.port
        ));
        return refuse(client, Status::FORBIDDEN, WRITE_TIMEOUT, log);
    }
    let upstream = match dial(&request.host, request.port, |host, port| {
        dns::resolve_at(host, port, dns)
    }) {
        Ok(upstream) => upstream,
        Err(status) => {
            log.line(&format!(
                "{}:{} not reached: {status}",
                request.host, request.port
            ));
            return refuse(client, status, WRITE_TIMEOUT, log);
        }
    };
    if let Err(err) = open(&client, &upstream, &buffered) {
        log.line(&format!(
            "{}:{} tunnel not opened: {err}",
            request.host, request.port
        ));
        return;
    }
    log.if_verbose(&format!("tunnel to {}:{}", request.host, request.port));
    if let Err(err) = relay::run(client, upstream, relay::IDLE) {
        log.line(&format!("{}:{} relay: {err}", request.host, request.port));
    }
}

/// Answer `200`, hand the upstream what came behind the blank line, and
/// leave both sockets as the relay wants them.
///
/// These are the only writes outside the relay that could block on a
/// peer, so both carry [`WRITE_TIMEOUT`]; the relay polls and wants
/// neither that nor the header deadline.
fn open(client: &TcpStream, upstream: &TcpStream, buffered: &[u8]) -> io::Result<()> {
    client.set_write_timeout(Some(WRITE_TIMEOUT))?;
    upstream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    (&mut &*client).write_all(connect::ESTABLISHED.as_bytes())?;
    // Bytes the client pipelined behind the blank line are already
    // tunnel data (RFC 9110 §9.3.6) and go out before anything is read
    // from either side again.
    (&mut &*upstream).write_all(buffered)?;
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    upstream.set_write_timeout(None)
}

/// Read until the request is whole.
///
/// `Err(Some(status))` is a request to answer and close; `Err(None)` is
/// a client that went away, which is answered with nothing. The success
/// value carries the tunnel bytes that arrived with the request.
///
/// `deadline` bounds the phase, not the read: a socket timeout starts
/// again with every `recv`, so what is set before each read is what is
/// left of the one budget. A client still talking when it runs out is
/// answered `408`.
fn read_request(
    client: &mut TcpStream,
    deadline: Instant,
) -> Result<(connect::Request, Vec<u8>), Option<Status>> {
    let mut buf = Vec::with_capacity(READ_CHUNK);
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        match connect::parse(&buf) {
            Ok(request) => {
                let rest = buf.split_off(request.consumed);
                return Ok((request, rest));
            }
            Err(status) if status.code != 0 => return Err(Some(status)),
            Err(_) => {}
        }
        if buf.len() >= connect::MAX_HEADERS {
            return Err(Some(Status::BAD_REQUEST));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Some(Status::REQUEST_TIMEOUT));
        }
        if client.set_read_timeout(Some(left)).is_err() {
            return Err(None);
        }
        match client.read(&mut chunk) {
            // The client hung up mid-request; there is nobody to answer.
            Ok(0) => return Err(None),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if is_timeout(&err) => return Err(Some(Status::REQUEST_TIMEOUT)),
            Err(_) => return Err(None),
        }
    }
}

/// Whether a read stopped because the deadline did, rather than because
/// the connection did.
fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Open the upstream connection, or say why there is none.
///
/// Addresses are tried in the order the resolver gave them, and the
/// whole dial shares one [`CONNECT_TIMEOUT`]: a name answering with
/// thirty blackholed records must not hold a tunnel slot thirty times
/// as long as one that answers with one.
///
/// A loopback or link-local answer is skipped rather than dialled.
/// Loopback inside this namespace is the sandbox's own, so a listed
/// name that resolves there points the proxy at the application — or at
/// the proxy itself, one tunnel slot per request. `169.254.0.0/16` is
/// where pasta's DNS forwarder sits, and a listed name resolving there
/// would hand the application back the resolver the ruleset took away
/// from it. Nothing else about the address is judged: what the sandbox
/// may reach is decided by the name its config granted, and the
/// namespace routes nowhere an `allow-out` could not name.
fn dial(
    host: &str,
    port: u16,
    resolve: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
) -> Result<TcpStream, Status> {
    let addrs = resolve(host, port).map_err(|_| Status::BAD_GATEWAY)?;
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut late = false;
    for addr in addrs {
        if is_inward(&addr.ip()) {
            continue;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            late = true;
            break;
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(upstream) => return Ok(upstream),
            Err(err) if err.kind() == io::ErrorKind::TimedOut => late = true,
            Err(_) => {}
        }
    }
    Err(if late {
        Status::GATEWAY_TIMEOUT
    } else {
        Status::BAD_GATEWAY
    })
}

/// Whether `ip` points back inside the namespace rather than out of
/// it: loopback (`127.0.0.0/8`, `::1`), the unspecified address, or
/// link-local (`169.254.0.0/16`, `fe80::/10`).
///
/// The IPv6 link-local half is written out rather than taken from
/// `Ipv6Addr::is_unicast_link_local`, which the workspace's declared
/// minimum toolchain need not have.
fn is_inward(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

/// Write the line for a request refused before it ever named a target:
/// one this proxy could not read, one that was not a `CONNECT`, one that
/// ran out the header deadline, or one that arrived with every tunnel
/// slot taken.
///
/// Unconditional, because none of these is traffic: each is a client
/// doing something no `allow-host` could explain, and with the traffic
/// log off a run of nothing but these would otherwise print nothing at
/// all. The refusals that *do* name a target write their own line and
/// must not come through here twice.
///
/// Nothing of the request is repeated: those bytes are the sandbox's to
/// choose, and a line built out of them is a line the application writes
/// into the run's record.
fn note_refusal(log: &Log, status: Status) {
    let why = match status.code {
        400 => "malformed request",
        405 => "not CONNECT",
        408 => "request header timed out",
        414 => "request line too long",
        503 => "too many tunnels",
        // No other status reaches this, and one that did would still be
        // worth a line: its own reason phrase says as much as anything
        // written here could.
        _ => status.reason,
    };
    log.line(&format!("refused {} {why}", status.code));
}

/// Answer a request that will not be served and close the connection.
fn refuse(mut client: TcpStream, status: Status, wait: Duration, log: &Log) {
    // One short line, but to a client that never reads it: the write
    // must not be able to hold the thread it is on, and for a `503`
    // that thread is the accept loop, which gets the shorter budget.
    let written = client
        .set_write_timeout(Some(wait))
        .and_then(|()| client.write_all(status.response().as_bytes()));
    if let Err(err) = written {
        log.line(&format!("{status} not delivered: {err}"));
    }
    // Both halves: nothing more will be read from a connection that has
    // been refused, and the client is told so at once.
    let _ = client.shutdown(std::net::Shutdown::Both);
}

/// Where the proxy's lines go, and how many of them a second carries.
///
/// Every line is about something the sandbox did, so a client opening
/// refused connections in a loop could otherwise write the whole of the
/// record this log is copied into. [`LOG_BUDGET`] lines a window get
/// through; the rest are counted, and the count goes out as one line
/// when the window rolls.
struct Log {
    sink: Mutex<Sink>,
    /// Whether [`Log::if_verbose`] writes anything.
    verbose: bool,
}

/// The sink and its budget under one lock, so two tunnel threads cannot
/// interleave a line.
struct Sink {
    /// Where the lines are written.
    out: Box<dyn Write + Send>,
    /// When the window now being counted began.
    window: Instant,
    /// Lines written in it.
    written: u32,
    /// Lines the budget swallowed in it.
    suppressed: u64,
}

impl Log {
    /// Write to `out`. `verbose` is `--log-tunnels`.
    fn new(out: Box<dyn Write + Send>, verbose: bool) -> Self {
        Self {
            sink: Mutex::new(Sink {
                out,
                window: Instant::now(),
                written: 0,
                suppressed: 0,
            }),
            verbose,
        }
    }

    /// Write to a descriptor the launcher passed.
    fn to_fd(fd: OwnedFd, verbose: bool) -> Self {
        Self::new(Box::new(File::from(fd)), verbose)
    }

    /// Write to stderr, which is where the lines go when the launcher
    /// named no descriptor.
    fn to_stderr(verbose: bool) -> Self {
        Self::new(Box::new(io::stderr()), verbose)
    }

    /// One line, prefixed with the program name, unless this window's
    /// budget is spent.
    fn line(&self, msg: &str) {
        self.at(Instant::now(), msg);
    }

    /// [`Log::line`], but only where the launcher asked for the traffic
    /// itself to be written. Nothing a user has to act on goes through
    /// here: this is the record of what the proxy carried, and it is
    /// silent by default so that a full-screen application sharing the
    /// terminal is not redrawn over.
    fn if_verbose(&self, msg: &str) {
        if self.verbose {
            self.line(msg);
        }
    }

    /// [`Log::line`] against a clock the caller names.
    fn at(&self, now: Instant, msg: &str) {
        let mut sink = self
            .sink
            .lock()
            .expect("the log mutex is poisoned only if a thread panicked holding it");
        if now.saturating_duration_since(sink.window) >= LOG_WINDOW {
            let swallowed = sink.suppressed;
            sink.window = now;
            sink.written = 0;
            sink.suppressed = 0;
            if swallowed > 0 {
                sink.put(&format!("suppressed {swallowed} lines"));
            }
        }
        if sink.written >= LOG_BUDGET {
            sink.suppressed = sink.suppressed.saturating_add(1);
            return;
        }
        sink.written += 1;
        sink.put(msg);
    }
}

impl Sink {
    /// Write one line and get it out of the buffer.
    ///
    /// A log that cannot be written is not worth failing a tunnel over,
    /// and there is nowhere left to report it to.
    fn put(&mut self, msg: &str) {
        let _ = writeln!(self.out, "bubbler-net-proxy: {msg}");
        let _ = self.out.flush();
    }
}

/// Take ownership of a descriptor the launcher passed by number, and
/// keep it out of anything this process might ever exec.
#[allow(unsafe_code)]
fn adopt(fd: i32) -> io::Result<OwnedFd> {
    // SAFETY: the precondition is that `fd` names a descriptor this
    // process owns and that nothing else will close. `fcntl_getfd` is
    // the probe that rules out a number that is not open at all (EBADF)
    // before any owning handle exists, so no closed number is ever
    // adopted or closed twice. The grammar refuses an argv that names
    // one number twice, and the launcher passes each of these
    // descriptors to this process alone.
    let owned = unsafe {
        fcntl_getfd(BorrowedFd::borrow_raw(fd))?;
        OwnedFd::from_raw_fd(fd)
    };
    fcntl_setfd(&owned, FdFlags::CLOEXEC)?;
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::net::Ipv6Addr;
    use std::os::fd::IntoRawFd;

    fn args(words: &[&str]) -> Option<Args> {
        parse_from(words.iter().map(OsString::from))
    }

    const MINIMAL: &[&str] = &[
        "--allow",
        "api.example:443",
        "--dns",
        "169.254.1.1",
        "--port",
        "3128",
        "--ready-fd",
        "3",
    ];

    #[test]
    fn the_shortest_grammar_names_one_target_the_port_and_the_ready_pipe() {
        assert_eq!(
            args(MINIMAL),
            Some(Args {
                allow: vec!["api.example:443".to_owned()],
                dns: vec![IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))],
                port: 3128,
                ready_fd: 3,
                log_fd: None,
                log_tunnels: false,
            })
        );
    }

    /// The launcher chooses the port, so every way of not naming one is
    /// a usage error rather than a listener the sandbox was not told
    /// about.
    #[test]
    fn a_proxy_that_was_told_no_port_is_a_usage_error() {
        assert_eq!(
            args(&[
                "--allow",
                "api.example:443",
                "--dns",
                "1.1.1.1",
                "--ready-fd",
                "3"
            ]),
            None
        );
        for port in ["0", "65536", "-1", "http", "", "3128.0"] {
            assert_eq!(
                args(&[
                    "--allow",
                    "api.example:443",
                    "--dns",
                    "1.1.1.1",
                    "--port",
                    port,
                    "--ready-fd",
                    "3"
                ]),
                None,
                "{port}"
            );
        }
    }

    /// The proxy resolves names itself, so a run without a resolver
    /// could answer nothing but `502`: the launcher passing none is a
    /// bug, and an address that is no address is one too.
    #[test]
    fn a_proxy_with_no_resolver_is_a_usage_error() {
        assert_eq!(
            args(&[
                "--allow",
                "api.example:443",
                "--port",
                "3128",
                "--ready-fd",
                "3"
            ]),
            None
        );
        for server in ["", "localhost", "1.1.1.1:53", "1.1.1", "999.1.1.1"] {
            assert_eq!(
                args(&[
                    "--allow",
                    "api.example:443",
                    "--dns",
                    server,
                    "--port",
                    "3128",
                    "--ready-fd",
                    "3"
                ]),
                None,
                "{server}"
            );
        }
        let both = args(&[
            "--allow",
            "api.example:443",
            "--dns",
            "169.254.1.1",
            "--dns",
            "2606:4700:4700::1111",
            "--port",
            "3128",
            "--ready-fd",
            "3",
        ])
        .expect("two resolvers");
        assert_eq!(both.dns.len(), 2);
    }

    #[test]
    fn every_option_is_accepted_together_and_allow_repeats() {
        assert_eq!(
            args(&[
                "--allow",
                "api.example:443",
                "--allow",
                "*.cdn.example:8443",
                "--dns",
                "169.254.1.1",
                "--port",
                "3128",
                "--ready-fd",
                "4",
                "--log-fd",
                "2",
            ]),
            Some(Args {
                allow: vec![
                    "api.example:443".to_owned(),
                    "*.cdn.example:8443".to_owned()
                ],
                dns: vec![IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))],
                port: 3128,
                ready_fd: 4,
                log_fd: Some(2),
                log_tunnels: false,
            })
        );
    }

    #[test]
    fn a_proxy_with_nothing_to_allow_is_a_usage_error() {
        assert_eq!(
            args(&["--dns", "1.1.1.1", "--port", "3128", "--ready-fd", "3"]),
            None
        );
        assert_eq!(args(&["--allow", "api.example:443"]), None);
    }

    #[test]
    fn a_repeated_option_is_a_usage_error() {
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.extend(["--ready-fd", "4"]);
        assert_eq!(args(&words), None);
    }

    /// The bare word takes no value, appears at most once like every
    /// other option, and is the only thing that turns the traffic lines
    /// on.
    #[test]
    fn the_tunnel_log_is_off_until_the_word_is_given_and_may_be_given_once() {
        assert!(!args(MINIMAL).expect("the shortest grammar").log_tunnels);
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.push("--log-tunnels");
        assert!(args(&words).expect("the word is accepted").log_tunnels);
        words.push("--log-tunnels");
        assert_eq!(args(&words), None);
    }

    #[test]
    fn two_options_may_not_name_the_same_descriptor() {
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.extend(["--log-fd", "3"]);
        assert_eq!(args(&words), None);
    }

    #[test]
    fn a_descriptor_that_is_not_a_number_is_a_usage_error() {
        for fd in ["stdin", "-1", "3.0", ""] {
            assert_eq!(
                args(&[
                    "--allow",
                    "a.example:443",
                    "--dns",
                    "1.1.1.1",
                    "--port",
                    "3128",
                    "--ready-fd",
                    fd
                ]),
                None,
                "{fd}"
            );
        }
    }

    #[test]
    fn a_word_the_grammar_does_not_have_is_a_usage_error() {
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.push("--listen-fd");
        assert_eq!(args(&words), None);
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.push("api.example:443");
        assert_eq!(args(&words), None);
    }

    #[test]
    fn a_number_that_names_nothing_is_not_adopted() {
        assert!(adopt(9999).is_err());
    }

    /// A whole run of the proxy on a port of the caller's, which is how
    /// the launcher runs it: the ready byte arrives once the listener is
    /// up, and every answer after that is the proxy's own.
    ///
    /// The port is taken by binding one and letting go of it again: two
    /// tests of this file run at once, and a constant would be a race
    /// between them rather than between a proxy and a sandbox.
    fn started(allow: &[&str], dns: &[SocketAddr]) -> u16 {
        started_with(allow, dns, Log::to_stderr(false))
    }

    /// [`started`] against a log of the caller's, which is how the two
    /// gated lines are read back.
    fn started_with(allow: &[&str], dns: &[SocketAddr], log: Log) -> u16 {
        let list = Allowlist::parse(allow).expect("an allowlist");
        let dns = dns.to_vec();
        let port = {
            let held =
                TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a free port");
            held.local_addr().expect("its address").port()
        };
        let (read, write) = rustix::pipe::pipe().expect("a pipe");
        let log = Arc::new(log);
        let ready = write.into_raw_fd();
        // The proxy serves until the process ends; a test outlives no
        // thread of its own here.
        std::thread::spawn(move || {
            let _ = serve(list, dns, port, ready, &log);
        });
        let mut byte = [0u8; 1];
        File::from(read)
            .read_exact(&mut byte)
            .expect("the ready byte");
        assert_eq!(byte, [READY]);
        port
    }

    /// An echo on `address`, which is what a tunnelled name resolves to.
    fn echo_server(address: Ipv4Addr) -> u16 {
        let listener =
            TcpListener::bind(SocketAddr::from((address, 0))).expect("an upstream listener");
        let port = listener.local_addr().expect("its address").port();
        std::thread::spawn(move || {
            while let Ok((mut sock, _)) = listener.accept() {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = sock.read(&mut buf) {
                        if n == 0 || sock.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// A resolver of the test's own, answering every `A` question with
    /// `address` and every other question with nothing.
    ///
    /// The proxy asks this rather than the host's, which is the whole
    /// point of the `--dns` argument: nothing it reads inside the
    /// sandbox decides where it connects.
    fn stub_resolver(address: Ipv4Addr) -> SocketAddr {
        let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a resolver socket");
        let at = socket.local_addr().expect("its address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let query = &buf[..n];
                let mut at = 12;
                while at < query.len() && query[at] != 0 {
                    at += 1 + usize::from(query[at]);
                }
                if at + 4 >= query.len() {
                    continue;
                }
                let qtype = u16::from_be_bytes([query[at + 1], query[at + 2]]);
                let mut answer = Vec::new();
                answer.extend_from_slice(&query[..2]);
                answer.extend_from_slice(&0x8180u16.to_be_bytes());
                answer.extend_from_slice(&1u16.to_be_bytes());
                answer.extend_from_slice(&u16::from(qtype == 1).to_be_bytes());
                answer.extend_from_slice(&[0, 0, 0, 0]);
                answer.extend_from_slice(&query[12..at + 5]);
                if qtype == 1 {
                    // The owner name as a pointer to the question's, then
                    // `A`, `IN`, a minute of TTL and the four octets.
                    answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    answer.extend_from_slice(&address.octets());
                }
                let _ = socket.send_to(&answer, from);
            }
        });
        at
    }

    /// An address of this host that is not the loopback, which is what
    /// the proxy will dial. `None` where there is no route at all, and
    /// then the tunnel cannot be tested here.
    fn routable_address() -> Option<Ipv4Addr> {
        let socket =
            std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).ok()?;
        // Connecting a datagram socket sends nothing; it only picks the
        // route, and with it the address this host would be seen at.
        socket
            .connect(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 1)))
            .ok()?;
        match socket.local_addr().ok()?.ip() {
            IpAddr::V4(v4) if !is_inward(&IpAddr::V4(v4)) => Some(v4),
            _ => None,
        }
    }

    #[test]
    fn an_allowed_target_is_tunnelled_and_anything_else_is_refused() {
        let Some(address) = routable_address() else {
            println!("skipping: this host has no address but the loopback");
            return;
        };
        let upstream = echo_server(address);
        let dns = stub_resolver(address);
        let proxy = started(&[&format!("api.example:{upstream}")], &[dns]);

        let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
            .expect("the proxy answers");
        sock.write_all(
            format!("CONNECT api.example:{upstream} HTTP/1.1\r\nHost: api.example\r\n\r\nping")
                .as_bytes(),
        )
        .expect("the request goes out");
        let mut reader = io::BufReader::new(sock.try_clone().expect("a second handle"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("the status line");
        assert_eq!(line, "HTTP/1.1 200 Connection established\r\n");
        line.clear();
        reader.read_line(&mut line).expect("the blank line");
        assert_eq!(line, "\r\n");
        // The four bytes behind the blank line were tunnel data and
        // came back from the echo server.
        let mut echoed = [0u8; 4];
        reader.read_exact(&mut echoed).expect("the echo");
        assert_eq!(&echoed, b"ping");
        drop(sock);

        let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
            .expect("the proxy answers");
        sock.write_all(b"CONNECT other.example:443 HTTP/1.1\r\nHost: other.example\r\n\r\n")
            .expect("the request goes out");
        let mut answer = String::new();
        sock.read_to_string(&mut answer).expect("the refusal");
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{answer}");

        let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
            .expect("the proxy answers");
        sock.write_all(b"GET http://other.example/ HTTP/1.1\r\nHost: other.example\r\n\r\n")
            .expect("the request goes out");
        let mut answer = String::new();
        sock.read_to_string(&mut answer).expect("the refusal");
        assert!(
            answer.starts_with("HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\n"),
            "{answer}"
        );
    }

    /// A listed name whose answer points back inside the namespace: the
    /// echo is there and would answer, and the proxy still refuses,
    /// because the loopback it would dial is the application's own and
    /// its own listener sits on it.
    #[test]
    fn a_listed_name_that_resolves_inward_is_refused() {
        let upstream = echo_server(Ipv4Addr::LOCALHOST);
        let dns = stub_resolver(Ipv4Addr::LOCALHOST);
        let proxy = started(&[&format!("api.example:{upstream}")], &[dns]);
        let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
            .expect("the proxy answers");
        sock.write_all(
            format!("CONNECT api.example:{upstream} HTTP/1.1\r\nHost: api.example\r\n\r\n")
                .as_bytes(),
        )
        .expect("the request goes out");
        let mut answer = String::new();
        sock.read_to_string(&mut answer).expect("the refusal");
        assert!(
            answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{answer}"
        );
    }

    /// A resolver that answers nothing is a name that cannot be
    /// dialled, not a name that is dialled anyway.
    #[test]
    fn a_name_no_resolver_answers_is_refused() {
        let dns = stub_resolver(Ipv4Addr::LOCALHOST);
        let proxy = started(&["api.example:443"], &[dns]);
        let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
            .expect("the proxy answers");
        // The stub answers `A` for every name, so this asks for one it
        // does not: the `AAAA` half of the answer is empty and the `A`
        // half points inward, and both are refused.
        sock.write_all(b"CONNECT api.example:443 HTTP/1.1\r\nHost: api.example\r\n\r\n")
            .expect("the request goes out");
        let mut answer = String::new();
        sock.read_to_string(&mut answer).expect("the refusal");
        assert!(
            answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{answer}"
        );
    }

    /// One connected pair on loopback: what the proxy would hold, and
    /// what the client on the other end of it holds.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("the bound address");
        let near = TcpStream::connect(addr).expect("a connection");
        let (far, _) = listener.accept().expect("the other end");
        (near, far)
    }

    /// The deadline is over the phase, not over one read: every read
    /// here succeeds, so a per-read timeout would never fire and this
    /// connection would hold its slot for as long as the client kept
    /// typing. The constants are the shipped ones divided by twenty.
    #[test]
    fn a_client_that_dribbles_is_dropped_at_the_header_deadline() {
        let budget = Duration::from_millis(500);
        let (mut serving, mut client) = pair();
        let writer = std::thread::spawn(move || {
            for _ in 0..20 {
                if client.write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(budget / 5);
            }
        });
        let start = Instant::now();
        let status = read_request(&mut serving, start + budget).expect_err("the deadline passes");
        let waited = start.elapsed();
        assert_eq!(status, Some(Status::REQUEST_TIMEOUT));
        assert!(waited >= budget, "gave up after only {waited:?}");
        assert!(waited < budget * 6, "held the slot for {waited:?}");
        drop(serving);
        writer.join().expect("the writer ends");
    }

    #[test]
    fn a_request_that_arrives_in_two_reads_still_parses() {
        let (mut serving, mut client) = pair();
        std::thread::spawn(move || {
            client
                .write_all(b"CONNECT api.example:443 HTTP/1.1\r\nHost: api")
                .expect("the first half goes out");
            std::thread::sleep(Duration::from_millis(300));
            client
                .write_all(b".example\r\n\r\nhello")
                .expect("the second half goes out");
        });
        let (request, buffered) =
            read_request(&mut serving, Instant::now() + Duration::from_secs(5))
                .expect("the request arrives whole");
        assert_eq!((request.host.as_str(), request.port), ("api.example", 443));
        assert_eq!(buffered.as_slice(), b"hello");
    }

    #[test]
    fn an_answer_that_points_back_inside_is_never_dialled() {
        let v4 = |_: &str, _: u16| Ok(vec![SocketAddr::from((Ipv4Addr::new(169, 254, 1, 1), 53))]);
        assert_eq!(
            dial("resolver.example", 53, v4).expect_err("refused"),
            Status::BAD_GATEWAY
        );
        let link = "fe80::1".parse::<Ipv6Addr>().expect("an address");
        let v6 = move |_: &str, _: u16| Ok(vec![SocketAddr::from((link, 53))]);
        assert_eq!(
            dial("resolver.example", 53, v6).expect_err("refused"),
            Status::BAD_GATEWAY
        );
        // The loopback inside the namespace is the application's own,
        // and the proxy's own listener sits on it.
        for inward in ["127.0.0.1", "127.9.9.9", "0.0.0.0"] {
            let ip = inward.parse::<Ipv4Addr>().expect("an address");
            let answer = move |_: &str, _: u16| Ok(vec![SocketAddr::from((ip, 443))]);
            assert_eq!(
                dial("api.example", 443, answer).expect_err("refused"),
                Status::BAD_GATEWAY,
                "{inward}"
            );
        }
        for inward in ["::1", "::"] {
            let ip = inward.parse::<Ipv6Addr>().expect("an address");
            let answer = move |_: &str, _: u16| Ok(vec![SocketAddr::from((ip, 443))]);
            assert_eq!(
                dial("api.example", 443, answer).expect_err("refused"),
                Status::BAD_GATEWAY,
                "{inward}"
            );
        }
    }

    #[test]
    fn a_link_local_answer_is_skipped_for_the_one_behind_it() {
        let Some(address) = routable_address() else {
            println!("skipping: this host has no address but the loopback");
            return;
        };
        let listener =
            TcpListener::bind(SocketAddr::from((address, 0))).expect("an upstream listener");
        let good = listener.local_addr().expect("its address");
        let answer = move |_: &str, _: u16| {
            Ok(vec![
                SocketAddr::from((Ipv4Addr::new(169, 254, 1, 1), 443)),
                good,
            ])
        };
        let upstream = dial("api.example", 443, answer).expect("the second address answers");
        assert_eq!(upstream.peer_addr().expect("the peer"), good);
    }

    #[test]
    fn a_name_that_resolves_to_nothing_is_a_bad_gateway() {
        let nothing = |_: &str, _: u16| Ok(Vec::new());
        assert_eq!(
            dial("api.example", 443, nothing).expect_err("refused"),
            Status::BAD_GATEWAY
        );
        let refused = |_: &str, _: u16| Err(io::Error::other("no resolver"));
        assert_eq!(
            dial("api.example", 443, refused).expect_err("refused"),
            Status::BAD_GATEWAY
        );
    }

    /// A sink the test can read back, since the real ones are
    /// descriptors.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("the test holds the lock alone")
                .extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            let bytes = self
                .0
                .lock()
                .expect("the test holds the lock alone")
                .clone();
            String::from_utf8(bytes).expect("the log is UTF-8")
        }
    }

    #[test]
    fn the_log_takes_a_budget_of_lines_a_window_and_counts_the_rest() {
        let buf = Buf::default();
        let log = Log::new(Box::new(buf.clone()), false);
        let start = Instant::now();
        for n in 0..LOG_BUDGET + 5 {
            log.at(start, &format!("line {n}"));
        }
        let text = buf.text();
        assert_eq!(text.lines().count(), LOG_BUDGET as usize, "{text}");
        assert!(text.starts_with("bubbler-net-proxy: line 0\n"), "{text}");
        assert!(
            text.ends_with(&format!("bubbler-net-proxy: line {}\n", LOG_BUDGET - 1)),
            "{text}"
        );

        log.at(start + LOG_WINDOW, "after");
        let text = buf.text();
        assert!(
            text.contains("bubbler-net-proxy: suppressed 5 lines\n"),
            "{text}"
        );
        assert!(text.ends_with("bubbler-net-proxy: after\n"), "{text}");

        // The count starts again with the window it was written in.
        log.at(start + LOG_WINDOW * 2, "later");
        let text = buf.text();
        assert_eq!(text.matches("suppressed").count(), 1, "{text}");
        assert!(text.ends_with("bubbler-net-proxy: later\n"), "{text}");
    }

    /// What the proxy carried is written only when the launcher asked
    /// for it; what it refused is written either way. The lines share a
    /// terminal with whatever the sandbox runs, and one line a tunnel is
    /// a full-screen application redrawn over — a refusal is the thing a
    /// user has to see.
    #[test]
    fn the_traffic_lines_wait_for_the_word_and_the_refusals_do_not() {
        let Some(address) = routable_address() else {
            println!("skipping: this host has no address but the loopback");
            return;
        };
        let upstream = echo_server(address);
        let dns = stub_resolver(address);
        let allowed = format!("api.example:{upstream}");
        for verbose in [false, true] {
            let buf = Buf::default();
            let proxy = started_with(
                &[&allowed],
                &[dns],
                Log::new(Box::new(buf.clone()), verbose),
            );

            let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
                .expect("the proxy answers");
            sock.write_all(
                format!("CONNECT {allowed} HTTP/1.1\r\nHost: api.example\r\n\r\nping").as_bytes(),
            )
            .expect("the request goes out");
            // The echo comes back through the relay, which the tunnel
            // thread enters after it has written its line: reading it is
            // what makes the log complete rather than merely likely.
            let mut reader = io::BufReader::new(sock.try_clone().expect("a second handle"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("the status line");
            assert_eq!(line, "HTTP/1.1 200 Connection established\r\n");
            line.clear();
            reader.read_line(&mut line).expect("the blank line");
            let mut echoed = [0u8; 4];
            reader.read_exact(&mut echoed).expect("the echo");
            assert_eq!(&echoed, b"ping");
            drop(reader);
            drop(sock);

            let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
                .expect("the proxy answers");
            sock.write_all(b"CONNECT other.example:443 HTTP/1.1\r\nHost: other.example\r\n\r\n")
                .expect("the request goes out");
            let mut answer = String::new();
            sock.read_to_string(&mut answer).expect("the refusal");

            let text = buf.text();
            assert!(
                text.contains("denied other.example:443: no allow-host covers it"),
                "{verbose}: {text}"
            );
            assert_eq!(
                text.contains("tunnel to api.example:"),
                verbose,
                "{verbose}: {text}"
            );
            assert_eq!(text.contains("listening on"), verbose, "{verbose}: {text}");
        }
    }

    /// A client that never gets as far as naming a target still leaves
    /// a line. With the traffic log off these are the only lines such a
    /// run has, and a proxy answering `405` in silence would look like
    /// one nothing had reached at all.
    #[test]
    fn a_request_refused_before_it_named_a_target_is_logged_by_default() {
        let dns = stub_resolver(Ipv4Addr::LOCALHOST);
        let buf = Buf::default();
        let proxy = started_with(
            &["api.example:443"],
            &[dns],
            Log::new(Box::new(buf.clone()), false),
        );
        let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
            .expect("the proxy answers");
        sock.write_all(b"GET http://api.example/ HTTP/1.1\r\nHost: api.example\r\n\r\n")
            .expect("the request goes out");
        let mut answer = String::new();
        sock.read_to_string(&mut answer).expect("the refusal");
        assert!(
            answer.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{answer}"
        );
        let text = buf.text();
        assert!(
            text.contains("bubbler-net-proxy: refused 405 not CONNECT\n"),
            "{text}"
        );
        // The one line and nothing about the listener it came in on.
        assert!(!text.contains("listening on"), "{text}");
    }

    #[test]
    fn a_log_clock_that_goes_backwards_does_not_panic() {
        let buf = Buf::default();
        let log = Log::new(Box::new(buf.clone()), false);
        let start = Instant::now() + LOG_WINDOW * 10;
        log.at(start, "one");
        log.at(start - LOG_WINDOW * 5, "two");
        assert_eq!(
            buf.text(),
            "bubbler-net-proxy: one\nbubbler-net-proxy: two\n"
        );
    }
}
