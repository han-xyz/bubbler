//! The egress proxy bubbler puts in the sandbox's network namespace.
//!
//! bubbler joins this process to the sandbox's user, network and mount
//! namespaces with no capability of its own and writes it into a cgroup
//! the nftables ruleset accepts. That is the whole of its privilege: it
//! is on the inside, in the one cgroup the filter lets out, and the
//! application beside it is not.
//!
//! So it binds `127.0.0.1:0` itself — after the namespaces are joined,
//! or the socket would be the host's loopback — reports the port it got
//! on `--ready-fd` as two bytes, and from then on answers `CONNECT` and
//! nothing else. Names come from argv; the sandbox never gets to add
//! one.

// The library — the parser, the allowlist and the relay — forbids
// `unsafe`. The binary cannot: taking over a descriptor the launcher
// passed by number is the one thing safe Rust has no wrapper for, and
// it happens once, here, before anything else runs.
#![deny(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

use bubbler_net_proxy::allow::Allowlist;
use bubbler_net_proxy::connect::{self, Status};
use bubbler_net_proxy::relay;

/// The one usage line, so a grammar error always names the whole
/// grammar.
const USAGE: &str = "bubbler-net-proxy: usage: --allow NAME:PORT [--allow NAME:PORT ...] \
--ready-fd N [--log-fd N]";

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

/// What the launcher asked for.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    /// The `name:port` targets a tunnel may be opened to, as written.
    allow: Vec<String>,
    /// Written the bound port as two bytes, big-endian, once the
    /// listener is up, and closed. The launcher waits on it before it
    /// starts the application, so the proxy variables it sets name a
    /// port that already answers.
    ready_fd: i32,
    /// Where the log goes; stderr when the launcher named nothing.
    log_fd: Option<i32>,
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
        Ok(Some(fd)) => Arc::new(Log::to_fd(fd)),
        Ok(None) => Arc::new(Log::to_stderr()),
        Err(err) => {
            eprintln!("bubbler-net-proxy: {err}");
            return ExitCode::from(1);
        }
    };
    match serve(list, args.ready_fd, &log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log.line(&format!("stopped: {err}"));
            ExitCode::from(1)
        }
    }
}

/// Parse the grammar over any argv but this process's own.
///
/// `--allow` repeats and must appear at least once — a proxy with an
/// empty allowlist would answer `403` to everything, which is a
/// launcher bug worth failing on. The other options appear once, and no
/// two may name the same descriptor: a number adopted twice would be
/// closed twice.
fn parse_from(mut it: impl Iterator<Item = OsString>) -> Option<Args> {
    let mut allow: Vec<String> = Vec::new();
    let mut ready_fd = None;
    let mut log_fd = None;
    while let Some(word) = it.next() {
        match word.to_str() {
            Some("--allow") => allow.push(it.next()?.to_str()?.to_owned()),
            Some("--ready-fd") if ready_fd.is_none() => ready_fd = Some(number(it.next()?)?),
            Some("--log-fd") if log_fd.is_none() => log_fd = Some(number(it.next()?)?),
            _ => return None,
        }
    }
    if allow.is_empty() {
        return None;
    }
    let args = Args {
        allow,
        ready_fd: ready_fd?,
        log_fd,
    };
    if Some(args.ready_fd) == args.log_fd {
        return None;
    }
    Some(args)
}

/// One non-negative descriptor number.
fn number(word: OsString) -> Option<i32> {
    match word.to_str()?.parse::<i32>() {
        Ok(fd) if fd >= 0 => Some(fd),
        _ => None,
    }
}

/// Bind the loopback listener, tell the launcher which port it got, and
/// serve until the process is stopped.
///
/// The port is reported only once the listener is up, so the launcher
/// never hands the application a proxy address that answers nothing.
fn serve(list: Allowlist, ready_fd: i32, log: &Arc<Log>) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let port = listener.local_addr()?.port();
    let ready = adopt(ready_fd)?;
    File::from(ready).write_all(&port.to_be_bytes())?;
    log.line(&format!(
        "listening on 127.0.0.1:{port} for {} allowed targets",
        list.len()
    ));

    let list = Arc::new(list);
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
            refuse(client, Status::SERVICE_UNAVAILABLE, log);
            continue;
        }
        let held = Live::take(&live);
        let list = Arc::clone(&list);
        let thread_log = Arc::clone(log);
        let spawned = std::thread::Builder::new().spawn(move || {
            tunnel(client, &list, &thread_log);
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
fn tunnel(mut client: TcpStream, list: &Allowlist, log: &Log) {
    // One deadline for the whole header phase. A request arriving in
    // pieces is ordinary and must still be served; a request that never
    // ends must not be able to keep a slot by writing a byte now and
    // then.
    let deadline = Instant::now() + HEADER_TIMEOUT;
    let (request, buffered) = match read_request(&mut client, deadline) {
        Ok(pair) => pair,
        Err(Some(status)) => return refuse(client, status, log),
        Err(None) => return,
    };
    if !list.matches(&request.host, request.port) {
        log.line(&format!(
            "denied {}:{}: no allow-host covers it",
            request.host, request.port
        ));
        return refuse(client, Status::FORBIDDEN, log);
    }
    let upstream = match dial(&request.host, request.port, resolve) {
        Ok(upstream) => upstream,
        Err(status) => {
            log.line(&format!(
                "{}:{} not reached: {status}",
                request.host, request.port
            ));
            return refuse(client, status, log);
        }
    };
    if let Err(err) = open(&client, &upstream, &buffered) {
        log.line(&format!(
            "{}:{} tunnel not opened: {err}",
            request.host, request.port
        ));
        return;
    }
    log.line(&format!("tunnel to {}:{}", request.host, request.port));
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

/// What a name resolves to: `getaddrinfo`, which inside the sandbox's
/// mount namespace reads the sandbox's own `/etc/resolv.conf`. The
/// ruleset lets this process to that resolver and lets nothing else
/// there.
fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(Iterator::collect)
}

/// Open the upstream connection, or say why there is none.
///
/// Addresses are tried in the order the resolver gave them, and the
/// whole dial shares one [`CONNECT_TIMEOUT`]: a name answering with
/// thirty blackholed records must not hold a tunnel slot thirty times
/// as long as one that answers with one.
///
/// A link-local answer is skipped rather than dialled. Nothing else
/// about the address is judged — what the sandbox may reach is decided
/// by name, and the namespace routes nowhere the sandbox could not be
/// granted with an `allow-out` — but `169.254.0.0/16` is where pasta's
/// DNS forwarder sits, and an `allow-host` on port 53 whose name
/// resolved there would hand the application back the resolver the
/// ruleset took away from it.
fn dial(
    host: &str,
    port: u16,
    resolve: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
) -> Result<TcpStream, Status> {
    let addrs = resolve(host, port).map_err(|_| Status::BAD_GATEWAY)?;
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut late = false;
    for addr in addrs {
        if is_link_local(&addr.ip()) {
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

/// Whether `ip` is link-local: `169.254.0.0/16` or `fe80::/10`.
///
/// The IPv6 half is written out rather than taken from
/// `Ipv6Addr::is_unicast_link_local`, which the workspace's declared
/// minimum toolchain need not have.
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Answer a request that will not be served and close the connection.
fn refuse(mut client: TcpStream, status: Status, log: &Log) {
    // One short line, but to a client that never reads it: the write
    // must not be able to hold the thread it is on, which for a `503`
    // is the accept loop itself.
    let written = client
        .set_write_timeout(Some(WRITE_TIMEOUT))
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
    /// Write to `out`.
    fn new(out: Box<dyn Write + Send>) -> Self {
        Self {
            sink: Mutex::new(Sink {
                out,
                window: Instant::now(),
                written: 0,
                suppressed: 0,
            }),
        }
    }

    /// Write to a descriptor the launcher passed.
    fn to_fd(fd: OwnedFd) -> Self {
        Self::new(Box::new(File::from(fd)))
    }

    /// Write to stderr, which is where the lines go when the launcher
    /// named no descriptor.
    fn to_stderr() -> Self {
        Self::new(Box::new(io::stderr()))
    }

    /// One line, prefixed with the program name, unless this window's
    /// budget is spent.
    fn line(&self, msg: &str) {
        self.at(Instant::now(), msg);
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

    const MINIMAL: &[&str] = &["--allow", "api.example:443", "--ready-fd", "3"];

    #[test]
    fn the_shortest_grammar_names_one_target_and_the_ready_pipe() {
        assert_eq!(
            args(MINIMAL),
            Some(Args {
                allow: vec!["api.example:443".to_owned()],
                ready_fd: 3,
                log_fd: None,
            })
        );
    }

    #[test]
    fn every_option_is_accepted_together_and_allow_repeats() {
        assert_eq!(
            args(&[
                "--allow",
                "api.example:443",
                "--allow",
                "*.cdn.example:8443",
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
                ready_fd: 4,
                log_fd: Some(2),
            })
        );
    }

    #[test]
    fn a_proxy_with_nothing_to_allow_is_a_usage_error() {
        assert_eq!(args(&["--ready-fd", "3"]), None);
        assert_eq!(args(&["--allow", "api.example:443"]), None);
    }

    #[test]
    fn a_repeated_option_is_a_usage_error() {
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.extend(["--ready-fd", "4"]);
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
                args(&["--allow", "a.example:443", "--ready-fd", fd]),
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

    /// A whole run of the proxy over loopback: the port arrives on the
    /// ready pipe, an allowed target is tunnelled with the bytes that
    /// came behind the blank line, and a target no `--allow` covers is
    /// refused without the upstream being touched.
    fn started(allow: &[&str]) -> u16 {
        let list = Allowlist::parse(allow).expect("an allowlist");
        let (read, write) = rustix::pipe::pipe().expect("a pipe");
        let log = Arc::new(Log::to_stderr());
        let ready = write.into_raw_fd();
        // The proxy serves until the process ends; a test outlives no
        // thread of its own here.
        std::thread::spawn(move || {
            let _ = serve(list, ready, &log);
        });
        let mut port = [0u8; 2];
        File::from(read)
            .read_exact(&mut port)
            .expect("the bound port");
        u16::from_be_bytes(port)
    }

    fn echo_server() -> u16 {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("an upstream listener");
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

    #[test]
    fn an_allowed_target_is_tunnelled_and_anything_else_is_refused() {
        let upstream = echo_server();
        let proxy = started(&[&format!("localhost:{upstream}")]);

        let mut sock = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy)))
            .expect("the proxy answers");
        sock.write_all(
            format!("CONNECT localhost:{upstream} HTTP/1.1\r\nHost: localhost\r\n\r\nping")
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
    fn a_link_local_answer_is_never_dialled() {
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
    }

    #[test]
    fn a_link_local_answer_is_skipped_for_the_one_behind_it() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("an upstream listener");
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
        let log = Log::new(Box::new(buf.clone()));
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

    #[test]
    fn a_log_clock_that_goes_backwards_does_not_panic() {
        let buf = Buf::default();
        let log = Log::new(Box::new(buf.clone()));
        let start = Instant::now() + LOG_WINDOW * 10;
        log.at(start, "one");
        log.at(start - LOG_WINDOW * 5, "two");
        assert_eq!(
            buf.text(),
            "bubbler-net-proxy: one\nbubbler-net-proxy: two\n"
        );
    }
}
