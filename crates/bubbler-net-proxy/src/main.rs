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
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

/// How long a client has to finish its request line and headers. A
/// connection that opens and says nothing holds a thread otherwise.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one upstream address has to answer before the next is
/// tried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    // A connection that says nothing must not hold a thread, and a
    // request that arrives in pieces is ordinary; the deadline covers
    // the whole header phase and is lifted before the relay, which does
    // its own waiting.
    if let Err(err) = client.set_read_timeout(Some(HEADER_TIMEOUT)) {
        log.line(&format!("no read deadline on a connection: {err}"));
        return;
    }
    let (request, buffered) = match read_request(&mut client) {
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
    let mut upstream = match dial(&request.host, request.port) {
        Ok(upstream) => upstream,
        Err(status) => {
            log.line(&format!(
                "{}:{} not reached: {status}",
                request.host, request.port
            ));
            return refuse(client, status, log);
        }
    };
    let established = client
        .write_all(connect::ESTABLISHED.as_bytes())
        // Bytes the client pipelined behind the blank line are already
        // tunnel data (RFC 9110 §9.3.6) and go out before anything is
        // read from either side again.
        .and_then(|()| upstream.write_all(&buffered))
        .and_then(|()| client.set_read_timeout(None));
    if let Err(err) = established {
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

/// Read until the request is whole.
///
/// `Err(Some(status))` is a request to answer and close; `Err(None)` is
/// a client that went away or stalled, which is answered with nothing.
/// The success value carries the tunnel bytes that arrived with the
/// request.
fn read_request(client: &mut TcpStream) -> Result<(connect::Request, Vec<u8>), Option<Status>> {
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
        match client.read(&mut chunk) {
            // The client hung up mid-request; there is nobody to answer.
            Ok(0) => return Err(None),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(None),
        }
    }
}

/// Open the upstream connection, or say why there is none.
///
/// The name is resolved by `getaddrinfo`, which inside the sandbox's
/// mount namespace reads the sandbox's own `/etc/resolv.conf`; the
/// ruleset lets this process to the resolver and lets nothing else
/// there. Addresses are tried in the order the resolver gave them.
///
/// Nothing here judges the address: what the sandbox may reach is
/// decided by name, and the netns it shares with the sandbox routes
/// nowhere the sandbox could not reach with an `allow-out` anyway.
fn dial(host: &str, port: u16) -> Result<TcpStream, Status> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|_| Status::BAD_GATEWAY)?;
    let mut timed_out = false;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(upstream) => return Ok(upstream),
            Err(err) if err.kind() == io::ErrorKind::TimedOut => timed_out = true,
            Err(_) => {}
        }
    }
    Err(if timed_out {
        Status::GATEWAY_TIMEOUT
    } else {
        Status::BAD_GATEWAY
    })
}

/// Answer a request that will not be served and close the connection.
fn refuse(mut client: TcpStream, status: Status, log: &Log) {
    if let Err(err) = client.write_all(status.response().as_bytes()) {
        log.line(&format!("{status} not delivered: {err}"));
    }
    // Both halves: nothing more will be read from a connection that has
    // been refused, and the client is told so at once.
    let _ = client.shutdown(std::net::Shutdown::Both);
}

/// Where the proxy's lines go.
enum Log {
    /// The descriptor the launcher named.
    Fd(Mutex<File>),
    /// This process's stderr, which the launcher redirects.
    Stderr,
}

impl Log {
    /// Write to a descriptor the launcher passed.
    fn to_fd(fd: OwnedFd) -> Self {
        Self::Fd(Mutex::new(File::from(fd)))
    }

    /// Write to stderr.
    fn to_stderr() -> Self {
        Self::Stderr
    }

    /// One line, prefixed with the program name.
    ///
    /// A log that cannot be written is not worth failing a tunnel over,
    /// and there is nowhere left to report it to.
    fn line(&self, msg: &str) {
        match self {
            Self::Fd(file) => {
                let mut file = file
                    .lock()
                    .expect("the log mutex is poisoned only if a thread panicked holding it");
                let _ = writeln!(file, "bubbler-net-proxy: {msg}");
            }
            Self::Stderr => eprintln!("bubbler-net-proxy: {msg}"),
        }
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
}
