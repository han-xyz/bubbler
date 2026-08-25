//! Wayland wire proxy: sits between a sandboxed client and the socket bubbler
//! gives it, so a clipboard read can be tied to recent user input and an
//! interface the tables do not describe can be kept out of the registry.
//!
//! The launcher hands this process a listening socket and the socket to
//! forward to; it creates nothing itself, and the sandbox it protects never
//! sees the upstream path.

// The library — every byte of parsing and all of the policy — forbids
// `unsafe`. The binary cannot: taking over a descriptor the launcher passed by
// number is the one thing safe Rust has no wrapper for, and it happens once,
// here, before anything else runs.
#![deny(unsafe_code)]

use std::ffi::OsString;
use std::io;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd, retry_on_intr};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use bubbler_wl_proxy::audit::Audit;
use bubbler_wl_proxy::policy::{Gate, Policy};
use bubbler_wl_proxy::relay;

/// The one usage line, so a grammar error always names the whole grammar.
const USAGE: &str = "bubbler-wl-proxy: usage: --listen-fd N --upstream PATH \
--gate paste|open [--fallback-deny] [--log-fd N] [--ready-fd N]";

/// What the launcher asked for.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    /// The listening socket the sandbox connects to.
    listen_fd: i32,
    /// The socket every connection is forwarded to.
    upstream: PathBuf,
    /// Whether a clipboard read has to follow user input.
    gate: Gate,
    /// Hide the privileged interfaces, for a compositor with no security
    /// context of its own to hide them.
    fallback_deny: bool,
    /// Where the audit log goes; stderr when the launcher named nothing.
    log_fd: Option<i32>,
    /// Written one byte and closed once the proxy is serving, so the launcher
    /// can start the sandbox knowing the socket will answer.
    ready_fd: Option<i32>,
}

fn main() -> ExitCode {
    let Some(args) = parse_from(std::env::args_os().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match serve(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("bubbler-wl-proxy: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Parse the grammar over any argv but this process's own.
///
/// Every option may appear once, and no two may name the same descriptor: a
/// number adopted twice would be closed twice.
fn parse_from(mut it: impl Iterator<Item = OsString>) -> Option<Args> {
    let mut listen_fd = None;
    let mut upstream = None;
    let mut gate = None;
    let mut fallback_deny = false;
    let mut log_fd = None;
    let mut ready_fd = None;
    while let Some(word) = it.next() {
        match word.to_str() {
            Some("--listen-fd") if listen_fd.is_none() => listen_fd = Some(number(it.next()?)?),
            Some("--upstream") if upstream.is_none() => upstream = Some(PathBuf::from(it.next()?)),
            Some("--gate") if gate.is_none() => {
                gate = match it.next()?.to_str()? {
                    "paste" => Some(Gate::Paste),
                    "open" => Some(Gate::Open),
                    _ => return None,
                };
            }
            Some("--fallback-deny") if !fallback_deny => fallback_deny = true,
            Some("--log-fd") if log_fd.is_none() => log_fd = Some(number(it.next()?)?),
            Some("--ready-fd") if ready_fd.is_none() => ready_fd = Some(number(it.next()?)?),
            _ => return None,
        }
    }
    let args = Args {
        listen_fd: listen_fd?,
        upstream: upstream?,
        gate: gate?,
        fallback_deny,
        log_fd,
        ready_fd,
    };
    let named: Vec<i32> = [Some(args.listen_fd), args.log_fd, args.ready_fd]
        .into_iter()
        .flatten()
        .collect();
    for (at, fd) in named.iter().enumerate() {
        if named[at + 1..].contains(fd) {
            return None;
        }
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

/// Adopt the listener, open the log, say the proxy is up, and relay until the
/// launcher stops the run.
fn serve(args: Args) -> io::Result<()> {
    let listener = adopt(args.listen_fd)?;
    if !rustix::net::sockopt::socket_acceptconn(&listener)? {
        return Err(io::Error::other(format!(
            "descriptor {} is not a listening socket",
            args.listen_fd
        )));
    }
    // Non-blocking: `poll` saying a listener is readable is not a promise that
    // `accept` will have something, and a blocking accept would stop every
    // other connection this process is serving.
    let flags = fcntl_getfl(&listener)?;
    fcntl_setfl(&listener, flags | OFlags::NONBLOCK)?;

    let audit = match args.log_fd {
        Some(fd) => Audit::to_fd(adopt(fd)?),
        None => Audit::to_stderr(),
    };
    // Reached once before the launcher is told anything: a proxy that cannot
    // talk to the compositor should fail the launch, not accept every
    // connection and close it again.
    if let Err(err) = probe(&args.upstream) {
        return Err(io::Error::other(format!(
            "cannot reach the upstream socket {}: {err}",
            args.upstream.display()
        )));
    }
    if let Some(fd) = args.ready_fd {
        let ready = adopt(fd)?;
        retry_on_intr(|| rustix::io::write(&ready, &[0]))?;
    }
    let policy = Policy::new(args.gate, args.fallback_deny);
    relay::run(listener, args.upstream, policy, audit)
}

/// Open and drop one connection to `upstream`, to prove it answers.
fn probe(upstream: &Path) -> Result<(), rustix::io::Errno> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let address = SocketAddrUnix::new(upstream)?;
    retry_on_intr(|| connect(&socket, &address))
}

/// Take ownership of a descriptor the launcher passed by number, and keep it
/// out of anything this process might ever exec.
#[allow(unsafe_code)]
fn adopt(fd: i32) -> io::Result<OwnedFd> {
    // SAFETY: the precondition is that `fd` names a descriptor this process
    // owns and that nothing else will close. `fcntl_getfd` is the probe that
    // rules out a number that is not open at all (EBADF) before any owning
    // handle exists, so no closed number is ever adopted or closed twice. The
    // grammar refuses an argv that names one number twice, and the launcher
    // passes each of these descriptors to this process alone.
    let owned = unsafe {
        fcntl_getfd(BorrowedFd::borrow_raw(fd))?;
        OwnedFd::from_raw_fd(fd)
    };
    fcntl_setfd(&owned, FdFlags::CLOEXEC)?;
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixListener;

    use super::*;

    fn args(words: &[&str]) -> Option<Args> {
        parse_from(words.iter().map(OsString::from))
    }

    const MINIMAL: &[&str] = &[
        "--listen-fd",
        "3",
        "--upstream",
        "/run/user/1000/wayland-1",
        "--gate",
        "paste",
    ];

    #[test]
    fn the_shortest_grammar_names_a_socket_a_target_and_a_gate() {
        assert_eq!(
            args(MINIMAL),
            Some(Args {
                listen_fd: 3,
                upstream: PathBuf::from("/run/user/1000/wayland-1"),
                gate: Gate::Paste,
                fallback_deny: false,
                log_fd: None,
                ready_fd: None,
            })
        );
    }

    #[test]
    fn every_option_is_accepted_together() {
        let parsed = args(&[
            "--listen-fd",
            "3",
            "--upstream",
            "/run/wl",
            "--gate",
            "open",
            "--fallback-deny",
            "--log-fd",
            "2",
            "--ready-fd",
            "4",
        ]);
        assert_eq!(
            parsed,
            Some(Args {
                listen_fd: 3,
                upstream: PathBuf::from("/run/wl"),
                gate: Gate::Open,
                fallback_deny: true,
                log_fd: Some(2),
                ready_fd: Some(4),
            })
        );
    }

    #[test]
    fn each_required_option_is_required() {
        for drop_at in [0, 2, 4] {
            let mut words: Vec<&str> = MINIMAL.to_vec();
            words.drain(drop_at..drop_at + 2);
            assert_eq!(args(&words), None, "{words:?}");
        }
    }

    #[test]
    fn a_gate_the_proxy_does_not_have_is_a_usage_error() {
        assert_eq!(
            args(&[
                "--listen-fd",
                "3",
                "--upstream",
                "/run/wl",
                "--gate",
                "sometimes"
            ]),
            None
        );
    }

    #[test]
    fn a_repeated_option_is_a_usage_error() {
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.extend(["--listen-fd", "4"]);
        assert_eq!(args(&words), None);
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.extend(["--fallback-deny", "--fallback-deny"]);
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
                    "--listen-fd",
                    fd,
                    "--upstream",
                    "/run/wl",
                    "--gate",
                    "paste"
                ]),
                None,
                "{fd}"
            );
        }
    }

    #[test]
    fn a_word_the_grammar_does_not_have_is_a_usage_error() {
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.push("--trace");
        assert_eq!(args(&words), None);
        let mut words: Vec<&str> = MINIMAL.to_vec();
        words.push("wayland-1");
        assert_eq!(args(&words), None);
    }

    #[test]
    fn an_inherited_descriptor_is_adopted_and_kept_out_of_any_exec() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let listener = UnixListener::bind(dir.path().join("wayland")).expect("a listener");
        let raw = listener.into_raw_fd();
        let owned = adopt(raw).expect("the listener is adopted");
        assert!(
            fcntl_getfd(&owned)
                .expect("the flags read")
                .contains(FdFlags::CLOEXEC)
        );
        assert!(rustix::net::sockopt::socket_acceptconn(&owned).expect("a socket"));
    }

    #[test]
    fn a_number_that_names_nothing_is_not_adopted() {
        assert!(adopt(9999).is_err());
    }

    #[test]
    fn an_upstream_that_does_not_answer_is_found_before_the_launcher_waits() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("wayland");
        assert!(probe(&path).is_err(), "nothing is listening there yet");
        let listener = UnixListener::bind(&path).expect("a listener");
        probe(&path).expect("a listening socket answers");
        drop(listener);
        assert!(probe(&path).is_err(), "the socket has gone again");
    }
}
