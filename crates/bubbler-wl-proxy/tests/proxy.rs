//! The proxy against a real compositor: the binary is started on a listening
//! socket of its own, and a client speaks the wire protocol through it.
//!
//! Every test here needs a Wayland session, so each one skips with a printed
//! reason when there is none — a machine without a compositor must still pass
//! the suite rather than carry an `#[ignore]` forever.

use std::collections::HashMap;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::{Duration, Instant};

use bubbler_wl_proxy::policy::PRIVILEGED;
use bubbler_wl_proxy::tables::{self, Interface};
use bubbler_wl_proxy::wire::{self, Arg, Header};

/// Every wait in this file is bounded by this, so a compositor that never
/// answers fails the test instead of hanging the suite.
const PATIENCE: Duration = Duration::from_secs(5);

/// The value the clipboard test copies and tries to read back.
const SECRET: &str = "bubbler-clipboard-probe";

/// The compositor's own socket, or `None` with a printed reason.
fn host_socket() -> Option<PathBuf> {
    let Some(display) = std::env::var_os("WAYLAND_DISPLAY") else {
        println!("skipped: WAYLAND_DISPLAY is not set");
        return None;
    };
    let display = PathBuf::from(display);
    let path = match display.is_absolute() {
        true => display,
        false => {
            let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") else {
                println!("skipped: XDG_RUNTIME_DIR is not set");
                return None;
            };
            Path::new(&dir).join(display)
        }
    };
    if !path.exists() {
        println!("skipped: {} is not there", path.display());
        return None;
    }
    Some(path)
}

/// Whether `program` is on `PATH`.
fn have(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

/// Wait for `fd` to have something to read.
fn readable(fd: BorrowedFd<'_>, wait: Duration) -> bool {
    let timeout = rustix::event::Timespec {
        tv_sec: wait.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: wait.subsec_nanos().into(),
    };
    let mut polled = [rustix::event::PollFd::from_borrowed_fd(
        fd,
        rustix::event::PollFlags::IN,
    )];
    matches!(rustix::event::poll(&mut polled, Some(&timeout)), Ok(n) if n > 0)
}

/// A running proxy, its socket, and its log. Dropping it kills the process,
/// so no test can leave one behind.
struct Proxy {
    child: Child,
    socket: PathBuf,
    dir: tempfile::TempDir,
    log: ChildStderr,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proxy {
    /// Start the built binary on a fresh socket in a temporary directory.
    ///
    /// The listener goes in as stdin and the readiness pipe comes back as
    /// stdout, because `Command` inherits descriptors safely only as stdio;
    /// the launcher passes higher numbers, which the grammar also takes.
    fn start(upstream: &Path, gate: &str, fallback_deny: bool) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let socket = dir.path().join("wayland");
        let listener = UnixListener::bind(&socket).expect("a listening socket");
        let mut command = Command::new(env!("CARGO_BIN_EXE_bubbler-wl-proxy"));
        command
            .arg("--listen-fd")
            .arg("0")
            .arg("--upstream")
            .arg(upstream)
            .arg("--gate")
            .arg(gate);
        if fallback_deny {
            command.arg("--fallback-deny");
        }
        command
            .arg("--ready-fd")
            .arg("1")
            .arg("--log-fd")
            .arg("2")
            .stdin(Stdio::from(OwnedFd::from(listener)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("the proxy starts");
        let mut ready = child.stdout.take().expect("a readiness pipe");
        let mut log = child.stderr.take().expect("a log pipe");
        assert!(
            readable(ready.as_fd(), PATIENCE),
            "the proxy never said it was serving"
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            ready.read(&mut byte).expect("the readiness byte"),
            1,
            "the proxy exited instead of serving: {}",
            drain(&mut log)
        );
        Self {
            child,
            socket,
            dir,
            log,
        }
    }

    /// Whatever the proxy has written to its log by now.
    fn log(&mut self) -> String {
        if !readable(self.log.as_fd(), PATIENCE) {
            return String::new();
        }
        drain(&mut self.log)
    }
}

/// Read what is waiting on a pipe without blocking for more.
fn drain(pipe: &mut ChildStderr) -> String {
    let mut buf = [0u8; 4096];
    match pipe.read(&mut buf) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
        Err(_) => String::new(),
    }
}

/// One event the client read.
#[derive(Debug)]
struct Event {
    object: u32,
    interface: &'static str,
    name: &'static str,
    args: Vec<Arg>,
}

/// A Wayland client of exactly the size these tests need: it speaks the wire
/// format straight, so it can also send a request no real client would.
struct Client {
    socket: UnixStream,
    objects: HashMap<u32, &'static Interface>,
    buf: Vec<u8>,
    next: u32,
    registry: u32,
}

impl Client {
    /// Connect and create a registry, as every client does first.
    fn connect(path: &Path) -> Self {
        let socket = UnixStream::connect(path).expect("the socket answers");
        socket
            .set_read_timeout(Some(PATIENCE))
            .expect("a read timeout");
        let display = tables::lookup("wl_display").expect("wl_display");
        let mut client = Self {
            socket,
            objects: HashMap::from([(1, display)]),
            buf: Vec::new(),
            next: 1,
            registry: 0,
        };
        client.registry = client.new_id("wl_registry");
        let registry = client.registry;
        client.send(1, "wl_display", "get_registry", &[Arg::NewId(registry)]);
        client
    }

    /// The next id, recorded as `interface` so its events can be decoded.
    fn new_id(&mut self, interface: &str) -> u32 {
        self.next += 1;
        let known = tables::lookup(interface).unwrap_or_else(|| panic!("{interface}"));
        self.objects.insert(self.next, known);
        self.next
    }

    fn send(&mut self, object: u32, interface: &str, name: &str, args: &[Arg]) {
        let known = tables::lookup(interface).unwrap_or_else(|| panic!("{interface}"));
        let at = known
            .requests
            .iter()
            .position(|message| message.name == name)
            .unwrap_or_else(|| panic!("{interface}.{name}"));
        let opcode = u16::try_from(at).expect("an opcode fits");
        let bytes = wire::encode(object, opcode, args).expect("the request encodes");
        use std::io::Write;
        self.socket.write_all(&bytes).expect("the request goes out");
    }

    /// One event, reading more from the socket when the buffer holds none.
    /// `None` when the connection ended or nothing came within [`PATIENCE`].
    fn event(&mut self) -> Option<Event> {
        loop {
            if let Some(event) = self.parse() {
                return Some(event);
            }
            let mut chunk = [0u8; 4096];
            match self.socket.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn parse(&mut self) -> Option<Event> {
        let header = Header::decode(&self.buf).ok()?;
        if self.buf.len() < usize::from(header.size) {
            return None;
        }
        let interface = *self
            .objects
            .get(&header.object)
            .unwrap_or_else(|| panic!("an event for unmapped object {}", header.object));
        let message = interface
            .event(header.opcode)
            .unwrap_or_else(|| panic!("{} has no event {}", interface.name, header.opcode));
        let (args, consumed) = wire::decode(&self.buf, message.args).expect("the event decodes");
        self.buf.drain(..consumed);
        Some(Event {
            object: header.object,
            interface: interface.name,
            name: message.name,
            args,
        })
    }

    /// Everything the compositor has to say up to the answer to a fresh sync.
    fn roundtrip(&mut self) -> Vec<Event> {
        let callback = self.new_id("wl_callback");
        self.send(1, "wl_display", "sync", &[Arg::NewId(callback)]);
        let mut events = Vec::new();
        while let Some(event) = self.event() {
            let done = event.object == callback && event.name == "done";
            let failed = event.interface == "wl_display" && event.name == "error";
            events.push(event);
            if done || failed {
                break;
            }
        }
        events
    }

    /// The registry as this connection was told it: name, interface, version.
    fn globals(&mut self) -> Vec<(u32, String, u32)> {
        self.roundtrip()
            .iter()
            .filter(|event| event.interface == "wl_registry" && event.name == "global")
            .filter_map(|event| match event.args.as_slice() {
                [
                    Arg::Uint(name),
                    Arg::String(Some(interface)),
                    Arg::Uint(version),
                ] => Some((*name, interface.to_string_lossy().into_owned(), *version)),
                _ => None,
            })
            .collect()
    }
}

/// Run a program, killing it if it outlives `wait`, and answer its stdout.
fn bounded(command: &mut Command, wait: Duration) -> Option<Vec<u8>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the program starts");
    let deadline = Instant::now() + wait;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_end(&mut out)
        .expect("the output reads");
    Some(out)
}

#[test]
fn a_sync_travels_to_the_compositor_and_back() {
    let Some(host) = host_socket() else { return };
    let proxy = Proxy::start(&host, "paste", false);
    let mut client = Client::connect(&proxy.socket);
    let events = client.roundtrip();
    assert!(
        events.iter().any(|event| event.name == "done"),
        "no callback came back: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event.interface == "wl_registry" && event.name == "global"),
        "the registry was empty"
    );
}

#[test]
fn the_registry_holds_no_more_than_the_host_and_nothing_privileged() {
    let Some(host) = host_socket() else { return };
    let direct = Client::connect(&host).globals();
    let proxy = Proxy::start(&host, "paste", true);
    let through = Client::connect(&proxy.socket).globals();
    assert!(!through.is_empty(), "the proxy advertised nothing at all");
    assert!(
        through.len() <= direct.len(),
        "{} through the proxy, {} on the host",
        through.len(),
        direct.len()
    );
    for (name, interface, version) in &through {
        let host_version = direct
            .iter()
            .find(|(host_name, _, _)| host_name == name)
            .map(|(_, host_interface, host_version)| {
                assert_eq!(host_interface, interface, "global {name} changed interface");
                *host_version
            })
            .unwrap_or_else(|| panic!("global {name} ({interface}) is not on the host"));
        assert!(
            *version <= host_version,
            "{interface} was advertised v{version} over the host's v{host_version}"
        );
        let known = tables::lookup(interface).unwrap_or_else(|| panic!("{interface} is unknown"));
        assert!(
            *version <= known.version,
            "{interface} v{version} is above the tables' v{}",
            known.version
        );
        assert!(
            !PRIVILEGED.contains(&interface.as_str()),
            "{interface} is privileged and was advertised anyway"
        );
    }
    println!(
        "{} globals on the host, {} through the proxy",
        direct.len(),
        through.len()
    );
}

#[test]
fn binding_a_global_the_proxy_hid_is_refused_by_name() {
    let Some(host) = host_socket() else { return };
    let direct = Client::connect(&host).globals();
    let proxy = Proxy::start(&host, "paste", true);
    let mut client = Client::connect(&proxy.socket);
    let through = client.globals();
    let hidden = direct
        .iter()
        .find(|(name, _, _)| !through.iter().any(|(seen, _, _)| seen == name));
    let Some((name, interface, version)) = hidden else {
        println!("skipped: this compositor advertises nothing the proxy hides");
        return;
    };
    let object = client.new_id("wl_callback"); // any id; the bind never lands
    let registry = client.registry;
    client.send(
        registry,
        "wl_registry",
        "bind",
        &[
            Arg::Uint(*name),
            Arg::String(Some(CString::new(interface.as_str()).expect("no NUL"))),
            Arg::Uint(*version),
            Arg::NewId(object),
        ],
    );
    let events = client.roundtrip();
    let error = events
        .iter()
        .find(|event| event.interface == "wl_display" && event.name == "error")
        .unwrap_or_else(|| panic!("the bind was not refused: {events:?}"));
    let text = match error.args.as_slice() {
        [Arg::Object(_), Arg::Uint(0), Arg::String(Some(text))] => text.to_string_lossy(),
        other => panic!("not a proxy error: {other:?}"),
    };
    assert_eq!(
        text,
        format!(
            "bind of hidden global {interface} (name {name}, v{version}) \
             refused by the sandbox proxy"
        )
    );
}

#[test]
fn the_gate_decides_whether_a_paste_reads_anything() {
    let Some(host) = host_socket() else { return };
    if !have("wl-copy") || !have("wl-paste") {
        println!("skipped: wl-clipboard is not installed");
        return;
    }
    // wl-copy stays in the background as the owner of the selection until it
    // is replaced, which the end of this test does.
    assert!(
        bounded(Command::new("wl-copy").arg("--").arg(SECRET), PATIENCE).is_some(),
        "wl-copy did not take the selection"
    );

    let open = Proxy::start(&host, "open", false);
    let read = bounded(
        Command::new("wl-paste")
            .arg("--no-newline")
            .env("XDG_RUNTIME_DIR", open.dir.path())
            .env("WAYLAND_DISPLAY", "wayland"),
        PATIENCE,
    );
    let read = read.expect("wl-paste finished through the open gate");
    assert_eq!(String::from_utf8_lossy(&read), SECRET);

    let mut paste = Proxy::start(&host, "paste", false);
    let denied = bounded(
        Command::new("wl-paste")
            .arg("--no-newline")
            .env("XDG_RUNTIME_DIR", paste.dir.path())
            .env("WAYLAND_DISPLAY", "wayland"),
        PATIENCE,
    );
    let denied = denied.expect("wl-paste finished through the closed gate");
    assert!(
        denied.is_empty(),
        "the gate let {} bytes through",
        denied.len()
    );
    let log = paste.log();
    assert!(
        log.contains("clipboard read denied"),
        "no audit line: {log:?}"
    );

    let _ = bounded(Command::new("wl-copy").arg("--clear"), PATIENCE);
}
