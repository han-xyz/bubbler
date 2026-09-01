//! The proxy against a real compositor: the binary is started on a listening
//! socket of its own, and a client speaks the wire protocol through it.
//!
//! Every test here needs a Wayland session, so each one skips with a printed
//! reason when there is none — a machine without a compositor must still pass
//! the suite rather than carry an `#[ignore]` forever.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::fs::{FlockOperation, flock};

use bubbler_wl_proxy::policy::PRIVILEGED;
use bubbler_wl_proxy::tables::{self, Interface};
use bubbler_wl_proxy::wire::{self, Arg, Header};

/// Every wait in this file is bounded by this, so a compositor that never
/// answers fails the test instead of hanging the suite.
const PATIENCE: Duration = Duration::from_secs(5);

/// The value the clipboard test copies and tries to read back.
const SECRET: &str = "bubbler-clipboard-probe";

/// The clipboard tool that owns the selection while the gate is tested.
const WL_COPY: &str = "wl-copy";

/// Its other half: how the test learns what it is about to take away, so it
/// can put it back.
const WL_PASTE: &str = "wl-paste";

/// The types a selection is read and put back through, best first. Not simply
/// the first one listed: rich text advertises `text/html` ahead of its plain
/// fallback, and a selection copied out of a browser would come back as markup
/// pasted into a plain-text field.
const RESTORE_TYPES: &[&str] = &[
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "STRING",
    "TEXT",
];

/// X11 selection bookkeeping, which Xwayland advertises beside the content and
/// lists first. Never what to read, whatever order it comes in.
const NOT_CONTENT: &[&str] = &["TARGETS", "TIMESTAMP", "MULTIPLE", "SAVE_TARGETS"];

/// How long the selection is given to become what it was just set to.
/// `wl-copy` forks to the background to serve what it copied, so the process a
/// caller waited for is gone before the compositor has necessarily handed the
/// selection over.
const SELECTION_SETTLE: Duration = Duration::from_secs(5);

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
        .stdin(Stdio::null())
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
    // Without `--fallback-deny`: the denylist no longer depends on it.
    let proxy = Proxy::start(&host, "paste", false);
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

/// One clipboard tool on the session's own display, with none of the
/// harness's descriptors on it.
///
/// `wl-copy` goes to the background to serve what it copied, as every
/// clipboard owner must, and a daemon holding the pipe `cargo test` is writing
/// its output down is a `cargo test | cat` that never reaches end of file.
/// A caller that needs one of the three back asks for it.
fn clipboard_tool(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// What the selection is holding, as far as this test can tell.
enum Held {
    /// Nothing on it.
    Empty,
    /// This type, and the bytes under it.
    Bytes(String, Vec<u8>),
    /// Something is on it that could not be read back. A test must not take a
    /// selection it has no way of giving back.
    Unreadable(String),
}

/// The type to read a selection through, out of everything `wl-paste` listed.
fn restore_type(types: &[&str]) -> Option<String> {
    let best = RESTORE_TYPES
        .iter()
        .find(|want| types.contains(*want))
        .or_else(|| types.iter().find(|kind| !NOT_CONTENT.contains(*kind)))?;
    Some((*best).to_owned())
}

/// What is on the selection right now.
///
/// `--list-types` first because a plain `wl-paste` fails on a selection that is
/// not text, and a test must not conclude the user's clipboard was empty
/// because it could not read an image.
fn selection_now() -> Held {
    let Ok(listed) = clipboard_tool(WL_PASTE)
        .arg("--list-types")
        .stdout(Stdio::piped())
        .output()
    else {
        return Held::Unreadable("wl-paste did not run".to_owned());
    };
    // A selection with nothing on it is what `wl-paste` exits non-zero for.
    if !listed.status.success() {
        return Held::Empty;
    }
    let text = String::from_utf8_lossy(&listed.stdout);
    let types: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .collect();
    if types.is_empty() {
        return Held::Empty;
    }
    let Some(mime) = restore_type(&types) else {
        return Held::Unreadable(format!("only bookkeeping types on it: {types:?}"));
    };
    match clipboard_tool(WL_PASTE)
        .args(["--no-newline", "--type", &mime])
        .stdout(Stdio::piped())
        .output()
    {
        Ok(out) if out.status.success() => Held::Bytes(mime, out.stdout),
        _ => Held::Unreadable(format!("wl-paste read nothing as {mime}")),
    }
}

/// Wait until the selection reads back as `want`, or until the deadline.
/// `None` is a selection with nothing on it.
fn selection_settles(want: Option<&[u8]>) -> bool {
    let deadline = Instant::now() + SELECTION_SETTLE;
    loop {
        let settled = match (selection_now(), want) {
            (Held::Bytes(_, back), Some(want)) => back == want,
            (Held::Empty, None) => true,
            _ => false,
        };
        if settled {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The session's selection, owned by one test at a time and given back the way
/// it was found.
///
/// There is one of it, and a `wl-copy` from one test is the offer another is
/// halfway through reading. A file lock and not a `Mutex` because two
/// `cargo test` processes on one login share the selection exactly as two
/// threads of one do — this crate's suite and the CLI crate's take the same
/// lock — and the kernel drops a `flock` when its holder exits, so a suite
/// that crashed leaves nothing stale behind. The same reasoning, and the same
/// lock file, as `hold_the_session` in `crates/bubbler/tests/cli.rs`, which
/// also guards the keyboard focus that decides who is offered the selection;
/// a test crate cannot share code with another without a dependency between
/// them, so the path is spelled out in both.
struct Selection {
    /// The lock file, whose open description is the lock.
    _lock: File,
    /// What was on the selection before this test took it, in the one flavour
    /// [`restore_type`] picked. `None` only where it was empty.
    previous: Option<(String, Vec<u8>)>,
}

impl Drop for Selection {
    /// Give the user their clipboard back. This runs before any field of the
    /// struct is dropped, so it still holds the lock and cannot race the next
    /// test's copy — and it runs on the way out of a failed assertion, which
    /// is exactly when the selection would otherwise be left saying `secret`.
    ///
    /// Where the selection could not be read, the test skipped rather than
    /// take it, so `--clear` here is only ever an empty selection put back the
    /// way it was found.
    fn drop(&mut self) {
        let Some((mime, bytes)) = &self.previous else {
            let _ = clipboard_tool(WL_COPY).arg("--clear").status();
            selection_settles(None);
            return;
        };
        let Ok(mut child) = clipboard_tool(WL_COPY)
            .args(["--type", mime])
            .stdin(Stdio::piped())
            .spawn()
        else {
            return;
        };
        if let Some(mut feed) = child.stdin.take() {
            let _ = feed.write_all(bytes);
        }
        let _ = child.wait();
        // Still under the lock, which is what the lock is for: the next test
        // must not look at the selection while this is on its way.
        selection_settles(Some(bytes));
    }
}

/// Take the selection: the lock first, then a look at what was on it.
///
/// `None` (after printing why) when something is on it that cannot be read
/// back. Taking a selection with no way of returning it would cost the user
/// their clipboard, which no assertion is worth.
fn hold_the_selection() -> Option<Selection> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")?;
    let path = Path::new(&dir).join("bubbler-test-session.lock");
    let lock = File::create(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    flock(&lock, FlockOperation::LockExclusive)
        .expect("an exclusive lock on a file this process has just created");
    // Under the lock: whatever is on it now is the user's, and no other test
    // may replace it between this look and the copy that follows.
    let previous = match selection_now() {
        Held::Empty => None,
        Held::Bytes(mime, bytes) => Some((mime, bytes)),
        Held::Unreadable(why) => {
            println!("skipped: this session's selection cannot be put back ({why})");
            return None;
        }
    };
    Some(Selection {
        _lock: lock,
        previous,
    })
}

#[test]
fn the_gate_decides_whether_a_paste_reads_anything() {
    let Some(host) = host_socket() else { return };
    if !have(WL_COPY) || !have(WL_PASTE) {
        println!("skipped: wl-clipboard is not installed");
        return;
    }
    // Held for the whole test, and given back when it drops — including on
    // the way out of a failed assertion below.
    let Some(_selection) = hold_the_selection() else {
        return;
    };
    // `wl-copy` forks to serve what it copied, so the selection is not the
    // test's until it reads back as such.
    let copied = clipboard_tool(WL_COPY)
        .arg("--")
        .arg(SECRET)
        .status()
        .is_ok_and(|status| status.success());
    if !copied || !selection_settles(Some(SECRET.as_bytes())) {
        println!("skipped: wl-copy put nothing on the selection");
        return;
    }

    let open = Proxy::start(&host, "open", false);
    let read = bounded(
        Command::new(WL_PASTE)
            .arg("--no-newline")
            .env("XDG_RUNTIME_DIR", open.dir.path())
            .env("WAYLAND_DISPLAY", "wayland"),
        PATIENCE,
    );
    let read = read.expect("wl-paste finished through the open gate");
    assert_eq!(String::from_utf8_lossy(&read), SECRET);

    let mut paste = Proxy::start(&host, "paste", false);
    let denied = bounded(
        Command::new(WL_PASTE)
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
}
