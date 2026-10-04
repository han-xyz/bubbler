//! The audio policy measured against a real PipeWire.
//!
//! Every test here runs against a private PipeWire and WirePlumber pair
//! started for it and torn down with it. Nothing touches the session's
//! audio: the bed's daemons listen in their own runtime directory, the
//! bed's WirePlumber loads a profile with every hardware monitor
//! disabled, and the bed's PipeWire loads no device factory, so the
//! graph holds one null sink and one null source and nothing else.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::process::Output;

use rustix::process::kill_process_group;

use bubbler_core::host::RealHost;
use bubbler_core::pipewire::{
    PIPEWIRE, PULSE_CONF, PULSE_DROP_IN, PULSE_NATIVE, PULSE_OVERRIDE, PULSE_SOCKET_INSIDE,
    pulse_conf,
};

include!("support/bed.rs");

/// A security context's properties as bubbler will set them for a
/// `pipewire` grant with no `microphone` child.
pub const PLAYBACK: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback" }"#;

/// The same with the `microphone` child.
pub const PLAYBACK_MICROPHONE: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback,microphone" }"#;

/// [`PLAYBACK_MICROPHONE`] for another sandbox: another instance id.
pub const OTHER_SANDBOX: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t2", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback,microphone" }"#;

/// The same with the `devices` child: the context's own devices stand
/// beside the host's.
pub const DEVICES: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback,devices" }"#;

/// Both children.
pub const MICROPHONE_DEVICES: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback,microphone,devices" }"#;

/// The same with the `exclusive` child: a stream may hold a sink for
/// itself.
pub const EXCLUSIVE: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback,exclusive" }"#;

/// A grant string the drop-in does not know, as a future bubbler or a
/// typo could produce.
pub const BOGUS_GRANT: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "bogus" }"#;

/// A bubbler context with the grant key missing altogether.
pub const NO_GRANT: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.access": "restricted" }"#;

/// Markers naming the bed's two nodes in a `pw-cli info all` listing.
const SINK: &str = r#"node.name = "bed-sink""#;
const SOURCE: &str = r#"node.name = "bed-source""#;

/// The same for a playing client's stream node, which is another
/// client's audio as the graph carries it.
const STREAM: &str = r#"media.class = "Stream/Output/Audio""#;

/// Every live process of the bed in `dir`, as `pid comm`: each one the
/// bed starts carries `PIPEWIRE_RUNTIME_DIR` or `PULSE_SERVER` under
/// `dir` in its environment, where its command line may name nothing of
/// the bed at all (`pw-cat -p -a -`, the pulse server's `pipewire -c`).
fn processes_of(dir: &Path) -> Vec<String> {
    let needle = format!("{}/", dir.display());
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            std::fs::read(entry.path().join("environ")).is_ok_and(|environ| {
                environ
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            })
        })
        .map(|entry| {
            let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            format!("{} {}", entry.file_name().to_string_lossy(), comm.trim())
        })
        .collect()
}

impl PipeWireBed {
    /// `pw-link -l` against the bed: every link in the graph, one
    /// endpoint per line.
    pub fn links(&self) -> String {
        self.host_tool("pw-link", &["-l"])
    }

    /// `pw-cli info all` against the bed, which prints each object's
    /// permissions where `pw-dump` spreads them over five lines.
    pub fn info_from_host(&self) -> String {
        self.host_tool("pw-cli", &["info", "all"])
    }

    /// The same from inside a security context carrying `props`, taken
    /// once every one of `markers` has arrived.
    ///
    /// WirePlumber attaches each object's permissions independently, so
    /// a listing taken between two such updates can hold one bed node
    /// but not the other — measured: the null sink present, the null
    /// source not yet. `markers` names what this context is expected to
    /// reach, so the wait covers the whole expected set rather than
    /// just the first node to arrive.
    pub fn info_in_context(&self, props: &str, markers: &[&str]) -> String {
        let mut listing = String::new();
        wait_for("the context's view of the graph", || {
            listing = self.in_context(props, "pw-cli info all");
            markers
                .iter()
                .all(|marker| object(&listing, &[marker]).is_some())
        });
        listing
    }

    /// `program`, run in a PipeWire security context carrying `props`,
    /// with its output captured.
    ///
    /// `pw-container` takes a single program argument and hands it to
    /// `system()`, dropping anything further on its command line, so
    /// `program` must be one shell word — a bare tool name here.
    pub fn in_context(&self, props: &str, program: &str) -> String {
        let out = self.output_in_context(props, program);
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        text
    }

    /// The same with the status the program ended on, for a test whose
    /// subject is a refusal: what the daemon told the client is as much
    /// the measurement as what the graph shows afterwards.
    pub fn output_in_context(&self, props: &str, program: &str) -> Output {
        self.context_command(props, program)
            .output()
            .expect("pw-container did not run")
    }

    /// The same, left running for the caller to watch the graph while it
    /// is up.
    pub fn spawn_in_context(&self, props: &str, program: &str) -> Child {
        self.spawn_in_context_logged(props, program, None)
    }

    /// The same with the program's output kept in `log`, which is what
    /// says why a server that did not come up did not.
    pub fn spawn_in_context_logged(&self, props: &str, program: &str, log: Option<&Path>) -> Child {
        let mut command = self.context_command(props, program);
        match log {
            Some(path) => {
                let out = std::fs::File::create(path).expect("a log for the context's program");
                let err = out.try_clone().expect("a second handle on that log");
                command.stdout(out).stderr(err);
            }
            None => {
                command.stdout(Stdio::null()).stderr(Stdio::null());
            }
        }
        own_process_group(&mut command);
        command.spawn().expect("pw-container did not run")
    }

    /// A private `pipewire-pulse` under a context carrying `props`,
    /// started the way a `pulseaudio` grant starts one: the same binary
    /// and config-file name, the host's effective configuration copied
    /// beside bubbler's own fragment, and one socket of this server's
    /// own.
    fn pulse_server(&self, props: &str) -> PulseServer {
        let config = self.dir.join("pwpulse/cfg");
        let socket = self.dir.join("pwpulse/pulse").join(PULSE_NATIVE);
        std::fs::create_dir_all(
            config
                .join(PULSE_DROP_IN)
                .parent()
                .expect("a drop-in directory"),
        )
        .expect("the server's config directory");
        std::fs::create_dir_all(socket.parent().expect("a socket directory"))
            .expect("the server's socket directory");
        // The system's file, never the developer's: `pulse_conf` reads
        // the user's `pipewire` directory first, and a bed that took
        // what it found there would measure that host's audio and not
        // bubbler's policy.
        let effective = pulse_conf(&RealHost, &self.dir.join("no-config-home"))
            .expect("a pipewire-pulse.conf on this host");
        std::fs::copy(&effective, config.join(PULSE_CONF)).expect("a copy of that config");
        std::fs::write(config.join(PULSE_DROP_IN), pulse_fragment(&socket))
            .expect("bubbler's pulse fragment");

        // `PIPEWIRE_CONFIG_DIR` is set on the server and not on the
        // whole context: it replaces PipeWire's search path outright,
        // and `pw-container` is itself a PipeWire client that would
        // then find no `client.conf` and refuse to start. In a run of
        // bubbler's own there is no such process — the sidecar has the
        // variable and the sidecar is the server.
        let log = self.dir.join("pwpulse.log");
        let running = Streaming(self.spawn_in_context_logged(
            props,
            &format!(
                "PIPEWIRE_CONFIG_DIR={} {PIPEWIRE} -c {PULSE_CONF}",
                config.display()
            ),
            Some(&log),
        ));
        wait_for_logged("the private pulse server's socket", &log, || {
            socket.exists()
        });
        PulseServer {
            _running: running,
            socket,
        }
    }

    /// Armed with the death signal even for a short call: `pw-container`
    /// keeps the context's listening socket open, so a client that
    /// connected after the bed's daemon died waits on it for ever, and
    /// `pw-container` waits on that client.
    fn context_command(&self, props: &str, program: &str) -> Command {
        let mut command = self.command("pw-container");
        command.arg("-P").arg(props).arg("--").arg(program);
        // SAFETY: as in `daemon`: `prctl` alone between fork and exec.
        unsafe {
            command.pre_exec(dies_with_this_thread);
        }
        command
    }
}

/// Start `command`'s child in a process group of its own that dies with
/// this thread.
///
/// A group, because a program started under `pw-container` is a
/// grandchild: `pw-container` sits inside `system()` while it runs and
/// only removes its socket once that returns, so a signal to
/// `pw-container` alone would leave the socket in `/tmp` for ever.
fn own_process_group(command: &mut Command) {
    // SAFETY: the closure runs in the child between fork and exec,
    // where only async-signal-safe work is allowed; `setpgid` and
    // `prctl` are bare syscalls that allocate nothing and take no lock.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setpgid(None, None)?;
            dies_with_this_thread()
        });
    }
}

/// One object as `pw-cli info all` prints it: a block opening with the
/// id and the five-character permission string the asking client holds
/// on it, with the object's properties below.
struct Object {
    id: String,
    permissions: String,
    /// The object's `object.serial`, which is the name a client gives a
    /// target it asks to be linked to (`pw-cat --target`).
    serial: Option<String>,
}

/// The object whose block carries every one of `markers`, or `None` when
/// the client `listing` came from cannot see it.
fn object(listing: &str, markers: &[&str]) -> Option<Object> {
    let block = block(listing, markers)?;
    Some(Object {
        id: block.lines().next()?.to_owned(),
        permissions: property_lines(block)
            .find_map(|line| line.strip_prefix("permissions: "))?
            .to_owned(),
        serial: property_lines(block)
            .find_map(|line| line.strip_prefix("object.serial = \""))
            .map(|serial| serial.trim_end_matches('"').to_owned()),
    })
}

fn blocks(listing: &str) -> impl Iterator<Item = &str> {
    listing.split("\tid: ").skip(1)
}

fn block<'a>(listing: &'a str, markers: &[&str]) -> Option<&'a str> {
    blocks(listing).find(|block| markers.iter().all(|marker| block.contains(marker)))
}

// pw-cli prints a property with a leading `*` when its value changed since
// the last listing.
fn property_lines(block: &str) -> impl Iterator<Item = &str> {
    block
        .lines()
        .map(|line| line.trim().trim_start_matches('*').trim_start())
}

/// The same, with the process's own log in the failure: a server that
/// refuses to start says why there and nowhere else.
fn wait_for_logged(what: &str, log: &Path, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let said = std::fs::read_to_string(log).unwrap_or_default();
    panic!("{what} never came up:\n{said}");
}

#[test]
fn the_bed_holds_one_null_sink_and_one_null_source_and_no_hardware() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let dump = bed.dump_from_host();
    assert_eq!(
        dump.matches("\"media.class\": \"Audio/").count(),
        2,
        "the bed should hold exactly two Audio/* nodes:\n{dump}"
    );
    assert!(dump.contains("\"node.name\": \"bed-sink\""), "{dump}");
    assert!(dump.contains("\"node.name\": \"bed-source\""), "{dump}");
    assert!(!dump.contains("\"device.api\": \"alsa\""), "{dump}");
    assert!(!dump.contains("\"device.api\": \"bluez5\""), "{dump}");
}

#[test]
fn dropping_the_bed_leaves_no_daemon_and_no_directory() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let dir = bed.dir().to_path_buf();
    let pids = bed.daemon_pids();
    drop(bed);
    for pid in pids {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "daemon {pid} outlived the bed"
        );
    }
    assert!(!dir.exists(), "{} outlived the bed", dir.display());
    let left = processes_of(&dir);
    assert!(left.is_empty(), "outlived the bed: {left:?}");
}

/// Set on the copy of this binary the test below kills; the test it
/// names holds a bed until then and does nothing in any other run.
const HELD_BED: &str = "BUBBLER_TEST_HELD_BED";

#[test]
fn a_bed_held_until_its_test_is_killed() {
    if std::env::var_os(HELD_BED).is_none() {
        return;
    }
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let server = bed.pulse_server(PLAYBACK_MICROPHONE);
    let out = bed.dir().join("captured.wav");
    let _recording = server.spawn(
        "parecord",
        &[
            OsStr::new("--device=bed-source"),
            OsStr::new("--file-format=wav"),
            out.as_os_str(),
        ],
    );
    let _tone = streaming(
        &bed,
        PLAYBACK,
        "pw-cat -p -a - < /dev/zero",
        "Stream/Output/Audio",
    );
    wait_for("the recording and the tone", || {
        let links = bed.links();
        links.contains("bed-source:capture_") && links.contains("bed-sink:playback_")
    });
    println!("{HELD_BED}={}", bed.dir().display());
    // A pipe's stdout is not flushed line by line (measured).
    std::io::Write::flush(&mut std::io::stdout()).expect("the line to the killing test");
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
fn nothing_of_a_bed_outlives_a_killed_test_binary() {
    if !session_tests_wanted() {
        say(
            "skipping: set BUBBLER_TEST_SESSION=1 to run tests that reach the session or start audio daemons",
        );
        return;
    }
    let mut command = Command::new(std::env::current_exe().expect("the path of this test binary"));
    command
        .args([
            "--exact",
            "a_bed_held_until_its_test_is_killed",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELD_BED, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: as in `daemon`: `prctl` alone between fork and exec.
    unsafe {
        command.pre_exec(dies_with_this_thread);
    }
    let mut held = command.spawn().expect("a copy of this test binary");
    let prefix = format!("{HELD_BED}=");
    let dir = std::io::BufRead::lines(std::io::BufReader::new(
        held.stdout.take().expect("the copy's stdout"),
    ))
    .map_while(Result::ok)
    .find_map(|line| line.split_once(&prefix).map(|(_, dir)| PathBuf::from(dir)));
    let Some(dir) = dir else {
        let status = held.wait().expect("the copy's status");
        assert!(status.success(), "the held bed did not come up: {status}");
        return;
    };

    let before = processes_of(&dir);
    let pid = Pid::from_raw(held.id() as i32).expect("a live child");
    kill_process(pid, Signal::KILL).expect("SIGKILL to the copy");
    let _ = held.wait();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut left = processes_of(&dir);
    while !left.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        left = processes_of(&dir);
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        left.is_empty(),
        "outlived a SIGKILLed test binary: {left:?} of {before:?}"
    );
    for program in ["parecord", "pw-cat", "pw-container"] {
        assert!(
            before.iter().any(|process| process.ends_with(program)),
            "the held bed ran no {program}: {before:?}"
        );
    }
}

/// Three seconds of silence as a 48 kHz stereo WAV, for `pw-cat` to play
/// long enough that the graph can be read while it does.
fn silence(path: &Path) {
    const FRAMES: u32 = 48_000 * 3;
    let data = FRAMES * 4;
    let mut wav = Vec::with_capacity(44 + data as usize);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&48_000u32.to_le_bytes());
    wav.extend_from_slice(&(48_000u32 * 4).to_le_bytes());
    wav.extend_from_slice(&4u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data.to_le_bytes());
    wav.resize(44 + data as usize, 0);
    std::fs::write(path, wav).expect("a wav for pw-cat to play");
}

/// A `pw-cat` killed with the test rather than left to finish.
struct Streaming(Child);

impl Drop for Streaming {
    fn drop(&mut self) {
        let group = Pid::from_raw(self.0.id() as i32).expect("a live child");
        let _ = kill_process_group(group, Signal::TERM);
        wait_or_kill(&mut self.0);
    }
}

/// bubbler's own pulse fragment with the socket path moved into the
/// bed. Everything else the server's behaviour turns on — no module
/// loading, no session bus — is the shipped text, so a change to it is
/// measured here and not only asserted on in a unit test.
fn pulse_fragment(socket: &Path) -> String {
    let moved = PULSE_OVERRIDE.replace(PULSE_SOCKET_INSIDE, &socket.to_string_lossy());
    assert_ne!(
        moved, PULSE_OVERRIDE,
        "the shipped fragment no longer names {PULSE_SOCKET_INSIDE}"
    );
    moved
}

/// A private `pipewire-pulse` and the socket it serves, killed with the
/// test.
struct PulseServer {
    _running: Streaming,
    socket: PathBuf,
}

impl PulseServer {
    /// `program` run against this server and no other, from outside the
    /// security context: what a `pulseaudio` grant gives the sandboxed
    /// application is this socket, and the PipeWire daemon behind it is
    /// the server's business alone.
    fn run(&self, program: &str, args: &[&OsStr]) -> Output {
        self.command(program, args)
            .output()
            .unwrap_or_else(|e| panic!("{program} did not run: {e}"))
    }

    /// The same, left running and killed with the test: `parecord`
    /// writes until it is stopped.
    fn spawn(&self, program: &str, args: &[&OsStr]) -> Streaming {
        let mut command = self.command(program, args);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        own_process_group(&mut command);
        Streaming(
            command
                .spawn()
                .unwrap_or_else(|e| panic!("{program} did not run: {e}")),
        )
    }

    fn command(&self, program: &str, args: &[&OsStr]) -> Command {
        let mut command = Command::new(program);
        command
            .args(args)
            .env("PULSE_SERVER", format!("unix:{}", self.socket.display()));
        command
    }
}

/// Start `program` in a context carrying `props` and wait until the
/// node it opens is in the graph, so what follows measures a stream that
/// exists rather than one that has not arrived yet.
fn streaming(bed: &PipeWireBed, props: &str, program: &str, class: &str) -> Streaming {
    let child = Streaming(bed.spawn_in_context(props, program));
    wait_for(&format!("a {class} node from {program}"), || {
        bed.dump_from_host()
            .contains(&format!("\"media.class\": \"{class}\""))
    });
    child
}

/// Wait until the session manager has decided the access of a context
/// carrying `grant` — `pipewire.access.effective` is what
/// `apply-access.lua` writes once it has attached the permission
/// manager, so from then on it has everything it needs to link — and
/// then leave it the window in which it would.
///
/// A bound, not a proof: nothing announces "I considered this stream
/// and declined". A host slow enough to rescan later than this would
/// pass a no-link test with a link still coming.
fn window_in_which_it_would_link(bed: &PipeWireBed, grant: &str) {
    let decided = format!("pipewire.sec.bubbler.audio = \"{grant}\"");
    wait_for("the capture client's access decision", || {
        object(
            &bed.info_from_host(),
            &[&decided, "pipewire.access.effective"],
        )
        .is_some()
    });
    std::thread::sleep(Duration::from_secs(2));
}

/// Every node a stream can record from, by the markers that name it in a
/// listing: what a context without the microphone grant may not see.
const CAPTURE_NODES: [&str; 5] = [
    SOURCE,
    r#"node.name = "virtual-source""#,
    r#"node.name = "duplex""#,
    r#"node.name = "odd-source""#,
    r#"node.name = "stream-source""#,
];

/// Classes holding `Audio/Source` past their start, which the drop-in's
/// unanchored match hides, one of them also a stream's.
const ODD_SOURCES: [(&str, &str); 2] = [
    ("odd-source", "Custom/Audio/Source"),
    ("stream-source", "Stream/Input/Audio/Source"),
];

/// The bed's `OTHER_SOURCES` added and a host recorder linked to the null
/// source, so each capture node has ports and one has a link: the
/// recorder, and the ids of every capture node.
fn capture_nodes_with_a_link(bed: &PipeWireBed) -> (Streaming, Vec<String>) {
    add_other_sources(bed);
    for (name, class) in ODD_SOURCES {
        // Ports for a class the adapter does not know need
        // `adapter.auto-port-config` (PipeWire 1.6.9).
        let created = bed
            .command("pw-cli")
            .args([
                "create-node",
                "adapter",
                &format!(
                    "{{ factory.name = support.null-audio-sink, node.name = {name}, \
                     media.class = {class}, audio.position = \"FL,FR\", object.linger = true, \
                     node.autoconnect = false, adapter.auto-port-config = {{ mode = dsp }} }}"
                ),
            ])
            .output()
            .expect("pw-cli did not run");
        assert!(created.status.success(), "{created:?}");
    }
    wait_for("the odd sources' ports", || {
        let ports = bed.host_tool("pw-link", &["-io"]);
        ODD_SOURCES
            .iter()
            .all(|(name, _)| ports.contains(&format!("{name}:")))
    });
    let recorder = host_stream(
        bed,
        &["-r", "-a", "-P", "{ node.name = host-rec }", "/dev/null"],
    );
    wait_for("the host recorder's link from the null source", || {
        bed.links().contains("bed-source:capture_")
    });
    let listing = bed.info_from_host();
    let nodes: Vec<String> = CAPTURE_NODES
        .iter()
        .map(|marker| {
            object(&listing, &[marker, NODE])
                .expect("a capture node in the bed")
                .id
        })
        .collect();
    for node in &nodes {
        assert!(
            !objects_of(&listing, std::slice::from_ref(node)).is_empty(),
            "no port of capture node {node} found in the host's listing:\n{listing}"
        );
    }
    (recorder, nodes)
}

fn objects_of(listing: &str, nodes: &[String]) -> Vec<String> {
    let markers: Vec<String> = nodes
        .iter()
        .flat_map(|node| {
            ["node.id", "link.output.node", "link.input.node"]
                .map(|key| format!("{key} = \"{node}\""))
        })
        .collect();
    let mut ids: Vec<String> = blocks(listing)
        .filter(|block| markers.iter().any(|marker| block.contains(marker.as_str())))
        .filter_map(|block| block.lines().next())
        .map(str::to_owned)
        .collect();
    ids.sort();
    ids
}

/// `pw-mon` in a context for the length of a test: what a client that
/// connected before the objects it is shown sees of them.
struct ContextMonitor {
    _running: Streaming,
    log: PathBuf,
}

impl ContextMonitor {
    /// Started once its client sees the sink, so its access is decided.
    fn start(bed: &PipeWireBed, props: &str) -> ContextMonitor {
        ContextMonitor::running(bed, props, "stdbuf -oL pw-mon -N -a -o")
    }

    /// The same for any `program` that prints the globals it is shown as
    /// `pw-mon` does.
    fn running(bed: &PipeWireBed, props: &str, program: &str) -> ContextMonitor {
        let log = bed.dir().join("context-monitor.log");
        let running = Streaming(bed.spawn_in_context_logged(props, program, Some(&log)));
        let monitor = ContextMonitor {
            _running: running,
            log,
        };
        let sink = object(&bed.info_from_host(), &[SINK]).expect("the sink").id;
        wait_for("the monitor's view of the sink", || {
            monitor.visible().contains(&sink)
        });
        monitor
    }

    fn visible(&self) -> BTreeSet<String> {
        let said = std::fs::read_to_string(&self.log).unwrap_or_default();
        let mut visible = BTreeSet::new();
        let mut lines = said.lines();
        while let Some(line) = lines.next() {
            let id = || {
                lines
                    .clone()
                    .next()
                    .and_then(|next| next.trim().strip_prefix("id: "))
                    .map(str::to_owned)
            };
            match (line, id()) {
                ("added:", Some(id)) => {
                    visible.insert(id);
                }
                ("removed:", Some(id)) => {
                    visible.remove(&id);
                }
                _ => {}
            }
        }
        visible
    }

    fn sees_none_of(&self, ids: &[String]) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let seen: Vec<_> = ids
                .iter()
                .filter(|id| self.visible().contains(*id))
                .collect();
            if seen.is_empty() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "a context still sees {seen:?} of a hidden capture node"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
fn a_playback_context_sees_no_source_no_metadata_and_only_reads_streams() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let (_recorder, capture_nodes) = capture_nodes_with_a_link(&bed);
    let wav = bed.dir().join("tone.wav");
    silence(&wav);
    let _other = streaming(
        &bed,
        PLAYBACK,
        &format!("pw-cat -p {}", wav.display()),
        "Stream/Output/Audio",
    );

    // A dump taken before the session manager has granted this context
    // anything is empty, and would pass every negative assertion below.
    let mut seen = String::new();
    wait_for("the sink in a playback context's dump", || {
        seen = bed.in_context(PLAYBACK, "pw-dump");
        seen.contains("\"node.name\": \"bed-sink\"")
    });
    assert!(!seen.contains("\"node.name\": \"bed-source\""), "{seen}");
    // `metadata.name` is on the metadata objects and on nothing else;
    // the interface name is also the metadata *factory*'s type, which
    // the sandbox may keep seeing.
    assert!(!seen.contains("\"metadata.name\""), "{seen}");

    let listing = bed.info_in_context(PLAYBACK, &[SINK, STREAM]);
    for marker in CAPTURE_NODES {
        assert!(object(&listing, &[marker]).is_none(), "{listing}");
    }
    assert_eq!(
        objects_of(&listing, &capture_nodes),
        Vec::<String>::new(),
        "ports or links of a hidden capture node:\n{listing}"
    );
    let sink = object(&listing, &[SINK]).expect("the sink is visible");
    assert_eq!(sink.permissions, "r-x--", "on the sink:\n{listing}");
    // Another client's stream is visible because the private pulse
    // server must see the streams it creates, and read is the whole of
    // it: no `x` to call a method on it, no `l` to be linked to it.
    let stream = object(&listing, &[STREAM]).expect("another client's stream is visible");
    assert_eq!(
        stream.permissions, "r----",
        "on another client's stream:\n{listing}"
    );
    // What the sink's `r-x--` means, asked of the daemon rather than
    // read off the manager's own configuration: a `default_permissions`
    // widened to include `w` would leave every assertion above intact.
    let refused = bed.in_context(
        PLAYBACK,
        &format!("pw-cli set-param {} Props \"{{ mute: true }}\"", sink.id),
    );
    assert!(
        refused.contains("Permission denied") && refused.contains("requires -wx--"),
        "muting the sink from a playback context was not refused:\n{refused}"
    );
}

#[test]
fn a_playback_context_connected_first_sees_no_port_or_link_of_a_later_capture_node() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let monitor = ContextMonitor::start(&bed, PLAYBACK);
    let (_recorder, capture_nodes) = capture_nodes_with_a_link(&bed);
    monitor.sees_none_of(&objects_of(&bed.info_from_host(), &capture_nodes));
}

#[test]
fn a_playback_context_sees_no_port_or_link_of_a_capture_node_across_a_restart() {
    let Some(mut bed) = PipeWireBed::start() else {
        return;
    };
    let monitor = ContextMonitor::start(&bed, PLAYBACK);
    let (_recorder, capture_nodes) = capture_nodes_with_a_link(&bed);
    // The restarted WirePlumber finds the context, the capture nodes and
    // their ports already in the graph.
    bed.restart_session_manager();
    let created = bed
        .command("pw-cli")
        .args([
            "create-node",
            "adapter",
            "{ factory.name = support.null-audio-sink, node.name = late-source, \
             media.class = Audio/Source, audio.position = \"FL,FR\", object.linger = true }",
        ])
        .output()
        .expect("pw-cli did not run");
    assert!(created.status.success(), "{created:?}");
    let late = r#"node.name = "late-source""#;
    let mut nodes = capture_nodes;
    let mut host = String::new();
    wait_for("the late source's ports", || {
        host = bed.info_from_host();
        object(&host, &[late, NODE])
            .is_some_and(|node| !objects_of(&host, std::slice::from_ref(&node.id)).is_empty())
    });
    nodes.push(object(&host, &[late, NODE]).expect("the late source").id);
    monitor.sees_none_of(&objects_of(&host, &nodes));
    let listing = bed.info_in_context(PLAYBACK, &[SINK]);
    assert_eq!(
        objects_of(&listing, &nodes),
        Vec::<String>::new(),
        "ports or links of a hidden capture node after a restart:\n{listing}"
    );
}

#[test]
fn a_playback_context_sees_no_port_of_a_node_that_turns_into_a_source() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let Some(fixture) = changes_its_properties(&bed) else {
        return;
    };
    let monitor = ContextMonitor::start(&bed, PLAYBACK);
    let mut command = bed.command(&fixture.to_string_lossy());
    command
        .args([
            "out",
            "{ media.class = Stream/Output/Audio, node.name = turncoat, node.autoconnect = false }",
            "{ media.class = Audio/Source }",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    own_process_group(&mut command);
    let _turncoat = Streaming(command.spawn().expect("the fixture did not run"));
    let turned = [
        r#"node.name = "turncoat""#,
        r#"media.class = "Audio/Source""#,
        NODE,
    ];
    let mut host = String::new();
    wait_for("the stream turned into a source, with its ports", || {
        host = bed.info_from_host();
        object(&host, &turned)
            .is_some_and(|node| !objects_of(&host, std::slice::from_ref(&node.id)).is_empty())
    });
    let node = object(&host, &turned).expect("the turned node").id;
    let mut ids = objects_of(&host, std::slice::from_ref(&node));
    ids.push(node.clone());
    monitor.sees_none_of(&ids);
    // The node itself stays visible to a context connected after the
    // change: the permission manager matches the class it was created with.
    let later = bed.info_in_context(PLAYBACK, &[SINK]);
    assert_eq!(
        objects_of(&later, std::slice::from_ref(&node)),
        Vec::<String>::new(),
        "a context connected after the change sees its ports:\n{later}"
    );
}

#[test]
fn a_microphone_context_sees_every_port_and_link_of_a_capture_node() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let (_recorder, capture_nodes) = capture_nodes_with_a_link(&bed);
    let listing = bed.info_in_context(PLAYBACK_MICROPHONE, &CAPTURE_NODES);
    assert_eq!(
        objects_of(&listing, &capture_nodes),
        objects_of(&bed.info_from_host(), &capture_nodes),
        "{listing}"
    );
}

const VIDEO_NODES: [(&str, &str); 5] = [
    ("video-source", "Video/Source"),
    ("video-sink", "Video/Sink"),
    ("video-duplex", "Video/Duplex"),
    ("odd-video-source", "Custom/Video/Source"),
    ("video-stream", "Stream/Output/Video"),
];

const EVERY_GRANT: [&str; 4] = [PLAYBACK, PLAYBACK_MICROPHONE, MICROPHONE_DEVICES, EXCLUSIVE];

/// The bed's `VIDEO_NODES` added, lingering, with ports and a link from
/// the sink's monitor into the video sink: the ids of the nodes.
fn video_nodes_with_a_link(bed: &PipeWireBed) -> Vec<String> {
    for (name, class) in VIDEO_NODES {
        // Without `adapter.auto-port-config` a null node of a class the
        // adapter does not know gets no ports (PipeWire 1.6.9).
        let out = bed
            .command("pw-cli")
            .args([
                "create-node",
                "adapter",
                &format!(
                    "{{ factory.name = support.null-audio-sink, node.name = {name}, \
                     media.class = {class}, audio.position = \"FL,FR\", object.linger = true, \
                     adapter.auto-port-config = {{ mode = dsp, position = preserve }} }}"
                ),
            ])
            .output()
            .expect("pw-cli did not run");
        assert!(out.status.success(), "{out:?}");
    }
    let ends = ["bed-sink:monitor_FL", "video-sink:playback_FL"];
    wait_for("the two ports the link joins", || {
        let ports = bed.host_tool("pw-link", &["-io"]);
        ends.iter()
            .all(|end| ports.lines().any(|port| port.trim() == *end))
    });
    let linked = bed
        .command("pw-link")
        .args(["-L", ends[0], ends[1]])
        .output()
        .expect("pw-link did not run");
    assert!(linked.status.success(), "{linked:?}");
    wait_for("the link into the video sink", || {
        bed.links().contains(ends[1])
    });
    let node = |listing: &str, name: &str| {
        object(listing, &[&format!("node.name = \"{name}\""), NODE]).map(|node| node.id)
    };
    let mut listing = String::new();
    wait_for("every video node with its ports", || {
        listing = bed.info_from_host();
        VIDEO_NODES.iter().all(|(name, _)| {
            node(&listing, name)
                .is_some_and(|id| !objects_of(&listing, std::slice::from_ref(&id)).is_empty())
        })
    });
    VIDEO_NODES
        .iter()
        .filter_map(|(name, _)| node(&listing, name))
        .collect()
}

#[test]
fn no_audio_context_sees_a_video_node_or_its_ports_and_links() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let nodes = video_nodes_with_a_link(&bed);
    for props in EVERY_GRANT {
        let listing = bed.info_in_context(props, &[SINK]);
        for (name, _) in VIDEO_NODES {
            assert!(
                object(&listing, &[&format!("node.name = \"{name}\""), NODE]).is_none(),
                "{name} under {props}:\n{listing}"
            );
        }
        assert_eq!(
            objects_of(&listing, &nodes),
            Vec::<String>::new(),
            "ports or links of a video node under {props}:\n{listing}"
        );
    }
}

#[test]
fn a_microphone_context_connected_first_sees_no_later_video_node_or_its_ports_and_links() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let monitor = ContextMonitor::start(&bed, PLAYBACK_MICROPHONE);
    let nodes = video_nodes_with_a_link(&bed);
    let mut ids = objects_of(&bed.info_from_host(), &nodes);
    ids.extend(nodes);
    monitor.sees_none_of(&ids);
}

#[test]
fn a_video_stream_is_hidden_from_every_sandbox_but_its_own() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let Some(fixture) = changes_its_properties(&bed) else {
        return;
    };
    let props = |name: &str| {
        format!(
            "{{ media.class = Stream/Output/Video, node.name = {name}, node.autoconnect = false, \
             adapter.auto-port-config = {{ mode = dsp, position = preserve }} }}"
        )
    };
    let own = ContextMonitor::running(
        &bed,
        PLAYBACK,
        &format!("'{}' out '{}'", fixture.display(), props("own-video")),
    );
    let _sibling = Streaming(bed.spawn_in_context(
        PLAYBACK_MICROPHONE,
        &format!("'{}' out '{}'", fixture.display(), props("sibling-video")),
    ));
    let _other = Streaming(bed.spawn_in_context(
        OTHER_SANDBOX,
        &format!("'{}' out '{}'", fixture.display(), props("other-video")),
    ));
    let mut command = bed.command(&fixture.to_string_lossy());
    command
        .args(["out", &props("host-video")])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    own_process_group(&mut command);
    let _host = Streaming(command.spawn().expect("the fixture did not run"));
    let mut hidden = video_nodes_with_a_link(&bed);

    let mut host = String::new();
    let stream = |host: &str, name: &str| object(host, &[&format!("node.name = \"{name}\""), NODE]);
    wait_for("the four video streams with their ports", || {
        host = bed.info_from_host();
        ["own-video", "sibling-video", "other-video", "host-video"]
            .iter()
            .all(|name| {
                stream(&host, name).is_some_and(|node| {
                    !objects_of(&host, std::slice::from_ref(&node.id)).is_empty()
                })
            })
    });
    let own_nodes = ["own-video", "sibling-video"].map(|name| stream(&host, name).unwrap().id);
    let mut own_ids = objects_of(&host, &own_nodes);
    own_ids.extend(own_nodes);
    wait_for(
        "the sandbox's video streams and their ports, seen by one of its clients",
        || {
            let visible = own.visible();
            own_ids.iter().all(|id| visible.contains(id))
        },
    );
    for name in ["other-video", "host-video"] {
        hidden.push(stream(&host, name).expect("a video stream").id);
    }
    let mut ids = objects_of(&host, &hidden);
    ids.extend(hidden);
    own.sees_none_of(&ids);
}

#[test]
fn a_bubbler_context_with_no_grant_the_drop_in_knows_falls_back_to_playback() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    for props in [BOGUS_GRANT, NO_GRANT] {
        let listing = bed.info_in_context(props, &[SINK]);
        let sink = object(&listing, &[SINK]).expect("the sink is visible");
        assert_eq!(sink.permissions, "r-x--", "under {props}:\n{listing}");
        assert!(
            object(&listing, &[SOURCE]).is_none(),
            "under {props} the null source was reachable:\n{listing}"
        );
    }
}

#[test]
fn a_playback_output_stream_links_to_the_sink() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let wav = bed.dir().join("tone.wav");
    silence(&wav);
    let _playing = streaming(
        &bed,
        PLAYBACK,
        &format!("pw-cat -p {}", wav.display()),
        "Stream/Output/Audio",
    );
    wait_for("a link to the null sink", || {
        bed.links().contains("bed-sink:playback_")
    });
}

#[test]
fn a_playback_capture_stream_gets_no_link() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let out = bed.dir().join("captured.wav");
    let _recording = streaming(
        &bed,
        PLAYBACK,
        &format!("pw-cat -r {}", out.display()),
        "Stream/Input/Audio",
    );
    window_in_which_it_would_link(&bed, "playback");
    let links = bed.links();
    assert!(
        !links.contains("bed-source"),
        "a playback-only context captured from the null source:\n{links}"
    );
}

/// The audio grant links a sandbox's two audio stream classes and no
/// other: a stream of any other class gets no link, rather than one the
/// hook then destroys.
#[test]
fn a_context_stream_of_another_class_gets_no_link() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let class = "Stream/Output/Audio/Internal";
    let _odd = streaming(
        &bed,
        PLAYBACK,
        &format!("pw-cat -p -a -P '{{ media.class = {class}, node.name = odd }}' - < /dev/zero"),
        class,
    );
    window_in_which_it_would_link(&bed, "playback");
    assert_eq!(
        links_destroyed(&bed),
        0,
        "the hook destroyed links of a {class} stream"
    );
    let links = bed.links();
    assert!(
        !links.contains("odd:"),
        "a {class} stream was linked:\n{links}"
    );
}

#[test]
fn a_playback_context_gets_no_link_to_another_clients_stream() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let wav = bed.dir().join("tone.wav");
    silence(&wav);
    let _other = streaming(
        &bed,
        PLAYBACK,
        &format!("pw-cat -p {}", wav.display()),
        "Stream/Output/Audio",
    );
    let listing = bed.info_in_context(PLAYBACK, &[STREAM]);
    let stream = object(&listing, &[STREAM]).expect("another client's stream is visible");
    let serial = stream.serial.expect("the stream's object.serial");

    // Seeing a stream is what the pulse server needs; being linked to
    // one is eavesdropping, and `--target` is how a client asks for it
    // by name.
    let out = bed.dir().join("stolen.wav");
    let _thief = streaming(
        &bed,
        PLAYBACK,
        &format!("pw-cat -r --target={serial} {}", out.display()),
        "Stream/Input/Audio",
    );
    window_in_which_it_would_link(&bed, "playback");

    let links = bed.links();
    // The playing client is still linked, so this is a graph that
    // links rather than one that has stopped.
    assert!(links.contains("bed-sink:playback_"), "{links}");
    // A capture stream's ports are the only `input_` ports here: the
    // sink's are `playback_`, the source's `capture_` and its monitor's
    // `monitor_`.
    assert!(
        !links.contains("input_"),
        "a playback context was linked to another client's stream:\n{links}"
    );
}

/// The microphone claimed by the client itself, both under the key the
/// policy reads and under the one it read before: what the client says
/// at connect, from its configuration's `context.properties` or from
/// `PIPEWIRE_PROPS`, reaches the daemon in its first update, before any
/// session manager can see the client; `Core.update_properties` is an
/// update after that. Beside it, the two keys besides `pipewire.access`
/// from which WirePlumber's `get_client_access` reads "flatpak".
const CLAIM: &str = r#"{ "bubbler.audio": "playback,microphone", "pipewire.sec.bubbler.audio": "playback,microphone", "pipewire.client.access": "flatpak", "pipewire.sec.flatpak": "true" }"#;

/// PipeWire 1.6.9 drops `pipewire.sec.flatpak` of `CLAIM`.
const CLAIMED_FLATPAK: &str = r#"pipewire.client.access = "flatpak""#;

/// What `wpexec` runs to claim the microphone once connected and then
/// open a capture stream of its own.
const CLAIM_LATER: &str = r#"
Core.update_properties {
  ["bubbler.audio"] = "playback,microphone",
  ["pipewire.sec.bubbler.audio"] = "playback,microphone",
  ["pipewire.client.access"] = "flatpak",
  ["pipewire.sec.flatpak"] = "true",
}
claimer = LocalNode ("adapter", {
  ["factory.name"] = "support.null-audio-sink",
  ["node.name"] = "claimer",
  ["media.class"] = "Stream/Input/Audio",
  ["audio.position"] = "FL,FR",
  ["node.autoconnect"] = "true",
})
claimer:activate (Feature.Proxy.BOUND)
"#;

/// Markers for a client object, for a capture stream's node, and for an
/// object carrying the claim under the key the policy no longer reads:
/// the tab before it is what `pw-cli info` prints ahead of each property,
/// so the marker cannot match inside `pipewire.sec.bubbler.audio`.
const CLIENT: &str = "type: PipeWire:Interface:Client";
const CAPTURE_STREAM: &str = r#"media.class = "Stream/Input/Audio""#;
const CLAIMED: &str = "\tbubbler.audio = \"playback,microphone\"";

/// The grant the claim asks for, as the daemon would carry it had the
/// claim worked.
const GRANTED_THE_MICROPHONE: &str = r#"pipewire.sec.bubbler.audio = "playback,microphone""#;

/// Each route a client in a playback context can drive to claim the
/// microphone, and for each, the evidence that the claim reached the
/// daemon (the host's `pw-cli info` shows it on the client or, for
/// `PIPEWIRE_PROPS`, on the stream), that WirePlumber aimed the capture
/// stream at the source (the hook logged refusing that link), and that
/// the grant did not change and no link was made.
#[test]
fn a_playback_context_that_claims_the_microphone_gets_the_playback_grant() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let config = bed.dir().join("claim");
    std::fs::create_dir_all(config.join("client.conf.d")).expect("a client config directory");
    std::fs::copy(PIPEWIRE_CLIENT_CONF, config.join("client.conf"))
        .expect("a copy of the stock client.conf");
    std::fs::write(
        config.join("client.conf.d/claim.conf"),
        format!("context.properties = {CLAIM}\n"),
    )
    .expect("the claim's drop-in");
    let script = bed.dir().join("claim.lua");
    std::fs::write(&script, CLAIM_LATER).expect("the later claim's script");
    let out = bed.dir().join("captured.wav");

    let plain = measure(&bed, PLAYBACK, &[SINK], str::to_owned).reach;
    let claimer = measure(&bed, PLAYBACK, &[SINK], |program| {
        format!("PIPEWIRE_CONFIG_DIR={} {program}", config.display())
    })
    .reach;
    for kept in [CLAIMED_FLATPAK, AS_THE_CONTEXT_SET_IT] {
        assert!(
            claimer.properties.iter().any(|line| line == kept),
            "{:?}",
            claimer.properties
        );
    }
    assert_eq!(
        claimer.view, plain.view,
        "a client that claims Flatpak's access"
    );

    for (route, claimed, program) in [
        (
            "its configuration",
            [CLIENT, CLAIMED],
            format!(
                "PIPEWIRE_CONFIG_DIR={} pw-cat -r {}",
                config.display(),
                out.display()
            ),
        ),
        // `PIPEWIRE_PROPS` lands on the stream and not the client.
        (
            "PIPEWIRE_PROPS",
            [CAPTURE_STREAM, CLAIMED],
            format!("PIPEWIRE_PROPS='{CLAIM}' pw-cat -r {}", out.display()),
        ),
        (
            "a later update",
            [CLIENT, CLAIMED],
            format!(
                "WIREPLUMBER_CONFIG_DIR={} wpexec {}",
                bed.dir().join("wireplumber").display(),
                script.display()
            ),
        ),
    ] {
        claim_is_refused(&bed, route, &claimed, || {
            Streaming(bed.spawn_in_context(PLAYBACK, &program))
        });
    }
    // The private pulse server connects each pulse client to the daemon
    // with that client's property list, `PULSE_PROP` included.
    let server = bed.pulse_server(PLAYBACK);
    claim_is_refused(
        &bed,
        "a pulse client's property list",
        &[CLIENT, CLAIMED],
        || {
            server.spawn(
                "sh",
                &[
                    OsStr::new("-c"),
                    OsStr::new(&format!(
                        "PULSE_PROP='bubbler.audio=\"playback,microphone\" \
                     pipewire.sec.bubbler.audio=\"playback,microphone\"' \
                     exec parecord --file-format=wav {}",
                        out.display()
                    )),
                ],
            )
        },
    );
}

/// Start a claimer with `start`, once the previous one is gone, and
/// require the claim in the daemon (an object carrying every one of
/// `claimed`), a refused link to the source, no client holding the
/// microphone grant, and no link to the source.
fn claim_is_refused(
    bed: &PipeWireBed,
    route: &str,
    claimed: &[&str],
    start: impl FnOnce() -> Streaming,
) {
    wait_for("the end of the previous claimer", || {
        let listing = bed.info_from_host();
        object(&listing, &[CLAIMED]).is_none() && object(&listing, &[CAPTURE_STREAM]).is_none()
    });
    let refused = links_refused(bed, "bed-source");
    let _recording = start();
    wait_for(&format!("the claim through {route} in the daemon"), || {
        object(&bed.info_from_host(), claimed).is_some()
    });
    wait_for(
        &format!("a link to the source refused through {route}"),
        || links_refused(bed, "bed-source") > refused,
    );
    let clients = bed.info_from_host();
    assert!(
        object(&clients, &[CLIENT, GRANTED_THE_MICROPHONE]).is_none(),
        "a client changed its grant through {route}:\n{clients}"
    );
    let links = bed.links();
    assert!(
        !links.contains("bed-source"),
        "a playback context that claimed the microphone through {route} captured:\n{links}"
    );
}

/// A sandbox cannot open a security context of its own with the grant it
/// lacks: a client that already carries `pipewire.sec.engine` is refused
/// a nested one.
#[test]
fn a_playback_context_cannot_nest_a_context_that_claims_the_microphone() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let nested = bed.output_in_context(
        PLAYBACK,
        &format!("pw-container -P '{CLAIM}' -- 'echo the nested program ran'"),
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&nested.stdout),
        String::from_utf8_lossy(&nested.stderr)
    );
    assert!(
        said.contains("can't create security context: Operation not permitted")
            && !said.contains("the nested program ran"),
        "a nested context was not refused:\n{said}"
    );
    let clients = bed.info_from_host();
    assert!(
        object(&clients, &[CLIENT, GRANTED_THE_MICROPHONE]).is_none(),
        "a client holds the microphone grant:\n{clients}"
    );
}

/// What `wpexec` runs to list the factories its client can see, once
/// the session manager has let it see anything.
const LIST_FACTORIES: &str = r#"
factories = ObjectManager { Interest { type = "factory" } }
factories:connect ("installed", function (om)
  for factory in om:iterate () do
    print ("factory " .. factory.properties ["factory.name"])
  end
  print ("listed")
  Core.quit ()
end)
factories:activate ()
"#;

/// A sandbox connected while WirePlumber starts has its factories hidden
/// all the same, though the hook's own list of them may still be empty
/// when WirePlumber decides that client's access.
#[test]
fn a_context_connected_before_the_session_manager_cannot_see_the_link_factory() {
    let started = PipeWireBed::start_with(|dir| {
        let script = dir.join("list-factories.lua");
        std::fs::write(&script, LIST_FACTORIES).expect("the listing script");
        let log = dir.join("early.log");
        let out = std::fs::File::create(&log).expect("a log for the early client");
        let err = out.try_clone().expect("a second handle on that log");
        let mut command = Command::new("pw-container");
        command
            .env("PIPEWIRE_RUNTIME_DIR", dir.join("run"))
            .arg("-P")
            .arg(PLAYBACK)
            .arg("--")
            .arg(format!(
                "WIREPLUMBER_CONFIG_DIR={} wpexec {}",
                dir.join("wireplumber").display(),
                script.display()
            ))
            .stdout(out)
            .stderr(err);
        own_process_group(&mut command);
        let early = Streaming(command.spawn().expect("pw-container did not run"));
        wait_for("the early client in the daemon", || {
            let dump = Command::new("pw-dump")
                .env("PIPEWIRE_RUNTIME_DIR", dir.join("run"))
                .output()
                .expect("pw-dump did not run");
            String::from_utf8_lossy(&dump.stdout)
                .contains("\"pipewire.sec.engine\": \"org.bubbler\"")
        });
        (early, log)
    });
    let Some((bed, (_early, log))) = started else {
        return;
    };
    let mut listed = String::new();
    wait_for("the early client's factory list", || {
        listed = std::fs::read_to_string(&log).unwrap_or_default();
        listed.contains("listed")
    });
    let wireplumber =
        std::fs::read_to_string(bed.dir().join("wireplumber.log")).unwrap_or_default();
    let hidden_as_it_appeared = wireplumber.contains("link-factory hidden from bed as it appeared");
    assert!(
        listed.contains("factory client-node") && !listed.contains("factory link-factory"),
        "a context connected before the session manager sees (link factory hidden \
         as it appeared: {hidden_as_it_appeared}):\n{listed}"
    );
    say(&format!(
        "the early context's link factory was hidden {}",
        if hidden_as_it_appeared {
            "by the factories handler as it appeared"
        } else {
            "by bubbler/hide-factories"
        }
    ));
}

/// How many links the bed's linking hook has refused toward the node
/// named `target`, by the line it logs for each.
fn links_refused(bed: &PipeWireBed, target: &str) -> usize {
    std::fs::read_to_string(bed.dir().join("wireplumber.log"))
        .unwrap_or_default()
        .matches(&format!("a link to {target}: "))
        .count()
}

#[test]
fn a_microphone_context_captures_from_the_null_source() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let out = bed.dir().join("captured.wav");
    let _recording = streaming(
        &bed,
        PLAYBACK_MICROPHONE,
        &format!("pw-cat -r {}", out.display()),
        "Stream/Input/Audio",
    );
    wait_for("a link from the null source", || {
        bed.links().contains("bed-source:capture_")
    });
    let seen = bed.in_context(PLAYBACK_MICROPHONE, "pw-dump");
    assert!(seen.contains("\"node.name\": \"bed-source\""), "{seen}");
}

/// Every class a node records from other than `Audio/Source` itself, as
/// the bed adds one null node of each: `Audio/Source/Virtual` is what a
/// filter's source is (echo-cancel, noise suppression), `Audio/Duplex` a
/// device that both plays and records.
const OTHER_SOURCES: [(&str, &str); 2] = [
    ("virtual-source", "Audio/Source/Virtual"),
    ("duplex", "Audio/Duplex"),
];

/// The bed's `OTHER_SOURCES`, created from the host and left lingering,
/// with the `object.serial` of each: a capture stream must name a duplex
/// node by serial, since WirePlumber matches a `target.object` given by
/// name only against nodes of the opposite direction
/// (linking/find-defined-target.lua), and a duplex node is an input.
fn add_other_sources(bed: &PipeWireBed) -> Vec<String> {
    for (name, class) in OTHER_SOURCES {
        let out = bed
            .command("pw-cli")
            .args([
                "create-node",
                "adapter",
                &format!(
                    "{{ factory.name = support.null-audio-sink, node.name = {name}, \
                     media.class = {class}, audio.position = \"FL,FR\", object.linger = true }}"
                ),
            ])
            .output()
            .expect("pw-cli did not run");
        assert!(out.status.success(), "{out:?}");
    }
    wait_for("the bed's other sources", || {
        let dump = bed.dump_from_host();
        OTHER_SOURCES
            .iter()
            .all(|(name, _)| dump.contains(&format!("\"node.name\": \"{name}\"")))
    });
    let listing = bed.info_from_host();
    OTHER_SOURCES
        .iter()
        .map(|(name, _)| {
            object(&listing, &[&format!("node.name = \"{name}\"")])
                .and_then(|node| node.serial)
                .expect("the serial of the node just created")
        })
        .collect()
}

#[test]
fn a_playback_context_neither_sees_nor_records_any_other_source() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let serials = add_other_sources(&bed);
    let listing = bed.info_in_context(PLAYBACK, &[SINK]);
    for ((name, class), serial) in OTHER_SOURCES.iter().zip(&serials) {
        assert!(
            object(&listing, &[&format!("node.name = \"{name}\"")]).is_none(),
            "a playback context sees an {class}:\n{listing}"
        );
        let out = bed.dir().join(format!("{name}.wav"));
        let _recording = streaming(
            &bed,
            PLAYBACK,
            &format!("pw-cat -r --target={serial} {}", out.display()),
            "Stream/Input/Audio",
        );
        window_in_which_it_would_link(&bed, "playback");
        let links = bed.links();
        assert!(
            !links.contains("pw-cat:input_"),
            "a playback context recorded from an {class}:\n{links}"
        );
    }
}

#[test]
fn a_microphone_context_records_from_every_other_source() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let serials = add_other_sources(&bed);
    for ((name, class), serial) in OTHER_SOURCES.iter().zip(&serials) {
        let out = bed.dir().join(format!("{name}.wav"));
        let _recording = streaming(
            &bed,
            PLAYBACK_MICROPHONE,
            &format!("pw-cat -r --target={serial} {}", out.display()),
            "Stream/Input/Audio",
        );
        wait_for(&format!("a link from the {class}"), || {
            bed.links()
                .lines()
                .skip_while(|line| !line.starts_with(&format!("{name}:")))
                .any(|line| line.contains("pw-cat:input_"))
        });
    }
}

#[test]
fn no_context_records_the_sinks_monitor_ports() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    // Under `microphone` too: what that grant opens is the microphone,
    // never the mix of everything the session is playing.
    for (props, grant) in [
        (PLAYBACK, "playback"),
        (PLAYBACK_MICROPHONE, "playback,microphone"),
        (DEVICES, "playback,devices"),
        (MICROPHONE_DEVICES, "playback,microphone,devices"),
    ] {
        let out = bed.dir().join("mix.wav");
        let _recording = streaming(
            &bed,
            props,
            &format!(
                "pw-cat -r -P '{{ stream.capture.sink = true }}' --target=bed-sink {}",
                out.display()
            ),
            "Stream/Input/Audio",
        );
        window_in_which_it_would_link(&bed, grant);

        let links = bed.links();
        assert!(
            !links.contains("monitor_"),
            "a {grant} context was linked to the sink's monitor ports:\n{links}"
        );
    }
}

#[test]
fn no_context_makes_a_link_of_its_own() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    for (props, grant) in [
        (PLAYBACK, "playback"),
        (PLAYBACK_MICROPHONE, "playback,microphone"),
    ] {
        // Without end, so the port waited for below cannot be gone
        // before a slow session manager has shown it to the context.
        let _other = streaming(
            &bed,
            PLAYBACK,
            "pw-cat -p -a - < /dev/zero",
            "Stream/Output/Audio",
        );
        // Autoconnect off, so the session manager never offers this
        // stream a target: what follows measures the client's own reach
        // through the link factory and nothing the hook decides.
        let out = bed.dir().join("stolen.wav");
        let _thief = streaming(
            &bed,
            props,
            &format!(
                "pw-record -P '{{ node.autoconnect = false }}' {}",
                out.display()
            ),
            "Stream/Input/Audio",
        );

        for source in ["bed-sink:monitor_FL", "pw-cat:output_FL"] {
            // `pw-link` says the same words for a port it cannot find and
            // a link it was refused (measured), so the refusal below only
            // counts once the context is known to see both ports.
            wait_for(&format!("{source} in the {grant} context's view"), || {
                let ports = bed.in_context(props, "pw-link -io");
                ports.contains(source) && ports.contains("pw-record:input_FL")
            });
            let refused =
                bed.output_in_context(props, &format!("pw-link -L {source} pw-record:input_FL"));
            // `pw-link` exits 0 whatever the daemon answers (measured),
            // so what it was told is on its stderr: the hidden factory's
            // ENOENT, and not the EINVAL of a link made and destroyed
            // before it settled, nor the silence of one that stayed.
            assert!(
                String::from_utf8_lossy(&refused.stderr)
                    .contains("failed to link ports: No such file or directory"),
                "a {grant} context linked {source} to its own capture stream: {refused:?}"
            );
        }
        let links = bed.links();
        assert!(
            !links.contains("pw-record:input_"),
            "a {grant} context linked itself to something:\n{links}"
        );
    }
}

/// A node made through a factory other than `client-node` is the
/// daemon's, and with `object.linger` carries no `client.id` at all
/// (module-adapter.c), so nothing could tell it was a sandbox's.
#[test]
fn a_context_creates_nodes_only_as_its_own_streams() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    for (props, grant) in [
        (PLAYBACK, "playback"),
        (PLAYBACK_MICROPHONE, "playback,microphone"),
        (DEVICES, "playback,devices"),
        (MICROPHONE_DEVICES, "playback,microphone,devices"),
    ] {
        for factory in ["adapter", "spa-node-factory"] {
            let name = format!("made-{factory}");
            let out = bed.output_in_context(
                props,
                &format!(
                    "pw-cli create-node {factory} '{{ factory.name = support.null-audio-sink, \
                     node.name = {name}, media.class = Audio/Sink, object.linger = true }}'"
                ),
            );
            std::thread::sleep(FORBIDDEN_LINK_LIFE);
            let dump = bed.dump_from_host();
            assert!(
                !dump.contains(&format!("\"node.name\": \"{name}\"")),
                "a {grant} context made a node through {factory}: {out:?}"
            );
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("unknown factory name"),
                "a {grant} context was not refused {factory}: {out:?}"
            );
        }
        let listing = bed.info_in_context(props, &[SINK]);
        let factories: Vec<&str> = listing
            .split("\n\tid: ")
            .filter(|block| block.contains("type: PipeWire:Interface:Factory"))
            .filter_map(|block| {
                block.lines().find_map(|line| {
                    line.trim()
                        .trim_start_matches('*')
                        .trim_start()
                        .strip_prefix("factory.name = ")
                })
            })
            .collect();
        assert_eq!(
            factories,
            [r#""client-node""#],
            "the factories a {grant} context can see"
        );
    }
}

/// How long the test below keeps opening fresh contexts: long enough for
/// a few hundred, short enough for the normal suite. It runs wherever the
/// bed can start, like every test here, and adds no load of its own; the
/// measurement under load that motivated it is not part of the suite.
const FRESH_CONTEXTS_FOR: Duration = Duration::from_secs(3);

/// The longest a forbidden link may be seen alive. Not zero: should a
/// context ever win a link again, the linking hook destroys it once
/// WirePlumber sees it, and this bounds how long that may take.
const FORBIDDEN_LINK_LIFE: Duration = Duration::from_millis(500);

#[test]
fn no_fresh_context_keeps_a_link_it_asks_for_in_its_first_instant() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    // `pw-cat` must end when the bed's daemon does: nothing here outlives
    // a killed test binary.
    let _other = streaming(
        &bed,
        PLAYBACK,
        "pw-cat -p -a - < /dev/zero",
        "Stream/Output/Audio",
    );
    let out = bed.dir().join("stolen.wav");
    let _thief = streaming(
        &bed,
        PLAYBACK,
        &format!(
            "pw-record -P '{{ node.autoconnect = false }}' {}",
            out.display()
        ),
        "Stream/Input/Audio",
    );

    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let mut longest = Duration::ZERO;
            let mut alive_since = None;
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let now = Instant::now();
                if bed.links().contains("pw-record:input_") {
                    longest = longest.max(now - *alive_since.get_or_insert(now));
                } else {
                    alive_since = None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            longest
        });
        // Every call is a new connection in a new context, each with the
        // instant before the session manager has acted on it.
        let deadline = Instant::now() + FRESH_CONTEXTS_FOR;
        let mut attempts = 0;
        let mut enoent = 0;
        while Instant::now() < deadline {
            let props = [PLAYBACK, PLAYBACK_MICROPHONE][attempts % 2];
            let source = ["bed-sink:monitor_FL", "pw-cat:output_FL"][attempts / 2 % 2];
            let out =
                bed.output_in_context(props, &format!("pw-link -L {source} pw-record:input_FL"));
            if String::from_utf8_lossy(&out.stderr)
                .contains("failed to link ports: No such file or directory")
            {
                enoent += 1;
            }
            attempts += 1;
        }
        assert!(
            enoent > 0,
            "none of {attempts} attempts got ENOENT, so none can have met a hidden link factory"
        );
        std::thread::sleep(FORBIDDEN_LINK_LIFE);
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        let longest = watcher.join().expect("the watcher thread");
        assert!(
            longest < FORBIDDEN_LINK_LIFE,
            "a link a context made for itself was seen alive for {longest:?} in {attempts} attempts"
        );
    });
    let links = bed.links();
    assert!(
        !links.contains("pw-record:input_"),
        "a link a context made for itself outlived the attempts:\n{links}"
    );
}

#[test]
fn a_link_to_a_bubbler_context_that_wireplumber_did_not_make_is_destroyed() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _player = streaming(
        &bed,
        PLAYBACK,
        "pw-cat -p -a -P '{ node.name = player }' - < /dev/zero",
        "Stream/Output/Audio",
    );
    let _microphone = streaming(
        &bed,
        PLAYBACK_MICROPHONE,
        "pw-cat -r -a -P '{ node.name = microphone }' /dev/null",
        "Stream/Input/Audio",
    );
    // WirePlumber's own links for both permitted paths, by link id: a
    // hook that destroyed them too would leave them relinked under a new
    // id at best.
    let permitted = || {
        bed.host_tool("pw-link", &["-l", "-I"])
            .lines()
            .filter(|line| {
                line.contains('|')
                    && (line.contains("player:output_") || line.contains("microphone:input_"))
            })
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let mut before = Vec::new();
    wait_for(
        "WirePlumber's links for the player and the microphone",
        || {
            before = permitted();
            ["player:", "microphone:"]
                .iter()
                .all(|node| before.iter().any(|link| link.contains(node)))
        },
    );
    let out = bed.dir().join("stolen.wav");
    let _thief = streaming(
        &bed,
        PLAYBACK,
        &format!(
            "pw-record -P '{{ node.autoconnect = false, node.name = thief }}' {}",
            out.display()
        ),
        "Stream/Input/Audio",
    );
    // The microphone's node already answers to the thief's media class.
    wait_for("the thief's capture port", || {
        bed.host_tool("pw-link", &["-i"]).contains("thief:input_FL")
    });
    let wireplumber = object(&bed.info_from_host(), &[r#"wireplumber.daemon = "true""#])
        .expect("WirePlumber's client")
        .id;

    // From the host, so it is not the link factory that stops it; and a
    // lingering link carries whatever `client.id` its creator gives it,
    // so the second claims to be WirePlumber's.
    for claim in [
        "{}".to_owned(),
        format!(r#"{{ "client.id": "{wireplumber}" }}"#),
    ] {
        for source in ["bed-sink:monitor_FL", "player:output_FL"] {
            // `pw-link`'s own answer cannot say a link was made: one
            // destroyed before it settled is EINVAL, as are other faults
            // (pw-link.c `link_proxy_destroy`). The hook's log line can.
            let before = links_destroyed(&bed);
            bed.command("pw-link")
                .args(["-L", "-p", &claim, source, "thief:input_FL"])
                .output()
                .expect("pw-link did not run");
            wait_for(
                &format!("the hook destroying a link from {source} claiming {claim}"),
                || links_destroyed(&bed) == before + 1,
            );
            wait_for(
                &format!("the end of a link from {source} claiming {claim}"),
                || !bed.links().contains("thief:input_"),
            );
        }
    }
    let after = permitted();
    assert!(
        before.iter().all(|link| after.contains(link)),
        "WirePlumber's own links did not survive:\n{before:#?}\n{after:#?}"
    );
}

/// How many links the bed's linking hook has destroyed so far, by the
/// line it logs for each.
fn links_destroyed(bed: &PipeWireBed) -> usize {
    std::fs::read_to_string(bed.dir().join("wireplumber.log"))
        .unwrap_or_default()
        .matches("destroying a link to a bubbler context")
        .count()
}

/// The bed runs one WirePlumber, so a second instance of a split setup
/// is stood in for by a client that carries the marker every instance's
/// client carries; whether one in a security context can wear it is the
/// question a sandbox's forgery would ask.
#[test]
fn only_a_session_manager_outside_every_context_keeps_a_link_to_a_bubbler_stream() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _player = streaming(
        &bed,
        PLAYBACK,
        "pw-cat -p -a -P '{ node.name = player }' - < /dev/zero",
        "Stream/Output/Audio",
    );
    wait_for("WirePlumber's link for the player", || {
        bed.links().contains("bed-sink:playback_")
    });
    // One of the player's own links in its own direction, crossed so it
    // is not the one WirePlumber already made.
    let crossed = || {
        bed.links()
            .lines()
            .skip_while(|line| *line != "player:output_FL")
            .skip(1)
            .take_while(|line| line.starts_with(' '))
            .any(|line| line.ends_with("bed-sink:playback_FR"))
    };

    let before = links_destroyed(&bed);
    let forging = || bed.context_command(r#"{ "wireplumber.daemon": "true" }"#, "pw-cli");
    let forged = holding_a_link(forging(), CROSSED);
    wait_for(
        "the destruction of a link from a context claiming to be WirePlumber",
        || links_destroyed(&bed) == before + 1,
    );
    assert!(!crossed(), "{}", bed.links());
    drop(forged);

    let _second_instance = holding_a_link(second_session_manager(&bed), CROSSED);
    wait_for("the link of a second session manager", crossed);
    // The hook decides links in the order WirePlumber sees them, so once
    // a forged link made after it is destroyed, this one has been decided.
    let _forged_again = holding_a_link(forging(), "player output_FR bed-sink playback_FL");
    wait_for("the destruction of a second forged link", || {
        links_destroyed(&bed) == before + 2
    });
    assert!(
        crossed(),
        "a second session manager's link was destroyed:\n{}",
        bed.links()
    );
    assert_eq!(links_destroyed(&bed), before + 2);
}

/// The player's left channel into the sink's right: not the link
/// WirePlumber makes itself.
const CROSSED: &str = "player output_FL bed-sink playback_FR";

/// `pw-cli` from the host as a second session manager: a client's
/// properties outside a context come from its own configuration's
/// `context.properties`, and this one carries the marker every
/// WirePlumber instance's client carries.
fn second_session_manager(bed: &PipeWireBed) -> Command {
    let config = bed.dir().join("second-instance");
    std::fs::create_dir_all(config.join("client.conf.d")).expect("a client config directory");
    std::fs::copy(PIPEWIRE_CLIENT_CONF, config.join("client.conf"))
        .expect("a copy of the stock client.conf");
    std::fs::write(
        config.join("client.conf.d/marker.conf"),
        "context.properties = { wireplumber.daemon = true }\n",
    )
    .expect("the marker's drop-in");
    let mut command = bed.command("pw-cli");
    command.env("PIPEWIRE_CONFIG_DIR", &config);
    command
}

/// `command`, a `pw-cli`, making `link` and holding it: a link `pw-cli`
/// makes lives while it runs, and it runs until its stdin closes.
fn holding_a_link(command: Command, link: &str) -> Streaming {
    holding_a_link_logged(command, link, Path::new("/dev/null"))
}

/// The same with what `pw-cli` says kept in `log`, where a refusal shows.
fn holding_a_link_logged(mut command: Command, link: &str, log: &Path) -> Streaming {
    let out = std::fs::File::create(log).expect("a log for pw-cli");
    let err = out.try_clone().expect("a second handle on that log");
    command.stdin(Stdio::piped()).stdout(out).stderr(err);
    own_process_group(&mut command);
    let mut child = command.spawn().expect("pw-cli did not run");
    std::io::Write::write_all(
        child.stdin.as_mut().expect("pw-cli's stdin"),
        format!("create-link {link}\n").as_bytes(),
    )
    .expect("a command for pw-cli");
    Streaming(child)
}

/// A session manager's link into a sandbox's capture stream is kept only
/// where the policy would have made it — from a source, with the
/// microphone grant — as when WirePlumber linked the stream before it
/// knew the stream's client and the first line could not decide.
#[test]
fn a_session_managers_link_into_a_capture_stream_is_kept_only_where_the_grant_allows() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _player = streaming(
        &bed,
        PLAYBACK,
        "pw-cat -p -a -P '{ node.name = player }' - < /dev/zero",
        "Stream/Output/Audio",
    );
    let unlinked = |name: &str| {
        format!("pw-record -P '{{ node.autoconnect = false, node.name = {name} }}' /dev/null")
    };
    let _recorder = streaming(
        &bed,
        PLAYBACK_MICROPHONE,
        &unlinked("recorder"),
        "Stream/Input/Audio",
    );
    let _thief = Streaming(bed.spawn_in_context(PLAYBACK, &unlinked("thief")));
    // The source's left channel is not always listed (measured), so
    // every link here is of the right one.
    wait_for("the ports to link", || {
        let ports = bed.host_tool("pw-link", &["-io"]);
        [
            "bed-source:capture_FR",
            "recorder:input_FR",
            "thief:input_FR",
        ]
        .iter()
        .all(|port| ports.contains(port))
    });

    let before = links_destroyed(&bed);
    let _granted = holding_a_link(
        second_session_manager(&bed),
        "bed-source capture_FR recorder input_FR",
    );
    wait_for("the second session manager's link to the recorder", || {
        bed.links().contains("recorder:input_FR")
    });
    // Not the source into the thief: the daemon refuses that link itself
    // (measured: EPERM, impl-link.c `check_permission`), since the
    // thief's client cannot see the source and this one holds no link
    // permission.
    let mut refused = Vec::new();
    for (n, link) in [
        "bed-sink monitor_FR thief input_FR",
        "player output_FR thief input_FR",
    ]
    .into_iter()
    .enumerate()
    {
        refused.push(holding_a_link(second_session_manager(&bed), link));
        wait_for(&format!("the hook destroying {link}"), || {
            links_destroyed(&bed) == before + n + 1
        });
    }
    let links = bed.links();
    assert!(!links.contains("thief:input_"), "{links}");
    // Decided before the three after it, which were destroyed.
    assert!(links.contains("recorder:input_FR"), "{links}");
    assert_eq!(links_destroyed(&bed), before + 2);
}

/// A context under `props` offers a device node ranked above the bed's
/// own (`offers`, each run in a context of its own and naming its node
/// `offered` or `offered-<something>`) before a host stream starts
/// (`host`, a node named `host`): the host stream must reach `bed_end`
/// and no port of the offered node, which would otherwise be the
/// session's default for want of a configured one.
fn a_host_stream_passes_by_a_node_a_context_offers(
    props: &str,
    grant: &str,
    offers: &[&str],
    host: &[&str],
    bed_end: &str,
) {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _offered: Vec<Streaming> = offers
        .iter()
        .map(|offer| Streaming(bed.spawn_in_context(props, offer)))
        .collect();
    wait_for("the context's offered nodes", || {
        bed.dump_from_host()
            .matches("\"node.name\": \"offered")
            .count()
            == offers.len()
    });
    window_in_which_it_would_link(&bed, grant);
    a_host_stream_passes_by_what_a_context_offered(&bed, grant, host, bed_end);
}

/// The host stream `host` (a node named `host`) reaches `bed_end` and no
/// port of a node named `offered`, which is no default either.
fn a_host_stream_passes_by_what_a_context_offered(
    bed: &PipeWireBed,
    grant: &str,
    host: &[&str],
    bed_end: &str,
) {
    let _host = host_stream(bed, host);
    wait_for("a link for the host's stream", || {
        bed.links().contains("host:")
    });
    // Long enough for a default decided again after the first link to
    // have moved the stream.
    std::thread::sleep(FORBIDDEN_LINK_LIFE);
    let links = bed.links();
    let defaults = default_metadata(bed);
    assert!(defaults.contains("default.audio."), "{defaults}");
    assert!(
        !defaults.contains("offered"),
        "a node a {grant} context offered became a default:\n{defaults}"
    );
    // A stream sent to the default in place of its own target keeps that
    // target: nothing tells it to follow the default from now on.
    assert!(
        !defaults.contains("target."),
        "a host stream was set to follow the default:\n{defaults}"
    );
    assert!(
        !links.contains("offered:"),
        "a host stream was linked to a node a {grant} context offered:\n{links}"
    );
    assert!(links.contains(bed_end), "{links}");
}

/// Not `pw-metadata`: under load it printed no keys in 7 of 800 reads
/// (`pw-dump` 0 of 400, PipeWire 1.6.9).
fn default_metadata(bed: &PipeWireBed) -> String {
    bed.dump_from_host()
        .split_once("\"metadata.name\": \"default\"")
        .and_then(|(_, rest)| rest.split("\"id\":").next())
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_host_stream_does_not_play_into_a_sink_a_playback_context_offers() {
    a_host_stream_passes_by_a_node_a_context_offers(
        PLAYBACK,
        "playback",
        &[
            "pw-cat -r -a -P '{ media.class = Audio/Sink, priority.session = 5000, node.name = offered }' /dev/null",
        ],
        &["-p", "-a", "-P", "{ node.name = host }", "-"],
        "bed-sink:playback_",
    );
}

#[test]
fn a_host_stream_does_not_play_into_a_sink_a_microphone_context_offers() {
    a_host_stream_passes_by_a_node_a_context_offers(
        PLAYBACK_MICROPHONE,
        "playback,microphone",
        &[
            "pw-cat -r -a -P '{ media.class = Audio/Sink, priority.session = 5000, node.name = offered }' /dev/null",
        ],
        &["-p", "-a", "-P", "{ node.name = host }", "-"],
        "bed-sink:playback_",
    );
}

#[test]
fn a_host_recorder_does_not_record_from_a_source_a_playback_context_offers() {
    a_host_stream_passes_by_a_node_a_context_offers(
        PLAYBACK,
        "playback",
        &[
            "pw-cat -p -a -P '{ media.class = Audio/Source, priority.session = 5000, node.name = offered }' - < /dev/zero",
        ],
        &["-r", "-a", "-P", "{ node.name = host }", "/dev/null"],
        "bed-source:capture_",
    );
}

#[test]
fn a_host_stream_aimed_at_a_sink_a_playback_context_offers_plays_on_the_default() {
    a_host_stream_passes_by_a_node_a_context_offers(
        PLAYBACK,
        "playback",
        &["pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered }' /dev/null"],
        &[
            "-p",
            "-a",
            "--target=offered",
            "-P",
            "{ node.name = host }",
            "-",
        ],
        "bed-sink:playback_",
    );
}

/// The output stream of a host loopback carries a link group that is no
/// smart filter's, which WirePlumber's filter search looks at first.
#[test]
fn a_host_loopbacks_stream_aimed_at_a_sink_a_playback_context_offers_plays_on_the_default() {
    a_host_stream_passes_by_a_node_a_context_offers(
        PLAYBACK,
        "playback",
        &["pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered }' /dev/null"],
        &[
            "-p",
            "-a",
            "--target=offered",
            "-P",
            "{ node.name = host, node.link-group = host-loopback }",
            "-",
        ],
        "bed-sink:playback_",
    );
}

/// A smart filter is a pair of nodes sharing a link group: the sink
/// streams are routed into and the stream it plays on with, both made
/// through `client-node`. Two connections, not two clients of one
/// `pw-container`: one of two clients connecting to it at once now and
/// then gets EPIPE (measured, under every policy).
#[test]
fn a_host_stream_passes_by_a_smart_filter_a_playback_context_offers() {
    a_host_stream_passes_by_a_node_a_context_offers(
        PLAYBACK,
        "playback",
        &[
            "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered, \
             node.link-group = sandbox-filter, filter.smart = true, \
             filter.smart.name = sandbox-filter }' /dev/null",
            "pw-cat -p -a -P '{ node.name = offered-out, \
             node.link-group = sandbox-filter }' - < /dev/zero",
        ],
        &["-p", "-a", "-P", "{ node.name = host }", "-"],
        "bed-sink:playback_",
    );
}

/// A sink a context offered while WirePlumber was up is no device for the
/// WirePlumber that starts after it, which meets the sink and its client
/// in whatever order its object managers deliver them.
#[test]
fn a_sink_a_context_offered_before_the_session_manager_restarted_is_no_device() {
    let Some(mut bed) = PipeWireBed::start() else {
        return;
    };
    let _offered = Streaming(bed.spawn_in_context(
        PLAYBACK,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, priority.session = 5000, node.name = offered }' /dev/null",
    ));
    wait_for("the context's sink", || {
        bed.dump_from_host().contains("\"node.name\": \"offered\"")
    });
    window_in_which_it_would_link(&bed, "playback");
    bed.restart_session_manager();
    window_in_which_it_would_link(&bed, "playback");
    a_host_stream_passes_by_what_a_context_offered(
        &bed,
        "playback",
        &["-p", "-a", "-P", "{ node.name = host }", "-"],
        "bed-sink:playback_",
    );
}

/// The C fixture that changes its own node's properties, built into the
/// bed's directory, or `None` (having said why) on a host without a C
/// compiler or PipeWire's headers.
fn changes_its_properties(bed: &PipeWireBed) -> Option<PathBuf> {
    for tool in ["cc", "pkg-config"] {
        if on_path(tool).is_none() {
            say(&format!("skipping: {tool} not installed"));
            return None;
        }
    }
    let flags = Command::new("pkg-config")
        .args(["--cflags", "--libs", "libpipewire-0.3"])
        .output()
        .expect("pkg-config did not run");
    if !flags.status.success() {
        say("skipping: libpipewire-0.3 headers not installed");
        return None;
    }
    let binary = bed.dir().join("changes_its_properties");
    let built = Command::new("cc")
        .arg("-o")
        .arg(&binary)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/changes_its_properties.c"
        ))
        .args(String::from_utf8_lossy(&flags.stdout).split_whitespace())
        .output()
        .expect("cc did not run");
    assert!(
        built.status.success(),
        "the fixture did not build:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    Some(binary)
}

/// A context's capture stream that turns itself into a smart filter's
/// sink once WirePlumber has made it a session item — with the link
/// group from the start, and with the link group added only then — takes
/// no host stream: an untargeted host stream still plays on the bed's
/// sink.
#[test]
fn a_stream_a_context_turns_into_a_smart_filter_takes_no_host_stream() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let Some(fixture) = changes_its_properties(&bed) else {
        return;
    };
    let filter = "media.class = Audio/Sink, node.link-group = sandbox-filter, \
                  filter.smart = true, filter.smart.name = sandbox-filter";
    for (n, created) in [
        "media.class = Stream/Input/Audio, node.name = offered, node.link-group = sandbox-filter",
        "media.class = Stream/Input/Audio, node.name = offered",
    ]
    .into_iter()
    .enumerate()
    {
        let offered = Streaming(bed.spawn_in_context(
            PLAYBACK,
            &format!(
                "'{}' in '{{ {created} }}' '{{ {filter} }}'",
                fixture.display()
            ),
        ));
        wait_for("the context's stream turned into a filter", || {
            bed.dump_from_host()
                .contains("\"filter.smart.name\": \"sandbox-filter\"")
        });
        window_in_which_it_would_link(&bed, "playback");

        let watched = LinkMonitor::start(&bed);
        let host = format!("host{n}");
        let _host = host_stream(
            &bed,
            &["-p", "-a", "-P", &format!("{{ node.name = {host} }}"), "-"],
        );
        wait_for(&format!("a link for {host} (created as {created})"), || {
            !peers(&bed.links(), &format!("{host}:output_FL")).is_empty()
        });
        std::thread::sleep(FORBIDDEN_LINK_LIFE);
        let links = bed.links();
        assert_eq!(
            peers(&links, &format!("{host}:output_FL")),
            ["bed-sink:playback_FL"],
            "{host} left the sink beside a context's stream created as {created}:\n{links}"
        );
        let seen = watched.seen();
        assert!(
            !seen.contains("|-> offered:"),
            "a host stream was linked to a context's stream created as {created}:\n{seen}"
        );
        drop(offered);
        wait_for("the context's stream gone", || {
            !bed.dump_from_host().contains("\"node.name\": \"offered\"")
        });
    }
}

/// `pw-cat` with `args`, run on the host outside every context and fed
/// silence, killed with the test.
fn host_stream(bed: &PipeWireBed, args: &[&str]) -> Streaming {
    let mut command = bed.command("pw-cat");
    command
        .args(args)
        .stdin(std::fs::File::open("/dev/zero").expect("/dev/zero"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    own_process_group(&mut command);
    Streaming(command.spawn().expect("pw-cat did not run"))
}

/// A context offers a sink under the name of a host device, before the
/// device itself appears (as when a Bluetooth headset reconnects) and
/// after it: a host stream pinned to that name with `node.dont-fallback`
/// is linked to the host's device, never to the copy. The device is mono,
/// so its ports (`playback_MONO`) tell it from the copy's (`playback_FL`,
/// `_FR`).
///
/// Observed through `pw-link -m`: stock WirePlumber links a stream pinned
/// this way and then destroys it on its next rescan, with or without a
/// sandbox in the graph (measured on 0.5.18), so the link does not last.
#[test]
fn a_host_stream_pinned_to_a_device_whose_name_a_context_copies_links_to_the_device() {
    a_host_stream_pinned_to_a_device_links_to_it_beside(
        None,
        PLAYBACK,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = bed-headset }' /dev/null",
        "bed-headset",
        "bed-headset",
    );
}

/// The same with a capture stream as the copy: WirePlumber resolves a
/// pinned name over streams too, and matches it against either the
/// `node.name` or the `object.path` of each
/// (linking/find-defined-target.lua), so the copy may take the device's
/// `node.name` as its `object.path`, or the reverse.
#[test]
fn a_host_stream_pinned_to_a_device_whose_name_a_contexts_stream_copies_links_to_the_device() {
    a_host_stream_pinned_to_a_device_links_to_it_beside(
        None,
        PLAYBACK,
        "pw-cat -r -a -P '{ node.name = bed-headset }' /dev/null",
        "bed-headset",
        "bed-headset",
    );
    a_host_stream_pinned_to_a_device_links_to_it_beside(
        None,
        PLAYBACK,
        "pw-cat -r -a -P '{ node.name = bed-headset-path }' /dev/null",
        "bed-headset-path",
        "bed-headset-path",
    );
    a_host_stream_pinned_to_a_device_links_to_it_beside(
        None,
        PLAYBACK,
        "pw-cat -r -a -P '{ node.name = shadow, object.path = bed-headset }' /dev/null",
        "shadow",
        "bed-headset",
    );
}

/// A device a `devices` context offers is a device like the host's:
/// another context's stream that copies its name does not take a host
/// stream pinned to it.
#[test]
fn a_host_stream_pinned_to_a_devices_contexts_sink_links_to_it_beside_another_contexts_copy() {
    a_host_stream_pinned_to_a_device_links_to_it_beside(
        Some(DEVICES),
        PLAYBACK,
        "pw-cat -r -a -P '{ node.name = bed-headset }' /dev/null",
        "bed-headset",
        "bed-headset",
    );
}

/// The device grant does not lift the name rule: a `devices` context's
/// sink, or its stream, named after a host device takes no host stream
/// pinned to that device.
#[test]
fn a_host_stream_pinned_to_a_device_links_to_it_beside_a_devices_contexts_copy() {
    a_host_stream_pinned_to_a_device_links_to_it_beside(
        None,
        DEVICES,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = bed-headset }' /dev/null",
        "bed-headset",
        "bed-headset",
    );
    a_host_stream_pinned_to_a_device_links_to_it_beside(
        None,
        DEVICES,
        "pw-cat -r -a -P '{ node.name = bed-headset }' /dev/null",
        "bed-headset",
        "bed-headset",
    );
}

/// The grant a context's `props` carry, as `window_in_which_it_would_link`
/// waits for it.
fn grant_of(props: &str) -> &str {
    props
        .split(r#""pipewire.sec.bubbler.audio": ""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a context with a grant")
}

/// A host stream pinned to `target` — the `node.name` (`bed-headset`) or
/// the `object.path` (`bed-headset-path`) of a mono sink, the host's or,
/// under `device_context`, a context's — is linked to the sink beside
/// `copy`, a node a context under `copy_context` names `copy_name`,
/// whichever of the two came first.
fn a_host_stream_pinned_to_a_device_links_to_it_beside(
    device_context: Option<&str>,
    copy_context: &str,
    copy: &str,
    copy_name: &str,
    target: &str,
) {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let copy = || Streaming(bed.spawn_in_context(copy_context, copy));
    let device_args = [
        "-r",
        "-a",
        "--channels=1",
        "--channel-map=mono",
        "-P",
        "{ media.class = Audio/Sink, node.name = bed-headset, \
         object.path = bed-headset-path }",
        "/dev/null",
    ];
    let device = || match device_context {
        None => host_stream(&bed, &device_args),
        Some(props) => Streaming(bed.spawn_in_context(
            props,
            &format!(
                "pw-cat {} -P '{}' {}",
                device_args[..4].join(" "),
                device_args[5],
                device_args[6]
            ),
        )),
    };
    let names = if copy_name == "bed-headset" {
        vec!["bed-headset"]
    } else {
        vec!["bed-headset", copy_name]
    };
    let present = || {
        let dump = bed.dump_from_host();
        names
            .iter()
            .map(|name| dump.matches(&format!("\"node.name\": \"{name}\"")).count())
            .sum::<usize>()
    };
    for (n, copy_first) in [true, false].into_iter().enumerate() {
        let first = if copy_first { copy() } else { device() };
        wait_for("the first node", || present() == 1);
        if copy_first {
            window_in_which_it_would_link(&bed, grant_of(copy_context));
        }
        let second = if copy_first { device() } else { copy() };
        wait_for("the host's device beside the copy", || present() == 2);
        if !copy_first {
            window_in_which_it_would_link(&bed, grant_of(copy_context));
        }

        let watched = LinkMonitor::start(&bed);
        let host = format!("host{n}");
        let _host = host_stream(
            &bed,
            &[
                "-p",
                "-a",
                &format!("--target={target}"),
                "-P",
                &format!("{{ node.name = {host}, node.dont-fallback = true }}"),
                "-",
            ],
        );
        wait_for(
            &format!("a link from the host stream pinned to {target} to the host's device"),
            || watched.seen().contains("|-> bed-headset:playback_MONO"),
        );
        std::thread::sleep(FORBIDDEN_LINK_LIFE);
        let seen = watched.seen();
        assert!(
            seen.lines()
                .filter(|line| names
                    .iter()
                    .any(|name| line.contains(&format!("|-> {name}:"))))
                .all(|line| line.contains("bed-headset:playback_MONO")),
            "a host stream pinned to {target} was linked to a context's copy \
             {copy_name} of its device (copy first: {copy_first}):\n{seen}"
        );
        drop((first, second));
        wait_for("the device and the copy gone", || present() == 0);
    }
}

/// A context's stream that takes a device's name a second after it was
/// created, while the device is there, and one created under the device's
/// name that drops it a second later, before the device appears: a host
/// stream pinned to the device is linked to it. WirePlumber matches the
/// pinned name against the properties a session item froze at its
/// creation, the default-node rescan against the node's current ones.
#[test]
fn a_host_stream_pinned_to_a_device_links_to_it_beside_a_contexts_renamed_stream() {
    a_host_stream_pinned_to_a_device_links_to_it_beside_a_renamed_copy(
        "early",
        "bed-headset",
        true,
    );
    a_host_stream_pinned_to_a_device_links_to_it_beside_a_renamed_copy(
        "bed-headset",
        "renamed",
        false,
    );
}

/// A host stream pinned to the host's mono sink `bed-headset` is linked to
/// it beside a context's capture stream created as `created` and renamed
/// to `later` a second later, with the device started before the stream
/// or after its rename.
fn a_host_stream_pinned_to_a_device_links_to_it_beside_a_renamed_copy(
    created: &str,
    later: &str,
    device_first: bool,
) {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let Some(fixture) = changes_its_properties(&bed) else {
        return;
    };
    let device = || {
        host_stream(
            &bed,
            &[
                "-r",
                "-a",
                "--channels=1",
                "--channel-map=mono",
                "-P",
                "{ media.class = Audio/Sink, node.name = bed-headset, \
                 object.path = bed-headset-path }",
                "/dev/null",
            ],
        )
    };
    let start_device = || {
        let started = device();
        wait_for("the host's device", || {
            bed.dump_from_host()
                .contains("\"object.path\": \"bed-headset-path\"")
        });
        started
    };
    let renamed = || {
        let wanted = if device_first { 2 } else { 1 };
        bed.dump_from_host()
            .matches(&format!("\"node.name\": \"{later}\""))
            .count()
            >= wanted
    };

    let device_before = device_first.then(start_device);
    let _copy = Streaming(bed.spawn_in_context(
        PLAYBACK,
        &format!(
            "'{}' in '{{ media.class = Stream/Input/Audio, node.name = {created} }}' \
             '{{ node.name = {later} }}'",
            fixture.display()
        ),
    ));
    window_in_which_it_would_link(&bed, "playback");
    wait_for(&format!("the context's stream renamed to {later}"), renamed);
    let _device = device_before.unwrap_or_else(&start_device);

    let watched = LinkMonitor::start(&bed);
    let _host = host_stream(
        &bed,
        &[
            "-p",
            "-a",
            "--target=bed-headset",
            "-P",
            "{ node.name = host, node.dont-fallback = true }",
            "-",
        ],
    );
    wait_for(
        &format!("a link from the pinned host stream to the host's device ({created} -> {later})"),
        || watched.seen().contains("|-> bed-headset:playback_MONO"),
    );
    std::thread::sleep(FORBIDDEN_LINK_LIFE);
    let seen = watched.seen();
    assert!(
        seen.lines()
            .filter(|line| {
                [created, later]
                    .iter()
                    .any(|name| line.contains(&format!("|-> {name}:")))
            })
            .all(|line| line.contains("bed-headset:playback_MONO")),
        "a pinned host stream was linked to a context's stream renamed from {created} \
         to {later}:\n{seen}"
    );
}

/// `pw-link -m` on the host for the length of a test: every link made,
/// however briefly it lived, where `pw-link -l` shows only the ones up
/// at the moment it is asked.
struct LinkMonitor {
    _running: Streaming,
    log: PathBuf,
}

impl LinkMonitor {
    /// Started once it has listed the bed's source, so a link made from
    /// here on is in what it saw. `stdbuf`, because `pw-link` writing to
    /// a file holds its lines until it exits, and it exits killed.
    fn start(bed: &PipeWireBed) -> LinkMonitor {
        let log = bed.dir().join("links.log");
        let out = std::fs::File::create(&log).expect("a log for pw-link");
        let mut command = bed.command("stdbuf");
        command
            .args(["-oL", "pw-link", "-m", "-o", "-l"])
            .stdout(out)
            .stderr(Stdio::null());
        own_process_group(&mut command);
        let running = Streaming(command.spawn().expect("pw-link did not run"));
        let monitor = LinkMonitor {
            _running: running,
            log,
        };
        wait_for("pw-link's first listing", || {
            monitor.seen().contains("bed-source:capture_")
        });
        monitor
    }

    fn seen(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// A host smart filter in front of the sink keeps every host stream: one
/// with no target and one aimed at the name of a context's filter play
/// into it, and its own stream plays on the sink, while a context offers
/// a smart filter that WirePlumber's chain would put after the host's, and
/// while it offers one that asks to go before it (`filter.smart.before`).
#[test]
fn a_host_stream_keeps_to_the_hosts_smart_filter_whatever_filter_a_context_offers() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _filter = host_stream(
        &bed,
        &[
            "-r",
            "-a",
            "-P",
            "{ media.class = Audio/Sink, node.name = host-filter, \
             node.link-group = host-filter, filter.smart = true, \
             filter.smart.name = host-filter, \
             filter.smart.target = { node.name = bed-sink } }",
            "/dev/null",
        ],
    );
    let _filter_out = host_stream(
        &bed,
        &[
            "-p",
            "-a",
            "-P",
            "{ node.name = host-filter-out, node.link-group = host-filter }",
            "-",
        ],
    );
    wait_for("the host filter's own stream on the sink", || {
        peers(&bed.links(), "host-filter-out:output_FL").contains(&"bed-sink:playback_FL")
    });

    for (n, placement) in ["", "filter.smart.before = [ host-filter ], "]
        .into_iter()
        .enumerate()
    {
        let offered = [
            Streaming(bed.spawn_in_context(
                PLAYBACK,
                &format!(
                    "pw-cat -r -a -P '{{ media.class = Audio/Sink, node.name = offered, \
                     node.link-group = sandbox-filter, filter.smart = true, \
                     filter.smart.name = sandbox-filter, {placement}\
                     filter.smart.target = {{ node.name = bed-sink }} }}' /dev/null"
                ),
            )),
            Streaming(bed.spawn_in_context(
                PLAYBACK,
                "pw-cat -p -a -P '{ node.name = offered-out, \
                 node.link-group = sandbox-filter }' - < /dev/zero",
            )),
        ];
        wait_for("the context's filter", || {
            bed.dump_from_host()
                .matches("\"node.name\": \"offered")
                .count()
                == 2
        });
        window_in_which_it_would_link(&bed, "playback");

        let watched = LinkMonitor::start(&bed);
        let plain = format!("plain{n}");
        let aimed = format!("aimed{n}");
        let _plain = host_stream(
            &bed,
            &["-p", "-a", "-P", &format!("{{ node.name = {plain} }}"), "-"],
        );
        let _aimed = host_stream(
            &bed,
            &[
                "-p",
                "-a",
                "--target=offered",
                "-P",
                &format!("{{ node.name = {aimed} }}"),
                "-",
            ],
        );
        wait_for("links for both host streams", || {
            let links = bed.links();
            [&plain, &aimed]
                .iter()
                .all(|node| !peers(&links, &format!("{node}:output_FL")).is_empty())
        });
        std::thread::sleep(FORBIDDEN_LINK_LIFE);
        let links = bed.links();
        for node in [&plain, &aimed] {
            assert_eq!(
                peers(&links, &format!("{node}:output_FL")),
                ["host-filter:playback_FL"],
                "{node} missed the host's filter beside a context's filter {placement}:\n{links}"
            );
        }
        assert_eq!(
            peers(&links, "host-filter-out:output_FL"),
            ["bed-sink:playback_FL"],
            "the host filter's own stream left the sink beside a context's filter {placement}:\n{links}"
        );
        let seen = watched.seen();
        assert!(
            !seen.contains("|-> offered:"),
            "a host stream was linked to a context's filter {placement}:\n{seen}"
        );
        drop(offered);
        wait_for("the context's filter gone", || {
            !bed.dump_from_host().contains("\"node.name\": \"offered")
        });
    }
}

/// What `port` is linked to in a `pw-link -l` listing.
fn peers<'a>(links: &'a str, port: &str) -> Vec<&'a str> {
    links
        .lines()
        .skip_while(|line| *line != port)
        .skip(1)
        .take_while(|line| line.starts_with(' '))
        .filter_map(|line| line.trim().strip_prefix("|-> "))
        .collect()
}

/// The microphone rule matches the grant's words, not one whole string:
/// `devices` beside `microphone` keeps the microphone, and `devices`
/// alone does not bring it.
#[test]
fn a_devices_context_reaches_the_microphone_only_with_the_microphone_grant() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let listing = bed.info_in_context(MICROPHONE_DEVICES, &[SINK, SOURCE]);
    let source = object(&listing, &[SOURCE]).expect("the source is visible");
    assert_eq!(source.permissions, "r-x--", "{listing}");
    for props in [DEVICES, &DEVICES.replace("devices", "microphones")] {
        let listing = bed.info_in_context(props, &[SINK]);
        assert!(
            object(&listing, &[SOURCE]).is_none(),
            "{props} sees the source:\n{listing}"
        );
    }

    let out = bed.dir().join("captured.wav");
    let _recording = streaming(
        &bed,
        DEVICES,
        &format!("pw-cat -r --target=bed-source {}", out.display()),
        "Stream/Input/Audio",
    );
    window_in_which_it_would_link(&bed, "playback,devices");
    let links = bed.links();
    assert!(
        !links.contains("pw-cat:input_"),
        "a playback,devices context recorded from the source:\n{links}"
    );
}

/// A host stream aimed by name at a sink a `devices` context offers
/// through `client-node` plays into it: the sink made by `offer`, a node
/// named `offered`. Both are returned, kept up for the caller.
fn a_host_stream_plays_into_a_sink_a_devices_context_offers(
    bed: &PipeWireBed,
    offer: &str,
) -> [Streaming; 2] {
    let offered = Streaming(bed.spawn_in_context(DEVICES, offer));
    wait_for("the context's sink", || {
        bed.dump_from_host().contains("\"node.name\": \"offered\"")
    });
    window_in_which_it_would_link(bed, "playback,devices");
    let host = host_stream(
        bed,
        &[
            "-p",
            "-a",
            "--target=offered",
            "-P",
            "{ node.name = host }",
            "-",
        ],
    );
    wait_for(&format!("the host stream in the sink {offer} made"), || {
        peers(&bed.links(), "host:output_FL").contains(&"offered:playback_FL")
    });
    [offered, host]
}

#[test]
fn a_host_stream_plays_into_a_sink_a_devices_context_makes_with_pw_cat() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _running = a_host_stream_plays_into_a_sink_a_devices_context_offers(
        &bed,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered }' /dev/null",
    );
}

/// A loopback is a sink and a stream sharing a link group: the host's
/// audio goes into the sink and on out of the context's stream to the
/// host's sink.
#[test]
fn a_host_stream_plays_through_a_loopback_a_devices_context_makes() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _running = a_host_stream_plays_into_a_sink_a_devices_context_offers(
        &bed,
        "pw-loopback --capture-props='{ media.class = Audio/Sink, node.name = offered }' \
         --playback-props='{ node.name = offered-out }'",
    );
    wait_for("the loopback's stream on the host's sink", || {
        peers(&bed.links(), "offered-out:output_FL").contains(&"bed-sink:playback_FL")
    });
}

/// Whether the bed's linking hook kept the node named `name` out of the
/// session, by the line it logs for each of the two ways.
fn kept_out_of_the_session(bed: &PipeWireBed, name: &str) -> bool {
    wireplumber_log(bed).lines().any(|line| {
        (line.contains(&format!(" {name} (client "))
            && line.contains("is no device of the session"))
            || line.contains(&format!("removing the session item of {name} (client "))
    })
}

/// The ports linked to any port of the node `node` in a `pw-link -l`
/// listing, in either direction.
fn linked_to<'a>(links: &'a str, node: &str) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut at_node = false;
    for line in links.lines() {
        if !line.starts_with(' ') {
            at_node = line.starts_with(&format!("{node}:"));
        } else if at_node {
            let peer = line.trim();
            found.push(
                peer.strip_prefix("|-> ")
                    .or_else(|| peer.strip_prefix("|<- "))
                    .unwrap_or(peer),
            );
        }
    }
    found
}

/// A `devices` context offers a smart filter — `filter`, a node named
/// `offered`, and the stream of its link group — aimed at the bed's
/// device whose ports begin `device`; a host stream (`host`, a node named
/// `host`) pinned to that device is linked to it alone, and the filter's
/// node is kept out of the session.
fn a_host_stream_passes_by_a_smart_filter_a_devices_context_offers(
    bed: &PipeWireBed,
    filter: [&str; 2],
    host: &[&str],
    device: &str,
) {
    let _filter = filter.map(|program| Streaming(bed.spawn_in_context(DEVICES, program)));
    wait_for("the context's smart filter", || {
        bed.dump_from_host()
            .contains("\"filter.smart.name\": \"sandbox-filter\"")
    });
    window_in_which_it_would_link(bed, "playback,devices");

    let _host = host_stream(bed, host);
    wait_for("a link for the host stream", || {
        !linked_to(&bed.links(), "host").is_empty()
    });
    std::thread::sleep(FORBIDDEN_LINK_LIFE);
    let links = bed.links();
    let peers = linked_to(&links, "host");
    assert!(
        peers.iter().all(|peer| peer.starts_with(device)),
        "a host stream pinned to {device} met a devices context's smart filter:\n{links}"
    );
    assert!(
        kept_out_of_the_session(bed, "offered"),
        "a devices context's smart filter kept its session item:\n{}",
        wireplumber_log(bed)
    );
}

const SMART_FILTER_OUT: &str =
    "pw-cat -p -a -P '{ node.name = offered-out, node.link-group = sandbox-filter }' - < /dev/zero";

/// The device grant offers no smart filter, whichever way it is aimed:
/// a filter in front of the bed's sink takes no host stream pinned to
/// the sink, one behind its source no host recorder pinned to the source,
/// and a node that says it is a smart filter a second after it was made
/// is caught then. A `devices` context cannot reach the `filters`
/// metadata, the other way WirePlumber reads a node as smart.
#[test]
fn a_host_stream_passes_by_a_smart_filter_a_devices_context_offers_in_front_of_a_device() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    a_host_stream_passes_by_a_smart_filter_a_devices_context_offers(
        &bed,
        [
            "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered, \
             node.link-group = sandbox-filter, filter.smart = true, \
             filter.smart.name = sandbox-filter, \
             filter.smart.target = { node.name = bed-sink } }' /dev/null",
            SMART_FILTER_OUT,
        ],
        &[
            "-p",
            "-a",
            "--target=bed-sink",
            "-P",
            "{ node.name = host }",
            "-",
        ],
        "bed-sink:playback_",
    );
    drop(bed);
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    a_host_stream_passes_by_a_smart_filter_a_devices_context_offers(
        &bed,
        [
            "pw-cat -p -a -P '{ media.class = Audio/Source, node.name = offered, \
             node.link-group = sandbox-filter, filter.smart = true, \
             filter.smart.name = sandbox-filter, \
             filter.smart.target = { node.name = bed-source } }' - < /dev/zero",
            "pw-cat -r -a -P '{ node.name = offered-in, node.link-group = sandbox-filter }' /dev/null",
        ],
        &[
            "-r",
            "-a",
            "--target=bed-source",
            "-P",
            "{ node.name = host }",
            "/dev/null",
        ],
        "bed-source:capture_",
    );
    drop(bed);

    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let mut seen = String::new();
    wait_for("the sink in a devices context's dump", || {
        seen = bed.in_context(DEVICES, "pw-dump");
        seen.contains("\"node.name\": \"bed-sink\"")
    });
    assert!(!seen.contains("\"metadata.name\""), "{seen}");
    let Some(fixture) = changes_its_properties(&bed) else {
        return;
    };
    let late = format!(
        "'{}' in '{{ media.class = Audio/Sink, node.name = offered, \
         node.link-group = sandbox-filter }}' '{{ filter.smart = true, \
         filter.smart.name = sandbox-filter, \
         filter.smart.target = {{ node.name = bed-sink }} }}'",
        fixture.display()
    );
    a_host_stream_passes_by_a_smart_filter_a_devices_context_offers(
        &bed,
        [&late, SMART_FILTER_OUT],
        &[
            "-p",
            "-a",
            "--target=bed-sink",
            "-P",
            "{ node.name = host }",
            "-",
        ],
        "bed-sink:playback_",
    );
}

/// The session may make a `devices` context's sink its default, and
/// takes its own back once the sink is gone.
#[test]
fn a_sink_a_devices_context_offers_may_become_the_default() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let default_sink = || {
        default_metadata(&bed)
            .split("\"key\": \"default.audio.sink\"")
            .nth(1)
            .and_then(|rest| rest.split("\"key\":").next())
            .unwrap_or_default()
            .to_owned()
    };
    let offered = Streaming(bed.spawn_in_context(
        DEVICES,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, priority.session = 5000, \
         node.name = offered }' /dev/null",
    ));
    wait_for("the context's sink as the default", || {
        default_sink().contains("\"name\": \"offered\"")
    });
    drop(offered);
    wait_for("the host's sink as the default again", || {
        default_sink().contains("\"name\": \"bed-sink\"")
    });
}

/// A source a `devices` context offers is a source like the host's: a
/// host recorder aimed at it records from it, and another context's
/// capture stream without the microphone grant does not. Nor does one
/// aimed at the monitor of a sink the context offers, which a playback
/// context can see: there the hook is what refuses it.
#[test]
fn a_host_recorder_records_from_a_source_a_devices_context_offers() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _offered = Streaming(bed.spawn_in_context(
        DEVICES,
        "pw-cat -p -a -P '{ media.class = Audio/Source, node.name = offered }' - < /dev/zero",
    ));
    wait_for("the context's source", || {
        bed.dump_from_host().contains("\"node.name\": \"offered\"")
    });
    window_in_which_it_would_link(&bed, "playback,devices");
    let _host = host_stream(
        &bed,
        &[
            "-r",
            "-a",
            "--target=offered",
            "-P",
            "{ node.name = host }",
            "/dev/null",
        ],
    );
    wait_for("the host recorder on the context's source", || {
        peers(&bed.links(), "offered:capture_FL").contains(&"host:input_FL")
    });
    let _thief = streaming(
        &bed,
        PLAYBACK,
        "pw-cat -r -a --target=offered -P '{ node.name = thief }' /dev/null",
        "Stream/Input/Audio",
    );
    let _offered_sink = Streaming(bed.spawn_in_context(
        DEVICES,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered-sink }' /dev/null",
    ));
    wait_for("the context's sink", || {
        bed.dump_from_host()
            .contains("\"node.name\": \"offered-sink\"")
    });
    let _monitor_thief = Streaming(bed.spawn_in_context(
        PLAYBACK,
        "pw-cat -r -a --target=offered-sink \
         -P '{ node.name = monitor-thief, stream.capture.sink = true }' /dev/null",
    ));
    wait_for("the hook refusing the sink's monitor", || {
        links_refused(&bed, "offered-sink") > 0
    });
    window_in_which_it_would_link(&bed, "playback");
    let links = bed.links();
    for thief in ["thief", "monitor-thief"] {
        assert!(
            linked_to(&links, thief).is_empty(),
            "a playback context's {thief} recorded from a devices context's node:\n{links}"
        );
    }
}

/// What may flow into a `devices` context's sink is a stream's audio,
/// linked by a session manager: a host stream is kept, a sink's monitor
/// is destroyed even from a session manager, the source's link is refused
/// by the daemon or destroyed by the hook where the context cannot see the
/// source and destroyed by the hook where it can (`microphone`), and a
/// patchbay's link from the stream is destroyed.
#[test]
fn only_a_session_managers_link_from_a_stream_into_a_devices_sink_is_kept() {
    only_a_session_managers_link_from_a_stream_into_the_sink_of(DEVICES);
    only_a_session_managers_link_from_a_stream_into_the_sink_of(MICROPHONE_DEVICES);
}

fn only_a_session_managers_link_from_a_stream_into_the_sink_of(context: &str) {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _offered = Streaming(bed.spawn_in_context(
        context,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered }' /dev/null",
    ));
    let _player = host_stream(
        &bed,
        &[
            "-p",
            "-a",
            "-P",
            "{ node.name = player, node.autoconnect = false }",
            "-",
        ],
    );
    wait_for("the ports to link", || {
        let ports = bed.host_tool("pw-link", &["-io"]);
        [
            "bed-source:capture_FR",
            "bed-sink:monitor_FR",
            "player:output_FR",
            "offered:playback_FR",
        ]
        .iter()
        .all(|port| ports.contains(port))
    });
    window_in_which_it_would_link(&bed, grant_of(context));

    let before = links_destroyed(&bed);
    let _granted = holding_a_link(
        second_session_manager(&bed),
        "player output_FR offered playback_FR",
    );
    wait_for("the session manager's link from the host stream", || {
        peers(&bed.links(), "player:output_FR").contains(&"offered:playback_FR")
    });
    let _monitor = holding_a_link(
        second_session_manager(&bed),
        "bed-sink monitor_FR offered playback_FR",
    );
    wait_for("the hook destroying the monitor's link", || {
        links_destroyed(&bed) == before + 1
    });
    let said = bed.dir().join("source-link.log");
    let _source = holding_a_link_logged(
        second_session_manager(&bed),
        "bed-source capture_FR offered playback_FR",
        &said,
    );
    if context == DEVICES {
        // Measured on PipeWire 1.6.9 under CPU load: the daemon let the
        // link be made 23 times in 150, and the hook destroyed each.
        let refused = || {
            std::fs::read_to_string(&said)
                .unwrap_or_default()
                .contains("Operation not permitted")
        };
        wait_for("the source's link refused or destroyed", || {
            refused() || links_destroyed(&bed) > before + 1
        });
    } else {
        wait_for("the hook destroying the source's link", || {
            links_destroyed(&bed) == before + 2
        });
    }
    let destroyed = links_destroyed(&bed);
    bed.command("pw-link")
        .args(["-L", "player:output_FL", "offered:playback_FL"])
        .output()
        .expect("pw-link did not run");
    wait_for("the hook destroying the patchbay's link", || {
        links_destroyed(&bed) == destroyed + 1
    });
    std::thread::sleep(FORBIDDEN_LINK_LIFE);
    let links = bed.links();
    for from in [
        "bed-sink:monitor_FR",
        "bed-source:capture_FR",
        "player:output_FL",
    ] {
        assert!(
            !peers(&links, from)
                .iter()
                .any(|to| to.starts_with("offered:")),
            "{from} reached the devices context's sink:\n{links}"
        );
    }
    assert!(
        peers(&links, "player:output_FR").contains(&"offered:playback_FR"),
        "{links}"
    );
}

#[test]
fn a_playback_context_plays_through_a_private_pulse_server() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let wav = bed.dir().join("tone.wav");
    silence(&wav);
    let server = bed.pulse_server(PLAYBACK);

    let played = server.run("paplay", &[wav.as_os_str()]);
    assert!(
        played.status.success(),
        "paplay through the private pulse server: {played:?}"
    );
}

#[test]
fn a_pulse_client_under_playback_lists_only_the_sinks_monitor_as_a_source() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let server = bed.pulse_server(PLAYBACK);

    let listed = server.run("pactl", &["list", "short", "sources"].map(OsStr::new));
    assert!(
        listed.status.success(),
        "pactl list short sources: {listed:?}"
    );
    let sources = String::from_utf8_lossy(&listed.stdout);
    assert_eq!(
        sources.lines().count(),
        1,
        "sources under playback:\n{sources}"
    );
    assert!(
        sources.contains("bed-sink.monitor"),
        "sources under playback:\n{sources}"
    );
}

#[test]
fn a_pulse_client_under_playback_gets_no_capture_link() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let server = bed.pulse_server(PLAYBACK);
    let out = bed.dir().join("captured.wav");
    let _recording = server.spawn(
        "parecord",
        &[OsStr::new("--file-format=wav"), out.as_os_str()],
    );
    wait_for("the pulse client's capture stream", || {
        bed.dump_from_host()
            .contains("\"media.class\": \"Stream/Input/Audio\"")
    });
    window_in_which_it_would_link(&bed, "playback");

    let links = bed.links();
    assert!(
        !links.contains("bed-source") && !links.contains("monitor_"),
        "a pulse client under playback was linked to something it may not record:\n{links}"
    );
}

#[test]
fn a_pulse_client_under_microphone_records_from_the_null_source() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let server = bed.pulse_server(PLAYBACK_MICROPHONE);
    let out = bed.dir().join("captured.wav");
    let _recording = server.spawn(
        "parecord",
        &[
            OsStr::new("--device=bed-source"),
            OsStr::new("--file-format=wav"),
            out.as_os_str(),
        ],
    );
    wait_for("a link from the null source", || {
        bed.links().contains("bed-source:capture_")
    });
}

#[test]
fn a_context_that_is_not_bubblers_keeps_the_reach_it_had() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    // `pw-container`'s own defaults: `org.flatpak`, no `pipewire.sec.bubbler.audio`.
    // The drop-in must not narrow a context it did not create.
    let listing = bed.info_in_context("{}", &[SINK, SOURCE]);
    for marker in [SINK, SOURCE] {
        let node = object(&listing, &[marker])
            .unwrap_or_else(|| panic!("{marker} is visible:\n{listing}"));
        // Measured, not documented: WirePlumber 0.5.15 handed an unmatched
        // restricted client `Perm.ALL` (`rwxml`), 0.5.17 hands it `rwx-l`,
        // the metadata bit withheld and read, write, execute and link
        // kept; either way the drop-in narrowed nothing. If this ever
        // reads `r-x--`, the upstream default became the documented one
        // and the warning bubbler prints when the drop-in is missing
        // overstates the reach.
        assert!(
            node.permissions.starts_with("rwx"),
            "on {marker}: {} — either the drop-in narrowed a foreign context or the upstream default became the documented one\n{listing}",
            node.permissions
        );
    }
}

/// What stock WirePlumber logs when it turns a stream away from a sink
/// another stream holds for itself (linking/prepare-link.lua, 0.5.18).
const HELD_EXCLUSIVELY: &str = "target is linked exclusively";

/// Wait until the stream `holder` is either linked to the sink or gone,
/// its client having been told why it is not: either way WirePlumber has
/// decided it, so a stream started after this one meets that decision.
fn holder_decided(bed: &PipeWireBed, holder: &mut Streaming) {
    wait_for("the holding stream linked or turned away", || {
        !peers(&bed.links(), "holder:output_FL").is_empty()
            || holder.0.try_wait().expect("the holder's status").is_some()
    });
}

/// A host stream, started on the host once `holder` is decided, and
/// waited for on the sink.
fn host_stream_on_the_sink(bed: &PipeWireBed) -> Streaming {
    let host = host_stream(bed, &["-p", "-a", "-P", "{ node.name = host }", "-"]);
    wait_for("the host stream on the sink", || {
        peers(&bed.links(), "host:output_FL").contains(&"bed-sink:playback_FL")
    });
    host
}

fn wireplumber_log(bed: &PipeWireBed) -> String {
    std::fs::read_to_string(bed.dir().join("wireplumber.log")).unwrap_or_default()
}

/// A playback context's stream that asks for the sink exclusively is not
/// linked and its client is told so; a host stream started after it
/// plays on the sink.
///
/// The encoded-only half of the rule has no row: the session item's
/// `item.node.encoded-only` is WirePlumber's own (measured on 0.5.18: a
/// node carrying it `true` gets an item carrying it `false`), and the
/// bed's null sink takes no encoded format to make a stream that is.
#[test]
fn a_host_stream_plays_after_a_playback_contexts_stream_asked_for_the_sink_alone() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let told = bed.dir().join("holder.log");
    let mut holder = Streaming(bed.spawn_in_context_logged(
        PLAYBACK,
        "pw-cat -p -a -P '{ node.name = holder, node.exclusive = true }' /dev/zero",
        Some(&told),
    ));
    holder_decided(&bed, &mut holder);
    let _host = host_stream_on_the_sink(&bed);

    assert!(
        peers(&bed.links(), "holder:output_FL").is_empty(),
        "the holder was linked:\n{}",
        bed.links()
    );
    let said = std::fs::read_to_string(&told).unwrap_or_default();
    assert!(
        said.contains("needs the exclusive grant"),
        "the holder's client was not told why:\n{said}"
    );
    assert!(!wireplumber_log(&bed).contains(HELD_EXCLUSIVELY));
}

/// The same through the private pulse server: a pulse client may set
/// `node.exclusive` on the stream the server makes for it.
#[test]
fn a_host_stream_plays_after_a_pulse_clients_stream_asked_for_the_sink_alone() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let server = bed.pulse_server(PLAYBACK);
    let mut holder = server.spawn(
        "pacat",
        &[
            "--property=node.exclusive=true",
            "--property=node.name=holder",
            "/dev/zero",
        ]
        .map(OsStr::new),
    );
    holder_decided(&bed, &mut holder);
    let _host = host_stream_on_the_sink(&bed);

    assert!(
        peers(&bed.links(), "holder:output_FL").is_empty(),
        "the pulse client's stream was linked:\n{}",
        bed.links()
    );
    let ended = holder.0.try_wait().expect("pacat's status");
    assert!(
        ended.is_some_and(|status| !status.success()),
        "pacat was not told its stream failed: {ended:?}"
    );
    let log = wireplumber_log(&bed);
    assert!(
        refusals_of(&log, "holder").any(|line| line.ends_with(HOLDS_ITS_TARGET)),
        "the hook did not refuse the pulse client's stream for holding the sink:\n{log}"
    );
    assert!(!log.contains(HELD_EXCLUSIVELY));
}

/// The reason the hook logs for a stream refused for holding its target.
const HOLDS_ITS_TARGET: &str = "without the exclusive grant";

/// The hook's lines refusing the stream `name` a link.
fn refusals_of<'a>(log: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    let refusing = format!("refusing {name} (client");
    log.lines().filter(move |line| line.contains(&refusing))
}

/// A playback context's capture stream that asks for its source alone is
/// refused for the missing microphone grant, which granting `exclusive`
/// would not lift, and is not told it needs `exclusive`.
#[test]
fn a_playback_contexts_capture_stream_asking_for_the_source_alone_is_refused_the_source() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let told = bed.dir().join("recorder.log");
    let _recorder = Streaming(bed.spawn_in_context_logged(
        PLAYBACK,
        "pw-cat -r -a -P '{ node.name = recorder, node.exclusive = true }' /dev/null",
        Some(&told),
    ));
    let mut log = String::new();
    wait_for("the hook refusing the recorder", || {
        log = wireplumber_log(&bed);
        refusals_of(&log, "recorder").next().is_some()
    });
    let refusals: Vec<&str> = refusals_of(&log, "recorder").collect();
    assert!(
        refusals
            .iter()
            .all(|line| line.ends_with("a source, without the microphone grant")),
        "the recorder was refused for something else:\n{refusals:#?}"
    );
    let said = std::fs::read_to_string(&told).unwrap_or_default();
    assert!(
        !said.contains("needs the exclusive grant"),
        "the recorder's client was told it needs exclusive:\n{said}"
    );
}

/// A stream refused for holding its target is told so once: a rescan
/// after it refuses it again and tells it nothing more.
#[test]
fn a_contexts_stream_refused_for_holding_the_sink_is_told_once() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let Some(fixture) = changes_its_properties(&bed) else {
        return;
    };
    let _holder = Streaming(bed.spawn_in_context(
        PLAYBACK,
        &format!(
            "'{}' out '{{ media.class = Stream/Output/Audio, node.name = holder, \
             node.exclusive = true }}' '{{ media.name = holder }}'",
            fixture.display()
        ),
    ));
    wait_for("the hook refusing the holder", || {
        refusals_of(&wireplumber_log(&bed), "holder")
            .next()
            .is_some()
    });
    let _host = host_stream_on_the_sink(&bed);
    let mut log = String::new();
    wait_for("the hook refusing the holder on a later rescan", || {
        log = wireplumber_log(&bed);
        refusals_of(&log, "holder").count() >= 2
    });
    assert_eq!(
        log.matches("telling the client of holder").count(),
        1,
        "the holder's client was not told exactly once:\n{log}"
    );
}

/// A playback context's stream that asks for the sink alone only once it
/// is linked holds nothing after WirePlumber restarts: the WirePlumber
/// that starts meets the stream and its client in whatever order its
/// object managers deliver them, and a link it made before it knew the
/// client is undone once it does. A host stream started then plays on the
/// sink.
#[test]
fn a_host_stream_plays_after_a_restart_met_a_playback_contexts_stream_asking_for_the_sink_alone() {
    let Some(mut bed) = PipeWireBed::start() else {
        return;
    };
    let Some(fixture) = changes_its_properties(&bed) else {
        return;
    };
    let _holder = Streaming(bed.spawn_in_context(
        PLAYBACK,
        &format!(
            "'{}' out '{{ media.class = Stream/Output/Audio, node.name = holder }}' \
             '{{ node.exclusive = true }}'",
            fixture.display()
        ),
    ));
    wait_for("the holder linked and asking for the sink alone", || {
        bed.dump_from_host().contains("\"node.exclusive\"")
            && peers(&bed.links(), "holder:output_FL").contains(&"bed-sink:playback_FL")
    });
    bed.restart_session_manager();
    window_in_which_it_would_link(&bed, "playback");
    let _host = host_stream_on_the_sink(&bed);

    assert!(
        peers(&bed.links(), "holder:output_FL").is_empty(),
        "the holder was linked after the restart:\n{}",
        bed.links()
    );
    let log = wireplumber_log(&bed);
    assert!(
        log.contains("refusing holder") && log.contains("without the exclusive grant"),
        "the hook did not refuse the holder after the restart:\n{log}"
    );
    assert!(!log.contains(HELD_EXCLUSIVELY));
}

/// With the `exclusive` grant stock behaviour holds: the context's stream
/// takes the sink for itself and a host stream started after it is
/// turned away.
#[test]
fn an_exclusive_contexts_stream_holds_the_sink_against_a_later_host_stream() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let mut holder = Streaming(bed.spawn_in_context(
        EXCLUSIVE,
        "pw-cat -p -a -P '{ node.name = holder, node.exclusive = true }' /dev/zero",
    ));
    holder_decided(&bed, &mut holder);
    assert!(
        peers(&bed.links(), "holder:output_FL").contains(&"bed-sink:playback_FL"),
        "the exclusive context's stream was not linked:\n{}",
        bed.links()
    );
    let _host = host_stream(&bed, &["-p", "-a", "-P", "{ node.name = host }", "-"]);
    wait_for("the host stream turned away from the held sink", || {
        wireplumber_log(&bed).contains(HELD_EXCLUSIVELY)
    });
    assert!(
        peers(&bed.links(), "host:output_FL").is_empty(),
        "the host stream was linked to a held sink:\n{}",
        bed.links()
    );
}

/// The application name every node below carries: the first of the names
/// stock WirePlumber keys a node's saved volume on (node/state-stream.lua
/// `formKey`), so the host's nodes and the context's share one key.
const SHARED_APP: &str = "shared-app";

const NODE: &str = "type: PipeWire:Interface:Node";

/// A node `pw-cat` makes: its direction, the class it is given, and its
/// file.
struct NodeKind {
    direction: &'static str,
    class: &'static str,
    file: &'static str,
}

const PLAYBACK_STREAM: NodeKind = NodeKind {
    direction: "-p",
    class: "",
    file: "-",
};

/// A sink without routes, which stock WirePlumber saves and restores as
/// it does a stream.
const ROUTELESS_SINK: NodeKind = NodeKind {
    direction: "-r",
    class: "media.class = Audio/Sink, ",
    file: "/dev/null",
};

impl NodeKind {
    fn props(&self, name: &str) -> String {
        format!(
            "{{ {}application.name = {SHARED_APP}, node.name = {name} }}",
            self.class
        )
    }

    fn on_the_host(&self, bed: &PipeWireBed, name: &str) -> Streaming {
        host_stream(
            bed,
            &[self.direction, "-a", "-P", &self.props(name), self.file],
        )
    }

    fn in_context(&self, bed: &PipeWireBed, context: &str, name: &str) -> Streaming {
        Streaming(bed.spawn_in_context(
            context,
            &format!(
                "pw-cat {} -a -P '{}' {} < /dev/zero",
                self.direction,
                self.props(name),
                self.file
            ),
        ))
    }
}

/// A node's volume and mute, as its `Props` parameter carries them: the
/// volume of its first channel, which is what a mixer sets.
#[derive(Debug, PartialEq)]
struct Levels {
    volume: f32,
    mute: bool,
}

/// What the host's first node of `SHARED_APP` is set to and saved with.
const SAVED: Levels = Levels {
    volume: 0.8,
    mute: false,
};

/// The `pw-cli` id of the node named `name`, once it is in the graph.
fn node_id(bed: &PipeWireBed, name: &str) -> String {
    let marker = format!("node.name = \"{name}\"");
    let mut id = String::new();
    wait_for(&format!("the node {name}"), || {
        object(&bed.info_from_host(), &[NODE, &marker]).is_some_and(|node| {
            id = node.id;
            true
        })
    });
    id
}

fn levels(bed: &PipeWireBed, name: &str) -> Levels {
    let params = bed.host_tool("pw-cli", &["enum-params", &node_id(bed, name), "Props"]);
    // The first value printed after a key is a scalar's own, or an
    // array's first element: the first channel's volume.
    let value = |key: &str| {
        params
            .lines()
            .skip_while(|line| !line.contains(&format!("Props:{key} (")))
            .map(str::trim)
            .find(|line| line.starts_with("Float ") || line.starts_with("Bool "))
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("no {key} in the Props of {name}:\n{params}"))
    };
    Levels {
        volume: value("channelVolumes")
            .strip_prefix("Float ")
            .and_then(|volume| volume.parse().ok())
            .expect("a float volume"),
        mute: value("mute") == "Bool true",
    }
}

/// Set `pod` on the node named `name` from the host, as a mixer does.
fn set_levels(bed: &PipeWireBed, name: &str, pod: &str) {
    bed.host_tool("pw-cli", &["set-param", &node_id(bed, name), "Props", pod]);
}

/// What the bed's WirePlumber has written of its saved stream state.
fn saved_stream_state(bed: &PipeWireBed) -> String {
    std::fs::read_to_string(bed.dir().join("state/wireplumber/stream-properties"))
        .unwrap_or_default()
}

/// A bound, not a proof, as `window_in_which_it_would_link` is: nothing
/// announces a save that did not happen, or a restore that set nothing.
fn window_in_which_it_would_save() {
    std::thread::sleep(Duration::from_secs(2));
}

/// Wait for the node named `name` and the window in which stock
/// WirePlumber sets the levels it restores on a new node: saved ones, or
/// defaults where none are, so a change made earlier would be undone.
fn restored(bed: &PipeWireBed, name: &str) {
    node_id(bed, name);
    window_in_which_it_would_save();
}

/// A host node of `kind` set to `SAVED`, kept until WirePlumber has
/// written it to its state, and gone.
fn save_on_the_host(bed: &PipeWireBed, kind: &NodeKind) {
    let _first = kind.on_the_host(bed, "host-first");
    restored(bed, "host-first");
    let volume = SAVED.volume;
    set_levels(
        bed,
        "host-first",
        &format!("{{ channelVolumes: [ {volume}, {volume} ] }}"),
    );
    let stored = format!("{volume:.6}");
    wait_for("the host node's volume in the saved state", || {
        saved_stream_state(bed)
            .lines()
            .any(|line| line.contains(SHARED_APP) && line.contains(&stored))
    });
}

/// A node of `kind` in a context carrying `context`, once `pod` set on
/// it has changed its levels.
fn changed_in_context(bed: &PipeWireBed, kind: &NodeKind, context: &str, pod: &str) -> Streaming {
    let node = kind.in_context(bed, context, "sandboxed");
    restored(bed, "sandboxed");
    let untouched = levels(bed, "sandboxed");
    set_levels(bed, "sandboxed", pod);
    wait_for("the context's node changed", || {
        levels(bed, "sandboxed") != untouched
    });
    node
}

/// The levels the next host node of `kind` has once WirePlumber would
/// have restored them.
fn next_host_levels(bed: &PipeWireBed, kind: &NodeKind) -> Levels {
    let _next = kind.on_the_host(bed, "host-next");
    restored(bed, "host-next");
    levels(bed, "host-next")
}

/// A context's stream named like a host application and turned down
/// leaves that application's saved volume as the host saved it.
#[test]
fn a_host_stream_keeps_its_volume_when_a_contexts_stream_of_its_name_is_turned_down() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    save_on_the_host(&bed, &PLAYBACK_STREAM);
    let sandboxed = changed_in_context(
        &bed,
        &PLAYBACK_STREAM,
        PLAYBACK,
        "{ channelVolumes: [ 0.3, 0.3 ] }",
    );
    window_in_which_it_would_save();
    drop(sandboxed);
    assert_eq!(
        next_host_levels(&bed, &PLAYBACK_STREAM),
        SAVED,
        "saved:\n{}",
        saved_stream_state(&bed)
    );
}

#[test]
fn a_host_stream_keeps_its_mute_when_a_contexts_stream_of_its_name_is_muted() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    save_on_the_host(&bed, &PLAYBACK_STREAM);
    let sandboxed = changed_in_context(&bed, &PLAYBACK_STREAM, PLAYBACK, "{ mute: true }");
    window_in_which_it_would_save();
    drop(sandboxed);
    assert_eq!(
        next_host_levels(&bed, &PLAYBACK_STREAM),
        SAVED,
        "saved:\n{}",
        saved_stream_state(&bed)
    );
}

/// What is not saved still takes effect on the context's own stream.
#[test]
fn a_contexts_stream_takes_the_volume_it_is_set_to() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _sandboxed = changed_in_context(
        &bed,
        &PLAYBACK_STREAM,
        PLAYBACK,
        "{ channelVolumes: [ 0.3, 0.3 ] }",
    );
    window_in_which_it_would_save();
    assert_eq!(
        levels(&bed, "sandboxed"),
        Levels {
            volume: 0.3,
            mute: false
        }
    );
}

#[test]
fn a_host_streams_volume_is_restored_to_the_next_host_stream_of_its_name() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    save_on_the_host(&bed, &PLAYBACK_STREAM);
    assert_eq!(next_host_levels(&bed, &PLAYBACK_STREAM), SAVED);
}

/// The same for a sink a `devices` context offers and a later host sink
/// of its names.
///
/// The nodes share `application.name`, not `node.name` as a host device
/// does: `pw-cat` and `pw-loopback` both give a node a `media.name` where
/// it has none (measured on PipeWire 1.6.9), and stock keys on that before
/// `node.name`. The hook does not depend on which name forms the key.
#[test]
fn a_host_sink_keeps_its_volume_when_a_devices_contexts_sink_of_its_name_is_turned_down() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    save_on_the_host(&bed, &ROUTELESS_SINK);
    let offered = changed_in_context(
        &bed,
        &ROUTELESS_SINK,
        DEVICES,
        "{ channelVolumes: [ 0.3, 0.3 ] }",
    );
    window_in_which_it_would_save();
    drop(offered);
    assert_eq!(
        next_host_levels(&bed, &ROUTELESS_SINK),
        SAVED,
        "saved:\n{}",
        saved_stream_state(&bed)
    );
}

/// A context's stream turned down after a WirePlumber restart: the rule
/// holds under the WirePlumber started then, which finds the stream
/// already in the graph. Its levels are set once that WirePlumber is up
/// and knows the stream's client.
#[test]
fn a_host_stream_keeps_its_volume_when_a_contexts_stream_is_turned_down_across_a_restart() {
    let Some(mut bed) = PipeWireBed::start() else {
        return;
    };
    save_on_the_host(&bed, &PLAYBACK_STREAM);
    let sandboxed = PLAYBACK_STREAM.in_context(&bed, PLAYBACK, "sandboxed");
    restored(&bed, "sandboxed");
    bed.restart_session_manager();
    set_levels(&bed, "sandboxed", "{ channelVolumes: [ 0.3, 0.3 ] }");
    wait_for("the context's node turned down", || {
        levels(&bed, "sandboxed").volume == 0.3
    });
    window_in_which_it_would_save();
    drop(sandboxed);
    assert_eq!(
        next_host_levels(&bed, &PLAYBACK_STREAM),
        SAVED,
        "saved:\n{}",
        saved_stream_state(&bed)
    );
}

#[test]
fn the_loaded_policy_states_this_bubblers_revision() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    assert_eq!(loaded_revision(&bed), LoadedRevision::Current);
}

#[test]
fn a_hook_that_publishes_no_revision_is_absent() {
    let Some(bed) = bed_with_the_hook_changed(
        r#"ImplMetadata ("bubbler-policy")"#,
        r#"ImplMetadata ("not-bubbler-policy")"#,
    ) else {
        return;
    };
    assert_eq!(loaded_revision(&bed), LoadedRevision::Absent);
}

#[test]
fn a_hook_of_another_revision_names_it() {
    let current = audio_policy::revision();
    let other = current + 1;
    let Some(bed) = bed_with_the_hook_changed(
        &format!("local POLICY_REVISION = {current}\n"),
        &format!("local POLICY_REVISION = {other}\n"),
    ) else {
        return;
    };
    assert_eq!(
        loaded_revision(&bed),
        LoadedRevision::Other(other.to_string())
    );
}

/// A context's attempt to pass for WirePlumber: it claims to be outside any security context, then
/// publishes this bubbler's revision.
const PUBLISH_CURRENT: &str = r#"
Core.update_properties { ["pipewire.sec.engine"] = "org.host" }
published = ImplMetadata ("bubbler-policy")
published:activate (Features.ALL, function (m, e)
  if e then
    print ("not published: " .. tostring (e))
    return
  end
  m:set (0, "revision", "Spa:Int", "REVISION")
  print ("published")
end)
"#;

/// A bed whose hook, like 0.24.1's and older, leaves a context the metadata factory, and whose
/// drop-in leaves it the metadata objects: without both, its own metadata is gone as soon as it is
/// made (PipeWire 1.6.9). The hook's `from` is replaced by `to` as well.
fn bed_that_lets_a_context_publish(from: &str, to: &str) -> Option<PipeWireBed> {
    let factories_hidden = "if name ~= STREAM_FACTORY then";
    let metadata_hidden = r#"metadata.name = "!null""#;
    assert!(HOOK.contains(factories_hidden) && HOOK.contains(from));
    assert!(DROP_IN.contains(metadata_hidden));
    let hook = HOOK
        .replace(
            factories_hidden,
            r#"if name ~= STREAM_FACTORY and name ~= "metadata" then"#,
        )
        .replace(from, to);
    let drop_in = DROP_IN.replace(metadata_hidden, r#"metadata.name = "no-such-metadata""#);
    PipeWireBed::start_with(|dir| {
        std::fs::write(dir.join("data").join(HOOK_IN_DATA_DIR), hook).expect("the changed hook");
        std::fs::write(
            dir.join("wireplumber/wireplumber.conf.d/50-bubbler.conf"),
            drop_in,
        )
        .expect("the changed drop-in");
    })
    .map(|(bed, ())| bed)
}

#[test]
fn a_contexts_policy_metadata_is_not_read_as_wireplumbers() {
    let current = audio_policy::revision();
    let older = current - 1;
    for (from, to, expected) in [
        (
            format!("local POLICY_REVISION = {current}\n"),
            format!("local POLICY_REVISION = {older}\n"),
            LoadedRevision::Other(older.to_string()),
        ),
        (
            r#"ImplMetadata ("bubbler-policy")"#.to_owned(),
            r#"ImplMetadata ("not-bubbler-policy")"#.to_owned(),
            LoadedRevision::Absent,
        ),
    ] {
        let Some(bed) = bed_that_lets_a_context_publish(&from, &to) else {
            return;
        };
        let script = bed.dir().join("publish.lua");
        std::fs::write(
            &script,
            PUBLISH_CURRENT.replace("REVISION", &current.to_string()),
        )
        .expect("the publishing script");
        let log = bed.dir().join("publish.log");
        let _publisher = Streaming(bed.spawn_in_context_logged(
            PLAYBACK,
            &format!(
                "WIREPLUMBER_CONFIG_DIR={} wpexec {}",
                bed.dir().join("wireplumber").display(),
                script.display()
            ),
            Some(&log),
        ));
        let named = "\"metadata.name\": \"bubbler-policy\"";
        let wireplumbers = bed.dump_from_host().matches(named).count();
        wait_for("the context's bubbler-policy in the graph", || {
            bed.dump_from_host().matches(named).count() > wireplumbers
        });
        assert_eq!(
            loaded_revision(&bed),
            expected,
            "{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
    }
}

/// Load generators this test started, stopped and reaped however it ends.
struct Load(Vec<Child>);

impl Drop for Load {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// `pw-metadata` printed no key in 5 of 400 reads under this load (PipeWire 1.6.9).
#[test]
#[ignore = "keeps every core busy, which the tests beside it would feel; run with BUBBLER_TEST_SESSION=1 and --ignored"]
fn the_revision_reads_as_current_every_time_under_cpu_load() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut load = Load(Vec::new());
    for _ in 0..2 * cores {
        match Command::new("yes").stdout(Stdio::null()).spawn() {
            Ok(child) => load.0.push(child),
            Err(e) => {
                say(&format!("skipping: yes did not start: {e}"));
                return;
            }
        }
    }
    let answers: Vec<LoadedRevision> = (0..400).map(|_| loaded_revision(&bed)).collect();
    drop(load);
    let missed: Vec<_> = answers
        .iter()
        .filter(|answer| **answer != LoadedRevision::Current)
        .collect();
    assert!(missed.is_empty(), "{} of 400: {missed:?}", missed.len());
}

/// A context can neither read the revision, nor write it, nor publish a
/// metadata of the same name for bubbler to read instead.
#[test]
fn no_context_sees_or_makes_the_policys_metadata() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    assert_eq!(loaded_revision(&bed), LoadedRevision::Current);
    let named = "\"metadata.name\": \"bubbler-policy\"";
    for (props, grant) in [(PLAYBACK, "playback"), (DEVICES, "playback,devices")] {
        bed.info_in_context(props, &[SINK]);
        let seen = bed.in_context(props, "pw-dump");
        assert!(
            seen.contains("\"node.name\": \"bed-sink\""),
            "a {grant} context's pw-dump listed nothing:\n{seen}"
        );
        assert!(!seen.contains(named), "a {grant} context sees it:\n{seen}");

        let set = bed.output_in_context(props, "pw-metadata -n bubbler-policy 0 revision 0");
        // pw-cli has no command for any type but a node, a device or a
        // link; the core looks the factory up before it checks the type,
        // so a visible metadata factory answers "wrong resource type"
        // (measured from the host on PipeWire 1.6.9) and a hidden one this.
        let made = bed.output_in_context(
            props,
            "pw-cli create-node metadata '{ metadata.name = bubbler-policy, \
             object.linger = true }'",
        );
        assert!(
            String::from_utf8_lossy(&made.stderr).contains("unknown factory name metadata"),
            "a {grant} context was not refused the metadata factory: {made:?}"
        );
        std::thread::sleep(FORBIDDEN_LINK_LIFE);
        assert_eq!(
            bed.dump_from_host().matches(named).count(),
            1,
            "a {grant} context made a second one: {made:?}"
        );
        assert_eq!(
            audio_policy::loaded_revision_asking(
                Path::new(audio_policy::PW_DUMP),
                &bed.dir().join("run")
            ),
            LoadedRevision::Current,
            "a {grant} context changed the revision: {set:?}"
        );
    }
}

// bwrap's own tmpfs as the root, so a file can sit at `/.flatpak-info`
// without touching the host's `/`.
const NESTED_ROOT: &str = "bwrap --unshare-user --die-with-parent \
    --ro-bind /usr /usr --ro-bind /etc /etc --ro-bind-try /bin /bin \
    --ro-bind-try /lib /lib --ro-bind-try /lib64 /lib64 \
    --bind /tmp /tmp --proc /proc --dev /dev";

fn nested(flatpak_info: Option<&Path>, program: &str) -> String {
    let file = flatpak_info
        .map(|file| format!(" --ro-bind {} /.flatpak-info", file.display()))
        .unwrap_or_default();
    format!("{NESTED_ROOT}{file} -- {program}")
}

#[derive(Debug, PartialEq)]
struct Reach {
    properties: Vec<String>,
    view: Vec<String>,
}

struct Measured {
    reach: Reach,
    flatpak_info: Option<String>,
}

// `pw-cli -m` ends at the end of its input, which the test's own stdin may reach.
const MONITOR: &str = "sh -c 'sleep 600 | pw-cli -m'";
const MONITOR_CLIENT: &str = r#"application.name = "pw-cli""#;
const IN_A_CONTEXT: &str = "pipewire.sec.engine";
const DECIDED: &str = "pipewire.access.effective";
const PID: &str = "pipewire.sec.pid = ";
const PER_CONNECTION: [&str; 2] = [PID, "pipewire.sec.socket = "];

// What the daemon would publish had it read a client's `/.flatpak-info`.
const FROM_THE_FILE: [&str; 3] = [
    "pipewire.access.portal.app_id = ",
    "pipewire.access.portal.instance_id = ",
    "pipewire.sec.flatpak = ",
];
const AS_THE_CONTEXT_SET_IT: &str = r#"pipewire.access = "restricted""#;

// The most specific first: a port's `port.alias` names its node too.
const NAMES: [&str; 6] = [
    "port.alias = ",
    "node.name = ",
    "factory.name = ",
    "module.name = ",
    "application.name = ",
    "core.name = ",
];

// The view is a second client's, started the same way: the monitor prints
// nothing that could be read while it runs.
fn measure(
    bed: &PipeWireBed,
    props: &str,
    markers: &[&str],
    wrap: impl Fn(&str) -> String,
) -> Measured {
    let monitor = [CLIENT, MONITOR_CLIENT, IN_A_CONTEXT, DECIDED];
    wait_for("the previous monitor gone", || {
        block(&bed.info_from_host(), &monitor[..3]).is_none()
    });
    let running = Streaming(bed.spawn_in_context(props, &wrap(MONITOR)));
    let mut listing = String::new();
    wait_for("the monitor's access decision", || {
        listing = bed.info_from_host();
        block(&listing, &monitor).is_some()
    });
    let client = block(&listing, &monitor).expect("the monitor");
    let pid = property_lines(client)
        .find_map(|line| line.strip_prefix(PID))
        .expect("the monitor's pid")
        .trim_matches('"');
    let flatpak_info = std::fs::read_to_string(format!("/proc/{pid}/root/.flatpak-info")).ok();
    let mut properties: Vec<String> = property_lines(client)
        .filter(|line| {
            line.starts_with("pipewire.") && !PER_CONNECTION.iter().any(|key| line.starts_with(key))
        })
        .map(str::to_owned)
        .collect();
    properties.sort();
    drop(running);

    let mut seen = String::new();
    wait_for("the client's view of the graph", || {
        seen = bed.in_context(props, &wrap("pw-cli info all"));
        markers
            .iter()
            .all(|marker| object(&seen, &[marker]).is_some())
    });
    let mut view: Vec<String> = blocks(&seen)
        .map(|block| {
            let field = |prefix: &str| {
                property_lines(block)
                    .find_map(|line| line.strip_prefix(prefix))
                    .unwrap_or_default()
                    .to_owned()
            };
            let name = NAMES
                .iter()
                .map(|prefix| field(prefix))
                .find(|name| !name.is_empty())
                .unwrap_or_default();
            format!("{} {name} {}", field("type: "), field("permissions: "))
        })
        .collect();
    view.sort();
    Measured {
        reach: Reach { properties, view },
        flatpak_info,
    }
}

#[test]
fn a_forged_or_hidden_flatpak_info_changes_nothing_a_context_gets() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    if on_path("bwrap").is_none() {
        say("skipping: bwrap not installed");
        return;
    }
    let probe = Command::new("sh")
        .args(["-c", &nested(None, "true")])
        .output()
        .expect("sh did not run");
    if !probe.status.success() {
        say(&format!(
            "skipping: bwrap cannot make the nested namespace on this host: {}",
            String::from_utf8_lossy(&probe.stderr).trim()
        ));
        return;
    }
    let bubblers = bubbler_core::dbus::flatpak_info("bed", true);
    let forged = b"[Application]\nname=org.example.Other\n\n[Instance]\ninstance-id=4242\n";
    let mut files = Vec::new();
    for (name, text) in [("bubblers", &bubblers[..]), ("forged", &forged[..])] {
        let path = bed.dir().join(format!("{name}-flatpak-info"));
        std::fs::write(&path, text).expect("a /.flatpak-info to bind");
        files.push((path, String::from_utf8_lossy(text).into_owned()));
    }

    for (props, markers) in [
        (PLAYBACK, &[SINK][..]),
        (PLAYBACK_MICROPHONE, &[SINK, SOURCE][..]),
    ] {
        let plain = measure(&bed, props, markers, str::to_owned).reach;
        for (case, file) in [
            ("bubbler's file", Some(&files[0])),
            ("a forged file", Some(&files[1])),
            ("no file", None),
        ] {
            let nested_client = measure(&bed, props, markers, |program| {
                nested(file.map(|(path, _)| path.as_path()), program)
            });
            assert_eq!(
                nested_client.flatpak_info.as_ref(),
                file.map(|(_, text)| text),
                "{case}: not what the client's /proc/<pid>/root holds"
            );
            let properties = &nested_client.reach.properties;
            assert!(
                properties.iter().any(|line| line == AS_THE_CONTEXT_SET_IT),
                "{case}: {properties:?}"
            );
            for key in FROM_THE_FILE {
                assert!(
                    !properties.iter().any(|line| line.starts_with(key)),
                    "{case}: the daemon read the file: {properties:?}"
                );
            }
            assert_eq!(nested_client.reach, plain, "{case} under {props}");
        }
    }
}
