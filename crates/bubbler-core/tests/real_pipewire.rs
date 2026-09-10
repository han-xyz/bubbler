//! The audio policy measured against a real PipeWire.
//!
//! Every test here runs against a private PipeWire and WirePlumber pair
//! started for it and torn down with it. Nothing touches the session's
//! audio: the bed's daemons listen in their own runtime directory, the
//! bed's WirePlumber loads a profile with every hardware monitor
//! disabled, and the bed's PipeWire loads no device factory, so the
//! graph holds one null sink and one null source and nothing else.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{
    Pid, Signal, kill_process, kill_process_group, set_parent_process_death_signal,
};

use bubbler_core::host::RealHost;
use bubbler_core::pipewire::{
    PIPEWIRE, PULSE_CONF, PULSE_DROP_IN, PULSE_NATIVE, PULSE_OVERRIDE, PULSE_SOCKET_INSIDE,
    pulse_conf,
};

/// The policy drop-in as it is shipped, loaded by the bed's WirePlumber
/// from the bed's own config directory. The tests below are what says
/// whether the shipped file grants what it promises.
const DROP_IN: &str = include_str!("../../../contrib/wireplumber/50-bubbler.conf");

/// The linking hook that drop-in loads, likewise as it is shipped.
const HOOK: &str = include_str!("../../../contrib/wireplumber/scripts/bubbler/refuse-links.lua");

/// Where the hook goes for the bed's WirePlumber to find it: script
/// lookup is the data-directory search (`WP_BASE_DIRS_DATA`), which
/// `XDG_DATA_HOME` joins without replacing, so the stock scripts still
/// come from the system's own directory.
const HOOK_IN_DATA_DIR: &str = "wireplumber/scripts/bubbler/refuse-links.lua";

/// The bed's PipeWire: the protocol, the client-node and adapter
/// factories, the metadata factory WirePlumber needs, and two null
/// nodes. No ALSA, no udev, no RTKit, no pulse, no JACK.
///
/// `libpipewire-module-access` is not optional: without it a connecting
/// client is left flagged busy for ever and every request against the
/// daemon hangs (measured on PipeWire 1.6.8).
const PIPEWIRE_CONF: &str = r#"
context.properties = {
    core.daemon = true
    core.name   = pipewire-0
    link.max-buffers = 16
    support.dbus = false
}
context.spa-libs = {
    audio.convert.* = audioconvert/libspa-audioconvert
    audio.adapt     = audioconvert/libspa-audioconvert
    support.*       = support/libspa-support
}
context.modules = [
    { name = libpipewire-module-protocol-native }
    { name = libpipewire-module-metadata }
    { name = libpipewire-module-spa-node-factory }
    { name = libpipewire-module-access }
    { name = libpipewire-module-client-node }
    { name = libpipewire-module-adapter }
    { name = libpipewire-module-link-factory }
]
context.objects = [
    { factory = spa-node-factory
        args = {
            factory.name    = support.node.driver
            node.name       = Dummy-Driver
            node.group      = pipewire.dummy
            priority.driver = 20000
        }
    }
    { factory = adapter
        args = {
            factory.name     = support.null-audio-sink
            node.name        = "bed-sink"
            node.description = "Bed Null Sink"
            media.class      = "Audio/Sink"
            audio.position   = "FL,FR"
            object.linger    = true
        }
    }
    { factory = adapter
        args = {
            factory.name     = support.null-audio-sink
            node.name        = "bed-source"
            node.description = "Bed Null Source"
            media.class      = "Audio/Source"
            audio.position   = "FL,FR"
            monitor.passthrough = true
            object.linger    = true
        }
    }
]
"#;

/// The bed's WirePlumber profile. It inherits `base` and the standard
/// policy rather than `main`, so no `hardware.*` feature is required in
/// the first place, and then names every monitor `disabled` so a
/// future profile change cannot pull the host's cards in behind it.
const BED_PROFILE: &str = r#"
wireplumber.profiles = {
  bubbler-bed = {
    inherits = [ base ]

    metadata.sm-settings = required
    metadata.sm-objects = required
    policy.standard = required

    hardware.audio = disabled
    hardware.bluetooth = disabled
    hardware.video-capture = disabled
    monitor.alsa = disabled
    monitor.alsa-midi = disabled
    monitor.bluez = disabled
    monitor.bluez-midi = disabled
    monitor.v4l2 = disabled
    monitor.libcamera = disabled
    support.dbus = disabled
    support.logind = disabled
    support.mpris = disabled
    support.reserve-device = disabled
    support.portal-permissionstore = disabled
    script.client.access-portal = disabled
  }
}
"#;

/// WirePlumber's stock configuration, which `WIREPLUMBER_CONFIG_DIR`
/// replaces rather than extends: pointed at the bed's directory,
/// WirePlumber finds no main file at all and starts with no modules, so
/// the bed copies this one in beside its own drop-ins.
const WIREPLUMBER_MAIN_CONF: &str = "/usr/share/wireplumber/wireplumber.conf";

/// Everything the bed shells out to, in the order a missing one is
/// worth reporting.
const NEEDED: [&str; 10] = [
    "pipewire",
    "wireplumber",
    "pw-container",
    "pw-dump",
    "pw-cli",
    "pw-cat",
    "pw-link",
    "pactl",
    "paplay",
    "parecord",
];

/// A security context's properties as bubbler will set them for a
/// `pipewire` grant with no `microphone` child.
pub const PLAYBACK: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "bubbler.audio": "playback" }"#;

/// The same with the `microphone` child.
pub const PLAYBACK_MICROPHONE: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "bubbler.audio": "playback,microphone" }"#;

/// A grant string the drop-in does not know, as a future bubbler or a
/// typo could produce.
pub const BOGUS_GRANT: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.access": "restricted", "bubbler.audio": "bogus" }"#;

/// A bubbler context with the grant key missing altogether.
pub const NO_GRANT: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.access": "restricted" }"#;

/// Markers naming the bed's two nodes in a `pw-cli info all` listing.
const SINK: &str = r#"node.name = "bed-sink""#;
const SOURCE: &str = r#"node.name = "bed-source""#;

/// The same for a playing client's stream node, which is another
/// client's audio as the graph carries it.
const STREAM: &str = r#"media.class = "Stream/Output/Audio""#;

/// Say why a test is being skipped where a plain `cargo test` will show
/// it. Written to descriptor 2 rather than through `eprintln!`: libtest
/// captures the Rust-side handle until a test fails, and a skip nobody
/// sees is a skip nobody acts on.
fn say(line: &str) {
    let text = format!("{line}\n");
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        match rustix::io::write(rustix::stdio::stderr(), rest) {
            Ok(0) | Err(_) => return,
            Ok(n) => rest = &rest[n..],
        }
    }
}

/// The first `PATH` entry that holds an executable named `name`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
        .unwrap_or_default()
}

/// Where a bed's directory goes. Not `TMPDIR`: `sockaddr_un.sun_path`
/// holds 108 bytes and the daemon refuses to listen on a longer path,
/// and `pw-container` puts its own socket under `/tmp` whatever the
/// environment says, so a bed elsewhere would gain nothing and could
/// only be too deep.
const BEDS: &str = "/tmp";

/// Prefix of a bed directory. The rest is the owning process's pid and a
/// counter, so a stale one can be told from a live one.
const BED_PREFIX: &str = "bubbler-bed-";

/// A fresh bed directory named after this process, so what is left over
/// after an abnormal end can be attributed and swept.
fn new_bed_dir() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nth = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = Path::new(BEDS).join(format!("{BED_PREFIX}{}.{nth}", std::process::id()));
    std::fs::create_dir(&dir).expect("a bed directory of this run's own");
    dir
}

/// Remove the bed directories of runs that are gone.
///
/// `Drop` removes a bed's own directory, but a `SIGKILL` on the test
/// binary — a CI timeout, an OOM kill, a developer's `kill -9` — runs no
/// destructor, and the leftovers would accumulate in `/tmp` unnoticed.
fn sweep_stale_beds() {
    let Ok(entries) = std::fs::read_dir(BEDS) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name
            .to_string_lossy()
            .strip_prefix(BED_PREFIX)
            .map(str::to_owned)
        else {
            continue;
        };
        let owner = rest.split('.').next().unwrap_or_default().to_owned();
        if owner.is_empty() || Path::new("/proc").join(&owner).exists() {
            continue;
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

/// A private PipeWire and WirePlumber pair, with the shipped policy
/// drop-in loaded, and the handles to drive it.
pub struct PipeWireBed {
    pipewire: Child,
    wireplumber: Child,
    dir: PathBuf,
}

impl PipeWireBed {
    /// A running bed, or `None` (having said which binary is missing)
    /// on a host that cannot hold one.
    pub fn start() -> Option<PipeWireBed> {
        for binary in NEEDED {
            if on_path(binary).is_none() {
                say(&format!("skipping: {binary} not installed"));
                return None;
            }
        }
        if !Path::new(WIREPLUMBER_MAIN_CONF).is_file() {
            say(&format!("skipping: {WIREPLUMBER_MAIN_CONF} not installed"));
            return None;
        }
        sweep_stale_beds();
        Some(Self::start_in(new_bed_dir()))
    }

    fn start_in(dir: PathBuf) -> PipeWireBed {
        let root = dir.clone();
        let run = root.join("run");
        let pw = root.join("pipewire");
        let wp = root.join("wireplumber");
        std::fs::create_dir_all(&run).expect("the bed's runtime directory");
        std::fs::create_dir_all(&pw).expect("the bed's pipewire config directory");
        std::fs::create_dir_all(wp.join("wireplumber.conf.d"))
            .expect("the bed's wireplumber config directory");
        std::fs::write(pw.join("pipewire.conf"), PIPEWIRE_CONF).expect("the bed's pipewire.conf");
        std::fs::copy(WIREPLUMBER_MAIN_CONF, wp.join("wireplumber.conf"))
            .expect("a copy of the stock wireplumber.conf");
        std::fs::write(wp.join("wireplumber.conf.d/00-bed.conf"), BED_PROFILE)
            .expect("the bed's wireplumber profile");
        std::fs::write(wp.join("wireplumber.conf.d/50-bubbler.conf"), DROP_IN)
            .expect("the policy drop-in");
        let data = root.join("data");
        let hook = data.join(HOOK_IN_DATA_DIR);
        std::fs::create_dir_all(hook.parent().expect("a script directory"))
            .expect("the bed's script directory");
        std::fs::write(&hook, HOOK).expect("the policy's linking hook");

        let pipewire = daemon(
            Command::new("pipewire")
                .arg("-c")
                .arg("pipewire.conf")
                .env("PIPEWIRE_RUNTIME_DIR", &run)
                .env("PIPEWIRE_CONFIG_DIR", &pw),
            &root.join("pipewire.log"),
        );
        wait_for("the bed's pipewire socket", || {
            run.join("pipewire-0").exists()
        });

        let wireplumber = daemon(
            Command::new("wireplumber")
                .args(["-p", "bubbler-bed"])
                .env("PIPEWIRE_RUNTIME_DIR", &run)
                .env("WIREPLUMBER_CONFIG_DIR", &wp)
                .env("XDG_DATA_HOME", &data)
                .env("XDG_STATE_HOME", root.join("state")),
            &root.join("wireplumber.log"),
        );
        let bed = PipeWireBed {
            pipewire,
            wireplumber,
            dir,
        };
        // WirePlumber registers itself as a client before it applies any
        // policy, so the bed is only ready once its session manager is
        // in the graph; a context opened before that gets the daemon's
        // own permissions instead of the drop-in's.
        wait_for("the bed's wireplumber", || {
            bed.dump_from_host().contains("\"wireplumber.daemon\"")
        });
        bed
    }

    /// The bed's directory, so a test can look for it after the drop.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The two daemons' pids, for the same reason.
    pub fn daemon_pids(&self) -> [u32; 2] {
        [self.pipewire.id(), self.wireplumber.id()]
    }

    /// `pw-dump` run against the bed from outside any security context:
    /// the whole graph, as the session manager sees it.
    pub fn dump_from_host(&self) -> String {
        self.host_tool("pw-dump", &[])
    }

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

    fn host_tool(&self, program: &str, args: &[&str]) -> String {
        let out = self
            .command(program)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("{program} did not run: {e}"));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A command pointed at the bed and at nothing else.
    pub fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.env("PIPEWIRE_RUNTIME_DIR", self.dir.join("run"));
        command
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

    fn context_command(&self, props: &str, program: &str) -> Command {
        let mut command = self.command("pw-container");
        command.arg("-P").arg(props).arg("--").arg(program);
        command
    }
}

impl Drop for PipeWireBed {
    fn drop(&mut self) {
        for child in [&mut self.wireplumber, &mut self.pipewire] {
            // SIGTERM first: PipeWire and WirePlumber both unlink their
            // sockets on it, and a SIGKILL would leave them in the
            // directory `dir` is about to remove.
            let pid = Pid::from_raw(child.id() as i32).expect("a live child");
            let _ = kill_process(pid, Signal::TERM);
            wait_or_kill(child);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
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

/// Ask the kernel to `SIGKILL` this process when the thread that forked
/// it goes.
///
/// `Drop` covers a normal end; this covers the rest. libtest gives each
/// test its own thread and `PipeWireBed::start` is called from the test
/// body, so the death signal is armed against the thread that owns the
/// bed — which also ends when the process is killed.
fn dies_with_this_thread() -> std::io::Result<()> {
    set_parent_process_death_signal(Some(Signal::KILL)).map_err(Into::into)
}

/// Reap a child that has been asked to stop, and stop insisting: a
/// SIGKILL after two seconds, so a wedged daemon fails the test it is
/// in rather than the whole run.
fn wait_or_kill(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

/// Spawn a daemon with its output in `log`, so a failure to start can be
/// read after the fact.
fn daemon(command: &mut Command, log: &Path) -> Child {
    let out = std::fs::File::create(log).expect("a daemon log");
    let err = out.try_clone().expect("a second handle on the daemon log");
    command
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("DISPLAY")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    // SAFETY: the closure runs in the child between fork and exec, where
    // only async-signal-safe work is allowed; `prctl` is a bare syscall
    // that allocates nothing and takes no lock.
    unsafe {
        command.pre_exec(dies_with_this_thread);
    }
    command
        .spawn()
        .unwrap_or_else(|e| panic!("{command:?} did not run: {e}"))
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
    let listing = format!("\n{listing}");
    let block = listing
        .split("\n\tid: ")
        .skip(1)
        .find(|block| markers.iter().all(|marker| block.contains(marker)))?;
    Some(Object {
        id: block.lines().next()?.to_owned(),
        permissions: block
            .lines()
            .find_map(|line| line.trim().strip_prefix("permissions: "))?
            .to_owned(),
        // A property line is printed with a leading `*` when the value
        // has changed since the last listing, so the name is not at the
        // start of what `trim` leaves.
        serial: block
            .lines()
            .find_map(|line| {
                line.trim()
                    .trim_start_matches('*')
                    .trim_start()
                    .strip_prefix("object.serial = \"")
            })
            .map(|serial| serial.trim_end_matches('"').to_owned()),
    })
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

/// Poll `ready` until it holds, or fail the test naming what never came.
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{what} never came up");
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
    let decided = format!("bubbler.audio = \"{grant}\"");
    wait_for("the capture client's access decision", || {
        object(
            &bed.info_from_host(),
            &[&decided, "pipewire.access.effective"],
        )
        .is_some()
    });
    std::thread::sleep(Duration::from_secs(2));
}

#[test]
fn a_playback_context_sees_no_source_no_metadata_and_only_reads_streams() {
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

    let seen = bed.in_context(PLAYBACK, "pw-dump");
    assert!(seen.contains("\"node.name\": \"bed-sink\""), "{seen}");
    assert!(!seen.contains("\"node.name\": \"bed-source\""), "{seen}");
    // `metadata.name` is on the metadata objects and on nothing else;
    // the interface name is also the metadata *factory*'s type, which
    // the sandbox may keep seeing.
    assert!(!seen.contains("\"metadata.name\""), "{seen}");

    let listing = bed.info_in_context(PLAYBACK, &[SINK, STREAM]);
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
    let wav = bed.dir().join("tone.wav");
    silence(&wav);
    for (props, grant) in [
        (PLAYBACK, "playback"),
        (PLAYBACK_MICROPHONE, "playback,microphone"),
    ] {
        let _other = streaming(
            &bed,
            PLAYBACK,
            &format!("pw-cat -p {}", wav.display()),
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
            let refused =
                bed.output_in_context(props, &format!("pw-link -L {source} pw-record:input_FL"));
            // `pw-link` exits 0 whatever the daemon answers (measured),
            // so what it was told is on its stderr and the graph below
            // is the rest of the measurement.
            assert!(
                String::from_utf8_lossy(&refused.stderr).contains("failed to link ports"),
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
    // `pw-container`'s own defaults: `org.flatpak`, no `bubbler.audio`.
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
            "on {marker}: {} is narrowed to what the drop-in's managers give\n{listing}",
            node.permissions
        );
    }
}
