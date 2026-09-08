//! The audio policy measured against a real PipeWire.
//!
//! Every test here runs against a private PipeWire and WirePlumber pair
//! started for it and torn down with it. Nothing touches the session's
//! audio: the bed's daemons listen in their own runtime directory, the
//! bed's WirePlumber loads a profile with every hardware monitor
//! disabled, and the bed's PipeWire loads no device factory, so the
//! graph holds one null sink and one null source and nothing else.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use tempfile::TempDir;

/// The policy drop-in as it is shipped, loaded by the bed's WirePlumber
/// from the bed's own config directory. The tests below are what says
/// whether the shipped file grants what it promises.
const DROP_IN: &str = include_str!("../../../contrib/wireplumber/50-bubbler.conf");

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
const NEEDED: [&str; 6] = [
    "pipewire",
    "wireplumber",
    "pw-container",
    "pw-dump",
    "pw-cat",
    "pw-link",
];

/// A security context's properties as bubbler will set them for a
/// `pipewire` grant with no `microphone` child.
pub const PLAYBACK: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "bubbler.audio": "playback" }"#;

/// The same with the `microphone` child.
pub const PLAYBACK_MICROPHONE: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "bubbler.audio": "playback,microphone" }"#;

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

/// A private PipeWire and WirePlumber pair, with the shipped policy
/// drop-in loaded, and the handles to drive it.
pub struct PipeWireBed {
    /// Killed before `dir` is removed: the fields drop in declaration
    /// order, and a daemon still running when its runtime directory goes
    /// would recreate parts of it.
    pipewire: Child,
    wireplumber: Child,
    dir: TempDir,
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
        let dir = TempDir::with_prefix("bubbler-bed-").expect("a temporary directory");
        // `sockaddr_un.sun_path` is 108 bytes including the terminator,
        // and the daemon refuses to listen on a longer path. A build
        // whose `TMPDIR` is deep enough to break that gets a skip rather
        // than a failure nobody can act on.
        let socket = dir.path().join("run").join("pipewire-0-manager");
        if socket.as_os_str().len() >= 108 {
            say(&format!(
                "skipping: {} is too long for a unix socket",
                socket.display()
            ));
            return None;
        }
        Some(Self::start_in(dir))
    }

    fn start_in(dir: TempDir) -> PipeWireBed {
        let root = dir.path();
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
        self.dir.path()
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
        command.env("PIPEWIRE_RUNTIME_DIR", self.dir.path().join("run"));
        command
    }

    /// `program`, run in a PipeWire security context carrying `props`,
    /// with its output captured.
    ///
    /// `pw-container` takes a single program argument and hands it to
    /// `system()`, dropping anything further on its command line, so
    /// `program` must be one shell word — a bare tool name here.
    pub fn in_context(&self, props: &str, program: &str) -> String {
        let out = self
            .context_command(props, program)
            .output()
            .expect("pw-container did not run");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        text
    }

    /// The same, left running for the caller to watch the graph while it
    /// is up.
    pub fn spawn_in_context(&self, props: &str, program: &str) -> Child {
        let mut command = self.context_command(props, program);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        // Its own process group, so the whole context can be signalled
        // at once. `pw-container` sits inside `system()` while the
        // program runs and only removes its socket once that returns,
        // so a signal to `pw-container` alone would leave the socket in
        // `/tmp` for ever.
        //
        // SAFETY: the closure runs in the child between fork and exec,
        // where only async-signal-safe work is allowed; `setpgid` is a
        // bare syscall that allocates nothing and takes no lock.
        unsafe {
            command.pre_exec(|| rustix::process::setpgid(None, None).map_err(Into::into));
        }
        command.spawn().expect("pw-container did not run")
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
    }
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
        .stderr(err)
        .spawn()
        .unwrap_or_else(|e| panic!("{command:?} did not run: {e}"))
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

#[test]
fn a_playback_context_sees_no_source_no_other_stream_and_no_metadata() {
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
    assert!(!seen.contains("\"media.class\": \"Stream/"), "{seen}");
    // `metadata.name` is on the metadata objects and on nothing else;
    // the interface name is also the metadata *factory*'s type, which
    // the sandbox may keep seeing.
    assert!(!seen.contains("\"metadata.name\""), "{seen}");
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
    // The stream is in the graph; give the session manager the rescan it
    // would need to link it before asking whether it did.
    std::thread::sleep(Duration::from_secs(2));
    let links = bed.links();
    assert!(
        !links.contains("bed-source"),
        "a playback-only context captured from the null source:\n{links}"
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
fn a_context_that_is_not_bubblers_keeps_the_reach_it_had() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    // `pw-container`'s own defaults: `org.flatpak`, no `bubbler.audio`.
    // The drop-in must not narrow a context it did not create.
    let seen = bed.in_context("{}", "pw-dump");
    assert!(seen.contains("\"node.name\": \"bed-sink\""), "{seen}");
    assert!(seen.contains("\"node.name\": \"bed-source\""), "{seen}");
}
