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

/// PipeWire's stock client configuration, which a client pointed at a
/// `PIPEWIRE_CONFIG_DIR` of its own needs beside its drop-ins in the
/// same way.
const PIPEWIRE_CLIENT_CONF: &str = "/usr/share/pipewire/client.conf";

/// Everything the bed shells out to, in the order a missing one is
/// worth reporting.
const NEEDED: [&str; 11] = [
    "pipewire",
    "wireplumber",
    "pw-container",
    "pw-dump",
    "pw-cli",
    "pw-cat",
    "pw-link",
    "pw-metadata",
    "pactl",
    "paplay",
    "parecord",
];

/// A security context's properties as bubbler will set them for a
/// `pipewire` grant with no `microphone` child.
pub const PLAYBACK: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback" }"#;

/// The same with the `microphone` child.
pub const PLAYBACK_MICROPHONE: &str = r#"{ "pipewire.sec.engine": "org.bubbler", "pipewire.sec.app-id": "bed", "pipewire.sec.instance-id": "t1", "pipewire.access": "restricted", "pipewire.sec.bubbler.audio": "playback,microphone" }"#;

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

/// What ends a bed's processes when its test binary goes, however it
/// goes: it waits for the end of a pipe only the test holds, then kills
/// every process `processes_of` would find. A death signal reaches only
/// a direct child, and a program under `pw-container` is a grandchild
/// that need not end with the bed's daemon (the pulse server does not,
/// measured); one process group for the bed would do as much, but each
/// `Streaming` has a group of its own so that a test can stop it alone.
const SUPERVISOR: &str = r#"
trap '' INT TERM HUP QUIT
read -r _
for _ in 1 2 3 4 5 6 7 8 9 10; do
  left=
  for p in /proc/[0-9]*; do
    if grep -qsF -- "$1/" "$p/environ"; then
      kill -KILL "${p#/proc/}" 2>/dev/null && left=1
    fi
  done
  [ -z "$left" ] && exit 0
  sleep 0.1
done
"#;

/// The bed's supervisor, in a group of its own so that a terminal's
/// `^C` to the test does not end it before it has done its work.
fn supervisor(dir: &Path) -> Child {
    Command::new("sh")
        .args(["-c", SUPERVISOR, "sh"])
        .arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("the bed's supervisor")
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
    supervisor: Child,
    dir: PathBuf,
}

impl PipeWireBed {
    /// A running bed, or `None` (having said which binary is missing)
    /// on a host that cannot hold one.
    pub fn start() -> Option<PipeWireBed> {
        Self::start_with(|_| ()).map(|(bed, ())| bed)
    }

    /// The same, with `before_session_manager` run against the bed's
    /// directory once its PipeWire listens and before its WirePlumber
    /// starts, and what it returned.
    fn start_with<T>(before_session_manager: impl FnOnce(&Path) -> T) -> Option<(PipeWireBed, T)> {
        for binary in NEEDED {
            if on_path(binary).is_none() {
                say(&format!("skipping: {binary} not installed"));
                return None;
            }
        }
        for conf in [WIREPLUMBER_MAIN_CONF, PIPEWIRE_CLIENT_CONF] {
            if !Path::new(conf).is_file() {
                say(&format!("skipping: {conf} not installed"));
                return None;
            }
        }
        sweep_stale_beds();
        Some(Self::start_in(new_bed_dir(), before_session_manager))
    }

    fn start_in<T>(
        dir: PathBuf,
        before_session_manager: impl FnOnce(&Path) -> T,
    ) -> (PipeWireBed, T) {
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

        let supervisor = supervisor(&dir);
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
        let early = before_session_manager(&dir);

        let wireplumber = daemon(
            Command::new("wireplumber")
                .args(["-p", "bubbler-bed"])
                .env("PIPEWIRE_RUNTIME_DIR", &run)
                .env("WIREPLUMBER_CONFIG_DIR", &wp)
                .env("XDG_DATA_HOME", &data)
                .env("XDG_STATE_HOME", root.join("state"))
                // Info for the linking scripts' topic, where the hook logs
                // each link it refuses (`links_refused`); the default level
                // everywhere else.
                .env("WIREPLUMBER_DEBUG", "2,s-linking:I"),
            &root.join("wireplumber.log"),
        );
        let bed = PipeWireBed {
            pipewire,
            wireplumber,
            supervisor,
            dir,
        };
        // WirePlumber registers itself as a client before it applies any
        // policy, so the bed is only ready once its session manager is
        // in the graph; a context opened before that gets the daemon's
        // own permissions instead of the drop-in's.
        wait_for("the bed's wireplumber", || {
            bed.dump_from_host().contains("\"wireplumber.daemon\"")
        });
        (bed, early)
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
        drop(self.supervisor.stdin.take());
        let _ = self.supervisor.wait();
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
/// update after that.
const CLAIM: &str = r#"{ "bubbler.audio": "playback,microphone", "pipewire.sec.bubbler.audio": "playback,microphone" }"#;

/// What `wpexec` runs to claim the microphone once connected and then
/// open a capture stream of its own.
const CLAIM_LATER: &str = r#"
Core.update_properties {
  ["bubbler.audio"] = "playback,microphone",
  ["pipewire.sec.bubbler.audio"] = "playback,microphone",
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
    let Some((_bed, (_early, log))) = started else {
        return;
    };
    let mut listed = String::new();
    wait_for("the early client's factory list", || {
        listed = std::fs::read_to_string(&log).unwrap_or_default();
        listed.contains("listed")
    });
    assert!(
        listed.contains("factory client-node") && !listed.contains("factory link-factory"),
        "a context connected before the session manager sees:\n{listed}"
    );
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
fn holding_a_link(mut command: Command, link: &str) -> Streaming {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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

    let _host = host_stream(&bed, host);
    wait_for("a link for the host's stream", || {
        bed.links().contains("host:")
    });
    // Long enough for a default decided again after the first link to
    // have moved the stream.
    std::thread::sleep(FORBIDDEN_LINK_LIFE);
    let links = bed.links();
    let defaults = bed.host_tool("pw-metadata", &["-n", "default"]);
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

/// A context offers a sink named after a host device that is not there.
/// A host stream pinned to that device with `node.dont-fallback` is what
/// WirePlumber leaves unlinked when its device is missing
/// (linking/find-defined-target.lua destroys it with an error), so it is
/// neither played into the sandbox's sink nor sent to the default.
#[test]
fn a_pinned_host_stream_does_not_fall_back_from_a_sink_a_context_names_after_its_device() {
    let Some(bed) = PipeWireBed::start() else {
        return;
    };
    let _offered = Streaming(bed.spawn_in_context(
        PLAYBACK,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = bed-headset }' /dev/null",
    ));
    wait_for("the context's sink", || {
        bed.dump_from_host()
            .contains("\"node.name\": \"bed-headset\"")
    });
    window_in_which_it_would_link(&bed, "playback");

    let watched = LinkMonitor::start(&bed);
    let mut host = host_stream(
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
    wait_for("the end of the pinned host stream", || {
        matches!(host.0.try_wait(), Ok(Some(_)))
    });
    // The host stream is the only thing in the graph that could be
    // linked.
    let seen = watched.seen();
    assert!(
        !seen.contains("|->"),
        "a pinned host stream was linked:\n{seen}"
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

/// A host stream aimed at a sink a context offers goes where a stream
/// with no target goes: through the host's own smart filter, as a stream
/// sent to the default by linking/find-default-target is.
#[test]
fn a_host_stream_aimed_at_a_sink_a_context_offers_passes_through_the_hosts_filter() {
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
    let _plain = host_stream(&bed, &["-p", "-a", "-P", "{ node.name = plain }", "-"]);
    wait_for("a stream with no target in the host's filter", || {
        peers(&bed.links(), "plain:output_FL").contains(&"host-filter:playback_FL")
    });
    let defaults = bed.host_tool("pw-metadata", &["-n", "default", "0"]);
    assert!(
        defaults.contains("'default.audio.sink' value:'{\"name\":\"bed-sink\"}'"),
        "the filter took the default, so a stream sent there says nothing:\n{defaults}"
    );

    let _offered = Streaming(bed.spawn_in_context(
        PLAYBACK,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered }' /dev/null",
    ));
    wait_for("the context's sink", || {
        bed.dump_from_host().contains("\"node.name\": \"offered\"")
    });
    window_in_which_it_would_link(&bed, "playback");
    wait_for("the filter's own stream on the sink", || {
        peers(&bed.links(), "host-filter-out:output_FL").contains(&"bed-sink:playback_FL")
    });
    let watched = LinkMonitor::start(&bed);
    let _host = host_stream(
        &bed,
        &[
            "-p",
            "-a",
            "--target=offered",
            "-P",
            "{ node.name = host }",
            "-",
        ],
    );
    wait_for("a link for the host's stream", || {
        !peers(&bed.links(), "host:output_FL").is_empty()
    });
    std::thread::sleep(FORBIDDEN_LINK_LIFE);
    let links = bed.links();
    assert_eq!(
        peers(&links, "host:output_FL"),
        ["host-filter:playback_FL"],
        "a host stream sent away from a context's sink missed the host's filter:\n{links}"
    );
    // Every other link was up before the monitor started, so a link to
    // the sink after the host's ports appeared is the host stream's,
    // however briefly it lived.
    let seen = watched.seen();
    let since_the_host = seen.split_once("+host:").map_or("", |(_, after)| after);
    assert!(
        !since_the_host.contains("|-> bed-sink:"),
        "a host stream was played past the host's filter first:\n{seen}"
    );
}

/// A context's smart filter with the host filter's target is put after
/// it in WirePlumber's chain, so the host filter's own stream is aimed at
/// the sandbox's filter: it must still play on the sink, not be sent back
/// into the host filter, which no link can reach.
#[test]
fn a_host_filters_own_stream_plays_on_past_a_smart_filter_a_context_offers_after_it() {
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

    let _offered = Streaming(bed.spawn_in_context(
        PLAYBACK,
        "pw-cat -r -a -P '{ media.class = Audio/Sink, node.name = offered, \
         node.link-group = sandbox-filter, filter.smart = true, \
         filter.smart.name = sandbox-filter, \
         filter.smart.target = { node.name = bed-sink } }' /dev/null",
    ));
    let _offered_out = Streaming(bed.spawn_in_context(
        PLAYBACK,
        "pw-cat -p -a -P '{ node.name = offered-out, \
         node.link-group = sandbox-filter }' - < /dev/zero",
    ));
    wait_for("the context's filter on the sink", || {
        peers(&bed.links(), "offered-out:output_FL").contains(&"bed-sink:playback_FL")
    });
    window_in_which_it_would_link(&bed, "playback");
    std::thread::sleep(FORBIDDEN_LINK_LIFE);
    let links = bed.links();
    assert_eq!(
        peers(&links, "host-filter-out:output_FL"),
        ["bed-sink:playback_FL"],
        "the host filter's own stream left the sink for a context's filter:\n{links}"
    );
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
