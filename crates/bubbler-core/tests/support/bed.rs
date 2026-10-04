// A private PipeWire and WirePlumber pair, `include!`d by `real_pipewire.rs` and by the bubbler
// crate's `tests/common`.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process, set_parent_process_death_signal};

use bubbler_core::audio_policy::{self, LoadedRevision};

/// The policy drop-in as it is shipped, loaded by the bed's WirePlumber
/// from the bed's own config directory. The tests below are what says
/// whether the shipped file grants what it promises.
const DROP_IN: &str = include_str!("../../../../contrib/wireplumber/50-bubbler.conf");

/// The linking hook that drop-in loads, likewise as it is shipped.
const HOOK: &str = include_str!("../../../../contrib/wireplumber/scripts/bubbler/refuse-links.lua");

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
    /// A running bed, or `None` (having said why) on a run that did not
    /// opt in or a host that cannot hold one.
    pub fn start() -> Option<PipeWireBed> {
        Self::start_with(|_| ()).map(|(bed, ())| bed)
    }

    /// The same, with `before_session_manager` run against the bed's
    /// directory once its PipeWire listens and before its WirePlumber
    /// starts, and what it returned.
    pub fn start_with<T>(
        before_session_manager: impl FnOnce(&Path) -> T,
    ) -> Option<(PipeWireBed, T)> {
        if !session_tests_wanted() {
            say(
                "skipping: set BUBBLER_TEST_SESSION=1 to run tests that reach the session or start audio daemons",
            );
            return None;
        }
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

        let bed = PipeWireBed {
            pipewire,
            wireplumber: session_manager(&root),
            supervisor,
            dir,
        };
        bed.wait_for_the_session_manager();
        (bed, early)
    }

    /// WirePlumber registers itself as a client before it applies any
    /// policy, so the bed is only ready once its session manager is in
    /// the graph; a context opened before that gets the daemon's own
    /// permissions instead of the drop-in's.
    fn wait_for_the_session_manager(&self) {
        wait_for("the bed's wireplumber", || {
            self.dump_from_host().contains("\"wireplumber.daemon\"")
        });
    }

    /// Stop the bed's WirePlumber and start it again, as a user's session
    /// does on a restart: everything already in the graph is new to it.
    fn restart_session_manager(&mut self) {
        let pid = Pid::from_raw(self.wireplumber.id() as i32).expect("a live child");
        let _ = kill_process(pid, Signal::TERM);
        wait_or_kill(&mut self.wireplumber);
        wait_for("the bed's wireplumber gone", || {
            !self.dump_from_host().contains("\"wireplumber.daemon\"")
        });
        self.wireplumber = session_manager(&self.dir);
        self.wait_for_the_session_manager();
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

/// The bed's WirePlumber, over the bed in `root`, logging to
/// `wireplumber.log` there.
fn session_manager(root: &Path) -> Child {
    let data = root.join("data");
    daemon(
        Command::new("wireplumber")
            .args(["-p", "bubbler-bed"])
            .env("PIPEWIRE_RUNTIME_DIR", root.join("run"))
            .env("WIREPLUMBER_CONFIG_DIR", root.join("wireplumber"))
            .env("XDG_DATA_HOME", &data)
            .env("XDG_STATE_HOME", root.join("state"))
            // Info for the linking scripts' topic, where the hook logs
            // each link it refuses (`links_refused`); the default level
            // everywhere else.
            .env("WIREPLUMBER_DEBUG", "2,s-linking:I"),
        &root.join("wireplumber.log"),
    )
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

/// Whether `BUBBLER_TEST_SESSION=1` asks for the tests that start audio daemons.
fn session_tests_wanted() -> bool {
    std::env::var_os("BUBBLER_TEST_SESSION").is_some_and(|value| value == "1")
}

/// What the bed's WirePlumber answers once the hook it loaded has had the
/// time to publish its revision. A bound, not a proof, as
/// `window_in_which_it_would_link` is: nothing announces a metadata that
/// is never published.
pub fn loaded_revision(bed: &PipeWireBed) -> LoadedRevision {
    let run = bed.dir().join("run");
    let mut answer = audio_policy::loaded_revision_asking(Path::new(audio_policy::PW_METADATA), &run);
    let deadline = Instant::now() + Duration::from_secs(2);
    while answer == LoadedRevision::Absent && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        answer = audio_policy::loaded_revision_asking(Path::new(audio_policy::PW_METADATA), &run);
    }
    answer
}

/// A bed whose hook is the shipped one with `from` replaced by `to`.
pub fn bed_with_the_hook_changed(from: &str, to: &str) -> Option<PipeWireBed> {
    assert!(HOOK.contains(from), "the hook holds no {from:?}");
    PipeWireBed::start_with(|dir| {
        std::fs::write(
            dir.join("data").join(HOOK_IN_DATA_DIR),
            HOOK.replace(from, to),
        )
        .expect("the changed hook");
    })
    .map(|(bed, ())| bed)
}
