//! Shared helpers for CLI integration tests.

use std::ffi::OsStr;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process_group};
use rustix::termios::Winsize;
use rustix::thread::{
    CapabilitySet, UnshareFlags, capabilities, configure_capability_in_ambient_set,
    set_capabilities, unshare_unsafe,
};

/// Say why a test is being skipped, where a default `cargo test` will
/// show it.
///
/// Not `eprintln!`: libtest installs a capture that holds everything the
/// `print!` family writes until the run asks for `--nocapture` or the
/// test fails, and a skip nobody sees is a skip nobody acts on. The
/// capture is a Rust-side handle, so writing to descriptor 2 itself goes
/// straight out beside libtest's own progress line.
pub fn say(line: &str) {
    let text = format!("{line}\n");
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        match rustix::io::write(rustix::stdio::stderr(), rest) {
            Ok(0) => return,
            Ok(n) => rest = &rest[n..],
            Err(Errno::INTR) => {}
            Err(_) => return,
        }
    }
}

/// The two host binaries the probes below run. Named absolutely: a probe
/// that resolved them on `PATH` would be measuring the `PATH` a test set
/// rather than the host.
const TRUE: &str = "/usr/bin/true";
const SLEEP: &str = "/usr/bin/sleep";

/// Each probe's verdict, kept so a suite of dozens of guarded tests pays
/// for it once. `None` is "this works here"; `Some(reason)` is what to
/// print instead of running.
static USERNS: OnceLock<Option<String>> = OnceLock::new();
static BWRAP: OnceLock<Option<String>> = OnceLock::new();
static PASTA: OnceLock<Option<String>> = OnceLock::new();
static NFT: OnceLock<Option<String>> = OnceLock::new();

/// Run `probe` once, then print its reason on *every* call that finds it
/// negative: a skipped test that says nothing is indistinguishable from
/// one that ran.
fn probed(cache: &OnceLock<Option<String>>, probe: impl FnOnce() -> Option<String>) -> bool {
    match cache.get_or_init(probe) {
        None => true,
        Some(why) => {
            say(&format!("skipping: {why}"));
            false
        }
    }
}

/// A child process that has made itself a user and a network namespace,
/// for whatever wants to attach to one. The namespaces are made between
/// fork and exec, and `spawn` reports a failure there as a failed spawn,
/// so a handle coming back means they exist.
fn namespace_holder(program: &str, args: &[&str]) -> std::io::Result<Child> {
    let mut c = Command::new(program);
    c.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure runs in the child between fork and exec, where
    // only async-signal-safe work is allowed; `unshare` is a bare syscall
    // that allocates nothing and takes no lock. The child is
    // single-threaded there, so the new namespaces surprise no other
    // thread of it — which is the hazard `unshare_unsafe` is named for.
    unsafe {
        c.pre_exec(|| {
            unshare_unsafe(UnshareFlags::NEWUSER | UnshareFlags::NEWNET).map_err(Into::into)
        });
    }
    c.spawn()
}

/// Returns false (after printing why) when this kernel will not give an
/// unprivileged process a user namespace of its own.
///
/// Probed by creating one rather than by looking for
/// `/proc/self/ns/user`: that path is there in every container, whether
/// or not the container's own policy lets the syscall behind it through.
pub fn require_userns() -> bool {
    probed(&USERNS, || {
        match namespace_holder(TRUE, &[]).and_then(|mut c| c.wait()) {
            Ok(s) if s.success() => None,
            Ok(s) => Some(format!("a user namespace of its own left `true` at {s}")),
            Err(e) => Some(format!("this kernel gives no user namespace: {e}")),
        }
    })
}

/// Returns false (after printing why) when real bwrap runs cannot work
/// here.
///
/// The probe builds a sandbox — the namespaces, `/proc` and `/dev` every
/// bubbler run asks for — instead of running `bwrap --version`. A
/// container can have bwrap installed and a seccomp or LSM policy that
/// refuses the mounts under it, and a probe that only looked for the
/// binary would turn that host's forty-odd guarded tests into failures
/// rather than skips.
pub fn require_bwrap() -> bool {
    require_userns()
        && probed(&BWRAP, || {
            let out = Command::new("bwrap")
                .args([
                    "--unshare-all",
                    "--ro-bind",
                    "/",
                    "/",
                    "--proc",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--",
                    TRUE,
                ])
                .output();
            match out {
                Ok(o) if o.status.success() => None,
                Ok(o) => Some(format!(
                    "bwrap builds no sandbox here ({}): {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => Some(format!("bwrap did not run: {e}")),
            }
        })
}

/// Returns false (after printing why) when the real pasta sidecar cannot
/// be started here.
///
/// The probe is the launcher's own move: hold a network namespace open in
/// a child, hand pasta a path to that child's user namespace, and let it
/// configure the namespace by pid. A `pasta --version` would pass on a
/// host where joining the namespace is what fails.
pub fn require_pasta() -> bool {
    require_userns() && probed(&PASTA, pasta_attaches)
}

/// One real attach, torn down again. pasta goes to the background once
/// the namespace is configured, so the foreground exit status is the
/// verdict; killing the holder is what ends the sidecar behind it.
fn pasta_attaches() -> Option<String> {
    let mut holder = match namespace_holder(SLEEP, &["60"]) {
        Ok(c) => c,
        Err(e) => return Some(format!("no namespace for pasta to attach to: {e}")),
    };
    let pid = holder.id();
    let attached = Command::new("pasta")
        .args(["--config-net", "--quiet", "-t", "none", "-u", "none"])
        .arg("--userns")
        .arg(format!("/proc/{pid}/ns/user"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status();
    let _ = holder.kill();
    let _ = holder.wait();
    match attached {
        Ok(s) if s.success() => None,
        Ok(s) => Some(format!("pasta configured no namespace here ({s})")),
        Err(e) => Some(format!("pasta is not installed (package `passt`): {e}")),
    }
}

/// Interpreter the fake `xdg-dbus-proxy` fixtures are written in; their
/// shebang names this exact path.
pub const PYTHON: &str = "/usr/bin/python3";

/// Returns false (after printing why) when the fake-proxy fixtures cannot
/// run here, because that interpreter is not installed.
pub fn require_python() -> bool {
    require_host_program(PYTHON)
}

/// Returns false (after printing why) when `program` is not installed on
/// this host, which is also where a sandbox reads its `/usr` from: a
/// host without it has none inside either.
pub fn require_host_program(program: &str) -> bool {
    let ok = Path::new(program).is_file();
    if !ok {
        say(&format!("skipping: {program} is not installed"));
    }
    ok
}

/// Returns false (after printing why) when the outbound ruleset cannot be
/// installed here.
///
/// The probe installs one, in a namespace of its own, rather than running
/// `nft --version`: the ruleset bubbler generates needs `nft_reject_inet`
/// and the conntrack match, and a host that loads no modules
/// (`kernel.modules_disabled`) or a container that forbids the netlink
/// has the binary and none of what it needs.
pub fn require_nft() -> bool {
    require_userns() && probed(&NFT, nft_installs_a_ruleset)
}

/// The shape bubbler installs, cut down to the rules that need something
/// of the kernel: the reject statement, the conntrack match and the
/// ICMPv6 types.
const PROBE_RULESET: &str = "table inet bubblerprobe {
	chain out {
		type filter hook output priority 0; policy drop;
		oifname \"lo\" accept
		ct state established,related accept
		icmpv6 type { nd-router-solicit, nd-neighbor-solicit } accept
		reject with icmpx admin-prohibited
	}
}
";

/// One real install, in a user and network namespace the child makes for
/// itself, which is thrown away with it.
fn nft_installs_a_ruleset() -> Option<String> {
    let mut c = Command::new("nft");
    c.arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: as in `namespace_holder`, plus the capability calls the
    // launcher makes for the same reason: capabilities do not survive
    // `execve`, so without the ambient set `nft` would exec with nothing
    // and the probe would report every host as unable. `capget`,
    // `capset` and `prctl` are bare syscalls that allocate nothing.
    unsafe {
        c.pre_exec(|| {
            unshare_unsafe(UnshareFlags::NEWUSER | UnshareFlags::NEWNET)?;
            let mut caps = capabilities(None)?;
            caps.inheritable |= CapabilitySet::NET_ADMIN;
            set_capabilities(None, caps)?;
            configure_capability_in_ambient_set(CapabilitySet::NET_ADMIN, true)?;
            Ok(())
        });
    }
    let mut child = match c.spawn() {
        Ok(c) => c,
        Err(e) => return Some(format!("nft is not installed (package `nftables`): {e}")),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(PROBE_RULESET.as_bytes());
    }
    match child.wait_with_output() {
        Ok(o) if o.status.success() => None,
        Ok(o) => Some(format!(
            "nft installs no ruleset here ({}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Some(format!("nft did not run: {e}")),
    }
}

/// Returns false (after printing why) when the man pages cannot be
/// checked here, because `groff` is not installed.
pub fn require_groff() -> bool {
    let ok = Command::new("groff")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        say("skipping: groff is not installed");
    }
    ok
}

/// The `bubbler-init` binary cargo builds next to the `bubbler` binary,
/// if it is there. `cargo test --workspace` builds it as a workspace
/// member; `cargo test -p bubbler` does not, so tests that need the real
/// supervisor skip with a printed reason instead of failing.
pub fn real_init() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_BIN_EXE_bubbler"))
        .parent()
        .expect("a cargo binary always has a parent directory")
        .join("bubbler-init");
    if path.is_file() {
        return Some(path);
    }
    say(&format!("skipping: {} is not built", path.display()));
    None
}

/// How long a program this test wrote is given to stop being busy.
const TXTBSY_LIMIT: Duration = Duration::from_secs(30);

/// Run `cmd` and hand back its output, waiting out an `ETXTBSY` on a
/// program the test wrote moments earlier.
///
/// A test binary spawns children from many threads at once, and one that
/// forked while such a file was still open for writing holds that
/// descriptor until it execs — an `execve` of the file fails until then,
/// however long ago the writer closed it. It reaches a test as the
/// spawn's own error, or, where bubbler is the one exec'ing, as that
/// error in bubbler's stderr. Neither is anything about what is under
/// test, and both are gone within a scheduling turn.
pub fn output_past_a_busy_exec(cmd: &mut Command) -> Output {
    let busy = format!("os error {}", Errno::TXTBSY.raw_os_error());
    let deadline = Instant::now() + TXTBSY_LIMIT;
    loop {
        match cmd.output() {
            Ok(out) if !String::from_utf8_lossy(&out.stderr).contains(&busy) => return out,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {}
            Err(e) => panic!("running {cmd:?}: {e}"),
        }
        assert!(
            Instant::now() < deadline,
            "{cmd:?} was still busy after {TXTBSY_LIMIT:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A `bubbler` Command with an isolated HOME, XDG_DATA_HOME,
/// XDG_CONFIG_HOME, XDG_RUNTIME_DIR and profile directory under `root`,
/// a known TERM, and `$BUBBLER_INIT`
/// pointing at the stand-in `root/bubbler-init`, so argv assertions do
/// not depend on where the test binary lives. Tests that really start a
/// sandbox override it with [`real_init`].
pub fn bubbler(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bubbler"));
    isolate(&mut c, root);
    c
}

/// The isolated environment every test process gets, whatever the program.
///
/// stdin is `/dev/null` unless a test hands over a terminal of its own:
/// inherited, it is whatever started `cargo test`, and under `makepkg`
/// on a desktop that is the user's terminal. bubbler would then take it
/// into raw mode, and one started in a process group of its own would be
/// stopped by `SIGTTOU` the moment it touched it.
fn isolate(c: &mut Command, root: &Path) {
    c.stdin(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        // The system data layer points into the test root too, so a
        // desktop entry installed on this host cannot be what a test
        // resolves, and nothing a test writes lands outside it.
        .env("XDG_DATA_DIRS", root.join("share"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        // Both profile layers point into the test root, so a profile
        // installed on the host cannot change what a test resolves.
        .env("BUBBLER_PROFILE_DIR", root.join("profiles"))
        .env("BUBBLER_INIT", root.join("bubbler-init"))
        .env("TERM", "dumb");
}

/// bubbler started from a shell, for the two things `Command` cannot
/// express: closing one of its standard descriptors, and putting it in a
/// pipeline whose reader leaves early. `$B` in `script` is the binary.
///
/// The shell leads a process group of its own, so a test that gives up
/// on it can end the bubbler and bwrap under it with [`kill_group`]
/// instead of leaving them running.
pub fn bubbler_in_sh(root: &Path, init: &Path, script: &str) -> Command {
    let mut c = Command::new("/usr/bin/sh");
    isolate(&mut c, root);
    c.env("BUBBLER_INIT", init)
        .env("B", env!("CARGO_BIN_EXE_bubbler"))
        .arg("-c")
        .arg(script)
        .process_group(0);
    c
}

/// SIGKILL to a child's whole process group, for a run that has to be
/// given up on: killing only the shell would leave the sandbox behind.
/// Only for children started with a group of their own
/// ([`bubbler_in_sh`]), whose pid is that group's id.
pub fn kill_group(child: &Child) {
    // A group that is already gone is what this wanted anyway.
    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
}

/// Whether a `bwrap` whose command line holds `needle` is still running.
/// A run that has ended must leave none: bubbler tears its sandboxes down
/// itself, and `--die-with-parent` is only the backstop behind that.
pub fn bwrap_alive(needle: &str) -> bool {
    process_running("bwrap", needle)
}

/// Whether some process has `program` and `needle` in its command line.
/// Read from `/proc` directly: `pgrep` is procps-ng, which a clean build
/// chroot does not have.
pub fn process_running(program: &str, needle: &str) -> bool {
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return false;
    };
    procs
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .map(|raw| String::from_utf8_lossy(&raw).replace('\0', " "))
        .any(|line| line.contains(program) && line.contains(needle))
}

/// [`bubbler`] pointed at the real supervisor binary, for tests that
/// start an actual sandbox instead of only building its argv.
pub fn bubbler_live(root: &Path, init: &Path) -> Command {
    let mut c = bubbler(root);
    c.env("BUBBLER_INIT", init);
    c
}

/// [`bubbler_live`] with the session's real `XDG_RUNTIME_DIR` and bus
/// addresses, which a proxied bus needs; HOME and
/// XDG_DATA_HOME stay under `root`. Instance runtime state therefore
/// lands in the real runtime dir, so such tests need distinctive names.
pub fn bubbler_dbus(root: &Path, init: &Path) -> Command {
    let mut c = bubbler_live(root, init);
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        c.env("XDG_RUNTIME_DIR", dir);
    }
    for var in ["DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS"] {
        if let Some(addr) = std::env::var_os(var) {
            c.env(var, addr);
        }
    }
    c
}

/// [`bubbler_live`] with the session's real `XDG_RUNTIME_DIR` and
/// `WAYLAND_DISPLAY`, which a security context needs: the run connects to
/// the compositor itself. Instance runtime state therefore lands in the
/// real runtime dir, so such tests need distinctive names.
pub fn bubbler_wayland(root: &Path, init: &Path) -> Command {
    let mut c = bubbler_live(root, init);
    for var in ["XDG_RUNTIME_DIR", "WAYLAND_DISPLAY"] {
        if let Some(value) = std::env::var_os(var) {
            c.env(var, value);
        }
    }
    c
}

/// Returns false (after printing why) when a Wayland security context
/// cannot be tested here: no bwrap, no `WAYLAND_DISPLAY`, or a compositor
/// that offers no `wp_security_context_manager_v1`.
///
/// The probe is the launcher's own: `probe` connects over the very
/// environment a test hands the run through [`bubbler_wayland`].
pub fn require_security_context() -> bool {
    if !require_bwrap() {
        return false;
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        say("skipping: WAYLAND_DISPLAY unset");
        return false;
    }
    match bubbler_core::wayland::probe() {
        Ok(true) => true,
        Ok(false) => {
            say("skipping: the compositor offers no wp_security_context_manager_v1");
            false
        }
        Err(e) => {
            say(&format!("skipping: {e}"));
            false
        }
    }
}

/// Returns false (after printing why) when the host holds nothing to
/// build a nested X server's arguments from: no `/dev/dri` for the `dri`
/// grant the mode needs beside it, or no `Xwayland` for the supervisor to
/// start. Both are read from the host — `/usr` and `/dev` are bound from
/// it — so even a dry run refuses a server that is not installed there.
pub fn require_nested_x11_host() -> bool {
    if !Path::new("/dev/dri").is_dir() {
        say("skipping: this host has no /dev/dri");
        return false;
    }
    let server = Path::new(bubbler_core::config::XWAYLAND);
    if !server.is_file() {
        say(&format!(
            "skipping: {} is not installed (package `xorg-xwayland`)",
            server.display()
        ));
        return false;
    }
    true
}

/// Returns false (after printing why) when a real nested X server cannot
/// be tested here: the sandbox's own Wayland socket is what the server
/// draws in, so this is [`require_security_context`] and the host files
/// [`require_nested_x11_host`] probes.
pub fn require_nested_x11() -> bool {
    require_security_context() && require_nested_x11_host()
}

/// Whether `program` is on `PATH`. Only the spawn is checked: `dbus-send`
/// exits 1 on `--version` even when it is installed.
fn has_program(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok()
}

/// The path a `unix:path=` D-Bus address in `var` names, if it names one.
fn unix_path(var: &str) -> Option<PathBuf> {
    let address = std::env::var_os(var)?;
    let rest = address.as_bytes().strip_prefix(b"unix:path=")?.to_vec();
    let end = rest.iter().position(|b| *b == b',').unwrap_or(rest.len());
    Some(PathBuf::from(OsStr::from_bytes(&rest[..end])))
}

/// The host session bus socket, resolved the way bubbler resolves it.
pub fn host_bus() -> Option<PathBuf> {
    unix_path("DBUS_SESSION_BUS_ADDRESS")
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("bus")))
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket()))
}

/// The host system bus socket, resolved the way bubbler resolves it.
pub fn host_system_bus() -> Option<PathBuf> {
    unix_path("DBUS_SYSTEM_BUS_ADDRESS")
        .or_else(|| Some(PathBuf::from(bubbler_core::dbus::SYSTEM_BUS_PATH)))
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket()))
}

/// Whether the host *system* bus has an owner for `name` right now.
pub fn system_owns(name: &str) -> bool {
    Command::new("dbus-send")
        .args([
            "--system",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            &format!("string:{name}"),
        ])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("true"))
}

/// Returns false (after printing why) when a proxied system bus cannot be
/// tested here: no bwrap, no `xdg-dbus-proxy` or `dbus-send`, or no
/// system bus socket on the host.
pub fn require_system_bus() -> bool {
    if !require_bwrap() {
        return false;
    }
    let proxy = has_program("xdg-dbus-proxy");
    let send = has_program("dbus-send");
    let bus = host_system_bus();
    if !proxy || !send || bus.is_none() {
        say(&format!(
            "skipping: xdg-dbus-proxy={proxy} dbus-send={send} system-bus={bus:?}"
        ));
        return false;
    }
    true
}

/// Whether the session bus has an owner for `name` right now. Asking
/// does not activate the service, so a portal that is merely
/// activatable counts as absent.
fn bus_name_has_owner(name: &str) -> bool {
    Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            &format!("string:{name}"),
        ])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("true"))
}

/// Returns false (after printing why) when portal calls cannot be tested
/// here: no proxied session bus, or no running xdg-desktop-portal.
pub fn require_portal() -> bool {
    if !require_dbus() {
        return false;
    }
    let desktop = bus_name_has_owner("org.freedesktop.portal.Desktop");
    if !desktop {
        say("skipping: no org.freedesktop.portal.Desktop on the session bus");
    }
    desktop
}

/// Returns false (after printing why) when the document portal cannot be
/// tested here: no proxied session bus, or nothing mounted at
/// `$XDG_RUNTIME_DIR/doc`.
pub fn require_document_portal() -> bool {
    use std::os::unix::fs::MetadataExt;
    if !require_dbus() {
        return false;
    }
    let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) else {
        say("skipping: XDG_RUNTIME_DIR unset");
        return false;
    };
    let doc = run.join("doc");
    let mounted = match (std::fs::metadata(&doc), std::fs::metadata(&run)) {
        (Ok(d), Ok(r)) => d.is_dir() && d.dev() != r.dev(),
        _ => false,
    };
    if !mounted {
        say("skipping: nothing mounted at $XDG_RUNTIME_DIR/doc");
    }
    mounted
}

/// Returns false (after printing why) when tray calls cannot be tested
/// here: no proxied session bus, or no running StatusNotifier watcher.
pub fn require_tray() -> bool {
    if !require_dbus() {
        return false;
    }
    let watcher = bus_name_has_owner("org.kde.StatusNotifierWatcher");
    if !watcher {
        say("skipping: no org.kde.StatusNotifierWatcher on the session bus");
    }
    watcher
}

/// Returns false (after printing why) when the accessibility bus cannot
/// be tested here: no proxied session bus, or nothing owning
/// `org.a11y.Bus` to answer `GetAddress` with the host socket's path.
///
/// [`require_dbus`] has already looked for `dbus-send`, which is the
/// program the launcher itself runs to ask that name.
pub fn require_a11y() -> bool {
    if !require_dbus() {
        return false;
    }
    let bus = bus_name_has_owner("org.a11y.Bus");
    if !bus {
        say("skipping: no org.a11y.Bus on the session bus");
    }
    bus
}

/// Returns false (after printing why) when a proxied session bus cannot
/// be tested here: no bwrap, no `xdg-dbus-proxy` or `dbus-send`, or no
/// session bus on the host.
pub fn require_dbus() -> bool {
    if !require_bwrap() {
        return false;
    }
    let proxy = has_program("xdg-dbus-proxy");
    let send = has_program("dbus-send");
    let bus = host_bus();
    if !proxy || !send || bus.is_none() {
        say(&format!(
            "skipping: xdg-dbus-proxy={proxy} dbus-send={send} bus={bus:?}"
        ));
        return false;
    }
    true
}

/// Rows and columns every test pty is given, so `stty size` inside a
/// sandbox has something to report: a fresh pty has none.
const TEST_WINSIZE: Winsize = Winsize {
    ws_row: 24,
    ws_col: 80,
    ws_xpixel: 0,
    ws_ypixel: 0,
};

/// A terminal the test owns. bubbler is spawned with the slave as its
/// stdio, which is the only way to exercise the pty mode: with pipes for
/// stdio there is no terminal to replace.
pub struct TestPty {
    /// The test's end, where everything bubbler writes shows up.
    pub master: OwnedFd,
    /// bubbler's end, handed over as one or more of its stdio fds.
    pub slave: OwnedFd,
}

/// A pty pair with a known window size.
pub fn test_pty() -> TestPty {
    let flags = rustix::pty::OpenptFlags::RDWR
        | rustix::pty::OpenptFlags::NOCTTY
        | rustix::pty::OpenptFlags::CLOEXEC;
    let master = rustix::pty::openpt(flags).unwrap();
    rustix::pty::grantpt(&master).unwrap();
    rustix::pty::unlockpt(&master).unwrap();
    let slave = rustix::pty::ioctl_tiocgptpeer(&master, flags).unwrap();
    rustix::termios::tcsetwinsize(&slave, TEST_WINSIZE).unwrap();
    TestPty { master, slave }
}

impl TestPty {
    /// A duplicate of the slave for one of a command's three stdio slots.
    pub fn stdio(&self) -> Stdio {
        Stdio::from(self.slave.try_clone().unwrap())
    }

    /// This pty's device as `major:minor` in decimal, the way the probes
    /// inside a sandbox report theirs. How a test tells the sandbox's
    /// terminal from its own.
    pub fn dev(&self) -> String {
        let st = rustix::fs::fstat(&self.slave).unwrap();
        format!(
            "{}:{}",
            rustix::fs::major(st.st_rdev),
            rustix::fs::minor(st.st_rdev)
        )
    }

    /// Type into the terminal, as a user at the keyboard would.
    pub fn type_in(&self, bytes: &[u8]) {
        rustix::io::write(&self.master, bytes).unwrap();
    }

    /// Everything the terminal shows until `done` matches it or `limit`
    /// passes. Carriage returns are dropped: this is a terminal, so every
    /// line ends `\r\n`.
    pub fn read_until(&self, limit: Duration, done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + limit;
        let mut out = String::new();
        let mut buf = [0u8; 4096];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || done(&out) {
                return out;
            }
            let slice = Timespec {
                tv_sec: left.as_secs() as _,
                tv_nsec: left.subsec_nanos() as _,
            };
            let mut fds = [PollFd::new(&self.master, PollFlags::IN)];
            if poll(&mut fds, Some(&slice)).is_err() || fds[0].revents().is_empty() {
                continue;
            }
            match rustix::io::read(&self.master, &mut buf) {
                // EOF and EIO both mean the last slave is gone.
                Ok(0) | Err(_) => return out,
                Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n]).replace('\r', "")),
            }
        }
    }
}

/// A `Command` for a PATH shim: the same isolated environment
/// [`bubbler`] gets, but the program is the symlink, so `argv[0]` is the
/// name the shim was made under rather than `bubbler`.
pub fn shim(root: &Path, program: &Path) -> Command {
    let mut c = Command::new(program);
    isolate(&mut c, root);
    c
}
