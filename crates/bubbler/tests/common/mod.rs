//! Shared helpers for CLI integration tests.

use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::process::{Pid, Signal, kill_process_group};
use rustix::termios::Winsize;

/// Returns false (after printing why) when real bwrap runs cannot work
/// here: no `bwrap` on PATH or no user namespaces.
pub fn require_bwrap() -> bool {
    let has_bwrap = Command::new("bwrap")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    let has_userns = Path::new("/proc/self/ns/user").exists();
    if !has_bwrap || !has_userns {
        eprintln!("skipping: bwrap={has_bwrap} userns={has_userns}");
    }
    has_bwrap && has_userns
}

/// Interpreter the fake `xdg-dbus-proxy` fixtures are written in; their
/// shebang names this exact path.
pub const PYTHON: &str = "/usr/bin/python3";

/// Returns false (after printing why) when the fake-proxy fixtures cannot
/// run here, because that interpreter is not installed.
pub fn require_python() -> bool {
    let ok = Path::new(PYTHON).is_file();
    if !ok {
        eprintln!("skipping: {PYTHON} is not installed");
    }
    ok
}

/// Returns false (after printing why) when the real pasta sidecar cannot
/// be started here, because the `passt` package is not installed.
pub fn require_pasta() -> bool {
    let ok = Command::new("pasta")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipping: pasta is not installed (package `passt`)");
    }
    ok
}

/// Returns false (after printing why) when the man pages cannot be
/// checked here, because `groff` is not installed.
pub fn require_groff() -> bool {
    let ok = Command::new("groff")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipping: groff is not installed");
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
    eprintln!("skipping: {} is not built", path.display());
    None
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
fn isolate(c: &mut Command, root: &Path) {
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CONFIG_HOME", root.join("config"))
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
    let out = Command::new("pgrep")
        .args(["-a", "-f", needle])
        .output()
        .expect("pgrep is part of procps-ng, which these tests need");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.contains("bwrap"))
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
        eprintln!("skipping: xdg-dbus-proxy={proxy} dbus-send={send} system-bus={bus:?}");
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
        eprintln!("skipping: no org.freedesktop.portal.Desktop on the session bus");
    }
    desktop
}

/// Returns false (after printing why) when tray calls cannot be tested
/// here: no proxied session bus, or no running StatusNotifier watcher.
pub fn require_tray() -> bool {
    if !require_dbus() {
        return false;
    }
    let watcher = bus_name_has_owner("org.kde.StatusNotifierWatcher");
    if !watcher {
        eprintln!("skipping: no org.kde.StatusNotifierWatcher on the session bus");
    }
    watcher
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
        eprintln!("skipping: xdg-dbus-proxy={proxy} dbus-send={send} bus={bus:?}");
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
