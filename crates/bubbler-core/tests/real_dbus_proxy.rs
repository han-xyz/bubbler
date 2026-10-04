//! xdg-dbus-proxy(1) says a filtered name becomes "(at least) TALK" once called or heard;
//! measured here on a private bus whether that lets a call outside the rule through.

use std::fs::File;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bubbler_core::dbus::portal_rules;

const PYTHON: &str = "/usr/bin/python3";
const SERVICE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/dbus_split_service.py"
);
const CLIENT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/dbus_split_client.py"
);

const SERVED: &str = "served";
const REFUSED: &str = "refused org.freedesktop.DBus.Error.AccessDenied";

include!("support/say.rs");

/// What this host lacks for the probe, if anything.
fn missing() -> Option<String> {
    for program in ["dbus-daemon", "xdg-dbus-proxy"] {
        let found = Command::new(program)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok();
        if !found {
            return Some(format!("{program} is not installed"));
        }
    }
    let python = Command::new(PYTHON)
        .args([
            "-c",
            "import dbus.mainloop.glib; from gi.repository import GLib",
        ])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    (!python).then(|| format!("{PYTHON} with dbus-python and PyGObject is not installed"))
}

/// A private bus, a service owning `name` on it, and an xdg-dbus-proxy
/// in front of it with `rules`.
struct Probe {
    dir: tempfile::TempDir,
    name: String,
    unique: String,
    children: Vec<Child>,
}

impl Probe {
    fn start(name: &str, signal_path: &str, signal_iface: &str, rules: &[String]) -> Probe {
        // `/tmp`, not `TMPDIR`: a socket path longer than 108 bytes cannot
        // be bound.
        let dir = tempfile::Builder::new()
            .prefix("bubbler-dbus-")
            .tempdir_in("/tmp")
            .unwrap();
        let mut probe = Probe {
            name: name.to_owned(),
            unique: String::new(),
            children: Vec::new(),
            dir,
        };
        let bus = probe.address("bus");
        let socket = probe.dir.path().join("bus");
        probe.spawn(
            "dbus-daemon",
            &[
                "--session".to_owned(),
                "--nofork".to_owned(),
                format!("--address={bus}"),
            ],
            "daemon.log",
        );
        wait_for("the private bus", || socket.exists());
        probe.spawn(
            PYTHON,
            &[
                SERVICE.to_owned(),
                bus.clone(),
                name.to_owned(),
                signal_path.to_owned(),
                signal_iface.to_owned(),
            ],
            "service.out",
        );
        let out = probe.dir.path().join("service.out");
        wait_for("the service", || {
            std::fs::read_to_string(&out).is_ok_and(|s| s.ends_with('\n'))
        });
        probe.unique = std::fs::read_to_string(&out).unwrap().trim().to_owned();
        let proxy = probe.dir.path().join("proxy");
        let mut args = vec![
            bus,
            proxy.display().to_string(),
            "--filter".to_owned(),
            "--log".to_owned(),
        ];
        args.extend(rules.iter().cloned());
        probe.spawn("xdg-dbus-proxy", &args, "proxy.log");
        wait_for("the proxy", || proxy.exists());
        probe
    }

    fn address(&self, socket: &str) -> String {
        format!("unix:path={}", self.dir.path().join(socket).display())
    }

    fn spawn(&mut self, program: &str, args: &[String], log: &str) {
        let out = File::create(self.dir.path().join(log)).unwrap();
        let child = Command::new(program)
            .args(args)
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
            .stdin(Stdio::null())
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .unwrap_or_else(|e| panic!("{program} did not run: {e}"));
        self.children.push(child);
    }

    /// Run `steps` on one client connection through the proxy and return
    /// its transcript.
    fn client(&self, steps: &[&str]) -> String {
        let out = Command::new(PYTHON)
            .arg(CLIENT)
            .args([&self.address("proxy"), &self.name, &self.unique])
            .args(steps)
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        for child in self.children.iter_mut().rev() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "{what} never came up");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_row(transcript: &str, label: &str, verdict: &str) {
    assert!(
        transcript
            .lines()
            .any(|l| l == format!("{label}: {verdict}")),
        "row {label} is not `{verdict}`:\n{transcript}"
    );
}

const SPLIT: &str = "org.example.Split";
const OBJECT: &str = "/org/example/Obj";

/// Rows a-f against the Allowed/Denied split, on the object at `OBJECT`.
fn split_steps() -> Vec<String> {
    let at =
        |label: &str, target: &str, method: &str| format!("{label} {target} {OBJECT} {method}");
    vec![
        at("a", "name", "org.example.Denied.Ping"),
        at("b", "name", "org.example.Allowed.Ping"),
        at("c", "name", "org.example.Denied.Ping"),
        at("d", "unique", "org.example.Denied.Ping"),
        at("e1", "name", "org.freedesktop.DBus.Properties.GetAll"),
        at(
            "e2",
            "name",
            "org.freedesktop.DBus.Introspectable.Introspect",
        ),
        at("e3", "unique", "org.freedesktop.DBus.Properties.GetAll"),
        at("f0", "name", "org.example.Allowed.Emit"),
        "wait".to_owned(),
        at("f1", "name", "org.example.Denied.Ping"),
        at("f2", "unique", "org.example.Denied.Ping"),
    ]
}

fn assert_split_holds(t: &str) {
    for (row, verdict) in [
        ("a", REFUSED),
        ("b", SERVED),
        ("c", REFUSED),
        ("d", REFUSED),
        ("e1", REFUSED),
        ("e2", REFUSED),
        ("e3", REFUSED),
        ("f0", SERVED),
        ("wait", "1 signals"),
        ("f1", REFUSED),
        ("f2", REFUSED),
    ] {
        assert_row(t, row, verdict);
    }
}

// Measured with xdg-dbus-proxy 0.1.9: the man page's TALK upgrade never
// lets a call outside the rule through.
#[test]
fn a_call_rule_with_a_path_still_refuses_after_a_call_and_a_broadcast() {
    if let Some(why) = missing() {
        say(&format!("skipping: {why}"));
        return;
    }
    let rule = format!("{SPLIT}=org.example.Allowed.*@{OBJECT}");
    let probe = Probe::start(
        SPLIT,
        OBJECT,
        "org.example.Allowed",
        &[format!("--call={rule}"), format!("--broadcast={rule}")],
    );
    let mut steps = split_steps();
    steps.push(format!("x name {OBJECT}/other org.example.Allowed.Ping"));
    let t = probe.client(&steps.iter().map(String::as_str).collect::<Vec<_>>());
    assert_split_holds(&t);
    assert_row(&t, "x", REFUSED);
}

#[test]
fn a_call_rule_without_a_path_still_refuses_after_a_call_and_a_broadcast() {
    if let Some(why) = missing() {
        say(&format!("skipping: {why}"));
        return;
    }
    let rule = format!("{SPLIT}=org.example.Allowed.*");
    let probe = Probe::start(
        SPLIT,
        OBJECT,
        "org.example.Allowed",
        &[format!("--call={rule}"), format!("--broadcast={rule}")],
    );
    let steps = split_steps();
    let t = probe.client(&steps.iter().map(String::as_str).collect::<Vec<_>>());
    assert_split_holds(&t);
}

/// The `portals` rule set as bubbler renders it, against a stand-in
/// owning the portal's own name on the private bus.
#[test]
fn portals_still_refuse_screencast_after_a_settings_call_and_broadcast() {
    if let Some(why) = missing() {
        say(&format!("skipping: {why}"));
        return;
    }
    let desktop = "/org/freedesktop/portal/desktop";
    let probe = Probe::start(
        "org.freedesktop.portal.Desktop",
        desktop,
        "org.freedesktop.portal.Settings",
        &portal_rules(&[]),
    );
    let at =
        |label: &str, target: &str, method: &str| format!("{label} {target} {desktop} {method}");
    let steps = [
        at(
            "a",
            "name",
            "org.freedesktop.portal.ScreenCast.CreateSession",
        ),
        at("b", "name", "org.freedesktop.portal.Settings.Read"),
        at(
            "c",
            "name",
            "org.freedesktop.portal.ScreenCast.CreateSession",
        ),
        at(
            "d",
            "unique",
            "org.freedesktop.portal.ScreenCast.CreateSession",
        ),
        at("e1", "name", "org.freedesktop.DBus.Properties.GetAll"),
        at(
            "e2",
            "name",
            "org.freedesktop.DBus.Introspectable.Introspect",
        ),
        at("e3", "name", "org.freedesktop.DBus.Properties.Set"),
        at("e4", "unique", "org.freedesktop.DBus.Properties.Set"),
        at(
            "e5",
            "name",
            "org.freedesktop.DBus.Properties.GetAll org.freedesktop.portal.ScreenCast",
        ),
        at(
            "e6",
            "name",
            "org.freedesktop.DBus.Properties.Get org.freedesktop.portal.RemoteDesktop AvailableDeviceTypes",
        ),
        at("f0", "name", "org.freedesktop.portal.Settings.Emit"),
        "wait".to_owned(),
        at(
            "f1",
            "name",
            "org.freedesktop.portal.ScreenCast.CreateSession",
        ),
        at(
            "f2",
            "unique",
            "org.freedesktop.portal.ScreenCast.CreateSession",
        ),
        at(
            "f3",
            "unique",
            "org.freedesktop.portal.RemoteDesktop.CreateSession",
        ),
    ];
    let t = probe.client(&steps.iter().map(String::as_str).collect::<Vec<_>>());
    for (row, verdict) in [
        ("a", REFUSED),
        ("b", SERVED),
        ("c", REFUSED),
        ("d", REFUSED),
        ("e1", SERVED),
        ("e2", SERVED),
        ("e3", REFUSED),
        ("e4", REFUSED),
        ("e5", SERVED),
        ("e6", SERVED),
        ("f0", SERVED),
        ("wait", "1 signals"),
        ("f1", REFUSED),
        ("f2", REFUSED),
        ("f3", REFUSED),
    ] {
        assert_row(&t, row, verdict);
    }
}
