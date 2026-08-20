mod common;

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bubbler_core::bwrap::ETC_ALLOWLIST;
use common::{
    bubbler, bubbler_dbus, bubbler_live, real_init, require_bwrap, require_dbus, require_portal,
};
use rustix::process::{Pid, Signal, kill_process};

fn setup() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("home")).unwrap();
    std::fs::create_dir_all(tmp.path().join("run")).unwrap();
    // Stand-in for the supervisor binary: `$BUBBLER_INIT` must name a
    // regular file for argv building, which is all a dry run needs.
    std::fs::write(tmp.path().join("bubbler-init"), b"").unwrap();
    tmp
}

#[test]
fn create_list_and_dry_run() {
    let tmp = setup();
    let out = bubbler(tmp.path()).args(["create", "t"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = bubbler(tmp.path()).arg("list").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "t\n");

    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let home = tmp.path().join("data/bubbler/instances/t/home");
    let run = tmp.path().join("run");
    // Which allowlisted `/etc` entries exist is a property of this host, so
    // only the parts around them are exact.
    let expected_prefix = "bwrap\n--unshare-all\n--die-with-parent\n--new-session\n--hostname\nbubbler\n--chdir\n/home/bubbler\n\
         --info-fd\n3\n\
         --ro-bind\n/usr\n/usr\n--symlink\nusr/bin\n/bin\n--symlink\nusr/lib\n/lib\n\
         --symlink\nusr/lib64\n/lib64\n--symlink\nusr/bin\n/sbin\n\
         --ro-bind-try\n/opt\n/opt\n--tmpfs\n/etc\n";
    let expected_suffix = format!(
        "--proc\n/proc\n--dev\n/dev\n--tmpfs\n/tmp\n--tmpfs\n/var\n--tmpfs\n/run\n\
         --bind\n{home}\n/home/bubbler\n--perms\n0700\n--dir\n{run}\n\
         --ro-bind\n{init}\n/run/bubbler-init\n--clearenv\n--setenv\nTERM\ndumb\n\
         --setenv\nHOME\n/home/bubbler\n--setenv\nPATH\n/usr/bin\n--setenv\nXDG_RUNTIME_DIR\n{run}\n\
         --setenv\nUSER\nbubbler\n--setenv\nLOGNAME\nbubbler\n\
         --\n/run/bubbler-init\n--socket-fd\n6\n--\n/usr/bin/true\n",
        home = home.display(),
        run = run.display(),
        init = tmp.path().join("bubbler-init").display()
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.starts_with(expected_prefix), "{s}");
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n4\n/etc/passwd\n"),
        "{s}"
    );
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n5\n/etc/group\n"),
        "{s}"
    );
    assert!(s.ends_with(&expected_suffix), "{s}");
}

#[test]
fn profiles_lists_builtins_and_firefox_seeds_gpu_and_toolkit_env() {
    let tmp = setup();
    let out = bubbler(tmp.path()).arg("profiles").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "alacritty\nfirefox\ngeneric\n"
    );

    let out = bubbler(tmp.path())
        .args(["create", "ff", "--profile", "firefox"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A dry run needs this host's sockets and GPU, so only the seeded
    // config is asserted on.
    let cfg =
        std::fs::read_to_string(tmp.path().join("data/bubbler/instances/ff/config.kdl")).unwrap();
    assert!(
        cfg.contains("dri\n") && cfg.contains("MOZ_ENABLE_WAYLAND"),
        "{cfg}"
    );
}

#[test]
fn run_without_command_fails_with_message() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no command"));
}

// `network` binds /etc/resolv.conf, so this test needs one on the host.
#[test]
fn network_share_and_home_share_appear_in_dry_run() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    std::fs::create_dir_all(tmp.path().join("home/Downloads")).unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(
        &cfg,
        "network\nhome-share \"Downloads\"\ncommand \"true\"\n",
    )
    .unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.contains("--unshare-all\n--share-net\n"));
    assert!(s.contains(&format!(
        "--ro-bind\n{}\n/home/bubbler/Downloads\n",
        tmp.path().join("home/Downloads").display()
    )));
}

#[test]
fn missing_home_share_source_is_an_error() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "home-share \"Nope\"\ncommand \"true\"\n").unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not exist"));
}

#[test]
fn home_share_through_a_symlink_out_of_the_home_is_refused() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    std::os::unix::fs::symlink("/", tmp.path().join("home/RootLink")).unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "home-share \"RootLink\" mode=rw\ncommand \"true\"\n").unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("outside"), "{err}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("/home/bubbler/RootLink"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn real_bwrap_runs_true_and_propagates_exit_code() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/false"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(tmp.path().join("run/bubbler/t").is_dir());
}

#[test]
fn real_bwrap_home_is_fixed_and_private() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "echo $HOME; ls /home",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "/home/bubbler\nbubbler\n"
    );
}

#[test]
fn real_bwrap_etc_is_allowlisted_and_user_is_bubbler() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "id -un; cat /etc/passwd | wc -l; test -e /etc/shadow && echo LEAK; ls /etc",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(!s.contains("LEAK"), "{s}");
    let mut lines = s.lines();
    assert_eq!(lines.next(), Some("bubbler"), "{s}");
    assert_eq!(lines.next().map(str::trim), Some("2"), "{s}");
    let entries: Vec<&str> = lines.collect();
    assert!(entries.contains(&"passwd"), "{s}");
    for name in entries {
        assert!(
            ETC_ALLOWLIST.contains(&name) || name == "passwd" || name == "group",
            "unexpected /etc entry `{name}`:\n{s}"
        );
    }
}

/// Poll until `ready` holds, so the test never sleeps longer than it must.
fn wait_until(mut ready: impl FnMut() -> bool, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// The background run's stderr is where a failed start explains itself.
fn fail_with(mut run: Child, what: &str) -> ! {
    let _ = run.kill();
    let out = run.wait_with_output().expect("waiting for the run process");
    panic!("{what}: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn real_bwrap_exec_round_trip() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let mut run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/sleep", "30"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let sock = tmp.path().join("run/bubbler/t/init.sock");
    if !wait_until(
        || UnixStream::connect(&sock).is_ok(),
        Duration::from_secs(10),
    ) {
        fail_with(run, "the instance never accepted a connection");
    }

    let out = bubbler_live(tmp.path(), &init)
        .args(["exec", "t", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = bubbler_live(tmp.path(), &init)
        .args(["exec", "t", "--", "/usr/bin/sh", "-c", "exit 3"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));

    let out = bubbler_live(tmp.path(), &init)
        .args(["exec", "t", "--", "/usr/bin/sh", "-c", "echo $HOME; id -un"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "/home/bubbler\nbubbler\n"
    );

    // A second `run` finds the instance live and executes inside it.
    let out = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    let note = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{note}");
    assert!(note.contains("executing inside it"), "{note}");

    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    let mut status = None;
    assert!(
        wait_until(
            || {
                status = run.try_wait().expect("waiting for the run process");
                status.is_some()
            },
            Duration::from_secs(8)
        ),
        "the run did not stop after SIGTERM"
    );
    assert_eq!(status.and_then(|s| s.code()), Some(143));
    assert!(!sock.exists(), "the control socket outlived the run");

    let out = bubbler_live(tmp.path(), &init)
        .args(["exec", "t", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not running"), "{err}");
}

#[test]
fn real_bwrap_sigterm_reaches_the_command_inside() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    // `sleep` runs in the background and the shell waits for it: a POSIX
    // shell only runs a trap once the foreground command has finished, so
    // a foreground sleep would hide the forwarded signal until it ended.
    let run = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "trap 'echo got; exit 7' TERM; /usr/bin/sleep 30 & wait",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let sock = tmp.path().join("run/bubbler/t/init.sock");
    if !wait_until(
        || UnixStream::connect(&sock).is_ok(),
        Duration::from_secs(10),
    ) {
        fail_with(run, "the instance never accepted a connection");
    }

    let sent = Instant::now();
    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    let out = run.wait_with_output().expect("waiting for the run process");
    // The command's own exit code, not 143: the signal reached it through
    // the supervisor rather than killing the sandbox from outside.
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "got\n");
    assert!(
        sent.elapsed() < Duration::from_secs(2),
        "the command took {:?} to see the signal",
        sent.elapsed()
    );
    assert!(!sock.exists(), "the control socket outlived the run");
}

/// Ask the host's own session bus whether a name is on it, so a test
/// that expects the proxy to hide it is not proving the obvious.
fn host_owns(name: &str) -> bool {
    Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ListNames",
        ])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains(name))
}

/// Whether any `xdg-dbus-proxy` still has `needle` in its argv.
fn proxy_running_for(needle: &str) -> bool {
    match Command::new("pgrep")
        .args(["-f", &format!("xdg-dbus-proxy.*{needle}")])
        .output()
    {
        Ok(o) => o.status.success(),
        // No pgrep: the assertion cannot be made, so it does not fail.
        Err(_) => false,
    }
}

/// Instance whose runtime state lands in the session's real runtime dir,
/// removed again so a bus test leaves nothing behind.
struct RuntimeLeftovers {
    /// `$XDG_RUNTIME_DIR/bubbler/<name>`.
    runtime: PathBuf,
    /// `$XDG_RUNTIME_DIR/.flatpak/<name>`, written only with `portals`.
    flatpak: PathBuf,
}

impl Drop for RuntimeLeftovers {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.runtime);
        let _ = std::fs::remove_dir_all(&self.flatpak);
    }
}

fn dbus_instance(tmp: &Path, init: &Path, name: &str, config: &str) -> RuntimeLeftovers {
    let out = bubbler_dbus(tmp, init)
        .args(["create", name])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(
        tmp.join("data/bubbler/instances")
            .join(name)
            .join("config.kdl"),
        config,
    )
    .unwrap();
    let run_dir =
        PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("checked by require_dbus"));
    RuntimeLeftovers {
        runtime: run_dir.join("bubbler").join(name),
        flatpak: run_dir.join(".flatpak").join(name),
    }
}

#[test]
fn real_dbus_hides_names_the_rules_do_not_grant() {
    if !require_dbus() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !host_owns("org.freedesktop.Notifications") {
        eprintln!("skipping: the host session bus has no org.freedesktop.Notifications");
        return;
    }
    let tmp = setup();
    let name = "bubbler-test-dbus-bare";
    let leftovers = dbus_instance(tmp.path(), &init, name, "dbus\ncommand \"true\"\n");

    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            name,
            "--",
            "/usr/bin/dbus-send",
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ListNames",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(s.contains("org.freedesktop.DBus"), "{s}");
    assert!(
        !s.contains("org.freedesktop.Notifications"),
        "the proxy passed a name no rule grants:\n{s}"
    );
    assert!(
        !proxy_running_for(&leftovers.runtime.display().to_string()),
        "the proxy outlived the run"
    );
}

#[test]
fn real_dbus_run_ends_as_soon_as_the_command_does() {
    if !require_dbus() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let name = "bubbler-test-dbus-timing";
    let _leftovers = dbus_instance(tmp.path(), &init, name, "dbus\ncommand \"/usr/bin/true\"\n");

    let started = Instant::now();
    let out = bubbler_dbus(tmp.path(), &init)
        .args(["run", name])
        .output()
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The proxy leaves when the ready pipe closes; a run that waits out
    // the stop grace and kills it instead takes a second longer.
    assert!(
        elapsed < Duration::from_millis(800),
        "the run took {elapsed:?}, so the proxy was killed rather than closed"
    );
}

#[test]
fn real_dbus_notify_reaches_the_notification_service() {
    if !require_dbus() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !host_owns("org.freedesktop.Notifications") {
        eprintln!("skipping: the host session bus has no org.freedesktop.Notifications");
        return;
    }
    let tmp = setup();
    let name = "bubbler-test-dbus-notify";
    let _leftovers = dbus_instance(tmp.path(), &init, name, "dbus\nnotify\ncommand \"true\"\n");

    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            name,
            "--",
            "/usr/bin/dbus-send",
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications.GetCapabilities",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("array"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn real_portal_answers_a_call_that_needs_the_app_identity() {
    if !require_portal() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let name = "bubbler-test-portal-read";
    let _leftovers = dbus_instance(tmp.path(), &init, name, "dbus\nportals\ncommand \"true\"\n");

    // Settings.ReadAll goes through the portal's app-info lookup, unlike
    // introspection or a property read, which any peer gets.
    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            name,
            "--",
            "/usr/bin/dbus-send",
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Settings.ReadAll",
            "array:string:org.freedesktop.appearance",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(s.contains("method return"), "stdout: {s}stderr: {err}");
}

#[test]
fn real_portal_identity_lives_exactly_as_long_as_the_run() {
    if !require_portal() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let name = "bubbler-test-portal-identity";
    let leftovers = dbus_instance(tmp.path(), &init, name, "dbus\nportals\ncommand \"true\"\n");
    let dir = leftovers.flatpak.clone();
    let info = dir.join("bwrapinfo.json");

    let mut run = bubbler_dbus(tmp.path(), &init)
        .args(["run", name, "--", "/usr/bin/sleep", "20"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if !wait_until(|| info.is_file(), Duration::from_secs(10)) {
        fail_with(run, "the run never published its bwrapinfo.json");
    }
    let text = std::fs::read_to_string(&info).unwrap();
    assert!(text.contains("\"child-pid\""), "{text}");

    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    assert!(
        wait_until(
            || run
                .try_wait()
                .expect("waiting for the run process")
                .is_some(),
            Duration::from_secs(8)
        ),
        "the run did not stop after SIGTERM"
    );
    assert!(!dir.exists(), "the identity outlived the run");
    // Only this instance's entry is removed: the directory above it holds
    // flatpak's own instances.
    assert!(
        dir.parent().is_some_and(Path::is_dir),
        "the .flatpak directory itself was removed"
    );
}

#[test]
fn real_dbus_leaves_the_instance_runtime_directory_empty() {
    if !require_dbus() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let name = "bubbler-test-dbus-leftovers";
    let leftovers = dbus_instance(tmp.path(), &init, name, "dbus\ncommand \"/usr/bin/true\"\n");
    let out = bubbler_dbus(tmp.path(), &init)
        .args(["run", name])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The moved socket, the control socket and the proxy's own directory
    // are all this run's, and all of them go with it.
    let left: Vec<_> = std::fs::read_dir(&leftovers.runtime)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// A stand-in for `xdg-dbus-proxy` that puts a symlink where its socket
/// belongs and only then reports itself ready. Its arguments are the ones
/// bubbler passes: `--fd=N`, the bus address, the socket path.
fn symlink_proxy(path: &Path, target: &str) {
    write_script(
        path,
        &format!(
            "#!/bin/sh\nfd=${{1#--fd=}}\nln -sfn {target} \"$3\"\neval \"echo r >&$fd\"\nexec sleep 5\n"
        ),
    );
}

#[test]
fn a_proxy_that_swaps_its_socket_for_a_symlink_never_reaches_the_sandbox() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    // A host bus socket for the proxy sandbox to bind; nothing ever
    // speaks D-Bus on it, because the run must fail before that.
    let bus = tmp.path().join("fakebus");
    let _listener = UnixListener::bind(&bus).unwrap();
    let fake = tmp.path().join("fake-proxy");
    symlink_proxy(&fake, "/etc");
    let out = bubbler_live(tmp.path(), &init)
        .args(["create", "atk"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(
        tmp.path().join("data/bubbler/instances/atk/config.kdl"),
        "dbus\n",
    )
    .unwrap();
    let marker = tmp.path().join("data/bubbler/instances/atk/home/ran");
    let out = bubbler_live(tmp.path(), &init)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", bus.display()),
        )
        .env("BUBBLER_DBUS_PROXY", &fake)
        .args(["run", "atk", "--", "/usr/bin/touch", "/home/bubbler/ran"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(err.contains("a socket"), "stderr: {err}");
    assert!(
        !marker.exists(),
        "the application ran with the proxy's symlink bound in"
    );
    assert!(
        !tmp.path().join("run/bubbler/atk/bus").exists(),
        "the swapped socket was moved into the instance directory"
    );
}

#[test]
fn x11_warns_before_a_real_run() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "x11\ncommand \"/usr/bin/true\"\n").unwrap();
    let out = bubbler(tmp.path()).args(["run", "t"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("x11 grants no isolation"), "{err}");
    // $DISPLAY is cleared here, so the run fails after the warning is out.
    assert_eq!(out.status.code(), Some(1), "{err}");
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stderr).contains("x11 grants no isolation"));
}

#[test]
fn empty_required_vars_are_rejected() {
    let tmp = setup();
    let out = bubbler(tmp.path())
        .env("HOME", "")
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("HOME is not set"));

    let out = bubbler(tmp.path())
        .env("XDG_RUNTIME_DIR", "")
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("XDG_RUNTIME_DIR is not set"));
}

#[test]
fn dry_run_survives_a_closed_pipe() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let mut child = bubbler(tmp.path())
        .args(["run", "t", "--dry-run", "--", "/usr/bin/true"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take().expect("stdout was requested as a pipe"));
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn dry_run_writes_argv_bytes_verbatim() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let arg = OsStr::from_bytes(b"/tmp/\xff");
    let out = bubbler(tmp.path())
        .args([
            OsStr::new("run"),
            OsStr::new("t"),
            OsStr::new("--dry-run"),
            OsStr::new("--"),
            arg,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.ends_with(b"--\n/tmp/\xff\n"), "{:?}", out.stdout);
}

#[test]
fn wayland_display_must_name_a_socket() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "wayland\ncommand \"true\"\n").unwrap();

    let out = bubbler(tmp.path())
        .env("WAYLAND_DISPLAY", ".")
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("only a plain socket name"), "{err}");

    std::fs::write(tmp.path().join("run/notasocket"), "").unwrap();
    let out = bubbler(tmp.path())
        .env("WAYLAND_DISPLAY", "notasocket")
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("notasocket"), "{err}");
}

#[test]
fn create_and_list_survive_a_closed_pipe() {
    let tmp = setup();
    for args in [["create", "t"], ["list", ""]] {
        let mut cmd = bubbler(tmp.path());
        cmd.args(args.iter().filter(|a| !a.is_empty()));
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take().expect("stdout was requested as a pipe"));
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn invalid_config_names_the_file_once() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "command \"unclosed\n").unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains(&cfg.display().to_string()), "{err}");
    assert_eq!(
        err.matches("Failed to parse KDL document").count(),
        1,
        "{err}"
    );
}

#[test]
fn instance_name_cannot_start_with_a_dash() {
    let tmp = setup();
    let out = bubbler(tmp.path())
        .args(["create", "--", "-x"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("invalid instance name"), "{err}");
}

#[test]
fn delete_needs_yes_and_then_removes() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let out = bubbler(tmp.path()).args(["delete", "t"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--yes"));
    assert!(tmp.path().join("data/bubbler/instances/t").is_dir());

    let out = bubbler(tmp.path())
        .args(["delete", "t", "--yes"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!tmp.path().join("data/bubbler/instances/t").exists());

    let out = bubbler(tmp.path())
        .args(["delete", "t", "--yes"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
}

/// Write `body` as an executable script at `path`.
fn write_script(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
}

#[test]
fn edit_runs_editor_and_rechecks() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let out = bubbler(tmp.path())
        .env("EDITOR", "/usr/bin/true")
        .args(["edit", "t"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = bubbler(tmp.path())
        .env("EDITOR", "/usr/bin/false")
        .args(["edit", "t"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    let out = bubbler(tmp.path()).args(["edit", "t"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("EDITOR"));

    // The editor under test is a script that corrupts the config: the
    // re-check must report it and keep the file as the user left it.
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    let bad = tmp.path().join("bad-editor");
    write_script(&bad, "#!/usr/bin/sh\nprintf 'bogus\\n' > \"$1\"\n");
    let out = bubbler(tmp.path())
        .env("EDITOR", &bad)
        .args(["edit", "t"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("still has errors"), "{err}");
    assert!(err.contains("unknown node `bogus`"), "{err}");
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "bogus\n");

    let unclosed = tmp.path().join("unclosed-editor");
    write_script(
        &unclosed,
        "#!/usr/bin/sh\nprintf 'command \"x\\n' > \"$1\"\n",
    );
    let out = bubbler(tmp.path())
        .env("EDITOR", &unclosed)
        .args(["edit", "t"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains(&cfg.display().to_string()), "{err}");
    assert_eq!(
        err.matches("Failed to parse KDL document").count(),
        1,
        "{err}"
    );

    // The config is broken now, which is exactly when `edit` is needed: it
    // must still spawn instead of refusing on the parse error.
    let out = bubbler(tmp.path())
        .env("EDITOR", "/usr/bin/true")
        .args(["edit", "t"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("still has errors"), "{err}");
    assert_eq!(
        err.matches("Failed to parse KDL document").count(),
        1,
        "{err}"
    );

    let fixer = tmp.path().join("fix-editor");
    write_script(
        &fixer,
        "#!/usr/bin/sh\nprintf 'command \"true\"\\n' > \"$1\"\n",
    );
    let out = bubbler(tmp.path())
        .env("EDITOR", &fixer)
        .args(["edit", "t"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "command \"true\"\n");
}

#[test]
fn edit_rejects_a_blank_editor_and_propagates_a_signal() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let out = bubbler(tmp.path())
        .env("EDITOR", "   ")
        .args(["edit", "t"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("blank"), "{err}");

    let script = tmp.path().join("dying-editor");
    write_script(&script, "#!/usr/bin/sh\nkill -TERM $$\n");
    let out = bubbler(tmp.path())
        .env("EDITOR", &script)
        .args(["edit", "t"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(143),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn edit_prefers_visual_and_passes_editor_arguments() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let marker = tmp.path().join("marker");
    let script = tmp.path().join("record-editor");
    write_script(
        &script,
        &format!(
            "#!/usr/bin/sh\nprintf '%s\\n' \"$@\" > {}\n",
            marker.display()
        ),
    );
    let mut visual = script.clone().into_os_string();
    visual.push(" --flag");
    let out = bubbler(tmp.path())
        .env("VISUAL", &visual)
        .env("EDITOR", "/usr/bin/false")
        .args(["edit", "t"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        format!(
            "--flag\n{}\n",
            tmp.path()
                .join("data/bubbler/instances/t/config.kdl")
                .display()
        )
    );
}

#[test]
fn try_rejects_bad_grants_and_cleans_up_a_failed_start() {
    let tmp = setup();
    let out = bubbler(tmp.path())
        .args(["try", "--grant", "bogus", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown grant `bogus`"), "{err}");
    for grant in [
        "wayland",
        "x11",
        "network",
        "dri",
        "pipewire",
        "pulseaudio",
        "dbus",
        "portals",
        "notify",
    ] {
        assert!(err.contains(grant), "{grant} missing from {err}");
    }

    let out = bubbler(tmp.path())
        .args(["try", "--grant", "portals", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("requires dbus"), "{err}");

    // No command anywhere: the failure happens after the directory exists,
    // so it also shows the guard cleaning up.
    let out = bubbler(tmp.path()).arg("try").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no command"), "{err}");
    let left: Vec<_> = std::fs::read_dir(tmp.path().join("data/bubbler/try"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn real_bwrap_try_grants_network_and_leaves_nothing_behind() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "try",
            "--grant",
            "network",
            "--",
            "/usr/bin/sh",
            "-c",
            "cat /etc/resolv.conf",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.stdout.is_empty());
    let left: Vec<_> = std::fs::read_dir(tmp.path().join("data/bubbler/try"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");
    let left: Vec<_> = std::fs::read_dir(tmp.path().join("run/bubbler"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn real_bwrap_try_leaves_no_instance_unless_kept() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let out = bubbler_live(tmp.path(), &init)
        .args(["try", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = bubbler_live(tmp.path(), &init)
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");

    let out = bubbler_live(tmp.path(), &init)
        .args(["try", "--keep", "kept", "--", "/usr/bin/false"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let out = bubbler_live(tmp.path(), &init)
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "kept\n");
    assert!(tmp.path().join("data/bubbler/instances/kept/home").is_dir());

    let out = bubbler_live(tmp.path(), &init)
        .args(["try", "--keep", "kept", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("already exists"), "{err}");
    assert!(
        tmp.path()
            .join("data/bubbler/instances/kept/config.kdl")
            .is_file()
    );
}
