//! The editor on a real terminal: what it writes when it hands the
//! terminal over and takes it back. A `TestBackend` cannot answer this —
//! the question is which escape sequences reach the terminal, and whether
//! any of them waits for one back.

use std::fs;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

/// A pty of a known size: 80x24, so what is drawn does not depend on the
/// terminal the tests happen to run under.
fn terminal() -> (OwnedFd, OwnedFd) {
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
    let master = openpt(flags).expect("a pty");
    grantpt(&master).expect("a granted pty");
    unlockpt(&master).expect("an unlocked pty");
    let slave = ioctl_tiocgptpeer(&master, flags).expect("its other end");
    tcsetwinsize(
        &slave,
        Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .expect("a size");
    (master, slave)
}

/// Read whatever the editor has written, for up to `wait`.
fn pump(master: &OwnedFd, into: &mut Vec<u8>, wait: Duration) {
    let deadline = Instant::now() + wait;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let mut fds = [PollFd::new(master, PollFlags::IN)];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: i64::try_from(left.min(Duration::from_millis(50)).as_nanos()).unwrap_or(0),
        };
        if poll(&mut fds, Some(&timeout)).is_err() || fds[0].revents().is_empty() {
            continue;
        }
        let mut buf = [0u8; 65536];
        match rustix::io::read(master, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => into.extend_from_slice(&buf[..n]),
        }
    }
}

/// A stand-in for the `bubbler` binary: the editor runs it for every
/// action, and here it is only a command that ends.
fn fake_bubbler(path: &Path) {
    fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// One instance in a store of its own, written rather than created, so
/// the test needs no `bubbler` binary that works.
fn store(root: &Path) {
    let dir = root.join("data/bubbler/instances/ff");
    fs::create_dir_all(dir.join("home")).unwrap();
    fs::write(
        dir.join("config.kdl"),
        "// bubbler profile: generic\n// bubbler config: 2\nwayland\ncommand \"/bin/true\"\n",
    )
    .unwrap();
}

#[test]
fn handing_the_terminal_over_and_taking_it_back_asks_the_terminal_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(root.join("home")).unwrap();
    fs::create_dir_all(root.join("run")).unwrap();
    store(root);
    // Beside a copy of the editor, so the `bubbler` it finds is this one.
    let editor = bin.join("bubbler-ui");
    fs::copy(env!("CARGO_BIN_EXE_bubbler-ui"), &editor).unwrap();
    fake_bubbler(&bin.join("bubbler"));

    let (master, slave) = terminal();
    let stdio = || Stdio::from(slave.try_clone().unwrap());
    let mut child = Command::new(&editor)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", "xterm-256color")
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("BUBBLER_PROFILE_DIR", root.join("profiles"))
        .stdin(stdio())
        .stdout(stdio())
        .stderr(stdio())
        .spawn()
        .unwrap();
    drop(slave);
    let mut out = Vec::new();
    pump(&master, &mut out, Duration::from_millis(800));
    let drawn = String::from_utf8_lossy(&out).into_owned();
    assert!(
        drawn.contains("wayland"),
        "the editor never drew: {drawn:?}"
    );

    // `e` runs `bubbler edit ff` on this terminal: the editor leaves the
    // alternate screen, the command ends at once, and it comes back.
    rustix::io::write(master.as_fd(), b"e").unwrap();
    pump(&master, &mut out, Duration::from_millis(800));
    rustix::io::write(master.as_fd(), b"q").unwrap();
    pump(&master, &mut out, Duration::from_millis(800));
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));

    let text = String::from_utf8_lossy(&out).into_owned();
    // Twice in and twice out: the round trip really happened.
    assert_eq!(text.matches("\x1b[?1049h").count(), 2, "{text:?}");
    assert_eq!(text.matches("\x1b[?1049l").count(), 2, "{text:?}");
    // And nothing asked the terminal where its cursor is. `Terminal::clear`
    // does exactly that and then waits for the reply, which is a stall
    // under anything driving the editor that does not answer — a script,
    // an expect harness, a terminal that has been resized away.
    assert!(!text.contains("\x1b[6n"), "the editor asked for a report");
    // The cursor is given back before the screen is, both times: the
    // last frame drawn hid it, and a shell with an invisible cursor is
    // what leaving without showing it again would hand back.
    assert_eq!(
        text.matches("\x1b[?25h\x1b[?1049l").count(),
        2,
        "the cursor was not shown before leaving: {text:?}"
    );
    // And nothing hid it after the screen was given back.
    let tail = text.rsplit("\x1b[?1049l").next().unwrap_or_default();
    assert!(!tail.contains("\x1b[?25l"), "the cursor was left hidden");
}
