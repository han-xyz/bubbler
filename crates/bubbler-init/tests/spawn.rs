//! The supervisor binary under its other name: bwrap binds one file at
//! `/run/bubbler-init` and at `/usr/bin/flatpak-spawn`, and `argv[0]` is
//! the whole of what tells the two modes apart.

use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

const SHIM: &str = "flatpak-spawn";

fn shim(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bubbler-init"))
        .arg0(SHIM)
        .args(args)
        .output()
        .expect("the test binary is on disk")
}

#[test]
fn the_command_runs_in_this_sandbox_with_the_directory_it_asked_for() {
    let out = shim(&[
        "--sandbox",
        "--watch-bus",
        "--directory=/tmp",
        "/usr/bin/pwd",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end(), "/tmp");
}

#[test]
fn a_cleared_environment_holds_only_what_the_command_line_set() {
    let out = shim(&["--clear-env", "--env=MARK=here", "/usr/bin/env"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "MARK=here\n");
}

#[test]
fn asking_for_the_host_is_refused_and_nothing_runs() {
    let out = shim(&["--host", "/usr/bin/true"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim_end(),
        "flatpak-spawn: --host is not available inside a bubbler sandbox"
    );
}

/// Only the name selects the mode: under its own the binary is the
/// supervisor, and the shim's grammar is not one it knows.
#[test]
fn the_supervisor_does_not_answer_to_the_shim_grammar() {
    let out = Command::new(env!("CARGO_BIN_EXE_bubbler-init"))
        .args(["--sandbox", "--directory=/tmp", "/usr/bin/pwd"])
        .output()
        .expect("the test binary is on disk");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).starts_with("bubbler-init: usage:"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}
