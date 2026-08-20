mod common;

use common::{bubbler, require_bwrap};

fn setup() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("home")).unwrap();
    std::fs::create_dir_all(tmp.path().join("run")).unwrap();
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
    let expected_prefix = "bwrap\n--unshare-all\n--die-with-parent\n--new-session\n--hostname\nbubbler\n\
         --ro-bind\n/usr\n/usr\n--symlink\nusr/bin\n/bin\n--symlink\nusr/lib\n/lib\n\
         --symlink\nusr/lib64\n/lib64\n--symlink\nusr/bin\n/sbin\n\
         --ro-bind-try\n/opt\n/opt\n--tmpfs\n/etc\n";
    let expected_suffix = format!(
        "--proc\n/proc\n--dev\n/dev\n--tmpfs\n/tmp\n--tmpfs\n/var\n--tmpfs\n/run\n\
         --bind\n{home}\n/home/bubbler\n--perms\n0700\n--dir\n{run}\n--clearenv\n--setenv\nTERM\ndumb\n\
         --setenv\nHOME\n/home/bubbler\n--setenv\nPATH\n/usr/bin\n--setenv\nXDG_RUNTIME_DIR\n{run}\n\
         --setenv\nUSER\nbubbler\n--setenv\nLOGNAME\nbubbler\n--\n/usr/bin/true\n",
        home = home.display(),
        run = run.display()
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.starts_with(expected_prefix), "{s}");
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n3\n/etc/passwd\n"),
        "{s}"
    );
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n4\n/etc/group\n"),
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
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = bubbler(tmp.path())
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
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let out = bubbler(tmp.path())
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
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let out = bubbler(tmp.path())
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "id -un; cat /etc/passwd | wc -l; test -e /etc/shadow && echo LEAK; ls /etc | grep -c .",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.starts_with("bubbler\n2\n"), "{s}");
    assert!(!s.contains("LEAK"));
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
