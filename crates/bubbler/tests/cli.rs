mod common;

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bubbler_core::bwrap::ETC_ALLOWLIST;
use bubbler_core::profile::NAMES;
use bubbler_core::seccomp::{DEFAULT_ENOSYS, DEFAULT_EPERM, syscall_number};
use common::{
    bubbler, bubbler_dbus, bubbler_in_sh, bubbler_live, bwrap_alive, kill_group, real_init,
    require_bwrap, require_dbus, require_portal, require_python, require_system_bus, require_tray,
    system_owns, test_pty,
};
use rustix::fs::{OFlags, fcntl_getfl};
use rustix::process::{Pid, Signal, kill_process};
use rustix::termios::{ControlModes, InputModes, LocalModes, OutputModes, tcgetattr};

fn setup() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("home")).unwrap();
    std::fs::create_dir_all(tmp.path().join("run")).unwrap();
    // Stand-in for the supervisor binary: `$BUBBLER_INIT` must name a
    // regular file for argv building, which is all a dry run needs.
    std::fs::write(tmp.path().join("bubbler-init"), b"").unwrap();
    tmp
}

/// Whether this host has the `/dev/ntsync` node the baseline binds. The
/// kernel module is not loaded everywhere, so both answers are normal.
fn has_ntsync() -> bool {
    std::fs::metadata("/dev/ntsync").is_ok_and(|m| m.file_type().is_char_device())
}

/// The baseline's `/dev/ntsync` bind as `--dry-run` prints it, empty where
/// the host has no such node.
fn ntsync_bind() -> &'static str {
    if has_ntsync() {
        "--dev-bind\n/dev/ntsync\n/dev/ntsync\n"
    } else {
        ""
    }
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
         --info-fd\n3\n--add-seccomp-fd\n4\n--add-seccomp-fd\n5\n\
         --ro-bind\n/usr\n/usr\n--symlink\nusr/bin\n/bin\n--symlink\nusr/lib\n/lib\n\
         --symlink\nusr/lib64\n/lib64\n--symlink\nusr/bin\n/sbin\n\
         --ro-bind-try\n/opt\n/opt\n--tmpfs\n/etc\n";
    let expected_suffix = format!(
        "--proc\n/proc\n--dev\n/dev\n{ntsync}--tmpfs\n/tmp\n--tmpfs\n/var\n--tmpfs\n/run\n\
         --bind\n{home}\n/home/bubbler\n--perms\n0700\n--dir\n{run}\n\
         --ro-bind\n{init}\n/run/bubbler-init\n--clearenv\n--setenv\nTERM\ndumb\n\
         --setenv\nHOME\n/home/bubbler\n--setenv\nPATH\n/usr/bin\n--setenv\nXDG_RUNTIME_DIR\n{run}\n\
         --setenv\nUSER\nbubbler\n--setenv\nLOGNAME\nbubbler\n\
         --\n/run/bubbler-init\n--socket-fd\n8\n--\n/usr/bin/true\n",
        ntsync = ntsync_bind(),
        home = home.display(),
        run = run.display(),
        init = tmp.path().join("bubbler-init").display()
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.starts_with(expected_prefix), "{s}");
    // Fd 3 is the info pipe and 4 and 5 the two seccomp programs.
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n6\n/etc/passwd\n"),
        "{s}"
    );
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n7\n/etc/group\n"),
        "{s}"
    );
    assert!(s.ends_with(&expected_suffix), "{s}");
}

#[test]
fn profiles_lists_builtins_and_firefox_seeds_gpu_and_its_bus_name() {
    let tmp = setup();
    let out = bubbler(tmp.path()).arg("profiles").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let builtins: String = NAMES.iter().map(|n| format!("{n}\n")).collect();
    assert_eq!(String::from_utf8_lossy(&out.stdout), builtins);

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
    assert!(cfg.starts_with("// bubbler profile: firefox\n"), "{cfg}");
    assert!(
        cfg.contains("dri\n") && cfg.contains("own \"org.mozilla.firefox.*\""),
        "{cfg}"
    );
}

/// Write `text` as profile `name` in one of the layers under `root`.
fn write_profile(root: &Path, layer: &str, name: &str, text: &str) -> PathBuf {
    let dir = match layer {
        "user" => root.join("config/bubbler/profiles"),
        _ => root.join("profiles"),
    };
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.kdl"));
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn profiles_list_every_layer_and_origin_names_the_file() {
    let tmp = setup();
    let user = write_profile(
        tmp.path(),
        "user",
        "firefox",
        "include \"firefox\"\nnetwork\n",
    );
    let system = write_profile(tmp.path(), "system", "editor", "wayland\ncommand \"vi\"\n");

    // Every built-in plus the one name only the system layer holds, each
    // listed once whichever layers carry it.
    let mut names: Vec<&str> = NAMES.to_vec();
    names.push("editor");
    names.sort_unstable();

    let out = bubbler(tmp.path()).arg("profiles").output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        names.iter().map(|n| format!("{n}\n")).collect::<String>()
    );

    let out = bubbler(tmp.path())
        .args(["profiles", "--origin"])
        .output()
        .unwrap();
    let expected: String = names
        .iter()
        .map(|n| match *n {
            "editor" => format!("editor\tsystem\t{}\n", system.display()),
            "firefox" => format!("firefox\tuser\t{}\n", user.display()),
            _ => format!("{n}\tbuilt-in\t-\n"),
        })
        .collect();
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
}

#[test]
fn a_user_profile_including_the_built_in_seeds_the_union() {
    let tmp = setup();
    write_profile(
        tmp.path(),
        "user",
        "libreoffice",
        "include \"libreoffice\"\nx11\nenv SAL_USE_VCLPLUGIN=\"qt6\"\n",
    );
    let out = bubbler(tmp.path())
        .args(["create", "lo", "--profile", "libreoffice"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg =
        std::fs::read_to_string(tmp.path().join("data/bubbler/instances/lo/config.kdl")).unwrap();
    // The built-in's grants, the user layer's extra one, and its override
    // of one key rather than a second `env` node for it.
    assert!(cfg.contains("\nwayland\n"), "{cfg}");
    assert!(cfg.contains("\nx11\n"), "{cfg}");
    assert!(cfg.contains("env SAL_USE_VCLPLUGIN=\"qt6\"\n"), "{cfg}");
    assert!(!cfg.contains("gtk3"), "{cfg}");
}

#[test]
fn a_broken_layer_is_reported_and_never_falls_through() {
    let tmp = setup();
    let path = write_profile(tmp.path(), "user", "generic", "bluetooth\n");
    let out = bubbler(tmp.path()).args(["create", "t"]).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(&path.display().to_string()), "{err}");
    assert!(err.contains("unknown node `bluetooth`"), "{err}");
    assert!(!tmp.path().join("data/bubbler/instances/t").exists());
}

#[test]
fn include_in_an_instance_config_is_an_error() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "include \"generic\"\n").unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("include is only valid in profiles"), "{err}");
}

#[test]
fn profile_show_flattens_and_names_the_layer_each_node_came_from() {
    let tmp = setup();
    let user = write_profile(tmp.path(), "user", "app", "include \"base\"\nnetwork\n");
    let system = write_profile(tmp.path(), "system", "base", "wayland\ncommand \"x\"\n");
    let out = bubbler(tmp.path())
        .args(["profile", "show", "app"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "// bubbler profile: app\n// from: {system}\nwayland\n// from: {user}\nnetwork\n\
             // from: {system}\ncommand \"x\"\n",
            system = system.display(),
            user = user.display(),
        )
    );

    let out = bubbler(tmp.path())
        .args(["profile", "show", "generic"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "// bubbler profile: generic\n"
    );

    let out = bubbler(tmp.path())
        .args(["profile", "show", "nope"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown profile `nope`"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn profile_edit_seeds_the_user_layer_and_rechecks_it() {
    let tmp = setup();
    let path = tmp.path().join("config/bubbler/profiles/firefox.kdl");

    // No editor to run means no starting point written: the editor is
    // resolved first, so a host with neither variable set is left exactly
    // as it was rather than holding a profile nobody asked to create.
    let out = bubbler(tmp.path())
        .args(["profile", "edit", "firefox"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("EDITOR"), "{err}");
    assert!(!path.exists(), "{err}");
    assert!(
        !tmp.path().join("config/bubbler/profiles").exists(),
        "{err}"
    );

    let out = bubbler(tmp.path())
        .env("EDITOR", "/usr/bin/true")
        .args(["profile", "edit", "firefox"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The layer below is the built-in, so the seed extends it.
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "// bubbler profile: firefox (user layer)\ninclude \"firefox\"\n"
    );

    // A name no layer holds gets commented examples instead, and both
    // seeds resolve.
    let out = bubbler(tmp.path())
        .env("EDITOR", "/usr/bin/true")
        .args(["profile", "edit", "mine"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mine =
        std::fs::read_to_string(tmp.path().join("config/bubbler/profiles/mine.kdl")).unwrap();
    assert!(
        mine.starts_with("// bubbler profile: mine (user layer)\n"),
        "{mine}"
    );
    assert!(!mine.contains("include"), "{mine}");

    // A blank editor is also caught before the file is written.
    let out = bubbler(tmp.path())
        .env("EDITOR", "   ")
        .args(["profile", "edit", "never"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("blank"), "{err}");
    assert!(
        !tmp.path()
            .join("config/bubbler/profiles/never.kdl")
            .exists()
    );

    // A broken profile is reported and kept, exactly as `edit` does.
    let bad = tmp.path().join("bad-editor");
    write_script(&bad, "#!/usr/bin/sh\nprintf 'bogus\\n' >> \"$1\"\n");
    let out = bubbler(tmp.path())
        .env("EDITOR", &bad)
        .args(["profile", "edit", "firefox"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("still has errors"), "{err}");
    assert!(err.contains("unknown node `bogus`"), "{err}");
    assert!(
        std::fs::read_to_string(&path).unwrap().ends_with("bogus\n"),
        "the file must be kept as the editor left it"
    );

    // An editor that fails hands its own exit code back, and the file it
    // did not finish is left alone.
    let out = bubbler(tmp.path())
        .env("EDITOR", "/usr/bin/false")
        .args(["profile", "edit", "firefox"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(std::fs::read_to_string(&path).unwrap().ends_with("bogus\n"));
}

#[test]
fn reseed_rewrites_the_config_from_the_profile_and_backs_it_up() {
    let tmp = setup();
    write_profile(tmp.path(), "user", "app", "wayland\n");
    let out = bubbler(tmp.path())
        .args(["create", "a", "--profile", "app"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = tmp.path().join("data/bubbler/instances/a/config.kdl");
    let before = std::fs::read_to_string(&cfg).unwrap();

    write_profile(
        tmp.path(),
        "user",
        "app",
        "wayland\nnetwork\ncommand \"sh\"\n",
    );
    let out = bubbler(tmp.path()).args(["reseed", "a"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}\n", cfg.display())
    );
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        "// bubbler profile: app\nwayland\nnetwork\ncommand \"sh\"\n"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("data/bubbler/instances/a/config.kdl.bak"))
            .unwrap(),
        before
    );

    // A config nothing seeded names no profile to re-flatten.
    std::fs::write(&cfg, "wayland\n").unwrap();
    let out = bubbler(tmp.path()).args(["reseed", "a"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("has no `// bubbler profile:"), "{err}");
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "wayland\n");
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

/// `path-share` is refused for everything outside `$BUBBLER_TEST_ALLOW_PATH`
/// here, because a temporary directory lives under the denied `/tmp`.
#[test]
fn path_share_binds_a_host_path_only_with_the_test_hook() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let shared = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(
        &cfg,
        format!(
            "path-share \"{}\"\ncommand \"true\"\n",
            shared.path().display()
        ),
    )
    .unwrap();

    let out = bubbler(tmp.path())
        .env("BUBBLER_TEST_ALLOW_PATH", shared.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!(
            "--ro-bind\n{p}\n{p}\n",
            p = shared.path().display()
        )),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("/tmp"), "{err}");

    // The hook adds one root; it does not switch the denylist off.
    let out = bubbler(tmp.path())
        .env("BUBBLER_TEST_ALLOW_PATH", other.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("/tmp"), "{err}");
}

/// The reserved roots are compared resolved: with `$HOME` reached through
/// a symlink, the real home must still be refused.
#[test]
fn path_share_of_a_symlinked_home_or_data_dir_is_refused() {
    let tmp = setup();
    std::fs::create_dir_all(tmp.path().join("real/home")).unwrap();
    std::fs::create_dir_all(tmp.path().join("real/data/bubbler")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).unwrap();
    let home = tmp.path().join("link/home");
    let data = tmp.path().join("link/data");
    bubbler(tmp.path())
        .env("HOME", &home)
        .env("XDG_DATA_HOME", &data)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = data.join("bubbler/instances/t/config.kdl");
    for path in [tmp.path().join("real/home"), tmp.path().join("real/data")] {
        std::fs::write(
            &cfg,
            format!(
                "path-share \"{}\" mode=rw\ncommand \"true\"\n",
                path.display()
            ),
        )
        .unwrap();
        let out = bubbler(tmp.path())
            .env("HOME", &home)
            .env("XDG_DATA_HOME", &data)
            .env("BUBBLER_TEST_ALLOW_PATH", tmp.path())
            .args(["run", "t", "--dry-run"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{}: {err}", path.display());
        assert!(err.contains("never shares"), "{err}");
    }
}

#[test]
fn test_allow_path_must_be_an_absolute_path_below_the_root() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    for value in ["relative/dir", "/"] {
        let out = bubbler(tmp.path())
            .env("BUBBLER_TEST_ALLOW_PATH", value)
            .args(["run", "t", "--dry-run", "--", "/usr/bin/true"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{value}: {err}");
        assert!(err.contains("BUBBLER_TEST_ALLOW_PATH"), "{value}: {err}");
    }
}

#[test]
fn real_bwrap_path_share_reads_the_host_and_mode_rw_writes_through() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let shared = tempfile::tempdir().unwrap();
    let ro = shared.path().join("ro");
    let rw = shared.path().join("rw");
    std::fs::create_dir(&ro).unwrap();
    std::fs::create_dir(&rw).unwrap();
    std::fs::write(ro.join("hello.txt"), b"from the host\n").unwrap();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(
        &cfg,
        format!(
            "path-share \"{}\"\npath-share \"{}\" mode=rw\n",
            ro.display(),
            rw.display()
        ),
    )
    .unwrap();

    let out = bubbler_live(tmp.path(), &init)
        .env("BUBBLER_TEST_ALLOW_PATH", shared.path())
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            &format!(
                "cat {ro}/hello.txt; touch {ro}/nope.txt 2>/dev/null || echo READONLY; \
                 echo written > {rw}/out.txt",
                ro = ro.display(),
                rw = rw.display()
            ),
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "from the host\nREADONLY\n"
    );
    assert!(!ro.join("nope.txt").exists());
    assert_eq!(
        std::fs::read_to_string(rw.join("out.txt")).unwrap(),
        "written\n"
    );
}

#[test]
fn real_bwrap_gamepad_shows_the_host_input_nodes_and_no_uinput() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/dev/input").is_dir() {
        eprintln!("skipping: this host has no /dev/input directory");
        return;
    }
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "gamepad\n").unwrap();

    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "ls -1 /dev/input; echo ---; test -e /dev/uinput && echo uinput; \
             test -r /run/udev/data && echo udev; true",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (listing, rest) = stdout
        .split_once("---\n")
        .unwrap_or_else(|| panic!("{stdout}"));

    let mut inside: Vec<&str> = listing.lines().collect();
    let mut host: Vec<String> = std::fs::read_dir("/dev/input")
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    inside.sort_unstable();
    host.sort_unstable();
    assert_eq!(inside, host, "{stdout}");

    // The sandbox may not inject input into the host session.
    assert!(!rest.contains("uinput"), "{stdout}");
    assert_eq!(
        rest.contains("udev"),
        Path::new("/run/udev/data").is_dir(),
        "{stdout}"
    );
}

/// Host `/dev` entries named `hidraw*` that really are character
/// devices, sorted: what the `hidraw` property is expected to bind.
fn host_hidraw_nodes() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/dev")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("hidraw"))
                .filter(|e| {
                    e.file_type()
                        .is_ok_and(|t| std::os::unix::fs::FileTypeExt::is_char_device(&t))
                })
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort_unstable();
    names
}

#[test]
fn real_bwrap_gamepad_hidraw_shows_the_host_hidraw_nodes() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/dev/input").is_dir() {
        eprintln!("skipping: this host has no /dev/input directory");
        return;
    }
    let host = host_hidraw_nodes();
    if host.is_empty() {
        eprintln!("skipping: this host has no /dev/hidraw* nodes");
        return;
    }
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "gamepad hidraw=#true\n").unwrap();

    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "ls -1 /dev | grep '^hidraw'; echo ---; test -d /sys/class/hidraw && echo sysfs; true",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (listing, rest) = stdout
        .split_once("---\n")
        .unwrap_or_else(|| panic!("{stdout}"));
    let mut inside: Vec<String> = listing.lines().map(str::to_owned).collect();
    inside.sort_unstable();
    assert_eq!(inside, host, "{stdout}");
    assert_eq!(
        rest.contains("sysfs"),
        Path::new("/sys/class/hidraw").is_dir(),
        "{stdout}"
    );

    // Without the property the same host nodes stay outside.
    std::fs::write(&cfg, "gamepad\n").unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "ls -1 /dev | grep -c '^hidraw' || true",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
}

#[test]
fn real_bwrap_gamepad_uinput_binds_the_node_and_says_so() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/dev/input").is_dir() || !Path::new("/dev/uinput").exists() {
        eprintln!("skipping: this host has no /dev/input directory or no /dev/uinput");
        return;
    }
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "gamepad uinput=#true\n").unwrap();

    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "test -c /dev/uinput && echo injection",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "injection\n");
    // A grant this wide is never a quiet one.
    assert!(err.contains("uinput"), "{err}");
}

#[test]
fn real_bwrap_userns_disable_stops_a_nested_user_namespace() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/usr/bin/unshare").is_file() {
        eprintln!("skipping: this host has no /usr/bin/unshare");
        return;
    }
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    let probe = "/usr/bin/unshare -U /usr/bin/true 2>/dev/null && echo NESTED || echo REFUSED";
    let run = |text: &str| {
        std::fs::write(&cfg, text).unwrap();
        let out = bubbler_live(tmp.path(), &init)
            .args(["run", "t", "--", "/usr/bin/sh", "-c", probe])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    // The default keeps bwrap's own semantics: a nested user namespace,
    // which Steam's pressure-vessel and a browser's inner sandbox need.
    assert_eq!(run(""), "NESTED\n");
    assert_eq!(run("userns \"disable\"\n"), "REFUSED\n");
}

#[test]
fn real_bwrap_dri_hands_over_the_hosts_nvidia_stack() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/dev/nvidiactl").exists() {
        eprintln!("skipping: this host has no NVIDIA device nodes");
        return;
    }
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "dri\n").unwrap();

    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "ls -1 /dev | grep '^nvidia'; echo ---; cat /sys/module/nvidia/initstate; \
             command -v nvidia-smi >/dev/null && { nvidia-smi -L || echo NVML-FAILED; }; true",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (listing, rest) = stdout
        .split_once("---\n")
        .unwrap_or_else(|| panic!("{stdout}"));

    // Every char device, and only those: `/dev/nvidia-caps` holds MIG
    // capability files, which nothing outside MIG reads. The listing is
    // taken before nvidia-smi runs, because NVML creates that directory
    // for itself inside the sandbox's own `/dev` tmpfs.
    let mut host: Vec<String> = std::fs::read_dir("/dev")
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("nvidia")
                && e.file_type().unwrap().is_char_device()
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let mut inside: Vec<String> = listing.lines().map(str::to_owned).collect();
    inside.sort_unstable();
    host.sort_unstable();
    assert_eq!(inside, host, "{stdout}");
    assert!(!inside.iter().any(|n| n == "nvidia-caps"), "{stdout}");

    // What libnvidia-glvnd and NVML gate on; without it both take the Mesa
    // fallback instead.
    assert!(rest.starts_with("live\n"), "{stdout}");
    assert!(!rest.contains("NVML-FAILED"), "{stdout}");
    if Command::new("nvidia-smi")
        .arg("-L")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        assert!(rest.contains("GPU 0:"), "{stdout}");
    }
}

#[test]
fn real_bwrap_ntsync_is_bound_exactly_where_the_host_has_it() {
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
        .args(["run", "t", "--dry-run", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    let argv = String::from_utf8_lossy(&out.stdout);
    assert_eq!(argv.contains("/dev/ntsync"), has_ntsync(), "{argv}");

    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "test -c /dev/ntsync && echo ntsync; true",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).contains("ntsync"),
        has_ntsync(),
        "a sandbox gets the node when the host has it, and nothing when it does not"
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
    /// `$XDG_RUNTIME_DIR/.flatpak/bubbler-<name>`, written only with
    /// `portals`.
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
        flatpak: run_dir.join(".flatpak").join(format!("bubbler-{name}")),
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
fn real_dbus_tray_reaches_the_status_notifier_watcher() {
    if !require_tray() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let name = "bubbler-test-dbus-tray";
    let _leftovers = dbus_instance(tmp.path(), &init, name, "dbus\ntray\ncommand \"true\"\n");

    // A property read on the watcher's own object: the one call the
    // single `--talk` rule has to carry, and it fails without it.
    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            name,
            "--",
            "/usr/bin/dbus-send",
            "--session",
            "--print-reply",
            "--dest=org.kde.StatusNotifierWatcher",
            "/StatusNotifierWatcher",
            "org.freedesktop.DBus.Properties.Get",
            "string:org.kde.StatusNotifierWatcher",
            "string:RegisteredStatusNotifierItems",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(s.contains("variant"), "stdout: {s}stderr: {err}");
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
fn real_system_bus_answers_for_the_names_it_grants_and_no_others() {
    if !require_system_bus() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !system_owns("org.freedesktop.UPower") {
        eprintln!("skipping: the host system bus has no org.freedesktop.UPower");
        return;
    }
    let tmp = setup();
    let name = "bubbler-test-system-bus";
    let _leftovers = dbus_instance(
        tmp.path(),
        &init,
        name,
        "system-bus { talk \"org.freedesktop.UPower\" }\ncommand \"true\"\n",
    );

    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            name,
            "--",
            "/usr/bin/dbus-send",
            "--system",
            "--print-reply",
            "--dest=org.freedesktop.UPower",
            "/org/freedesktop/UPower",
            "org.freedesktop.UPower.EnumerateDevices",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(s.contains("array"), "stdout: {s}stderr: {err}");

    // A name the host bus does own and no rule grants: the proxy answers
    // for it instead of letting the call through.
    if !system_owns("org.freedesktop.login1") {
        eprintln!("skipping the denial half: the host has no org.freedesktop.login1");
        return;
    }
    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            name,
            "--",
            "/usr/bin/dbus-send",
            "--system",
            "--print-reply",
            "--dest=org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.DBus.Peer.Ping",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "the ungranted name answered");
    assert!(
        err.contains("AccessDenied") || err.contains("ServiceUnknown"),
        "{err}"
    );
}

#[test]
fn real_system_bus_needs_no_session_bus_and_is_absent_without_the_node() {
    if !require_system_bus() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    // The socket, the address and the session bus are three separate
    // things: the system bus grant brings the first and neither other.
    const PROBE: &str = r#"test -S /run/dbus/system_bus_socket || { echo NOSOCKET; exit 1; }
test -z "$DBUS_SESSION_BUS_ADDRESS" || { echo SESSIONADDR; exit 1; }
test -z "$DBUS_SYSTEM_BUS_ADDRESS" || { echo SYSTEMADDR; exit 1; }
test ! -e "$XDG_RUNTIME_DIR/bus" || { echo SESSIONSOCKET; exit 1; }
echo OK"#;
    let name = "bubbler-test-system-bus-alone";
    let _leftovers = dbus_instance(
        tmp.path(),
        &init,
        name,
        "system-bus { talk \"org.freedesktop.UPower\" }\ncommand \"true\"\n",
    );
    let out = bubbler_dbus(tmp.path(), &init)
        .args(["run", name, "--", "/usr/bin/sh", "-c", PROBE])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {s}stderr: {err}");
    assert!(s.contains("OK"), "stdout: {s}stderr: {err}");

    // And without the node the sandbox has no system bus at all, whether
    // or not it has a session one.
    let bare = "bubbler-test-system-bus-none";
    let _bare = dbus_instance(tmp.path(), &init, bare, "dbus\ncommand \"true\"\n");
    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            bare,
            "--",
            "/usr/bin/sh",
            "-c",
            r#"test ! -e /run/dbus/system_bus_socket || { echo LEAK; exit 1; }"#,
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {s}stderr: {err}");
    assert!(!s.contains("LEAK"), "stdout: {s}stderr: {err}");
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

/// A stand-in for `xdg-dbus-proxy` that binds a socket, reports itself
/// ready like a real one, and from then on keeps replacing that socket
/// with a symlink by atomic rename. It stops when its ready pipe closes.
fn racing_proxy(path: &Path) {
    write_script(
        path,
        r#"#!/usr/bin/python3
import os, select, socket, sys, time
args = sys.argv[1:]
fd = int(args[0].split("=", 1)[1])
bus = args[2]
d = os.path.dirname(bus)
stage, link = os.path.join(d, "stage-s"), os.path.join(d, "stage-l")

def fresh_socket():
    try:
        os.unlink(stage)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX)
    s.bind(stage)
    s.listen(8)
    os.rename(stage, bus)
    return s

def fresh_link():
    try:
        os.unlink(link)
    except FileNotFoundError:
        pass
    os.symlink("/etc", link)
    os.rename(link, bus)

held = fresh_socket()
os.write(fd, b"r")
poller = select.poll()
poller.register(fd, 0)
deadline = time.time() + 15
while time.time() < deadline:
    if poller.poll(0):
        break
    fresh_link()
    held.close()
    held = fresh_socket()
"#,
    );
}

#[test]
fn a_proxy_racing_its_own_socket_never_gets_a_symlink_bound() {
    if !require_bwrap() || !require_python() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let bus = tmp.path().join("fakebus");
    let _listener = UnixListener::bind(&bus).unwrap();
    let racer = tmp.path().join("race-proxy");
    racing_proxy(&racer);
    let out = bubbler_live(tmp.path(), &init)
        .args(["create", "race"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(
        tmp.path().join("data/bubbler/instances/race/config.kdl"),
        "dbus\n",
    )
    .unwrap();
    let mut refused = 0;
    let mut ran = 0;
    for i in 0..30 {
        let out = bubbler_live(tmp.path(), &init)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", bus.display()),
            )
            .env("BUBBLER_DBUS_PROXY", &racer)
            .args([
                "run",
                "race",
                "--",
                "/usr/bin/sh",
                "-c",
                // What the sandbox sees at the bus path: only ever a
                // socket, never the symlink's target.
                r#"test -S "$XDG_RUNTIME_DIR/bus" || { echo LEAK; ls "$XDG_RUNTIME_DIR/bus"; }"#,
            ])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("LEAK"), "run {i}: {stdout}{err}");
        match out.status.code() {
            Some(0) => ran += 1,
            Some(1) if err.contains("a socket") => refused += 1,
            other => panic!("run {i}: exit {other:?}: {stdout}{err}"),
        }
        assert!(
            !tmp.path().join("run/bubbler/race/bus").exists(),
            "run {i} left the moved entry behind"
        );
    }
    // Both outcomes have to occur, or the race was never run at all.
    assert!(ran > 0 && refused > 0, "{ran} ran, {refused} refused");
}

/// A stand-in for `xdg-dbus-proxy` that puts a non-empty directory where
/// its socket belongs, which cannot be unlinked as a file.
fn directory_proxy(path: &Path) {
    write_script(
        path,
        "#!/bin/sh\nmkdir -p \"$3\"\n: > \"$3/x\"\neval \"echo r >&${1#--fd=}\"\nexec sleep 5\n",
    );
}

/// A stand-in for `xdg-dbus-proxy` that does the honest thing: bind a
/// socket, report ready, and leave when the ready pipe closes.
fn honest_proxy(path: &Path) {
    write_script(
        path,
        r#"#!/usr/bin/python3
import os, select, socket, sys, time
fd = int(sys.argv[1].split("=", 1)[1])
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[3])
s.listen(8)
os.write(fd, b"r")
poller = select.poll()
poller.register(fd, 0)
deadline = time.time() + 15
while time.time() < deadline and not poller.poll(20):
    pass
"#,
    );
}

#[test]
fn a_directory_left_at_the_socket_path_does_not_wedge_the_instance() {
    if !require_bwrap() || !require_python() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let bus = tmp.path().join("fakebus");
    let _listener = UnixListener::bind(&bus).unwrap();
    let planting = tmp.path().join("dir-proxy");
    directory_proxy(&planting);
    let honest = tmp.path().join("honest-proxy");
    honest_proxy(&honest);
    let out = bubbler_live(tmp.path(), &init)
        .args(["create", "wedge"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(
        tmp.path().join("data/bubbler/instances/wedge/config.kdl"),
        "dbus\n",
    )
    .unwrap();
    let run = |proxy: &Path| {
        bubbler_live(tmp.path(), &init)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", bus.display()),
            )
            .env("BUBBLER_DBUS_PROXY", proxy)
            .args([
                "run",
                "wedge",
                "--",
                "/usr/bin/sh",
                "-c",
                r#"test -S "$XDG_RUNTIME_DIR/bus""#,
            ])
            .output()
            .unwrap()
    };

    let out = run(&planting);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("a socket"), "{err}");
    let left: Vec<_> = std::fs::read_dir(tmp.path().join("run/bubbler/wedge"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "the refused run left {left:?}");

    // The name has to be free again: renaming a socket onto a directory
    // fails, so a leftover would fail every later start.
    let out = run(&honest);
    assert!(
        out.status.success(),
        "the instance stayed wedged: {}",
        String::from_utf8_lossy(&out.stderr)
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
        "tray",
        "gamepad",
    ] {
        assert!(err.contains(grant), "{grant} missing from {err}");
    }

    // A bundle grant is refused by the same parse check whether it comes
    // from a config file or from `--grant`.
    for grant in ["portals", "tray"] {
        let out = bubbler(tmp.path())
            .args(["try", "--grant", grant, "--", "/usr/bin/true"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("requires dbus"), "{grant}: {err}");
    }

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
fn try_keeps_nothing_when_the_launch_never_happened() {
    let tmp = setup();
    // A `$BUBBLER_INIT` that is not there fails the launch itself, after
    // the throwaway sandbox has been created.
    let out = bubbler(tmp.path())
        .env("BUBBLER_INIT", tmp.path().join("gone"))
        .args(["try", "--keep", "kept", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    let out = bubbler(tmp.path()).arg("list").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(!tmp.path().join("data/bubbler/instances/kept").exists());
}

#[test]
fn try_refuses_a_keep_name_whose_sockets_would_be_truncated() {
    let tmp = setup();
    // The name is checked before anything is launched, so what the user
    // sees is the name they can fix, not a bind failing later.
    let out = bubbler(tmp.path())
        .args(["try", "--keep", &"k".repeat(100), "--", "/usr/bin/true"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("Unix socket path"), "{err}");
    assert!(!err.contains("bwrap"), "{err}");
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

/// What a command sees of its terminal: the device behind its stdin, the
/// one bwrap bound at `/dev/console`, and the one the kernel calls its
/// controlling terminal.
///
/// The devices are read from descriptors through `/proc/self/fd`, which
/// the kernel resolves to the open file itself. Paths cannot answer this:
/// `/dev/tty` is the 5:0 node in every session, and the pty's own
/// `/dev/pts` name is the host's, which the sandbox's fresh devpts does
/// not have.
const TTY_PROBE: &str = concat!(
    r#"echo "fd0 $(stat -L -c %Hr:%Lr /proc/self/fd/0)"; "#,
    r#"echo "console $(stat -L -c %Hr:%Lr /dev/console 2>/dev/null)"; "#,
    // Field 7 of /proc/<pid>/stat is `tty_nr`, the controlling terminal
    // the kernel recorded, and 0 when there is none. Field 2 is `comm`,
    // which is `sh` here and holds no space to shift the fields.
    r#"echo "ttynr $(awk '{print $7}' /proc/self/stat)""#,
);

/// The `tty_nr` the kernel records for the device `major:minor`, encoded
/// as `MKDEV` does it (`include/linux/kdev_t.h`): the low eight bits of
/// the minor sit under the major and the rest above it.
fn tty_nr(dev: &str) -> u64 {
    let (major, minor) = dev.split_once(':').expect("a `major:minor` device");
    let (major, minor): (u64, u64) = (major.parse().unwrap(), minor.parse().unwrap());
    (major << 8) | (minor & 0xff) | ((minor & !0xff) << 12)
}

/// The value the probe printed for `key`.
fn probed<'a>(out: &'a str, key: &str) -> &'a str {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key} ")))
        .unwrap_or_else(|| panic!("no `{key}` line in {out:?}"))
        .trim()
}

/// An instance ready to be run, with the real supervisor behind it.
fn live_instance(name: &str) -> Option<(tempfile::TempDir, PathBuf)> {
    if !require_bwrap() {
        return None;
    }
    let init = real_init()?;
    let tmp = setup();
    let out = bubbler_live(tmp.path(), &init)
        .args(["create", name])
        .output()
        .unwrap();
    assert!(out.status.success(), "creating `{name}` failed");
    Some((tmp, init))
}

#[test]
fn real_bwrap_run_from_a_terminal_gives_the_sandbox_a_terminal_of_its_own() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    let mut run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/sh", "-c", TTY_PROBE])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    let out = pty.read_until(Duration::from_secs(20), |s| s.contains("ttynr "));
    assert_eq!(run.wait().unwrap().code(), Some(0), "{out:?}");
    let (fd0, console) = (probed(&out, "fd0"), probed(&out, "console"));
    assert_eq!(
        fd0, console,
        "/dev/console is not the sandbox's own pty:\n{out}"
    );
    assert_ne!(
        fd0,
        pty.dev(),
        "the sandbox was handed the host terminal:\n{out}"
    );
    assert_eq!(
        probed(&out, "ttynr").parse::<u64>().unwrap(),
        tty_nr(fd0),
        "the sandbox's pty is not its controlling terminal:\n{out}"
    );
}

#[test]
fn real_bwrap_run_with_tty_passthrough_hands_over_the_host_terminal() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    let mut run = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--tty",
            "passthrough",
            "--",
            "/usr/bin/sh",
            "-c",
            TTY_PROBE,
        ])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    let out = pty.read_until(Duration::from_secs(20), |s| s.contains("ttynr "));
    assert_eq!(run.wait().unwrap().code(), Some(0), "{out:?}");
    // The old behaviour, kept as a knob: bwrap binds the user's own
    // terminal at /dev/console for anything inside to open, and the
    // sandbox's stdin is that terminal.
    assert_eq!(probed(&out, "console"), pty.dev(), "{out}");
    assert_eq!(probed(&out, "fd0"), pty.dev(), "{out}");
    assert_eq!(
        probed(&out, "ttynr"),
        "0",
        "passthrough must not take the user's terminal:\n{out}"
    );
}

#[test]
fn real_bwrap_run_writes_nothing_to_a_terminal_it_does_not_own() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    // Only stdin is the terminal, so the sandbox's own output goes to the
    // pipe and anything reaching the pty came from /dev/console.
    let run = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "test -e /dev/console && echo CONSOLE; echo INJECT > /dev/console 2>&1; echo done",
        ])
        .stdin(pty.stdio())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = run.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("done"), "{stdout:?}");
    assert!(
        !stdout.contains("CONSOLE"),
        "a /dev/console was bound although no output went to a terminal:\n{stdout}"
    );
    let seen = pty.read_until(Duration::from_millis(300), |_| false);
    assert!(
        !seen.contains("INJECT"),
        "the sandbox wrote to the user's terminal: {seen:?}"
    );
}

#[test]
fn real_bwrap_run_survives_a_terminal_that_cannot_take_its_output() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    // `bubbler run t < /dev/tty > out 2> err`: the only terminal is a
    // read-only descriptor, so the pty's output has nowhere to go — and
    // that must cost the run nothing, neither its command nor its status.
    let path = std::fs::read_link(format!("/proc/self/fd/{}", pty.slave.as_raw_fd())).unwrap();
    let read_only = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let (out, err) = (tmp.path().join("out"), tmp.path().join("err"));
    let mut run = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "read line; echo GOT $line; exit 4",
        ])
        .stdin(Stdio::from(read_only))
        .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&err).unwrap()))
        .spawn()
        .unwrap();
    pty.type_in(b"hello\n");
    let mut status = None;
    let finished = wait_until(
        || {
            status = run.try_wait().expect("waiting for the run");
            status.is_some()
        },
        Duration::from_secs(20),
    );
    let said = std::fs::read_to_string(&err).unwrap_or_default();
    if !finished {
        let _ = run.kill();
        panic!("the run never finished: {said}");
    }
    // The command's own status, not a failed relay's.
    assert_eq!(status.and_then(|s| s.code()), Some(4), "{said}");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "GOT hello\n",
        "{said}"
    );
}

#[test]
fn real_bwrap_run_with_tty_none_outlives_a_reader_that_leaves() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    // `bubbler run t --tty none -- ... | head -c 100`: the reader is gone
    // long before the command is, and the pipe bubbler pumps into stops
    // taking anything. Nothing may block on that — neither the command
    // inside, on a pipe nobody empties, nor bubbler, waiting for it.
    let mut run = bubbler_in_sh(
        tmp.path(),
        &init,
        "\"$B\" run t --tty none -- /usr/bin/sh -c 'yes bytes | head -c 1000000' | head -c 100",
    )
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let mut status = None;
    let finished = wait_until(
        || {
            status = run.try_wait().expect("waiting for the run");
            status.is_some()
        },
        Duration::from_secs(15),
    );
    if !finished {
        // The shell's whole group: the bubbler and bwrap behind it must
        // not outlive the test that gave up on them.
        kill_group(&run);
        let _ = run.wait();
        panic!("bubbler never finished after its output pipe closed");
    }
    let out = run.wait_with_output().expect("collecting stderr");
    let err = String::from_utf8_lossy(&out.stderr);
    // Truncation is not silent, and it names the fd the user knows.
    assert!(err.contains("bubbler: output to stdout failed"), "{err:?}");
    assert!(err.contains("discarding further output"), "{err:?}");
}

#[test]
fn real_bwrap_run_returns_the_status_when_the_terminal_goes_away() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    let mut run = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "echo started; sleep 0.3; yes bytes | head -c 400000; exit 5",
        ])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    // Only once the relay is really running: a terminal that is already
    // gone is not a terminal at all, and no pty would be allocated.
    let out = pty.read_until(Duration::from_secs(20), |s| s.contains("started"));
    assert!(
        out.contains("started"),
        "the sandbox never started: {out:?}"
    );
    // The user's terminal disappears mid-run, before the command's bulk
    // output. Everything written from here on has nowhere to go, and a
    // relay that stopped reading would leave the command blocked on a
    // full pty for good.
    drop(pty);
    let mut status = None;
    let finished = wait_until(
        || {
            status = run.try_wait().expect("waiting for the run");
            status.is_some()
        },
        Duration::from_secs(15),
    );
    if !finished {
        let _ = run.kill();
        panic!("bubbler never finished after its terminal went away");
    }
    // The command's own status, still reported after the relay lost its end.
    assert_eq!(status.and_then(|s| s.code()), Some(5));
}

#[test]
fn real_bwrap_run_with_a_closed_stdout_hands_the_sandbox_dev_null() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    // `bubbler run t 1>&-`: the slot is empty, and whatever bubbler opens
    // next must not become the sandbox's stdout. The probe reads fd 1
    // through a duplicate, because `>&2` would replace the very fd it is
    // asked about.
    let out = bubbler_in_sh(
        tmp.path(),
        &init,
        "exec \"$B\" run t -- /usr/bin/sh -c 'exec 4>&1; readlink /proc/self/fd/4 >&2' 1>&-",
    )
    .stderr(Stdio::piped())
    .output()
    .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.trim(), "/dev/null", "{err:?}");
}

#[test]
fn real_bwrap_run_with_tty_none_leaves_the_sandbox_without_one() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    let mut run = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--tty",
            "none",
            "--",
            "/usr/bin/sh",
            "-c",
            "tty; test -e /dev/console || echo NOCONSOLE; echo hello",
        ])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    let out = pty.read_until(Duration::from_secs(20), |s| s.contains("hello"));
    assert_eq!(run.wait().unwrap().code(), Some(0), "{out:?}");
    // The output still reaches the terminal, through bubbler's pipes.
    assert!(out.contains("not a tty"), "{out:?}");
    assert!(out.contains("NOCONSOLE"), "{out:?}");
    assert!(out.contains("hello"), "{out:?}");
}

#[test]
fn real_bwrap_run_reads_a_pipe_on_stdin_while_the_terminal_takes_the_output() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    let mut run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    // A pipe is not a terminal, so `cat` reads it directly; only the
    // output side is replaced by the pty.
    let mut stdin = run.stdin.take().expect("stdin was piped");
    std::io::Write::write_all(&mut stdin, b"piped in\n").unwrap();
    drop(stdin);
    let out = pty.read_until(Duration::from_secs(20), |s| s.contains("piped in"));
    assert_eq!(run.wait().unwrap().code(), Some(0), "{out:?}");
    assert!(out.contains("piped in"), "{out:?}");
}

/// What an exec'd command must see of the terminal it was given: its own
/// session, and the window size of the user's terminal.
const EXEC_PROBE: &str = concat!(
    r#"test "$(ps -o sid= -p $$ | tr -d ' ')" = "$$" && echo LEADER; "#,
    r#"echo "size $(stty size)""#,
);

#[test]
fn real_bwrap_exec_from_a_terminal_leads_its_own_session_with_the_window_size() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/sleep", "30"])
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

    let pty = test_pty();
    let mut exec = bubbler_live(tmp.path(), &init)
        .args(["exec", "t", "--", "/usr/bin/sh", "-c", EXEC_PROBE])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    let out = pty.read_until(Duration::from_secs(20), |s| s.contains("size "));
    assert_eq!(exec.wait().unwrap().code(), Some(0), "{out:?}");
    assert!(
        out.contains("LEADER"),
        "the command leads no session:\n{out}"
    );
    assert_eq!(probed(&out, "size"), "24 80", "{out:?}");

    // Passthrough is the old behaviour: bubbler's own fds, and no session
    // of its own, because taking one would take the user's terminal.
    let plain = test_pty();
    let mut exec = bubbler_live(tmp.path(), &init)
        .args([
            "exec",
            "t",
            "--tty",
            "passthrough",
            "--",
            "/usr/bin/sh",
            "-c",
            EXEC_PROBE,
        ])
        .stdin(plain.stdio())
        .stdout(plain.stdio())
        .stderr(plain.stdio())
        .spawn()
        .unwrap();
    let out = plain.read_until(Duration::from_secs(20), |s| s.contains("size "));
    assert_eq!(exec.wait().unwrap().code(), Some(0), "{out:?}");
    assert!(!out.contains("LEADER"), "took a session anyway:\n{out}");

    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    let mut run = run;
    assert!(
        wait_until(
            || run.try_wait().expect("waiting for the run").is_some(),
            Duration::from_secs(8)
        ),
        "the run did not stop after SIGTERM"
    );
}

#[test]
fn real_bwrap_run_detaches_on_three_escapes_and_keeps_the_sandbox() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    let mut run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/sleep", "30"])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    let sock = tmp.path().join("run/bubbler/t/init.sock");
    if !wait_until(
        || UnixStream::connect(&sock).is_ok(),
        Duration::from_secs(10),
    ) {
        let _ = run.kill();
        panic!("the instance never accepted a connection");
    }
    pty.type_in(&[0x1d, 0x1d, 0x1d]);
    let out = pty.read_until(Duration::from_secs(5), |s| s.contains("detached"));
    assert!(out.contains("bubbler: detached"), "no detach note: {out:?}");
    // The sandbox is still there, and bubbler is still waiting for it:
    // leaving would end it through --die-with-parent.
    assert!(UnixStream::connect(&sock).is_ok(), "the instance is gone");
    assert!(run.try_wait().unwrap().is_none(), "bubbler left with it");

    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    assert!(
        wait_until(
            || run.try_wait().expect("waiting for the run").is_some(),
            Duration::from_secs(8)
        ),
        "the detached run did not stop after SIGTERM"
    );
}

/// Whether a terminal is in raw mode, which is how a test sees that
/// bubbler has taken it over.
fn is_raw(fd: BorrowedFd<'_>) -> bool {
    !tcgetattr(fd)
        .unwrap()
        .local_modes
        .contains(LocalModes::ICANON)
}

/// The terminal settings a test compares before and after: the four mode
/// words, which is everything raw mode changes about them.
fn modes(fd: BorrowedFd<'_>) -> (InputModes, OutputModes, ControlModes, LocalModes) {
    let t = tcgetattr(fd).unwrap();
    (
        t.input_modes,
        t.output_modes,
        t.control_modes,
        t.local_modes,
    )
}

/// Fail if `fd`'s open file description does not keep the flags `want`
/// for `window`. A relay that made the user's own descriptor
/// non-blocking shows up here wherever inside the window it started.
fn flags_hold(fd: BorrowedFd<'_>, want: OFlags, window: Duration) {
    let until = Instant::now() + window;
    while Instant::now() < until {
        assert_eq!(
            fcntl_getfl(fd).unwrap(),
            want,
            "the relay changed the flags of the user's own descriptor"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn real_bwrap_exec_stops_on_a_signal_and_gives_the_terminal_back() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/sleep", "30"])
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
    let pty = test_pty();
    let before = modes(pty.slave.as_fd());
    // The flags of the open file description the terminal's descriptor
    // carries, which a shell handing bubbler its own fd would share.
    let flags = fcntl_getfl(pty.slave.as_fd()).unwrap();
    let mut exec = bubbler_live(tmp.path(), &init)
        .args(["exec", "t", "--", "/usr/bin/sleep", "30"])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    // Only once the relay really holds the terminal: a signal before that
    // would prove nothing about handing it back.
    assert!(
        wait_until(|| is_raw(pty.slave.as_fd()), Duration::from_secs(10)),
        "the exec never put the terminal in raw mode"
    );
    // Mid-relay: the non-blocking writes go through a description bubbler
    // opened for itself, so nothing a SIGKILL could leave behind ever
    // reaches the descriptor the user holds.
    flags_hold(pty.slave.as_fd(), flags, Duration::from_secs(1));
    kill_process(Pid::from_child(&exec), Signal::TERM).unwrap();
    let mut status = None;
    let stopped = wait_until(
        || {
            status = exec.try_wait().expect("waiting for the exec");
            status.is_some()
        },
        Duration::from_secs(1),
    );
    if !stopped {
        let _ = exec.kill();
        panic!("the exec did not stop within a second of SIGTERM");
    }
    assert_eq!(status.and_then(|s| s.code()), Some(128 + 15));
    // And the terminal is the user's again, exactly as they left it.
    assert_eq!(modes(pty.slave.as_fd()), before);
    assert_eq!(fcntl_getfl(pty.slave.as_fd()).unwrap(), flags);

    let mut run = run;
    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    assert!(
        wait_until(
            || run.try_wait().expect("waiting for the run").is_some(),
            Duration::from_secs(8)
        ),
        "the run did not stop after SIGTERM"
    );
}

#[test]
fn real_bwrap_exec_stops_on_a_signal_with_the_terminal_wedged() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    // Its own process group, so a test that gives up on it can end the
    // bubbler and the bwrap under it instead of leaving them running.
    let run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/sleep", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let sock = tmp.path().join("run/bubbler/t/init.sock");
    if !wait_until(
        || UnixStream::connect(&sock).is_ok(),
        Duration::from_secs(10),
    ) {
        kill_group(&run);
        fail_with(run, "the instance never accepted a connection");
    }
    let pty = test_pty();
    let before = modes(pty.slave.as_fd());
    // Nothing ever reads this terminal, so the command floods it until
    // every buffer between the two is full and bubbler is left holding
    // the rest. Its own stderr is that same terminal, so the warning
    // about output it has to drop has nowhere to go either: writing it
    // is what would park the relay, with the signals unanswered and only
    // SIGKILL left.
    let mut exec = bubbler_live(tmp.path(), &init)
        .args(["exec", "t", "--", "/usr/bin/seq", "1", "200000"])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    assert!(
        wait_until(|| is_raw(pty.slave.as_fd()), Duration::from_secs(10)),
        "the exec never put the terminal in raw mode"
    );
    // Long enough for the flood to have filled everything downstream.
    std::thread::sleep(Duration::from_millis(500));
    kill_process(Pid::from_child(&exec), Signal::TERM).unwrap();
    let mut status = None;
    let stopped = wait_until(
        || {
            status = exec.try_wait().expect("waiting for the exec");
            status.is_some()
        },
        Duration::from_secs(2),
    );
    if !stopped {
        let _ = exec.kill();
        kill_group(&run);
        panic!("the exec did not stop within two seconds of SIGTERM");
    }
    assert_eq!(status.and_then(|s| s.code()), Some(128 + 15));
    assert_eq!(modes(pty.slave.as_fd()), before);

    let mut run = run;
    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    assert!(
        wait_until(
            || run.try_wait().expect("waiting for the run").is_some(),
            Duration::from_secs(8)
        ),
        "the run did not stop after SIGTERM"
    );
}

#[test]
fn real_bwrap_run_gives_the_terminal_back_after_a_hangup() {
    let Some((tmp, init)) = live_instance("t") else {
        return;
    };
    let pty = test_pty();
    let before = modes(pty.slave.as_fd());
    let flags = fcntl_getfl(pty.slave.as_fd()).unwrap();
    let mut run = bubbler_live(tmp.path(), &init)
        .args(["run", "t", "--", "/usr/bin/sleep", "30"])
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio())
        .spawn()
        .unwrap();
    assert!(
        wait_until(|| is_raw(pty.slave.as_fd()), Duration::from_secs(20)),
        "the run never put the terminal in raw mode"
    );
    flags_hold(pty.slave.as_fd(), flags, Duration::from_secs(1));
    // A terminal that hangs up: the sandbox is stopped like any other
    // signal, and the settings are put back on the way out.
    kill_process(Pid::from_child(&run), Signal::HUP).unwrap();
    assert!(
        wait_until(
            || run.try_wait().expect("waiting for the run").is_some(),
            Duration::from_secs(10)
        ),
        "the run did not stop after SIGHUP"
    );
    assert_eq!(modes(pty.slave.as_fd()), before);
    assert_eq!(fcntl_getfl(pty.slave.as_fd()).unwrap(), flags);
}

/// A python probe reporting how each syscall the default filter denies
/// actually fails inside the sandbox, as `name value` lines. The numbers
/// are resolved on the host, so it is right for whatever architecture the
/// tests run on; `ioctl` goes through libc, since its request argument is
/// what the filter looks at.
fn probe_source() -> String {
    let nr = |name: &str| {
        syscall_number(name).unwrap_or_else(|| panic!("no `{name}` on this architecture"))
    };
    format!(
        r#"import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

def named(rc):
    if rc >= 0:
        return "ok"
    e = ctypes.get_errno()
    return errno.errorcode.get(e, "E%d" % e)

def call(nr, *args):
    ctypes.set_errno(0)
    return named(libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args]))

def ioctl(request):
    ctypes.set_errno(0)
    buf = ctypes.create_string_buffer(b"x")
    return named(libc.ioctl(0, ctypes.c_ulong(request), buf))

probe = [
    # KEYCTL_GET_KEYRING_ID of KEY_SPEC_SESSION_KEYRING, creating nothing.
    ("keyctl", call({keyctl}, 0, -3, 0)),
    # A null attribute struct: the kernel faults before it opens anything.
    ("perf_event_open", call({perf_event_open}, 0, 0, -1, -1, 0)),
    # Size 0 is rejected before any thread is made, so nothing is forked.
    ("clone3", call({clone3}, 0, 0)),
    ("tiocsti", ioctl(0x5412)),
    ("tioclinux", ioctl(0x541C)),
    ("getpid", call({getpid})),
]
report = "\n".join("%s %s" % p for p in probe)
"#,
        keyctl = nr("keyctl"),
        perf_event_open = nr("perf_event_open"),
        clone3 = nr("clone3"),
        getpid = nr("getpid"),
    )
}

/// The probe as a one-shot program for `python3 -c`.
fn probe_program() -> String {
    format!("{}print(report)\n", probe_source())
}

/// Run the probe inside `name`, whose `config.kdl` is `config`, and
/// return its `name value` lines.
fn probe_in(name: &str, config: &str) -> Option<(String, String)> {
    if !require_python() {
        return None;
    }
    let (tmp, init) = live_instance(name)?;
    std::fs::write(
        tmp.path()
            .join("data/bubbler/instances")
            .join(name)
            .join("config.kdl"),
        config,
    )
    .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            name,
            "--",
            "/usr/bin/python3",
            "-c",
            &probe_program(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{stderr}");
    Some((String::from_utf8_lossy(&out.stdout).into_owned(), stderr))
}

#[test]
fn a_filter_a_profile_emptied_is_as_loud_as_a_disabled_one() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    // Allowing every name back leaves nothing to load, which is
    // `seccomp { disable }` taken the long way round.
    let names: Vec<String> = DEFAULT_EPERM
        .iter()
        .chain(DEFAULT_ENOSYS)
        .filter(|n| syscall_number(n).is_some())
        .map(|n| format!("\"{n}\""))
        .collect();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        format!(
            "seccomp {{ allow \"ioctl\" {} }}\ncommand \"/usr/bin/true\"\n",
            names.join(" ")
        ),
    )
    .unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("bubbler: seccomp has no rules left for instance t"),
        "{err}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("--add-seccomp-fd"),
        "an empty filter must load nothing"
    );
}

#[test]
fn real_bwrap_seccomp_denies_the_default_list_and_nothing_else() {
    let Some((out, _)) = probe_in("secc", "") else {
        return;
    };
    assert_eq!(probed(&out, "keyctl"), "EPERM", "{out}");
    assert_eq!(probed(&out, "perf_event_open"), "EPERM", "{out}");
    // ENOSYS, so glibc falls back to `clone`; unfiltered this is EINVAL.
    assert_eq!(probed(&out, "clone3"), "ENOSYS", "{out}");
    assert_eq!(probed(&out, "tiocsti"), "EPERM", "{out}");
    assert_eq!(probed(&out, "tioclinux"), "EPERM", "{out}");
    // A denylist: everything not named keeps working.
    assert_eq!(probed(&out, "getpid"), "ok", "{out}");
}

#[test]
fn real_bwrap_seccomp_allow_hands_one_syscall_back() {
    let Some((out, _)) = probe_in("secca", "seccomp { allow \"keyctl\" }\n") else {
        return;
    };
    assert_ne!(probed(&out, "keyctl"), "EPERM", "{out}");
    assert_eq!(probed(&out, "perf_event_open"), "EPERM", "{out}");
    assert_eq!(probed(&out, "clone3"), "ENOSYS", "{out}");
}

#[test]
fn real_bwrap_seccomp_disable_leaves_the_sandbox_unfiltered_and_says_so() {
    let Some((out, err)) = probe_in("seccd", "seccomp { disable }\n") else {
        return;
    };
    assert!(
        err.contains("bubbler: seccomp disabled for instance seccd"),
        "{err}"
    );
    assert_ne!(probed(&out, "keyctl"), "EPERM", "{out}");
    assert_ne!(probed(&out, "perf_event_open"), "EPERM", "{out}");
    assert_ne!(probed(&out, "clone3"), "ENOSYS", "{out}");
    assert_ne!(probed(&out, "tiocsti"), "EPERM", "{out}");
}

#[test]
fn real_bwrap_seccomp_leaves_threads_and_installed_programs_running() {
    if !require_python() {
        return;
    }
    let Some((tmp, init)) = live_instance("seccr") else {
        return;
    };
    // clone3 answers ENOSYS, so a thread is only created if glibc really
    // does fall back to `clone`.
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "seccr",
            "--",
            "/usr/bin/python3",
            "-c",
            "import threading\nt = threading.Thread(target=lambda: print('thread ok'))\nt.start()\nt.join()\n",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "thread ok\n");

    for program in ["/usr/bin/alacritty", "/usr/bin/firefox"] {
        if !Path::new(program).is_file() {
            eprintln!("skipping: {program} is not installed");
            continue;
        }
        let out = bubbler_live(tmp.path(), &init)
            .args(["run", "seccr", "--", program, "--version"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{program} --version under the filter: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A stand-in for `xdg-dbus-proxy` that runs the probe first and leaves
/// its report next to the socket it then serves, which is the only place
/// the proxy sandbox can write to.
fn probing_proxy(path: &Path) {
    write_script(
        path,
        &format!(
            r#"#!/usr/bin/python3
import os, select, socket, sys, time
{probe}
d = os.path.dirname(sys.argv[3])
with open(os.path.join(d, "probe.part"), "w") as f:
    f.write(report)
os.rename(os.path.join(d, "probe.part"), os.path.join(d, "probe.txt"))
fd = int(sys.argv[1].split("=", 1)[1])
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[3])
s.listen(8)
os.write(fd, b"r")
poller = select.poll()
poller.register(fd, 0)
deadline = time.time() + 15
while time.time() < deadline and not poller.poll(20):
    pass
"#,
            probe = probe_source()
        ),
    );
}

#[test]
fn real_bwrap_seccomp_covers_the_dbus_proxy_sandbox() {
    if !require_bwrap() || !require_python() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let bus = tmp.path().join("fakebus");
    let _listener = UnixListener::bind(&bus).unwrap();
    let proxy = tmp.path().join("probe-proxy");
    probing_proxy(&proxy);
    let out = bubbler_live(tmp.path(), &init)
        .args(["create", "seccp"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(
        tmp.path().join("data/bubbler/instances/seccp/config.kdl"),
        "dbus\n",
    )
    .unwrap();
    // The proxy's directory is removed when the run ends, so the report
    // has to be read while the sandbox is still up.
    let mut run = bubbler_live(tmp.path(), &init)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", bus.display()),
        )
        .env("BUBBLER_DBUS_PROXY", &proxy)
        .args(["run", "seccp", "--", "/usr/bin/sleep", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let report = tmp.path().join("run/bubbler/seccp/dbus/probe.txt");
    if !wait_until(|| report.is_file(), Duration::from_secs(10)) {
        fail_with(run, "the proxy never wrote its report");
    }
    let out = std::fs::read_to_string(&report).unwrap();
    // SIGTERM and wait, never SIGKILL: bubbler is what tears the two
    // sandboxes down, and killing it here — while the run is still
    // starting up — is how a test leaves a bwrap of its own behind.
    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    assert!(
        wait_until(
            || run.try_wait().expect("waiting for the run").is_some(),
            Duration::from_secs(10)
        ),
        "the run did not stop after SIGTERM"
    );
    assert_eq!(probed(&out, "keyctl"), "EPERM", "{out}");
    assert_eq!(probed(&out, "clone3"), "ENOSYS", "{out}");
    assert_eq!(probed(&out, "getpid"), "ok", "{out}");
    // Neither the app sandbox nor the proxy's outlives the run.
    let instance = format!("{}/run/bubbler/seccp", tmp.path().display());
    assert!(
        wait_until(|| !bwrap_alive(&instance), Duration::from_secs(5)),
        "a bwrap of instance `seccp` outlived the run"
    );
}
