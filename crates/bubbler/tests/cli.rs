mod common;

use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bubbler_core::bwrap::ETC_ALLOWLIST;
use bubbler_core::profile::NAMES;
use bubbler_core::seccomp::{ARCHES, RuleSet, syscall_number};
use common::{
    PYTHON, bubbler, bubbler_dbus, bubbler_in_sh, bubbler_live, bubbler_wayland, bwrap_alive,
    kill_group, output_past_a_busy_exec, process_running, real_init, require_bwrap, require_dbus,
    require_document_portal, require_groff, require_nested_x11, require_nested_x11_host,
    require_nft, require_pasta, require_portal, require_python, require_security_context,
    require_system_bus, require_tray, say, system_owns, test_pty,
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
         --info-fd\n3\n--add-seccomp-fd\n4\n\
         --ro-bind\n/usr\n/usr\n--symlink\nusr/bin\n/bin\n--symlink\nusr/lib\n/lib\n\
         --symlink\nusr/lib64\n/lib64\n--symlink\nusr/bin\n/sbin\n\
         --ro-bind-try\n/opt\n/opt\n--tmpfs\n/etc\n";
    let expected_suffix = format!(
        "--proc\n/proc\n--dev\n/dev\n{ntsync}--tmpfs\n/tmp\n--tmpfs\n/var\n--tmpfs\n/run\n\
         --bind\n{home}\n/home/bubbler\n--perms\n0700\n--dir\n{run}\n\
         --ro-bind\n{init}\n/run/bubbler-init\n--clearenv\n--setenv\nTERM\ndumb\n\
         --setenv\nHOME\n/home/bubbler\n--setenv\nPATH\n/usr/bin\n--setenv\nXDG_RUNTIME_DIR\n{run}\n\
         --setenv\nUSER\nbubbler\n--setenv\nLOGNAME\nbubbler\n\
         --\n/run/bubbler-init\n--socket-fd\n7\n--\n/usr/bin/true\n",
        ntsync = ntsync_bind(),
        home = home.display(),
        run = run.display(),
        init = tmp.path().join("bubbler-init").display()
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.starts_with(expected_prefix), "{s}");
    // Fd 3 is the info pipe and 4 the seccomp filter.
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n5\n/etc/passwd\n"),
        "{s}"
    );
    assert!(
        s.contains("--perms\n0644\n--ro-bind-data\n6\n/etc/group\n"),
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
        "// bubbler profile: app\n// bubbler config: 2\nwayland\nnetwork\ncommand \"sh\"\n"
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

/// An instance whose grants need nothing of this host: the D-Bus socket
/// is bound from a path the launcher would create, and `notify` is a rule
/// for the proxy rather than an argument.
fn explainable(tmp: &Path) -> PathBuf {
    bubbler(tmp).args(["create", "t"]).status().unwrap();
    std::fs::create_dir_all(tmp.join("home/Downloads")).unwrap();
    let cfg = tmp.join("data/bubbler/instances/t/config.kdl");
    std::fs::write(
        &cfg,
        "dbus\nportals\nnotify\nhome-share \"Downloads\" mode=rw\nuserns \"disable\"\n\
         env FOO=\"bar\"\ncommand \"true\"\n",
    )
    .unwrap();
    cfg
}

#[test]
fn explain_puts_every_argument_under_the_node_it_came_from() {
    let tmp = setup();
    explainable(tmp.path());
    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.starts_with("bwrap\n\n  baseline "), "{s}");
    // The fd numbers are the ones `--dry-run` prints, and each says what
    // is behind it.
    assert!(
        s.contains("    --info-fd 3  (pipe: bwrap reports the sandbox pid on it)\n"),
        "{s}"
    );
    assert!(
        s.contains("    --block-fd 4  (pipe: the sandbox waits on it until bubbler lets it go)\n"),
        "{s}"
    );
    // One filter for every architecture and every error it answers with.
    assert!(s.contains("    --add-seccomp-fd 5  (filter, "), "{s}");
    assert!(s.contains(&format!(", {ARCHES}")), "{s}");
    assert!(
        s.contains("--ro-bind-data 8 /.flatpak-info  (generated file, "),
        "{s}"
    );
    assert!(
        s.contains("--socket-fd 9  (socket: the exec channel bubbler-init serves)"),
        "{s}"
    );
    // Each granted node is named with the line it is on, `notify` too,
    // though it contributes no argument at all.
    for (node, line) in [
        ("dbus", 1),
        ("portals", 2),
        ("notify", 3),
        ("home-share \"Downloads\" mode=rw", 4),
    ] {
        assert!(
            s.contains(&format!("  {node} ")) && s.contains(&format!("config.kdl:{line}")),
            "{node}: {s}"
        );
    }
    // A node whose whole grant is proxy rules lists them, and a node
    // that has both lists them under its arguments.
    assert!(
        s.contains("  0 arguments\n    rule-only: --talk=org.freedesktop.Notifications\n"),
        "{s}"
    );
    assert!(
        s.contains(
            "    rules: --talk=org.freedesktop.portal.Desktop\n           \
             --talk=org.freedesktop.portal.Documents\n"
        ),
        "{s}"
    );
    assert!(s.contains("\n  userns "), "{s}");
    assert!(s.contains("\n    --unshare-user --disable-userns\n"), "{s}");
    assert!(s.contains("\n  env FOO "), "{s}");
    assert!(
        s.contains(&format!(
            "    --bind {}/Downloads /home/bubbler/Downloads\n",
            tmp.path().join("home").display()
        )),
        "{s}"
    );
    assert!(s.contains(" more (--explain=full)\n"), "{s}");
    assert!(
        s.ends_with("; 6 D-Bus rules to the proxy (--proxy)\n"),
        "{s}"
    );
}

#[test]
fn explain_full_lists_the_baseline_and_json_elides_nothing() {
    let tmp = setup();
    explainable(tmp.path());
    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain=full"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.contains("\n    --symlink usr/bin /bin\n"), "{s}");
    assert!(!s.contains("(--explain=full)"), "{s}");

    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain", "--format", "json"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.starts_with("[\n  {\"origin\": "), "{s}");
    assert!(s.ends_with("]\n"), "{s}");
    assert!(
        s.contains(
            "{\"origin\": {\"kind\": \"service\", \"node\": \
             \"home-share \\\"Downloads\\\" mode=rw\", \"index\": 3, \"line\": 4}"
        ),
        "{s}"
    );
    assert!(
        s.contains("\"note\": \"pipe: bwrap reports the sandbox pid on it\""),
        "{s}"
    );
    // Nothing is left out: one object per operation of the whole argv.
    let dry = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let elements = String::from_utf8_lossy(&dry.stdout).lines().count() - 1;
    let quoted: usize = s
        .lines()
        .filter(|l| l.starts_with("  {"))
        .map(|l| {
            let args = l
                .split("\"args\": [")
                .nth(1)
                .and_then(|a| a.split("], \"note\"").next())
                .unwrap_or_default();
            args.matches(", ").count() + 1
        })
        .sum();
    assert_eq!(quoted, elements, "{s}");
}

#[test]
fn explain_proxy_explains_the_sidecar_and_says_when_there_is_none() {
    let tmp = setup();
    explainable(tmp.path());
    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain", "--proxy"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.starts_with("bwrap  (the D-Bus proxy sidecar)\n"), "{s}");
    // The sidecar's rules are its command, one per line.
    assert!(s.contains("\n    --filter\n"), "{s}");
    assert!(
        s.contains("\n    --talk=org.freedesktop.Notifications\n"),
        "{s}"
    );
    assert!(s.contains("\n  identity "), "{s}");
    // Each rule is grouped under the node that asked for it, with the
    // line that node is on; a grant that gave the sidecar nothing is not
    // a group of this argv.
    assert!(
        s.contains(
            "\n  notify    config.kdl:3  1 argument\n    --talk=org.freedesktop.Notifications\n"
        ),
        "{s}"
    );
    assert!(
        s.contains("\n  portals   config.kdl:2  5 arguments\n"),
        "{s}"
    );
    assert!(!s.contains("home-share"), "{s}");
    assert!(!s.contains("rule-only"), "{s}");

    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "command \"true\"\n").unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain", "--proxy"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("starts no proxy sidecar"), "{err}");

    // `--proxy` is about an explanation and means nothing without one.
    let out = bubbler(tmp.path())
        .args(["run", "t", "--proxy"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// One sidecar filters both buses, and `xdg-dbus-proxy` applies an option
/// to the address before it. So the explanation reads one bus at a time —
/// each address under the node that granted that bus, and the rule groups
/// between the two addresses are the ones that bus carries.
#[test]
fn explain_proxy_reads_the_two_buses_one_at_a_time() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(
        &cfg,
        "dbus {\n    own \"com.steampowered.Steam\"\n}\nnotify\ntray\n\
         system-bus {\n    talk \"org.freedesktop.UPower\"\n}\n\
         seccomp {\n    disable\n}\ncommand \"true\"\n",
    )
    .unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain", "--proxy"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let headers: Vec<&str> = s
        .lines()
        .filter(|l| l.starts_with("  ") && l.contains(" argument"))
        .map(|l| l.split_whitespace().next().unwrap_or_default())
        .collect();
    assert_eq!(
        headers,
        [
            "baseline",
            "seccomp",
            "identity",
            "command",
            "dbus",
            "notify",
            "tray",
            "system-bus"
        ],
        "{s}"
    );
    // The proxy's own invocation is what is left over once each bus has
    // its address, its socket and the options that apply to them.
    assert!(s.contains("\n  command "), "{s}");
    assert!(s.contains("\n    --fd=3\n"), "{s}");
    assert!(
        s.contains(&format!(
            "\n  dbus        config.kdl:1  4 arguments\n    unix:path={}/bus\n",
            tmp.path().join("run").display()
        )),
        "{s}"
    );
    assert!(
        s.contains(
            "\n  system-bus  config.kdl:6  4 arguments\n    \
             unix:path=/run/dbus/system_bus_socket\n"
        ),
        "{s}"
    );
    assert_eq!(s.matches("\n    --filter\n").count(), 2, "{s}");
    // The sidecar's filter is the default set, whatever the `seccomp`
    // node of this config says, so that group names no line of it.
    let seccomp = s
        .lines()
        .find(|l| l.starts_with("  seccomp "))
        .unwrap_or_default();
    assert!(seccomp.contains("arguments"), "{s}");
    assert!(!seccomp.contains("config.kdl"), "{s}");
}

#[test]
fn try_explains_a_throwaway_sandbox_without_running_it() {
    let tmp = setup();
    write_profile(
        tmp.path(),
        "user",
        "app",
        "network \"host\"\ncommand \"true\"\n",
    );
    let out = bubbler(tmp.path())
        .args(["try", "--profile", "app", "--explain"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.contains("\n  network \"host\" "), "{s}");
    assert!(s.contains("\n    --share-net\n"), "{s}");
    // Line 3: the profile header and the config version come first.
    assert!(s.contains("config.kdl:3"), "{s}");
    // The throwaway directory is gone again, and no instance was left.
    let out = bubbler(tmp.path()).arg("list").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let left = std::fs::read_dir(tmp.path().join("data/bubbler/try"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(left, 0);
}

/// The socket both sides of the `app-runtime` integration tests use,
/// relative to the shared directory.
const SHARED_SOCKET: &str = "s.sock";

/// Server for the `app-runtime` integration test: binds a socket in the
/// shared directory, then reports what each of two peers sends.
const SHARED_SERVER: &str = "\
import os, socket, sys
p = os.environ['XDG_RUNTIME_DIR'] + '/app/org.bubbler.test/s.sock'
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(p)
s.listen(2)
print('listening', flush=True)
for _ in range(2):
    c, _ = s.accept()
    print('got ' + c.recv(64).decode(), flush=True)
";

/// Client for the same test, in a sandbox holding the directory `ro`.
const SHARED_CLIENT: &str = "\
import os, socket
p = os.environ['XDG_RUNTIME_DIR'] + '/app/org.bubbler.test/s.sock'
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.connect(p)
c.sendall(b'from-sandbox')
";

#[test]
fn app_runtime_binds_only_the_leaf_and_explain_names_the_node() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(
        &cfg,
        "app-runtime \"org.keepassxc.KeePassXC\"\n\
         app-runtime \"org.example.Other\" mode=rw\ncommand \"true\"\n",
    )
    .unwrap();
    let run = tmp.path().join("run");
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
    let leaf = |id: &str| run.join("app").join(id).display().to_string();
    assert!(
        s.contains(&format!(
            "--ro-bind\n{a}\n{a}\n",
            a = leaf("org.keepassxc.KeePassXC")
        )),
        "{s}"
    );
    assert!(
        s.contains(&format!(
            "--bind\n{a}\n{a}\n",
            a = leaf("org.example.Other")
        )),
        "{s}"
    );
    // Never the parent: `app/` holds every other id.
    assert!(
        !s.contains(&format!("\n{a}\n{a}\n", a = run.join("app").display())),
        "{s}"
    );
    // A dry run describes a launch rather than performing one, so it
    // creates nothing on the host either.
    assert!(!run.join("app").exists());

    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("  app-runtime \"org.keepassxc.KeePassXC\" "),
        "{s}"
    );
    assert!(
        s.contains("  app-runtime \"org.example.Other\" mode=rw "),
        "{s}"
    );
    assert!(s.contains("config.kdl:1"), "{s}");
    assert!(s.contains("config.kdl:2"), "{s}");
}

#[test]
fn app_runtime_refuses_a_symlink_where_the_directory_belongs() {
    let tmp = setup();
    write_profile(
        tmp.path(),
        "user",
        "shared",
        "app-runtime \"org.bubbler.test\"\ncommand \"true\"\n",
    );
    let app = tmp.path().join("run/app");
    std::fs::create_dir_all(&app).unwrap();
    std::os::unix::fs::symlink("/etc", app.join("org.bubbler.test")).unwrap();
    let out = bubbler(tmp.path())
        .args(["try", "--profile", "shared"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("app-runtime"), "{err}");
    assert!(err.contains("to be a directory"), "{err}");
}

#[test]
fn real_bwrap_app_runtime_carries_a_byte_between_two_sandboxes_and_the_host() {
    if !require_bwrap() || !require_python() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    write_profile(
        tmp.path(),
        "user",
        "shared-rw",
        "app-runtime \"org.bubbler.test\" mode=rw\n",
    );
    write_profile(
        tmp.path(),
        "user",
        "shared-ro",
        "app-runtime \"org.bubbler.test\"\n",
    );
    // Created by hand at 0755 first, the way a native application leaves
    // it (Qt's `mkpath` honours the umask): bubbler must adopt it rather
    // than fail or widen it.
    let dir = tmp.path().join("run/app/org.bubbler.test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut server = bubbler_live(tmp.path(), &init)
        .args([
            "try",
            "--profile",
            "shared-rw",
            "--",
            PYTHON,
            "-c",
            SHARED_SERVER,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let sock = dir.join(SHARED_SOCKET);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !std::fs::symlink_metadata(&sock).is_ok_and(|m| m.file_type().is_socket()) {
        if Instant::now() >= deadline || server.try_wait().unwrap().is_some() {
            kill_group(&server);
            let out = server.wait_with_output().unwrap();
            panic!(
                "no socket in the shared directory: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // The mode the host set is still the mode the directory has.
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o755
    );

    // A second sandbox holding the same id read-only: `connect()` works
    // through a `--ro-bind`, which is why `ro` is the default.
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "try",
            "--profile",
            "shared-ro",
            "--",
            PYTHON,
            "-c",
            SHARED_CLIENT,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // And the host, which is the KeePassXC-in-a-sandbox shape: the
    // directory is one host directory, so an unsandboxed peer reaches it.
    let mut stream = UnixStream::connect(&sock).unwrap();
    stream.write_all(b"from-host").unwrap();
    drop(stream);

    let deadline = Instant::now() + Duration::from_secs(30);
    while server.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            kill_group(&server);
            panic!("the server sandbox did not finish");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = server.wait_with_output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("got from-sandbox"), "{s}");
    assert!(s.contains("got from-host"), "{s}");
    // The shared directory outlives the runs: it is a rendezvous, and a
    // peer of another instance may still be serving in it.
    assert!(dir.is_dir());
}

// `network "host"` binds /etc/resolv.conf, so this test needs one on the
// host.
#[test]
fn network_share_and_home_share_appear_in_dry_run() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    std::fs::create_dir_all(tmp.path().join("home/Downloads")).unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(
        &cfg,
        "network \"host\"\nhome-share \"Downloads\"\ncommand \"true\"\n",
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
        say("skipping: this host has no /dev/input directory");
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
        say("skipping: this host has no /dev/input directory");
        return;
    }
    let host = host_hidraw_nodes();
    if host.is_empty() {
        say("skipping: this host has no /dev/hidraw* nodes");
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
fn real_bwrap_hidraw_binds_the_nodes_without_the_input_tree() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let host = host_hidraw_nodes();
    if host.is_empty() {
        say("skipping: this host has no /dev/hidraw* nodes");
        return;
    }
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "hidraw\n").unwrap();

    let out = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            "/usr/bin/sh",
            "-c",
            "ls -1 /dev | grep '^hidraw'; echo ---; ls /dev/input 2>/dev/null | head -1",
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
    // The point of the grant against `gamepad hidraw=#true`: the HID
    // nodes without every keyboard and mouse the host has.
    assert_eq!(rest.trim(), "", "{stdout}");
}

/// Host `/dev` entries named `video*` or `media*` that really are
/// character devices, sorted: what `camera nodes=#true` binds. Empty on
/// a host with no camera, which is the case the emit-when-present rule
/// is about.
fn host_camera_nodes() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/dev")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.starts_with("video") || n.starts_with("media")
                })
                .filter(|e| e.file_type().is_ok_and(|t| t.is_char_device()))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort_unstable();
    names
}

/// The directories `camera nodes=#true` binds where the host has them.
const CAMERA_DIRS: [&str; 4] = [
    "/dev/v4l",
    "/sys/class/video4linux",
    "/sys/bus/media",
    "/run/udev",
];

/// What both halves of the test ask the sandbox: the camera device nodes
/// it can see, then `/.flatpak-info` and whichever of [`CAMERA_DIRS`]
/// reached it.
const CAMERA_PROBE: &str = "ls -1 /dev | grep -E '^(video|media)' | tr '\\n' ' '; echo; \
     echo ---; test -f /.flatpak-info && echo flatpak-info; \
     for d in /dev/v4l /sys/class/video4linux /sys/bus/media /run/udev; do \
     test -d \"$d\" && echo \"$d\"; done; true";

#[test]
fn real_dbus_camera_binds_no_device_and_nodes_only_bind_what_is_there() {
    if !require_dbus() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();

    // The bare grant is the portal and nothing else: no device node, no
    // sysfs, no udev database, on a host with a camera or without one.
    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "try",
            "--grant",
            "dbus",
            "--grant",
            "portals",
            "--grant",
            "camera",
            "--",
            "/usr/bin/sh",
            "-c",
            CAMERA_PROBE,
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (nodes, rest) = stdout
        .split_once("---\n")
        .unwrap_or_else(|| panic!("{stdout}"));
    assert_eq!(nodes.trim(), "", "{stdout}");
    // `/.flatpak-info` is what earns the instance a camera permission of
    // its own instead of the blanket one every unsandboxed process
    // shares, so the bare grant is worth nothing without it.
    assert!(rest.contains("flatpak-info"), "{stdout}");
    for d in CAMERA_DIRS {
        assert!(
            !rest.contains(d),
            "{d} reached a bare camera grant: {stdout}"
        );
    }

    // `nodes=#true` adds the device nodes the host has at launch and
    // says nothing about the ones it does not: on a machine with no
    // camera that half of the grant binds nothing at all.
    let name = "bubbler-test-camera";
    let _leftovers = dbus_instance(
        tmp.path(),
        &init,
        name,
        "dbus\nportals\ncamera nodes=#true\n",
    );
    let out = bubbler_dbus(tmp.path(), &init)
        .args(["run", name, "--", "/usr/bin/sh", "-c", CAMERA_PROBE])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (nodes, rest) = stdout
        .split_once("---\n")
        .unwrap_or_else(|| panic!("{stdout}"));
    let mut inside: Vec<String> = nodes.split_whitespace().map(str::to_owned).collect();
    inside.sort_unstable();
    assert_eq!(inside, host_camera_nodes(), "{stdout}");
    for d in CAMERA_DIRS {
        assert_eq!(rest.contains(d), Path::new(d).is_dir(), "{d}: {stdout}");
    }
}

#[test]
fn real_bwrap_alsa_configuration_reaches_the_sandbox() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/etc/alsa").is_dir() {
        say("skipping: this host has no /etc/alsa directory");
        return;
    }
    let tmp = setup();
    bubbler_dbus(tmp.path(), &init)
        .args(["create", "alsacfg"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/alsacfg/config.kdl");
    // The runtime dir is the session's own here, so the socket the
    // `pipewire` grant binds is the one alsa-lib is routed to.
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let sound = runtime.is_some_and(|d| d.join("pipewire-0").exists());
    std::fs::write(&cfg, if sound { "pipewire\n" } else { "" }).unwrap();

    let out = bubbler_dbus(tmp.path(), &init)
        .args([
            "run",
            "alsacfg",
            "--",
            "/usr/bin/sh",
            "-c",
            "ls /etc/alsa/conf.d",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let listing = String::from_utf8_lossy(&out.stdout);
    // The symlinks in there point into the read-only /usr, so they
    // resolve inside; an empty directory would mean the tmpfs won.
    assert!(!listing.trim().is_empty(), "{listing}");

    // `default` is the pipewire PCM those files define. Without them
    // alsa-lib falls back to the hardware card, which no sandbox has.
    if sound && Path::new("/usr/bin/aplay").is_file() {
        let out = bubbler_dbus(tmp.path(), &init)
            .args(["run", "alsacfg", "--", "/usr/bin/aplay", "-L"])
            .output()
            .unwrap();
        let pcms = String::from_utf8_lossy(&out.stdout);
        assert!(
            pcms.lines().any(|l| l == "default"),
            "{pcms}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The instance's runtime state is in the session's own runtime dir
    // rather than under the test root, so it is deleted rather than left
    // for the temporary directory to take with it.
    let out = bubbler_dbus(tmp.path(), &init)
        .args(["delete", "alsacfg", "--yes"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn real_bwrap_gamepad_uinput_binds_the_node_and_says_so() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/dev/input").is_dir() || !Path::new("/dev/uinput").exists() {
        say("skipping: this host has no /dev/input directory or no /dev/uinput");
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
        say("skipping: this host has no /usr/bin/unshare");
        return;
    }
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    // The error is kept rather than discarded: `--disable-userns` works by
    // setting the namespace limit to zero, so the refusal is ENOSPC, and
    // that errno is what tells it apart from a host with no unprivileged
    // user namespaces at all — which would fail the same command with
    // EPERM and make this test pass for the wrong reason.
    let probe = "/usr/bin/unshare -U /usr/bin/true 2>&1 && echo NESTED || echo REFUSED";
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
    let refused = run("userns \"disable\"\n");
    assert!(refused.ends_with("REFUSED\n"), "{refused}");
    assert!(
        refused.contains("No space left on device"),
        "ENOSPC is what the namespace limit produces, not a host without \
         unprivileged user namespaces: {refused}"
    );
}

#[test]
fn real_bwrap_dri_hands_over_the_hosts_nvidia_stack() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new("/dev/nvidiactl").exists() {
        say("skipping: this host has no NVIDIA device nodes");
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
fn test_processes_never_inherit_the_callers_stdin() {
    // Under `makepkg` on a desktop the caller's stdin is a terminal, and a
    // bubbler that inherits one takes it: raw mode on the user's
    // terminal, and SIGTTOU stopping any bubbler in a process group of
    // its own. `isolate` gives every test process /dev/null instead;
    // a test that wants a terminal hands one over explicitly.
    let tmp = setup();
    let out = bubbler_in_sh(
        tmp.path(),
        Path::new("/nonexistent"),
        "readlink /proc/self/fd/0",
    )
    .stdout(Stdio::piped())
    // `spawn`, not `output`: `output` pipes stdin itself, which is the
    // default every other spawn in this file does not get.
    .spawn()
    .unwrap()
    .wait_with_output()
    .unwrap();
    let fd0 = String::from_utf8_lossy(&out.stdout);
    assert_eq!(fd0.trim(), "/dev/null", "{fd0:?}");
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
    process_running("xdg-dbus-proxy", needle)
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
    session_instance(bubbler_dbus(tmp, init), tmp, name, config)
}

/// An instance created with `create`, given `config`, and cleaned out of
/// the real runtime dir again when the guard drops. `create` is the
/// command that creates it, which decides what of the session the run
/// sees.
fn session_instance(mut create: Command, tmp: &Path, name: &str, config: &str) -> RuntimeLeftovers {
    let out = create.args(["create", name]).output().unwrap();
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
    let run_dir = PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR")
            .expect("the session runtime dir, checked by the caller's guard"),
    );
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
        say("skipping: the host session bus has no org.freedesktop.Notifications");
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
        say("skipping: the host session bus has no org.freedesktop.Notifications");
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
fn real_portals_bind_the_document_view_and_nothing_above_it() {
    if !require_document_portal() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let name = "bubbler-test-doc-portal";
    let _leftovers = dbus_instance(tmp.path(), &init, name, "dbus\nportals\ncommand \"true\"\n");
    let run = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
    let doc = PathBuf::from(run).join("doc");
    let out = bubbler_dbus(tmp.path(), &init)
        .args(["run", name, "--", "/usr/bin/ls", "-a"])
        .arg(&doc)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{err}");
    // The by-app view lists document ids only; the mount root would list `by-app`.
    assert!(
        !s.lines().any(|l| l == "by-app"),
        "stdout: {s}stderr: {err}"
    );
    assert!(!err.contains("no document portal"), "{err}");
}

#[test]
fn portals_without_a_document_portal_warns_once_and_still_runs() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "dbus\nportals\ncommand \"true\"\n",
    )
    .unwrap();
    // `setup()` points $XDG_RUNTIME_DIR at an empty temp dir: no mount there.
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(err.matches("no document portal at").count(), 1, "{err}");
    let argv = String::from_utf8_lossy(&out.stdout);
    assert!(!argv.contains("/doc/by-app/"), "{argv}");
}

#[test]
fn real_system_bus_answers_for_the_names_it_grants_and_no_others() {
    if !require_system_bus() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !system_owns("org.freedesktop.UPower") {
        say("skipping: the host system bus has no org.freedesktop.UPower");
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
        say("skipping the denial half: the host has no org.freedesktop.login1");
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
    std::fs::write(&cfg, "x11 \"host\"\ncommand \"/usr/bin/true\"\n").unwrap();
    let out = bubbler(tmp.path()).args(["run", "t"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("x11 \"host\" grants no isolation"), "{err}");
    // $DISPLAY is cleared here, so the run fails after the warning is out.
    assert_eq!(out.status.code(), Some(1), "{err}");
    let out = bubbler(tmp.path())
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stderr).contains("x11 \"host\" grants no isolation"));
}

/// The nested mode's whole server command line reaches the supervisor:
/// `--helper`, the argv, and the `--` that closes it, all before the `--`
/// the sandbox's own command follows. The words are the contract with
/// `bubbler-init`, so a dry run is where a user can read them.
#[test]
fn a_nested_x11_dry_run_hands_the_supervisor_the_server_argv() {
    if !require_nested_x11_host() {
        return;
    }
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "wayland\ndri\nx11\ncommand \"/usr/bin/true\"\n",
    )
    .unwrap();
    // The bare `wayland` grant binds a socket this run would listen on
    // itself, so the name need not point at anything yet.
    let out = bubbler(tmp.path())
        .env("WAYLAND_DISPLAY", "wayland-0")
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let s = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = s.lines().collect();
    let tail = [
        "--helper",
        "/usr/bin/Xwayland",
        ":0",
        "-noreset",
        "-nolisten",
        "tcp",
        "-nolisten",
        "local",
        "-ac",
        "-hidpi",
        "-decorate",
        "-geometry",
        "1280x720",
        "--",
        "--",
        "/usr/bin/true",
    ];
    assert_eq!(lines[lines.len() - tail.len()..], tail, "{s}");
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

    // The bare grant binds the socket this run would listen on itself,
    // which nothing has created yet: the host's name is only the one it
    // takes inside, and a dry-run asks the compositor nothing.
    std::fs::write(tmp.path().join("run/notasocket"), "").unwrap();
    let out = bubbler(tmp.path())
        .env("WAYLAND_DISPLAY", "notasocket")
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");

    // `wayland "host"` hands over the session's own socket, so what the
    // name points at has to be one.
    std::fs::write(&cfg, "wayland \"host\"\ncommand \"true\"\n").unwrap();
    let out = bubbler(tmp.path())
        .env("WAYLAND_DISPLAY", "notasocket")
        .args(["run", "t", "--dry-run"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("notasocket"), "{err}");
}

/// A `wayland` instance whose runtime state lands in the session's real
/// runtime dir, so a run can reach the compositor there.
fn wayland_instance(tmp: &Path, init: &Path, name: &str, config: &str) -> RuntimeLeftovers {
    session_instance(bubbler_wayland(tmp, init), tmp, name, config)
}

/// `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` on the host: the session's own
/// socket, and the path the sandbox sees a socket at whichever mode
/// serves it.
fn host_wayland_socket() -> PathBuf {
    let run = std::env::var_os("XDG_RUNTIME_DIR").expect("checked by require_security_context");
    let display = std::env::var_os("WAYLAND_DISPLAY").expect("checked by require_security_context");
    PathBuf::from(run).join(display)
}

/// The inode of `path`. A bind mount carries the source file's inode, so
/// the number tells bubbler's own socket from the session's without
/// connecting to either.
fn socket_ino(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .ino()
}

/// What a real run of `config` finds at `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`
/// inside the sandbox: the inode of the socket bound there, and what the
/// run said on stderr. The instance is removed again before this returns.
fn wayland_ino_inside(tmp: &Path, init: &Path, name: &str, config: &str) -> (u64, String) {
    let _leftovers = wayland_instance(tmp, init, name, config);
    let out = bubbler_wayland(tmp, init)
        .args(["run", name, "--", "/usr/bin/stat", "-L", "-c", "%i"])
        .arg(host_wayland_socket())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let s = String::from_utf8_lossy(&out.stdout);
    let ino = s.trim().parse().unwrap_or_else(|e| panic!("{s:?}: {e}"));
    (ino, err)
}

/// The whole point of the grant: the application is handed a socket of
/// this run's, which the compositor accepts on as a security context, and
/// not the session's, which every client shares.
#[test]
fn real_wayland_binds_bubblers_own_socket_not_the_hosts() {
    if !require_security_context() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let host_ino = socket_ino(&host_wayland_socket());
    let (inside, err) = wayland_ino_inside(
        tmp.path(),
        &init,
        "bubbler-test-wl-ctx",
        "wayland\ncommand \"true\"\n",
    );
    assert_ne!(inside, host_ino, "the sandbox got the host socket: {err}");
    // A compositor without the manager binds the session's socket and
    // says so here, so an absent warning is the run stating that the
    // inode above differs because a context was registered.
    assert!(!err.contains("no wp_security_context_manager_v1"), "{err}");
}

/// `wayland "host"` is the opt-out, and opting out has to reach the
/// sandbox: the session's own socket, the same file by inode.
#[test]
fn real_wayland_host_binds_the_host_socket() {
    if !require_security_context() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let host_ino = socket_ino(&host_wayland_socket());
    let (inside, err) = wayland_ino_inside(
        tmp.path(),
        &init,
        "bubbler-test-wl-host",
        "wayland \"host\"\ncommand \"true\"\n",
    );
    assert_eq!(inside, host_ino, "{err}");
}

/// The X client this test runs inside the sandbox. Read from the host's
/// `/usr`, which is bound read-only, so a host without it has none
/// inside either.
const XDPYINFO: &str = "/usr/bin/xdpyinfo";

/// The config a nested `x11` needs: the compositor connection the server
/// draws its window in, and the render node it draws with.
const NESTED_X11: &str = "wayland\ndri\nx11\ncommand \"true\"\n";

/// The point of the nested mode: the sandbox gets an X display of its
/// own, served by an Xwayland the supervisor started inside it, with the
/// GLX the `dri` grant beside it is what makes possible.
#[test]
fn real_nested_x11_serves_a_private_display() {
    if !require_nested_x11() {
        return;
    }
    let Some(init) = real_init() else { return };
    if !Path::new(XDPYINFO).is_file() {
        say(&format!("skipping: {XDPYINFO} is not installed"));
        return;
    }
    let tmp = setup();
    let name = "bubbler-test-x11-nested";
    let _leftovers = wayland_instance(tmp.path(), &init, name, NESTED_X11);

    let out = bubbler_wayland(tmp.path(), &init)
        .args(["run", name, "--", XDPYINFO])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    let s = String::from_utf8_lossy(&out.stdout);
    // The display the grant fixes, reported by a client that connected to
    // it: the server was up before the command ran.
    assert!(s.contains("name of display:    :0"), "{s}{err}");
    // GLX is in the extension list only where the server found a render
    // device, which is the `dri` grant reaching the nested display.
    assert!(s.lines().any(|l| l.trim() == "GLX"), "{s}{err}");
}

/// `exec` children are what a nested display is for: a browser started
/// later has to reach the same server, so the supervisor hands them the
/// `DISPLAY` it set for the command.
#[test]
fn real_nested_x11_exec_children_see_the_display() {
    if !require_nested_x11() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let name = "bubbler-test-x11-exec";
    let _leftovers = wayland_instance(tmp.path(), &init, name, NESTED_X11);

    let mut run = bubbler_wayland(tmp.path(), &init)
        .args(["run", name, "--", "/usr/bin/sleep", "20"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The supervisor accepts connections only once the display is up, so
    // the first `exec` that works is also the first that could have been
    // handed a `DISPLAY`.
    let mut inside = None;
    if !wait_until(
        || {
            let out = bubbler_wayland(tmp.path(), &init)
                .args(["exec", name, "--", "/usr/bin/env"])
                .output()
                .expect("running bubbler exec");
            if out.status.success() {
                inside = Some(String::from_utf8_lossy(&out.stdout).into_owned());
            }
            inside.is_some()
        },
        Duration::from_secs(10),
    ) {
        fail_with(run, "no exec child ran inside the instance");
    }
    let env = inside.expect("set by the poll above");
    assert!(env.lines().any(|l| l == "DISPLAY=:0"), "{env}");

    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    let mut status = None;
    assert!(
        wait_until(
            || {
                status = run.try_wait().expect("waiting for the run process");
                status.is_some()
            },
            Duration::from_secs(10)
        ),
        "the run did not stop after SIGTERM"
    );
    // The instance is gone with it: the supervisor tears the display
    // helper down on every exit, so nothing of it outlives the run.
    let sock = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("checked by the guard"))
        .join("bubbler")
        .join(name)
        .join("init.sock");
    assert!(!sock.exists(), "the control socket outlived the run");
}

/// `--explain` describes the run a compositor with the protocol gives,
/// and asks no compositor anything: here `$WAYLAND_DISPLAY` names a
/// socket that does not exist, so a connection attempt would fail.
#[test]
fn explain_names_the_security_context_without_asking_the_compositor() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "wayland\ncommand \"true\"\n",
    )
    .unwrap();
    let out = bubbler(tmp.path())
        .env("WAYLAND_DISPLAY", "wayland-0")
        .args(["run", "t", "--explain"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let run = tmp.path().join("run");
    assert!(
        s.contains(&format!(
            "    --ro-bind {}/bubbler/t/wayland {}/wayland-0\n",
            run.display(),
            run.display()
        )),
        "{s}"
    );
    assert!(
        s.contains(
            "    security-context: engine=org.bubbler app=org.bubbler.t instance=bubbler-t\n"
        ),
        "{s}"
    );
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

/// The input the fuzzer found in `kdl` 6.7.1: the parser descends into
/// `{` by recursion, so a file of nothing but open braces overflowed the
/// stack and aborted bubbler — with a core dump and no message — on
/// every path that reads a configuration.
#[test]
fn a_configuration_nested_past_the_bound_is_refused_wherever_it_is_read() {
    let tmp = setup();
    let evil = format!("a {}", "{".repeat(1400));
    let profile = write_profile(tmp.path(), "system", "evil", &evil);
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, &evil).unwrap();
    for (args, file) in [
        (vec!["profile", "show", "evil"], &profile),
        (vec!["profile", "lint", "evil"], &profile),
        (vec!["create", "e", "--profile", "evil"], &profile),
        (vec!["run", "t", "--dry-run"], &cfg),
    ] {
        let out = bubbler(tmp.path()).args(&args).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        // An abort has no exit code at all, which is what this had.
        assert!(out.status.code().is_some_and(|c| c != 0), "{args:?}: {err}");
        assert!(err.contains(&file.display().to_string()), "{args:?}: {err}");
        // The bound as the constant holds it: a message naming a depth
        // the parser no longer stops at would be a lie to whoever hit it.
        let bound = format!("nested deeper than {}", bubbler_core::config::MAX_NESTING);
        assert!(err.contains(&bound), "{args:?}: {err}");
    }
    // The shim registry is read on every start under a shim name, so it
    // is the same stack and needs the same bound. Far past it, because
    // what a bound is worth is what it does to the input nobody sized.
    let registry = tmp.path().join("config/bubbler/wraps.kdl");
    std::fs::create_dir_all(registry.parent().unwrap()).unwrap();
    std::fs::write(&registry, "wrap ".to_owned() + &"{".repeat(20000)).unwrap();
    let out = bubbler(tmp.path())
        .args(["wrap", "--list"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.code().is_some_and(|c| c != 0), "{err}");
    assert!(err.contains(&registry.display().to_string()), "{err}");
    let bound = format!("nested deeper than {}", bubbler_core::config::MAX_NESTING);
    assert!(err.contains(&bound), "{err}");
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
    // `edit` records the config version, so the file the user has just
    // read through stops warning about what `network` now means.
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        "// bubbler config: 2\ncommand \"true\"\n"
    );
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
    let out = output_past_a_busy_exec(
        bubbler(tmp.path())
            .env("VISUAL", &visual)
            .env("EDITOR", "/usr/bin/false")
            .args(["edit", "t"]),
    );
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
        "hidraw",
        "camera",
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

    // `camera` is a portal grant, so it is refused until the portals
    // that carry it are granted too.
    let out = bubbler(tmp.path())
        .args([
            "try",
            "--grant",
            "dbus",
            "--grant",
            "camera",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("requires portals"), "{err}");

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

/// A bare `--grant x11` is the nested server, which has nowhere to draw
/// without a compositor connection and nothing to draw with without a
/// render node. The refusal names both, so the fix is in the message.
#[test]
fn try_grant_x11_alone_names_the_requirement() {
    let tmp = setup();
    let out = bubbler(tmp.path())
        .args(["try", "--grant", "x11", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("requires wayland and dri"), "{err}");
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
    // Field 6 of /proc/<pid>/stat is the session id; `ps` is not in a
    // clean build chroot.
    r#"read -r _ _ _ _ _ sid _ < /proc/$$/stat; test "$sid" = "$$" && echo LEADER; "#,
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
    // Only x86_64 has a second ABI sharing its `AUDIT_ARCH` value, so it
    // is the only one where `nr | __X32_SYSCALL_BIT` names a syscall at
    // all; elsewhere the line would report a number the kernel never had.
    // The filter kills such a caller instead of answering it, so the call
    // is made in a child process and the line reports how the child died.
    #[cfg(target_arch = "x86_64")]
    let x32 = format!(
        "    (\"keyctl_x32\", forked({}, 0, -3, 0)),\n",
        nr("keyctl") | 0x4000_0000
    );
    #[cfg(not(target_arch = "x86_64"))]
    let x32 = String::new();
    format!(
        r#"import ctypes, errno, os
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

def forked(nr, *args):
    """`call` in a child, reported as "signal:N" when the filter kills it."""
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        os.write(write, call(nr, *args).encode())
        os._exit(0)
    os.close(write)
    answer = b""
    while True:
        chunk = os.read(read, 64)
        if not chunk:
            break
        answer += chunk
    os.close(read)
    status = os.waitpid(pid, 0)[1]
    if os.WIFSIGNALED(status):
        return "signal:%d" % os.WTERMSIG(status)
    return answer.decode() or "none"

probe = [
    # KEYCTL_GET_KEYRING_ID of KEY_SPEC_SESSION_KEYRING, creating nothing.
    ("keyctl", call({keyctl}, 0, -3, 0)),
{x32}    # A null attribute struct: the kernel faults before it opens anything.
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
        x32 = x32,
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
    let set = RuleSet::default_set();
    let names: Vec<String> = set
        .eperm
        .iter()
        .chain(&set.enosys)
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
    // The same call with __X32_SYSCALL_BIT set. x32 shares x86_64's
    // AUDIT_ARCH value but offsets every number, so no rule can match it;
    // libseccomp answers such a caller with its bad-architecture action,
    // which bubbler sets to kill. SIGSYS is 31 on x86.
    #[cfg(target_arch = "x86_64")]
    assert_eq!(probed(&out, "keyctl_x32"), "signal:31", "{out}");
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
    // No filter, so nothing kills the x32 caller: the kernel strips
    // __X32_SYSCALL_BIT and runs the syscall it names.
    #[cfg(target_arch = "x86_64")]
    assert_ne!(probed(&out, "keyctl_x32"), "signal:31", "{out}");
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

    for program in [
        "/usr/bin/alacritty",
        "/usr/bin/firefox",
        "/usr/bin/chromium",
    ] {
        if !Path::new(program).is_file() {
            say(&format!("skipping: {program} is not installed"));
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

/// A 32-bit probe reporting how the filter answers three syscalls and one
/// glibc wrapper. Static, so the sandbox needs no 32-bit libraries; and
/// `adjtimex` goes through glibc on purpose, because on i386 it issues
/// `clock_adjtime64` (405) rather than the `clock_adjtime` (124) a table
/// written for x86_64 would carry.
const I386_PROBE: &str = r#"#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <unistd.h>

static char other[32];

static const char *named(long rc)
{
    if (rc >= 0)
        return "ok";
    switch (errno) {
    case EPERM:
        return "EPERM";
    case ENOSYS:
        return "ENOSYS";
    default:
        snprintf(other, sizeof other, "E%d", errno);
        return other;
    }
}

int main(void)
{
    struct timex tx;
    memset(&tx, 0, sizeof tx);
    /* Mode 0 reads the clock and changes nothing, so an unfiltered run
       leaves the host's timekeeping exactly as it was. */
    printf("keyctl %s\n", named(syscall(__NR_keyctl, 0, -3, 0)));
    printf("clone3 %s\n", named(syscall(__NR_clone3, 0, 0)));
    printf("adjtimex %s\n", named(adjtimex(&tx)));
    printf("getpid %s\n", named(syscall(__NR_getpid)));
    return 0;
}
"#;

/// [`I386_PROBE`] built into `dir`, or `None` (with a printed skip) where
/// no 32-bit toolchain can link it.
fn build_i386_probe(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("probe32.c");
    std::fs::write(&src, I386_PROBE).unwrap();
    let binary = dir.join("probe32");
    let built = Command::new("gcc")
        .args(["-m32", "-static", "-O0", "-o"])
        .arg(&binary)
        .arg(&src)
        .output();
    match built {
        Ok(out) if out.status.success() => Some(binary),
        Ok(out) => {
            say(&format!(
                "skipping: `gcc -m32 -static` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
            None
        }
        Err(e) => {
            say(&format!("skipping: gcc is not usable here: {e}"));
            None
        }
    }
}

#[test]
fn real_bwrap_seccomp_filters_a_32_bit_binary_instead_of_killing_it() {
    if ARCHES != "x86_64 + i386" {
        say("skipping: this filter carries no second architecture");
        return;
    }
    let Some((tmp, init)) = live_instance("secc32") else {
        return;
    };
    let Some(probe) = build_i386_probe(tmp.path()) else {
        return;
    };
    // The instance's home is what the sandbox sees at /home/bubbler.
    let inside = tmp
        .path()
        .join("data/bubbler/instances/secc32/home/probe32");
    std::fs::copy(&probe, &inside).unwrap();
    std::fs::set_permissions(&inside, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .args(["run", "secc32", "--", "/home/bubbler/probe32"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    // A filter carrying only x86_64 would kill this process with SIGSYS
    // before its first `printf`.
    assert!(out.status.success(), "{err}");
    let s = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(probed(&s, "keyctl"), "EPERM", "{s}");
    assert_eq!(probed(&s, "clone3"), "ENOSYS", "{s}");
    assert_eq!(probed(&s, "adjtimex"), "EPERM", "{s}");
    assert_eq!(probed(&s, "getpid"), "ok", "{s}");
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

/// Exit code of a bubbler run, with its stdout and stderr as text.
fn run(tmp: &Path, args: &[&str]) -> (i32, String, String) {
    let out = bubbler(tmp).args(args).output().unwrap();
    (
        out.status
            .code()
            .expect("bubbler exits rather than signals"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn profile_lint_warns_with_a_line_and_a_lint_allow_node_accepts_it() {
    let tmp = setup();
    let path = write_profile(
        tmp.path(),
        "user",
        "risky",
        "x11 \"host\"\ncommand \"sh\"\n",
    );
    let (code, out, _) = run(tmp.path(), &["profile", "lint", "risky"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains(&format!(
            "{}:1:1: warning[x11-without-reason]",
            path.display()
        )),
        "{out}"
    );
    assert!(
        out.contains("1 layer linted, 0 errors, 1 warning, 0 notes"),
        "{out}"
    );
    // The same warning is an error for a CI job that asks for it.
    let (code, _, _) = run(
        tmp.path(),
        &["profile", "lint", "risky", "--deny", "warnings"],
    );
    assert_eq!(code, 2);
    write_profile(
        tmp.path(),
        "user",
        "risky",
        "x11 \"host\"\nlint-allow \"x11-without-reason\" reason=\"measured: no Wayland \
         backend\"\ncommand \"sh\"\n",
    );
    let (code, out, _) = run(
        tmp.path(),
        &["profile", "lint", "risky", "--deny", "warnings"],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(out, "1 layer linted, 0 errors, 0 warnings, 0 notes\n");
}

#[test]
fn profile_lint_all_reads_every_layer_once_and_json_carries_the_counts() {
    let tmp = setup();
    make_builtin_share_sources(tmp.path());
    let (code, out, err) = run(
        tmp.path(),
        &["profile", "lint", "--all", "--format", "json"],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("\"errors\": 0, \"warnings\": 0"), "{out}");
    assert!(
        out.contains(&format!("\"layers\": {}", NAMES.len())),
        "{out}"
    );
    // Every `lint-allow` a built-in profile carries still accepts a
    // finding: one that stopped doing so is a note of its own.
    assert!(!out.contains("lint-allow-unused"), "{out}");
    // Two profiles over one base read that base twice; it is one layer,
    // and its `x11` is one finding.
    write_profile(tmp.path(), "user", "base", "x11 \"host\"\ncommand \"sh\"\n");
    write_profile(tmp.path(), "user", "a", "include \"base\"\n");
    write_profile(tmp.path(), "user", "b", "include \"base\"\n");
    let (code, out, err) = run(tmp.path(), &["profile", "lint", "--all"]);
    assert_eq!(code, 1, "{out}{err}");
    assert_eq!(
        out.matches("warning[x11-without-reason]").count(),
        1,
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "{} layers linted, 0 errors, 1 warning",
            NAMES.len() + 3
        )),
        "{out}"
    );
    // A name no layer holds is a run that could not be made, not a
    // profile that lints clean.
    let (code, _, err) = run(tmp.path(), &["profile", "lint", "nosuch"]);
    assert_eq!(code, 3);
    assert!(err.contains("unknown profile `nosuch`"), "{err}");
}

/// Every `home-share` source the built-in profiles name, created under
/// the test's home. A missing source is an error, so a host without them
/// is not what a built-in profile lint measures. Read from the profiles
/// themselves, so one added later needs no edit here.
fn make_builtin_share_sources(root: &Path) {
    for name in NAMES {
        let text = bubbler_core::profile::lookup(name).expect("NAMES lists built-ins");
        let cfg = bubbler_core::config::parse_profile(text).unwrap().config;
        for s in &cfg.services {
            if let bubbler_core::config::Service::HomeShare { path, .. } = s {
                std::fs::create_dir_all(root.join("home").join(path)).unwrap();
            }
        }
    }
}

#[test]
fn a_built_in_share_this_host_does_not_have_is_a_warning_not_an_error() {
    // A profile is written for a host that has the directory; this one
    // need not. The run itself still refuses, so the lint says "this
    // file grants more than it can here", not "this file is broken".
    let tmp = setup();
    let (code, out, err) = run(tmp.path(), &["profile", "lint", "--all"]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.contains("warning[share-source-missing]"), "{out}");
    assert!(!out.contains("error[share-source-missing]"), "{out}");
    assert!(out.contains(", 0 errors, "), "{out}");
}

#[test]
fn a_finding_never_stands_in_for_a_layer_that_does_not_parse() {
    let tmp = setup();
    // The share error is real and says nothing about `bluetooth`, so the
    // run reports the parse failure rather than a verdict built on half
    // the profile.
    write_profile(tmp.path(), "user", "base", "home-share \"NoSuchDir\"\n");
    write_profile(tmp.path(), "user", "app", "include \"base\"\nbluetooth\n");
    let (code, out, err) = run(tmp.path(), &["profile", "lint", "app"]);
    assert_eq!(code, 3, "{out}{err}");
    assert!(err.contains("unknown node `bluetooth`"), "{err}");
}

#[test]
fn editing_an_instance_config_lints_it_afterwards() {
    let tmp = setup();
    run(tmp.path(), &["create", "t"]);
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "x11 \"host\"\nhome-share \".ssh\"\n").unwrap();
    std::fs::create_dir_all(tmp.path().join("home/.ssh")).unwrap();
    let out = bubbler(tmp.path())
        .env("EDITOR", "/usr/bin/true")
        .args(["edit", "t"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        err.contains("bubbler: lint: ") && err.contains("x11-without-reason"),
        "{err}"
    );
    assert!(err.contains("home-share-sensitive"), "{err}");
}

#[test]
fn create_and_reseed_print_the_findings_without_failing() {
    let tmp = setup();
    write_profile(
        tmp.path(),
        "user",
        "generic",
        "x11 \"host\"\ncommand \"sh\"\n",
    );
    let (code, out, err) = run(tmp.path(), &["create", "t"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.trim().ends_with("instances/t"), "{out}");
    assert!(
        err.contains("bubbler: lint: ") && err.contains("warning[x11-without-reason]"),
        "{err}"
    );
    assert!(err.contains("bubbler: lint:   help: "), "{err}");
    let (code, _, err) = run(tmp.path(), &["reseed", "t"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("warning[x11-without-reason]"), "{err}");
}

#[test]
fn lint_on_an_instance_reads_its_own_config() {
    let tmp = setup();
    run(tmp.path(), &["create", "t"]);
    let (code, out, err) = run(tmp.path(), &["lint", "t"]);
    assert_eq!(code, 0, "{out}{err}");
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "x11 \"host\"\n").unwrap();
    let (code, out, _) = run(tmp.path(), &["lint", "t"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains(&format!(
            "{}:1:1: warning[x11-without-reason]",
            cfg.display()
        )),
        "{out}"
    );
    // A config bubbler cannot read at all, and an instance that is not
    // there, are both "the lint could not run" rather than a verdict.
    std::fs::write(&cfg, "bluetooth\n").unwrap();
    let (code, _, err) = run(tmp.path(), &["lint", "t"]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("unknown node `bluetooth`"), "{err}");
    let (code, _, _) = run(tmp.path(), &["lint", "nosuch"]);
    assert_eq!(code, 3);
}

/// A stand-in pasta: it records the argv it was given, reports readiness
/// on the `--pid` path exactly as pasta does, and then waits to be
/// killed. What it proves is what bubbler does around the sidecar, not
/// what pasta does with a namespace.
const FAKE_PASTA: &str = "\
#!/usr/bin/python3
import os, signal, sys
argv = sys.argv[1:]
open(os.environ['FAKE_PASTA_ARGV'], 'w').write('\\n'.join(argv))
open(os.environ['FAKE_PASTA_PID'], 'w').write(str(os.getpid()))
if os.environ.get('FAKE_PASTA_SILENT') == '1':
    sys.exit(3)
with open(argv[argv.index('--pid') + 1], 'w') as f:
    f.write(f'{os.getpid()}\\n')
signal.pause()
";

/// Whether `pid` names a live process, for the sidecar lifetime checks.
fn pid_alive(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// A `network` instance under `root` whose config is `kdl`, with the
/// stand-in pasta written next to it. Returns the command to run it.
fn pasta_case(root: &std::path::Path, init: &std::path::Path, kdl: &str) -> Command {
    let fake = root.join("fake-pasta");
    write_script(&fake, FAKE_PASTA);
    let mut c = bubbler_live(root, init);
    c.env("BUBBLER_PASTA", &fake)
        .env("FAKE_PASTA_ARGV", root.join("pasta.argv"))
        .env("FAKE_PASTA_PID", root.join("pasta.pid"));
    std::fs::write(root.join("data/bubbler/instances/t/config.kdl"), kdl).unwrap();
    c
}

#[test]
fn the_pasta_sidecar_gets_the_hardened_argv_and_does_not_outlive_the_run() {
    if !require_bwrap() || !require_python() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let out = pasta_case(
        tmp.path(),
        &init,
        "network {\n    allow-port 8080\n    no-ipv6\n}\n",
    )
    .args(["run", "t", "--", "/usr/bin/echo", "ran"])
    .output()
    .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    // The sandbox ran, which means the block was released only after the
    // sidecar reported that the namespace was configured.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n");

    let argv: Vec<String> = std::fs::read_to_string(tmp.path().join("pasta.argv"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let after = |flag: &str| {
        let i = argv.iter().position(|a| a == flag).expect(flag);
        argv[i + 1].clone()
    };
    assert_eq!(after("-T"), "none");
    assert_eq!(after("-U"), "none");
    assert_eq!(after("--map-host-loopback"), "none");
    assert_eq!(after("--map-guest-addr"), "none");
    assert_eq!(after("--dns-forward"), "169.254.1.1");
    assert_eq!(after("-t"), "127.0.0.1/8080");
    assert_eq!(after("-u"), "none");
    for flag in ["--config-net", "--foreground", "-4"] {
        assert!(argv.contains(&flag.to_owned()), "{flag}: {argv:?}");
    }
    // The pid it was pointed at is the sandbox's own.
    assert!(argv.last().unwrap().parse::<u32>().is_ok(), "{argv:?}");

    let pid: i32 = std::fs::read_to_string(tmp.path().join("pasta.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // It ignores the closed pipe and waits to be signalled, so a sidecar
    // still here would be one bubbler never killed.
    assert!(!pid_alive(pid), "the pasta sidecar outlived the run");
}

#[test]
fn a_sandbox_whose_network_cannot_be_connected_never_runs() {
    if !require_bwrap() || !require_python() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let out = pasta_case(tmp.path(), &init, "network\n")
        .env("FAKE_PASTA_SILENT", "1")
        .args(["run", "t", "--", "/usr/bin/echo", "ran"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("network namespace"), "{err}");
    // Held at its `--block-fd` and then stopped: the command never ran.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

/// A sidecar that dies mid-run leaves the sandbox with a namespace
/// connected to nothing. The run says so once and keeps going: an
/// application that has lost its network still has whatever it has not
/// written out.
#[test]
fn a_pasta_that_dies_mid_run_is_reported_once_and_the_sandbox_runs_on() {
    if !require_bwrap() || !require_python() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let mut run = pasta_case(tmp.path(), &init, "network\n")
        .args(["run", "t", "--", "/usr/bin/sleep", "30"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let sock = tmp.path().join("run/bubbler/t/init.sock");
    if !wait_until(
        || UnixStream::connect(&sock).is_ok(),
        Duration::from_secs(10),
    ) {
        fail_with(run, "the isolated instance never started");
    }
    // The control socket is bound and listening before bwrap is started
    // at all, so connecting to it says nothing about the sidecar beside
    // it: the pid file is what says the stand-in pasta has run.
    let pidfile = tmp.path().join("pasta.pid");
    let read_pid = || {
        let text = std::fs::read_to_string(&pidfile).ok()?;
        text.trim().parse::<i32>().ok()
    };
    if !wait_until(|| read_pid().is_some(), Duration::from_secs(10)) {
        fail_with(run, "the sidecar never wrote its pid");
    }
    let pid = read_pid().expect("the pid file was just read");
    kill_process(
        Pid::from_raw(pid).expect("the sidecar has a pid"),
        Signal::KILL,
    )
    .unwrap();
    // bubbler is the only process that can reap it, and it reaps it as it
    // notices: a pid that is gone is a notice that has been printed.
    if !wait_until(|| !pid_alive(pid), Duration::from_secs(10)) {
        fail_with(run, "the run never noticed the dead sidecar");
    }
    assert!(
        run.try_wait().unwrap().is_none(),
        "the run ended with the sidecar"
    );
    assert!(UnixStream::connect(&sock).is_ok(), "the sandbox is gone");
    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    let out = run.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("pasta exited (signal: 9"), "{err}");
    assert_eq!(
        err.matches("the sandbox has lost its network").count(),
        1,
        "{err}"
    );
}

#[test]
fn a_missing_pasta_names_the_package_and_the_host_mode() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network\n",
    )
    .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .env("BUBBLER_PASTA", tmp.path().join("no-such-pasta"))
        .args(["run", "t", "--", "/usr/bin/echo", "ran"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("passt"), "{err}");
    assert!(err.contains("network \"host\""), "{err}");
    // Never a quiet fall back to the host namespace.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

#[test]
fn a_config_written_before_the_flip_warns_on_every_run() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    let warns = |text: &str| {
        std::fs::write(&cfg, text).unwrap();
        let out = bubbler(tmp.path())
            .args(["run", "t", "--dry-run"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let err = warns("network\ncommand \"true\"\n");
    assert!(err.contains("isolated network namespace"), "{err}");
    // Both ways out are named: one re-flattens the profile over the
    // file, the other keeps the edits already in it.
    assert!(err.contains("bubbler reseed t"), "{err}");
    assert!(err.contains("bubbler edit t"), "{err}");
    // A file that records the version, or names the mode, says what it
    // means and is left alone.
    for quiet in [
        "// bubbler config: 2\nnetwork\ncommand \"true\"\n",
        "network \"host\"\ncommand \"true\"\n",
        "network \"none\"\ncommand \"true\"\n",
    ] {
        assert!(!warns(quiet).contains("isolated network"), "{quiet}");
    }
}

/// A port nothing is listening on, taken by binding one and letting it
/// go. Nothing else here binds it in between, and a port that turns out
/// to be taken fails the test rather than passing quietly.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Whether this host can reach the public internet at all, so a sandbox
/// that cannot is a finding rather than the weather.
fn host_is_online() -> bool {
    let addr = "1.1.1.1:443".parse().unwrap();
    let ok = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok();
    if !ok {
        say("skipping: this host cannot reach 1.1.1.1:443");
    }
    ok
}

/// Whether this host reaches the public internet over IPv6, which is
/// what a positive IPv6 test through the sandbox needs: pasta copies the
/// host's own configuration into the namespace, so a host with no global
/// IPv6 address gives the sandbox none either.
fn host_has_ipv6() -> bool {
    let addr = "[2606:4700:4700::1111]:443".parse().unwrap();
    let ok = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok();
    if !ok {
        say("skipping the IPv6 half: this host has no route to 2606:4700:4700::1111");
    }
    ok
}

/// A python snippet run inside instance `name`, as its whole output.
fn in_sandbox(root: &std::path::Path, init: &std::path::Path, name: &str, py: &str) -> String {
    let out = bubbler_live(root, init)
        .args(["run", name, "--", PYTHON, "-c", py])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Connect to `127.0.0.1:<port>` and print what came back, or why not.
const PROBE: &str = "\
import socket, sys
try:
    s = socket.create_connection(('127.0.0.1', int(sys.argv[1])), 3)
    print(s.recv(64).decode().strip())
except OSError as e:
    print('BLOCKED', type(e).__name__)
";

/// The user namespace pasta is handed is taken from the sandbox's
/// network namespace, which cannot be raced: what it replaced was a
/// `/proc/<child-pid>/ns/user` open that had to happen before bwrap
/// moved the sandbox into a nested user namespace. Twenty runs in a
/// row, because a race is something a single run wins.
#[test]
fn twenty_isolated_runs_in_a_row_all_reach_their_sidecar() {
    if !require_bwrap() || !require_pasta() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network
",
    )
    .unwrap();
    for run in 1..=20 {
        let out = bubbler_live(tmp.path(), &init)
            .args(["run", "t", "--", "/usr/bin/true"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "run {run} of 20: {err}");
    }
}

#[test]
fn real_pasta_hides_the_host_loopback_that_network_host_still_reaches() {
    if !require_bwrap() || !require_python() || !require_pasta() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let port = free_port();
    // A host service on loopback, exactly what `--share-net` hands over.
    let mut server = Command::new(PYTHON)
        .args([
            "-c",
            "import socket,sys\n\
             s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
             s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(8)\n\
             while True:\n c,_=s.accept(); c.sendall(b'SECRET-HOST-SERVICE\\n'); c.close()\n",
            &port.to_string(),
        ])
        .spawn()
        .unwrap();
    assert!(
        wait_until(
            || std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(),
            Duration::from_secs(5)
        ),
        "the host listener never came up"
    );

    for (kdl, expected) in [
        ("network \"host\"\n", "SECRET-HOST-SERVICE"),
        ("network\n", "BLOCKED"),
    ] {
        let name = if kdl.contains("host") { "h" } else { "i" };
        bubbler_live(tmp.path(), &init)
            .args(["create", name])
            .status()
            .unwrap();
        std::fs::write(
            tmp.path()
                .join(format!("data/bubbler/instances/{name}/config.kdl")),
            kdl,
        )
        .unwrap();
        let out = bubbler_live(tmp.path(), &init)
            .args(["run", name, "--", PYTHON, "-c", PROBE, &port.to_string()])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{kdl}: {err}");
        let got = String::from_utf8_lossy(&out.stdout);
        assert!(got.starts_with(expected), "{kdl}: got {got:?} ({err})");
    }
    let _ = server.kill();
    let _ = server.wait();
}

#[test]
fn real_pasta_reaches_the_internet_and_carries_the_generated_resolver() {
    if !require_bwrap() || !require_python() || !require_pasta() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");

    // The generated resolver: the address pasta translates to the host's
    // nameserver, since the host's own file may name a loopback stub.
    std::fs::write(&cfg, "network\n").unwrap();
    let out = in_sandbox(
        tmp.path(),
        &init,
        "t",
        "print(open('/etc/resolv.conf').read().strip())",
    );
    assert_eq!(out.trim(), "nameserver 169.254.1.1");

    // A `dns` child replaces it outright.
    std::fs::write(&cfg, "network {\n    dns \"1.1.1.1\"\n}\n").unwrap();
    let out = in_sandbox(
        tmp.path(),
        &init,
        "t",
        "print(open('/etc/resolv.conf').read().strip())",
    );
    assert_eq!(out.trim(), "nameserver 1.1.1.1");

    if !host_is_online() {
        return;
    }
    std::fs::write(&cfg, "network\n").unwrap();
    let out = in_sandbox(
        tmp.path(),
        &init,
        "t",
        "import socket\n\
         try:\n socket.create_connection(('1.1.1.1', 443), 8); print('ONLINE')\n\
         except OSError as e: print('OFFLINE', e)\n",
    );
    assert_eq!(out.trim(), "ONLINE");
}

#[test]
fn real_pasta_allow_port_publishes_one_port_on_the_host_loopback() {
    if !require_bwrap() || !require_python() || !require_pasta() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let port = free_port();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        format!("network {{\n    allow-port {port}\n}}\n"),
    )
    .unwrap();
    // Bound to every address in the namespace: without
    // `--host-lo-to-ns-lo` pasta delivers a forwarded connection to the
    // namespace's own public address, not to its loopback.
    let mut run = bubbler_live(tmp.path(), &init)
        .args([
            "run",
            "t",
            "--",
            PYTHON,
            "-c",
            "import socket,sys\n\
             s=socket.socket(); s.bind(('0.0.0.0', int(sys.argv[1]))); s.listen(4)\n\
             c,_=s.accept(); c.sendall(b'FROM-THE-SANDBOX\\n'); c.close()\n",
            &port.to_string(),
        ])
        .spawn()
        .unwrap();
    let mut got = String::new();
    let reached = wait_until(
        || {
            let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
                return false;
            };
            use std::io::Read;
            let _ = s.read_to_string(&mut got);
            !got.is_empty()
        },
        Duration::from_secs(15),
    );
    let _ = run.kill();
    let _ = run.wait();
    assert!(reached, "the forwarded port was never reachable");
    assert_eq!(got.trim(), "FROM-THE-SANDBOX");
}

#[test]
fn real_pasta_keeps_serving_an_instance_that_is_exec_ed_into() {
    if !require_bwrap() || !require_python() || !require_pasta() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network\n",
    )
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
        fail_with(run, "the isolated instance never accepted a connection");
    }
    let out = bubbler_live(tmp.path(), &init)
        .args([
            "exec",
            "t",
            "--",
            PYTHON,
            "-c",
            "print(open('/etc/resolv.conf').read().strip())",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "nameserver 169.254.1.1"
    );
    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    let _ = run.wait();
}

/// What a filtered sandbox is allowed to reach, and how everything else
/// fails. Every rendering the generator has — a bare address, a port and
/// protocol, a v4 prefix and a v6 literal — goes through the real `nft`
/// here, so a form the golden pins but nftables would refuse fails this
/// test rather than a user's run.
#[test]
fn outbound_deny_filters_what_no_allow_out_names_and_the_sandbox_cannot_undo_it() {
    if !require_bwrap() || !require_python() || !require_pasta() || !require_nft() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443 proto=\"tcp\"\n    \
         allow-out \"192.168.0.0/16\" proto=\"udp\"\n    \
         allow-out \"2606:4700:4700::1111\" port=443 proto=\"tcp\"\n    \
         allow-out \"2606:4700::/32\" port=853\n}\n",
    )
    .unwrap();
    let out = in_sandbox(tmp.path(), &init, "t", OUTBOUND_PROBE);
    let line = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("{name} missing from {out}"))
            .trim()
            .to_owned()
    };
    // A blocked destination fails immediately and by name, not by
    // timeout: the trailing `reject` is what turns a hang into an error
    // the application can print. Measured on this host: EHOSTUNREACH for
    // TCP (nft translates `icmpx admin-prohibited` to ICMP
    // host-prohibited) and EPERM straight out of `sendto` for UDP.
    for probe in ["tcp-blocked-port:", "tcp-blocked-host:"] {
        let got = line(probe);
        assert!(!got.starts_with("CONNECTED"), "{probe} {got}");
        assert!(!got.starts_with("TIMEOUT"), "{probe} {got}");
        let secs: f64 = got.rsplit(' ').next().unwrap().parse().unwrap();
        assert!(secs < 1.0, "{probe} took {secs}s; a reject is immediate");
    }
    assert!(line("udp-blocked:").starts_with("EPERM"), "{out}");
    // IPv6 is rejected too, and by the same rule: the table is `inet`, so
    // a v6 destination no `allow-out` names falls to the same reject. It
    // arrives as EACCES rather than EHOSTUNREACH, and about a second
    // late: the ICMPv6 error is matched to the socket only after the
    // first SYN retransmit. Measured at 1.02-1.05 s over ten runs, so the
    // bound here is what separates it from a silent drop's timeout.
    let blocked6 = line("tcp6-blocked:");
    assert!(blocked6.starts_with("EACCES"), "{out}");
    let secs: f64 = blocked6.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(
        secs < 3.0,
        "blocked IPv6 took {secs}s; a reject is not a timeout"
    );
    // The rules live in the user namespace that owns the sandbox's
    // network namespace, and the sandbox is in a nested one: it cannot
    // even read them, let alone flush them.
    assert!(
        line("nft-list:").contains("Operation not permitted"),
        "{out}"
    );
    assert!(
        line("nft-flush:").contains("Operation not permitted"),
        "{out}"
    );
    if !host_is_online() {
        return;
    }
    assert!(line("tcp-allowed:").starts_with("CONNECTED"), "{out}");
    // The IPv6 half only where the host has IPv6 at all: pasta copies the
    // host's configuration into the namespace, so a host without a global
    // address gives the sandbox none and neither answer would be about
    // the filter. What the ruleset has to get right for this to work at
    // all is the neighbour discovery accept — without it the sandbox
    // never resolves its own gateway and every v6 destination fails with
    // EHOSTUNREACH after three seconds, `allow-out` or not.
    if host_has_ipv6() {
        assert!(line("tcp6-allowed:").starts_with("CONNECTED"), "{out}");
    }
    // The resolver is opened by the generator, never by the user: an
    // `outbound "deny"` that broke name resolution would look like a
    // network outage rather than a policy.
    assert!(line("dns:").starts_with("ANSWERED"), "{out}");
}

/// The probe [`outbound_deny_filters_what_no_allow_out_names_and_the_sandbox_cannot_undo_it`]
/// runs inside the sandbox: one line per destination, each ending in the
/// seconds it took.
const OUTBOUND_PROBE: &str = "\
import socket, time, errno, subprocess

def tcp(host, port):
    t0 = time.monotonic()
    s = socket.socket(); s.settimeout(4)
    try:
        s.connect((host, port)); return 'CONNECTED'
    except socket.timeout: return 'TIMEOUT'
    except OSError as e: return errno.errorcode.get(e.errno, e.errno)
    finally:
        s.close()
        globals()['took'] = time.monotonic() - t0

def tcp6(host, port):
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(6)
    try:
        s.connect((host, port)); return 'CONNECTED'
    except socket.timeout: return 'TIMEOUT'
    except OSError as e: return errno.errorcode.get(e.errno, e.errno)
    finally:
        s.close()
        globals()['took'] = time.monotonic() - t0

def dns(server):
    q = b'\\xab\\xcd\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'
    for lab in b'example.com'.split(b'.'):
        q += bytes([len(lab)]) + lab
    q += b'\\x00\\x00\\x01\\x00\\x01'
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
    try:
        s.sendto(q, (server, 53)); s.recvfrom(512); return 'ANSWERED'
    except socket.timeout: return 'TIMEOUT'
    except OSError as e: return errno.errorcode.get(e.errno, e.errno)
    finally:
        s.close()
        globals()['took'] = time.monotonic() - t0

def say(name, what):
    print('%s %s %.3f' % (name, what, took), flush=True)

say('tcp-allowed:', tcp('1.1.1.1', 443))
say('tcp-blocked-port:', tcp('1.1.1.1', 80))
say('tcp-blocked-host:', tcp('8.8.8.8', 443))
say('tcp6-allowed:', tcp6('2606:4700:4700::1111', 443))
say('tcp6-blocked:', tcp6('2001:4860:4860::8888', 443))
say('dns:', dns('169.254.1.1'))
say('udp-blocked:', dns('8.8.8.8'))
for name, argv in [('nft-list:', ['list', 'ruleset']), ('nft-flush:', ['flush', 'ruleset'])]:
    done = subprocess.run(['nft'] + argv, capture_output=True, text=True)
    print(name, done.stderr.replace('\\n', ' ').strip(), flush=True)
";

/// What the process holding CAP_NET_ADMIN over the sandbox's namespaces
/// is allowed to do, and what it is fed.
///
/// A stand-in `nft` on `PATH` writes its own `/proc/self/status` and the
/// ruleset it was given, so both halves of the hand-off are checked
/// without needing nftables installed. The capability set is the point:
/// bwrap's own nested user namespace maps bubbler to uid 0, and a uid-0
/// exec is handed the full set unless `SECBIT_NOROOT` says otherwise.
#[test]
fn the_nft_child_holds_cap_net_admin_and_is_fed_the_ruleset() {
    if !require_bwrap() || !require_python() || !require_pasta() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    let path = tmp.path().join("fakenft");
    std::fs::create_dir_all(&path).unwrap();
    for bin in ["bwrap", "pasta"] {
        std::os::unix::fs::symlink(format!("/usr/bin/{bin}"), path.join(bin)).unwrap();
    }
    let status = tmp.path().join("nft.status");
    let stdin = tmp.path().join("nft.stdin");
    std::fs::write(
        path.join("nft"),
        format!(
            "#!{PYTHON}\n\
             import sys\n\
             open({stdin:?}, 'wb').write(sys.stdin.buffer.read())\n\
             open({status:?}, 'w').write(open('/proc/self/status').read())\n",
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        path.join("nft"),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .unwrap();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443 proto=\"tcp\"\n}\n",
    )
    .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .env("PATH", &path)
        .args(["run", "t", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fed = std::fs::read_to_string(&stdin).unwrap();
    assert!(fed.starts_with("table inet bubbler {\n"), "{fed}");
    assert!(
        fed.contains("\n\t\ticmpv6 type { nd-router-solicit"),
        "{fed}"
    );
    assert!(
        fed.contains("\n\t\tip daddr 1.1.1.1 tcp dport 443 accept\n"),
        "{fed}"
    );
    let status = std::fs::read_to_string(&status).unwrap();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("{name} missing from {status}"))
            .trim()
            .to_owned()
    };
    // CAP_NET_ADMIN is bit 12, and it is the only bit set: not the full
    // set a uid-0 exec would otherwise be given, and not an empty one,
    // which is what an exec without the ambient set would have.
    const ONLY_NET_ADMIN: &str = "0000000000001000";
    assert_eq!(field("CapEff:"), ONLY_NET_ADMIN, "{status}");
    assert_eq!(field("CapPrm:"), ONLY_NET_ADMIN, "{status}");
    assert_eq!(field("CapAmb:"), ONLY_NET_ADMIN, "{status}");
}

/// `nftables` is an optional dependency: only a config that filters needs
/// it, and a host without it is told which package to install rather than
/// given a sandbox with the unfiltered network it did not ask for.
#[test]
fn outbound_deny_without_nft_on_path_names_the_package_and_starts_nothing() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    // A PATH holding what a run needs and nothing else; `nft` is what it
    // is missing.
    let path = tmp.path().join("nonft");
    std::fs::create_dir_all(&path).unwrap();
    std::os::unix::fs::symlink("/usr/bin/bwrap", path.join("bwrap")).unwrap();
    bubbler_live(tmp.path(), &init)
        .args(["create", "t"])
        .status()
        .unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\"\n}\n",
    )
    .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .env("PATH", &path)
        .args(["run", "t", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("nftables"), "{err}");
    assert!(err.contains("`nft` is not on PATH"), "{err}");
}

/// The ruleset is a grant that is neither a bwrap argument nor a D-Bus
/// rule, so `--explain` is the only place a reader can see what a run
/// will actually enforce.
#[test]
fn explain_lists_the_outbound_ruleset_under_the_network_node() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network {\n    outbound \"deny\"\n    allow-out \"1.1.1.1\" port=443 proto=\"tcp\"\n}\n\
         command \"true\"\n",
    )
    .unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.contains("\n    ruleset: table inet bubbler {\n"), "{s}");
    for line in [
        "type filter hook output priority 0; policy drop;",
        "oifname \"lo\" accept",
        "ip daddr 169.254.1.1 udp dport 53 accept",
        "ip daddr 1.1.1.1 tcp dport 443 accept",
        "reject with icmpx admin-prohibited",
    ] {
        assert!(s.contains(line), "{line} missing from {s}");
    }
    // Nothing to install, nothing to show.
    std::fs::write(
        tmp.path().join("data/bubbler/instances/t/config.kdl"),
        "network\ncommand \"true\"\n",
    )
    .unwrap();
    let out = bubbler(tmp.path())
        .args(["run", "t", "--explain"])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("sidecar: pasta"), "{s}");
    assert!(!s.contains("ruleset:"), "{s}");
}

/// Under `network "host"` there is no namespace of bubbler's to filter
/// and the rules would land on the host's own ruleset, so the parser
/// refuses the node rather than the launcher discovering it later.
#[test]
fn outbound_under_the_host_mode_is_a_config_error() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    for text in [
        "network \"host\" {\n    outbound \"deny\"\n}\ncommand \"true\"\n",
        "network \"none\" {\n    outbound \"deny\"\n}\ncommand \"true\"\n",
        "network {\n    allow-out \"1.1.1.1\"\n}\ncommand \"true\"\n",
    ] {
        std::fs::write(&cfg, text).unwrap();
        let out = bubbler(tmp.path())
            .args(["run", "t", "--dry-run"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{text}: {err}");
        assert!(err.contains("network"), "{text}: {err}");
    }
}

#[test]
fn edit_warns_about_the_flip_before_it_stamps_the_version() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "network\ncommand \"true\"\n").unwrap();
    let edit = || {
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
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    // The edit that stamps the file is the one that still says why.
    assert!(edit().contains("isolated network namespace"));
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        "// bubbler config: 2\nnetwork\ncommand \"true\"\n"
    );
    // And having been stamped, it is the last time.
    assert!(!edit().contains("isolated network namespace"));
}

/// An instance whose config runs `/usr/bin/true`, which is all a shim
/// needs: dispatch reads the `command` node and never starts anything.
fn wrapped_instance(root: &Path, name: &str) -> PathBuf {
    let out = bubbler(root).args(["create", name]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = root
        .join("data/bubbler/instances")
        .join(name)
        .join("config.kdl");
    std::fs::write(&cfg, "command \"/usr/bin/true\"\n").unwrap();
    root.join("home/.local/bin").join(name)
}

#[test]
fn a_shim_is_a_symlink_that_dispatches_to_open() {
    let tmp = setup();
    let link = wrapped_instance(tmp.path(), "ff");
    let out = bubbler(tmp.path()).args(["wrap", "ff"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}\n", link.display())
    );
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        Path::new(env!("CARGO_BIN_EXE_bubbler"))
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("config/bubbler/wraps.kdl")).unwrap(),
        "// bubbler wraps: 1\nwrap \"ff\" instance=\"ff\"\n"
    );

    // Called through the link, bubbler becomes `open` on that instance,
    // with the instance's own command ahead of the shim's arguments.
    let out = common::shim(tmp.path(), &link)
        .env("BUBBLER_WRAP_DRY_RUN", "1")
        .args(["https://example.invalid", "--version"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "bubbler\nopen\nff\n--\n/usr/bin/true\nhttps://example.invalid\n--version\n"
    );
}

#[test]
fn a_name_the_registry_does_not_hold_is_the_ordinary_cli() {
    let tmp = setup();
    wrapped_instance(tmp.path(), "ff");
    let link = tmp.path().join("home/.local/bin/zzz");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_bubbler"), &link).unwrap();
    let out = common::shim(tmp.path(), &link)
        .arg("list")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ff\n");
}

#[test]
fn wrap_list_reports_the_shim_that_is_gone_as_broken() {
    let tmp = setup();
    let link = wrapped_instance(tmp.path(), "ff");
    bubbler(tmp.path()).args(["wrap", "ff"]).status().unwrap();
    let list = || {
        let out = bubbler(tmp.path())
            .args(["wrap", "--list"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert_eq!(list(), format!("ff\tff\t{}\tok\n", link.display()));
    std::fs::remove_file(&link).unwrap();
    assert_eq!(list(), format!("ff\tff\t{}\tbroken\n", link.display()));
}

#[test]
fn wrap_refuses_a_reserved_name_and_a_file_that_is_not_ours() {
    let tmp = setup();
    wrapped_instance(tmp.path(), "ff");
    for name in ["bubbler", "bwrap", "xdg-dbus-proxy", "pasta", "passt"] {
        let out = bubbler(tmp.path())
            .args(["wrap", "ff", "--as", name])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{name} was accepted");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("refusing to name a shim"),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = bubbler(tmp.path())
        .args(["wrap", "ff", "--as", "a/b"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("invalid shim name"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bin = tmp.path().join("home/.local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("ff"), b"#!/bin/sh\n").unwrap();
    let out = bubbler(tmp.path()).args(["wrap", "ff"]).output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not a bubbler shim"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(bin.join("ff")).unwrap(),
        "#!/bin/sh\n"
    );
}

#[test]
fn unwrap_removes_the_shim_and_the_registry_line() {
    let tmp = setup();
    let link = wrapped_instance(tmp.path(), "ff");
    bubbler(tmp.path()).args(["wrap", "ff"]).status().unwrap();
    let out = bubbler(tmp.path()).args(["unwrap", "ff"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(std::fs::symlink_metadata(&link).is_err());
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("config/bubbler/wraps.kdl")).unwrap(),
        "// bubbler wraps: 1\n"
    );
    let out = bubbler(tmp.path()).args(["unwrap", "ff"]).output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no shim named `ff`"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_shim_directory_off_the_path_is_warned_about_and_a_renamed_shim_says_what_it_takes() {
    let tmp = setup();
    wrapped_instance(tmp.path(), "ff");
    // The test PATH is `/usr/bin:/bin`, so the shim directory is never on it.
    let out = bubbler(tmp.path()).args(["wrap", "ff"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("is not on your PATH"), "{err}");
    assert!(!err.contains("note:"), "{err}");

    let out = bubbler(tmp.path())
        .args(["wrap", "ff", "--as", "firefox"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("wherever PATH resolves it"), "{err}");

    // A real program earlier on PATH is what the shim would lose to.
    let out = bubbler(tmp.path())
        .args(["wrap", "ff", "--as", "true"])
        .env(
            "PATH",
            format!("/usr/bin:{}", tmp.path().join("home/.local/bin").display()),
        )
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("/usr/bin/true comes first"), "{err}");
}

#[test]
fn twelve_wraps_at_once_leave_twelve_lines_and_twelve_links() {
    let tmp = setup();
    wrapped_instance(tmp.path(), "ff");
    // Spawned before any is waited on, so the read-modify-write of the
    // registry really does overlap: without a lock across it, the last
    // writer wins and the other eleven entries are gone.
    let names: Vec<String> = (0..12).map(|i| format!("shim{i}")).collect();
    let running: Vec<Child> = names
        .iter()
        .map(|name| {
            bubbler(tmp.path())
                .args(["wrap", "ff", "--as", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut child in running {
        assert!(child.wait().unwrap().success());
    }
    let text = std::fs::read_to_string(tmp.path().join("config/bubbler/wraps.kdl")).unwrap();
    let lines = text.lines().filter(|l| l.starts_with("wrap ")).count();
    let mut links: Vec<_> = std::fs::read_dir(tmp.path().join("home/.local/bin"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    links.sort();
    assert_eq!(lines, 12, "{text}");
    assert_eq!(links.len(), 12, "{links:?}");
    for name in &names {
        assert!(text.contains(&format!("wrap \"{name}\"")), "{text}");
    }
}

#[test]
fn a_shim_starts_a_real_sandbox() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else {
        return;
    };
    let tmp = setup();
    let link = wrapped_instance(tmp.path(), "sh");
    std::fs::write(
        tmp.path().join("data/bubbler/instances/sh/config.kdl"),
        "command \"/usr/bin/id\"\n",
    )
    .unwrap();
    let out = bubbler_live(tmp.path(), &init)
        .args(["wrap", "sh"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // No dry-run hook: this is the symlink, dispatch, `open` and bwrap,
    // reporting the uid the sandbox actually runs as.
    let out = common::shim(tmp.path(), &link)
        .env("BUBBLER_INIT", &init)
        .arg("-u")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        rustix::process::getuid().as_raw().to_string()
    );
}

#[test]
fn deleting_an_instance_names_the_shims_left_pointing_at_it() {
    let tmp = setup();
    wrapped_instance(tmp.path(), "ff");
    bubbler(tmp.path())
        .args(["wrap", "ff", "--as", "firefox"])
        .status()
        .unwrap();
    let out = bubbler(tmp.path())
        .args(["delete", "ff", "--yes"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    // Named, not removed: the file on the user's PATH is theirs to keep.
    assert!(err.contains("shim `firefox` still opens `ff`"), "{err}");
    assert!(tmp.path().join("home/.local/bin/firefox").exists());
    let out = bubbler(tmp.path())
        .args(["wrap", "--list"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).ends_with("\tbroken\n"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Every command and subcommand the CLI takes, as the man page has to
/// name them. Written out rather than derived: the page is the promise
/// bubbler makes to a reader, and a subcommand added without a word
/// about it in the page is the drift this asserts against.
const COMMANDS: &[&str] = &[
    "bubbler create",
    "bubbler run",
    "bubbler try",
    "bubbler exec",
    "bubbler open",
    "bubbler log",
    "bubbler desktop",
    "bubbler list",
    "bubbler profiles",
    "bubbler delete",
    "bubbler edit",
    "bubbler profile",
    "bubbler profile show",
    "bubbler profile edit",
    "bubbler profile lint",
    "bubbler reseed",
    "bubbler lint",
    "bubbler wrap",
    "bubbler unwrap",
    "bubbler ui",
    "bubbler man",
];

/// Roff as the reader sees it: the escapes a page is written with are
/// not what it says, and what it says is what these tests are about.
fn rendered(roff: &str) -> String {
    roff.replace(r"\*(Aq", "'")
        .replace(r"\(em", "\u{2014}")
        .replace(r"\fB", "")
        .replace(r"\fI", "")
        .replace(r"\fR", "")
        .replace(r"\-", "-")
        .replace(r"\&", "")
}

#[test]
fn the_long_help_of_a_shim_says_what_it_takes_over() {
    let tmp = setup();
    let out = bubbler(tmp.path())
        .args(["wrap", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    // The three things a reader has to know before putting a name of
    // their own on PATH, and the three the README spends a section on.
    assert!(text.contains("argv[0]"), "what a shim is:\n{text}");
    assert!(text.contains("PATH"), "the PATH caveat:\n{text}");
    assert!(text.contains("~/.local/bin"), "where it lands:\n{text}");
    for reserved in ["bubbler-init", "bwrap", "xdg-dbus-proxy", "pasta"] {
        assert!(text.contains(reserved), "reserved `{reserved}`:\n{text}");
    }
    let out = bubbler(tmp.path())
        .args(["unwrap", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("never deletes"), "{text}");
}

#[test]
fn man_needs_no_session_environment() {
    // A package build renders the pages under fakeroot, where no session
    // manager has set XDG_RUNTIME_DIR or HOME.
    let tmp = setup();
    for args in [&["man"][..], &["man", "--config"][..]] {
        let out = bubbler(tmp.path())
            .args(args)
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("HOME")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{args:?}: {err}");
        assert!(
            out.stdout.starts_with(b".") || out.stdout.starts_with(b"'"),
            "{args:?}"
        );
    }
}

#[test]
fn man_renders_the_page_and_a_section_for_every_subcommand() {
    let tmp = setup();
    let out = bubbler(tmp.path()).arg("man").output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let roff = String::from_utf8_lossy(&out.stdout);
    assert!(roff.contains("\n.TH BUBBLER 1 "), "{:?}", &roff[..60]);
    for name in COMMANDS {
        // The heading of that command's own section: a page that named a
        // subcommand only in the top-level synopsis would document none
        // of its options.
        let heading = format!(".SS {name}");
        assert!(
            roff.lines().any(|l| l == heading),
            "no section for `{name}`"
        );
    }
    // The sections clap knows nothing about and a man page is for.
    for section in [".SH FILES", ".SH ENVIRONMENT", ".SH \"SEE ALSO\""] {
        assert!(roff.contains(section), "no {section}");
    }
}

#[test]
fn man_config_names_every_grant_and_every_lint_check() {
    let tmp = setup();
    let out = bubbler(tmp.path())
        .args(["man", "--config"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let roff = String::from_utf8_lossy(&out.stdout);
    assert!(
        roff.contains("\n.TH BUBBLER-CONFIG 5 "),
        "{:?}",
        &roff[..60]
    );
    let text = rendered(&roff);
    for grant in bubbler_core::catalogue::GRANTS {
        assert!(
            text.contains(grant.node),
            "the config page never names `{}`",
            grant.node
        );
        assert!(
            text.contains(grant.summary),
            "the config page never summarises `{}`",
            grant.node
        );
        assert!(
            text.contains(grant.grammar),
            "the config page never says how `{}` is written",
            grant.node
        );
    }
    for check in bubbler_core::lint::CHECKS {
        assert!(
            text.contains(check.id),
            "the config page never names the check `{}`",
            check.id
        );
    }
}

#[test]
fn man_exits_zero_when_nothing_is_reading() {
    let tmp = setup();
    for args in [&["man"][..], &["man", "--config"][..]] {
        // The read end is closed before the child is started, so the
        // very first write is a broken pipe rather than a race with the
        // pipe's buffer.
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        drop(reader);
        let child = bubbler(tmp.path())
            .args(args)
            .stdout(Stdio::from(writer))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{args:?}: {err}");
        assert!(err.is_empty(), "{args:?}: {err}");
    }
}

#[test]
fn groff_reads_both_pages_without_a_complaint() {
    if !require_groff() {
        return;
    }
    let tmp = setup();
    for args in [&["man"][..], &["man", "--config"][..]] {
        let page = bubbler(tmp.path()).args(args).output().unwrap();
        assert!(
            page.status.success(),
            "{}",
            String::from_utf8_lossy(&page.stderr)
        );
        // `-z` renders nothing and only reports. `-ww` rather than
        // `-wall`, which leaves out the one category hand-written roff
        // gets wrong: a macro or string that is not defined. groff exits
        // 0 having warned, so what it said is the assertion.
        let mut groff = Command::new("groff")
            .args(["-man", "-ww", "-z"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        groff
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(&page.stdout)
            .unwrap();
        let out = groff.wait_with_output().unwrap();
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{args:?}: groff failed: {said}");
        assert!(said.is_empty(), "{args:?}: {said}");
    }
}

/// A vendor-style entry in one of the test root's own applications
/// directories: `user` is what `$XDG_DATA_HOME` points at, `system` what
/// `$XDG_DATA_DIRS` does. No test ever reads or writes the user's real
/// `~/.local/share/applications`.
fn write_entry(root: &Path, layer: &str, name: &str, text: &str) -> PathBuf {
    let dir = match layer {
        "user" => root.join("data/applications"),
        _ => root.join("share/applications"),
    };
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn a_desktop_entry_is_written_refreshed_and_removed_without_touching_anything_else() {
    let tmp = setup();
    // A command no application on this host is named after, so the
    // lookup can only find the entry this test writes.
    write_profile(
        tmp.path(),
        "user",
        "app",
        "wayland\ncommand \"bubbler-test-app\"\n",
    );
    // In a `$XDG_DATA_DIRS` directory, the way a packaged application
    // installs its entry.
    let vendor = write_entry(
        tmp.path(),
        "system",
        "bubbler-test-app.desktop",
        "[Desktop Entry]\nType=Application\nName=Test App\nName[de]=Test-Anwendung\n\
         Exec=bubbler-test-app %U\nDBusActivatable=true\nActions=new;\n\n\
         [Desktop Action new]\nName=New\nExec=bubbler-test-app --new\n",
    );
    bubbler(tmp.path())
        .args(["create", "t", "--profile", "app"])
        .status()
        .unwrap();

    let out = bubbler(tmp.path()).args(["desktop", "t"]).output().unwrap();
    let written = tmp.path().join("data/applications/bubbler-t.desktop");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}\n", written.display()),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let entry = std::fs::read_to_string(&written).unwrap();
    assert!(entry.contains("\nName=Test App (Bubbler)\n"), "{entry}");
    assert!(
        entry.contains("\nName[de]=Test-Anwendung (Bubbler)\n"),
        "{entry}"
    );
    assert!(entry.contains("\nX-Bubbler-Instance=t\n"), "{entry}");
    // The key that would have the session bus start the application
    // outside the sandbox, with nothing printed anywhere.
    assert!(entry.contains("\nDBusActivatable=false\n"), "{entry}");
    assert!(!entry.contains("DBusActivatable=true"), "{entry}");
    for exec in ["-- bubbler-test-app %U", "-- bubbler-test-app --new"] {
        assert!(entry.contains(exec), "{exec}\n{entry}");
    }
    // The `Exec` names a bubbler a launcher can find: this test binary is
    // not on PATH, so the entry has to name it where it is.
    let program = format!("Exec={} open t --", env!("CARGO_BIN_EXE_bubbler"));
    assert!(entry.contains(&program), "{program}\n{entry}");
    if Command::new("desktop-file-validate")
        .arg(&written)
        .output()
        .is_ok()
    {
        let out = Command::new("desktop-file-validate")
            .arg(&written)
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(!said.contains("error:"), "{said}");
    }

    // The application's own entry is untouched.
    assert!(
        std::fs::read_to_string(&vendor)
            .unwrap()
            .contains("Name=Test App\n")
    );
    // `--replace` writes the vendor's file name into the user's own
    // directory, and refuses when a file that is not bubbler's is there.
    let planted = write_entry(
        tmp.path(),
        "user",
        "bubbler-test-app.desktop",
        "[Desktop Entry]\nType=Application\nName=Mine\nExec=bubbler-test-app\n",
    );
    let out = bubbler(tmp.path())
        .args(["desktop", "t", "--replace"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(
        err.contains("is not bubbler's; move it aside first"),
        "{err}"
    );
    assert!(
        std::fs::read_to_string(&planted)
            .unwrap()
            .contains("Name=Mine")
    );
    std::fs::remove_file(&planted).unwrap();

    // `--refresh` rewrites what bubbler wrote and reports each path.
    std::fs::write(&written, "[Desktop Entry]\nExec=x\nX-Bubbler-Instance=t\n").unwrap();
    let out = bubbler(tmp.path())
        .args(["desktop", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}\n", written.display()),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        std::fs::read_to_string(&written)
            .unwrap()
            .contains("Name=Test App (Bubbler)")
    );

    // `--remove` takes bubbler's entry and nothing else in the directory.
    let out = bubbler(tmp.path())
        .args(["desktop", "t", "--remove"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!written.exists());
    assert!(vendor.is_file());
}

#[test]
fn desktop_print_writes_nothing_and_an_unresolvable_entry_names_the_node_to_add() {
    let tmp = setup();
    write_profile(tmp.path(), "user", "app", "command \"bubbler-test-app\"\n");
    bubbler(tmp.path())
        .args(["create", "t", "--profile", "app"])
        .status()
        .unwrap();
    // Nothing on this host runs `bubbler-test-app`, so the error is the
    // one that tells the user which node fixes it.
    let out = bubbler(tmp.path())
        .args(["desktop", "t", "--print"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(
        err.contains("no desktop entry runs `bubbler-test-app`"),
        "{err}"
    );
    assert!(err.contains("`desktop \"<name>.desktop\"`"), "{err}");

    write_entry(
        tmp.path(),
        "system",
        "org.example.App.desktop",
        "[Desktop Entry]\nType=Application\nName=App\nExec=bubbler-test-app %U\n",
    );
    let out = bubbler(tmp.path())
        .args(["desktop", "t", "--print"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Name=App (Bubbler)"), "{text}");
    // Printing is a preview: bubbler's own directory is not even made.
    assert!(!tmp.path().join("data/applications").exists());
}

#[test]
fn open_without_a_terminal_leaves_its_errors_in_the_log_that_log_prints() {
    let tmp = setup();
    write_profile(tmp.path(), "user", "app", "command \"/usr/bin/true\"\n");
    bubbler(tmp.path())
        .args(["create", "t", "--profile", "app"])
        .status()
        .unwrap();
    // `$BUBBLER_INIT` names the stand-in file `setup` writes, so the run
    // fails at a point every host reaches the same way.
    std::fs::remove_file(tmp.path().join("bubbler-init")).unwrap();
    let out = bubbler(tmp.path()).args(["open", "t"]).output().unwrap();
    assert!(!out.status.success());
    // Nothing reached the caller's stderr: it went to the log, the error
    // this run ended with included.
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");

    let log = tmp.path().join("data/bubbler/instances/t/last-run.log");
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the log is readable by others");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("bubbler-init"), "{text}");

    let out = bubbler(tmp.path()).args(["log", "t"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), text);

    // Each run starts the log again rather than growing it forever.
    let out = bubbler(tmp.path()).args(["open", "t"]).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(&log).unwrap(), text);

    let out = bubbler(tmp.path()).args(["log", "other"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("instance `other` not found"), "{err}");
}

#[test]
fn real_bwrap_open_execs_into_a_live_instance_and_starts_one_that_is_not() {
    if !require_bwrap() {
        return;
    }
    let Some(init) = real_init() else { return };
    let tmp = setup();
    write_profile(tmp.path(), "user", "app", "command \"/usr/bin/sleep\"\n");
    bubbler_live(tmp.path(), &init)
        .args(["create", "t", "--profile", "app"])
        .status()
        .unwrap();
    let home = tmp.path().join("data/bubbler/instances/t/home");

    // Not live: `open` starts the sandbox, which is what a launcher does.
    let marker = home.join("started");
    let out = bubbler_live(tmp.path(), &init)
        .args(["open", "t", "--", "/usr/bin/touch", "/home/bubbler/started"])
        .output()
        .unwrap();
    let said = std::fs::read_to_string(tmp.path().join("data/bubbler/instances/t/last-run.log"))
        .unwrap_or_default();
    assert!(out.status.success(), "{said}");
    assert!(marker.is_file(), "the sandbox never ran: {said}");

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

    // Live: the command is handed to the sandbox that is already running,
    // which is how a second click on a menu entry reaches the open window.
    let out = bubbler_live(tmp.path(), &init)
        .args(["open", "t", "--", "/usr/bin/touch", "/home/bubbler/execed"])
        .output()
        .unwrap();
    // Nothing on stderr: with no terminal anywhere, what bubbler had to
    // say went to the log, and it added to the log of the run it went
    // into rather than emptying it under a sandbox that is still writing.
    let log = tmp.path().join("data/bubbler/instances/t/last-run.log");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(out.status.success(), "{text}");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
    assert!(home.join("execed").is_file(), "{text}");
    assert!(text.contains("executing inside it"), "{text}");

    kill_process(Pid::from_child(&run), Signal::TERM).unwrap();
    let _ = run.wait();
}

#[test]
fn an_entry_the_validator_rejects_is_written_and_reported() {
    if Command::new("desktop-file-validate").output().is_err() {
        say("skipping: desktop-file-validate is not installed");
        return;
    }
    let tmp = setup();
    write_profile(tmp.path(), "user", "app", "command \"bubbler-test-app\"\n");
    // The application's own entry names an action group it does not have,
    // which is an error in the copy bubbler writes as much as in it.
    write_entry(
        tmp.path(),
        "system",
        "bubbler-test-app.desktop",
        "[Desktop Entry]\nType=Application\nName=App\nExec=bubbler-test-app\nActions=nope;\n",
    );
    bubbler(tmp.path())
        .args(["create", "t", "--profile", "app"])
        .status()
        .unwrap();
    let out = bubbler(tmp.path()).args(["desktop", "t"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("warning:") && err.contains("nope"), "{err}");
    assert!(
        tmp.path()
            .join("data/applications/bubbler-t.desktop")
            .is_file()
    );
}

#[test]
fn a_config_that_does_not_parse_reaches_the_log_of_the_run_it_stopped() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "bluetooth\n").unwrap();
    // The log is opened before the config is read, so the reason a
    // launcher-started run never began is in it rather than nowhere.
    let out = bubbler(tmp.path()).args(["open", "t"]).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
    let out = bubbler(tmp.path()).args(["log", "t"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("unknown node `bluetooth`"), "{text}");

    // A log that cannot be opened costs the record and not the run: a
    // symlink is never bubbler's file, and the warning names what is
    // being given up.
    std::fs::write(&cfg, "command \"/usr/bin/true\"\n").unwrap();
    let log = tmp.path().join("data/bubbler/instances/t/last-run.log");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::remove_file(&log).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &log).unwrap();
    let mut cmd = bubbler(tmp.path());
    cmd.args(["open", "t"]);
    // With a sandbox available the run completes; without one, what
    // stops it is bwrap or the missing supervisor, never the log.
    let sandboxed = require_bwrap();
    if let (true, Some(init)) = (sandboxed, real_init()) {
        cmd.env("BUBBLER_INIT", init);
    }
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no log for this run"), "{err}");
    assert!(err.contains("last-run.log"), "{err}");
    assert!(!elsewhere.exists(), "the symlink was followed");
    if sandboxed && real_init().is_some() {
        assert!(out.status.success(), "{err}");
    } else {
        assert!(
            err.contains("bubbler-init") || err.contains("bwrap"),
            "{err}"
        );
    }
}

#[test]
fn open_with_a_terminal_on_any_descriptor_leaves_the_log_alone() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    let cfg = tmp.path().join("data/bubbler/instances/t/config.kdl");
    std::fs::write(&cfg, "bluetooth\n").unwrap();
    // Only stdin is a terminal, which is still somebody watching: the
    // run says what stopped it where they can see it instead of taking
    // the log over, the way the sandbox is given a terminal too.
    let pty = test_pty();
    let out = bubbler(tmp.path())
        .args(["open", "t"])
        .stdin(pty.stdio())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("unknown node `bluetooth`"), "{err}");
    assert!(
        !tmp.path()
            .join("data/bubbler/instances/t/last-run.log")
            .exists(),
        "the log was taken over with a terminal on stdin"
    );
}

/// A log is the sandbox's own output, so printing it is bubbler handing
/// a terminal whatever the application wrote — an OSC 52 in it writes
/// the clipboard of whoever reads the log. On a terminal the control
/// characters are shown; down a pipe the log is the log, since what is
/// on the other end is a tool.
#[test]
fn log_shows_a_terminal_the_control_bytes_and_a_pipe_the_log_itself() {
    let tmp = setup();
    bubbler(tmp.path()).args(["create", "t"]).status().unwrap();
    const WRITTEN: &[u8] = b"\x1b]52;c;aGk=\x07done\n";
    let log = tmp.path().join("data/bubbler/instances/t/last-run.log");
    std::fs::write(&log, WRITTEN).unwrap();

    let pty = test_pty();
    let mut child = bubbler(tmp.path())
        .args(["log", "t"])
        .stdout(pty.stdio())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let shown = pty.read_until(Duration::from_secs(10), |s| s.contains("done\n"));
    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert_eq!(shown, "^[]52;c;aGk=^Gdone\n");
    assert!(!shown.contains('\x1b'), "an escape reached the terminal");

    let out = bubbler(tmp.path()).args(["log", "t"]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, WRITTEN);
}

/// A stand-in for the terminal editor: `bubbler ui` execs whatever is
/// named `bubbler-ui`, so a script that says which copy it is proves
/// which one was found.
fn fake_ui(path: &Path, says: &str, code: u8) {
    std::fs::write(path, format!("#!/bin/sh\necho '{says}'\nexit {code}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn ui_runs_the_editor_beside_it_before_the_one_on_the_path() {
    let tmp = setup();
    let root = tmp.path();
    // A copy of the binary, so what is "beside it" is the test's to
    // decide: the built binary's own directory holds the real editor.
    let beside = root.join("beside");
    let on_path = root.join("on-path");
    std::fs::create_dir_all(&beside).unwrap();
    std::fs::create_dir_all(&on_path).unwrap();
    let bubbler = beside.join("bubbler");
    std::fs::copy(env!("CARGO_BIN_EXE_bubbler"), &bubbler).unwrap();
    let ui = || {
        let mut c = Command::new(&bubbler);
        c.arg("ui")
            .env_clear()
            .env("PATH", &on_path)
            .env("HOME", root.join("home"))
            .env("XDG_RUNTIME_DIR", root.join("run"));
        c
    };

    // With no editor anywhere, the way to get one.
    let out = output_past_a_busy_exec(&mut ui());
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("bubbler-ui"), "{err}");
    assert!(err.contains("separate binary"), "{err}");

    // Then the one on PATH.
    fake_ui(&on_path.join("bubbler-ui"), "the editor on PATH", 7);
    let out = output_past_a_busy_exec(&mut ui());
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "the editor on PATH"
    );

    // And a copy beside the binary wins, so a pair built or unpacked
    // together stay a pair.
    fake_ui(&beside.join("bubbler-ui"), "the editor beside it", 9);
    let out = output_past_a_busy_exec(&mut ui());
    assert_eq!(out.status.code(), Some(9));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "the editor beside it"
    );
}

/// The guarded test this one runs again in a child of itself. Any of the
/// forty-odd would do; this is the smallest.
const GUARDED: &str = "real_bwrap_runs_true_and_propagates_exit_code";

/// A probe is only worth something if the host it says no on then *skips*
/// the tests behind it — a green run that names what it did not cover —
/// rather than failing them. There is no such host here, so one is made:
/// this test binary is run again, on one test, with a `PATH` carrying a
/// `bwrap` that exits 1 and then with one carrying no `bwrap` at all.
///
/// The child is run the way anyone runs the suite, with no `--nocapture`:
/// the reason has to reach the terminal of an ordinary `cargo test` or
/// the skip is silent, which is what [`common::say`] writing to
/// descriptor 2 itself is for.
#[test]
fn a_host_without_a_working_bwrap_skips_the_guarded_tests_rather_than_failing_them() {
    let tmp = tempfile::tempdir().unwrap();
    let failing = tmp.path().join("failing");
    let empty = tmp.path().join("empty");
    std::fs::create_dir(&failing).unwrap();
    std::fs::create_dir(&empty).unwrap();
    let fake = failing.join("bwrap");
    std::fs::write(&fake, "#!/usr/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

    for path in [&failing, &empty] {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", GUARDED, "--test-threads=1"])
            .env("PATH", path)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        let all = format!("{}{err}", String::from_utf8_lossy(&out.stdout));
        assert!(out.status.success(), "{}: {all}", path.display());
        assert!(err.contains("skipping: "), "{}: {all}", path.display());
        assert!(all.contains("1 passed"), "{}: {all}", path.display());
    }
}
