//! The PipeWire security context an audio grant is served through: where
//! its socket goes, what the context says about the instance, and the
//! `pw-container` command line that creates it.
//!
//! A sandbox never reaches the session's own `pipewire-0`. It gets a
//! socket of a context created for this run, and every client that
//! arrives through it is tagged on the daemon's side with the engine,
//! the instance and the grant set — which is what the session manager's
//! policy acts on. Nothing here starts anything: [`crate::launcher`]
//! runs the sidecar, and this module says what it is.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::config::AudioSet;
use crate::host::Host;
use crate::json;

/// Engine name every context bubbler creates carries. The session
/// manager's policy matches on it, exactly as it matches `org.flatpak`.
pub const ENGINE: &str = "org.bubbler";

/// What `pipewire.access` is set to, which the daemon turns into
/// `pipewire.access.effective` on every client of the context.
const ACCESS: &str = "restricted";

/// The tool that creates a context, from the `pipewire` package. Bound
/// nowhere: the sidecar has the host's read-only `/usr`, which is where
/// this is.
pub const PW_CONTAINER: &str = "/usr/bin/pw-container";

/// Where the holder mode of `bubbler-init` is bound inside the sidecar,
/// and the whole of what `pw-container` is given as its program.
///
/// One word with no shell metacharacter in it, because `pw-container`
/// hands its program to `system()`; `/run` rather than `/usr/lib`, for
/// the same reason [`crate::bwrap::INIT_INSIDE`] is there.
pub const HOLDER_INSIDE: &str = "/run/bubbler-pw-hold";

/// Names the descriptor the holder reports the socket's path on
/// (`bubbler-init`'s `pw_hold::REPORT_FD`). `pw-container` drops every
/// argv word after the program, so the environment is the only channel
/// the holder has.
pub const REPORT_FD: &str = "BUBBLER_PW_REPORT_FD";

/// The name a PipeWire client looks for under its runtime directory, and
/// so the name the holder renames the context socket to.
pub const SOCKET_NAME: &str = "pipewire-0";

/// The context socket as the sidecar sees it: [`dir`] is bound as that
/// sandbox's `/tmp`, which is where `pw-container` puts its socket
/// whatever the environment says.
pub const SOCKET_INSIDE: &str = "/tmp/pipewire-0";

/// What an explanation shows in place of the run id, which is only known
/// once there is a run.
pub const RUN_ID_SHOWN: &str = "<run id>";

/// The daemon binary the private PulseAudio server of a `pulseaudio`
/// grant is one configuration of: the same `pipewire` that serves the
/// session, started on a config of bubbler's.
pub const PIPEWIRE: &str = "/usr/bin/pipewire";

/// The module that config loads, and the whole of what makes the sidecar
/// a PulseAudio server. From the `pipewire-pulse` package, which the
/// `pipewire` package does not pull in, so a host can have every other
/// piece of this and not that one.
pub const PULSE_MODULE: &str = "/usr/lib/pipewire-0.3/libpipewire-module-protocol-pulse.so";

/// Name of the config file the private server is started with, and so
/// the name of the copy bubbler writes: `PIPEWIRE_CONFIG_DIR` replaces
/// the whole search path, and there is no fallback for the main file
/// (measured on 1.6.8: "error loading config … pipewire-pulse.conf: No
/// such file or directory").
pub const PULSE_CONF: &str = "pipewire-pulse.conf";

/// Bubbler's own fragment beside that copy. The drop-in directory of the
/// main file's name is read as well, and a dictionary in it overrides
/// what the main file set (`pipewire.conf(5)`, DROP-IN CONFIGURATION
/// FILES).
pub const PULSE_DROP_IN: &str = "pipewire-pulse.conf.d/00-bubbler.conf";

/// The config directory as the pulse sidecar sees it, which is what its
/// `PIPEWIRE_CONFIG_DIR` names: [`pulse_config_dir`] under the `/tmp`
/// that directory is bound as.
pub const PULSE_CONFIG_INSIDE: &str = "/tmp/cfg";

/// The private pulse socket as that sidecar sees it, and so the address
/// [`PULSE_OVERRIDE`] names.
pub const PULSE_SOCKET_INSIDE: &str = "/tmp/pulse/native";

/// The name the private server gives its socket, which is the last
/// component of [`PULSE_SOCKET_INSIDE`].
pub const PULSE_NATIVE: &str = "native";

/// The name that socket takes once bubbler has moved it beside the
/// sidecar's directory, where the server cannot reach it. Not `native`:
/// it sits in the instance's runtime directory beside the context
/// socket, and each name there says which sidecar made it.
pub const PULSE_ADOPTED: &str = "pulse-native";

/// Where the context socket is bound in the pulse sidecar, and what its
/// `PIPEWIRE_REMOTE` names. Under `/run` rather than the runtime dir:
/// the sidecar has no runtime directory of the session's, and an
/// absolute remote is taken as a path (measured: the private server
/// arrives on the session daemon as a client of the context).
pub const REMOTE_INSIDE: &str = "/run/pipewire-0";

/// The whole of what bubbler changes about the host's pulse
/// configuration: the server listens on one socket of this run's own,
/// and a client may not make it load a module.
///
/// Module loading is what a pulse client uses to reach past the policy —
/// `module-null-sink`, `module-loopback` and the rest run inside the
/// server, not the sandbox — so it is refused here rather than left to
/// the session manager's rules. The user's own
/// `pipewire-pulse.conf.d` fragments are not copied beside this one:
/// theirs would set `server.address` too, and the last one read would
/// decide which socket this run serves.
pub const PULSE_OVERRIDE: &str = concat!(
    "pulse.properties = {\n",
    "    server.address = [ \"unix:/tmp/pulse/native\" ]\n",
    "    pulse.allow-module-loading = false\n",
    "}\n"
);

/// The security context one run of one instance is served through: what
/// it says about the sandbox, and where its socket goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<'a> {
    /// `$XDG_RUNTIME_DIR/bubbler/<instance>` on the host.
    pub instance_runtime: &'a Path,
    /// The instance's name, which the context carries as its `app-id`.
    pub instance: &'a str,
    /// What tells two runs of one instance apart, or [`RUN_ID_SHOWN`]
    /// where there is no run to identify yet.
    pub run_id: &'a str,
    /// The grant set the session manager's policy is to apply.
    pub audio: AudioSet,
}

/// The session's own PipeWire socket. Only the sidecar ever reaches it;
/// the sandbox gets the context's socket at the same name instead, which
/// is why no client needs telling where to look.
pub fn host_socket(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(SOCKET_NAME)
}

/// `<instance runtime dir>/pw`: the directory the context socket is
/// created in, which is the sidecar's whole `/tmp`.
pub fn dir(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join("pw")
}

/// Host path of the context socket the sandbox binds: beside [`dir`],
/// never in it. The holder gives the socket its name in there and
/// bubbler moves it here before anything binds it, so what bwrap
/// resolves is a name the sidecar cannot reach.
pub fn socket(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join(SOCKET_NAME)
}

/// `<instance runtime dir>/pwpulse`: the directory the private pulse
/// server of a `pulseaudio` grant writes, which is that sidecar's whole
/// `/tmp`.
///
/// Not [`dir`]: the two audio sidecars share the instance's context but
/// neither may write what the other reads — the pulse server is the
/// process the sandboxed application talks to, and the context sidecar
/// has the session's own socket.
pub fn pulse_dir(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join("pwpulse")
}

/// `<pulse dir>/pulse`: where that server creates its socket, since the
/// address it is given is under the runtime directory it is handed.
pub fn pulse_socket_dir(instance_runtime: &Path) -> PathBuf {
    pulse_dir(instance_runtime).join("pulse")
}

/// Host path of the private pulse socket the sandbox binds: beside
/// [`pulse_dir`], never in it. bubbler moves it here before anything
/// binds it, so what bwrap resolves is a name the server cannot swap.
pub fn pulse_socket(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join(PULSE_ADOPTED)
}

/// `<pulse dir>/cfg`: the configuration bubbler writes for that server —
/// the host's effective [`PULSE_CONF`] copied, and [`PULSE_OVERRIDE`]
/// beside it.
pub fn pulse_config_dir(instance_runtime: &Path) -> PathBuf {
    pulse_dir(instance_runtime).join("cfg")
}

/// The three directories a `pipewire-pulse.conf` is looked for in, in
/// the order PipeWire itself reads them: the user's own, the system's,
/// then the one the package ships ("An equally named file in a directory
/// with a higher precedence makes the analogous files ignored", Arch
/// wiki, PipeWire#Configuration).
pub fn pulse_conf_dirs(config_home: &Path) -> [PathBuf; 3] {
    [
        config_home.join("pipewire"),
        PathBuf::from("/etc/pipewire"),
        PathBuf::from("/usr/share/pipewire"),
    ]
}

/// The `pipewire-pulse.conf` this host would start a pulse server with,
/// which is the one bubbler copies; `None` where no directory holds one.
pub fn pulse_conf(host: &dyn Host, config_home: &Path) -> Option<PathBuf> {
    pulse_conf_dirs(config_home).into_iter().find_map(|dir| {
        let path = dir.join(PULSE_CONF);
        host.file_type(&path)
            .is_some_and(|t| t.is_file())
            .then_some(path)
    })
}

/// The command the pulse sidecar runs. The config is named by file name
/// and not by path: `PIPEWIRE_CONFIG_DIR` is what says which directory
/// it is read from.
pub fn pulse_command() -> Vec<OsString> {
    [PIPEWIRE, "-c", PULSE_CONF]
        .into_iter()
        .map(OsString::from)
        .collect()
}

/// The grant set as the policy drop-in matches it.
pub fn grant(audio: AudioSet) -> &'static str {
    match audio.microphone {
        true => "playback,microphone",
        false => "playback",
    }
}

/// The context properties, as one JSON object for `pw-container -P`.
///
/// Every value is written through [`json::string`]: `instance` is a name
/// the user chose, and although the parser allows nothing in it that
/// would end a JSON string, this is the encoder and not the place to
/// depend on that. The whole value is one argv element handed to bwrap,
/// which no shell sees — only the program word is.
pub fn properties(instance: &str, run_id: &str, audio: AudioSet) -> String {
    let pairs = [
        ("pipewire.sec.engine", ENGINE),
        ("pipewire.sec.app-id", instance),
        ("pipewire.sec.instance-id", run_id),
        ("pipewire.access", ACCESS),
        ("bubbler.audio", grant(audio)),
    ];
    let body: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{}:{}", json::string(key), json::string(value)))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// The `pw-container` command line the sidecar runs.
///
/// `--` before the program is not decoration: without it `pw-container`
/// reads the program's own leading `-` words as its options.
pub fn command(properties: &str) -> Vec<OsString> {
    [PW_CONTAINER, "-P", properties, "--", HOLDER_INSIDE]
        .into_iter()
        .map(OsString::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::{FakeHost, types};

    fn set(microphone: bool) -> AudioSet {
        AudioSet { microphone }
    }

    #[test]
    fn the_context_properties_are_the_five_keys_in_order() {
        assert_eq!(
            properties("vesktop", "4711", set(false)),
            r#"{"pipewire.sec.engine":"org.bubbler","pipewire.sec.app-id":"vesktop","pipewire.sec.instance-id":"4711","pipewire.access":"restricted","bubbler.audio":"playback"}"#
        );
        assert_eq!(
            properties("vesktop", "4711", set(true)),
            r#"{"pipewire.sec.engine":"org.bubbler","pipewire.sec.app-id":"vesktop","pipewire.sec.instance-id":"4711","pipewire.access":"restricted","bubbler.audio":"playback,microphone"}"#
        );
    }

    /// The parser cannot produce such a name today; the encoder still
    /// has to be one, or the day it can is the day a name closes the
    /// object and adds properties of its own.
    #[test]
    fn a_quote_in_the_name_cannot_end_the_json_string() {
        let p = properties("a\"b", "1", set(false));
        assert!(p.contains(r#""pipewire.sec.app-id":"a\"b""#), "{p}");
    }

    #[test]
    fn the_program_word_is_one_word_a_shell_leaves_alone() {
        // `pw-container` passes it to `system()`, so a space or a
        // metacharacter here would be a second command, not a path.
        assert!(
            HOLDER_INSIDE
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
            "{HOLDER_INSIDE}"
        );
    }

    #[test]
    fn the_command_names_the_properties_and_the_holder_behind_a_double_dash() {
        let props = properties("t", "1", set(false));
        assert_eq!(
            command(&props),
            [
                "/usr/bin/pw-container",
                "-P",
                props.as_str(),
                "--",
                "/run/bubbler-pw-hold"
            ]
        );
    }

    #[test]
    fn the_socket_is_named_beside_the_directory_the_sidecar_writes() {
        let instance = Path::new("/run/user/1000/bubbler/t");
        assert_eq!(
            socket(instance),
            Path::new("/run/user/1000/bubbler/t/pipewire-0")
        );
        assert_eq!(dir(instance), Path::new("/run/user/1000/bubbler/t/pw"));
        assert!(
            !socket(instance).starts_with(dir(instance)),
            "the socket bwrap binds is out of the sidecar's reach"
        );
        assert_eq!(
            socket(instance).file_name(),
            Path::new(SOCKET_INSIDE).file_name(),
            "the holder names it, and the move keeps that name"
        );
    }

    #[test]
    fn the_effective_pulse_config_is_the_users_before_etc_before_the_shipped_one() {
        let (file, _, _) = types();
        let config_home = Path::new("/home/user/.config");
        let dirs = pulse_conf_dirs(config_home);
        assert_eq!(
            dirs,
            [
                PathBuf::from("/home/user/.config/pipewire"),
                PathBuf::from("/etc/pipewire"),
                PathBuf::from("/usr/share/pipewire"),
            ]
        );
        for (i, dir) in dirs.iter().enumerate() {
            // Every directory below this one holds the file too, so what
            // is measured is the precedence and not which one exists.
            let mut host = FakeHost::default();
            for lower in &dirs[i..] {
                host = host.with(lower.join(PULSE_CONF).to_str().unwrap(), file);
            }
            assert_eq!(
                pulse_conf(&host, config_home),
                Some(dir.join(PULSE_CONF)),
                "{}",
                dir.display()
            );
        }
        assert_eq!(pulse_conf(&FakeHost::default(), config_home), None);
    }

    #[test]
    fn the_bubbler_fragment_names_the_private_socket_and_refuses_module_loading() {
        assert!(
            PULSE_OVERRIDE.contains(&format!(
                r#"server.address = [ "unix:{PULSE_SOCKET_INSIDE}" ]"#
            )),
            "{PULSE_OVERRIDE}"
        );
        assert!(
            PULSE_OVERRIDE.contains("pulse.allow-module-loading = false"),
            "{PULSE_OVERRIDE}"
        );
    }

    #[test]
    fn the_pulse_socket_is_named_beside_the_directory_the_sidecar_writes() {
        let instance = Path::new("/run/user/1000/bubbler/t");
        assert_eq!(
            pulse_socket(instance),
            Path::new("/run/user/1000/bubbler/t/pulse-native")
        );
        assert!(
            !pulse_socket(instance).starts_with(pulse_dir(instance)),
            "the socket bwrap binds is out of the server's reach"
        );
        assert_eq!(
            pulse_socket_dir(instance).join(PULSE_NATIVE),
            Path::new("/run/user/1000/bubbler/t/pwpulse/pulse/native")
        );
        // The directory is the sidecar's whole `/tmp`, so the host paths
        // and the ones its configuration names are the same places.
        assert_eq!(
            pulse_socket_dir(instance)
                .join(PULSE_NATIVE)
                .strip_prefix(pulse_dir(instance)),
            Path::new(PULSE_SOCKET_INSIDE).strip_prefix("/tmp")
        );
        assert_eq!(
            pulse_config_dir(instance).strip_prefix(pulse_dir(instance)),
            Path::new(PULSE_CONFIG_INSIDE).strip_prefix("/tmp")
        );
        // Neither audio sidecar can write what the other reads.
        assert!(
            !pulse_dir(instance).starts_with(dir(instance))
                && !dir(instance).starts_with(pulse_dir(instance)),
            "the two sidecars share a directory"
        );
    }

    #[test]
    fn the_pulse_command_starts_the_daemon_on_the_copied_config() {
        assert_eq!(
            pulse_command(),
            ["/usr/bin/pipewire", "-c", "pipewire-pulse.conf"]
        );
    }
}
