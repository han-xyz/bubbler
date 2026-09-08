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

/// Host path of the context socket, once the holder has renamed it.
pub fn socket(instance_runtime: &Path) -> PathBuf {
    dir(instance_runtime).join(SOCKET_NAME)
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
    fn the_socket_is_named_under_the_instances_own_runtime_directory() {
        let dir = Path::new("/run/user/1000/bubbler/t");
        assert_eq!(
            socket(dir),
            Path::new("/run/user/1000/bubbler/t/pw/pipewire-0")
        );
        assert_eq!(
            socket(dir).file_name(),
            Path::new(SOCKET_INSIDE).file_name(),
            "the holder renames to one name, seen from two mount namespaces"
        );
    }
}
