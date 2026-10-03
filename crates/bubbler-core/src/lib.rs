//! Core of bubbler: turns an instance configuration into a bubblewrap
//! invocation. Nothing in this crate knows about the CLI.

pub mod audio_policy;
pub mod bwrap;
pub mod catalogue;
pub mod cgroup;
pub mod config;
pub mod dbus;
pub mod dbus_wire;
pub mod desktop;
pub mod env;
pub mod error;
pub mod exec;
pub mod explain;
pub mod forward;
pub mod fsutil;
pub mod host;
pub mod init_bin;
pub mod instance;
pub mod json;
pub mod kdl_out;
pub mod launcher;
pub mod lint;
pub mod network;
pub mod pipewire;
pub mod profile;
pub mod run_log;
pub mod safe_text;
pub mod seccomp;
pub mod service;
pub mod tty;
pub mod version;
pub mod wayland;
pub mod wrap;

/// Whether `BUBBLER_TEST_SESSION=1` asks for the tests that reach the
/// developer's session or start audio daemons. For bubbler's own tests;
/// any other value, unset included, leaves them skipped.
#[doc(hidden)]
pub fn session_tests_wanted() -> bool {
    std::env::var_os("BUBBLER_TEST_SESSION").is_some_and(|value| value == "1")
}
