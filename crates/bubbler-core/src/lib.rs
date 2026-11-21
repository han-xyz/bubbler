//! Core of bubbler: turns an instance configuration into a bubblewrap
//! invocation. Nothing in this crate knows about the CLI.

pub mod model;
pub mod plan;
pub mod run;

pub use model::catalogue;
pub use model::checks;
pub use model::config;
pub use model::env;
pub use model::error;
pub use model::json;
pub use model::kdl_out;
pub use model::names;
pub use model::paths;
pub use model::profile;
pub use model::safe_text;
pub use plan::bwrap;
pub use plan::cgroup_text;
pub use plan::dbus;
pub use plan::explain;
pub use plan::host;
pub use plan::init_bin;
pub use plan::lint;
pub use plan::network;
pub use plan::pipewire;
pub use plan::seccomp;
pub use plan::service;
pub use plan::wayland;
pub use run::audio_policy;
pub use run::cgroup;
pub use run::dbus_wire;
pub use run::desktop;
pub use run::exec;
pub use run::forward;
pub use run::fsutil;
pub use run::instance;
pub use run::launcher;
pub use run::proc;
pub use run::run_log;
pub use run::tty;
pub use run::version;
pub use run::wrap;
