//! Core of bubbler: turns an instance configuration into a bubblewrap
//! invocation. Nothing in this crate knows about the CLI.

/// Every error type at the path it had before the layers split.
pub mod error {
    pub use bubbler_model::error::*;
    pub use bubbler_plan::plan_error::PlanError;
    pub use bubbler_run::launch_error::*;
}

pub use bubbler_model::catalogue;
pub use bubbler_model::checks;
pub use bubbler_model::config;
pub use bubbler_model::env;
pub use bubbler_model::instance;
pub use bubbler_model::json;
pub use bubbler_model::kdl_out;
pub use bubbler_model::names;
pub use bubbler_model::paths;
pub use bubbler_model::profile;
pub use bubbler_model::safe_text;
pub use bubbler_model::wrap;
pub use bubbler_plan::audio_policy;
pub use bubbler_plan::bwrap;
pub use bubbler_plan::cgroup_text;
pub use bubbler_plan::dbus;
pub use bubbler_plan::dbus_wire;
pub use bubbler_plan::desktop;
pub use bubbler_plan::explain;
pub use bubbler_plan::forward;
pub use bubbler_plan::host;
pub use bubbler_plan::init_bin;
pub use bubbler_plan::lint;
pub use bubbler_plan::network;
pub use bubbler_plan::pipewire;
pub use bubbler_plan::seccomp;
pub use bubbler_plan::service;
pub use bubbler_plan::sidecar_argv;
pub use bubbler_plan::tty;
pub use bubbler_plan::version;
pub use bubbler_plan::wayland;
pub use bubbler_run::audio_policy_ask;
pub use bubbler_run::cgroup;
pub use bubbler_run::dbus_a11y;
pub use bubbler_run::dbus_session;
pub use bubbler_run::desktop_ops;
pub use bubbler_run::exec;
pub use bubbler_run::forward_register;
pub use bubbler_run::fsutil;
pub use bubbler_run::instance_ops;
pub use bubbler_run::launcher;
pub use bubbler_run::proc;
pub use bubbler_run::profile_ops;
pub use bubbler_run::run_log;
pub use bubbler_run::tty_relay;
pub use bubbler_run::version_probe;
pub use bubbler_run::wayland_context;
pub use bubbler_run::wrap_ops;
