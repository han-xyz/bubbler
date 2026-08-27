//! Core of bubbler: turns an instance configuration into a bubblewrap
//! invocation. Nothing in this crate knows about the CLI.

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
pub mod kdl_out;
pub mod launcher;
pub mod lint;
pub mod network;
pub mod profile;
pub mod run_log;
pub mod safe_text;
pub mod seccomp;
pub mod service;
pub mod tty;
pub mod wayland;
pub mod wrap;
