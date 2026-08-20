//! Core of bubbler: turns an instance configuration into a bubblewrap
//! invocation. Nothing in this crate knows about the CLI.

pub mod bwrap;
pub mod config;
pub mod dbus;
pub mod env;
pub mod error;
pub mod exec;
pub mod host;
pub mod init_bin;
pub mod instance;
pub mod launcher;
pub mod profile;
pub mod service;
