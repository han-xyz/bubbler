//! Core of bubbler: turns an instance configuration into a bubblewrap
//! invocation. Nothing in this crate knows about the CLI.

pub mod bwrap;
pub mod config;
pub mod env;
pub mod error;
pub mod instance;
pub mod profile;
pub mod service;
