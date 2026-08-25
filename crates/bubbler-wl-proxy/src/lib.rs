//! The parsing half of bubbler's Wayland proxy: the generated interface
//! tables, the wire codec that turns bytes into arguments and back, and the
//! per-connection object map that says which interface an id belongs to.
//!
//! Nothing here talks to a socket or decides policy. It exists so that the
//! relay can measure every message exactly — a message the proxy cannot
//! measure is a message it cannot safely forward.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod objects;
pub mod tables;
pub mod wire;
