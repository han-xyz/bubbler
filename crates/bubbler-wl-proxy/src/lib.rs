//! bubbler's Wayland proxy: the generated interface tables, the wire codec
//! that turns bytes into arguments and back, the per-connection object map
//! that says which interface an id belongs to, the policy that judges each
//! message, and the relay that carries them between a sandboxed client and
//! the compositor.
//!
//! The proxy measures every message exactly — a message it cannot measure is
//! a message it cannot safely forward, and the answer to one is to close the
//! connection rather than to guess.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod objects;
pub mod policy;
pub mod relay;
pub mod tables;
pub mod wire;
