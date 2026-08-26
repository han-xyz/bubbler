//! Wire protocol and socket I/O of the bubbler exec channel, shared by the
//! in-sandbox supervisor and the host side that talks to it, together with
//! the descriptor hygiene both of them owe every process they start.

pub mod fds;
pub mod proto;
pub mod wire;
