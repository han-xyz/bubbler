//! The sandbox's stdio decision: what each of fds 0, 1 and 2 is
//! connected to, and whether that needs a pty.

use std::os::fd::OwnedFd;

pub use crate::config::tty::TtyMode;

/// What one of the sandbox's fds 0, 1 and 2 is connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioTarget {
    /// The slave of the pty allocated for this launch.
    Slave,
    /// bubbler's own fd, passed through unchanged.
    Inherit,
    /// `/dev/null`.
    Null,
    /// A pipe bubbler copies to its own output.
    Pipe,
}

/// One pseudoterminal: bubbler keeps the master, the sandbox gets the slave.
#[derive(Debug)]
pub struct Pty {
    /// bubbler's end, which the relay reads and writes.
    pub master: OwnedFd,
    /// The sandbox's end, handed to bwrap or to the supervisor.
    pub slave: OwnedFd,
}

/// Where each of the sandbox's stdio fds goes, and the pty they need.
/// `pty` is filled in by the caller with `tty_relay::allocate` when
/// [`StdioPlan::needs_pty`] says one is required.
#[derive(Debug)]
pub struct StdioPlan {
    /// Target for fds 0, 1 and 2, in that order.
    pub fds: [StdioTarget; 3],
    /// The pty the [`StdioTarget::Slave`] entries name.
    pub pty: Option<Pty>,
}

impl StdioPlan {
    /// Whether this plan needs a pty allocated for it.
    pub fn needs_pty(&self) -> bool {
        self.fds.contains(&StdioTarget::Slave)
    }

    /// Whether the user's terminal must go to raw mode: only when the
    /// sandbox reads its input through the pty, so its line discipline is
    /// the one interpreting Ctrl-C and the erase key.
    pub fn raw_mode(&self) -> bool {
        self.ctty()
    }

    /// Whether the sandbox may take its fd 0 as a controlling terminal:
    /// only when that fd is the slave of a pty bubbler allocated, never a
    /// terminal it merely inherited from the user.
    pub fn ctty(&self) -> bool {
        self.fds[0] == StdioTarget::Slave
    }
}

/// What to call each of bubbler's own stdio fds in a message: the relay
/// carries the output on dups of them, whose numbers name nothing the
/// user has heard of.
pub const FD_NAMES: [&str; 3] = ["stdin", "stdout", "stderr"];

/// Decide each of fds 0, 1 and 2 on its own from `mode` and which of
/// bubbler's fds are terminals. Pure: it opens nothing.
pub fn plan(mode: TtyMode, is_tty: [bool; 3]) -> StdioPlan {
    let fds = match mode {
        TtyMode::Pty => is_tty.map(|t| {
            if t {
                StdioTarget::Slave
            } else {
                StdioTarget::Inherit
            }
        }),
        TtyMode::Passthrough => [StdioTarget::Inherit; 3],
        TtyMode::None => [StdioTarget::Null, StdioTarget::Pipe, StdioTarget::Pipe],
    };
    StdioPlan { fds, pty: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plan_decides_each_fd_on_its_own() {
        use StdioTarget::{Inherit, Null, Pipe, Slave};
        let combos = [
            ([false, false, false], [Inherit, Inherit, Inherit]),
            ([true, false, false], [Slave, Inherit, Inherit]),
            ([false, true, false], [Inherit, Slave, Inherit]),
            ([false, false, true], [Inherit, Inherit, Slave]),
            ([true, true, false], [Slave, Slave, Inherit]),
            ([true, false, true], [Slave, Inherit, Slave]),
            ([false, true, true], [Inherit, Slave, Slave]),
            ([true, true, true], [Slave, Slave, Slave]),
        ];
        for (is_tty, want) in combos {
            let p = plan(TtyMode::Pty, is_tty);
            assert_eq!(p.fds, want, "pty mode with {is_tty:?}");
            assert_eq!(p.needs_pty(), is_tty.iter().any(|t| *t));
            assert_eq!(p.raw_mode(), is_tty[0]);
            assert!(p.pty.is_none());

            let p = plan(TtyMode::Passthrough, is_tty);
            assert_eq!(p.fds, [Inherit; 3], "passthrough with {is_tty:?}");
            assert!(!p.needs_pty() && !p.raw_mode());

            let p = plan(TtyMode::None, is_tty);
            assert_eq!(p.fds, [Null, Pipe, Pipe], "none with {is_tty:?}");
            assert!(!p.needs_pty() && !p.raw_mode());
        }
    }
}
