//! The `tty` node's value: how the sandbox's stdio meets the user's
//! terminal.

use std::str::FromStr;

use crate::error::ConfigError;

/// How the sandbox's stdio is connected to the user's terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TtyMode {
    /// Every fd that is a terminal gets the slave of a pty bubbler owns;
    /// the sandbox never holds a descriptor for the user's terminal.
    #[default]
    Pty,
    /// bubbler's own fds are handed over: the sandbox can read the user's
    /// keystrokes and write escape sequences to their terminal.
    Passthrough,
    /// No terminal at all: stdin is `/dev/null`, output comes back
    /// through pipes, and bwrap binds nothing at `/dev/console`.
    None,
}

impl FromStr for TtyMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pty" => Ok(Self::Pty),
            "passthrough" => Ok(Self::Passthrough),
            "none" => Ok(Self::None),
            _ => Err(ConfigError::BadArgument {
                node: "tty".to_owned(),
                reason: format!("expected `pty`, `passthrough` or `none`, got `{s}`"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse_by_name_only() {
        assert_eq!(TtyMode::from_str("pty").unwrap(), TtyMode::Pty);
        assert_eq!(
            TtyMode::from_str("passthrough").unwrap(),
            TtyMode::Passthrough
        );
        assert_eq!(TtyMode::from_str("none").unwrap(), TtyMode::None);
        assert_eq!(TtyMode::default(), TtyMode::Pty);
        assert!(matches!(
            TtyMode::from_str("PTY"),
            Err(ConfigError::BadArgument { .. })
        ));
    }
}
