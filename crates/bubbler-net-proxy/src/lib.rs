//! bubbler's egress proxy: the `CONNECT` request parser, the list of
//! names a run may reach, and the byte relay behind them.
//!
//! The sandbox this serves has no route of its own — the ruleset in its
//! network namespace accepts one cgroup, and this process is what
//! bubbler puts in it. So the proxy is the whole of the sandbox's way
//! out, and every byte it forwards is a byte a name in the config
//! allowed.
//!
//! Nothing here reads a config file or an environment variable: the
//! allowlist arrives as argv, already validated by the config that
//! wrote it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod allow;
pub mod connect;
pub mod relay;
