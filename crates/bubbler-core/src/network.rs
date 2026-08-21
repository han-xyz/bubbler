//! The `network` grant: which network namespace the sandbox gets, the
//! `/etc/resolv.conf` bubbler generates for it, and the one place the
//! `pasta` argv is built.
//!
//! An isolated namespace is the default. The baseline already unshares
//! the network, so isolation costs nothing to arrange; what it takes is a
//! userspace connection to the outside, and that is `pasta` from the
//! `passt` package.
//!
//! pasta's own defaults are wrong for a sandbox, which is why every
//! invocation here carries the same six `none` values. `pasta(1)`: port
//! forwarding "default is none for passt and auto for pasta", and in auto
//! mode it scans `/proc/net/{tcp,tcp6,udp,udp6}` on both sides and
//! publishes what it finds — without the bound address, so a service the
//! sandbox binds to its own `127.0.0.1` is published on the host's public
//! address. `--map-host-loopback` defaults to the guest's gateway and
//! `--map-guest-addr` to the host's global address, which puts the host's
//! loopback services back inside the sandbox that unshared the network to
//! be rid of them.

use std::ffi::{OsStr, OsString};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;

use crate::env::Env;
use crate::error::ConfigError;

/// The sidecar bubbler runs for an isolated network namespace, as it is
/// looked up on `PATH`. Arch ships it in `passt`.
pub const PASTA_BIN: &str = "pasta";

/// Address the sandbox's resolver points at in an isolated namespace, and
/// the one pasta translates to the host's nameserver. Link-local, and
/// deliberately not a loopback address: pasta's `conf.c` refuses a
/// loopback `--dns-forward` outright.
pub const DNS_FORWARD: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));

/// Host address an `allow-port` forward listens on. Only the host itself,
/// never the LAN: the node says the host may reach a port of the sandbox,
/// and pasta's own default of every address would say rather more.
const FORWARD_ADDRESS: &str = "127.0.0.1";

/// Which network namespace the sandbox runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// The sandbox's own namespace, connected to the outside by a pasta
    /// sidecar: its own loopback, none of the host's listening services,
    /// none of the host's abstract unix sockets and no LAN broadcast.
    ///
    /// Not a firewall: pasta routes, so a host service bound to
    /// `0.0.0.0` on an address pasta did not copy into the namespace — a
    /// VPN endpoint, `docker0`, a second NIC — is reachable from inside
    /// exactly as it is from any other machine on that network.
    #[default]
    Isolated,
    /// The host's own namespace (`--share-net`): every service on the
    /// host's loopback, every host abstract unix socket and the host's
    /// interfaces and addresses.
    Host,
    /// No network at all, which is what the baseline already gives. The
    /// spelling exists so a profile can say so on purpose.
    None,
}

impl FromStr for Mode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "host" => Ok(Self::Host),
            "none" => Ok(Self::None),
            _ => Err(ConfigError::BadArgument {
                node: "network".to_owned(),
                reason: format!("expected `host` or `none`, got `{s}`"),
            }),
        }
    }
}

/// One inbound port forward: the host may reach this port of the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forward {
    /// Port number, the same on both sides.
    pub port: u16,
    /// UDP rather than TCP.
    pub udp: bool,
}

/// The whole `network` node: its mode and what its children asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkConfig {
    /// Which namespace the sandbox runs in.
    pub mode: Mode,
    /// Nameservers for the generated `/etc/resolv.conf`, in file order;
    /// empty means bubbler picks one.
    pub dns: Vec<IpAddr>,
    /// Inbound port forwards, in file order. Only [`Mode::Isolated`] has
    /// a namespace to forward into.
    pub forwards: Vec<Forward>,
    /// Drop IPv6 (`pasta -4`). Only [`Mode::Isolated`] has a pasta.
    pub no_ipv6: bool,
}

impl NetworkConfig {
    /// Whether this grant runs a pasta sidecar.
    pub fn is_isolated(&self) -> bool {
        self.mode == Mode::Isolated
    }
}

/// The `/etc/resolv.conf` the sandbox gets, or `None` where the host's
/// own file is bound instead.
///
/// An isolated namespace can never reach a resolver on the host's
/// loopback, which is what `/etc/resolv.conf` names on a systemd-resolved
/// host, so the file is generated rather than bound. Under `"host"` the
/// host's file is right as it stands unless `dns` children replace it,
/// and under `"none"` nothing is written at all: there is no network to
/// carry a query, whatever the node names.
pub fn resolv_conf(cfg: &NetworkConfig) -> Option<Vec<u8>> {
    let servers: Vec<IpAddr> = match (cfg.mode, cfg.dns.is_empty()) {
        // Nothing to resolve with and nothing to resolve for: a `dns`
        // child under `none` names a server no sandbox can reach.
        (Mode::None, _) => return None,
        (_, false) => cfg.dns.clone(),
        (Mode::Isolated, true) => vec![DNS_FORWARD],
        (Mode::Host, true) => return None,
    };
    let mut out = String::new();
    for s in servers {
        out.push_str(&format!("nameserver {s}\n"));
    }
    Some(out.into_bytes())
}

/// Where pasta finds the sandbox. Each is a path pasta opens for itself,
/// so they are the caller's to keep valid until it has started.
#[derive(Debug, Clone, Copy)]
pub struct Attach<'a> {
    /// The sandbox's user namespace. It must be the one that *owns* the
    /// network namespace, which is not always the one
    /// `/proc/<child-pid>/ns/user` names by the time pasta looks: bwrap
    /// moves the sandbox into a nested user namespace shortly after it
    /// reports `child-pid` (measured on bwrap 0.11.2, 6 runs of 6), and
    /// the network namespace stays owned by the outer one. Handing pasta
    /// a descriptor bubbler opened at `child-pid` time closes that race;
    /// letting pasta resolve the path itself failed 5 times in 8.
    pub userns: &'a OsStr,
    /// Where pasta writes its own pid once the namespace is configured,
    /// which is what bubbler waits for. `pasta(1)`: "Write own PID to
    /// file once initialisation is done".
    pub ready: &'a OsStr,
    /// bwrap's `child-pid`: the process whose network namespace this is.
    pub child: &'a OsStr,
}

/// The complete pasta argv after the program name.
///
/// The six `none` values are not optional and not configurable: they are
/// what makes an isolated namespace an isolation rather than a second way
/// into the host (see the module documentation). `--foreground` is load
/// bearing too — a backgrounded pasta is not bubbler's child any more and
/// could not be killed when the run ends.
pub fn pasta_argv(cfg: &NetworkConfig, at: Attach) -> Vec<OsString> {
    let o = |s: &str| OsString::from(s);
    let mut argv = vec![
        o("--config-net"),
        o("--foreground"),
        o("--quiet"),
        o("-t"),
        forwards(cfg, false),
        o("-u"),
        forwards(cfg, true),
        o("-T"),
        o("none"),
        o("-U"),
        o("none"),
        o("--map-host-loopback"),
        o("none"),
        o("--map-guest-addr"),
        o("none"),
    ];
    // Only where bubbler picked the resolver itself. A `dns` child names
    // a server the sandbox reaches over the tap like any other address,
    // and a translation rule for an address nothing points at is one more
    // way into the host for no gain.
    if cfg.dns.is_empty() {
        argv.push(o("--dns-forward"));
        argv.push(OsString::from(DNS_FORWARD.to_string()));
    }
    if cfg.no_ipv6 {
        argv.push(o("-4"));
    }
    argv.push(o("--userns"));
    argv.push(at.userns.to_os_string());
    argv.push(o("--pid"));
    argv.push(at.ready.to_os_string());
    argv.push(at.child.to_os_string());
    argv
}

/// The `-t` or `-u` value: `none`, or the forwarded ports of that
/// protocol behind the host address they listen on. `pasta(1)` takes one
/// address for the whole list, and a UDP list is always given even when
/// it is empty, since without it "UDP ports with numbers corresponding to
/// forwarded TCP port numbers are forwarded too".
fn forwards(cfg: &NetworkConfig, udp: bool) -> OsString {
    let ports: Vec<String> = cfg
        .forwards
        .iter()
        .filter(|f| f.udp == udp)
        .map(|f| f.port.to_string())
        .collect();
    match ports.is_empty() {
        true => OsString::from("none"),
        false => OsString::from(format!("{FORWARD_ADDRESS}/{}", ports.join(","))),
    }
}

/// The pasta binary to run: `$BUBBLER_PASTA` when it is set, else
/// [`PASTA_BIN`] from `PATH`.
pub fn program(env: &Env) -> PathBuf {
    env.pasta_override
        .clone()
        .unwrap_or_else(|| PathBuf::from(PASTA_BIN))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|a| a.to_string_lossy().into_owned()).collect()
    }

    fn argv(cfg: &NetworkConfig) -> Vec<String> {
        strs(&pasta_argv(
            cfg,
            Attach {
                userns: OsStr::new("/proc/9/fd/7"),
                ready: OsStr::new("/proc/9/fd/8"),
                child: OsStr::new("4321"),
            },
        ))
    }

    /// The golden argv. Every flag here is a hardening flag; a change to
    /// this list is a change to what an isolated sandbox is worth.
    #[test]
    fn pasta_argv_is_the_hardened_invocation() {
        assert_eq!(
            argv(&NetworkConfig::default()),
            [
                "--config-net",
                "--foreground",
                "--quiet",
                "-t",
                "none",
                "-u",
                "none",
                "-T",
                "none",
                "-U",
                "none",
                "--map-host-loopback",
                "none",
                "--map-guest-addr",
                "none",
                "--dns-forward",
                "169.254.1.1",
                "--userns",
                "/proc/9/fd/7",
                "--pid",
                "/proc/9/fd/8",
                "4321",
            ]
        );
    }

    /// Named one by one rather than only in the golden above: pasta's
    /// defaults for these are `auto`, the gateway address and the host's
    /// global address, and any of them going missing re-opens the host.
    #[test]
    fn every_hardening_flag_is_present_whatever_the_node_asked_for() {
        let cfg = NetworkConfig {
            mode: Mode::Isolated,
            dns: vec![IpAddr::from([1, 1, 1, 1])],
            forwards: vec![
                Forward {
                    port: 8080,
                    udp: false,
                },
                Forward {
                    port: 5353,
                    udp: true,
                },
            ],
            no_ipv6: true,
        };
        let a = argv(&cfg);
        // The node named its own resolver, so pasta translates nothing.
        assert!(!a.contains(&"--dns-forward".to_owned()), "{a:?}");
        let pair = |flag: &str| {
            let i = a.iter().position(|x| x == flag).expect(flag);
            a[i + 1].clone()
        };
        assert_eq!(pair("-T"), "none");
        assert_eq!(pair("-U"), "none");
        assert_eq!(pair("--map-host-loopback"), "none");
        assert_eq!(pair("--map-guest-addr"), "none");
        // The two the node does control still name the host address they
        // listen on, and only the ports it asked for.
        assert_eq!(pair("-t"), "127.0.0.1/8080");
        assert_eq!(pair("-u"), "127.0.0.1/5353");
        assert!(a.contains(&"-4".to_owned()), "{a:?}");
        for flag in [
            "-t",
            "-u",
            "-T",
            "-U",
            "--map-host-loopback",
            "--map-guest-addr",
        ] {
            assert_eq!(a.iter().filter(|x| *x == flag).count(), 1, "{flag}");
        }
    }

    #[test]
    fn forwards_of_one_protocol_share_one_address_prefix() {
        let cfg = NetworkConfig {
            forwards: vec![
                Forward {
                    port: 80,
                    udp: false,
                },
                Forward {
                    port: 443,
                    udp: false,
                },
            ],
            ..NetworkConfig::default()
        };
        let a = argv(&cfg);
        let i = a.iter().position(|x| x == "-t").unwrap();
        assert_eq!(a[i + 1], "127.0.0.1/80,443");
        // UDP is given explicitly even with no UDP forward: without it
        // pasta forwards the UDP ports matching the TCP ones.
        let i = a.iter().position(|x| x == "-u").unwrap();
        assert_eq!(a[i + 1], "none");
    }

    /// The generated resolver and the translation rule that makes it
    /// work are one decision: neither appears without the other.
    #[test]
    fn the_forward_address_is_dropped_when_the_node_names_a_resolver() {
        let named = NetworkConfig {
            dns: vec![IpAddr::from([1, 1, 1, 1])],
            ..NetworkConfig::default()
        };
        assert!(!argv(&named).contains(&"--dns-forward".to_owned()));
        assert_eq!(resolv_conf(&named).unwrap(), b"nameserver 1.1.1.1\n");
        let picked = NetworkConfig::default();
        assert!(argv(&picked).contains(&"--dns-forward".to_owned()));
        assert_eq!(resolv_conf(&picked).unwrap(), b"nameserver 169.254.1.1\n");
    }

    #[test]
    fn ipv4_only_is_written_only_when_asked_for() {
        assert!(!argv(&NetworkConfig::default()).contains(&"-4".to_owned()));
    }

    #[test]
    fn resolv_conf_points_at_the_forward_address_by_default() {
        let cfg = NetworkConfig::default();
        assert_eq!(resolv_conf(&cfg).unwrap(), b"nameserver 169.254.1.1\n");
    }

    #[test]
    fn resolv_conf_lists_every_dns_child_in_order() {
        let cfg = NetworkConfig {
            mode: Mode::Host,
            dns: vec![IpAddr::from([1, 1, 1, 1]), IpAddr::from([9, 9, 9, 9])],
            ..NetworkConfig::default()
        };
        assert_eq!(
            resolv_conf(&cfg).unwrap(),
            b"nameserver 1.1.1.1\nnameserver 9.9.9.9\n"
        );
    }

    #[test]
    fn only_isolation_generates_a_resolver_of_its_own() {
        for mode in [Mode::Host, Mode::None] {
            let cfg = NetworkConfig {
                mode,
                ..NetworkConfig::default()
            };
            assert_eq!(resolv_conf(&cfg), None, "{mode:?}");
        }
    }

    /// `none` is no network, so there is nothing a nameserver could be
    /// reached over and no file worth writing.
    #[test]
    fn network_none_writes_no_resolver_even_with_a_dns_child() {
        let cfg = NetworkConfig {
            mode: Mode::None,
            dns: vec![IpAddr::from([1, 1, 1, 1])],
            ..NetworkConfig::default()
        };
        assert_eq!(resolv_conf(&cfg), None);
    }

    #[test]
    fn mode_names_are_the_two_written_ones() {
        assert_eq!(Mode::from_str("host").unwrap(), Mode::Host);
        assert_eq!(Mode::from_str("none").unwrap(), Mode::None);
        for bad in ["isolated", "", "HOST", "pasta"] {
            assert!(Mode::from_str(bad).is_err(), "{bad}");
        }
    }
}
