//! The `network` grant: which network namespace the sandbox gets, the
//! `/etc/resolv.conf` bubbler generates for it, and the one place the
//! `pasta` argv is built.
//!
//! Outbound filtering lives here too: `outbound "deny"` turns the
//! `allow-out` children into the nftables ruleset the launcher installs
//! in the sandbox's own network namespace. Rules are generated from
//! typed values and from nothing else — an address that reached `nft -f
//! -` as a string would be command injection into a process holding
//! `CAP_NET_ADMIN` over the sandbox's namespaces.

use std::ffi::{OsStr, OsString};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use crate::env::Env;
use crate::host::Host;
use crate::init_bin::{self, Found};
use crate::plan::plan_error::PlanError;

pub use crate::config::network::{
    AllowHost, AllowOut, Cgroup, Cidr, Forward, HostPattern, Mode, NetworkConfig, Outbound,
    PROXY_PORT, Proto,
};
pub use crate::names::PASTA_BIN;

/// Address the sandbox's resolver points at in an isolated namespace, and
/// the one pasta translates to the host's nameserver. Link-local, and
/// deliberately not a loopback address: pasta's `conf.c` refuses a
/// loopback `--dns-forward` outright.
pub const DNS_FORWARD: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));

// The port a resolver is queried on, which is the one port an
// `allow-host` takes away from the application: only the proxy's cgroup
// may reach it.
const DNS_PORT: u16 = 53;

// Only the host itself, never the LAN: the node says the host may reach a
// port of the sandbox, and pasta's own default of every address would say
// rather more.
const FORWARD_ADDRESS: &str = "127.0.0.1";

/// File name of the egress proxy binary.
pub const NET_PROXY_NAME: &str = "bubbler-net-proxy";

/// Where the egress proxy is installed, beside `bubbler-init` and the
/// Wayland proxy.
pub const NET_PROXY_INSTALLED: &str = "/usr/lib/bubbler/bubbler-net-proxy";

/// Host path of the egress proxy binary and where it was found:
/// [`Env::net_proxy_override`] (`$BUBBLER_NET_PROXY`), else next to the
/// running executable, else [`NET_PROXY_INSTALLED`].
///
/// The [`Found`] half is what says whether the binary has to be bound
/// into the sandbox's mount namespace, which the proxy joins before it
/// execs.
pub fn net_proxy_program(env: &Env, host: &dyn Host) -> Result<(PathBuf, Found), PlanError> {
    init_bin::locate_binary(
        env.net_proxy_override.as_deref(),
        NET_PROXY_NAME,
        NET_PROXY_INSTALLED,
        "network",
        host,
    )
}

/// Where the egress proxy is bound inside the sandbox, and the path it
/// is exec'd from once its `pre_exec` has joined the sandbox's mount
/// namespace: a host path of bubbler's own resolves to nothing in
/// there.
///
/// Bound whatever the binary is and wherever it came from, so the argv
/// the launcher builds and the one `--explain` prints name the same
/// program.
pub const NET_PROXY_INSIDE: &str = "/run/bubbler-net-proxy";

/// The egress proxy's own argv, after the program name: what it may
/// reach, which resolvers to ask, where it listens, and the descriptors
/// it answers on.
///
/// One place, so the process the launcher starts and the one `--explain`
/// describes cannot drift apart. The proxy is spawned with one argument
/// per `arg()` and never through a shell.
///
/// `log_tunnels` is [`crate::env::Env::net_proxy_log`]: without it the
/// proxy writes its refusals and its own failures and nothing about the
/// traffic it carried.
pub fn net_proxy_argv(cfg: &NetworkConfig, fds: ProxyFds<'_>, log_tunnels: bool) -> Vec<OsString> {
    let mut argv = Vec::new();
    for allowed in &cfg.allow_hosts {
        argv.push(OsString::from("--allow"));
        argv.push(OsString::from(format!(
            "{}:{}",
            allowed.pattern, allowed.port
        )));
    }
    for server in resolvers(cfg).unwrap_or_default() {
        argv.push(OsString::from("--dns"));
        argv.push(OsString::from(server.to_string()));
    }
    argv.push(OsString::from("--port"));
    argv.push(OsString::from(PROXY_PORT.to_string()));
    argv.push(OsString::from("--ready-fd"));
    argv.push(fds.ready.to_os_string());
    argv.push(OsString::from("--log-fd"));
    argv.push(fds.log.to_os_string());
    if log_tunnels {
        argv.push(OsString::from("--log-tunnels"));
    }
    argv
}

/// The descriptors the egress proxy is given, by the number it will see
/// them at.
#[derive(Debug, Clone, Copy)]
pub struct ProxyFds<'a> {
    /// Written one byte once the proxy is listening. The launcher waits
    /// on it before it lets the application go, so nothing inside can
    /// reach for the proxy before it answers.
    pub ready: &'a OsStr,
    /// Where the proxy's audit lines go, which is bubbler's own stderr
    /// and never a file: the lines are about what the sandbox tried.
    pub log: &'a OsStr,
}

/// Names of the variables [`proxy_env`] sets, in the order it returns
/// them. Every one of them is in [`crate::config::RESERVED_ENV`], so no
/// `env` node can point the sandbox at a proxy of its own.
pub const PROXY_ENV_NAMES: [&str; 7] = [
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "https_proxy",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
];

// Destinations the sandbox reaches without the proxy, which is its own
// loopback and nothing else.
const PROXY_BYPASS: &str = "localhost,127.0.0.1,::1";

/// What a sandbox with an `allow-host` gets in its environment: the
/// proxy listening on the namespace's own loopback at `port`, the
/// loopback exemptions, and the one switch Node needs before its `fetch`
/// reads any of them.
pub fn proxy_env(port: u16) -> Vec<(String, String)> {
    let url = format!("http://127.0.0.1:{port}");
    PROXY_ENV_NAMES
        .iter()
        .map(|name| {
            let value = match *name {
                "NO_PROXY" | "no_proxy" => PROXY_BYPASS.to_owned(),
                "NODE_USE_ENV_PROXY" => "1".to_owned(),
                _ => url.clone(),
            };
            ((*name).to_owned(), value)
        })
        .collect()
}
/// The `/etc/resolv.conf` the sandbox gets, or `None` where the host's
/// own file is bound instead.
///
/// Under `"host"` the host's file is right as it stands unless `dns`
/// children replace it, and under `"none"` nothing is written at all.
pub fn resolv_conf(cfg: &NetworkConfig) -> Option<Vec<u8>> {
    let mut out = String::new();
    for s in resolvers(cfg)? {
        out.push_str(&format!("nameserver {s}\n"));
    }
    Some(out.into_bytes())
}

// The one place that decides the nameservers, because the outbound
// ruleset has to accept exactly these addresses.
fn resolvers(cfg: &NetworkConfig) -> Option<Vec<IpAddr>> {
    match (cfg.mode, cfg.dns.is_empty()) {
        // Nothing to resolve with and nothing to resolve for: a `dns`
        // child under `none` names a server no sandbox can reach, which
        // is why the parser refuses one.
        (Mode::None, _) => None,
        (_, false) => Some(cfg.dns.clone()),
        (Mode::Isolated, true) => Some(vec![DNS_FORWARD]),
        (Mode::Host, true) => None,
    }
}

/// The nftables ruleset an `outbound "deny"` is, as `nft -f -` takes it,
/// or `None` where nothing is filtered.
///
/// `oifname "lo" accept` opens the sandbox's own loopback, and it is
/// safe only because [`pasta_argv`] passes `-T none -U none`: pasta's
/// outbound forwarding would put a socket of pasta's on that loopback
/// and splice it to the host, which never becomes a packet and so is
/// never seen by netfilter.
///
/// `cgroup` is the leaf the proxy sidecar puts itself in, beside the
/// sandbox's own and outside anything the application can name. Without
/// an `allow-host` the argument is unused.
///
/// `None` where an `allow-host` needs a cgroup and none was passed is a
/// programming error of the caller's. The launcher must refuse such a
/// run: a sandbox that asked for `outbound "deny"` and got no ruleset
/// would have the whole network.
pub fn ruleset(cfg: &NetworkConfig, cgroup: Option<&Cgroup>) -> Option<String> {
    if cfg.outbound != Outbound::Deny || !cfg.is_isolated() {
        return None;
    }
    let gate = match (cfg.allow_hosts.is_empty(), cgroup) {
        (true, _) => None,
        (false, Some(cg)) => Some(cg.to_string()),
        (false, None) => return None,
    };
    // Every rule the proxy has to pass carries the match, and every rule
    // it does not is written as it always was.
    let gated = |rule: String| match &gate {
        Some(m) => format!("{m} {rule}"),
        None => rule,
    };
    let mut rules = vec![
        "oifname \"lo\" accept".to_owned(),
        "ct state established,related accept".to_owned(),
    ];
    // Neighbour discovery is how an IPv6 stack finds its router and its
    // neighbours, and the sandbox sends it like any other packet: without
    // this rule the policy below stops IPv6 before any `allow-out` over
    // it could ever match, so a v6 destination would be dead however it
    // was written. Listed in nftables' own order, which is what `nft list
    // ruleset` prints back. `no-ipv6` leaves the namespace no IPv6
    // address at all, and then the rule would match nothing.
    if !cfg.no_ipv6 {
        rules.push(
            "icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, \
             nd-neighbor-advert } accept"
                .to_owned(),
        );
    }
    for ip in resolvers(cfg).unwrap_or_default() {
        let dest = Cidr {
            addr: ip,
            prefix: Cidr::bits(ip),
        };
        for proto in [Proto::Udp, Proto::Tcp] {
            rules.push(gated(format!(
                "{} daddr {dest} {} dport {DNS_PORT} accept",
                dest.family(),
                proto.keyword()
            )));
        }
    }
    for allowed in &cfg.allow_out {
        // A resolver named by address is still a resolver: under an
        // `allow-host` it belongs to the proxy like the generated rules
        // above. An `allow-out` that names no port covers 53 among every
        // other and is written as it stands — narrowing a whole address
        // because one of its ports is DNS would take away what the node
        // plainly asks for.
        let resolver = allowed.port == Some(DNS_PORT);
        for rule in allow_out_rules(allowed) {
            rules.push(match resolver {
                true => gated(rule),
                false => rule,
            });
        }
    }
    // Last of the accepts: the proxy reaches whatever the names it was
    // given resolve to, which is an address the config never wrote and
    // no rule here could name.
    if let Some(m) = &gate {
        rules.push(format!("{m} accept"));
    }
    rules.push("reject with icmpx admin-prohibited".to_owned());
    let mut out = String::from("table inet bubbler {\n\tchain out {\n");
    out.push_str("\t\ttype filter hook output priority 0; policy drop;\n");
    for rule in rules {
        out.push_str(&format!("\t\t{rule}\n"));
    }
    out.push_str("\t}\n}\n");
    Some(out)
}

// A child that names no protocol means TCP and UDP, and nothing else.
fn allow_out_rules(allowed: &AllowOut) -> Vec<String> {
    let protos: &[Proto] = match allowed.proto {
        Some(Proto::Tcp) => &[Proto::Tcp],
        Some(Proto::Udp) => &[Proto::Udp],
        None => &[Proto::Tcp, Proto::Udp],
    };
    protos
        .iter()
        .map(|proto| {
            let head = format!("{} daddr {}", allowed.dest.family(), allowed.dest);
            match allowed.port {
                Some(port) => format!("{head} {} dport {port} accept", proto.keyword()),
                None => format!("{head} meta l4proto {} accept", proto.keyword()),
            }
        })
        .collect()
}

/// The binary that installs the ruleset, as it is looked up on `PATH`.
/// Arch ships it in `nftables`, which is not part of `base`.
pub const NFT_BIN: &str = "nft";

/// Where pasta finds the sandbox. Each is a path pasta opens for itself,
/// so they are the caller's to keep valid until it has started.
#[derive(Debug, Clone, Copy)]
pub struct Attach<'a> {
    /// The sandbox's user namespace. It must be the one that *owns* the
    /// network namespace, which is not always the one
    /// `/proc/<child-pid>/ns/user` names by the time pasta looks. Handing
    /// pasta a descriptor bubbler asked of the network namespace
    /// (`NS_GET_USERNS`) closes that race.
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
/// The six `none` values are not optional and not configurable.
///
/// `-T none` and `-U none` are load bearing for [`ruleset`] as well.
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
    // A `dns` child names a server the sandbox reaches over the tap like
    // any other address, and a translation rule for an address nothing
    // points at is one more way into the host for no gain.
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

// `pasta(1)` takes one address for the whole list, and a UDP list is
// always given even when it is empty, since without it "UDP ports with
// numbers corresponding to forwarded TCP port numbers are forwarded too".
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
            ..NetworkConfig::default()
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
    /// reached over and no file worth writing. The parser refuses such a
    /// node; this holds for a config built in code as well.
    #[test]
    fn network_none_writes_no_resolver_even_with_a_dns_child() {
        let cfg = NetworkConfig {
            mode: Mode::None,
            dns: vec![IpAddr::from([1, 1, 1, 1])],
            ..NetworkConfig::default()
        };
        assert_eq!(resolv_conf(&cfg), None);
    }

    fn cidr(s: &str) -> Cidr {
        Cidr::from_str(s).expect(s)
    }

    fn denying(allow_out: Vec<AllowOut>) -> NetworkConfig {
        NetworkConfig {
            outbound: Outbound::Deny,
            allow_out,
            ..NetworkConfig::default()
        }
    }

    /// The golden ruleset. Every line of it is a policy decision: the
    /// family, the loopback opening, the resolver accepts the generator
    /// adds by itself, and the reject that turns a block into an
    /// immediate error rather than a timeout.
    #[test]
    fn the_ruleset_is_the_golden_text_nft_is_fed() {
        let cfg = denying(vec![
            AllowOut {
                dest: cidr("1.1.1.1"),
                port: Some(443),
                proto: Some(Proto::Tcp),
            },
            AllowOut {
                dest: cidr("140.82.112.0/20"),
                port: None,
                proto: None,
            },
            AllowOut {
                dest: cidr("2606:4700:4700::1111"),
                port: Some(853),
                proto: None,
            },
            AllowOut {
                dest: cidr("192.168.0.0/16"),
                port: None,
                proto: Some(Proto::Udp),
            },
        ]);
        assert_eq!(
            ruleset(&cfg, None).unwrap(),
            "table inet bubbler {
\tchain out {
\t\ttype filter hook output priority 0; policy drop;
\t\toifname \"lo\" accept
\t\tct state established,related accept
\t\ticmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
\t\tip daddr 169.254.1.1 udp dport 53 accept
\t\tip daddr 169.254.1.1 tcp dport 53 accept
\t\tip daddr 1.1.1.1 tcp dport 443 accept
\t\tip daddr 140.82.112.0/20 meta l4proto tcp accept
\t\tip daddr 140.82.112.0/20 meta l4proto udp accept
\t\tip6 daddr 2606:4700:4700::1111 tcp dport 853 accept
\t\tip6 daddr 2606:4700:4700::1111 udp dport 853 accept
\t\tip daddr 192.168.0.0/16 meta l4proto udp accept
\t\treject with icmpx admin-prohibited
\t}
}
"
        );
    }

    /// Without neighbour discovery an IPv6 stack never finds its router,
    /// so every v6 `allow-out` under it would be a rule nothing could
    /// reach. `no-ipv6` takes the address away instead, and then the rule
    /// has nothing to match.
    #[test]
    fn ipv6_neighbour_discovery_is_open_unless_the_node_dropped_ipv6() {
        const ND: &str = "icmpv6 type { nd-router-solicit, nd-router-advert, \
                          nd-neighbor-solicit, nd-neighbor-advert } accept";
        let cfg = denying(vec![AllowOut {
            dest: cidr("2606:4700:4700::1111"),
            port: Some(443),
            proto: Some(Proto::Tcp),
        }]);
        let rules = ruleset(&cfg, None).unwrap();
        assert!(rules.contains(ND), "{rules}");
        // Ahead of every accept the config asked for: discovery has to
        // work before an address of the config can be reached over it.
        let nd = rules.find(ND).unwrap();
        let dest = rules.find("ip6 daddr 2606:4700:4700::1111").unwrap();
        assert!(nd < dest, "{rules}");
        let no_v6 = NetworkConfig {
            no_ipv6: true,
            ..denying(Vec::new())
        };
        assert!(
            !ruleset(&no_v6, None).unwrap().contains("icmpv6"),
            "{no_v6:?}"
        );
    }

    /// The resolver the filter opens is the one the generated
    /// `/etc/resolv.conf` names, whichever of the two decided it. A
    /// ruleset that forgot it would break every lookup and look like a
    /// network outage.
    #[test]
    fn the_ruleset_opens_exactly_the_resolvers_resolv_conf_names() {
        let picked = denying(Vec::new());
        assert_eq!(resolv_conf(&picked).unwrap(), b"nameserver 169.254.1.1\n");
        let rules = ruleset(&picked, None).unwrap();
        assert!(
            rules.contains("ip daddr 169.254.1.1 udp dport 53 accept"),
            "{rules}"
        );
        assert!(
            rules.contains("ip daddr 169.254.1.1 tcp dport 53 accept"),
            "{rules}"
        );

        let named = NetworkConfig {
            dns: vec![IpAddr::from([9, 9, 9, 9]), "2620:fe::fe".parse().unwrap()],
            ..denying(Vec::new())
        };
        let rules = ruleset(&named, None).unwrap();
        assert!(!rules.contains("169.254.1.1"), "{rules}");
        for line in [
            "ip daddr 9.9.9.9 udp dport 53 accept",
            "ip daddr 9.9.9.9 tcp dport 53 accept",
            "ip6 daddr 2620:fe::fe udp dport 53 accept",
            "ip6 daddr 2620:fe::fe tcp dport 53 accept",
        ] {
            assert!(rules.contains(line), "{line} missing from {rules}");
        }
    }

    /// The loopback accept and pasta's forwarding options are one
    /// decision, measured: with `-T auto` an application reaches a host
    /// service through the namespace's own loopback, pasta splices it,
    /// and no packet ever reaches the chain. Whoever relaxes one of these
    /// flags has to come past this test.
    #[test]
    fn the_loopback_accept_is_coupled_to_pastas_forwarding_being_off() {
        let cfg = denying(vec![AllowOut {
            dest: cidr("1.1.1.1"),
            port: None,
            proto: None,
        }]);
        assert!(
            ruleset(&cfg, None)
                .unwrap()
                .contains("oifname \"lo\" accept")
        );
        let a = argv(&cfg);
        for flag in ["-T", "-U", "--map-host-loopback", "--map-guest-addr"] {
            let i = a.iter().position(|x| x == flag).expect(flag);
            assert_eq!(a[i + 1], "none", "{flag} must stay none while lo is open");
        }
    }

    /// Only the isolated mode has a namespace of bubbler's to filter, and
    /// only `outbound "deny"` filters it. The parser refuses the other
    /// combinations; this holds for a config built in code as well.
    #[test]
    fn nothing_is_installed_without_an_isolated_deny() {
        assert_eq!(ruleset(&NetworkConfig::default(), None), None);
        for mode in [Mode::Host, Mode::None] {
            let cfg = NetworkConfig {
                mode,
                ..denying(vec![AllowOut {
                    dest: cidr("1.1.1.1"),
                    port: None,
                    proto: None,
                }])
            };
            assert_eq!(ruleset(&cfg, None), None, "{mode:?}");
        }
        let allowing = NetworkConfig {
            outbound: Outbound::Allow,
            allow_out: vec![AllowOut {
                dest: cidr("1.1.1.1"),
                port: None,
                proto: None,
            }],
            ..NetworkConfig::default()
        };
        assert_eq!(ruleset(&allowing, None), None);
    }

    fn pattern(s: &str) -> HostPattern {
        HostPattern::parse(s).expect(s)
    }

    /// The proxy's cgroup is the one thing the filter accepts and the
    /// one thing that may resolve a name: an application that ignores
    /// the proxy variables fails at the lookup rather than reaching
    /// anything of its own.
    #[test]
    fn allow_host_puts_the_cgroup_accept_before_the_reject_and_gates_dns() {
        let cfg = NetworkConfig {
            allow_hosts: vec![AllowHost {
                pattern: pattern("api.example"),
                port: AllowHost::DEFAULT_PORT,
            }],
            ..denying(Vec::new())
        };
        let cg = cgroup();
        let rules = ruleset(&cfg, Some(&cg)).unwrap();
        let m = cg.to_string();
        let accept = rules.find(&format!("{m} accept")).unwrap();
        let reject = rules.find("reject with icmpx").unwrap();
        assert!(accept < reject, "{rules}");
        assert!(
            rules.contains(&format!("{m} ip daddr 169.254.1.1 udp dport 53 accept")),
            "{rules}"
        );
        // The ungated resolver rule is gone with it: a rule of its own
        // is what would let the application look a name up.
        assert!(
            !rules.contains("\n\t\tip daddr 169.254.1.1 udp dport 53 accept"),
            "{rules}"
        );
        // A cgroup the caller did not create gives no ruleset at all
        // rather than one that filters less than the config says. The
        // launcher refuses the run on it.
        assert!(ruleset(&cfg, None).is_none());
        // Without an `allow-host` the text is what it always was, and a
        // cgroup nothing needs changes nothing.
        let plain = denying(Vec::new());
        assert!(!ruleset(&plain, None).unwrap().contains("cgroupv2"));
        assert_eq!(ruleset(&plain, Some(&cg)), ruleset(&plain, None));
    }

    #[test]
    fn proxy_env_names_every_variable_once() {
        let env = proxy_env(3128);
        assert_eq!(env.len(), PROXY_ENV_NAMES.len());
        assert_eq!(
            env[0],
            ("HTTPS_PROXY".to_owned(), "http://127.0.0.1:3128".to_owned())
        );
        assert_eq!(
            env[4],
            ("NO_PROXY".to_owned(), "localhost,127.0.0.1,::1".to_owned())
        );
        assert_eq!(env[6], ("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()));
        for (i, (k, _)) in env.iter().enumerate() {
            assert_eq!(k, PROXY_ENV_NAMES[i]);
            assert!(crate::config::RESERVED_ENV.contains(&k.as_str()), "{k}");
        }
    }

    /// The cgroup a systemd user session actually delegates: the
    /// writable subtree is under `user@1000.service`, whose name holds
    /// an `@`. A validator that refused this shape would refuse every
    /// real run.
    fn cgroup() -> Cgroup {
        Cgroup::new("user.slice/user-1000.slice/user@1000.service/app.slice/bubbler-t-1")
            .expect("the delegated shape a user session has")
    }

    /// A resolver named by address is a resolver: beside an
    /// `allow-host` it belongs to the proxy, like the rules the
    /// generator writes from `dns`.
    #[test]
    fn an_allow_out_on_the_resolver_port_is_gated_with_the_rest_of_dns() {
        let dns_rule = AllowOut {
            dest: cidr("9.9.9.9"),
            port: Some(53),
            proto: Some(Proto::Udp),
        };
        let other = AllowOut {
            dest: cidr("1.1.1.1"),
            port: Some(443),
            proto: Some(Proto::Tcp),
        };
        let cfg = NetworkConfig {
            allow_hosts: vec![AllowHost {
                pattern: pattern("api.example"),
                port: AllowHost::DEFAULT_PORT,
            }],
            allow_out: vec![dns_rule, other],
            ..denying(Vec::new())
        };
        let cg = cgroup();
        let rules = ruleset(&cfg, Some(&cg)).unwrap();
        assert!(
            rules.contains(&format!("{cg} ip daddr 9.9.9.9 udp dport 53 accept")),
            "{rules}"
        );
        // Only the resolver port: the rest of an `allow-out` is what the
        // node plainly asks for and stays the application's.
        assert!(
            rules.contains("\n\t\tip daddr 1.1.1.1 tcp dport 443 accept"),
            "{rules}"
        );
        // With no `allow-host` there is no gate and nothing is prefixed.
        let plain = NetworkConfig {
            allow_hosts: Vec::new(),
            ..cfg.clone()
        };
        assert!(
            ruleset(&plain, Some(&cg))
                .unwrap()
                .contains("\n\t\tip daddr 9.9.9.9 udp dport 53 accept"),
            "{plain:?}"
        );
    }

    /// The proxy's argv is the allowlist, the fixed port and the two
    /// descriptors, in that order: a golden, because it is the contract
    /// between bubbler and the one process a name-filtered sandbox lets
    /// out.
    #[test]
    fn net_proxy_argv_is_the_allowlist_the_port_and_the_descriptors() {
        let cfg = NetworkConfig {
            outbound: Outbound::Deny,
            allow_hosts: vec![
                AllowHost {
                    pattern: HostPattern::parse("api.example.com").unwrap(),
                    port: AllowHost::DEFAULT_PORT,
                },
                AllowHost {
                    pattern: HostPattern::parse("*.cdn.example").unwrap(),
                    port: 8443,
                },
            ],
            ..NetworkConfig::default()
        };
        assert_eq!(
            strs(&net_proxy_argv(
                &cfg,
                ProxyFds {
                    ready: OsStr::new("5"),
                    log: OsStr::new("2"),
                },
                false,
            )),
            [
                "--allow",
                "api.example.com:443",
                "--allow",
                "*.cdn.example:8443",
                "--dns",
                "169.254.1.1",
                "--port",
                "3128",
                "--ready-fd",
                "5",
                "--log-fd",
                "2",
            ]
        );
        // The traffic log is the one thing about the argv a variable of
        // the caller's decides, and it is the last word of it.
        let loud = strs(&net_proxy_argv(
            &cfg,
            ProxyFds {
                ready: OsStr::new("5"),
                log: OsStr::new("2"),
            },
            true,
        ));
        assert_eq!(loud.last().map(String::as_str), Some("--log-tunnels"));
        assert_eq!(loud.len(), 13);
    }

    /// The resolvers in the argv are the ones the ruleset opens port 53
    /// to, and the proxy is given them there rather than left to read a
    /// `resolv.conf` the application can write.
    #[test]
    fn the_proxy_is_told_the_resolvers_the_ruleset_opens() {
        let cfg = NetworkConfig {
            outbound: Outbound::Deny,
            dns: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                "2606:4700:4700::1111".parse().expect("an address"),
            ],
            allow_hosts: vec![AllowHost {
                pattern: HostPattern::parse("api.example").unwrap(),
                port: AllowHost::DEFAULT_PORT,
            }],
            ..NetworkConfig::default()
        };
        let argv = strs(&net_proxy_argv(
            &cfg,
            ProxyFds {
                ready: OsStr::new("5"),
                log: OsStr::new("2"),
            },
            false,
        ));
        let named: Vec<&String> = argv
            .iter()
            .zip(argv.iter().skip(1))
            .filter(|(flag, _)| *flag == "--dns")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(named, ["9.9.9.9", "2606:4700:4700::1111"]);
        // The same addresses the ruleset accepts for the proxy's cgroup.
        let rules = ruleset(
            &cfg,
            Some(&Cgroup::new("user.slice/x/proxy").expect("a cgroup")),
        )
        .expect("a ruleset");
        for server in named {
            assert!(rules.contains(server), "{server} is not in the ruleset");
        }
    }

    /// The port in the variables is the port the proxy is told to bind,
    /// and both are the constant: an explanation that printed one and a
    /// run that used the other would be a sandbox pointed at nothing.
    #[test]
    fn the_proxy_variables_name_the_port_the_proxy_is_told_to_bind() {
        let argv = strs(&net_proxy_argv(
            &NetworkConfig::default(),
            ProxyFds {
                ready: OsStr::new("5"),
                log: OsStr::new("2"),
            },
            false,
        ));
        let i = argv.iter().position(|a| a == "--port").expect("--port");
        assert_eq!(argv[i + 1], PROXY_PORT.to_string());
        for (name, value) in proxy_env(PROXY_PORT) {
            if name.eq_ignore_ascii_case("https_proxy") {
                assert_eq!(value, format!("http://127.0.0.1:{PROXY_PORT}"));
            }
        }
    }

    /// An `Env` whose only interesting field is where the egress proxy
    /// is looked for.
    fn proxy_env_for(net_proxy_override: Option<PathBuf>) -> Env {
        Env {
            home: "/home/user".into(),
            data_home: "/home/user/.local/share".into(),
            config_home: "/home/user/.config".into(),
            config_dirs: Vec::new(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            at_spi_bus_address: None,
            dbus_log: false,
            net_proxy_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            pw_dump_override: None,
            wl_proxy_override: None,
            net_proxy_override,
        }
    }

    /// A run with an `allow-host` has no way out but this binary, so an
    /// override naming something that is not one fails the launch rather
    /// than falling back to whatever else answers to the name.
    #[test]
    fn an_override_wins_and_must_be_a_regular_file() {
        let (file, dir, _) = crate::host::fake::types();
        let host = crate::host::fake::FakeHost::default()
            .with("/build/bubbler-net-proxy", file)
            .with("/build/adir", dir);
        assert_eq!(
            net_proxy_program(
                &proxy_env_for(Some("/build/bubbler-net-proxy".into())),
                &host
            )
            .unwrap(),
            (PathBuf::from("/build/bubbler-net-proxy"), Found::Override)
        );
        assert!(matches!(
            net_proxy_program(&proxy_env_for(Some("/build/adir".into())), &host),
            Err(PlanError::WrongType {
                service: "network",
                expected: "a regular file",
                ..
            })
        ));
        assert!(matches!(
            net_proxy_program(&proxy_env_for(Some("/build/gone".into())), &host),
            Err(PlanError::MissingResource {
                service: "network",
                ..
            })
        ));
    }

    /// The packaged path is the last resort, and a missing one is a
    /// failed launch: the sandbox would be handed a proxy address
    /// nothing listens on.
    #[test]
    fn without_an_override_the_installed_path_is_the_last_resort() {
        let (file, _, _) = crate::host::fake::types();
        let host = crate::host::fake::FakeHost::default().with(NET_PROXY_INSTALLED, file);
        assert_eq!(
            net_proxy_program(&proxy_env_for(None), &host).unwrap(),
            (PathBuf::from(NET_PROXY_INSTALLED), Found::Installed)
        );
        assert!(matches!(
            net_proxy_program(&proxy_env_for(None), &crate::host::fake::FakeHost::default()),
            Err(PlanError::MissingResource { service: "network", path })
                if path == std::path::Path::new(NET_PROXY_INSTALLED)
        ));
    }

    /// A build tree runs what it just built, without being told where it
    /// is — and [`Found::Sibling`] is what says the binary has to be
    /// bound into the sandbox's mount namespace, which the installed one
    /// never needs.
    #[test]
    fn a_sibling_of_the_running_binary_is_preferred_over_the_installed_one() {
        let (file, _, _) = crate::host::fake::types();
        let sibling = std::env::current_exe()
            .expect("a test binary has a path")
            .parent()
            .expect("and a directory")
            .join(NET_PROXY_NAME);
        let host = crate::host::fake::FakeHost::default()
            .with(&sibling.to_string_lossy(), file)
            .with(NET_PROXY_INSTALLED, file);
        assert_eq!(
            net_proxy_program(&proxy_env_for(None), &host).unwrap(),
            (sibling, Found::Sibling)
        );
    }
}
