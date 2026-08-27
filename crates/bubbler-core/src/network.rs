//! The `network` grant: which network namespace the sandbox gets, the
//! `/etc/resolv.conf` bubbler generates for it, and the one place the
//! `pasta` argv is built.
//!
//! An isolated namespace is the default. The baseline already unshares
//! the network, so isolation costs nothing to arrange; what it takes is a
//! userspace connection to the outside, and that is `pasta` from the
//! `passt` package.
//!
//! Outbound filtering lives here too: `outbound "deny"` turns the
//! `allow-out` children into the nftables ruleset the launcher installs
//! in the sandbox's own network namespace. Rules are generated from
//! typed values and from nothing else — an address that reached `nft -f
//! -` as a string would be command injection into a process holding
//! `CAP_NET_ADMIN` over the sandbox's namespaces.
//!
//! `allow-host` is the same filter written by name. Names are no part
//! of a packet filter, so what the ruleset does with one is accept a
//! single cgroup — the one bubbler puts its `CONNECT` proxy in — and
//! gate the resolver rules on it as well, leaving the application no
//! DNS of its own; the proxy is what compares a `CONNECT` target
//! against the [`HostPattern`]s, and [`proxy_env`] is how the sandbox
//! is told where it listens.
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
use std::fmt;
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

/// The port a resolver is queried on, which is the one port an
/// `allow-host` takes away from the application: only the proxy's
/// cgroup may reach it, whether the rule came from `dns` or was written
/// as an `allow-out`.
const DNS_PORT: u16 = 53;

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

/// Which destinations the sandbox may open a connection to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Outbound {
    /// Every destination the namespace can route to, which is what a
    /// `network` grant has always meant.
    #[default]
    Allow,
    /// Only the sandbox's own loopback, its resolver and what
    /// [`AllowOut`] names; everything else is rejected by an nftables
    /// ruleset the launcher installs in the sandbox's own network
    /// namespace, where the sandbox itself can neither read nor flush it.
    Deny,
}

impl FromStr for Outbound {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(ConfigError::BadArgument {
                node: "outbound".to_owned(),
                reason: format!("expected `allow` or `deny`, got `{s}`"),
            }),
        }
    }
}

/// A transport protocol an `allow-out` can be narrowed to. Nothing else
/// is reachable under [`Outbound::Deny`]: ICMP included, so `ping` does
/// not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Proto {
    /// The word both nftables and the config spell it with.
    pub fn keyword(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl FromStr for Proto {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(ConfigError::BadArgument {
                node: "allow-out".to_owned(),
                reason: format!("proto must be \"tcp\" or \"udp\", got `{s}`"),
            }),
        }
    }
}

/// One destination an `allow-out` names: a single address, or a network
/// with its prefix length.
///
/// The host bits of a prefix must be clear. `nft` would take
/// `1.1.1.1/24` and quietly mean `1.1.0.0/24`, which is a rule allowing
/// 256 addresses where its author wrote one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// The address, which is the network address where the prefix covers
    /// more than one.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// How many leading bits of [`Cidr::addr`] the rule matches on.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether this destination is reached over IPv6, which is the half
    /// of the stack `no-ipv6` takes away.
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// The nftables address family keyword this destination matches in:
    /// the table is `inet`, so each rule names its own.
    fn family(&self) -> &'static str {
        match self.addr {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        }
    }

    /// The widest prefix of this address family.
    fn bits(addr: IpAddr) -> u8 {
        match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// Whether every bit below the prefix is zero.
    fn is_network_address(addr: IpAddr, prefix: u8) -> bool {
        if prefix == Self::bits(addr) {
            return true;
        }
        match addr {
            IpAddr::V4(a) => u32::from(a) & (u32::MAX >> prefix) == 0,
            IpAddr::V6(a) => u128::from(a) & (u128::MAX >> prefix) == 0,
        }
    }
}

impl FromStr for Cidr {
    type Err = ConfigError;

    /// `<address>` or `<address>/<prefix-length>`, v4 or v6. The value is
    /// never echoed back: it is arbitrary text and may hold the control
    /// bytes the error message would then carry.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = |reason: &str| ConfigError::BadArgument {
            node: "allow-out".to_owned(),
            reason: reason.to_owned(),
        };
        let (addr, len) = match s.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (s, None),
        };
        let addr = IpAddr::from_str(addr).map_err(|_| {
            bad("expects an address or a prefix, such as \"1.1.1.1\" or \"140.82.112.0/20\"")
        })?;
        // An IPv4-mapped address is an IPv4 destination wearing IPv6
        // notation: the packet leaves as IPv4 and an `ip6 daddr` rule
        // never matches it, so the rule would be silently inert.
        if let IpAddr::V6(v6) = addr
            && v6.to_ipv4_mapped().is_some()
        {
            return Err(bad(
                "an IPv4-mapped address names an IPv4 destination, which an IPv6 rule \
                 never matches; write the address in its IPv4 form",
            ));
        }
        let prefix = match len {
            None => Self::bits(addr),
            Some(len) => len
                .parse::<u8>()
                .ok()
                .filter(|n| *n <= Self::bits(addr))
                .ok_or_else(|| bad("prefix length is out of range for the address family"))?,
        };
        if !Self::is_network_address(addr, prefix) {
            return Err(bad(
                "the bits below the prefix must be zero, or the rule covers a network its \
                 author did not write",
            ));
        }
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    /// The prefix length is written only where it narrows anything, so a
    /// single address renders as itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.prefix == Self::bits(self.addr) {
            true => write!(f, "{}", self.addr),
            false => write!(f, "{}/{}", self.addr, self.prefix),
        }
    }
}

/// One `allow-out` child: a destination the sandbox may reach under
/// [`Outbound::Deny`], optionally narrowed to one port and one protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowOut {
    /// The address or network.
    pub dest: Cidr,
    /// The destination port, or every port.
    pub port: Option<u16>,
    /// The protocol, or both TCP and UDP.
    pub proto: Option<Proto>,
}

impl fmt::Display for AllowOut {
    /// The child as a config writes it: the destination quoted, then only
    /// the properties that narrow it. One rendering, so the emitter and
    /// the messages that name a rule cannot describe it differently.
    ///
    /// The quotes need no escaping: a [`Cidr`] renders as an [`IpAddr`]
    /// and a prefix length, which is hex digits, dots, colons and a
    /// slash.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.dest)?;
        if let Some(port) = self.port {
            write!(f, " port={port}")?;
        }
        if let Some(proto) = self.proto {
            write!(f, " proto=\"{}\"", proto.keyword())?;
        }
        Ok(())
    }
}

/// A name an `allow-host` names: ASCII labels, lower case, with an
/// optional `*.` in front standing for exactly one label.
///
/// The rules are DNS's own (RFC 1035 §2.3.1 with RFC 1123 §2.1's leading
/// digit): letters, digits and `-`, no label starting or ending in `-`,
/// 63 characters to a label and 253 to a name. bubbler converts nothing:
/// an internationalised name is written as the `xn--` A-labels it
/// resolves as, so what the config says and what the proxy compares a
/// `CONNECT` target against are the same bytes.
///
/// A name whose last label is all digits is refused, so no address in
/// the notations a config would write one in parses as a name;
/// `allow-out` is where an address goes. `getaddrinfo` also reads hex
/// forms such as `0x7f000001`, which are letters and digits and do parse
/// here — a config writing one has named an address on purpose, and the
/// proxy refuses an address as a `CONNECT` target whatever its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// The labels under the wildcard, lower case and without the root
    /// dot: `["example", "com"]` for `example.com` and for
    /// `*.example.com` alike.
    pub labels: Vec<String>,
    /// Whether a `*.` stands in front of [`HostPattern::labels`], which
    /// matches one label and never zero or two.
    pub wildcard: bool,
}

impl HostPattern {
    /// Longest name accepted, measured over the text as written: a
    /// trailing dot counts toward it, so no name buys a label with one.
    const MAX_NAME: usize = 253;
    /// Longest single label, from DNS.
    const MAX_LABEL: usize = 63;

    /// Parse `s` as an `allow-host` name, or say what is wrong with it.
    ///
    /// The reason never echoes the value: it is arbitrary text out of a
    /// config file and may hold the control bytes the message would then
    /// carry to a terminal.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.len() > Self::MAX_NAME {
            return Err(format!(
                "a name is at most {} characters, trailing dot included",
                Self::MAX_NAME
            ));
        }
        // The root dot is what a name may end in and nothing else: two
        // of them leave an empty label, which the loop below refuses.
        let name = s.strip_suffix('.').unwrap_or(s);
        let mut labels = Vec::new();
        let mut wildcard = false;
        for (i, label) in name.split('.').enumerate() {
            if i == 0 && label == "*" {
                wildcard = true;
                continue;
            }
            Self::check_label(label)?;
            labels.push(label.to_ascii_lowercase());
        }
        if labels.is_empty() {
            return Err(
                "a wildcard stands for one label under a name, as in `*.example.com`".to_owned(),
            );
        }
        // `1.2.3.4` would otherwise parse as a name of four labels and
        // match nothing a resolver ever answers with.
        if labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(
                "a name whose last label is all digits is an address, and an address is \
                 what `allow-out` names; the proxy matches names only"
                    .to_owned(),
            );
        }
        Ok(Self { labels, wildcard })
    }

    /// Whether `s` is a label, or why it is not one. The one place the
    /// rule is written: [`HostPattern::parse`] holds a config to it and
    /// [`HostPattern::matches`] holds the probe to the same rule, so a
    /// name that could never be written cannot be matched either.
    fn check_label(s: &str) -> Result<(), String> {
        if s.is_empty() {
            return Err(
                "a name holds no empty label: no two dots in a row, and none at the start"
                    .to_owned(),
            );
        }
        if s.len() > Self::MAX_LABEL {
            return Err(format!("a label is at most {} characters", Self::MAX_LABEL));
        }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(
                "a label holds ASCII letters, digits and `-` only; write an internationalised \
                 name as the `xn--` form it resolves as, and a `*` as the whole first label"
                    .to_owned(),
            );
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err("a label neither starts nor ends with `-`".to_owned());
        }
        Ok(())
    }

    /// Whether `host` is a name this pattern covers. Case is ignored and
    /// one trailing dot with it, since a `CONNECT` target may carry
    /// either form; a wildcard covers exactly one label, never the name
    /// itself and never two labels under it.
    ///
    /// The probe is held to the rules [`HostPattern::parse`] takes, the
    /// wildcard's own label included: a `CONNECT` target is text the
    /// sandbox wrote, and one that is no name matches nothing here
    /// rather than reaching a resolver on the strength of its suffix.
    pub fn matches(&self, host: &str) -> bool {
        if host.len() > Self::MAX_NAME {
            return false;
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        let mut got: Vec<&str> = host.split('.').collect();
        if !got.iter().all(|l| Self::check_label(l).is_ok()) {
            return false;
        }
        if self.wildcard {
            // Never empty: `split` yields at least one label and every
            // one of them just passed the rule above.
            got.remove(0);
        }
        got.len() == self.labels.len()
            && got
                .iter()
                .zip(&self.labels)
                .all(|(g, l)| g.eq_ignore_ascii_case(l))
    }
}

impl fmt::Display for HostPattern {
    /// The name as a config writes it, which is its canonical form:
    /// lower case, no trailing dot.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.labels.join("."))
    }
}

/// One `allow-host` child: a name the sandbox may reach under
/// [`Outbound::Deny`], and the single port it may reach it on.
///
/// Not a rule of the ruleset: names have no place in one. It is the
/// proxy sidecar that enforces this, and the ruleset's part is to accept
/// nothing but that proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowHost {
    /// The name, or the wildcard covering one label under it.
    pub pattern: HostPattern,
    /// The port the proxy may connect to for this name.
    pub port: u16,
}

impl AllowHost {
    /// The port an `allow-host` covers where the node does not say. HTTPS
    /// is the whole of what the proxy tunnels; plain HTTP is not
    /// forwarded.
    pub const DEFAULT_PORT: u16 = 443;
}

impl fmt::Display for AllowHost {
    /// The child as a config writes it: the name quoted, and the port
    /// only where it narrows anything. One rendering, so the emitter and
    /// the message that names a duplicate cannot describe it
    /// differently.
    ///
    /// The quotes need no escaping: a [`HostPattern`] renders as letters,
    /// digits, `-`, `.` and a leading `*`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.pattern)?;
        if self.port != Self::DEFAULT_PORT {
            write!(f, " port={}", self.port)?;
        }
        Ok(())
    }
}

/// The sandbox's cgroup, as the nftables `socket cgroupv2` match names
/// it, and the one thing the ruleset accepts once an `allow-host` is in
/// play.
///
/// The match resolves the path to a cgroup id when `nft` reads the rule,
/// so the directory has to exist before the ruleset is installed and to
/// live as long as the sandbox: a cgroup created afterwards matches
/// nothing. The sandbox itself cannot join it — it has an empty
/// capability set, its own cgroup namespace and no cgroupfs to write.
///
/// The fields are private and [`Cgroup::new`] is the only way to one, so
/// the [`fmt::Display`] below cannot be reached with a path no rule
/// could carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgroup {
    path: String,
    level: u8,
}

impl Cgroup {
    /// The sandbox's cgroup from its path relative to the cgroup2 mount,
    /// or why that text is no path to write a rule from. `level` is
    /// counted from the path, so the two can never disagree.
    ///
    /// What is refused is what nft could not carry inside a quoted path,
    /// and nothing else: a `"` would end the string and `;` after it
    /// would start a second rule, in a process holding `CAP_NET_ADMIN`
    /// over the sandbox's namespaces. Everything a systemd unit name
    /// holds passes — `user@1000.service` is where a user session's
    /// delegated subtree lives, and `@`, `:` and `+` are ordinary
    /// characters in one.
    pub fn new(path: &str) -> Result<Self, String> {
        if path.is_empty() {
            return Err("a cgroup path is not empty".to_owned());
        }
        if path.starts_with('/') || path.ends_with('/') {
            return Err(
                "a cgroup path is relative to the cgroup2 mount: no leading or trailing `/`"
                    .to_owned(),
            );
        }
        if let Some(what) = path.bytes().find_map(|b| match b {
            b'"' => Some("a quote"),
            b'\\' => Some("a backslash"),
            b if b.is_ascii_whitespace() => Some("whitespace"),
            b if b.is_ascii_control() => Some("a control byte"),
            b if !b.is_ascii() => Some("a byte outside ASCII"),
            _ => None,
        }) {
            return Err(format!(
                "a cgroup path is written into a quoted nftables rule, so it holds no \
                 {what}"
            ));
        }
        let comps: Vec<&str> = path.split('/').collect();
        if comps
            .iter()
            .any(|c| c.is_empty() || *c == "." || *c == "..")
        {
            return Err(
                "every component of a cgroup path is a directory name, so none of them is \
                 empty, `.` or `..`"
                    .to_owned(),
            );
        }
        let level = u8::try_from(comps.len())
            .map_err(|_| "a cgroup path has more components than nftables counts".to_owned())?;
        Ok(Self {
            path: path.to_owned(),
            level,
        })
    }

    /// The path relative to the cgroup2 mount, as it was given.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// How many components the path has, which is the `level` nftables
    /// matches at.
    pub fn level(&self) -> u8 {
        self.level
    }
}

impl fmt::Display for Cgroup {
    /// The nftables match text this cgroup is, without a verdict: the
    /// generator writes the verdict, or another match, after it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "socket cgroupv2 level {} \"{}\"", self.level, self.path)
    }
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

/// Destinations the sandbox reaches without the proxy, which is its own
/// loopback and nothing else.
const PROXY_BYPASS: &str = "localhost,127.0.0.1,::1";

/// What a sandbox with an `allow-host` gets in its environment: the
/// proxy listening on the namespace's own loopback at `port`, the
/// loopback exemptions, and the one switch Node needs before its `fetch`
/// reads any of them.
///
/// Both cases of each name, since which one a client reads is the
/// client's business: curl takes `http_proxy` in lower case only, and
/// other clients try the upper-case spellings first. An application that
/// reads none of them has its packets rejected — the variables are how a
/// sandbox is told where its one opening is, not what enforces it.
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
    /// Whether outbound traffic is filtered at all. Only
    /// [`Mode::Isolated`] has a namespace of bubbler's to filter.
    pub outbound: Outbound,
    /// Destinations reachable under [`Outbound::Deny`], in file order.
    pub allow_out: Vec<AllowOut>,
    /// Names reachable under [`Outbound::Deny`] through the proxy
    /// sidecar, in file order. A non-empty list is what puts a proxy in
    /// the sandbox and turns the ruleset into one that accepts only it.
    pub allow_hosts: Vec<AllowHost>,
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
/// carry a query. The parser refuses a `dns` child there, so that last
/// case is this function standing on its own rather than a config.
pub fn resolv_conf(cfg: &NetworkConfig) -> Option<Vec<u8>> {
    let mut out = String::new();
    for s in resolvers(cfg)? {
        out.push_str(&format!("nameserver {s}\n"));
    }
    Some(out.into_bytes())
}

/// The nameservers this sandbox queries, or `None` where the host's own
/// `/etc/resolv.conf` is bound instead. The one place that decides them,
/// because the outbound ruleset has to accept exactly these addresses:
/// a resolver the filter did not open makes every lookup fail and every
/// failure look like a network outage.
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
/// Built from typed values only: every address is an [`IpAddr`] and
/// every port a `u16` before it is rendered here, since this text is fed
/// to a process holding `CAP_NET_ADMIN` over the sandbox's namespaces.
///
/// The chain is `inet` so that IPv6 falls under the same policy — an
/// `ip` table would leave it wide open and read identically in `nft list
/// ruleset` to anyone not looking at the family. `policy drop` is the
/// backstop under the trailing `reject`, since an nftables base chain
/// takes only `accept` or `drop` as its policy; what a blocked
/// application actually sees is the reject, measured on this host as
/// `EHOSTUNREACH` for IPv4 and `EACCES` for IPv6 immediately, and
/// `EPERM` out of `sendto` for UDP, rather than the connect timeout a
/// silent drop would give it.
///
/// `oifname "lo" accept` opens the sandbox's own loopback, and it is
/// safe only because [`pasta_argv`] passes `-T none -U none`: pasta's
/// outbound forwarding would put a socket of pasta's on that loopback
/// and splice it to the host, which never becomes a packet and so is
/// never seen by netfilter.
///
/// `cgroup` is the sandbox's own cgroup, which the proxy sidecar puts
/// itself in. With an `allow-host` the ruleset is written around it:
/// the proxy's traffic is accepted whole, since the proxy is what
/// judges a name, and the resolver rules carry the same match, so the
/// application resolves nothing at all. Without an `allow-host` the
/// argument is unused and the text is byte for byte what it always was.
///
/// An `allow-out` on port 53 carries the match as well: a resolver named
/// by address is a resolver, and the gate would be worth little with one
/// beside it. An `allow-out` that names no port covers 53 among every
/// other and is written as it stands — narrowing a whole address because
/// one of its ports is DNS would take away what the node plainly asks
/// for.
///
/// `None` where an `allow-host` needs a cgroup and none was passed is a
/// programming error of the caller's, and the answer is no ruleset
/// rather than one that filters less than the config says. The launcher
/// must refuse such a run: a sandbox that asked for `outbound "deny"`
/// and got no ruleset would have the whole network.
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
        // above, or the application would have the lookup channel the
        // gate is there to close.
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

/// The one or two rules one `allow-out` becomes: a child that names no
/// protocol means TCP and UDP, and nothing else.
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
///
/// `-T none` and `-U none` are load bearing for [`ruleset`] as well.
/// pasta forwards a local connection by creating a socket in the other
/// namespace and `splice(2)`ing between the two (`pasta(1)`, handling of
/// local traffic), so such traffic is never a packet and netfilter never
/// sees it: with outbound forwarding on, an application could reach a
/// host service through the namespace's own loopback, which the ruleset
/// has to accept for the sandbox's own sake. Measured: with pasta's
/// defaults a host service on `127.0.0.1` answers inside the sandbox
/// while the same ruleset is installed. `allow-port` (`-t`/`-u`) does
/// not reopen it — pasta binds those on the *host* and connects into the
/// namespace, which is a direction an application cannot ride outwards.
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

    /// One rendering for the emitter and for every message that names a
    /// rule, so the two cannot describe the same child differently.
    #[test]
    fn a_destination_writes_itself_the_way_a_config_does() {
        let one = |port, proto| {
            AllowOut {
                dest: cidr("1.1.1.1"),
                port,
                proto,
            }
            .to_string()
        };
        assert_eq!(one(None, None), "\"1.1.1.1\"");
        assert_eq!(one(Some(443), None), "\"1.1.1.1\" port=443");
        assert_eq!(one(None, Some(Proto::Udp)), "\"1.1.1.1\" proto=\"udp\"");
        assert_eq!(
            one(Some(443), Some(Proto::Tcp)),
            "\"1.1.1.1\" port=443 proto=\"tcp\""
        );
        assert_eq!(
            AllowOut {
                dest: cidr("2606:4700::/32"),
                port: None,
                proto: None,
            }
            .to_string(),
            "\"2606:4700::/32\""
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

    #[test]
    fn a_destination_is_an_address_or_a_network_written_canonically() {
        assert_eq!(cidr("1.1.1.1").to_string(), "1.1.1.1");
        assert_eq!(cidr("1.1.1.1/32").to_string(), "1.1.1.1");
        assert_eq!(cidr("140.82.112.0/20").to_string(), "140.82.112.0/20");
        assert_eq!(cidr("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert_eq!(
            cidr("2606:4700:4700::1111").to_string(),
            "2606:4700:4700::1111"
        );
        assert_eq!(cidr("2606:4700::/32").to_string(), "2606:4700::/32");
        assert_eq!(cidr("::/0").to_string(), "::/0");
        assert_eq!(cidr("1.1.1.1").addr(), IpAddr::from([1, 1, 1, 1]));
        assert_eq!(cidr("140.82.112.0/20").prefix(), 20);
    }

    /// A prefix with host bits set is refused rather than silently
    /// widened: `nft` reads `1.1.1.1/24` as `1.1.0.0/24`, which allows
    /// 256 addresses where its author wrote one.
    #[test]
    fn a_destination_with_bits_below_its_prefix_is_refused() {
        for bad in [
            "1.1.1.1/24",
            "1.1.1.1/0",
            "2606:4700:4700::1111/32",
            "1.1.1.1/33",
            "2606:4700::/129",
            "1.1.1.1/",
            "1.1.1.1/-1",
            "1.1.1.1/x",
            "not-an-address",
            "",
            "1.1.1.1/24/24",
            "example.com",
            // An IPv4 destination in IPv6 notation: the packet leaves as
            // IPv4 and no `ip6 daddr` rule would ever match it.
            "::ffff:1.1.1.1",
            "::ffff:101:101",
            "::ffff:0:0/96",
        ] {
            assert!(Cidr::from_str(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn outbound_and_proto_names_are_the_written_ones() {
        assert_eq!(Outbound::from_str("allow").unwrap(), Outbound::Allow);
        assert_eq!(Outbound::from_str("deny").unwrap(), Outbound::Deny);
        assert_eq!(Outbound::default(), Outbound::Allow);
        assert_eq!(Proto::from_str("tcp").unwrap(), Proto::Tcp);
        assert_eq!(Proto::from_str("udp").unwrap(), Proto::Udp);
        for bad in ["", "DENY", "reject", "drop"] {
            assert!(Outbound::from_str(bad).is_err(), "{bad}");
        }
        for bad in ["", "TCP", "icmp", "sctp", "any"] {
            assert!(Proto::from_str(bad).is_err(), "{bad}");
        }
    }

    fn pattern(s: &str) -> HostPattern {
        HostPattern::parse(s).expect(s)
    }

    #[test]
    fn host_patterns_parse_by_the_ldh_rules() {
        for ok in [
            "api.anthropic.com",
            "Claude.AI.",
            "xn--bcher-kva.example",
            "*.example.com",
            "a1.b2",
        ] {
            assert!(HostPattern::parse(ok).is_ok(), "{ok}");
        }
        assert_eq!(pattern("Claude.AI.").to_string(), "claude.ai");
        assert_eq!(pattern("*.Example.COM").to_string(), "*.example.com");
        for bad in [
            "",
            ".",
            "a..b",
            "-a.b",
            "a-.b",
            "a_b.c",
            "b\u{fc}cher.de",
            "*",
            "*.",
            "a.*.b",
            "*.*.c",
            "1.2.3.4",
            "[::1]",
            "a b",
            &format!("{}.c", "x".repeat(64)),
            &"a.".repeat(127),
        ] {
            assert!(HostPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_wildcard_matches_exactly_one_label() {
        let p = pattern("*.example.com");
        assert!(p.matches("a.example.com"));
        assert!(!p.matches("example.com"));
        assert!(!p.matches("a.b.example.com"));
        assert!(!p.matches(".example.com"));
        let e = pattern("example.com");
        assert!(e.matches("EXAMPLE.com."));
        assert!(!e.matches("a.example.com"));
    }

    /// The probe is held to the rules a config is held to, the
    /// wildcard's own label included: a `CONNECT` target is text the
    /// sandbox wrote, and one that is no name must not reach a resolver
    /// on the strength of its suffix.
    #[test]
    fn a_probe_that_is_no_name_matches_nothing() {
        let p = pattern("*.example.com");
        assert!(p.matches("a1.example.com"));
        for bad in [
            "a_b.example.com",
            "-a.example.com",
            "a-.example.com",
            "a b.example.com",
            "b\u{fc}cher.example.com",
            "a..example.com",
            "*.example.com",
            &format!("{}.example.com", "x".repeat(64)),
            &format!("{}.example.com", "x.".repeat(126)),
        ] {
            assert!(!p.matches(bad), "{bad}");
        }
        let e = pattern("example.com");
        assert!(!e.matches("exam ple.com"));
        assert!(!e.matches("example.com.."));
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

    #[test]
    fn a_cgroup_path_is_what_systemd_names_and_nft_can_quote() {
        let cg = cgroup();
        assert_eq!(
            cg.path(),
            "user.slice/user-1000.slice/user@1000.service/app.slice/bubbler-t-1"
        );
        assert_eq!(cg.level(), 5);
        assert_eq!(
            cg.to_string(),
            "socket cgroupv2 level 5 \
             \"user.slice/user-1000.slice/user@1000.service/app.slice/bubbler-t-1\""
        );
        // Everything a unit name may hold is a directory name here.
        for ok in ["a", "a/b", "system.slice/dbus:name+more@1.service"] {
            assert!(Cgroup::new(ok).is_ok(), "{ok}");
        }
        // A `"` would end the quoted path and a `;` after it would start
        // a second rule, in a process holding CAP_NET_ADMIN over the
        // sandbox's namespaces.
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "a\"b",
            "a\\b",
            "a b",
            "a\tb",
            "a\nb",
            "a\u{7f}b",
            "a\u{0}b",
            "b\u{fc}cher",
        ] {
            assert!(Cgroup::new(bad).is_err(), "{bad:?}");
        }
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

    /// One rendering for the emitter and for the message that names a
    /// duplicate, and the default port is the one a config need not
    /// write.
    #[test]
    fn an_allowed_host_writes_itself_the_way_a_config_does() {
        let one = |name: &str, port| {
            AllowHost {
                pattern: pattern(name),
                port,
            }
            .to_string()
        };
        assert_eq!(
            one("api.example.com", AllowHost::DEFAULT_PORT),
            "\"api.example.com\""
        );
        assert_eq!(one("*.example.com", 8443), "\"*.example.com\" port=8443");
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
