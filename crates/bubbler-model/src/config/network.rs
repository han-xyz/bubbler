//! The `network` node's values: the namespace a sandbox runs in, its
//! forwards, and the destinations `outbound "deny"` lets through.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::ConfigError;

/// Which network namespace the sandbox runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// The sandbox's own namespace, connected to the outside by a pasta
    /// sidecar: its own loopback, none of the host's abstract unix
    /// sockets and no LAN broadcast.
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
    /// namespace.
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
/// The host bits of a prefix must be clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
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

    // The nftables address family keyword this destination matches in:
    // the table is `inet`, so each rule names its own.
    pub fn family(&self) -> &'static str {
        match self.addr {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        }
    }

    pub fn bits(addr: IpAddr) -> u8 {
        match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

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
/// The rule itself lives in the proxy crate, because both ends need the
/// same one.
pub use bubbler_net_proxy::allow::HostPattern;

/// One `allow-host` child: a name the sandbox may reach under
/// [`Outbound::Deny`], and the single port it may reach it on.
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

/// The egress proxy's cgroup, as the nftables `socket cgroupv2` match
/// names it, and the one thing the ruleset accepts once an `allow-host`
/// is in play.
///
/// The match resolves the path to a cgroup id when `nft` reads the rule,
/// so the directory has to exist before the ruleset is installed and to
/// live as long as the sandbox: a cgroup created afterwards matches
/// nothing.
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
    /// The egress proxy's cgroup from its path relative to the cgroup2
    /// mount, or why that text is no path to write a rule from. `level` is
    /// counted from the path, so the two can never disagree.
    ///
    /// What is refused is what nft could not carry inside a quoted path,
    /// and nothing else: a `"` would end the string and `;` after it
    /// would start a second rule, in a process holding `CAP_NET_ADMIN`
    /// over the sandbox's namespaces. Everything a systemd unit name
    /// holds passes — `user@1000.service` is where a user session's
    /// delegated subtree lives, `@`, `:` and `+` are ordinary characters
    /// in one, and a `-` in a name arrives escaped as `\x2d`. Measured:
    /// nft resolves such a path as written and fails to resolve it with
    /// the backslash doubled, and a trailing `\` does not escape the
    /// closing quote, so passing them through is both necessary and
    /// safe.
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

/// The loopback port the egress proxy listens on inside the sandbox.
///
/// Fixed, and chosen by bubbler rather than by the proxy, because the
/// seven variables that point the application at it are `--setenv` pairs
/// of bwrap's argv.
pub const PROXY_PORT: u16 = 3128;

/// Names of the variables `bubbler_plan::network::proxy_env` sets,
/// in the order it returns them. Every one of them is in
/// [`crate::config::RESERVED_ENV`], so no `env` node can point the
/// sandbox at a proxy of its own.
pub const PROXY_ENV_NAMES: [&str; 7] = [
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "https_proxy",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
];

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

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr {
        Cidr::from_str(s).expect(s)
    }

    fn pattern(s: &str) -> HostPattern {
        HostPattern::parse(s).expect(s)
    }

    /// The cgroup a systemd user session actually delegates: the
    /// writable subtree is under `user@1000.service`, whose name holds
    /// an `@`. A validator that refused this shape would refuse every
    /// real run.
    fn cgroup() -> Cgroup {
        Cgroup::new("user.slice/user-1000.slice/user@1000.service/app.slice/bubbler-t-1")
            .expect("the delegated shape a user session has")
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
        // Everything a unit name may hold is a directory name here,
        // systemd's `\xNN` escape for a `-` among it: a scope started
        // from `xfce4-terminal` is named that way, and nft resolves the
        // path with the backslash as written.
        let escaped =
            "user.slice/user@1000.service/app.slice/app-dbus\\x2d:1.21\\x2dorg.a11y.slice";
        assert_eq!(
            Cgroup::new(escaped).unwrap().to_string(),
            format!("socket cgroupv2 level 4 \"{escaped}\"")
        );
        for ok in [
            "a",
            "a/b",
            "a\\b",
            "system.slice/dbus:name+more@1.service",
            "system.slice/system-gpg\\x2dagent.slice",
        ] {
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
