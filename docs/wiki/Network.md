# Network

```kdl
network                          // own namespace, connected by a pasta sidecar
network "host"                   // the host's namespace
network "none"                   // no network (same as no node)
network {
    dns "1.1.1.1"                // generated /etc/resolv.conf (any mode but "none")
    allow-port 8080              // host 127.0.0.1:8080 reaches the sandbox
    allow-port 5353 udp=#true
    outbound "deny"              // default "allow"
    allow-out "1.1.1.1"          // any port, tcp and udp
    allow-out "140.82.112.0/20" port=443 proto="tcp"
    allow-out "2606:4700:4700::1111" port=853
    no-ipv6
}
```

## Isolated (default) vs host

| | isolated | `"host"` |
|---|---|---|
| host `127.0.0.1` services | unreachable | reachable |
| abstract unix sockets | isolated | exposed (no permission checks at all) |
| host interfaces, VPN, socket table | hidden | visible |
| LAN broadcast / mDNS (Chromecast, Spotify Connect, Remote Play) | **does not work** | works |
| services on other host addresses (`docker0`, VPN endpoint) | reachable, routed | reachable |

Needs `pasta` (package `passt`). Missing pasta is an error, never a quiet
fallback. pasta is the one sidecar not wrapped in a sandbox: it must join the
sandbox's user namespace to configure it, and it isolates itself
(`pivot_root` into an empty fs, seccomp, no-new-privs). Its authority is over
the sandbox's namespaces only, which your uid created.

Fixed pasta flags on every run: `-t none -u none -T none -U none
--map-host-loopback none --map-guest-addr none --foreground`. pasta's own
defaults would publish sandbox ports on the host and put host loopback back
inside; bubbler turns all of it off.

## DNS

`/etc/resolv.conf` is generated, not bound: without `dns` it names
`169.254.1.1`, which pasta forwards to the host's first resolver. `dns "<ip>"`
replaces the list; a loopback address is refused in isolated mode (it would be
the sandbox's own loopback), allowed under `"host"`, and `dns` is refused
under `"none"`.

## Inbound: allow-port

Published on the host's `127.0.0.1` only, never the LAN. The server inside must
listen on `0.0.0.0`, not its own loopback.

## Outbound: outbound "deny"

An nftables ruleset installed in the sandbox's network namespace (`inet`
table, `policy drop`, trailing `reject`). Always open: loopback, established
connections, IPv6 neighbour discovery, the resolver on port 53. Everything
else needs an `allow-out`.

- By **address** only; `allow-out "api.example.com"` does not exist and will
  not (CDN/anycast answers change mid-run).
- Bits below a prefix must be zero (`1.1.1.1/24` refused). IPv4-mapped v6 and
  v6 rules under `no-ipv6` refused.
- No ICMP: `ping` does not answer.
- Blocked TCP v4 fails fast with `EHOSTUNREACH`, UDP with `EPERM`, TCP v6 with
  `EACCES` after ~1 s.
- The sandbox cannot read or flush the rules (`nft list ruleset` inside:
  `Operation not permitted`).
- Installed by `nft -f -` entering the namespace with `CAP_NET_ADMIN` only,
  before pasta attaches and before the app runs; any failure stops the run.
  Needs the `nftables` package.
- A layer above cannot drop a `deny` from an `include`d layer; it can add
  destinations.
- `--explain` prints the ruleset; `bubbler lint` notes it as `outbound-deny`.

## Failure modes

Before pasta starts bubbler checks the reported pid's netns differs from its
own (a dead pid reused would hand pasta the host namespace). A pasta that dies
mid-run is reported once (`pasta exited … the sandbox has lost its network`)
and the app keeps running.

## Legacy configs

A `config.kdl` without `// bubbler config: 2` and a bare `network` used to
mean the host namespace; every run warns until `bubbler reseed` or `bubbler
edit` stamps the header.
