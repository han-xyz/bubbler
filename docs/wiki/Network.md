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
    allow-host "api.example.com"  // by name, through bubbler's own proxy
    allow-host "*.example.org" port=8443
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
fallback. pasta is not wrapped in a sandbox: it must join the sandbox's user
namespace to configure it, and it isolates itself (`pivot_root` into an empty
fs, seccomp, no-new-privs). Its authority is over the sandbox's namespaces
only, which your uid created. The egress proxy below and the one-shot `nft` are
the other two without a bwrap of their own; the proxy is confined the other way
— it joins the sandbox's namespaces and keeps no capability in them.

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
connections, IPv6 neighbour discovery, and the resolver on port 53 — that last
one for the sandbox only while no `allow-host` is present, since an
`allow-host` gates the resolver rules on the proxy's cgroup too (see below).
Everything else needs an `allow-out`.

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

## Egress by name: allow-host

```kdl
network {
    outbound "deny"
    allow-host "api.example.com"          // port 443
    allow-host "files.example.com" port=8443
    allow-host "*.example.org"            // exactly one label in place of the *
}
```

What an address rule cannot say. `allow-host` needs `outbound "deny"` in the
same node (anything else is a parse error) and is refused under `network "host"`
and `network "none"`.

**The mechanism.** bubbler starts `bubbler-net-proxy` — a CONNECT-only proxy —
as a host process that joins the sandbox's user, network and mount namespaces
and listens on `127.0.0.1:3128` **inside** the namespace. The ruleset accepts
that one process by its cgroup and rejects everything else, so the application
has no route out at all; what it has is the proxy, and the seven variables the
`network` node sets to point it there:

```
HTTPS_PROXY  HTTP_PROXY  https_proxy  http_proxy  = http://127.0.0.1:3128
NO_PROXY     no_proxy                             = localhost,127.0.0.1,::1
NODE_USE_ENV_PROXY                                = 1
```

All seven are reserved: an `env` node naming one is a config error, with or
without an `allow-host`. `allow-port 3128` beside an `allow-host` is one too —
pasta serves a forwarded port from a socket inside the namespace, which would
publish the proxy on the host's loopback.

**Names.** ASCII LDH labels, lower-cased, one trailing dot stripped, up to 63
per label and 253 in all. A single label (`localhost`) is allowed. `*.` at the
front matches exactly one label, and `*.<tld>` — a wildcard directly under a
top-level domain — is the `allow-host-wildcard` lint note. No IDNA conversion:
write the A-label (`xn--…`) yourself. An IP literal is not a name; `allow-out`
is how an address is named. Duplicates (same name and port) are an error.

**What the proxy does.** `CONNECT host:port` and nothing else, authorised on
the request target rather than on `Host`, then bytes relayed blind — no TLS
interception. Anything else is a status and no tunnel: `405` for another
method (with `Allow: CONNECT`), `403` for a name no `allow-host` covers, for
the wrong port and for an IP literal, `502` for a name that does not resolve
and for one whose every address refuses the connection, `504` for a connect
timeout, `503` past 64 concurrent tunnels, `408` for a request that arrives
too slowly, `400`/`414` for a malformed or over-long one. A name that resolves
to a loopback or link-local address is skipped: inside the namespace those point
back at the application, or at the proxy's own listener. Plain HTTP is not forwarded, and neither
is UDP: HTTP/3 is not tunnelled, so a client falls back to TCP.

**DNS is the proxy's.** With any `allow-host` the resolver rules carry the
cgroup match too, so the proxy resolves and the application does not — that
closes the `<secret>.attacker.example` channel out through a query. The proxy
uses a DNS client of its own (A and AAAA over UDP, TCP on truncation) aimed at
the addresses bubbler passes it as `--dns`, which are the ones those rules open;
it never calls `getaddrinfo`, because it sits in the sandbox's mount namespace
and NSS there is the application's to answer — an application that binds
`/run/systemd/resolve/io.systemd.Resolve` in its own `/run` tmpfs would
otherwise choose the address every listed name is dialled at (measured
2026-08-28). The
trade-off: a client that ignores the proxy variables fails at the name lookup
rather than at the connection, which reads like a broken resolver rather than
like a policy. Beside that, an `allow-out` naming an address with no `port=`
still covers port 53 at that address, so a resolver named that way is one the
application can still query directly.

**What it costs to run.** The proxy's cgroup has to exist before `nft -f` runs,
under a cgroup2 subtree delegated to your user — a systemd user session provides
one. Without it a config with an `allow-host` is refused rather than started
unfiltered, and the message names the requirement. For the length of such a run
bubbler moves *itself* into `<its own cgroup>/bubbler-<instance>-<pid>/sandbox`
and leaves the proxy in the sibling `proxy` leaf, so systemd accounting shows
the run one level deeper than usual; both leaves are removed at teardown, and
a `SIGKILL`ed bubbler leaves two empty directories that the next run of that
instance sweeps.

The proxy writes its tunnels and refusals to bubbler's own stderr, at most 20
lines a second plus a count of what was suppressed:

```
bubbler-net-proxy: tunnel to api.example.com:443
bubbler-net-proxy: denied unlisted.example:443: no allow-host covers it
```

`bubbler run <inst> --explain` shows the proxy's argv and the seven values
under the `network` node, and `--explain --net-proxy` renders that argv on its
own. What the proxy is trusted with, and what keeps the application out of its
cgroup, is in [Security](Security.md#egress-proxy).

## Failure modes

Before pasta starts bubbler checks the reported pid's netns differs from its
own (a dead pid reused would hand pasta the host namespace). A pasta that dies
mid-run is reported once (`pasta exited … the sandbox has lost its network`)
and the app keeps running.

## Legacy configs

A `config.kdl` without `// bubbler config: 2` and a bare `network` used to
mean the host namespace; every run warns until `bubbler reseed` or `bubbler
edit` stamps the header.
