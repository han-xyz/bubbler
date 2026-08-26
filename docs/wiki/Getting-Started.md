# Getting Started

## Install

**Arch Linux:** AUR packages `bubbler` / `bubbler-git` (with `bubbler-ui`
split off) are prepared but **not published yet** — AUR account registration
is down at the moment, so they cannot be uploaded. Build from source until
then.

**From source:**

```
cargo build --release --locked
install -Dm755 target/release/bubbler      /usr/bin/bubbler
install -Dm755 target/release/bubbler-init /usr/lib/bubbler/bubbler-init
install -Dm755 target/release/bubbler-wl-proxy /usr/lib/bubbler/bubbler-wl-proxy
install -Dm755 target/release/bubbler-ui   /usr/bin/bubbler-ui      # optional
target/release/bubbler man          > /usr/share/man/man1/bubbler.1
target/release/bubbler man --config > /usr/share/man/man5/bubbler-config.5
```

`bubbler-init`, the supervisor bound into every sandbox, and
`bubbler-wl-proxy`, the sidecar in front of a sandboxed `wayland` socket, are
not commands to type; keep both out of `/usr/bin`. Each is looked for in its
own variable (`$BUBBLER_INIT`, `$BUBBLER_WL_PROXY`), then beside the running
`bubbler`, then under `/usr/lib/bubbler/`. Build needs Rust 1.95+ and
`libseccomp`.

## Runtime dependencies

| Package (Arch) | Needed for |
|---|---|
| `bubblewrap` | everything |
| `libseccomp` | everything (linked) |
| `bubbler-wl-proxy` (not a package — installed above) | every sandboxed `wayland`; the run stops if it is missing or will not start |
| `xdg-dbus-proxy` | any `dbus` or `system-bus` grant — of the shipped profiles, `chromium`, `code` and `firefox`; no profile grants `system-bus` |
| `passt` | isolated `network` — every shipped profile with a network |
| `nftables` | `outbound "deny"` only |
| `xdg-desktop-portal` + a backend | `portals`, `camera` |
| `xorg-xwayland` | a bare `x11` — the X server that runs inside the sandbox |
| `xorg-twm`, `openbox`, `jwm` or `icewm` | `x11 wm=` — any window manager on the sandbox's PATH; bubbler ships none |
| `at-spi2-core` | `a11y` — it is the accessibility bus, and the registry on it |
| `fcitx5` or `ibus` | `input-method`, optional: without a daemon the grant reaches nothing |

Also a kernel with unprivileged user namespaces.

## First instance

```
bubbler create ff --profile firefox   # prints the instance directory
bubbler run ff                        # runs `command` from config.kdl
bubbler run ff --dry-run              # print the bwrap argv instead
bubbler desktop ff                    # menu entry "Firefox (Bubbler)"
bubbler wrap ff                       # ~/.local/bin/ff starts it
```

The profile needs `~/Downloads` to exist (it is a `home-share`); a missing
share source is an error, never a silently weaker sandbox.

No profile for your application? `bubbler create x` uses `generic` (baseline
only), then `bubbler edit x` to add grants, or `bubbler ui` to toggle them.
See [Configuration](Configuration.md).

## Try without keeping anything

```
bubbler try -- id
bubbler try --profile firefox --grant network -- firefox --version
bubbler try --keep scratch -- sh      # keep it afterwards as instance `scratch`
```

## Remove

```
bubbler delete ff --yes    # instance and its private home, irreversible
bubbler unwrap ff          # the shim
bubbler desktop ff --remove
```
