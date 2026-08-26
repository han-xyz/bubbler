# Lint and Explain

## bubbler lint

```
bubbler profile lint firefox
bubbler profile lint --all [--deny warnings] [--format json]
bubbler lint ff
```

Measures a profile or instance config against what a sandbox is meant to
give away. Launches nothing, edits nothing. Findings are in editor-parsable
form with a `help:` line; spans point at the layer that has to change, even
three `include`s deep.

Exit codes: 0 clean, 1 warnings, 2 errors, 3 could not lint (parse failure,
unknown name). `--deny warnings` turns 1 into 2. `create`, `reseed`, `edit`
and `profile edit` run the lint afterwards and print errors and warnings as
advice (exit code untouched).

**Errors** (the file will not do what it says): `bundle-without-dbus`,
`path-share-reserved`, `dup-name-policy`, `own-on-system-bus`,
`camera-without-portals`.

**Warnings** (grants more than it probably means): `x11-without-reason`,
`seccomp-disabled`, `userns-disabled-with-nested-sandbox`, `own-too-wide`,
`mpris-wildcard`, `system-bus-polkit-name`, `home-share-sensitive`,
`path-share-mountpoint`, `path-share-socket`, `share-source-missing`,
`dbus-without-rules`, `env-looks-secret`, `tty-passthrough`,
`portal-talk-without-portals`, `wayland-host`, `wayland-clipboard-open`,
`usb-all-devices`.

**Notes** (information): `app-runtime-rw`, `network-host`, `outbound-deny`,
`ozone-hint-unnecessary`, `command-not-found`, `desktop-entry-missing`,
`camera-nodes-none-present`, `camera-nodes-no-hotplug`, `secrets-access`,
`lint-allow-unused`, `x11-nested-no-wm`.

`x11-nested-no-wm` is about the windows inside a nested `x11` server, so a
config that already asks for the whole output with `fullscreen=#true`, or names
a window manager to run inside with `wm="twm"`, never gets it.

`usb-all-devices` is about a `usb` node with no `vendor=`. That form binds the
whole `/dev/bus/usb` directory — every USB device the host has, the raw
interfaces of your keyboard and your security key among them, and every device
plugged in while the sandbox runs, since it is the directory that is bound and
not the nodes in it. The fix the help names is
`usb vendor="0bb4" product="0c8d"`, the two ids `lsusb` prints; that form is
resolved at launch, so the device has to be plugged in first. A node carrying
`vendor=` never raises the warning, and a bare node you meant is accepted with
`lint-allow "usb-all-devices" reason="..."`.

`wayland-clipboard-open` is about `wayland clipboard="open"`, which turns the
paste gate off: the sandbox may then read the selection whenever it holds
keyboard focus, with no keystroke of yours behind the read, and the proxy only
logs it. Accept it with a `lint-allow` naming what reads the clipboard
unattended. A bare `wayland` never raises it, and neither does a
`clipboard="open"` a later layer has replaced with the bare node — the check
reads the merged mode, not each layer.

Accept a warning or note with a reason:

```kdl
x11 "host"
lint-allow "x11-without-reason" reason="steamwebhelper is an X11/CEF client"
```

Holds for the whole flattened profile; a `lint-allow` in your layer accepts a
finding about a built-in. Unknown ids and error ids are parse errors. Every
shipped profile lints clean.

## --dry-run and --explain

```
bubbler run ff --dry-run                 # `bwrap` then one argv element per line, diffable
bubbler run ff --explain                 # grouped under the node that produced each argument
bubbler run ff --explain=full            # baseline included
bubbler run ff --explain --proxy         # the xdg-dbus-proxy sidecar's argv
bubbler run ff --explain --wl-proxy      # the bubbler-wl-proxy sidecar's argv
bubbler run ff --explain --format json   # one object per operation, true argv order
bubbler try --profile firefox --explain
```

Neither launches anything or creates a runtime directory. `--explain` shows,
per group, the config line, the argument count, what is behind each generated
descriptor (seccomp filter size and architectures, `--ro-bind-data` size,
which pipe an `--info-fd`/`--block-fd` is), and grants that are not bwrap
arguments: D-Bus `rules:`, `rule-only:` for nodes contributing nothing else,
which socket a `wayland` node binds (`security-context:` plus the
`sidecar: bubbler-wl-proxy …` line for a bare grant,
`raw socket: wayland "host"` for the session's own), `raw socket: x11 "host"`
for a session X display, `sidecar: pasta …` and the nft ruleset under
`network`. A nested `x11` needs no such line: the `--x11` argument is the
Xwayland command line itself, and `--wm` the window manager's name, both
arguments of `bubbler-init` rather than of bwrap.

`compute`, `smartcard` and a bare `usb` each add a `grants:` line saying what
their few binds reach, and a `usb` node with `vendor=` adds `matched:` — one
line per device it resolved (product `*` where the node named a vendor alone),
or the text of the launch warning where nothing matched:

```
  usb vendor="1532" product="0531"  config.kdl:1  9 arguments
    --ro-bind /sys/bus/usb /sys/bus/usb
    --dev-bind-try /dev/bus/usb/001/004 /dev/bus/usb/001/004
    --ro-bind /sys/devices/…/usb1/1-8 /sys/devices/…/usb1/1-8
    matched: 1532:0531 at bus 001 device 004

  usb vendor="ffff"                 config.kdl:2  0 arguments
    matched: no device matches vendor=ffff
```

```
  portals                         config.kdl:11  10 arguments
    --block-fd 4  (pipe: the sandbox waits on it until bubbler lets it go)
    --perms 0644 --ro-bind-data 9 /.flatpak-info  (generated file, 69 bytes)
    --bind /run/user/1000/doc/by-app/org.bubbler.ff /run/user/1000/doc
    rules: --talk=org.freedesktop.portal.Desktop
           ...
  seccomp                                        2 arguments
    --add-seccomp-fd 5  (filter, 896 bytes, x86_64 + i386)
  wayland                         config.kdl:3   6 arguments
    --ro-bind /run/user/1000/bubbler/ff/wayland /run/user/1000/wayland-1
    --setenv WAYLAND_DISPLAY wayland-1
    security-context: engine=org.bubbler app=org.bubbler.ff instance=bubbler-ff
    sidecar: bubbler-wl-proxy listener /run/user/1000/bubbler/ff/wayland → upstream /run/user/1000/bubbler/ff/wayland-context, gate paste
  init                                           7 arguments
    --ro-bind /usr/lib/bubbler/bubbler-init /run/bubbler-init
    -- /run/bubbler-init --socket-fd 10  (socket: the exec channel bubbler-init serves)
  x11 wm="openbox"                config.kdl:5   21 arguments
    --setenv DISPLAY :0
    --x11 /usr/bin/Xwayland :0 -noreset -nolisten tcp -nolisten local -nolisten unix -ac -hidpi -decorate -geometry 1280x720 --  (nested Xwayland, started by bubbler-init on the first X connection; -listenfd is added at run time)
    --wm openbox  (window manager inside the sandbox, started with the server)
```

That config has an `x11` node, which is why its `wayland` group carries no
`--setenv XDG_SESSION_TYPE wayland`: bubbler claims a Wayland session only for
a sandbox with no X display in it. The `x11` group sits after `init` because
its first argument is a `--setenv`, and the environment phase comes after every
bind — the one that puts `bubbler-init` in place included.

`--explain --wl-proxy` renders the Wayland proxy's own sandbox instead. Its
`baseline` and `seccomp` groups carry no config line — the sidecar's filter is
the default set whatever the instance's `seccomp` node says — its `command`
group holds the proxy's argv (`--listen-fd`, `--upstream`, `--log-fd`,
`--ready-fd`, and a `--ro-bind` of the binary itself unless it is the installed
one, already under the read-only `/usr`), and the one part of the argv the
config decides is grouped under the `wayland` node that decided it:

```
  wayland   config.kdl:3  2 arguments
    --gate
    paste
```

`--proxy` and `--wl-proxy` each render one sidecar and cannot be combined;
either without `--explain` is a usage error. A config that starts no such
sidecar says so instead of printing an empty view.

With `portals` granted, a command line carrying host file arguments prints one
`forward:` or `visible:` line each, on **stderr** so that stdout stays the
byte-exact argv or parsable JSON. Without the grant only the `visible:` lines
appear. Neither mode calls the portal, so the id is a literal `<id>`:

```
forward: /tmp/fwd-ro.txt → $XDG_RUNTIME_DIR/doc/<id>/fwd-ro.txt (read)
visible: /home/han/Documents/paper.pdf → /home/bubbler/Documents/paper.pdf
```

Groups sit where a node's first argument appears, so the listing is neither
file order nor argv order; `--dry-run` and `--format json` are the order of
record. `--explain` attributes, it does not justify: why the baseline holds
`/etc/ssl` is the [Security](Security.md) page's job.
