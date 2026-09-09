# Lint and Explain

## bubbler lint

A node commented out with `/-` at the start of its line is a disabled entry:
lint checks that it is a valid node and otherwise reports nothing about it, and
`--explain` never lists it (see Configuration → Disabling a node).

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
`path-share-reserved`, `home-share-reserved`, `dup-name-policy`,
`own-on-system-bus`, `camera-without-portals`, `dbus-name-is-host-exec` (a
`dbus`/`system-bus` rule naming `org.freedesktop.systemd1`,
`org.freedesktop.Flatpak`, an `org.freedesktop.impl.portal.*` backend or
`ca.desrt.dconf`, each of which runs a command or sets policy outside the
sandbox).

**Warnings** (grants more than it probably means): `x11-without-reason`,
`seccomp-disabled`, `userns-disabled-with-nested-sandbox`, `own-too-wide`,
`mpris-wildcard`, `system-bus-polkit-name`, `home-share-sensitive`,
`path-share-mountpoint`, `path-share-socket`, `share-source-missing`,
`dbus-without-rules`, `env-looks-secret`, `tty-passthrough`,
`tty-passthrough-without-seccomp`, `portal-talk-without-portals`,
`wayland-host`, `wayland-clipboard-open`, `network-host`, `etc-host` (`etc
"host"` binds the host's whole `/etc` read-only in place of the allowlist:
`hostname`, `fstab`, `ssh/ssh_config`, `X11` config and every other
world-readable file becomes visible; `passwd`/`group` stay the synthetic
ones bubbler writes, overlaid with the shadow-suite backups and empty
`subuid`/`subgid` where the host has them, so the host username stays
hidden),
`dbus-name-is-risky` (a `dbus`/`system-bus` rule naming a name that is
defensible but wide — KWin's or the GNOME shell's own bus name, the session's
file manager, or the Secret Service), `audio-policy-missing` (a `pipewire`
or `pulseaudio` grant with part of the WirePlumber policy not installed: the
drop-in in none of `/usr/share/wireplumber/wireplumber.conf.d/`,
`/etc/wireplumber/wireplumber.conf.d/` or
`$XDG_CONFIG_HOME/wireplumber/wireplumber.conf.d/`, or the hook script in no
`wireplumber/scripts/` under `$XDG_DATA_HOME`, `$XDG_DATA_DIRS` or
`/usr/share`. Without the drop-in the grant is full access to every PipeWire
node instead of what it asks for; without the hook it is scoped but every other
client's audio stays recordable — its streams and the sink's monitor ports,
which the sandbox can also link to itself. The finding names the half that is missing and
the `bubbler audio-policy --print` or `--print --script` that writes it, then
restart WirePlumber).

**Notes** (information): `allow-host-wildcard`, `app-runtime-rw`,
`outbound-deny`, `ozone-hint-unnecessary`,
`command-not-found`, `desktop-entry-missing`, `camera-nodes-none-present`,
`camera-nodes-no-hotplug`, `dri-kms`, `dri-nvidia-primary`,
`secrets-access`, `lint-allow-unused`,
`x11-nested-no-wm`, `repeat-outside-block`, `pipewire-microphone` (a
`microphone` child on `pipewire` or `pulseaudio`: every microphone and
line-in the session has, and capture from them).

`allow-host-wildcard` is about a pattern that is a wildcard directly under a
top-level domain (`*.com`): the `*` stands for one label, so that one covers
every name anyone registers under the suffix. A wildcard deeper down
(`*.example.com`) never raises it.

`dri-kms` is about the primary (`card*`) nodes `kms=#true` adds: with them
the sandbox becomes DRM master on a virtual terminal switch and reads the
monitors' EDID, the framebuffer geometry and every other client's flink
names. The bare node binds the render nodes, which carry none of that.

`dri-nvidia-primary` reads this host: where a render node's GPU is on the
proprietary NVIDIA driver, a bare `dri` binds that GPU's primary node too
(its EGL will not drive a Wayland display without one), and the node
carries the connectors, their modes, the monitors' EDID through DRM
ioctls; `kms=#true` reaches further still, adding DRM master, the
framebuffer geometry and the flink names.

`x11-nested-no-wm` is about the windows inside a nested `x11` server, so a
config that already asks for the whole output with `fullscreen=#true`, or names
a window manager to run inside with `wm="twm"`, never gets it.

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
bubbler run ff --explain --net-proxy     # the bubbler-net-proxy sidecar's argv
bubbler run ff --explain --format json   # one object per operation, true argv order
bubbler try --profile firefox --explain
```

Neither launches anything or creates a runtime directory. `--explain` shows,
per group, the config line, the argument count, what is behind each generated
descriptor and file (seccomp filter size and architectures, the size of a
generated file and where in the runtime directory it is bound from,
which pipe an `--info-fd`/`--block-fd` is), and grants that are not bwrap
arguments: D-Bus `rules:`, `rule-only:` for nodes contributing nothing else,
which socket a `wayland` node binds (`security-context:` plus the
`sidecar: bubbler-wl-proxy …` line for a bare grant,
`raw socket: wayland "host"` for the session's own), `raw socket: x11 "host"`
for a session X display, and, under `network`, `sidecar: pasta …`, a second
`sidecar:` line for the egress proxy where the node has an `allow-host`, and
the nft ruleset the run installs. A nested `x11` needs no such line: the
`--x11` argument is the Xwayland command line itself, and `--wm` the window
manager's name, both arguments of `bubbler-init` rather than of bwrap.

```
  portals                         config.kdl:11  17 arguments
    --block-fd 4  (pipe: the sandbox waits on it until bubbler lets it go)
    --ro-bind /run/user/1000/bubbler/ff/.flatpak-info /.flatpak-info  (generated file, 69 bytes)
    --overlay-src /usr/bin --tmp-overlay /usr/bin  (flatpak-spawn shim (glycin, gdk-pixbuf))
    --ro-bind /usr/lib/bubbler/bubbler-init /usr/bin/flatpak-spawn
    --remount-ro /usr/bin
    --bind /run/user/1000/doc/by-app/org.bubbler.ff /run/user/1000/doc
    rules: --call=org.freedesktop.portal.Desktop=org.freedesktop.portal.FileChooser.*@/org/freedesktop/portal/desktop
           ...
  seccomp                                        2 arguments
    --add-seccomp-fd 5  (filter, 1120 bytes, x86_64 + i386)
  wayland                         config.kdl:3   6 arguments
    --ro-bind /run/user/1000/bubbler/ff/wayland /run/user/1000/wayland-1
    --setenv WAYLAND_DISPLAY wayland-1
    security-context: engine=org.bubbler app=org.bubbler.ff instance=bubbler-ff
    sidecar: bubbler-wl-proxy listener /run/user/1000/bubbler/ff/wayland → upstream /run/user/1000/bubbler/ff/wayland-context, gate paste, hides 40 privileged globals, compositor enforces too: yes
  init                                           7 arguments
    --ro-bind /usr/lib/bubbler/bubbler-init /run/bubbler-init
    -- /run/bubbler-init --socket-fd 6  (socket: the exec channel bubbler-init serves)
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

`--net-proxy` does the same for the egress proxy an `allow-host` starts. Its
`command` group is the binary as the sandbox execs it (`/run/bubbler-net-proxy`,
with the host path it is bound from as a note) and every option sits under the
`network` node that decided it:

```
  network   config.kdl:4  10 arguments
    --allow api.example.com:443
    --dns 169.254.1.1
    --port 3128
    --ready-fd <ready-fd>
    --log-fd 2
```

That is the default argv; `BUBBLER_NET_PROXY_LOG=1` adds `--log-tunnels` to the
end of it, and one to the count.

`--proxy`, `--wl-proxy` and `--net-proxy` each render one sidecar and no two can
be combined; any of them without `--explain` is a usage error. A config that
starts no such sidecar says so instead of printing an empty view.

With `portals` granted, a command line carrying host file arguments prints one
`forward:` or `visible:` line each, on **stderr** so that stdout stays the
byte-exact argv or parsable JSON. Without the grant only the `visible:` lines
appear. Neither mode calls the portal, so the id is a literal `<id>`:

```
forward: /tmp/fwd-ro.txt → $XDG_RUNTIME_DIR/doc/<id>/fwd-ro.txt (read)
visible: /home/user/Documents/paper.pdf → /home/bubbler/Documents/paper.pdf
```

Groups sit where a node's first argument appears, so the listing is neither
file order nor argv order; `--dry-run` and `--format json` are the order of
record. `--explain` attributes, it does not justify: why the baseline holds
`/etc/ssl` is the [Security](Security.md) page's job.
