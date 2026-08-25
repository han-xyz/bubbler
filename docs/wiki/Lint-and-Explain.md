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
`portal-talk-without-portals`, `wayland-host`.

**Notes** (information): `app-runtime-rw`, `network-host`, `outbound-deny`,
`ozone-hint-unnecessary`, `command-not-found`, `desktop-entry-missing`,
`camera-nodes-none-present`, `camera-nodes-no-hotplug`, `secrets-access`,
`lint-allow-unused`, `x11-nested-no-wm`.

`x11-nested-no-wm` is about the windows inside a nested `x11` server, so a
config that already asks for the whole output with `fullscreen=#true`, or names
a window manager to run inside with `wm="twm"`, never gets it.

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
bubbler run ff --explain --format json   # one object per operation, true argv order
bubbler try --profile firefox --explain
```

Neither launches anything or creates a runtime directory. `--explain` shows,
per group, the config line, the argument count, what is behind each generated
descriptor (seccomp filter size and architectures, `--ro-bind-data` size,
which pipe an `--info-fd`/`--block-fd` is), and grants that are not bwrap
arguments: D-Bus `rules:`, `rule-only:` for nodes contributing nothing else,
which socket a `wayland` node binds (`security-context:` for a bare grant,
`raw socket: wayland "host"` for the session's own), `raw socket: x11 "host"`
for a session X display, `sidecar: pasta …` and the nft ruleset under
`network`. A nested `x11` needs no such line: the `--x11` argument is the
Xwayland command line itself, and `--wm` the window manager's name, both
arguments of `bubbler-init` rather than of bwrap.

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

Groups sit where a node's first argument appears, so the listing is neither
file order nor argv order; `--dry-run` and `--format json` are the order of
record. `--explain` attributes, it does not justify: why the baseline holds
`/etc/ssl` is the [Security](Security.md) page's job.
