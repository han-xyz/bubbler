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
`portal-talk-without-portals`.

**Notes** (information): `app-runtime-rw`, `network-host`, `outbound-deny`,
`ozone-hint-unnecessary`, `command-not-found`, `desktop-entry-missing`,
`camera-nodes-none-present`, `camera-nodes-no-hotplug`, `secrets-access`,
`lint-allow-unused`.

Accept a warning or note with a reason:

```kdl
x11
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
`sidecar: pasta …` and the nft ruleset under `network`.

```
  portals                         config.kdl:11  7 arguments
    --block-fd 4  (pipe: the sandbox waits on it until bubbler lets it go)
    --perms 0644 --ro-bind-data 9 /.flatpak-info  (generated file, 69 bytes)
    rules: --talk=org.freedesktop.portal.Desktop
           ...
  seccomp                                        2 arguments
    --add-seccomp-fd 5  (filter, 896 bytes, x86_64 + i386)
```

Groups sit where a node's first argument appears, so the listing is neither
file order nor argv order; `--dry-run` and `--format json` are the order of
record. `--explain` attributes, it does not justify: why the baseline holds
`/etc/ssl` is the [Security](Security) page's job.
