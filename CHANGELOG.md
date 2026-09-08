# Changelog

## 0.22.0

### Added

- Lint note `dri-nvidia-primary`: a bare `dri` on a host whose GPU is on the
  proprietary NVIDIA driver binds that GPU's primary node, and the note says
  what the node opens.
- `dri kms=#true` grants the primary (`card*`) nodes and leaves their sysfs
  readable, for a compositor or a mode-setting tool. `bubbler lint` notes it
  as `dri-kms` and `--explain` marks the group: with those nodes a sandbox
  becomes DRM master on a virtual terminal switch and reads the monitors'
  EDID, the framebuffer geometry and every other client's flink names. No
  shipped profile sets it.
- `home-share` and `path-share` take `optional=#true`: a source absent on
  this host is skipped instead of refusing the launch, so one profile can
  name a path only some installs of an app have. `--explain` says when a
  share was skipped this way; a present source binds exactly as it would
  without the property.
- `etc "host"` binds the host's whole `/etc` read-only in place of the tmpfs
  allowlist. `bubbler lint` warns about it as `etc-host`; the synthetic
  `passwd` and `group` files are still the ones bubbler writes either way,
  so the host username never reaches the sandbox. No shipped profile sets
  it.
- A `flatpak-spawn` shim: every sandbox that carries `/.flatpak-info` gets a
  second `bubbler-init` mode at `/usr/bin/flatpak-spawn`, reachable through
  glibc's default `/bin:/usr/bin` path once `/usr/bin` becomes an overlay
  of itself remounted read-only. gdk-pixbuf's glycin image loaders look for
  that program as soon as the identity file is there, and a GTK 3
  application aborts on a missing SVG icon without it; `--host` and the
  other options that would reach the host's own bus are refused by name.
  Needs unprivileged overlayfs (Linux 5.11 or newer).
- A live smoke test per shipped profile (`profile_smoke` in
  `crates/bubbler/tests/cli.rs`, run with `--ignored --exact
  profile_smoke::<name>`): a GUI profile's window mapping on Hyprland, or a
  CLI profile's command output. `BUBBLER_SMOKE_STEAM_INSTANCE=<instance>`
  points the steam entry at one already installed, instead of downloading a
  fresh client on every run.

### Changed

- `dri` binds the render node of every GPU instead of all of `/dev/dri`:
  the targets of the `/dev/dri/by-path/*-render` links, each GPU's own
  `/sys/devices` directory with its `drm/card*` directories masked by an
  empty read-only tmpfs, and `/sys/class/drm` rebuilt inside from one
  symlink per render node plus `version`. The `/sys/devices/pci*` roots and
  the whole-`/sys/class/drm` bind are gone. `by-path` is the only place a
  node is looked for, so a host that has `/dev/dri` without a `*-render`
  link there now fails instead of binding more. A mask is emitted after
  every other bind of the run, so a sibling grant that binds a tree above
  it — `gamepad`, with the whole of `/sys/devices` — cannot reopen the card
  sysfs. The NVIDIA nodes are unchanged, having no render/primary split of
  their own, and a GPU whose PCI driver is `nvidia` keeps its primary node
  with them: that stack's EGL declines a Wayland display without it, and a
  sandboxed GUI application would render in software. That node answers DRM
  ioctls — the connectors, their modes, the monitors' EDID — which the
  masked card sysfs does not withhold; `dri kms=#true` reaches further
  still, adding DRM master, the framebuffer geometry and the flink names.
  `--explain` marks the group and the new `dri-nvidia-primary` lint note
  says so. No other driver's primary node is bound.
- The sandbox `PATH` is `/usr/bin:/home/bubbler/.local/bin` instead of
  `/usr/bin` alone, so a bare command name resolves an app installed under
  a shared `.local/bin` (the native Claude Code installer, XDG user
  binaries) without naming the absolute path. Host binaries stay first,
  so nothing an app writes to its own `~/.local/bin` can shadow `/usr/bin`
  for it.
- Generated files (`/etc/passwd`, `/etc/group`, `/etc/resolv.conf`,
  `/.flatpak-info`) are written into the instance's own runtime directory
  and bound read-only from there, instead of `--ro-bind-data`'s anonymous,
  already-unlinked fd. A nested bwrap — Steam's own `pressure-vessel` among
  them — cannot re-open such a source through `/proc/self/fd`, so nothing
  that nests a sandbox inside this one could bind these files again; a path
  on disk still can.
- `pulseaudio-module-loading` is now a warning, not a note: measurement
  showed no bwrap bind can stop a host's `pipewire-pulse` daemon from
  loading a module — a network sink or tunnel among them — outside the
  sandbox's own network namespace and egress proxy on a client's request.
  The message names the host-side fix: a `pipewire-pulse.conf.d` drop-in
  setting `pulse.allow-module-loading = false`, and a service restart.

### Fixed

- `share-source-missing` no longer warns for a `home-share`/`path-share`
  whose source is absent when the node carries `optional=#true`: the
  launch already skips such a bind silently, so the lint now agrees
  instead of reporting a fault that isn't one.

### Notes

- xdg-desktop-portal 1.22.1 aborts a `ScreenCast.CreateSession` call that
  has no `session_handle_token` in its options dict (`xdp-session.c:296`),
  stopping the host's portal service for every other application on the
  desktop until D-Bus activation restarts it. This is an upstream bug in a
  process bubbler does not run; the proxy cannot filter for it, since the
  missing key is absent from the call rather than a value a rule can
  reject.
- What `portals` buys from PipeWire's own Flatpak policy is narrower than
  it sounds: a client that carries `/.flatpak-info` gets WirePlumber's
  Flatpak access rules — `rwx` rather than the unsandboxed default `rwxm`,
  so no muting, rerouting or destroying another client's nodes — but no
  narrower visibility (every node on the graph still shows, capture nodes
  included). Camera nodes are the one exception, gated separately through
  the portal's own permission store.

### Profiles

- `claude-code`/`claude-code-strict`: run `command "claude"`, so the native
  installer's `~/.local/bin/claude` and an npm global install at
  `/usr/bin/claude` both resolve through the sandbox `PATH`; the two shares
  the native layout needs are `optional=#true`, skipped rather than
  refusing the launch when the other layout is what the host has.
- `firefox`: works again — the `flatpak-spawn` shim answers the `portals`
  grant's `/.flatpak-info`, which GTK's SVG loader was aborting on.
- `libreoffice`: shares `etc-share "libreoffice"`, the directory this
  distribution's `bootstraprc`/`sofficerc` symlink into, which the suite
  needs for a user-installation path to exist at all.
- `code`: runs `command "code" "--wait"`, so its window outlives the
  launcher that starts it detached and returns.
- `lutris`: `home-share "Games"` is `optional=#true` — Lutris installs into
  its own private home where `~/Games` does not exist, instead of failing
  the launch.
- `steam`: starts — `steamwebhelper` needed the generated `/etc` files
  bound from the runtime directory to survive its own nested bwrap.
- `spotify`: starts — it grants `dbus` and `mpris name="spotify"`, without
  which the client reads the `RequestName` it cannot own as another copy of
  itself already running, calls `Raise` on that name and exits before
  drawing anything; with no bus at all it stops after its GPU process and
  never starts a renderer.

## 0.21.0

Hardening milestone: closes several gaps found by an escape-research pass
over the sandbox boundary. No config or CLI surface removed; every change
below either narrows a default or adds an opt-in node.

### Added

- `tmp size="<n>K|M|G"` caps the sandbox's own `/tmp` above its 2 GiB
  default, up to 64 GiB; every other tmpfs (`/etc`, `/var`, `/run`, and the
  runtime directory inside it) is now capped at 64 MiB. Each sidecar's own
  two tmpfs mounts, its `/etc` and its `/tmp`, are capped at 64 MiB too.
- `portals` takes children — `screencast`, `remote-desktop`,
  `global-shortcuts`, `background`, `location`, `secrets`, `camera` — each
  opening one interface group instead of the wildcard the bundle used to
  grant. An instance created before this release keeps its old node until
  reseeded, and every run of one warns once, naming the children to add:
  the config header is now `// bubbler config: 3`, and `bubbler reseed` or
  `bubbler edit` stamps it.
- Six repeatable nodes (`home-share`, `path-share`, `etc-share`,
  `app-runtime`, `env`, `lint-allow`) may be written as one block instead of
  one line each; the line form is still accepted, and `bubbler lint` notes a
  file that repeats one on separate lines (`repeat-outside-block`).
- New lint checks: `dbus-name-is-host-exec` (error — a bus name that runs a
  command or sets policy outside the sandbox), `dbus-name-is-risky`
  (warning — a defensible but wide bus name), `tty-passthrough-without-seccomp`
  (warning), `pulseaudio-module-loading` (note). `network-host` is now a
  warning rather than unchecked.
- The sandbox joins a session keyring of its own before it execs, rather
  than inheriting the login session keyring.
- `bubbler-init` drops what capabilities it can, sets `no_new_privs`,
  becomes non-dumpable and ties its life to its parent's death signal before
  it does anything else; it now answers `SIGHUP` and `SIGQUIT` with the same
  grace as `SIGTERM`.
- Every run warns, before anything else, when the host's `bwrap` is older
  than 0.12.0 (GHSA-pxhw-h44j-8pfx) or `xdg-dbus-proxy` older than 0.1.8
  (CVE-2026-34080, GHSA-r7hp-698j-2h6c); `--explain` prints the `bwrap`
  version it would run under.
- A launch refuses a bind destination — the private home, an `app-runtime`
  leaf, the document-portal view — that sits behind a symlink an earlier
  run could have planted, and refuses one it cannot even check.
- The default seccomp denylist gained io_uring (`io_uring_setup`,
  `io_uring_enter`, `io_uring_register`), `pidfd_getfd` and `kcmp`
  (`EPERM`); `open_tree_attr`, `listns` and `fchroot` (`ENOSYS`, by syscall
  number, since libseccomp 2.6.0 has no name for them); and a `personality`
  argument filter that allows only the five values a desktop application
  has any business setting. `seccomp { allow "…" }` / `deny "…"` reach all
  of these by name.
- Control sequences in config- or profile-derived text are drawn as `?`
  instead of sent to the terminal, in `bubbler-ui` and everywhere a lint
  finding or an explanation echoes a config value; every error and warning
  on stderr and the entry `bubbler desktop --print` writes show them in
  caret notation instead, as `bubbler log` already did.
- `XDG_ACTIVATION_TOKEN` joins the environment keys a config's `env` node
  may not set.

### Changed

- The Wayland proxy's privileged-interface denylist now applies to every
  sandboxed `wayland` connection unconditionally, not only when the
  compositor offers no security context of its own — closing the gap where
  a compositor (KWin) offers the protocol but does not actually enforce it.

### Fixed

- A malformed node in a `config.kdl` no longer silences every lint finding
  that would have been reported after it.
