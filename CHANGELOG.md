# Changelog

## 0.21.0 (unreleased)

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
