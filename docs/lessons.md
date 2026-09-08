# Lessons

One entry per lesson: a one-line summary first, then why it mattered. Update
rather than duplicate; delete an entry that turns out wrong.

## A `--talk` on a D-Bus name silences every `--call` filter on that name

xdg-dbus-proxy's policy ladder is NONE < SEE < FILTERED < TALK < OWN and the
most permissive rule for a name wins. The 0.21 spec kept
`--talk=org.freedesktop.portal.Desktop` next to the per-interface `--call`
rules, so the `portals { … }` split was inert until the whole-branch review
called the portal from inside a sandbox; five per-task reviews had read the
argv and passed it. A proxy rule change is proven by a live call from inside
the sandbox — a GTK client (zenity) and a Qt client (PyQt6) — never by reading
the argument list.

## `/.flatpak-info` is a claim other software acts on

Steam's runtime exits 71 without the flatpak-portal service, and
gdk-pixbuf's glycin loader refuses to load an SVG without
`flatpak-spawn` reachable, both measured during the 0.22 build. Writing
the marker file is a promise the rest of the sandbox has to keep, so no
grant may imply it — only `portals` writes `/.flatpak-info`, and a
sandbox that carries it ships a `flatpak-spawn` shim (a `bubbler-init`
mode) alongside.

## A portal probe sends both tokens

`ScreenCast.CreateSession` without `session_handle_token` aborts
xdg-desktop-portal 1.22.1 (`xdp-session.c:296`); the 0.21 acceptance
probe took the host's portal down three times before anyone read the
journal. Read `journalctl --user -u xdg-desktop-portal` first when a
portal call returns `NoReply`.

## bwrap `--ro-bind-data` binds an unlinked inode

A nested bwrap (pressure-vessel, Steam) cannot re-bind such a file:
the source is an anonymous fd under `/proc/self/fd`, already unlinked,
and the nested sandbox's own bind sees "No such file or directory".
Generated files (`/etc/passwd`, `/.flatpak-info`, ...) are written to
the runtime directory and bound read-only from there instead, so a
path a nested sandbox can re-open still exists on disk.

## A "hidden" claim is swept against the whole bound tree

`etc "host"` promised the username stays hidden and overlaid the two
files everyone names, `passwd` and `group`; the final review of 0.22
found `/etc/passwd-`, `/etc/group-`, `/etc/subuid` and `/etc/subgid`
world-readable through the same bind, each naming the account. When a
grant binds a tree and a promise says one fact stays out of it, grep the
bound tree for that fact from inside a live sandbox before the claim goes
in a doc — the per-task reviews and the verifier both passed the two
files they were told about.

## A sidecar that reports readiness must be able to take a signal before it reports

`bubbler-pw-hold` (0.23's PipeWire context holder) wrote the report line
that tells bubbler the sidecar is up, and closed the descriptor, before it
registered its own SIGTERM handler. A signal landing in that window found
the default disposition and killed the holder outright, leaving
`pw-container` waiting inside `system()` for its child until the
launcher's own stop deadline turned into a SIGKILL — 10 of 25 runs of the
holder's own tests failed on it. Register the signal handlers before the
line that says "ready", never after, in every sidecar built on this
report-then-wait shape.
