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
