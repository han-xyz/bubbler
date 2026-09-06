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
