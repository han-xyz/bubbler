# D-Bus

The session bus is never bound directly. bubbler starts an `xdg-dbus-proxy` in
a sandbox of its own (no network, no home, read-only `/usr`, almost empty
`/etc`) and binds the filtered socket it serves at `$XDG_RUNTIME_DIR/bus`
inside the app sandbox. Everything the app may reach is a rule.

```kdl
dbus {
    see  "org.freedesktop.ScreenSaver"     // name visible
    talk "ca.desrt.dconf"                  // call it
    own  "org.example.App"                 // own that well-known name
    call "org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.Read@/org/freedesktop/portal/desktop"
    broadcast "org.freedesktop.portal.Desktop=@/org/freedesktop/portal/desktop"
}
portals            // portal.Desktop/.Documents/.FileChooser + /.flatpak-info
notify             // talk org.freedesktop.Notifications
tray               // talk org.kde.StatusNotifierWatcher
mpris name="firefox.*"   // own org.mpris.MediaPlayer2.firefox.*
```

`portals`, `notify`, `tray`, `mpris` each need `dbus`. Filtering applies to
outgoing calls/signals and incoming broadcasts; a call *into* the sandbox
needs no rule.

## Wildcards are wide

`*` is a dot-namespace wildcard: `org.freedesktop.*` matches
`org.freedesktop.UPower`, not `org.freedesktopFoo`. `own "org.*"` claims every
name under `org.`; `mpris name="*"` lets the sandbox impersonate any player.
Never `own "org.kde.*"` — it covers the tray watcher. Name the application.
`bubbler lint` warns on `own-too-wide` and `mpris-wildcard`.

## portals

Writes `/.flatpak-info` with app id `org.bubbler.<instance>` (`.` in the name
becomes `_`), publishes `$XDG_RUNTIME_DIR/.flatpak/bubbler-<name>/bwrapinfo.json`
so `xdg-desktop-portal` can verify the caller, and holds the app at
`--block-fd` until that exists. The spawn portal
(`org.freedesktop.portal.Flatpak`) is not granted. Needs `xdg-desktop-portal`
and a backend on the host.

Known gap: no document-portal FUSE mount, so a file chooser handing back a
`/run/user/<uid>/doc/…` path gives the sandbox nothing it can open. Files under
a `home-share`/`path-share` work.

## System bus

```kdl
system-bus {
    talk "org.freedesktop.UPower"
    see  "org.freedesktop.NetworkManager"
    call "org.freedesktop.UDisks2=org.freedesktop.DBus.ObjectManager.GetManagedObjects@/org/freedesktop/UDisks2"
}
```

Same proxy, filtering the host system bus, bound at
`/run/dbus/system_bus_socket`. Takes the `dbus` children except `own`; needs
at least one; independent of `dbus`. **No default names.**

Weaker than the session bus: the system bus and polkit see the *proxy* — an
ordinary process of yours — not the sandbox. Behind a granted name the sandbox
is judged as you: an `auth_admin` action pops your password prompt with no
hint which sandbox asked. Grant one name at a time; `bubbler lint` warns on
polkit-judged names (`system-bus-polkit-name`). Prefer a portal
(`portals` covers `Inhibit`; PipeWire gets realtime via `portal.Realtime`).

## Debugging

`BUBBLER_DBUS_LOG=1` runs the proxy with `--log`: every filtered message on
stderr. `bubbler run <inst> --explain --proxy` prints the proxy's argv with
each rule under the node that asked for it.
