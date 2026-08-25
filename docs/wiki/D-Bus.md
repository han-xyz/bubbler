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
a11y               // the accessibility bus, proxied as a third bus
input-method       // talk the fcitx5 and IBus portal names
```

`portals`, `notify`, `tray`, `mpris`, `a11y` and `input-method` each need
`dbus`. Filtering applies to outgoing calls/signals and incoming broadcasts;
a call *into* the sandbox needs no rule.

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

The instance's own view of the document portal, host
`$XDG_RUNTIME_DIR/doc/by-app/org.bubbler.<instance>`, is bound read-write at
`$XDG_RUNTIME_DIR/doc` inside: a file picked in the host's chooser appears as
`/run/user/<uid>/doc/<id>/<name>`, and the portal's own per-document
permissions decide whether it is writable. Only that subtree is bound, never
the mount root. Without xdg-document-portal running the launch warns
(`no document portal at …`) and files picked in a dialog stay unreachable.
Files under a `home-share`/`path-share` work either way.

Known gap: a desktop entry's `%f`/`%F` arguments are host paths; they are
not registered with the document portal, so they are unreachable inside.

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

## Accessibility bus

`a11y` is a **third bus** served by the same proxy process. bubbler finds the
host's accessibility bus the way at-spi2's own clients do: `$AT_SPI_BUS_ADDRESS`
if the session set one, else `org.a11y.Bus.GetAddress` on the session bus, asked
with `dbus-send` (package `dbus`) spawned directly, no shell. The filtered
socket is bound at `$XDG_RUNTIME_DIR/at-spi/bus` inside and named in
`AT_SPI_BUS_ADDRESS`, which is what every toolkit reads first. A bus that
cannot be found fails the run naming the step, never silently drops the grant;
a `unix:abstract=` address is refused, since the proxy's sandbox has no host
network namespace to reach one through.

`--explain --proxy` on an `a11y` config resolves that address too — it is part
of the proxy argv that view prints — so it asks `org.a11y.Bus` when the
variable is unset, and fails without a session bus. Plain `--explain` and `--dry-run` still speak
to nothing: they print the bind of the socket the sidecar would serve.

The node takes no children. Nine fixed rules are the whole of what the sandbox
may ask that bus:

```
--call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Embed@/org/a11y/atspi/accessible/root
--call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Unembed@/org/a11y/atspi/accessible/root
--call=org.a11y.atspi.Registry=org.a11y.atspi.Registry.GetRegisteredEvents@/org/a11y/atspi/registry
--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetKeystrokeListeners@/org/a11y/atspi/registry/deviceeventcontroller
--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetDeviceEventListeners@/org/a11y/atspi/registry/deviceeventcontroller
--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersSync@/org/a11y/atspi/registry/deviceeventcontroller
--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersAsync@/org/a11y/atspi/registry/deviceeventcontroller
--broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerRegistered@/org/a11y/atspi/registry
--broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerDeregistered@/org/a11y/atspi/registry
```

The app registers itself and reports its own events. Not in that list, and so
refused: `RegisterKeystrokeListener` (every keystroke of every accessible
application), `GenerateKeyboardEvent` and `GenerateMouseEvent` (input injected
into your session), and any destination but the registry — which is how every
*other* application on that bus is read. See [Security](Security.md#accessibility-bus).

Measured here, in a `dbus a11y` sandbox against this host's bus:
`Registry.GetRegisteredEvents` and `DeviceEventController.GetKeystrokeListeners`
answer, while `RegisterKeystrokeListener` and `GenerateKeyboardEvent` come back
`Error org.freedesktop.DBus.Error.AccessDenied` from the proxy.

To check the grant works, run `accerciser` (archwiki Accessibility): the app
should appear there with a deeply nested tree of children. Chromium- and
Electron-based apps need `ACCESSIBILITY_ENABLED=1` and
`--force-renderer-accessibility`, and Java apps the ATK bridge — both archwiki
Accessibility, and both the profile's business (`env`, `command`).

## Input methods

```kdl
input-method       // --talk=org.freedesktop.portal.Fcitx
                   // --talk=org.freedesktop.portal.IBus, IBUS_USE_PORTAL=1
```

Two session-bus rules, both names whichever daemon your session runs, plus
`IBUS_USE_PORTAL=1` so the IBus client library takes the portal name. Those
are the sandboxed entry points: per-client text input and nothing else. The
daemons' own names are **not** granted — they carry `Exit`, `Restart`,
`SetConfig`, `SetCurrentIM` and their kin, which is reconfiguration and denial
of service for the whole session.

On Wayland you may not need the grant at all: archwiki Fcitx5 "Wayland" says
the native *text-input* protocol "usually yields better results than input
method modules" and that GTK/Qt use it "if no other IM module is explicitly
specified", so it recommends IM modules "only ... in Xwayland applications".
The bus path is what those Xwayland clients (a bare `x11` runs one), apps with
an IM module set, and *text-input-v1* clients need.

bubbler sets no IM-module variable; a profile does, with `env`:

```kdl
input-method
env GTK_IM_MODULE="fcitx"   // archwiki Fcitx5 "IM modules": per Xwayland app
env QT_IM_MODULE="fcitx"    //   on a text-input compositor, globally on X11
env SDL_IM_MODULE="fcitx"   //   some SDL2 games
```

For IBus on Wayland, archwiki IBus "Integration" gives `GTK_IM_MODULE=wayland`,
`QT_IM_MODULE=ibus` and `XMODIFIERS=@im=ibus` (on X11, `GTK_IM_MODULE=ibus`).

## Debugging

`BUBBLER_DBUS_LOG=1` runs the proxy with `--log`: every filtered message on
stderr. `bubbler run <inst> --explain --proxy` prints the proxy's argv with
each rule under the node that asked for it.
