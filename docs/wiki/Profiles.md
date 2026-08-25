# Profiles

A profile seeds a new instance's `config.kdl`. Same KDL as a config, plus one
node a config may not use: `include`. Three layers; first that holds the name
wins, and a layer that does not parse is an error rather than a fall-through:

```
~/.config/bubbler/profiles/<name>.kdl     yours
/usr/share/bubbler/profiles/<name>.kdl    the system's ($BUBBLER_PROFILE_DIR overrides)
built-in                                  compiled into bubbler
```

## Built-in profiles

Every profile carries what the application needs to *run* and nothing else.
Whatever else it can be given — a bus, notifications, a tray icon, screen
sharing, a browser rendezvous — is listed in the profile's own header comment,
node for node, ready to paste in (`bubbler profile edit <name>`). Read the
header before adding one: each entry says what the grant buys and what it hands
over.

Wayland-first; only the two gaming profiles grant `x11`, and both take the
`"host"` mode. `~/name` is a `home-share`, read-only unless `rw`.

| Profile | Grants |
|---|---|
| `alacritty` | wayland |
| `chromium` | wayland dri pulseaudio network dbus portals, ~/Downloads rw |
| `code` | wayland dri network dbus portals, ~/Projects rw |
| `firefox` | wayland dri pulseaudio network dbus portals, ~/Downloads rw |
| `generic` | nothing beyond the baseline (commented examples to start from) |
| `keepassxc` | wayland, ~/Documents rw |
| `kitty` | wayland dri |
| `libreoffice` | wayland, ~/Documents rw, `SAL_USE_VCLPLUGIN=gtk3` |
| `lutris` | wayland `x11 "host"` dri pulseaudio network gamepad, ~/Games rw |
| `mpv` | wayland dri pipewire, ~/Videos |
| `spotify` | wayland dri pulseaudio network |
| `steam` | wayland `x11 "host"` dri pulseaudio network gamepad |
| `thunderbird` | wayland network, ~/Downloads rw |
| `vesktop` | wayland dri pulseaudio network |

**Sound is `pulseaudio` almost everywhere.** Firefox and Chromium list
`libpulse` in their Arch dependencies, and Spotify, Electron applications and
CEF ones open `libpulse.so.0` themselves; that grant binds
`$XDG_RUNTIME_DIR/pulse/native`, which PipeWire's pulse server holds on a
PipeWire host. `pipewire` binds `pipewire-0`, the native socket — what a client
that speaks PipeWire itself takes (`mpv`), and what the portal hands a screen
or camera stream over. Either socket carries capture as well as playback.
`steam` and `lutris` are the unmeasured half: the client downloads its own
runtime on first run and Wine was not installed when this was written, so both
headers say so — if a game is silent, add `pipewire` beside the `pulseaudio`.

Notes worth knowing:

- **steam**: no `portals` on purpose — Steam's runtime reads `/.flatpak-info`
  as "unofficial Flatpak" and aborts. Never add `userns "disable"`
  (pressure-vessel nests bwrap per Proton game). Move an existing install in
  with the instance stopped:
  `mv ~/.local/share/Steam ~/.local/share/bubbler/instances/steam/home/.local/share/`.
  A library outside the home needs a `path-share` (commented example in the
  profile). Steam Input's virtual controllers need `gamepad hidraw=#true
  uinput=#true` — read [Devices](Devices.md) first.
- **steam and lutris**: neither reaches a bus. The names each client claims,
  the GameMode and screensaver rules, and the UDisks2 enumeration Wine builds
  its drive list from (`see` plus one `GetManagedObjects` call, never `talk`)
  are opt-ins in the two headers. `lutris` also lists `portals`, which Lutris
  itself calls — a Proton or umu game may then hit the same Flatpak complaint
  `steam` avoids.
- **steam and lutris**: both write `x11 "host"` and a `lint-allow` saying why —
  steamwebhelper opens many windows and Wine's X11 driver wants a real window
  manager, and a bare `x11` starts a server with none. That is the weak point of
  both profiles: on the session's display no X client is isolated from any
  other. The nested server takes a window manager of its own, so
  `x11 geometry="2560x1440" wm="openbox"` (with `openbox` installed) is worth
  trying in place of it, as is `x11 fullscreen=#true grab=#true` for a single
  fullscreen game; see [Security](Security.md#x11).
- **keepassxc**: a display and `~/Documents`, nothing more — no network, no bus
  name, no `hidraw`. Browser integration is the `app-runtime` opt-in its header
  spells out, with the matching read-only line in `firefox` and `chromium`; see
  [Sharing Files](Sharing-Files.md).
- **chromium / code / vesktop**: keep their own nested namespace sandbox; no
  `--no-sandbox`, no `userns "disable"`.
- **firefox / thunderbird**: Wayland by default; `env MOZ_ENABLE_WAYLAND="0"` for Xwayland.
- `alacritty`, `keepassxc`, `lutris`, `thunderbird`, `libreoffice` carry a
  `desktop` node because their `.desktop` is not named after the command.

## Your own profile

```
bubbler profile edit firefox        # creates ~/.config/bubbler/profiles/firefox.kdl
```

A new file starts as `include "firefox"`, so it extends the shipped profile:

```kdl
include "firefox"              // the layer below: the built-in firefox
home-share "Pictures"
env MOZ_ENABLE_WAYLAND="0"
```

`include "<own name>"` resolves one layer down. Includes nest 8 deep, resolve
depth-first, and a cycle is an error naming the chain.

**Merge rules:** grants union; same share path in two modes is an error;
`command`, `tty`, `userns`, `mpris` from the including file replace the
included; `wayland` and `x11` replace as well, being one mode each and the
`x11` window properties with it; `env` replaces by key;
`dbus`/`system-bus`/`seccomp` lists union;
`seccomp { disable }` anywhere disables; `outbound "deny"` below cannot be
undone above. `portals`/`notify`/`tray`/`mpris`/`a11y`/`input-method` need
`dbus` in the merged result, not in every layer.

## Instances and profiles

`create` and `try` write the **flattened** result (comments dropped) with a
`// bubbler profile: <name>` header. Editing one never changes the other.

```
bubbler profile show firefox    # flattened, each run of nodes under `// from: <file>`
bubbler reseed ff               # re-flatten ff's profile; hand edits dropped, config.kdl.bak kept
```

`reseed` refuses while the instance runs.
