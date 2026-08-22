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

Wayland-first; only the two gaming profiles grant `x11`. `~/name` is a
`home-share`, read-only unless `rw`.

| Profile | Grants |
|---|---|
| `alacritty` | wayland |
| `chromium` | wayland dri pipewire network dbus portals notify, ~/Downloads rw |
| `code` | wayland dri network dbus portals notify, ~/Projects rw |
| `firefox` | wayland dri pipewire pulseaudio network dbus portals notify mpris, ~/Downloads rw |
| `generic` | nothing beyond the baseline (commented examples to start from) |
| `keepassxc` | wayland dbus portals notify tray app-runtime rw, ~/Documents rw |
| `kitty` | wayland dri dbus portals notify |
| `libreoffice` | wayland dri dbus portals, ~/Documents rw, `SAL_USE_VCLPLUGIN=gtk3` |
| `lutris` | wayland x11 dri pipewire network dbus portals notify tray gamepad system-bus, ~/Games rw |
| `mpv` | wayland dri pipewire, ~/Videos |
| `spotify` | wayland dri pipewire network dbus notify tray mpris |
| `steam` | wayland x11 dri pipewire network dbus notify tray gamepad system-bus |
| `thunderbird` | wayland network dri dbus portals notify, ~/Downloads rw |
| `vesktop` | wayland dri pipewire network dbus portals notify tray, ~/Downloads rw |

Notes worth knowing:

- **steam**: no `portals` on purpose — Steam's runtime reads `/.flatpak-info`
  as "unofficial Flatpak" and aborts. Never add `userns "disable"`
  (pressure-vessel nests bwrap per Proton game). Move an existing install in
  with the instance stopped:
  `mv ~/.local/share/Steam ~/.local/share/bubbler/instances/steam/home/.local/share/`.
  A library outside the home needs a `path-share` (commented example in the
  profile). Steam Input's virtual controllers need `gamepad hidraw=#true
  uinput=#true` — read [Devices](Devices) first.
- **lutris**: keeps `portals`; drop it if a Proton/umu game complains about Flatpak.
- **keepassxc**: no `network`, no `own "org.freedesktop.secrets"`, no `hidraw`;
  each omission is a comment saying how to add it back. Browser integration
  via `app-runtime` — see [Sharing Files](Sharing-Files).
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
included; `env` replaces by key; `dbus`/`system-bus`/`seccomp` lists union;
`seccomp { disable }` anywhere disables; `outbound "deny"` below cannot be
undone above. `portals`/`notify`/`tray`/`mpris` need `dbus` in the merged
result, not in every layer.

## Instances and profiles

`create` and `try` write the **flattened** result (comments dropped) with a
`// bubbler profile: <name>` header. Editing one never changes the other.

```
bubbler profile show firefox    # flattened, each run of nodes under `// from: <file>`
bubbler reseed ff               # re-flatten ff's profile; hand edits dropped, config.kdl.bak kept
```

`reseed` refuses while the instance runs.
