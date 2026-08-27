# Configuration

An instance's `config.kdl` is one node per grant plus `command`. Unknown nodes
are errors; file order does not matter. Every source must exist on the host
with the expected type, or the run is refused.

```kdl
// bubbler profile: firefox
wayland                          // socket the compositor treats as sandboxed,
                                 //   proxied; a clipboard read needs your input
wayland clipboard="open"         // the same socket, the paste gate off; lint warns
wayland "host"                   // the session socket as it is, unproxied; lint warns
x11                              // nested Xwayland, on its first X client
x11 geometry="2560x1440"         // the window that server draws itself in
x11 fullscreen=#true grab=#true  // a whole output; input held inside (games)
x11 wm="openbox"                 // a window manager inside, with the server
x11 "host"                       // session X socket + cookie; lint warns
network                          // own namespace via pasta; see Network
network "host"                   // host's namespace
network {
    outbound "deny"              // filter egress: nothing but what the children name
    allow-out "1.1.1.1" port=53  // by address
    allow-host "api.example.com" // by name, through a CONNECT proxy of bubbler's
}
dri                              // GPU: /dev/dri, NVIDIA nodes, PCI sysfs
pipewire                         // $XDG_RUNTIME_DIR/pipewire-0 (playback AND capture)
pulseaudio                       // pulse/native, sets PULSE_SERVER
gamepad                          // /dev/input rw + sysfs; hidraw=#true uinput=#true
hidraw                           // every /dev/hidraw* node
camera                           // via portal; nodes=#true also binds /dev/video*
home-share "Downloads"           // ~/Downloads at /home/bubbler/Downloads, ro
home-share "Projects/x" mode=rw
path-share "/mnt/data" mode=rw   // host path outside home, same path inside
etc-share "vulkan"               // one /etc entry, ro
app-runtime "org.example.App"    // $XDG_RUNTIME_DIR/app/<id>, shared; mode=rw to serve
dbus { talk "ca.desrt.dconf"; own "org.example.App" }
system-bus { talk "org.freedesktop.UPower" }
portals                          // XDG portals + /.flatpak-info (needs dbus)
notify                           // org.freedesktop.Notifications (needs dbus)
tray                             // org.kde.StatusNotifierWatcher (needs dbus)
mpris name="firefox.*"           // own org.mpris.MediaPlayer2.firefox.*
a11y                             // the accessibility bus, proxied (needs dbus)
input-method                     // fcitx5/IBus portal names (needs dbus)
tty "pty"                        // pty | passthrough | none
userns "allow"                   // allow | disable nested user namespaces
seccomp { allow "perf_event_open"; deny "unshare" }
env MOZ_ENABLE_WAYLAND="0"       // repeatable, one key each
lint-allow "x11-without-reason" reason="the session's window manager"
desktop "org.mozilla.Thunderbird.desktop"   // which entry `bubbler desktop` copies
command "firefox"
```

`mode=` is optional on the way in — a share written without it is read-only —
and always written on the way out: `home-share`, `path-share` and `app-runtime`
come back from `profile show`, `reseed`, `--explain`, the editor and a saved
`config.kdl` with `mode=ro` or `mode=rw` spelled out.

## Disabling a node

A node whose line starts with `/-` is kept by the file and granted by nothing:

```kdl
home-share "Downloads"
/-home-share "Music"             // kept, not granted
/-dbus { talk "ca.desrt.dconf" } // a block keeps its children with it
```

KDL drops the line and bubbler reads it back as an entry that is turned off:
`run`, `--explain` and `lint` never see it, and it counts for neither the
duplicate check nor the bundle checks. It is not a comment — the line is parsed
as the node it spells out, so `/-home-shre "x"` is still `unknown node` — and it
is only a whole top-level node at the start of its line; a `/-` in front of an
argument or a child of a block is the ordinary KDL comment. `edit` and
`bubbler ui` keep those lines (`Space` in the editor writes them), `reseed`
writes the file again from the profile; a `/-` line in a profile seeds a
disabled entry into every instance made from it.

A `/-` line grants nothing and revokes nothing: an enabled node of the same
name, in the same file or in a layer under it, still applies.

## Grant reference

| Node | Grants | Watch out |
|---|---|---|
| `wayland` | bubbler's own socket, registered as a security context and served through `bubbler-wl-proxy`, which forwards a clipboard read only just after a key, button or touch of yours; `WAYLAND_DISPLAY` | which globals a sandboxed client loses is the compositor's policy; `clipboard="open"` drops the gate and lint warns |
| `wayland "host"` | the session's socket, with every global | the compositor cannot tell the sandbox from your session; lint warns |
| `x11` | a rootful Xwayland started inside the sandbox on its first X client, `DISPLAY=:0`; `wm="<program>"` starts a window manager inside with it | needs `wayland` and `dri`; one compositor window, and no window manager unless `wm=` names one bubbler does not ship |
| `x11 "host"` | the session's X socket, Xauthority at `/home/bubbler/.Xauthority` | X11 clients can keylog each other; lint warns |
| `network` | own namespace, internet via pasta | LAN/mDNS and host loopback unreachable; see [Network](Network.md) |
| `network "host"` | host's network stack | host loopback services and abstract sockets exposed |
| `network { outbound "deny" … }` | egress narrowed to the `allow-out` addresses and the `allow-host` names | a name is served by a CONNECT proxy of bubbler's on `127.0.0.1:3128` inside, which is also the only thing that resolves: the application gets no DNS, and one that ignores `HTTPS_PROXY` fails at the lookup. Needs a delegated cgroup2 subtree |
| `dri` | `/dev/dri` rw, NVIDIA nodes, `/sys/devices/pci*`, `/sys/class/drm` | sysfs of **every** PCI device |
| `pipewire`, `pulseaudio` | session audio socket | microphone too, no portal |
| `gamepad` | `/dev/input` rw, `/sys/devices`, `/run/udev` | every input node your user can open; keyboard if a group lets you |
| `hidraw` | every `/dev/hidraw*` at launch | security keys, wallets; list frozen at launch |
| `camera` | portal camera; `nodes=#true` adds `/dev/video*` | needs `portals`; untested on real hardware |
| `home-share` | a path under `$HOME` | one path once; symlinks out of home refused |
| `path-share` | an absolute path outside home | system roots, instance store and profile dir refused |
| `etc-share` | one `/etc` entry | not the account files |
| `app-runtime` | `$XDG_RUNTIME_DIR/app/<id>` | same dir for every sandbox naming the id, no peer auth |
| `dbus` / `system-bus` | filtered bus via proxy | rules are the whole confinement |
| `portals` | portal names + app id `org.bubbler.<inst>`; binds the instance's document-portal view at `$XDG_RUNTIME_DIR/doc`, which is also where host file arguments of `run`/`try`/`open` land | Steam's runtime misreads `/.flatpak-info` |
| `a11y` | the session's accessibility bus, proxied as a third bus; `AT_SPI_BUS_ADDRESS` | a screen reader reads this app's widgets; needs `dbus` |
| `notify`, `tray`, `mpris`, `input-method` | one or two bus rules each; `IBUS_USE_PORTAL` for `input-method` | need `dbus` in the merged result, as `portals` and `a11y` do |
| `seccomp` | edit the default denylist | `disable` prints a warning each run |
| `userns "disable"` | no nested user namespaces | breaks Firefox/Chromium inner sandbox, Steam, podman |
| `env` | extra variables | `HOME`, `PATH`, `DISPLAY` and the seven proxy variables an `allow-host` sets are refused |

Details: [Sharing Files](Sharing-Files.md), [Devices](Devices.md), [Network](Network.md),
[D-Bus](D-Bus.md), [Terminal](Terminal.md), [Security](Security.md).

## Baseline (every sandbox)

All namespaces unshared, no network, read-only `/usr` and `/opt`, empty `/tmp`
`/var` `/run`, private home `/home/bubbler`, empty `$XDG_RUNTIME_DIR` (0700),
cleared environment (only `TERM`, `LANG`, `LANGUAGE`, `COLORTERM`, `TZ`, `LC_*`
survive), `/dev/ntsync` when the host has it, `--new-session`,
`--die-with-parent`, the default seccomp filter. `/etc` is an allowlist over a
tmpfs (`ld.so.*`, `fonts`, `localtime`, `machine-id`, `nsswitch.conf`, `hosts`,
`ssl`, `ca-certificates`, `mime.types`, `xdg`, `gtk-3.0`, `gtk-4.0`, `pulse`,
`pipewire`, `alsa`, `drirc`, `vulkan`, `glvnd`, `egl`, `vdpau_wrapper.cfg`,
`os-release`); `passwd` and `group` are generated with user `bubbler` and
`nobody` only.

## Config header

`create` writes `// bubbler profile: <name>` and `// bubbler config: 2`. A file
without the version header and a bare `network` node gets a warning on every
run: that node used to mean the host namespace. `reseed` or `edit` stamps it.
