# Devices

Each grant below names paths it **requires** at launch and, in some cases,
paths it binds only where the host has them. A required path that is missing,
or is not of the type expected, stops the run — never a quietly weaker
sandbox — and each section says which is which. Broadly: the device node and
the sysfs a grant cannot work without are required (`/dev/dri` with
`/sys/dev/char`, `/sys/devices/system/cpu` and at least one
`/sys/devices/pci*` root for `dri`, `/dev/input` with `/sys/class/input` and
`/sys/devices` for `gamepad`, `/dev/kfd` and its topology for `compute`,
`/sys/bus/usb` for `usb` — plus `/dev/bus/usb` and `/sys/devices` for the bare
form, and each node a filter matched — the `pcscd` socket for `smartcard`,
`/dev/uinput` for `gamepad uinput=#true`), while the hardware a host may
simply not have is bound where it exists (`/dev/nvidia*`, `/dev/video*`,
`/dev/hidraw*`, `/run/udev`).

## dri — GPU

Binds `/dev/dri` read-write, and read-only: `/sys/dev/char`,
`/sys/devices/system/cpu`, every `/sys/devices/pci*` root, `/sys/class/drm`.
That is the sysfs of **every** PCI device, not only the GPU.

NVIDIA: every `/dev/nvidia*` char device and `/sys/module/nvidia*` when
present (`nvidia-caps` skipped; `/proc/driver/nvidia` comes with `--proc`).
`dri` sets no environment — `DRI_PRIME`, `__NV_PRIME_RENDER_OFFLOAD` are a
profile's `env` decision. An OpenCL ICD still needs `etc-share "OpenCL"` and
NVIDIA application profiles `etc-share "nvidia"`; AMD compute is the `compute`
grant below.

## compute — AMD GPU compute

```kdl
dri
compute
```

Binds `/dev/kfd` read-write plus, read-only, `/sys/devices/virtual/kfd`,
`/sys/class/kfd` and `/sys/devices/system/node` (`/sys/devices/system/cpu`
comes with `dri`). Requires `dri`: `compute` alone is a parse error, because
the topology hands a runtime a render minor it then opens under `/dev/dri`.

- `/dev/kfd` is **one** node for the whole machine — every AMD GPU, not the
  card you meant. Permissions do not narrow it either: systemd's
  `50-udev-default.rules` sets `SUBSYSTEM=="kfd", GROUP="render", MODE="0666"`.
- Against `dri` it adds reach, not a new class of access: the same GPU
  through the same kernel driver the render nodes already opened, so no
  capture risk `dri` did not carry. The reach is the difference — `/dev/kfd`
  is machine-wide where a render node is per card.
- Missing `/dev/kfd` or a missing topology directory fails the launch.
- Nothing else is needed on Arch — ROCm lives in `/opt/rocm`, which the
  baseline binds read-only. **Never run against a real ROCm/HIP/OpenCL
  runtime**; this machine has none installed.

## pipewire, pulseaudio — audio

Hand over the session's audio socket directly: playback **and capture**,
microphone included, no portal. ALSA clients reach the same server through
`/etc/alsa` (baseline). `/dev/snd` is never bound.

## gamepad

```kdl
gamepad
gamepad hidraw=#true uinput=#true
```

Binds `/dev/input` (the directory, so hotplug works) read-write, plus
`/sys/class/input`, `/sys/devices`, `/run/udev` read-only.

- `/dev/input` is every input device on the machine. Node permissions, not
  bubbler, stop the sandbox reading your keyboard: on Arch `event*` is
  `0660 root:input` with a `uaccess` ACL on controllers. Any group that owns an
  input node (`input`, `openrazer`, …) undoes that. Compare `ls -l /dev/input`
  with `id` first.
- The bind is rw: an app can `EVIOCGRAB` a device, upload force-feedback,
  remap keycodes.
- `/sys/devices` is the whole device tree (DMI strings, battery, interface
  counters); `/run/udev/data` is the identity of every device.
- SDL only watches the directory for hotplug when it sees `/.flatpak-info`
  (the `portals` grant).
- `hidraw=#true` is the `hidraw` grant below. `uinput=#true` adds
  `/dev/uinput`: the sandbox can create virtual input devices and **type into
  your session**; every launch warns. Only for profiles you would trust with
  your keyboard (Steam Input).

## hidraw

Every `/dev/hidraw*` node present at launch, plus `/sys/class/hidraw`. Raw HID:
FIDO keys, hardware wallets, 3D mice, SDL's hidapi controllers. Unlike
`gamepad` it hands over no `/dev/input`.

- List is **frozen at launch** (no directory to bind): a key plugged in later
  is invisible until restart.
- It is every HID device; `uaccess` gives you an ACL on security tokens and
  wallets, so a sandbox with `hidraw` can talk to your FIDO key. Check
  `getfacl /dev/hidraw*`.

## usb

```kdl
usb                                // every device; lint warns (usb-all-devices)
usb vendor="1532"                  // every device of that vendor
usb vendor="1532" product="0531"   // that device
```

Bare: `/dev/bus/usb` read-write (the **directory**, so hotplug works) plus
`/sys/bus/usb` and `/sys/devices` read-only. Filtered: `/sys/bus/usb`, and per
matching device its `/dev/bus/usb/BBB/DDD` node and its own `/sys/devices/…`
directory.

- The bare node is every USB device, raw — your keyboard's interface and your
  security key's included. That is what `usb-all-devices` warns about.
- A filter is **frozen at launch**: matched from
  `/sys/bus/usb/devices/*/{idVendor,idProduct,busnum,devnum}` once, so plug
  the device in first. No match is a printed warning, not a failure.
- Ids are four hex digits in a string (`vendor="0BB4"` is lower-cased);
  `product=` without `vendor=` is refused. `lsusb` prints the pair.
- Two overlapping nodes in one file are an error; **across profile layers the
  wider node silently wins**, so an including layer can widen a scoped grant.
- A filter narrows **access**, not visibility. Alone it leaves the other
  `/sys/bus/usb` links dangling, but `dri` (PCI roots) or `gamepad`
  (`/sys/devices`) makes every device's descriptors readable again: measured
  here, `lsusb` with `dri` + a filter lists all fourteen devices while only
  the matched node is in `/dev`.
- The ids are what the device claims about itself — a filter is not
  authentication.
- Permissions stay the host's: a usbfs node is `0664 root:root`
  (`50-udev-default.rules`), and write access comes from `uaccess` tags or a
  vendor's `ATTR{idVendor}` rule. Check `getfacl /dev/bus/usb/*/*`.
- `--explain` prints a `matched:` line per resolved device; `lsusb` inside is
  the check that it is what you meant (`usbutils`).

## smartcard

Binds one socket, `/run/pcscd/pcscd.comm`, read-only at the same path. No
device node, no sysfs, no environment: libpcsclite finds that path itself.

- Host side: `pcsclite` + `ccid`, with `pcscd.socket` started — its
  `ListenStream` is that path. A stopped daemon fails the launch naming it.
- Costs every reader and card the daemon has, at APDU level: while a card is
  unlocked the sandbox can have it sign or decrypt as you, and the PIN is
  typed into the application inside. No per-reader narrowing exists.
- The socket ships `SocketMode=0666`, so the grant decides only whether this
  sandbox is one of the local processes that could already connect.
- **Never exercised against a real reader** — no `pcscd` on this machine.

## camera

```kdl
camera              // through org.freedesktop.portal.Camera; binds nothing
camera nodes=#true  // also /dev/video*, /dev/media*, /dev/v4l, their sysfs, /run/udev
```

Requires `portals` (parse error otherwise): the portal keys its permission
store on the app id from `/.flatpak-info`, so each instance gets its own
revocable entry. Host needs an `impl.portal.Access` backend (`-gtk`, `-kde`;
`-hyprland` alone is not enough) and `pipewire-libcamera` for MIPI cameras.

Applications opt in: Firefox `media.webrtc.camera.allow-pipewire`, Chromium
`#enable-webrtc-pipewire-camera`, OBS "Camera (PipeWire)". Plain V4L2 users
(mpv, ffmpeg, Cheese) need `nodes=#true`; node list frozen at launch, and
libudev-based pickers (GStreamer) find nothing without `gamepad`/`dri`'s
sysfs.

**Never tested against a real camera** — the development machine has none.
