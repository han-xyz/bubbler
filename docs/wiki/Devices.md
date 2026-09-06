# Devices

Every device grant is emitted only where the host has the thing; a missing
`/dev/nvidia*` or `/dev/video*` binds nothing rather than failing. The
exception is `/dev/uinput`, which is an error when missing.

## dri — GPU

```kdl
dri
dri kms=#true
```

Binds the **render node** of every GPU read-write — each
`/dev/dri/by-path/*-render` link resolved, nothing else of `/dev/dri`, and
not `by-path` itself — and read-only: `/sys/dev/char`,
`/sys/devices/system/cpu` and each of those GPUs' own `/sys/devices`
directory. The `drm/card*` directories under it are covered with an empty
read-only tmpfs, and `/sys/class/drm` is rebuilt inside as one symlink per
render node plus `version`, so a driver finds its device without the
primary nodes, the connectors or the other PCI devices being there. A host
with `/dev/dri` but no `by-path/*-render` entry is an error, not a wider
bind.

`kms=#true` adds the primary (`card*`) nodes and leaves their sysfs
readable. That is mode setting, and with it: DRM master on a virtual
terminal switch, the monitors' EDID (serial numbers included), the
framebuffer geometry, and every other client's flink names. Only for a
compositor, a mode-setting tool or a bare-KMS player; `lint` notes it as
`dri-kms`. Rendering, video decoding and Vulkan need the bare node.

The masks are emitted after every other bind of the run, so no sibling
grant — `gamepad`, which binds `/sys/devices` whole — reopens the card
sysfs underneath them.

NVIDIA: every `/dev/nvidia*` char device and `/sys/module/nvidia*` when
present (`nvidia-caps` skipped; `/proc/driver/nvidia` comes with `--proc`).
Those nodes have no render/primary split of their own, so `dri` on the
proprietary driver stays as wide as it was, with or without `kms`.
`dri` sets no environment — `DRI_PRIME`, `__NV_PRIME_RENDER_OFFLOAD` are a
profile's `env` decision. Compute needs `etc-share "OpenCL"` / `etc-share
"nvidia"`; AMD ROCm via `/dev/kfd` is not supported yet.

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
