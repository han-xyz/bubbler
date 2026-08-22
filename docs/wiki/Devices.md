# Devices

Every device grant is emitted only where the host has the thing; a missing
`/dev/nvidia*` or `/dev/video*` binds nothing rather than failing. The
exception is `/dev/uinput`, which is an error when missing.

## dri — GPU

Binds `/dev/dri` read-write, and read-only: `/sys/dev/char`,
`/sys/devices/system/cpu`, every `/sys/devices/pci*` root, `/sys/class/drm`.
That is the sysfs of **every** PCI device, not only the GPU.

NVIDIA: every `/dev/nvidia*` char device and `/sys/module/nvidia*` when
present (`nvidia-caps` skipped; `/proc/driver/nvidia` comes with `--proc`).
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
