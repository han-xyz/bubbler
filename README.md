# bubbler

Application sandboxing on top of [bubblewrap](https://github.com/containers/bubblewrap),
combining bubblejail's explicit instances and resource grants with a profile
library in the spirit of firejail. bubbler itself is unprivileged; `bwrap`
does the namespace work.

Status: milestone 8 — a library of 14 profiles (`alacritty`, `chromium`,
`code`, `firefox`, `generic`, `keepassxc`, `kitty`, `libreoffice`, `lutris`,
`mpv`, `spotify`, `steam`, `thunderbird`, `vesktop`) over GPU, sound, a private
home, host paths through `path-share`, a runtime directory shared between
sandboxes through `app-runtime`, game controllers through `gamepad`, a camera
through the portal, a filtered session and system bus with portals,
notifications and `tray`, a terminal of their own, a network namespace of their
own through pasta and a seccomp filter that covers 32-bit binaries as well as
64-bit. Profiles come in three layers — yours, the system's, built-in — and
compose with `include`. `bubbler lint` measures a profile or an instance config
against what a sandbox is meant to give away, and `--dry-run --explain` puts
every bwrap argument under the node that produced it. See "Known gaps" below.

## Usage

    bubbler create ff --profile firefox   # seed config.kdl from a profile
    bubbler create ff                     # --profile defaults to `generic`
    bubbler profiles                      # profile names, one per line
    bubbler profiles --origin             # and which layer each comes from
    bubbler profile show firefox          # one profile, flattened, layer by layer
    bubbler profile edit firefox          # your copy of it, in $VISUAL or $EDITOR
    bubbler profile lint firefox          # check it for grants wider than it means
    bubbler profile lint --all            # every profile every layer holds
    bubbler lint ff                       # the same checks on an instance's config
    bubbler edit ff                       # open config.kdl, then re-check it
    bubbler reseed ff                     # re-flatten its profile, keeping home/
    bubbler run ff                        # uses `command` from config.kdl
    bubbler run ff -- firefox --version   # or run something else inside
    bubbler run ff --dry-run              # print the bwrap argv, do not launch
    bubbler run ff --explain              # the same argv, grouped under its nodes
    bubbler run ff --tty none             # no terminal inside at all
    bubbler exec ff -- firefox --version  # run inside the instance already running
    bubbler try -- id                     # throwaway sandbox, nothing kept
    bubbler try --profile firefox --grant network -- firefox --version
    bubbler try --keep scratch -- sh      # keep it afterwards as instance `scratch`
    bubbler list
    bubbler delete ff --yes               # instance and private home; irreversible
    bubbler man                           # bubbler(1) as roff, on stdout
    bubbler man --config                  # bubbler-config(5): every node, every check

`create` prints the directory it made. `--dry-run` prints `bwrap` and then one
argv element per line, byte for byte, so it can be diffed; an element
containing a newline would be ambiguous in that framing. It builds the argv
only: nothing is launched and no runtime directory is created. `--explain`
prints the same argv under the node each argument came from (see "Explaining
an argv").

Every sandbox runs under `bubbler-init`, a small supervisor bound in at
`/run/bubbler-init`. It serves a control socket in the instance's runtime
directory, which `exec` connects to; the socket is bound by bubbler and only
handed to the sandbox as an inherited file descriptor, so nothing inside can
reach the path. `run` on an instance that is already running says so and
execs into it instead of starting a second sandbox; configuration changes
apply on the next start. An exec'd process is given whatever the terminal
mode decides on (see "Terminal"), and descriptors passed to exec'd commands
are reachable by the sandboxed application through `/proc`: exec is a
convenience channel, not a boundary.

A run is a chain of processes; `bubbler` waits at the top of it and returns the
command's status.

    bubbler ─┬─ bwrap ── bwrap (pid 1 in the sandbox, reaps orphans)
             │              └─ bubbler-init (pid 2) ── your command
             ├─ bwrap ── bwrap ── xdg-dbus-proxy    (only with `dbus`)
             └─ pasta                               (only with an isolated
                                                     `network`; not sandboxed)

Each `bwrap` leaves a reaper as pid 1 of its own pid namespace. The proxy's
sandbox is a sibling of the app's, started by `bubbler` and invisible from
inside it.

**pasta is the one sidecar bubbler does not wrap.** bubbler starts it as your
user, outside every sandbox, and hands it a descriptor for the sandbox's outer
user namespace, which pasta joins in order to configure the network namespace
that hangs off it. Joining one grants "all capabilities in that namespace,
regardless of its user and group IDs" (`setns(2)`), and a capability in a user
namespace permits privileged operations only "on resources governed by that
namespace" (`user_namespaces(7)`). So a pasta that has been taken over owns the
sandboxed application — it *is* that sandbox's network, and it holds root over
the namespaces the sandbox is built from — and owns nothing beyond what your
own account already has: your uid created that namespace, so the descriptor
hands over no authority you did not have.

Running it under bwrap would not add any: it would *remove* what pasta needs.
bwrap would put pasta in a user namespace of its own, and a process can only
join a *descendant* of the namespace it is in (`setns(2)`) — the sandbox's
namespace would then be a sibling, so pasta could no longer reach the thing it
exists to configure. What it does instead is isolate itself: it `pivot_root()`s
into an empty filesystem "for stricter isolation", and a `pivot_root()` that
fails fails the whole start, since bubbler passes no `--chroot-fallback`
(`pasta(1)`). Measured on a bubbler run on this host, the sidecar also runs
with `NoNewPrivs: 1`, one seccomp filter (`Seccomp: 2`) and a `/proc/<pid>` its
own user may not read — `PR_SET_DUMPABLE` off, which is also why the two paths
bubbler hands it name bubbler's descriptors rather than pasta's own. This is a
recorded decision, not an oversight: the alternative is not a sandboxed pasta
but no isolated network namespace at all.

`try` runs one command in a sandbox without creating an instance. Its config is
the flattened profile (`generic` unless `--profile` says otherwise) plus one
bare node per `--grant`; the grants are `wayland`, `x11`, `network`, `dri`,
`pipewire`, `pulseaudio`, `dbus`, `portals`, `notify`, `tray`, `gamepad`,
`hidraw` and `camera`, and anything with arguments needs a real instance —
`system-bus` among them, since it is not a grant without rules. The bundles are
checked as they are in a config file, so `--grant tray` without `--grant dbus`
is refused rather than silently dropped, and `--grant camera` needs
`--grant portals` (and the `--grant dbus` that carries it) the same way. A
grant the profile already made is not repeated, properties and all:
`--grant gamepad` on a profile carrying `gamepad hidraw=#true` keeps the
`hidraw` node rather than narrowing it to the bare one, and `--grant camera` on
a profile carrying `camera nodes=#true` likewise leaves the device half in
place. The sandbox lives in
`$XDG_DATA_HOME/bubbler/try/<pid>/`, never appears in `list`, and is removed
when the command exits whatever its status; `--keep <name>` renames it into an
instance instead, refusing a name that is taken. Directories left behind by a
killed `bubbler` are swept on the next `try`.

`SIGINT` and `SIGTERM` sent to `bubbler` are passed on once, as `SIGTERM`, to
`bubbler-init` inside the sandbox — bwrap forwards no signals of its own, so
its `--info-fd` is used to find the supervisor. The supervisor signals the
command and every exec'd process, waits five seconds, and `SIGKILL`s whatever
is left; the command's own exit status is what `bubbler` returns. If the
supervisor cannot be found the signal goes to `bwrap` instead, and the sandbox
is torn down by `--die-with-parent`, which is the backstop in any case.

`edit` runs `$VISUAL`, else `$EDITOR`, split on whitespace into an argv with
the config path appended — there is no shell, so quotes and `$VAR` in those
variables are not expanded. A non-zero editor exit is propagated and the file
is left alone; otherwise the config is re-parsed and any error printed, again
without touching the file.

`delete` refuses to do anything without `--yes`. It removes the instance
directory (including its `home/`) and any leftover runtime directory, and
refuses outright if the instance path is a symlink rather than following it.

Instance names are letters, digits, `.`, `_` and `-`; they cannot start with
`-`, cannot be `.` or `..`, and cannot look like `try-<digits>`, which is the
shape `try` gives its own sandboxes and sweeps by pid.

`man` prints roff on stdout, rendered from the command tree this binary was
built with: `bubbler.1` with a subsection for every subcommand, the files a run
reads and writes and the environment it honours, and with `--config` the
`bubbler-config(5)` page — every config node with its grammar, what it grants
and what granting it costs, and every lint check by id — generated from the
same catalogue the rest of bubbler explains grants from. Nothing is written to
disk: a packager redirects it (see "Installing"), and a reader pipes it into
`man -l -`.

## Explaining an argv

`--explain` prints the argv grouped under the node each argument came from. It
implies `--dry-run`: nothing is launched, no runtime directory is made, and the
file descriptor numbers are the ones a dry run prints.

    bubbler run ff --explain               # groups, with the baseline summed up
    bubbler run ff --explain=full          # every argument, the baseline included
    bubbler run ff --explain --proxy       # the D-Bus proxy sidecar's argv instead
    bubbler run ff --explain --format json # one object per operation, nothing elided
    bubbler try --profile firefox --explain

    bwrap

      baseline                                       138 arguments
        --unshare-all
        --die-with-parent
        --new-session
        --hostname bubbler
        --chdir /home/bubbler
        --info-fd 3  (pipe: bwrap reports the sandbox pid on it)
        ... 129 more (--explain=full)

      portals                         config.kdl:11  7 arguments
        --block-fd 4  (pipe: the sandbox waits on it until bubbler lets it go)
        --perms 0644 --ro-bind-data 9 /.flatpak-info  (generated file, 69 bytes)
        rules: --talk=org.freedesktop.portal.Desktop
               --talk=org.freedesktop.portal.Documents
               --talk=org.freedesktop.portal.FileChooser
               --call=org.freedesktop.portal.*=*
               --broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*

      notify                          config.kdl:12  0 arguments
        rule-only: --talk=org.freedesktop.Notifications

      seccomp                                        2 arguments
        --add-seccomp-fd 5  (filter, 896 bytes, x86_64 + i386)

      wayland                         config.kdl:3   9 arguments
        --ro-bind /run/user/1000/wayland-1 /run/user/1000/wayland-1
        --setenv WAYLAND_DISPLAY wayland-1
        --setenv XDG_SESSION_TYPE wayland

      network                         config.kdl:7   5 arguments
        --perms 0644 --ro-bind-data 8 /etc/resolv.conf  (generated file, 23 bytes)
        sidecar: pasta --config-net --foreground --quiet -t none -u none -T none -U none --map-host-loopback none --map-guest-addr none --dns-forward 169.254.1.1 --userns <userns> --pid <ready-fd> <child-pid>

      init                                           7 arguments
        --ro-bind /usr/lib/bubbler/bubbler-init /run/bubbler-init
        -- /run/bubbler-init --socket-fd 10  (socket: the exec channel bubbler-init serves)

      command                                        2 arguments
        -- firefox

    230 arguments in 14 groups, 129 hidden (--explain=full); 8 D-Bus rules to the proxy (--proxy)

A group sits where the node's *first* argument is emitted and gathers every
later one it contributed, whichever phase that came from: `network "host"` is
placed by the `--share-net` inserted into phase 1 and its `/etc/resolv.conf`
bind from phase 4 is listed with it, though the whole baseline separates the two
in the argv. The listing is therefore neither file order nor argv order, and it
is not the order of record: `--dry-run` is, and so is `--format json`, which
stays in true argv order.

A grant that is not only bwrap arguments says so under its own group: a `dbus`
node lists the `rules:` it hands the proxy, and an isolated `network` lists the
`sidecar:` argv pasta is started with — neither is in the argv, and `--dry-run`
prints the sandbox's argv alone.

Every generated descriptor says what is behind it: the size of the seccomp
filter and the architectures it carries, the size of a `--ro-bind-data`, which
pipe an `--info-fd` or `--block-fd` is, and which socket the supervisor is
handed. A node whose grant
is D-Bus rules rather than bwrap arguments lists those rules instead — under
`rule-only:` when it contributes nothing else, `rules:` when it also has
arguments. A `seccomp` node reads the same way, since what it changed is not
an argument either: `rules: allow ptrace` under the filter it did load, and
`rule-only: filter disabled` for a `seccomp { disable }`, which loads none and
would otherwise be missing from the listing altogether.

`--explain --proxy` explains the sidecar's own argv, where those rules are
grouped under the nodes that asked for them and each bus's address, socket and
`--filter` under the node that granted that bus: an `xdg-dbus-proxy` option
applies to the address before it, so the listing reads one bus at a time —
`dbus`, the session-bus rule groups, then `system-bus` and its own. The
sidecar's seccomp group carries no line of the config: its filter is the
default set whatever the instance's `seccomp` node says.

Line numbers are those of the instance's own `config.kdl`, the flattened file
`create` wrote, not of the profile layer a node was written in; under
`bubbler try` they are the throwaway instance's copy. `profile show` is what
prints a node with the layer it came from.

This is a reading format, not a diffing one: it joins the elements of an
operation onto one line and stops listing the baseline after its first arguments
(`--explain=full` lists all of it). `--dry-run` on its own remains the
byte-exact, one-element-per-line form. `--format json` elides nothing; an
argument that is not UTF-8 is written there with the replacement character,
since JSON has no byte strings.

`--explain` attributes, it does not justify: "why is `/etc/ssl` in there" is
answered with "the baseline", and why the baseline holds it is this README's
job.

## Config (KDL)

One top-level node per grant, plus `command`. Unknown nodes are errors, and
file order does not affect the generated argv.

    wayland                          # the host Wayland socket
    x11                              # X socket and Xauthority
    network                          # the sandbox's own network namespace,
                                     #   connected by a pasta sidecar
    network "host"                   # the host's namespace instead
    network "none"                   # no network; the same as no node at all
    network {                        # children; `dns` in any of the three
        dns "1.1.1.1"                #   generated /etc/resolv.conf
        allow-port 8080              #   host 127.0.0.1:8080 reaches the sandbox
        allow-port 5353 udp=#true    #   isolated mode only, like no-ipv6
        no-ipv6
    }
    dri                              # GPU: /dev/dri, NVIDIA nodes, the PCI devices' sysfs
    pipewire                         # $XDG_RUNTIME_DIR/pipewire-0
    pulseaudio                       # $XDG_RUNTIME_DIR/pulse/native, sets PULSE_SERVER
    gamepad                          # /dev/input, and the sysfs that names it
                                     #   hidraw=#true is the `hidraw` grant,
                                     #   uinput=#true adds /dev/uinput
    hidraw                           # every /dev/hidraw* node, /sys/class/hidraw
    camera                           # cameras through the portal; binds nothing
    camera nodes=#true               #   also /dev/video*, /dev/media*, /dev/v4l,
                                     #   their sysfs and /run/udev
    home-share "Downloads"           # $HOME/Downloads at /home/bubbler/Downloads
    home-share "Projects/x" mode=rw
    path-share "/kioxia/Steam"       # a host path, at that same path inside
    path-share "/mnt/data" mode=rw
    etc-share "vulkan"               # /etc/vulkan read-only; one path component
    app-runtime "org.example.App"    # $XDG_RUNTIME_DIR/app/<id>, shared with
                                     #   every sandbox naming that id;
                                     #   mode=rw to serve a socket there
    dbus {                           # session bus through a filtering proxy
        see "org.freedesktop.ScreenSaver"
        talk "ca.desrt.dconf"
        own "org.example.App"
        call "org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.Read@/org/freedesktop/portal/desktop"
        broadcast "org.freedesktop.portal.Desktop=@/org/freedesktop/portal/desktop"
    }
    system-bus {                     # system bus through the same proxy
        talk "org.freedesktop.UPower"
    }
    portals                          # XDG portal rules plus /.flatpak-info
    notify                           # talk to org.freedesktop.Notifications
    tray                             # talk to org.kde.StatusNotifierWatcher
    mpris name="firefox.*"           # own org.mpris.MediaPlayer2.firefox.*
    tty "pty"                        # terminal: "pty", "passthrough" or "none"
    userns "allow"                   # nested user namespaces: "allow" or "disable"
    seccomp {                        # changes to the default syscall denylist
        allow "perf_event_open"
        deny "unshare" errno="EPERM"
        disable
    }
    env MOZ_ENABLE_WAYLAND="1"       # extra variables, KEY="value", repeatable
    lint-allow "x11-without-reason" reason="no Wayland backend"
    desktop "org.mozilla.Thunderbird.desktop"
    command "firefox"

Every source must exist and be of the expected type when the argv is built; a
missing one is an error rather than a silently weaker sandbox. That covers
`home-share` too, so the `firefox` profile needs a `~/Downloads` and `lutris`
a `~/Games`. A `home-share` source is resolved before it is bound and must
stay inside your home directory: a symlink pointing elsewhere is refused, not
followed. One home path may be shared once, whatever the modes, so
`home-share "D"` beside `home-share "D" mode=rw` is an error rather than a
share whose width depends on which line came first; a share below another
(`"D"` and `"D/sub"`) names a different path and stays allowed.
`etc-share` is confined to `/etc` the same way, and cannot name the account
files (`passwd`, `group`, `shadow`, `gshadow` and their `-`/`+` variants),
which the sandbox generates itself. `path-share` reaches outside the home and
has rules of its own, under "Host paths"; `app-runtime`, which shares one
directory under `$XDG_RUNTIME_DIR`, and `network` each have a section of their
own below. `dri` binds `/dev/dri` read-write and exposes `/sys/dev/char`,
`/sys/devices/system/cpu`, every
`/sys/devices/pci*` root and, where the host has it, `/sys/class/drm` (whose
entries are relative symlinks into those roots, so it adds only `version`)
read-only — that is the sysfs attributes of every PCI device on the machine,
not just the GPU. `pipewire` and `pulseaudio` hand the sandbox the session's
audio socket directly, which is capture as well as playback: everything the
session exposes, including the microphone, with no portal in between. An ALSA
client reaches the same server through `/etc/alsa`, which the baseline binds:
those files are where pipewire-alsa defines the `default` PCM, and without them
alsa-lib falls back to a hardware card whose `/dev/snd` nodes no sandbox has.
Only `/etc/alsa` is on the allowlist, not `/etc/asound.conf`, so a system-wide
override of yours does not reach the sandbox; an `.asoundrc` in the private home
does. `/dev/snd` itself is never bound, so an application that opens the
hardware directly still has nothing to open.

`dri` also hands over the proprietary NVIDIA stack where the host has it:
every `/dev/nvidia*` char device with device access, and every
`/sys/module/nvidia*` directory read-only. NVML and libglvnd read
`/sys/module/nvidia/initstate` and fall back to Mesa without it. All of it is
emitted only when it exists — the nodes are made by the setuid
`nvidia-modprobe` a udev rule runs, which a sandbox can never do for itself,
so a node missing at launch stays missing. The `/dev/nvidia-caps` directory
is not bound: those are MIG capability files, which nothing outside MIG reads
(`nvidia-cap1` is root-only, `nvidia-cap2` is world-readable).
`/proc/driver/nvidia` needs no bind, the baseline `--proc` already shows it.
`dri` sets no environment: `DRI_PRIME`, `__NV_PRIME_RENDER_OFFLOAD`,
`__GLX_VENDOR_LIBRARY_NAME` and their kind pick a GPU on a hybrid machine,
which is a profile's `env` decision, not a service's. Compute is one gap:
`/etc/OpenCL` and `/etc/nvidia` are not in the `/etc` allowlist, so OpenCL
needs `etc-share "OpenCL"` and the NVIDIA application profiles need
`etc-share "nvidia"`.

`gamepad` binds `/dev/input` with device access and `/sys/class/input`,
`/sys/devices` and `/run/udev` (when the host has it) read-only, which is
what a controller takes to be found and identified. It is the directory that
is bound, not the nodes in it, so a controller plugged in later shows up
too — though the application has to be watching the directory, which SDL only
does when it can tell it is sandboxed, from the `/.flatpak-info` that
`portals` writes. `/dev/uinput` is never bound: writing to it injects input
into the host session.

That bind is read-write. bwrap has no read-only device bind and flatpak's
`--device=input` takes the same posture, so an application inside can
`EVIOCGRAB` a device away from the session, upload force-feedback effects to
it and remap its keycodes. And `/dev/input` is **every** input device the
machine has, keyboards included; what stops a sandbox from reading yours is
the permissions on the nodes, not bubbler. On Arch `event*` is
`0660 root:input`, and a controller carries an extra ACL for the logged-in
user from udev's `uaccess` tag, so an ordinary user's sandbox opens the
controller and not the keyboard. Any group that owns an input node undoes that — Arch's
`input`, but also vendor groups such as `openrazer` — because the sandbox
keeps the host's supplementary groups, and a keyboard node your user can open
is a keylogger grant. Compare `ls -l /dev/input` with `id` before granting
`gamepad`.

The `/sys` side is wide too. `/sys/devices` is the whole device tree, which
contains `dri`'s PCI roots and much more: DMI vendor, board and BIOS strings
(the serial numbers among them stay root-only), ACPI, platform, thermal and
battery state, the attributes of every block and tty device, and
`/sys/devices/virtual/net/*`, where interface names and live traffic counters
are readable even with no `network` grant. `/run/udev/data` hands over udev's
database, which is the identity of every device on the machine. The wide bind
is emitted after `dri`'s narrower ones, and bwrap takes both.

Raw HID devices are the `hidraw` grant below, which `gamepad hidraw=#true`
is the older spelling of; a config holding both binds them once.

`gamepad uinput=#true` adds `/dev/uinput`, which is how Steam Input creates its
virtual controllers — and how anything creates a virtual keyboard. A sandbox
holding it can type into your session, which is outside the sandbox by design
rather than a hole in it, so every launch prints `bubbler: warning: gamepad
uinput=#true: the sandbox can create virtual input devices and type into your
session`. On Arch the node is `0660 root:root` with a `uaccess` ACL from
Steam's udev rules, which the wiki itself notes lets any logged-in user create
globally available input devices; grant it only to a profile you would trust
with your keyboard. A host whose `/dev/uinput` is missing (the `uinput` module
not loaded) is an error, not a quietly weaker sandbox.

### hidraw

`hidraw` binds every `/dev/hidraw*` node the host has when the sandbox starts,
with device access, plus `/sys/class/hidraw` read-only where the host has it.
Those are the raw HID interfaces: a FIDO security key, a hardware wallet, a 3D
mouse, and the controllers SDL's hidapi backend drives — without them SDL falls
back to evdev, which `SDL_JOYSTICK_HIDAPI=0` also forces. `gamepad
hidraw=#true` is the same grant written the older way, and a config with both
nodes binds the devices once. Unlike `gamepad` it hands over no `/dev/input`,
so an application that speaks to a FIDO key or a hardware wallet is not handed
every keyboard on the machine as well.

There is no `/dev/hidraw` directory to bind, so unlike `/dev/input` this list is
frozen at launch: a device plugged in afterwards has no hidraw node inside
until the instance is restarted. A key plugged in on demand is the common case,
so that, and not the permission surface, is the real cost of the grant.

The glob is **every** HID device on the machine, not the one you meant: on this
host `/dev/hidraw0` is a keyboard. What stops a sandbox from using one is the
permissions on the node. Arch's stock `70-uaccess.rules` hands the logged-in
user an ACL on security tokens (FIDO/U2F, `ID_SECURITY_TOKEN`), hardware
wallets, 3D mice and AV control devices, and Steam's `60-steam-input.rules`
adds one per supported controller — so a sandbox with `hidraw` can speak to
your security key or your hardware wallet whenever one is plugged in. Compare
`ls -l /dev/hidraw*` and `getfacl /dev/hidraw*` with `id` before granting it.

### camera

`camera` grants cameras through `org.freedesktop.portal.Camera`, and binds
nothing at all. The portal opens `/dev/videoN` in the host's PipeWire daemon
and hands the sandbox an already-connected socket over the bus; frames come
back as memfds. So the sandbox needs no device node, no `/sys` bind and no
`pipewire` grant — only the `portals` the node requires, which is why `camera`
without `portals` is a parse error rather than a warning.

That requirement is not bookkeeping. `xdg-desktop-portal` decides camera access
from a permission store keyed by the app id it reads out of `/.flatpak-info`,
which is the file `portals` writes. With one, each instance holds its own
revocable permission under `org.bubbler.<instance>`; without one the caller has
no app id at all and falls into the blanket entry that every unsandboxed
process on the machine shares. `--explain` shows the grant as a rule-only line,
since the whole of it is on the bus rather than in the argv.

Two host-side conditions apply and neither is bubbler's to fix: the portal
needs an `org.freedesktop.impl.portal.Access` backend, which
`xdg-desktop-portal-gtk` and `-kde` provide and `xdg-desktop-portal-hyprland`
alone does not, and MIPI/libcamera cameras need `pipewire-libcamera`.

Applications opt in too. Firefox reads the portal behind
`media.webrtc.camera.allow-pipewire`, which is false by default and only read
at startup; Chromium behind `chrome://flags/#enable-webrtc-pipewire-camera`,
also off by default — not to be confused with the screen-sharing
`enable-webrtc-pipewire-capturer`, which is already on. OBS ships a
"Camera (PipeWire)" source. Plain V4L2 consumers — mpv, ffmpeg, VLC,
`v4l2-ctl`, Cheese, OBS's classic source — will never speak it.

`camera nodes=#true` is for those. It also binds every `/dev/video*` and
`/dev/media*` character device the host has at launch with device access, and
`/dev/v4l`, `/sys/class/video4linux`, `/sys/bus/media` and `/run/udev`
read-only where the host has them. Each is emitted only where it exists, so the
property adds nothing on a machine with no camera rather than failing the
launch. The media nodes are bound beside the video ones because a UVC camera's
controls are a media controller device; `/dev/v4l/by-id` and `by-path` are the
persistent names udev writes, as relative symlinks (`../../video0`) onto the
nodes bound above, so they resolve inside. `/run/udev` is bound once even when
`gamepad` asks for it too. The two paths reach the same devices — a
v4l2loopback or OBS virtual camera among them, since Arch's `70-uaccess.rules`
keys on the `video4linux` and `media` subsystems and nothing further — but the
portal is strictly the narrower of the two.

Permissions on the nodes are what stop a sandbox from opening one: `/dev/video*`
is `0660 root:video`, plus an ACL for the logged-in user from that `uaccess`
tag. On a seat with no `uaccess` — a headless machine, a session logind does
not own — the grant produces a node the sandbox cannot read.

The device list is frozen at launch: there is no `/dev/video` directory to bind
instead, so a camera plugged in later has no node inside, and with a network
namespace of its own the sandbox is not told about one either — the udev
monitor is a netlink socket, and its notifications do not cross a network
namespace. `/run/udev/data` still names the devices that were there when the
sandbox started. The portal path has neither problem: the watching happens in
the host daemon, and node changes arrive as traffic on the socket it already
handed over.

The `/sys` half is names, not a working sysfs. Both
`/sys/class/video4linux/videoN` and the entries under `/sys/bus/media` are
relative symlinks into `/sys/devices`, which this grant does **not** bind — nor
`/sys/dev/char`, which libudev resolves a device number through. Those are
`gamepad`'s and `dri`'s wide binds and no part of a camera grant, so anything
that enumerates through sysfs — libudev, and therefore GStreamer's
`v4l2src`/device monitor and the pickers built on it — finds nothing inside and
shows no device. What does work is opening `/dev/videoN` (or a `/dev/v4l/by-id`
name) directly, which is what mpv, ffmpeg and `v4l2-ctl` do. If a libudev
consumer has to work, add `gamepad` or `dri` for the tree it reads, and know
what those grants cost — or use the portal, which needs none of it.

**Neither path has been tested against a real camera.** The machine bubbler is
developed on has none, so the portal call, the PipeWire fd crossing
`xdg-dbus-proxy` and the device binds have unit and argv coverage and no frame
has ever come through. Treat `camera` as untested on real hardware.
### app-runtime

`app-runtime "<id>" [mode=rw]` shares `$XDG_RUNTIME_DIR/app/<id>` — **the same
path on the host and inside every sandbox that names the id**. That is the
directory applications already serve their own sockets in: a stock KeePassXC
puts `org.keepassxc.KeePassXC.BrowserServer` in
`$XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC` whether or not flatpak is
installed, and computes that path from `$XDG_RUNTIME_DIR` at both ends. So a
sandboxed KeePassXC and a browser — in its own instance or on the host — meet
there:

    # keepassxc's config.kdl (the built-in profile ships this)
    app-runtime "org.keepassxc.KeePassXC" mode=rw
    # the browser's, on the other side
    app-runtime "org.keepassxc.KeePassXC"

Only the leaf `app/<id>` is ever bound, never `app/` itself and never
`$XDG_RUNTIME_DIR`, which is where every instance's control socket lives.
bubbler creates the directory before the sandbox starts, never the sandbox, and
opens it `O_NOFOLLOW` to refuse a symlink planted where it belongs; a directory
that is already there is reused whatever its mode, because a native application
creates it 0755 and `$XDG_RUNTIME_DIR` itself is 0700. It is not removed when
the run ends: it is a rendezvous, and another instance's peer may still be
serving in it.

The id is an application id — at least two `.`-separated elements of letters,
digits and `_`, with `-` allowed in the last — which is both the convention
every consumer follows and the reason an id can never name `bubbler`, `..` or a
path with a `/` in it. The node is repeatable, and one id may be granted once
per config.

`ro` is the default and is what a client wants: `connect()` works through a
read-only bind, so a sandbox that only talks to a socket needs no write access.
`mode=rw` is for the side that *serves*, and it is a real grant — that sandbox
can unlink the socket others connect to and bind its own, or leave a symlink
that the peer then resolves on its own side of the boundary. `bubbler lint`
notes it as `app-runtime-rw`.

Four things this does not give you:

- **No peer authentication.** `SO_PEERCRED` reports pid 0 across the boundary
  (there is no such pid in the reader's namespace) and the uid is yours on both
  sides, so a server cannot tell its peers apart. KeePassXC's own
  associate/identification keys are what authenticate a browser; a protocol
  with no such layer has none.
- **One id is one trust domain.** Every instance granted the same id, and every
  unsandboxed process of yours, can read, write, replace and delete everything
  in that directory. There is no way to make a rendezvous only the "right"
  sandboxes can reach — the name *is* the rendezvous.
- **Not Discord rich presence.** Discord's clients look for `discord-ipc-N` at
  the top of `$XDG_RUNTIME_DIR`, not under `app/`, so this does not carry it.
- **Do not point `TMPDIR` at it.** Everything the application writes would
  become something a co-tenant of the id can replace or redirect.

#### KeePassXC-Browser, both sides under bubbler

The grant carries the socket; the browser still has to be told about the proxy
that speaks to it. That is one file, and nothing in bubbler writes it for you,
because KeePassXC's own installer writes into *its* private home rather than
the browser's.

Grant the id on both sides — `keepassxc` ships
`app-runtime "org.keepassxc.KeePassXC" mode=rw` already, and `firefox` and
`chromium` carry the read-only line commented out, so uncomment it (or run
`bubbler edit firefox` and add it):

    app-runtime "org.keepassxc.KeePassXC"

Then put the native messaging manifest in the browser instance's private home,
which is an ordinary host directory —
`$XDG_DATA_HOME/bubbler/instances/<name>/home/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json`
for Firefox, `…/home/.config/chromium/NativeMessagingHosts/` for Chromium:

    {
        "allowed_extensions": ["keepassxc-browser@keepassxc.org"],
        "description": "KeePassXC integration with native messaging support",
        "name": "org.keepassxc.keepassxc_browser",
        "path": "/usr/bin/keepassxc-proxy",
        "type": "stdio"
    }

`path` must be absolute and `type` must be `"stdio"`; `/usr/bin/keepassxc-proxy`
is a normal distribution file, and since `/usr` is read-only bound into every
sandbox the browser can already execute it. If KeePassXC's own "browser
integration" installer has run on the host, that file is already at
`~/.mozilla/native-messaging-hosts/` and can simply be copied. The flatpak
wrapper script the manifest names in a flatpak install is not used here.

One file under `/usr/lib/mozilla/native-messaging-hosts/` (or
`/usr/lib64/…`) is Firefox's documented system-wide location and serves every
instance and the host browser at once, at the cost of needing root; bubbler
never writes there.

### network

`network` is the sandbox's **own** network namespace, connected to the outside
by a [pasta](https://passt.top/) sidecar — the `passt` package, which is also
what podman uses for rootless networking. `network "host"` is the host's
namespace, which is what a bare `network` meant before this; `network "none"`
is the baseline, spelled out.

What the isolated namespace is worth is what the host one gives away. Measured
against a host serving on `127.0.0.1:8099`: a sandbox on the host namespace
reads it, one with its own namespace cannot reach it at all. The same holds for
**abstract** unix sockets, which `network_namespaces(7)` isolates and which
have no permission checks at all — flatpak documents that hole and has never
closed it. The host namespace also hands over the host's interfaces, addresses,
VPN tunnels and its whole listening-socket table.

It is not a firewall, though. pasta routes, so a host service bound to
`0.0.0.0` on an address pasta did not copy into the namespace — a VPN endpoint,
`docker0`, a second NIC — is reachable from inside exactly as it is from any
other machine on that network. What the isolated namespace closes is the
host's *loopback* and its abstract sockets, not everything the host listens on.

What it costs is the LAN. pasta does not bridge, so nothing that depends on
broadcast or mDNS crosses the boundary: Chromecast, Spotify Connect, Steam
Remote Play and local game discovery all need `network "host"`. Nor is a
service on the host's own `127.0.0.1` — a dev server, say — reachable from
inside. The shipped profiles that lose something say so in a comment.

bubbler starts pasta with the same six values on every run, and they are not
configurable:

    pasta --config-net --foreground --quiet \
          -t <ports|none> -u <ports|none> -T none -U none \
          --map-host-loopback none --map-guest-addr none \
          [--dns-forward 169.254.1.1] [-4] \
          --userns <the sandbox's> --pid <a pipe> <the sandbox's pid>

pasta's own defaults are `-t auto -u auto -T auto -U auto`, with
`--map-host-loopback` set to the guest's gateway and `--map-guest-addr` to the
host's global address. In `auto` mode it scans `/proc/net/{tcp,tcp6,udp,udp6}`
on both sides and publishes what it finds — discarding the bound address, so a
service the sandbox binds to its *own* `127.0.0.1` would be published on the
host's public address — and the two `--map-*` defaults put the host's loopback
services back inside the sandbox that unshared the network to be rid of them.
Ship the naive invocation and the isolated mode would be worse than the host
one in a dimension it was meant to be better in. `--foreground` is there for a
different reason: a backgrounded pasta is not bubbler's child, and could not be
killed when the run ends.

`allow-port <n>` is the one thing that reaches *in*: the port is published on
the host's `127.0.0.1` only, never on the LAN, and `udp=#true` makes it a UDP
forward rather than a TCP one. pasta delivers such a connection to the
namespace's public address, so the server inside must listen on `0.0.0.0` and
not on its own loopback. `no-ipv6` is pasta's `-4`.

**Outbound traffic is all or nothing.** pasta has no destination filtering and
the passt project has no plans for any, so there is no `allow-host` here and
nothing pretending to be one. A future version could install nftables rules in
the sandbox's own namespace from the launcher side — the sandbox itself could
not flush them — but a host allowlist by name breaks on every CDN, so it would
be an address policy and not a name one.

`/etc/resolv.conf` is **generated**, not bound: an isolated namespace can never
reach a resolver on the host's loopback, which is exactly what the host file
names on a systemd-resolved machine (`127.0.0.53`). Without `dns` children the
file reads `nameserver 169.254.1.1` and pasta is given the matching
`--dns-forward`, which translates that link-local address to the host's own
first nameserver; the address cannot be a loopback one, pasta refuses that
outright. `dns "<ip>"` replaces the list and drops the `--dns-forward` with it:
a named resolver is reached over the tap like any other address, and a
translation rule nothing points at is one more route to the host for no gain.
For the same reason `dns` may not name a loopback address under the isolated
mode — that is the sandbox's own loopback, not the host's — and the parser
refuses it; under `network "host"` a stub resolver there is the normal case and
is accepted. Under `network "none"` a `dns` child is refused outright: there is
no network to carry the query, so it would name a resolver nothing in the
sandbox could reach. Only `network "host"` with no `dns` child binds the host's
own `/etc/resolv.conf`, which is what it always did.

pasta is a hard requirement of the isolated mode, not a preference: a private
namespace with connectivity has no other unprivileged route (a veth pair needs
`CAP_NET_ADMIN` in the initial user namespace, which is real root). A missing
`pasta` is an error naming the `passt` package and `network "host"`, never a
quiet fall back to the host namespace — which would undo the whole grant. It is
the one sidecar bubbler does not wrap in a sandbox of its own; what that means
for the trust boundary is under "A run is a chain of processes" above. The
sidecar is killed on every way out of a run, and a sandbox whose namespace
cannot be connected is stopped where it stands rather than started without the
network it was granted: it waits at bwrap's `--block-fd` until pasta reports
that the namespace is configured.

Two things are checked around that. Before pasta is started, bubbler compares
the network namespace of the pid bwrap reported with its own: a sandbox that
died in between leaves that pid to be handed out again, and pasta would then
configure the network namespace of whatever holds it now — the host's. Equal
namespaces stop the run instead. And a pasta that dies *during* a run is
reported once, as `pasta exited (<status>); the sandbox has lost its network`;
the application keeps running without one, since a lost network is no reason to
throw away what it has not written out yet.

A config written before this — one with no `// bubbler config: 2` header line
and a bare `network` node — asks for a different sandbox now than it did then,
so every run of it prints a warning naming the change and both ways out of it.
`bubbler reseed <name>` writes the config again from its profile and stamps the
header; `bubbler edit <name>` keeps whatever was written by hand and stamps the
header too, since a file you have just read through means what it says.

### env, command and desktop

`env` keys must look like `[A-Za-z_][A-Za-z0-9_]*`, and each key may appear
only once. `env` values and `command` arguments may not contain NUL, a newline
or a carriage return — a newline would forge a line in `--dry-run` output. The
variables the sandbox owns are rejected: `HOME`, `PATH`, `XDG_RUNTIME_DIR`,
`USER`, `LOGNAME`, `WAYLAND_DISPLAY`, `DISPLAY`, `XAUTHORITY`,
`XDG_SESSION_TYPE`, `PULSE_SERVER`, `DBUS_SESSION_BUS_ADDRESS`,
`DBUS_SYSTEM_BUS_ADDRESS`.

`desktop "<name>.desktop"` names the desktop entry `bubbler desktop` copies an
instance's menu entry from. It grants nothing and nothing at launch reads it:
it is there for the applications whose vendor entry is not named after their
command, where the lookup would otherwise have to guess — `thunderbird` ships
`org.mozilla.Thunderbird.desktop`, `keepassxc` ships
`org.keepassxc.KeePassXC.desktop`. The value is a file name and not a path,
since the entry is looked up in the usual application directories, and a
profile may carry it like any other node.

## Host paths

`path-share "<absolute path>" [mode=rw]` binds a host path outside your home at
that same path inside the sandbox: `/kioxia/Steam` stays `/kioxia/Steam`, and
bwrap creates the directories above it. The node is repeatable, read-only
unless `mode=rw`, and a whole mountpoint is a fine target.

The path is resolved before anything is bound, and it must be a directory or a
regular file. Neither end of the share may touch a path the sandbox is built
out of — not what it resolves to, and not the path it is bound at, which differ
when what you wrote is a symlink. Those paths are `/`, `/proc`, `/sys`, `/dev`,
`/etc`, `/usr`, `/opt`, `/home`, your home directory, `/tmp`, `/var`, `/run`,
`$XDG_RUNTIME_DIR`, `$XDG_DATA_HOME/bubbler` where the instances live, and
`/home/bubbler`, the private home, on the side that is bound at. Being one of
them, being inside one, or containing one is refused, and the error names the
root that stopped it. So a share of `/kioxia` is refused if `$XDG_DATA_HOME` is
on that disk: a sandbox that can write another instance's `config.kdl` grants
itself anything on the next run. All three roots your environment names — your
home, `$XDG_RUNTIME_DIR` and the instance store `$XDG_DATA_HOME/bubbler`, the
store itself as well as the directory above it — are compared both as written
and as resolved, so a symlinked home or a symlinked instance store cannot be
shared under its real name either. `/etc` and your home have typed grants of
their own (`etc-share`, `home-share`), and the rest of that list is what the
baseline replaces. The one carve-out is `/run/media` and everything
under it, where udisks mounts removable media — though not when your instances
live there. `/mnt`, `/media`, `/srv` and top-level mountpoints of your own are
allowed.

Resolving first is also what stops a symlink from smuggling a denied directory
in: `path-share "/mnt/link"` with `/mnt/link -> /etc` is refused naming `/etc`.
The flip side is that what gets bound is the link's target under the name you
wrote, so the sandbox sees a directory where the host has a symlink.

Two `path-share`s may not overlap. Where the paths as written nest, bwrap
applies binds in the order it is given them, so one of them would either fail
outright or silently hide the other depending on that order; refusing keeps
file order irrelevant. Where only the resolved sources overlap — two names for
one host tree, bound at unrelated places — bwrap would accept it, and bubbler
refuses it anyway so that one host tree has one place inside the sandbox.

`$BUBBLER_TEST_ALLOW_PATH=<dir>` adds one more allowed root; it must be
absolute and cannot be `/`. It exists so tests can share a temporary directory
under the otherwise denied `/tmp`. It adds a root rather than switching the
denylist off, and it cannot lift the ones your environment names: your home,
`$XDG_RUNTIME_DIR` and the instance directory stay refused.

## Profiles

A profile seeds a new instance's `config.kdl`. It is the same KDL as an
instance config, with one node an instance config may not use: `include`.
Profiles come from three layers, and the first that holds the name wins:

    $XDG_CONFIG_HOME/bubbler/profiles/<name>.kdl   # yours
    /usr/share/bubbler/profiles/<name>.kdl         # the system's
    built-in                                       # compiled into bubbler

`$BUBBLER_PROFILE_DIR` replaces the middle directory. A layer that does not
parse is an error naming the file — bubbler never falls through to a looser
layer below it. Profile names use the instance name grammar
(`[A-Za-z0-9._-]+`, not `.` or `..`, not starting with `-`), so no name can
reach a file outside those two directories.

    bubbler profiles            # every name from every layer, deduplicated
    bubbler profiles --origin   # name<TAB>user|system|built-in<TAB>path or -

`include "<name>"` layers another profile underneath this one:

    // ~/.config/bubbler/profiles/firefox.kdl
    include "firefox"           // the layer below: the built-in firefox
    home-share "Pictures"
    env MOZ_ENABLE_WAYLAND="0"

`include "<own name>"` resolves at the *next layer down*, which is how a
profile of yours extends the shipped one instead of forking it; in the last
layer that holds the name there is nothing below it, and that is an error.
Includes may nest 8 deep, they resolve depth first before the including
file's own nodes, and a chain that comes back to a file it already read is an
error naming the chain. A layer that two includes both reach is read and
merged once, where it is first reached, so a diamond grants exactly what a
single chain through it would.

Merging is by node: grants are unioned, identical share nodes collapse, and
the same `home-share` or `path-share` path in two modes is an error rather
than a silent choice of `ro` or `rw`. `command`, `tty`, `userns` and `mpris`
from the including file replace the included one — so a layer can relax a
`userns "disable"` below it, the way it decides the terminal — `env` replaces
by key, `gamepad`'s `hidraw` and `uinput` are unioned one property at a time
rather than the last layer deciding both, `dbus` and `system-bus` rules and
`seccomp` lists are unioned, and `seccomp { disable }` in any layer disables
the filter. One bus name may not end up with two policies — `talk` in one
layer and `see` in another — which is an error naming the name, as it is
inside a single node. `portals`, `notify`, `tray` and `mpris` need `dbus` in
the merged result, not in every layer, so a layer may add `notify` to a
`dbus` it includes.

`create` and `try` write the flattened result, so `config.kdl` is one screen
that says everything the sandbox will be granted. Flattening keeps no
comments, so a profile that grants nothing — `generic` — is seeded as the
same commented examples it is written with, and `bubbler edit` on a fresh
instance has something to start from. The first line records where the
instance came from:

    // bubbler profile: firefox

Editing an instance never edits the profile, and editing a profile never
changes an instance that was already seeded from it.

### Built-in profiles

Every one is Wayland-first; only the two gaming profiles grant `x11`.
`~/name` below is a `home-share`, read-only unless it says `rw`.

    alacritty     wayland
    chromium      wayland dri pipewire network dbus portals notify, ~/Downloads rw
    code          wayland dri network dbus portals notify, ~/Projects rw
    firefox       wayland dri pipewire pulseaudio network dbus portals notify mpris, ~/Downloads rw
    generic       nothing beyond the baseline
    keepassxc     wayland dbus portals notify tray app-runtime rw, ~/Documents rw
    kitty         wayland dri dbus portals notify
    libreoffice   wayland dri dbus portals, ~/Documents rw, SAL_USE_VCLPLUGIN=gtk3
    lutris        wayland x11 dri pipewire network dbus portals notify tray gamepad system-bus, ~/Games rw
    mpv           wayland dri pipewire, ~/Videos
    spotify       wayland dri pipewire network dbus notify tray mpris
    steam         wayland x11 dri pipewire network dbus notify tray gamepad system-bus
    thunderbird   wayland network dri dbus portals notify, ~/Downloads rw
    vesktop       wayland dri pipewire network dbus portals notify tray, ~/Downloads rw

`SAL_USE_VCLPLUGIN=gtk3` is there because bubbler clears the environment,
leaving LibreOffice's VCL plugin to an autodetection with nothing to go on.
The Mozilla apps need no variable of their own: Gecko has defaulted to Wayland
since Firefox 121 and takes it from the `WAYLAND_DISPLAY` the `wayland` grant
sets, so `MOZ_ENABLE_WAYLAND=1` is gone from both profiles — write
`env MOZ_ENABLE_WAYLAND="0"` to go back to Xwayland. `firefox` owns
`org.mozilla.firefox.*` instead, which is the remote-instance protocol a
second `firefox` reaches the running one through.

`chromium`, `code` and `vesktop` keep their own namespace sandbox: it nests
inside bubbler's, so none of them needs `--no-sandbox`. Where a package ships a
setuid `chrome-sandbox` helper the namespace path is taken instead of it; Arch's
`code` ships that helper without the setuid bit at all, so it never had another
path. On a kernel with unprivileged user namespaces turned off, that nesting is
what breaks first. None of the
three may carry `userns "disable"`, and none of them needs an ozone hint:
Electron picks the Wayland backend on its own, and Arch's `vesktop` wrapper
sets the variable anyway.

`keepassxc` is the one profile written mostly out of what it does **not**
grant, and each omission is a comment in the profile saying how to add it back.
No `network`: a database opens without one, and the grant is your password
manager's process reaching the internet. No `own "org.freedesktop.secrets"`:
that name makes the sandbox the Secret Service for the whole session, so every
libsecret client in it — `code` among them, which is granted `talk` on that
same name — would store its secrets there. It is an outward grant rather than a
confinement. No `hidraw`, which would not help anyway: KeePassXC drives a
YubiKey through libusb and a smart card through pcsclite, and bubbler grants
neither. Browser integration does work: the profile grants
`app-runtime "org.keepassxc.KeePassXC" mode=rw` so the socket it serves is
reachable from the host or from another instance — `firefox` and `chromium`
carry the matching read-only line commented out. Installing the native
messaging manifest is still yours to do; "KeePassXC-Browser, both sides under
bubbler" under "app-runtime" is the whole procedure.

`spotify` owns `org.mpris.MediaPlayer2.spotify` exactly, not as a prefix, and
its tray icon is the same one-rule `tray` grant as everywhere else. It has no
`portals`, because there is no file chooser to speak of; add `portals` and a
`home-share "Music"` for local files. `kitty` needs no grant for the
pseudoterminals it makes: `--dev` gives each sandbox a private devpts instance
with an index space of its own, and the host's `/dev/pts` is never bound. Its
`dbus` and `portals` are what the `org.freedesktop.portal.Settings` read takes,
without which it cannot follow the desktop colour scheme. Never share kitty's
remote-control socket across the boundary — `kitten @` includes `launch`, so a
reachable socket is command execution in whichever direction it was shared.

`steam` and `lutris` are the two that grant `x11`, and that is the weak point
of both: X11 has no isolation between clients, so a sandbox on your display can
keylog every other client on it, Xwayland included. They have it because Steam's
UI (steamwebhelper) is an X11/CEF client with no Wayland support and because
Wine's X11 driver takes precedence over its Wayland one for every game Lutris
starts. Neither carries a `seccomp` node any more: the Steam runtime,
umu/Proton and DXVK's 32-bit path are i386, and the default filter now covers
i386 alongside x86_64, so they are filtered rather than killed. Neither
may ever carry `userns "disable"` — pressure-vessel nests its own bubblewrap for
every Proton game. On the system bus `steam` talks to UPower, and both grant
UDisks2 enumeration alone — `see` plus the one `GetManagedObjects` call Wine
builds its drive list from — because a `talk` there would also hand the
sandbox loop setup, mount and LUKS unlock, which polkit judges as you; widen
it yourself if a game needs more.
`/dev/hugepages`, `/dev/fuse` and `/dev/snd` are still not bound.

`steam` is also the one profile with no `portals`, and that is not an
oversight: the grant writes `/.flatpak-info`, Steam's own runtime reads that
file as "I am the unofficial Steam Flatpak", and
`steam-runtime-check-requirements` then exits 71 demanding the flatpak-portal
service, which stops `steam.sh` before the client starts. Steam has its own
file browser, so what it costs is the screencast and file-chooser portals.
`lutris` keeps `portals` because Lutris itself calls them, but a Proton or umu
game brings the same steam-runtime-tools along, so drop the grant there too if
one stops with a Flatpak complaint.

`steam` does not share the host's `~/.steam`. That is not a data directory but
seven absolute symlinks into the host home, which dangle inside a sandbox whose
home is `/home/bubbler` and which leak the account name the synthetic
`/etc/passwd` exists to hide. Steam builds its own on first run; an existing
install is moved into the instance's private home instead, with the instance
stopped:

    mv ~/.local/share/Steam ~/.local/share/bubbler/instances/steam/home/.local/share/

A library folder outside the private home needs a `path-share` of its own,
which both profiles carry as a commented example to edit. Steam Input's virtual
controllers take `gamepad hidraw=#true uinput=#true` on top of the profile —
read what those two properties grant under "Config" first: `uinput` lets the
sandbox type into your session, and `hidraw` hands it every HID device on the
machine, security keys and hardware wallets among them.

Opening an arbitrary file from inside — LibreOffice's or Thunderbird's file
chooser — goes through the portal, and the path it hands back today is one
bubbler cannot mount (see "Known gaps").

### Managing profiles and instances

    bubbler profile show firefox   # the flattened profile, layer by layer
    bubbler profile edit firefox   # your copy of it, in $VISUAL or $EDITOR
    bubbler profile lint firefox   # check it, see "Linting"
    bubbler reseed ff              # re-flatten ff's profile into its config

`profile show` prints the nodes `create` would seed, each run of them under a
`// from:` comment naming the file it came from, or `built-in` for one
compiled in:

    // bubbler profile: app
    // from: /usr/share/bubbler/profiles/base.kdl
    wayland
    // from: /home/you/.config/bubbler/profiles/app.kdl
    network

It shows the flattening, not the file, so the comments a profile is written
with are not in it: a profile that grants nothing — `generic` — is its header
and nothing else, where `create` seeds the instance with commented examples
to start from.

A `dbus` or `seccomp` block is one node in the flattened result even when
several layers wrote into it, so its `// from:` names the last layer that
contributed to it, not every layer whose rules are in it.

`profile edit` opens `$XDG_CONFIG_HOME/bubbler/profiles/<name>.kdl`, creating
the directory if it is missing, under the same editor rules as `edit`. A name
your layer does not hold yet is written first: `include "<name>"` when a lower
layer has that name, so your copy extends the shipped profile instead of
forking it, and commented examples when no layer does. A profile that is
already there is opened as it is. When the editor exits 0 the profile is
resolved again and any error printed; the file is kept as you saved it either
way.

`reseed` re-flattens the profile named in the first line of an instance's
`config.kdl` and writes it back, keeping the private `home/` — it is how an
existing instance picks up a profile you have since edited. It replaces the
whole config rather than merging into it: grants you added by hand, and the
ones `try --keep --grant` wrote in, are dropped, because the profile is the
only thing being flattened. The file it replaces is kept beside it as
`config.kdl.bak`, overwriting an older backup, so a reseed that dropped an
edit of yours can be undone. The new config is written to a sibling file and
renamed over the old one, so an interrupted reseed leaves the config it
started from rather than half of a new one. A config without the
`// bubbler profile: <name>` header names no profile to reseed from, and that
is an error. It refuses while the instance is running: that sandbox was built
from the file as it stands, bwrap cannot be told about a bind after the fact,
and a `config.kdl` describing grants the running sandbox does not have would
be a lie about what is confined.

## Linting

    bubbler profile lint firefox           # one profile, flattened through its layers
    bubbler profile lint --all             # every name any layer holds
    bubbler lint ff                        # an instance's own config.kdl
    bubbler profile lint --all --deny warnings --format json

`lint` reads what a file grants and measures it against what a sandbox is
meant to give away. It never launches anything and never edits a file.
Findings come out in the shape an editor's error parser already reads, with an
indented `help:` line carrying the fix:

    /home/you/.config/bubbler/profiles/app.kdl:3:1: warning[own-too-wide]: `own "org.*"` claims every well-known name under `org.`
      help: name the application itself, e.g. `own "org.example.App.*"`
    built-in:mpv: note[command-not-found]: `mpv` is not on this host's PATH
      help: a profile may be written for software you have not installed; otherwise fix the `command` node

    2 layers linted, 0 errors, 1 warning, 1 note

Spans come from the file, not from the flattened profile, so a finding names
the layer that has to change even when the grant is three `include`s deep. A
built-in layer has no path, so it reports as `built-in:<name>` with no line.
`--format json` prints one object per finding — `{file, line, col, severity,
check, message, help}` — and a summary object, for a tool that should not have
to parse text.

Exit codes: 0 clean (notes are fine), 1 warnings, 2 errors, 3 the lint could
not be run at all — a layer that does not parse, a file that cannot be read, a
name no layer holds. `--deny warnings` turns 1 into 2 for CI. "Does not parse"
is deliberately a different code from "grants too much".

**Errors** say the file will not do what it says: `bundle-without-dbus` (a
`portals`/`notify`/`tray`/`mpris` bundle no layer gives a `dbus` to carry),
`path-share-reserved` (a root bubbler never shares),
`dup-name-policy` (one bus name given two policies by two layers),
`own-on-system-bus`, `camera-without-portals` (a `camera` grant no layer gives
a `portals` to carry, so the portal reads the sandbox as an ordinary process
of yours).

**Warnings** say the file grants more than it probably means to:
`x11-without-reason`, `seccomp-disabled`, `userns-disabled-with-nested-sandbox`
(`userns "disable"` under a command known to nest a sandbox of its own — the
list of such commands is a heuristic), `own-too-wide` (an `own` ending in `*`
with fewer than three name elements before it, so `org.kde.*` warns and
`org.mozilla.firefox.*` does not), `mpris-wildcard`, `system-bus-polkit-name`
(a `talk` on a system service whose privileged actions polkit judges as you),
`home-share-sensitive` (`.ssh`, `.gnupg`, `.pki`, `.password-store`,
`.local/share/keyrings` and `.mozilla`, those four with everything under them,
and `.config`, `.local`, `.local/share` and `.cache` whole — a share of one
application's own directory under those is what a profile is for),
`path-share-mountpoint` (a whole mounted filesystem, `mode=rw`),
`path-share-socket` (a socket, or the directory one sits in — a shared control
socket is command execution across the boundary), `share-source-missing` (a
`home-share`, `path-share` or `etc-share` source this host does not have, or
has as something other than a directory or a regular file — a profile is
written for a host that has the directory, and the launcher refuses the run
outright rather than skipping the bind), `dbus-without-rules`,
`env-looks-secret` (an underscore-separated word of the name is `TOKEN`,
`SECRET`, `PASSWORD`, `APIKEY`, `PAT` and the like, or the value starts
`ghp_`/`sk-`/`AKIA` — whole words, so `TOKENIZERS_PARALLELISM` is not one),
`tty-passthrough`, `portal-talk-without-portals` (a portal rule is inert
without `/.flatpak-info`, which is worse than wrong).

**Notes** are information and fail nothing: `app-runtime-rw` (a shared
application runtime directory granted `mode=rw`, so the sandbox can replace the
sockets everything else naming that id connects to), `network-host`
(`network "host"`, the one mode that puts the sandbox on the host's network
stack), `ozone-hint-unnecessary`,
`command-not-found`, `camera-nodes-none-present` (`camera nodes=#true` on a
host with no `/dev/video*` or `/dev/media*`, so that half of the grant binds
nothing), `camera-nodes-no-hotplug` (the node list is frozen at launch, and
under an isolated network namespace no uevent reaches the sandbox either —
that second half is dropped under `network "host"`), `secrets-access`
(`talk`/`own` of
`org.freedesktop.secrets` on the session bus reaches the whole login keyring:
the Secret Service API partitions nothing between the applications that call
it), `lint-allow-unused` (a `lint-allow` node that accepts nothing, which is a
suppression outliving what it was written for — and the one check no
`lint-allow` silences, since that node would be the unused one).

A warning or a note is accepted with a `lint-allow` node, which takes a check
id and a required reason:

    x11
    lint-allow "x11-without-reason" reason="steamwebhelper is an X11/CEF client"

The node holds for the whole flattened profile, not for one line, and a
`lint-allow` in your layer accepts a finding about a built-in one. An id no
check has is a parse error, so a typo cannot leave a finding un-accepted with
nothing to say so; an id whose check reports an *error* is a parse error too,
since an error names something the file cannot do and nothing would ever
silence it. `steam` and `lutris` carry the node for their `x11` grant and
`code` for its Secret Storage rule, with the reason each of their comments
already gives; every shipped profile lints clean on a host that has what it
shares.

`create`, `reseed`, `edit` and `profile edit` run the lint themselves at the
end and print any errors and warnings — never notes — to stderr, prefixed
`bubbler: lint:`. It is advice, not a gate: the exit code is untouched and
nothing is blocked.

`profile lint --all` reads a base profile once however many profiles
`include` it, so a layer and anything found in it are counted once.

## D-Bus

`dbus` never binds the session bus itself. bubbler starts an `xdg-dbus-proxy`
in a sandbox of its own — no network, no home, read-only `/usr`, an `/etc`
holding at most `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d` and
`nsswitch.conf`, the host socket of each granted bus read-only and the
instance's `dbus/` subdirectory read-write — and binds the filtered socket it
serves at
`$XDG_RUNTIME_DIR/bus` inside the sandbox, with `DBUS_SESSION_BUS_ADDRESS`
pointing there. The start waits up to five seconds for the proxy to report
that it has bound its socket and is accepting connections, and fails if it
does not; the proxy exits with the sandbox. `--dry-run` prints that bind
without starting anything.

The proxy creates its sockets in `$XDG_RUNTIME_DIR/bubbler/<name>/dbus/`, and
that directory is the only writable path in the proxy's own sandbox. The
instance directory above it is never bound there: it holds the control socket
`init.sock`, and reaching that socket means running commands inside the app.
Once the proxy reports itself ready, bubbler opens the socket without
following symlinks, checks that it really is a socket, and moves it up to
`$XDG_RUNTIME_DIR/bubbler/<name>/bus` — out of the proxy's reach — before
anything is bound into the sandbox. A proxy that replaced its socket with a
symlink would otherwise have that symlink's target bound in its place. The
proxy keeps serving after the move: it listens on the socket, not on the path.

The host bus is `$DBUS_SESSION_BUS_ADDRESS` when it is set, else
`$XDG_RUNTIME_DIR/bus`, and must be a socket. Either bus address variable
holding a transport bubbler cannot bind — `tcp:`, `unix:abstract=` — fails the
run naming the variable instead of falling back to the default socket, which
would filter a bus the session is not on; unset or empty is that default.
Everything the sandbox may reach is a rule: the `dbus` children above, plus the bundles
`portals`, `notify`, `tray` and `mpris`, each of which needs `dbus`.
`portals` also puts a `/.flatpak-info` in the sandbox giving it the
application id `org.bubbler.<name>`, which is what portals and the proxy
identify it by. A `.` in the name becomes `_`, since only the last element
of an id may hold a `-` and xdg-desktop-portal refuses every operation of a
sandbox whose id it cannot parse; a leading digit is prefixed with `_`,
which the portal would take but flatpak's own name check would not. The
rules it grants are `--talk` for `org.freedesktop.portal.Desktop`,
`.Documents` and `.FileChooser` plus the `--call`/`--broadcast` pair from
the `xdg-dbus-proxy(1)` examples; the spawn portal
(`org.freedesktop.portal.Flatpak`), which starts processes outside the
sandbox, is not among them.

`tray` is one rule, `--talk=org.kde.StatusNotifierWatcher`: an app registers
its icon with the watcher and serves the item itself on its own unique name,
and what the host's tray then calls back into the app is incoming, which the
proxy does not filter. Nothing needs `own`. The wildcard is a dot-namespace
one, so `own "org.kde.StatusNotifierItem-*"` is not a pattern but a literal
name that never matches, and an app that really needs a well-known item name
must write that exact name. Never `own "org.kde.*"`: it covers the watcher's
own name, and a sandbox that owns it can impersonate the tray and collect
every other application's items.

`BUBBLER_DBUS_LOG=1` runs the proxy with `--log`, so every filtered message is
printed to bubbler's stderr, for each bus the instance is granted.

`portals` also publishes the instance's identity on the host, as
`$XDG_RUNTIME_DIR/.flatpak/bubbler-<name>/bwrapinfo.json`: bwrap's own
`--info-fd` document, naming the `child-pid` of the sandbox. That file is how
xdg-desktop-portal checks a sandboxed caller — it reads `instance-id` out of
the caller's `/.flatpak-info`, looks the instance up there and opens a pidfd
of that pid — and without it every portal *operation* is refused. The sandbox
is held at bwrap's `--block-fd` until the file has been written, so the
application never runs before its identity exists, and the directory is
removed again when the run ends. The `.flatpak/` directory above it is shared
with flatpak, which names its own instances with plain numbers; bubbler
creates it if it is missing and otherwise only ever adds and removes its own
`bubbler-<name>` entry. That entry is created outright, never adopted: a
leftover from a killed run is removed first, and only if it holds nothing but
a `bwrapinfo.json` whose pid is gone.

A rule grants exactly as much as it reads, and the globs are wide: `own
"org.*"` claims every well-known name under `org.`, and `mpris name="*"` owns
the whole `org.mpris.MediaPlayer2.` tree, so the sandbox can impersonate any
player on the session bus. Name the application, not a prefix.

### The system bus

`system-bus` is the same proxy, filtering the host system bus:

    system-bus {
        talk "org.freedesktop.UPower"
        see  "org.freedesktop.NetworkManager"
        call "org.freedesktop.UDisks2=org.freedesktop.DBus.ObjectManager.GetManagedObjects@/org/freedesktop/UDisks2"
    }

It takes the `dbus` children except `own`, needs at least one of them, and
does not need or imply `dbus` — the two buses are independent, and a sandbox
may have UPower and no session bus at all. When both are granted, one
`xdg-dbus-proxy` process serves both: options apply to the address they
follow, so each bus has its own rule list. There is **no default name**; a
sandbox reaches nothing on the system bus that the node does not write.

The filtered socket is bound at `/run/dbus/system_bus_socket`, which is what
libdbus and libsystemd compile in, so no environment variable is set and
`DBUS_SYSTEM_BUS_ADDRESS` is one of the variables `env` may not set. The host
socket is `$DBUS_SYSTEM_BUS_ADDRESS` when it is set, else
`/run/dbus/system_bus_socket`, and must resolve to a socket. Everything the
launcher does with the session socket it does with this one: the proxy writes it in
`dbus/`, bubbler moves it to `$XDG_RUNTIME_DIR/bubbler/<name>/system` without
following symlinks, checks it really is a socket, and only then does the
sandbox bind it.

**The `talk` list is the entire confinement, and it is a weaker boundary than
the session bus.** The system bus sees the *proxy's* connection, not the
sandbox: `busctl --system list` attributes it to `xdg-dbus-proxy`, running as
your user in your session, and the sandbox's uid, pid namespace and
`/.flatpak-info` never reach `dbus-broker` or polkit. So behind a granted name
the sandbox is judged as an ordinary local process of yours — a method whose
polkit action is `auth_admin` pops a password prompt on your desktop, with
nothing on it to say which sandbox asked. `own` is refused by the parser for
the same reason: a name owned that way would be owned with your credentials.
Grant one name at a time, and prefer a portal (`portals` covers
`org.freedesktop.portal.Inhibit`, and PipeWire gets realtime priority from
`RLIMIT_RTPRIO` and `org.freedesktop.portal.Realtime` before it would ask
rtkit) over opening a system service.

Two things carry over from the session bus. The wildcard is a dot-namespace
one, so `talk "org.freedesktop.*"` matches `org.freedesktop.UPower` but not
`org.freedesktopFoo`. And filtering applies to outgoing calls and signals and
to incoming broadcasts only: a call *from* a system daemon into the sandbox
needs no rule.

## Terminal

The host terminal does not enter the sandbox. For each of bubbler's own fds
0, 1 and 2 that is a terminal, `run` and `exec` hand the sandbox the slave of
a pseudoterminal bubbler allocated and relay between the two; an fd that is
not a terminal — a pipe, a redirect — is passed through unchanged, so a
piped `bubbler run t -- cat` still reads the pipe and a redirected
`bubbler run t` still writes the file. A pty is allocated only when at least
one of the three is a terminal. The mode is the `tty` node in `config.kdl` and
`--tty <mode>` on `run`, `exec` and `try`, which wins over it:

    pty          the default, described above
    passthrough  bubbler's own descriptors, handed over as they are
    none         no terminal: stdin is /dev/null and the output comes back
                 through pipes, with nothing bound at /dev/console

In `pty` mode the command inside leads its own session with that pty as its
controlling terminal, so job control, `/dev/tty` and `stty` work. bwrap binds
a terminal at `/dev/console` only when it sees one on its own stdout, and in
`pty` mode that is the sandbox's pty rather than yours; with the output
redirected there is no `/dev/console` at all. Your terminal is in raw mode
while the sandbox runs: Ctrl-C and the erase key are bytes for the line
discipline inside, and a window resize is copied onto the pty.

Every sandbox is started with bwrap's `--new-session`, in every mode, so it
begins in a session of its own and inherits no controlling terminal from
bubbler; in `pty` mode the supervisor then makes the pty the controlling
terminal of the command's own session. The filter denies the `TIOCSTI` and
`TIOCLINUX` ioctls on top of that (see "Seccomp"), which is what
`bwrap(1)` recommends wherever a terminal descriptor still reaches a sandbox.

`^]` (Ctrl-]) three times within a second detaches. `run` stops relaying,
restores the terminal, prints a note and goes on waiting for the sandbox in
silence, since leaving would end it through `--die-with-parent` — bubbler is
still in the foreground, so `^Z` and `bg` are how you get the prompt back,
and a Ctrl-C after detaching forwards SIGTERM to the sandbox as it always
does. `exec` instead exits 0 and leaves the command to the supervisor, whose
terminal hangs up with bubbler. A `^]` you meant for the application still
reaches it, just after the run of three cannot complete.

What remains, and is inherent to any relay: the application can read what you
type into that session, and can emit escape sequences your terminal emulator
parses — title changes, OSC 52 clipboard writes, and query sequences whose
answers arrive as its own input. Do not type a password into a session you do
not trust. `passthrough` gives up the rest as well: the sandbox holds your
terminal's descriptors and reaches it again through `/dev/console`.

`run` and `exec` catch SIGINT, SIGTERM and SIGHUP while they hold your
terminal and put your settings back on the way out. For `run` that also
stops the sandbox. For `exec` it stops the relay and nothing else: the
instance stays up, and the command stays with the supervisor until its own
pty hangs up with bubbler — the same as after a detach, not a signal
delivered to the command.

Either way, the output the sandbox has already produced is handed over
before bubbler leaves, however long your terminal takes to accept it. One
ten-second window covers the whole hand-over, whatever it is being handed
to; a terminal that has gone five seconds without taking a single byte is
given up on inside it, and so is the rest of the output a fifth of a
second after a signal, since by then you are waiting for bubbler rather
than for it.

bubbler tries to say how much it dropped, but that message is best-effort
and never waited for: when your stderr is the same terminal that has
stopped reading, there is nowhere to put it and it is skipped rather than
written, because waiting for it would take the whole run down with it.

SIGKILL cannot be caught, and neither can anything else that takes bubbler
down without letting it unwind — a hang-up it never gets to act on
included. All those can leave behind is your terminal still in raw mode,
with no echo and no line editing; `reset`, or `stty sane`, puts it right.
No descriptor of yours is left changed: bubbler opens one of its own for
the output it relays, so the non-blocking flag it needs never reaches
the descriptor your shell holds, and where it cannot open one — a
redirect to a socket, say — it writes without setting the flag at all
rather than set it on something you share.

The pty is allocated on the host, so its name inside is not its name outside.
`/proc/self/fd/0` still reads back a host `/dev/pts/N`, a path the sandbox's
fresh devpts either does not have or has since handed to a different pty, so
anything resolving its terminal by that path is misled. `ttyname` then falls
back to searching `/dev`, where it finds the console bind: `tty` inside
prints `/dev/console` when bubbler's stdout is a terminal, and fails with
`ttyname error: No such device` when nothing is bound there — and in an
`exec`'d command, whose pty is one of its own that `/dev/console` does not
name, it fails that way even while the run's terminal is bound. A program that
wants a real `/dev/pts` entry — `script`, `wall`, `sudo` with tty tickets —
can fail either way; `tty "passthrough"` is the way out if an application
needs it.

`bubbler exec` takes the instance's `tty` node when `config.kdl` parses and
the default `pty` when it does not, since a running instance stays reachable
while its config is being edited.

## Seccomp

Every sandbox — an instance's, `try`'s, and the D-Bus proxy's own — starts with
a seccomp-bpf denylist. bubbler compiles it at launch with `libseccomp` and
hands it to bwrap as one program on `--add-seccomp-fd`. Rules are written by
syscall name and carry their own error: `EPERM` for most, `ENOSYS` where libc
should fall back to an older call instead of failing outright. Everything not
named is allowed; this narrows the kernel surface, it is not a capability
model.

`EPERM`: the kernel keyring (`add_key`, `keyctl`, `request_key`),
`perf_event_open`, `bpf`, `userfaultfd`, `fanotify_init`, the NUMA and
page-migration calls, module and kexec loading, `iopl`/`ioperm`, swap,
`reboot`, `syslog`, quota, the system clock and the host name — the list is
`DEFAULT_EPERM` in `crates/bubbler-core/src/seccomp.rs`. Two `ioctl` requests
are denied by their argument as well: `TIOCSTI` (0x5412) and `TIOCLINUX`
(0x541C), which push bytes into a terminal's input queue (CVE-2017-5226,
CVE-2023-28100). `ENOSYS`: `clone3` and the new mount API (`open_tree`,
`move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`),
which is `DEFAULT_ENOSYS` in the same file. `unshare`, `setns`, `clone`,
`mount`, `pivot_root`, `chroot` and `ptrace` are deliberately *not* denied:
Firefox and Chromium build their own sandbox out of them, and a nested user
namespace cannot undo bwrap's read-only binds.

The `seccomp` node changes the list for one instance; the proxy sandbox always
keeps the default:

    seccomp {
        allow "ptrace" "perf_event_open"   # take names off the list
        deny "unshare" "setns"             # add names, EPERM unless stated
        deny "clone3" errno="ENOSYS"
        disable                            # no filter at all
    }

`deny` applies after `allow`, and a syscall named twice keeps only its last
action. An unknown name is an error rather than a silent skip — a name only the
filter's second architecture has, `vm86old` on x86_64 say, is *not* unknown —
and `deny "prctl"` is refused because glibc and Chromium call `prctl` for
themselves — thread names, `PR_SET_NO_NEW_PRIVS`, the renderer's own filter —
so denying it breaks the sandbox from the inside.
`allow "ioctl"` is the only way to take back the two
argument rules, so it re-enables `TIOCSTI` and `TIOCLINUX` for that instance —
do not reach for it to fix an unrelated `ioctl`. `deny "ioctl"` replaces those
two rules with one that matches every request, which breaks nearly every
program. `disable` prints `bubbler: seccomp disabled for instance <name>` on
each run, so an unfiltered sandbox is never a quiet one; an `allow` list that
takes back every rule leaves nothing to load and says
`bubbler: seccomp has no rules left for instance <name>` for the same reason.

A syscall name the linked libseccomp does not know is left out of the filter
rather than failing the launch, and every run that does so prints, once,

    bubbler: seccomp: <name> unknown to this libseccomp, rule skipped

on stderr — a skipped rule is a weaker sandbox than the profile asked for, so
it is never silent, and no environment variable is needed to see it. It should
not happen on a supported build: see the floor under "Build".

`BUBBLER_SECCOMP_LOG=1` compiles the same rules with the log action instead.
The filter is loaded as always, but a call that would have been denied is
written to the kernel audit log and then succeeds — so the sandbox runs
unrestricted while it says what it would have lost. It is for finding
over-denies while writing a profile, not for running with.

On x86_64 the filter carries **two** architectures, x86_64 and i386, so 32-bit
binaries in the sandbox are filtered rather than killed — Steam, umu/Proton and
DXVK's 32-bit path run under the same rules as everything else, and no profile
needs `seccomp { disable }` for them. libseccomp translates each rule to both
ABIs by name, which is what makes this safe to write once: on i386 glibc issues
`clock_settime64` (404) and `clock_adjtime64` (405) rather than the numbers
x86_64 uses, and the name resolves to whichever number each architecture has.
Elsewhere the filter carries the build architecture alone.

Multiarch costs one rule, and the cost is not confined to 32-bit code.
`modify_ldt` sets up the local descriptor table, which 16-bit programs and
several Wine patches need. bubbler adds every rule *after* both architectures
are in the filter, so a rule holds for both ABIs — there is no "deny it on
x86_64 only" here — and keeping the deny would break the 32-bit code the second
architecture exists to filter. So it is allowed, as flatpak allows it wherever
its own filter is multiarch. Be clear about what that widens: on x86_64 **every
profile** now lets 64-bit code call `modify_ldt` too, where the
single-architecture filter answered `EPERM` (measured both ways). A
single-architecture build still denies it. Put it back for one instance with

    seccomp {
        deny "modify_ldt"
    }

`--explain` prints the size and the architectures under the descriptor, e.g.
`--add-seccomp-fd 5  (filter, 896 bytes, x86_64 + i386)`.

A syscall from an ABI the filter does **not** carry is killed rather than
allowed. x32 is the ABI this matters for: it shares x86_64's `AUDIT_ARCH`
value but sets `__X32_SYSCALL_BIT` on every syscall number, so no rule keyed to
x86_64 can match it, and `man 2 seccomp` requires a policy to either enumerate
those numbers or deny them all. An x32 caller therefore dies with `SIGSYS`
instead of walking past the denylist. Neither `allow` nor `BUBBLER_SECCOMP_LOG`
softens that: it is an ABI gate, not one of the rules. x32 binaries are
vanishingly rare — Arch does not build any — but a 64-bit program can issue an
x32 syscall on purpose, which is exactly the bypass this closes.

## User namespaces

    userns "disable"                 # "allow" is the default

The baseline unshares every namespace, but `--unshare-all` still leaves the
sandbox able to create *new* user namespaces, and a process inside one of those
holds full capabilities there — which is how the mount and pid namespaces
become reachable again. `userns "disable"` closes that one door: bubbler emits
`--unshare-user --disable-userns` in the namespace phase, and `unshare -U`
inside then fails with `ENOSPC`. The explicit `--unshare-user` is part of it
because bwrap refuses `--disable-userns` without one, and `--unshare-all` does
not count: it asks for the user namespace only if the host offers unprivileged
ones. So with `userns "disable"` a host without them fails to start the sandbox
at all instead of starting it without a user namespace.

What it costs: Firefox loses its own inner sandbox — it still runs, and says so
with `Sandbox: CanCreateUserNamespace() clone() failure: ENOSPC` — and Chromium,
which falls back to a user-namespace sandbox inside bwrap because its suid
helper is blocked there, is expected to lose that layer as well. Anything that
nests a container breaks outright — Steam, whose pressure-vessel
runs its own bubblewrap for every Proton game, plus `unshare`, podman and
flatpak inside the sandbox. The node applies to the app's own sandbox: the
`xdg-dbus-proxy` sidecar is built from the same baseline as always, since
nothing of the application runs in it. It is also unavailable exactly where it would be
wanted most: `bwrap(1)` says the flag "doesn't work in the setuid version of
bubblewrap", which is the version a kernel without unprivileged user namespaces
needs. No shipped profile sets it.

## Baseline

Every sandbox gets: all namespaces unshared, no network, read-only `/usr` and
`/opt`, empty `/tmp` `/var` `/run`, a private home at `/home/bubbler`, an
empty `$XDG_RUNTIME_DIR` at the host's path with mode 0700, `/home/bubbler` as
the working directory, and a cleared environment (only the locale and terminal
variables — `TERM`, `LANG`, `LANGUAGE`, `COLORTERM`, `TZ`, `LC_*` — are
carried over). Grants only add to that.

`/dev/ntsync` is bound too, on a host that has the node — the one device the
baseline hands over, and a deliberate widening of it. It is the kernel's
Windows-style synchronisation primitive (`drivers/misc/ntsync`, kernel 6.14 and
later), which Wine and Proton fall back to much slower sync without, and the
objects made through it belong to the process that opened it, so there is no
host state behind it to leak. The tradeoff is that every sandbox, not only a
gaming one, gets that driver's ioctl surface to reach; flatpak makes the same
trade and binds it with no permission of its own. A kernel without the module
loaded simply has no node, and then nothing is bound.

`/etc` is an allowlist over a tmpfs: only the entries in `ETC_ALLOWLIST`
(`crates/bubbler-core/src/bwrap.rs`) are bound, and only those that exist on
the host — `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d`, `fonts`, `localtime`,
`machine-id`, `nsswitch.conf`, `hosts`, `host.conf`, `ssl`, `ca-certificates`,
`mime.types`, `xdg`, `gtk-3.0`, `gtk-4.0`, `pulse`, `pipewire`, `alsa`,
`drirc`, `vulkan`, `glvnd`, `egl`, `vdpau_wrapper.cfg`, `os-release`. `passwd`
and `group` are generated: the sandbox sees the user `bubbler` (holding the
host's uid and gid) and `nobody`, never the host's accounts, and `USER` and
`LOGNAME` are `bubbler` as well.

`x11` remaps any Xauthority file to `/home/bubbler/.Xauthority`, but it stays
a compatibility grant: X11 offers no isolation between clients. Sockets and
cookie files named by the environment must really be of that type, so a
`WAYLAND_DISPLAY` or `XAUTHORITY` naming a directory is refused instead of
binding the tree under it.

## Known gaps

- No accessibility bus, no document-portal FUSE mount, so a portal that hands
  back a `/run/user/<uid>/doc` path gives the sandbox nothing it can open.
- Descriptors handed to a command through `exec` are reachable by the
  sandboxed application through `/proc` — exec is a convenience channel, not
  a boundary. What the sandbox can still do with the terminal it is given is
  under "Terminal".
- AMD compute (ROCm/OpenCL via `/dev/kfd`) is not supported yet; it needs its
  sysfs topology alongside the node.
- `dri` binds the NVIDIA device nodes but not `/etc/OpenCL` or `/etc/nvidia`,
  so compute and vendor application profiles need an `etc-share` of their own.
- `hidraw` binds the `/dev/hidraw*` nodes that exist at launch and there is no
  directory to bind instead, so a device plugged in later is invisible to
  hidapi until the instance restarts; evdev still sees it.
- No raw-USB grant (`/dev/bus/usb` and its sysfs) and no pcsclite socket, so a
  challenge-response YubiKey or a smart card reader cannot be reached from a
  sandbox; `hidraw` is a different device class and no substitute.
- Outbound traffic under `network` is all or nothing: pasta cannot filter by
  destination, so there is no per-host or per-port egress policy. `allow-port`
  covers the inbound direction only.
- `app-runtime` does not carry Discord rich presence: those clients look for
  `discord-ipc-N` at the top of `$XDG_RUNTIME_DIR`, which no sandbox shares.
- Nothing installs a browser's native messaging manifest into an instance's
  private home, so KeePassXC browser integration still needs that file put in
  place by hand.
- `/etc/machine-id` is bound in, so every instance shares one stable
  identifier with the host.
- `camera` has never been exercised against a real camera: this machine has
  none, so neither the portal call nor the device binds are more than unit and
  argv tested; see "camera".
- No desktop entries.

## Files

Instances live in `$XDG_DATA_HOME/bubbler/instances/<name>/` (by default under
`~/.local/share`), each holding a `config.kdl` and the private `home/`. Every
run except a dry run or an explanation also creates
`$XDG_RUNTIME_DIR/bubbler/<name>/`, mode 0700, reusing one left over from an
earlier run, and binds the control socket `init.sock` in it; a `dbus` or
`system-bus` grant adds the subdirectory
`dbus/` the proxy creates its sockets in and the checked socket `bus` and/or
`system` beside it, and a `portals` grant adds
`$XDG_RUNTIME_DIR/.flatpak/bubbler-<name>/`, creating `.flatpak/` if it is
missing. Everything a run makes there is removed again when it ends, with one
exception: an `app-runtime` grant creates `$XDG_RUNTIME_DIR/app/<id>` (and
`app/` above it) and leaves it, since a peer of another instance may still be
using it.
`HOME` and `XDG_RUNTIME_DIR` must be set and non-empty. Your profiles live in
`$XDG_CONFIG_HOME/bubbler/profiles/` (by default under `~/.config`) and the
system's in `/usr/share/bubbler/profiles/`, or wherever
`$BUBBLER_PROFILE_DIR` points instead.

Those socket paths have to fit the 107 bytes a Unix socket address holds, so
`create` and `try` refuse a name that would make one longer instead of letting
the kernel truncate it silently and the connection fail somewhere else.

The `bubbler-init` binary is taken from `$BUBBLER_INIT` if set (it must be a
regular file), else from next to the `bubbler` binary, else from
`/usr/lib/bubbler/bubbler-init`. `$BUBBLER_DBUS_PROXY` likewise replaces the
`xdg-dbus-proxy` on `PATH` with a regular file bound into the proxy sandbox at
its own path; it exists for tests and debugging, as does the
`$BUBBLER_TEST_ALLOW_PATH` described under "Host paths".

## Build

    cargo build --release

Links `libseccomp.so` — the `libseccomp` package on Arch, `libseccomp-dev` on
Debian for the linker symlink. It is bubbler's only C dependency; everything
else is Rust. No headers and no bindgen: the binding crate writes the FFI by
hand, and `pkg-config` is optional, used only to set a cfg for a libseccomp 2.6
API bubbler does not call.

**libseccomp 2.5.4 or newer.** The floor is the syscall table, not the API:
bubbler names its rules, and a libseccomp whose table predates Linux 5.17 does
not know `mount_setattr`, so that rule would be skipped and the sandbox quietly
weaker. A skipped name is printed (see "Seccomp"), so a too-old library is loud
rather than silent, but it is still a downgrade.

Requires `bwrap` at runtime and a kernel with user namespaces, plus `pasta`
(the `passt` package) for any profile with an isolated `network` — which is
every shipped profile that has one.

## Installing

    cargo build --release --locked

    install -Dm755 target/release/bubbler      /usr/bin/bubbler
    install -Dm755 target/release/bubbler-init /usr/lib/bubbler/bubbler-init
    target/release/bubbler man          > /usr/share/man/man1/bubbler.1
    target/release/bubbler man --config > /usr/share/man/man5/bubbler-config.5

That is the whole install set, and each path is one the code itself names.

`bubbler-init` is deliberately not in `/usr/bin`. It is the supervisor bubbler
binds into every sandbox, not a command to type. bubbler looks for it in
`$BUBBLER_INIT`, then next to the running `bubbler`, then at
`/usr/lib/bubbler/bubbler-init`; a copy in `/usr/bin` would be found by the
second of those and work fine, which is the point — it buys nothing, and it
puts a supervisor binary on everyone's `PATH`, where it is one to run by
accident and one for a `PATH` shim to collide with.

The man pages are generated by the binary that was just built, so they cannot
promise a flag it does not have. Install them uncompressed; a package manager
that compresses man pages does it itself.

`/usr/share/bubbler/profiles/` is not part of the install set. The fourteen
shipped profiles are compiled into the binary, and that directory is the
system layer *between* your profiles and the built-in ones: a file put there
would shadow the built-in of the same name and keep shadowing it after an
upgrade. It is the administrator's, and bubbler ships nothing in it.

At runtime bubbler needs `bwrap` (bubblewrap), `xdg-dbus-proxy` for any profile
with a `dbus` or `system-bus` grant, which is most of them, `pasta` (the
`passt` package) for an isolated `network`, and `libseccomp`. Portals need
`xdg-desktop-portal` and a backend for your desktop; neither is bubbler's to
start. Nothing here depends on a shell: bubbler ships no completions.

Packaging lives in a repository of its own, not in this one.
