# bubbler manual

The long-form reference: every mechanism with its rationale and what was
measured. The [wiki](wiki/Home.md) is the short form.


Application sandboxing on top of [bubblewrap](https://github.com/containers/bubblewrap),
with named instances, explicit resource grants, and a profile library for
common applications. bubbler itself is unprivileged; `bwrap`
does the namespace work.

Status: milestone 10 — a library of 14 profiles (`alacritty`, `chromium`,
`code`, `firefox`, `generic`, `keepassxc`, `kitty`, `libreoffice`, `lutris`,
`mpv`, `spotify`, `steam`, `thunderbird`, `vesktop`) over GPU, sound, a private
home, host paths through `path-share`, a runtime directory shared between
sandboxes through `app-runtime`, game controllers through `gamepad`, a camera
through the portal, a filtered session, system and accessibility bus with
portals, notifications, `tray` and input methods, a terminal of their own, a
network namespace of their own through pasta with outbound filtering through an
nftables ruleset installed in it, and a seccomp filter that covers 32-bit
binaries as well as 64-bit.
Profiles come in three layers — yours, the system's, built-in — and compose
with `include`. `bubbler lint` measures a profile or an instance config
against what a sandbox is meant to give away, and `--dry-run --explain` puts
every bwrap argument under the node that produced it. `bubbler open` starts an
instance or hands a URL to the one already running, and keeps what a launch
with no terminal printed where `bubbler log` finds it; `bubbler desktop` writes
the menu entry that calls it, `bubbler wrap` the `~/.local/bin` shim. `bubbler
man` prints both manual pages, and `bubbler ui` opens the terminal editor
`bubbler-ui`, which is every subcommand over a list of instances and their
grants. `docs/threat-model.md` says what each mechanism defends and what it
does not, `fuzz/` holds seven cargo-fuzz targets beside the property tests over
the same parsers, `cargo deny check` guards the dependency tree,
`.github/workflows/ci.yml` runs the lot, and `contrib/apparmor/usr.bin.bubbler`
is an AppArmor profile for packagers that has never been loaded here. See
"Known gaps" below.

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
    bubbler open ff                       # exec into it if it is running, else run
    bubbler open ff -- firefox https://a  # hand a URL to the one already running
    bubbler log ff                        # what its last run without a terminal said
    bubbler desktop ff                    # a menu entry that starts the sandbox
    bubbler desktop ff --replace          # …that shadows the application's own entry
    bubbler desktop --refresh             # rewrite every entry bubbler has written
    bubbler wrap ff                       # ~/.local/bin/ff starts that sandbox
    bubbler wrap --list                   # every shim, and whether it still works
    bubbler unwrap ff                     # remove it again
    bubbler try -- id                     # throwaway sandbox, nothing kept
    bubbler try --profile firefox --grant network -- firefox --version
    bubbler try --keep scratch -- sh      # keep it afterwards as instance `scratch`
    bubbler list
    bubbler delete ff --yes               # instance and private home; irreversible
    bubbler ui                            # the terminal editor, if it is installed
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

`open` is what a menu entry or a shim calls: it execs into the instance when
it is running and starts it when it is not, so a URL opens in the window that
is already there. A terminal on any of its three standard descriptors is
somebody watching, and the sandbox gets the terminal its `tty` node asks for;
with none on any of them, which is how a launcher starts its children, it
takes `tty "none"` (see "Terminal") and writes bubbler's own stderr — its warnings, a sidecar's
errors, the application's own output — to `last-run.log` in the instance
directory, which `bubbler log` prints. The log is opened before the config is
read, so a `config.kdl` that stopped the run is in it too, and a log that
cannot be opened at all — a symlink where the file belongs — costs the record
rather than the run: bubbler says so and starts the sandbox anyway. Printed to a
terminal, the log has its control characters shown (`^[`) rather than sent, so
reading what a sandbox wrote is not letting it write to your terminal a second
time; down a pipe it is the log, byte for byte. See "Desktop entries".

A run is a chain of processes; `bubbler` waits at the top of it and returns the
command's status.

    bubbler ─┬─ bwrap ── bwrap (pid 1 in the sandbox, reaps orphans)
             │              └─ bubbler-init (pid 2) ─┬─ your command
             │                                       ├─ Xwayland (a bare `x11`,
             │                                       │            on its first
             │                                       │            X client)
             │                                       └─ a window manager (only
             │                                                            with `wm=`)
             ├─ bwrap ── bwrap ── bubbler-wl-proxy  (with a sandboxed `wayland`)
             ├─ bwrap ── bwrap ── xdg-dbus-proxy    (only with `dbus`)
             └─ pasta                               (only with an isolated
                                                     `network`; not sandboxed)

Each `bwrap` leaves a reaper as pid 1 of its own pid namespace. Either proxy's
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
`pipewire`, `pulseaudio`, `dbus`, `portals`, `notify`, `tray`, `a11y`,
`input-method`, `gamepad`, `hidraw` and `camera`, and anything with arguments
needs a real instance — `system-bus` among them, since it is not a grant
without rules. The bundles are checked as they are in a config file, so
`--grant tray` without `--grant dbus` is refused rather than silently dropped,
and `--grant camera` needs `--grant portals` (and the `--grant dbus` that
carries it) the same way.
`--grant x11` needs `--grant wayland --grant dri`, without which the X server
it starts inside has nothing to draw in or with. A
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
    bubbler run ff --explain --wl-proxy    # the Wayland proxy sidecar's argv instead
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

      portals                         config.kdl:11  10 arguments
        --block-fd 4  (pipe: the sandbox waits on it until bubbler lets it go)
        --perms 0644 --ro-bind-data 9 /.flatpak-info  (generated file, 69 bytes)
        --bind /run/user/1000/doc/by-app/org.bubbler.ff /run/user/1000/doc
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
        --ro-bind /run/user/1000/bubbler/ff/wayland /run/user/1000/wayland-1
        --setenv WAYLAND_DISPLAY wayland-1
        --setenv XDG_SESSION_TYPE wayland
        security-context: engine=org.bubbler app=org.bubbler.ff instance=bubbler-ff
        sidecar: bubbler-wl-proxy listener /run/user/1000/bubbler/ff/wayland → upstream /run/user/1000/bubbler/ff/wayland-context, gate paste

      network                         config.kdl:7   5 arguments
        --perms 0644 --ro-bind-data 8 /etc/resolv.conf  (generated file, 23 bytes)
        sidecar: pasta --config-net --foreground --quiet -t none -u none -T none -U none --map-host-loopback none --map-guest-addr none --dns-forward 169.254.1.1 --userns <userns> --pid <ready-fd> <child-pid>

      init                                           7 arguments
        --ro-bind /usr/lib/bubbler/bubbler-init /run/bubbler-init
        -- /run/bubbler-init --socket-fd 10  (socket: the exec channel bubbler-init serves)

      command                                        2 arguments
        -- firefox

    233 arguments in 14 groups, 129 hidden (--explain=full); 8 D-Bus rules to the proxy (--proxy)

A group sits where the node's *first* argument is emitted and gathers every
later one it contributed, whichever phase that came from: `network "host"` is
placed by the `--share-net` inserted into phase 1 and its `/etc/resolv.conf`
bind from phase 4 is listed with it, though the whole baseline separates the two
in the argv. The listing is therefore neither file order nor argv order, and it
is not the order of record: `--dry-run` is, and so is `--format json`, which
stays in true argv order.

A grant that is not only bwrap arguments says so under its own group: a `dbus`
node lists the `rules:` it hands the proxy, an isolated `network` lists the
`sidecar:` argv pasta is started with, and a `wayland` node says which socket
the one bind is — `security-context:` with the three strings a bare grant
registers plus the `sidecar:` line naming the proxy in front of it, its two
sockets and its gate, `raw socket: wayland "host"` for the session's own — none
of which is in the argv, and `--dry-run` prints the sandbox's argv alone.
`--explain --proxy` prints the D-Bus proxy's own argv and `--explain --wl-proxy`
the Wayland proxy's.

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

`--explain --wl-proxy` does the same for the Wayland proxy. Its filter is the
default set for the same reason, and the one part of its argv the config
decides — `--gate paste` or `--gate open` — is grouped under the `wayland` node
that decided it, with that node's line number. The two flags cannot be combined:
each renders one sidecar's argv, and `--proxy --wl-proxy` together is a usage
error, as is either without `--explain`. A config with no sidecar of that kind
says so rather than printing an empty view:

    bubbler: instance `wlopen` grants no sandboxed wayland, so it starts no Wayland proxy sidecar

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

    wayland                          # a socket the compositor treats as sandboxed,
                                     #   behind a proxy that gates clipboard reads
    wayland clipboard="open"         # the same socket, the gate off; lint warns
    wayland "host"                   # the session's own socket instead, no proxy
    x11                              # a rootful Xwayland inside the sandbox,
                                     #   started by its first X client:
                                     #   1280x720, decorated, DISPLAY=:0
    x11 geometry="1920x1080"         # the window that server draws itself in
    x11 fullscreen=#true grab=#true  # a whole output; input held inside it
    x11 wm="openbox"                 # a window manager inside, with the server
    x11 "host"                       # the session's X socket and cookie instead
    network                          # the sandbox's own network namespace,
                                     #   connected by a pasta sidecar
    network "host"                   # the host's namespace instead
    network "none"                   # no network; the same as no node at all
    network {                        # children; `dns` in any of the three
        dns "1.1.1.1"                #   generated /etc/resolv.conf
        allow-port 8080              #   host 127.0.0.1:8080 reaches the sandbox
        allow-port 5353 udp=#true    #   isolated mode only, like the rest
        outbound "deny"              #   filter outbound traffic (default "allow")
        allow-out "1.1.1.1"          #   any port, tcp and udp
        allow-out "140.82.112.0/20" port=443 proto="tcp"
        allow-out "2606:4700:4700::1111" port=853
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
    a11y                             # the accessibility bus, through the proxy
    input-method                     # the fcitx5 and IBus portal names
    tty "pty"                        # terminal: "pty", "passthrough" or "none"
    userns "allow"                   # nested user namespaces: "allow" or "disable"
    seccomp {                        # changes to the default syscall denylist
        allow "perf_event_open"
        deny "unshare" errno="EPERM"
        disable
    }
    env MOZ_ENABLE_WAYLAND="1"       # extra variables, KEY="value", repeatable
    lint-allow "x11-without-reason" reason="the session's window manager"
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

### wayland

`wayland` on its own does not hand the application the session's compositor
socket. A sandboxed `wayland` grant binds two sockets of bubbler's own in the
instance's runtime directory, and the sandbox is given exactly one of them.
`$XDG_RUNTIME_DIR/bubbler/<inst>/wayland-context` is the one the compositor
gets: bubbler listens on it and hands the compositor that listening descriptor
through `wp_security_context_v1` (wayland-protocols, staging) together with
three strings — sandbox engine `org.bubbler`, application id
`org.bubbler.<inst>`, instance id `bubbler-<inst>`. Nothing inside the sandbox
can reach it. `$XDG_RUNTIME_DIR/bubbler/<inst>/wayland` is the other, and that
is the one bound into the sandbox, at the session's own `WAYLAND_DISPLAY` name,
so nothing inside has to know it is not the session's. `bubbler-wl-proxy`
listens on the second and connects to the first, and it is that connection the
compositor sees: a client on it is one the compositor knows to be sandboxed,
and the compositor withholds its privileged globals from such a client — screen
capture, clipboard management, input injection, overlays and window management
on Hyprland and sway.

On that path, which globals those are is the compositor's policy and not
bubbler's — Hyprland keeps an allowlist of what a sandboxed client may bind,
sway a denylist of what it may not — so the security context is worth what the
compositor implements, and bubbler attaches the metadata and nothing else. What
the proxy withholds on top of that is bubbler's: every global whose interface
its tables cannot describe, on either path, and on a compositor with no
`wp_security_context_manager_v1` a denylist of 40 privileged interface names,
applied in the compositor's place. Both are described below.

Measured here on Hyprland 0.56.2: `wayland-info` counted 73 globals over 71
interfaces on the host and 38 over 37 inside a bare `wayland` sandbox.
Thirty-one of those interfaces the compositor withholds from a security-context
client — the screencopy manager (recording the screen with no portal in
between), both data-control managers, the virtual keyboard and virtual pointer
protocols (typing and clicking into your session), layer-shell (drawing over
everything), foreign-toplevel and workspace listing, session-lock, and
`wp_security_context_manager_v1` itself, so a sandbox cannot create a context of
its own. The other three are the proxy's doing and are described below. What the
data-control managers cost an application is reading the clipboard without
focus; reading it *with* focus is the core `wl_data_device`, which is not
privileged on any compositor and is what the proxy gates instead.

The compositor keeps accepting connections on the context socket after
bubbler's own connection to it is gone, until the descriptor it was given as
`close_fd` hangs up. bubbler holds the write end of that pipe for the length of
the run, so the context ends when the run does and the socket file goes with
it.

`bubbler-wl-proxy` sits between the two sockets in a bwrap of its own, started
before the sandbox and stopped with it. The listener it serves — the `wayland`
the sandbox connects to — reaches it as an inherited descriptor rather than a
path, so the only thing of this run bound into that sandbox is the
`wayland-context` upstream, read-only: the proxy can reach neither the
instance's runtime directory nor the `init.sock` in it. It gets the read-only
`/usr`, the `/etc` allowlist every sidecar gets, a private `/proc`, `/dev` and
`/tmp`, a cleared environment and the default seccomp filter — the instance's
own `seccomp` node never reaches it.
`bubbler run … --explain --wl-proxy` prints that argv:

    bwrap  (the Wayland proxy sidecar)

      baseline                42 arguments
        --unshare-all
        --die-with-parent
        --new-session
        --ro-bind /usr /usr
        --symlink usr/bin /bin
        ... 33 more (--explain=full)

      seccomp                 2 arguments
        --add-seccomp-fd 5  (filter, 896 bytes, x86_64 + i386)

      command                 13 arguments
        --ro-bind <build tree>/target/debug/bubbler-wl-proxy <build tree>/target/debug/bubbler-wl-proxy
        --
        <build tree>/target/debug/bubbler-wl-proxy
        --listen-fd
        3
        --upstream
        /run/user/1000/bubbler/try-631049/wayland-context
        --log-fd
        2
        --ready-fd
        4

      wayland   config.kdl:3  2 arguments
        --gate
        paste

    59 arguments in 4 groups, 33 hidden (--explain=full)

`<build tree>` is this checkout's path, elided; nothing else is edited. That
build-tree binary is why the group has a `--ro-bind` of it and 13 arguments —
the installed binary is not bound in and the group is 10. The descriptor
numbers are a dry run's, as everywhere else under `--explain`.

The binary is `$BUBBLER_WL_PROXY` if that is set, else the one beside the
running `bubbler`, else `/usr/lib/bubbler/bubbler-wl-proxy` — the same order
`bubbler-init` is looked up in, so a build tree runs what it just built. It is
bound into the sidecar's sandbox at its own path unless it is that last one,
the installed path, which is already under the read-only `/usr` that sandbox
has: an override is bound in wherever it sits, `/usr` included. A `wayland`
grant with no proxy to run is a failed run and not a weaker one:

    bubbler: running a throwaway sandbox: bubbler-wl-proxy did not start; it exited (exit status: 1)

Before it reports itself ready the proxy dials the upstream socket once, so a
compositor that is not answering stops the launch rather than every connection
inside it. That probe is bounded at two seconds — a Unix socket whose accept
queue is full answers `EAGAIN` rather than blocking, so the dial is retried
every 50 ms until the deadline. The proxy then writes its own reason to the
audit log, `bubbler-wl-proxy: cannot reach the upstream socket <path>: timed
out after 2 s`, and exits 1; what the launcher says is the `did not start` line
above, so a failed launch leaves both, in that order.

What the proxy does with the wire is decode it. Every message is read against a
table of interfaces and message signatures generated at build time from the
protocol XML the `wayrs` crates ship, and what is forwarded is *re-encoded*
from the arguments the policy saw rather than copied through, so the far side
reads exactly what this proxy parsed and judged. An interface the tables do not
describe is one the proxy cannot read a single message for, so its globals are
never advertised; a global advertised at a version above the tables' is clamped
to the version they describe, because a client that bound the higher one would
send opcodes past the end of the message list. Three interfaces went that way
on this host — `wl_drm`, `org_kde_kwin_server_decoration_manager` and
`hyprland_surface_manager_v1` — and the first two have current replacements
present inside (`zwp_linux_dmabuf_v1`, `zxdg_decoration_manager_v1`) while
nothing here binds the third.

Hiding the advertisement is not enough on its own: `wl_registry.bind` names a
global by a number, and a client can name one it was never shown. So `bind` is
checked against what this connection was actually offered — a name it never
saw, an interface that is not the one that name was advertised under, or a
version above what it was offered is refused with a synthesised
`wl_display.error` and the connection is closed. Asking inside a sandbox for
the number `zwlr_data_control_manager_v1` has on this host:

    refused: bind of hidden global zwlr_data_control_manager_v1 (name 38, v1) refused by the sandbox proxy
    bubbler-wl-proxy: connection closed: bind of hidden global zwlr_data_control_manager_v1 (name 38, v1) refused by the sandbox proxy

The proxy is also what a hostile client would try to exhaust, so it is bounded
in every direction — and the bounds do not all do the same thing. Three of them
end a connection, with a `bubbler-wl-proxy: connection closed: …` line naming
which and why, the others carrying on: **253 descriptors** waiting on one side,
which is Linux's own maximum for a single `recvmsg` and far past the two any
message owns; **64 MiB** of bytes queued across all of one sandbox's
connections at once, where the connection holding the most is the one that
gives way; and **65 536** live object ids on a connection (server ids the
compositor has not yet reused are counted separately against the same number).
The other two apply back-pressure instead of closing anything. **4 MiB** queued
in one direction stops the proxy reading the side that feeds it until the far
side drains — a peer that will not read is not a reason to grow, and nothing is
lost. **256 connections** is where the listener stops being accepted on; the
kernel's backlog holds the rest until a connection ends, and one that has been
waiting is served then rather than refused.

**The paste gate.** This is the rule the proxy exists for. A `receive` request
on `wl_data_offer`, `zwp_primary_selection_offer_v1`,
`zwlr_data_control_offer_v1` or `ext_data_control_offer_v1` is forwarded only
within one second of real user input: a `wl_keyboard.key` the compositor
reported as pressed, a `wl_pointer.button` in either direction, or a
`wl_touch.down` or `wl_touch.up`. Both ends of a press arm, and deliberately:
letting go of the mouse over a paste target is user input by any reading, and a
touch drag *drops* on the `up`, which a long one would otherwise reach the gate
a second or more after the `down` that started it. The window is one second and
the state is per instance rather than per connection — an application with
helper processes reads the selection on a connection that never held keyboard
focus, and gating each connection on its own input would deny every
multi-process toolkit. A drag-and-drop offer is a `wl_data_offer` like any other
and goes through the same gate, which costs nothing: a drop is a button or
touch release, and the release is what arms, so the `receive` that follows a
drop is inside the window that release opened however long the drag itself
took. Outside the window the request is not forwarded and the descriptor it
carried is closed, so the client reads end of file, exactly as if the selection
had been empty, and one line goes to the log. Run with `secret` on the
session's selection, a client that
maps a window, takes focus, is offered the selection and reads it:

    0
    bubbler-wl-proxy: clipboard read denied (wl_data_offer, text/plain): no input since the proxy started

Once something has armed the gate the tail counts the gap instead — `no input
for <n> ms`, the same refusal either way. Audit lines go to bubbler's own
stderr, which for a run without a terminal is `last-run.log` (see "Terminal"),
and are rate-limited to one a second: gate lines and connection-closed lines
have a budget each, counted apart so a
`receive` in a tight loop cannot spend the log's whole allowance and push the
line that says why a connection ended out of the record. What a burst swallowed
rides on the next line of its kind as a count.

Be clear about what that is worth. It stops an application reading the
selection *in the background*: mapped, focused, handed the offer by the
compositor, and reading it while your attention is elsewhere — which is the
case this exists for, and which needs no paste and no keystroke. It does not
stop an application you are typing into. The keystrokes you send it are exactly
what arms the gate, so a focused editor or terminal can read the selection
within a second of any key you press in it. And it inspects nothing that
travels on a passed descriptor: the selection's bytes go down a pipe the
compositor writes and the client reads, and the proxy's decision is made on the
request that carries the pipe, never on what comes back through it.

An application whose job *is* the clipboard can have the gate off:

    wayland clipboard="open"

The proxy stays in front of the socket and everything above still applies —
only the gate goes. Every `receive` is forwarded, and every one is logged
rather than counted:

    6
    bubbler-wl-proxy: clipboard read allowed (open): wl_data_offer, text/plain

`bubbler lint` warns about it (`wayland-clipboard-open`) and takes a
`lint-allow "wayland-clipboard-open" reason="…"` naming what reads the
clipboard unattended. There is no third value. `clipboard="paste"` is refused
rather than accepted as the default written out, because the emitter renders
the default as the bare `wayland` node and a second spelling would be a round
trip the file does not survive unchanged; and `wayland "host"` with any
`clipboard=` is refused too — no proxy runs on the session socket, so a gate
written there would be one nothing applies.

One thing the sidecar costs: the compositor reads its peer's credentials from
the connection (`SO_PEERCRED`), and the peer is the proxy. A window the
sandboxed application maps is therefore attributed to the `bubbler-wl-proxy`
process rather than to the application — measured here, `hyprctl clients`
reported the sidecar's pid for the sandbox's own window. Compositor window
rules keyed on a pid, and any tool that maps windows back to processes, see the
sidecar; rules keyed on the application id, the class or the title are
unaffected.

A bare `x11` changes none of this. The Xwayland it starts inside the sandbox is
an ordinary client of `<instance runtime>/wayland`, decoded, filtered and gated
exactly like the application beside it.

A compositor that implements none of this — no `wp_security_context_manager_v1`
in its globals — is not a failed run: the proxy connects to the session socket
instead and hides the privileged interfaces itself, in the compositor's place,
and the launcher says so once per launch.

    bubbler: note: wayland: no wp_security_context_manager_v1; the proxy hides the privileged globals instead

On that path the proxy adds a denylist of its own: 40 interface names — screen
capture and export-dmabuf, both data-control managers, virtual keyboard and
pointer, the input-method protocols, the input-inhibit and Xwayland keyboard
grabs, transient seats, layer-shell, foreign-toplevel and workspace listing,
idle notification, session lock, global shortcuts, gamma and output control,
and the security context manager itself. The 31 names Hyprland withholds from a
security-context client are where it started; the other nine came from reading
every global the proxy's tables describe against the same class — protocols
another compositor implements, or that Hyprland hands a sandboxed client
anyway. It stays a denylist and not "the class of privileged protocols": one
nobody has written into it is advertised to the sandbox on this path, and a line
in `PRIVILEGED` is the only thing that hides it. The sidecar line of an
explanation gains `, hides 40 privileged globals` on that path, which is the
length of the denylist and not a count of what a given compositor offers — an
explanation never probes, so one printed from the command line always describes
the security-context path.

A compositor bubbler cannot reach at all — nothing answering on
`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` — stops the run instead, the way a missing
bind source does everywhere else. So does a run started with `$WAYLAND_SOCKET`
set: `$WAYLAND_SOCKET is set; bubbler must be started without an inherited
compositor connection`, because the client would take that value as a
descriptor number, adopt it as the connection and close it when the connection
drops, and nothing says the number is not one this run opened for itself. That
client is pure Rust (`wayrs`); bubbler links no libwayland.

`wayland "host"` asks for that socket outright, with every global the compositor
offers, which is what an application that drives one of those protocols itself
needs — a screen recorder, a clipboard manager, a bar. No proxy runs in front of
it either: the sandbox connects to the session socket directly, so nothing
decodes what it sends and no clipboard read is gated, focused or not. `bubbler
lint` warns about it (`wayland-host`) and takes a `lint-allow` node naming the
protocol as the reason. No shipped profile grants it. The mode is one value and
not a set, so a layer that includes another replaces it in either direction,
tightening `"host"` to the security context or widening it back; the lint reads
the result.

`--dry-run` and `--explain` never speak to the compositor, so what they print
assumes the security context: the bind source is the instance's own socket, and
under `--explain` its group carries a `security-context:` line naming the three
strings. A real run is the only thing that probes, and the only thing that
falls back. An explanation asks nothing of anything, with one exception: on a
config with `a11y`, `--explain --proxy` prints the proxy's argv, and the
accessibility bus address is part of that argv, so it is resolved the way a run
resolves it — see "The accessibility bus".

`x11 "host"` bypasses all of it. Those clients speak the X protocol to a server
which is itself an ordinary client of your session, connected on the session's
socket rather than through this one, so no security context reaches them — and
X11 offers no isolation between its own clients either. A bare `x11` bypasses
nothing: the server it starts is a client of this socket, as sandboxed as the
application talking to it, which is the next section.

### x11

A bare `x11` binds nothing of your X session. `bubbler-init` binds the display
socket itself — `/tmp/.X11-unix/X0`, in the private `/tmp` every sandbox gets —
and starts the command straight away; the rootful `Xwayland` behind that socket
goes up when the first client connects to it. That server is one more client of
whichever socket the `wayland` grant bound into the sandbox — the proxy's under
a sandboxed `wayland`, the session's own under `wayland "host"`. The display the
application talks to is the sandbox's own: its MIT-SHM segments are in the
private `/dev/shm`, and the only clients on it are processes of this instance.
X11 still offers no isolation between the clients of one server, and that has
not changed; what changed is who else is on the server.

Nothing about that display is eager. The socket is listening before the command
runs, so a client that arrives before the server exists waits in its queue
instead of failing to connect; the supervisor hands that listening descriptor
to Xwayland as `-listenfd <fd>` and deliberately leaves the queued connection
where it is, so the server accepts it on the very descriptor it inherited and
the client that woke it is the client it serves. Measured here, that first
client waits about 0.2 s and nothing after it waits at all. A command that
never speaks X11 never wakes a server: no Xwayland process and no empty window
of one in your session, which is what an instance granted `x11` for the
occasional X client used to cost whether or not one ever appeared.

`DISPLAY` is `:0`, set with `--setenv` so a dry run shows it, and the
supervisor hands the same value to every `exec` child rather than letting one
inherit whatever your terminal had. It is set from the first instruction the
command runs, server or no server: `:0` is that socket, and the socket is bound
before the command is spawned.

The command line is fixed but for the window:

    /usr/bin/Xwayland :0 -noreset -nolisten tcp -nolisten local -nolisten unix -ac -hidpi -decorate -geometry 1280x720

`-noreset` prevents the server reset that closing the last client connection
would otherwise trigger: a reset frees every remaining client's resources and
returns the server to its initial state, which is what a launcher restarting
its own interface would pay. The server keeps running either way — `-terminate`
is the flag that would end it, and bubbler passes none. The three `-nolisten`
flags name transports `Xserver(1)` would otherwise listen on: `tcp` keeps the
display off the network; `local` keeps it off the abstract socket namespace,
which is where the second listener would be, an abstract unix socket being
addressed by name in a network namespace and ignoring the mount namespace
entirely, so under `network "host"` every process on the host could reach it;
and `unix` keeps the server from opening a path socket of its own, that being
the one `bubbler-init` has already bound and is handing over. What is left is
that one filesystem socket at `/tmp/.X11-unix/X0`, which is the only way in.
`-ac` then turns off the access control X11 would apply on it: no cookie is
generated and none is needed, the reachable set being the sandbox itself.
`-hidpi` has the server follow the scale of the output it is on. `-listenfd
<fd>` is appended at run time and names the descriptor the socket arrives on;
the words `--dry-run` prints are the rest of what runs.

Three properties describe that window, and a fourth names a program:

    x11                              # 1280x720, decorated
    x11 geometry="1920x1080"         # <width>x<height>, both non-zero
    x11 fullscreen=#true grab=#true  # a whole output; input held inside it
    x11 wm="openbox"                 # a window manager inside, with the server

`fullscreen` (`-fullscreen`) takes an output instead of a window and drops
`-decorate` with it, there being nothing left to decorate, and `geometry` goes
unused. `grab` (`-host-grab`) inhibits the compositor's own keyboard shortcuts
and confines the pointer to the server's window — what a game wants, and what
Ctrl+Shift releases; Xwayland's manual page notes that it leans on the
shortcut-inhibit and pointer-constraint protocols and does nothing under a
compositor offering neither. `x11 "host"` takes none of the four: a property
describing a window bubbler never opens, or a window manager for a display that
is not this sandbox's to manage, is a parse error rather than a line with no
effect.

The server is a Wayland client that renders through glamor, and glamor has no
software path here, so the flattened config must carry a `wayland` (either
mode) and a `dri`, or nothing starts at all:

    bad argument for `x11`: requires wayland and dri

`bubbler try --grant x11` therefore wants `--grant wayland --grant dri` beside
it. What runs is the host's `/usr/bin/Xwayland`, out of the read-only `/usr`
every sandbox has — the `xorg-xwayland` package — probed while the argv is
built, so a host without it fails with ``service `x11` needs
`/usr/bin/Xwayland` which does not exist`` rather than handing the application
a `DISPLAY` that names nothing.

Under `--explain` the grant is those lines:

      x11 geometry="2560x1440" wm="openbox"  config.kdl:4  21 arguments
        --setenv DISPLAY :0
        --x11 /usr/bin/Xwayland :0 -noreset -nolisten tcp -nolisten local -nolisten unix -ac -hidpi -decorate -geometry 2560x1440 --  (nested Xwayland, started by bubbler-init on the first X connection; -listenfd is added at run time)
        --wm openbox  (window manager inside the sandbox, started with the server)

`--x11 <argv…> --` and `--wm <program>` are arguments of `bubbler-init` and not
of bwrap: the supervisor reads the server's command line up to that `--`, then
the window manager's name, and the sandbox's own command follows the last one.

`wm=` is one program name — non-empty, no `/`, no whitespace, no NUL, no
leading `-` — resolved on the sandbox's own `PATH`, and the supervisor starts
it immediately after the server on that same first connection, so the window
manager is lazy too and is never itself the client that wakes the server. An
ICCCM window manager reparents the windows that already exist when it starts,
so the client that woke the server is managed even though its first window came
first. bubbler ships no window manager and probes none on the host: a name that
resolves to nothing inside is a log line rather than a failed launch,

    bubbler-init: wm nosuchwm: No such file or directory (os error 2)

as is one that starts and then exits, said once and never restarted:

    bubbler-init: wm true exited

Both leave the display serving and the command running. The archwiki's "Window
manager" page is the list to pick from: `xorg-twm` (twm, Xorg's own
default/fallback since 1989), `openbox`, `jwm` and `icewm` are in the official
repositories, and `matchbox-window-manager` (AUR) shows one window at a time,
which is close to what a single-window game wants. Whichever it is, it is
inside the boundary: one more process of this instance, with the same access to
the X server as the application it manages. A Steam-shaped instance writes it as

    x11 geometry="2560x1440" wm="openbox"

There is one server, so it stopping is the display going away. A server that
cannot be spawned at all takes the command with it —

    bubbler-init: Xwayland did not start: <error>

— and so does one that dies later (`bubbler-init: Xwayland exited; stopping the
command`); the run still reports the command's own status. From that moment the
supervisor is *stopping*: the command and every `exec` child are sent SIGTERM,
whatever is still there five seconds later is SIGKILLed, and the deadline
belongs to the first stop event rather than being renewed by the next. A
`bubbler exec` arriving inside that grace is refused rather than started,

    bubbler-init: stopping; xterm was not run

on the request's own stderr with exit code 127, and a client connecting to the
display socket during it wakes nothing: a run that is ending does not start a
server. A SIGTERM to `bubbler-init` from outside is the same stop, by the same
rules.

In the other direction the display goes last: the command exits, every `exec`
child is shut down, then the window manager, and only then does Xwayland get
its SIGTERM, five seconds and a SIGKILL. Nothing outlives the run and there is
nothing to clean up on the host, the socket having been in a `/tmp` that goes
with the sandbox. The one failure that happens before any of this is the socket
itself:

    bubbler-init: cannot bind the display socket: <reason>

with exit code 2, printed before the command is spawned, so nothing has run.

Without `wm=` there is no window manager in there, which is what the lint note
`x11-nested-no-wm` says: X windows are undecorated, unmanaged and stacked in
the one compositor window, so an application that opens dialogs gets them piled
on its main window with nothing to move them. Keyboard focus follows the
pointer too, as X does without a window manager: while the pointer is over the
root rather than a window, keys go nowhere, and a game that fills only part of
the root loses input whenever the pointer leaves it. Fullscreen in the game, or
`fullscreen=#true grab=#true`, is what makes input stable. Neither a
`fullscreen=#true` config nor a `wm=` one gets the note: the first has asked
for the single full-output window already, the second has named the manager.

The server writes its own startup noise to the sandbox's stderr, which is
yours: xkbcomp warnings about the session's keymap, under a line saying that
errors from xkbcomp are not fatal to the X server. They are not fatal to the
run either — only a server that fails to start or exits stops the command.

Measured here on Xwayland 24.1.13, Hyprland 0.56.2 and an RTX 4070 SUPER: a
client inside the nested server saw 26 extensions, GLX among them with direct
rendering, plus MIT-SHM, XInput, XKEYBOARD and XTEST. `dri` is not optional for
that — without it Xwayland dies in glamor during startup, `-glamor off`
included.

`x11 "host"` is the older behaviour, kept: the session's `/tmp/.X11-unix/X<n>`
bound at the same path inside (a different display number may not work), and
whatever Xauthority the environment names — `$XAUTHORITY`, else
`$HOME/.Xauthority` when that is a regular file, which is libX11's default and
not the wiki's — remapped to `/home/bubbler/.Xauthority` so the host path stays
hidden. That grant is no boundary at all: every X client on your display can
read every other's input and windows, this sandbox included, and the
compositor's security context does not reach an X client. `bubbler lint` warns
(`x11-without-reason`), `bubbler run` warns again before a real run —

    bubbler: warning: x11 "host" grants no isolation between X clients

— and `steam` and `lutris` are the two shipped profiles carrying it, each with
a `lint-allow` naming the window manager their applications want as the reason.

The X SECURITY extension's untrusted mode is not offered as a third one. An
untrusted client is granted `XC-MISC` and `BIG-REQUESTS` and nothing else
(`SecurityTrustedExtensions` in the X server's `Xext/security.c`), so it has no
GLX, no RENDER, no XInput, no XKEYBOARD and no MIT-SHM: a mode in which the
applications that need `x11` do not run is not a mode.

The mode is one value and not a set, so a layer that includes another replaces
its `x11` node whole, window properties and all, in either direction, and the
lint reads the result.

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

    # keepassxc's config.kdl (its profile lists the line in the header)
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

Grant the id on both sides. No shipped profile carries it, because a password
manager and a browser each run without it: `keepassxc`'s header lists
`app-runtime "org.keepassxc.KeePassXC" mode=rw` with the `lint-allow
"app-runtime-rw"` that goes with it, `firefox` and `chromium` list the
read-only line, and each is pasted into that instance's config
(`bubbler edit kp`, `bubbler edit ff`) or into your own profile layer:

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

`outbound "deny"` narrows what the sandbox may reach to the addresses the
config names. pasta has no destination filtering of its own, so the filter is
an nftables ruleset bubbler installs in the sandbox's own network namespace:

    table inet bubbler {
      chain out {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
        icmpv6 type { nd-router-solicit, nd-router-advert,
                      nd-neighbor-solicit, nd-neighbor-advert } accept
        ip daddr 169.254.1.1 udp dport 53 accept
        ip daddr 169.254.1.1 tcp dport 53 accept
        <one or two rules per allow-out>
        reject with icmpx admin-prohibited
      }
    }

`--explain` prints the ruleset a run would install, and the shipped profiles
install none: `outbound` is opt-in per instance and defaults to `"allow"`.

**Neighbour discovery is open, and it has to be.** It is how an IPv6 stack finds
its router and its neighbours, and the sandbox sends it like any other packet.
Measured with the rule taken out: an `allow-out` naming a v6 address fails five
times out of five with `EHOSTUNREACH` after three seconds, because the sandbox
never resolves its own gateway — IPv6 is dead under the filter whatever the
config says. With the rule the filtered namespace behaves exactly as an
unfiltered one does. `no-ipv6` leaves the namespace no IPv6 address at all, and
then the rule is left out with it, along with the refusal below.

`allow-out "<address>[/<prefix>]"` takes a v4 or v6 address or network, with an
optional `port=` and an optional `proto="tcp"|"udp"`; a child that names neither
means every port over TCP and UDP, and nothing else — ICMP included, so `ping`
does not answer under a filter. The bits below a prefix must be zero:
`nft` would read `1.1.1.1/24` as `1.1.0.0/24` and allow 256 addresses where its
author wrote one, so bubbler refuses it instead. Two more nodes are refused for
being rules that could never match: an IPv4-mapped address (`::ffff:1.1.1.1`),
which names an IPv4 destination that no `ip6` rule ever sees, and an IPv6
`allow-out` or `dns` under `no-ipv6`, which takes the address family away. The **resolver** is opened by
bubbler, not by you: whatever `/etc/resolv.conf` ends up naming — the generated
`169.254.1.1` or a `dns` child — is accepted on UDP and TCP port 53, since a
filter that broke name resolution would look like a network outage rather than
a policy. The table is `inet`, so IPv6 falls under the same policy; an `ip`
table would leave it open and read identically in `nft list ruleset` to anyone
not looking at the family.

**It filters by address, and it cannot filter by name.** `allow-out
"api.example.com"` does not exist and will not: a name would have to be
resolved once at launch into a set of addresses, and a CDN, an Anycast pool or
a DNS failover answers with different ones later — the connection then dies
mid-run, refused by the sandbox's own firewall rather than by the peer, which
is a worse failure than not offering it. `bubbler lint` says the same thing as
the `outbound-deny` note.

**What a blocked destination looks like.** A trailing `reject` rather than a
drop, so the application gets an error instead of hanging for its own connect
timeout — tens of seconds in a browser, forever in something with no timeout at
all. Measured on this host: TCP over IPv4 fails with `EHOSTUNREACH` ("No route
to host") and UDP with `EPERM` straight out of `sendto`, both in under a
millisecond; TCP over IPv6 fails with `EACCES` after about a second, since the
kernel matches the ICMPv6 error to the socket only on the first SYN
retransmit. `policy drop` is only the backstop under that rule: an nftables base
chain takes `accept` or `drop` as a policy and nothing else.

**The sandbox cannot read the rules, let alone flush them.** They live in the
user namespace that owns the sandbox's network namespace, and bwrap puts the
application in a *nested* one; `user_namespaces(7)` grants privileged
operations on a non-user namespace only to a process holding the capability in
the namespace that owns it. Measured from inside a filtered sandbox: `nft list
ruleset` fails with `Operation not permitted` before it can even read the
table. Creating its own user and network namespace does not help either — that
namespace is a child, and it is empty.

**`oifname "lo" accept` is safe only because pasta forwards nothing.** The
sandbox's own loopback has to work, and pasta's `-T`/`-U` port forwarding would
put a socket of pasta's on that loopback and `splice(2)` it to the host —
traffic that never becomes a packet and that netfilter therefore never sees.
Measured: with pasta's defaults a host service on `127.0.0.1` answers inside
the sandbox while this ruleset is installed. bubbler passes `-T none -U none`
on every run and a unit test holds the two together, so whoever relaxes one has
to come past it. `allow-port` does not reopen it: pasta binds those on the
*host* and connects into the namespace, a direction an application cannot ride
outwards.

The rules are installed by spawning `nft -f -` — a short-lived child that
enters the sandbox's owning user namespace and its network namespace, and is
fed the ruleset on stdin. It runs after bwrap reports the sandbox pid, before
pasta and before the sandbox is let go of its `--block-fd`, so the namespace
has a policy before it has a route and the application has not executed an
instruction either way. If it fails for any reason — a ruleset nftables
refuses, a five-second silence, a missing package — the run is stopped: a
sandbox that asked to be filtered never runs unfiltered. `nftables` is
therefore a runtime dependency of `outbound "deny"` and of nothing else — on
Arch it is not part of `base` — and a host without it is told which package to
install rather than given the network it did not ask for.

That child holds **CAP_NET_ADMIN and nothing else**. Capabilities do not survive
`execve`, so the one it needs is put in the ambient set, which does; and
`SECBIT_NOROOT` stops the kernel from adding the rest, since bwrap's own nested
user namespace maps bubbler to uid 0 and a uid-0 exec would otherwise come up
with the full set. Measured both ways, and pinned by a test: with the securebit
the child's `CapEff` is `0000000000001000`, without it `000001ffffffffff`. As
with pasta, the capability is one in the *sandbox's* user namespace, which your
own account created, so it is authority over the sandbox and over nothing else.

An `outbound "deny"` in one layer cannot be dropped by a layer above it. A
profile that filters and an `include` of it under a bare `network` node is a
conflict `bubbler` refuses by name, rather than a merge in which the plain node
wins and the sandbox quietly gets the whole internet back. Adding destinations
from above is fine, and they add up.

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
`DBUS_SYSTEM_BUS_ADDRESS`, `AT_SPI_BUS_ADDRESS`, `IBUS_USE_PORTAL`.

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
`$XDG_RUNTIME_DIR`, `$XDG_DATA_HOME/bubbler` where the instances live,
`$XDG_CONFIG_HOME/bubbler` where your own profile layer lives, and
`/home/bubbler`, the private home, on the side that is bound at. Being one of
them, being inside one, or containing one is refused, and the error names the
root that stopped it. So a share of `/kioxia` is refused if `$XDG_DATA_HOME` is
on that disk: a sandbox that can write another instance's `config.kdl` grants
itself anything on the next run, and one that can write a profile grants itself
that on every instance seeded from it afterwards. All four roots your
environment names — your home, `$XDG_RUNTIME_DIR`, the instance store
`$XDG_DATA_HOME/bubbler` and the profile layer `$XDG_CONFIG_HOME/bubbler`, each
of them as well as the directory above it — are compared both as written and as
resolved, so a symlinked home or a symlinked instance store cannot be shared
under its real name either. `/etc` and your home have typed grants of
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
`$XDG_RUNTIME_DIR`, the instance directory and the profile layer stay refused.

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
inside a single node. `portals`, `notify`, `tray`, `mpris`, `a11y` and
`input-method` need `dbus` in the merged result, not in every layer, so a layer
may add `notify` to a `dbus` it includes.

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

Every profile carries what its application needs to *run* and nothing beyond
that. A bus, notifications, a tray icon, screen sharing, media keys, a browser
rendezvous — each is written out in the profile's own header comment, as the
node to paste in, with what it buys and what it hands over. So the shipped set
is the floor, `bubbler profile edit <name>` is where you raise it, and nothing
is granted because an application "usually" wants it.

Every one is Wayland-first; only the two gaming profiles grant `x11`, and both
ask for the session's display with `x11 "host"`. `~/name` below is a
`home-share`, read-only unless it says `rw`.

    alacritty     wayland
    chromium      wayland dri pulseaudio network dbus portals, ~/Downloads rw
    code          wayland dri network dbus portals, ~/Projects rw
    firefox       wayland dri pulseaudio network dbus portals, ~/Downloads rw
    generic       nothing beyond the baseline
    keepassxc     wayland, ~/Documents rw
    kitty         wayland dri
    libreoffice   wayland, ~/Documents rw, SAL_USE_VCLPLUGIN=gtk3
    lutris        wayland x11 "host" dri pulseaudio network gamepad, ~/Games rw
    mpv           wayland dri pipewire, ~/Videos
    spotify       wayland dri pulseaudio network
    steam         wayland x11 "host" dri pulseaudio network gamepad
    thunderbird   wayland network, ~/Downloads rw
    vesktop       wayland dri pulseaudio network

Sound is `pulseaudio` in every profile that has any, and `pipewire` only in
`mpv`. That is not a preference: `pulseaudio` binds
`$XDG_RUNTIME_DIR/pulse/native` and sets `PULSE_SERVER` to it, which is the
path a libpulse client takes, and most of the applications here are measured
libpulse clients: `libpulse` is in the Arch dependencies of `firefox` and
`chromium`, and `/opt/spotify/spotify`, `/opt/spotify/libcef.so` and
`/usr/lib/electron40/electron` each carry `libpulse.so.0` for the dlopen. On a
PipeWire host that socket is the one pipewire-pulse serves, so nothing is lost
by taking it. `steam` and `lutris` are the unmeasured half of that claim — the
client fetches its own runtime on first run, and Wine is not installed on the
machine this was written on — so both headers say so and name the fix: if a
game is silent, add `pipewire` beside the `pulseaudio`. `pipewire`
binds `pipewire-0`, the native socket, which is what a client speaking the
PipeWire protocol itself uses (mpv) and what the portal hands a screen or
camera stream over — which is why the profiles that could share a screen list
`pipewire` as an opt-in beside their `portals`. Either socket carries capture
as well as playback, so either is the microphone.

Five carry a `desktop` node, because their application's entry is not named
after its command: `alacritty` (`Alacritty.desktop`), `keepassxc`, `lutris`
and `thunderbird` (reverse-DNS names), and `libreoffice`, whose command is run
by eight entries — the start centre is the one meant. The rest resolve by file
name; `mpv`'s does too, once mpv is installed. See "Desktop entries".

`SAL_USE_VCLPLUGIN=gtk3` is there because bubbler clears the environment,
leaving LibreOffice's VCL plugin to an autodetection with nothing to go on.
The Mozilla apps need no variable of their own: Gecko has defaulted to Wayland
since Firefox 121 and takes it from the `WAYLAND_DISPLAY` the `wayland` grant
sets, so `MOZ_ENABLE_WAYLAND=1` is gone from both profiles — write
`env MOZ_ENABLE_WAYLAND="0"` to go back to Xwayland. `firefox` no longer owns
`org.mozilla.firefox.*` either: that name is the remote-instance protocol a
second `firefox` reaches the running one through, which is a convenience
rather than a condition of starting, so it is the `dbus { own … }` block its
header lists.

`chromium`, `code` and `vesktop` keep their own namespace sandbox: it nests
inside bubbler's, so none of them needs `--no-sandbox`. Where a package ships a
setuid `chrome-sandbox` helper the namespace path is taken instead of it; Arch's
`code` ships that helper without the setuid bit at all, so it never had another
path. On a kernel with unprivileged user namespaces turned off, that nesting is
what breaks first. None of the
three may carry `userns "disable"`, and none of them needs an ozone hint:
Electron picks the Wayland backend on its own, and Arch's `vesktop` wrapper
sets the variable anyway.

`keepassxc` is the shortest profile of the set: a display and `~/Documents`.
No `network` — a database opens without one, and the grant is your password
manager's process reaching the internet. No `own "org.freedesktop.secrets"`:
that name makes the sandbox the Secret Service for the whole session, so every
libsecret client in it would store its secrets there. It is an outward grant
rather than a confinement. No `hidraw`, which would not help anyway: KeePassXC
drives a YubiKey through libusb and a smart card through pcsclite, and bubbler
grants neither. Browser integration is not in the profile either, but it is one
line away: the header carries the
`app-runtime "org.keepassxc.KeePassXC" mode=rw` node and its `lint-allow`, and
`firefox` and `chromium` carry the matching read-only line, so the socket
KeePassXC serves is reachable from another instance once both sides name the
id. Installing the native messaging manifest is still yours to do;
"KeePassXC-Browser, both sides under bubbler" under "app-runtime" is the whole
procedure.

`spotify` and `vesktop` end up the same four nodes — display, GPU, the
PulseAudio socket, a network — because that is what playing and calling take.
The media keys (`mpris name="spotify"`, the exact name and not a prefix: the
player name is `org.mpris.MediaPlayer2.spotify` while the app id is
`com.spotify.Client`, and a `*` would own every player on the bus), the tray
icon, the notifications, the screen sharing (`pipewire` plus `portals`) and
Vesktop's `~/Downloads` are opt-ins in their headers. `kitty` is two nodes and
needs no grant for the pseudoterminals it makes: `--dev` gives each sandbox a
private devpts instance with an index space of its own, and the host's
`/dev/pts` is never bound. Its `dbus` and `portals` opt-in is what the
`org.freedesktop.portal.Settings` read takes, without which it cannot follow
the desktop colour scheme — it starts either way. Never share kitty's
remote-control socket across the boundary — `kitten @` includes `launch`, so a
reachable socket is command execution in whichever direction it was shared.

`steam` and `lutris` are the two that grant `x11`, and both write it as
`x11 "host"`, which is the weak point of both: X11 has no isolation between
clients, so a sandbox on your display can keylog every other client on it,
Xwayland included. They ask for the session's display rather than the nested
one because Steam's UI (steamwebhelper) is an X11/CEF client with no Wayland
support whose many windows want a real window manager, and because Wine's X11
driver takes precedence over its Wayland one for every game Lutris starts, with
the same want. The nested server has no window manager unless the config names
one, so it is ready as it is for a single fullscreen game (`x11
fullscreen=#true grab=#true`) and wants a `wm=` for a launcher: `x11
geometry="2560x1440" wm="openbox"`, with `openbox` installed, is what to try in
place of either profile's `x11 "host"` before accepting that grant's cost — and
is what the `lint-allow` reason each of them carries names. Neither carries a
`seccomp` node any more: the Steam
runtime, umu/Proton and DXVK's 32-bit path are i386, and the default filter now
covers i386 alongside x86_64, so they are filtered rather than killed. Neither
may ever carry `userns "disable"` — pressure-vessel nests its own bubblewrap for
every Proton game. `/dev/hugepages`, `/dev/fuse` and `/dev/snd` are still not
bound.

Neither gaming profile reaches a bus at all now. What their headers list, and
what each is worth: the names the client claims for itself
(`own "com.steampowered.*"` with its `own-too-wide` allow, `own
"net.lutris.Lutris"`), the power-save blockers a running game holds
(`org.freedesktop.ScreenSaver`, `org.freedesktop.PowerManagement`), GameMode
for Lutris — inert where `gamemoded` is not installed — and on the system bus
UPower plus UDisks2 enumeration: `see` and the one `GetManagedObjects` call
Wine builds its drive list from, never a `talk`, which would also hand the
sandbox loop setup, mount and LUKS unlock, judged by polkit as you. `notify`
and `tray` are there too, one rule each.

`steam` is also the one profile that must not be given `portals`, and that is
not an oversight: the grant writes `/.flatpak-info`, Steam's own runtime reads
that file as "I am the unofficial Steam Flatpak", and
`steam-runtime-check-requirements` then exits 71 demanding the flatpak-portal
service, which stops `steam.sh` before the client starts. Steam has its own
file browser, so what it costs is the screencast and file-chooser portals.
`lutris` lists `portals` in its header because Lutris itself calls them, but a
Proton or umu game brings the same steam-runtime-tools along, so that is the
grant to drop first if one stops with a Flatpak complaint.

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

Opening an arbitrary file from outside the shared directories — LibreOffice's
or Thunderbird's file chooser — is what the `dbus` and `portals` pair in those
two headers is for: the portal runs the chooser on the host, exports what you
pick into the instance's own document-portal view, and the path it hands back
opens there (see "D-Bus"). Without them the chooser is the one inside the
sandbox, and it sees the private home and the shared directory.

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

## Desktop entries

    bubbler desktop ff              # ~/.local/share/applications/bubbler-ff.desktop
    bubbler desktop ff --replace    # …/firefox.desktop, shadowing the application's
    bubbler desktop ff --print      # print the entry instead, touching nothing
    bubbler desktop ff --remove     # delete the entries written for ff
    bubbler desktop --refresh       # rewrite every entry bubbler has written

`desktop` copies the application's own `.desktop` file and changes five things
in the copy: every `Name` and `Name[xx]` gains ` (Bubbler)`, so the entry is
marked in every locale rather than in English; every `Exec` — the main one and
each `[Desktop Action]`'s — becomes `bubbler open <instance> -- <the
application's own command line>`; `TryExec` names bubbler; `DBusActivatable`
is set to `false`; and `X-Bubbler-Instance=<instance>` is added. Everything
else is copied through untouched — every group, every key, every locale, the
comments and the blank lines — including keys bubbler knows nothing about.

The field codes (`%u`, `%F`, `%i`, …) stay exactly where the application put
them, which is at the end, which is where `bubbler open` collects its command.
Nothing is quoted around them: a field code inside a quoted argument has no
defined meaning.

Which entry is copied is decided in this order: the instance's `desktop
"<name>.desktop"` node, then `<command>.desktop`, then the one entry whose
`Exec` runs `<command>`. All three look in `$XDG_DATA_HOME/applications` first
and then in the `applications` directory of every absolute `$XDG_DATA_DIRS`
entry (`/usr/local/share` and `/usr/share` when that variable is unset; a
relative entry is ignored, as the XDG base directory specification asks),
which is where a launcher looks, so a flatpak export or a Nix profile on that
list is found too. Entries bubbler wrote itself are never a source, and neither is one
a launcher does not display (`NoDisplay=true`), which is what an application's
MIME-handler-only entries are: both the scan and the `<command>.desktop`
lookup pass over them. A `desktop` node is the exception, since that is you
naming the file you mean. Two candidates are an error listing both rather than
a guess — that is what the `desktop` node is for, and five shipped profiles
carry one. An entry carrying `Hidden=true` is refused wherever it is reached:
that key means the file is to be treated as if it were not there, so a copy of
it would be an entry that does nothing.

`Exec` names `bubbler` bare only when `PATH` resolves that name to the running
binary, and the binary's own path otherwise. This matters more than it looks:
GLib refuses to build an application entry at all when the `Exec` program or
the `TryExec` cannot be found, so an entry naming a `bubbler` that has since
moved does not fail loudly — it silently vanishes from the menu.
`bubbler desktop --refresh` rewrites every entry bubbler has written, with the
binary re-resolved and each application's file copied again.

**bubbler never writes over a file it did not write.** The default entry is a
second one, `bubbler-<instance>.desktop`, beside the application's.
`--replace` writes the application's own file name into your applications
directory instead, where it shadows the system entry: a user entry wins over a
system one of the same name, so the menu keeps one entry, `mimeapps.list`
defaults keep resolving to it, and window matching by `app_id` keeps working.
Either way, a file already there that carries no `X-Bubbler-Instance` of this
instance's is refused with its path — move it aside yourself. There is no
`--force` and no backup file; deleting bubbler's entry is what brings the
application's own back. `--remove` deletes the entries carrying this
instance's marker and nothing else.

After writing or removing, `update-desktop-database` is run on the directory
if it is installed, which is what puts the entry in "Open With" lists; a
missing one is a warning. `desktop-file-validate`, when installed, is run on
the result and the errors it reports are printed as warnings — its hints and
warnings about the application's own keys are not, since bubbler copied them.
`mimeapps.list` is never touched: `xdg-mime default <entry> <type>` is the
documented way to make the sandboxed entry a default for a type it did not
already handle.

Three limits worth knowing before clicking:

- **`%f` and `%F` hand over host paths the sandbox cannot see.** They expand
  to `/home/you/…`, and the sandbox's home is `/home/bubbler` with the host's
  never bound; the specification even allows a temporary copy under `/tmp`.
  Only files under a `home-share` or `path-share` resolve. `%u` needs no
  mount and is better where the application offers it.
- **Two URLs at once may lose one.** A `%u` or `%f` entry is started once per
  argument, and two `bubbler open` processes that both find the instance
  stopped will both try to start it; one of them loses.
- **D-Bus activation is only closed for this entry.** `DBusActivatable=false`
  stops a launcher from ignoring `Exec` and asking the session bus to start
  the application unsandboxed. Anything that activates the application's bus
  name directly still starts the host copy: shadowing that would mean owning
  `$XDG_DATA_HOME/dbus-1/services` too, which bubbler does not do.
## PATH shims

    bubbler wrap ff                  # ~/.local/bin/ff opens instance `ff`
    bubbler wrap ff --as firefox     # under the application's own name instead
    bubbler wrap --list              # name, instance, path, ok|broken
    bubbler unwrap ff                # the shim and its registry line

A shim is a symlink in `~/.local/bin` pointing at the bubbler binary. Started
through it, bubbler reads the name it was called by out of `argv[0]`, looks it
up in `$XDG_CONFIG_HOME/bubbler/wraps.kdl` and becomes `bubbler open
<instance> -- <the instance's command> <your arguments>`, so `ff
https://example.com` opens that URL in the sandbox — in the window that is
already open when one is, since that is what `open` does. There is no extra
process and no script to keep in step: the symlink *is* bubbler.

`argv[0]` is the caller's to choose — `exec -a firefox …` sets it to anything —
so the name is a key into a file bubbler wrote, never a name turned into an
instance: a name the registry does not hold runs the ordinary CLI. It is also
the only source, since `current_exe()` reads `/proc/self/exe` and so resolves
the symlink back to the real binary.

**The default name is the instance's, not the application's.** `bubbler wrap
ff` puts `ff` on `PATH`, and typing `firefox` still starts the real one.
`--as firefox` is how you ask for the other thing, and it prints a note when
you do, because a shim intercepts more than what you type: of the 109 `Exec=`
lines under `/usr/share/applications` on the desktop this was measured on, 75
name a bare command for `PATH` to resolve, so wrapping `code` also changes what
the VS Code menu entry starts — no desktop file edited, and nothing to see. A
desktop entry that says in its own name what it is is the explicit way to say
that.

`~/.local/bin` is not on Arch's default `PATH`: the whole of `/etc/profile`'s
contribution is `/usr/local/sbin`, `/usr/local/bin` and `/usr/bin`, and nothing
under `/etc/profile.d` adds to it. So `wrap` says so rather than leaving behind
a file that can never run, and says so again when a directory earlier on your
`PATH` already holds that name.

Refused, in every case naming the path and changing nothing: the names bubbler
resolves itself (`bubbler`, `bubbler-init`, `bwrap`, `xdg-dbus-proxy`, `pasta`,
`passt`) — wrapping `bubbler` is a loop, and the rest would break every sandbox
on the machine; anything outside the instance name grammar, so no `/`, no
spaces and no control characters; an instance with no `command`, which would
leave the shim nothing to run; a name another instance already holds; and any
existing path that is not a shim of bubbler's own. "bubbler's own" is a symlink
pointing at a file named `bubbler`, so a package upgrade that moves the binary
does not turn your shims into strangers, and a symlink somebody aimed elsewhere
never becomes one. bubbler never moves a file aside and never deletes what it
did not create, so `unwrap` on a name someone has since put their own file
under drops the registry line and leaves the file alone.

`wrap --list` prints one tab-separated line per shim: name, instance, path, and
`ok` or `broken`. `broken` is anything that would not run — the link deleted by
hand, a file of that name that is not one of bubbler's symlinks, a bubbler
binary that has moved, or an instance that has been deleted — and `bubbler wrap
<instance>` writes it again. `delete` names the shims left pointing at the
instance it removed rather than deleting them for you: they are files on your
`PATH`, and taking them away is `unwrap`'s job.

Two `wrap`s at once cannot lose each other's entry: the read-modify-write of
the registry is held under a `flock(2)` on `wraps.kdl.lock` beside it, and the
file itself is replaced by a rename, so a reader sees one whole registry or the
other.

Nothing inside a sandbox can reach a shim: the sandbox's `PATH` is `/usr/bin`,
its home is `/home/bubbler`, and no shim directory is ever bound in. The one
footgun left is wrapping a program bubbler itself runs on the host — `edit`
execs `$VISUAL`/`$EDITOR` with no shell, so a wrapped `nvim` would open
`config.kdl` inside a sandbox that has no bind for it.

## Terminal editor

    bubbler ui                       # start it
    bubbler-ui                       # the same thing, on its own

`config.kdl` is a list of grants whose meanings are the rest of this README,
and the editor exists to put that text next to the toggle. The centre of it is
one instance's grants: every node the config holds, then every node it could,
with what granting each one costs and what `bubbler lint` makes of it — of the
buffer as edited, not of the file on disk — in the pane beside it. `!` marks a
grant that reaches wider than its name, `!!` one that gives the sandbox power
outside itself.

It is a **separate binary**. The command line links no terminal UI toolkit: by
`cargo tree -e normal`, `bubbler`'s tree is 42 crates and the editor's is 76,
and `bubbler ui` runs the `bubbler-ui` beside it, else the first on `$PATH`,
and says how to install one when there is none.

Everything it does, it does by running `bubbler`. There is no second path into
a sandbox: `r` runs `bubbler run <instance> --tty none`, `x` runs `bubbler exec
…`, `e` runs `bubbler edit …`, and each is built as an argv with no shell
anywhere. `run` and `open` are started detached: a process group of their own, so a `^C`
meant for the editor is not sent to them, and `/dev/null` for stdio, so they
hold no descriptor of this terminal. It is a new process group and not a new
session — they stay in the editor's session, under its controlling terminal —
and the state column catches up on the next second's probe. `exec`, `try` and
the editors take the terminal instead: the editor leaves raw mode and the
alternate screen first, and takes them back when the command exits, without
asking the terminal anything on the way in or out.

Whatever it ran, what is in the buffer stays in it: the list is read again
afterwards, unsaved edits are kept, and the status line says so.

`q` leaves and `Esc` goes back one screen. `^C` does nothing while the editor
is up: the terminal is in raw mode, so every key reaches the editor rather
than the shell.

Keys, with `?` for the full list on every screen:

| screen | keys |
|---|---|
| instances | `Enter` grants, `r` run, `o` open, `x` exec, `t` try, `n` new, `d` delete, `R` reseed, `e` `$EDITOR`, `l` lint, `L` last-run log, `D` desktop entry, `W` shim, `X` explain, `p` profiles, `^R` re-read |
| grants | `Space` grant or revoke, `Enter` write the node as KDL, `e` `$EDITOR`, `s` save, `u` undo, `l` lint, `X` explain, `Esc` back |
| profiles | `Enter` show it flattened, `c` create an instance from it, `e` `$EDITOR` on your layer, `l` lint |
| viewer | `j`/`k` scroll, `f` every argument, `p` the proxy's argv |

`Space` grants a node that means something on its own and revokes any node at
all. Everything else is `Enter`, which opens the node as one line of KDL —
`home-share "Downloads" mode=rw` — parsed by the parser that reads the file, so
a line the editor accepts is a line bubbler accepts, and one it refuses stays on
screen with the reason under it. A block node is valid KDL on one line too, so
`dbus { talk "ca.desrt.dconf" }` goes in the same field; `e` drops to `$EDITOR`
when a node is better read as a file, which is the escape hatch for anything
the editor cannot express.

The two prompts that take a command line — `x` and `t` — split it the way a
shell splits a simple one and no further: spaces separate arguments, `"` holds
a run of them together, `\` escapes the next character, and nothing at all is
expanded, since nothing here reaches a shell. `t` takes
`<profile> [bare grant ...] [keep=<instance>] [-- <command ...>]`, so a profile
with no `command` node of its own can still be given one.

`s` writes the file through the same path `reseed` does: the profile header and
the config version are kept, `config.kdl.bak` is written first, and what was
rendered is parsed again before it replaces anything. **Comments are not kept**
— the file is rendered from the config, exactly as `create` and `reseed` render
it — and the status line says so. `u` goes back to the config as last written.
Saving while the sandbox is running is allowed and says what `bubbler edit`
says: bwrap cannot be told about a bind after the fact, so it applies on the
next start.

The terminal comes back three ways: the ordinary one, a panic — the hook
restores it before the message — and `SIGINT`, `SIGTERM` or `SIGHUP`, which set
a flag the loop reads rather than touching the terminal from a signal handler.
There are no threads: one `poll` with a one-second timeout is the whole
scheduler, and the only thing a tick does is probe each instance's control
socket, which never unlinks a stale one.

Not in it: profile editing (`e` drops to `$EDITOR`), a run monitor, mouse
support and `bubbler man`.

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
`portals`/`notify`/`tray`/`mpris`/`a11y`/`input-method` grant no layer gives a
`dbus` to carry), `path-share-reserved` (a root bubbler never shares),
`dup-name-policy` (one bus name given two policies by two layers),
`own-on-system-bus`, `camera-without-portals` (a `camera` grant no layer gives
a `portals` to carry, so the portal reads the sandbox as an ordinary process
of yours).

**Warnings** say the file grants more than it probably means to:
`x11-without-reason` (an `x11 "host"` grant with no `lint-allow` reason; the
nested default never warns), `seccomp-disabled`,
`userns-disabled-with-nested-sandbox`
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
without `/.flatpak-info`, which is worse than wrong), `wayland-host`
(`wayland "host"`, the session's own compositor socket, which the compositor
cannot tell from your session).

**Notes** are information and fail nothing: `app-runtime-rw` (a shared
application runtime directory granted `mode=rw`, so the sandbox can replace the
sockets everything else naming that id connects to), `network-host`
(`network "host"`, the one mode that puts the sandbox on the host's network
stack), `outbound-deny` (an address policy, not a name one),
`ozone-hint-unnecessary`,
`command-not-found`, `desktop-entry-missing` (a `desktop` node naming an entry
no application directory here holds, which is what a profile for software you
have not installed looks like), `camera-nodes-none-present` (`camera nodes=#true` on a
host with no `/dev/video*` or `/dev/media*`, so that half of the grant binds
nothing), `camera-nodes-no-hotplug` (the node list is frozen at launch, and
under an isolated network namespace no uevent reaches the sandbox either —
that second half is dropped under `network "host"`), `secrets-access`
(`talk`/`own` of
`org.freedesktop.secrets` on the session bus reaches the whole login keyring:
the Secret Service API partitions nothing between the applications that call
it), `lint-allow-unused` (a `lint-allow` node that accepts nothing, which is a
suppression outliving what it was written for — and the one check no
`lint-allow` silences, since that node would be the unused one),
`x11-nested-no-wm` (a nested `x11` with neither `fullscreen=#true` nor `wm=`:
the server it starts has no window manager, so the X windows inside are
undecorated and unmanaged in the one compositor window it draws).

A warning or a note is accepted with a `lint-allow` node, which takes a check
id and a required reason:

    x11 "host"
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
would filter a bus the session is not on; unset or empty is that default. An
address naming a socket under `$XDG_RUNTIME_DIR/bubbler/` is refused outright,
before anything is probed or bound:

    service `dbus`: the host bus address names a socket under bubbler's own runtime directory

That is bubbler's own runtime directory. It holds an instance's control socket,
the one `bubbler exec` connects to, and the bus socket the proxy serves at
`<name>/bus`, so the guard catches an address naming the exec channel and one
naming a socket this very proxy is about to serve. Neither is a bus the session
is on. All three addresses are guarded
(`dbus`, `system-bus` and the accessibility bus under `a11y`, each named in the
message as the node it belongs to), and each is resolved before it is compared:
symlinks followed, `..` folded, and the resolved path is what is bound, so the
comparison and the bind are made on the same path. The guard is against a
misdirected address — stale, copied, or hostile in an otherwise sane
environment — and not against your own uid, which owns that directory and every
socket in it either way. `--explain --proxy` applies the same guard, so an
explanation and a run agree; the one gap is an address whose socket and whose
parent directory are both absent, where only the lexical form is left to
resolve and a link that a run would follow is not followed, so an explanation
can describe a bus the run it describes goes on to refuse.

Everything the sandbox may reach is a rule: the `dbus` children above, plus the
bundles `portals`, `notify`, `tray`, `mpris` and `input-method`, and the `a11y`
grant whose rules are on a bus of its own — each of which needs `dbus`.
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

The grant also binds this instance's own view of the document portal: host
`$XDG_RUNTIME_DIR/doc/by-app/org.bubbler.<name>` at `$XDG_RUNTIME_DIR/doc`
inside. A file chooser hands the application a path of the form
`/run/user/<uid>/doc/<id>/<name>`, which lives on the `fuse.portal` mount
`xdg-document-portal` makes; without that bind there is nothing there to
open. Only the app id's own subtree is bound, never the mount root, which
holds every other application's documents as well. The bind is read-write
because the portal's own FUSE decides the mode per document: one this app id
has no WRITE grant on has `0222` stripped from its bits and is refused an
open for writing, so a read-only bind would take away nothing but the writes
the user did grant. A host with no such mount — the portal not running — is
not an error: the launch binds nothing there and prints `bubbler: warning:
portals: no document portal at /run/user/<uid>/doc, so a file picked in a
portal dialog cannot be opened inside`. Files under a `home-share` or
`path-share` are reachable either way.

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

### The accessibility bus

`a11y` grants the session's accessibility bus, the one AT-SPI runs on: it is
how a screen reader, a magnifier or an on-screen keyboard reads an
application, and without it a sandbox is invisible to them. archwiki
Accessibility says a Gtk-, Qt- or Gecko-based application "should work out of
the box" and appear in `accerciser` with "a deeply nested tree structure of
children"; a sandbox without this grant cannot appear there at all, since
nothing binds that socket and the session proxy has no rule for it.

Handing the sandbox that bus as it stands would be the same mistake as binding
the session's X11 socket. It is a peer bus with no per-client policy, and what
is on it is offered to whatever connects: at-spi2-core's `DeviceEventController`
carries `RegisterKeystrokeListener`, which is how a screen reader's global keys
work and which is every keystroke of every accessible application in the
session, and `GenerateKeyboardEvent` and `GenerateMouseEvent`, which type and
click into that session; the registry and the desktop object tree behind it are
every other application's widgets, labels and text.

So it is proxied like the other two buses, and by the same process. The
accessibility bus is a **third address** on the instance's one
`xdg-dbus-proxy`: an option applies to the address before it
(`xdg-dbus-proxy(1)`), so that address gets a `--filter` of its own and rules
of its own, and nothing of this grant lands on the session bus. The rules are
fixed — the node takes no children — because there is no other subset of that
bus worth offering:

    --call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Embed@/org/a11y/atspi/accessible/root
    --call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Unembed@/org/a11y/atspi/accessible/root
    --call=org.a11y.atspi.Registry=org.a11y.atspi.Registry.GetRegisteredEvents@/org/a11y/atspi/registry
    --call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetKeystrokeListeners@/org/a11y/atspi/registry/deviceeventcontroller
    --call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetDeviceEventListeners@/org/a11y/atspi/registry/deviceeventcontroller
    --call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersSync@/org/a11y/atspi/registry/deviceeventcontroller
    --call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersAsync@/org/a11y/atspi/registry/deviceeventcontroller
    --broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerRegistered@/org/a11y/atspi/registry
    --broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerDeregistered@/org/a11y/atspi/registry

That is the application registering itself with the registry, unregistering,
reading back which events are registered so a toolkit knows whether to emit
them, and notifying the listeners that exist. Every destination but the
registry is refused, which is what keeps the sandbox away from the other
applications on that bus, and the two `Register`/`Generate` families above are
not in the list at all. What the assistive tool does in the other direction
needs no rule: a call *into* the sandbox is incoming, and `xdg-dbus-proxy`
filters only what the client sends — the property `tray` already relies on.

The bus is found the way at-spi2's own clients find it: `$AT_SPI_BUS_ADDRESS`
if the session set one, else `org.a11y.Bus.GetAddress` on the session bus,
asked by bubbler itself over its own bus client — one method call on one
object of one name, with no program on `PATH` to spawn and no shell anywhere.
The session bus it asks on is the one the `dbus` grant proxies
(`$DBUS_SESSION_BUS_ADDRESS`, else `$XDG_RUNTIME_DIR/bus`), so the address that
comes back belongs to that same session. Asking in that order means the bus
bubbler proxies is the one the applications on this host are already on, and
asking it ourselves means an `a11y` grant needs no second package to look it
up with. The address has to be a `unix:path=` one: at-spi's launcher can report
a `unix:abstract=` address instead, and the proxy's own sandbox has no host
network namespace, so there would be nothing there to connect to — that is
refused with a message saying so, as `tcp:` is on the other two buses. Every
failure — no session bus to ask, no `org.a11y.Bus` answering, an answer that is
not a socket path — stops the run naming the step rather than dropping the
grant: a socket with no bus behind it looks to the application like a broken
toolkit and to you like a sandbox that quietly gave less than the config asked
for. The address itself is never echoed back in an error, being host input like
any other.

Inside the sandbox the filtered socket is bound read-only at
`$XDG_RUNTIME_DIR/at-spi/bus` and `AT_SPI_BUS_ADDRESS` is set to `unix:path=`
that path, which is what every at-spi2 client reads before it asks any bus for
an address. The host's own accessibility socket is bound only into the proxy's
sandbox, never into the application's. `AT_SPI_BUS_ADDRESS` is a reserved `env`
key, so no config can point a client at another one — see "env, command and
desktop".

`--dry-run` and a plain `--explain` still speak to nothing: they print the bind
of the socket the sidecar would serve, which does not exist yet either way.
`--explain --proxy` is the exception — the argv it prints for the proxy is
built *from* the host address, so it resolves that address the way a run would,
and on a session with no `org.a11y.Bus` it fails instead of printing a
placeholder.

Measured here, inside a `dbus a11y` sandbox on a session running at-spi2:
`Registry.GetRegisteredEvents` and `DeviceEventController.GetKeystrokeListeners`
answer with an empty array, while
`DeviceEventController.RegisterKeystrokeListener` and
`DeviceEventController.GenerateKeyboardEvent` come back
`Error org.freedesktop.DBus.Error.AccessDenied` — the proxy's refusal, before
the registry sees them.

To check the grant on your own desktop, install `accerciser` and look for the
sandboxed application's tree in it (archwiki Accessibility). Two kinds of
application need more than the grant, and both are the profile's business
rather than bubbler's: a Chromium- or Electron-based one needs the environment
variable `ACCESSIBILITY_ENABLED=1` and the argument
`--force-renderer-accessibility`, and a Java one needs the ATK bridge
installed (archwiki Accessibility). `env` and `command` are where those go.

### Input methods

`input-method` is the D-Bus half of typing through fcitx5 or IBus. It grants
two session-bus rules, `--talk=org.freedesktop.portal.Fcitx` and
`--talk=org.freedesktop.portal.IBus`, and sets `IBUS_USE_PORTAL=1` in the
sandbox. Both names are granted whichever daemon the session runs, since the
grant costs nothing where the name has no owner: the Qt and GTK client
libraries watch for their portal name and use it when the daemon's own name is
not visible, which is exactly what the proxy's name filtering leaves them, and
the IBus client library takes the portal when `IBUS_USE_PORTAL` is set.

Those two names are the daemons' sandboxed entry points, and they carry the
per-client text-input interface and nothing else. The daemons' own names are
deliberately not granted: fcitx5's carries `Exit`, `Restart`, `SetConfig`,
`SetAddonsState`, `SetCurrentIM`, `SetLogRule` and `OpenWaylandConnection` —
reconfiguring or stopping the input method for every application in the
session, which is tampering and denial of service rather than keylogging, since
an input context belongs to one client.

On Wayland the grant is often unnecessary. archwiki Fcitx5 "Wayland": the
native *text-input* protocol "usually yields better results than input method
modules", GTK and Qt "utilize *text-input* if no other IM module is explicitly
specified", and so it is "generally recommended to only use IM modules in
Xwayland applications". That path is the compositor's and needs nothing from
bubbler. The bus path is for the rest: an Xwayland client (a bare `x11` starts
one inside), an application with an IM module set, or a *text-input-v1* client
where the compositor speaks v3.

bubbler sets no IM-module variable itself, because which one is right depends
on the application and the toolkit, and a wrong one takes away the working
Wayland path. A profile sets them with `env`. archwiki Fcitx5 "IM modules"
gives `GTK_IM_MODULE=fcitx` and `QT_IM_MODULE=fcitx`, "globally if using X11"
or "for each Xwayland application" on a Wayland compositor with *text-input*
support, plus `SDL_IM_MODULE=fcitx` for "some games that use a specific version
of the SDL2 library":

    input-method
    env GTK_IM_MODULE="fcitx"
    env QT_IM_MODULE="fcitx"
    env SDL_IM_MODULE="fcitx"

archwiki IBus "Integration" gives `GTK_IM_MODULE=wayland`, `QT_IM_MODULE=ibus`
and `XMODIFIERS=@im=ibus` for a Wayland session, and `GTK_IM_MODULE=ibus` with
the same two for X11. `env` is emitted after every variable a grant sets, so a
profile layers these on top. `AT_SPI_BUS_ADDRESS` and `IBUS_USE_PORTAL` are
refused there like the two bus addresses: the address names the only
accessibility socket the sandbox has, and the flag is what makes an IBus
client look for the portal name at all, so a config setting either could only
aim a client away from what the grant provides. That also means `input-method`
is the one way to reach the IBus portal: a hand-written `talk` rule with
`env IBUS_USE_PORTAL="1"` is a parse error.

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

`x11 "host"` remaps any Xauthority file to `/home/bubbler/.Xauthority`, but it
stays a compatibility grant: X11 offers no isolation between clients. A bare
`x11` reads neither variable — it starts a server of its own. Sockets and
cookie files named by the environment must really be of that type, so a
`WAYLAND_DISPLAY` or `XAUTHORITY` naming a directory is refused instead of
binding the tree under it.

## Threat model

`docs/threat-model.md` is the long form: the assets, the attacker — one
compromised application inside one sandbox, or a profile someone talked you
into installing — the four trust boundaries, and what each mechanism above
defends and what it does not, every claim against the section that describes
it and the test that would fail if it changed.

The short form: the boundary bubbler builds is between your account and the
application. It is not a boundary against root, not one against your own
processes outside a sandbox — anything running as your uid can read the
instance store and connect to a live instance's control socket. On the display,
`wayland` is a boundary the compositor enforces with a proxy of bubbler's in
front of it, and a bare `x11` an X server of the sandbox's own behind that;
`x11 "host"` is no boundary at all.

bubbler itself is unprivileged and unconfined: it can do whatever your account
can. `contrib/apparmor/usr.bin.bubbler` is an AppArmor profile that would narrow
that to bubbler's own directories — for as long as bubbler stays inside it,
which `bubbler edit` running your `$EDITOR` does not — offered as a courtesy to
packagers on distributions that mediate user namespaces through AppArmor. **It has never been
loaded.** The kernel here has AppArmor compiled in but left out of its LSM list,
so the module never initialises, and `apparmor_parser` — which ships in the same
`apparmor` package — is not installed here either, so that file has not even
been syntax-checked, let alone exercised. It ships in complain mode, nothing in
bubbler installs or reads it, and `allow userns create,` is the line to keep if
you narrow it: without it every `bubbler run` on Ubuntu 23.10 and later fails at
the uid map, because bwrap inherits the profile wherever the distribution loaded
none of its own.

## Known gaps

- The `input-method` grant has never been exercised against a running input
  method: neither fcitx5 nor IBus is installed on this machine. What is proven
  inside a real sandbox is the proxy's half — the daemons' own names have no
  owner there, the two portal names resolve, and `IBUS_USE_PORTAL=1` is in the
  environment — and no daemon has ever answered. See "Input methods".
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
- The `kdl` crate parses `{` by recursing, so a deeply nested profile or
  `config.kdl` would overflow the stack and abort bubbler with no diagnostic
  at all. bubbler pre-checks every configuration it reads and refuses one
  larger than 1 MiB or nested deeper than 32 braces, naming the file; the
  check counts braces outside strings and comments and is not a parser, and
  the recursion itself is upstream's (`kdl` 6.7.1).
- A generated desktop entry closes D-Bus activation for itself only, and its
  `%f` file arguments are host paths the sandbox cannot open; both are under
  "Desktop entries".
- The clipboard gate stops a *background* read, not a focused application. The
  keystrokes you type into a sandboxed window are exactly what arms it, so an
  application you are working in can read the selection within a second of any
  key you press in it, and `clipboard="open"` drops the gate entirely. Nothing
  travelling on a passed descriptor is inspected either — the proxy judges the
  request that carries the pipe, not the bytes that come back; see "wayland".
- A window a sandboxed application maps is attributed by the compositor to the
  `bubbler-wl-proxy` sidecar, whose credentials the connection carries.
  Compositor window rules keyed on a pid, and any tool that maps windows back to
  processes, name the sidecar rather than the application; see "wayland".
- The proxy's interface tables are generated at build time from the protocol XML
  the `wayrs` crates ship, so a protocol newer than those crates is one the
  proxy cannot parse and therefore hides from the sandbox. Three interfaces went
  that way on this host; two of them have current replacements the sandbox does
  get. Refreshing the tables means bumping those crates; see "wayland".
- The fallback denylist lets `zwp_keyboard_shortcuts_inhibit_manager_v1`
  through: it takes the compositor's own key combinations only while a surface
  of the sandbox's own has focus, which is what a VM or a remote-desktop window
  needs. On a compositor that reserves no combination for itself, a fullscreen
  window holding it is a keyboard trap, and getting out of one is the
  compositor's policy and not bubbler's; see "wayland".
- `x11 "host"` bypasses the Wayland security context: those clients speak to a
  server that is a client of your session's own socket, so what a compositor
  withholds from a sandboxed client it does not withhold there; see "wayland".
- bubbler ships no window manager, so a nested `x11` has one only where the
  host has a `wm=` program installed and the config names it; without that an
  application with more than one window gets them undecorated and stacked; see
  "x11".

## Files

Instances live in `$XDG_DATA_HOME/bubbler/instances/<name>/` (by default under
`~/.local/share`), each holding a `config.kdl` and the private `home/`, plus a
`last-run.log` once a run without a terminal has left one there — mode 0600,
emptied by each run that starts a sandbox, added to by one that execs into a
running instance, and never over a mebibyte: the cap is measured against the
file before every write, so two bubblers writing to it cannot between them
push it over. Desktop entries are written to `$XDG_DATA_HOME/applications/`,
which together with the shim directory below is all bubbler ever writes to
outside its own state. Every
run except a dry run or an explanation also creates
`$XDG_RUNTIME_DIR/bubbler/<name>/`, mode 0700, reusing one left over from an
earlier run, and binds the control socket `init.sock` in it; a sandboxed
`wayland` grant adds `wayland`, the socket the sandbox connects to and
`bubbler-wl-proxy` serves, and beside it `wayland-context`, where the
compositor accepts the security context; a `dbus`, `system-bus` or `a11y` grant
adds the subdirectory
`dbus/` the proxy creates its sockets in and the checked sockets `bus`,
`system` and `a11y` — one per granted bus — beside it, and a `portals` grant adds
`$XDG_RUNTIME_DIR/.flatpak/bubbler-<name>/`, creating `.flatpak/` if it is
missing. Everything a run makes there is removed again when it ends, with one
exception: an `app-runtime` grant creates `$XDG_RUNTIME_DIR/app/<id>` (and
`app/` above it) and leaves it, since a peer of another instance may still be
using it.
`HOME` and `XDG_RUNTIME_DIR` must be set and non-empty. Your profiles live in
`$XDG_CONFIG_HOME/bubbler/profiles/` (by default under `~/.config`) and the
system's in `/usr/share/bubbler/profiles/`, or wherever
`$BUBBLER_PROFILE_DIR` points instead. `wrap` keeps its registry beside them in
`$XDG_CONFIG_HOME/bubbler/wraps.kdl` and its symlinks in `~/.local/bin/`.

Those socket paths have to fit the 107 bytes a Unix socket address holds, so
`create` and `try` refuse a name that would make one longer instead of letting
the kernel truncate it silently and the connection fail somewhere else.

The `bubbler-init` binary is taken from `$BUBBLER_INIT` if set (it must be a
regular file), else from next to the `bubbler` binary, else from
`/usr/lib/bubbler/bubbler-init`; `bubbler-wl-proxy` is looked up the same way,
from `$BUBBLER_WL_PROXY`, then next to `bubbler`, then
`/usr/lib/bubbler/bubbler-wl-proxy`. `$BUBBLER_DBUS_PROXY` likewise replaces the
`xdg-dbus-proxy` on `PATH` with a regular file bound into the proxy sandbox at
its own path; it exists for tests and debugging, as do the
`$BUBBLER_TEST_ALLOW_PATH` described under "Host paths" and
`$BUBBLER_WRAP_DRY_RUN=1`, which makes a shim print the `bubbler open` command
line it resolved to, one argument per line, and exit without starting
anything.

## Build

    cargo build --release
    cargo build --release -p bubbler -p bubbler-init -p bubbler-wl-proxy   # no editor

The workspace builds four binaries: `bubbler`, the `bubbler-init` supervisor
bound into every sandbox, the `bubbler-wl-proxy` sidecar every sandboxed
`wayland` grant runs behind, and `bubbler-ui`, the terminal editor. Only the
last of them links a terminal UI toolkit (see "Terminal editor"), so leaving it
out is a `-p` away and costs nothing else; the other three are not optional.

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
every shipped profile that has one — and `nft` (the `nftables` package) for a
config that writes `outbound "deny"`, which no shipped profile does.

## Checks

Four commands, all clean before every commit:

    cargo fmt --all
    cargo clippy --all-targets -- -D warnings
    cargo test
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

**Rust 1.95 or newer**, pinned as `rust-version` in the workspace manifest.
Edition 2024 alone would need only 1.85; the floor is `kdl` 6, and writing it
down buys one clear error on an older toolchain instead of a spray of syntax
failures. It is a recent floor: bubbler does not build on Debian stable's
rustc, and `kdl` is the single crate to reconsider if that ever matters.

The suite starts real sandboxes wherever it can, and every test that needs one
is guarded by a probe that does the thing it is a probe for: a user namespace
that has to be created, a `bwrap --unshare-all --ro-bind / / --proc /proc --dev
/dev` that has to build a sandbox, a pasta that has to attach to a namespace.
A host that cannot sandbox — a container whose policy refuses the mounts, say —
skips those tests, with the reason on stderr, instead of failing them, so the
run stays green and says what it did not cover. Run it as `cargo test
--workspace`: `cargo test -p bubbler` alone does not build `bubbler-init`, and
the tests that need the real supervisor skip for that reason too.

With `$WAYLAND_DISPLAY` set the Wayland tests are as real as the rest: they run
against your own compositor, mapping a window and taking the focus for a
moment, and they take the selection and give it back with one flavour on it —
its plainest text form, or its first content type where it had no text, so an
HTML selection comes back as text and an image-only one as the image. What was
serving it does not come back: a selection has one owner, and the test took it.

`cargo test` includes the property tests in
`crates/bubbler-core/tests/proptest.rs`, which are three claims about generated
input rather than about a written-down example:

- every configuration the emitter writes, the parser reads back as the same
  grants — a round trip that loses or widens one would be a sandbox that
  differs from the file describing it, and nothing else in the suite looks for
  that;
- a patched desktop entry is refused a second patch, so a launcher entry can
  never end up starting a sandbox inside a sandbox;
- the `include` resolver answers on any graph of layers, cycles and chains
  past the depth limit included, instead of recursing until the stack ends.

A fifth check needs the network for the RustSec advisory database, so it runs
in CI and at each release rather than per commit:

    cargo deny check          # configured in deny.toml

Four things at once: advisories (a yanked or unmaintained crate anywhere in the
graph fails, not only a vulnerable one), a licence allowlist where every entry
is one-way compatible with bubbler's GPL-3.0-or-later, crates.io as the only
permitted source, and a ban on wildcard version requirements. Two versions of
one crate is a warning rather than an error: the editor's tree carries three
(`syn`, `unicode-width`, `hashbrown`), which is what ratatui costs, and the
number is worth reading at each release rather than blocking on.

## Fuzzing

`fuzz/` is a [cargo-fuzz](https://rust-fuzz.github.io/book/) crate, excluded
from the workspace: libFuzzer wants a nightly compiler, and the four checks
above run on stable. It is a tool for the maintainer to reach for when a parser
changes, not part of CI.

    cargo install cargo-fuzz
    cargo +nightly fuzz run config_parse \
        fuzz/corpus/config_parse fuzz/seeds/config_parse -- -max_total_time=60

Seven targets, each an entry point that reads bytes bubbler did not write:

| Target | What it feeds |
|---|---|
| `config_parse` | `config.kdl` and profile-layer text |
| `kdl_roundtrip` | parse -> render -> parse, asserting the grants are equal |
| `profile_resolve` | layer files split out of the input, then flattened |
| `desktop_patch` | a `.desktop` file a packager shipped |
| `init_wire` | the in-sandbox supervisor's exec request decoder |
| `seccomp_names` | syscall names, through `libseccomp` to a compiled filter |
| `wrap_registry` | `wraps.kdl`, and the `argv[0]` a shim is dispatched on |

`fuzz/seeds/<target>/` holds the starting inputs, and is committed: the
fourteen shipped profiles for the two KDL targets, the desktop fixtures for the
patcher, hand-written bytes for the rest. The first two sets are symlinks into
the tree rather than copies, so a profile that changes changes the seed with
it. Random bytes barely reach past the KDL tokenizer, so seeding is what makes
those targets worth running at all. The working corpus (`fuzz/corpus/`) and any
crash artifacts are not committed.

The targets also build and run on stable, without a nightly toolchain:

    cd fuzz && cargo build --release
    ./target/release/config_parse -max_total_time=60 seeds/config_parse

That is worth knowing and worth being honest about. Stable has no sanitizer
coverage, so libFuzzer says as much on startup and degrades to an unguided
mutation loop: it executes the harness at full speed and catches a crash, but
it does not grow an input across generations, which is the part that finds
anything a unit test would not have. Use it to check a target still works; use
nightly to actually fuzz.

## Installing

    cargo build --release --locked

    install -Dm755 target/release/bubbler      /usr/bin/bubbler
    install -Dm755 target/release/bubbler-init /usr/lib/bubbler/bubbler-init
    install -Dm755 target/release/bubbler-wl-proxy /usr/lib/bubbler/bubbler-wl-proxy
    install -Dm755 target/release/bubbler-ui   /usr/bin/bubbler-ui
    target/release/bubbler man          > /usr/share/man/man1/bubbler.1
    target/release/bubbler man --config > /usr/share/man/man5/bubbler-config.5

That is the whole install set, and each path is one the code itself names.

`bubbler-ui` is the terminal editor (see "Terminal editor") and is optional:
`bubbler ui` looks for it beside the `bubbler` binary and then on `$PATH`, and
a build without it is a command line that says where to get one. Splitting it
off is what keeps the tree of the binary that starts sandboxes at 42 crates
against the editor's 76.

`bubbler-init` is deliberately not in `/usr/bin`. It is the supervisor bubbler
binds into every sandbox, not a command to type. `bubbler-wl-proxy`, the
sidecar in front of a sandboxed `wayland` socket, is beside it for the same
reason and is found the same way (`$BUBBLER_WL_PROXY`, then next to the running
`bubbler`, then `/usr/lib/bubbler/bubbler-wl-proxy`), so a build tree runs what
it just built. bubbler looks for the supervisor in
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
`passt` package) for an isolated `network`, and `libseccomp`. An `a11y` grant
needs an accessibility bus to find — `at-spi2-core`; the address is asked of
the session bus by bubbler itself, so no other package goes with it. An
`input-method` grant reaches something only where fcitx5 or IBus is running.
Portals need `xdg-desktop-portal` and a backend for your desktop; neither is
bubbler's to start. Nothing here depends on a shell: bubbler ships no
completions.

Packaging lives in a repository of its own, not in this one.

## CI

`.github/workflows/ci.yml` runs on every push to `master` and on pull requests
at <https://github.com/han-xyz/bubbler>. Four jobs, each in an `archlinux:latest`
container that installs its toolchain with rustup: `check` runs the four
checks (`cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo doc --no-deps` under `RUSTDOCFLAGS=-D warnings`, `cargo test
--workspace`), `deny` runs `cargo deny check` against `deny.toml`, `msrv`
type-checks the workspace with the 1.95 toolchain that `rust-version` pins,
and `sandbox-probe` installs `bubblewrap`, `passt`, `libseccomp` and `nftables`
and prints whether `unshare -Urn` and `bwrap --unshare-all` actually work on
that runner.

That last job is the one to read first. Tests that need a real sandbox probe
for one and return early with a printed reason when they cannot have it, so a
green `check` does not by itself mean a sandbox was ever built. A hosted runner
is expected to fail the `bwrap` line — Docker's default seccomp profile denies
`pivot_root`, `mount` and `umount2` — which leaves the real-sandbox coverage to
a self-hosted runner. `sandbox-probe` is what tells you which of the two you
are looking at.

## Acknowledgements

Thanks to [bubblejail](https://github.com/igo95862/bubblejail) and
[firejail](https://github.com/netblue30/firejail) for the inspiration, and to
[bubblewrap](https://github.com/containers/bubblewrap) for doing the namespace
work.

## License

GPL-3.0-or-later. See `LICENSE`.
