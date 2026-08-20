# bubbler

Application sandboxing on top of [bubblewrap](https://github.com/containers/bubblewrap),
combining bubblejail's explicit instances and resource grants with a profile
library in the spirit of firejail. bubbler itself is unprivileged; `bwrap`
does the namespace work.

Status: milestone 2 — the `alacritty` and `firefox` profiles run, with GPU,
sound and a private home. See "Known gaps" below.

## Usage

    bubbler create ff --profile firefox   # seed config.kdl from a built-in profile
    bubbler create ff                     # --profile defaults to `generic`
    bubbler profiles                      # built-in profile names, one per line
    bubbler edit ff                       # open config.kdl, then re-check it
    bubbler run ff                        # uses `command` from config.kdl
    bubbler run ff -- firefox --version   # or run something else inside
    bubbler run ff --dry-run              # print the bwrap argv, do not launch
    bubbler exec ff -- firefox --version  # run inside the instance already running
    bubbler try -- id                     # throwaway sandbox, nothing kept
    bubbler try --profile firefox --grant network -- firefox --version
    bubbler try --keep scratch -- sh      # keep it afterwards as instance `scratch`
    bubbler list
    bubbler delete ff --yes               # instance and private home; irreversible

`create` prints the directory it made. `--dry-run` prints `bwrap` and then one
argv element per line, byte for byte, so it can be diffed; an element
containing a newline would be ambiguous in that framing. It builds the argv
only: nothing is launched and no runtime directory is created.

Every sandbox runs under `bubbler-init`, a small supervisor bound in at
`/run/bubbler-init`. It serves a control socket in the instance's runtime
directory, which `exec` connects to; the socket is bound by bubbler and only
handed to the sandbox as an inherited file descriptor, so nothing inside can
reach the path. `run` on an instance that is already running says so and
execs into it instead of starting a second sandbox; configuration changes
apply on the next start. An exec'd process is given bubbler's own stdin,
stdout and stderr, so the channel is for tooling and debugging, not an extra
boundary.

`try` runs one command in a sandbox without creating an instance. Its config is
the profile text (`generic` unless `--profile` says otherwise) plus one bare
node per `--grant`; the grants are `wayland`, `x11`, `network`, `dri`,
`pipewire`, `pulseaudio`, `dbus`, `portals` and `notify`, and anything with
arguments needs a real instance. The sandbox lives in
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
`-`, and cannot be `.` or `..`.

## Config (KDL)

One top-level node per grant, plus `command`. Unknown nodes are errors, and
file order does not affect the generated argv.

    wayland                          # the host Wayland socket
    x11                              # X socket and Xauthority
    network                          # network namespace shared, plus /etc/resolv.conf
    dri                              # GPU: /dev/dri and the PCI devices' sysfs
    pipewire                         # $XDG_RUNTIME_DIR/pipewire-0
    pulseaudio                       # $XDG_RUNTIME_DIR/pulse/native, sets PULSE_SERVER
    home-share "Downloads"           # $HOME/Downloads at /home/bubbler/Downloads
    home-share "Projects/x" mode=rw
    etc-share "vulkan"               # /etc/vulkan read-only; one path component
    dbus {                           # session bus through a filtering proxy
        see "org.freedesktop.ScreenSaver"
        talk "ca.desrt.dconf"
        own "org.example.App"
        call "org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.Read@/org/freedesktop/portal/desktop"
        broadcast "org.freedesktop.portal.Desktop=@/org/freedesktop/portal/desktop"
    }
    portals                          # XDG portal rules plus /.flatpak-info
    notify                           # talk to org.freedesktop.Notifications
    mpris name="firefox.*"           # own org.mpris.MediaPlayer2.firefox.*
    env MOZ_ENABLE_WAYLAND="1"       # extra variables, KEY="value", repeatable
    command "firefox"

Every source must exist and be of the expected type when the argv is built; a
missing one is an error rather than a silently weaker sandbox. That covers
`home-share` too, so the `firefox` profile needs a `~/Downloads`. A
`home-share` source is resolved before it is bound and must stay inside your
home directory: a symlink pointing elsewhere is refused, not followed.
`etc-share` is confined to `/etc` the same way, and cannot name the account
files (`passwd`, `group`, `shadow`, `gshadow` and their `-`/`+` variants),
which the sandbox generates itself. `network` needs `/etc/resolv.conf` (the
tmpfs over `/etc` would otherwise hide it). `dri` binds `/dev/dri` read-write
and exposes `/sys/dev/char`, `/sys/devices/system/cpu` and every
`/sys/devices/pci*` root read-only — that is the sysfs attributes of every PCI
device on the machine, not just the GPU. `pipewire` and `pulseaudio` hand the
sandbox the session's audio socket directly, which is capture as well as
playback: everything the session exposes, including the microphone, with no
portal in between.

`env` keys must look like `[A-Za-z_][A-Za-z0-9_]*`, and each key may appear
only once. `env` values and `command` arguments may not contain NUL, a newline
or a carriage return — a newline would forge a line in `--dry-run` output. The
variables the sandbox owns are rejected: `HOME`, `PATH`, `XDG_RUNTIME_DIR`,
`USER`, `LOGNAME`, `WAYLAND_DISPLAY`, `DISPLAY`, `XAUTHORITY`,
`XDG_SESSION_TYPE`, `PULSE_SERVER`, `DBUS_SESSION_BUS_ADDRESS`.

## D-Bus

`dbus` never binds the session bus itself. bubbler starts an `xdg-dbus-proxy`
in a sandbox of its own — no network, no home, read-only `/usr`, an `/etc`
holding at most `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d` and
`nsswitch.conf`, the host bus socket read-only and the instance's runtime
directory read-write — and binds the filtered socket it serves at
`$XDG_RUNTIME_DIR/bus` inside the sandbox, with `DBUS_SESSION_BUS_ADDRESS`
pointing there. The start waits up to five seconds for the proxy to report
that it has bound its socket and is accepting connections, and fails if it
does not; the proxy exits with the sandbox. `--dry-run` prints that bind
without starting anything.

The proxy's socket lives in `$XDG_RUNTIME_DIR/bubbler/<name>/dbus/`, and that
directory is the only writable path in the proxy's own sandbox. The instance
directory above it is never bound there: it holds the control socket
`init.sock`, and reaching that socket means running commands inside the app.

The host bus is `$DBUS_SESSION_BUS_ADDRESS` when it is a `unix:path=`
address, else `$XDG_RUNTIME_DIR/bus`, and must be a socket. Everything the
sandbox may reach is a rule: the `dbus` children above, plus the bundles
`portals`, `notify` and `mpris`, each of which needs `dbus`. `portals` also
puts a `/.flatpak-info` naming the instance in the sandbox, which is what
portals identify it by. `BUBBLER_DBUS_LOG=1` runs the proxy with `--log`, so
every filtered message is printed to bubbler's stderr.

## Baseline

Every sandbox gets: all namespaces unshared, no network, read-only `/usr` and
`/opt`, empty `/tmp` `/var` `/run`, a private home at `/home/bubbler`, an
empty `$XDG_RUNTIME_DIR` at the host's path with mode 0700, `/home/bubbler` as
the working directory, and a cleared environment (only the locale and terminal
variables — `TERM`, `LANG`, `LANGUAGE`, `COLORTERM`, `TZ`, `LC_*` — are
carried over). Grants only add to that.

`/etc` is an allowlist over a tmpfs: only the entries in `ETC_ALLOWLIST`
(`crates/bubbler-core/src/bwrap.rs`) are bound, and only those that exist on
the host — `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d`, `fonts`, `localtime`,
`machine-id`, `nsswitch.conf`, `hosts`, `host.conf`, `ssl`, `ca-certificates`,
`mime.types`, `xdg`, `gtk-3.0`, `gtk-4.0`, `pulse`, `pipewire`, `drirc`,
`vulkan`, `glvnd`, `egl`, `os-release`. `passwd` and `group` are generated:
the sandbox sees the user `bubbler` (holding the host's uid and gid) and
`nobody`, never the host's accounts, and `USER` and `LOGNAME` are `bubbler`
as well.

`x11` remaps any Xauthority file to `/home/bubbler/.Xauthority`, but it stays
a compatibility grant: X11 offers no isolation between clients. Sockets and
cookie files named by the environment must really be of that type, so a
`WAYLAND_DISPLAY` or `XAUTHORITY` naming a directory is refused instead of
binding the tree under it.

## Known gaps

- No system bus, no accessibility bus, no document-portal FUSE mount: `dbus`
  covers the session bus only.
- No seccomp filter — the sandbox is namespaces and mounts only.
- No proprietary nvidia driver; `dri` covers the open stack.
- `/etc/machine-id` is bound in, so every instance shares one stable
  identifier with the host.
- No desktop entries.

## Files

Instances live in `$XDG_DATA_HOME/bubbler/instances/<name>/` (by default under
`~/.local/share`), each holding a `config.kdl` and the private `home/`. Every
run except `--dry-run` also creates `$XDG_RUNTIME_DIR/bubbler/<name>/`, mode
0700, reusing one left over from an earlier run, and binds the control socket
`init.sock` in it; a `dbus` grant adds the subdirectory `dbus/` holding the
proxied bus socket. `HOME` and `XDG_RUNTIME_DIR` must be set and non-empty.

The `bubbler-init` binary is taken from `$BUBBLER_INIT` if set (it must be a
regular file), else from next to the `bubbler` binary, else from
`/usr/lib/bubbler/bubbler-init`.

## Build

    cargo build --release

Requires `bwrap` at runtime and a kernel with user namespaces.
