# bubbler

Application sandboxing on top of [bubblewrap](https://github.com/containers/bubblewrap),
combining bubblejail's explicit instances and resource grants with a profile
library in the spirit of firejail. bubbler itself is unprivileged; `bwrap`
does the namespace work.

Status: milestone 4 — the `alacritty` and `firefox` profiles run, with GPU,
sound, a private home, a filtered session bus, a terminal of their own and a
seccomp denylist. See "Known gaps" below.

## Usage

    bubbler create ff --profile firefox   # seed config.kdl from a profile
    bubbler create ff                     # --profile defaults to `generic`
    bubbler profiles                      # profile names, one per line
    bubbler profiles --origin             # and which layer each comes from
    bubbler edit ff                       # open config.kdl, then re-check it
    bubbler run ff                        # uses `command` from config.kdl
    bubbler run ff -- firefox --version   # or run something else inside
    bubbler run ff --dry-run              # print the bwrap argv, do not launch
    bubbler run ff --tty none             # no terminal inside at all
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
apply on the next start. An exec'd process is given whatever the terminal
mode decides on (see "Terminal"), and descriptors passed to exec'd commands
are reachable by the sandboxed application through `/proc`: exec is a
convenience channel, not a boundary.

A run is a chain of processes; `bubbler` waits at the top of it and returns the
command's status.

    bubbler ─┬─ bwrap ── bwrap (pid 1 in the sandbox, reaps orphans)
             │              └─ bubbler-init (pid 2) ── your command
             └─ bwrap ── bwrap ── xdg-dbus-proxy    (only with `dbus`)

Each `bwrap` leaves a reaper as pid 1 of its own pid namespace. The proxy's
sandbox is a sibling of the app's, started by `bubbler` and invisible from
inside it.

`try` runs one command in a sandbox without creating an instance. Its config is
the flattened profile (`generic` unless `--profile` says otherwise) plus one
bare node per `--grant`; the grants are `wayland`, `x11`, `network`, `dri`,
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
`-`, cannot be `.` or `..`, and cannot look like `try-<digits>`, which is the
shape `try` gives its own sandboxes and sweeps by pid.

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
    path-share "/kioxia/Steam"       # a host path, at that same path inside
    path-share "/mnt/data" mode=rw
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
    tty "pty"                        # terminal: "pty", "passthrough" or "none"
    seccomp {                        # changes to the default syscall denylist
        allow "perf_event_open"
        deny "unshare" errno="EPERM"
        disable
    }
    env MOZ_ENABLE_WAYLAND="1"       # extra variables, KEY="value", repeatable
    command "firefox"

Every source must exist and be of the expected type when the argv is built; a
missing one is an error rather than a silently weaker sandbox. That covers
`home-share` too, so the `firefox` profile needs a `~/Downloads`. A
`home-share` source is resolved before it is bound and must stay inside your
home directory: a symlink pointing elsewhere is refused, not followed.
`etc-share` is confined to `/etc` the same way, and cannot name the account
files (`passwd`, `group`, `shadow`, `gshadow` and their `-`/`+` variants),
which the sandbox generates itself. `path-share` reaches outside the home and
has rules of its own, under "Host paths". `network` needs `/etc/resolv.conf`
(the tmpfs over `/etc` would otherwise hide it). `dri` binds `/dev/dri`
read-write and exposes `/sys/dev/char`, `/sys/devices/system/cpu` and every
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
profile of yours extends the shipped one instead of forking it. Includes may
nest 8 deep, they resolve depth first before the including file's own nodes,
and a chain that comes back to a file it already read is an error naming the
chain.

Merging is by node: grants are unioned, identical share nodes collapse, and
the same `home-share` path in two modes is an error rather than a silent
choice of `ro` or `rw`. `command`, `tty` and `mpris` from the including file
replace the included one, `env` replaces by key, `dbus` rules and `seccomp`
lists are unioned, and `seccomp { disable }` in any layer disables the
filter. `portals`, `notify` and `mpris` need `dbus` in the merged result, not
in every layer, so a layer may add `notify` to a `dbus` it includes.

`create` and `try` write the flattened result, so `config.kdl` is one screen
that says everything the sandbox will be granted. Its first line records
where it came from:

    // bubbler profile: firefox

Editing an instance never edits the profile, and editing a profile never
changes an instance that was already seeded from it.

## D-Bus

`dbus` never binds the session bus itself. bubbler starts an `xdg-dbus-proxy`
in a sandbox of its own — no network, no home, read-only `/usr`, an `/etc`
holding at most `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d` and
`nsswitch.conf`, the host bus socket read-only and the instance's `dbus/`
subdirectory read-write — and binds the filtered socket it serves at
`$XDG_RUNTIME_DIR/bus` inside the sandbox, with `DBUS_SESSION_BUS_ADDRESS`
pointing there. The start waits up to five seconds for the proxy to report
that it has bound its socket and is accepting connections, and fails if it
does not; the proxy exits with the sandbox. `--dry-run` prints that bind
without starting anything.

The proxy creates its socket in `$XDG_RUNTIME_DIR/bubbler/<name>/dbus/`, and
that directory is the only writable path in the proxy's own sandbox. The
instance directory above it is never bound there: it holds the control socket
`init.sock`, and reaching that socket means running commands inside the app.
Once the proxy reports itself ready, bubbler opens the socket without
following symlinks, checks that it really is a socket, and moves it up to
`$XDG_RUNTIME_DIR/bubbler/<name>/bus` — out of the proxy's reach — before
anything is bound into the sandbox. A proxy that replaced its socket with a
symlink would otherwise have that symlink's target bound in its place. The
proxy keeps serving after the move: it listens on the socket, not on the path.

The host bus is `$DBUS_SESSION_BUS_ADDRESS` when it is a `unix:path=`
address, else `$XDG_RUNTIME_DIR/bus`, and must be a socket. Everything the
sandbox may reach is a rule: the `dbus` children above, plus the bundles
`portals`, `notify` and `mpris`, each of which needs `dbus`. `portals` also
puts a `/.flatpak-info` in the sandbox giving it the application id
`org.bubbler.<name>`, which is what portals and the proxy identify it by. A
`.` in the name becomes `_`, since only the last element of an id may hold a
`-` and xdg-desktop-portal refuses every operation of a sandbox whose id it
cannot parse; a leading digit is prefixed with `_`, which the portal would
take but flatpak's own name check would not. The rules it grants are `--talk`
for `org.freedesktop.portal.Desktop`, `.Documents` and `.FileChooser` plus the
`--call`/`--broadcast` pair from the `xdg-dbus-proxy(1)` examples; the spawn
portal (`org.freedesktop.portal.Flatpak`), which starts processes outside the
sandbox, is not among them.
`BUBBLER_DBUS_LOG=1` runs the proxy with `--log`, so every filtered message is
printed to bubbler's stderr.

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
a seccomp-bpf denylist. bubbler compiles it at launch with `seccompiler` and
hands it to bwrap as two programs on `--add-seccomp-fd`: one answering `EPERM`,
one answering `ENOSYS` so that libc falls back to an older call instead of
failing outright. Everything not named is allowed; this narrows the kernel
surface, it is not a capability model.

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
action. An unknown name, or one this architecture never had, is an error rather
than a silent skip, and `deny "prctl"` is refused because bwrap needs `prctl`
to install the filter. `allow "ioctl"` is the only way to take back the two
argument rules, so it re-enables `TIOCSTI` and `TIOCLINUX` for that instance —
do not reach for it to fix an unrelated `ioctl`. `deny "ioctl"` replaces those
two rules with one that matches every request, which breaks nearly every
program. `disable` prints `bubbler: seccomp disabled for instance <name>` on
each run, so an unfiltered sandbox is never a quiet one; an `allow` list that
takes back every rule leaves nothing to load and says
`bubbler: seccomp has no rules left for instance <name>` for the same reason.

`BUBBLER_SECCOMP_LOG=1` compiles the same rules with the log action instead.
The programs are loaded as always, but a call that would have been denied is
written to the kernel audit log and then succeeds — so the sandbox runs
unrestricted while it says what it would have lost. It is for finding
over-denies while writing a profile, not for running with. It also names, once
per run, the default list's syscalls this architecture never had, which are
skipped rather than compiled.

The filter carries the architecture bubbler was built for, and a syscall made
from any other ABI is killed rather than allowed — a 32-bit (i386) binary
inside a sandbox dies on its first syscall. Anything shipping 32-bit code,
Steam and some Wine setups among them, needs `seccomp { disable }` until a
libseccomp backend can add the second architecture to the filter.

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
  covers the session bus only, so a portal that hands back a `/run/user/<uid>/doc`
  path gives the sandbox nothing it can open.
- Descriptors handed to a command through `exec` are reachable by the
  sandboxed application through `/proc` — exec is a convenience channel, not
  a boundary. What the sandbox can still do with the terminal it is given is
  under "Terminal".
- The seccomp filter holds one architecture, so 32-bit binaries inside are
  killed rather than filtered; see "Seccomp".
- No proprietary nvidia driver; `dri` covers the open stack.
- `/etc/machine-id` is bound in, so every instance shares one stable
  identifier with the host.
- No desktop entries.

## Files

Instances live in `$XDG_DATA_HOME/bubbler/instances/<name>/` (by default under
`~/.local/share`), each holding a `config.kdl` and the private `home/`. Every
run except `--dry-run` also creates `$XDG_RUNTIME_DIR/bubbler/<name>/`, mode
0700, reusing one left over from an earlier run, and binds the control socket
`init.sock` in it; a `dbus` grant adds the subdirectory `dbus/` the proxy
creates its socket in and the checked socket `bus` beside it, and a `portals`
grant adds `$XDG_RUNTIME_DIR/.flatpak/bubbler-<name>/`, creating `.flatpak/`
if it is missing. Everything a run makes there is removed again when it ends.
`HOME` and `XDG_RUNTIME_DIR` must be set and non-empty. Your profiles live in
`$XDG_CONFIG_HOME/bubbler/profiles/` (by default under `~/.config`) and the
system's in `/usr/share/bubbler/profiles/`, or wherever
`$BUBBLER_PROFILE_DIR` points instead.

The `bubbler-init` binary is taken from `$BUBBLER_INIT` if set (it must be a
regular file), else from next to the `bubbler` binary, else from
`/usr/lib/bubbler/bubbler-init`. `$BUBBLER_DBUS_PROXY` likewise replaces the
`xdg-dbus-proxy` on `PATH` with a regular file bound into the proxy sandbox at
its own path; it exists for tests and debugging, as does the
`$BUBBLER_TEST_ALLOW_PATH` described under "Host paths".

## Build

    cargo build --release

Requires `bwrap` at runtime and a kernel with user namespaces.
