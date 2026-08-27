# Security

## Threat model (short form)

The boundary is between **your account and one application**. It is not a
boundary against root, not against your own unsandboxed processes (anything
running as your uid can read the instance store and connect to a live
instance's control socket). On the display, `wayland` is a boundary the
compositor enforces with a proxy of bubbler's in front of it, and a bare `x11`
an X server of the sandbox's own behind that (all below); `x11 "host"` is no
boundary at all. bubbler itself is unprivileged and unconfined. Long form with
every claim pinned to a test:
[`docs/threat-model.md`](https://github.com/han-xyz/bubbler/blob/master/docs/threat-model.md).

## Process chain

```
bubbler ─┬─ bwrap ── bwrap (pid 1 inside, reaps) ── bubbler-init (pid 2) ─┬─ your command
         │                                                                ├─ Xwayland (a bare x11, on its first X client)
         │                                                                └─ a window manager (only with wm=)
         ├─ bwrap ── bwrap ── bubbler-wl-proxy      (with a sandboxed wayland)
         ├─ bwrap ── bwrap ── xdg-dbus-proxy        (only with dbus / system-bus)
         ├─ pasta                                   (only with isolated network; not sandboxed)
         └─ bubbler-net-proxy                       (only with allow-host; in the sandbox's
                                                     namespaces, holding no capability)
```

`bubbler-init` serves the control socket `exec` connects to; the socket is
handed in as an inherited fd, so nothing inside reaches its path. Descriptors
passed through `exec` are reachable via `/proc` — exec is a convenience
channel, not a boundary. `--die-with-parent` is the backstop for everything.

## Wayland

A sandboxed `wayland` grant binds two sockets of bubbler's own, and the sandbox
is given one of them. `$XDG_RUNTIME_DIR/bubbler/<inst>/wayland-context` is the
one bubbler listens on and registers with the compositor through
`wp_security_context_v1` (wayland-protocols staging): engine `org.bubbler`,
app id `org.bubbler.<inst>`, instance id `bubbler-<inst>`. The sandbox does not
connect to it and cannot reach it. What is bound inside, at the session's
`WAYLAND_DISPLAY` name, is the second socket,
`$XDG_RUNTIME_DIR/bubbler/<inst>/wayland`, which `bubbler-wl-proxy` serves; the
context socket is the proxy's upstream. Clients arriving over it are marked as
sandboxed, and the compositor withholds its privileged globals from them —
screen capture, clipboard management, input injection, overlays, window
management on Hyprland and sway. Which globals those are is the compositor's
policy on this path, not bubbler's; bubbler only attaches the metadata. Only on
the fallback below does the list become bubbler's own. The compositor stops
accepting on the context socket when the run ends.

Measured on Hyprland 0.56.2: `wayland-info` counted 73 globals over 71
interfaces on the host and 38 over 37 inside. Thirty-one of those interfaces the
compositor withholds from a security-context client — screencopy, both
data-control managers, virtual keyboard and pointer, layer-shell,
foreign-toplevel and workspace listing, session-lock, and the security context
manager itself, so a sandbox cannot nest another one. The other three the proxy
below hides, its tables having no description for them.

The sidecar runs in a bwrap of its own. The listener it serves is handed to it
as an inherited descriptor rather than a path, so `wayland-context` is the only
thing of the run bound into its sandbox — no home, no network, no instance
runtime directory, the default seccomp filter. `bubbler run … --explain
--wl-proxy` prints that argv. Missing or unable to start, it stops the run:
`bubbler-wl-proxy did not start; …`.

Every message is decoded against tables generated from the protocol XML at
build time and re-encoded from what was decoded, so the far side reads what the
proxy judged rather than what the sender wrote. An interface the tables do not
describe is never advertised, a version above them is clamped, and a
`wl_registry.bind` of a name this connection was never offered — hidden,
unknown, or above the version it saw — is refused and the connection closed,
because hiding an advertisement alone does not stop a client naming a global by
its number:

```
refused: bind of hidden global zwlr_data_control_manager_v1 (name 38, v1) refused by the sandbox proxy
```

**The paste gate.** `receive` on `wl_data_offer`,
`zwp_primary_selection_offer_v1` and the two data-control offers is forwarded
only within one second of a `wl_keyboard.key` press, a `wl_pointer.button` or a
`wl_touch.down` or `.up` — both ends of a press arm, so a drag arms on the
release that drops it — seen on any of that instance's connections. Otherwise
the descriptor is closed — the client reads end of file, as if the selection
were empty — and a line goes to the log (at most one a second):

```
bubbler-wl-proxy: clipboard read denied (wl_data_offer, text/plain): no input since the proxy started
```

That stops an application reading the selection in the background while it holds
focus. It does not stop one you are typing into: your keystrokes are what arm
the gate. Nothing on a passed descriptor is inspected. `wayland
clipboard="open"` keeps the proxy and drops the gate, logging every read
(`clipboard read allowed (open)`); lint warns (`wayland-clipboard-open`) and
wants a `lint-allow` reason. `wayland "host"` has no proxy at all.

The compositor reads the connection's peer credentials, and the peer is the
sidecar: a window the sandbox maps is attributed to the `bubbler-wl-proxy`
process, so window rules keyed on a pid name the sidecar rather than the
application. A bare `x11`'s Xwayland is an ordinary client of the same socket,
decoded and gated like anything else inside.

A compositor that implements none of this gets the session socket as the
proxy's upstream — the proxy then hides 40 privileged interfaces itself, a
denylist of bubbler's own: the 31 Hyprland withholds from a security-context
client, plus nine of the same class found by reading every global the proxy's
tables describe. Being a denylist and not the whole class of privileged
protocols, a protocol nobody has written into it reaches the sandbox on this
path; what it does let through is written down beside it, so a protocol bump
that brings a new global fails a test. The fallback is announced once per
launch:

```
bubbler: note: wayland: no wp_security_context_manager_v1; the proxy hides the privileged globals instead
```

`wayland "host"` asks for the session socket outright, with every global the
compositor offers and no proxy in front of it — what a sandbox needs if it
drives one of those protocols itself, and nothing else. `bubbler lint` warns
(`wayland-host`); accept it with `lint-allow "wayland-host" reason="…"`. No
shipped profile grants it.

`--dry-run` and `--explain` never talk to the compositor: they assume the
security context and print it, so the argv they show is what a run builds where
the protocol is there. `x11 "host"` bypasses all of it — those X clients reach
a server which is a client of your session, not of this socket. A bare `x11`
does not: the Xwayland it starts is a client of this one, like anything else
inside. One thing an explanation does ask for: `--explain --proxy` on an `a11y`
config resolves the accessibility bus address, which is part of the proxy argv
it prints.

## X11

A bare `x11` starts a rootful `Xwayland` **inside** the sandbox, as one more
Wayland client of whichever socket the `wayland` grant bound. X11 still has no
isolation between the clients of one server — but the only clients on this one
are the sandbox's own. Nothing of the session's X display is bound: no socket,
no cookie. `-nolisten tcp` keeps the display off the network, `-nolisten
local` off the abstract socket namespace, which no mount namespace covers and
`network "host"` would share with the whole host, and `-nolisten unix` off a
path socket of the server's own; the one way in is the filesystem socket
`/tmp/.X11-unix/X0`, in the sandbox's private `/tmp`.

`bubbler-init` binds that socket itself and sets `DISPLAY=:0` before the
command runs, so the command and every `exec` child have a display from their
first instruction — and starts Xwayland with `-listenfd` only when a client
connects to it. A sandbox whose command never speaks X11 runs no X server at
all; the first client that does waits about 0.2 s for one. The server is
stopped after the command and every `exec` child, and its socket goes with the
sandbox's `/tmp`.

```kdl
x11                              // one 1280x720 decorated window
x11 geometry="1920x1080"
x11 fullscreen=#true grab=#true  // games: the whole output, input held inside
x11 wm="openbox"                 // a window manager inside, with the server
```

The server is a Wayland client that renders through glamor, so the grant needs
`wayland` (either mode) and `dri` in the merged config; a config without them
is refused rather than promising a display that dies on its first frame. What
runs is the host's `/usr/bin/Xwayland` (`xorg-xwayland`), read from the
read-only `/usr` and probed while the argv is built. Measured here on Xwayland
24.1.13, Hyprland 0.56.2 and an NVIDIA card: a client inside the nested server
saw 26 extensions, GLX with direct rendering among them, plus MIT-SHM, XInput,
XKEYBOARD and XTEST.

There is no window manager in there unless `wm=` names one: without it X
windows are undecorated, unmanaged and stacked in the one compositor window the
server draws. `bubbler lint` says so as the note `x11-nested-no-wm`, which
neither a `fullscreen=#true` config nor a `wm=` one gets — the first has asked
for the one full-output window already, the second has named the manager.
Keyboard focus follows the pointer, so a window that fills only part of the root
loses input when the pointer leaves it; in-game fullscreen or `fullscreen=#true
grab=#true` makes it stable. `grab=#true` holds pointer and keyboard inside
(Ctrl+Shift releases them).

`wm=` takes one program name — non-empty, no `/`, no whitespace, no NUL, no
leading `-` — resolved on the sandbox's own `PATH` and started right after the
server on that first connection, so it is never itself the client that wakes
the server; an ICCCM
window manager reparents windows that already exist, so the client that woke it
is managed anyway. bubbler ships none: a missing one, or one that exits, is a
log line and not a failed run, and the display keeps serving. The archwiki's
[Window manager](https://wiki.archlinux.org/title/Window_manager) list is where
to pick from — `xorg-twm`, `openbox`, `jwm` and `icewm` are in the official
repositories, `matchbox-window-manager` (AUR) shows one window at a time. It
runs **inside** the boundary: one more process of this instance, with the same
access to the X server as the application it manages. `x11 "host"` takes no
`wm=`; that display is not this sandbox's to manage.

`x11 "host"` is the other mode: the session's `/tmp/.X11-unix/X<n>` socket and
whichever Xauthority cookie `$XAUTHORITY` or `~/.Xauthority` names, remapped to
`/home/bubbler/.Xauthority` so the host path stays hidden. That is no boundary
at all — every X client on your display can read every other's input and
windows, this sandbox included and Xwayland with it, and the compositor's
security context does not reach an X client. `bubbler lint` warns
(`x11-without-reason`); accept it with `lint-allow "x11-without-reason"
reason="…"`. `steam` and `lutris` ship it because their windows want a
window manager; `x11 geometry="…" wm="…"` on the nested server is the thing to
try before accepting that.

The X SECURITY extension's untrusted mode is not offered as a third choice: an
untrusted client is granted `XC-MISC` and `BIG-REQUESTS` and nothing else
(`SecurityTrustedExtensions`, xserver `Xext/security.c`), which leaves no GLX,
no XInput and no MIT-SHM for an application to draw with.

## Accessibility bus

The raw AT-SPI bus is X11-class. It is a peer bus with no per-client policy,
and its registry offers every client on it `RegisterKeystrokeListener` — every
keystroke of every accessible application, which is how a screen reader's
global shortcuts work — `GenerateKeyboardEvent` and `GenerateMouseEvent`, which
inject input into your session, and the desktop object tree, which is every
other application's widgets and text. Binding that socket into a sandbox would
hand it the session's input.

`a11y` binds a filtered socket instead. The instance's one `xdg-dbus-proxy`
serves the accessibility bus as a third address behind its own `--filter`, with
[nine fixed rules](D-Bus.md#accessibility-bus) and nothing from the config: the
application embeds itself in the registry, unembeds, reads back which events
are registered, and notifies listeners of its own. None of the calls above is
among them. What the assistive tool does back to the sandbox needs no rule at
all — a call *into* it is incoming, and `xdg-dbus-proxy` filters what the
client sends.

Measured here, inside a `dbus a11y` sandbox: `Registry.GetRegisteredEvents` and
`DeviceEventController.GetKeystrokeListeners` answer, while
`RegisterKeystrokeListener` and `GenerateKeyboardEvent` come back
`Error org.freedesktop.DBus.Error.AccessDenied` from the proxy.

The grant is still real in the other direction, and that is its point: an
assistive tool on the host reads this application's widgets and text. Grant it
where a screen reader has to work, not by default.

## Input methods

`input-method` grants the two portal names, `org.freedesktop.portal.Fcitx` and
`org.freedesktop.portal.IBus`, which carry the per-client text-input interface
only. The IM daemon receives the keys typed into this application's text
fields — that is what an input method is — and the sandbox is one more client
of it. The daemons' own names are not granted: fcitx5's carries `Exit`,
`Restart`, `SetConfig`, `SetCurrentIM` and `SetAddonsState`, which reconfigure
or stop the input method for every application in the session. On Wayland the
compositor's own text-input path needs no grant at all.

## Egress proxy

`allow-host` filters egress by name, and a name is no part of a packet, so the
filtering is done by a process: `bubbler-net-proxy`, a CONNECT-only proxy the
sandbox is pointed at with `HTTPS_PROXY` and the six other variables the
`network` node sets. The nftables ruleset accepts that process by its cgroup
and rejects everything else, so what the application can reach is what the
proxy opens for it. How to write the node is under
[Network](Network.md#egress-by-name-allow-host).

The proxy is a host process that joins the run's cgroup and then the sandbox's
user, network and mount namespaces before `execve`, and holds **no
capability**: permitted, effective, inheritable and ambient are all empty, and
`SECBIT_NOROOT|SECBIT_NOROOT_LOCKED` is set *before* they are emptied, because
bwrap's outer user namespace maps bubbler to uid 0 and an `execve` without
those bits would hand the sidecar the full set in the sandbox's user namespace.
It therefore cannot open `AF_PACKET` on the tap and cannot read or flush the
sandbox's own ruleset — the two powers a `CAP_NET_RAW` or `CAP_NET_ADMIN`
sidecar would have handed an attacker who found a bug in it. What a compromised
proxy does get is the sandbox's filesystem view, the sandbox's DNS, and the
ability to reach whatever the names in the config resolve to. Its working
directory is `/` inside the sandbox's mount namespace and it is non-dumpable;
it dies with bubbler (`PR_SET_PDEATHSIG`) and is stopped with the run.

It runs with **no seccomp filter** in v1: rustix exposes no filter load, the
`pre_exec` that sets all of the above must stay async-signal-safe, and neither
libc nor a new crate is being added for it. Two of a run's sidecars go without
one — this proxy and `nft`, a one-shot host binary that exits before the
application runs — against the three bubbler wraps in a bwrap of its own and
gives the default filter to; pasta loads a filter of its own making.
What stands in for the filter: no capability at all, a crate that is
`#![deny(unsafe_code)]` apart from one descriptor adoption, an allowlist that
arrives as argv rather than as a file the sandbox could touch, and a request
parser that is fuzzed (`fuzz/fuzz_targets/net_proxy_request.rs`).

The application cannot reach the proxy's privilege, and the reason is
**placement** rather than its own confinement. With the default `userns "allow"`
it can make itself a user, cgroup and mount namespace and mount cgroup2
(measured), but that mount is rooted at the `sandbox` leaf bubbler moved itself
into before spawning bwrap, and the proxy's `proxy` leaf is a sibling outside
it — unnameable through that mount, and refused by `nsdelegate` even if it were
named. `allow-port 3128`, the one way the host could have been given a path to
the proxy since pasta serves a forwarded port from inside the namespace, is a
config error whenever an `allow-host` is present.

The proxy's log goes to bubbler's own stderr, never to a file. Its budget bounds
the *rate* of those lines (20 a second, then a suppressed count), not the total,
so a sandbox that keeps being refused for long enough can still push older lines
out of the 1 MiB `last-run.log` cap: the log is a diagnostic, and losing its
head that way is the trade-off rather than a bound bubbler enforces.

## Seccomp

Every sandbox (instances, `try`, and each sidecar bubbler wraps in a bwrap of
its own — the D-Bus and Wayland proxies) loads a denylist compiled with
libseccomp at launch. The egress proxy is in no bwrap and loads none, as
above. Everything not named is allowed: it narrows the kernel surface, it is
not a capability model.

- `EPERM`: kernel keyring, `perf_event_open`, `bpf`, `userfaultfd`,
  `fanotify_init`, NUMA/page migration, module and kexec loading,
  `iopl`/`ioperm`, swap, `reboot`, `syslog`, quota, clock, hostname; the
  `TIOCSTI` and `TIOCLINUX` ioctls by argument.
- `ENOSYS`: `clone3` and the new mount API (`open_tree`, `fsopen`, …).
- Deliberately **not** denied: `unshare`, `setns`, `clone`, `mount`,
  `pivot_root`, `chroot`, `ptrace` — Firefox and Chromium build their own
  sandbox from them.
- On x86_64 the filter carries **x86_64 + i386**, so Steam/Proton/DXVK 32-bit
  code is filtered, not killed. Cost: `modify_ldt` is allowed for both ABIs
  (`seccomp { deny "modify_ldt" }` puts it back). x32 syscalls are killed with
  `SIGSYS` — an ABI gate, not a rule.

```kdl
seccomp {
    allow "ptrace" "perf_event_open"   // take names off the list
    deny "unshare" "setns"             // add, EPERM unless stated
    deny "clone3" errno="ENOSYS"
    disable                            // no filter; warns on every run
}
```

`deny "prctl"` is refused (glibc needs it). `allow "ioctl"` re-enables
`TIOCSTI`. A name this libseccomp does not know is skipped with a printed
warning (floor: libseccomp 2.5.4). `BUBBLER_SECCOMP_LOG=1` logs instead of
denies, for profile writing only.

## User namespaces

```kdl
userns "disable"    // default "allow"
```

`--unshare-all` still lets the sandbox create new user namespaces.
`"disable"` closes that (`--unshare-user --disable-userns`). Cost: Firefox and
Chromium lose their inner sandbox, Steam (pressure-vessel), podman and
flatpak inside break. Does not work with setuid bwrap. No shipped profile
sets it.

## Baseline

See [Configuration](Configuration.md#baseline-every-sandbox). Two deliberate
widenings: `/dev/ntsync` (Wine/Proton sync; per-process objects, no host
state) and `/etc/machine-id` (every instance shares one identifier with the
host).

## Known gaps

- `x11 "host"`: no isolation between the X clients on your display, and no
  Wayland security context on the session's Xwayland. The nested default runs
  without a window manager; bubbler ships none, so `wm=` needs one installed
  on the host.
- `input-method` has never been exercised against a running fcitx5 or IBus:
  neither is installed on this machine.
- AMD compute (`/dev/kfd` + sysfs topology) unsupported; NVIDIA compute needs
  `etc-share "OpenCL"`/`"nvidia"`.
- `hidraw` and `camera nodes=#true` device lists are frozen at launch.
- No raw USB grant, no pcsclite socket: challenge-response YubiKey and smart
  cards unreachable.
- `bubbler-net-proxy` runs with no seccomp filter (above), and `allow-host`
  needs a delegated cgroup2 subtree — without one the run is refused. Its
  refusals go to bubbler's stderr: your terminal, or `bubbler log <inst>` for a
  run that had none.
- `app-runtime` does not carry Discord rich presence.
- KeePassXC native messaging manifest must be placed by hand.
- `camera` never exercised on real hardware.
- Deeply nested KDL, a block comment full of `*`/`/`, or a run of tokens the
  parser cannot place (`}` alone, say) would overflow the `kdl` crate's
  parser, which recurses on each. bubbler refuses files with more than 32
  `{` anywhere (strings and comments included) or a comment holding more
  than 128 such marks before the parser sees them, and, since no count bounds
  the third, refuses files over 64 KiB and parses on a thread with 512 MiB of
  stack reserved — room for a frame per byte, twice over.
- Desktop entries: D-Bus activation closed for the entry only.
- Forwarded file arguments are visible to the instance for the rest of the
  portal session, and a symlink argument exports its target.

## AppArmor

`contrib/apparmor/usr.bin.bubbler` is offered to packagers on distributions
that mediate user namespaces through AppArmor (Ubuntu 23.10+). Ships in
complain mode and **has never been loaded**; keep `allow userns create,` if
you narrow it.
