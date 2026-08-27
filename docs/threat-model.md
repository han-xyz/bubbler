# bubbler threat model

What bubbler defends, what it does not, and where each answer is written
down and pinned by a test. Every mechanism below links the manual section
that describes it and the test that would fail if the behaviour changed.
Read it as the companion to the manual's "Known gaps": that list is what
is missing, this is what the parts that exist are worth.

The rule this document is held to: a claim with no test beside it is a
claim about code that was read, not code that was measured, and it says
so.

## Assets

In the order an attacker would want them:

- Your home directory and its dotfiles — SSH and GPG keys, browser
  profiles, shell history, `~/.config`.
- The session bus, and everything reachable through it: the secret
  service, the portal, every application that owns a name.
- The Wayland or X11 display, the input devices behind it, and the
  clipboard.
- The accessibility bus: the text and widgets of every accessible
  application, and the keystroke-listener and input-injection calls its
  registry offers any client that connects.
- The host network namespace: loopback services, abstract unix sockets,
  the interface and listening-socket table, VPN tunnels.
- Other instances — their `config.kdl` (which decides what the *next* run
  of that instance may do) and their private homes.
- bubbler's own runtime directory and the control sockets in it: reaching
  `init.sock` means running commands inside a live sandbox.
- Your uid. Nothing here is a boundary against root, and nothing here
  needs root.

## The attacker

One application inside one sandbox, fully compromised: arbitrary code
execution as your uid, full control of every descriptor it holds,
unlimited time, and bubbler's source in front of it.

A second, weaker attacker: a **hostile profile** — a `*.kdl` someone
talked you into dropping in `~/.config/bubbler/profiles/`. A profile is
code you chose to run and grants are its whole purpose, so bubbler cannot
defend against one. What it does instead is make the grant *visible*:
`bubbler lint` measures a config against what a sandbox gives away and
`--dry-run --explain` puts every bwrap argument under the node that asked
for it, so a profile cannot grant something the tooling does not name.
([Linting](manual.md#linting), [Explaining an
argv](manual.md#explaining-an-argv); `every_argument_is_attributed_to_the_node_that_asked_for_it`,
`every_builtin_profile_lints_clean`,
`a_finding_never_stands_in_for_a_layer_that_does_not_parse`.)

## Trust boundaries

In decreasing order of strength.

### 1. Host user ↔ sandbox — the real boundary

Enforced by bwrap's namespaces, the bind set the arg builder emits, and
the seccomp filter. This is the one everything below is measured against,
and the one the mechanism table covers.

### 2. Sandbox ↔ sidecars

Eight processes can come with a sandbox, and they are not one kind of thing:

| Sidecar | Where it runs | Is it a boundary? |
|---|---|---|
| `xdg-dbus-proxy` | its own bwrap sandbox, sibling of the app's | **Yes.** It is a filter, it sees only the host bus sockets read-only — up to three of them — and the instance's `dbus/` subdirectory read-write, and the socket it serves is moved out of its reach before anything is bound. |
| `bubbler-wl-proxy` | its own bwrap sandbox, sibling of the app's, in front of every sandboxed `wayland` (bare or `clipboard="open"`) | **Yes.** It is the only thing listening on the socket the sandbox connects to, and it forwards nothing it could not decode: every message is parsed against generated interface tables and re-encoded from what was parsed. It sees all of the sandbox's display traffic in both directions. What it holds is the app-facing listener, handed in by number, one connection to the compositor for each of the up to 256 client connections it accepts, and two more descriptors the launcher passes — the audit log and the readiness pipe. The `wayland-context` socket it dials is the one thing of the run bound into its sandbox: no home, no network, no instance runtime directory, no `init.sock`, default seccomp. It does not see what a clipboard read returns; those bytes travel on a descriptor it passes through without reading. |
| `bubbler-init` | *inside* the sandbox, as pid 2 | **No.** It is the supervisor, not a guard: it shares the sandbox with the application. What it holds — the listening control socket — is kept from the application by being an inherited descriptor with no path, `CLOEXEC` in the only process that has it, and `PR_SET_DUMPABLE` off so `/proc/<init>/fd` cannot be walked. |
| `Xwayland` | *inside* the sandbox, started by `bubbler-init` on the first X connection, only with a bare `x11` | **No.** It is the sandbox's own X server rather than a guard in front of one: every client on it is a process of this instance, and X11 isolates none of them from each other. What it replaces is the session's display — it reaches the compositor on the instance's own Wayland socket and listens nowhere but `/tmp/.X11-unix/X0` in the sandbox's private `/tmp`, a socket `bubbler-init` binds and hands over rather than one the server opens. A command that never speaks X11 never starts it. See "X11" below. |
| a window manager | *inside* the sandbox, started by `bubbler-init` with the server, only with `x11 wm="…"` | **No.** It is a sibling of the application under `bubbler-init`, resolved on the sandbox's own `PATH`, with the same access to that X server as the application it manages and no more reach into it than any other sibling has. Arch enables the Yama LSM with `kernel.yama.ptrace_scope` at 1 (restricted), which stops a `ptrace` on a tracee outside a restricted scope unless the tracer is privileged or holds `CAP_SYS_PTRACE`; the kernel's Yama document defines that scope as the tracer's own descendants, `PR_SET_PTRACER` being the opt-in, and two siblings are outside each other's. bubbler ships none and probes none; a name that resolves to nothing is a log line. |
| `pasta` | on the host, **not sandboxed**, holding the sandbox's outer user namespace | **No, in one direction.** A pasta that has been taken over *is* that sandbox's network and holds root over the namespaces the sandbox is built from. It owns nothing beyond what your own account already has: your uid created that namespace. Wrapping it in bwrap would not add anything — it would remove the very thing pasta needs, since a process can only join a descendant of its own user namespace. |
| `bubbler-net-proxy` | on the host, **not in a bwrap**: it joins the sandbox's user, network and mount namespaces and listens on `127.0.0.1:3128` inside, only with an `allow-host` | **Yes, one way.** It is the sandbox's only route out — the ruleset accepts its cgroup and rejects everything else — and it authorises each `CONNECT` target against the allowlist it was given as argv. It holds **no capability**: permitted, effective, inheritable and ambient are all emptied, with `SECBIT_NOROOT|SECBIT_NOROOT_LOCKED` set first because bwrap's outer user namespace maps bubbler to uid 0 and an `execve` without those bits would hand it the full set in the sandbox's user namespace (measured). So it cannot open `AF_PACKET` on the tap and cannot read or flush the sandbox's ruleset, which is what a `CAP_NET_RAW` or `CAP_NET_ADMIN` sidecar would have handed whoever found a bug in it. What a compromised one does get is the sandbox's filesystem view, the sandbox's DNS and the hosts the config named; it sees ciphertext, since it relays bytes after `200` and terminates no TLS. Its cwd is `/` in the sandbox's mount namespace, it is non-dumpable, it dies with bubbler (`PR_SET_PDEATHSIG`) and it runs with **no seccomp filter** in v1 — one of the two rows here without one, beside `nft`, which is a one-shot host binary that exits before the application runs; the three bubbler wraps in a bwrap of its own carry the default filter, and pasta loads one of its own making. What stands in for that: the empty capability sets, `PR_SET_NO_NEW_PRIVS`, a crate that is `#![deny(unsafe_code)]` apart from one descriptor adoption, an allowlist that is argv rather than a file the sandbox could touch, and a fuzzed request parser. |
| `nft` | on the host, entering the sandbox's user and network namespaces to install the ruleset | **Not a party to one.** It builds the network boundary rather than standing in it: it runs before pasta and before the sandbox is let go of its `--block-fd`, so the namespace has a policy before it has a route and before the application has run an instruction either way. Nothing the sandbox controls reaches it — the ruleset is generated from typed values and handed over on stdin, and its argv is two fixed arguments. It holds CAP_NET_ADMIN in the sandbox's user namespace and no other capability anywhere: the capability crosses `execve` through the ambient set, and `SECBIT_NOROOT` with `_LOCKED` stops the uid-0 that bwrap's nested user namespace maps bubbler to from being handed the full set. It exits before the run begins, and one that stops answering is killed rather than left holding that capability. |

([A run is a chain of processes](manual.md#usage),
[D-Bus](manual.md#d-bus), [network](manual.md#network);
`the_proxy_never_sees_the_instances_control_socket`,
`a_proxied_socket_is_moved_out_of_the_proxys_reach`,
`proxy_argv_runs_the_proxy_in_its_own_sandbox`,
`wl_proxy_argv_runs_the_proxy_in_its_own_sandbox`,
`real_wayland_proxy_serves_the_only_socket_the_sandbox_sees`,
`real_wayland_a_proxy_that_will_not_start_stops_the_run`,
`the_x_server_is_not_started_until_a_client_connects`,
`the_window_manager_starts_with_the_server_and_the_shutdown_runs_inwards`,
`the_nft_child_holds_cap_net_admin_and_is_fed_the_ruleset`,
`the_ruleset_is_the_golden_text_nft_is_fed`,
`outbound_deny_filters_what_no_allow_out_names_and_the_sandbox_cannot_undo_it`,
`net_proxy_argv_is_the_allowlist_the_port_and_the_descriptors`,
`real_allow_host_relays_a_listed_name_and_nothing_else`.)

### 3. Instance ↔ instance

Two instances are separated by the fact that neither can see the other's
paths — not by any check made at the moment of access. Three ways that
separation is deliberately given up:

- An `app-runtime` id shared between instances is **one trust domain**.
  Everything granted the id can read, write, replace and delete
  everything in that directory, and `SO_PEERCRED` cannot tell peers apart
  across the boundary. The name *is* the rendezvous.
- A `path-share` that reaches `$XDG_DATA_HOME/bubbler` is a total break:
  a sandbox that can write another instance's `config.kdl` grants itself
  anything on that instance's next run. `$XDG_CONFIG_HOME/bubbler`, where
  your own profile layer lives, is the same break one seeding later: a
  profile written there is the config of every instance created from it,
  and so is the directory `$BUBBLER_PROFILE_DIR` names when it moves the
  system layer somewhere reachable.
  That is why the denylist exists, why every share is held to it —
  `path-share`, `--share` and `home-share`, which reaches those roots by
  a relative path whenever XDG puts them under your home — why it
  compares the roots your environment names both as written and as
  resolved, and why the `$BUBBLER_TEST_ALLOW_PATH` hook cannot lift
  them.
- `/etc/machine-id` is bound in, so every instance shares one stable
  identifier with the host.

([app-runtime](manual.md#app-runtime), [Host
paths](manual.md#host-paths), [Known gaps](manual.md#known-gaps);
`path_share_resolves_the_instance_store_itself`,
`path_share_compares_the_environment_roots_resolved`,
`path_share_refuses_the_profile_layer_under_a_relocated_config_home`,
`path_share_environment_roots_outlast_the_carve_out_and_the_hook`.)

### 4. bubbler ↔ the host it runs on — not a boundary

bubbler is you. It is unprivileged, never setuid, and can do exactly what
your account can do; a compromised bubbler is a compromised account. An
AppArmor profile would make this a weak boundary — blast radius, not
privilege — and `contrib/apparmor/usr.bin.bubbler` is one, written from
documentation and never loaded on any machine here. It ships in complain
mode and bubbler does not install it.

## What each mechanism defends, and what it does not

### Namespaces and the bind set

**Defends:** the filesystem outside the bind set does not exist inside.
bwrap has no blacklist, so the model is "bind what you need": `/usr` and
`/opt` read-only, an `/etc` allowlist over a tmpfs, empty `/tmp` `/var`
`/run`, a private home at `/home/bubbler`, an empty `$XDG_RUNTIME_DIR` at
the host's path, and a cleared environment. All namespaces are unshared —
except the network one under `network "host"`, which is the whole of that
grant; `--die-with-parent` and `--new-session` are always on. Bind order is
semantics — a later `--tmpfs /run` would silently shadow a socket bound
under it — so the builder emits in fixed phases and no service controls
global order.

**Does not defend:** anything you bind in. `home-share`, `path-share`,
`etc-share` and `dri` are grants, and a grant is what it says it is. A
`portals` grant binds the instance's document-portal view at
`$XDG_RUNTIME_DIR/doc`: what the host chooser exported for this app id, with
the portal's per-document mode bits, and nothing of the mount's other apps.

[Baseline](manual.md#baseline) ·
`baseline_argv_is_exact`, `etc_is_an_allowlist_of_existing_entries`,
`service_binds_come_after_runtime_dir_and_before_env`,
`portals_binds_this_instances_document_portal_view_read_write`,
`portals_without_a_document_portal_mount_binds_nothing_there`,
`real_bwrap_home_is_fixed_and_private`,
`real_bwrap_etc_is_allowlisted_and_user_is_bubbler`

### Host environment values

**Defends:** `WAYLAND_DISPLAY`, `XAUTHORITY` and `DISPLAY` are untrusted
input. Their shape is validated (one path component) and the *file type*
is probed, never mere existence, so a variable naming a directory is
refused instead of binding the tree under it. `WAYLAND_DISPLAY` is checked
in both the values it has — the run's own and the process environment's,
which the Wayland client reads itself — before the launcher connects to
the compositor. `WAYLAND_SOCKET` is refused when set at all: the client
would adopt the descriptor number it names as its connection and close it
with the connection.

The three bus addresses — `$DBUS_SESSION_BUS_ADDRESS`,
`$DBUS_SYSTEM_BUS_ADDRESS` and `$AT_SPI_BUS_ADDRESS` — are guarded on the
path as well as the type. Each is resolved first (the socket itself
canonicalised when it exists, else its parent, else a lexical fold of
`.` and `..`), and one that lands under `$XDG_RUNTIME_DIR/bubbler/` is
refused before anything is probed or bound: ``service `<node>`: the host
bus address names a socket under bubbler's own runtime directory``,
naming `dbus`, `system-bus` or `a11y`. That directory holds an instance's
control socket — the one `bubbler exec` connects to — and the bus socket
the proxy itself serves, so the guard catches an address naming the exec
channel and one naming a socket this very proxy is about to serve.
Neither is a host bus. The resolved path is the one returned and bound,
so the path compared and the path bound are the same string.

The descriptors bubbler is started with are untrusted the same way: a
shell, a terminal, a service manager or a build system leaves open what it
likes — `makepkg` runs a `check()` with two of its own — and bwrap passes
on every descriptor it holds, so before each spawn the launcher marks
every descriptor above stdio close-on-exec except the ones that spawn was
built to inherit, and the supervisor closes every one but the control
socket its argv names before it starts anything at all.

**Does not defend:** a value that really does name a socket of the right
type is bound, whatever it is a socket for. The bus guard compares paths,
so it does not see a *hard link* to a control socket made elsewhere, and
its reference side is `$XDG_RUNTIME_DIR/bubbler/` rather than a
`/run/user/<uid>` derived from the kernel — a `$XDG_RUNTIME_DIR` pointing
somewhere else moves both sides at once. Both need the uid that already
owns that directory and every socket in it, which is the attacker this
model does not have: the guard is against a misdirected address in an
otherwise sane environment. `--explain --proxy` runs the same guard, but
where neither the socket nor its parent exists yet only the lexical form
is left to resolve, so an explanation can describe a bus the run it
describes goes on to refuse.

[Baseline](manual.md#baseline), [D-Bus](manual.md#d-bus) ·
`wayland_display_must_name_a_socket`,
`wayland_display_that_is_not_one_component_is_rejected`,
`a_display_name_that_is_a_path_is_refused_before_the_compositor`,
`an_inherited_connection_is_refused`,
`wayland_socket_path_of_the_wrong_type_fails`,
`x11_socket_that_is_not_a_socket_fails`,
`x11_xauthority_at_a_directory_fails`,
`launcher::tests::a_host_bus_address_under_bubblers_runtime_directory_is_refused`,
`dbus::tests::a_guarded_bus_path_comes_back_resolved`,
`a_bus_address_under_bubblers_runtime_directory_is_refused`,
`real_bwrap_run_hands_on_nothing_the_shell_that_started_it_left_open`,
`no_descriptor_the_supervisor_was_not_given_reaches_anything_it_starts`

### Wayland

**Defends:** a `wayland` grant binds a socket bubbler listens on itself,
registered with the compositor through `wp_security_context_v1` as engine
`org.bubbler`, app id `org.bubbler.<inst>`, instance id `bubbler-<inst>`.
A client on it is one the compositor knows to be sandboxed, and the
compositor withholds its privileged globals from such a client. The
sandbox does not connect to that socket: it connects to a second one
beside it, `<instance runtime>/wayland`, which `bubbler-wl-proxy` serves
and which is bound into the sandbox at the session's `WAYLAND_DISPLAY`
name; the security-context socket is the proxy's upstream. Measured on
Hyprland 0.56.2: `wayland-info` counted 73 globals over 71 interfaces on
the host and 38 over 37 inside. Thirty-one interfaces are the
compositor's doing — screencopy and image-copy-capture, both data-control
managers, the virtual keyboard and pointer protocols, layer-shell,
foreign-toplevel and workspace listing, session-lock, global shortcuts,
gamma and output control, and the security context manager itself, so a
sandbox cannot create a context of its own. Recording the screen, reading
the clipboard without focus and injecting input into the session are what
those cost.

The other three interfaces are the proxy's: it hides every global whose
interface its tables cannot describe, clamps an advertised version down to
the version the tables know, and refuses a `wl_registry.bind` of a global
this connection was never offered — hidden, unknown, or above the version
it saw — with a synthesised `wl_display.error` and a closed connection.
That last check is the one that matters: hiding a global from
`wl_registry.global` does not stop a client naming it by number, and a
draft that only withheld advertisements was bound straight through by
exactly that route while this was being built. On a compositor with no
security context the proxy applies a denylist of its own — 40 interface
names: the 31 Hyprland withholds from a sandboxed client, plus nine of
the same class found by reading every global the proxy's tables describe,
whether another compositor implements it or Hyprland hands it to a
sandboxed client anyway — and the launch says so with a note. What the
list lets through is written down too, so a protocol bump that brings a
new global fails a test rather than reaching a sandbox unexamined.

**Does not defend:** on the security-context path, which globals are
hidden is the compositor's policy and not bubbler's — bubbler attaches the
metadata and the compositor does every bit of the enforcing, so the grant
is worth what the compositor implements. On the fallback path the list is
bubbler's own and is a denylist, so a privileged protocol no one has added
to it reaches the sandbox. One is left through deliberately:
`zwp_keyboard_shortcuts_inhibit_manager_v1` suppresses the compositor's own
key combinations only while a surface of the client's own has focus, which
is what a VM or a remote-desktop window inside a sandbox needs — but a
fullscreen window holding it is a keyboard trap on a compositor that
reserves no combination for itself, and the way out of one is the
compositor's policy rather than anything bubbler can do.
`wayland "host"` asks for the session socket
outright, with no context and no proxy at all (lint `wayland-host`). The
session's Xwayland is outside all of it: `x11 "host"` reaches a server that
is an ordinary client of your session, though a bare `x11` starts one on
this socket (below) which the proxy filters and gates like anything else.

The proxy is also not a shield in front of the compositor. Everything it
can parse it re-encodes and forwards, so a message that is well formed and
hostile arrives exactly as it would have without a proxy; what it removes
is what it could not parse and what it was told to refuse, not exploit
attempts inside protocols it does understand. A compositor's own bugs are
the compositor's. And the sidecar is what the compositor sees: peer
credentials on the connection are the proxy's, so a window the sandbox maps
is attributed to the `bubbler-wl-proxy` process and a window rule keyed on
a pid names the sidecar.

[wayland](manual.md#wayland) ·
`wayland_context_binds_bubblers_socket_at_the_host_name`,
`wayland_host_binds_the_session_socket`,
`the_application_and_the_compositor_get_different_sockets`,
`the_fallback_proxy_dials_the_session_socket_and_denies`,
`the_privileged_denylist_is_pinned_sorted_and_unique`,
`policy::tests::a_global_the_tables_do_not_describe_is_hidden_and_remembered`,
`policy::tests::a_privileged_global_is_hidden_only_under_the_fallback`,
`policy::tests::an_advertised_version_above_the_tables_is_rewritten`,
`policy::tests::binding_a_hidden_global_by_its_number_is_refused`,
`policy::tests::binding_a_global_that_was_never_advertised_is_refused`,
`policy::tests::binding_above_the_advertised_version_is_refused`,
`policy::tests::binding_a_name_under_another_interface_is_refused`,
`a_sandboxed_wayland_grant_names_the_proxy_in_front_of_it`,
`real_wayland_binds_bubblers_own_socket_not_the_hosts`,
`real_wayland_proxy_hands_the_application_a_smaller_registry`,
`real_wayland_proxy_refuses_a_hidden_bind`

### Clipboard

The clipboard is not a buffer somewhere: on both Xorg and Wayland its
content is held by the program that copied it, and nothing is copied
until it is pasted — close that program and the content is gone unless a
clipboard manager kept its own copy (archwiki, "Clipboard"). A read is
therefore a live request, made by a client, that something has to answer,
which is what makes it a thing a proxy can see and refuse. There are two
of them per session: PRIMARY, the currently selected text, and CLIPBOARD,
what an explicit copy put there (same source).

**Defends:** a sandboxed application that is mapped and focused is handed
the selection by the compositor as core protocol — `wl_data_device.selection`
arrives immediately before keyboard focus and again on every selection
change while it has focus — and may `receive` it at any time the offer is
valid, with no paste and no keystroke behind the read. No compositor gates
that per client; the security context does not touch it, because reading
the selection *with* focus is not a privileged protocol. `bubbler-wl-proxy`
gates it instead. A `receive` on `wl_data_offer`,
`zwp_primary_selection_offer_v1`, `zwlr_data_control_offer_v1` or
`ext_data_control_offer_v1` is forwarded only within one second of real
user input — a `wl_keyboard.key` the compositor reported as pressed, a
`wl_pointer.button` in either direction, or a `wl_touch.down` or
`wl_touch.up` — seen on any connection of that instance. Both ends of a
press arm, so a drag that ends over a paste target arms on the release
that ends it rather than only on the press that began it, however long
the drag took. Outside the window the request is not
forwarded and the descriptor it carried is closed, so the client reads end
of file exactly as if the selection had been empty, and one line goes to
the audit log:

```
bubbler-wl-proxy: clipboard read denied (wl_data_offer, text/plain): no input since the proxy started
```

What that stops is background polling: an application reading whatever you
copy next while your attention is elsewhere. The state is per instance
rather than per connection on purpose — a multi-process toolkit reads the
selection on a connection that never held keyboard focus, and gating each
connection on its own input would deny every one of them.

Refusing a `bind` of a hidden global belongs here too, because the two
data-control protocols are how a client reads the selection *without*
focus. Under the security context the compositor never advertises them;
the proxy additionally refuses them by number, and a sandbox that asks
gets its connection closed. What is left is measured, and
`real_wayland_proxy_leaves_no_headless_clipboard_path` is what pins it:
with `secret` on the selection, a data-control client reads 6 bytes on the
host and finds no manager inside, and a client with no surface is offered
nothing inside, because the compositor sends `wl_data_device.selection`
only to whoever has keyboard focus. (A surfaceless client is offered
nothing on the host either, for the same reason; that half is a hand
measurement, not part of the test.) A sandbox reaches the selection only
as a window you can see, and only when the gate is open.

**Does not defend:** an application you are typing into. Your keystrokes
are exactly what arm the gate, so a focused editor, terminal or browser can
read the selection within one second of any key you press in it — the gate
stops a background reader, not a foreground one waiting for you to type.
Nothing that travels on a passed descriptor is inspected: the selection's
bytes go down a pipe the compositor writes and the client reads, and the
proxy judges the request that carries the pipe, never what comes back
through it. `wayland clipboard="open"` turns the gate off entirely, leaving
only an audit line per read (lint `wayland-clipboard-open`, which wants a
`lint-allow` reason), and `wayland "host"` has no proxy in front of it at
all. Nothing here stops the sandbox *writing* the selection, and nothing
here is a boundary against a compositor's own bugs. There is no per-MIME
policy and no prompt.

**Hard limits.** The proxy is bounded rather than trusting, and the
bounds do not all do the same thing. Three of them end one connection,
with a `connection closed: …` line naming which and why while every other
connection carries on: 253 descriptors waiting on one side, which is
Linux's own maximum for a single `recvmsg` and far past the two any
message owns; 64 MiB of bytes queued across all of one sandbox's
connections at once, where the connection holding the most is the one
that gives way; and 65 536 live object ids on a connection. The other two
apply back-pressure instead. 4 MiB queued in one direction stops the
proxy reading the side that feeds it until the far side drains, and
nothing is lost. 256 connections is where the proxy stops accepting, the
kernel's backlog holding the rest until a connection ends.

The gate window is one second and the audit log is one line a
second per kind — gate lines and closures budgeted apart, so a `receive` in
a loop cannot push the line that says why a connection ended out of the
record — with what a burst swallowed counted onto the next line. The
upstream socket is dialled once before the run starts, bounded at two
seconds, so a compositor that is not answering stops the launch rather than
every connection inside it.

[wayland](manual.md#wayland) ·
`real_wayland_proxy_denies_a_background_read`,
`real_wayland_proxy_open_allows_the_read`,
`real_wayland_proxy_opens_the_gate_for_a_keystroke`,
`real_wayland_proxy_refuses_a_hidden_bind`,
`real_wayland_proxy_leaves_no_headless_clipboard_path`,
`policy::tests::a_clipboard_read_without_input_is_denied_on_every_offer`,
`policy::tests::every_arming_event_opens_the_gate`,
`policy::tests::a_key_release_does_not_open_the_gate`,
`policy::tests::the_gate_closes_again_one_millisecond_past_the_window`,
`policy::tests::an_open_gate_forwards_the_read_and_says_so`,
`policy::tests::an_offer_the_compositor_created_is_gated_like_any_other`,
`policy::tests::the_four_gated_offers_are_sorted_and_in_the_tables`,
`policy::tests::the_privileged_list_is_sorted_so_the_search_cannot_fail_open`,
`relay::tests::a_hung_up_upstream_with_a_client_that_never_reads_does_not_spin`,
`wayland_clipboard_takes_open_and_nothing_else`,
`wayland_clipboard_open_is_a_warning_the_bare_node_does_not_raise`

### X11

**Defends:** a bare `x11` binds nothing of the session's X display — no
socket, no cookie, and neither `DISPLAY` nor `XAUTHORITY` is read.
`bubbler-init` owns the display instead. It binds `/tmp/.X11-unix/X0`
itself before the command runs and sets `DISPLAY=:0` for the command and
for every `exec` child; a rootful Xwayland is started on the first
connection to that socket, inheriting it through `-listenfd`, as one more
Wayland client of the socket the `wayland` grant bound. What the
compositor sees is a sandboxed client like any other, and what the
application talks to is a display of the sandbox's own: that socket is in
the private `/tmp`, its shared memory in the private `/dev/shm`, and the
only clients on it are processes of this instance. It is also the only
way in — `-nolisten tcp` keeps the server off the network, `-nolisten
local` off the abstract socket namespace, which a mount namespace does
not cover and `network "host"` would share with every host process, and
`-nolisten unix` off a path socket of its own, the supervisor's being the
one it is handed. X11's lack of isolation between clients therefore
reaches no further than this sandbox, and a command that never speaks X11
never starts a server at all. Measured here on Xwayland 24.1.13,
Hyprland 0.56.2 and an NVIDIA card: a client inside saw 26 extensions,
GLX with direct rendering among them.

The `mkdir`, `chmod 1777` and `bind` on `/tmp/.X11-unix` would be a
time-of-check race if `/tmp` were shared with anything: it is not. Every
sandbox gets a private tmpfs, empty at start, and the only writers in it
are this instance's own processes — which are exactly who the display is
for. On a shared `/tmp` that sequence would need `O_NOFOLLOW`/`mkdirat`
discipline instead.

**Does not defend:** the sandbox's own processes against each other.
There is one server and X11 isolates nothing on it, so the command, its
`exec` children and a window manager read each other's input and windows.
Without `wm=` nothing manages those windows at all, so they are
undecorated and stacked in the server's one compositor window (lint note
`x11-nested-no-wm`); with it, the named program is resolved on the
sandbox's own `PATH` and started by `bubbler-init` right after the server
— a sibling of the application, not a layer over it. What the two share
is the X server, where X11 isolates nothing; being siblings gains them
nothing beyond it on an Arch host at its default. Arch enables the Yama
LSM with `kernel.yama.ptrace_scope` at 1 (restricted), which stops a
tracer from `ptrace`-ing a tracee outside a restricted scope unless the
tracer is privileged or holds `CAP_SYS_PTRACE`; the kernel's Yama
document, which the wiki links, defines that scope as the tracer's own
descendants, with `PR_SET_PTRACER` as the tracee's opt-in for anything
else. Neither of these two is the other's descendant. That is the host's
setting rather than bubbler's, and `ptrace` is not on bubbler's seccomp
denylist. bubbler ships no window
manager and probes none on the host: a name that resolves to nothing, or
a program that exits, is a log line rather than a failed run.
The server is the host's `/usr/bin/Xwayland` and cannot start without
`wayland` and `dri`, so the grant carries a GPU grant's cost with it.
`x11 "host"` defends nothing at all: it binds the session's socket and
cookie, where every X client reads every other's input and windows and no
security context applies — lint `x11-without-reason`, a warning before
every real run, and the two gaming profiles are the only ones shipping
it.

[x11](manual.md#x11) ·
`x11_parses_nested_properties_and_host_and_refuses_the_rest`,
`nested_x11_requires_wayland_and_dri_on_the_flattened_config`,
`x11_host_is_a_warning_and_the_nested_default_is_a_note`,
`nested_x11_binds_nothing_and_only_names_the_display`,
`nested_x11_hands_the_supervisor_the_server_argv`,
`nested_x11_without_xwayland_on_the_host_fails`,
`the_x_server_is_not_started_until_a_client_connects`,
`no_child_but_the_server_inherits_the_display_socket`,
`the_window_manager_starts_with_the_server_and_the_shutdown_runs_inwards`,
`a_window_manager_that_cannot_be_started_is_logged_and_the_command_runs_on`,
`a_window_manager_that_exits_is_reported_once_and_the_command_runs_on`,
`a_server_that_cannot_be_spawned_terminates_the_command`,
`a_server_that_exits_after_serving_terminates_the_command`,
`a_command_that_ignores_the_signal_is_killed_when_the_display_goes`,
`a_second_stop_does_not_buy_the_command_another_grace`,
`a_client_that_connects_while_stopping_wakes_nothing`,
`an_exec_is_refused_once_the_run_is_stopping`,
`real_nested_x11_serves_a_private_display`,
`real_nested_x11_exec_children_see_the_display`,
`real_nested_x11_starts_the_server_on_the_first_client`,
`real_nested_x11_wm_exiting_is_logged_not_fatal`,
`real_nested_x11_missing_wm_is_logged_not_fatal`

### seccomp

**Defends:** a denylist compiled at launch and handed to bwrap as one
program — the keyring, `perf_event_open`, `bpf`, `userfaultfd`, module
and kexec loading, the clock and the host name, plus `TIOCSTI` and
`TIOCLINUX` denied by ioctl argument (CVE-2017-5226, CVE-2023-28100). A
second, smaller set answers `ENOSYS` rather than `EPERM` — `clone3` and
the whole new mount API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`,
`fsmount`, `fspick`, `mount_setattr`) — so libc falls back to the older
call instead of failing outright; that API is the one CVE-2021-41133
walked past flatpak's filter through, because a denylist written before
it existed did not name it. On
x86_64 the filter carries i386 as well, so a 32-bit binary is filtered
rather than killed, and a syscall from an ABI the filter does not carry
(x32) is killed rather than allowed to walk past it. The proxy sandbox
gets the same filter. A weaker filter is never quiet: `disable`, an
`allow` list that empties the rules, and a name this libseccomp does not
know each print on every run.

**Does not defend:** this narrows the kernel surface; it is not a
capability model. Everything unnamed is allowed, and `unshare`, `setns`,
`clone`, `mount`, `pivot_root`, `chroot` and `ptrace` are deliberately
among them so Firefox and Chromium can build their own inner sandbox. A
kernel bug behind an allowed syscall is a kernel bug in the sandbox.

[Seccomp](manual.md#seccomp) ·
`real_bwrap_seccomp_denies_the_default_list_and_nothing_else`,
`the_default_set_compiles_to_one_program_of_a_known_size`,
`the_ioctl_rules_compare_the_request_argument_once_per_architecture`,
`an_unknown_abi_is_killed_rather_than_allowed`,
`real_bwrap_seccomp_filters_a_32_bit_binary_instead_of_killing_it`,
`real_bwrap_seccomp_covers_the_dbus_proxy_sandbox`,
`a_filter_a_profile_emptied_is_as_loud_as_a_disabled_one`

### User namespaces inside the sandbox

**Defends:** `userns "disable"` emits `--unshare-user --disable-userns`,
and `unshare -U` inside then fails with `ENOSPC`.

**Does not defend:** it is off by default, because Firefox and Chromium
build their own sandbox out of a nested user namespace and Steam's
pressure-vessel runs bubblewrap of its own. So by default a sandboxed
process *can* make a user namespace and hold full capabilities in it —
which is how the mount and pid namespaces become reachable again. A
nested user namespace cannot undo bwrap's read-only binds, which is why
this is a default rather than a hole; `bubbler lint` warns when the node
is set under a command known to nest.

[User namespaces](manual.md#user-namespaces) ·
`real_bwrap_userns_disable_stops_a_nested_user_namespace`,
`disabling_user_namespaces_adds_two_phase_one_flags_and_nothing_else`,
`disabling_user_namespaces_under_a_nesting_command_is_a_warning`

### D-Bus

**Defends:** the session bus is never bound. An `xdg-dbus-proxy` runs in
a sandbox of its own and the *filtered* socket is what the application
gets. The proxy's only writable path is the instance's `dbus/`
subdirectory — the directory above it holds `init.sock` — and the socket
it serves is **moved** out of the proxy's reach first, and only then
opened `O_PATH|O_NOFOLLOW` and `fstat`ed to prove it really is a socket.
That order and not the reverse: proving first and moving second leaves a
window in which a proxy that keeps swapping the name can put a symlink in
the place of the socket that was just checked. Nothing outside the
instance directory can touch the entry once it is there, so its type
cannot change after the check, and `O_NOFOLLOW` makes a symlink fail with
`ELOOP` instead of being followed — a `stat` through the path would
report the *target's* type and bwrap would bind that target. The system
bus has no default name at all.

Two calls bubbler makes for itself go on the host session bus rather
than through the proxy — the accessibility bus address under `a11y`,
and `Documents.AddFull` for a file argument — over an in-tree client,
no program and no shell. Its trust rules: a call must name a
destination; a well-known name is resolved to its unique name
(`GetNameOwner`, and `StartServiceByName` where nobody holds it yet,
then resolved again) and the message is addressed *there*; a reply is
taken only when it carries the pending serial, is a reply type, and its
`SENDER` is that owner — or is an error from `org.freedesktop.DBus`,
the one name the bus stamps itself and no peer can forge. Signals,
replies to other serials and message types the client does not know are
skipped; the five-second budget is per call — one for the connect, the
authentication and `Hello`, another for each call, covering that call's
owner lookup, its activation and the call itself, so a peer that always
has another message to skip cannot outlast it, and a bus that goes
silent costs a forwarding run fifteen seconds at the outside (the
connect plus one `AddFull` per permission set, of which there are at
most two) and an `a11y` lookup ten, bounded rather than hung; the
decoder refuses what it cannot read exactly — padding that is not nul,
a length that does not match its elements, an interior nul, a repeated
header field, a container nested past the limit — instead of guessing;
and every descriptor a reply carries is closed on arrival, since
bubbler passes descriptors out and never takes one back. The client is
host-side code running as your uid on your own bus: it is bubbler
talking to your session, not the sandbox, which reaches that bus only
through the proxy.

**Does not defend:** what the rules grant. `talk` to a service is talk to
that service, and a service reachable through the bus is as trusted as
the bus makes it; `bubbler lint` warns about the wide ones (a name owned
beyond the application, every media-player name, polkit-backed system
services, the secret service).

[D-Bus](manual.md#d-bus), [The system
bus](manual.md#the-system-bus) ·
`real_dbus_hides_names_the_rules_do_not_grant`,
`a_proxied_socket_is_moved_out_of_the_proxys_reach`,
`a_proxy_that_swaps_its_socket_for_a_symlink_never_reaches_the_sandbox`,
`a_proxy_racing_its_own_socket_never_gets_a_symlink_bound`,
`the_proxy_never_sees_the_instances_control_socket`,
`real_system_bus_answers_for_the_names_it_grants_and_no_others`,
`reaching_the_secret_service_is_a_note`,
`a_reply_from_anyone_but_the_owner_of_the_name_is_ignored`,
`a_reply_with_no_sender_is_refused`,
`a_forged_answer_to_the_owner_lookup_is_ignored`,
`an_error_the_bus_sends_itself_answers_a_call_to_a_peer`,
`a_return_the_bus_sends_for_a_peer_is_not_taken_for_a_reply`,
`an_activatable_name_is_started_and_looked_up_again`,
`an_owner_that_answers_that_nobody_is_there_is_forgotten`,
`a_message_of_an_unknown_type_carrying_the_serial_is_skipped`,
`a_flood_of_messages_to_skip_does_not_outlast_the_deadline`,
`a_bus_that_says_nothing_times_the_call_out`,
`descriptors_a_reply_carries_are_closed`

### Accessibility bus

**Defends:** the accessibility bus is proxied, never bound. It is a peer
bus with no policy of its own, and it offers every client on it
`RegisterKeystrokeListener` — every keystroke of every accessible
application, which is how a screen reader's global keys work —
`GenerateKeyboardEvent` and `GenerateMouseEvent`, which inject input into
the session, and the object tree of every other application registered on
it. That is what makes the raw socket the same class of grant as the
session's X11 one. `a11y` gives the sandbox a third address on the
instance's own `xdg-dbus-proxy`, behind a `--filter` of its own, carrying
nine fixed rules and nothing from the config: the application registers
itself with the AT-SPI registry, unregisters, reads back which events are
registered, and notifies the listeners that exist. None of the calls
above is among them, and every destination but the registry is refused.
Measured inside a `dbus a11y` sandbox against this host's own bus:
`Registry.GetRegisteredEvents` and
`DeviceEventController.GetKeystrokeListeners` answer, while
`RegisterKeystrokeListener` and `GenerateKeyboardEvent` come back
`org.freedesktop.DBus.Error.AccessDenied` from the proxy, which the
registry never sees. `Socket.Embed` reaches the registry, which drops a
caller whose `(so)` argument `dbus-send` cannot type: the answer is
`org.freedesktop.DBus.Error.NoReply`, not a proxy refusal.

**Does not defend:** the grant itself. An assistive tool on the host
reads this application's widgets, labels and text — that is what a screen
reader is, and a call *into* the sandbox is incoming, which
`xdg-dbus-proxy` does not filter. Nothing here distinguishes Orca from
anything else running as your uid. The bus address is host input like
`$DBUS_SESSION_BUS_ADDRESS`: it comes from `$AT_SPI_BUS_ADDRESS` or from
`org.a11y.Bus`, must be a `unix:path=` socket, and is proxied under these
rules whatever it names.

[The accessibility bus](manual.md#the-accessibility-bus),
[D-Bus](manual.md#d-bus) ·
`real_a11y_lets_the_app_register_and_nothing_else`,
`real_a11y_lookup_needs_no_dbus_send`,
`a11y_dry_run_builds_the_bind_without_asking_any_bus`,
`a11y_is_a_third_bus_with_the_fixed_allowlist`,
`the_a11y_bus_is_a_third_address_and_its_rules_follow_its_own_filter`,
`the_a11y_bus_is_the_third_bus_of_the_one_proxy`,
`the_a11y_host_socket_is_bound_only_where_that_bus_is_proxied`,
`a11y_binds_the_proxied_bus_where_at_spi_clients_look_for_it`,
`an_a11y_section_without_a_host_socket_is_no_bus_at_all`,
`a11y_without_a_bus_is_refused_rather_than_downgraded`,
`a_set_at_spi_address_is_the_answer_and_only_a_unix_path_is_one`,
`an_answer_that_is_no_unix_socket_is_refused_and_never_echoed`,
`a_bus_that_does_not_answer_is_a_launch_error_naming_the_step`

### Input methods

**Defends:** `input-method` grants the two portal names,
`org.freedesktop.portal.Fcitx` and `org.freedesktop.portal.IBus`, which
carry the per-client text-input interface and nothing else. The daemons'
own names are not granted, and the proxy's name filtering is what makes
the client libraries fall back to the portal one. Behind a daemon name is
what the portal one leaves out: fcitx5's carries `Exit`, `Restart`,
`SetConfig`, `SetAddonsState`, `SetCurrentIM` and `SetLogRule`,
reconfiguring or stopping the input method of every application in the
session.

**Does not defend:** what an input method is. The daemon receives the keys
typed into this application's text fields, and the sandbox is one more of
its clients — a compromised application can feed it anything, and a
compromised daemon reads what is typed into everything it serves,
sandboxed or not. Contexts are per client, so this is not a path to
another application's keys. Neither daemon is installed on this host, so
what is proven inside a real sandbox is that their own names have no
owner there while the two portal names resolve — not a round trip
through a running input method.

[Input methods](manual.md#input-methods) ·
`real_input_method_hides_the_daemons_main_names`,
`input_method_talks_the_two_portal_names_only`,
`input_method_is_the_portal_variable_and_no_bind_at_all`,
`a11y_and_input_method_are_bare_nodes_that_need_dbus`,
`the_a11y_and_input_method_grants_show_the_rules_they_are`

### Network

**Defends:** an isolated `network` is the sandbox's own namespace. The
host's loopback services and its abstract unix sockets — which
`network_namespaces(7)` isolates and which have no permission checks at
all — are out of reach. pasta is started with six hardening values that
are not configurable, because its own defaults (`-t auto -u auto -T auto
-U auto`, `--map-host-loopback` at the gateway) would publish what the
sandbox binds and map the host's loopback back in. `/etc/resolv.conf` is
generated rather than bound. Before pasta starts, the namespace of the
pid bwrap reported is compared with bubbler's own, so a sandbox that died
in between cannot make pasta configure the *host* namespace; the user
namespace is asked of the network namespace that owns it rather than of
the pid, which bwrap moves. A sandbox whose namespace cannot be connected
waits at `--block-fd` and is stopped, never started without the network
it was granted.

`outbound "deny"` narrows the namespace to what the config names. By
address that is an nftables ruleset in the sandbox's own network
namespace, which the sandbox can neither read nor flush: the rules live
in the user namespace that owns its network namespace and bwrap puts the
application in a *nested* one, so `nft list ruleset` inside fails with
`Operation not permitted` before it reads the table.

By name it is `allow-host`, and the enforcement is a process rather than
a rule. `bubbler-net-proxy` (§2 above) runs in a per-sandbox cgroup and
in the sandbox's namespaces; the ruleset accepts that cgroup —
`socket cgroupv2 level <n> "<own cgroup>/bubbler-<inst>-<pid>/proxy"` —
and rejects the rest, so the application's own packets never leave and
what it can reach is what the proxy opens on the names the config listed.

The application cannot reach the proxy's privilege, and the reason is
**placement** rather than its own confinement. With the default
`userns "allow"` it can make itself a user, cgroup and mount namespace
and mount cgroup2 (measured), but that mount is rooted at the `sandbox`
leaf bubbler moved itself into before spawning bwrap, and the proxy's
`proxy` leaf is a sibling outside it — unnameable through that mount,
and refused by `nsdelegate` even if it were named. `allow-port 3128` —
the one way the host could have been given a path to the proxy, since
pasta serves a forwarded port from inside the namespace — is a config
error whenever an `allow-host` is present. Measured from inside such a
sandbox, doing exactly that:

```
mount ok        visible 0       join refused
direct refused EHOSTUNREACH     dns none
```

`dns none` is deliberate: with any `allow-host` the resolver rules carry
the cgroup match too, so only the proxy resolves. A sandbox that could
query would have a channel out of a network that otherwise has none
(`<secret>.attacker.example`, read off the attacker's own authoritative
server). The cost is that an application ignoring `HTTPS_PROXY` fails at
the name lookup rather than at the connection.

**Does not defend:** it is not a firewall. pasta routes, so a host
service bound to `0.0.0.0` on an address pasta did not copy in — a VPN
endpoint, `docker0`, a second NIC — is reachable from inside exactly as
from any other machine on that network. `network "host"` gives all of it
back on purpose, and neither filter is offered under it.

The proxy is trusted with the tunnel's bytes and runs without a seccomp
filter (§2). Its log is bubbler's own stderr, and the budget bounds the
*rate* of those lines (20 a second, then a suppressed count) and not the
total, so a sandbox refused often enough for long enough can still push
older lines out of the 1 MiB `last-run.log` cap — the log is a
diagnostic, and losing its head that way is a trade-off rather than a
bound bubbler enforces. `allow-host` also needs a delegated cgroup2
subtree; without one the run is refused rather than started unfiltered.
An `allow-out` written with no `port=` covers port 53 at that address as
well, which leaves the application a resolver to query directly.

[network](manual.md#network) ·
`pasta_argv_is_the_hardened_invocation`,
`every_hardening_flag_is_present_whatever_the_node_asked_for`,
`the_namespace_check_compares_the_held_descriptor_by_identity`,
`the_user_namespace_comes_from_the_network_namespace_it_owns`,
`a_sandbox_whose_network_cannot_be_connected_never_runs`,
`real_pasta_hides_the_host_loopback_that_network_host_still_reaches`,
`a_loopback_resolver_is_refused_only_where_it_would_be_the_sandbox`,
`allow_host_puts_the_cgroup_accept_before_the_reject_and_gates_dns`,
`an_allow_out_on_the_resolver_port_is_gated_with_the_rest_of_dns`,
`the_rule_names_the_proxy_leaf_beside_the_sandbox_s`,
`the_teardown_moves_bubbler_back_and_removes_every_directory`,
`an_empty_leftover_of_an_earlier_run_is_swept`,
`allow_host_needs_outbound_deny_and_an_isolated_namespace`,
`the_proxy_port_cannot_be_forwarded_in_beside_an_allow_host`,
`the_proxy_variables_are_reserved`,
`real_allow_host_relays_a_listed_name_and_nothing_else`,
`real_allow_host_survives_the_sandbox_mounting_cgroup2_for_itself`,
`allow_host_explains_the_proxy_and_the_variables_without_running`

### The terminal

**Defends:** your terminal does not enter the sandbox. Each of bubbler's
own fds 0, 1 and 2 that is a terminal is replaced by the slave of a pty
bubbler allocated, and bubbler relays. Every sandbox is started with
`--new-session`, so it inherits no controlling terminal, and the seccomp
filter denies `TIOCSTI` and `TIOCLINUX` on top of that. A terminal that
will not take output cannot wedge bubbler, and nothing is dropped while
the run lasts: once 64 KiB is waiting the sandbox's own side is left
unread, so the application blocks in its `write` and the output runs at
the speed of your terminal. Discarding happens only at the hand-over on
the way out, inside a ten-second window with a five-second stall rule.
No descriptor of yours is left with its flags changed.

Reading a record of that output is not replaying it: `bubbler log`
renders the control characters — C0 and `DEL` as `^[`, C1 and bytes that
are not UTF-8 as `\x9b` — whenever its stdout is a terminal, so an OSC 52
a sandbox left in `last-run.log` cannot write the clipboard of whoever
reads it. A pipe gets the log byte for byte, since the reader there is a
tool. The same rendering covers what `--explain` and `lint` echo out of a
config that need not be yours.

**Does not defend:** what is inherent to any relay. The application reads
what you type into that session and can emit escape sequences your
emulator parses — title changes, OSC 52 clipboard writes, query sequences
whose answers arrive as its own input. Do not type a password into a
session you do not trust. `tty "passthrough"` gives up the rest as well:
the sandbox holds your terminal's descriptors and reaches it through
`/dev/console`.

[Terminal](manual.md#terminal) ·
`real_bwrap_run_from_a_terminal_gives_the_sandbox_a_terminal_of_its_own`,
`real_bwrap_run_writes_nothing_to_a_terminal_it_does_not_own`,
`a_host_that_never_reads_holds_the_sandbox_back_instead_of_the_relay`,
`output_the_host_cannot_take_is_discarded_and_the_pty_kept_empty`,
`a_warning_leaves_the_stderr_it_was_given_exactly_as_it_was`,
`the_guard_enters_raw_mode_and_restores_the_terminal`,
`allowing_ioctl_is_what_takes_back_the_tiocsti_rules`,
`log_shows_a_terminal_the_control_bytes_and_a_pipe_the_log_itself`,
`a_terminal_is_shown_the_control_characters_instead_of_acting_on_them`

### Host paths

**Defends:** a `path-share` is resolved before anything is bound, must be
a directory or a regular file, and neither end may be, be inside, or
contain one of the roots the sandbox is built out of — including your
home, `$XDG_RUNTIME_DIR`, the instance store and either profile layer —
your own and the directory `$BUBBLER_PROFILE_DIR` names — each compared
as written *and* as resolved so a symlinked home cannot be shared under
its real name. Overlapping shares are refused so that bind order stays
irrelevant. `home-share` and `etc-share` refuse a symlink that leaves
their own tree, and a `home-share` — like a `--share` under your home —
is held to the roots that live *inside* it: the instance store, your
profile layer, a `$BUBBLER_PROFILE_DIR` pointed there, and any path
containing one, read-only as much as read-write.

**Does not defend:** TOCTOU. bwrap resolves the path again when it binds,
so between bubbler's check and that bind the tree can change; on a
single-user machine the party who could change it is you. And the flip
side of resolving first is that what gets bound is the link's *target*
under the name you wrote.

[Host paths](manual.md#host-paths) ·
`path_share_refuses_every_reserved_root`,
`path_share_through_a_symlink_into_a_reserved_root_is_refused`,
`path_share_overlapping_shares_are_refused`,
`path_share_refuses_a_destination_on_a_reserved_root`,
`path_share_of_a_symlinked_home_or_data_dir_is_refused`,
`home_share_through_a_symlink_out_of_the_home_is_refused`,
`home_share_of_the_instance_store_is_refused`,
`home_share_of_the_profile_layer_is_refused`,
`home_share_of_an_ancestor_of_the_instance_store_is_refused`,
`home_share_of_the_profile_dir_override_is_refused`,
`path_share_of_the_profile_dir_override_is_refused`,
`home_share_reserved_fires_on_the_store_the_layer_and_their_ancestors`,
`home_share_of_the_instance_store_is_refused_and_linted`,
`etc_share_through_a_symlink_out_of_etc_is_refused`

### File arguments

**Defends:** the only host file that enters is the one the user named on
the command line, and it enters through the document portal rather than a
bind. `run`, `try` and `open` register a trailing argument that is an
absolute path or a `file://` URI to an existing regular file, one call
per permission set, with the portal's own per-document permission —
`read`, plus `write` only where the user could already write the file
(`access(W_OK)`), never `delete` and never `grant-permissions`. The
registration is session-scoped: `reuse_existing` is set so a file handed
over twice keeps one id, `persistent` is not, so nothing lasting is
written into the portal's database. The descriptor handed over is
`O_PATH`, which names a file without opening it for reading or writing,
and its type is re-checked on that descriptor, so a path that became a
directory between the plan and the open cannot be smuggled to the portal.
The program itself is never a document — replacing argument 0 would swap
the binary that runs. Refused, each leaving the argument exactly as it
was: a directory (`path-share` and `home-share` are the typed grants for
one), anything that is not a regular file, anything under `/proc`, `/sys`
or `/dev` — tested on the path, on its resolved form, and once more on
the opened descriptor, whose filesystem magic is checked as well as its
`/proc/self/fd` name, since a bind mount of procfs or sysfs answers to a
path no prefix test catches — and any path holding a `..` component,
which is refused rather than folded because what it resolves to depends
on the symlinks along the way. A file the sandbox already reaches is
renamed to the path it has inside instead of being registered, which
spends no grant at all. Every failure is soft: the argument is passed on
unchanged and a warning names the gap.

**Does not defend:** the by-app view. A document is registered against
the instance's app id and that whole view is bound at
`$XDG_RUNTIME_DIR/doc` inside, so the application can list and reopen
every document the same instance was handed earlier in the session, not
only the one it was started for. That is the portal's design and the
reason the view is per-app rather than the mount root. A symlink
argument exports its *target* under the target's name: the link is what
the desktop handed over and the file at the end of it is what the user
meant, so an argument naming a link to a private file registers that
file. Nor does it stop at what the baseline hides: the rule is that the
file the user named enters, and a `/etc` path the allowlist does not
carry is one of those — `/etc/passwd` inside is the synthetic two-line
file bubbler writes over a tmpfs, and `run <inst> -- cat /etc/passwd`
hands the sandbox the host's real one at a document path. Naming it is
the choice; forwarding does not second-guess it. And the client that
makes the call is host-side code running as your uid on your own
session bus — see "D-Bus" above. A `portals` sandbox holds a `--talk`
rule for `org.freedesktop.portal.Documents` of its own besides, so what
it may ask that portal for directly is the portal's policy for its app
id rather than bubbler's.

[File arguments](manual.md#file-arguments),
[D-Bus](manual.md#d-bus) ·
`real_open_forwards_a_host_file`,
`real_run_forwards_with_write_when_writable`,
`real_open_into_a_running_instance_forwards_too`,
`run_without_portals_warns_and_leaves_the_argument`,
`a_home_share_path_is_renamed_not_forwarded`,
`dry_run_prints_the_forward_line`,
`every_argument_is_classified_once`,
`the_program_is_never_a_document`,
`a_link_that_lands_in_proc_is_refused_like_the_path_itself`,
`a_descriptor_that_lands_in_proc_is_refused_after_the_open`,
`a_file_that_is_not_one_when_it_is_opened_is_dropped_from_the_call`,
`one_call_carries_the_descriptor_the_flags_and_the_app_id`,
`a_permission_set_is_one_call_and_the_ids_come_back_in_order`,
`a_document_id_that_is_not_a_name_is_refused_rather_than_joined`,
`a_refusal_leaves_every_file_of_that_call_alone`,
`a_session_that_broke_is_not_called_again`,
`nothing_to_register_makes_no_call_at_all`

### app-runtime

**Defends:** only the leaf `app/<id>` is ever bound, never `app/` and
never `$XDG_RUNTIME_DIR`, where every instance's control socket lives.
bubbler creates the directory, never the sandbox, and opens it
`O_NOFOLLOW` so a symlink planted where it belongs is refused. The id
grammar — at least two `.`-separated elements — is what makes an id that
names `bubbler`, `..` or a path impossible.

**Does not defend:** co-tenancy. `mode=rw` lets that sandbox unlink the
socket its peers connect to and bind its own, or leave a symlink the peer
then resolves on its own side of the boundary. That is the grant, not a
bug; `bubbler lint` notes it as `app-runtime-rw`.

[app-runtime](manual.md#app-runtime) ·
`app_runtime_rejects_an_id_that_could_name_another_runtime_entry`,
`app_runtime_refuses_a_symlink_where_the_directory_belongs`,
`an_app_parent_that_is_a_symlink_is_refused_before_any_id_is_made`,
`real_bwrap_app_runtime_carries_a_byte_between_two_sandboxes_and_the_host`,
`a_writable_app_runtime_share_is_a_note`

### The exec control channel

**Defends:** the socket is bound by bubbler on the host and handed to the
sandbox only as an inherited descriptor, so no path to it exists inside;
`bubbler-init` sets `CLOEXEC` on it at once and makes itself
non-dumpable. The wire decoder refuses an empty, truncated or oversized
request and one that carries no descriptors, and a client that trickles
bytes cannot extend the deadline. Once the run is stopping — the display
gone, or a SIGTERM to `bubbler-init` — a request is turned down rather
than served (`bubbler-init: stopping; <program> was not run`, exit 127),
so nothing is spawned into a sandbox that is being torn down and no child
reaches the SIGKILL deadline without having been asked to stop first.

**Does not defend:** descriptors passed to an exec'd command are
reachable by the sandboxed application through `/proc`. `exec` is a
convenience channel, not a boundary, and the manual says so.

[Usage](manual.md#usage), [Known gaps](manual.md#known-gaps) ·
`rejects_empty_truncated_and_oversize`,
`request_without_fds_is_rejected`,
`an_incoming_request_larger_than_the_cap_is_rejected`,
`a_truncated_payload_times_out_instead_of_hanging`,
`a_trickling_client_cannot_extend_the_deadline`,
`a_stale_socket_is_unlinked_so_a_fresh_start_can_bind`,
`an_exec_is_refused_once_the_run_is_stopping`,
`real_bwrap_exec_round_trip`

### Desktop entries and PATH shims

**Defends:** four things are written outside bubbler's own state:
`$XDG_DATA_HOME/applications/` entries, `~/.local/bin/` symlinks,
`$XDG_RUNTIME_DIR/.flatpak/bubbler-<instance>/bwrapinfo.json` (bwrap's
own info document, which a portals grant needs before the app starts) and
`$XDG_RUNTIME_DIR/app/<id>`, the app-runtime rendezvous, which is left
behind on purpose because a peer may still be serving in it. The first
two are the generated ones, and both refuse to write through something
they did not put there: a symlink
planted where an entry is built is never written through, only bubbler's
own entry for that instance is overwritten, a file that is not our shim
is never replaced, and a registry bubbler did not write is an error. The
shim dispatches on `argv[0]`, which is caller-controlled, so names
bubbler resolves itself are refused and a name that is not one plain file
name is refused.

**Does not defend:** the entry is a command line you can edit afterwards.
The `%u`/`%f` host paths a launcher expands into it reach `bubbler open`
as trailing arguments and go through the document portal from there —
what that grants, and what it does not, is "File arguments" above.

[Desktop entries](manual.md#desktop-entries), [PATH
shims](manual.md#path-shims) ·
`a_symlink_planted_where_the_entry_is_built_is_never_written_through`,
`only_bubblers_own_entry_for_this_instance_is_overwritten`,
`the_keys_that_bypass_the_sandbox_are_forced_even_where_they_are_absent`,
`a_file_that_is_not_our_shim_is_never_replaced`,
`names_bubbler_resolves_itself_are_refused`,
`a_registry_bubbler_did_not_write_is_an_error`

### Configuration parsing

**Defends:** the input is your own file, so this is correctness rather
than security — with one exception. The `kdl` crate recurses in three
places, and a file shaped for any of them would overflow the stack and
abort bubbler with no diagnostic. Two are driven by bytes a count can
see — it descends once per `{` and once per `*` or `/` in a `/* */`
comment — so every configuration bubbler reads is pre-checked and refused
above 32 `{` counted wherever they stand, or holding a `/*` with more
than 128 `*` or `/` after it, naming the file. The count trusts no string
and no comment and lets no `}` give a brace back: the parser recovers
from a string it cannot read by reading the inside as nodes, so a bound
that followed its grammar was one its recovery stepped around. The third
recursion is the parser's recovery from a top-level token it cannot place
(`}`, `)`, `=`, …): one byte consumed and the document parser re-entered,
one stack frame per such byte, which no count of the text bounds short of
refusing every syntax error. So the stack is sized for it instead: a
configuration is refused above 64 KiB, and the parser runs on a thread
with 512 MiB of stack reserved, which holds a frame per byte of the
largest file admitted with more than twice the room to spare. The
reservation is address space charged at spawn, not memory used: under a
`ulimit -v` below about 520 MB, or `vm.overcommit_memory=2` with
`Committed_AS` near `CommitLimit`, every configuration read fails with
`cannot start the parser thread` — exit 1, never a crash.
Include cycles and depth are bounded, an unknown node is an error rather
than a silent skip, and a value that could forge a line in `--dry-run`
output is refused.

**Does not defend:** a profile you chose to install. See "The attacker".

[Profiles](manual.md#profiles), [Known
gaps](manual.md#known-gaps) ·
`nesting_past_the_bound_is_refused_before_the_parser_recurses`,
`a_configuration_past_the_size_bound_is_refused_unparsed`,
`a_token_the_parser_cannot_place_costs_a_frame_per_byte_and_the_stack_holds_them`,
`a_configuration_nested_past_the_bound_is_refused_wherever_it_is_read`,
`a_cycle_is_an_error_naming_the_chain`,
`nesting_stops_at_the_depth_limit`,
`env_and_command_values_reject_bytes_that_cannot_be_argv`,
`unknown_node_is_an_error`

## Non-goals

Stated so nobody has to infer them.

- **Not a boundary against root.** Everything here is unprivileged and
  built out of user namespaces.
- **Not a boundary against your own processes.** Anything running as your
  uid outside a sandbox can read the instance store, connect to
  `init.sock`, ptrace bubbler, and replace the binary on your `PATH`.
  bubbler protects you from the *application*, not from your account.
- **No defence for `x11 "host"`.** The session's display offers no
  isolation between clients: any client can read any other's input and
  windows, and an Xwayland client is outside the Wayland security context
  as well. The mode exists for compatibility, `bubbler lint` warns on it,
  `bubbler run` warns again before a real run, and only the two gaming
  profiles ship it. A bare `x11` is the nested server above instead.
  ([x11](manual.md#x11), [Linting](manual.md#linting);
  `x11_host_is_a_warning_and_the_nested_default_is_a_note`,
  `x11_warns_before_a_real_run`,
  `only_the_gaming_profiles_grant_x11_and_none_disables_user_namespaces`.)
- **No defence against the kernel.** seccomp narrows the surface; a bug
  behind an allowed syscall is reachable, and the syscalls Firefox and
  Chromium need to build their own sandbox are allowed on purpose.
- **`gamepad uinput=#true` is an outward grant.** `/dev/uinput` injects
  input into the host session. It is off unless a config asks for it.
- **Not protection against a `path-share` you wrote.** The denylist stops
  the shares that would break bubbler's own model; the rest is yours.
- **`/etc/machine-id` is shared**, so instances are not unlinkable.

## Honest probes

None of the above is worth anything if the tests that pin it silently do
not run. The real-sandbox tests are guarded by runtime probes rather than
`#[ignore]`, and each probe does the thing it is a probe for:
`require_userns()` creates a user namespace, `require_bwrap()` builds an
actual sandbox with `bwrap --unshare-all --ro-bind / / --proc /proc --dev
/dev`, and `require_pasta()` attaches a real pasta to a namespace it made
for the purpose. Looking for `/proc/self/ns/user` would have been
dishonest: that path exists in every container, including those whose
policy refuses the syscall behind it, and the guarded tests would fail
there instead of skipping. Each reason is written to descriptor 2
directly rather than with `eprintln!`, so it survives the capture libtest
installs and an ordinary `cargo test` shows what it did not cover. A host
that cannot sandbox is proved to skip rather than fail by
`a_host_without_a_working_bwrap_skips_the_guarded_tests_rather_than_failing_them`,
which runs one of those tests again — with no `--nocapture` — under a
`PATH` carrying a `bwrap` that exits 1, and then under one with no
`bwrap` at all.

## Audit targets

The paths a compromised application can actually reach, ranked, which the
milestone-10 audit works through one at a time. Fixes land as `fix:`
commits with a regression test; this document is updated where a claim
changes.

1. The exec wire protocol and its `SCM_RIGHTS` hand-off — truncated,
   oversized, zero-fd and too-many-fd messages, interleaved partial
   writes.
2. Who can reach that socket at all — the four separate assumptions that
   make it unreachable from inside (bound on the host, handed in as a
   descriptor only, `CLOEXEC` in the one process holding it, that process
   non-dumpable, and `$XDG_RUNTIME_DIR` inside an empty `--dir` on a
   fresh tmpfs that `path-share` refuses).
3. Proxy socket adoption — a symlink, directory, FIFO or regular file
   planted where the socket belongs, and the order of move and proof.
4. The `path-share` denylist — symlink smuggling in both directions, the
   `/run/media` carve-out, overlap only after resolution, and the
   `$BUBBLER_TEST_ALLOW_PATH` hook.
5. `app-runtime` — an id that escapes the leaf, a symlink at `app/<id>`,
   and the bounds of the co-tenancy hole above.
6. The pasta user-namespace descriptor — pid reuse between `--info-fd`
   and the open, and what the two `/proc/<pid>/fd/N` paths hand over.
7. `bubbler-init --ctty` and the pty relay — reaching the host's terminal
   through `/dev/console`, wedging bubbler through the flush or the stall
   rule, and warnings that mutate the caller's fd flags.
8. Desktop entries and PATH shims — `Exec=`/`TryExec=` injection through
   an instance name or a vendor entry's own text, writing through a
   symlink, and `argv[0]` as attacker-chosen input.
9. seccomp compilation — a node that removes every rule, a name on both
   lists, a name this libseccomp does not know, a filter that loses its
   i386 half. The failure mode is a weaker sandbox reporting success.
10. Config and profile parsing — include cycles, depth exhaustion, a
    diamond that grants more than a chain, one path merged in two modes.
11. The egress proxy — the `CONNECT` parser against a request the sandbox
    writes (the target and `Host` disagreeing, obs-fold, over-long lines,
    bytes pipelined behind the blank line), and the cgroup placement that
    keeps the application out of the proxy's leaf, which is the whole of
    why it may not be joined.
