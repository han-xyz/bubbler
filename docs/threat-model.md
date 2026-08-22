# bubbler threat model

What bubbler defends, what it does not, and where each answer is written
down and pinned by a test. Every mechanism below links the README section
that describes it and the test that would fail if the behaviour changed.
Read it as the companion to the README's "Known gaps": that list is what
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
([Linting](../README.md#linting), [Explaining an
argv](../README.md#explaining-an-argv); `every_argument_is_attributed_to_the_node_that_asked_for_it`,
`every_builtin_profile_lints_clean`,
`a_finding_never_stands_in_for_a_layer_that_does_not_parse`.)

## Trust boundaries

In decreasing order of strength.

### 1. Host user ↔ sandbox — the real boundary

Enforced by bwrap's namespaces, the bind set the arg builder emits, and
the seccomp filter. This is the one everything below is measured against,
and the one the mechanism table covers.

### 2. Sandbox ↔ sidecars

Four processes sit beside a sandbox, and they are not one kind of thing:

| Sidecar | Where it runs | Is it a boundary? |
|---|---|---|
| `xdg-dbus-proxy` | its own bwrap sandbox, sibling of the app's | **Yes.** It is a filter, it sees only the host bus socket read-only and the instance's `dbus/` subdirectory read-write, and the socket it serves is moved out of its reach before anything is bound. |
| `bubbler-init` | *inside* the sandbox, as pid 2 | **No.** It is the supervisor, not a guard: it shares the sandbox with the application. What it holds — the listening control socket — is kept from the application by being an inherited descriptor with no path, `CLOEXEC` in the only process that has it, and `PR_SET_DUMPABLE` off so `/proc/<init>/fd` cannot be walked. |
| `pasta` | on the host, **not sandboxed**, holding the sandbox's outer user namespace | **No, in one direction.** A pasta that has been taken over *is* that sandbox's network and holds root over the namespaces the sandbox is built from. It owns nothing beyond what your own account already has: your uid created that namespace. Wrapping it in bwrap would not add anything — it would remove the very thing pasta needs, since a process can only join a descendant of its own user namespace. |
| `nft` | on the host, entering the sandbox's namespaces to install rules | Not in this tree yet: outbound filtering lands in Task 1 of this milestone, which merges next. This row gets its answer, and the test that pins it, then. |

([A run is a chain of processes](../README.md#usage),
[D-Bus](../README.md#d-bus), [network](../README.md#network);
`the_proxy_never_sees_the_instances_control_socket`,
`a_proxied_socket_is_moved_out_of_the_proxys_reach`,
`proxy_argv_runs_the_proxy_in_its_own_sandbox`.)

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
  anything on that instance's next run. That is why the denylist exists,
  why it compares the roots your environment names both as written and as
  resolved, and why the `$BUBBLER_TEST_ALLOW_PATH` hook cannot lift them.
- `/etc/machine-id` is bound in, so every instance shares one stable
  identifier with the host.

([app-runtime](../README.md#app-runtime), [Host
paths](../README.md#host-paths), [Known gaps](../README.md#known-gaps);
`path_share_resolves_the_instance_store_itself`,
`path_share_compares_the_environment_roots_resolved`,
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
`etc-share` and `dri` are grants, and a grant is what it says it is.

[Baseline](../README.md#baseline) ·
`baseline_argv_is_exact`, `etc_is_an_allowlist_of_existing_entries`,
`service_binds_come_after_runtime_dir_and_before_env`,
`real_bwrap_home_is_fixed_and_private`,
`real_bwrap_etc_is_allowlisted_and_user_is_bubbler`

### Host environment values

**Defends:** `WAYLAND_DISPLAY`, `XAUTHORITY` and `DISPLAY` are untrusted
input. Their shape is validated (one path component) and the *file type*
is probed, never mere existence, so a variable naming a directory is
refused instead of binding the tree under it.

**Does not defend:** a value that really does name a socket of the right
type is bound, whatever it is a socket for.

[Baseline](../README.md#baseline) ·
`wayland_display_must_name_a_socket`,
`wayland_display_that_is_not_one_component_is_rejected`,
`wayland_socket_path_of_the_wrong_type_fails`,
`x11_socket_that_is_not_a_socket_fails`,
`x11_xauthority_at_a_directory_fails`

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

[Seccomp](../README.md#seccomp) ·
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

[User namespaces](../README.md#user-namespaces) ·
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

**Does not defend:** what the rules grant. `talk` to a service is talk to
that service, and a service reachable through the bus is as trusted as
the bus makes it; `bubbler lint` warns about the wide ones (a name owned
beyond the application, every media-player name, polkit-backed system
services, the secret service).

[D-Bus](../README.md#d-bus), [The system
bus](../README.md#the-system-bus) ·
`real_dbus_hides_names_the_rules_do_not_grant`,
`a_proxied_socket_is_moved_out_of_the_proxys_reach`,
`a_proxy_that_swaps_its_socket_for_a_symlink_never_reaches_the_sandbox`,
`a_proxy_racing_its_own_socket_never_gets_a_symlink_bound`,
`the_proxy_never_sees_the_instances_control_socket`,
`real_system_bus_answers_for_the_names_it_grants_and_no_others`,
`reaching_the_secret_service_is_a_note`

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

**Does not defend:** it is not a firewall. pasta routes, so a host
service bound to `0.0.0.0` on an address pasta did not copy in — a VPN
endpoint, `docker0`, a second NIC — is reachable from inside exactly as
from any other machine on that network. Outbound traffic is all or
nothing in this tree. `network "host"` gives all of it back on purpose.

[network](../README.md#network) ·
`pasta_argv_is_the_hardened_invocation`,
`every_hardening_flag_is_present_whatever_the_node_asked_for`,
`the_namespace_check_compares_what_the_links_name`,
`the_user_namespace_comes_from_the_network_namespace_it_owns`,
`a_sandbox_whose_network_cannot_be_connected_never_runs`,
`real_pasta_hides_the_host_loopback_that_network_host_still_reaches`,
`a_loopback_resolver_is_refused_only_where_it_would_be_the_sandbox`

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

[Terminal](../README.md#terminal) ·
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
home, `$XDG_RUNTIME_DIR` and the instance store, each compared as written
*and* as resolved so a symlinked home cannot be shared under its real
name. Overlapping shares are refused so that bind order stays irrelevant.
`home-share` and `etc-share` refuse a symlink that leaves their own tree.

**Does not defend:** TOCTOU. bwrap resolves the path again when it binds,
so between bubbler's check and that bind the tree can change; on a
single-user machine the party who could change it is you. And the flip
side of resolving first is that what gets bound is the link's *target*
under the name you wrote.

[Host paths](../README.md#host-paths) ·
`path_share_refuses_every_reserved_root`,
`path_share_through_a_symlink_into_a_reserved_root_is_refused`,
`path_share_overlapping_shares_are_refused`,
`path_share_refuses_a_destination_on_a_reserved_root`,
`path_share_of_a_symlinked_home_or_data_dir_is_refused`,
`home_share_through_a_symlink_out_of_the_home_is_refused`,
`etc_share_through_a_symlink_out_of_etc_is_refused`

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

[app-runtime](../README.md#app-runtime) ·
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
bytes cannot extend the deadline.

**Does not defend:** descriptors passed to an exec'd command are
reachable by the sandboxed application through `/proc`. `exec` is a
convenience channel, not a boundary, and the README says so.

[Usage](../README.md#usage), [Known gaps](../README.md#known-gaps) ·
`rejects_empty_truncated_and_oversize`,
`request_without_fds_is_rejected`,
`an_incoming_request_larger_than_the_cap_is_rejected`,
`a_truncated_payload_times_out_instead_of_hanging`,
`a_trickling_client_cannot_extend_the_deadline`,
`a_stale_socket_is_unlinked_so_a_fresh_start_can_bind`,
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

**Does not defend:** the entry is a command line you can edit afterwards,
and `%f` arguments in it are host paths the sandbox cannot open.

[Desktop entries](../README.md#desktop-entries), [PATH
shims](../README.md#path-shims) ·
`a_symlink_planted_where_the_entry_is_built_is_never_written_through`,
`only_bubblers_own_entry_for_this_instance_is_overwritten`,
`the_keys_that_bypass_the_sandbox_are_forced_even_where_they_are_absent`,
`a_file_that_is_not_our_shim_is_never_replaced`,
`names_bubbler_resolves_itself_are_refused`,
`a_registry_bubbler_did_not_write_is_an_error`

### Configuration parsing

**Defends:** the input is your own file, so this is correctness rather
than security — with one exception. The `kdl` crate parses `{` by
recursing, and a deeply nested file would overflow the stack and abort
bubbler with no diagnostic, so every configuration bubbler reads is
pre-checked and refused above 1 MiB or 32 braces, naming the file.
Include cycles and depth are bounded, an unknown node is an error rather
than a silent skip, and a value that could forge a line in `--dry-run`
output is refused.

**Does not defend:** a profile you chose to install. See "The attacker".

[Profiles](../README.md#profiles), [Known
gaps](../README.md#known-gaps) ·
`nesting_past_the_bound_is_refused_before_the_parser_recurses`,
`a_configuration_past_the_size_bound_is_refused_unparsed`,
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
- **No defence for `x11`.** X11 offers no isolation between clients: any
  client can read any other's input and windows. The grant exists for
  compatibility, `bubbler lint` warns on it, `bubbler run` warns again
  before a real run, and only the two gaming profiles ship it.
  ([Baseline](../README.md#baseline), [Linting](../README.md#linting);
  `x11_is_a_warning_a_lint_allow_node_accepts`,
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
