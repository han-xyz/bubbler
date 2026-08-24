# Security

## Threat model (short form)

The boundary is between **your account and one application**. It is not a
boundary against root, not against your own unsandboxed processes (anything
running as your uid can read the instance store and connect to a live
instance's control socket), and `x11` is not a boundary at all. bubbler itself
is unprivileged and unconfined. Long form with every claim pinned to a test:
[`docs/threat-model.md`](https://github.com/han-xyz/bubbler/blob/master/docs/threat-model.md).

## Process chain

```
bubbler ─┬─ bwrap ── bwrap (pid 1 inside, reaps) ── bubbler-init (pid 2) ── your command
         ├─ bwrap ── bwrap ── xdg-dbus-proxy        (only with dbus / system-bus)
         └─ pasta                                   (only with isolated network; not sandboxed)
```

`bubbler-init` serves the control socket `exec` connects to; the socket is
handed in as an inherited fd, so nothing inside reaches its path. Descriptors
passed through `exec` are reachable via `/proc` — exec is a convenience
channel, not a boundary. `--die-with-parent` is the backstop for everything.

## Seccomp

Every sandbox (instances, `try`, the proxy) loads a denylist compiled with
libseccomp at launch. Everything not named is allowed: it narrows the kernel
surface, it is not a capability model.

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

- No accessibility bus.
- AMD compute (`/dev/kfd` + sysfs topology) unsupported; NVIDIA compute needs
  `etc-share "OpenCL"`/`"nvidia"`.
- `hidraw` and `camera nodes=#true` device lists are frozen at launch.
- No raw USB grant, no pcsclite socket: challenge-response YubiKey and smart
  cards unreachable.
- `app-runtime` does not carry Discord rich presence.
- KeePassXC native messaging manifest must be placed by hand.
- `camera` never exercised on real hardware.
- Deeply nested KDL would overflow the `kdl` crate's parser; bubbler refuses
  files over 1 MiB or deeper than 32 braces first.
- Desktop entries: `%f` paths unreachable; D-Bus activation closed for the
  entry only.

## AppArmor

`contrib/apparmor/usr.bin.bubbler` is offered to packagers on distributions
that mediate user namespaces through AppArmor (Ubuntu 23.10+). Ships in
complain mode and **has never been loaded**; keep `allow userns create,` if
you narrow it.
