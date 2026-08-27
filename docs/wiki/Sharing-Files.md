# Sharing Files

The sandbox's home is `/home/bubbler`, a private directory under the instance.
Nothing of your real home is visible unless shared here — or picked by you in
a portal file chooser, or named on the command line, under `portals` (see
[D-Bus](D-Bus.md#portals)).

## File arguments

`run`, `try` and `open` hand the sandbox the host files named after the program
— which is how a desktop entry's `%u`/`%f` and an "open with" from a file
manager arrive. An argument that is an absolute path or a `file://` URI
(percent-decoded, empty or `localhost` authority) naming an existing regular
file is registered with the document portal under `portals` and replaced by
`$XDG_RUNTIME_DIR/doc/<id>/<name>`, the by-app view that grant already binds:

```
$ bubbler try --grant dbus --grant portals -- \
      /usr/bin/sh -c 'echo "$1"; cat "$1"' _ /tmp/fwd-demo.txt
/run/user/1000/doc/EorCLxJVSCrs7aKkv5AvCw/fwd-demo.txt
hi
```

- Permissions: `read`, plus `write` where you can write the file yourself.
  Never `delete`, never `grant-permissions`. Session-only (`reuse_existing`,
  not `persistent`).
- Already visible at the same path — `path-share`, `etc-share`, the baseline's
  `/etc` allowlist, `/usr`, `/opt` — the argument is left alone. Bound under
  another name — a `home-share` source, the instance home — it is rewritten to
  the `/home/bubbler/…` form, which needs no portal and no grant.
- With `portals`, refused with a warning and the argument untouched: a
  directory *not* under a share (that is what these shares are for — one that
  is under one is renamed by the rule above, with no warning), anything that
  is not a regular file, `/proc` `/sys` `/dev` (by the path, by what it
  resolves to, and again on the opened descriptor — by name for all three, by
  filesystem for procfs and sysfs), and any path containing `..`.
- Untouched and silent: relative paths, flags, bare words, other URI schemes.
- Symlinks are followed: what is exported is the file at the end of the link,
  under that file's name.
- Without `portals`: `<path> is not visible inside; grant portals to forward
  files`, and the argument stays. Every other failure is soft the same way —
  a launch is never stopped by a file it could not hand over.
- `--dry-run`/`--explain` print `forward:`/`visible:` lines on stderr and
  register nothing. `bubbler exec` deliberately does not forward.

## Per-run shares

`--share PATH[=ro|rw]` on `run` and `try` binds one host path for that run
only. Read-write unless `=ro` says otherwise — the last `=ro`/`=rw` is the
mode, so a directory whose own name ends in one needs it spelled out
(`dir=ro=rw`). A relative path is taken from the current directory, with a `..`
resolved on the host first. A path under `$HOME` lands at the same relative
path under the private home, the way `home-share` maps its source; any other
path lands at the path it has on the host, the way `path-share` does — with the
type checks and the reserved roots of both, so your home itself, the instance
store and the profile layer are refused here as well. What does not carry over
is the default: those two nodes are read-only unless `mode=rw` says otherwise,
while a `--share` is read-write unless `=ro` does.

```
cd <project>
bubbler run cc --share . --share ~/notes.md=ro
```

- The first directory shared is the sandbox's working directory; with only
  files shared it stays `/home/bubbler`.
- Repeatable, and refused rather than guessed at: a path `config.kdl` already
  shares (`already shared by config.kdl`), the same path twice (`given twice`),
  two shares where one contains the other (`one share cannot contain another`).
- Nothing is written to `config.kdl`, so the file keeps saying what the
  instance is granted with no arguments.
- Refused on an instance that is already running — a share is one of the binds
  `bwrap` made at start and a live mount namespace takes no more, so exit it
  first (an instance ends when its command does). `--dry-run` and `--explain`
  describe a fresh sandbox either way, with the share under a
  `--share "<path>" mode=…` group of its own.
- A file argument under a `--share` is inside already: it is passed under the
  name the bind gives it rather than forwarded through the document portal.

## home-share

```kdl
home-share "Downloads"            // ~/Downloads at /home/bubbler/Downloads, read-only
home-share "Projects/x" mode=rw
```

- Source must exist; resolved before binding; a symlink pointing outside your
  home is refused.
- `mode=` is optional on the way in and always written on the way out: bubbler
  writes `home-share`, `path-share` and `app-runtime` back with `mode=ro` or
  `mode=rw` spelled out, so a share's width is read off the line.
- One path once, whatever the modes (`"D"` and `"D" mode=rw` together is an
  error). `"D"` beside `"D/sub"` is fine.
- Lint warns on `.ssh`, `.gnupg`, `.pki`, `.password-store`,
  `.local/share/keyrings`, `.mozilla`, and on `.config`, `.local`, `.cache` whole.

## path-share

```kdl
path-share "/kioxia/Steam"        // same path inside, read-only
path-share "/mnt/data" mode=rw
```

Binds a host path outside your home at that same path. Must be a directory or
regular file. Refused, naming the root: `/`, `/proc`, `/sys`, `/dev`, `/etc`,
`/usr`, `/opt`, `/home`, your home, `/tmp`, `/var`, `/run`, `$XDG_RUNTIME_DIR`,
the instance store (`~/.local/share/bubbler`), your profile layer
(`~/.config/bubbler`), `/home/bubbler` — being one, inside one, or containing
one, as written and as resolved. Carve-out: `/run/media`. `/mnt`, `/media`,
`/srv` and your own top-level mountpoints are allowed. One path once, whatever
the modes; two `path-share`s may not overlap.

Why so strict: a sandbox that can write another instance's `config.kdl` or a
profile grants itself anything on the next run.

## etc-share

```kdl
etc-share "vulkan"                // /etc/vulkan read-only; one path component
etc-share "OpenCL"                // needed for OpenCL; `nvidia` for NVIDIA app profiles
```

One entry once. Cannot name the account files (`passwd`, `group`, `shadow`, …),
which the sandbox generates. The baseline already binds the common entries — see
[Configuration](Configuration.md#baseline-every-sandbox).

## app-runtime

```kdl
app-runtime "org.keepassxc.KeePassXC" mode=rw   // the side that serves a socket
app-runtime "org.keepassxc.KeePassXC"           // a client; ro suffices for connect()
```

Shares `$XDG_RUNTIME_DIR/app/<id>` — the **same path on the host and in every
sandbox naming the id**, which is where applications already put their
sockets. bubbler creates the directory (refusing a planted symlink) and never
removes it. The id is an application id (`a.b`, `-` only in the last element);
repeatable, once per id.

What it does not give: peer authentication (`SO_PEERCRED` is useless across the
boundary — KeePassXC's own keys do that job), isolation between instances
naming the same id, Discord rich presence (those sockets live at the top of
`$XDG_RUNTIME_DIR`). Do not point `TMPDIR` at it.

### KeePassXC-Browser, both sides sandboxed

1. Grant the id on both sides — no shipped profile does, and both headers
   list the line to paste: `app-runtime "org.keepassxc.KeePassXC" mode=rw`
   with `lint-allow "app-runtime-rw"` in the KeePassXC instance
   (`bubbler edit kp`), the read-only line in the browser's
   (`bubbler edit ff`).
2. Put the native messaging manifest in the browser's private home:
   `~/.local/share/bubbler/instances/ff/home/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json`
   (Chromium: `…/home/.config/chromium/NativeMessagingHosts/`):

```json
{
    "allowed_extensions": ["keepassxc-browser@keepassxc.org"],
    "description": "KeePassXC integration with native messaging support",
    "name": "org.keepassxc.keepassxc_browser",
    "path": "/usr/bin/keepassxc-proxy",
    "type": "stdio"
}
```

If KeePassXC's own installer ran on the host, copy the file from
`~/.mozilla/native-messaging-hosts/`.
