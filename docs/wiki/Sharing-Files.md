# Sharing Files

The sandbox's home is `/home/bubbler`, a private directory under the instance.
Nothing of your real home is visible unless shared.

## home-share

```kdl
home-share "Downloads"            // ~/Downloads at /home/bubbler/Downloads, read-only
home-share "Projects/x" mode=rw
```

- Source must exist; resolved before binding; a symlink pointing outside your
  home is refused.
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
`/srv` and your own top-level mountpoints are allowed. Two `path-share`s may
not overlap.

Why so strict: a sandbox that can write another instance's `config.kdl` or a
profile grants itself anything on the next run.

## etc-share

```kdl
etc-share "vulkan"                // /etc/vulkan read-only; one path component
etc-share "OpenCL"                // needed for OpenCL; `nvidia` for NVIDIA app profiles
```

Cannot name the account files (`passwd`, `group`, `shadow`, …), which the
sandbox generates. The baseline already binds the common entries — see
[Configuration](Configuration#baseline-every-sandbox).

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

1. `keepassxc` already grants the id `mode=rw`; in the browser instance
   uncomment the `app-runtime "org.keepassxc.KeePassXC"` line (`bubbler edit ff`).
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
