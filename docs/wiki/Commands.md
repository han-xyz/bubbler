# Commands

```
bubbler create <inst> [--profile <p>]   seed config.kdl from a profile (default: generic)
bubbler list                            instances
bubbler delete <inst> --yes             instance and private home; irreversible
bubbler edit <inst>                     open config.kdl in $VISUAL/$EDITOR, re-check it
bubbler reseed <inst>                   re-flatten its profile into config.kdl, keep home/
bubbler lint <inst>                     check config.kdl for grants wider than it means

bubbler run <inst> [-- cmd...]          start it (or exec into it if already running)
bubbler run <inst> --dry-run            print the bwrap argv, launch nothing
bubbler run <inst> --explain            the same argv grouped under the node that made it
bubbler run <inst> --tty <mode>         pty | passthrough | none
bubbler run <inst> --share <p>[=ro|rw]  bind a host path for this run only
bubbler exec <inst> -- cmd...           run a command inside the running instance
bubbler open <inst> [-- cmd...]         exec if running, else run; what menu entries call
bubbler log <inst>                      what its last terminal-less run printed
bubbler try [--profile p] [--grant g]... [--share p]... -- cmd...   throwaway sandbox
bubbler try --keep <name> -- cmd...     keep it afterwards as an instance

bubbler profiles [--origin]             profile names (and which layer holds each)
bubbler profile show <p>                flattened, layer by layer
bubbler profile edit <p>                your copy of it
bubbler profile lint <p> | --all        lint one or every profile

bubbler desktop <inst> [--replace|--print|--remove]   menu entry
bubbler desktop --refresh               rewrite every entry bubbler wrote
bubbler wrap <inst> [--as <name>]       ~/.local/bin shim
bubbler wrap --list                     every shim, ok|broken
bubbler unwrap <inst>

bubbler ui                              terminal editor (bubbler-ui)
bubbler man [--config]                  bubbler(1) / bubbler-config(5) as roff on stdout
```

## Notes

- `run` on a running instance execs into it instead of starting a second
  sandbox. Config changes apply on the next start.
- `SIGINT`/`SIGTERM` to bubbler are forwarded once as `SIGTERM` to the
  supervisor inside, which gives the command five seconds before `SIGKILL`.
  bubbler returns the command's exit status.
- `try` grants are bare nodes only: `wayland x11 network dri pipewire pulseaudio
  dbus portals notify tray a11y input-method gamepad hidraw camera`. Bundles are
  checked as in a file (`--grant tray` needs `--grant dbus`, `--grant x11` needs
  `--grant wayland --grant dri` for the X server it starts inside).
- `run`, `try` and `open` hand host files named after the program to the
  sandbox through the document portal when `portals` is granted, and print a
  warning naming the gap when they cannot; `exec` does not. See
  [Sharing Files](Sharing-Files.md#file-arguments).
- `--share PATH[=ro|rw]` on `run` and `try` binds a host path for that run
  only: read-write unless `=ro`, at the same relative path under the private
  home when it is under `$HOME`, at its own path otherwise, with the checks and
  reserved roots of `home-share`/`path-share`. The first directory shared is
  the working directory inside. Refused on a running instance, and never
  written to `config.kdl`. See
  [Sharing Files](Sharing-Files.md#per-run-shares).
- `--proxy`, `--wl-proxy` and `--net-proxy` on `run` and `try` each render one
  sidecar's own argv instead of the sandbox's: the D-Bus proxy, the Wayland
  proxy, and the egress proxy an `allow-host` starts. Each needs `--explain`,
  and no two can be given together. See
  [Lint and Explain](Lint-and-Explain.md#--dry-run-and---explain).
- `edit` splits `$VISUAL`/`$EDITOR` on whitespace; no shell, no expansion.
- `ui` keys on the grants screen: `Space` grants a node, turns a granted one
  that carries an argument, a property or children into a `/-` line the file
  keeps, and grants a `/-` line back; `Delete` (`Backspace` too) removes the
  entry the row names; `Enter` writes it as one line of KDL, and the bare `○`
  row under a repeatable node's last entry adds another. `s` saves, `u` undoes.
  See [Terminal](Terminal.md#bubbler-ui) and
  [Configuration](Configuration.md#disabling-a-node).
- Instance names: `[A-Za-z0-9._-]`, not starting with `-`, not `try-<digits>`.
- Environment: `HOME` and `XDG_RUNTIME_DIR` must be set. `BUBBLER_PROFILE_DIR`
  replaces the system profile layer; `BUBBLER_DBUS_LOG=1` logs every filtered
  D-Bus message; `BUBBLER_SECCOMP_LOG=1` logs denied syscalls instead of
  denying them (for profile writing only). With `a11y`, `AT_SPI_BUS_ADDRESS`
  is where bubbler looks for the accessibility bus before it asks
  `org.a11y.Bus` itself, over its own session-bus client.
