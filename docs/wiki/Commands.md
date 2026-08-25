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
bubbler exec <inst> -- cmd...           run a command inside the running instance
bubbler open <inst> [-- cmd...]         exec if running, else run; what menu entries call
bubbler log <inst>                      what its last terminal-less run printed
bubbler try [--profile p] [--grant g]... -- cmd...   throwaway sandbox
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
- `edit` splits `$VISUAL`/`$EDITOR` on whitespace; no shell, no expansion.
- Instance names: `[A-Za-z0-9._-]`, not starting with `-`, not `try-<digits>`.
- Environment: `HOME` and `XDG_RUNTIME_DIR` must be set. `BUBBLER_PROFILE_DIR`
  replaces the system profile layer; `BUBBLER_DBUS_LOG=1` logs every filtered
  D-Bus message; `BUBBLER_SECCOMP_LOG=1` logs denied syscalls instead of
  denying them (for profile writing only).
