# bubbler

Application sandboxing on top of [bubblewrap](https://github.com/containers/bubblewrap).
Each application runs in a **named instance** with its own private home and a
short `config.kdl` that lists exactly what it is granted. bubbler is
unprivileged; `bwrap` does the namespace work.

```
bubbler create ff --profile firefox   # make an instance from a profile
bubbler run ff                        # start it
bubbler desktop ff                    # add a menu entry that starts it
```

## Pages

| Page | What it covers |
|---|---|
| [Getting Started](Getting-Started.md) | Install, dependencies, first instance |
| [Commands](Commands.md) | Every subcommand, one line each |
| [Configuration](Configuration.md) | `config.kdl`: every node and what it grants |
| [Profiles](Profiles.md) | The 17 built-in profiles, layers, `include`, your own |
| [AI Agents](AI-Agents.md) | Claude Code and other coding agents: the profiles, `--share`, what is not protected |
| [Sharing Files](Sharing-Files.md) | File arguments through the document portal; `home-share`, `path-share`, `etc-share`, `app-runtime` |
| [Devices](Devices.md) | GPU, audio, gamepad, hidraw, camera |
| [Network](Network.md) | Isolated namespace via pasta, inbound ports, outbound filtering by address and by name |
| [D-Bus](D-Bus.md) | Session, system and accessibility bus through `xdg-dbus-proxy`, portals, tray, input methods |
| [Desktop Entries and Shims](Desktop-Entries-and-Shims.md) | `bubbler desktop`, `bubbler wrap`, `bubbler open` |
| [Terminal](Terminal.md) | `tty` modes, detaching, the `bubbler-ui` editor |
| [Lint and Explain](Lint-and-Explain.md) | `bubbler lint`, `lint-allow`, `--dry-run --explain` |
| [Security](Security.md) | Baseline, seccomp, user namespaces, threat model, known gaps |
| [Development](Development.md) | Build, checks, fuzzing, CI |

## Where things live

| Path | Holds |
|---|---|
| `~/.local/share/bubbler/instances/<name>/` | `config.kdl`, private `home/`, `last-run.log` |
| `~/.config/bubbler/profiles/<name>.kdl` | your profile layer |
| `/usr/share/bubbler/profiles/<name>.kdl` | the system's profile layer (empty by default) |
| `~/.config/bubbler/wraps.kdl` | shim registry |
| `$XDG_RUNTIME_DIR/bubbler/<name>/` | control socket and proxy sockets of a running instance |

Full reference: `bubbler man | man -l -` and `bubbler man --config | man -l -`.
