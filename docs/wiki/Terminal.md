# Terminal

## tty modes

```kdl
tty "pty"            // default
```

`--tty <mode>` on `run`, `exec`, `try` overrides the node.

| Mode | What the sandbox gets |
|---|---|
| `pty` | the slave of a pseudoterminal bubbler allocates and relays; job control, `/dev/tty`, `stty` work; your terminal is in raw mode meanwhile |
| `passthrough` | bubbler's own descriptors as they are — the sandbox holds your terminal and reaches it via `/dev/console` |
| `none` | stdin `/dev/null`, output back through pipes, nothing at `/dev/console` |

A non-terminal descriptor (pipe, redirect) passes through unchanged in any
mode. Every sandbox starts with `--new-session`; the seccomp filter denies
`TIOCSTI`/`TIOCLINUX`.

**Detach:** `^]` three times within a second. `run` stops relaying and keeps
waiting (then `^Z`, `bg`); `exec` exits and leaves the command with the
supervisor.

**What a relay cannot hide:** the app can read what you type into that
session and emit escape sequences your emulator parses (title, OSC 52
clipboard, queries). Do not type a password into a session you do not trust.

**After SIGKILL** your terminal may be left raw: `reset` or `stty sane`.

`tty` inside prints `/dev/console` (the pty is allocated on the host, so
`/dev/pts/N` paths do not resolve); programs wanting a real pts entry
(`script`, `sudo` tty tickets) need `passthrough`.

## bubbler-ui

```
bubbler ui            # or bubbler-ui
```

A separate binary (the only one linking a TUI toolkit): a list of instances,
then one instance's grants — every node it holds, every node it could, with
what each costs and what lint says about the buffer as edited. `!` marks a
grant wider than its name, `!!` one that reaches outside the sandbox.

Everything it does, it does by running `bubbler` — no second path into a
sandbox. `?` on any screen lists keys:

| Screen | Keys |
|---|---|
| instances | `Enter` grants, `r` run, `o` open, `x` exec, `t` try, `n` new, `d` delete, `R` reseed, `e` `$EDITOR`, `l` lint, `L` log, `D` desktop entry, `W` shim, `X` explain, `p` profiles, `^R` re-read |
| grants | `Space` grant/revoke, `Enter` edit the node as one line of KDL, `e` `$EDITOR`, `s` save, `u` undo, `l` lint, `X` explain, `Esc` back |
| profiles | `Enter` show flattened, `c` create instance, `e` edit your layer, `l` lint |
| viewer | `j`/`k` scroll, `f` every argument, `p` the proxy's argv |

`s` writes through the same path as `reseed`: header kept, `config.kdl.bak`
written first, **comments not kept**. `q` quits, `Esc` goes back, `^C` does
nothing while the editor is up.
