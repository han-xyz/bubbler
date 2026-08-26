# Desktop Entries and Shims

Three ways to start an instance without typing `bubbler run`:

| | What it writes | Starts |
|---|---|---|
| `bubbler desktop ff` | `~/.local/share/applications/bubbler-ff.desktop` | `bubbler open ff -- <app's Exec>` |
| `bubbler desktop ff --replace` | `~/.local/share/applications/firefox.desktop`, shadowing the system entry | same |
| `bubbler wrap ff` | `~/.local/bin/ff` symlink to bubbler | `bubbler open ff -- <command> <args>` |

## bubbler open

Execs into the instance when it runs, starts it when it does not — so a
second URL opens in the window already there. With no terminal on any of its
stdio (how a launcher starts things) it uses `tty "none"` and writes stderr
to `last-run.log` in the instance directory; `bubbler log ff` prints it,
control characters escaped.

## Desktop entries

```
bubbler desktop ff              # write the entry
bubbler desktop ff --replace    # under the application's own file name
bubbler desktop ff --print      # show it, write nothing
bubbler desktop ff --remove     # delete bubbler's entries for ff
bubbler desktop --refresh       # rewrite every entry bubbler wrote (after a move/upgrade)
```

bubbler copies the application's own `.desktop` and changes five things:
every `Name`/`Name[xx]` gains ` (Bubbler)`; every `Exec` (main and each
`[Desktop Action]`) becomes `bubbler open <inst> -- <original command line>`
with field codes (`%u`, `%F`, …) left where they were; `TryExec` names
bubbler; `DBusActivatable=false`; `X-Bubbler-Instance=<inst>` added.
Everything else is copied verbatim.

**Which entry:** the instance's `desktop "<name>.desktop"` node, else
`<command>.desktop`, else the one entry whose `Exec` runs `<command>`.
Searched in `$XDG_DATA_HOME/applications` then every `$XDG_DATA_DIRS/applications`
(Flatpak exports and Nix profiles included). `NoDisplay=true` entries are
skipped, `Hidden=true` refused, bubbler's own never a source. Two candidates is
an error listing both — add a `desktop` node.

**Safety:** bubbler never overwrites a file it did not write; an existing
file without this instance's `X-Bubbler-Instance` is refused. No `--force`,
no backups: deleting bubbler's entry brings the application's back.
`update-desktop-database` and `desktop-file-validate` run when installed.
`mimeapps.list` is never touched (`xdg-mime default …` is the way).

**Limits:**

- `%f`/`%F`/`%u`/`%U` expand to host paths, which `bubbler open` hands to the
  sandbox through the document portal (needs `portals`); a file already under a
  `home-share`/`path-share` is passed under the name it has inside. See
  [Sharing Files](Sharing-Files.md#file-arguments).
- Two URLs at once may race two `bubbler open`s to start the instance.
- `DBusActivatable=false` only closes activation for this entry; anything
  activating the app's bus name directly still starts the host copy.

## Shims

```
bubbler wrap ff                  # ~/.local/bin/ff
bubbler wrap ff --as firefox     # under the application's own name
bubbler wrap --list              # name, instance, path, ok|broken
bubbler unwrap ff
```

A shim is a symlink to the bubbler binary; bubbler reads `argv[0]`, looks it
up in `~/.config/bubbler/wraps.kdl`, and becomes `bubbler open`. No script, no
extra process. `ff https://example.com` opens the URL in the running sandbox.

- Default name is the **instance's**, so `firefox` still runs the real one.
  `--as firefox` intercepts more than what you type: most menu entries name a
  bare command on `PATH`, so the VS Code menu entry starts the shim too.
- `~/.local/bin` is not on Arch's default `PATH`; `wrap` says so.
- Refused: `bubbler`, `bwrap`, `xdg-dbus-proxy`, `pasta`, names outside the
  instance grammar, instances with no `command`, names another instance holds,
  any existing file that is not bubbler's own symlink.
- `broken` in `--list` = link gone, binary moved, instance deleted;
  `bubbler wrap <inst>` again fixes it. `delete` lists leftover shims rather
  than removing them.
- Footgun: wrapping an editor bubbler runs on the host (`$EDITOR`) makes
  `bubbler edit` open `config.kdl` inside a sandbox that cannot see it.
- `BUBBLER_WRAP_DRY_RUN=1` makes a shim print the command it resolved to.
