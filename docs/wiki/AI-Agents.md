# AI Agents

A coding agent reads and writes the project it is pointed at, runs commands in
it, and talks to its API. Inside bubbler it gets exactly that: the project, a
network, and a private home for its own state. The host's `~/.claude`, its ssh
agent, its keyring and the rest of its dotfiles are not there to read.

## Claude Code

```
bubbler create claude-code --profile claude-code   # once
cd <project>
bubbler run claude-code --share .
```

`--share .` binds the project for that run only — read-write, at the same
relative path under the private home when it is under `$HOME`, at its own path
otherwise — and the sandbox starts in it. Nothing is written to the instance's
`config.kdl`: the next run shares whatever it is started with. See
[Per-run shares](Sharing-Files.md#per-run-shares).

The first run asks for a login. There is no browser inside: choose to copy the
URL, open it on the host, and paste the code back. The credentials land in the
instance's own `~/.claude/.credentials.json`. Copying the host's file into
`~/.local/share/bubbler/instances/claude-code/home/.claude/` does the same
without the dialogue.

What the profile grants, the way `bubbler profile show claude-code` flattens
it:

```kdl
network
home-share ".local/bin/claude" mode=ro
home-share ".local/share/claude" mode=ro
env DISABLE_AUTOUPDATER="1"
userns "disable"
command "/home/bubbler/.local/bin/claude"
```

- `network` — the API, and every other host the agent chooses to fetch. Egress
  cannot be narrowed to the API by address: `outbound "deny"` filters addresses
  only, and the answers for those hosts change mid-run. See
  [Network](Network.md).
- The two shares are the native install: `~/.local/bin/claude` is a symlink
  into `~/.local/share/claude/versions/`, and both go in read-only with the
  link resolved on the host. Installed from a package (`/usr/bin/claude`)
  instead, drop them both and write `command "claude"`.
- `env DISABLE_AUTOUPDATER="1"` — the tree the updater writes to is read-only
  in there. Updating happens on the host.
- `userns "disable"` — one sandbox, and bubbler is it. Claude Code's own
  bubblewrap sandbox warns and is skipped; a Playwright or Chromium MCP server
  nests a namespace of its own and needs `userns "allow"` instead.

Deliberately absent: an ssh agent — `git` over SSH needs a key in the private
home — a keyring, the host's dotfiles, a display. The editor bridge (`/ide`)
listens on the host's loopback, which the sandbox's own network namespace does
not reach, so it finds nothing to connect to.

## Any other agent

`agent` is the same sandbox with no command in it:

```
bubbler create codex --profile agent
bubbler edit codex               # add the tool and the command
cd <project> && bubbler run codex --share .
```

Two lines make it a tool:

```kdl
home-share ".local/bin/<tool>" mode=ro
command "/home/bubbler/.local/bin/<tool>"
```

A tool installed under `/usr` needs no share at all — the baseline binds `/usr`
read-only — so its `command` is the bare name. Credentials belong in the
private home (`~/.config/<tool>` in there is the instance's own), not in a
share of the host's.

Codex, and inference servers such as vLLM or SGLang, have not been tested. A
server also wants `dri` for the GPU, a read-only share of the model cache, and
`network { allow-port <n> }` to publish its port on the host's loopback — see
[Devices](Devices.md) and [Network](Network.md).

## What the sandbox does not protect

The agent has the network and it has the project. Anything in the project — a
token in `.env`, a key in a script — can leave through the API or through any
command the agent runs. The boundary is around your account, not around what
the agent does with what you handed it. Keep secrets out of the share, or share
what it needs and no more:

```
bubbler run claude-code --share ./src --share ./config.toml=ro
```

`=ro` is read-only, and the first directory shared is where the command starts,
so `./src` above is the working directory inside as well.
