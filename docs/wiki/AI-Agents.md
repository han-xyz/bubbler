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
home-share ".local/bin/claude" mode=ro optional=#true
home-share ".local/share/claude" mode=ro optional=#true
env DISABLE_AUTOUPDATER="1"
userns "disable"
command "claude"
```

- `network` — the API, and every other host the agent chooses to fetch. Narrow
  it by name with `claude-code-strict` below; an address policy cannot do it,
  since the answers for those hosts change mid-run. See [Network](Network.md).
- The two optional shares adapt to the install layout: the native installer
  puts a symlink at `~/.local/bin/claude` into `~/.local/share/claude/versions/`,
  and npm global puts `/usr/bin/claude` on the PATH. Both resolve through the
  sandbox PATH (`/usr/bin` first); whichever is present on the host is used,
  and `bubbler try --profile claude-code --explain` shows which shares bound or
  `absent on this host, skipped`.
- `env DISABLE_AUTOUPDATER="1"` — the tree the updater writes to is read-only
  in there. Updating happens on the host.
- `userns "disable"` — one sandbox, and bubbler is it. Claude Code's own
  bubblewrap sandbox warns and is skipped; a Playwright or Chromium MCP server
  nests a namespace of its own and needs `userns "allow"` instead.

Deliberately absent: an ssh agent — `git` over SSH needs a key in the private
home — a keyring, the host's dotfiles, a display. The editor bridge (`/ide`)
listens on the host's loopback, which the sandbox's own network namespace does
not reach, so it finds nothing to connect to.

## Claude Code, egress filtered by name

`claude-code-strict` is the same profile with `allow-host` lines on it: the
sandbox reaches every host Anthropic's network access requirements table names
— save `formulae.brew.sh`, which is Homebrew's — over HTTPS, and no other name
at all.

```
bubbler create strict --profile claude-code-strict
cd <project>
bubbler run strict --share .
```

The `network` node and the `lint-allow` beside it are the whole difference;
pasting them over the bare `network` of a `claude-code` instance gets the same
sandbox:

```kdl
network {
    outbound "deny"
    // the API, the sign-in pages, and the OAuth exchange a login code goes
    // through; the API also answers WebFetch's domain safety check, and
    // claude.com is a target WebFetch is pre-approved for
    allow-host "api.anthropic.com"
    allow-host "claude.ai"
    allow-host "claude.com"
    allow-host "platform.claude.com"
    // claude.ai connectors (ENABLE_CLAUDEAI_MCP_SERVERS=false drops this)
    allow-host "mcp-proxy.anthropic.com"
    // releases and version checks, plugin executables, plugin metadata, and
    // the npm packages an `npx`-launched MCP server installs. The Google
    // storage host is shared hosting anyone may publish to, so listing it
    // names a host rather than a party: anything in the sandbox that reaches
    // it can put bytes in a bucket of its own. Drop that line if no plugin
    // here needs its metadata.
    allow-host "downloads.claude.ai"
    allow-host "storage.googleapis.com"
    allow-host "registry.npmjs.org"
    // Claude in Chrome, and Artifacts (CLAUDE_CODE_DISABLE_ARTIFACT=1
    // drops the second)
    allow-host "bridge.claudeusercontent.com"
    allow-host "*.frame.claudeusercontent.com"
    // the changelog `/release-notes` reads. Shared hosting as well — every
    // public repository on GitHub is under this one name — so it is a way
    // out as much as a source; drop it if the changelog can go unread.
    allow-host "raw.githubusercontent.com"
    // telemetry and error reports, on Datadog's us5 site
    allow-host "http-intake.logs.us5.datadoghq.com"
    allow-host "browser-intake-us5-datadoghq.com"
    // the documentation the tool looks things up in
    allow-host "code.claude.com"
}
lint-allow "outbound-deny" reason="the deny is the point of this profile: egress is filtered by name, through the proxy, rather than by address"
```

bubbler runs a CONNECT proxy in the sandbox's own network namespace and lets
only that process out; the tool is pointed at it with `HTTPS_PROXY` and the six
other variables the node sets. The proxy resolves each listed name with a DNS
client of its own, against the resolver bubbler names on its argv — the sandbox
answers no lookup of the proxy's, and cannot make a listed name point where it
likes. `/login` still works — the URL opens in a browser
on the host, and the code you paste back is exchanged with `claude.ai` and
`platform.claude.com`.

The comment over each group says what deleting it costs, which is how to prune:
no connectors, no Artifacts, no telemetry, no documentation lookups. To send no
telemetry rather than to allow it, delete that group and add
`env DISABLE_TELEMETRY="1"` and
`env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"` — and note that those two
names are one Datadog site's (`us5`), so a tenant on another site sends its
telemetry somewhere they do not cover.

The list is documentation, not measurement: nobody has yet run the tool through
this profile end to end, so a feature reaching a host the table does not name
fails here first. It fails as a refusal from the proxy, and that line goes to
bubbler's stderr — your terminal for a run started from one, as the commands
above are, and `bubbler log <name>` for a run with no terminal, which is how a
desktop entry or a shim starts one. The fix is one more `allow-host` line.

What stays filtered away whatever you keep:

- `WebFetch` of any URL off the list.
- An MCP server that reaches a service of its own — and `git`, `gh` or `curl`
  against a forge or a registry that is not named.
- Anything that speaks plain HTTP, or that ignores the proxy variables: the
  application has no DNS of its own under this node, so such a client fails at
  the name lookup rather than at the connection.

Two of the fourteen are not destination bounds, and the list is weaker than it
looks because of them: `storage.googleapis.com` and `raw.githubusercontent.com`
are shared hosting that anyone may publish under, so a listed name is not a
listed party and bytes can leave through either. They buy plugin metadata and
the changelog; delete their lines where neither is used.

It needs `passt` and `nftables` as any filtered network does, plus a cgroup2
subtree delegated to your user — a systemd user session has one. Without it the
run is refused, naming the requirement, rather than started unfiltered. The
mechanism is [Network](Network.md#egress-by-name-allow-host); what the proxy is
trusted with is [Security](Security.md#egress-proxy).

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

A tool a package installed needs no share at all — the baseline binds `/usr`
read-only, and `/opt` too wherever the host has one — so its `command` is the
bare name. Credentials belong in the private home (`~/.config/<tool>` in there
is the instance's own), not in a share of the host's.

Codex, and inference servers such as vLLM or SGLang, have not been tested. A
server also wants `dri` for the GPU, a read-only share of the model cache, and
`network { allow-port <n> }` to publish its port on the host's loopback — see
[Devices](Devices.md) and [Network](Network.md).

## What the sandbox does not protect

The agent has the network and it has the project. Anything in the project — a
token in `.env`, a key in a script — can leave through the API or through any
command the agent runs, and `allow-host` narrows the destinations without
changing that: the API itself is a way out, and the sandbox does not read what
goes through the tunnel. The boundary is around your account, not around what
the agent does with what you handed it. Keep secrets out of the share, or share
what it needs and no more:

```
bubbler run claude-code --share ./src --share ./config.toml=ro
```

`=ro` is read-only, and the first directory shared is where the command starts,
so `./src` above is the working directory inside as well.
