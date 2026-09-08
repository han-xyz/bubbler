# Context

Terms this repo uses; synonyms to avoid in code, docs and commits.

## Glossary

- `render node` — `/dev/dri/renderD<N>`, the unprivileged GPU node; say "render node", not "GPU device".
- `primary node` — `/dev/dri/card<N>`; not "card device".
- `KMS` — kernel mode setting, the primary node's display control; the `dri kms=#true` property.
- `Flatpak policy` — what PipeWire/WirePlumber grant a client that carries `/.flatpak-info`: `rwx` without `m`, camera through the portal permission store.
- `security context` — a per-sandbox server socket a compositor or PipeWire labels; wl-proxy has one, PipeWire's is 0.23.
- `module loading` — pipewire-pulse `LOAD_MODULE`, gated only by `pulse.allow-module-loading`.
- `permission manager` — a WirePlumber `access.permission-managers` entry the policy drop-in's `access.rules` matches a context into by its `bubbler.audio` value; not "access rule", which is the match rather than the grant it applies.
- `audio policy drop-in` — `contrib/wireplumber/50-bubbler.conf`, the WirePlumber config that scopes a bubbler context to its grant set; `bubbler audio-policy --print` hands out the copy embedded in the binary.
- `linking hook` — `contrib/wireplumber/scripts/bubbler/refuse-links.lua`, the second half of the policy: the drop-in loads it and it refuses the links a permission cannot, since a permission is about one object and a link is about two; `bubbler audio-policy --print --script` hands it out.
- `playback grant` — a bare `pipewire` or `pulseaudio`: `bubbler.audio = "playback"`; with the policy installed, sinks and the client's own objects stay visible, every `Audio/Source` is hidden and unlinkable, another client's stream is readable but not linkable, and no capture stream reaches a sink's monitor ports.
- `microphone grant` — the `microphone` child on `pipewire` or `pulseaudio`, ORed into one per-instance set across both nodes and every layer; `bubbler.audio = "playback,microphone"`, and every `Audio/Source` becomes visible and linkable.
- `context socket` — the PipeWire security context's own socket, named `pipewire-0` in the instance's runtime directory; `pw-container` creates it and bubbler moves it out of the sidecar's reach before checking and binding it, as it does the D-Bus proxy's.
- `holder` — `bubbler-init`'s `bubbler-pw-hold` mode: renames the context socket beside itself, reports its path over a pipe, then waits on a signal to keep the context alive until the sandbox exits.
- `optional share` — `home-share`/`path-share` with `optional=#true`: skipped when the source is absent, `--explain` says so.
- `smoke test` — the opt-in live test per shipped profile in `crates/bubbler/tests/cli.rs`: window class seen or version line printed.
- `generated file` — a file bubbler writes for the sandbox (`/etc/passwd`, `/etc/group`, `/etc/resolv.conf`, `/.flatpak-info`), bound read-only.
