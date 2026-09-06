# Context

Terms this repo uses; synonyms to avoid in code, docs and commits.

## Glossary

- `render node` — `/dev/dri/renderD<N>`, the unprivileged GPU node; say "render node", not "GPU device".
- `primary node` — `/dev/dri/card<N>`; not "card device".
- `KMS` — kernel mode setting, the primary node's display control; the `dri kms=#true` property.
- `Flatpak policy` — what PipeWire/WirePlumber grant a client that carries `/.flatpak-info`: `rwx` without `m`, camera through the portal permission store.
- `security context` — a per-sandbox server socket a compositor or PipeWire labels; wl-proxy has one, PipeWire's is 0.23.
- `module loading` — pipewire-pulse `LOAD_MODULE`, gated only by `pulse.allow-module-loading`.
- `optional share` — `home-share`/`path-share` with `optional=#true`: skipped when the source is absent, `--explain` says so.
- `smoke test` — the opt-in live test per shipped profile in `crates/bubbler/tests/cli.rs`: window class seen or version line printed.
- `generated file` — a file bubbler writes for the sandbox (`/etc/passwd`, `/etc/group`, `/etc/resolv.conf`, `/.flatpak-info`), bound read-only.
