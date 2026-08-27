# Development

Repository: <https://github.com/han-xyz/bubbler>. Rust 1.95+, edition 2024.
Workspace crates: `bubbler-core` (library: config, profiles, bwrap argv,
services), `bubbler` (CLI), `bubbler-init` (in-sandbox supervisor),
`bubbler-ui` (terminal editor). Only `bubbler-ui` links a TUI toolkit.

## Build

```
cargo build --release
cargo build --release -p bubbler -p bubbler-init   # without the editor
```

Links `libseccomp.so` (the only C dependency; no bindgen). 64-bit targets
only: the KDL parser reserves 512 MiB of address space per read, which the
build refuses to promise a 32-bit one. Runtime:
`bwrap`, `xdg-dbus-proxy`, `pasta`, `nft` as the grants need them.

## Checks (all clean before every commit)

```
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo deny check        # needs the network; CI and releases
```

Run tests with `--workspace`: `-p bubbler` alone does not build
`bubbler-init`, and tests needing the real supervisor skip. Tests that need a
sandbox probe for one (create a userns, run a real `bwrap`, attach pasta) and
skip with a printed reason on a host that cannot — a green run says what it
did not cover. `crates/bubbler-core/tests/proptest.rs` holds the property
tests: emitter/parser round trip, desktop patch idempotence, include resolver
never recursing past the stack. With `$WAYLAND_DISPLAY` set the Wayland tests
run against your own compositor: they map a window and take the focus for a
moment, and they take the selection and give it back with one flavour on it —
its plainest text form, or its first content type where it had no text, so an
HTML selection comes back as text and an image-only one as the image.

## Fuzzing

`fuzz/` is a cargo-fuzz crate outside the workspace (nightly):

```
cargo install cargo-fuzz
cargo +nightly fuzz run config_parse fuzz/corpus/config_parse fuzz/seeds/config_parse -- -max_total_time=60
```

Targets: `config_parse`, `kdl_roundtrip`, `profile_resolve`, `desktop_patch`,
`init_wire`, `seccomp_names`, `wrap_registry`. Seeds are committed; the corpus
is not. Stable builds run the harnesses without coverage guidance — a smoke
test, not fuzzing.

## CI

`.github/workflows/ci.yml`, four jobs in `archlinux:latest`: `check` (the four
checks), `deny`, `msrv` (1.95), `sandbox-probe` (prints whether `unshare -Urn`
and `bwrap --unshare-all` work on the runner — hosted runners fail the bwrap
line under Docker's seccomp profile, so real-sandbox coverage needs a
self-hosted runner).

## Layout

| Path | Purpose |
|---|---|
| `crates/bubbler-core/src/bwrap.rs` | the only place bwrap flags are emitted; `ETC_ALLOWLIST` |
| `crates/bubbler-core/src/service.rs` | each grant node to bwrap arguments |
| `crates/bubbler-core/src/network.rs` | pasta argv and nft ruleset |
| `crates/bubbler-core/src/seccomp.rs` | `DEFAULT_EPERM`, `DEFAULT_ENOSYS`, filter compile |
| `crates/bubbler-core/src/dbus.rs` | proxy plan |
| `crates/bubbler-core/src/lint.rs` | every check id |
| `crates/bubbler-core/profiles/*.kdl` | built-in profiles |
| `docs/threat-model.md` | long-form threat model |
| `contrib/apparmor/` | untested AppArmor profile |

Packaging (AUR `bubbler`, `bubbler-git`) lives in repositories of its own;
not published yet while AUR registration is down.

## License

GPL-3.0-or-later.
