# Development

Repository: <https://github.com/han-xyz/bubbler>. Rust 1.95+, edition 2024.
Workspace crates: `bubbler-core` (library: config, profiles, bwrap argv,
services), `bubbler` (CLI), `bubbler-init` (in-sandbox supervisor),
`bubbler-wl-proxy` (the Wayland proxy), `bubbler-net-proxy` (the egress proxy),
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

`bubbler-wl-proxy` generates its protocol tables in `build.rs` from the
`wayrs-*` sources. `BUBBLER_WL_PROXY_TABLES=verbose cargo build -p
bubbler-wl-proxy` prints which copy of a clashing interface it kept and which
file it dropped whole — read them when bumping the `wayrs-*` versions;
otherwise the build is quiet.

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

## Profile smoke tests

`crates/bubbler/tests/cli.rs`'s `profile_smoke` module starts every shipped
profile for real and checks that it did what it should: a GUI profile's
window mapped on Hyprland, a CLI profile's command printed what was
documented. It measures a profile; it does not fix one that fails here.
Every test in it is `#[ignore]`d — `cargo test --workspace` never opens an
app on your desktop — so run one explicitly, by its whole name:

```
cargo test -p bubbler --test cli -- --ignored --exact profile_smoke::kitty_window_appears --test-threads=1
```

`--exact` is what holds that to one test. libtest ORs its filters, so a
profile name added to a `profile_smoke` filter widens the run to the whole
suite — Steam included — instead of narrowing it: `-- --ignored --list
profile_smoke kitty_window_appears` lists all 17. Drop `--exact` and the
name to ask for the whole suite on purpose; `--list` reads the names off,
GUI ones ending in `_window_appears` and the four command ones not.

Serial only: it starts real desktop apps one at a time against a session
with exactly one desktop to watch them on. It needs Hyprland (`hyprctl`) and
each app installed — either missing is a printed skip, not a failure, so a
host with neither reports nothing rather than a wall of red.

`steam` skips instead of running: `bubbler try` hands the client an empty
home, which makes every run its first, and a first run downloads the whole
client (496 MB) before anything starts. Point the test at an instance you
have already warmed up — created from the profile, started once, and left
installed — and it runs against that:

```
BUBBLER_SMOKE_STEAM_INSTANCE=<instance> cargo test -p bubbler --test cli -- --ignored --exact profile_smoke::steam_window_appears --test-threads=1
```

## Audio policy test bed

```
cargo test -p bubbler-core --test real_pipewire
```

A hermetic PipeWire/WirePlumber pair of its own: a private
`PIPEWIRE_RUNTIME_DIR` with a null sink and a null source, and a
WirePlumber loading the drop-in from a `wireplumber.conf.d` of the bed's
own, with `pw-container` run against that daemon. It measures the 0.23
audio policy — the two permission managers, the link permission a
playback context does not get, the fallback for a context the drop-in
does not recognise — and never reaches the session's own PipeWire or
WirePlumber to do it. Needs `pipewire`, `wireplumber`, `pw-container` and
`pw-dump`; each is checked and a missing one is a printed skip naming it,
not a failure. Every daemon and sidecar the bed forks dies with the
thread that forked it (`PR_SET_PDEATHSIG`), so a `kill -9` of the test
binary leaves no daemon and no directory behind either.

## Fuzzing

`fuzz/` is a cargo-fuzz crate outside the workspace (nightly):

```
cargo install cargo-fuzz
cargo +nightly fuzz run config_parse fuzz/corpus/config_parse fuzz/seeds/config_parse -- -max_total_time=60
```

Targets: `config_parse`, `kdl_roundtrip`, `profile_resolve`, `desktop_patch`,
`init_wire`, `seccomp_names`, `wrap_registry`, `net_proxy_request`. Seeds are
committed; the corpus is not. Stable builds run the harnesses without coverage guidance — a smoke
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
| `crates/bubbler-core/src/network.rs` | pasta argv, nft ruleset, `allow-host` and the egress proxy's argv |
| `crates/bubbler-core/src/cgroup.rs` | the `sandbox`/`proxy` cgroup leaves an `allow-host` run needs |
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
