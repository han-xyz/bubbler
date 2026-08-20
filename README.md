# bubbler

Application sandboxing on top of [bubblewrap](https://github.com/containers/bubblewrap),
combining bubblejail's explicit instances and resource grants with a profile
library in the spirit of firejail. bubbler itself is unprivileged; `bwrap`
does the namespace work.

Status: milestone 1 — baseline sandbox with `wayland`, `x11`, `network`,
`home-share`. No seccomp, no D-Bus filtering, no desktop entries yet.

## Usage

    bubbler create firefox            # seeds from the built-in `generic` profile
    $EDITOR ~/.local/share/bubbler/instances/firefox/config.kdl
    bubbler run firefox               # uses `command` from config.kdl
    bubbler run firefox -- foot       # or run something else inside
    bubbler run firefox --dry-run     # print the bwrap argv, do not launch
    bubbler list

`--dry-run` prints `bwrap` and then one argv element per line, byte for byte,
so it can be diffed; an element containing a newline would be ambiguous in
that framing. A name starting with `-` must come after `--`
(`bubbler create -- -x`); `run` has no such escape, so avoid leading dashes.

## Config (KDL)

    wayland
    network
    home-share "Downloads"
    home-share "Projects/x" mode=rw
    command "firefox"

Every sandbox gets: all namespaces unshared, no network, read-only `/usr`
`/etc` `/opt`, empty `/tmp` `/var` `/run`, a private home at `/home/bubbler`,
and a cleared environment. Grants only add to that. `x11` binds the X socket
and remaps any Xauthority file to `/home/bubbler/.Xauthority`, but it stays a
compatibility grant: X11 offers no isolation between clients.

## Files

Instances live in `$XDG_DATA_HOME/bubbler/instances/<name>/` (by default under
`~/.local/share`), each holding a `config.kdl` and the private `home/`. Every
run also creates `$XDG_RUNTIME_DIR/bubbler/<name>/`, mode 0700. `HOME` and
`XDG_RUNTIME_DIR` must be set and non-empty.

## Build

    cargo build --release

Requires `bwrap` at runtime and a kernel with user namespaces.
