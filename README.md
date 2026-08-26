# bubbler

Application sandboxing on top of [bubblewrap](https://github.com/containers/bubblewrap),
with named instances, explicit resource grants, and a profile library for
common applications. bubbler itself is unprivileged; `bwrap` does the
namespace work.

Each application runs in an **instance**: a private home plus a short
`config.kdl` listing exactly what it is granted — a Wayland socket, the GPU,
one USB device, a directory of yours, a filtered D-Bus, a network namespace of
its own. Nothing is granted by default. Profiles seed that file for 14
applications and compose with `include`; `bubbler lint` says where a config
gives away more than it means to, and `--dry-run --explain` puts every bwrap
argument under the node that produced it.

**Documentation:** the [wiki](docs/wiki/Home.md) is the short form, one page per
topic; [`docs/manual.md`](docs/manual.md) is the long form with every
mechanism's rationale; [`docs/threat-model.md`](docs/threat-model.md) says what
each defends and what it does not. `bubbler man | man -l -` and
`bubbler man --config | man -l -` are the manual pages.

## Usage

    bubbler create ff --profile firefox   # seed config.kdl from a profile
    bubbler run ff                        # start it; exec into it if already running
    bubbler run ff --dry-run              # print the bwrap argv, launch nothing
    bubbler run ff --explain              # the same argv, grouped under its nodes
    bubbler exec ff -- firefox --version  # run inside the running instance
    bubbler open ff -- https://a          # hand a URL to the running one, or start it
    bubbler open ff -- firefox ~/x.pdf    # …or a host file, through the document portal
    bubbler edit ff                       # config.kdl in $EDITOR, then re-check it
    bubbler lint ff                       # grants wider than they mean?
    bubbler desktop ff                    # menu entry "Firefox (Bubbler)"
    bubbler wrap ff                       # ~/.local/bin/ff starts the sandbox
    bubbler try --profile firefox --grant network -- firefox --version
    bubbler ui                            # terminal editor for instances and grants
    bubbler list
    bubbler delete ff --yes

`create` with no `--profile` uses `generic`: the baseline and nothing else,
with commented examples to start from. Full list: [Commands](docs/wiki/Commands.md).

A host file named after the program in `run`, `try` or `open` is registered
with the document portal and handed in at `$XDG_RUNTIME_DIR/doc/<id>/<name>`
(read, and write where you can write it), so a desktop entry's `%u`/`%f` and
"open with" from a file manager reach the sandbox. Needs `portals`; without it
the argument is left alone and a warning names the gap, and a file already
under a share is passed under the name it has inside:
[Sharing Files](docs/wiki/Sharing-Files.md#file-arguments).

## Config

    // bubbler profile: firefox
    wayland                          // security-context socket, proxied; "host" for the session's
    dri
    pulseaudio                       // pulse/native; `pipewire` binds the native socket instead
    network                          // own namespace via pasta; "host" for the host's
    home-share "Downloads" mode=rw
    dbus                             // the session bus through a filtering sidecar
    portals
    command "firefox"

Every grant is one node; unknown nodes are errors; a share whose source is
missing is an error, never a weaker sandbox. A bare `wayland` puts
`bubbler-wl-proxy` in front of the compositor socket: it decodes every message,
refuses a bind of a global the sandbox was never offered, and forwards a
clipboard read only within a second of a key, button or touch of yours, so an
application cannot poll the selection in the background for whatever you copy
next (`wayland clipboard="open"` drops that gate and lint warns). The baseline
every sandbox gets: all namespaces unshared, no network, read-only `/usr`, an
`/etc` allowlist, a private home at `/home/bubbler`, a cleared environment,
`--new-session`, `--die-with-parent`, and a seccomp denylist covering x86_64
and i386.
Reference: [Configuration](docs/wiki/Configuration.md).

## Profiles

    alacritty  chromium  code  firefox  generic  keepassxc  kitty
    libreoffice  lutris  mpv  spotify  steam  thunderbird  vesktop

Each ships what its application needs to *run* and nothing else; everything it
can also be given — a tray icon, notifications, media keys, screen sharing, a
browser rendezvous — is written out in the profile's own header comment, as the
node to paste in and what it hands over.

Three layers — `~/.config/bubbler/profiles/`, `/usr/share/bubbler/profiles/`,
built-in — and `bubbler profile edit firefox` starts your layer as
`include "firefox"` so it extends the shipped one. What each grants and why:
[Profiles](docs/wiki/Profiles.md).

## Installing

Arch Linux: AUR packages (`bubbler`, `bubbler-git`) are prepared but not
published yet — AUR account registration is currently down. From source:

    cargo build --release --locked
    install -Dm755 target/release/bubbler      /usr/bin/bubbler
    install -Dm755 target/release/bubbler-init /usr/lib/bubbler/bubbler-init
    install -Dm755 target/release/bubbler-wl-proxy /usr/lib/bubbler/bubbler-wl-proxy
    install -Dm755 target/release/bubbler-ui   /usr/bin/bubbler-ui      # optional editor
    target/release/bubbler man          > /usr/share/man/man1/bubbler.1
    target/release/bubbler man --config > /usr/share/man/man5/bubbler-config.5

Build needs Rust 1.95+ and `libseccomp` (2.5.4+). Runtime: `bubblewrap` and a
kernel with user namespaces; `bubbler-wl-proxy` from the set above in front of
every sandboxed `wayland`, which is not optional — a run stops without it;
`xdg-dbus-proxy` for `dbus`/`system-bus`;
`passt` (pasta) for an isolated `network`; `nftables` for `outbound "deny"`;
`xdg-desktop-portal` with a backend for `portals` and `camera`;
`pcsclite` with `ccid` for `smartcard`, whose whole grant is that daemon's
socket;
`xorg-xwayland` for the X server a bare `x11` runs inside the sandbox;
`at-spi2-core` for `a11y`, and fcitx5 or IBus running for `input-method` to
reach anything.
See [Getting Started](docs/wiki/Getting-Started.md).

## What it is not

A boundary between your account and one application — not against root, not
against your other processes, and `x11 "host"` is no boundary at all (a bare
`x11` runs an X server of the sandbox's own instead). Grants are as wide as
their names suggest and sometimes wider (`gamepad` is every input device your
user can open; `pulseaudio` and `pipewire` are each the microphone as well as
playback, with no portal in front; a bare `usb` is raw I/O to every USB device
including one plugged in later, and `bubbler lint` says so; `compute` is every
AMD GPU through the one `/dev/kfd`; `smartcard` is every card `pcscd` has, at
the level of the APDUs it answers); the wiki's
[Devices](docs/wiki/Devices.md) and [Security](docs/wiki/Security.md) pages and
the threat model say exactly how wide. Known gaps are listed under
[Security](docs/wiki/Security.md#known-gaps).

## Development

    cargo fmt --all
    cargo clippy --all-targets -- -D warnings
    cargo test --workspace
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

Sandbox tests probe for a working `bwrap` and skip with a reason where there
is none. With `$WAYLAND_DISPLAY` set the Wayland tests run against your own
compositor: they map a window and take the focus for a moment, and they take
the selection and give it back with one flavour on it — its plainest text form,
or its first content type where it had no text, so an HTML selection comes back
as text and an image-only one as the image. `cargo deny check`, cargo-fuzz
targets under `fuzz/`, and the CI workflow are described under
[Development](docs/wiki/Development.md).

## Acknowledgements

Thanks to [bubblejail](https://github.com/igo95862/bubblejail) and
[firejail](https://github.com/netblue30/firejail) for the inspiration, and to
[bubblewrap](https://github.com/containers/bubblewrap) for doing the namespace
work.

## License

GPL-3.0-or-later. See `LICENSE`.
