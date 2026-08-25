"""Bind a Wayland global by a numeric name this connection was never
offered, and print what the other end said about it.

Keeping a global out of the registry is not on its own enough to keep a
client away from it: the numeric name belongs to the compositor and is the
same for every connection, so an application can ask for one it was never
shown. This is that attempt, made from wherever it is run.

One line on stdout: `refused: <text>` when a `wl_display.error` came back,
`bound` when the bind was accepted, or `silence` when neither happened
before the deadline. `--dump` instead lists what the registry did offer,
one `<number> <interface>` per line, which is how a caller learns a number
worth trying.

    wl_bind.py [--dump] [--interface=NAME] [--name=NUMBER] [--timeout=SECONDS]
"""

import os
import select
import socket
import struct
import sys
import time

#: Object ids fixed before either side has sent anything, and the one this
#: program gives the registry.
DISPLAY, REGISTRY = 1, 2

#: Id of the `wl_display.sync` that closes the registry listing.
LISTED = 3

#: Id the bind would create. Never a number a callback has held: an id the
#: compositor has only just released may not have reached the proxy yet.
BOUND = 4

#: Id of the `wl_display.sync` callback that follows the bind: its `done`
#: is what says the bind went through unremarked.
SYNC = 5

#: Interface asked for when none is named. It is in the proxy's tables and
#: on bubbler's denylist, and a compositor with a security context is not
#: expected to hand it to a sandboxed client either, so binding it is
#: binding something this connection was never offered.
DEFAULT_INTERFACE = "zwlr_data_control_manager_v1"


def string(text):
    """One length-prefixed, NUL-terminated, four-byte-padded wire string."""
    raw = text.encode() + b"\0"
    return struct.pack("<I", len(raw)) + raw + b"\0" * (-len(raw) % 4)


def take_string(body):
    """The wire string at the front of `body`, and what follows its padding."""
    size = struct.unpack("<I", body[:4])[0]
    return body[4 : 3 + size].decode(), body[4 + (size + 3) // 4 * 4 :]


def connect():
    """A connection with a registry on id 2 and a sync behind it."""
    run = os.environ["XDG_RUNTIME_DIR"]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(os.path.join(run, os.environ["WAYLAND_DISPLAY"]))
    return sock


def send(sock, oid, opcode, body):
    sock.sendall(struct.pack("<II", oid, ((8 + len(body)) << 16) | opcode) + body)


def messages(sock, deadline):
    """Every message that arrives before `deadline`, in order."""
    buf = b""
    while True:
        while len(buf) >= 8:
            oid, head = struct.unpack("<II", buf[:8])
            size, opcode = head >> 16, head & 0xFFFF
            if size < 8 or len(buf) < size:
                break
            yield oid, opcode, buf[8:size]
            buf = buf[size:]
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([sock], [], [], left)[0]:
            return
        more = sock.recv(65536)
        if not more:
            return
        buf += more


def registry(sock, deadline):
    """Every global this connection is offered, by numeric name. The
    compositor answers `get_registry` before the `sync` after it, which is
    what makes the listing complete."""
    send(sock, DISPLAY, 1, struct.pack("<I", REGISTRY))
    send(sock, DISPLAY, 0, struct.pack("<I", LISTED))
    offered = {}
    for oid, opcode, body in messages(sock, deadline):
        if oid == REGISTRY and opcode == 0:
            name = struct.unpack("<I", body[:4])[0]
            offered[name] = take_string(body[4:])[0]
        elif oid == LISTED:
            return offered
    sys.exit("the compositor never answered a sync")


def option(args, name, fallback):
    """The value of a `--name=value` argument, or `fallback`."""
    prefix = "--%s=" % name
    return next((a[len(prefix) :] for a in args if a.startswith(prefix)), fallback)


def main(args):
    deadline = time.monotonic() + float(option(args, "timeout", "5"))
    sock = connect()
    offered = registry(sock, deadline)
    if "--dump" in args:
        for name in sorted(offered):
            print(name, offered[name])
        return 0
    if not offered:
        sys.exit("the compositor offered this connection no globals at all")
    interface = option(args, "interface", DEFAULT_INTERFACE)
    # One past the largest name in hand is a name this connection was
    # certainly never offered, whether or not the compositor has a global
    # there for someone else.
    name = int(option(args, "name", str(max(offered) + 1)))
    print("binding %s as global name %d" % (interface, name), file=sys.stderr)
    body = struct.pack("<I", name) + string(interface) + struct.pack("<II", 1, BOUND)
    send(sock, REGISTRY, 0, body)
    send(sock, DISPLAY, 0, struct.pack("<I", SYNC))
    for oid, opcode, rest in messages(sock, deadline):
        if oid == DISPLAY and opcode == 0:
            print("refused:", take_string(rest[8:])[0])
            return 0
        if oid == SYNC:
            print("bound")
            return 0
    print("silence")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
