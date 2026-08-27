"""Read the Wayland selection the way an application does, and print how
many bytes came back.

Hand-rolled wire, so the sandbox this runs in needs nothing but python.
A client with no surface never gains keyboard focus, and a client without
keyboard focus is never sent `wl_data_device.selection` at all, so the
default is to map a window first — that is what makes the core clipboard
reachable from inside a sandbox, where the data-control protocols the
`--data-control` mode uses are hidden.

One line on stdout: the byte count, `NO_OFFER` when the selection never
arrived, `NO_KEY` when `--after-key` was waited out, `NO_MANAGER` when
`--data-control` found neither protocol, or `OLD_PYTHON` on an interpreter
below 3.9. Everything else is stderr, `retried: N` among it.

    wl_read.py [--no-window] [--after-key] [--data-control]
               [--mime=TYPE] [--timeout=SECONDS] [--title=NAME]
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

#: Side of the window mapped for focus, in pixels. Nothing is drawn in it.
SIDE = 64

#: `wl_shm` format 1, XRGB8888. Every compositor supports it, and unlike
#: ARGB8888 it needs no alpha channel filled in.
XRGB8888 = 1

#: Window title when `--title=` names none. A caller that means to send a
#: key into this window gives it one of its own: two windows of the same
#: name are two windows a compositor cannot tell apart.
TITLE = "bubbler-wl-read"

#: The data-control managers, newest first. Outside a sandbox one of them
#: is there; inside bubbler's security context both are hidden.
CONTROL_MANAGERS = ("ext_data_control_manager_v1", "zwlr_data_control_manager_v1")

#: Printed in place of a byte count where the interpreter is older than the
#: descriptor passing this needs (`socket.send_fds`, 3.9). The caller reads
#: it as a reason to skip rather than as a failed read.
OLD_PYTHON = "OLD_PYTHON"

#: How many times an empty read is tried again, and how long each of those
#: waits for the compositor to offer the selection afresh.
#:
#: An empty read has two causes that look identical from here: the gate
#: refused it, or the offer died because keyboard focus moved while this
#: window was mapped — a compositor sends the selection to the focused
#: client only, and a read on the offer it left behind is answered with
#: nothing at all. They are told apart by what follows: focus coming back
#: brings a fresh `wl_data_device.selection`, and a refusal brings nothing.
#: So the wait is short and bounded, and a refusal costs it once.
RETRIES, RETRY_PATIENCE = 2, 1.0

#: `xdg_toplevel.state.activated`: the window has keyboard focus.
ACTIVATED = 4


def string(text):
    """One length-prefixed, NUL-terminated, four-byte-padded wire string."""
    raw = text.encode() + b"\0"
    return struct.pack("<I", len(raw)) + raw + b"\0" * (-len(raw) % 4)


def take_string(body):
    """The wire string at the front of `body`, and what follows its padding."""
    size = struct.unpack("<I", body[:4])[0]
    return body[4 : 3 + size].decode(), body[4 + (size + 3) // 4 * 4 :]


class Client:
    """One connection: its object ids, and the events this program acts on."""

    def __init__(self, deadline):
        run = os.environ["XDG_RUNTIME_DIR"]
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(os.path.join(run, os.environ["WAYLAND_DISPLAY"]))
        self.deadline = deadline
        self.buf = b""
        self.last = REGISTRY
        self.globals = {}
        self.role = {REGISTRY: "registry"}
        self.offer = None
        self.mimes = []
        self.configured = False
        #: What the compositor said about keyboard focus, through the
        #: `activated` state of `xdg_toplevel.configure`: `never` while it
        #: has not given this window focus, `held` once it has, `lost` when
        #: a later configure took it away. A window a compositor never
        #: focused is never offered the selection, and one it took focus
        #: from mid-read gets an empty read — neither says anything about
        #: the proxy, so the tests read this line to tell them apart.
        self.focus = "never"
        self.pressed = False
        # Filled in by `data_device`: the two protocols spell the same
        # three messages at different opcodes.
        self.offer_event = 0
        self.selection_event = 0
        self.receive_request = 0
        self.send(DISPLAY, 1, struct.pack("<I", REGISTRY))

    def next_id(self):
        self.last += 1
        return self.last

    def send(self, oid, opcode, body=b"", fd=None):
        head = struct.pack("<II", oid, ((8 + len(body)) << 16) | opcode)
        if fd is None:
            self.sock.sendall(head + body)
        else:
            socket.send_fds(self.sock, [head + body], [fd])

    def message(self):
        """The next message, or None once the deadline has passed."""
        while True:
            if len(self.buf) >= 8:
                oid, head = struct.unpack("<II", self.buf[:8])
                size, opcode = head >> 16, head & 0xFFFF
                if size >= 8 and len(self.buf) >= size:
                    body, self.buf = self.buf[8:size], self.buf[size:]
                    return oid, opcode, body
            left = self.deadline - time.monotonic()
            if left <= 0 or not select.select([self.sock], [], [], left)[0]:
                return None
            # No ancillary buffer: the one event that carries a descriptor
            # here is `wl_keyboard.keymap`, which this program does not read.
            more = self.sock.recv(65536)
            if not more:
                sys.exit("the compositor closed the connection")
            self.buf += more

    def dispatch(self):
        """Handle one message. False when the deadline came first."""
        got = self.message()
        if got is None:
            return False
        oid, opcode, body = got
        if oid == DISPLAY and opcode == 0:
            obj, code = struct.unpack("<II", body[:8])
            why, _ = take_string(body[8:])
            sys.exit("wl_display.error(object %d, code %d): %s" % (obj, code, why))
        role = self.role.get(oid)
        if role == "registry" and opcode == 0:
            name = struct.unpack("<I", body[:4])[0]
            interface, rest = take_string(body[4:])
            self.globals[interface] = (name, struct.unpack("<I", rest[:4])[0])
        elif role == "callback" and opcode == 0:
            self.role[oid] = "done"
        elif role == "xdg_wm_base" and opcode == 0:
            self.send(oid, 3, body[:4])
        elif role == "xdg_surface" and opcode == 0:
            self.send(oid, 4, body[:4])
            self.configured = True
        elif role == "xdg_toplevel" and opcode == 0:
            count = struct.unpack("<I", body[8:12])[0] // 4
            states = struct.unpack(f"<{count}I", body[12 : 12 + count * 4])
            if ACTIVATED in states:
                self.focus = "held"
            elif self.focus == "held":
                self.focus = "lost"
        elif role == "device" and opcode == self.offer_event:
            self.role[struct.unpack("<I", body[:4])[0]] = "offer"
            self.mimes = []
        elif role == "device" and opcode == self.selection_event:
            self.offer = struct.unpack("<I", body[:4])[0] or None
        elif role == "offer" and opcode == 0:
            self.mimes.append(take_string(body)[0])
        elif role == "wl_keyboard" and opcode == 3:
            self.pressed = self.pressed or struct.unpack("<I", body[12:16])[0] == 1
        return True

    def until(self, ready):
        """Dispatch until `ready` holds. False when the deadline came first."""
        while not ready():
            if not self.dispatch():
                return False
        return True

    def roundtrip(self):
        """A `wl_display.sync`, waited out: everything the compositor had to
        say before it was asked is in hand when this returns."""
        done = self.next_id()
        self.role[done] = "callback"
        self.send(DISPLAY, 0, struct.pack("<I", done))
        if not self.until(lambda: self.role[done] == "done"):
            sys.exit("the compositor never answered a sync")

    def bind(self, interface, version=1):
        """Bind a global by name, at no more than the version offered."""
        name, offered = self.globals[interface]
        oid = self.next_id()
        self.send(
            REGISTRY,
            0,
            struct.pack("<I", name)
            + string(interface)
            + struct.pack("<II", min(version, offered), oid),
        )
        self.role[oid] = interface
        return oid

    def data_device(self, manager, offer_event, selection_event, receive_request):
        """This seat's data device, on whichever clipboard protocol.
        Hands back the seat, which is also what a keyboard comes from."""
        self.offer_event = offer_event
        self.selection_event = selection_event
        self.receive_request = receive_request
        seat = self.bind("wl_seat")
        manager = self.bind(manager)
        device = self.next_id()
        self.role[device] = "device"
        self.send(manager, 1, struct.pack("<II", device, seat))
        return seat

    def keyboard(self, seat):
        """This seat's keyboard, whose key events are what open the gate."""
        oid = self.next_id()
        self.role[oid] = "wl_keyboard"
        self.send(seat, 1, struct.pack("<I", oid))

    def buffer(self, shm):
        """A blank buffer in memory shared with the compositor. A surface
        with nothing attached is never mapped, and an unmapped window is
        never focused."""
        size = SIDE * SIDE * 4
        memory = os.memfd_create("bubbler-wl-read")
        os.ftruncate(memory, size)
        pool = self.next_id()
        self.send(shm, 0, struct.pack("<Ii", pool, size), fd=memory)
        os.close(memory)
        buffer = self.next_id()
        self.send(
            pool, 0, struct.pack("<IiiiiI", buffer, 0, SIDE, SIDE, SIDE * 4, XRGB8888)
        )
        return buffer

    def map_window(self, title):
        """Map a toplevel and wait for it to be on screen: the compositor
        offers the selection to the client it has given keyboard focus."""
        compositor = self.bind("wl_compositor")
        shm = self.bind("wl_shm")
        shell = self.bind("xdg_wm_base")
        surface = self.next_id()
        self.send(compositor, 0, struct.pack("<I", surface))
        xdg = self.next_id()
        self.role[xdg] = "xdg_surface"
        self.send(shell, 2, struct.pack("<II", xdg, surface))
        toplevel = self.next_id()
        self.role[toplevel] = "xdg_toplevel"
        self.send(xdg, 1, struct.pack("<I", toplevel))
        self.send(toplevel, 2, string(title))
        self.send(surface, 6)
        if not self.until(lambda: self.configured):
            sys.exit("the compositor never configured the window")
        self.send(surface, 1, struct.pack("<Iii", self.buffer(shm), 0, 0))
        self.send(surface, 2, struct.pack("<iiii", 0, 0, SIDE, SIDE))
        self.send(surface, 6)
        self.roundtrip()

    def fresh_offer(self, patience):
        """Wait for the compositor to offer the selection again, which is
        what it does when this window is given focus back. False once
        `patience` seconds have passed without one, so a read nothing will
        replace is not waited out to the deadline."""
        was, whole = self.offer, self.deadline
        self.deadline = min(whole, time.monotonic() + patience)
        try:
            return self.until(lambda: self.offer not in (None, was))
        finally:
            self.deadline = whole

    def read_selection(self, mime):
        """Ask for the offer over a pipe and count what arrives. A denied
        read is the write end closed with nothing written, which reads
        here as end of file: zero bytes."""
        read, write = os.pipe()
        self.send(self.offer, self.receive_request, string(mime), fd=write)
        os.close(write)
        self.roundtrip()
        total = 0
        while True:
            left = self.deadline - time.monotonic()
            if left <= 0 or not select.select([read], [], [], left)[0]:
                break
            chunk = os.read(read, 4096)
            if not chunk:
                break
            total += len(chunk)
        os.close(read)
        return total


def option(args, name, fallback):
    """The value of a `--name=value` argument, or `fallback`."""
    prefix = "--%s=" % name
    return next((a[len(prefix) :] for a in args if a.startswith(prefix)), fallback)


def main(args):
    if sys.version_info < (3, 9):
        print(OLD_PYTHON)
        return 0
    client = Client(time.monotonic() + float(option(args, "timeout", "5")))
    client.roundtrip()
    if "--data-control" in args:
        manager = next((m for m in CONTROL_MANAGERS if m in client.globals), None)
        if manager is None:
            print("NO_MANAGER")
            return 0
        client.data_device(manager, 0, 1, 0)
    else:
        seat = client.data_device("wl_data_device_manager", 0, 5, 1)
        # Only where a key is what this waits for. A keyboard nothing ever
        # reads still delivers `wl_keyboard.key` to the connection, and
        # that is what opens the gate — so a run meant to prove a read was
        # denied must not hold one, or a user typing anywhere near it
        # would arm the proxy on its behalf.
        if "--after-key" in args:
            client.keyboard(seat)
        if "--no-window" not in args:
            client.map_window(option(args, "title", TITLE))
    if not client.until(lambda: client.offer is not None):
        print("focus:", client.focus, file=sys.stderr, flush=True)
        print("NO_OFFER")
        return 0
    print("offered:", " ".join(client.mimes), file=sys.stderr, flush=True)
    if "--after-key" in args and not client.until(lambda: client.pressed):
        print("NO_KEY")
        return 0
    mime = option(args, "mime", "text/plain")
    read = client.read_selection(mime)
    retried = 0
    while read == 0 and retried < RETRIES and client.fresh_offer(RETRY_PATIENCE):
        retried += 1
        read = client.read_selection(mime)
    if retried:
        print("retried:", retried, file=sys.stderr, flush=True)
    print("focus:", client.focus, file=sys.stderr, flush=True)
    print(read)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
