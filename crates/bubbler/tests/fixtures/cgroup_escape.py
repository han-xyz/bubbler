# The escape a review measured against the first version of this feature,
# run from inside the sandbox: make a user, cgroup and mount namespace,
# mount cgroup2 (which is rooted at the sandbox's cgroup-namespace root),
# look for the egress proxy's cgroup, join it, and see whether the
# ruleset lets the process out.
#
# Run under `unshare --user --map-root-user --cgroup --mount`, which is
# what a sandbox with the default `userns "allow"` can do for itself.
# One line per step; the Rust side asserts them.
import ctypes
import errno
import os
import socket

MOUNTPOINT = "/tmp/cg"


def say(name, what):
    print("%s %s" % (name, what), flush=True)


def own_cgroup():
    for line in open("/proc/self/cgroup"):
        if line.startswith("0::"):
            return line[3:].strip()
    return "?"


def mount_cgroup2():
    os.makedirs(MOUNTPOINT, exist_ok=True)
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ok = libc.mount(b"none", MOUNTPOINT.encode(), b"cgroup2", 0, None)
    if ok != 0:
        return errno.errorcode.get(ctypes.get_errno(), ctypes.get_errno())
    return None


def join(path):
    """Write our pid into a cgroup, which is how a process moves itself."""
    try:
        with open(os.path.join(path, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))
        return None
    except OSError as e:
        return errno.errorcode.get(e.errno, e.errno)


refused = mount_cgroup2()
if refused:
    # `userns "disable"` closes the escape this way instead, and that is
    # a pass as much as an empty mount is.
    say("mount", "refused %s" % refused)
    say("visible", "0")
    say("join", "no target")
else:
    say("mount", "ok")
    # Everything the mount shows: with the proxy's cgroup outside the
    # sandbox's cgroup-namespace root there is nothing of bubbler's here.
    targets = sorted(
        d
        for d in os.listdir(MOUNTPOINT)
        if d.startswith("bubbler-") and os.path.isdir(os.path.join(MOUNTPOINT, d))
    )
    say("visible", "%d %s" % (len(targets), " ".join(targets)))
    # Try every cgroup under the root anyway, proxy leaf first: a mount
    # that shows nothing of bubbler's is the point, and a join that
    # somehow worked would show up here.
    attempts = []
    for d in targets:
        attempts.append(os.path.join(MOUNTPOINT, d, "proxy"))
        attempts.append(os.path.join(MOUNTPOINT, d))
    # `..` is not a way out of a mount either, but it costs one line to
    # be sure the root really is the boundary.
    attempts.append(os.path.join(MOUNTPOINT, "..", "proxy"))
    joined = [p for p in attempts if join(p) is None]
    say("join", "ok %s" % joined[0] if joined else "refused")

say("cgroup", own_cgroup())

# The two probes the escape was worth making for.
s = socket.socket()
s.settimeout(5)
try:
    s.connect(("1.1.1.1", 443))
    say("direct", "reached")
except socket.timeout:
    say("direct", "timeout")
except OSError as e:
    say("direct", "refused %s" % errno.errorcode.get(e.errno, e.errno))
finally:
    s.close()

try:
    socket.getaddrinfo("one.one.one.one", 443)
    say("dns", "answered")
except OSError:
    say("dns", "none")
