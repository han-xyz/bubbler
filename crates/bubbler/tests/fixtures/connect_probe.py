# What a sandbox with `outbound "deny"` and an `allow-host` can and
# cannot do, one line per probe. Run inside the sandbox; the Rust side
# asserts on the lines below.
#
# Two of the probes are about where the proxy will *not* go. A listed
# name that resolves to the loopback inside this namespace is refused,
# because that loopback is the application's own and the proxy's own
# listener sits on it; and a name only this process can answer is
# refused, because the proxy carries its own DNS client rather than
# asking NSS in a mount namespace the application writes. The relay
# itself is proved by `egress`, which needs a destination off this host
# and so runs only where the argv names a routable name.
import errno
import json
import os
import socket
import sys
import threading

ECHO_PORT = int(sys.argv[1])
# What bubbler said the proxy listens on, which this checks the seven
# variables against rather than reading them and believing them.
PROXY_PORT = int(sys.argv[2])
# A name the config does not list, and one it does where the argv gives
# one: an off-namespace destination the proxy must dial through the tap.
UNLISTED = "unlisted.invalid"
ROUTABLE = sys.argv[3] if len(sys.argv) > 3 else ""
# A listed name no resolver on earth answers, which is the point: the
# only way it resolves is through the interposition below.
HIJACK = "hijack.invalid"
# Where `libnss_resolve.so.2` asks. Inside the sandbox `/run` is a tmpfs
# this process owns, and the host's `/etc/nsswitch.conf` names `resolve`
# ahead of `dns`, so a socket here answers every NSS lookup in the
# namespace.
VARLINK = "/run/systemd/resolve/io.systemd.Resolve"
# How many connections the echo took. The proxy must make none of them.
echoed = 0


def say(name, what):
    print("%s %s" % (name, what), flush=True)


def echo_listener():
    """Bound before anything is asked of the proxy, so a dial cannot race
    the bind. On every address this namespace has, so that a proxy taking
    either the loopback answer or the interposed one would reach it and
    say so."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", ECHO_PORT))
    s.listen(8)
    return s


def tap_address():
    """This namespace's own address on pasta's tap, found without
    sending anything: a connected UDP socket only picks the route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def varlink_listener():
    """The interposition a review measured. Returns None where the
    sandbox does not let this process bind the path at all, which is a
    weaker run of this probe and not a failure of it."""
    try:
        os.makedirs(os.path.dirname(VARLINK), exist_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(VARLINK)
        s.listen(8)
        return s
    except OSError:
        return None


def varlink_serve(s, address):
    while True:
        try:
            c, _ = s.accept()
        except OSError:
            return
        threading.Thread(target=varlink_one, args=(c, address), daemon=True).start()


def varlink_one(c, address):
    """Answer `io.systemd.Resolve.ResolveHostname` with an address of
    this process's choosing: the echo above, which a proxy that believed
    it would reach."""
    try:
        buf = b""
        while not buf.endswith(b"\0"):
            data = c.recv(4096)
            if not data:
                return
            buf += data
        call = json.loads(buf[:-1].decode())
        name = call.get("parameters", {}).get("name") or HIJACK
        octets = [int(o) for o in address.split(".")]
        c.sendall(
            json.dumps(
                {
                    "parameters": {
                        "addresses": [
                            {"ifindex": 1, "family": socket.AF_INET, "address": octets}
                        ],
                        "name": name,
                        "flags": 1,
                    }
                }
            ).encode()
            + b"\0"
        )
    except (OSError, ValueError):
        pass
    finally:
        c.close()


def echo_server(s):
    global echoed
    while True:
        c, _ = s.accept()
        echoed += 1
        threading.Thread(target=echo_one, args=(c,), daemon=True).start()


def echo_one(c):
    try:
        while True:
            data = c.recv(64)
            if not data:
                return
            c.sendall(data)
    except OSError:
        pass
    finally:
        c.close()


def proxy_address():
    """Where the seven variables say the proxy is. Read from the
    environment, not assumed: a probe that dialled the port it was told
    on the command line would pass with the variables set to anything."""
    url = os.environ.get("HTTPS_PROXY", "")
    host, _, port = url.rpartition("//")[2].partition(":")
    return host, int(port)


def connect_request(target, body="", until=None):
    """One CONNECT to the proxy, and whatever came back.

    `Host` is sent every time: RFC 9110 requires it and the proxy
    refuses a request without one, so leaving it out would test the
    parser rather than the policy. `until` reads on until the answer
    ends with it, which is how the relayed bytes are waited for: the
    `200` and the echo arrive in separate reads."""
    return request(
        "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s" % (target, target, body), until
    )


def request(text, until=None):
    host, port = proxy_address()
    s = socket.socket()
    s.settimeout(10)
    answer = ""
    try:
        s.connect((host, port))
        s.sendall(text.encode())
        while True:
            data = s.recv(256)
            if not data:
                break
            answer += data.decode("latin-1")
            if until is None or answer.endswith(until):
                break
        return answer
    except OSError as e:
        return "OSError %s" % errno.errorcode.get(e.errno, e.errno)
    finally:
        s.close()


def status(answer):
    return answer.split("\r\n", 1)[0]


threading.Thread(target=echo_server, args=(echo_listener(),), daemon=True).start()
TAP = tap_address()

# 1. A listed name that resolves to this namespace's loopback: the proxy
#    refuses to dial inward, so the echo waiting there is never reached.
answer = connect_request("localhost:%d" % ECHO_PORT, body="ping")
say("inward", "502" if "502" in status(answer) else "no: %r" % answer)

# 2. A name no `allow-host` covers, on the same port.
answer = connect_request("%s:%d" % (UNLISTED, ECHO_PORT))
say("unlisted", "403" if "403" in status(answer) else "no: %r" % answer)

# 3. Anything but CONNECT.
answer = request("GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
say("get", "405" if "405" in status(answer) else "no: %r" % answer)

# 4. Straight out, with no proxy in the way: the ruleset accepts the
#    proxy's cgroup and rejects everything else, and the application is
#    not in it. `1.1.1.1` is not dialled here — the reject is immediate
#    and needs nothing at the other end.
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

# 5. The application's own name resolution: the resolver rules carry the
#    cgroup match too, so a lookup that leaves this process gets nothing.
try:
    socket.getaddrinfo("one.one.one.one", 443)
    say("dns", "answered")
except OSError:
    say("dns", "none")

# 6. The seven variables, exactly as bubbler sets them.
url = "http://127.0.0.1:%d" % PROXY_PORT
want = {
    "HTTPS_PROXY": url,
    "HTTP_PROXY": url,
    "https_proxy": url,
    "http_proxy": url,
    "NO_PROXY": "localhost,127.0.0.1,::1",
    "no_proxy": "localhost,127.0.0.1,::1",
    "NODE_USE_ENV_PROXY": "1",
}
wrong = {k: os.environ.get(k) for k, v in want.items() if os.environ.get(k) != v}
say("env", "ok" if not wrong else "no: %r" % wrong)

# 7. Only where the caller named a routable host and this host is
#    online: the proxy resolves it (the gated resolver rules let it) and
#    reaches it (the cgroup accept rule lets it), neither of which the
#    application beside it could do.
if ROUTABLE:
    answer = connect_request("%s:443" % ROUTABLE)
    say("egress", "ok" if "200" in status(answer) else "no: %r" % answer)

# 8. The interposition: this process answers NSS for a name no resolver
#    has, and then asks the proxy for it. A proxy that resolved through
#    `getaddrinfo` would be told the echo's address and would answer
#    `200`; one with its own DNS client gets no such name and answers
#    `502`. `nss` says whether the interposition was live at all, which
#    is what makes the proxy's answer worth reading.
# Bound only now, and not before: while it is up this process answers
# every NSS lookup in the namespace, its own included, and probe 5 above
# is about the lookups that leave the sandbox.
varlink = varlink_listener()
if varlink is None:
    say("nss", "unavailable")
else:
    threading.Thread(target=varlink_serve, args=(varlink, TAP), daemon=True).start()
    try:
        socket.getaddrinfo(HIJACK, ECHO_PORT, socket.AF_INET)
        say("nss", "live")
    except OSError:
        say("nss", "inert")
answer = connect_request("%s:%d" % (HIJACK, ECHO_PORT), body="ping")
say("hijack", "502" if "502" in status(answer) else "no: %r" % answer)

# 9. Nothing above reached the echo: the two refusals are refusals, not
#    a relay that happened to fail late.
say("echoed", str(echoed))
