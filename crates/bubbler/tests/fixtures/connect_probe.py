# What a sandbox with `outbound "deny"` and an `allow-host` can and
# cannot do, one line per probe. Run inside the sandbox; the Rust side
# asserts on the six lines.
#
# The listed name is `localhost`, and the echo server this starts on the
# namespace's own loopback is what it resolves to. That is deliberate:
# `--map-host-loopback none` and `--map-guest-addr none` leave the
# sandbox no way to reach a listener on the host at all, and an
# unprivileged test cannot bind port 53 there to answer for a name of its
# own either. Reaching the echo therefore proves the proxy is inside the
# namespace, is reachable at the port bubbler put in the environment,
# resolves through the sandbox's own `/etc/hosts` (so it joined the mount
# namespace), matches the target against its allowlist and relays the
# bytes. What it does not prove is the cgroup accept rule, which needs a
# destination off this host: `egress ok` covers that where the argv names
# a routable name and this host is online.
import errno
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


def say(name, what):
    print("%s %s" % (name, what), flush=True)


def echo_listener():
    """Bound before anything is asked of the proxy, so the dial cannot
    race the bind. Answers on the namespace's own loopback, which is what
    `localhost` resolves to in here."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", ECHO_PORT))
    s.listen(8)
    return s


def echo_server(s):
    while True:
        c, _ = s.accept()
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

# 1. The listed name, on the listed port: the proxy answers 200 and the
#    bytes behind the blank line come back from the echo.
answer = connect_request("localhost:%d" % ECHO_PORT, body="ping", until="ping")
ok = "200" in status(answer) and answer.endswith("ping")
say("relay", "ok" if ok else "no: %r" % answer)

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
