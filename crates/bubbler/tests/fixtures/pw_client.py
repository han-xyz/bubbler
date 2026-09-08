# The security tokens the host's PipeWire daemon has attached to the
# clients of one bubbler instance, one line per client, in the order the
# Rust side asserts them. `pw-dump`'s output arrives on stdin and the
# instance name is the one argument; a client of another context, or of
# no context at all, is not printed.
import json
import sys

KEYS = (
    "pipewire.sec.engine",
    "pipewire.sec.app-id",
    "pipewire.sec.instance-id",
    "pipewire.access",
    "pipewire.access.effective",
    "bubbler.audio",
)

app = sys.argv[1]
for obj in json.load(sys.stdin):
    if obj.get("type") != "PipeWire:Interface:Client":
        continue
    props = obj.get("info", {}).get("props", {})
    if props.get("pipewire.sec.app-id") != app:
        continue
    print(" ".join(f"{key}={props.get(key)}" for key in KEYS))
