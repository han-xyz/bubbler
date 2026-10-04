# Prints `label: verdict` per step, all on one connection. A step is `label name|unique path
# interface.member [string args]`, or `wait`: half a second of main loop, then the signals heard.
import sys

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
address, name, unique = sys.argv[1:4]
bus = dbus.bus.BusConnection(address)
ticks = []
bus.add_signal_receiver(lambda: ticks.append(1), signal_name="Tick")


def call(dest, path, method, args):
    iface, member = method.rsplit(".", 1)
    try:
        return str(bus.call_blocking(dest, path, iface, member, "s" * len(args), args, timeout=5))
    except dbus.exceptions.DBusException as e:
        return f"refused {e.get_dbus_name()}"


for step in sys.argv[4:]:
    if step == "wait":
        loop = GLib.MainLoop()
        GLib.timeout_add(500, loop.quit)
        loop.run()
        print(f"wait: {len(ticks)} signals", flush=True)
        continue
    label, target, path, method, *args = step.split(" ")
    dest = unique if target == "unique" else name
    print(f"{label}: {call(dest, path, method, args)}", flush=True)
