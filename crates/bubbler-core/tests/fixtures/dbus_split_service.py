# Answers every method call, whatever the interface, so a refusal can only have come from the
# proxy in front of it. `Emit` also broadcasts `Tick` on the interface and path given.
import sys

import dbus
import dbus.lowlevel
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
address, name, signal_path, signal_iface = sys.argv[1:5]
bus = dbus.bus.BusConnection(address)


def answer(conn, msg):
    if not isinstance(msg, dbus.lowlevel.MethodCallMessage):
        return dbus.lowlevel.HANDLER_RESULT_NOT_YET_HANDLED
    reply = dbus.lowlevel.MethodReturnMessage(msg)
    reply.append("served")
    conn.send_message(reply)
    if msg.get_member() == "Emit":
        conn.send_message(dbus.lowlevel.SignalMessage(signal_path, signal_iface, "Tick"))
    return dbus.lowlevel.HANDLER_RESULT_HANDLED


bus.add_message_filter(answer)
bus.request_name(name)
print(bus.get_unique_name(), flush=True)
GLib.MainLoop().run()
