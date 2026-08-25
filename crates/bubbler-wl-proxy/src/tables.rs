//! What every Wayland message on the wire looks like: the argument kinds of
//! each request and event, generated at build time from the protocol XML the
//! `wayrs-protocols` and `wayrs-client` packages ship (see `build.rs`).
//!
//! The proxy trusts nothing else about a message. An interface that is not in
//! here cannot be parsed, and the policy layer hides it rather than guessing
//! its wire shape.

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

/// The wire kind of one argument, which is all the codec needs: how many
/// bytes it occupies and whether it carries a file descriptor or an object id.
///
/// `Int` and `Uint` differ only in how the value reads; both are four bytes,
/// and an argument the XML types as an enum is recorded as `Uint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// Signed 32-bit integer.
    Int,
    /// Unsigned 32-bit integer, including every enum argument.
    Uint,
    /// Signed 24.8 fixed-point number, four bytes.
    Fixed,
    /// Length-prefixed, NUL-terminated string, padded to four bytes.
    String,
    /// Object id, or 0 for a null object.
    Object,
    /// Id of the object this message creates.
    NewId,
    /// Length-prefixed byte array, padded to four bytes.
    Array,
    /// File descriptor: no bytes on the wire, one fd in the ancillary data.
    Fd,
}

/// One request or event of an interface. Its position in the interface's list
/// is its opcode.
#[derive(Debug)]
pub struct Message {
    /// Name as the protocol XML spells it, e.g. `receive`.
    pub name: &'static str,
    /// First interface version in which this message exists.
    pub since: u32,
    /// Whether the XML marks this message `type="destructor"`: the one
    /// that ends the object it is sent to.
    pub is_destructor: bool,
    /// Argument kinds in wire order; `wl_registry.bind` carries the interface
    /// name and version of its untyped `new_id` as the `String` and `Uint`
    /// ahead of it, exactly as libwayland encodes them.
    pub args: &'static [ArgKind],
    /// Interface of the object this message creates, when the XML names one.
    /// `None` both for messages that create nothing and for `wl_registry.bind`,
    /// whose interface is only known from the message itself.
    pub new_id_interface: Option<&'static str>,
}

/// One interface: its highest known version and every message the proxy can
/// decode for it.
#[derive(Debug)]
pub struct Interface {
    /// Name as it appears in `wl_registry.global`, e.g. `wl_data_offer`.
    pub name: &'static str,
    /// Highest version the tables describe. A global advertised above this is
    /// clamped, because a client bound higher could send opcodes past the end
    /// of these lists.
    pub version: u32,
    /// Requests, client to server, indexed by opcode.
    pub requests: &'static [Message],
    /// Events, server to client, indexed by opcode.
    pub events: &'static [Message],
}

impl Interface {
    /// The request with this opcode, or `None` when the sender used an opcode
    /// this interface does not have.
    pub fn request(&self, opcode: u16) -> Option<&'static Message> {
        self.requests.get(usize::from(opcode))
    }

    /// The event with this opcode, or `None` when the sender used an opcode
    /// this interface does not have.
    pub fn event(&self, opcode: u16) -> Option<&'static Message> {
        self.events.get(usize::from(opcode))
    }

    /// The message a sender on this side identified by `opcode`: a request
    /// from the client, an event from the server.
    pub fn message(&self, from_client: bool, opcode: u16) -> Option<&'static Message> {
        if from_client {
            self.request(opcode)
        } else {
            self.event(opcode)
        }
    }
}

/// The interface with this name, or `None` when the tables do not describe it
/// — which is the proxy's definition of "unknown", and reason enough to hide
/// a global rather than forward messages it cannot measure.
pub fn lookup(name: &str) -> Option<&'static Interface> {
    index_of(name).and_then(by_index)
}

/// Position of `name` in [`INTERFACES`], the form the object map stores.
pub fn index_of(name: &str) -> Option<usize> {
    INTERFACES
        .binary_search_by(|iface| iface.name.cmp(name))
        .ok()
}

/// The interface an index taken from [`index_of`] refers to.
pub fn by_index(index: usize) -> Option<&'static Interface> {
    INTERFACES.get(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_so_a_lookup_is_a_binary_search() {
        assert!(
            INTERFACES.len() > 100,
            "only {} interfaces",
            INTERFACES.len()
        );
        for pair in INTERFACES.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "{} then {}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn object_one_is_wl_display() {
        let display = by_index(WL_DISPLAY_INDEX).expect("wl_display is in the table");
        assert_eq!(display.name, "wl_display");
        assert_eq!(lookup("wl_display").map(|i| i.name), Some("wl_display"));
        assert_eq!(display.request(0).map(|m| m.name), Some("sync"));
        assert_eq!(display.request(1).map(|m| m.name), Some("get_registry"));
        assert_eq!(display.event(0).map(|m| m.name), Some("error"));
        assert_eq!(display.event(1).map(|m| m.name), Some("delete_id"));
        assert_eq!(display.request(2).map(|m| m.name), None);
    }

    #[test]
    fn one_interface_never_has_two_layouts() {
        let mut names: Vec<&str> = INTERFACES.iter().map(|iface| iface.name).collect();
        names.dedup();
        assert_eq!(
            names.len(),
            INTERFACES.len(),
            "an interface name appears twice"
        );
        // xdg-shell-unstable-v5 gives `xdg_surface` a different layout, so
        // that whole file is dropped rather than merged: the stable interface
        // stands, and the v5 shell global is not in the table to be bound.
        let surface = lookup("xdg_surface").expect("xdg_surface is in the table");
        assert_eq!(surface.request(1).map(|m| m.name), Some("get_toplevel"));
        assert!(lookup("xdg_shell").is_none());
    }

    #[test]
    fn a_typed_new_id_names_the_interface_it_creates() {
        let display = by_index(WL_DISPLAY_INDEX).expect("wl_display is in the table");
        let sync = display.request(0).expect("wl_display.sync");
        assert_eq!(sync.args, &[ArgKind::NewId]);
        assert_eq!(sync.new_id_interface, Some("wl_callback"));
    }

    #[test]
    fn wl_registry_bind_carries_its_interface_and_version_on_the_wire() {
        let registry = lookup("wl_registry").expect("wl_registry is in the table");
        let bind = registry.request(0).expect("wl_registry.bind");
        assert_eq!(bind.name, "bind");
        assert_eq!(
            bind.args,
            &[
                ArgKind::Uint,
                ArgKind::String,
                ArgKind::Uint,
                ArgKind::NewId
            ]
        );
        assert_eq!(bind.new_id_interface, None);
    }

    #[test]
    fn messages_carry_the_fds_the_xml_gives_them() {
        let shm = lookup("wl_shm").expect("wl_shm is in the table");
        let create_pool = shm.request(0).expect("wl_shm.create_pool");
        assert_eq!(
            create_pool
                .args
                .iter()
                .filter(|a| **a == ArgKind::Fd)
                .count(),
            1
        );
        let ctx = lookup("wp_security_context_manager_v1").expect("the security context manager");
        let listener = ctx.request(1).expect("create_listener");
        assert_eq!(listener.name, "create_listener");
        assert_eq!(
            listener.args.iter().filter(|a| **a == ArgKind::Fd).count(),
            2
        );
    }

    #[test]
    fn a_destructor_is_marked_and_nothing_else_is() {
        let offer = lookup("wl_data_offer").expect("wl_data_offer is in the table");
        let destroy = offer
            .requests
            .iter()
            .find(|m| m.name == "destroy")
            .expect("wl_data_offer.destroy");
        assert!(destroy.is_destructor);
        let receive = offer
            .requests
            .iter()
            .find(|m| m.name == "receive")
            .expect("wl_data_offer.receive");
        assert!(!receive.is_destructor);
        // An event may be a destructor too, and the tables say so; only a
        // request is acted on, in `Policy::apply`.
        let callback = lookup("wl_callback").expect("wl_callback is in the table");
        assert!(callback.event(0).is_some_and(|m| m.is_destructor));
    }

    #[test]
    fn a_since_version_survives_generation() {
        let seat = lookup("wl_seat").expect("wl_seat is in the table");
        let release = seat
            .requests
            .iter()
            .find(|m| m.name == "release")
            .expect("wl_seat.release");
        assert_eq!(release.since, 5);
    }

    #[test]
    fn an_interface_outside_the_table_has_no_entry() {
        assert!(lookup("hyprland_global_shortcuts_manager_v1").is_none());
        assert!(lookup("").is_none());
        assert!(by_index(INTERFACES.len()).is_none());
    }
}
