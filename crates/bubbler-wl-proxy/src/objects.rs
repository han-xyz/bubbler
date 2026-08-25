//! What each object id on one connection is: the interface the proxy must use
//! to decode the next message for it, and the version it was created with.
//!
//! Two rules here are load-bearing rather than tidy. An id is dropped only
//! when the server sends `wl_display.delete_id`, never when the client asks
//! for the object to be destroyed — events for a destroyed object can still be
//! in flight, and a proxy that forgot the id would fail to decode them and
//! kill the connection. And the map is capped, because its size is otherwise
//! chosen by the client on the other side.
//!
//! `wl_display.delete_id` names client ids only, so an id from the server's
//! range leaves the map only when the server reuses it. The relay must not
//! wait for such an id to disappear, and the live cap does not count
//! server-range zombies: how many there are is the compositor's decision.
//! It is the client's doing that they exist at all, though — every server
//! object answers a request the client made — so those zombies have a cap of
//! their own, and the map is bounded either way.

use std::collections::hash_map::Entry as MapEntry;
use std::collections::{HashMap, HashSet};

use crate::tables::{self, Interface, WL_DISPLAY_INDEX};
use crate::wire::Arg;

/// First object id the server allocates. Everything below it is the client's
/// to allocate, sequentially, starting at 1. An id at or above it is released
/// by the server reusing it, never by `wl_display.delete_id`.
pub const SERVER_ID_BASE: u32 = 0xFF00_0000;

/// Most objects one connection may have mapped at once, counting every client
/// id and every live server id. A client picks its own ids, so without a cap
/// it also picks how much memory the proxy spends on it.
///
/// Server-range zombies are counted separately against the same number, since
/// only the compositor decides when it reuses one of its ids; the map
/// therefore holds at most twice this many entries.
pub const MAX_OBJECTS: usize = 1 << 16;

/// Why an id could not be recorded. Each one means the connection has stopped
/// making sense, which is a reason to close it rather than to guess on.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObjectError {
    /// The client used an id outside the range it may allocate from.
    #[error("object id {0} is not in the client range 1..{SERVER_ID_BASE:#x}")]
    NotClientId(u32),
    /// The server used an id outside the range it may allocate from.
    #[error("object id {0} is not in the server range {SERVER_ID_BASE:#x}..")]
    NotServerId(u32),
    /// The client reused an id before `wl_display.delete_id` released it.
    #[error("object {0} is still mapped")]
    InUse(u32),
    /// A message arrived for an id no object is mapped to.
    #[error("object {0} is not mapped")]
    Unmapped(u32),
    /// The message creates an object whose interface is only named on the
    /// wire; `wl_registry.bind` is the one such message, and it has its own
    /// path through [`Objects::bind`].
    #[error("the interface of this new object is only known from the message itself")]
    UntypedNewId,
    /// The sender used an opcode the object's interface does not have, which
    /// means the proxy cannot know the message's shape.
    #[error("{0} has no message with opcode {1} on this side")]
    NoSuchMessage(&'static str, u16),
    /// The interface index does not name an entry of the generated tables.
    #[error("interface {0} is not in the tables")]
    UnknownInterface(usize),
    /// The tables name an interface for this new object but do not describe
    /// it, which means the generated tables are inconsistent.
    #[error("the tables do not describe interface {0}")]
    MissingInterface(&'static str),
    /// The global was kept out of the registry, so binding it is refused.
    #[error("global {0} is hidden from this connection")]
    HiddenGlobal(u32),
    /// The cap on mapped objects is reached.
    #[error("more than {MAX_OBJECTS} objects are mapped, or as many are dead server ids")]
    TooManyObjects,
}

/// What one id is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Index of the interface in [`tables::INTERFACES`].
    pub interface: usize,
    /// Version the object was created with, never above the version the
    /// tables describe: a higher one would have opcodes past the end of
    /// the message lists here.
    pub version: u32,
    /// The client asked for this object to be destroyed. The id stays
    /// resolvable until `wl_display.delete_id` releases it.
    pub zombie: bool,
}

/// The object ids of one connection, plus the globals it may not bind.
#[derive(Debug)]
pub struct Objects {
    map: HashMap<u32, Entry>,
    hidden_globals: HashSet<u32>,
    /// Destroyed objects in the server's range, which the cap does not count.
    server_zombies: usize,
}

impl Default for Objects {
    fn default() -> Self {
        Self::new()
    }
}

impl Objects {
    /// A fresh connection: object id 1 is `wl_display`, which is true before
    /// either side has sent anything.
    pub fn new() -> Self {
        // Not through `record`: id 1 is not allocated by either side, it is
        // the one object both ends agree on before any message.
        let display = Entry {
            interface: WL_DISPLAY_INDEX,
            version: 1,
            zombie: false,
        };
        Self {
            map: HashMap::from([(1, display)]),
            hidden_globals: HashSet::new(),
            server_zombies: 0,
        }
    }

    /// Map `id`, checking the range its sender may allocate from and the cap.
    fn record(
        &mut self,
        from_client: bool,
        id: u32,
        interface: usize,
        version: u32,
    ) -> Result<(), ObjectError> {
        if from_client && (id == 0 || id >= SERVER_ID_BASE) {
            return Err(ObjectError::NotClientId(id));
        }
        if !from_client && id < SERVER_ID_BASE {
            return Err(ObjectError::NotServerId(id));
        }
        let max = tables::by_index(interface)
            .ok_or(ObjectError::UnknownInterface(interface))?
            .version;
        let entry = Entry {
            interface,
            version: version.min(max),
            zombie: false,
        };
        let live = self.live();
        match self.map.entry(id) {
            // The server reuses an id of its own as soon as it drops the
            // object; the client has to wait for `wl_display.delete_id`.
            MapEntry::Occupied(_) if from_client => Err(ObjectError::InUse(id)),
            MapEntry::Occupied(mut slot) => {
                if slot.get().zombie {
                    self.server_zombies -= 1;
                }
                slot.insert(entry);
                Ok(())
            }
            MapEntry::Vacant(_) if live >= MAX_OBJECTS || self.server_zombies >= MAX_OBJECTS => {
                Err(ObjectError::TooManyObjects)
            }
            MapEntry::Vacant(slot) => {
                slot.insert(entry);
                Ok(())
            }
        }
    }

    /// What id `id` is bound to, zombie or not.
    pub fn get(&self, id: u32) -> Option<Entry> {
        self.map.get(&id).copied()
    }

    /// The interface to decode the next message for `id` with.
    pub fn interface(&self, id: u32) -> Option<&'static Interface> {
        self.get(id)
            .and_then(|entry| tables::by_index(entry.interface))
    }

    /// How many ids are mapped, zombies included. This is not what the cap
    /// counts: [`MAX_OBJECTS`] bounds the live objects (every client id plus
    /// every server id that is not a zombie) and, separately, the server-range
    /// zombies, so this can reach twice that.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no id at all is mapped, which a live connection never is.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// How many ids count against [`MAX_OBJECTS`]: every client id plus
    /// every server id the client has not destroyed.
    pub fn live(&self) -> usize {
        self.map.len() - self.server_zombies
    }

    /// Record the object `wl_registry.bind` creates.
    ///
    /// Refuses a global that was hidden from this connection: dropping the
    /// advertisement is not enough, since the client can name the global by
    /// its number without ever having seen it. The recorded version is capped
    /// at the version the tables describe.
    pub fn bind(
        &mut self,
        name: u32,
        interface: usize,
        version: u32,
        new_id: u32,
    ) -> Result<(), ObjectError> {
        if self.hidden_globals.contains(&name) {
            return Err(ObjectError::HiddenGlobal(name));
        }
        self.record(true, new_id, interface, version)
    }

    /// Record the object a message creates, if it creates one, and return its
    /// id. The new object inherits its parent's version, capped at the
    /// version the tables describe for its own interface.
    ///
    /// `from_client` is the side that sent the message: it picks the request
    /// or the event list `opcode` indexes, and the id range the new id must
    /// come from.
    pub fn new_id_from(
        &mut self,
        from_client: bool,
        parent: u32,
        opcode: u16,
        args: &[Arg],
    ) -> Result<Option<u32>, ObjectError> {
        let entry = self.get(parent).ok_or(ObjectError::Unmapped(parent))?;
        let iface = tables::by_index(entry.interface)
            .ok_or(ObjectError::UnknownInterface(entry.interface))?;
        let msg = iface
            .message(from_client, opcode)
            .ok_or(ObjectError::NoSuchMessage(iface.name, opcode))?;
        let new_id = args.iter().find_map(|arg| match arg {
            Arg::NewId(id) => Some(*id),
            _ => None,
        });
        let Some(new_id) = new_id else {
            return Ok(None);
        };
        let Some(name) = msg.new_id_interface else {
            return Err(ObjectError::UntypedNewId);
        };
        let interface = tables::index_of(name).ok_or(ObjectError::MissingInterface(name))?;
        self.record(from_client, new_id, interface, entry.version)?;
        Ok(Some(new_id))
    }

    /// Mark `id` destroyed by its client. It stays mapped, and messages for it
    /// keep decoding, until the server releases the id.
    pub fn destroy(&mut self, id: u32) -> bool {
        match self.map.get_mut(&id) {
            Some(entry) => {
                if !entry.zombie && id >= SERVER_ID_BASE {
                    self.server_zombies += 1;
                }
                entry.zombie = true;
                true
            }
            None => false,
        }
    }

    /// Release `id` on `wl_display.delete_id`: the only place an id is
    /// dropped, and the point from which the client may reuse it.
    pub fn delete_id(&mut self, id: u32) -> bool {
        match self.map.remove(&id) {
            Some(entry) => {
                if entry.zombie && id >= SERVER_ID_BASE {
                    self.server_zombies -= 1;
                }
                true
            }
            None => false,
        }
    }

    /// Keep global `name` from being bound, because its advertisement was not
    /// forwarded.
    pub fn hide_global(&mut self, name: u32) {
        self.hidden_globals.insert(name);
    }

    /// Whether global `name` was kept out of this connection's registry.
    pub fn is_hidden(&self, name: u32) -> bool {
        self.hidden_globals.contains(&name)
    }

    /// How many globals were kept out of this connection's registry.
    pub fn hidden_count(&self) -> usize {
        self.hidden_globals.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(name: &str) -> usize {
        tables::index_of(name).unwrap_or_else(|| panic!("{name} is in the tables"))
    }

    fn opcode(interface: &str, from_client: bool, name: &str) -> u16 {
        let iface =
            tables::lookup(interface).unwrap_or_else(|| panic!("{interface} is in the tables"));
        let list = if from_client {
            iface.requests
        } else {
            iface.events
        };
        let at = list
            .iter()
            .position(|m| m.name == name)
            .unwrap_or_else(|| panic!("{interface}.{name} is in the tables"));
        u16::try_from(at).unwrap_or_else(|_| panic!("{interface}.{name} has an opcode"))
    }

    fn request(interface: &str, name: &str) -> u16 {
        opcode(interface, true, name)
    }

    fn event(interface: &str, name: &str) -> u16 {
        opcode(interface, false, name)
    }

    #[test]
    fn a_fresh_connection_knows_only_the_display() {
        let objects = Objects::new();
        assert!(!objects.is_empty());
        assert_eq!(objects.len(), 1);
        assert_eq!(objects.interface(1).map(|i| i.name), Some("wl_display"));
        assert_eq!(objects.get(1).map(|e| e.interface), Some(WL_DISPLAY_INDEX));
        assert_eq!(objects.get(2), None);
    }

    #[test]
    fn a_client_allocates_its_ids_in_sequence() {
        let mut objects = Objects::new();
        let get_registry = request("wl_display", "get_registry");
        let sync = request("wl_display", "sync");
        assert_eq!(
            objects.new_id_from(true, 1, get_registry, &[Arg::NewId(2)]),
            Ok(Some(2))
        );
        assert_eq!(
            objects.new_id_from(true, 1, sync, &[Arg::NewId(3)]),
            Ok(Some(3))
        );
        assert_eq!(objects.interface(2).map(|i| i.name), Some("wl_registry"));
        assert_eq!(objects.interface(3).map(|i| i.name), Some("wl_callback"));
        assert_eq!(objects.len(), 3);
    }

    #[test]
    fn a_message_that_creates_nothing_maps_nothing() {
        let mut objects = Objects::new();
        let error = event("wl_display", "error");
        let args = [Arg::Object(1), Arg::Uint(0), Arg::String(None)];
        assert_eq!(objects.new_id_from(false, 1, error, &args), Ok(None));
        assert_eq!(objects.len(), 1);
    }

    #[test]
    fn each_side_allocates_from_its_own_range() {
        let mut objects = Objects::new();
        let get_registry = request("wl_display", "get_registry");
        assert_eq!(
            objects.new_id_from(true, 1, get_registry, &[Arg::NewId(SERVER_ID_BASE)]),
            Err(ObjectError::NotClientId(SERVER_ID_BASE))
        );
        assert_eq!(
            objects.new_id_from(true, 1, get_registry, &[Arg::NewId(0)]),
            Err(ObjectError::NotClientId(0))
        );
        objects
            .new_id_from(true, 1, get_registry, &[Arg::NewId(2)])
            .expect("the registry");
        objects
            .bind(1, index("wl_data_device_manager"), 3, 3)
            .expect("the data device manager");
        objects.bind(2, index("wl_seat"), 3, 4).expect("a seat");
        let get_device = request("wl_data_device_manager", "get_data_device");
        objects
            .new_id_from(true, 3, get_device, &[Arg::NewId(5), Arg::Object(4)])
            .expect("the data device");
        // wl_data_device.data_offer creates the offer from the server's range.
        let data_offer = event("wl_data_device", "data_offer");
        assert_eq!(
            objects.new_id_from(false, 5, data_offer, &[Arg::NewId(6)]),
            Err(ObjectError::NotServerId(6))
        );
        let id = SERVER_ID_BASE + 1;
        assert_eq!(
            objects.new_id_from(false, 5, data_offer, &[Arg::NewId(id)]),
            Ok(Some(id))
        );
        assert_eq!(objects.interface(id).map(|i| i.name), Some("wl_data_offer"));
    }

    #[test]
    fn a_new_object_never_outranks_the_tables() {
        let mut objects = Objects::new();
        objects
            .bind(1, index("wl_seat"), 7, 2)
            .expect("a seat at v7");
        let get_pointer = request("wl_seat", "get_pointer");
        objects
            .new_id_from(true, 2, get_pointer, &[Arg::NewId(3)])
            .expect("the pointer");
        assert_eq!(objects.get(3).map(|e| e.version), Some(7));
        // wl_buffer stays at its own version however new its parent is.
        objects
            .bind(2, index("zwp_linux_dmabuf_v1"), 5, 4)
            .expect("dmabuf at v5");
        let create_params = request("zwp_linux_dmabuf_v1", "create_params");
        objects
            .new_id_from(true, 4, create_params, &[Arg::NewId(5)])
            .expect("the params");
        let create_immed = request("zwp_linux_buffer_params_v1", "create_immed");
        let args = [
            Arg::NewId(6),
            Arg::Int(1),
            Arg::Int(1),
            Arg::Uint(0),
            Arg::Uint(0),
        ];
        objects
            .new_id_from(true, 5, create_immed, &args)
            .expect("the buffer");
        let buffer = tables::lookup("wl_buffer").expect("wl_buffer");
        assert_eq!(objects.get(6).map(|e| e.version), Some(buffer.version));
    }

    #[test]
    fn an_untyped_new_id_has_to_go_through_bind() {
        let mut objects = Objects::new();
        objects
            .new_id_from(
                true,
                1,
                request("wl_display", "get_registry"),
                &[Arg::NewId(2)],
            )
            .expect("the registry");
        let args = [
            Arg::Uint(9),
            Arg::String(Some(c"wl_compositor".into())),
            Arg::Uint(6),
            Arg::NewId(3),
        ];
        assert_eq!(
            objects.new_id_from(true, 2, request("wl_registry", "bind"), &args),
            Err(ObjectError::UntypedNewId)
        );
        assert_eq!(objects.bind(9, index("wl_compositor"), 6, 3), Ok(()));
        assert_eq!(objects.interface(3).map(|i| i.name), Some("wl_compositor"));
        assert_eq!(objects.get(3).map(|e| e.version), Some(6));
    }

    #[test]
    fn a_hidden_global_cannot_be_bound_by_number() {
        let mut objects = Objects::new();
        objects.hide_global(42);
        assert!(objects.is_hidden(42));
        assert!(!objects.is_hidden(43));
        assert_eq!(objects.hidden_count(), 1);
        assert_eq!(
            objects.bind(42, index("wl_compositor"), 1, 2),
            Err(ObjectError::HiddenGlobal(42))
        );
        assert_eq!(objects.get(2), None);
    }

    #[test]
    fn a_destroyed_object_stays_mapped_until_the_server_releases_the_id() {
        let mut objects = Objects::new();
        objects.bind(1, index("wl_shm"), 1, 2).expect("shm");
        assert!(objects.destroy(2));
        assert_eq!(objects.get(2).map(|e| e.zombie), Some(true));
        assert_eq!(objects.interface(2).map(|i| i.name), Some("wl_shm"));
        // Reusing the id before the release is the client getting ahead of
        // the protocol, not something to overwrite quietly.
        assert_eq!(
            objects.bind(1, index("wl_shm"), 1, 2),
            Err(ObjectError::InUse(2))
        );
        assert!(objects.delete_id(2));
        assert_eq!(objects.get(2), None);
        assert!(!objects.delete_id(2));
        assert!(!objects.destroy(2));
        assert_eq!(objects.bind(1, index("wl_shm"), 1, 2), Ok(()));
    }

    #[test]
    fn the_server_may_reuse_an_id_it_owns() {
        let mut objects = Objects::new();
        objects.bind(1, index("wl_seat"), 7, 2).expect("a seat");
        objects
            .new_id_from(
                true,
                2,
                request("wl_seat", "get_keyboard"),
                &[Arg::NewId(3)],
            )
            .expect("the keyboard");
        let id = SERVER_ID_BASE + 7;
        let repeat = event("wl_keyboard", "keymap");
        assert_eq!(objects.new_id_from(false, 3, repeat, &[Arg::Fd]), Ok(None));
        objects
            .bind(2, index("wl_data_device_manager"), 3, 4)
            .expect("the manager");
        objects
            .new_id_from(
                true,
                4,
                request("wl_data_device_manager", "get_data_device"),
                &[Arg::NewId(5), Arg::Object(2)],
            )
            .expect("the device");
        let offer = event("wl_data_device", "data_offer");
        objects
            .new_id_from(false, 5, offer, &[Arg::NewId(id)])
            .expect("an offer");
        objects
            .new_id_from(false, 5, offer, &[Arg::NewId(id)])
            .expect("the same id again, as the server recycles it");
        assert_eq!(objects.get(id).map(|e| e.zombie), Some(false));
    }

    #[test]
    fn an_opcode_the_interface_does_not_have_is_refused() {
        let mut objects = Objects::new();
        assert_eq!(
            objects.new_id_from(true, 1, 9, &[Arg::NewId(2)]),
            Err(ObjectError::NoSuchMessage("wl_display", 9))
        );
        // The side decides which list the opcode indexes: 0 is `sync` as a
        // request and `error` as an event, and only one of them creates.
        assert_eq!(objects.new_id_from(false, 1, 0, &[]), Ok(None));
        assert_eq!(
            objects.new_id_from(true, 1, 0, &[Arg::NewId(2)]),
            Ok(Some(2))
        );
        assert_eq!(objects.interface(2).map(|i| i.name), Some("wl_callback"));
    }

    #[test]
    fn zombies_the_compositor_made_do_not_fill_the_cap() {
        let mut objects = Objects::new();
        objects
            .bind(1, index("wl_data_device_manager"), 3, 2)
            .expect("the manager");
        objects.bind(2, index("wl_seat"), 3, 3).expect("a seat");
        objects
            .new_id_from(
                true,
                2,
                request("wl_data_device_manager", "get_data_device"),
                &[Arg::NewId(4), Arg::Object(3)],
            )
            .expect("the device");
        let offer = event("wl_data_device", "data_offer");
        for n in 0..MAX_OBJECTS as u32 - 1 {
            let id = SERVER_ID_BASE + n;
            objects
                .new_id_from(false, 4, offer, &[Arg::NewId(id)])
                .unwrap_or_else(|e| panic!("offer {n}: {e}"));
            assert!(objects.destroy(id));
        }
        assert!(objects.len() > MAX_OBJECTS);
        // The client's own ids still fit: how many dead offers the compositor
        // leaves behind is not the sandboxed client's doing.
        assert_eq!(objects.bind(1, index("wl_compositor"), 1, 5), Ok(()));
        // They are not unbounded either. One more dead offer fills the second
        // cap, and the next object of any kind is refused.
        let last = SERVER_ID_BASE + MAX_OBJECTS as u32;
        objects
            .new_id_from(false, 4, offer, &[Arg::NewId(last)])
            .expect("one more offer");
        assert!(objects.destroy(last));
        assert_eq!(
            objects.new_id_from(false, 4, offer, &[Arg::NewId(last + 1)]),
            Err(ObjectError::TooManyObjects)
        );
        assert_eq!(
            objects.bind(1, index("wl_compositor"), 1, 6),
            Err(ObjectError::TooManyObjects)
        );
        // Reusing a dead id is still allowed: it frees the slot it holds.
        assert_eq!(
            objects.new_id_from(false, 4, offer, &[Arg::NewId(last)]),
            Ok(Some(last))
        );
        assert_eq!(objects.bind(1, index("wl_compositor"), 1, 6), Ok(()));
    }

    #[test]
    fn a_message_for_an_unmapped_object_creates_nothing() {
        let mut objects = Objects::new();
        let sync = request("wl_display", "sync");
        assert_eq!(
            objects.new_id_from(true, 99, sync, &[Arg::NewId(2)]),
            Err(ObjectError::Unmapped(99))
        );
    }

    #[test]
    fn an_interface_outside_the_tables_is_refused() {
        let mut objects = Objects::new();
        assert_eq!(
            objects.bind(1, tables::INTERFACES.len(), 1, 2),
            Err(ObjectError::UnknownInterface(tables::INTERFACES.len()))
        );
    }

    #[test]
    fn the_map_stops_at_the_cap() {
        let mut objects = Objects::new();
        let compositor = index("wl_compositor");
        for id in 2..=MAX_OBJECTS as u32 {
            objects
                .bind(1, compositor, 1, id)
                .unwrap_or_else(|e| panic!("id {id}: {e}"));
        }
        assert_eq!(objects.len(), MAX_OBJECTS);
        assert_eq!(
            objects.bind(1, compositor, 1, MAX_OBJECTS as u32 + 1),
            Err(ObjectError::TooManyObjects)
        );
        // A zombie holds its slot; releasing the id gives it back.
        assert!(objects.destroy(2));
        assert_eq!(
            objects.bind(1, compositor, 1, MAX_OBJECTS as u32 + 1),
            Err(ObjectError::TooManyObjects)
        );
        assert!(objects.delete_id(2));
        assert_eq!(
            objects.bind(1, compositor, 1, MAX_OBJECTS as u32 + 1),
            Ok(())
        );
    }
}
