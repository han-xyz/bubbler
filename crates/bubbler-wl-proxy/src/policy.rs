//! What the proxy does with each message it has decoded: forward it, drop it,
//! or refuse it and end the connection.
//!
//! Three rules matter, and all three came out of the spike measuring a real
//! compositor. A global whose interface the tables do not describe is kept out
//! of the registry, because the proxy could not parse a single message for it.
//! Hiding the advertisement is not enough on its own — a client can name a
//! global by its number without ever having seen it — so `bind` is checked
//! against what this connection was actually offered. And an advertised
//! version above the tables is clamped, because a client that bound the higher
//! version would send opcodes past the end of the message lists.
//!
//! On top of that sits the one rule this proxy exists for: a clipboard
//! `receive` is forwarded only just after real user input, so an app cannot
//! read the selection in the background.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use crate::audit::{Audit, Kind};
use crate::objects::{ObjectError, Objects};
use crate::tables::{self, Interface, Message};
use crate::wire::{self, Arg};

// The list is shared with `bubbler-core`, which includes the same file, so it
// stays a bare `const` with no module of its own.
include!("privileged.rs");

/// How long a clipboard read stays allowed after a user input event.
pub const GATE_WINDOW: Duration = Duration::from_millis(1000);

/// The offer interfaces whose `receive` request the gate covers: the core
/// selection, the primary selection and both data-control protocols. Sorted,
/// so the check is a binary search.
pub const GATED_OFFERS: &[&str] = &[
    "ext_data_control_offer_v1",
    "wl_data_offer",
    "zwlr_data_control_offer_v1",
    "zwp_primary_selection_offer_v1",
];

/// Object id of `wl_display`, which is the same on every connection before
/// either side has sent anything.
const DISPLAY_ID: u32 = 1;

/// Opcode of the `wl_display.error` event the proxy synthesises to refuse a
/// bind. Code 0 goes with it: the error is the proxy's, not an interface's.
const DISPLAY_ERROR: u16 = 0;

/// Whether a clipboard read has to follow user input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Forward a `receive` only within [`GATE_WINDOW`] of an input event.
    Paste,
    /// Forward every `receive`, and log each one.
    Open,
}

/// What the relay must do with the message it just decoded.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Send it on, re-encoded from the arguments the policy may have rewritten.
    Forward,
    /// Do not send it on. Any descriptors it carried are already closed, which
    /// is what a denied clipboard read looks like to the client: end of file.
    Drop,
    /// Do not send it on: write these bytes back to the sender instead — a
    /// `wl_display.error` — and close the connection. Empty when the error
    /// could not be encoded, in which case the connection just closes.
    Refuse {
        /// The encoded `wl_display.error` event.
        error: Vec<u8>,
    },
}

/// The proxy's state that is shared by every connection of one sandbox: the
/// gate and the moment the user last touched an input device.
///
/// It is deliberately per process rather than per connection. An app with a
/// helper process reads the clipboard on a connection that never had keyboard
/// focus, and gating that connection on its own input would deny every
/// multi-process toolkit.
#[derive(Debug)]
pub struct Policy {
    gate: Gate,
    fallback_deny: bool,
    last_input: Option<Instant>,
}

/// What one global the compositor advertised is, as this connection was told
/// it: the tables' entry for the interface and the version the client was
/// offered, which is never above what the tables describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Global {
    interface: usize,
    version: u32,
}

/// Everything the proxy remembers about one client connection.
#[derive(Debug, Default)]
pub struct Connection {
    /// Which interface each object id on this connection belongs to.
    pub objects: Objects,
    /// The globals this connection was offered, by their numeric name. A name
    /// that is not in here was never advertised to this client, or was hidden
    /// from it, and cannot be bound.
    globals: HashMap<u32, Global>,
}

/// One decoded message on its way through, with everything the policy needs to
/// judge it. `args` and `fds` are the message's own, and both may be changed:
/// an argument is rewritten when a version is clamped, and the descriptors are
/// closed when the message is dropped.
#[derive(Debug)]
pub struct Incoming<'a> {
    /// Whether the client sent it. The server sent it otherwise.
    pub from_client: bool,
    /// Object id the message addresses.
    pub object: u32,
    /// Opcode within that object's interface.
    pub opcode: u16,
    /// Interface of the addressed object.
    pub interface: &'static Interface,
    /// The message that opcode names.
    pub message: &'static Message,
    /// Decoded arguments, in wire order.
    pub args: &'a mut Vec<Arg>,
    /// Descriptors the message carries, in the order its `fd` arguments name.
    pub fds: &'a mut Vec<OwnedFd>,
}

impl Connection {
    /// A connection that has seen nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many globals this connection was offered.
    pub fn globals(&self) -> usize {
        self.globals.len()
    }
}

impl Policy {
    /// A policy with this gate, hiding the privileged interfaces when
    /// `fallback_deny` — which the launcher sets when the compositor has no
    /// security context of its own to hide them.
    pub fn new(gate: Gate, fallback_deny: bool) -> Self {
        Self {
            gate,
            fallback_deny,
            last_input: None,
        }
    }

    /// The moment an arming input event was last seen, on any connection.
    pub fn last_input(&self) -> Option<Instant> {
        self.last_input
    }

    /// Record user input at `now`: from here a clipboard read is forwarded for
    /// [`GATE_WINDOW`].
    pub fn arm(&mut self, now: Instant) {
        self.last_input = Some(now);
    }

    /// Judge one message, and keep the connection's object map in step with
    /// what is forwarded.
    ///
    /// An error means the connection has stopped making sense — an unmapped
    /// id, an id from the wrong range, the object cap — and the relay's answer
    /// to that is to close it, never to forward a message it could not account
    /// for.
    pub fn apply(
        &mut self,
        msg: &mut Incoming<'_>,
        conn: &mut Connection,
        audit: &mut Audit,
        now: Instant,
    ) -> Result<Action, ObjectError> {
        // `bind` is the one message that creates an object the tables do not
        // name, so it registers its own id and never reaches the bookkeeping
        // below.
        if msg.from_client && msg.interface.name == "wl_registry" && msg.message.name == "bind" {
            return self.bind(msg, conn, audit, now);
        }
        let action = match msg.from_client {
            true => self.request(msg, audit, now),
            false => self.event(msg, conn, now),
        };
        if action == Action::Forward {
            conn.objects
                .new_id_from(msg.from_client, msg.object, msg.opcode, msg.args)?;
        }
        Ok(action)
    }

    /// Requests: the clipboard gate. Everything else the client sends is the
    /// compositor's business, not the proxy's.
    fn request(&mut self, msg: &mut Incoming<'_>, audit: &mut Audit, now: Instant) -> Action {
        if msg.message.name != "receive" || GATED_OFFERS.binary_search(&msg.interface.name).is_err()
        {
            return Action::Forward;
        }
        let iface = msg.interface.name;
        let mime = match msg.args.first() {
            Some(Arg::String(Some(mime))) => mime.to_string_lossy().into_owned(),
            _ => String::new(),
        };
        if self.gate == Gate::Open {
            audit.line(
                Kind::Gate,
                now,
                &format!("bubbler-wl-proxy: clipboard read allowed (open): {iface}, {mime}"),
            );
            return Action::Forward;
        }
        let age = self
            .last_input
            .map(|last| now.saturating_duration_since(last));
        if age.is_some_and(|age| age <= GATE_WINDOW) {
            return Action::Forward;
        }
        // A sandbox that has had no input at all is the case this gate exists
        // for, and saying so is more use than an age counted from a start the
        // reader cannot see.
        let why = match age {
            Some(age) => format!("no input for {} ms", age.as_millis()),
            None => "no input since the proxy started".to_owned(),
        };
        audit.line(
            Kind::Gate,
            now,
            &format!("bubbler-wl-proxy: clipboard read denied ({iface}, {mime}): {why}"),
        );
        drop_message(msg)
    }

    /// Events: the registry is filtered, and input events arm the gate.
    fn event(&mut self, msg: &mut Incoming<'_>, conn: &mut Connection, now: Instant) -> Action {
        match (msg.interface.name, msg.message.name) {
            ("wl_registry", "global") => return self.global(msg, conn),
            ("wl_registry", "global_remove") => return Self::global_remove(msg, conn),
            ("wl_display", "delete_id") => {
                if let Some(Arg::Uint(id)) = msg.args.first() {
                    conn.objects.delete_id(*id);
                }
            }
            // `state` is argument 3 of both, and 1 is pressed. A pointer
            // button arms on release as well: letting go of the mouse over a
            // paste target is user input by any reading.
            ("wl_keyboard", "key") => {
                if let Some(Arg::Uint(1)) = msg.args.get(3) {
                    self.arm(now);
                }
            }
            ("wl_pointer", "button") => self.arm(now),
            ("wl_touch", "down") => self.arm(now),
            _ => {}
        }
        Action::Forward
    }

    /// `wl_registry.global`: hide what cannot be parsed or must not be
    /// reachable, and clamp what the tables describe at a lower version.
    fn global(&self, msg: &mut Incoming<'_>, conn: &mut Connection) -> Action {
        let (Some(Arg::Uint(name)), Some(Arg::String(Some(iface))), Some(Arg::Uint(version))) =
            (msg.args.first(), msg.args.get(1), msg.args.get(2))
        else {
            return Action::Forward;
        };
        let (name, version) = (*name, *version);
        let described = iface.to_str().ok().and_then(|iface| {
            let known = tables::index_of(iface).zip(tables::lookup(iface));
            known.filter(|_| !(self.fallback_deny && PRIVILEGED.binary_search(&iface).is_ok()))
        });
        // Unnamed here, and refused by number in `bind`: an advertisement the
        // client never saw is not a global it may reach for.
        let Some((index, known)) = described else {
            conn.objects.hide_global(name);
            return drop_message(msg);
        };
        let offered = version.min(known.version);
        conn.globals.insert(
            name,
            Global {
                interface: index,
                version: offered,
            },
        );
        if offered != version {
            msg.args[2] = Arg::Uint(offered);
        }
        Action::Forward
    }

    /// `wl_registry.global_remove`: a name this connection never saw must not
    /// be withdrawn either, or the client learns the global was there.
    fn global_remove(msg: &mut Incoming<'_>, conn: &mut Connection) -> Action {
        let Some(Arg::Uint(name)) = msg.args.first() else {
            return Action::Forward;
        };
        let name = *name;
        if conn.objects.is_hidden(name) {
            return drop_message(msg);
        }
        conn.globals.remove(&name);
        Action::Forward
    }

    /// `wl_registry.bind`: only a global this connection was offered, at a
    /// version it was offered, and the new object is recorded at the version
    /// the client actually bound so later opcodes are read against the right
    /// message list.
    fn bind(
        &self,
        msg: &mut Incoming<'_>,
        conn: &mut Connection,
        audit: &mut Audit,
        now: Instant,
    ) -> Result<Action, ObjectError> {
        let (
            Some(Arg::Uint(name)),
            Some(Arg::String(Some(iface))),
            Some(Arg::Uint(version)),
            Some(Arg::NewId(new_id)),
        ) = (
            msg.args.first(),
            msg.args.get(1),
            msg.args.get(2),
            msg.args.get(3),
        )
        else {
            return Ok(refuse(
                msg.object,
                "a bind the proxy could not read",
                audit,
                now,
            ));
        };
        let (name, version, new_id) = (*name, *version, *new_id);
        let wanted = iface.to_string_lossy().into_owned();
        // The name must have been offered, for this very interface, at this
        // version or above: a client may name a global it never saw.
        let offered = conn.globals.get(&name).copied().filter(|global| {
            tables::by_index(global.interface).is_some_and(|known| known.name == wanted)
                && (1..=global.version).contains(&version)
        });
        let Some(global) = offered else {
            let why = format!(
                "bind of hidden global {wanted} (name {name}, v{version}) refused by the sandbox proxy"
            );
            return Ok(refuse(msg.object, &why, audit, now));
        };
        conn.objects.bind(name, global.interface, version, new_id)?;
        Ok(Action::Forward)
    }
}

/// Do not forward this message, and close the descriptors it carried. That
/// close is what a denied clipboard read is: the client's own read end sees
/// end of file, exactly as if the selection had been empty.
fn drop_message(msg: &mut Incoming<'_>) -> Action {
    msg.fds.clear();
    Action::Drop
}

/// Refuse the request with a `wl_display.error` naming `object`, and say so in
/// the log — the connection is about to end, so this is the only record.
fn refuse(object: u32, why: &str, audit: &mut Audit, now: Instant) -> Action {
    audit.line(
        Kind::Close,
        now,
        &format!("bubbler-wl-proxy: connection closed: {why}"),
    );
    Action::Refuse {
        error: display_error(object, why),
    }
}

/// The bytes of a `wl_display.error` event blaming `object`.
///
/// An error the wire cannot carry (a client that bound an interface name of
/// tens of kilobytes) encodes to nothing, and the relay closes the connection
/// without a message rather than sending a truncated one.
fn display_error(object: u32, text: &str) -> Vec<u8> {
    let args = [
        Arg::Object(object),
        Arg::Uint(0),
        Arg::String(Some(CString::new(text).unwrap_or_default())),
    ];
    wire::encode(DISPLAY_ID, DISPLAY_ERROR, &args).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::rc::Rc;

    use super::*;
    use crate::objects::SERVER_ID_BASE;

    /// A log the test can read back.
    #[derive(Clone, Default)]
    struct Buf(Rc<RefCell<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).expect("the log is UTF-8")
        }
    }

    struct Proxy {
        policy: Policy,
        conn: Connection,
        audit: Audit,
        log: Buf,
        now: Instant,
    }

    impl Proxy {
        fn new(gate: Gate, fallback_deny: bool) -> Self {
            let log = Buf::default();
            Self {
                policy: Policy::new(gate, fallback_deny),
                conn: Connection::new(),
                audit: Audit::new(Box::new(log.clone())),
                log,
                now: Instant::now(),
            }
        }

        /// Put one message through the policy, as the relay would.
        fn send(
            &mut self,
            from_client: bool,
            object: u32,
            iface: &str,
            name: &str,
            args: &mut Vec<Arg>,
            fds: &mut Vec<OwnedFd>,
        ) -> Result<Action, ObjectError> {
            let interface =
                tables::lookup(iface).unwrap_or_else(|| panic!("{iface} in the tables"));
            let list = match from_client {
                true => interface.requests,
                false => interface.events,
            };
            let at = list
                .iter()
                .position(|m| m.name == name)
                .unwrap_or_else(|| panic!("{iface}.{name} in the tables"));
            let opcode = u16::try_from(at).expect("an opcode fits");
            let mut msg = Incoming {
                from_client,
                object,
                opcode,
                interface,
                message: &list[at],
                args,
                fds,
            };
            self.policy
                .apply(&mut msg, &mut self.conn, &mut self.audit, self.now)
        }

        /// A `wl_registry.global` event for `iface` at `version`.
        fn advertise(&mut self, name: u32, iface: &str, version: u32) -> (Action, Vec<Arg>) {
            let mut args = vec![
                Arg::Uint(name),
                Arg::String(Some(CString::new(iface).expect("no NUL"))),
                Arg::Uint(version),
            ];
            let action = self
                .send(
                    false,
                    REGISTRY,
                    "wl_registry",
                    "global",
                    &mut args,
                    &mut Vec::new(),
                )
                .expect("a registry event is always accountable");
            (action, args)
        }

        /// A `wl_registry.bind` request for `iface` at `version`.
        fn bind(&mut self, name: u32, iface: &str, version: u32, new_id: u32) -> Action {
            let mut args = vec![
                Arg::Uint(name),
                Arg::String(Some(CString::new(iface).expect("no NUL"))),
                Arg::Uint(version),
                Arg::NewId(new_id),
            ];
            self.send(
                true,
                REGISTRY,
                "wl_registry",
                "bind",
                &mut args,
                &mut Vec::new(),
            )
            .expect("a bind is refused, not unaccountable")
        }

        /// A `receive` request on an offer object, carrying the write end of a
        /// pipe. Answers the action and the read end the client kept.
        fn receive(&mut self, offer: u32, iface: &str, mime: &str) -> (Action, std::fs::File) {
            map(&mut self.conn, offer, iface, 1);
            let (read, write) = rustix::pipe::pipe().expect("a pipe");
            let mut args = vec![
                Arg::String(Some(CString::new(mime).expect("no NUL"))),
                Arg::Fd,
            ];
            let mut fds = vec![write];
            let action = self
                .send(true, offer, iface, "receive", &mut args, &mut fds)
                .expect("a receive is dropped, not unaccountable");
            (action, std::fs::File::from(read))
        }

        /// One arming input event of the given kind.
        fn input(&mut self, iface: &str, name: &str, state: u32) {
            let object = 90;
            map(&mut self.conn, object, iface, 1);
            let mut args = match name {
                "down" => vec![
                    Arg::Uint(1),
                    Arg::Uint(0),
                    Arg::Object(0),
                    Arg::Int(0),
                    Arg::Fixed(0),
                    Arg::Fixed(0),
                ],
                _ => vec![Arg::Uint(1), Arg::Uint(0), Arg::Uint(30), Arg::Uint(state)],
            };
            let action = self
                .send(false, object, iface, name, &mut args, &mut Vec::new())
                .expect("an input event is always accountable");
            assert_eq!(action, Action::Forward);
        }
    }

    /// The registry object id every test uses; the client would have created
    /// it with `wl_display.get_registry`.
    const REGISTRY: u32 = 2;

    /// Map `id` to `iface` directly, standing in for the chain of messages
    /// that would have created the object on a live connection.
    fn map(conn: &mut Connection, id: u32, iface: &str, version: u32) {
        if conn.objects.get(id).is_some() {
            return;
        }
        let index = tables::index_of(iface).unwrap_or_else(|| panic!("{iface} in the tables"));
        conn.objects
            .bind(u32::MAX, index, version, id)
            .expect("an unhidden global maps");
    }

    /// The text of a refusal's `wl_display.error`.
    fn error_text(action: &Action) -> String {
        let Action::Refuse { error } = action else {
            panic!("not a refusal: {action:?}");
        };
        let sig = &[
            crate::tables::ArgKind::Object,
            crate::tables::ArgKind::Uint,
            crate::tables::ArgKind::String,
        ];
        let (args, _) = wire::decode(error, sig).expect("the proxy's own error decodes");
        match &args[2] {
            Arg::String(Some(text)) => text.to_string_lossy().into_owned(),
            other => panic!("not a string: {other:?}"),
        }
    }

    fn proxy() -> Proxy {
        let mut proxy = Proxy::new(Gate::Paste, false);
        map(&mut proxy.conn, REGISTRY, "wl_registry", 1);
        proxy
    }

    #[test]
    fn the_privileged_list_is_sorted_so_the_search_cannot_fail_open() {
        let mut sorted = PRIVILEGED.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted.as_slice(), PRIVILEGED);
        sorted.dedup();
        assert_eq!(sorted.len(), PRIVILEGED.len(), "a name appears twice");
        for name in PRIVILEGED {
            assert_eq!(
                PRIVILEGED.binary_search(name),
                Ok(PRIVILEGED
                    .iter()
                    .position(|it| it == name)
                    .expect("present")),
                "{name} is not where a binary search looks"
            );
        }
    }

    #[test]
    fn the_four_gated_offers_are_sorted_and_in_the_tables() {
        let mut sorted = GATED_OFFERS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted.as_slice(), GATED_OFFERS);
        for iface in GATED_OFFERS {
            assert!(tables::lookup(iface).is_some(), "{iface}");
        }
    }

    #[test]
    fn a_global_the_tables_do_not_describe_is_hidden_and_remembered() {
        let mut proxy = proxy();
        let (action, _) = proxy.advertise(42, "hyprland_global_shortcuts_manager_v1", 1);
        assert_eq!(action, Action::Drop);
        assert!(proxy.conn.objects.is_hidden(42));
        assert_eq!(proxy.conn.globals(), 0);
    }

    #[test]
    fn a_privileged_global_is_hidden_only_under_the_fallback() {
        let mut open = proxy();
        let (action, _) = open.advertise(7, "zxdg_output_manager_v1", 3);
        assert_eq!(action, Action::Forward);
        assert!(!open.conn.objects.is_hidden(7));

        let mut denied = Proxy::new(Gate::Paste, true);
        map(&mut denied.conn, REGISTRY, "wl_registry", 1);
        let (action, _) = denied.advertise(7, "zxdg_output_manager_v1", 3);
        assert_eq!(action, Action::Drop);
        assert!(denied.conn.objects.is_hidden(7));
    }

    #[test]
    fn an_advertised_version_above_the_tables_is_rewritten() {
        let mut proxy = proxy();
        let known = tables::lookup("wl_compositor").expect("wl_compositor");
        let (action, args) = proxy.advertise(3, "wl_compositor", known.version + 5);
        assert_eq!(action, Action::Forward);
        assert_eq!(args[2], Arg::Uint(known.version));
    }

    #[test]
    fn a_version_the_tables_cover_is_advertised_unchanged() {
        let mut proxy = proxy();
        let (action, args) = proxy.advertise(3, "wl_compositor", 1);
        assert_eq!(action, Action::Forward);
        assert_eq!(args[2], Arg::Uint(1));
    }

    #[test]
    fn removing_a_hidden_global_is_not_forwarded_either() {
        let mut proxy = proxy();
        proxy.advertise(42, "hyprland_global_shortcuts_manager_v1", 1);
        let mut args = vec![Arg::Uint(42)];
        let action = proxy
            .send(
                false,
                REGISTRY,
                "wl_registry",
                "global_remove",
                &mut args,
                &mut Vec::new(),
            )
            .expect("accountable");
        assert_eq!(action, Action::Drop);
    }

    #[test]
    fn removing_a_visible_global_is_forwarded_and_forgotten() {
        let mut proxy = proxy();
        proxy.advertise(3, "wl_compositor", 1);
        assert_eq!(proxy.conn.globals(), 1);
        let mut args = vec![Arg::Uint(3)];
        let action = proxy
            .send(
                false,
                REGISTRY,
                "wl_registry",
                "global_remove",
                &mut args,
                &mut Vec::new(),
            )
            .expect("accountable");
        assert_eq!(action, Action::Forward);
        assert_eq!(proxy.conn.globals(), 0);
    }

    #[test]
    fn binding_a_hidden_global_by_its_number_is_refused() {
        let mut proxy = proxy();
        proxy.advertise(42, "hyprland_global_shortcuts_manager_v1", 1);
        let action = proxy.bind(42, "hyprland_global_shortcuts_manager_v1", 1, 3);
        assert_eq!(
            error_text(&action),
            "bind of hidden global hyprland_global_shortcuts_manager_v1 (name 42, v1) \
             refused by the sandbox proxy"
        );
        assert!(proxy.conn.objects.get(3).is_none());
        assert!(proxy.log.text().contains(
            "bubbler-wl-proxy: connection closed: bind of hidden global \
             hyprland_global_shortcuts_manager_v1 (name 42, v1) refused by the sandbox proxy"
        ));
    }

    #[test]
    fn binding_a_global_that_was_never_advertised_is_refused() {
        let mut proxy = proxy();
        let action = proxy.bind(9, "wl_compositor", 1, 3);
        assert_eq!(
            error_text(&action),
            "bind of hidden global wl_compositor (name 9, v1) refused by the sandbox proxy"
        );
    }

    #[test]
    fn binding_above_the_advertised_version_is_refused() {
        let mut proxy = proxy();
        proxy.advertise(3, "wl_compositor", 2);
        let action = proxy.bind(3, "wl_compositor", 3, 4);
        assert_eq!(
            error_text(&action),
            "bind of hidden global wl_compositor (name 3, v3) refused by the sandbox proxy"
        );
    }

    #[test]
    fn binding_a_name_under_another_interface_is_refused() {
        let mut proxy = proxy();
        proxy.advertise(3, "wl_compositor", 1);
        let action = proxy.bind(3, "wl_shm", 1, 4);
        assert_eq!(
            error_text(&action),
            "bind of hidden global wl_shm (name 3, v1) refused by the sandbox proxy"
        );
    }

    #[test]
    fn a_bind_the_registry_offered_records_the_bound_version() {
        let mut proxy = proxy();
        let known = tables::lookup("wl_seat").expect("wl_seat");
        proxy.advertise(5, "wl_seat", known.version);
        let action = proxy.bind(5, "wl_seat", 4, 3);
        assert_eq!(action, Action::Forward);
        let entry = proxy.conn.objects.get(3).expect("the seat is mapped");
        assert_eq!(entry.version, 4);
        assert_eq!(
            tables::by_index(entry.interface).map(|i| i.name),
            Some("wl_seat")
        );
    }

    #[test]
    fn a_clipboard_read_without_input_is_denied_on_every_offer() {
        for iface in GATED_OFFERS {
            let mut proxy = proxy();
            let (action, mut read) = proxy.receive(10, iface, "text/plain");
            assert_eq!(action, Action::Drop, "{iface}");
            let mut buf = [0u8; 8];
            assert_eq!(read.read(&mut buf).expect("the read end is open"), 0);
            assert_eq!(
                proxy.log.text(),
                format!(
                    "bubbler-wl-proxy: clipboard read denied ({iface}, text/plain): \
                     no input since the proxy started\n"
                ),
                "{iface}"
            );
        }
    }

    #[test]
    fn every_arming_event_opens_the_gate() {
        for (iface, name, state) in [
            ("wl_keyboard", "key", 1),
            ("wl_pointer", "button", 1),
            ("wl_pointer", "button", 0),
            ("wl_touch", "down", 0),
        ] {
            let mut proxy = proxy();
            proxy.input(iface, name, state);
            proxy.now += GATE_WINDOW;
            let (action, _read) = proxy.receive(10, "wl_data_offer", "text/plain");
            assert_eq!(action, Action::Forward, "{iface}.{name} state {state}");
            assert_eq!(proxy.log.text(), "");
        }
    }

    #[test]
    fn a_key_release_does_not_open_the_gate() {
        let mut proxy = proxy();
        proxy.input("wl_keyboard", "key", 0);
        let (action, _read) = proxy.receive(10, "wl_data_offer", "text/plain");
        assert_eq!(action, Action::Drop);
    }

    #[test]
    fn the_gate_closes_again_one_millisecond_past_the_window() {
        let mut proxy = proxy();
        proxy.input("wl_keyboard", "key", 1);
        proxy.now += GATE_WINDOW + Duration::from_millis(1);
        let (action, _read) = proxy.receive(10, "wl_data_offer", "text/plain");
        assert_eq!(action, Action::Drop);
        assert!(
            proxy.log.text().contains("no input for 1001 ms"),
            "{}",
            proxy.log.text()
        );
    }

    #[test]
    fn an_open_gate_forwards_the_read_and_says_so() {
        let mut proxy = Proxy::new(Gate::Open, false);
        map(&mut proxy.conn, REGISTRY, "wl_registry", 1);
        let (action, _read) = proxy.receive(10, "wl_data_offer", "text/plain;charset=utf-8");
        assert_eq!(action, Action::Forward);
        assert_eq!(
            proxy.log.text(),
            "bubbler-wl-proxy: clipboard read allowed (open): \
             wl_data_offer, text/plain;charset=utf-8\n"
        );
    }

    #[test]
    fn an_offer_the_compositor_created_is_gated_like_any_other() {
        let mut proxy = proxy();
        // The chain a real client walks: manager and seat from the registry,
        // then a data device, then the offer the compositor pushes at it.
        proxy.advertise(5, "wl_data_device_manager", 3);
        assert_eq!(
            proxy.bind(5, "wl_data_device_manager", 3, 3),
            Action::Forward
        );
        proxy.advertise(6, "wl_seat", 4);
        assert_eq!(proxy.bind(6, "wl_seat", 4, 4), Action::Forward);
        let mut args = vec![Arg::NewId(5), Arg::Object(4)];
        assert_eq!(
            proxy
                .send(
                    true,
                    3,
                    "wl_data_device_manager",
                    "get_data_device",
                    &mut args,
                    &mut Vec::new()
                )
                .expect("accountable"),
            Action::Forward
        );
        let offer = SERVER_ID_BASE + 1;
        let mut args = vec![Arg::NewId(offer)];
        assert_eq!(
            proxy
                .send(
                    false,
                    5,
                    "wl_data_device",
                    "data_offer",
                    &mut args,
                    &mut Vec::new()
                )
                .expect("accountable"),
            Action::Forward
        );
        assert_eq!(
            proxy.conn.objects.interface(offer).map(|i| i.name),
            Some("wl_data_offer"),
            "the offer was not recorded from the event that created it"
        );

        let (denied, mut read) = proxy.receive(offer, "wl_data_offer", "text/plain");
        assert_eq!(denied, Action::Drop);
        let mut buf = [0u8; 8];
        assert_eq!(read.read(&mut buf).expect("the read end is open"), 0);

        proxy.input("wl_keyboard", "key", 1);
        let (allowed, _read) = proxy.receive(offer, "wl_data_offer", "text/plain");
        assert_eq!(allowed, Action::Forward);
    }

    #[test]
    fn a_message_that_creates_an_object_records_it() {
        let mut proxy = proxy();
        let mut args = vec![Arg::NewId(3)];
        let action = proxy
            .send(true, 1, "wl_display", "sync", &mut args, &mut Vec::new())
            .expect("accountable");
        assert_eq!(action, Action::Forward);
        assert_eq!(
            proxy.conn.objects.interface(3).map(|i| i.name),
            Some("wl_callback")
        );
    }

    #[test]
    fn delete_id_releases_the_id_the_server_named() {
        let mut proxy = proxy();
        let mut args = vec![Arg::NewId(3)];
        proxy
            .send(true, 1, "wl_display", "sync", &mut args, &mut Vec::new())
            .expect("accountable");
        let mut args = vec![Arg::Uint(3)];
        let action = proxy
            .send(
                false,
                1,
                "wl_display",
                "delete_id",
                &mut args,
                &mut Vec::new(),
            )
            .expect("accountable");
        assert_eq!(action, Action::Forward);
        assert!(proxy.conn.objects.get(3).is_none());
    }

    #[test]
    fn a_message_for_an_unmapped_object_is_unaccountable() {
        let mut proxy = proxy();
        let mut args = vec![Arg::NewId(4)];
        let err = proxy
            .send(true, 77, "wl_display", "sync", &mut args, &mut Vec::new())
            .expect_err("object 77 is not mapped");
        assert_eq!(err, ObjectError::Unmapped(77));
    }
}
