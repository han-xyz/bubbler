//! What the filtering D-Bus sidecar needs: the proxy's rule list per bus,
//! the `.flatpak-info` portals identify the sandbox by, where portals look
//! that identity up, and where the filtered sockets live. The sandbox
//! never reaches a host bus itself.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use crate::config::{BusRule, Portal, Service};
use crate::dbus_wire::{Session, Value, WireError};
use crate::env::Env;
use crate::error::LaunchError;
use crate::host::Host;
use crate::launcher::RUNTIME_SUBDIR;

/// Program that filters the buses; found on `PATH` inside the proxy
/// sandbox. One process serves every bus an instance is granted.
pub const PROXY_BIN: &str = "xdg-dbus-proxy";

/// File name of the session bus socket, in the proxy's directory and in
/// the instance's after the launcher moves it.
pub const SESSION_SOCKET: &str = "bus";

/// File name of the system bus socket, in the same two directories.
pub const SYSTEM_SOCKET: &str = "system";

/// Config node that grants the session bus, for errors about its socket.
pub const SESSION_NODE: &str = "dbus";

/// Config node that grants the system bus, for errors about its socket.
pub const SYSTEM_NODE: &str = "system-bus";

/// File name of the accessibility bus socket, in the same two
/// directories.
pub const A11Y_SOCKET: &str = "a11y";

/// Config node that grants the accessibility bus, for errors about its
/// socket.
pub const A11Y_NODE: &str = "a11y";

/// Where a system bus socket lives: the host's when no address overrides
/// it, and the path the filtered one is bound at inside the sandbox.
// libdbus and libsystemd both compile in this path, so a sandbox that has
// the socket there needs no environment variable to find it.
pub const SYSTEM_BUS_PATH: &str = "/run/dbus/system_bus_socket";

/// Where portals expect the sandbox identity file.
pub const FLATPAK_INFO: &str = "/.flatpak-info";

/// Directory of live sandbox instances under `$XDG_RUNTIME_DIR`. It is
/// flatpak's; bubbler only ever adds and removes its own entry in it.
pub const FLATPAK_DIR: &str = ".flatpak";

/// bwrap's `--info-fd` document, published for one instance. Portals read
/// `child-pid` out of it to get a pidfd of the sandbox.
pub const BWRAPINFO: &str = "bwrapinfo.json";

const DESKTOP_PATH: &str = "/org/freedesktop/portal/desktop";

// `xdg-dbus-proxy(1)` matches a rule's path exactly, so a rule at
// `DESKTOP_PATH` never matches one of these.
const REQUEST_PATH: &str = "/org/freedesktop/portal/desktop/request/*";

const SESSION_PATH: &str = "/org/freedesktop/portal/desktop/session/*";

/// Interfaces the bare `portals` node opens on
/// `org.freedesktop.portal.Desktop`: a file chooser, a link, a
/// notification, a print job, the read-only monitors a toolkit polls.
// `Request` and `Session` are not here: their objects live under their
// own subtrees, not at `DESKTOP_PATH`, so `portal_rules` gives them rules of their own.
pub const PORTAL_SAFE: &[&str] = &[
    "FileChooser",
    "OpenURI",
    "Notification",
    "Settings",
    "Print",
    "Email",
    "Trash",
    "Account",
    "Inhibit",
    "ProxyResolver",
    "NetworkMonitor",
    "MemoryMonitor",
    "PowerProfileMonitor",
    "Realtime",
    "GameMode",
];

fn portal_call(iface: &str) -> String {
    format!("--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.{iface}.*@{DESKTOP_PATH}")
}

fn portal_broadcast(iface: &str) -> String {
    format!(
        "--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.{iface}.*@{DESKTOP_PATH}"
    )
}

/// Every proxy argument `portals` and its `children` ask for. The `Documents` bus keeps
/// a wildcard: it is one service with no privileged interface on it, and the document
/// view it serves is the grant itself.
// No `--talk` of either bus name: a `--call` rule only applies while the name sits below
// TALK (`xdg-dbus-proxy(1)`), so a `--talk` would leave the rules below as dead text.
pub fn portal_rules(children: &[Portal]) -> Vec<String> {
    let ifaces = || {
        PORTAL_SAFE
            .iter()
            .copied()
            .chain(children.iter().flat_map(|c| c.interfaces().iter().copied()))
    };
    let mut out: Vec<String> = ifaces().map(portal_call).collect();
    out.push("--call=org.freedesktop.portal.Documents=*".to_owned());
    out.extend(ifaces().map(portal_broadcast));
    // A filtered name receives no signal without a `--broadcast` rule of its own.
    out.push("--broadcast=org.freedesktop.portal.Documents=*".to_owned());
    for (iface, path) in [("Request", REQUEST_PATH), ("Session", SESSION_PATH)] {
        out.push(format!(
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.{iface}.*@{path}"
        ));
    }
    for (iface, path) in [("Request", REQUEST_PATH), ("Session", SESSION_PATH)] {
        out.push(format!(
            "--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.{iface}.*@{path}"
        ));
    }
    // GDBusProxy and libportal both call Properties.Get/GetAll when a client constructs its
    // proxy. `Set` is left out: no portal property here is meant to be written from inside.
    out.push(format!(
        "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.Get@{DESKTOP_PATH}"
    ));
    out.push(format!(
        "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.GetAll@{DESKTOP_PATH}"
    ));
    // Introspection reads the desktop object's XML and nothing else, so it is
    // safe where `Properties.Set` is not.
    out.push(format!(
        "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Introspectable.Introspect@{DESKTOP_PATH}"
    ));
    out
}

/// What `camera` opens.
pub fn camera_rules() -> [String; 2] {
    [portal_call("Camera"), portal_broadcast("Camera")]
}

/// The `talk` and `own` rules a grant adds on the session bus.
pub(crate) fn grant_policies(svc: &Service) -> Vec<BusRule> {
    match svc {
        Service::Notify => vec![BusRule::Talk("org.freedesktop.Notifications".to_owned())],
        // An item registers on the app's own unique name, and the calls the host makes back
        // into it are incoming, which the proxy does not filter (`xdg-dbus-proxy(1)`).
        Service::Tray => vec![BusRule::Talk("org.kde.StatusNotifierWatcher".to_owned())],
        // Both portal names, whichever daemon the session runs; not the
        // daemons' own names, which carry `Exit` and `SetConfig`.
        Service::InputMethod => vec![
            BusRule::Talk("org.freedesktop.portal.Fcitx".to_owned()),
            BusRule::Talk("org.freedesktop.portal.IBus".to_owned()),
        ],
        Service::Mpris { name } => vec![BusRule::Own(format!("org.mpris.MediaPlayer2.{name}"))],
        Service::Portals { .. }
        | Service::Camera { .. }
        | Service::A11y
        | Service::Wayland(_)
        | Service::X11(_)
        | Service::Network { .. }
        | Service::Dri { .. }
        | Service::Pipewire { .. }
        | Service::Pulseaudio { .. }
        | Service::Gamepad { .. }
        | Service::Hidraw
        | Service::HomeShare { .. }
        | Service::PathShare { .. }
        | Service::EtcShare { .. }
        | Service::Dbus { .. }
        | Service::SystemBus { .. }
        | Service::AppRuntime { .. } => Vec::new(),
    }
}

/// Rules the `a11y` grant gets on the accessibility bus, which is the
/// whole of what a sandboxed client may ask that bus for: registering
/// the application with the AT-SPI registry, and reading back what is registered.
// The set flatpak grants a sandboxed client (`flatpak-run-dbus.c`).
pub const A11Y_RULES: &[&str] = &[
    "--call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Embed@/org/a11y/atspi/accessible/root",
    "--call=org.a11y.atspi.Registry=org.a11y.atspi.Socket.Unembed@/org/a11y/atspi/accessible/root",
    "--call=org.a11y.atspi.Registry=org.a11y.atspi.Registry.GetRegisteredEvents@/org/a11y/atspi/registry",
    "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetKeystrokeListeners@/org/a11y/atspi/registry/deviceeventcontroller",
    "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.GetDeviceEventListeners@/org/a11y/atspi/registry/deviceeventcontroller",
    "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersSync@/org/a11y/atspi/registry/deviceeventcontroller",
    "--call=org.a11y.atspi.Registry=org.a11y.atspi.DeviceEventController.NotifyListenersAsync@/org/a11y/atspi/registry/deviceeventcontroller",
    "--broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerRegistered@/org/a11y/atspi/registry",
    "--broadcast=org.a11y.atspi.Registry=org.a11y.atspi.Registry.EventListenerDeregistered@/org/a11y/atspi/registry",
];

/// One policy argument with the node that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The argument as `xdg-dbus-proxy` takes it, e.g. `--talk=org.a.B`.
    pub arg: OsString,
    /// Position in the instance config's `services` of the node that
    /// contributed it: the bus node for its own rules, the bundle's node
    /// for a bundle's. A repeat keeps the first node that asked.
    pub node: usize,
}

/// One bus the proxy filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Position in the instance config's `services` of the node that
    /// granted this bus. The address, the socket and the options that
    /// apply to them are that node's, as its rules are.
    pub node: usize,
    /// `xdg-dbus-proxy` policy arguments for this bus, deduplicated,
    /// explicit rules first and bundles after them.
    pub rules: Vec<Rule>,
}

/// Everything the launcher needs to run one instance's proxy. One process
/// serves every granted bus (`xdg-dbus-proxy(1)`: options apply to the
/// address they follow), so a plan exists as soon as one is granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The session bus, when `dbus` is granted.
    pub session: Option<Section>,
    /// The system bus, when `system-bus` is granted.
    pub system: Option<Section>,
    /// The session's accessibility bus, when `a11y` is granted. Its
    /// rules are [`A11Y_RULES`], never the config's: the node takes no
    /// children and the bus has no other safe subset.
    pub a11y: Option<Section>,
    /// Contents of `/.flatpak-info` for the proxy, and for the sandbox
    /// itself when `portals` is granted.
    pub flatpak_info: Vec<u8>,
    /// Whether the `portals` bundle was granted.
    pub portals: bool,
    /// `org.bubbler.<instance>`: the id portals file this sandbox's
    /// permissions and documents under.
    pub app_id: String,
}

impl Plan {
    /// The buses the proxy serves, in the order it is told to bind them: each socket's
    /// file name with the config node that granted it, so a failure names what to change.
    pub fn buses(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        if self.session.is_some() {
            out.push((SESSION_SOCKET, SESSION_NODE));
        }
        if self.system.is_some() {
            out.push((SYSTEM_SOCKET, SYSTEM_NODE));
        }
        if self.a11y.is_some() {
            out.push((A11Y_SOCKET, A11Y_NODE));
        }
        out
    }
}

/// The proxy plan for `services`, or `None` when no bus is granted and no
/// proxy runs at all. `a11y` is never the only bus: the parser refuses
/// the node without `dbus`. `instance` is a validated instance name.
pub fn plan(services: &[Service], instance: &str) -> Option<Plan> {
    let session = services.iter().enumerate().find_map(|(i, s)| match s {
        Service::Dbus { rules } => Some((i, rules)),
        _ => None,
    });
    let system = services.iter().enumerate().find_map(|(i, s)| match s {
        Service::SystemBus { rules } => Some((i, rules)),
        _ => None,
    });
    if session.is_none() && system.is_none() {
        return None;
    }
    let a11y = services.iter().position(|s| *s == Service::A11y);
    let portals = services
        .iter()
        .any(|s| matches!(s, Service::Portals { .. }));
    let session = session.map(|(node, explicit)| {
        let mut rules = explicit_rules(explicit, node);
        // Bundles are sets of session-bus rules; the system bus never
        // gets one, and its own list is the whole confinement.
        for (i, s) in services.iter().enumerate() {
            match s {
                Service::Portals { children } => {
                    for r in portal_rules(children) {
                        push(&mut rules, r, i);
                    }
                }
                Service::Notify | Service::Tray | Service::InputMethod | Service::Mpris { .. } => {
                    for r in grant_policies(s) {
                        push(&mut rules, render(&r), i);
                    }
                }
                // Its rules are on its own bus (`A11Y_RULES`), and that bus's address is
                // resolved before the sandbox starts rather than asked for from inside it.
                Service::A11y => {}
                // Listed rather than caught by a wildcard: a new bundle must be given
                // its rules here, and a wildcard would silently give it none.
                Service::Wayland(_)
                | Service::X11(_)
                | Service::Network { .. }
                | Service::Dri { .. }
                | Service::Pipewire { .. }
                | Service::Pulseaudio { .. }
                | Service::Gamepad { .. }
                | Service::Hidraw
                | Service::HomeShare { .. }
                | Service::PathShare { .. }
                | Service::EtcShare { .. }
                | Service::Dbus { .. }
                | Service::SystemBus { .. }
                | Service::AppRuntime { .. } => {}
                Service::Camera { .. } => {
                    for r in camera_rules() {
                        push(&mut rules, r, i);
                    }
                }
            }
        }
        Section { node, rules }
    });
    let system = system.map(|(node, explicit)| Section {
        node,
        rules: explicit_rules(explicit, node),
    });
    let a11y = a11y.map(|node| {
        let mut rules = Vec::new();
        for r in A11Y_RULES {
            push(&mut rules, (*r).to_owned(), node);
        }
        Section { node, rules }
    });
    Some(Plan {
        session,
        system,
        a11y,
        flatpak_info: flatpak_info(instance, portals),
        portals,
        app_id: app_id(instance),
    })
}

fn explicit_rules(rules: &[BusRule], node: usize) -> Vec<Rule> {
    let mut out = Vec::new();
    for rule in rules {
        push(&mut out, render(rule), node);
    }
    out
}

// The proxy takes repeats, but a deduplicated list is what the user can
// compare against the config.
fn push(rules: &mut Vec<Rule>, rule: String, node: usize) {
    let arg = OsString::from(rule);
    if !rules.iter().any(|r| r.arg == arg) {
        rules.push(Rule { arg, node });
    }
}

// The glued `--talk=<name>` form: a name may start with `-`, which a separated
// `--talk <name>` would turn into an option of its own.
fn render(rule: &BusRule) -> String {
    match rule {
        BusRule::See(n) => format!("--see={n}"),
        BusRule::Talk(n) => format!("--talk={n}"),
        BusRule::Own(n) => format!("--own={n}"),
        BusRule::Call(n, r) => format!("--call={n}={r}"),
        BusRule::Broadcast(n, r) => format!("--broadcast={n}={r}"),
    }
}

/// Application id of an instance: `org.bubbler.` and the instance name as
/// one trailing element. Every `.` in the name becomes `_`, and a leading digit is
/// prefixed.
pub fn app_id(instance: &str) -> String {
    let mut tail = instance.replace('.', "_");
    if tail.starts_with(|c: char| c.is_ascii_digit()) {
        tail.insert(0, '_');
    }
    format!("org.bubbler.{tail}")
}

/// The instance among `existing` whose [`app_id`] is `name`'s under another
/// name: the two would share portal permissions, forwarded documents and
/// the window app id.
pub fn app_id_twin<'a>(name: &str, existing: &'a [String]) -> Option<&'a str> {
    let id = app_id(name);
    existing
        .iter()
        .find(|other| *other != name && app_id(other) == id)
        .map(String::as_str)
}

/// Whether `id` is an application id xdg-desktop-portal accepts: at least
/// two `.`-separated non-empty elements of `[A-Za-z0-9_]`, `-` allowed
/// only in the last one, at most 255 bytes.
// Mirrors `xdp_is_valid_app_id` (xdg-desktop-portal, shared/xdp-utils.c).
// An id it rejects makes the portal refuse every operation of the sandbox.
pub fn is_valid_app_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 255 {
        return false;
    }
    let last = id.split('.').count() - 1;
    last >= 1
        && id.split('.').enumerate().all(|(i, element)| {
            !element.is_empty()
                && element
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || (i == last && b == b'-'))
        })
}

/// The `/.flatpak-info` a sandbox is identified by. Without `portals` the
/// proxy still gets the `[Application]` section, which is what makes
/// `xdg-dbus-proxy` treat the peer as a sandboxed app.
// An instance name is `[A-Za-z0-9._-]+`, so it cannot start a new key or
// section in this file.
pub fn flatpak_info(instance: &str, portals: bool) -> Vec<u8> {
    let mut s = format!("[Application]\nname={}\n", app_id(instance));
    if portals {
        s.push_str(&format!(
            "\n[Instance]\ninstance-id={}\n",
            flatpak_instance_id(instance)
        ));
    }
    s.into_bytes()
}

/// `bubbler-<instance>`: the `instance-id` portals look a sandbox up by.
/// Namespaced because the `.flatpak` directory is shared with flatpak,
/// whose own instance ids are plain numbers.
pub fn flatpak_instance_id(instance: &str) -> String {
    format!("bubbler-{instance}")
}

/// `$XDG_RUNTIME_DIR/.flatpak/bubbler-<instance>`: where xdg-desktop-portal
/// looks a sandboxed caller up, by the `instance-id` in its
/// `/.flatpak-info`. `instance` is a validated instance name.
pub fn flatpak_instance_dir(env: &Env, instance: &str) -> PathBuf {
    env.runtime_dir
        .join(FLATPAK_DIR)
        .join(flatpak_instance_id(instance))
}

/// The only directory the proxy sandbox may write to. The instance
/// directory above it is never handed to the proxy: it holds the control
/// socket, and reaching that socket means running commands in the app.
pub fn socket_dir(instance_runtime: &Path) -> PathBuf {
    instance_runtime.join("dbus")
}

/// Where the proxy creates one filtered socket, in [`socket_dir`]: the
/// one path the proxy sandbox can write to. `socket` is [`SESSION_SOCKET`],
/// [`SYSTEM_SOCKET`] or [`A11Y_SOCKET`].
pub fn proxy_bus_path(instance_runtime: &Path, socket: &str) -> PathBuf {
    socket_dir(instance_runtime).join(socket)
}

/// Where a sandbox's bus bind comes from: the socket after the launcher
/// has checked it and moved it out of [`socket_dir`]. The proxy cannot
/// reach this path, so nothing can be swapped for it once it is there.
pub fn app_bus_path(instance_runtime: &Path, socket: &str) -> PathBuf {
    instance_runtime.join(socket)
}

/// Host session bus socket: the `unix:path=` of `$DBUS_SESSION_BUS_ADDRESS`
/// when it is set, else `$XDG_RUNTIME_DIR/bus`. Unguarded, and crate-private for it:
/// outside this crate the session bus is reachable only through [`guarded_host_bus`].
pub(crate) fn host_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    Ok(address_path(
        env.dbus_address.as_deref(),
        "DBUS_SESSION_BUS_ADDRESS",
        "dbus",
    )?
    .unwrap_or_else(|| env.runtime_dir.join("bus")))
}

/// The host session bus address, refused when it lands in bubbler's own
/// runtime directory. A run and a dry run both resolve the bus through
/// here; the unguarded resolver behind it is crate-private.
pub fn guarded_host_bus(host: &dyn Host, env: &Env) -> Result<PathBuf, LaunchError> {
    outside_our_runtime(host, env, SESSION_NODE, host_bus(env)?)
}

/// The host system bus address, refused when it lands in bubbler's own
/// runtime directory. The unguarded resolver behind it is crate-private.
pub fn guarded_host_system_bus(host: &dyn Host, env: &Env) -> Result<PathBuf, LaunchError> {
    outside_our_runtime(host, env, SYSTEM_NODE, host_system_bus(env)?)
}

/// The host accessibility bus address, refused when it lands in
/// bubbler's own runtime directory. The bus is asked for its address
/// first, as a run does; the unguarded resolver is crate-private.
pub fn guarded_host_a11y_bus(host: &dyn Host, env: &Env) -> Result<PathBuf, LaunchError> {
    outside_our_runtime(host, env, A11Y_NODE, host_a11y_bus(env)?)
}

// The resolved path is what comes back, so the caller stats and connects to
// the path this checked rather than to a name that can be repointed in between.
fn outside_our_runtime(
    host: &dyn Host,
    env: &Env,
    node: &'static str,
    path: PathBuf,
) -> Result<PathBuf, LaunchError> {
    let ours = resolve(host, &env.runtime_dir.join(RUNTIME_SUBDIR));
    let path = resolve(host, &path);
    if path.starts_with(&ours) {
        return Err(LaunchError::BadValue {
            service: node,
            reason: "the host bus address names a socket under bubbler's own runtime directory"
                .to_owned(),
        });
    }
    Ok(path)
}

// A bus socket need not exist yet, and the explanation of a run resolves before
// anything is created; what no lookup answers is folded lexically.
fn resolve(host: &dyn Host, path: &Path) -> PathBuf {
    if let Some(real) = host.canonicalize(path) {
        return lexical(&real);
    }
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => match host.canonicalize(dir) {
            Some(real) => lexical(&real).join(name),
            None => lexical(path),
        },
        _ => lexical(path),
    }
}

fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            // `pop` on a root or an empty path keeps it, which is the
            // same place `..` leads there.
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Host system bus socket: the `unix:path=` of `$DBUS_SYSTEM_BUS_ADDRESS`
/// when it is set, else [`SYSTEM_BUS_PATH`]. Unguarded, and crate-private for it:
/// outside this crate the system bus is reachable only through [`guarded_host_system_bus`].
pub(crate) fn host_system_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    Ok(address_path(
        env.dbus_system_address.as_deref(),
        "DBUS_SYSTEM_BUS_ADDRESS",
        "system-bus",
    )?
    .unwrap_or_else(|| PathBuf::from(SYSTEM_BUS_PATH)))
}

/// Host accessibility bus socket: the `unix:path=` of `$AT_SPI_BUS_ADDRESS` when the
/// session set one, else the address `org.a11y.Bus` answers `GetAddress` with on the
/// session bus. Unguarded; every failure stops the run instead of dropping the grant.
pub(crate) fn host_a11y_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    match address_path(
        env.at_spi_bus_address.as_deref(),
        "AT_SPI_BUS_ADDRESS",
        A11Y_NODE,
    )? {
        Some(path) => Ok(path),
        None => ask_a11y_bus(env),
    }
}

// Precondition: `a11y` is never granted without `dbus`, and both the run and the
// explanation resolve the session bus through `guarded_host_bus` before they reach this.
fn ask_a11y_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    let mut session = Session::connect(&host_bus(env)?).map_err(a11y_failure)?;
    let reply = session
        .call(
            "org.a11y.Bus",
            "/org/a11y/bus",
            "org.a11y.Bus",
            "GetAddress",
            "",
            &[],
            &[],
        )
        .map_err(a11y_failure)?;
    let [Value::Str(address)] = reply.as_slice() else {
        return Err(LaunchError::A11y(
            "org.a11y.Bus answered GetAddress with no address".to_owned(),
        ));
    };
    // The address is not echoed: it is host input, and an address may
    // hold anything.
    unix_path(OsStr::new(address.as_str())).map_err(|fault| {
        LaunchError::A11y(
            match fault {
                AddressFault::NoPath => {
                    "the address org.a11y.Bus returned is not a `unix:path=<path>` socket"
                }
                AddressFault::BadEscape => {
                    "the address org.a11y.Bus returned has a bad `%XX` escape in its `unix:path=`"
                }
            }
            .to_owned(),
        )
    })
}

fn a11y_failure(e: WireError) -> LaunchError {
    LaunchError::A11y(match e {
        // The name is the half that matters, and a trailing colon would promise a
        // sentence that is not there.
        WireError::Remote { name, message } if message.is_empty() => {
            format!("org.a11y.Bus.GetAddress failed: {}", bus_note(&name))
        }
        WireError::Remote { name, message } => format!(
            "org.a11y.Bus.GetAddress failed: {}: {}",
            bus_note(&name),
            bus_note(&message)
        ),
        other => format!(
            "asking the session bus for the accessibility bus: {}",
            bus_note(&other.to_string())
        ),
    })
}

// Text bubbler did not write: the first line of it, with the control characters
// shown rather than sent to whatever terminal reads the message.
fn bus_note(text: &str) -> String {
    // A D-Bus error name and its text fit; a peer with more to say does not get
    // to fill the terminal with it.
    const KEPT: usize = 200;

    let line = text.split('\n').next().unwrap_or_default();
    let rendered = String::from_utf8(crate::safe_text::render(line.as_bytes()))
        .expect("the rendering escapes every byte that is not text");
    let text = rendered.trim();
    match text.char_indices().nth(KEPT) {
        Some((cut, _)) => format!("{}...", &text[..cut]),
        None => text.to_owned(),
    }
}

// A transport bubbler cannot bind is an error rather than the default path: the session is
// on the bus the variable names, and proxying another one would filter the wrong bus.
fn address_path(
    address: Option<&OsStr>,
    var: &'static str,
    service: &'static str,
) -> Result<Option<PathBuf>, LaunchError> {
    let Some(address) = address.filter(|a| !a.is_empty()) else {
        return Ok(None);
    };
    // The value itself is not echoed: it is host input.
    let reason = match unix_path(address) {
        Ok(p) => return Ok(Some(p)),
        Err(AddressFault::NoPath) => format!(
            "${var} names no Unix socket path; bubbler can proxy only a \
             `unix:path=<path>` address"
        ),
        Err(AddressFault::BadEscape) => format!(
            "${var} has a bad `%XX` escape in its `unix:path=`; a `%` must be \
             followed by two hex digits"
        ),
    };
    Err(LaunchError::BadValue { service, reason })
}

#[derive(Debug, PartialEq, Eq)]
enum AddressFault {
    NoPath,
    BadEscape,
}

// Keys of which a `unix:` entry names exactly one (the D-Bus
// specification, "Server Addresses").
const UNIX_SOCKET_KEYS: [&[u8]; 5] = [b"path", b"abstract", b"runtime", b"dir", b"tmpdir"];

fn unix_path(address: &OsStr) -> Result<PathBuf, AddressFault> {
    let mut fault = AddressFault::NoPath;
    let entries = address.as_bytes().split(|b| *b == b';');
    for pairs in entries.filter_map(|entry| entry.strip_prefix(b"unix:")) {
        let mut socket_keys = pairs.split(|b| *b == b',').filter_map(|pair| {
            let at = pair.iter().position(|b| *b == b'=')?;
            let key = &pair[..at];
            UNIX_SOCKET_KEYS
                .contains(&key)
                .then_some((key, &pair[at + 1..]))
        });
        let (Some((b"path", value)), None) = (socket_keys.next(), socket_keys.next()) else {
            continue;
        };
        match unescape_address_value(value) {
            Some(path) if !path.is_empty() && !path.contains(&0) => {
                return Ok(PathBuf::from(OsString::from_vec(path)));
            }
            Some(_) => {}
            None => fault = AddressFault::BadEscape,
        }
    }
    Err(fault)
}

fn unescape_address_value(value: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some((&b, tail)) = rest.split_first() {
        if b != b'%' {
            out.push(b);
            rest = tail;
            continue;
        }
        let hex = tail
            .get(..2)
            .filter(|h| h.iter().all(u8::is_ascii_hexdigit))?;
        out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
        rest = &tail[2..];
    }
    Some(out)
}

fn escape_address_value(value: &[u8]) -> OsString {
    let mut out = Vec::with_capacity(value.len());
    for &b in value {
        if b.is_ascii_alphanumeric() || b"-_/.\\*".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02x}").as_bytes());
        }
    }
    OsString::from_vec(out)
}

/// The proxy binary to run: `$BUBBLER_DBUS_PROXY` when it is set, else
/// [`PROXY_BIN`] from `PATH` inside the proxy sandbox.
pub fn proxy_program(env: &Env) -> PathBuf {
    env.proxy_override
        .clone()
        .unwrap_or_else(|| PathBuf::from(PROXY_BIN))
}

/// The host socket of each bus a plan grants, as the launcher resolved
/// them. `None` leaves that bus out of the proxy's command, and the sandbox's bind of it
/// then fails, since the proxy never creates it.
// One named value rather than three arguments of one type: which socket serves which
// bus is the whole of the confinement.
#[derive(Debug, Clone, Copy)]
pub struct HostBuses<'a> {
    /// Session bus, from [`guarded_host_bus`].
    pub session: Option<&'a Path>,
    /// System bus, from [`guarded_host_system_bus`].
    pub system: Option<&'a Path>,
    /// Accessibility bus, from [`guarded_host_a11y_bus`].
    pub a11y: Option<&'a Path>,
}

/// Argv of the proxy itself, run inside its own sandbox: it connects to
/// each granted host bus, serves the filtered socket for it in the
/// `dbus/` subdirectory of `instance_runtime` and exits when `ready_fd`
/// is closed (`xdg-dbus-proxy(1)`).
pub fn proxy_command(
    program: &Path,
    plan: &Plan,
    buses: HostBuses<'_>,
    instance_runtime: &Path,
    log: bool,
    ready_fd: &OsStr,
) -> Vec<OsString> {
    proxy_command_nodes(program, plan, buses, instance_runtime, log, ready_fd)
        .into_iter()
        .map(|(arg, _)| arg)
        .collect()
}

/// [`proxy_command`] with the node behind each element: a rule carries
/// the position in the config's `services` of the node that asked for it,
/// and the proxy's own invocation carries none.
pub fn proxy_command_nodes(
    program: &Path,
    plan: &Plan,
    buses: HostBuses<'_>,
    instance_runtime: &Path,
    log: bool,
    ready_fd: &OsStr,
) -> Vec<(OsString, Option<usize>)> {
    let mut fd = OsString::from("--fd=");
    fd.push(ready_fd);
    let mut argv = vec![(program.as_os_str().to_os_string(), None), (fd, None)];
    for (section, host, socket) in [
        (plan.session.as_ref(), buses.session, SESSION_SOCKET),
        (plan.system.as_ref(), buses.system, SYSTEM_SOCKET),
        (plan.a11y.as_ref(), buses.a11y, A11Y_SOCKET),
    ] {
        let (Some(section), Some(host)) = (section, host) else {
            continue;
        };
        let mut address = OsString::from("unix:path=");
        address.push(escape_address_value(host.as_os_str().as_bytes()));
        // An option applies to the address before it, so each bus's address and socket come
        // first. These carry the bus's granting node, so an explanation reads one bus at a time.
        let node = Some(section.node);
        argv.push((address, node));
        argv.push((
            proxy_bus_path(instance_runtime, socket).into_os_string(),
            node,
        ));
        argv.push((OsString::from("--filter"), node));
        if log {
            argv.push((OsString::from("--log"), node));
        }
        argv.extend(section.rules.iter().map(|r| (r.arg.clone(), Some(r.node))));
    }
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WaylandMode;
    use crate::dbus_wire::testing::*;
    use std::thread::JoinHandle;

    fn strs(v: &[OsString]) -> Vec<&str> {
        v.iter()
            .map(|s| s.to_str().expect("test rules are ASCII"))
            .collect()
    }

    fn args(rules: &[Rule]) -> Vec<&str> {
        rules
            .iter()
            .map(|r| r.arg.to_str().expect("test rules are ASCII"))
            .collect()
    }

    /// The session bus's rules; the plan under test grants that bus.
    fn session(p: &Plan) -> Vec<&str> {
        args(&p.session.as_ref().expect("dbus is granted").rules)
    }

    /// The system bus's rules; the plan under test grants that bus.
    fn system(p: &Plan) -> Vec<&str> {
        args(&p.system.as_ref().expect("system-bus is granted").rules)
    }

    fn env() -> Env {
        Env {
            home: "/home/user".into(),
            data_home: "/home/user/.local/share".into(),
            config_home: "/home/user/.config".into(),
            config_dirs: Vec::new(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            at_spi_bus_address: None,
            dbus_log: false,
            net_proxy_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            pw_dump_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
        }
    }

    #[test]
    fn no_bus_means_no_proxy() {
        assert!(plan(&[Service::Wayland(WaylandMode::default())], "t").is_none());
        assert!(plan(&[], "t").is_none());
    }

    #[test]
    fn firefox_like_rules_are_bundles_in_service_order() {
        let p = plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::Portals {
                    children: Vec::new(),
                },
                Service::Notify,
                Service::Mpris {
                    name: "firefox.*".into(),
                },
            ],
            "ff",
        )
        .expect("dbus is granted");
        // The bundle's own content is `portal_rules`' contract, checked
        // below; what this test owns is the order services contribute in.
        let mut expected = portal_rules(&[]);
        expected.push("--talk=org.freedesktop.Notifications".to_owned());
        expected.push("--own=org.mpris.MediaPlayer2.firefox.*".to_owned());
        assert_eq!(
            session(&p),
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert!(p.portals);
        assert_eq!(
            p.flatpak_info,
            b"[Application]\nname=org.bubbler.ff\n\n[Instance]\ninstance-id=bubbler-ff\n".to_vec()
        );
    }

    /// The bare bundle names every interface it opens: no
    /// `--call=org.freedesktop.portal.*=*`, which was ScreenCast,
    /// RemoteDesktop, InputCapture, GlobalShortcuts, Background,
    /// DynamicLauncher, Location and Secret behind one node.
    #[test]
    fn the_bare_bundle_opens_the_safe_interfaces_only() {
        let rules = portal_rules(&[]);
        assert!(rules.contains(&"--call=org.freedesktop.portal.Documents=*".to_owned()));
        assert!(rules.contains(&"--broadcast=org.freedesktop.portal.Documents=*".to_owned()));
        assert!(
            rules.contains(
                &"--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.FileChooser.*\
              @/org/freedesktop/portal/desktop"
                    .to_owned()
            )
        );
        assert!(
            rules.contains(
                &"--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*\
              @/org/freedesktop/portal/desktop/request/*"
                    .to_owned()
            )
        );
        assert!(
            rules.contains(
                &"--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*\
              @/org/freedesktop/portal/desktop/session/*"
                    .to_owned()
            )
        );
        // Request and Session objects are per-call and per-session, never
        // the desktop object itself, so a call needs the same subtree
        // rule the broadcasts above already have — without it
        // Request.Close()/Session.Close() are silently dropped.
        for rule in [
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*\
             @/org/freedesktop/portal/desktop/request/*",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*\
             @/org/freedesktop/portal/desktop/session/*",
        ] {
            assert!(rules.contains(&rule.to_owned()), "{rule}");
        }
        // GDBusProxy/libportal call Properties.Get(All) on the desktop
        // object when a client constructs its proxy; without these two
        // every GTK portal client breaks on the first property read.
        for rule in [
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.Get\
             @/org/freedesktop/portal/desktop",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.GetAll\
             @/org/freedesktop/portal/desktop",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Introspectable.Introspect\
             @/org/freedesktop/portal/desktop",
        ] {
            assert!(rules.contains(&rule.to_owned()), "{rule}");
        }
        // Gone: the wildcards, every `--talk`, and a Request/Session rule
        // at the bare desktop path — no object of either kind is ever
        // served there, so such a rule would match nothing bwrap sends.
        // A `--talk` of a name this function also filters puts that name
        // above FILTERED on the proxy's ladder, which forwards every call
        // to it and makes every rule below inert.
        for gone in [
            "--talk=org.freedesktop.portal.Desktop",
            "--talk=org.freedesktop.portal.Documents",
            "--talk=org.freedesktop.portal.FileChooser",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.Set\
             @/org/freedesktop/portal/desktop",
            "--call=org.freedesktop.portal.*=*",
            "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*\
             @/org/freedesktop/portal/desktop",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*\
             @/org/freedesktop/portal/desktop",
            "--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*\
             @/org/freedesktop/portal/desktop",
            "--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*\
             @/org/freedesktop/portal/desktop",
        ] {
            assert!(!rules.iter().any(|r| r == gone), "{gone}");
        }
        // And none of the interfaces a child is for.
        for iface in ["ScreenCast", "RemoteDesktop", "GlobalShortcuts", "Secret"] {
            assert!(
                !rules.iter().any(|r| r.contains(&format!(".{iface}."))),
                "{iface} is granted by the bare node"
            );
        }
    }

    /// Each child adds its own interfaces and nothing else.
    #[test]
    fn a_child_adds_the_interfaces_it_is_named_for() {
        let bare = portal_rules(&[]);
        let with = portal_rules(&[Portal::ScreenCast]);
        let added: Vec<&String> = with.iter().filter(|r| !bare.contains(r)).collect();
        assert_eq!(
            added,
            [
                "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.ScreenCast.*\
                 @/org/freedesktop/portal/desktop",
                "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Screenshot.*\
                 @/org/freedesktop/portal/desktop",
                "--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.ScreenCast.*\
                 @/org/freedesktop/portal/desktop",
                "--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Screenshot.*\
                 @/org/freedesktop/portal/desktop",
            ]
        );
        // A child adds interfaces; it does not touch the Request/Session
        // subtree rules or the Properties rules, which are the same for
        // every `portals` grant regardless of its children.
        for rule in [
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*\
             @/org/freedesktop/portal/desktop/request/*",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*\
             @/org/freedesktop/portal/desktop/session/*",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.Get\
             @/org/freedesktop/portal/desktop",
            "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.GetAll\
             @/org/freedesktop/portal/desktop",
        ] {
            assert!(with.contains(&rule.to_owned()), "{rule}");
        }
    }

    /// `camera` used to ride on the wildcard; with the wildcard gone it
    /// carries the Camera interface itself.
    #[test]
    fn camera_carries_its_own_interface_now() {
        let p = plan(
            &[
                Service::Dbus { rules: Vec::new() },
                Service::Portals {
                    children: Vec::new(),
                },
                Service::Camera { nodes: false },
            ],
            "inst",
        )
        .unwrap();
        let args: Vec<String> = p
            .session
            .unwrap()
            .rules
            .iter()
            .map(|r| r.arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.contains(
                &"--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Camera.*\
              @/org/freedesktop/portal/desktop"
                    .to_owned()
            )
        );
        // Without `camera` the interface is not open.
        let p = plan(
            &[
                Service::Dbus { rules: Vec::new() },
                Service::Portals {
                    children: Vec::new(),
                },
            ],
            "inst",
        )
        .unwrap();
        assert!(
            !p.session
                .unwrap()
                .rules
                .iter()
                .any(|r| r.arg.to_string_lossy().contains("portal.Camera."))
        );
    }

    /// Every rule names the node that asked for it, which is what
    /// `--explain --proxy` groups them under.
    #[test]
    fn each_rule_carries_the_node_that_contributed_it() {
        let services = [
            Service::Wayland(WaylandMode::default()),
            Service::Dbus {
                rules: vec![BusRule::Own("org.a.B".into())],
            },
            Service::Notify,
            Service::SystemBus {
                rules: vec![BusRule::Talk("org.freedesktop.UDisks2".into())],
            },
        ];
        let p = plan(&services, "t").expect("dbus is granted");
        let nodes: Vec<(&str, usize)> = p
            .session
            .as_ref()
            .expect("dbus is granted")
            .rules
            .iter()
            .map(|r| (r.arg.to_str().expect("ASCII"), r.node))
            .collect();
        assert_eq!(
            nodes,
            vec![
                ("--own=org.a.B", 1),
                ("--talk=org.freedesktop.Notifications", 2),
            ]
        );
        let system = &p.system.as_ref().expect("system-bus is granted").rules;
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].node, 3);
        // A rule two nodes ask for keeps the first that did.
        let p = plan(
            &[
                Service::Dbus {
                    rules: vec![BusRule::Talk("org.freedesktop.Notifications".into())],
                },
                Service::Notify,
            ],
            "t",
        )
        .expect("dbus is granted");
        let rules = &p.session.as_ref().expect("dbus is granted").rules;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].node, 0);
    }

    #[test]
    fn tray_grants_only_the_status_notifier_watcher() {
        let p =
            plan(&[Service::Dbus { rules: vec![] }, Service::Tray], "t").expect("dbus is granted");
        assert_eq!(session(&p), vec!["--talk=org.kde.StatusNotifierWatcher"]);
        assert!(p.system.is_none());
        assert!(!p.portals);
    }

    /// The two sandboxed portal names and nothing else: the daemons' own
    /// names carry their configuration interfaces, which this is not.
    #[test]
    fn input_method_talks_the_two_portal_names_only() {
        let p = plan(
            &[Service::Dbus { rules: vec![] }, Service::InputMethod],
            "t",
        )
        .expect("dbus is granted");
        assert_eq!(
            session(&p),
            vec![
                "--talk=org.freedesktop.portal.Fcitx",
                "--talk=org.freedesktop.portal.IBus"
            ]
        );
        let rules = &p.session.as_ref().expect("dbus is granted").rules;
        assert!(rules.iter().all(|r| r.node == 1));
        // The rules are the whole grant: no bus of its own.
        assert!(p.a11y.is_none());
    }

    /// The accessibility bus is a section of its own, with the fixed
    /// rule set and nothing of the config's in it.
    #[test]
    fn a11y_is_a_third_bus_with_the_fixed_allowlist() {
        let p =
            plan(&[Service::Dbus { rules: vec![] }, Service::A11y], "t").expect("dbus is granted");
        let a = p.a11y.as_ref().expect("a11y is granted");
        assert_eq!(a.node, 1);
        assert!(a.rules.iter().all(|r| r.node == 1));
        let rules = args(&a.rules);
        assert_eq!(rules, A11Y_RULES);
        // What the grant is for: the app registers itself with the
        // registry and reads back what is registered.
        assert!(rules.iter().any(|r| r.contains("Socket.Embed@")));
        // What the same bus would otherwise offer it: every keystroke of
        // every accessible application, and input injection into the
        // session.
        assert!(!rules.iter().any(|r| {
            r.contains("RegisterKeystrokeListener")
                || r.contains("GenerateKeyboardEvent")
                || r.contains("GenerateMouseEvent")
                || r.contains("RegisterEvent")
        }));
        // Nothing of it reaches the session bus.
        assert!(session(&p).is_empty());
        assert_eq!(
            p.buses(),
            vec![(SESSION_SOCKET, SESSION_NODE), (A11Y_SOCKET, A11Y_NODE)]
        );
    }

    #[test]
    fn explicit_rules_come_first_and_are_deduplicated() {
        let p = plan(
            &[
                Service::Notify,
                Service::Dbus {
                    rules: vec![
                        BusRule::See("a.b".into()),
                        BusRule::Talk("org.freedesktop.Notifications".into()),
                        BusRule::See("a.b".into()),
                    ],
                },
            ],
            "t",
        )
        .expect("dbus is granted");
        assert_eq!(
            session(&p),
            vec!["--see=a.b", "--talk=org.freedesktop.Notifications"]
        );
    }

    #[test]
    fn every_rule_variant_has_a_glued_form() {
        let p = plan(
            &[Service::Dbus {
                rules: vec![
                    BusRule::See("a.b".into()),
                    BusRule::Talk("-c.d".into()),
                    BusRule::Own("e.f".into()),
                    BusRule::Call("g.h".into(), "i.j@/k".into()),
                    BusRule::Broadcast("l.m".into(), "@/n/*".into()),
                ],
            }],
            "t",
        )
        .expect("dbus is granted");
        assert_eq!(
            session(&p),
            vec![
                "--see=a.b",
                "--talk=-c.d",
                "--own=e.f",
                "--call=g.h=i.j@/k",
                "--broadcast=l.m=@/n/*",
            ]
        );
    }

    #[test]
    fn an_app_id_is_one_the_portal_accepts_however_the_instance_is_named() {
        for (instance, id) in [
            ("t", "org.bubbler.t"),
            ("ff", "org.bubbler.ff"),
            ("my.app", "org.bubbler.my_app"),
            ("a_b.c-d", "org.bubbler.a_b_c-d"),
            ("2fa", "org.bubbler._2fa"),
            (".hidden", "org.bubbler._hidden"),
            ("..", "org.bubbler.__"),
        ] {
            assert_eq!(app_id(instance), id, "{instance}");
            assert!(is_valid_app_id(&app_id(instance)), "{instance}");
        }
    }

    #[test]
    fn an_app_id_twin_is_another_name_with_the_same_app_id() {
        let names = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        for (name, existing, twin) in [
            ("my_app", names(&["ff", "my.app"]), Some("my.app")),
            ("my.app", names(&["my_app"]), Some("my_app")),
            ("_2fa", names(&["2fa"]), Some("2fa")),
            ("2fa", names(&["_2fa"]), Some("_2fa")),
            ("_hidden", names(&[".hidden"]), Some(".hidden")),
            ("my.app", names(&["my.app"]), None),
            ("my-app", names(&["my.app", "my_app2", "ff"]), None),
            ("ff", names(&[]), None),
        ] {
            assert_eq!(app_id_twin(name, &existing), twin, "{name} {existing:?}");
        }
    }

    #[test]
    fn the_app_id_grammar_is_the_one_xdg_desktop_portal_checks() {
        for ok in [
            "a.b",
            "org.bubbler.t",
            "org.bubbler.2t",
            "org.bubbler.a-b",
            "a.b.c_d",
            "org.bubbler._",
            &format!("a.{}", "x".repeat(253)),
        ] {
            assert!(is_valid_app_id(ok), "{ok}");
        }
        // The last two are what an instance name with a dash and a dot,
        // or with a leading dot, used to produce.
        for no in [
            "",
            "a",
            "a.",
            ".a",
            "a..b",
            "org.bubbler.a b",
            "a.b/c",
            "a.b\u{e9}",
            &format!("a.{}", "x".repeat(254)),
            "org.bubbler.my-app.v2",
            "org.bubbler..hidden",
        ] {
            assert!(!is_valid_app_id(no), "{no}");
        }
    }

    #[test]
    fn without_portals_the_flatpak_info_is_the_application_section_only() {
        let p = plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        assert!(p.session.is_some() && p.system.is_none());
        assert!(!p.portals);
        assert_eq!(
            p.flatpak_info,
            b"[Application]\nname=org.bubbler.t\n".to_vec()
        );
    }

    #[test]
    fn portals_look_the_instance_up_under_the_runtime_dir() {
        // Namespaced: flatpak names its own instances in the same
        // directory, with plain numbers.
        assert_eq!(
            flatpak_instance_dir(&env(), "t"),
            PathBuf::from("/run/user/1000/.flatpak/bubbler-t")
        );
        assert_eq!(
            flatpak_instance_dir(&env(), "t").join(BWRAPINFO),
            PathBuf::from("/run/user/1000/.flatpak/bubbler-t/bwrapinfo.json")
        );
    }

    #[test]
    fn host_bus_prefers_the_address_and_falls_back_to_the_runtime_dir() {
        let mut e = env();
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/run/user/1000/bus"));
        e.dbus_address = Some("unix:path=/tmp/other,guid=deadbeef".into());
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/tmp/other"));
        // An unset variable and an empty one both mean "wherever the bus
        // usually is".
        e.dbus_address = Some("".into());
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/run/user/1000/bus"));
        // A transport that names no socket is refused: proxying the
        // default socket instead would be a bus the session is not on.
        for bad in [
            "tcp:host=localhost,port=1",
            "unix:abstract=/x",
            "unix:path=",
        ] {
            e.dbus_address = Some(bad.into());
            let Err(LaunchError::BadValue { service, reason }) = host_bus(&e) else {
                panic!("{bad} was accepted");
            };
            assert_eq!(service, "dbus");
            assert!(reason.contains("DBUS_SESSION_BUS_ADDRESS"), "{reason}");
        }
    }

    /// The guard hands back the path it checked, so what a run stats
    /// and what the proxy connects to is the socket the comparison was
    /// made on rather than the name the address reached it by.
    #[test]
    fn a_guarded_bus_path_comes_back_resolved() {
        use crate::host::fake::FakeHost;
        let mut e = env();
        e.dbus_address = Some("unix:path=/run/user/1000/link/bus".into());
        let elsewhere = FakeHost::default().link("/run/user/1000/link", "/run/user/1000/real");
        assert_eq!(
            guarded_host_bus(&elsewhere, &e).unwrap(),
            PathBuf::from("/run/user/1000/real/bus")
        );
        // The same address is refused when the link ends in bubbler's
        // own directory: the name it took to get there is not what is
        // compared.
        let ours = FakeHost::default().link("/run/user/1000/link", "/run/user/1000/bubbler/t");
        assert!(
            matches!(
                guarded_host_bus(&ours, &e),
                Err(LaunchError::BadValue {
                    service: SESSION_NODE,
                    ..
                })
            ),
            "the link into bubbler's own directory was accepted"
        );
    }

    #[test]
    fn the_first_unix_entry_naming_a_path_in_an_address_list_is_taken() {
        assert_eq!(
            unix_path(OsStr::new(
                "tcp:host=localhost,port=1;unix:abstract=/x;unix:path=/a;unix:path=/b"
            )),
            Ok(PathBuf::from("/a"))
        );
    }

    #[test]
    fn an_address_key_may_come_after_the_path_or_before_it() {
        assert_eq!(
            unix_path(OsStr::new("unix:guid=deadbeef,path=/x")),
            Ok(PathBuf::from("/x"))
        );
    }

    #[test]
    fn a_path_value_is_unescaped() {
        assert_eq!(
            unix_path(OsStr::new("unix:path=/run/a%2cb%3Bc%25d%20e%ff")),
            Ok(PathBuf::from(OsStr::from_bytes(b"/run/a,b;c%d e\xff")))
        );
        for bad in ["unix:path=/x%", "unix:path=/x%2", "unix:path=/x%zz"] {
            assert_eq!(
                unix_path(OsStr::new(bad)),
                Err(AddressFault::BadEscape),
                "{bad}"
            );
        }
        assert_eq!(
            unix_path(OsStr::new("unix:path=%00")),
            Err(AddressFault::NoPath)
        );
    }

    #[test]
    fn an_entry_naming_more_than_one_socket_key_is_passed_over() {
        let mut e = env();
        for (address, want) in [
            ("unix:path=/a,abstract=/b;unix:path=/c", Some("/c")),
            ("unix:path=/a,path=/b;unix:path=/c", Some("/c")),
            ("unix:abstract=/b,path=/a", None),
        ] {
            e.dbus_address = Some(address.into());
            assert_eq!(host_bus(&e).ok(), want.map(PathBuf::from), "{address}");
        }
    }

    #[test]
    fn a_bad_escape_is_passed_over_and_named_when_nothing_else_is_usable() {
        let mut e = env();
        e.dbus_address = Some("unix:path=/x%zz;unix:path=/b".into());
        assert_eq!(host_bus(&e).ok(), Some(PathBuf::from("/b")));
        for bad in ["unix:path=/x%zz", "unix:path=/x%2;tcp:host=h,port=1"] {
            e.dbus_address = Some(bad.into());
            let Err(LaunchError::BadValue { reason, .. }) = host_bus(&e) else {
                panic!("{bad} was accepted");
            };
            assert!(reason.contains("escape"), "{bad}: {reason}");
        }
    }

    #[test]
    fn an_abstract_address_alone_is_still_refused() {
        let mut e = env();
        e.dbus_address = Some("unix:guid=deadbeef,abstract=/x".into());
        let Err(LaunchError::BadValue { reason, .. }) = host_bus(&e) else {
            panic!("an abstract address was accepted");
        };
        assert!(reason.contains("`unix:path=<path>`"), "{reason}");
    }

    #[test]
    fn the_proxy_address_escapes_the_path_so_it_parses_back_to_it() {
        let p = plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        let host = Path::new(OsStr::from_bytes(b"/run/a,b;c%d=e f\xff/A-z_0.9*\\bus"));
        let argv = proxy_command(
            Path::new(PROXY_BIN),
            &p,
            HostBuses {
                session: Some(host),
                system: None,
                a11y: None,
            },
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        assert_eq!(
            argv[2],
            OsString::from("unix:path=/run/a%2cb%3bc%25d%3de%20f%ff/A-z_0.9*\\bus")
        );
        assert_eq!(unix_path(&argv[2]).ok().as_deref(), Some(host));
    }

    #[test]
    fn proxy_command_is_the_documented_invocation() {
        let p = plan(&[Service::Dbus { rules: vec![] }, Service::Notify], "t")
            .expect("dbus is granted");
        let argv = proxy_command(
            Path::new(PROXY_BIN),
            &p,
            HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: None,
                a11y: None,
            },
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        // The session-only invocation is what it was before the system
        // bus existed: a config without `system-bus` runs the same proxy.
        assert_eq!(
            strs(&argv),
            vec![
                "xdg-dbus-proxy",
                "--fd=4",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "--talk=org.freedesktop.Notifications",
            ]
        );
        let logged = proxy_command(
            Path::new(PROXY_BIN),
            &p,
            HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: None,
                a11y: None,
            },
            Path::new("/run/user/1000/bubbler/t"),
            true,
            OsStr::new("4"),
        );
        assert_eq!(logged[5], OsString::from("--log"));
    }

    /// One process, three buses: each address is followed by the socket
    /// it is served on, its own `--filter` and the rules of that bus
    /// alone. An option applies to the address before it
    /// (`xdg-dbus-proxy(1)`), so the nine accessibility rules standing
    /// after the third address are what the application may ask the
    /// AT-SPI registry; the same nine after the session address would
    /// name a session-bus service and leave the accessibility bus
    /// filtered by nothing.
    #[test]
    fn the_a11y_bus_is_a_third_address_and_its_rules_follow_its_own_filter() {
        let p = plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
                },
                Service::A11y,
            ],
            "t",
        )
        .expect("three buses are granted");
        let argv = proxy_command(
            Path::new(PROXY_BIN),
            &p,
            HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: Some(Path::new(SYSTEM_BUS_PATH)),
                a11y: Some(Path::new("/run/user/1000/at-spi/bus_0")),
            },
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        let mut expected = vec![
            "xdg-dbus-proxy",
            "--fd=4",
            "unix:path=/run/user/1000/bus",
            "/run/user/1000/bubbler/t/dbus/bus",
            "--filter",
            "unix:path=/run/dbus/system_bus_socket",
            "/run/user/1000/bubbler/t/dbus/system",
            "--filter",
            "--talk=org.freedesktop.UPower",
            "unix:path=/run/user/1000/at-spi/bus_0",
            "/run/user/1000/bubbler/t/dbus/a11y",
            "--filter",
        ];
        expected.extend_from_slice(A11Y_RULES);
        let s = strs(&argv);
        assert_eq!(s, expected);
        let third = s
            .iter()
            .position(|a| *a == "unix:path=/run/user/1000/at-spi/bus_0")
            .expect("the third address is in the argv");
        assert!(
            s[..third].iter().all(|a| !a.contains("org.a11y.atspi")),
            "an accessibility rule applies to a bus before the a11y one: {s:?}"
        );
        // Every element of that bus is the `a11y` node's, rules included.
        let nodes = proxy_command_nodes(
            Path::new(PROXY_BIN),
            &p,
            HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: Some(Path::new(SYSTEM_BUS_PATH)),
                a11y: Some(Path::new("/run/user/1000/at-spi/bus_0")),
            },
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        let tail = &nodes[nodes.len() - (3 + A11Y_RULES.len())..];
        assert!(tail.iter().all(|(_, node)| *node == Some(2)), "{tail:?}");
    }

    /// A bus the caller resolved no socket for is left out rather than
    /// pointed at another one: an explanation of an argv builds the
    /// same command without a proxy running.
    #[test]
    fn an_a11y_section_without_a_host_socket_is_no_bus_at_all() {
        let p =
            plan(&[Service::Dbus { rules: vec![] }, Service::A11y], "t").expect("dbus is granted");
        let argv = proxy_command(
            Path::new(PROXY_BIN),
            &p,
            HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: None,
                a11y: None,
            },
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        assert_eq!(
            strs(&argv),
            vec![
                "xdg-dbus-proxy",
                "--fd=4",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
            ]
        );
    }

    /// Each bus's address, socket and options carry the node that granted
    /// that bus, and not the proxy's own invocation: an option applies to
    /// the address before it, so an explanation has to read one bus at a
    /// time rather than one `command` group holding both addresses.
    #[test]
    fn each_bus_pair_carries_the_node_that_granted_that_bus() {
        let p = plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::Notify,
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
                },
            ],
            "t",
        )
        .expect("both buses are granted");
        let argv = proxy_command_nodes(
            Path::new(PROXY_BIN),
            &p,
            HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: Some(Path::new(SYSTEM_BUS_PATH)),
                a11y: None,
            },
            Path::new("/run/user/1000/bubbler/t"),
            false,
            OsStr::new("4"),
        );
        let nodes: Vec<Option<usize>> = argv.iter().map(|(_, node)| *node).collect();
        assert_eq!(
            nodes,
            [
                None,    // xdg-dbus-proxy
                None,    // --fd=4
                Some(0), // unix:path=<session bus>
                Some(0), // <the socket it is served on>
                Some(0), // --filter
                Some(1), // --talk=org.freedesktop.Notifications
                Some(2), // unix:path=<system bus>
                Some(2),
                Some(2), // --filter
                Some(2), // --talk=org.freedesktop.UPower
            ]
        );
    }

    #[test]
    fn the_system_bus_alone_is_a_plan_and_a_proxy_of_its_own() {
        let p = plan(
            &[Service::SystemBus {
                rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
            }],
            "t",
        )
        .expect("system-bus is granted");
        assert!(p.session.is_none());
        assert_eq!(system(&p), vec!["--talk=org.freedesktop.UPower"]);
        assert_eq!(p.buses(), vec![(SYSTEM_SOCKET, SYSTEM_NODE)]);
        // No session address and no session socket: the proxy is told
        // about the one bus the config granted.
        assert_eq!(
            strs(&proxy_command(
                Path::new(PROXY_BIN),
                &p,
                HostBuses {
                    session: None,
                    system: Some(Path::new(SYSTEM_BUS_PATH)),
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                false,
                OsStr::new("4"),
            )),
            vec![
                "xdg-dbus-proxy",
                "--fd=4",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--talk=org.freedesktop.UPower",
            ]
        );
    }

    #[test]
    fn both_buses_are_one_proxy_with_the_session_pair_first() {
        let p = plan(
            &[
                Service::Dbus {
                    rules: vec![BusRule::Talk("ca.desrt.dconf".into())],
                },
                Service::Notify,
                Service::SystemBus {
                    rules: vec![
                        BusRule::Talk("org.freedesktop.UPower".into()),
                        BusRule::See("org.freedesktop.UDisks2".into()),
                    ],
                },
            ],
            "t",
        )
        .expect("both buses are granted");
        // A bundle is a session-bus rule set; the system section holds
        // only what the node wrote.
        assert_eq!(
            session(&p),
            vec![
                "--talk=ca.desrt.dconf",
                "--talk=org.freedesktop.Notifications"
            ]
        );
        assert_eq!(
            system(&p),
            vec![
                "--talk=org.freedesktop.UPower",
                "--see=org.freedesktop.UDisks2"
            ]
        );
        assert_eq!(
            p.buses(),
            vec![(SESSION_SOCKET, SESSION_NODE), (SYSTEM_SOCKET, SYSTEM_NODE)]
        );
        assert_eq!(
            strs(&proxy_command(
                Path::new(PROXY_BIN),
                &p,
                HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: Some(Path::new(SYSTEM_BUS_PATH)),
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                true,
                OsStr::new("4"),
            )),
            vec![
                "xdg-dbus-proxy",
                "--fd=4",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "--log",
                "--talk=ca.desrt.dconf",
                "--talk=org.freedesktop.Notifications",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--log",
                "--talk=org.freedesktop.UPower",
                "--see=org.freedesktop.UDisks2",
            ]
        );
    }

    #[test]
    fn the_system_bus_address_falls_back_to_the_compiled_in_path() {
        let mut e = env();
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from(SYSTEM_BUS_PATH));
        e.dbus_system_address = Some("unix:path=/tmp/other,guid=deadbeef".into());
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from("/tmp/other"));
        e.dbus_system_address = Some("".into());
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from(SYSTEM_BUS_PATH));
        for bad in [
            "tcp:host=localhost,port=1",
            "unix:abstract=/x",
            "unix:path=",
        ] {
            e.dbus_system_address = Some(bad.into());
            let Err(LaunchError::BadValue { service, reason }) = host_system_bus(&e) else {
                panic!("{bad} was accepted");
            };
            assert_eq!(service, "system-bus");
            assert!(reason.contains("DBUS_SYSTEM_BUS_ADDRESS"), "{reason}");
        }
        // The two addresses are read from their own variables.
        e.dbus_address = Some("unix:path=/tmp/session".into());
        e.dbus_system_address = None;
        assert_eq!(host_bus(&e).unwrap(), PathBuf::from("/tmp/session"));
        assert_eq!(host_system_bus(&e).unwrap(), PathBuf::from(SYSTEM_BUS_PATH));
    }

    #[test]
    fn a_set_at_spi_address_is_the_answer_and_only_a_unix_path_is_one() {
        let mut e = env();
        // Not this host's a11y socket: had the variable been ignored and
        // the bus asked instead, the answer would be that one.
        e.at_spi_bus_address = Some("unix:path=/tmp/from-the-variable,guid=deadbeef".into());
        assert_eq!(
            host_a11y_bus(&e).unwrap(),
            PathBuf::from("/tmp/from-the-variable")
        );
        // `unix:abstract=` is what at-spi's own launcher may hand out,
        // and it names no file the proxy sandbox could bind.
        for bad in [
            "tcp:host=localhost,port=1",
            "unix:abstract=/x",
            "unix:path=",
        ] {
            e.at_spi_bus_address = Some(bad.into());
            let Err(LaunchError::BadValue { service, reason }) = host_a11y_bus(&e) else {
                panic!("{bad} was accepted");
            };
            assert_eq!(service, A11Y_NODE);
            assert!(reason.contains("AT_SPI_BUS_ADDRESS"), "{reason}");
        }
    }

    /// Header field codes and message types the fake bus below writes,
    /// from the D-Bus specification's "Header Fields" and "Message
    /// Format". `dbus_wire` keeps its own copies; a test that shares
    /// them would agree with the encoder by construction.
    /// The unique name the fake bus says `org.a11y.Bus` is held by.
    /// Every reply carries the `SENDER` a real bus stamps on it, since
    /// the client answers only to the owner of the name it called.
    const A11Y_OWNER: &str = ":1.42";

    /// A bus that answers the one call this module makes with `sig` and
    /// `body`, whatever they are.
    fn bus_answering(dir: &Path, sig: &'static str, body: Vec<Value>) -> (PathBuf, JoinHandle<()>) {
        fake_bus(dir, move |stream| {
            server_start(&stream);
            let call = server_awaiting(&stream, "GetAddress", A11Y_OWNER);
            server_reply(&stream, 2, call.serial, A11Y_OWNER, sig, &body);
        })
    }

    #[test]
    fn without_the_variable_the_bus_is_asked_with_one_fixed_call() {
        let tmp = tempfile::tempdir().unwrap();
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_awaiting(&stream, "GetAddress", A11Y_OWNER);
            // The whole of what bubbler asks the accessibility bus for:
            // one method on one object of one name. The destination is
            // the unique name the bus said owns `org.a11y.Bus`, so the
            // call and its reply are bound to that one connection.
            assert_eq!(
                call.texts(),
                vec![
                    (FIELD_PATH, "/org/a11y/bus".to_owned()),
                    (FIELD_DESTINATION, A11Y_OWNER.to_owned()),
                    (FIELD_INTERFACE, "org.a11y.Bus".to_owned()),
                    (FIELD_MEMBER, "GetAddress".to_owned()),
                ]
            );
            server_reply(
                &stream,
                2,
                call.serial,
                A11Y_OWNER,
                "s",
                &[Value::Str("unix:path=/run/user/1000/at-spi/bus".to_owned())],
            );
        });
        let mut e = env();
        e.runtime_dir = tmp.path().to_owned();
        // No `$DBUS_SESSION_BUS_ADDRESS` in this environment: the
        // question goes to the socket every other bus falls back to, so
        // an unset variable is no longer a lookup with no bus behind it.
        assert_eq!(bus, e.runtime_dir.join("bus"));
        assert_eq!(
            host_a11y_bus(&e).unwrap(),
            PathBuf::from("/run/user/1000/at-spi/bus")
        );
        server.join().unwrap();
    }

    #[test]
    fn the_session_bus_asked_is_the_one_the_env_names() {
        let tmp = tempfile::tempdir().unwrap();
        let named = tempfile::tempdir().unwrap();
        let (bus, server) = bus_answering(
            named.path(),
            "s",
            vec![Value::Str("unix:path=/tmp/from-the-named-bus".to_owned())],
        );
        let mut e = env();
        // Not the address this test process inherited, and not the
        // fallback either: the accessibility bus has to be the one
        // belonging to the session whose socket the `dbus` grant
        // proxies. Nothing listens in the runtime dir below, so an
        // answer at all is the proof.
        e.runtime_dir = tmp.path().to_owned();
        e.dbus_address = Some(OsString::from(format!("unix:path={}", bus.display())));
        assert_eq!(
            host_a11y_bus(&e).unwrap(),
            PathBuf::from("/tmp/from-the-named-bus")
        );
        server.join().unwrap();
    }

    #[test]
    fn a_bus_that_does_not_answer_is_a_launch_error_naming_the_step() {
        let tmp = tempfile::tempdir().unwrap();
        // What the bus answers when nothing owns the name. The message
        // is the bus's own text, so the control sequences in it are
        // shown rather than sent to whatever terminal reads the error.
        let (_bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_awaiting(&stream, "GetAddress", A11Y_OWNER);
            server_error(
                &stream,
                call.serial,
                A11Y_OWNER,
                "org.freedesktop.DBus.Error.ServiceUnknown",
                "The name is not activatable \x1b]52;c;aGk=\x07\nmore",
            );
        });
        let mut e = env();
        e.runtime_dir = tmp.path().to_owned();
        let Err(LaunchError::A11y(msg)) = host_a11y_bus(&e) else {
            panic!("a refused call was accepted");
        };
        server.join().unwrap();
        assert!(msg.contains("org.a11y.Bus.GetAddress failed"), "{msg}");
        assert!(
            msg.contains("org.freedesktop.DBus.Error.ServiceUnknown"),
            "{msg}"
        );
        assert!(msg.contains("^[]52;c;aGk=^G"), "{msg}");
        assert!(!msg.contains('\x1b'), "{msg}");
        assert!(!msg.contains("more"), "{msg}");
        assert!(
            LaunchError::A11y(msg)
                .to_string()
                .starts_with("finding the accessibility bus: "),
        );
    }

    #[test]
    fn a_bus_that_is_not_there_is_a_launch_error_naming_the_step() {
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env();
        // A directory with no socket in it, named with an escape
        // sequence: the path comes from the environment, and a failure
        // that echoed it raw would hand the terminal whatever it holds.
        e.runtime_dir = tmp.path().join("a\x1bb");
        std::fs::create_dir(&e.runtime_dir).unwrap();
        let Err(LaunchError::A11y(msg)) = host_a11y_bus(&e) else {
            panic!("a bus that is not there was accepted");
        };
        assert!(
            msg.starts_with("asking the session bus for the accessibility bus: "),
            "{msg}"
        );
        assert!(msg.contains("^["), "{msg}");
        assert!(!msg.contains('\x1b'), "{msg}");
    }

    #[test]
    fn an_answer_that_is_no_unix_socket_is_refused_and_never_echoed() {
        let tmp = tempfile::tempdir().unwrap();
        // What at-spi-bus-launcher reports when it listens on an
        // abstract socket: a bus that exists and that the proxy sandbox,
        // with no network namespace of the host's, cannot reach.
        let (_bus, server) = bus_answering(
            tmp.path(),
            "s",
            vec![Value::Str("unix:abstract=/tmp/dbus-Ab3".to_owned())],
        );
        let mut e = env();
        e.runtime_dir = tmp.path().to_owned();
        let Err(LaunchError::A11y(msg)) = host_a11y_bus(&e) else {
            panic!("an abstract address was accepted");
        };
        server.join().unwrap();
        assert!(msg.contains("unix:path="), "{msg}");
        // The address is host input; the message says what was wrong
        // with it, not what it held.
        assert!(!msg.contains("dbus-Ab3"), "{msg}");
    }

    #[test]
    fn an_answer_that_is_not_one_address_is_no_answer() {
        // `GetAddress` answers with a single string. A reply with two,
        // or with none, is an answer to some other question, and picking
        // a value out of it would be a guess.
        for (sig, body) in [
            ("", vec![]),
            (
                "ss",
                vec![
                    Value::Str("unix:path=/a".to_owned()),
                    Value::Str("unix:path=/b".to_owned()),
                ],
            ),
            ("u", vec![Value::Uint32(1)]),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let (_bus, server) = bus_answering(tmp.path(), sig, body);
            let mut e = env();
            e.runtime_dir = tmp.path().to_owned();
            let Err(LaunchError::A11y(msg)) = host_a11y_bus(&e) else {
                panic!("a reply of {sig:?} was accepted");
            };
            server.join().unwrap();
            assert!(msg.contains("org.a11y.Bus"), "{sig:?}: {msg}");
        }
    }
}
