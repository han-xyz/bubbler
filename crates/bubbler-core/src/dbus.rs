//! What the filtering D-Bus sidecar needs: the proxy's rule list per bus,
//! the `.flatpak-info` portals identify the sandbox by, where portals look
//! that identity up, and where the filtered sockets live. The sandbox
//! never reaches a host bus itself.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::config::{BusRule, Service};
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

/// Rules the `portals` bundle grants: the three portal services a
/// sandboxed app talks to, plus the `--call`/`--broadcast` pair from the
/// `xdg-dbus-proxy(1)` EXAMPLES section.
// Not `org.freedesktop.portal.Flatpak`: that is the spawn portal, which
// starts processes outside the sandbox, and Settings, FileChooser and
// Notification all live on `portal.Desktop`.
const PORTAL_RULES: &[&str] = &[
    "--talk=org.freedesktop.portal.Desktop",
    "--talk=org.freedesktop.portal.Documents",
    "--talk=org.freedesktop.portal.FileChooser",
    "--call=org.freedesktop.portal.*=*",
    "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
];

/// Rules the `input-method` grant gets: both portal names, whichever
/// daemon the session runs. The client libraries watch for the name and
/// use it when the daemon's own name is not visible, which is what the
/// proxy's filtering leaves them.
// Not the daemons' own names: fcitx5's carries `Exit`, `SetConfig` and
// their kin, which reconfigure the daemon for the whole session.
const INPUT_METHOD_RULES: &[&str] = &[
    "--talk=org.freedesktop.portal.Fcitx",
    "--talk=org.freedesktop.portal.IBus",
];

/// Rules the `a11y` grant gets on the accessibility bus, which is the
/// whole of what a sandboxed client may ask that bus for: registering
/// the application with the AT-SPI registry, and reading back what is
/// registered so a toolkit knows whether to emit its events.
///
/// `RegisterKeystrokeListener`, `GenerateKeyboardEvent`,
/// `GenerateMouseEvent` and `RegisterEvent` are deliberately absent. The
/// bus is a peer bus with no policy of its own and offers them to every
/// client: they are every keystroke of every accessible application and
/// input injected into the session, which is what makes the raw bus the
/// same class of grant as the X11 socket. What a screen reader does to
/// the sandbox needs no rule here — calls *into* it are incoming, and
/// `xdg-dbus-proxy(1)` filters only what the client sends.
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
    /// The buses the proxy serves, in the order it is told to bind them:
    /// each socket's file name — the one it has in the proxy's directory
    /// and, once the launcher has moved it, in the instance's — with the
    /// config node that granted it, so a failure names what to change.
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
    let portals = services.contains(&Service::Portals);
    let session = session.map(|(node, explicit)| {
        let mut rules = explicit_rules(explicit, node);
        // Bundles are sets of session-bus rules; the system bus never
        // gets one, and its own list is the whole confinement.
        for (i, s) in services.iter().enumerate() {
            match s {
                Service::Portals => {
                    for r in PORTAL_RULES {
                        push(&mut rules, (*r).to_owned(), i);
                    }
                }
                Service::Notify => push(
                    &mut rules,
                    "--talk=org.freedesktop.Notifications".to_owned(),
                    i,
                ),
                // The watcher is all a tray icon takes: an item registers
                // on the app's own unique name, and the calls the host
                // makes back into it are incoming, which the proxy does
                // not filter (`xdg-dbus-proxy(1)`).
                Service::Tray => push(
                    &mut rules,
                    "--talk=org.kde.StatusNotifierWatcher".to_owned(),
                    i,
                ),
                Service::InputMethod => {
                    for r in INPUT_METHOD_RULES {
                        push(&mut rules, (*r).to_owned(), i);
                    }
                }
                // Its rules are its own bus's, below: nothing of the
                // grant belongs on the session bus, since the address of
                // the accessibility bus is resolved before the sandbox
                // starts rather than asked for from inside it.
                Service::A11y => {}
                Service::Mpris { name } => {
                    push(
                        &mut rules,
                        format!("--own=org.mpris.MediaPlayer2.{name}"),
                        i,
                    );
                }
                // Every other grant is listed rather than caught by a
                // wildcard: a new bundle must be given its rules here, and
                // a wildcard would silently give it none.
                Service::Wayland(_)
                | Service::X11(_)
                | Service::Network { .. }
                | Service::Dri
                | Service::Pipewire
                | Service::Pulseaudio
                | Service::Gamepad { .. }
                | Service::Hidraw
                // `camera` adds no rule of its own: the Camera interface
                // lives on `org.freedesktop.portal.Desktop`, which the
                // `portals` bundle above already talks to.
                | Service::Camera { .. }
                | Service::HomeShare { .. }
                | Service::PathShare { .. }
                | Service::EtcShare { .. }
                | Service::Dbus { .. }
                | Service::SystemBus { .. }
                | Service::AppRuntime { .. } => {}
            }
        }
        Section { node, rules }
    });
    let system = system.map(|(node, explicit)| Section {
        node,
        rules: explicit_rules(explicit, node),
    });
    // A fixed set, with no user rules to merge: the node takes no
    // children, and every rule is the granting node's.
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

/// The config's own rules for one bus, in file order, all of them the
/// bus node's own.
fn explicit_rules(rules: &[BusRule], node: usize) -> Vec<Rule> {
    let mut out = Vec::new();
    for rule in rules {
        push(&mut out, render(rule), node);
    }
    out
}

/// Append `rule` unless it is already there: the proxy takes repeats, but
/// a deduplicated list is what the user can compare against the config.
fn push(rules: &mut Vec<Rule>, rule: String, node: usize) {
    let arg = OsString::from(rule);
    if !rules.iter().any(|r| r.arg == arg) {
        rules.push(Rule { arg, node });
    }
}

/// One policy argument in the glued `--talk=<name>` form. A name may
/// start with `-`, which a separated `--talk <name>` would turn into an
/// option of its own.
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
/// one trailing element. Every `.` in the name becomes `_`, because only
/// the last element of an id may hold `-`, and a leading digit is
/// prefixed, which flatpak's own name check rejects even though the
/// portal's does not.
pub fn app_id(instance: &str) -> String {
    let mut tail = instance.replace('.', "_");
    if tail.starts_with(|c: char| c.is_ascii_digit()) {
        tail.insert(0, '_');
    }
    format!("org.bubbler.{tail}")
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
/// when it is set, else `$XDG_RUNTIME_DIR/bus`. Unguarded, and
/// crate-private for it: outside this crate the session bus is reachable
/// only through [`guarded_host_bus`], so the guard is not a step a
/// caller can leave out.
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

/// Refuse a host bus path that resolves into bubbler's own runtime
/// directory, naming `node` as the grant that rejected it. Those
/// directories hold the instances' control sockets and the proxy's own
/// output: an address pointing there would have the proxy connect to a
/// sandbox's exec channel or to a socket it is about to serve itself,
/// and the address is host environment, which is untrusted input.
///
/// Caught: an address that names such a socket, whether it spells the
/// path out, reaches it through a symlink, or walks into it with `..`.
/// Both sides are compared in the form [`resolve`] gives, and that
/// resolved path is what comes back, so the caller stats and connects to
/// the path this checked rather than to a name that can be repointed
/// in between.
///
/// Not caught: a hard link to one of those sockets, or a
/// `$XDG_RUNTIME_DIR` that names a different directory altogether. Both
/// need the uid that already owns the runtime directory and every socket
/// in it, which is the user's own; bubbler does not defend a user
/// against themselves. What this defends is the address — a stale,
/// copied or hostile value in an otherwise sane environment.
///
/// Resolving reads the filesystem, which is why the caller passes its
/// [`Host`]: an explanation resolves the same way a run does.
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

/// `path` with links and `..` taken out: the host's own canonical form
/// where the path exists, else its directory's canonical form with the
/// file name joined back on — a bus socket need not exist yet, and the
/// explanation of a run resolves before anything is created. What no
/// lookup answers is folded lexically, so a `..` is never left in place
/// for a prefix comparison to walk past.
///
/// Where neither the socket nor its directory exists, only that lexical
/// form is left, and a link that would be followed later is not followed
/// here: an explanation can describe a bus the run it describes goes on
/// to refuse. An explanation is not a run, and the run is the one that
/// has to be right.
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

/// `path` with `.` dropped and every `..` folded into the component
/// before it. Purely textual: it is what is left when the filesystem
/// cannot answer, and it is applied to a canonical path too, which by
/// definition has neither component.
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
/// when it is set, else [`SYSTEM_BUS_PATH`], which is what libdbus and
/// libsystemd fall back to. Unguarded, and crate-private for it: outside
/// this crate the system bus is reachable only through
/// [`guarded_host_system_bus`].
pub(crate) fn host_system_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    Ok(address_path(
        env.dbus_system_address.as_deref(),
        "DBUS_SYSTEM_BUS_ADDRESS",
        "system-bus",
    )?
    .unwrap_or_else(|| PathBuf::from(SYSTEM_BUS_PATH)))
}

/// Host accessibility bus socket: the `unix:path=` of
/// `$AT_SPI_BUS_ADDRESS` when the session set one, else the address
/// `org.a11y.Bus` answers `GetAddress` with on the session bus. That is
/// the order at-spi2's own clients ask in, so bubbler proxies the bus
/// the applications on this host are already on. Unguarded, and
/// crate-private for it: outside this crate the accessibility bus is
/// reachable only through [`guarded_host_a11y_bus`].
///
/// Every failure stops the run instead of dropping the grant: an `a11y`
/// sandbox whose socket has no bus behind it looks to the application
/// like a broken toolkit and to the user like a sandbox that quietly
/// gave them less than the config asked for.
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

/// The socket `org.a11y.Bus` hands out: one `GetAddress` call, made by
/// bubbler's own bus client, so an `a11y` grant needs no program on
/// `PATH` to find the bus with.
///
/// The question goes to the bus `env` names rather than to whatever
/// `$DBUS_SESSION_BUS_ADDRESS` this process happens to have inherited:
/// the address that comes back is the one the sandbox is given, and it
/// must name the same session as the socket the `dbus` grant proxies.
/// [`host_bus`] resolves it, so an unset variable falls back to
/// `$XDG_RUNTIME_DIR/bus` here as it does everywhere else.
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
    // `GetAddress` answers with a single string. Anything else is an
    // answer to some other question, and picking a value out of it would
    // be a guess.
    let [Value::Str(address)] = reply.as_slice() else {
        return Err(LaunchError::A11y(
            "org.a11y.Bus answered GetAddress with no address".to_owned(),
        ));
    };
    // A D-Bus string is UTF-8 by the specification and the decoder holds
    // it to that, so the socket path in it is text; the reply is bytes
    // no further.
    //
    // The address is not echoed, for the reason `address_path` does not
    // echo the variable's either: it is host input, and an address may
    // hold anything.
    unix_path(OsStr::new(address.as_str())).ok_or_else(|| {
        LaunchError::A11y(
            "the address org.a11y.Bus returned is not a `unix:path=<path>` socket".to_owned(),
        )
    })
}

/// A failed `GetAddress` as a launch error: a refusal names itself, and
/// anything else is the connection or the wire under it.
///
/// Both carry text this process did not write — an error name and
/// message from the bus, a socket path from the environment — so both go
/// through [`bus_note`].
fn a11y_failure(e: WireError) -> LaunchError {
    LaunchError::A11y(match e {
        // A bus that answers an error with no text at all: the name is
        // the half that matters, and a trailing colon would promise a
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

/// Text bubbler did not write, as a note to hang on an error message:
/// the first line of it, with the control characters shown rather than
/// sent to whatever terminal reads the message.
fn bus_note(text: &str) -> String {
    /// Characters of the line the message carries; a D-Bus error name
    /// and its text fit, a peer with more to say does not get to fill
    /// the terminal with it.
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

/// The socket a `DBUS_*_BUS_ADDRESS` names: `None` when the variable is
/// unset or empty, so the caller's default path applies. A transport
/// bubbler cannot bind (`tcp:`, `unix:abstract=`) is an error naming the
/// variable rather than that default: the session is on the bus the
/// variable names, and proxying another one would filter the wrong bus.
fn address_path(
    address: Option<&OsStr>,
    var: &'static str,
    service: &'static str,
) -> Result<Option<PathBuf>, LaunchError> {
    let Some(address) = address.filter(|a| !a.is_empty()) else {
        return Ok(None);
    };
    match unix_path(address) {
        Some(p) => Ok(Some(p)),
        // The value itself is not echoed: it is host input, and an
        // address may hold anything.
        None => Err(LaunchError::BadValue {
            service,
            reason: format!(
                "${var} names no Unix socket path; bubbler can proxy only a \
                 `unix:path=<path>` address"
            ),
        }),
    }
}

/// Path out of a `unix:path=<path>[,<key>=<value>]...` D-Bus address;
/// `None` for any other transport, and for an empty path.
fn unix_path(address: &OsStr) -> Option<PathBuf> {
    let rest = address.as_bytes().strip_prefix(b"unix:path=")?;
    let end = rest.iter().position(|b| *b == b',').unwrap_or(rest.len());
    let path = &rest[..end];
    (!path.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(path)))
}

/// The proxy binary to run: `$BUBBLER_DBUS_PROXY` when it is set, else
/// [`PROXY_BIN`] from `PATH` inside the proxy sandbox.
pub fn proxy_program(env: &Env) -> PathBuf {
    env.proxy_override
        .clone()
        .unwrap_or_else(|| PathBuf::from(PROXY_BIN))
}

/// The host socket of each bus a plan grants, as the launcher resolved
/// them. One named value rather than three arguments of one type:
/// which socket serves which bus is the whole of the confinement, and a
/// call site that swapped two would hand an application one bus behind
/// another bus's rules. `None` leaves that bus out of the proxy's
/// command, so a section without a socket is not pointed anywhere else.
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
///
/// `buses` holds the host socket of each section the plan carries. A
/// section given no socket is left out rather than pointed somewhere
/// else; the sandbox's bind of it then fails, since the proxy never
/// creates it.
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
        address.push(host);
        // The address and the socket path must precede the options of
        // that bus: an option applies to the address before it. All of
        // them are the granting node's, so an explanation reads one bus
        // at a time instead of both addresses in one group.
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
    use crate::dbus_wire::{decode, encode};
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
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
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            config_home: "/home/han/.config".into(),
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
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            wl_proxy_override: None,
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
                Service::Portals,
                Service::Notify,
                Service::Mpris {
                    name: "firefox.*".into(),
                },
            ],
            "ff",
        )
        .expect("dbus is granted");
        assert_eq!(
            session(&p),
            vec![
                "--talk=org.freedesktop.portal.Desktop",
                "--talk=org.freedesktop.portal.Documents",
                "--talk=org.freedesktop.portal.FileChooser",
                "--call=org.freedesktop.portal.*=*",
                "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
                "--talk=org.freedesktop.Notifications",
                "--own=org.mpris.MediaPlayer2.firefox.*",
            ]
        );
        assert!(p.portals);
        assert_eq!(
            p.flatpak_info,
            b"[Application]\nname=org.bubbler.ff\n\n[Instance]\ninstance-id=bubbler-ff\n".to_vec()
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
    const FIELD_PATH: u8 = 1;
    const FIELD_INTERFACE: u8 = 2;
    const FIELD_MEMBER: u8 = 3;
    const FIELD_ERROR_NAME: u8 = 4;
    const FIELD_REPLY_SERIAL: u8 = 5;
    const FIELD_DESTINATION: u8 = 6;
    const FIELD_SIGNATURE: u8 = 8;
    const MSG_METHOD_RETURN: u8 = 2;
    const MSG_ERROR: u8 = 3;

    /// A bus on a socket under `dir` that runs `script` on the one
    /// connection it accepts, as `dbus_wire`'s own harness does it. Only
    /// what the one call this module makes needs is here.
    fn fake_bus<F>(dir: &Path, script: F) -> (PathBuf, JoinHandle<()>)
    where
        F: FnOnce(UnixStream) + Send + 'static,
    {
        let path = dir.join("bus");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // So a client that never sends what the script waits for
            // fails the test instead of hanging it.
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .unwrap();
            script(stream);
        });
        (path, handle)
    }

    /// One `\r\n` line from the client, read a byte at a time so none of
    /// the message stream that follows `BEGIN` is swallowed.
    fn server_line(stream: &UnixStream) -> String {
        let mut out = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            (&*stream).read_exact(&mut byte).unwrap();
            out.push(byte[0]);
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
                return String::from_utf8(out).unwrap();
            }
        }
    }

    /// The `EXTERNAL` handshake from the bus's side and the `Hello` reply
    /// every connection owes, after which the script is on the call.
    fn server_start(stream: &UnixStream) {
        assert!(server_line(stream).starts_with("\0AUTH EXTERNAL "));
        (&*stream).write_all(b"OK 1234deadbeef\r\n").unwrap();
        assert_eq!(server_line(stream), "NEGOTIATE_UNIX_FD");
        (&*stream).write_all(b"AGREE_UNIX_FD\r\n").unwrap();
        assert_eq!(server_line(stream), "BEGIN");
        let hello = server_message(stream);
        server_reply(
            stream,
            serial_of(&hello),
            "s",
            &[Value::Str(":1.7".to_owned())],
        );
    }

    /// One whole message from the client. After `BEGIN` the socket
    /// carries messages only, and every header says how long its own
    /// fields and its body are, so each message is read to its exact end.
    fn server_message(stream: &UnixStream) -> Vec<u8> {
        let mut head = [0u8; 16];
        (&*stream).read_exact(&mut head).unwrap();
        let word = |at: usize| {
            u32::from_le_bytes(head[at..at + 4].try_into().expect("four bytes")) as usize
        };
        // The body starts on the next 8-byte boundary after the fields.
        let mut rest = vec![0u8; word(12).next_multiple_of(8) + word(4)];
        (&*stream).read_exact(&mut rest).unwrap();
        [&head[..], &rest].concat()
    }

    /// The serial of a message: the second UINT32 of its header.
    fn serial_of(message: &[u8]) -> u32 {
        u32::from_le_bytes(message[8..12].try_into().expect("four bytes"))
    }

    /// The text of each header field of a message, in the order it was
    /// written: what the client asked, and of whom.
    fn text_fields(message: &[u8]) -> Vec<(u8, String)> {
        let end = 16 + u32::from_le_bytes(message[12..16].try_into().expect("four bytes")) as usize;
        let header = decode("yyyyuua(yv)", &message[..end]).unwrap();
        let [.., Value::Array(fields)] = header.as_slice() else {
            panic!("a header whose last member is not the field array");
        };
        fields
            .iter()
            .map(|field| {
                let Value::Struct(pair) = field else {
                    panic!("a header field that is not a struct");
                };
                let [Value::Byte(code), Value::Variant(value)] = pair.as_slice() else {
                    panic!("a header field that is not a code and a variant");
                };
                let text = match &**value {
                    Value::Str(s) | Value::ObjectPath(s) | Value::Signature(s) => s.clone(),
                    other => format!("{other:?}"),
                };
                (*code, text)
            })
            .collect()
    }

    /// One message from the bus's side: the fixed header, the
    /// header-field array, padding to the 8-byte boundary the body
    /// starts on, and the body.
    fn server_send(
        stream: &UnixStream,
        kind: u8,
        fields: &[(u8, Value)],
        sig: &str,
        body: &[Value],
    ) {
        let body = encode(sig, body).unwrap();
        let mut fields = fields.to_vec();
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        let fields = Value::Array(
            fields
                .into_iter()
                .map(|(code, value)| {
                    Value::Struct(vec![Value::Byte(code), Value::Variant(Box::new(value))])
                })
                .collect(),
        );
        let mut message = encode(
            "yyyyuua(yv)",
            &[
                // little-endian, this kind, no flags, protocol version 1
                Value::Byte(b'l'),
                Value::Byte(kind),
                Value::Byte(0),
                Value::Byte(1),
                Value::Uint32(u32::try_from(body.len()).expect("a test body")),
                // The bus's own serial; the client matches on the reply
                // serial in the fields, never on this one.
                Value::Uint32(1),
                fields,
            ],
        )
        .unwrap();
        message.resize(message.len().next_multiple_of(8), 0);
        message.extend_from_slice(&body);
        (&*stream).write_all(&message).unwrap();
    }

    /// A `METHOD_RETURN` to the call with serial `reply_to`.
    fn server_reply(stream: &UnixStream, reply_to: u32, sig: &str, body: &[Value]) {
        server_send(
            stream,
            MSG_METHOD_RETURN,
            &[(FIELD_REPLY_SERIAL, Value::Uint32(reply_to))],
            sig,
            body,
        );
    }

    /// An `ERROR` reply: what the bus answers with when the name is not
    /// there to answer for itself.
    fn server_error(stream: &UnixStream, reply_to: u32, name: &str, message: &str) {
        server_send(
            stream,
            MSG_ERROR,
            &[
                (FIELD_REPLY_SERIAL, Value::Uint32(reply_to)),
                (FIELD_ERROR_NAME, Value::Str(name.to_owned())),
            ],
            "s",
            &[Value::Str(message.to_owned())],
        );
    }

    /// A bus that answers the one call with `sig` and `body`, whatever
    /// they are.
    fn bus_answering(dir: &Path, sig: &'static str, body: Vec<Value>) -> (PathBuf, JoinHandle<()>) {
        fake_bus(dir, move |stream| {
            server_start(&stream);
            let call = server_message(&stream);
            server_reply(&stream, serial_of(&call), sig, &body);
        })
    }

    #[test]
    fn without_the_variable_the_bus_is_asked_with_one_fixed_call() {
        let tmp = tempfile::tempdir().unwrap();
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_message(&stream);
            // The whole of what bubbler asks the session bus for: one
            // method on one object of one name.
            assert_eq!(
                text_fields(&call),
                vec![
                    (FIELD_PATH, "/org/a11y/bus".to_owned()),
                    (FIELD_DESTINATION, "org.a11y.Bus".to_owned()),
                    (FIELD_INTERFACE, "org.a11y.Bus".to_owned()),
                    (FIELD_MEMBER, "GetAddress".to_owned()),
                ]
            );
            server_reply(
                &stream,
                serial_of(&call),
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
            let call = server_message(&stream);
            server_error(
                &stream,
                serial_of(&call),
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
