//! What the filtering D-Bus sidecar needs: the proxy's rule list per bus,
//! the `.flatpak-info` portals identify the sandbox by, where portals look
//! that identity up, and where the filtered sockets live. The sandbox
//! never reaches a host bus itself.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{BusRule, Service};
use crate::env::Env;
use crate::error::LaunchError;

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

/// Program that asks the session bus where the accessibility bus is,
/// from the `dbus` package. It is spawned directly, never through a
/// shell, and only ever for the one call [`host_a11y_bus`] makes.
pub const DBUS_SEND: &str = "dbus-send";

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
/// when it is set, else `$XDG_RUNTIME_DIR/bus`. The caller must still
/// check that the result is a socket.
pub fn host_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    Ok(address_path(
        env.dbus_address.as_deref(),
        "DBUS_SESSION_BUS_ADDRESS",
        "dbus",
    )?
    .unwrap_or_else(|| env.runtime_dir.join("bus")))
}

/// Host system bus socket: the `unix:path=` of `$DBUS_SYSTEM_BUS_ADDRESS`
/// when it is set, else [`SYSTEM_BUS_PATH`], which is what libdbus and
/// libsystemd fall back to. The caller must still check that the result
/// is a socket.
pub fn host_system_bus(env: &Env) -> Result<PathBuf, LaunchError> {
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
/// the applications on this host are already on. The caller must still
/// check that the result is a socket.
///
/// Every failure stops the run instead of dropping the grant: an `a11y`
/// sandbox whose socket has no bus behind it looks to the application
/// like a broken toolkit and to the user like a sandbox that quietly
/// gave them less than the config asked for.
pub fn host_a11y_bus(env: &Env) -> Result<PathBuf, LaunchError> {
    match address_path(
        env.at_spi_bus_address.as_deref(),
        "AT_SPI_BUS_ADDRESS",
        A11Y_NODE,
    )? {
        Some(path) => Ok(path),
        None => ask_a11y_bus(Path::new(DBUS_SEND), env),
    }
}

/// The socket `org.a11y.Bus` hands out, asked with `program`: one
/// `GetAddress` call on the session bus, spawned with one argument per
/// element and no shell anywhere. `program` is [`DBUS_SEND`] resolved on
/// `PATH` in every run; only a test hands it a path of its own.
///
/// The question goes to the bus `env` names rather than to whatever
/// `$DBUS_SESSION_BUS_ADDRESS` this process happens to have inherited:
/// the address that comes back is the one the sandbox is given, and it
/// must name the same session as the socket the `dbus` grant proxies.
fn ask_a11y_bus(program: &Path, env: &Env) -> Result<PathBuf, LaunchError> {
    let mut command = Command::new(program);
    command.args([
        "--session",
        "--print-reply",
        "--dest=org.a11y.Bus",
        "/org/a11y/bus",
        "org.a11y.Bus.GetAddress",
    ]);
    if let Some(session_bus) = env.dbus_address.as_deref() {
        command.env("DBUS_SESSION_BUS_ADDRESS", session_bus);
    }
    let out = command.output().map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => LaunchError::A11y(format!(
            "`{DBUS_SEND}` not found on PATH; install the `dbus` package"
        )),
        _ => LaunchError::A11y(format!("running `{DBUS_SEND}`: {e}")),
    })?;
    if !out.status.success() {
        return Err(LaunchError::A11y(format!(
            "org.a11y.Bus did not answer GetAddress{}",
            stderr_note(&out.stderr)
        )));
    }
    let address = parse_get_address_reply(&out.stdout).ok_or_else(|| {
        LaunchError::A11y("org.a11y.Bus answered GetAddress with no address".to_owned())
    })?;
    // The address is not echoed, for the reason `address_path` does not
    // echo the variable's either: it is host input, and an address may
    // hold anything.
    unix_path(&address).ok_or_else(|| {
        LaunchError::A11y(
            "the address org.a11y.Bus returned is not a `unix:path=<path>` socket".to_owned(),
        )
    })
}

/// The address in a `dbus-send --print-reply` reply: the value of its
/// one `string "..."` line. `None` when the output holds no such line,
/// and `None` when it holds more than one — `GetAddress` answers with a
/// single string, and a reply with two is an answer to some other
/// question that picking from would be a guess.
///
/// Bytes throughout: a socket path need not be UTF-8, and a lossy
/// reading of one names a different file than the bus is on.
fn parse_get_address_reply(stdout: &[u8]) -> Option<OsString> {
    let mut found = None;
    for line in stdout.split(|b| *b == b'\n') {
        let Some(rest) = line.trim_ascii().strip_prefix(b"string \"") else {
            continue;
        };
        let Some(value) = rest.strip_suffix(b"\"") else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(OsStr::from_bytes(value).to_owned());
    }
    found
}

/// The first line of a failed `dbus-send`'s standard error, as a note to
/// hang on the error message. It is another program's output, so the
/// control characters in it are shown rather than sent to whatever
/// terminal reads the message, and only a line's worth of it is kept.
fn stderr_note(stderr: &[u8]) -> String {
    /// Characters of the line the message carries; a D-Bus error name
    /// and its text fit, a program printing something else does not get
    /// to fill the terminal with it.
    const KEPT: usize = 200;

    let line = stderr.split(|b| *b == b'\n').next().unwrap_or_default();
    let rendered = String::from_utf8(crate::safe_text::render(line))
        .expect("the rendering escapes every byte that is not text");
    let text = rendered.trim();
    match (text.is_empty(), text.char_indices().nth(KEPT)) {
        (true, _) => String::new(),
        (false, Some((cut, _))) => format!(": {}...", &text[..cut]),
        (false, None) => format!(": {text}"),
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
    /// Session bus, from [`host_bus`].
    pub session: Option<&'a Path>,
    /// System bus, from [`host_system_bus`].
    pub system: Option<&'a Path>,
    /// Accessibility bus, from [`host_a11y_bus`].
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
    use std::os::unix::ffi::OsStringExt;

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
        }
    }

    #[test]
    fn no_bus_means_no_proxy() {
        assert!(plan(&[Service::Wayland(WaylandMode::Sandboxed)], "t").is_none());
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
            Service::Wayland(WaylandMode::Sandboxed),
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

    /// What this host's `dbus-send` printed for the call `host_a11y_bus`
    /// makes, captured 2026-08-25 on a session running at-spi2.
    const GET_ADDRESS_REPLY: &str = concat!(
        "method return time=1787654118.642581 sender=:1.20 -> ",
        "destination=:1.229719 serial=27 reply_serial=2\n",
        "   string \"unix:path=/run/user/1000/at-spi/bus_0\"\n"
    );

    /// A fake `dbus-send` in `dir`: it writes its argv to `dir/argv`,
    /// prints `stdout` and `stderr` and exits with `code`. Its output is
    /// handed to it in files so that nothing in the reply has to survive
    /// a trip through shell quoting.
    fn fake_dbus_send(dir: &Path, stdout: &[u8], stderr: &[u8], code: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(dir.join("stdout"), stdout).unwrap();
        std::fs::write(dir.join("stderr"), stderr).unwrap();
        let program = dir.join(DBUS_SEND);
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$@\" > {dir}/argv\n\
                 printf '%s\\n' \"$DBUS_SESSION_BUS_ADDRESS\" > {dir}/session\n\
                 cat {dir}/stdout\n\
                 cat {dir}/stderr >&2\n\
                 exit {code}\n",
                dir = dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A file written and then run by a process with threads in it
        // comes back `ETXTBSY` now and again: another thread's spawn
        // forked while this write's descriptor was open, and the fork
        // holds it until its own exec closes it. Taking the miss here
        // keeps it out of the test that follows.
        for _ in 0..100 {
            match Command::new(&program).output() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break,
            }
        }
        program
    }

    #[test]
    fn the_address_is_the_one_quoted_string_a_reply_holds() {
        assert_eq!(
            parse_get_address_reply(GET_ADDRESS_REPLY.as_bytes()),
            Some(OsString::from("unix:path=/run/user/1000/at-spi/bus_0"))
        );
        // A socket path is bytes, and a lossy reading of it would name
        // another file than the one the bus is on.
        let mut reply = b"method return sender=:1.2\n   string \"unix:path=/run/".to_vec();
        reply.extend_from_slice(b"\xff\"\n");
        assert_eq!(
            parse_get_address_reply(&reply),
            Some(OsString::from_vec(b"unix:path=/run/\xff".to_vec()))
        );
        for none in [
            "",
            "method return time=1 sender=:1.20 -> destination=:1.3 serial=3 reply_serial=2\n",
            // What a failed call prints; it is on stderr, but a reply
            // that holds no address is not one to guess at either.
            "Error org.freedesktop.DBus.Error.ServiceUnknown: The name is not activatable\n",
            // GetAddress answers with one string. Two is a reply to
            // some other question, and picking one of them is a guess.
            "   string \"unix:path=/a\"\n   string \"unix:path=/b\"\n",
            "   string unix:path=/a\n",
            "   strings \"unix:path=/a\"\n",
        ] {
            assert_eq!(parse_get_address_reply(none.as_bytes()), None, "{none:?}");
        }
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

    #[test]
    fn without_the_variable_the_bus_is_asked_with_one_fixed_invocation() {
        let tmp = tempfile::tempdir().unwrap();
        let program = fake_dbus_send(tmp.path(), GET_ADDRESS_REPLY.as_bytes(), b"", 0);
        assert_eq!(
            ask_a11y_bus(&program, &env()).unwrap(),
            PathBuf::from("/run/user/1000/at-spi/bus_0")
        );
        // The whole of what bubbler asks the session bus for: one method
        // on one object of one name.
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("argv")).unwrap(),
            "--session\n--print-reply\n--dest=org.a11y.Bus\n/org/a11y/bus\n\
             org.a11y.Bus.GetAddress\n"
        );
    }

    #[test]
    fn the_session_bus_asked_is_the_one_the_env_names() {
        let tmp = tempfile::tempdir().unwrap();
        let program = fake_dbus_send(tmp.path(), GET_ADDRESS_REPLY.as_bytes(), b"", 0);
        let mut e = env();
        // Not the address this test process inherited: the accessibility
        // bus has to be the one belonging to the session whose socket the
        // `dbus` grant proxies.
        e.dbus_address = Some("unix:path=/tmp/from-the-env".into());
        ask_a11y_bus(&program, &e).unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("session")).unwrap(),
            "unix:path=/tmp/from-the-env\n"
        );
    }

    #[test]
    fn a_bus_that_does_not_answer_is_a_launch_error_naming_the_step() {
        let tmp = tempfile::tempdir().unwrap();
        // dbus-send prints the D-Bus error and exits 1. Its output is
        // another program's, so the control sequences in it are shown
        // rather than sent to whatever terminal reads the message.
        let program = fake_dbus_send(
            tmp.path(),
            b"",
            b"Error org.freedesktop.DBus.Error.ServiceUnknown: \x1b]52;c;aGk=\x07\nmore\n",
            1,
        );
        let Err(LaunchError::A11y(msg)) = ask_a11y_bus(&program, &env()) else {
            panic!("a failed call was accepted");
        };
        assert!(msg.contains("org.a11y.Bus"), "{msg}");
        assert!(
            msg.contains("Error org.freedesktop.DBus.Error.ServiceUnknown"),
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
    fn an_answer_that_is_no_unix_socket_is_refused_and_never_echoed() {
        let tmp = tempfile::tempdir().unwrap();
        // What at-spi-bus-launcher reports when it listens on an
        // abstract socket: a bus that exists and that the proxy sandbox,
        // with no network namespace of the host's, cannot reach.
        let abstract_reply = "method return sender=:1.2 reply_serial=2\n   \
             string \"unix:abstract=/tmp/dbus-Ab3\"\n";
        let program = fake_dbus_send(tmp.path(), abstract_reply.as_bytes(), b"", 0);
        let Err(LaunchError::A11y(msg)) = ask_a11y_bus(&program, &env()) else {
            panic!("an abstract address was accepted");
        };
        assert!(msg.contains("unix:path="), "{msg}");
        // The address is host input; the message says what was wrong
        // with it, not what it held.
        assert!(!msg.contains("dbus-Ab3"), "{msg}");

        let other = tempfile::tempdir().unwrap();
        let program = fake_dbus_send(other.path(), b"method return sender=:1.2\n", b"", 0);
        let Err(LaunchError::A11y(msg)) = ask_a11y_bus(&program, &env()) else {
            panic!("a reply holding no address was accepted");
        };
        assert!(msg.contains("org.a11y.Bus"), "{msg}");
    }

    #[test]
    fn a_missing_dbus_send_names_the_program_and_its_package() {
        let tmp = tempfile::tempdir().unwrap();
        let Err(LaunchError::A11y(msg)) = ask_a11y_bus(&tmp.path().join(DBUS_SEND), &env()) else {
            panic!("a missing program was accepted");
        };
        assert!(msg.contains(DBUS_SEND), "{msg}");
        assert!(msg.contains("PATH"), "{msg}");
        assert!(msg.contains("dbus"), "{msg}");
    }
}
