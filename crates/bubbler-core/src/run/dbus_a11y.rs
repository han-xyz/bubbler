//! The host accessibility bus address: `$AT_SPI_BUS_ADDRESS`, or the
//! answer `org.a11y.Bus` gives on the session bus.

use std::ffi::OsStr;
use std::path::PathBuf;

use crate::dbus::{
    A11Y_NODE, AddressFault, address_path, host_bus, outside_our_runtime, unix_path,
};
use crate::dbus_session::Session;
use crate::dbus_wire::{Value, WireError};
use crate::env::Env;
use crate::host::Host;
use crate::run::launch_error::LaunchError;

/// The host accessibility bus address, refused when it lands in
/// bubbler's own runtime directory. The bus is asked for its address
/// first, as a run does; the unguarded resolver is crate-private.
pub fn guarded_host_a11y_bus(host: &dyn Host, env: &Env) -> Result<PathBuf, LaunchError> {
    Ok(outside_our_runtime(
        host,
        env,
        A11Y_NODE,
        host_a11y_bus(env)?,
    )?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::tests::env;
    use crate::dbus_session::testing::*;
    use crate::plan::plan_error::PlanError;
    use std::ffi::OsString;
    use std::path::Path;
    use std::thread::JoinHandle;

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
            let Err(LaunchError::Plan(PlanError::BadValue { service, reason })) = host_a11y_bus(&e)
            else {
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
