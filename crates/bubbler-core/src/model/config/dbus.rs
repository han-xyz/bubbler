//! What a config's D-Bus facing nodes come to on their own: the rules a
//! grant adds to the session bus, and the application id an instance is
//! known by.

use super::{BusRule, Service};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
