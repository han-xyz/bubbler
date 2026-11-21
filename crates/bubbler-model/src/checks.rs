//! The checks `bubbler lint` runs, each named by a stable id and
//! weighted by a severity, as `lint-allow` resolves them.

use std::fmt;

/// The `lint-allow` id that accepts two instances sharing a portal app id,
/// and the lint check that reports it.
pub(crate) const APP_ID_SHARED_CHECK: &str = "app-id-shared";

/// The `lint-allow` id that accepts an installed policy file differing
/// from this binary's: a copy edited on purpose. The same id names the
/// lint check that reports it.
pub const DIFFERS_CHECK: &str = "audio-policy-differs";

/// The lint check for a policy the running WirePlumber has not loaded.
pub const NOT_LOADED_CHECK: &str = "audio-policy-not-loaded";

/// How much a finding weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The file will not do what it says. Never suppressible.
    Error,
    /// Defensible, but the file should say so on purpose.
    Warning,
    /// Information only.
    Note,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
        })
    }
}

/// One check the linter runs, named by a stable id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    /// Kebab-case identifier, as `lint-allow` and `--format json` name it.
    pub id: &'static str,
    /// What a finding of this check weighs.
    pub severity: Severity,
}

// Each check as a constant the code that reports it names, so a
// finding cannot carry an id no table holds.

// A note, not a warning: a wildcard is what the config asked for, and
// how wide one is depends on who registers names under the suffix.
pub const ALLOW_HOST_WILDCARD: Check = Check {
    id: "allow-host-wildcard",
    severity: Severity::Note,
};
pub const APP_ID_SHARED: Check = Check {
    id: APP_ID_SHARED_CHECK,
    severity: Severity::Warning,
};
pub const APP_RUNTIME_RW: Check = Check {
    id: "app-runtime-rw",
    severity: Severity::Note,
};
// A warning, not a note: without the drop-in a `pipewire`/`pulseaudio` grant is not scoped at all.
pub const AUDIO_POLICY_MISSING: Check = Check {
    id: "audio-policy-missing",
    severity: Severity::Warning,
};
// A note, as `microphone` is: the child is what the config asked for.
pub const AUDIO_DEVICES_OFFERED: Check = Check {
    id: "audio-devices-offered",
    severity: Severity::Note,
};
pub const AUDIO_POLICY_DIFFERS: Check = Check {
    id: DIFFERS_CHECK,
    severity: Severity::Warning,
};
// A warning, as `audio-policy-missing` is: the files are in place and the
// grant is still not enforced as they state it.
pub const AUDIO_POLICY_NOT_LOADED: Check = Check {
    id: NOT_LOADED_CHECK,
    severity: Severity::Warning,
};
// The same id as a note, where the running WirePlumber could not be asked:
// nothing says the grant is not enforced, only that it was not measured.
pub const AUDIO_POLICY_NOT_LOADED_UNKNOWN: Check = Check {
    id: AUDIO_POLICY_NOT_LOADED.id,
    severity: Severity::Note,
};
pub const BUNDLE_WITHOUT_DBUS: Check = Check {
    id: "bundle-without-dbus",
    severity: Severity::Error,
};
pub const CAMERA_NODES_NONE_PRESENT: Check = Check {
    id: "camera-nodes-none-present",
    severity: Severity::Note,
};
pub const CAMERA_NODES_NO_HOTPLUG: Check = Check {
    id: "camera-nodes-no-hotplug",
    severity: Severity::Note,
};
pub const CAMERA_WITHOUT_PORTALS: Check = Check {
    id: "camera-without-portals",
    severity: Severity::Error,
};
pub const COMMAND_NOT_FOUND: Check = Check {
    id: "command-not-found",
    severity: Severity::Note,
};
// A hint is a file name, and a host that does not have the application does not have its entry
// either, so this is a note like `command-not-found` rather than a warning.
pub const DESKTOP_ENTRY_MISSING: Check = Check {
    id: "desktop-entry-missing",
    severity: Severity::Note,
};
pub const DBUS_WITHOUT_RULES: Check = Check {
    id: "dbus-without-rules",
    severity: Severity::Warning,
};
// An error, not a warning: these names are a way to run a command outside the sandbox, so granting
// one is not a wider sandbox but no sandbox at all.
pub const DBUS_NAME_IS_HOST_EXEC: Check = Check {
    id: "dbus-name-is-host-exec",
    severity: Severity::Error,
};
pub const DBUS_NAME_IS_RISKY: Check = Check {
    id: "dbus-name-is-risky",
    severity: Severity::Warning,
};
// A note, not a warning: the card nodes are what a mode-setting tool asks for, and what they cost
// is worth saying once rather than making the config argue for them.
pub const DRI_KMS: Check = Check {
    id: "dri-kms",
    severity: Severity::Note,
};
// A note about the host, like `audio-policy-missing`: the file asks for nothing beyond the render
// nodes, and what the run adds to them depends on which driver this machine's GPU is on.
pub const DRI_NVIDIA_PRIMARY: Check = Check {
    id: "dri-nvidia-primary",
    severity: Severity::Note,
};
pub const DUP_NAME_POLICY: Check = Check {
    id: "dup-name-policy",
    severity: Severity::Error,
};
pub const ENV_LOOKS_SECRET: Check = Check {
    id: "env-looks-secret",
    severity: Severity::Warning,
};
// A warning, not a note: the username stays hidden either way, but everything else the host keeps
// in `/etc` becomes readable, and the file cannot say which of that the application actually needs.
pub const ETC_HOST: Check = Check {
    id: "etc-host",
    severity: Severity::Warning,
};
// An error, not a warning: what it names, the launcher refuses. A `home-share` of the instance
// store or the profile layer would hand the sandbox the files bubbler builds it out of.
pub const HOME_SHARE_RESERVED: Check = Check {
    id: "home-share-reserved",
    severity: Severity::Error,
};
pub const HOME_SHARE_SENSITIVE: Check = Check {
    id: "home-share-sensitive",
    severity: Severity::Warning,
};
pub const LINT_ALLOW_UNUSED: Check = Check {
    id: "lint-allow-unused",
    severity: Severity::Note,
};
pub const MPRIS_WILDCARD: Check = Check {
    id: "mpris-wildcard",
    severity: Severity::Warning,
};
// A warning and not a note: this is the one mode where the sandbox's reach is decided by nothing
// bubbler binds.
pub const NETWORK_HOST: Check = Check {
    id: "network-host",
    severity: Severity::Warning,
};
// Information, not a warning: the filter is what the config asked for, and what it cannot do is a
// property of address filtering rather than a mistake in the file.
pub const OUTBOUND_DENY: Check = Check {
    id: "outbound-deny",
    severity: Severity::Note,
};
pub const OWN_ON_SYSTEM_BUS: Check = Check {
    id: "own-on-system-bus",
    severity: Severity::Error,
};
pub const OWN_TOO_WIDE: Check = Check {
    id: "own-too-wide",
    severity: Severity::Warning,
};
pub const OZONE_HINT_UNNECESSARY: Check = Check {
    id: "ozone-hint-unnecessary",
    severity: Severity::Note,
};
pub const PATH_SHARE_MOUNTPOINT: Check = Check {
    id: "path-share-mountpoint",
    severity: Severity::Warning,
};
pub const PATH_SHARE_RESERVED: Check = Check {
    id: "path-share-reserved",
    severity: Severity::Error,
};
pub const PATH_SHARE_SOCKET: Check = Check {
    id: "path-share-socket",
    severity: Severity::Warning,
};
// A note, not a warning: the child is what the config asked for, the same way `dri kms` is.
pub const PIPEWIRE_MICROPHONE: Check = Check {
    id: "pipewire-microphone",
    severity: Severity::Note,
};
pub const PORTAL_TALK_WITHOUT_PORTALS: Check = Check {
    id: "portal-talk-without-portals",
    severity: Severity::Warning,
};
// A note, not a warning: nothing is granted twice and nothing is wider than it says.
pub const REPEAT_OUTSIDE_BLOCK: Check = Check {
    id: "repeat-outside-block",
    severity: Severity::Note,
};
pub const SECCOMP_DISABLED: Check = Check {
    id: "seccomp-disabled",
    severity: Severity::Warning,
};
// Two sites report this check: the D-Bus rule in `dbus_node`, and the `secrets` child of `portals`
// in `per_layer`.
pub const SECRETS_ACCESS: Check = Check {
    id: "secrets-access",
    severity: Severity::Note,
};
// A warning, not an error: a profile is written for a host that has the directory, and one that
// does not is a host the profile was not written for.
pub const SHARE_SOURCE_MISSING: Check = Check {
    id: "share-source-missing",
    severity: Severity::Warning,
};
pub const SYSTEM_BUS_POLKIT_NAME: Check = Check {
    id: "system-bus-polkit-name",
    severity: Severity::Warning,
};
pub const TTY_PASSTHROUGH: Check = Check {
    id: "tty-passthrough",
    severity: Severity::Warning,
};
pub const TTY_PASSTHROUGH_WITHOUT_SECCOMP: Check = Check {
    id: "tty-passthrough-without-seccomp",
    severity: Severity::Warning,
};
pub const USERNS_DISABLED_WITH_NESTED_SANDBOX: Check = Check {
    id: "userns-disabled-with-nested-sandbox",
    severity: Severity::Warning,
};
pub const WAYLAND_CLIPBOARD_OPEN: Check = Check {
    id: "wayland-clipboard-open",
    severity: Severity::Warning,
};
pub const WAYLAND_HOST: Check = Check {
    id: "wayland-host",
    severity: Severity::Warning,
};
// A note, not a warning: the nested server gives up nothing outside the sandbox.
pub const X11_NESTED_NO_WM: Check = Check {
    id: "x11-nested-no-wm",
    severity: Severity::Note,
};
pub const X11_WITHOUT_REASON: Check = Check {
    id: "x11-without-reason",
    severity: Severity::Warning,
};

/// Every check, sorted by id. `lint-allow` resolves its argument here,
/// so a check taken out of this table makes the profiles naming it
/// errors rather than silently accepting nothing.
pub const CHECKS: &[Check] = &[
    ALLOW_HOST_WILDCARD,
    APP_ID_SHARED,
    APP_RUNTIME_RW,
    AUDIO_DEVICES_OFFERED,
    AUDIO_POLICY_DIFFERS,
    AUDIO_POLICY_MISSING,
    AUDIO_POLICY_NOT_LOADED,
    BUNDLE_WITHOUT_DBUS,
    CAMERA_NODES_NONE_PRESENT,
    CAMERA_NODES_NO_HOTPLUG,
    CAMERA_WITHOUT_PORTALS,
    COMMAND_NOT_FOUND,
    DBUS_NAME_IS_HOST_EXEC,
    DBUS_NAME_IS_RISKY,
    DBUS_WITHOUT_RULES,
    DESKTOP_ENTRY_MISSING,
    DRI_KMS,
    DRI_NVIDIA_PRIMARY,
    DUP_NAME_POLICY,
    ENV_LOOKS_SECRET,
    ETC_HOST,
    HOME_SHARE_RESERVED,
    HOME_SHARE_SENSITIVE,
    LINT_ALLOW_UNUSED,
    MPRIS_WILDCARD,
    NETWORK_HOST,
    OUTBOUND_DENY,
    OWN_ON_SYSTEM_BUS,
    OWN_TOO_WIDE,
    OZONE_HINT_UNNECESSARY,
    PATH_SHARE_MOUNTPOINT,
    PATH_SHARE_RESERVED,
    PATH_SHARE_SOCKET,
    PIPEWIRE_MICROPHONE,
    PORTAL_TALK_WITHOUT_PORTALS,
    REPEAT_OUTSIDE_BLOCK,
    SECCOMP_DISABLED,
    SECRETS_ACCESS,
    SHARE_SOURCE_MISSING,
    SYSTEM_BUS_POLKIT_NAME,
    TTY_PASSTHROUGH,
    TTY_PASSTHROUGH_WITHOUT_SECCOMP,
    USERNS_DISABLED_WITH_NESTED_SANDBOX,
    WAYLAND_CLIPBOARD_OPEN,
    WAYLAND_HOST,
    X11_NESTED_NO_WM,
    X11_WITHOUT_REASON,
];

/// The check `id` names, if it is one.
pub fn check(id: &str) -> Option<&'static Check> {
    CHECKS.iter().find(|c| c.id == id)
}
