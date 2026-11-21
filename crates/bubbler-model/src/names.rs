//! Names bubbler holds to one shape or keeps for itself: the grammar of an
//! instance or profile name, and the programs it finds on `PATH`.

use crate::error::InstanceError;

/// File name of the supervisor binary.
pub const INIT_BIN: &str = "bubbler-init";

/// Program that filters the buses; found on `PATH` inside the proxy
/// sandbox. One process serves every bus an instance is granted.
pub const PROXY_BIN: &str = "xdg-dbus-proxy";

/// The sidecar bubbler runs for an isolated network namespace, as it is
/// looked up on `PATH`. Arch ships it in `passt`.
pub const PASTA_BIN: &str = "pasta";

// Whether `name` is the shape `instance_ops::ephemeral` gives a throwaway
// sandbox, `try-<pid>`, whose runtime directory is swept once that pid is
// gone. An instance of that name would have its own swept out from under it.
fn is_try_name(name: &str) -> bool {
    name.strip_prefix("try-")
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

/// The name grammar instances and profiles share: `[A-Za-z0-9._-]+`, not
/// `.` or `..`, and not starting with `-`. Such a name is one path
/// component that cannot traverse out of a directory, and no CLI that
/// takes it reads it as an option.
pub fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

pub fn validate_name(name: &str) -> Result<(), InstanceError> {
    if is_plain_name(name) && !is_try_name(name) {
        Ok(())
    } else {
        Err(InstanceError::InvalidName(name.to_owned()))
    }
}
