//! Built-in profiles: KDL text compiled into the binary. A profile only
//! seeds a new instance's `config.kdl`; editing the instance never
//! changes the profile.

/// Names of all built-in profiles.
pub const NAMES: &[&str] = &["generic"];

/// KDL text of a built-in profile, if the name is known.
pub fn lookup(name: &str) -> Option<&'static str> {
    match name {
        "generic" => Some(include_str!("../profiles/generic.kdl")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_profile_parses() {
        for n in NAMES {
            let text = lookup(n).unwrap();
            crate::config::parse(text).unwrap();
        }
        assert!(lookup("nope").is_none());
    }
}
