//! Writes to the user profile layer.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::error::ProfileError;
use crate::profile::{Origin, Resolver, starter};

/// Path of `name` in the user layer, ready for an editor to open: the
/// directory exists, and a name the user layer does not hold yet is
/// written with a starting point. An existing file is never touched.
pub fn write_starter(profiles: &Resolver, name: &str) -> Result<PathBuf, ProfileError> {
    let path = profiles.edit_path(name)?;
    let below = profiles
        .lookup(name)?
        .iter()
        .any(|l| l.origin != Origin::User);
    let dir = profiles.user_dir();
    fs::create_dir_all(dir).map_err(|e| ProfileError::Io(dir.to_path_buf(), e))?;
    // `create_new`: asking and writing are one operation, so a profile
    // that appears in between is opened as it is rather than replaced.
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => f
            .write_all(starter(name, below).as_bytes())
            .map_err(|e| ProfileError::Io(path.clone(), e))?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(ProfileError::Io(path, e)),
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::TEMPLATE;
    use crate::profile::test_support::resolver;

    #[test]
    fn edit_path_seeds_an_include_of_the_layer_below() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[("only-system", "dri\n")]);
        for name in ["firefox", "only-system"] {
            let path = write_starter(&r, name).unwrap();
            assert_eq!(path, r.user_dir().join(format!("{name}.kdl")));
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                format!("// bubbler profile: {name} (user layer)\ninclude \"{name}\"\n")
            );
            // What it seeds must resolve, or the editor opens a file that
            // is already broken.
            assert!(r.resolve(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn edit_path_seeds_a_template_when_no_layer_below_holds_the_name() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[], &[]);
        let path = write_starter(&r, "mine").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            format!("// bubbler profile: mine (user layer)\n{TEMPLATE}")
        );
        // A template of commented examples only, so the profile resolves
        // to the same baseline `generic` does.
        assert!(!text.contains("include"), "{text}");
        assert_eq!(r.resolve("mine").unwrap().text, "");
    }

    #[test]
    fn edit_path_never_touches_a_profile_that_is_already_there() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolver(tmp.path(), &[("mine", "network\n")], &[]);
        let path = write_starter(&r, "mine").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "network\n");
    }
}
