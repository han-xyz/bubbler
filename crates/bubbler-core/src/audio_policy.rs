//! The WirePlumber policy that scopes each instance's audio grant — the
//! drop-in (`contrib/wireplumber/50-bubbler.conf`) and the linking hook
//! it loads — embedded so bubbler can hand both out (`bubbler
//! audio-policy --print`, `--print --script`) and detect when none of
//! the host's `wireplumber.conf.d` directories holds the drop-in,
//! without touching the source tree it was built from.

use std::path::{Path, PathBuf};

use crate::config::InstanceConfig;
use crate::env::Env;
use crate::host::Host;

/// The drop-in, exactly as shipped in `contrib/`. Loaded by the
/// real-PipeWire test bed and printed verbatim by `bubbler audio-policy
/// --print`.
pub const DROP_IN: &str = include_str!("../../../contrib/wireplumber/50-bubbler.conf");

/// File name WirePlumber loads the drop-in under, in any of
/// [`install_dirs`].
pub const DROP_IN_NAME: &str = "50-bubbler.conf";

/// The linking hook the drop-in loads, exactly as shipped in
/// `contrib/`. A permission says what one object may do; which links
/// may be made is a fact about two, so the part of the policy that
/// keeps a sandbox off the sink's monitor ports and off another
/// client's stream is this script rather than a rule.
pub const HOOK: &str =
    include_str!("../../../contrib/wireplumber/scripts/bubbler/refuse-links.lua");

/// Path WirePlumber loads the hook under, relative to one of
/// [`hook_dirs`]; the name the drop-in's `wireplumber.components` gives
/// it, so the two must change together.
pub const HOOK_NAME: &str = "bubbler/refuse-links.lua";

/// Where WirePlumber was built to look for its own scripts, which the
/// default `$XDG_DATA_DIRS` also ends with.
const DATA_DIR: &str = "/usr/share";

/// The three `wireplumber.conf.d` directories bubbler looks for the
/// drop-in in, in the order [`installed`] searches.
pub fn install_dirs(env: &Env) -> [PathBuf; 3] {
    [
        PathBuf::from("/usr/share/wireplumber/wireplumber.conf.d"),
        PathBuf::from("/etc/wireplumber/wireplumber.conf.d"),
        env.config_home.join("wireplumber/wireplumber.conf.d"),
    ]
}

/// The `wireplumber/scripts` directories bubbler looks for the hook in,
/// in the order [`hook_installed`] searches.
///
/// A script is found by the *data*-directory search and not the
/// configuration one the drop-in is found by, so none of
/// [`install_dirs`] is among these and `/etc` is not either:
/// `$XDG_DATA_HOME`, then `$XDG_DATA_DIRS`, then the directory
/// WirePlumber was built with, which the default `$XDG_DATA_DIRS`
/// already holds and which is listed once either way — these are what a
/// diagnostic names.
/// `$WIREPLUMBER_DATA_DIR`, which would replace the whole search, is not
/// consulted: a session that sets it is a WirePlumber developer's.
pub fn hook_dirs(env: &Env) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::with_capacity(env.data_dirs.len() + 2);
    let bases = std::iter::once(env.data_home.as_path())
        .chain(env.data_dirs.iter().map(PathBuf::as_path))
        .chain(std::iter::once(Path::new(DATA_DIR)));
    for base in bases {
        let dir = base.join("wireplumber/scripts");
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// Full path of the installed drop-in: the first of [`install_dirs`]
/// that holds a file named [`DROP_IN_NAME`]; `None` where none does,
/// which is what an absent policy is measured by everywhere else in
/// this module.
pub fn installed(host: &dyn Host, env: &Env) -> Option<PathBuf> {
    install_dirs(env).into_iter().find_map(|dir| {
        let path = dir.join(DROP_IN_NAME);
        host.file_type(&path).is_some().then_some(path)
    })
}

/// Full path of the installed hook: the first of [`hook_dirs`] that
/// holds [`HOOK_NAME`]; `None` where none does.
pub fn hook_installed(host: &dyn Host, env: &Env) -> Option<PathBuf> {
    hook_dirs(env).into_iter().find_map(|dir| {
        let path = dir.join(HOOK_NAME);
        host.file_type(&path).is_some().then_some(path)
    })
}

/// Which half of the policy a host does not hold. Both are needed: the
/// drop-in scopes the grant, and the hook refuses the links a
/// permission cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// No `wireplumber.conf.d` holds [`DROP_IN_NAME`].
    DropIn,
    /// No `wireplumber/scripts` directory holds [`HOOK_NAME`].
    Hook,
    /// Neither.
    Both,
}

/// Exact text of the warning a real run prints for each case, without
/// the `bubbler: warning:` prefix every diagnostic bubbler prints
/// already carries.
const RUN_WARNING_DROP_IN: &str = "audio policy drop-in not found (50-bubbler.conf): the \
     sandbox has full access to every PipeWire node (microphone and every other client's \
     audio reachable)";
const RUN_WARNING_HOOK: &str = "audio policy hook script not found \
     (bubbler/refuse-links.lua): the sandbox has full access to every PipeWire node \
     (microphone and every other client's audio reachable)";
const RUN_WARNING_BOTH: &str = "audio policy drop-in and hook script not found \
     (50-bubbler.conf, bubbler/refuse-links.lua): the sandbox has full access to every \
     PipeWire node (microphone and every other client's audio reachable)";

/// Suffix a `pipewire`/`pulseaudio` `--explain` group header takes for
/// each case: the grant looks scoped to what the config asks for and in
/// fact reaches more. `crate::explain::render` appends it in the same
/// place a group's `KMS_NOTE`/`NVIDIA_NOTE` lands.
const EXPLAIN_SUFFIX_DROP_IN: &str =
    " (policy drop-in 50-bubbler.conf not found: microphone reachable)";
const EXPLAIN_SUFFIX_HOOK: &str =
    " (policy hook script bubbler/refuse-links.lua not found: microphone reachable)";
const EXPLAIN_SUFFIX_BOTH: &str = " (policy drop-in 50-bubbler.conf and hook script \
     bubbler/refuse-links.lua not found: microphone reachable)";

impl Missing {
    /// The line a real run prints on stderr for this case.
    pub fn run_warning(self) -> &'static str {
        match self {
            Missing::DropIn => RUN_WARNING_DROP_IN,
            Missing::Hook => RUN_WARNING_HOOK,
            Missing::Both => RUN_WARNING_BOTH,
        }
    }

    /// What `--explain` appends to the audio group's header for it.
    pub fn explain_suffix(self) -> &'static str {
        match self {
            Missing::DropIn => EXPLAIN_SUFFIX_DROP_IN,
            Missing::Hook => EXPLAIN_SUFFIX_HOOK,
            Missing::Both => EXPLAIN_SUFFIX_BOTH,
        }
    }
}

/// What this host is missing of the policy, or `None` where it holds
/// both files.
pub fn missing(host: &dyn Host, env: &Env) -> Option<Missing> {
    match (
        installed(host, env).is_some(),
        hook_installed(host, env).is_some(),
    ) {
        (true, true) => None,
        (false, true) => Some(Missing::DropIn),
        (true, false) => Some(Missing::Hook),
        (false, false) => Some(Missing::Both),
    }
}

/// The warning where this run needs it: `cfg` grants `pipewire` or
/// `pulseaudio` and the host holds less than the whole policy. Printed
/// once per real run (`main.rs`'s `Run`, `Try` and `Open`), never for
/// `--dry-run` or `--explain`, which carry their own framing.
pub fn run_warning(cfg: &InstanceConfig, host: &dyn Host, env: &Env) -> Option<&'static str> {
    cfg.audio()?;
    Some(missing(host, env)?.run_warning())
}

/// The suffix an audio group's header takes, `""` where the host holds
/// the whole policy.
pub fn explain_suffix(host: &dyn Host, env: &Env) -> &'static str {
    match missing(host, env) {
        Some(case) => case.explain_suffix(),
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::{self, FakeHost};
    use std::path::Path;

    fn env() -> Env {
        Env {
            home: PathBuf::from("/home/user"),
            data_home: PathBuf::from("/home/user/.local/share"),
            config_home: PathBuf::from("/home/user/.config"),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: PathBuf::from("/run/user/1000"),
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
            wl_proxy_override: None,
            net_proxy_override: None,
        }
    }

    /// Every combination of the two files a host can hold.
    fn holding(paths: &[PathBuf]) -> FakeHost {
        let (file, _, _) = fake::types();
        let mut host = FakeHost::default();
        for path in paths {
            host = host.with(path.to_str().expect("the fixture's paths are UTF-8"), file);
        }
        host
    }

    #[test]
    fn missing_names_the_half_the_host_does_not_hold() {
        let e = env();
        let drop_in = install_dirs(&e)[0].join(DROP_IN_NAME);
        let hook = hook_dirs(&e)[0].join(HOOK_NAME);
        assert_eq!(
            missing(&holding(&[drop_in.clone(), hook.clone()]), &e),
            None
        );
        assert_eq!(missing(&holding(&[hook]), &e), Some(Missing::DropIn));
        assert_eq!(missing(&holding(&[drop_in]), &e), Some(Missing::Hook));
        assert_eq!(missing(&holding(&[]), &e), Some(Missing::Both));
    }

    #[test]
    fn hook_installed_finds_the_file_in_any_data_directory() {
        let e = env();
        for dir in hook_dirs(&e) {
            let path = dir.join(HOOK_NAME);
            assert_eq!(
                hook_installed(&holding(std::slice::from_ref(&path)), &e),
                Some(path),
                "{}",
                dir.display()
            );
        }
    }

    /// A diagnostic names the file the host is missing and not the one
    /// it has, or the reader installs the wrong half.
    #[test]
    fn every_diagnostic_names_the_files_it_is_about() {
        for (case, named, unnamed) in [
            (Missing::DropIn, &[DROP_IN_NAME][..], &[HOOK_NAME][..]),
            (Missing::Hook, &[HOOK_NAME][..], &[DROP_IN_NAME][..]),
            (Missing::Both, &[DROP_IN_NAME, HOOK_NAME][..], &[][..]),
        ] {
            for text in [case.run_warning(), case.explain_suffix()] {
                for file in named {
                    assert!(text.contains(file), "{case:?}: {text}");
                }
                for file in unnamed {
                    assert!(!text.contains(file), "{case:?}: {text}");
                }
            }
        }
    }

    /// The embedded copy is what a fresh read of the file on disk holds
    /// too: a stale embed would ship a drop-in that does not match what
    /// `contrib/` documents and reviews.
    #[test]
    fn drop_in_matches_the_file_on_disk() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contrib/wireplumber/50-bubbler.conf");
        let disk =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(DROP_IN, disk);
    }

    #[test]
    fn hook_matches_the_file_on_disk() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("contrib/wireplumber/scripts")
            .join(HOOK_NAME);
        let disk =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(HOOK, disk);
    }

    #[test]
    fn installed_finds_the_file_in_any_of_the_three_directories() {
        let e = env();
        let (file, _, _) = fake::types();
        for dir in install_dirs(&e) {
            let path = dir.join(DROP_IN_NAME);
            let host = FakeHost::default().with(path.to_str().unwrap(), file);
            assert_eq!(
                installed(&host, &e),
                Some(path.clone()),
                "{}",
                dir.display()
            );
        }
    }

    #[test]
    fn installed_is_none_where_no_directory_holds_it() {
        let e = env();
        assert_eq!(installed(&FakeHost::default(), &e), None);
    }

    #[test]
    fn run_warning_fires_only_for_an_audio_grant_with_half_a_policy() {
        let e = env();
        let whole = holding(&[
            install_dirs(&e)[0].join(DROP_IN_NAME),
            hook_dirs(&e)[0].join(HOOK_NAME),
        ]);
        let audio = crate::config::parse("pipewire\ncommand \"true\"").unwrap();
        let silent = crate::config::parse("command \"true\"").unwrap();
        assert_eq!(
            run_warning(&audio, &FakeHost::default(), &e),
            Some(Missing::Both.run_warning())
        );
        assert_eq!(
            run_warning(
                &audio,
                &holding(&[install_dirs(&e)[0].join(DROP_IN_NAME)]),
                &e
            ),
            Some(Missing::Hook.run_warning())
        );
        assert_eq!(run_warning(&audio, &whole, &e), None);
        assert_eq!(run_warning(&silent, &FakeHost::default(), &e), None);
    }

    #[test]
    fn explain_suffix_is_empty_once_both_files_are_installed() {
        let e = env();
        assert_eq!(
            explain_suffix(&FakeHost::default(), &e),
            Missing::Both.explain_suffix()
        );
        let half = holding(&[install_dirs(&e)[2].join(DROP_IN_NAME)]);
        assert_eq!(explain_suffix(&half, &e), Missing::Hook.explain_suffix());
        let whole = holding(&[
            install_dirs(&e)[2].join(DROP_IN_NAME),
            hook_dirs(&e)[0].join(HOOK_NAME),
        ]);
        assert_eq!(explain_suffix(&whole, &e), "");
    }
}
