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

/// Where WirePlumber was built to look for configuration after
/// `$XDG_CONFIG_DIRS`.
const SYSCONF_DIR: &str = "/etc";

/// The `wireplumber.conf.d` directories WirePlumber 0.5.18 reads the
/// drop-in from, highest-ranking first: `$XDG_CONFIG_HOME`, each of
/// `$XDG_CONFIG_DIRS`, `/etc`, each of `$XDG_DATA_DIRS`, `/usr/share`
/// (lib/wp/base-dirs.c `lookup_dirs` under `WP_BASE_DIRS_CONFIGURATION`),
/// each listed once. A fragment name is loaded once, from the first of
/// these holding it (`wp_base_dirs_new_files_iterator` drops a
/// lower-ranked file of the same name), so that copy is the one in
/// effect. `$WIREPLUMBER_CONFIG_DIR`, which would replace the whole
/// search, is not consulted, as for [`hook_dirs`].
pub fn install_dirs(env: &Env) -> Vec<PathBuf> {
    let bases = std::iter::once(env.config_home.as_path())
        .chain(env.config_dirs.iter().map(PathBuf::as_path))
        .chain(std::iter::once(Path::new(SYSCONF_DIR)))
        .chain(env.data_dirs.iter().map(PathBuf::as_path))
        .chain(std::iter::once(Path::new(DATA_DIR)));
    let mut dirs: Vec<PathBuf> = Vec::new();
    for base in bases {
        let dir = base.join("wireplumber/wireplumber.conf.d");
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
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

/// Full path of the drop-in WirePlumber loads: the first of
/// [`install_dirs`] that holds a file named [`DROP_IN_NAME`]; `None`
/// where none does, which is what an absent policy is measured by
/// everywhere else in this module.
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
/// already carries. Each says what is reachable in *that* case: with
/// the drop-in installed and only the hook missing the grant is still
/// scoped, so the microphone is not in reach and saying it were would
/// cost the warning its credit.
const RUN_WARNING_DROP_IN: &str = "audio policy drop-in not found (50-bubbler.conf): the \
     sandbox has full access to every PipeWire node (microphone and every other client's \
     audio reachable)";
const RUN_WARNING_HOOK: &str = "audio policy hook script not found \
     (bubbler/refuse-links.lua): another client's stream and the sink's monitor are \
     recordable";
const RUN_WARNING_BOTH: &str = "audio policy drop-in and hook script not found \
     (50-bubbler.conf, bubbler/refuse-links.lua): the sandbox has full access to every \
     PipeWire node (microphone and every other client's audio reachable)";

/// Suffix a `pipewire`/`pulseaudio` `--explain` group header takes for
/// each case: the grant looks scoped to what the config asks for and in
/// fact reaches more. `crate::explain::render` appends it in the same
/// place a group's `KMS_NOTE`/`NVIDIA_NOTE` lands.
const EXPLAIN_SUFFIX_DROP_IN: &str =
    " (policy drop-in 50-bubbler.conf not found: microphone reachable)";
const EXPLAIN_SUFFIX_HOOK: &str = " (policy hook script bubbler/refuse-links.lua not found: \
     another client's audio recordable)";
const EXPLAIN_SUFFIX_BOTH: &str = " (policy drop-in 50-bubbler.conf and hook script \
     bubbler/refuse-links.lua not found: microphone reachable)";

/// The `--explain` suffix where both files are installed but either
/// differs from the copy this binary embeds.
const EXPLAIN_SUFFIX_DIFFERS: &str = " (policy files 50-bubbler.conf and \
     bubbler/refuse-links.lua differ from this bubbler's: grant not enforced as documented)";

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
/// both files. A copy WirePlumber would pick but cannot read counts as
/// missing: it cannot load it either.
pub fn missing(host: &dyn Host, env: &Env) -> Option<Missing> {
    let readable = |path: Option<PathBuf>| path.is_some_and(|path| host.read(&path).is_some());
    match (
        readable(installed(host, env)),
        readable(hook_installed(host, env)),
    ) {
        (true, true) => None,
        (false, true) => Some(Missing::DropIn),
        (true, false) => Some(Missing::Hook),
        (false, false) => Some(Missing::Both),
    }
}

/// The `lint-allow` id that accepts an installed policy file differing
/// from this binary's: a copy edited on purpose. The same id names the
/// lint check that reports it.
pub const DIFFERS_CHECK: &str = "audio-policy-differs";

/// The warning where this run needs it: `cfg` grants `pipewire` or
/// `pulseaudio` and the host holds less than the whole policy, or a
/// copy that differs from this binary's which `cfg` does not accept with
/// a `lint-allow` of [`DIFFERS_CHECK`], or both. Printed once per real
/// run (`main.rs`'s `Run`, `Try` and `Open`), never for `--dry-run` or
/// `--explain`, which carry their own framing.
pub fn run_warning(cfg: &InstanceConfig, host: &dyn Host, env: &Env) -> Option<String> {
    cfg.audio()?;
    let missing = missing(host, env).map(Missing::run_warning);
    let accepted = cfg
        .lint_allows
        .iter()
        .any(|allow| allow.id == DIFFERS_CHECK);
    let paths = if accepted {
        Vec::new()
    } else {
        differing(host, env)
    };
    let differs = (!paths.is_empty())
        .then(|| format!("{}; {}", differs_message(&paths), differs_help(&paths)));
    match (missing, differs) {
        (Some(missing), Some(differs)) => Some(format!("{missing}; {differs}")),
        (Some(missing), None) => Some(missing.to_owned()),
        (None, differs) => differs,
    }
}

/// The suffix an audio group's header takes, `""` where the host holds
/// the whole policy.
pub fn explain_suffix(host: &dyn Host, env: &Env) -> &'static str {
    match missing(host, env) {
        Some(case) => case.explain_suffix(),
        None if !differing(host, env).is_empty() => EXPLAIN_SUFFIX_DIFFERS,
        None => "",
    }
}

/// The policy files WirePlumber loads that are not the ones this binary
/// embeds, an older bubbler's or an edited copy: the grant it states is
/// then not the grant enforced. The copies compared are [`installed`]
/// and [`hook_installed`], the ones WirePlumber loads; one it cannot read
/// is [`missing`] instead.
pub fn differing(host: &dyn Host, env: &Env) -> Vec<PathBuf> {
    [
        (installed(host, env), DROP_IN),
        (hook_installed(host, env), HOOK),
    ]
    .into_iter()
    .filter_map(|(path, embedded)| {
        let path = path?;
        (host.read(&path)? != embedded.as_bytes()).then_some(path)
    })
    .collect()
}

/// Which of `paths` differ, and what that leaves open.
pub fn differs_message(paths: &[PathBuf]) -> String {
    format!(
        "audio policy differs from this bubbler's in {}: under an older policy a sandbox \
         can claim the microphone grant for itself",
        paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" and ")
    )
}

/// What to run for `paths`: each written again with the `--print` that
/// produces it, or, under `/usr/share`, the package that installed it
/// updated; then WirePlumber restarted. Or, for an edit made on purpose,
/// the `lint-allow` that accepts it.
pub fn differs_help(paths: &[PathBuf]) -> String {
    let steps: Vec<String> = paths
        .iter()
        .map(|path| {
            let script = if path.ends_with(HOOK_NAME) {
                " --script"
            } else {
                ""
            };
            if path.starts_with(DATA_DIR) {
                format!("update the package that installed {}", path.display())
            } else {
                format!(
                    "`bubbler audio-policy --print{script} > {}`",
                    path.display()
                )
            }
        })
        .collect();
    format!(
        "{}, then `systemctl --user restart wireplumber`; a copy edited on purpose is \
         accepted with `lint-allow \"{DIFFERS_CHECK}\" reason=\"...\"`",
        steps.join(" and ")
    )
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
            config_dirs: crate::env::DEFAULT_CONFIG_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
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

    /// A host holding `paths`, each with the embedded text of the policy
    /// file it names.
    fn holding(paths: &[PathBuf]) -> FakeHost {
        let files: Vec<(PathBuf, &str)> = paths
            .iter()
            .map(|path| {
                let text = if path.ends_with(HOOK_NAME) {
                    HOOK
                } else {
                    DROP_IN
                };
                (path.clone(), text)
            })
            .collect();
        holding_texts(&files)
    }

    /// A host holding each path with the text beside it.
    fn holding_texts(files: &[(PathBuf, &str)]) -> FakeHost {
        let (file, _, _) = fake::types();
        let mut host = FakeHost::default();
        for (path, text) in files {
            let name = path.to_str().expect("the fixture's paths are UTF-8");
            host = host.with(name, file).text(name, text);
        }
        host
    }

    const STALE: &str = "# an older bubbler's copy\n";

    /// WirePlumber 0.5.18's configuration search, highest first
    /// (lib/wp/base-dirs.c `lookup_dirs` under
    /// `WP_BASE_DIRS_CONFIGURATION`), with `wireplumber.conf.d` below each.
    #[test]
    fn install_dirs_are_wireplumbers_configuration_search_highest_first() {
        let mut e = env();
        e.config_dirs = vec![PathBuf::from("/opt/xdg"), PathBuf::from("/etc/xdg")];
        e.data_dirs = vec![
            PathBuf::from("/usr/local/share"),
            PathBuf::from("/usr/share"),
        ];
        let expected: Vec<PathBuf> = [
            "/home/user/.config",
            "/opt/xdg",
            "/etc/xdg",
            "/etc",
            "/usr/local/share",
            "/usr/share",
        ]
        .iter()
        .map(|base| Path::new(base).join("wireplumber/wireplumber.conf.d"))
        .collect();
        assert_eq!(install_dirs(&e).to_vec(), expected);
    }

    /// Whichever copy ranks highest is the one WirePlumber loads, and so
    /// the one compared; a fragment name is loaded once
    /// (`wp_base_dirs_new_files_iterator` drops a lower-ranked file of the
    /// same name).
    #[test]
    fn the_copy_compared_is_the_one_wireplumber_loads() {
        let e = env();
        let conf = |base: &str| {
            Path::new(base)
                .join("wireplumber/wireplumber.conf.d")
                .join(DROP_IN_NAME)
        };
        let script = |base: &str| Path::new(base).join("wireplumber/scripts").join(HOOK_NAME);
        let hook = (script("/usr/share"), HOOK);
        for (case, files, differ) in [
            (
                "a stale copy in /usr/local/share over the package's",
                vec![
                    (conf("/usr/local/share"), STALE),
                    (conf("/usr/share"), DROP_IN),
                    hook.clone(),
                ],
                true,
            ),
            (
                "a stale copy in /etc/xdg over a current one in /etc",
                vec![
                    (conf("/etc/xdg"), STALE),
                    (conf("/etc"), DROP_IN),
                    hook.clone(),
                ],
                true,
            ),
            (
                "a current user copy over a stale package one",
                vec![
                    (conf("/home/user/.config"), DROP_IN),
                    (conf("/usr/share"), STALE),
                    hook.clone(),
                ],
                false,
            ),
            (
                "an edited hook in the user's data directory",
                vec![
                    (conf("/usr/share"), DROP_IN),
                    (script("/home/user/.local/share"), STALE),
                    hook.clone(),
                ],
                true,
            ),
            (
                "a current user hook over a stale package one",
                vec![
                    (conf("/usr/share"), DROP_IN),
                    (script("/home/user/.local/share"), HOOK),
                    (script("/usr/share"), STALE),
                ],
                false,
            ),
        ] {
            let host = holding_texts(&files);
            assert_eq!(missing(&host, &e), None, "{case}");
            assert_eq!(!differing(&host, &e).is_empty(), differ, "{case}");
        }
    }

    /// A copy a package installed is the package's to update; any other
    /// is written again with the `--print` that produces it.
    #[test]
    fn differs_help_writes_a_users_copy_and_updates_a_packaged_one() {
        let user_hook = Path::new("/home/user/.local/share/wireplumber/scripts").join(HOOK_NAME);
        let packaged_drop_in =
            Path::new("/usr/share/wireplumber/wireplumber.conf.d").join(DROP_IN_NAME);
        let help = differs_help(&[packaged_drop_in.clone(), user_hook.clone()]);
        assert!(
            help.contains(&format!(
                "update the package that installed {}",
                packaged_drop_in.display()
            )),
            "{help}"
        );
        assert!(
            help.contains(&format!(
                "`bubbler audio-policy --print --script > {}`",
                user_hook.display()
            )),
            "{help}"
        );
        assert!(
            help.contains("systemctl --user restart wireplumber"),
            "{help}"
        );
    }

    #[test]
    fn a_drop_in_only_in_a_config_or_data_dir_is_not_missing() {
        let e = env();
        for base in ["/etc/xdg", "/usr/local/share"] {
            let drop_in = Path::new(base)
                .join("wireplumber/wireplumber.conf.d")
                .join(DROP_IN_NAME);
            let host = holding(&[drop_in, hook_dirs(&e)[0].join(HOOK_NAME)]);
            assert_eq!(missing(&host, &e), None, "{base}");
        }
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
    fn installed_finds_the_file_in_any_install_directory() {
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

    /// WirePlumber cannot load a copy it cannot read either, so the half
    /// is missing — the stronger warning — rather than different.
    #[test]
    fn an_unreadable_copy_is_missing_not_differing() {
        let e = env();
        let (file, _, _) = fake::types();
        let drop_in = install_dirs(&e)[0].join(DROP_IN_NAME);
        let host = holding(&[hook_dirs(&e)[0].join(HOOK_NAME)])
            .with(drop_in.to_str().expect("a UTF-8 fixture path"), file);
        assert_eq!(missing(&host, &e), Some(Missing::DropIn));
        assert_eq!(differing(&host, &e), Vec::<PathBuf>::new());
    }

    /// Half a policy and the other half an older bubbler's: the run says
    /// both, since the older drop-in lets a sandbox claim the microphone.
    #[test]
    fn a_stale_drop_in_beside_a_missing_hook_is_named_too() {
        let e = env();
        let drop_in = install_dirs(&e)[0].join(DROP_IN_NAME);
        let host = holding_texts(&[(drop_in.clone(), STALE)]);
        let audio = crate::config::parse("pipewire\ncommand \"true\"").unwrap();
        let warning = run_warning(&audio, &host, &e).expect("a warning");
        assert!(warning.contains(Missing::Hook.run_warning()), "{warning}");
        assert!(warning.contains(&differs_message(&[drop_in])), "{warning}");
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
            Some(Missing::Both.run_warning().to_owned())
        );
        assert_eq!(
            run_warning(
                &audio,
                &holding(&[install_dirs(&e)[0].join(DROP_IN_NAME)]),
                &e
            ),
            Some(Missing::Hook.run_warning().to_owned())
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
        let half = holding(&[install_dirs(&e)[0].join(DROP_IN_NAME)]);
        assert_eq!(explain_suffix(&half, &e), Missing::Hook.explain_suffix());
        let whole = holding(&[
            install_dirs(&e)[0].join(DROP_IN_NAME),
            hook_dirs(&e)[0].join(HOOK_NAME),
        ]);
        assert_eq!(explain_suffix(&whole, &e), "");
        let edited = install_dirs(&e)[0].join(DROP_IN_NAME);
        let other = whole.text(edited.to_str().unwrap(), "# another version\n");
        assert_eq!(explain_suffix(&other, &e), EXPLAIN_SUFFIX_DIFFERS);
    }
}
