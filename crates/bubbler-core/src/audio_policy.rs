//! The WirePlumber policy that scopes each instance's audio grant — the
//! drop-in (`contrib/wireplumber/50-bubbler.conf`) and the linking hook
//! it loads — embedded so bubbler can hand both out (`bubbler
//! audio-policy --print`, `--print --script`) and detect when none of
//! the host's `wireplumber.conf.d` directories holds the drop-in,
//! without touching the source tree it was built from; and the policy
//! revision the running WirePlumber has loaded.

use std::cell::OnceCell;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Deserialize;

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

/// The lint check for a policy the running WirePlumber has not loaded.
pub const NOT_LOADED_CHECK: &str = "audio-policy-not-loaded";

/// The warning where this run needs it: `cfg` grants `pipewire` or
/// `pulseaudio` and the host holds less than the whole policy, or a
/// copy that differs from this binary's which `cfg` does not accept with
/// a `lint-allow` of [`DIFFERS_CHECK`], or both. Printed once per real
/// run (`main.rs`'s `Run`, `Try` and `Open`), never for `--dry-run` or
/// `--explain`, which carry their own framing.
pub fn run_warning(cfg: &InstanceConfig, host: &dyn Host, env: &Env) -> Option<String> {
    cfg.audio()?;
    let missing = missing(host, env).map(Missing::run_warning);
    let paths = if cfg.accepts(DIFFERS_CHECK) {
        Vec::new()
    } else {
        differing(host, env)
    };
    let differs = (!paths.is_empty())
        .then(|| format!("{}; {}", differs_message(&paths), differs_help(&paths, env)));
    match (missing, differs) {
        (Some(missing), Some(differs)) => Some(format!("{missing}; {differs}")),
        (Some(missing), None) => Some(missing.to_owned()),
        (None, differs) => differs,
    }
}

/// Held back where [`run_warning`] reports the installed files, which a restart alone does not fix,
/// and where `cfg` accepts [`NOT_LOADED_CHECK`]; `read` is not asked then.
pub fn not_loaded_warning(
    cfg: &InstanceConfig,
    host: &dyn Host,
    env: &Env,
    read: impl FnOnce(&Env) -> LoadedRevision,
) -> Option<String> {
    cfg.audio()?;
    let differs_reported = !cfg.accepts(DIFFERS_CHECK) && !differing(host, env).is_empty();
    if missing(host, env).is_some() || differs_reported || cfg.accepts(NOT_LOADED_CHECK) {
        return None;
    }
    read(env).run_warning()
}

/// The audio group header's suffix: the policy missing, differing or not loaded; `""` where it is
/// installed and loaded, or the loaded one is not known. `read` as for [`not_loaded_warning`].
pub fn explain_suffix(
    cfg: &InstanceConfig,
    host: &dyn Host,
    env: &Env,
    read: impl FnOnce(&Env) -> LoadedRevision,
) -> String {
    if let Some(case) = missing(host, env) {
        return case.explain_suffix().to_owned();
    }
    let differs = if differing(host, env).is_empty() {
        ""
    } else {
        EXPLAIN_SUFFIX_DIFFERS
    };
    let loaded = match cfg.audio() {
        Some(_) => read(env).explain_suffix(),
        None => None,
    };
    format!("{differs}{}", loaded.unwrap_or_default())
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

/// What to run for `paths`: a copy in the user's own directories written
/// again with the `--print` that produces it; under `/usr/share`, the
/// package that installed it updated; anywhere else, which the user's
/// shell cannot write, the user's own copy written, which outranks it;
/// then WirePlumber restarted. Or, for an edit made on purpose, the
/// `lint-allow` that accepts it.
pub fn differs_help(paths: &[PathBuf], env: &Env) -> String {
    let steps: Vec<String> = paths
        .iter()
        .map(|path| {
            let is_hook = path.ends_with(HOOK_NAME);
            let script = if is_hook { " --script" } else { "" };
            if path.starts_with(&env.config_home) || path.starts_with(&env.data_home) {
                format!(
                    "`bubbler audio-policy --print{script} > {}`",
                    shell_word(path)
                )
            } else if path.starts_with(DATA_DIR) {
                format!("update the package that installed {}", path.display())
            } else {
                let user_copy = if is_hook {
                    hook_dirs(env)[0].join(HOOK_NAME)
                } else {
                    install_dirs(env)[0].join(DROP_IN_NAME)
                };
                format!(
                    "`mkdir -p {} && bubbler audio-policy --print{script} > {}`, which \
                     outranks {}",
                    shell_word(user_copy.parent().expect("the user's copy has a directory")),
                    shell_word(&user_copy),
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

/// Where the tool that reads the running WirePlumber's metadata is
/// installed: the `pipewire` package, beside `pw-container`.
pub const PW_DUMP: &str = "/usr/bin/pw-dump";

/// The metadata object the loaded hook states its policy revision in,
/// under [`REVISION_KEY`] on subject 0.
pub const POLICY_METADATA: &str = "bubbler-policy";

/// The key of [`POLICY_METADATA`] that holds the revision.
pub const REVISION_KEY: &str = "revision";

/// How the hook states its revision, the one place it is written down.
const REVISION_LINE: &str = "local POLICY_REVISION = ";

/// How long [`loaded_revision`] waits for an answer before it calls the
/// revision unknown.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

// A session graph's dump is tens to hundreds of KiB.
const DUMP_CAP: u64 = 16 * 1024 * 1024;

const METADATA_TYPE: &str = "PipeWire:Interface:Metadata";

/// The policy revision of this bubbler's hook: the one the running
/// WirePlumber should have loaded.
pub fn revision() -> u32 {
    HOOK.lines()
        .find_map(|line| line.strip_prefix(REVISION_LINE))
        .and_then(|value| value.trim().parse().ok())
        .expect("the embedded hook states its revision as an integer")
}

/// Which policy revision the running WirePlumber has loaded, against
/// [`revision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadedRevision {
    /// This bubbler's.
    Current,
    /// Another, with the value it states.
    Other(String),
    /// None: no [`POLICY_METADATA`], or one without [`REVISION_KEY`],
    /// which is a hook older than revisions or none at all.
    Absent,
    /// Not known, and why: the tool is missing, the daemon unreachable,
    /// or the answer unreadable.
    Unknown(String),
}

const NOT_ENFORCED: &str = "audio grants are not enforced as configured";

/// WirePlumber reads the policy files only when it starts.
pub const RESTART: &str = "systemctl --user restart wireplumber";

impl LoadedRevision {
    /// Which policy the running WirePlumber holds where it is not this
    /// bubbler's; `None` where it is, or where that is not known.
    pub fn not_loaded(&self) -> Option<String> {
        match self {
            LoadedRevision::Current | LoadedRevision::Unknown(_) => None,
            LoadedRevision::Absent => Some(
                "the running WirePlumber has not loaded this bubbler's audio policy".to_owned(),
            ),
            LoadedRevision::Other(loaded) => Some(format!(
                "the running WirePlumber has loaded audio policy revision {loaded}, not this \
                 bubbler's {}",
                revision()
            )),
        }
    }

    /// The run's warning for [`Absent`](Self::Absent) and [`Other`](Self::Other); `None` otherwise.
    pub fn run_warning(&self) -> Option<String> {
        self.not_loaded()
            .map(|cause| format!("{cause}: {NOT_ENFORCED}; run `{RESTART}`"))
    }

    fn explain_suffix(&self) -> Option<String> {
        self.not_loaded()
            .map(|cause| format!(" ({cause}: grant not enforced as configured)"))
    }
}

#[derive(Deserialize)]
struct DumpObject {
    #[serde(rename = "type")]
    kind: String,
    props: Option<DumpProps>,
    metadata: Option<Vec<MetadataEntry>>,
}

#[derive(Deserialize)]
struct DumpProps {
    #[serde(rename = "metadata.name")]
    name: Option<String>,
}

#[derive(Deserialize)]
struct MetadataEntry {
    subject: u64,
    key: String,
    value: serde_json::Value,
}

/// What `pw-dump` printed on stdout, read as a [`LoadedRevision`]: the
/// [`REVISION_KEY`] on subject 0 of the metadata named [`POLICY_METADATA`].
pub fn parse_loaded_revision(dump: &[u8]) -> LoadedRevision {
    let objects: Vec<DumpObject> = match serde_json::from_slice(dump) {
        Ok(objects) => objects,
        Err(e) => return LoadedRevision::Unknown(format!("unreadable pw-dump output: {e}")),
    };
    let entry = objects
        .iter()
        .filter(|object| {
            object.kind == METADATA_TYPE
                && object
                    .props
                    .as_ref()
                    .and_then(|props| props.name.as_deref())
                    == Some(POLICY_METADATA)
        })
        .flat_map(|object| object.metadata.iter().flatten())
        .find(|entry| entry.subject == 0 && entry.key == REVISION_KEY);
    let Some(entry) = entry else {
        return LoadedRevision::Absent;
    };
    let value = match &entry.value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    if value == revision().to_string() {
        LoadedRevision::Current
    } else {
        LoadedRevision::Other(value)
    }
}

/// The revision loaded by the WirePlumber on `env`'s runtime directory, asked with nothing else of
/// bubbler's environment; no answer within two seconds is [`LoadedRevision::Unknown`].
pub fn loaded_revision(env: &Env) -> LoadedRevision {
    let program = env
        .pw_dump_override
        .as_deref()
        .unwrap_or(Path::new(PW_DUMP));
    loaded_revision_asking(program, &env.runtime_dir)
}

/// [`loaded_revision`] asked on the first [`get`](Self::get) only, so that everything one caller
/// lints or runs pays for one `pw-dump` at most.
#[derive(Default)]
pub struct AskedOnce(OnceCell<LoadedRevision>);

impl AskedOnce {
    /// The answer for `env`, asked of it on the first call and kept.
    pub fn get(&self, env: &Env) -> LoadedRevision {
        self.0.get_or_init(|| loaded_revision(env)).clone()
    }
}

/// [`loaded_revision`] of the WirePlumber serving `runtime_dir`, asked of `program`.
pub fn loaded_revision_asking(program: &Path, runtime_dir: &Path) -> LoadedRevision {
    let spawned = Command::new(program)
        .env_clear()
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return LoadedRevision::Unknown(format!("{}: {e}", program.display())),
    };
    // Read while it runs: a dump larger than the pipe would block it until the timeout.
    let stdout = read_capped(child.stdout.take().expect("stdout was piped"));
    let stderr = read_capped(child.stderr.take().expect("stderr was piped"));
    let deadline = Instant::now() + READ_TIMEOUT;
    let status = loop {
        let unknown = match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Ok(None) => format!(
                "{} did not answer within {} s",
                program.display(),
                READ_TIMEOUT.as_secs()
            ),
            Err(e) => format!("{}: {e}", program.display()),
        };
        // Killed and reaped either way; an error here is a child already
        // gone, which the wait collects.
        let _ = child.kill();
        let _ = child.wait();
        return LoadedRevision::Unknown(unknown);
    };
    let stdout = match stdout.join().expect("the pipe reader does not panic") {
        Ok(stdout) => stdout,
        Err(e) => return LoadedRevision::Unknown(format!("{}: {e}", program.display())),
    };
    if stdout.len() as u64 > DUMP_CAP {
        return LoadedRevision::Unknown(format!(
            "{} printed more than {DUMP_CAP} bytes",
            program.display()
        ));
    }
    if !status.success() {
        let said = stderr
            .join()
            .expect("the pipe reader does not panic")
            .unwrap_or_default();
        return LoadedRevision::Unknown(format!(
            "{} {}: {}",
            program.display(),
            status,
            String::from_utf8_lossy(&said).trim()
        ));
    }
    parse_loaded_revision(&stdout)
}

fn read_capped(pipe: impl Read + Send + 'static) -> JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut read = Vec::new();
        pipe.take(DUMP_CAP + 1).read_to_end(&mut read)?;
        Ok(read)
    })
}

/// `path` as one word of a POSIX shell command: as it is where a shell
/// would leave every character alone, else in single quotes.
fn shell_word(path: &Path) -> String {
    let text = path.display().to_string();
    let is_plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if is_plain {
        return text;
    }
    format!("'{}'", text.replace('\'', r"'\''"))
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
            pw_dump_override: None,
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
        let help = differs_help(&[packaged_drop_in.clone(), user_hook.clone()], &env());
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

    /// A copy outside the user's own directories and not a package's
    /// cannot be written by the user's shell; the user's own copy, which
    /// outranks it, can.
    #[test]
    fn differs_help_writes_a_users_copy_over_a_system_one() {
        let e = env();
        for (system, user, script) in [
            (
                Path::new("/etc/xdg/wireplumber/wireplumber.conf.d").join(DROP_IN_NAME),
                Path::new("/home/user/.config/wireplumber/wireplumber.conf.d").join(DROP_IN_NAME),
                "",
            ),
            (
                Path::new("/usr/local/share/wireplumber/scripts").join(HOOK_NAME),
                Path::new("/home/user/.local/share/wireplumber/scripts").join(HOOK_NAME),
                " --script",
            ),
        ] {
            let help = differs_help(std::slice::from_ref(&system), &e);
            assert!(
                help.contains(&format!(
                    "mkdir -p {} && bubbler audio-policy --print{script} > {}`, which outranks {}",
                    user.parent().expect("a directory").display(),
                    user.display(),
                    system.display()
                )),
                "{help}"
            );
            assert!(!help.contains(&format!("> {}", system.display())), "{help}");
            assert!(!help.contains("sudo"), "{help}");
        }
    }

    #[test]
    fn differs_help_quotes_a_path_the_shell_would_split() {
        let e = Env {
            config_home: PathBuf::from("/home/user/my config"),
            ..env()
        };
        let system = Path::new("/etc/xdg/wireplumber/wireplumber.conf.d").join(DROP_IN_NAME);
        let help = differs_help(std::slice::from_ref(&system), &e);
        assert!(
            help.contains(&format!(
                "`mkdir -p '/home/user/my config/wireplumber/wireplumber.conf.d' && \
                 bubbler audio-policy --print > \
                 '/home/user/my config/wireplumber/wireplumber.conf.d/{DROP_IN_NAME}'`"
            )),
            "{help}"
        );
        let user = e
            .config_home
            .join("wireplumber/wireplumber.conf.d")
            .join(DROP_IN_NAME);
        let help = differs_help(std::slice::from_ref(&user), &e);
        assert!(
            help.contains(&format!(
                "`bubbler audio-policy --print > \
                 '/home/user/my config/wireplumber/wireplumber.conf.d/{DROP_IN_NAME}'`"
            )),
            "{help}"
        );
        let quote = Path::new("/home/it's").join(DROP_IN_NAME);
        let e = Env {
            config_home: PathBuf::from("/home/it's"),
            ..env()
        };
        let help = differs_help(std::slice::from_ref(&quote), &e);
        assert!(
            help.contains(&format!("> '/home/it'\\''s/{DROP_IN_NAME}'`")),
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
        let audio = crate::config::parse("pipewire\ncommand \"true\"").unwrap();
        let current = |_: &Env| LoadedRevision::Current;
        assert_eq!(
            explain_suffix(&audio, &FakeHost::default(), &e, current),
            Missing::Both.explain_suffix()
        );
        let half = holding(&[install_dirs(&e)[0].join(DROP_IN_NAME)]);
        assert_eq!(
            explain_suffix(&audio, &half, &e, current),
            Missing::Hook.explain_suffix()
        );
        let whole = holding(&[
            install_dirs(&e)[0].join(DROP_IN_NAME),
            hook_dirs(&e)[0].join(HOOK_NAME),
        ]);
        assert_eq!(explain_suffix(&audio, &whole, &e, current), "");
        let edited = install_dirs(&e)[0].join(DROP_IN_NAME);
        let other = whole.text(edited.to_str().unwrap(), "# another version\n");
        assert_eq!(
            explain_suffix(&audio, &other, &e, current),
            EXPLAIN_SUFFIX_DIFFERS
        );
    }

    /// The metadata objects of what `pw-dump` printed on a bed whose hook
    /// states revision 4 (PipeWire 1.6.9, WirePlumber 0.5.18).
    const MEASURED: &str = r#"[
  {
    "id": 24,
    "type": "PipeWire:Interface:Metadata",
    "version": 3,
    "permissions": [ "r", "w", "x" ],
    "props": {
      "client.id": 18,
      "factory.id": 4,
      "metadata.name": "default",
      "module.id": 3,
      "object.serial": 25
    },
    "metadata": [
      { "subject": 0, "key": "default.audio.sink", "type": "Spa:String:JSON", "value": { "name": "bed-sink" } },
      { "subject": 0, "key": "default.audio.source", "type": "Spa:String:JSON", "value": { "name": "bed-source" } }
    ]
  },
  {
    "id": 27,
    "type": "PipeWire:Interface:Metadata",
    "version": 3,
    "permissions": [ "r", "w", "x" ],
    "props": {
      "client.id": 18,
      "factory.id": 4,
      "metadata.name": "bubbler-policy",
      "module.id": 3,
      "object.serial": 28
    },
    "metadata": [
      { "subject": 0, "key": "revision", "type": "Spa:Int", "value": 4 }
    ]
  }
]
"#;

    const MEASURED_REVISION: &str = r#""key": "revision", "type": "Spa:Int", "value": 4 }"#;

    fn stating(value: u32) -> String {
        assert!(MEASURED.contains(MEASURED_REVISION));
        MEASURED.replace(
            MEASURED_REVISION,
            &MEASURED_REVISION.replace("4 }", &format!("{value} }}")),
        )
    }

    #[test]
    fn the_revision_is_the_integer_the_hook_states() {
        assert!(HOOK.contains(&format!("\nlocal POLICY_REVISION = {}\n", revision())));
    }

    #[test]
    fn a_metadata_stating_this_revision_is_current() {
        assert_eq!(
            parse_loaded_revision(stating(revision()).as_bytes()),
            LoadedRevision::Current
        );
    }

    #[test]
    fn a_metadata_stating_another_revision_names_it() {
        let other = revision() + 1;
        assert_eq!(
            parse_loaded_revision(stating(other).as_bytes()),
            LoadedRevision::Other(other.to_string())
        );
    }

    #[test]
    fn no_metadata_or_no_revision_key_is_absent() {
        let renamed = MEASURED.replace("\"bubbler-policy\"", "\"not-bubbler-policy\"");
        let keyless = MEASURED.replace("\"revision\"", "\"other\"");
        let elsewhere = MEASURED.replace(
            "\"subject\": 0, \"key\": \"revision\"",
            "\"subject\": 31, \"key\": \"revision\"",
        );
        for dump in ["[]", &renamed, &keyless, &elsewhere] {
            assert_eq!(
                parse_loaded_revision(dump.as_bytes()),
                LoadedRevision::Absent,
                "{dump}"
            );
        }
    }

    #[test]
    fn an_unparsable_or_truncated_dump_is_unknown() {
        let truncated = &MEASURED[..MEASURED.find("\"revision\"").expect("the key")];
        for dump in ["", "no such line\n", "{}", truncated] {
            assert!(
                matches!(
                    parse_loaded_revision(dump.as_bytes()),
                    LoadedRevision::Unknown(_)
                ),
                "{dump}"
            );
        }
    }

    #[test]
    fn a_dump_larger_than_the_cap_is_unknown() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let tool = stand_in(
            tmp.path(),
            &format!("head -c {} /dev/zero | tr '\\0' ' '; echo '[]'", DUMP_CAP),
        );
        let answer = asking_past_a_busy_exec(&tool, tmp.path());
        let LoadedRevision::Unknown(reason) = answer else {
            panic!("{answer:?}");
        };
        assert!(reason.contains("more than"), "{reason}");
    }

    fn stand_in(dir: &Path, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("pw-dump");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("the stand-in");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("the stand-in made executable");
        path
    }

    // A thread of this binary that forked while the stand-in was open for writing makes its exec
    // fail with ETXTBSY until that child execs, within a scheduling turn.
    fn asking_past_a_busy_exec(tool: &Path, runtime_dir: &Path) -> LoadedRevision {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let answer = loaded_revision_asking(tool, runtime_dir);
            match &answer {
                LoadedRevision::Unknown(reason)
                    if reason.contains("os error 26") && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => return answer,
            }
        }
    }

    #[test]
    fn a_missing_tool_is_unknown() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let answer = loaded_revision_asking(&tmp.path().join("pw-dump"), tmp.path());
        assert!(matches!(answer, LoadedRevision::Unknown(_)), "{answer:?}");
    }

    #[test]
    fn an_unreachable_daemon_is_unknown_and_says_why() {
        // No daemon answering: `pw-dump` exits 255, the reason on stderr (PipeWire 1.6.9).
        let tmp = tempfile::tempdir().expect("a temp dir");
        let tool = stand_in(
            tmp.path(),
            "echo \"can't connect: Host is down\" >&2; exit 255",
        );
        let answer = asking_past_a_busy_exec(&tool, tmp.path());
        let LoadedRevision::Unknown(reason) = answer else {
            panic!("{answer:?}");
        };
        assert!(reason.contains("can't connect: Host is down"), "{reason}");
    }

    #[test]
    fn a_tool_that_does_not_answer_in_time_is_unknown() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let tool = stand_in(tmp.path(), "exec sleep 30");
        let started = Instant::now();
        let answer = asking_past_a_busy_exec(&tool, tmp.path());
        let elapsed = started.elapsed();
        let LoadedRevision::Unknown(reason) = answer else {
            panic!("{answer:?}");
        };
        assert!(reason.contains("did not answer within"), "{reason}");
        assert!(
            (READ_TIMEOUT..READ_TIMEOUT * 2).contains(&elapsed),
            "{elapsed:?}"
        );
    }

    #[test]
    fn a_policy_not_loaded_is_a_run_warning_naming_the_restart() {
        let absent = LoadedRevision::Absent.run_warning().expect("a warning");
        assert!(
            absent.contains("the running WirePlumber has not loaded this bubbler's audio policy"),
            "{absent}"
        );
        let other = LoadedRevision::Other("7".to_owned())
            .run_warning()
            .expect("a warning");
        assert!(
            other.contains(&format!("revision 7, not this bubbler's {}", revision())),
            "{other}"
        );
        for warning in [absent, other] {
            assert!(warning.contains("not enforced as configured"), "{warning}");
            assert!(
                warning.contains("`systemctl --user restart wireplumber`"),
                "{warning}"
            );
        }
        assert_eq!(LoadedRevision::Current.run_warning(), None);
        assert_eq!(
            LoadedRevision::Unknown("no daemon".to_owned()).run_warning(),
            None
        );
    }

    #[test]
    fn the_loaded_policy_is_asked_only_where_it_can_add_a_warning() {
        let e = env();
        let whole = holding(&[
            install_dirs(&e)[0].join(DROP_IN_NAME),
            hook_dirs(&e)[0].join(HOOK_NAME),
        ]);
        let audio = crate::config::parse("pipewire\ncommand \"true\"").unwrap();
        let silent = crate::config::parse("command \"true\"").unwrap();
        let unasked = |_: &Env| -> LoadedRevision { panic!("the reader was asked") };
        assert_eq!(not_loaded_warning(&silent, &whole, &e, unasked), None);
        assert_eq!(
            not_loaded_warning(&audio, &FakeHost::default(), &e, unasked),
            None
        );
        let asked = std::cell::Cell::new(None);
        let warning = not_loaded_warning(&audio, &whole, &e, |asked_of: &Env| {
            asked.set(Some(asked_of.runtime_dir.clone()));
            LoadedRevision::Absent
        });
        assert_eq!(warning, LoadedRevision::Absent.run_warning());
        assert_eq!(asked.take(), Some(e.runtime_dir.clone()));
    }

    #[test]
    fn a_differing_copy_is_the_one_warning_unless_accepted() {
        let e = env();
        let whole = || {
            holding(&[
                install_dirs(&e)[0].join(DROP_IN_NAME),
                hook_dirs(&e)[0].join(HOOK_NAME),
            ])
        };
        let edited = install_dirs(&e)[0].join(DROP_IN_NAME);
        let differs = whole().text(edited.to_str().unwrap(), "# another version\n");
        let absent = |_: &Env| LoadedRevision::Absent;
        let unasked = |_: &Env| -> LoadedRevision { panic!("the reader was asked") };
        let config = |allows: &[&str]| {
            let allows: String = allows
                .iter()
                .map(|id| format!("lint-allow \"{id}\" reason=\"kept on purpose\"\n"))
                .collect();
            crate::config::parse(&format!("pipewire\n{allows}command \"true\"")).unwrap()
        };
        let plain = config(&[]);
        assert!(run_warning(&plain, &differs, &e).is_some());
        assert_eq!(not_loaded_warning(&plain, &differs, &e, unasked), None);
        let differs_accepted = config(&[DIFFERS_CHECK]);
        assert_eq!(run_warning(&differs_accepted, &differs, &e), None);
        assert_eq!(
            not_loaded_warning(&differs_accepted, &differs, &e, absent),
            LoadedRevision::Absent.run_warning()
        );
        let both = config(&[DIFFERS_CHECK, NOT_LOADED_CHECK]);
        assert_eq!(run_warning(&both, &differs, &e), None);
        assert_eq!(not_loaded_warning(&both, &differs, &e, absent), None);
        let not_loaded_accepted = config(&[NOT_LOADED_CHECK]);
        assert_eq!(
            not_loaded_warning(&not_loaded_accepted, &whole(), &e, unasked),
            None
        );
    }

    #[test]
    fn explain_says_the_loaded_policy_beside_the_installed_one() {
        let e = env();
        let audio = crate::config::parse("pipewire\ncommand \"true\"").unwrap();
        let whole = holding(&[
            install_dirs(&e)[0].join(DROP_IN_NAME),
            hook_dirs(&e)[0].join(HOOK_NAME),
        ]);
        let other = |_: &Env| LoadedRevision::Other("7".to_owned());
        let suffix = explain_suffix(&audio, &whole, &e, other);
        assert!(suffix.starts_with(" ("), "{suffix}");
        assert!(suffix.contains("revision 7"), "{suffix}");
        assert_eq!(
            explain_suffix(&audio, &whole, &e, |_: &Env| LoadedRevision::Current),
            ""
        );
        assert_eq!(
            explain_suffix(&audio, &whole, &e, |_: &Env| LoadedRevision::Unknown(
                "no daemon".to_owned()
            )),
            ""
        );
        let edited = install_dirs(&e)[0].join(DROP_IN_NAME);
        let unasked = |_: &Env| -> LoadedRevision { panic!("the reader was asked") };
        let silent = crate::config::parse("command \"true\"").unwrap();
        assert_eq!(explain_suffix(&silent, &whole, &e, unasked), "");
        let differs = whole.text(edited.to_str().unwrap(), "# another version\n");
        assert_eq!(
            explain_suffix(&audio, &differs, &e, other),
            format!("{EXPLAIN_SUFFIX_DIFFERS}{suffix}")
        );
        assert_eq!(
            explain_suffix(&audio, &FakeHost::default(), &e, unasked),
            Missing::Both.explain_suffix()
        );
    }

    /// The revision and a digest of the two policy files it was last set
    /// for.
    const PINNED: (u32, u64) = (4, 14120264900061557076);

    /// FNV-1a, 64 bit.
    fn digest(bytes: impl Iterator<Item = u8>) -> u64 {
        bytes.fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    #[test]
    fn the_policy_files_are_the_ones_their_revision_was_pinned_for() {
        let now = (revision(), digest(DROP_IN.bytes().chain(HOOK.bytes())));
        assert_eq!(
            now, PINNED,
            "50-bubbler.conf or refuse-links.lua changed: if what WirePlumber does \
             changed with it, raise POLICY_REVISION in refuse-links.lua; then set PINNED \
             to the pair on the left"
        );
    }
}
