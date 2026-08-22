//! What the instance list shows, read from the store rather than kept:
//! one pass over `$XDG_DATA_HOME/bubbler/instances` per refresh, and a
//! liveness probe on every tick.

use anyhow::{Context, Result};
use bubbler_core::env::Env;
use bubbler_core::host::RealHost;
use bubbler_core::instance::{self, Instance};
use bubbler_core::lint::{self, Severity};
use bubbler_core::profile;
use bubbler_core::wrap::{self, Wrap};
use bubbler_core::{config::InstanceConfig, exec};

/// One instance as a row: what it was seeded from, whether it is running,
/// what it grants and what the linter makes of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Instance name, which is also its directory name.
    pub name: String,
    /// The profile its `config.kdl` header names, absent for a config
    /// written by hand.
    pub profile: Option<String>,
    /// Whether something answers on its control socket.
    pub live: bool,
    /// The node names it grants, in file order, for the grants column.
    pub grants: Vec<&'static str>,
    /// Errors, warnings and notes the linter reported; `None` when the
    /// run could not be made at all.
    pub lint: Option<[usize; 3]>,
    /// Why this row could not be read, for an instance whose config does
    /// not parse: the row is still listed, because the way out of a bad
    /// config is to open it.
    pub error: Option<String>,
}

impl Row {
    /// What the `LINT` column says: the worst severity with a count, or
    /// `clean`, or `?` for a config no run could be made against.
    pub fn lint_label(&self) -> String {
        let Some([errors, warnings, notes]) = self.lint else {
            return "?".to_owned();
        };
        match (errors, warnings, notes) {
            (0, 0, 0) => "clean".to_owned(),
            (0, 0, n) => format!("{n} note{}", plural(n)),
            (0, w, _) => format!("{w} warning{}", plural(w)),
            (e, _, _) => format!("{e} error{}", plural(e)),
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The instances and profiles the editor navigates. Rebuilt by
/// [`Store::load`], never patched in place: a config edited outside the
/// editor must show up the same way one edited inside it does.
#[derive(Debug, Clone)]
pub struct Store {
    /// Rows in the order [`Instance::list`] returns them, which is by name.
    pub rows: Vec<Row>,
    /// Every profile any layer holds, with the layer it resolves to.
    pub profiles: Vec<profile::Entry>,
    /// What went wrong reading the profile layers, if anything: profiles
    /// are a screen of their own and must not cost the instance list.
    pub profile_error: Option<String>,
    /// The shims on `PATH`, so wrapping an instance that already has one
    /// offers to remove it rather than writing a second.
    pub shims: Vec<Wrap>,
    /// What went wrong reading the shim registry, said when a shim key is
    /// pressed rather than swallowed.
    pub shim_error: Option<String>,
}

impl Store {
    /// Read the store. A directory that is not an instance is passed over
    /// by [`Instance::list`]; an instance whose config does not parse is
    /// listed with the reason on it.
    pub fn load(env: &Env) -> Result<Self> {
        let names = Instance::list(env).context("listing instances")?;
        let search = crate::env::search_path();
        let ctx = lint::Context {
            env,
            host: &RealHost,
            search_path: &search,
        };
        let rows = names.iter().map(|name| row(env, &ctx, name)).collect();
        let (profiles, profile_error) = match profile::Resolver::new(env).list() {
            Ok(entries) => (entries, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        let (shims, shim_error) = match wrap::load(env) {
            Ok(shims) => (shims, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        Ok(Self {
            rows,
            profiles,
            profile_error,
            shims,
            shim_error,
        })
    }

    /// Probe every instance's control socket again. The one thing the
    /// tick does: it must never unlink a socket, which is why it is
    /// [`exec::is_live`] and not `exec::connect`.
    pub fn refresh_liveness(&mut self, env: &Env) {
        for row in &mut self.rows {
            row.live = exec::is_live(env, &row.name);
        }
    }

    /// The shims that open `instance`, in registry order.
    pub fn shims_of(&self, instance: &str) -> Vec<&Wrap> {
        self.shims
            .iter()
            .filter(|w| w.instance == instance)
            .collect()
    }

    /// The row `name` names, if the store still holds it.
    pub fn row(&self, name: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.name == name)
    }
}

/// One row, built from the three things that can each fail on their own:
/// the config, the header and the lint run.
fn row(env: &Env, ctx: &lint::Context<'_>, name: &str) -> Row {
    let path = instance::config_path(env, name);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let opened = Instance::open(env, name);
    let (grants, error) = match &opened {
        Ok(inst) => (nodes(&inst.config), None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    Row {
        name: name.to_owned(),
        profile: instance::profile_header(&text).map(str::to_owned),
        live: exec::is_live(env, name),
        grants,
        lint: lint::lint_config(ctx, &path).ok().map(|r| {
            [
                r.count(Severity::Error),
                r.count(Severity::Warning),
                r.count(Severity::Note),
            ]
        }),
        error,
    }
}

/// The node names a config grants, in file order. Only the services: the
/// column is for reading at a glance, and `tty` or `command` is not what
/// a reader is scanning the list for.
fn nodes(config: &InstanceConfig) -> Vec<&'static str> {
    config.services.iter().map(|s| s.node_name()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;

    #[test]
    fn a_store_lists_every_instance_with_its_profile_and_grants() {
        let (_tmp, env) = fixture::store(&[("ff", "firefox"), ("term", "generic")]);
        let store = Store::load(&env).unwrap();
        let names: Vec<&str> = store.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["ff", "term"]);
        let ff = store.row("ff").unwrap();
        assert_eq!(ff.profile.as_deref(), Some("firefox"));
        assert!(ff.grants.contains(&"wayland"), "{:?}", ff.grants);
        assert!(!ff.live, "nothing was started");
        assert_eq!(ff.error, None);
        assert!(!store.profiles.is_empty(), "the built-in layer is a layer");
    }

    #[test]
    fn a_config_that_does_not_parse_is_listed_with_the_reason() {
        let (tmp, env) = fixture::store(&[("broken", "generic")]);
        std::fs::write(
            instance::config_path(&env, "broken"),
            "// bubbler profile: generic\nteleport\n",
        )
        .unwrap();
        let store = Store::load(&env).unwrap();
        let row = store.row("broken").unwrap();
        assert!(row.error.is_some(), "an unreadable config is said so");
        assert_eq!(row.profile.as_deref(), Some("generic"));
        assert!(row.grants.is_empty());
        drop(tmp);
    }

    #[test]
    fn the_lint_column_names_the_worst_it_found() {
        let clean = Row {
            name: "a".to_owned(),
            profile: None,
            live: false,
            grants: vec![],
            lint: Some([0, 0, 0]),
            error: None,
        };
        assert_eq!(clean.lint_label(), "clean");
        let notes = Row {
            lint: Some([0, 0, 1]),
            ..clean.clone()
        };
        assert_eq!(notes.lint_label(), "1 note");
        let warnings = Row {
            lint: Some([0, 2, 3]),
            ..clean.clone()
        };
        assert_eq!(warnings.lint_label(), "2 warnings");
        let errors = Row {
            lint: Some([1, 2, 3]),
            ..clean.clone()
        };
        assert_eq!(errors.lint_label(), "1 error");
        let unknown = Row {
            lint: None,
            ..clean
        };
        assert_eq!(unknown.lint_label(), "?");
    }
}
