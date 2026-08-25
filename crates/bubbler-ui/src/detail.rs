//! One instance's config as the editor holds it: a typed
//! [`InstanceConfig`] that is rendered to KDL for the linter and written
//! back by [`Instance::save`], never a text buffer. A config the editor
//! holds cannot fail to parse, which is why there is no syntax error to
//! recover from anywhere below.

use std::ffi::OsString;

use bubbler_core::catalogue::{self, Grant};
use bubbler_core::config::{self, InstanceConfig, LintAllow, RawProfile, Service, Userns};
use bubbler_core::env::Env;
use bubbler_core::host::RealHost;
use bubbler_core::instance::{self, Instance};
use bubbler_core::kdl_out;
use bubbler_core::lint::{self, Finding, Where};
use bubbler_core::seccomp::SeccompConfig;
use bubbler_core::tty::TtyMode;

/// Where a row's node lives in the config: what toggling it off removes,
/// and what an edited line replaces rather than adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A grant, by its index in [`InstanceConfig::services`].
    Service(usize),
    /// One variable, by its index in [`InstanceConfig::env`].
    Env(usize),
    /// One accepted finding, by its index.
    LintAllow(usize),
    /// The `tty` node, of which a config holds one.
    Tty,
    /// The `userns` node.
    Userns,
    /// The `seccomp` node.
    Seccomp,
    /// The `desktop` node.
    Desktop,
    /// The `command` node.
    Command,
    /// A node the config does not hold, offered so that granting it is a
    /// keystroke on the row rather than a separate flow.
    Absent,
}

/// One line of the grants pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The KDL node name, which is the key into [`catalogue::GRANTS`].
    pub node: &'static str,
    /// The node as it is written, absent for a node the config does not
    /// hold.
    pub text: Option<String>,
    /// Where it lives in the config.
    pub target: Target,
    /// 1-based first line of the node in the rendered config, and how
    /// many lines it takes: a finding is matched to the row it is about
    /// by the line the linter reports.
    pub line: u32,
    /// Lines the node takes; 0 for a node the config does not hold.
    pub height: u32,
}

impl Row {
    /// Whether the config holds this node.
    pub fn granted(&self) -> bool {
        self.text.is_some()
    }

    /// What the catalogue says about it.
    pub fn grant(&self) -> Option<&'static Grant> {
        catalogue::grant(self.node)
    }
}

/// The instance being edited, its unsaved config, and what the linter
/// makes of that config as it stands.
pub struct Detail {
    /// The instance, opened once: its `save` is the only writer.
    inst: Instance,
    /// The profile its header names, for the title line.
    pub profile: Option<String>,
    /// The config as edited.
    pub buf: InstanceConfig,
    /// The config as last written, which is what `u` goes back to.
    saved: InstanceConfig,
    /// The rows the pane shows: every node the config holds, then every
    /// node it does not.
    pub rows: Vec<Row>,
    /// Which row is selected.
    pub selected: usize,
    /// What the linter reported about the config as edited.
    pub findings: Vec<Finding>,
    /// Why there is no report: a config the whole-file checks refuse
    /// (`camera` without `portals`) is a save that would be refused too.
    pub trouble: Option<String>,
    /// Whether the sandbox is running, which decides the banner: bwrap
    /// cannot be told about a bind after the fact, so an edit describes
    /// the next start.
    pub live: bool,
}

impl Detail {
    /// Open `name` for editing. The config read here is the buffer's
    /// starting point and the state `u` returns to.
    pub fn open(env: &Env, name: &str, live: bool) -> Result<Self, String> {
        let inst = Instance::open(env, name).map_err(|e| e.to_string())?;
        let text = std::fs::read_to_string(inst.config_path()).unwrap_or_default();
        let buf = inst.config.clone();
        let mut detail = Self {
            profile: instance::profile_header(&text).map(str::to_owned),
            saved: buf.clone(),
            buf,
            inst,
            rows: Vec::new(),
            selected: 0,
            findings: Vec::new(),
            trouble: None,
            live,
        };
        detail.refresh(env);
        Ok(detail)
    }

    /// The instance's name.
    pub fn name(&self) -> &str {
        &self.inst.name
    }

    /// Path of the file being edited, for the title line and the editor.
    pub fn path(&self) -> std::path::PathBuf {
        self.inst.config_path()
    }

    /// Whether the buffer has changes the file does not.
    pub fn dirty(&self) -> bool {
        self.buf != self.saved
    }

    /// The selected row, or `None` for an instance whose catalogue is
    /// somehow empty, which no shipped build has.
    pub fn row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// Rebuild the rows from the buffer and lint it. Called after every
    /// change, because a finding about the config as it was is worse than
    /// no finding at all.
    pub fn refresh(&mut self, env: &Env) {
        let node = self.row().map(|r| (r.node, r.target));
        match rows(&self.buf) {
            Ok(rows) => {
                self.rows = rows;
                self.trouble = None;
            }
            Err(e) => {
                self.rows = Vec::new();
                self.trouble = Some(e);
            }
        }
        // The selection follows the node it was on: toggling `wayland`
        // off moves it into the ungranted half, and the cursor goes with
        // it rather than staying on whatever slid into the row.
        self.selected = node
            .and_then(|(node, target)| {
                self.rows
                    .iter()
                    .position(|r| r.node == node && r.target == target)
                    .or_else(|| self.rows.iter().position(|r| r.node == node))
            })
            .unwrap_or(self.selected)
            .min(self.rows.len().saturating_sub(1));
        self.lint(env);
    }

    /// Lint the buffer as it stands, which is the whole value of showing
    /// findings at all: the file on disk is not what is being read.
    fn lint(&mut self, env: &Env) {
        self.findings.clear();
        let Ok(text) = kdl_out::render(&self.buf) else {
            return;
        };
        let search = crate::env::search_path();
        let ctx = lint::Context {
            env,
            host: &RealHost,
            search_path: &search,
        };
        match lint::lint_text(&ctx, Where::File(self.path()), text) {
            Ok(report) => self.findings = report.findings,
            Err(e) => self.trouble = Some(e.to_string()),
        }
    }

    /// The findings about the node on `row`, matched by the line the
    /// linter reported them at.
    pub fn findings_of(&self, row: &Row) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| {
                f.line
                    .is_some_and(|l| l >= row.line && l < row.line + row.height.max(1))
            })
            .collect()
    }

    /// Findings no row carries: the whole-file checks, which name a line
    /// the rendered config does not have.
    pub fn loose_findings(&self) -> Vec<&Finding> {
        let lines: Vec<u32> = self
            .rows
            .iter()
            .filter(|r| r.granted())
            .flat_map(|r| r.line..r.line + r.height.max(1))
            .collect();
        self.findings
            .iter()
            .filter(|f| !f.line.is_some_and(|l| lines.contains(&l)))
            .collect()
    }

    /// Grant or revoke the selected node. A node that takes an argument
    /// cannot be granted this way and says so: there is nothing sensible
    /// to write for it.
    pub fn toggle(&mut self, env: &Env) -> String {
        let Some(row) = self.row().cloned() else {
            return String::new();
        };
        if row.granted() {
            self.remove(row.target);
            self.refresh(env);
            return format!("removed `{}`", row.node);
        }
        match self.apply(env, row.node) {
            Ok(()) => format!("granted `{}`", row.node),
            Err(_) => format!(
                "`{}` takes an argument: Enter writes the line, `e` opens the file",
                row.node
            ),
        }
    }

    /// The line a prompt starts from for the selected row: the node as it
    /// is written, flattened onto one line, or the bare node name for one
    /// the config does not hold yet.
    pub fn prompt_line(&self) -> String {
        match self.row() {
            Some(Row {
                text: Some(text), ..
            }) => flatten(text),
            Some(row) => format!("{} ", row.node),
            None => String::new(),
        }
    }

    /// Replace the selected node with `text`, or add it where the config
    /// does not hold it yet. The text is parsed by the same parser the
    /// file is, so what the editor accepts is exactly what bubbler reads.
    pub fn apply(&mut self, env: &Env, text: &str) -> Result<(), String> {
        let target = self.row().map_or(Target::Absent, |r| r.target);
        let node = self.row().map(|r| r.node);
        let raw = config::parse_profile(text).map_err(|e| e.to_string())?;
        let written = written(raw)?;
        if let Some(node) = node
            && written.node() != node
        {
            return Err(format!(
                "that line writes `{}`, and the row is `{node}`",
                written.node()
            ));
        }
        self.write(written, target);
        self.refresh(env);
        Ok(())
    }

    /// Put what was written into the buffer, over the node the row names
    /// where there is one.
    fn write(&mut self, written: Written, target: Target) {
        match (written, target) {
            (Written::Service(s), Target::Service(i)) => self.buf.services[i] = s,
            (Written::Service(s), _) => self.buf.services.push(s),
            (Written::Env(pairs), Target::Env(i)) => {
                self.buf.env.splice(i..=i, pairs);
            }
            (Written::Env(pairs), _) => self.buf.env.extend(pairs),
            (Written::LintAllow(allows), Target::LintAllow(i)) => {
                self.buf.lint_allows.splice(i..=i, allows);
            }
            (Written::LintAllow(allows), _) => self.buf.lint_allows.extend(allows),
            (Written::Tty(mode), _) => self.buf.tty = mode,
            (Written::Userns(mode), _) => self.buf.userns = mode,
            (Written::Seccomp(cfg), _) => self.buf.seccomp = cfg,
            (Written::Desktop(name), _) => self.buf.desktop = Some(name),
            (Written::Command(argv), _) => self.buf.command = Some(argv),
        }
    }

    /// Take the node a row names out of the buffer.
    fn remove(&mut self, target: Target) {
        match target {
            Target::Service(i) => {
                self.buf.services.remove(i);
            }
            Target::Env(i) => {
                self.buf.env.remove(i);
            }
            Target::LintAllow(i) => {
                self.buf.lint_allows.remove(i);
            }
            Target::Tty => self.buf.tty = TtyMode::default(),
            Target::Userns => self.buf.userns = Userns::default(),
            Target::Seccomp => self.buf.seccomp = SeccompConfig::default(),
            Target::Desktop => self.buf.desktop = None,
            Target::Command => self.buf.command = None,
            Target::Absent => {}
        }
    }

    /// Write the buffer to `config.kdl` through [`Instance::save`], which
    /// keeps the headers, backs the old file up and re-parses what it
    /// wrote before replacing anything.
    pub fn save(&mut self, env: &Env) -> Result<String, String> {
        self.inst.save(&self.buf).map_err(|e| e.to_string())?;
        self.saved = self.buf.clone();
        self.refresh(env);
        let mut said = format!(
            "wrote {} (the file it replaced is config.kdl.bak; comments are not kept)",
            self.path().display()
        );
        if self.live {
            said.push_str(" — the sandbox is running, so this applies on the next start");
        }
        Ok(said)
    }

    /// Go back to the config as last written.
    pub fn undo(&mut self, env: &Env) {
        self.buf = self.saved.clone();
        self.refresh(env);
    }
}

/// A node written on one line, whatever it looks like in the file: a
/// block node is valid KDL on one line too, so the prompt can hold every
/// node the config has and `e` stays for the ones worth reading in an
/// editor.
pub fn flatten(text: &str) -> String {
    text.lines().map(str::trim).collect::<Vec<&str>>().join(" ")
}

/// What one parsed node wrote. Exactly one of these comes out of a line,
/// which is what makes "the row and the line disagree" something the
/// editor can say before anything is changed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Written {
    Service(Service),
    Env(Vec<(String, String)>),
    LintAllow(Vec<LintAllow>),
    Tty(TtyMode),
    Userns(Userns),
    Seccomp(SeccompConfig),
    Desktop(String),
    Command(Vec<OsString>),
}

impl Written {
    /// The node name it was written as.
    fn node(&self) -> &'static str {
        match self {
            Self::Service(s) => s.node_name(),
            Self::Env(_) => "env",
            Self::LintAllow(_) => "lint-allow",
            Self::Tty(_) => "tty",
            Self::Userns(_) => "userns",
            Self::Seccomp(_) => "seccomp",
            Self::Desktop(_) => "desktop",
            Self::Command(_) => "command",
        }
    }
}

/// The one node a line wrote. Two nodes on one line is refused rather
/// than half-applied: the row the prompt was opened on names one node,
/// and the editor never writes a node the user cannot see.
fn written(raw: RawProfile) -> Result<Written, String> {
    if !raw.includes.is_empty() {
        return Err("an instance config includes no profile".to_owned());
    }
    let cfg = raw.config;
    let mut found: Vec<Written> = Vec::new();
    found.extend(cfg.services.into_iter().map(Written::Service));
    if !cfg.env.is_empty() {
        found.push(Written::Env(cfg.env));
    }
    if !cfg.lint_allows.is_empty() {
        found.push(Written::LintAllow(cfg.lint_allows));
    }
    if raw.tty_set {
        found.push(Written::Tty(cfg.tty));
    }
    if raw.userns_set {
        found.push(Written::Userns(cfg.userns));
    }
    if cfg.seccomp != SeccompConfig::default() {
        found.push(Written::Seccomp(cfg.seccomp));
    }
    if let Some(name) = cfg.desktop {
        found.push(Written::Desktop(name));
    }
    if let Some(argv) = cfg.command {
        found.push(Written::Command(argv));
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("that line writes no node".to_owned()),
        n => Err(format!("that line writes {n} nodes, and a row is one")),
    }
}

/// The rows of a config: every node it holds, in the order
/// [`kdl_out::nodes`] renders them so that the line numbers below are the
/// ones the linter reports, then every node it does not hold, in the
/// order the catalogue and the README document them.
fn rows(cfg: &InstanceConfig) -> Result<Vec<Row>, String> {
    let mut out = Builder::default();
    for (i, allow) in cfg.lint_allows.iter().enumerate() {
        out.push(
            "lint-allow",
            kdl_out::lint_allow(allow),
            Target::LintAllow(i),
        );
    }
    for (i, service) in cfg.services.iter().enumerate() {
        let text = kdl_out::service(service).map_err(|e| e.to_string())?;
        out.push(service.node_name(), text, Target::Service(i));
    }
    for (i, (key, value)) in cfg.env.iter().enumerate() {
        out.push("env", kdl_out::env(key, value), Target::Env(i));
    }
    if cfg.tty != TtyMode::default() {
        out.push("tty", kdl_out::tty(cfg.tty), Target::Tty);
    }
    if cfg.userns != Userns::default() {
        out.push("userns", kdl_out::userns(cfg.userns), Target::Userns);
    }
    if cfg.seccomp != SeccompConfig::default() {
        out.push("seccomp", kdl_out::seccomp(&cfg.seccomp), Target::Seccomp);
    }
    if let Some(name) = &cfg.desktop {
        out.push("desktop", kdl_out::desktop(name), Target::Desktop);
    }
    if let Some(argv) = &cfg.command {
        let text = kdl_out::command(argv).map_err(|e| e.to_string())?;
        out.push("command", text, Target::Command);
    }
    let mut rows = out.rows;
    let absent: Vec<Row> = catalogue::GRANTS
        .iter()
        .filter(|g| !rows.iter().any(|r| r.node == g.node))
        .map(|g| Row {
            node: g.node,
            text: None,
            target: Target::Absent,
            line: 0,
            height: 0,
        })
        .collect();
    rows.extend(absent);
    Ok(rows)
}

/// Rows and the line each starts on, counted as they are added.
#[derive(Default)]
struct Builder {
    rows: Vec<Row>,
    line: u32,
}

impl Builder {
    fn push(&mut self, node: &'static str, text: String, target: Target) {
        let height = u32::try_from(text.lines().count()).unwrap_or(1);
        self.rows.push(Row {
            node,
            text: Some(text),
            target,
            line: self.line + 1,
            height,
        });
        self.line += height;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use bubbler_core::config::{ShareMode, WaylandMode};
    use bubbler_core::lint::Severity;

    /// Errors, warnings and notes the buffer has as it stands.
    fn severities(detail: &Detail) -> [usize; 3] {
        [Severity::Error, Severity::Warning, Severity::Note]
            .map(|s| detail.findings.iter().filter(|f| f.severity == s).count())
    }

    /// Put the cursor on the first row for `node`, as the keys do.
    fn select(detail: &mut Detail, node: &str) {
        detail.selected = detail
            .rows
            .iter()
            .position(|r| r.node == node)
            .unwrap_or_else(|| panic!("no row for `{node}`"));
    }

    #[test]
    fn the_rows_are_the_rendered_config_line_for_line() {
        let mut cfg = InstanceConfig {
            services: vec![
                Service::Wayland(WaylandMode::default()),
                Service::HomeShare {
                    path: "Downloads".into(),
                    mode: ShareMode::ReadWrite,
                },
                Service::Dbus { rules: vec![] },
            ],
            ..InstanceConfig::default()
        };
        cfg.services[2] = config::parse_profile("dbus { talk \"ca.desrt.dconf\" }")
            .unwrap()
            .config
            .services
            .remove(0);
        cfg.env.push(("A".to_owned(), "1".to_owned()));
        cfg.tty = TtyMode::None;
        cfg.command = Some(vec!["true".into()]);
        let rows = rows(&cfg).unwrap();
        let granted: Vec<&Row> = rows.iter().filter(|r| r.granted()).collect();
        let text: String = granted
            .iter()
            .map(|r| format!("{}\n", r.text.as_deref().unwrap_or_default()))
            .collect();
        assert_eq!(text, kdl_out::render(&cfg).unwrap());
        // Every finding the linter reports names a line of that text, so
        // the row's line must be where the node really starts.
        let mut line = 1;
        for row in &granted {
            assert_eq!(row.line, line, "{:?}", row.node);
            line += row.height;
        }
        // The dbus node is the one that takes more than a line.
        let dbus = granted.iter().find(|r| r.node == "dbus").unwrap();
        assert_eq!(dbus.height, 3);
        // Every node the catalogue knows is offered, granted or not.
        assert_eq!(rows.len(), catalogue::GRANTS.len(), "one row per node");
    }

    #[test]
    fn space_grants_a_bare_node_and_takes_it_back() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        select(&mut detail, "pipewire");
        assert!(!detail.row().unwrap().granted());
        assert_eq!(detail.toggle(&env), "granted `pipewire`");
        assert!(detail.buf.services.contains(&Service::Pipewire));
        assert!(detail.dirty(), "the file does not have it yet");
        // The cursor follows the node it was on, into the granted half.
        assert_eq!(detail.row().unwrap().node, "pipewire");
        assert_eq!(detail.toggle(&env), "removed `pipewire`");
        assert!(!detail.buf.services.contains(&Service::Pipewire));
        assert!(!detail.dirty(), "back to the file");
    }

    #[test]
    fn a_node_that_takes_an_argument_is_not_guessed_at() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        select(&mut detail, "home-share");
        let said = detail.toggle(&env);
        assert!(said.contains("Enter"), "{said}");
        assert!(!detail.dirty(), "nothing was written");
        assert_eq!(detail.prompt_line(), "home-share ");
    }

    #[test]
    fn a_written_line_replaces_the_node_the_row_names() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        select(&mut detail, "home-share");
        detail
            .apply(&env, "home-share \"Downloads\" mode=rw")
            .unwrap();
        assert_eq!(
            detail
                .buf
                .services
                .iter()
                .filter(|s| matches!(s, Service::HomeShare { .. }))
                .count(),
            1
        );
        select(&mut detail, "home-share");
        assert_eq!(detail.prompt_line(), "home-share \"Downloads\" mode=rw");
        detail.apply(&env, "home-share \"Documents\"").unwrap();
        let shares: Vec<&Service> = detail
            .buf
            .services
            .iter()
            .filter(|s| matches!(s, Service::HomeShare { .. }))
            .collect();
        assert_eq!(
            shares,
            [&Service::HomeShare {
                path: "Documents".into(),
                mode: ShareMode::ReadOnly
            }],
            "the row was replaced, not added to"
        );
    }

    #[test]
    fn a_line_that_writes_another_node_or_none_is_refused() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        select(&mut detail, "wayland");
        let e = detail.apply(&env, "x11").unwrap_err();
        assert!(e.contains("writes `x11`"), "{e}");
        let e = detail.apply(&env, "").unwrap_err();
        assert!(e.contains("no node"), "{e}");
        let e = detail.apply(&env, "wayland; x11").unwrap_err();
        assert!(e.contains("2 nodes"), "{e}");
        let e = detail.apply(&env, "teleport").unwrap_err();
        assert!(!e.is_empty(), "the parser's own reason is passed on");
        assert!(!detail.dirty(), "nothing refused was applied");
    }

    #[test]
    fn saving_keeps_the_headers_and_leaves_the_old_file_beside_it() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        select(&mut detail, "pipewire");
        detail.toggle(&env);
        let said = detail.save(&env).unwrap();
        assert!(said.contains("config.kdl.bak"), "{said}");
        assert!(!detail.dirty(), "the file is the buffer now");
        let text = std::fs::read_to_string(detail.path()).unwrap();
        assert!(text.starts_with("// bubbler profile: generic\n"), "{text}");
        assert!(text.contains("// bubbler config: "), "{text}");
        assert!(text.contains("pipewire"), "{text}");
        assert!(detail.path().with_extension("kdl.bak").exists());
        // What was saved is what the next open reads.
        let again = Detail::open(&env, "ff", false).unwrap();
        assert_eq!(again.buf, detail.buf);
    }

    #[test]
    fn undo_goes_back_to_the_config_as_last_written() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        let before = detail.buf.clone();
        select(&mut detail, "x11");
        detail.toggle(&env);
        assert!(detail.dirty());
        detail.undo(&env);
        assert_eq!(detail.buf, before);
        assert!(!detail.dirty());
    }

    #[test]
    fn a_finding_is_shown_on_the_row_it_is_about() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        select(&mut detail, "x11");
        // The session's socket, which is the mode a finding is about: a
        // nested server needs `wayland` and `dri` under it.
        detail.apply(&env, "x11 \"host\"").unwrap();
        select(&mut detail, "x11");
        let row = detail.row().unwrap().clone();
        let findings = detail.findings_of(&row);
        assert!(
            findings.iter().any(|f| f.id == "x11-without-reason"),
            "{findings:?}"
        );
        assert_eq!(
            severities(&detail)[1],
            1,
            "one warning, before anything is saved"
        );
        // And a row that is not the one it is about does not carry it.
        select(&mut detail, "wayland");
        let wayland = detail.row().unwrap().clone();
        assert!(detail.findings_of(&wayland).is_empty());
    }

    #[test]
    fn a_config_the_whole_file_checks_refuse_says_so_before_a_save_does() {
        let (_tmp, env) = fixture::store(&[("ff", "generic")]);
        let mut detail = Detail::open(&env, "ff", false).unwrap();
        select(&mut detail, "camera");
        detail.toggle(&env);
        let row = detail.row().unwrap().clone();
        let said = detail
            .findings_of(&row)
            .into_iter()
            .chain(detail.loose_findings())
            .any(|f| f.message.contains("portals") || f.help.contains("portals"));
        assert!(said, "{:?}", detail.findings);
        assert_eq!(
            severities(&detail)[0],
            1,
            "an error is reported before a save is refused"
        );
        assert!(detail.save(&env).is_err(), "and the save is refused too");
    }
}
