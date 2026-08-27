//! One instance's config as the editor holds it: a typed
//! [`InstanceConfig`] that is rendered to KDL for the linter and written
//! back by [`Instance::save`], never a text buffer. A config the editor
//! holds cannot fail to parse, which is why there is no syntax error to
//! recover from anywhere below.

use bubbler_core::catalogue::{self, Grant};
use bubbler_core::config::{self, Disabled, InstanceConfig, Node, RawProfile, Userns};
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
    /// One entry the file keeps on a `/-` line without granting it, by
    /// its index in [`InstanceConfig::disabled`].
    Disabled(usize),
    /// The row that writes another entry of a repeatable node, named by
    /// that node: a second `home-share` is added, not written over the
    /// first.
    Add(&'static str),
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
    /// Whether the config grants this node. A disabled entry is written
    /// in the file and shown on a row of its own, and grants nothing.
    pub fn granted(&self) -> bool {
        self.text.is_some() && !self.disabled()
    }

    /// Whether the file keeps this entry on a `/-` line: a node the
    /// editor can hand back, and nothing downstream ever reads.
    pub fn disabled(&self) -> bool {
        matches!(self.target, Target::Disabled(_))
    }

    /// Whether this row writes another entry of a repeatable node
    /// rather than naming one the config holds.
    pub fn adds(&self) -> bool {
        matches!(self.target, Target::Add(_))
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
    /// The rows the pane shows: every entry the config holds, granted
    /// or disabled, the row that adds another entry of a repeatable
    /// node, then every node the config does not hold at all.
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
        let text = config::read_bounded(&inst.config_path()).unwrap_or_default();
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
        let row = self.row().map(|r| (r.node, r.target, r.text.clone()));
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
        // The selection follows the entry it was on: toggling `wayland`
        // off moves it into the ungranted half, and the cursor goes with
        // it rather than staying on whatever slid into the row. What the
        // row says is asked before where it lives, because an index is
        // what the entry beside it inherits: disabling the first of two
        // `home-share`s leaves `Service(0)` naming the second, and a
        // cursor that followed the index would put the next Space on an
        // entry nobody aimed at.
        self.selected = row
            .and_then(|(node, target, text)| {
                let rows = &self.rows;
                let is = |r: &Row| r.node == node;
                rows.iter()
                    .position(|r| is(r) && r.text == text && r.target == target)
                    // Only an entry is followed by what it says: the row
                    // that writes the next entry says nothing either,
                    // and a config the first `home-share` was just
                    // written into holds both.
                    .or_else(|| {
                        rows.iter()
                            .position(|r| is(r) && r.text.is_some() && r.text == text)
                    })
                    .or_else(|| rows.iter().position(|r| is(r) && r.target == target))
                    .or_else(|| rows.iter().position(is))
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
            .filter(|r| r.text.is_some())
            .flat_map(|r| r.line..r.line + r.height.max(1))
            .collect();
        self.findings
            .iter()
            .filter(|f| !f.line.is_some_and(|l| lines.contains(&l)))
            .collect()
    }

    /// Grant, disable, enable or revoke the selected node. A granted
    /// node that carries anything beyond its name is kept as a `/-`
    /// line rather than dropped: Space is how a grant is tried without,
    /// not how the line that spells it out is lost. A node that takes an
    /// argument cannot be granted this way and says so: there is nothing
    /// sensible to write for it.
    pub fn toggle(&mut self, env: &Env) -> String {
        let Some(row) = self.row().cloned() else {
            return String::new();
        };
        if let Target::Disabled(i) = row.target {
            let said = self.enable(i);
            self.refresh(env);
            return said;
        }
        if row.granted() {
            if self.node_at(row.target).is_some_and(|n| n.has_content()) {
                self.disable(row.target);
                self.refresh(env);
                return format!("disabled `{}` (kept as a `/-` line)", row.node);
            }
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

    /// The line a prompt starts from for the selected row: the entry as
    /// it is written, flattened onto one line and without the `/-` of a
    /// disabled one, or the bare node name for the row that adds an
    /// entry and for a node the config does not hold yet.
    pub fn prompt_line(&self) -> String {
        match self.row() {
            Some(Row {
                text: Some(text), ..
            }) => flatten(text),
            Some(row) => format!("{} ", row.node),
            None => String::new(),
        }
    }

    /// Replace the selected entry with `text`, or add it where the row
    /// is one that adds an entry or names a node the config does not
    /// hold yet; an entry that was disabled stays disabled. The text is
    /// parsed by the same parser the file is, so what the editor accepts
    /// is exactly what bubbler reads.
    pub fn apply(&mut self, env: &Env, text: &str) -> Result<(), String> {
        let target = self.row().map_or(Target::Absent, |r| r.target);
        let node = self.row().map(|r| r.node);
        let raw = config::parse_profile(text).map_err(|e| e.to_string())?;
        let written = written(raw)?;
        if let Some(node) = node
            && written.name() != node
        {
            return Err(format!(
                "that line writes `{}`, and the row is `{node}`",
                written.name()
            ));
        }
        // A disabled entry is written back as one node on one line. A
        // line with no such form — two `lint-allow` ids, say — would
        // leave the pane with nothing to draw until `u`, so the prompt
        // says why instead, as it does for every other line it refuses.
        if matches!(target, Target::Disabled(_)) {
            kdl_out::node(&written).map_err(|e| e.to_string())?;
        }
        // A row that adds an entry pushes rather than replaces it, and
        // what makes two entries one node — the path of a share, the
        // key of an `env` — is the parser's rule and not the editor's.
        // So the parser is asked before the push: a buffer holding both
        // renders to a config it refuses, which is the pane going blank
        // with `given more than once` under it.
        if matches!(target, Target::Add(_) | Target::Absent) && self.would_repeat(&written)? {
            return Err(format!("`{}` is already there", flatten(text.trim())));
        }
        self.write(written, target);
        self.refresh(env);
        Ok(())
    }

    /// Take the entry the selected row names out of the buffer, granted
    /// or not, and say what went. A row that names no entry — the row
    /// that adds one, and a node the config does not hold — has nothing
    /// to remove and says nothing.
    pub fn clear(&mut self, env: &Env) -> String {
        let Some(row) = self.row().cloned() else {
            return String::new();
        };
        let Some(text) = row.text else {
            return String::new();
        };
        self.remove(row.target);
        self.refresh(env);
        format!("removed {}", flatten(&text))
    }

    /// Whether the buffer already holds `written`, asked by rendering
    /// the buffer with that node under it and reading it back: the
    /// duplicate rule is the parser's, down to a share whose path is
    /// written another way. Only a repeat is answered here — a buffer
    /// that does not parse for some other reason is the pane's business
    /// and not this line's.
    fn would_repeat(&self, written: &Node) -> Result<bool, String> {
        let mut text = kdl_out::render(&self.buf).map_err(|e| e.to_string())?;
        text.push_str(&kdl_out::node(written).map_err(|e| e.to_string())?);
        text.push('\n');
        Ok(matches!(
            config::parse(&text),
            Err(config::ConfigError::Duplicate(_))
        ))
    }

    /// Put what was written into the buffer, over the node the row names
    /// where there is one.
    fn write(&mut self, written: Node, target: Target) {
        if let Target::Disabled(i) = target {
            // An edit of a disabled entry leaves it disabled: Space is
            // what turns one back on, Enter is what fixes what it says.
            let Some(entry) = self.buf.disabled.get_mut(i) else {
                return;
            };
            entry.node = written;
            return;
        }
        let rank = config::section_rank(&written);
        match (written, target) {
            (Node::Service(s), Target::Service(i)) => {
                // An index is stale only between a change and the
                // refresh that follows it, so this is an entry the
                // buffer has lost rather than a line to write anywhere
                // else; a panic here would leave the terminal raw.
                let Some(slot) = self.buf.services.get_mut(i) else {
                    return;
                };
                *slot = s;
            }
            (Node::Service(s), _) => self.buf.services.push(s),
            (Node::Env(pairs), Target::Env(i)) => {
                // An entry the buffer has lost, as above.
                if i >= self.buf.env.len() {
                    return;
                }
                let grew = grew_by(pairs.len());
                self.buf.env.splice(i..=i, pairs);
                self.shift_disabled(rank, i, grew);
            }
            (Node::Env(pairs), _) => self.buf.env.extend(pairs),
            (Node::LintAllow(allows), Target::LintAllow(i)) => {
                // An entry the buffer has lost, as above.
                if i >= self.buf.lint_allows.len() {
                    return;
                }
                let grew = grew_by(allows.len());
                self.buf.lint_allows.splice(i..=i, allows);
                self.shift_disabled(rank, i, grew);
            }
            (Node::LintAllow(allows), _) => self.buf.lint_allows.extend(allows),
            (Node::Tty(mode), _) => self.buf.tty = mode,
            (Node::Userns(mode), _) => self.buf.userns = mode,
            (Node::Seccomp(cfg), _) => self.buf.seccomp = cfg,
            (Node::Desktop(name), _) => self.buf.desktop = Some(name),
            (Node::Command(argv), _) => self.buf.command = Some(argv),
        }
    }

    /// The node a row names, read back out of the buffer as the parser
    /// would have read it from the file: what [`Node::has_content`] is
    /// asked about, and what a `/-` line keeps.
    fn node_at(&self, target: Target) -> Option<Node> {
        Some(match target {
            Target::Service(i) => Node::Service(self.buf.services.get(i)?.clone()),
            Target::Env(i) => Node::Env(vec![self.buf.env.get(i)?.clone()]),
            Target::LintAllow(i) => Node::LintAllow(vec![self.buf.lint_allows.get(i)?.clone()]),
            Target::Tty => Node::Tty(self.buf.tty),
            Target::Userns => Node::Userns(self.buf.userns),
            Target::Seccomp => Node::Seccomp(self.buf.seccomp.clone()),
            Target::Desktop => Node::Desktop(self.buf.desktop.clone()?),
            Target::Command => Node::Command(self.buf.command.clone()?),
            Target::Disabled(i) => self.buf.disabled.get(i)?.node.clone(),
            Target::Add(_) | Target::Absent => return None,
        })
    }

    /// Take the node a row names out of the buffer, and leave the `/-`
    /// lines of its section pointing at the entries they were read
    /// above: the ones below this entry now sit one nearer the top.
    fn remove(&mut self, target: Target) {
        let Some(node) = self.node_at(target) else {
            // The row names no entry, or names one the buffer has lost.
            // An index is stale only between a change and the refresh
            // that follows it, and a panic here would leave the terminal
            // raw and the editor gone.
            return;
        };
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
            Target::Disabled(i) => {
                self.buf.disabled.remove(i);
            }
            Target::Add(_) | Target::Absent => {}
        }
        if let Some(i) = index_of(target) {
            self.shift_disabled(config::section_rank(&node), i, -1);
        }
    }

    /// Move the `/-` lines of one section that sit below the entry at
    /// `i` by `by` entries. Each of them names the entry it was read
    /// above, so a section that grows or shrinks above them moves that
    /// entry and has to move them with it.
    fn shift_disabled(&mut self, rank: u8, i: usize, by: isize) {
        for entry in &mut self.buf.disabled {
            if config::section_rank(&entry.node) == rank && entry.before > i {
                entry.before = entry.before.saturating_add_signed(by);
            }
        }
    }

    /// Keep the entry a row names as a `/-` line where it is: `before`
    /// is the index it had, which is the index of the entry that
    /// follows it once it is out of its section.
    fn disable(&mut self, target: Target) {
        let (Some(node), Some(before)) = (self.node_at(target), index_of(target)) else {
            return;
        };
        let rank = config::section_rank(&node);
        // Read before the entry goes, because taking it out moves the
        // `/-` lines below it up: an entry disabled above one of them
        // is written above it, and one below it below.
        let at = self
            .buf
            .disabled
            .iter()
            .position(|d| (config::section_rank(&d.node), d.before) > (rank, before))
            .unwrap_or(self.buf.disabled.len());
        self.remove(target);
        self.buf.disabled.insert(at, Disabled { node, before });
    }

    /// Put a disabled entry back among the entries it was read with. A
    /// node a config holds one of — `tty`, `command` — is written over
    /// where one is granted: the entry the cursor is on is the one that
    /// was asked for.
    fn enable(&mut self, i: usize) -> String {
        let Some(entry) = self.buf.disabled.get(i).cloned() else {
            return String::new();
        };
        let node = entry.node.name();
        self.buf.disabled.remove(i);
        let rank = config::section_rank(&entry.node);
        let at = entry.before.min(self.section_len(&entry.node));
        let written = self.insert(entry.node, at);
        // The `/-` lines below it in its section stand above the entries
        // it added as well now. Which they are is a matter of where they
        // sit in the list rather than of the count they hold: one that
        // named the same entry from above stays above it.
        for entry in self.buf.disabled.iter_mut().skip(i) {
            if config::section_rank(&entry.node) == rank {
                entry.before += written.count();
            }
        }
        match written {
            Placed::Added(_) => format!("enabled `{node}`"),
            Placed::Replaced => format!("enabled `{node}` over the one it held"),
            Placed::Default => {
                format!("enabled `{node}`: the default, so there is no line to write")
            }
            Placed::DefaultOver => {
                format!("enabled `{node}`: the default, over the one it held, so no line remains")
            }
        }
    }

    /// Put an entry into its section at `at`, and say what that did to
    /// the section.
    fn insert(&mut self, node: Node, at: usize) -> Placed {
        match node {
            Node::Service(s) => {
                let at = at.min(self.buf.services.len());
                self.buf.services.insert(at, s);
                Placed::Added(1)
            }
            Node::Env(pairs) => {
                let at = at.min(self.buf.env.len());
                let added = pairs.len();
                self.buf.env.splice(at..at, pairs);
                Placed::Added(added)
            }
            Node::LintAllow(allows) => {
                let at = at.min(self.buf.lint_allows.len());
                let added = allows.len();
                self.buf.lint_allows.splice(at..at, allows);
                Placed::Added(added)
            }
            Node::Tty(mode) => {
                let held = self.buf.tty != TtyMode::default();
                self.buf.tty = mode;
                Placed::one_of(held, self.buf.tty == TtyMode::default())
            }
            Node::Userns(mode) => {
                let held = self.buf.userns != Userns::default();
                self.buf.userns = mode;
                Placed::one_of(held, self.buf.userns == Userns::default())
            }
            Node::Seccomp(cfg) => {
                let held = self.buf.seccomp != SeccompConfig::default();
                self.buf.seccomp = cfg;
                Placed::one_of(held, self.buf.seccomp == SeccompConfig::default())
            }
            Node::Desktop(name) => Placed::one_of(self.buf.desktop.replace(name).is_some(), false),
            Node::Command(argv) => Placed::one_of(self.buf.command.replace(argv).is_some(), false),
        }
    }

    /// How many entries the section `node` belongs to holds, which is
    /// where a `before` past the end of it lands.
    fn section_len(&self, node: &Node) -> usize {
        match node {
            Node::LintAllow(_) => self.buf.lint_allows.len(),
            Node::Service(_) => self.buf.services.len(),
            Node::Env(_) => self.buf.env.len(),
            Node::Tty(_) => usize::from(self.buf.tty != TtyMode::default()),
            Node::Userns(_) => usize::from(self.buf.userns != Userns::default()),
            Node::Seccomp(_) => usize::from(self.buf.seccomp != SeccompConfig::default()),
            Node::Desktop(_) => usize::from(self.buf.desktop.is_some()),
            Node::Command(_) => usize::from(self.buf.command.is_some()),
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

/// What putting an entry back into its section did, which is what the
/// editor says about it: a line appearing is not a line written over.
enum Placed {
    /// The section gained this many entries.
    Added(usize),
    /// The granted node of a kind a config holds one of was written
    /// over, because two of that node is not a config bubbler reads.
    Replaced,
    /// The value is the node's own default, which a file spells by
    /// leaving the node out: no line is written at all.
    Default,
    /// The default was written over a granted value: the line that was
    /// there is gone, and none takes its place.
    DefaultOver,
}

impl Placed {
    /// What writing a node a config holds one of did: `held` says
    /// whether one was granted before it, `bare` whether what was
    /// written is the default the file holds no line for.
    fn one_of(held: bool, bare: bool) -> Self {
        match (held, bare) {
            (true, true) => Self::DefaultOver,
            (false, true) => Self::Default,
            (true, false) => Self::Replaced,
            (false, false) => Self::Added(1),
        }
    }

    /// How many entries the section gained.
    fn count(&self) -> usize {
        match self {
            Self::Added(n) => *n,
            Self::Replaced | Self::Default | Self::DefaultOver => 0,
        }
    }
}

/// How far a line that writes `n` entries moves what was below the one
/// entry it replaced.
fn grew_by(n: usize) -> isize {
    isize::try_from(n.saturating_sub(1)).unwrap_or_default()
}

/// Where in its section the entry a target names sits, which is what a
/// `/-` line's `before` counts. A node a config holds one of is the
/// first entry of a section of its own; a row that names no entry has
/// no index at all.
fn index_of(target: Target) -> Option<usize> {
    Some(match target {
        Target::LintAllow(i) | Target::Service(i) | Target::Env(i) => i,
        Target::Tty | Target::Userns | Target::Seccomp | Target::Desktop | Target::Command => 0,
        Target::Disabled(_) | Target::Add(_) | Target::Absent => return None,
    })
}

/// The one node a line wrote. Two nodes on one line is refused rather
/// than half-applied: the row the prompt was opened on names one node,
/// and the editor never writes a node the user cannot see.
fn written(raw: RawProfile) -> Result<Node, String> {
    if !raw.includes.is_empty() {
        return Err("an instance config includes no profile".to_owned());
    }
    let cfg = raw.config;
    let mut found: Vec<Node> = Vec::new();
    found.extend(cfg.services.into_iter().map(Node::Service));
    if !cfg.env.is_empty() {
        found.push(Node::Env(cfg.env));
    }
    if !cfg.lint_allows.is_empty() {
        found.push(Node::LintAllow(cfg.lint_allows));
    }
    if raw.tty_set {
        found.push(Node::Tty(cfg.tty));
    }
    if raw.userns_set {
        found.push(Node::Userns(cfg.userns));
    }
    if cfg.seccomp != SeccompConfig::default() {
        found.push(Node::Seccomp(cfg.seccomp));
    }
    if let Some(name) = cfg.desktop {
        found.push(Node::Desktop(name));
    }
    if let Some(argv) = cfg.command {
        found.push(Node::Command(argv));
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("that line writes no node".to_owned()),
        n => Err(format!("that line writes {n} nodes, and a row is one")),
    }
}

/// The rows of a config: every entry it holds, granted or disabled, in
/// the order [`kdl_out::nodes`] renders them so that the line numbers
/// below are the ones the linter reports; a row after the last entry of
/// every repeatable node it holds, which is what writes another one;
/// then every node it does not hold at all, in the order the catalogue
/// and the README document them.
fn rows(cfg: &InstanceConfig) -> Result<Vec<Row>, String> {
    let mut out = Builder::default();
    out.section(
        cfg,
        |n| matches!(n, Node::LintAllow(_)),
        cfg.lint_allows
            .iter()
            .enumerate()
            .map(|(i, allow)| {
                (
                    "lint-allow",
                    kdl_out::lint_allow(allow),
                    Target::LintAllow(i),
                )
            })
            .collect(),
    )?;
    let services = cfg
        .services
        .iter()
        .enumerate()
        .map(|(i, service)| {
            kdl_out::service(service)
                .map(|text| (service.node_name(), text, Target::Service(i)))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    out.section(cfg, |n| matches!(n, Node::Service(_)), services)?;
    out.section(
        cfg,
        |n| matches!(n, Node::Env(_)),
        cfg.env
            .iter()
            .enumerate()
            .map(|(i, (key, value))| ("env", kdl_out::env(key, value), Target::Env(i)))
            .collect(),
    )?;
    out.section(
        cfg,
        |n| matches!(n, Node::Tty(_)),
        (cfg.tty != TtyMode::default())
            .then(|| ("tty", kdl_out::tty(cfg.tty), Target::Tty))
            .into_iter()
            .collect(),
    )?;
    out.section(
        cfg,
        |n| matches!(n, Node::Userns(_)),
        (cfg.userns != Userns::default())
            .then(|| ("userns", kdl_out::userns(cfg.userns), Target::Userns))
            .into_iter()
            .collect(),
    )?;
    out.section(
        cfg,
        |n| matches!(n, Node::Seccomp(_)),
        (cfg.seccomp != SeccompConfig::default())
            .then(|| ("seccomp", kdl_out::seccomp(&cfg.seccomp), Target::Seccomp))
            .into_iter()
            .collect(),
    )?;
    out.section(
        cfg,
        |n| matches!(n, Node::Desktop(_)),
        cfg.desktop
            .iter()
            .map(|name| ("desktop", kdl_out::desktop(name), Target::Desktop))
            .collect(),
    )?;
    let command = cfg
        .command
        .as_ref()
        .map(|argv| kdl_out::command(argv))
        .transpose()
        .map_err(|e| e.to_string())?;
    out.section(
        cfg,
        |n| matches!(n, Node::Command(_)),
        command
            .map(|text| ("command", text, Target::Command))
            .into_iter()
            .collect(),
    )?;
    let mut rows = out.rows;
    // A repeatable node with an entry keeps a bare row after its last
    // one: Enter on an entry writes that entry, and there has to be a
    // row that writes the next. With no entry at all its row is the one
    // in the absent block below, where Enter opens the same prompt.
    for node in config::REPEATABLE {
        let Some(last) = rows.iter().rposition(|r| r.node == *node) else {
            continue;
        };
        rows.insert(
            last + 1,
            Row {
                node,
                text: None,
                target: Target::Add(node),
                line: 0,
                height: 0,
            },
        );
    }
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
    /// One section of the file: its entries with the disabled ones of
    /// the same section among them, in the one order
    /// [`kdl_out::section_entries`] holds for every reader of a section.
    /// That order is the file's, which is what makes a row's line the
    /// line a finding names.
    fn section(
        &mut self,
        cfg: &InstanceConfig,
        is: fn(&Node) -> bool,
        enabled: Vec<(&'static str, String, Target)>,
    ) -> Result<(), String> {
        for entry in kdl_out::section_entries(cfg, is, enabled) {
            match entry {
                kdl_out::Entry::Enabled((node, text, target)) => self.push(node, text, target),
                // Shown as the node it holds and never as `/-`: the
                // prompt writes a line, and Space is what turns one
                // back on.
                kdl_out::Entry::Disabled(i, d) => {
                    let text = kdl_out::node(&d.node).map_err(|e| e.to_string())?;
                    self.push(d.node.name(), text, Target::Disabled(i));
                }
            }
        }
        Ok(())
    }

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
    use bubbler_core::config::{Service, ShareMode, WaylandMode};
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

    /// An editor over an instance whose `config.kdl` holds `text`. A
    /// disabled entry is read from the file like every other node, so a
    /// file is how one gets into the buffer.
    fn editing(text: &str) -> (tempfile::TempDir, Env, Detail) {
        let (tmp, env) = fixture::store(&[("ff", "generic")]);
        std::fs::write(
            instance::config_path(&env, "ff"),
            format!("// bubbler profile: generic\n// bubbler config: 2\n{text}"),
        )
        .expect("the config is written");
        let detail = Detail::open(&env, "ff", false).expect("the instance opens");
        (tmp, env, detail)
    }

    /// The rows for `node`, in the order the pane shows them.
    fn rows_for<'a>(detail: &'a Detail, node: &str) -> Vec<&'a Row> {
        detail.rows.iter().filter(|r| r.node == node).collect()
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
        // A node the file keeps without granting it stands on its own
        // line among the entries of its section, so the rows below it
        // are the lines the linter counts.
        cfg.disabled.push(config::Disabled {
            node: config::Node::Service(Service::HomeShare {
                path: "Music".into(),
                mode: ShareMode::ReadOnly,
            }),
            before: 1,
        });
        let rows = rows(&cfg).unwrap();
        let written: Vec<&Row> = rows.iter().filter(|r| r.text.is_some()).collect();
        let text: String = written
            .iter()
            .map(|r| {
                let text = r.text.as_deref().unwrap_or_default();
                match r.disabled() {
                    true => format!("/-{text}\n"),
                    false => format!("{text}\n"),
                }
            })
            .collect();
        assert_eq!(text, kdl_out::render(&cfg).unwrap());
        // Every finding the linter reports names a line of that text, so
        // the row's line must be where the node really starts.
        let mut line = 1;
        for row in &written {
            assert_eq!(row.line, line, "{:?}", row.node);
            line += row.height;
        }
        assert!(written[1].disabled(), "the `/-` line is where it was");
        assert!(!written[1].granted());
        // The dbus node is the one that takes more than a line.
        let dbus = written.iter().find(|r| r.node == "dbus").unwrap();
        assert_eq!(dbus.height, 3);
        // Every node the catalogue knows is offered, granted or not,
        // and beside them the disabled entry and the rows that add a
        // second `home-share` and a second `env`.
        assert_eq!(
            rows.len(),
            catalogue::GRANTS.len() + 3,
            "one row per node, and the repeatable ones say so"
        );
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

    /// A row that adds an entry pushes rather than replaces, so an
    /// entry the buffer already holds would make a config the parser
    /// refuses — and the pane would go blank with the parser's words
    /// under it. The prompt says so in a sentence instead, and the
    /// buffer is left as it was.
    #[test]
    fn writing_an_entry_that_is_already_there_says_so() {
        let (_tmp, env, mut detail) = editing("home-share \"D\" mode=ro\n");
        select(&mut detail, "home-share");
        // The row that writes the *next* entry, which is the one that
        // pushes; the row above it edits the entry that is there.
        detail.selected += 1;
        assert_eq!(detail.row().unwrap().target, Target::Add("home-share"));
        for line in [
            "home-share \"D\"",
            "home-share \"D\" mode=rw",
            "home-share \"D/\"",
        ] {
            let e = detail.apply(&env, line).unwrap_err();
            assert_eq!(e, format!("`{line}` is already there"));
            assert!(detail.trouble.is_none(), "{line}: {:?}", detail.trouble);
            assert!(!detail.dirty(), "{line}: nothing refused was applied");
        }
        // A path the buffer does not hold is added like any other.
        detail.apply(&env, "home-share \"E\"").unwrap();
        assert_eq!(rows_for(&detail, "home-share").len(), 3);
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

    #[test]
    fn a_repeatable_node_offers_a_row_for_the_next_entry() {
        let (_tmp, env, mut detail) =
            editing("home-share \"Downloads\"\nhome-share \"Music\" mode=rw\n");
        let shares = rows_for(&detail, "home-share");
        assert_eq!(shares.len(), 3, "two entries and the row that adds one");
        assert!(shares[0].granted() && shares[1].granted());
        assert_eq!(shares[2].target, Target::Add("home-share"));
        assert_eq!(shares[2].line, 0, "it is on no line of the file");
        assert!(!shares[2].granted());
        assert!(
            !detail
                .rows
                .iter()
                .any(|r| r.node == "home-share" && r.target == Target::Absent),
            "the node is held, so the absent block does not offer it"
        );
        // The add-row stands right after the entries, and Enter on it
        // opens a prompt that carries none of them.
        let at = detail
            .rows
            .iter()
            .position(|r| r.target == Target::Add("home-share"))
            .expect("the add-row");
        assert_eq!(detail.rows[at - 1].target, Target::Service(1));
        detail.selected = at;
        assert_eq!(detail.prompt_line(), "home-share ");
        detail.apply(&env, "home-share \"Videos\"").unwrap();
        assert_eq!(
            detail
                .buf
                .services
                .iter()
                .filter(|s| matches!(s, Service::HomeShare { .. }))
                .count(),
            3,
            "the line was added, not written over an entry"
        );
    }

    #[test]
    fn space_keeps_a_node_that_carries_content() {
        let (_tmp, env, mut detail) = editing("wayland\ndbus {\n    talk \"ca.desrt.dconf\"\n}\n");
        select(&mut detail, "dbus");
        let said = detail.toggle(&env);
        assert!(said.starts_with("disabled `dbus`"), "{said}");
        assert_eq!(
            detail.buf.services,
            [Service::Wayland(WaylandMode::default())]
        );
        assert_eq!(detail.buf.disabled.len(), 1);
        assert_eq!(detail.buf.disabled[0].before, 1, "the place it had");
        let row = detail.row().expect("the cursor followed it");
        assert_eq!(row.target, Target::Disabled(0));
        assert!(!row.granted(), "and it is drawn as a ○");
        assert!(row.disabled());
        assert_eq!(
            row.text.as_deref(),
            Some("dbus {\n    talk \"ca.desrt.dconf\"\n}"),
            "the rules are kept, and the prompt shows no `/-`"
        );
        assert_eq!(
            detail.rows.iter().position(|r| r.node == "dbus"),
            Some(1),
            "on the row it was on"
        );
        let text = kdl_out::render(&detail.buf).unwrap();
        assert!(text.contains("\n/-dbus {\n"), "{text}");
        // And Space again puts it back where it was.
        assert_eq!(detail.toggle(&env), "enabled `dbus`");
        assert!(detail.buf.disabled.is_empty());
        assert_eq!(
            kdl_out::render(&detail.buf).unwrap(),
            "wayland\ndbus {\n    talk \"ca.desrt.dconf\"\n}\n"
        );
    }

    #[test]
    fn space_removes_a_node_a_disabled_line_would_keep_nothing_of() {
        let (_tmp, env, mut detail) = editing("dri\nwayland\nx11 \"host\"\n");
        select(&mut detail, "dri");
        assert_eq!(detail.toggle(&env), "removed `dri`");
        assert!(detail.buf.disabled.is_empty(), "`/-dri` keeps nothing");
        select(&mut detail, "wayland");
        assert_eq!(detail.toggle(&env), "removed `wayland`");
        assert!(
            detail.buf.disabled.is_empty(),
            "the bare node is the default"
        );
        select(&mut detail, "x11");
        let said = detail.toggle(&env);
        assert!(said.starts_with("disabled `x11`"), "{said}");
        assert_eq!(detail.buf.disabled.len(), 1, "the mode is worth keeping");
        assert_eq!(kdl_out::render(&detail.buf).unwrap(), "/-x11 \"host\"\n");
    }

    #[test]
    fn delete_takes_the_entry_out_whether_it_is_granted_or_not() {
        let (_tmp, env, mut detail) = editing("home-share \"Downloads\"\n/-home-share \"Music\"\n");
        let at = detail
            .rows
            .iter()
            .position(|r| r.node == "home-share")
            .expect("a row for it");
        assert_eq!(detail.rows[at + 1].target, Target::Disabled(0));
        assert_eq!(detail.rows[at + 2].target, Target::Add("home-share"));
        detail.selected = at + 2;
        assert_eq!(detail.clear(&env), "", "the add-row names no entry");
        assert!(!detail.dirty());
        detail.selected = at + 1;
        assert_eq!(detail.clear(&env), "removed home-share \"Music\" mode=ro");
        assert!(detail.buf.disabled.is_empty());
        select(&mut detail, "home-share");
        assert_eq!(
            detail.clear(&env),
            "removed home-share \"Downloads\" mode=ro"
        );
        assert!(detail.buf.services.is_empty());
        // With the last entry gone the node is offered as any other
        // absent one, and there is nothing left to remove.
        select(&mut detail, "home-share");
        assert_eq!(detail.row().unwrap().target, Target::Absent);
        assert_eq!(detail.clear(&env), "");
        // And `u` is what puts both entries back.
        detail.undo(&env);
        assert_eq!(detail.buf.services.len(), 1);
        assert_eq!(detail.buf.disabled.len(), 1);
    }

    #[test]
    fn a_disabled_entry_is_written_back_where_its_line_was() {
        let text = "home-share \"A\" mode=ro\n/-home-share \"B\" mode=ro\n\
                    home-share \"C\" mode=ro\n";
        let (_tmp, env, mut detail) = editing(text);
        // The entry above the `/-` line keeps its place above it.
        select(&mut detail, "home-share");
        detail.toggle(&env);
        assert_eq!(
            kdl_out::render(&detail.buf).unwrap(),
            "/-home-share \"A\" mode=ro\n/-home-share \"B\" mode=ro\n\
             home-share \"C\" mode=ro\n"
        );
        // What the editor holds is what the file it wrote reads back as,
        // which is the whole point of ordering the entries at all.
        detail.save(&env).unwrap();
        let again = Detail::open(&env, "ff", false).unwrap();
        assert_eq!(again.buf, detail.buf);
        // And the entry below it keeps its place below it.
        let (_tmp, env, mut detail) = editing(text);
        detail.selected = detail
            .rows
            .iter()
            .position(|r| r.target == Target::Service(1))
            .expect("the second share");
        detail.toggle(&env);
        assert_eq!(
            kdl_out::render(&detail.buf).unwrap(),
            "home-share \"A\" mode=ro\n/-home-share \"B\" mode=ro\n\
             /-home-share \"C\" mode=ro\n"
        );
        assert!(
            detail.row().is_some_and(Row::disabled),
            "the cursor followed the entry, not the node"
        );
        assert_eq!(detail.toggle(&env), "enabled `home-share`", "and back");
        assert_eq!(kdl_out::render(&detail.buf).unwrap(), text);
    }

    #[test]
    fn space_twice_on_an_entry_leaves_the_file_as_it_was() {
        let text = "home-share \"A\" mode=ro\nhome-share \"B\" mode=ro\n";
        let (_tmp, env, mut detail) = editing(text);
        select(&mut detail, "home-share");
        assert_eq!(detail.row().unwrap().target, Target::Service(0));
        detail.toggle(&env);
        // On the entry it disabled, not on the one that slid into the
        // index that entry had.
        let row = detail.row().expect("a row").clone();
        assert!(row.disabled(), "{row:?}");
        assert_eq!(row.text.as_deref(), Some("home-share \"A\" mode=ro"));
        assert_eq!(detail.toggle(&env), "enabled `home-share`");
        assert_eq!(kdl_out::render(&detail.buf).unwrap(), text);
        assert!(!detail.dirty(), "two presses, and the file is untouched");
    }

    #[test]
    fn space_on_the_first_of_two_disabled_entries_grants_that_one() {
        let text = "/-home-share \"A\" mode=ro\n/-home-share \"B\" mode=ro\n";
        let (_tmp, env, mut detail) = editing(text);
        select(&mut detail, "home-share");
        assert_eq!(detail.row().unwrap().target, Target::Disabled(0));
        detail.toggle(&env);
        assert_eq!(
            detail.buf.services,
            [Service::HomeShare {
                path: "A".into(),
                mode: ShareMode::ReadOnly
            }],
            "the one the cursor was on"
        );
        let row = detail.row().expect("a row").clone();
        assert!(row.granted(), "{row:?}");
        assert_eq!(row.text.as_deref(), Some("home-share \"A\" mode=ro"));
        // And Space again takes that one back off, not the other.
        detail.toggle(&env);
        assert!(detail.buf.services.is_empty());
        assert_eq!(kdl_out::render(&detail.buf).unwrap(), text);
        assert!(!detail.dirty());
    }

    #[test]
    fn a_line_no_disabled_entry_can_be_written_from_is_refused() {
        let (_tmp, env, mut detail) = editing("/-lint-allow \"network-host\" reason=\"testing\"\n");
        select(&mut detail, "lint-allow");
        assert_eq!(detail.row().unwrap().target, Target::Disabled(0));
        let e = detail
            .apply(
                &env,
                "lint-allow \"network-host\" reason=\"a\"; lint-allow \"home-share-sensitive\" reason=\"b\"",
            )
            .unwrap_err();
        assert!(e.contains("one check id"), "{e}");
        assert!(detail.trouble.is_none(), "the pane still draws");
        assert!(!detail.rows.is_empty());
        assert!(!detail.dirty(), "nothing refused was applied");
    }

    #[test]
    fn enabling_a_node_a_config_holds_one_of_says_what_became_of_it() {
        let (_tmp, env, mut detail) = editing("tty \"none\"\n/-tty \"passthrough\"\n");
        select(&mut detail, "tty");
        assert_eq!(detail.row().unwrap().target, Target::Tty);
        detail.selected += 1;
        assert_eq!(detail.row().unwrap().target, Target::Disabled(0));
        assert_eq!(
            detail.toggle(&env),
            "enabled `tty` over the one it held",
            "a config holds one tty node, so the other one went"
        );
        assert_eq!(detail.buf.tty, TtyMode::Passthrough);
        assert!(detail.buf.disabled.is_empty());
        // And a disabled node whose value is the default is a node the
        // file writes no line for at all.
        let (_tmp, env, mut detail) = editing("/-tty \"pty\"\n");
        select(&mut detail, "tty");
        assert_eq!(
            detail.toggle(&env),
            "enabled `tty`: the default, so there is no line to write"
        );
        assert_eq!(kdl_out::render(&detail.buf).unwrap(), "");
    }

    #[test]
    fn the_cursor_lands_on_a_freshly_written_entry() {
        let (_tmp, env, mut detail) = editing("wayland\n");
        select(&mut detail, "home-share");
        assert_eq!(detail.row().unwrap().target, Target::Absent);
        detail.apply(&env, "home-share \"Downloads\"").unwrap();
        let row = detail.row().expect("a row").clone();
        assert_eq!(
            row.target,
            Target::Service(1),
            "on the entry, not on the row that writes the next: {row:?}"
        );
        assert_eq!(
            row.text.as_deref(),
            Some("home-share \"Downloads\" mode=ro")
        );
    }

    #[test]
    fn enabling_the_default_over_a_granted_value_says_both() {
        let (_tmp, env, mut detail) = editing("userns \"disable\"\n/-userns \"allow\"\n");
        select(&mut detail, "userns");
        assert_eq!(detail.row().unwrap().target, Target::Userns);
        detail.selected += 1;
        assert_eq!(detail.row().unwrap().target, Target::Disabled(0));
        assert_eq!(
            detail.toggle(&env),
            "enabled `userns`: the default, over the one it held, so no line remains",
            "the hardening line went, and the line says so"
        );
        assert_eq!(detail.buf.userns, Userns::Allow);
        assert_eq!(kdl_out::render(&detail.buf).unwrap(), "");
    }

    #[test]
    fn a_line_that_writes_two_check_ids_keeps_the_disabled_one_below_both() {
        let (_tmp, env, mut detail) = editing(
            "lint-allow \"network-host\" reason=\"a\"\n\
             /-lint-allow \"home-share-sensitive\" reason=\"b\"\n",
        );
        select(&mut detail, "lint-allow");
        assert_eq!(detail.row().unwrap().target, Target::LintAllow(0));
        detail
            .apply(
                &env,
                "lint-allow \"x11-without-reason\" reason=\"c\"; \
                 lint-allow \"dbus-without-rules\" reason=\"d\"",
            )
            .unwrap();
        assert_eq!(
            kdl_out::render(&detail.buf).unwrap(),
            "lint-allow \"x11-without-reason\" reason=\"c\"\n\
             lint-allow \"dbus-without-rules\" reason=\"d\"\n\
             /-lint-allow \"home-share-sensitive\" reason=\"b\"\n",
            "the `/-` line stayed below the entry it was read below"
        );
    }

    #[test]
    fn a_line_that_writes_two_variables_keeps_the_disabled_one_below_both() {
        let (_tmp, env, mut detail) = editing("env A=\"1\"\n/-env B=\"2\"\n");
        select(&mut detail, "env");
        assert_eq!(detail.row().unwrap().target, Target::Env(0));
        detail.apply(&env, "env C=\"3\" D=\"4\"").unwrap();
        assert_eq!(
            kdl_out::render(&detail.buf).unwrap(),
            "env C=\"3\"\nenv D=\"4\"\n/-env B=\"2\"\n",
            "the `/-` line stayed below the entry it was read below"
        );
    }

    #[test]
    fn a_node_a_config_holds_one_of_goes_off_and_on_again() {
        let (_tmp, env, mut detail) = editing("command \"true\"\n");
        select(&mut detail, "command");
        let said = detail.toggle(&env);
        assert!(said.starts_with("disabled `command`"), "{said}");
        assert!(detail.buf.command.is_none(), "nothing runs by default now");
        assert_eq!(detail.buf.disabled[0].before, 0);
        assert_eq!(
            kdl_out::render(&detail.buf).unwrap(),
            "/-command \"true\"\n"
        );
        assert_eq!(detail.toggle(&env), "enabled `command`");
        assert_eq!(detail.buf.command, Some(vec!["true".into()]));
        assert!(detail.buf.disabled.is_empty());
    }

    #[test]
    fn a_disabled_entry_is_written_over_and_stays_disabled() {
        let (_tmp, env, mut detail) = editing("/-home-share \"Music\"\n");
        select(&mut detail, "home-share");
        assert_eq!(detail.row().unwrap().target, Target::Disabled(0));
        assert_eq!(detail.prompt_line(), "home-share \"Music\" mode=ro");
        detail.apply(&env, "home-share \"Music\" mode=rw").unwrap();
        assert!(detail.buf.services.is_empty(), "an edit grants nothing");
        assert_eq!(
            kdl_out::render(&detail.buf).unwrap(),
            "/-home-share \"Music\" mode=rw\n"
        );
    }

    #[test]
    fn a_finding_finds_its_row_past_a_disabled_one() {
        let (_tmp, _env, detail) = editing("wayland\n/-home-share \"Music\"\nx11 \"host\"\n");
        let row = detail
            .rows
            .iter()
            .find(|r| r.node == "x11")
            .expect("a row for x11");
        assert_eq!(row.line, 3, "the `/-` line is a line of the file");
        let findings = detail.findings_of(row);
        assert!(
            findings.iter().any(|f| f.id == "x11-without-reason"),
            "{findings:?}"
        );
        let disabled = detail
            .rows
            .iter()
            .find(|r| r.disabled())
            .expect("the disabled row");
        assert!(
            detail.findings_of(disabled).is_empty(),
            "nothing is reported about a line that grants nothing"
        );
    }
}
