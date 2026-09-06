//! The editor's state and the keys that change it.
//!
//! Every key that starts something returns an [`Action`] rather than
//! running it: what a keystroke means is decided here and testable
//! without a terminal, and what it costs — a sandbox, a `$EDITOR`, a
//! deleted home — is spent by the loop in `main`.

use std::ffi::OsString;

use bubbler_core::env::Env;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::detail::Detail;
use crate::input::Input;
use crate::store::Store;

/// What a keystroke asks the loop to do. The editor never runs a sandbox
/// itself: it names a `bubbler` command line, and the CLI stays the one
/// place that decides what a subcommand does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Start it in a session of its own with no terminal, and come
    /// straight back: `run` and `open`, so the editor stays up and the
    /// live column catches up on the next tick.
    Detached(Vec<OsString>),
    /// Leave the alternate screen, hand the terminal over, and come back
    /// when it exits: `exec`, `try`, `edit`.
    Attached(Vec<OsString>),
    /// Run it and show what it printed: the reports and the explanation.
    Capture {
        /// What the viewer is called.
        title: String,
        /// The command line under it.
        args: Vec<OsString>,
        /// Which explanation this is, when it is one, so `f` and `p` can
        /// ask for another.
        explain: Option<Explain>,
    },
    /// Read the store again.
    Reload,
    /// Leave.
    Quit,
}

impl Action {
    /// A command whose whole answer is its output.
    fn capture(title: impl Into<String>, args: Vec<OsString>) -> Self {
        Self::Capture {
            title: title.into(),
            args,
            explain: None,
        }
    }
}

/// Which screen the keys go to. A stack, so `Esc` always means back and
/// the instance list is never popped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// The instance list, the root.
    Instances,
    /// One instance's grants, which is what the editor is for.
    Detail,
    /// Every profile any layer holds.
    Profiles,
    /// A report or an explanation, scrolled.
    Viewer,
}

/// What a prompt is collecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompt {
    /// A name for a new instance, seeded from this profile.
    Create(String),
    /// One KDL node, for the selected row of the detail screen.
    Node,
    /// The command an `exec` runs in this instance.
    Exec(String),
    /// A profile, bare grants and an optional `keep=<name>`.
    Try,
    /// The name a shim for this instance takes on `PATH`.
    Wrap(String),
}

/// What a confirmation is about. Every one of these either deletes
/// something or writes outside the instance directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    /// Delete the instance and its private home.
    Delete(String),
    /// Flatten its profile over its config.
    Reseed(String),
    /// Write a launcher entry, of its own name or the application's.
    Desktop {
        /// Instance the entry starts.
        name: String,
        /// Write it under the application's own file name, shadowing it.
        replace: bool,
    },
    /// Remove the launcher entries written for it.
    DesktopRemove(String),
    /// Remove the shim of this name.
    Unwrap(String),
    /// Ask for another name for this instance's shim.
    WrapAs(String),
    /// Leave the detail screen, losing what was edited.
    Discard,
}

/// One answer a confirmation offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// The key that picks it.
    pub key: char,
    /// What it says on the line.
    pub label: String,
    /// What it does.
    pub confirm: Confirm,
}

/// A modal over the current screen. Keys go here first while one is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialog {
    /// One line of text, with the grammar of what is being written under
    /// it.
    Ask {
        /// What is being asked for.
        title: String,
        /// The grammar or the example under the field.
        hint: String,
        /// What has been typed.
        input: Input,
        /// What the answer is for.
        prompt: Prompt,
    },
    /// A question and the keys that answer it.
    Choose {
        /// The question.
        question: String,
        /// The answers, in the order they are shown.
        choices: Vec<Choice>,
    },
}

/// A report, an explanation or a log, scrolled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewer {
    /// What it is called.
    pub title: String,
    /// The lines themselves.
    pub lines: Vec<String>,
    /// First line shown.
    pub offset: usize,
    /// The explanation this is, when it is one: `f` and `p` re-run it.
    pub explain: Option<Explain>,
}

/// Which explanation a viewer is showing, so the toggles can ask for
/// another one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explain {
    /// The instance being explained.
    pub name: String,
    /// Every argument, the baseline included.
    pub full: bool,
    /// The D-Bus proxy sidecar's argv rather than the sandbox's.
    pub proxy: bool,
}

/// The editor.
pub struct App {
    /// Host facts, for reading the store and linting a buffer.
    pub env: Env,
    /// The instances and profiles, as last read.
    pub store: Store,
    /// The screen stack; the first is always the instance list.
    pub stack: Vec<Screen>,
    /// Selected instance.
    pub instance: usize,
    /// Selected profile.
    pub profile: usize,
    /// The instance being edited, while the detail screen is up.
    pub detail: Option<Detail>,
    /// What the viewer is showing, while it is up.
    pub viewer: Option<Viewer>,
    /// The modal over the screen, if any.
    pub dialog: Option<Dialog>,
    /// Whether the key list is up.
    pub help: bool,
    /// Lines the viewer can show at once, kept up to date by the loop: a
    /// page is however tall the terminal is.
    pub page: usize,
    /// The last thing that happened, on the bottom line.
    pub status: String,
    /// Whether the loop should end.
    pub quit: bool,
}

impl App {
    /// An editor over `store`.
    pub fn new(env: Env, store: Store) -> Self {
        Self {
            env,
            store,
            stack: vec![Screen::Instances],
            instance: 0,
            profile: 0,
            detail: None,
            viewer: None,
            dialog: None,
            help: false,
            page: 10,
            status: String::new(),
            quit: false,
        }
    }

    /// The screen the keys go to.
    pub fn screen(&self) -> Screen {
        *self.stack.last().unwrap_or(&Screen::Instances)
    }

    /// The selected instance's name, if the store holds any.
    pub fn selected(&self) -> Option<&str> {
        self.store
            .rows
            .get(self.instance)
            .map(|row| row.name.as_str())
    }

    /// The selected profile's name, if any layer holds one.
    pub fn selected_profile(&self) -> Option<&str> {
        self.store
            .profiles
            .get(self.profile)
            .map(|entry| entry.name.as_str())
    }

    /// Say what just happened on the bottom line.
    pub fn say(&mut self, said: impl Into<String>) {
        self.status = said.into();
    }

    /// Add to what the bottom line already says rather than take its
    /// place: what a command did and what that did to the buffer are two
    /// things the user needs at once.
    pub fn note(&mut self, said: impl Into<String>) {
        let said = said.into();
        match self.status.is_empty() {
            true => self.status = said,
            false => self.status.push_str(&format!(" — {said}")),
        }
    }

    /// Show `lines` in the viewer, pushing it if it is not already up.
    pub fn show(&mut self, title: impl Into<String>, lines: Vec<String>, explain: Option<Explain>) {
        self.viewer = Some(Viewer {
            title: title.into(),
            lines,
            offset: 0,
            explain,
        });
        if self.screen() != Screen::Viewer {
            self.stack.push(Screen::Viewer);
        }
    }

    /// Read the store again: the list, the profiles and the shims. The
    /// detail screen's buffer is not touched, which is what a save wants —
    /// the grants and lint columns are stale the moment a file is written.
    pub fn reload_store(&mut self) {
        match Store::load(&self.env) {
            Ok(store) => self.store = store,
            Err(e) => self.say(format!("reading the store: {e:#}")),
        }
        self.instance = self.instance.min(self.store.rows.len().saturating_sub(1));
        self.profile = self
            .profile
            .min(self.store.profiles.len().saturating_sub(1));
        if let Some(detail) = &mut self.detail {
            detail.live = self.store.row(detail.name()).is_some_and(|r| r.live);
        }
    }

    /// Read the store again and put the detail screen's buffer back on
    /// the file, which is what an `$EDITOR` run or an outside change asks
    /// for — unless the buffer holds edits the file does not. Those are
    /// the user's, and nothing the editor ran is a reason to drop them.
    pub fn reload(&mut self) {
        self.reload_store();
        let Some(name) = self.detail.as_ref().map(|d| d.name().to_owned()) else {
            return;
        };
        if self.detail.as_ref().is_some_and(Detail::dirty) {
            self.note("unsaved edits kept; `s` writes them, `u` puts them back");
            return;
        }
        let live = self.store.row(&name).is_some_and(|r| r.live);
        match Detail::open(&self.env, &name, live) {
            Ok(detail) => self.detail = Some(detail),
            Err(e) => {
                self.detail = None;
                self.back();
                self.say(format!("instance `{name}`: {e}"));
            }
        }
    }

    /// Probe every instance's socket again, which is all a tick does.
    pub fn tick(&mut self) {
        self.store.refresh_liveness(&self.env);
        if let Some(detail) = &mut self.detail {
            detail.live = self.store.row(detail.name()).is_some_and(|r| r.live);
        }
    }

    /// Pop one screen, never the root.
    fn back(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
        }
        match self.screen() {
            Screen::Detail => self.viewer = None,
            Screen::Instances | Screen::Profiles => {
                self.viewer = None;
                self.detail = None;
            }
            Screen::Viewer => {}
        }
    }

    /// Handle one key press. `None` means the key changed only what is on
    /// the screen.
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        self.status.clear();
        if self.help {
            self.help = false;
            return None;
        }
        if self.dialog.is_some() {
            return self.dialog_key(key);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return match key.code {
                KeyCode::Char('r') => Some(Action::Reload),
                _ => None,
            };
        }
        match self.screen() {
            Screen::Instances => self.instances_key(key),
            Screen::Detail => self.detail_key(key),
            Screen::Profiles => self.profiles_key(key),
            Screen::Viewer => self.viewer_key(key),
        }
    }

    /// Keys every list screen shares: the movement, the help and the way
    /// out. `true` when the key was one of them.
    fn common_key(&mut self, key: KeyEvent, len: usize, index: usize) -> Option<usize> {
        let last = len.saturating_sub(1);
        Some(match key.code {
            KeyCode::Char('j') | KeyCode::Down => (index + 1).min(last),
            KeyCode::Char('k') | KeyCode::Up => index.saturating_sub(1),
            KeyCode::Char('g') | KeyCode::Home => 0,
            KeyCode::Char('G') | KeyCode::End => last,
            KeyCode::PageDown => (index + 10).min(last),
            KeyCode::PageUp => index.saturating_sub(10),
            _ => return None,
        })
    }

    fn instances_key(&mut self, key: KeyEvent) -> Option<Action> {
        if let Some(index) = self.common_key(key, self.store.rows.len(), self.instance) {
            self.instance = index;
            return None;
        }
        let name = self.selected().map(str::to_owned);
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Some(Action::Quit),
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('p') => {
                self.stack.push(Screen::Profiles);
            }
            KeyCode::Char('n') => {
                self.stack.push(Screen::Profiles);
                self.say("pick the profile to seed the instance from, then `c`");
            }
            _ => return self.instance_action(key, name?),
        }
        None
    }

    /// The keys that act on the selected instance. Split out because
    /// every one of them needs a name and the list may be empty.
    fn instance_action(&mut self, key: KeyEvent, name: String) -> Option<Action> {
        match key.code {
            KeyCode::Enter => {
                let live = self.store.row(&name).is_some_and(|r| r.live);
                match Detail::open(&self.env, &name, live) {
                    Ok(detail) => {
                        self.detail = Some(detail);
                        self.stack.push(Screen::Detail);
                    }
                    // A config that does not parse is exactly when the
                    // editor is no use and `e` is: say so and offer it.
                    Err(e) => self.say(format!("instance `{name}`: {e} — `e` opens the file")),
                }
                None
            }
            KeyCode::Char('r') => {
                self.say(format!("started `{name}`; nothing of its output is kept"));
                Some(Action::Detached(args(&["run", &name, "--tty", "none"])))
            }
            KeyCode::Char('o') => {
                self.say(format!("opened `{name}`; `L` shows what it wrote"));
                Some(Action::Detached(args(&["open", &name])))
            }
            KeyCode::Char('x') => {
                self.ask(
                    format!("exec in `{name}`"),
                    "the command: spaces separate arguments, \"quotes\" hold one \
                     together, and nothing is expanded",
                    crate::env::shell().to_string_lossy().into_owned(),
                    Prompt::Exec(name),
                );
                None
            }
            KeyCode::Char('t') => {
                let profile = self
                    .store
                    .row(&name)
                    .and_then(|r| r.profile.clone())
                    .unwrap_or_else(|| "generic".to_owned());
                self.ask(
                    "try a throwaway sandbox",
                    "<profile> [bare grant ...] [keep=<instance>] [-- <command ...>]",
                    profile,
                    Prompt::Try,
                );
                None
            }
            KeyCode::Char('e') => Some(Action::Attached(args(&["edit", &name]))),
            KeyCode::Char('l') => Some(Action::capture(
                format!("lint {name}"),
                args(&["lint", &name]),
            )),
            KeyCode::Char('L') => Some(Action::capture(
                format!("last-run.log of {name}"),
                args(&["log", &name]),
            )),
            KeyCode::Char('X') => Some(explain_action(&Explain {
                name,
                full: false,
                proxy: false,
            })),
            KeyCode::Char('d') => {
                self.choose(
                    format!("delete `{name}`, its config and its private home?"),
                    vec![Choice {
                        key: 'y',
                        label: "delete it".to_owned(),
                        confirm: Confirm::Delete(name),
                    }],
                );
                None
            }
            KeyCode::Char('R') => {
                self.choose(
                    format!("flatten `{name}`'s profile over its config, losing every edit?"),
                    vec![Choice {
                        key: 'y',
                        label: "reseed it".to_owned(),
                        confirm: Confirm::Reseed(name),
                    }],
                );
                None
            }
            KeyCode::Char('D') => {
                self.choose(
                    format!("launcher entry for `{name}`"),
                    vec![
                        Choice {
                            key: 'w',
                            label: "write one of its own".to_owned(),
                            confirm: Confirm::Desktop {
                                name: name.clone(),
                                replace: false,
                            },
                        },
                        Choice {
                            key: 'r',
                            label: "replace the application's own entry".to_owned(),
                            confirm: Confirm::Desktop {
                                name: name.clone(),
                                replace: true,
                            },
                        },
                        Choice {
                            key: 'x',
                            label: "remove the ones written for it".to_owned(),
                            confirm: Confirm::DesktopRemove(name),
                        },
                    ],
                );
                None
            }
            KeyCode::Char('W') => {
                if let Some(e) = self.store.shim_error.clone() {
                    self.say(format!("reading the shim registry: {e}"));
                    return None;
                }
                let mine: Vec<String> = self
                    .store
                    .shims_of(&name)
                    .iter()
                    .map(|w| w.name.clone())
                    .collect();
                match mine.first() {
                    Some(shim) => self.choose(
                        format!("`{name}` is on PATH as `{}`", mine.join("`, `")),
                        vec![
                            Choice {
                                key: 'u',
                                label: format!("remove the shim `{shim}`"),
                                confirm: Confirm::Unwrap(shim.clone()),
                            },
                            Choice {
                                key: 'a',
                                label: "add another name for it".to_owned(),
                                confirm: Confirm::WrapAs(name),
                            },
                        ],
                    ),
                    None => self.wrap_prompt(name),
                }
                None
            }
            _ => None,
        }
    }

    fn detail_key(&mut self, key: KeyEvent) -> Option<Action> {
        let rows = self.detail.as_ref().map_or(0, |d| d.rows.len());
        let at = self.detail.as_ref().map_or(0, |d| d.selected);
        if let Some(index) = self.common_key(key, rows, at) {
            if let Some(detail) = &mut self.detail {
                detail.selected = index;
            }
            return None;
        }
        let name = self.detail.as_ref()?.name().to_owned();
        match key.code {
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char(' ') => {
                let env = self.env.clone();
                if let Some(detail) = &mut self.detail {
                    let said = detail.toggle(&env);
                    self.say(said);
                }
            }
            // Only here: a prompt takes every key of what is under it,
            // so Backspace inside one is still what edits the line.
            KeyCode::Delete | KeyCode::Backspace => {
                let env = self.env.clone();
                if let Some(detail) = &mut self.detail {
                    let said = detail.clear(&env);
                    self.say(said);
                }
            }
            KeyCode::Enter => {
                let detail = self.detail.as_ref()?;
                let row = detail.row()?;
                let node = row.node;
                let hint = row
                    .grant()
                    .map_or_else(String::new, |g| g.grammar.to_owned());
                let line = detail.prompt_line();
                self.ask(format!("{node} in `{name}`"), hint, line, Prompt::Node);
            }
            KeyCode::Char('s') => {
                let env = self.env.clone();
                let said = self.detail.as_mut()?.save(&env);
                match said {
                    Ok(said) => {
                        // The file is what the list's grants and lint
                        // columns are read from, and it just changed.
                        self.reload_store();
                        self.say(said);
                    }
                    Err(e) => self.say(format!("not saved: {e}")),
                }
            }
            KeyCode::Char('u') => {
                let env = self.env.clone();
                self.detail.as_mut()?.undo(&env);
                self.say("back to the config as last written");
            }
            KeyCode::Char('e') => return Some(Action::Attached(args(&["edit", &name]))),
            KeyCode::Char('l') => {
                return Some(Action::capture(
                    format!("lint {name}"),
                    args(&["lint", &name]),
                ));
            }
            KeyCode::Char('X') => {
                return Some(explain_action(&Explain {
                    name,
                    full: false,
                    proxy: false,
                }));
            }
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.detail.as_ref().is_some_and(Detail::dirty) {
                    self.choose(
                        format!("`{name}` has changes config.kdl does not; leave them?"),
                        vec![Choice {
                            key: 'y',
                            label: "discard them".to_owned(),
                            confirm: Confirm::Discard,
                        }],
                    );
                    return None;
                }
                self.back();
            }
            _ => {}
        }
        None
    }

    fn profiles_key(&mut self, key: KeyEvent) -> Option<Action> {
        if let Some(index) = self.common_key(key, self.store.profiles.len(), self.profile) {
            self.profile = index;
            return None;
        }
        let name = self.selected_profile().map(str::to_owned);
        match key.code {
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('q') | KeyCode::Esc => self.back(),
            KeyCode::Enter => {
                let name = name?;
                return Some(Action::capture(
                    format!("profile {name}"),
                    args(&["profile", "show", &name]),
                ));
            }
            KeyCode::Char('l') => {
                let name = name?;
                return Some(Action::capture(
                    format!("lint profile {name}"),
                    args(&["profile", "lint", &name]),
                ));
            }
            KeyCode::Char('e') => {
                let name = name?;
                return Some(Action::Attached(args(&["profile", "edit", &name])));
            }
            KeyCode::Char('c') => {
                let profile = name?;
                self.ask(
                    format!("new instance from `{profile}`"),
                    "letters, digits, `.`, `_` and `-`; it names the directory too",
                    String::new(),
                    Prompt::Create(profile),
                );
            }
            _ => {}
        }
        None
    }

    fn viewer_key(&mut self, key: KeyEvent) -> Option<Action> {
        // The viewer scrolls by what it can show rather than by rows in a
        // list, so `G` is the last page and not the last line on its own.
        let page = self.page.max(1);
        let last = self
            .viewer
            .as_ref()
            .map_or(0, |v| v.lines.len())
            .saturating_sub(page);
        let at = self.viewer.as_ref()?.offset;
        let scrolled = match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some((at + 1).min(last)),
            KeyCode::Char('k') | KeyCode::Up => Some(at.saturating_sub(1)),
            KeyCode::PageDown => Some((at + page).min(last)),
            KeyCode::PageUp => Some(at.saturating_sub(page)),
            KeyCode::Char('g') | KeyCode::Home => Some(0),
            KeyCode::Char('G') | KeyCode::End => Some(last),
            _ => None,
        };
        if let Some(offset) = scrolled {
            self.viewer.as_mut()?.offset = offset;
            return None;
        }
        match key.code {
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('q') | KeyCode::Esc => self.back(),
            KeyCode::Char('f') => {
                let mut explain = self.viewer.as_ref()?.explain.clone()?;
                explain.full = !explain.full;
                return Some(explain_action(&explain));
            }
            KeyCode::Char('p') => {
                let mut explain = self.viewer.as_ref()?.explain.clone()?;
                explain.proxy = !explain.proxy;
                return Some(explain_action(&explain));
            }
            _ => {}
        }
        None
    }

    /// Open a one-line prompt.
    fn ask(
        &mut self,
        title: impl Into<String>,
        hint: impl Into<String>,
        value: impl Into<String>,
        prompt: Prompt,
    ) {
        self.dialog = Some(Dialog::Ask {
            title: title.into(),
            hint: hint.into(),
            input: Input::new(value),
            prompt,
        });
    }

    /// Ask for the name a shim takes on `PATH`.
    fn wrap_prompt(&mut self, name: String) {
        self.ask(
            format!("shim for `{name}` in ~/.local/bin"),
            "the name it takes on PATH; anything resolved through PATH by that \
             name starts this sandbox",
            name.clone(),
            Prompt::Wrap(name),
        );
    }

    /// Open a confirmation.
    fn choose(&mut self, question: impl Into<String>, choices: Vec<Choice>) {
        self.dialog = Some(Dialog::Choose {
            question: question.into(),
            choices,
        });
    }

    fn dialog_key(&mut self, key: KeyEvent) -> Option<Action> {
        match self.dialog.as_mut()? {
            Dialog::Choose { choices, .. } => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('n')) {
                    self.dialog = None;
                    return None;
                }
                let KeyCode::Char(c) = key.code else {
                    return None;
                };
                let confirm = choices.iter().find(|ch| ch.key == c)?.confirm.clone();
                self.dialog = None;
                self.confirmed(confirm)
            }
            Dialog::Ask { input, .. } => {
                match key.code {
                    KeyCode::Esc => {
                        self.dialog = None;
                        return None;
                    }
                    KeyCode::Enter => return self.answered(),
                    KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if c == 'u' {
                            input.clear_before();
                        }
                    }
                    KeyCode::Char(c) => input.insert(c),
                    KeyCode::Backspace => input.backspace(),
                    KeyCode::Delete => input.delete(),
                    KeyCode::Left => input.left(),
                    KeyCode::Right => input.right(),
                    KeyCode::Home => input.home(),
                    KeyCode::End => input.end(),
                    _ => {}
                }
                None
            }
        }
    }

    /// What a confirmed answer does.
    fn confirmed(&mut self, confirm: Confirm) -> Option<Action> {
        match confirm {
            Confirm::Delete(name) => Some(Action::capture(
                format!("delete {name}"),
                args(&["delete", &name, "--yes"]),
            )),
            Confirm::Reseed(name) => Some(Action::capture(
                format!("reseed {name}"),
                args(&["reseed", &name]),
            )),
            Confirm::Desktop { name, replace } => {
                let mut argv = args(&["desktop", &name]);
                if replace {
                    argv.push("--replace".into());
                }
                Some(Action::capture(format!("desktop {name}"), argv))
            }
            Confirm::DesktopRemove(name) => Some(Action::capture(
                format!("desktop --remove {name}"),
                args(&["desktop", &name, "--remove"]),
            )),
            Confirm::Unwrap(name) => Some(Action::capture(
                format!("unwrap {name}"),
                args(&["unwrap", &name]),
            )),
            Confirm::WrapAs(name) => {
                self.wrap_prompt(name);
                None
            }
            Confirm::Discard => {
                self.detail = None;
                self.back();
                None
            }
        }
    }

    /// What a submitted prompt does. A prompt whose answer the parser
    /// refuses stays open with the reason under it, because retyping the
    /// whole line to fix one character is what makes an editor worse than
    /// the file.
    fn answered(&mut self) -> Option<Action> {
        let Some(Dialog::Ask { input, prompt, .. }) = &self.dialog else {
            return None;
        };
        let value = input.value().trim().to_owned();
        let prompt = prompt.clone();
        match prompt {
            Prompt::Create(profile) => {
                self.dialog = None;
                Some(Action::capture(
                    format!("create {value}"),
                    // `--` closes the option list, so what was typed is
                    // the instance name whatever it starts with: a
                    // leading `-` is then refused by the CLI's own name
                    // grammar, which says why, rather than as a flag it
                    // has never heard of.
                    args(&["create", "--profile", &profile, "--", &value]),
                ))
            }
            Prompt::Node => {
                let env = self.env.clone();
                let applied = self.detail.as_mut()?.apply(&env, &value);
                match applied {
                    Ok(()) => {
                        self.dialog = None;
                        self.say("changed; `s` writes it, `u` puts it back");
                        None
                    }
                    Err(e) => {
                        self.say(e);
                        None
                    }
                }
            }
            Prompt::Exec(name) => match split(&value) {
                Ok(command) if command.is_empty() => {
                    self.say("a command to run in it");
                    None
                }
                Ok(command) => {
                    self.dialog = None;
                    let mut argv = args(&["exec", &name, "--"]);
                    argv.extend(command);
                    Some(Action::Attached(argv))
                }
                Err(e) => {
                    self.say(e);
                    None
                }
            },
            Prompt::Try => match try_args(&value) {
                Ok(argv) => {
                    self.dialog = None;
                    Some(Action::Attached(argv))
                }
                Err(e) => {
                    self.say(e);
                    None
                }
            },
            Prompt::Wrap(name) => {
                self.dialog = None;
                let mut argv = args(&["wrap"]);
                if value != name {
                    argv.push("--as".into());
                    argv.push(OsString::from(&value));
                }
                argv.push("--".into());
                argv.push(OsString::from(&name));
                Some(Action::capture(format!("wrap {name}"), argv))
            }
        }
    }
}

/// The `bubbler run --explain` a viewer is showing.
fn explain_action(explain: &Explain) -> Action {
    let mut argv = args(&["run", &explain.name, "--explain"]);
    if explain.full {
        argv.push("full".into());
    }
    if explain.proxy {
        argv.push("--proxy".into());
    }
    Action::Capture {
        title: format!("explain {}", explain.name),
        args: argv,
        explain: Some(explain.clone()),
    }
}

/// A command line, one argument per element.
fn args(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

/// A command line typed into a prompt, split the way a shell splits a
/// simple one and no further: whitespace separates arguments, `"` holds a
/// run of them together and `\` escapes the next character. Nothing is
/// expanded, because nothing here reaches a shell — there is no `$HOME`
/// and no `*` for anything to mean.
fn split(value: &str) -> Result<Vec<OsString>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quoted = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(next) => {
                    current.push(next);
                    started = true;
                }
                None => return Err("a backslash at the end escapes nothing".to_owned()),
            },
            // An empty pair of quotes is an empty argument, and dropping
            // it would change the command line.
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(OsString::from(std::mem::take(&mut current)));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if quoted {
        return Err("a quote is left open".to_owned());
    }
    if started {
        args.push(OsString::from(current));
    }
    Ok(args)
}

/// `<profile> [grant ...] [keep=<name>] [-- <command ...>]` as a `bubbler
/// try` command line. The whole grammar of that prompt: a throwaway
/// sandbox takes a profile, the bare grants on top of it, a name to keep
/// it under, and the command to run in it — which a profile with no
/// `command` node of its own has no other way of being given.
fn try_args(value: &str) -> Result<Vec<OsString>, String> {
    let typed = split(value)?;
    let mut parts = typed.iter();
    let profile = parts
        .next()
        .ok_or("a profile name first, then any bare grants")?;
    let mut argv = args(&["try", "--profile"]);
    argv.push(profile.clone());
    let mut command: Vec<OsString> = Vec::new();
    let mut after_dashes = false;
    for part in parts {
        if after_dashes {
            command.push(part.clone());
            continue;
        }
        if part == "--" {
            after_dashes = true;
            continue;
        }
        // A grant and an instance name are both names, so what is read
        // here is text; the command is not, and stays an `OsString`.
        match part.to_string_lossy().strip_prefix("keep=") {
            Some("") => return Err("`keep=` takes an instance name".to_owned()),
            Some(name) => {
                argv.push("--keep".into());
                argv.push(OsString::from(name));
            }
            None => {
                argv.push("--grant".into());
                argv.push(part.clone());
            }
        }
    }
    if !command.is_empty() {
        argv.push("--".into());
        argv.extend(command);
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use bubbler_core::env::Env;
    use ratatui::crossterm::event::KeyCode;

    /// An editor over a store holding `ff`, seeded from `generic`.
    fn app() -> (tempfile::TempDir, App) {
        let (tmp, env) = fixture::store(&[("ff", "generic")]);
        let store = Store::load(&env).unwrap();
        (tmp, App::new(env, store))
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Press a character key.
    fn press(app: &mut App, c: char) -> Option<Action> {
        app.on_key(key(KeyCode::Char(c)))
    }

    /// Type `text` into the open prompt and submit it.
    fn typed(app: &mut App, text: &str) -> Option<Action> {
        for c in text.chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter))
    }

    /// Everything the prompt was pre-filled with, gone.
    fn clear(app: &mut App) {
        for _ in 0..80 {
            app.on_key(key(KeyCode::Backspace));
        }
    }

    /// The command line an action names, as strings.
    fn argv(action: &Action) -> Vec<String> {
        let args = match action {
            Action::Detached(args) | Action::Attached(args) => args,
            Action::Capture { args, .. } => args,
            Action::Reload | Action::Quit => return Vec::new(),
        };
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn starting_a_sandbox_never_takes_the_terminal_and_a_shell_always_does() {
        let (_tmp, mut app) = app();
        let run = press(&mut app, 'r').unwrap();
        assert_eq!(argv(&run), ["run", "ff", "--tty", "none"]);
        assert!(matches!(run, Action::Detached(_)));
        let open = press(&mut app, 'o').unwrap();
        assert_eq!(argv(&open), ["open", "ff"]);
        assert!(matches!(open, Action::Detached(_)));
        press(&mut app, 'x');
        clear(&mut app);
        let exec = typed(&mut app, "/bin/sh -l").unwrap();
        assert_eq!(argv(&exec), ["exec", "ff", "--", "/bin/sh", "-l"]);
        assert!(
            matches!(exec, Action::Attached(_)),
            "a shell needs the terminal"
        );
        assert!(app.dialog.is_none(), "and the prompt is done with");
    }

    #[test]
    fn a_throwaway_sandbox_takes_a_profile_bare_grants_and_a_name_to_keep_it_under() {
        let (_tmp, mut app) = app();
        press(&mut app, 't');
        clear(&mut app);
        let action = typed(&mut app, "generic wayland dri keep=kept").unwrap();
        assert_eq!(
            argv(&action),
            [
                "try",
                "--profile",
                "generic",
                "--grant",
                "wayland",
                "--grant",
                "dri",
                "--keep",
                "kept"
            ]
        );
        assert!(matches!(action, Action::Attached(_)));
    }

    #[test]
    fn a_prompt_the_parser_refuses_stays_open_with_the_reason() {
        let (_tmp, mut app) = app();
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen(), Screen::Detail);
        // The detail screen opens on the first row, which the generic
        // profile grants nothing of; write a grant onto it instead.
        let detail = app.detail.as_mut().unwrap();
        detail.selected = detail
            .rows
            .iter()
            .position(|r| r.node == "home-share")
            .unwrap();
        app.on_key(key(KeyCode::Enter));
        assert!(app.dialog.is_some(), "the prompt is open");
        let refused = typed(&mut app, "\"Downloads");
        assert!(refused.is_none());
        assert!(app.dialog.is_some(), "and stays open");
        assert!(!app.status.is_empty(), "with the parser's reason under it");
        clear(&mut app);
        assert!(typed(&mut app, "home-share \"Downloads\"").is_none());
        assert!(app.dialog.is_none(), "an accepted line closes it");
        assert!(app.detail.as_ref().unwrap().dirty());
    }

    #[test]
    fn leaving_a_modified_instance_asks_first() {
        let (_tmp, mut app) = app();
        app.on_key(key(KeyCode::Enter));
        let detail = app.detail.as_mut().unwrap();
        detail.selected = detail.rows.iter().position(|r| r.node == "x11").unwrap();
        press(&mut app, ' ');
        assert!(app.detail.as_ref().unwrap().dirty());
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::Detail, "still there");
        assert!(app.dialog.is_some(), "asking");
        press(&mut app, 'n');
        assert_eq!(app.screen(), Screen::Detail);
        app.on_key(key(KeyCode::Esc));
        press(&mut app, 'y');
        assert_eq!(app.screen(), Screen::Instances);
        assert!(app.detail.is_none(), "and the buffer is gone with it");
    }

    #[test]
    fn a_dialog_takes_the_keys_of_whatever_is_under_it() {
        let (_tmp, mut app) = app();
        assert!(press(&mut app, 'd').is_none());
        assert!(app.dialog.is_some());
        assert!(press(&mut app, 'r').is_none(), "no sandbox is started");
        let delete = press(&mut app, 'y').unwrap();
        assert_eq!(argv(&delete), ["delete", "ff", "--yes"]);
        assert!(app.dialog.is_none());
    }

    #[test]
    fn the_explanation_is_re_run_by_its_own_toggles() {
        let (_tmp, mut app) = app();
        let action = press(&mut app, 'X').unwrap();
        assert_eq!(argv(&action), ["run", "ff", "--explain"]);
        let Action::Capture { title, explain, .. } = action else {
            panic!("an explanation is a viewer");
        };
        app.show(title, vec!["bwrap".to_owned()], explain);
        assert_eq!(app.screen(), Screen::Viewer);
        let full = press(&mut app, 'f').unwrap();
        assert_eq!(argv(&full), ["run", "ff", "--explain", "full"]);
        let Action::Capture { title, explain, .. } = full else {
            panic!("still an explanation");
        };
        app.show(title, vec!["bwrap".to_owned()], explain);
        let proxy = press(&mut app, 'p').unwrap();
        assert_eq!(
            argv(&proxy),
            ["run", "ff", "--explain", "full", "--proxy"],
            "the toggles compose"
        );
    }

    #[test]
    fn an_empty_store_says_how_to_fill_it_and_starts_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let env = fixture::env(tmp.path());
        std::fs::create_dir_all(&env.home).unwrap();
        let mut app = App::new(
            env,
            Store::load(&Env {
                ..fixture::env(tmp.path())
            })
            .unwrap(),
        );
        assert!(app.store.rows.is_empty());
        assert!(press(&mut app, 'r').is_none(), "nothing to start");
        assert!(press(&mut app, 'n').is_none());
        assert_eq!(app.screen(), Screen::Profiles, "the profile picker");
        assert!(app.status.contains("profile"), "{}", app.status);
        let create = {
            press(&mut app, 'c');
            typed(&mut app, "first")
        }
        .unwrap();
        let create = argv(&create);
        assert_eq!(create[..2], ["create", "--profile"]);
        assert_eq!(create[create.len() - 2..], ["--", "first"]);
    }

    #[test]
    fn a_name_typed_into_a_prompt_reaches_the_cli_as_a_name_and_not_a_flag() {
        // `--` closes the option list, so what was typed is the
        // positional argument whatever it starts with: without it clap
        // reads `-x` as a flag it has never heard of and refuses the run
        // rather than saying the name is not one.
        let (_tmp, mut app) = app();
        press(&mut app, 'n');
        press(&mut app, 'c');
        let create = argv(&typed(&mut app, "-x").unwrap());
        assert_eq!(create[0], "create");
        assert_eq!(create[create.len() - 2..], ["--", "-x"]);
    }

    #[test]
    fn a_shim_name_typed_into_a_prompt_reaches_the_cli_the_same_way() {
        let (_tmp, mut app) = app();
        press(&mut app, 'W');
        clear(&mut app);
        let wrap = argv(&typed(&mut app, "-y").unwrap());
        assert_eq!(wrap[0], "wrap");
        assert_eq!(wrap[wrap.len() - 2..], ["--", "ff"]);
        assert!(wrap.contains(&"--as".to_owned()), "{wrap:?}");
        assert!(wrap.contains(&"-y".to_owned()), "{wrap:?}");
    }

    /// Put the detail screen's cursor on `node`, as the keys do.
    fn on_node(app: &mut App, node: &str) {
        let detail = app.detail.as_mut().expect("the detail screen is open");
        detail.selected = detail
            .rows
            .iter()
            .position(|r| r.node == node)
            .unwrap_or_else(|| panic!("no row for `{node}`"));
    }

    #[test]
    fn delete_removes_the_entry_and_a_prompt_keeps_its_backspace() {
        fn services(app: &App) -> usize {
            app.detail.as_ref().expect("the editor").buf.services.len()
        }
        let (_tmp, mut app) = app();
        app.on_key(key(KeyCode::Enter));
        on_node(&mut app, "home-share");
        // Backspace inside the prompt takes off characters: the entry a
        // prompt is open on is not what it removes.
        app.on_key(key(KeyCode::Enter));
        clear(&mut app);
        assert!(app.dialog.is_some(), "the prompt is still open");
        typed(&mut app, "home-share \"Downloads\"");
        assert!(app.dialog.is_none(), "the line was taken");
        assert_eq!(services(&app), 1);
        // Delete on the row it wrote takes the entry out.
        on_node(&mut app, "home-share");
        app.on_key(key(KeyCode::Delete));
        assert!(
            app.status.starts_with("removed home-share \"Downloads\""),
            "{}",
            app.status
        );
        assert_eq!(services(&app), 0);
        // And so does Backspace, which reaches the pane only because no
        // prompt is open over it.
        on_node(&mut app, "home-share");
        app.on_key(key(KeyCode::Enter));
        typed(&mut app, "\"Music\"");
        assert_eq!(services(&app), 1);
        on_node(&mut app, "home-share");
        app.on_key(key(KeyCode::Backspace));
        assert!(
            app.status.starts_with("removed home-share \"Music\""),
            "{}",
            app.status
        );
        assert_eq!(services(&app), 0);
    }

    #[test]
    fn a_command_run_beside_the_editor_never_drops_what_was_typed_into_it() {
        let (_tmp, mut app) = app();
        app.on_key(key(KeyCode::Enter));
        on_node(&mut app, "x11");
        press(&mut app, ' ');
        assert!(app.detail.as_ref().unwrap().dirty());

        // What the loop does after an attached command or a captured one.
        app.say("done");
        app.reload();
        assert!(
            app.detail.as_ref().unwrap().dirty(),
            "the buffer was thrown away"
        );
        assert!(app.status.starts_with("done"), "{}", app.status);
        assert!(app.status.contains("unsaved edits kept"), "{}", app.status);

        // With nothing unsaved, the file is what the screen goes back to,
        // which is what an `$EDITOR` run leaves behind.
        press(&mut app, 'u');
        assert!(!app.detail.as_ref().unwrap().dirty());
        let path = app.detail.as_ref().unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{text}pipewire\n")).unwrap();
        app.reload();
        assert!(
            app.detail
                .as_ref()
                .unwrap()
                .rows
                .iter()
                .any(|r| r.node == "pipewire" && r.granted()),
            "the file's own change never arrived"
        );
    }

    #[test]
    fn saving_puts_the_new_grants_and_findings_in_the_list_behind_it() {
        let (_tmp, mut app) = app();
        assert_eq!(app.store.row("ff").unwrap().lint, Some([0, 0, 0]));
        app.on_key(key(KeyCode::Enter));
        // The display stack the nested X server is a client of, then the
        // server: `x11` on its own is a config that does not parse.
        for node in ["wayland", "dri", "x11"] {
            on_node(&mut app, node);
            press(&mut app, ' ');
        }
        press(&mut app, 's');
        let row = app.store.row("ff").expect("still listed");
        assert!(row.grants.contains(&"x11"), "{:?}", row.grants);
        // The nested server earns `x11-nested-no-wm`; a machine whose GPU
        // is on the proprietary NVIDIA driver earns `dri-nvidia-primary`
        // beside it, so the count is the host's, not the config's.
        let [errors, warnings, notes] = row.lint.expect("the row carries a lint result");
        assert_eq!(
            (errors, warnings, notes >= 1),
            (0, 0, true),
            "{:?}",
            row.lint
        );
    }

    #[test]
    fn the_viewer_scrolls_by_the_page_it_can_show() {
        let (_tmp, mut app) = app();
        app.page = 5;
        let lines: Vec<String> = (0..20).map(|i| i.to_string()).collect();
        app.show("long", lines, None);
        press(&mut app, 'G');
        let offset = |app: &App| app.viewer.as_ref().unwrap().offset;
        assert_eq!(offset(&app), 15, "the last page, not the last line");
        press(&mut app, 'j');
        assert_eq!(offset(&app), 15, "and there is nothing under it");
        app.on_key(key(KeyCode::PageUp));
        assert_eq!(offset(&app), 10);
        press(&mut app, 'k');
        assert_eq!(offset(&app), 9);
        press(&mut app, 'g');
        assert_eq!(offset(&app), 0);
        press(&mut app, 'k');
        assert_eq!(offset(&app), 0);
    }

    #[test]
    fn a_typed_command_line_is_split_the_way_a_shell_would_and_no_further() {
        assert_eq!(
            split("sh -c \"echo a b\" d\\ e").unwrap(),
            [
                OsString::from("sh"),
                "-c".into(),
                "echo a b".into(),
                "d e".into()
            ]
        );
        assert_eq!(split("  ").unwrap(), Vec::<OsString>::new());
        assert_eq!(
            split("a \"\" b").unwrap().len(),
            3,
            "an empty argument is one"
        );
        assert!(split("sh -c \"echo").is_err(), "a quote left open");
        assert!(split("sh \\").is_err(), "a backslash escaping nothing");
        // Nothing is expanded: there is no shell for it to mean anything to.
        assert_eq!(
            split("$HOME *").unwrap(),
            [OsString::from("$HOME"), "*".into()]
        );
    }

    #[test]
    fn a_throwaway_sandbox_takes_the_command_to_run_in_it() {
        let (_tmp, mut app) = app();
        press(&mut app, 't');
        clear(&mut app);
        let action = typed(&mut app, "generic wayland keep=kept -- sh -c \"echo hi\"").unwrap();
        assert_eq!(
            argv(&action),
            [
                "try",
                "--profile",
                "generic",
                "--grant",
                "wayland",
                "--keep",
                "kept",
                "--",
                "sh",
                "-c",
                "echo hi"
            ]
        );
        // And the command an exec sends is split the same way.
        press(&mut app, 'x');
        clear(&mut app);
        let action = typed(&mut app, "sh -c \"echo a b\"").unwrap();
        assert_eq!(argv(&action), ["exec", "ff", "--", "sh", "-c", "echo a b"]);
        // A line that cannot be split keeps the prompt and says why.
        press(&mut app, 'x');
        clear(&mut app);
        assert!(typed(&mut app, "sh -c \"echo").is_none());
        assert!(app.dialog.is_some(), "the prompt closed on a bad line");
        assert!(app.status.contains("quote"), "{}", app.status);
    }

    /// The parity rule: everything the CLI can do is reachable from the
    /// editor. The keys below are pressed on the two screens that carry
    /// them — the instance list first, then the profile list — and `man`
    /// is deliberately not among them, a roff page being nothing to press
    /// a key for; neither is `ui` itself.
    #[test]
    fn every_subcommand_is_reachable_from_a_key() {
        let (_tmp, mut app) = app();
        let mut reached: Vec<String> = Vec::new();
        let mut note = |app: &mut App, action: Option<Action>| {
            if let Some(action) = action {
                let argv = argv(&action);
                if let Some(first) = argv.first() {
                    let name = match (first.as_str(), argv.get(1)) {
                        ("profile", Some(sub)) => format!("profile {sub}"),
                        (first, _) => first.to_owned(),
                    };
                    reached.push(name);
                }
            }
            app.dialog = None;
        };
        for k in ['r', 'o', 'e', 'l', 'L', 'X'] {
            let action = press(&mut app, k);
            note(&mut app, action);
        }
        for (k, answer) in [('d', 'y'), ('R', 'y'), ('D', 'w')] {
            press(&mut app, k);
            let action = press(&mut app, answer);
            note(&mut app, action);
        }
        for (k, text) in [('x', "sh"), ('t', "generic"), ('W', "ff")] {
            press(&mut app, k);
            clear(&mut app);
            let action = typed(&mut app, text);
            note(&mut app, action);
        }
        // A shim in the registry is what makes `unwrap` reachable.
        app.store.shims.push(bubbler_core::wrap::Wrap {
            name: "ff".to_owned(),
            instance: "ff".to_owned(),
        });
        press(&mut app, 'W');
        let action = press(&mut app, 'u');
        note(&mut app, action);
        press(&mut app, 'p');
        for k in ['\n', 'l', 'e', 'c'] {
            let action = match k {
                '\n' => app.on_key(key(KeyCode::Enter)),
                'c' => {
                    press(&mut app, 'c');
                    typed(&mut app, "new")
                }
                other => press(&mut app, other),
            };
            note(&mut app, action);
        }
        reached.sort();
        reached.dedup();
        let expected = [
            "create",
            "delete",
            "desktop",
            "edit",
            "exec",
            "lint",
            "log",
            "open",
            "profile edit",
            "profile lint",
            "profile show",
            "reseed",
            "run",
            "try",
            "unwrap",
            "wrap",
        ];
        assert_eq!(reached, expected);
    }
}
