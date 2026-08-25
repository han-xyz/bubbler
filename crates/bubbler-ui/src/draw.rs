//! What the screens look like. Everything here reads the state and
//! writes cells; nothing here decides anything, which is what makes the
//! screens testable against a `TestBackend` buffer.

use bubbler_core::catalogue::Risk;
use bubbler_core::lint::{Finding, Severity};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Cell, Clear, List, ListItem, ListState, Paragraph, Row, StatefulWidget, Table,
    TableState, Widget, Wrap,
};

use crate::app::{App, Dialog, Screen, Viewer};
use crate::detail::Detail;
use crate::store::Row as InstanceRow;

/// What one screen offers. Two lists because a footer that does not fit
/// its terminal says nothing at all, and the full list is a screen of
/// its own; the full one is pairs rather than one string so that `?` can
/// lay it out in columns that keep a key beside what it does.
struct Keys {
    screen: Screen,
    name: &'static str,
    footer: &'static str,
    full: &'static [(&'static str, &'static str)],
}

const KEYS: [Keys; 4] = [
    Keys {
        screen: Screen::Instances,
        name: "instances",
        footer: "Enter grants  r run  o open  x exec  d delete  e edit  l lint  ? more  q quit",
        full: &[
            ("Enter", "grants"),
            ("r", "run"),
            ("o", "open"),
            ("x", "exec"),
            ("t", "try"),
            ("n", "new"),
            ("d", "delete"),
            ("R", "reseed"),
            ("e", "edit"),
            ("l", "lint"),
            ("L", "log"),
            ("D", "desktop"),
            ("W", "wrap"),
            ("X", "explain"),
            ("p", "profiles"),
            ("^R", "reload"),
            ("q", "quit"),
        ],
    },
    Keys {
        screen: Screen::Detail,
        name: "grants",
        footer: "Space grant  Enter write it  e $EDITOR  s save  u undo  ? more  Esc back",
        full: &[
            ("Space", "grant or revoke"),
            ("Enter", "write the node as KDL"),
            ("e", "$EDITOR on config.kdl"),
            ("s", "save"),
            ("u", "undo"),
            ("l", "lint"),
            ("X", "explain"),
            ("Esc", "back"),
        ],
    },
    Keys {
        screen: Screen::Profiles,
        name: "profiles",
        footer: "Enter show  c create an instance  e $EDITOR  l lint  Esc back",
        full: &[
            ("Enter", "show it flattened"),
            ("c", "create an instance from it"),
            ("e", "$EDITOR on your layer"),
            ("l", "lint"),
            ("Esc", "back"),
        ],
    },
    Keys {
        screen: Screen::Viewer,
        name: "viewer",
        footer: "j/k scroll  f full  p proxy  Esc back",
        full: &[
            ("j/k", "scroll"),
            ("g/G", "ends"),
            ("f", "every argument"),
            ("p", "the D-Bus proxy's argv"),
            ("Esc", "back"),
        ],
    },
];

/// Colour of a grant's row: the levels the catalogue draws, so an
/// `outward` grant is visible before it is read.
fn risk_style(risk: Risk) -> Style {
    match risk {
        Risk::Narrow => Style::default(),
        Risk::Wide => Style::default().fg(Color::Yellow),
        Risk::Outward => Style::default().fg(Color::Red),
    }
}

/// One character that says the same thing as the colour, for a terminal
/// with no colour and for a reader who cannot tell red from yellow.
fn risk_mark(risk: Risk) -> &'static str {
    match risk {
        Risk::Narrow => " ",
        Risk::Wide => "!",
        Risk::Outward => "!!",
    }
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Error => Style::default().fg(Color::Red),
        Severity::Warning => Style::default().fg(Color::Yellow),
        Severity::Note => Style::default().fg(Color::Cyan),
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);
        self.header().render(header, buf);
        match self.screen() {
            Screen::Instances => instances(self, body, buf),
            Screen::Detail => match &self.detail {
                Some(detail) => self::detail(detail, body, buf),
                None => Paragraph::new("no instance open").render(body, buf),
            },
            Screen::Profiles => profiles(self, body, buf),
            Screen::Viewer => match &self.viewer {
                Some(viewer) => self::viewer(viewer, body, buf),
                None => Paragraph::new("nothing to show").render(body, buf),
            },
        }
        self.footer().render(footer, buf);
        if self.help {
            help(area, buf);
        } else if let Some(dialog) = &self.dialog {
            self::dialog(dialog, area, buf);
        }
    }
}

impl App {
    fn header(&self) -> Paragraph<'_> {
        let what = match self.screen() {
            Screen::Instances => count(self.store.rows.len(), "instance"),
            Screen::Detail => match &self.detail {
                Some(detail) => title(detail),
                None => String::new(),
            },
            Screen::Profiles => count(self.store.profiles.len(), "profile"),
            Screen::Viewer => self
                .viewer
                .as_ref()
                .map_or_else(String::new, |v| v.title.clone()),
        };
        Paragraph::new(Line::from(vec![
            Span::styled("bubbler", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(" — {what}")),
        ]))
    }

    fn footer(&self) -> Paragraph<'_> {
        if !self.status.is_empty() {
            return Paragraph::new(Line::from(self.status.as_str()).italic());
        }
        let keys = KEYS
            .iter()
            .find(|keys| keys.screen == self.screen())
            .map_or("", |keys| keys.footer);
        Paragraph::new(Line::from(keys).dim())
    }
}

/// `1 instance`, `2 instances`.
fn count(n: usize, what: &str) -> String {
    match n {
        1 => format!("1 {what}"),
        n => format!("{n} {what}s"),
    }
}

/// The title line of the detail screen: what is being edited, what it
/// came from and whether it is running.
fn title(detail: &Detail) -> String {
    let mut title = detail.name().to_owned();
    if let Some(profile) = &detail.profile {
        title.push_str(&format!(" ({profile})"));
    }
    title.push_str(match detail.live {
        true => " ● running",
        false => " ○ stopped",
    });
    if detail.dirty() {
        title.push_str(" — modified, `s` writes it");
    }
    title
}

/// The instance list, or the one line that says how to make an instance.
fn instances(app: &App, area: Rect, buf: &mut Buffer) {
    if app.store.rows.is_empty() {
        Paragraph::new(Text::from(vec![
            Line::from("No instances yet."),
            Line::from(""),
            Line::from("`p` lists the profiles; `c` on one creates an instance from it."),
            Line::from("The same thing outside: `bubbler create <name> --profile <profile>`."),
        ]))
        .render(area, buf);
        return;
    }
    let rows = app.store.rows.iter().map(instance_row);
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Fill(1),
            Constraint::Length(11),
        ],
    )
    .header(
        Row::new(["NAME", "PROFILE", "STATE", "GRANTS", "LINT"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol("> ");
    let mut state = TableState::default().with_selected(Some(app.instance));
    StatefulWidget::render(table, area, buf, &mut state);
}

fn instance_row(row: &InstanceRow) -> Row<'_> {
    let state = match (row.live, &row.error) {
        (_, Some(_)) => "unread",
        (true, None) => "● run",
        (false, None) => "○ stop",
    };
    let grants = match &row.error {
        Some(e) => e.lines().next().unwrap_or("").to_owned(),
        None => row.grants.join(" "),
    };
    Row::new([
        Cell::from(row.name.as_str()),
        Cell::from(row.profile.as_deref().unwrap_or("-")),
        Cell::from(state),
        Cell::from(grants),
        Cell::from(row.lint_label()),
    ])
}

/// The instance being edited: its grants on the left, what the selected
/// one costs on the right.
fn detail(detail: &Detail, area: Rect, buf: &mut Buffer) {
    let [banner, body] = Layout::vertical([
        Constraint::Length(u16::from(detail.live)),
        Constraint::Fill(1),
    ])
    .areas(area);
    if detail.live {
        Paragraph::new(
            Line::from("the sandbox is running: what is written here applies on the next start")
                .yellow(),
        )
        .render(banner, buf);
    }
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Fill(1)]).areas(body);
    let items = detail.rows.iter().map(|row| {
        let grant = row.grant();
        let risk = grant.map_or(Risk::Narrow, |g| g.risk);
        let mark = match row.granted() {
            true => "●",
            false => "○",
        };
        let text = match &row.text {
            Some(text) => crate::detail::flatten(text),
            None => row.node.to_owned(),
        };
        let style = match row.granted() {
            true => risk_style(risk),
            false => Style::default().dim(),
        };
        ListItem::new(Line::styled(
            format!("{mark} {:<2} {text}", risk_mark(risk)),
            style,
        ))
    });
    let list = List::new(items)
        .block(Block::bordered().title_top("grants"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default().with_selected(Some(detail.selected));
    StatefulWidget::render(list, left, buf, &mut state);
    Paragraph::new(what_it_costs(detail))
        .wrap(Wrap { trim: true })
        .block(Block::bordered().title_top("what it grants"))
        .render(right, buf);
}

/// The right-hand pane: the catalogue entry for the selected node, then
/// what the linter said about it.
fn what_it_costs(detail: &Detail) -> Text<'static> {
    let mut lines = Vec::new();
    if let Some(trouble) = &detail.trouble {
        lines.push(Line::styled(
            trouble.clone(),
            severity_style(Severity::Error),
        ));
        lines.push(Line::from(""));
    }
    let Some(row) = detail.row() else {
        return Text::from(lines);
    };
    if let Some(grant) = row.grant() {
        lines.push(Line::styled(
            format!("{}  ({})", grant.node, grant.risk),
            risk_style(grant.risk).add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::styled(
            grant.grammar.to_owned(),
            Style::default().dim(),
        ));
        lines.push(Line::from(""));
        lines.push(Line::from(grant.summary.to_owned()));
        lines.push(Line::from(""));
        lines.push(Line::from(grant.cost.to_owned()));
    }
    let findings = detail.findings_of(row);
    let loose = detail.loose_findings();
    let findings = findings.into_iter().chain(loose);
    let mut any = false;
    for finding in findings {
        if !any {
            lines.push(Line::from(""));
            any = true;
        }
        lines.extend(finding_lines(finding));
    }
    Text::from(lines)
}

/// One finding as the two lines `bubbler lint` prints it in.
fn finding_lines(finding: &Finding) -> Vec<Line<'static>> {
    vec![
        Line::styled(
            format!("{}[{}]: {}", finding.severity, finding.id, finding.message),
            severity_style(finding.severity),
        ),
        Line::styled(format!("  help: {}", finding.help), Style::default().dim()),
    ]
}

/// Every profile any layer holds, with the layer it resolves to.
fn profiles(app: &App, area: Rect, buf: &mut Buffer) {
    if let Some(e) = &app.store.profile_error {
        Paragraph::new(Line::styled(
            format!("reading the profile layers: {e}"),
            severity_style(Severity::Error),
        ))
        .wrap(Wrap { trim: true })
        .render(area, buf);
        return;
    }
    let rows = app.store.profiles.iter().map(|entry| {
        Row::new([
            Cell::from(entry.name.clone()),
            Cell::from(entry.origin.to_string()),
            Cell::from(
                entry
                    .path
                    .as_deref()
                    .map_or_else(|| "-".to_owned(), |p| p.display().to_string()),
            ),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(["NAME", "LAYER", "FILE"]).style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol("> ");
    let mut state = TableState::default().with_selected(Some(app.profile));
    StatefulWidget::render(table, area, buf, &mut state);
}

/// A report, an explanation or a log.
fn viewer(viewer: &Viewer, area: Rect, buf: &mut Buffer) {
    let text = Text::from(
        viewer
            .lines
            .iter()
            .map(|l| Line::from(l.clone()))
            .collect::<Vec<Line>>(),
    );
    let offset = u16::try_from(viewer.offset).unwrap_or(u16::MAX);
    Paragraph::new(text)
        .block(Block::bordered().title_top(viewer.title.clone()))
        .scroll((offset, 0))
        .render(area, buf);
}

/// Where a dialog goes: the middle of the screen, wide enough for a node
/// and tall enough for the question, the field and its grammar.
fn dialog_area(area: Rect) -> Rect {
    let width = area.width.saturating_sub(4).clamp(20, 76);
    let height = 6.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

/// The prompt or the question over the screen.
fn dialog(dialog: &Dialog, area: Rect, buf: &mut Buffer) {
    let area = dialog_area(area);
    Clear.render(area, buf);
    match dialog {
        Dialog::Ask {
            title, hint, input, ..
        } => {
            let block = Block::bordered().title_top(title.clone());
            let inner = block.inner(area);
            block.render(area, buf);
            let (value, _) = input.view(usize::from(inner.width));
            Paragraph::new(Text::from(vec![
                Line::from(value.to_owned()),
                Line::from(""),
                Line::styled(hint.clone(), Style::default().dim()),
                Line::styled(
                    "Enter writes it, Esc leaves it alone",
                    Style::default().dim(),
                ),
            ]))
            .render(inner, buf);
        }
        Dialog::Choose { question, choices } => {
            let block = Block::bordered().title_top("confirm");
            let inner = block.inner(area);
            block.render(area, buf);
            let mut lines = vec![Line::from(question.clone()), Line::from("")];
            lines.extend(
                choices
                    .iter()
                    .map(|c| Line::from(format!("{}  {}", c.key, c.label))),
            );
            lines.push(Line::styled(
                "Esc or `n` leaves it alone",
                Style::default().dim(),
            ));
            Paragraph::new(Text::from(lines))
                .wrap(Wrap { trim: true })
                .render(inner, buf);
        }
    }
}

/// Where the terminal cursor belongs, which is inside the prompt's field
/// and nowhere else.
pub fn cursor(app: &App, area: Rect) -> Option<Position> {
    let Some(Dialog::Ask { input, .. }) = &app.dialog else {
        return None;
    };
    let inner = dialog_area(area).inner(ratatui::layout::Margin::new(1, 1));
    let (_, at) = input.view(usize::from(inner.width));
    Some(Position {
        x: inner.x + u16::try_from(at).unwrap_or(0),
        y: inner.y,
    })
}

/// One screen's keys as aligned columns, as wide as the overlay holds.
/// Columns rather than one run-on line because wrapping a run-on line
/// breaks wherever the width lands — between `D` and `desktop` at 100
/// columns — and a key with someone else's description under it is
/// worse than no list at all. No line starts with a space, so the
/// paragraph's `trim` leaves the columns where they are.
fn key_grid(keys: &[(&str, &str)], width: u16) -> Vec<String> {
    const GAP: usize = 2;
    let key_width = keys
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    let what_width = keys
        .iter()
        .map(|(_, w)| w.chars().count())
        .max()
        .unwrap_or(0);
    let cell = key_width + 1 + what_width;
    let columns = ((usize::from(width) + GAP) / (cell + GAP)).max(1);
    keys.chunks(columns)
        .map(|row| {
            row.iter()
                .map(|(key, what)| format!("{key:<key_width$} {what:<what_width$}"))
                .collect::<Vec<_>>()
                .join(&" ".repeat(GAP))
                .trim_end()
                .to_owned()
        })
        .collect()
}

/// Every key of every screen, over whatever is under it.
fn help(area: Rect, buf: &mut Buffer) {
    let block = Block::bordered().title_top("keys");
    let inner = block.inner(area);
    let mut lines = vec![
        Line::styled(
            "bubbler-ui — every action is a `bubbler` command line",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
    ];
    for keys in KEYS {
        lines.push(Line::styled(
            keys.name.to_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.extend(key_grid(keys.full, inner.width).into_iter().map(Line::from));
        lines.push(Line::from(""));
    }
    lines.push(Line::styled(
        "run and open start detached; exec, try and the editors take the terminal",
        Style::default().dim(),
    ));
    lines.push(Line::styled(
        "`q` leaves and `Esc` goes back one screen; `^C` does nothing while this is up, \
         since the terminal is raw and every key reaches the editor",
        Style::default().dim(),
    ));
    lines.push(Line::styled("any key closes this", Style::default().dim()));
    Clear.render(area, buf);
    block.render(area, buf);
    Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: true })
        .render(inner, buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::fixture;
    use crate::store::Store;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// The screen as literal lines, symbols only: a style is what a
    /// colour scheme changes, and pinning styles here would make every
    /// one of these a colour test as well.
    fn screen(app: &App, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| frame.render_widget(app, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .filter_map(|x| buffer.cell((x, y)).map(|c| c.symbol()))
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect()
    }

    /// An editor over a store holding one instance per pair.
    fn editor(instances: &[(&str, &str)]) -> (tempfile::TempDir, App) {
        let (tmp, env) = fixture::store(instances);
        let store = Store::load(&env).unwrap();
        (tmp, App::new(env, store))
    }

    /// One instance granting enough to fill every column, written as a
    /// file rather than toggled, so the screens below are what a config
    /// on disk looks like.
    fn list_editor() -> (tempfile::TempDir, App) {
        let (tmp, mut app) = editor(&[("ff", "generic")]);
        std::fs::write(
            bubbler_core::instance::config_path(&app.env, "ff"),
            "// bubbler profile: generic\n// bubbler config: 2\n\
             wayland\nx11 \"host\"\nhome-share \"Downloads\" mode=rw\n",
        )
        .unwrap();
        app.reload();
        app.say(String::new());
        (tmp, app)
    }

    #[test]
    fn the_instance_list_is_one_row_an_instance_with_what_it_grants() {
        let (_tmp, app) = list_editor();
        assert_eq!(
            screen(&app, 80, 8),
            [
                "bubbler — 1 instance",
                "  NAME             PROFILE        STATE    GRANTS                    LINT",
                "> ff               generic        ○ stop   wayland x11 home-share    2 warnings",
                "",
                "",
                "",
                "",
                "Enter grants  r run  o open  x exec  d delete  e edit  l lint  ? more  q quit",
            ]
        );
    }

    #[test]
    fn the_detail_screen_puts_what_a_grant_costs_beside_the_toggle() {
        let (_tmp, mut app) = list_editor();
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.detail.as_mut().unwrap().selected = 1;
        assert_eq!(
            screen(&app, 80, 14),
            [
                "bubbler — ff (generic) ○ stopped",
                "┌grants────────────────────────────┐┌what it grants────────────────────────────┐",
                "│●    wayland                      ││x11  (outward)                            │",
                "│● !! x11 \"host\"                   ││x11 [\"host\"] [geometry=\"WxH\"]             │",
                "│● !  home-share \"Downloads\" mode=r││[fullscreen=#true] [grab=#true]           │",
                "│○ !  network                      ││[wm=\"<program>\"]                          │",
                "│○ !  dri                          ││                                          │",
                "│○ !  pipewire                     ││an X server of the sandbox's own, or the  │",
                "│○ !  pulseaudio                   ││session's                                 │",
                "│○ !! gamepad                      ││                                          │",
                "│○ !  hidraw                       ││Bare, bubbler starts a rootful Xwayland   │",
                "│○ !  camera                       ││inside the sandbox as a client of the     │",
                "└──────────────────────────────────┘└──────────────────────────────────────────┘",
                "Space grant  Enter write it  e $EDITOR  s save  u undo  ? more  Esc back",
            ]
        );
        // And, further down the same pane, what the linter makes of it:
        // further than it was, the cost of this node having grown a
        // second server, a lazy start and a window manager to describe.
        let tall = screen(&app, 80, 40).join(" ");
        assert!(tall.contains("warning[x11-without-reason]"), "{tall}");
        assert!(
            tall.contains("help: drop the argument for a nested"),
            "{tall}"
        );
    }

    #[test]
    fn a_prompt_holds_the_node_as_it_is_written_and_its_grammar() {
        let (_tmp, mut app) = list_editor();
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.detail.as_mut().unwrap().selected = 1;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(
            screen(&app, 80, 14),
            [
                "bubbler — ff (generic) ○ stopped",
                "┌grants────────────────────────────┐┌what it grants────────────────────────────┐",
                "│●    wayland                      ││x11  (outward)                            │",
                "│● !! x11 \"host\"                   ││x11 [\"host\"] [geometry=\"WxH\"]             │",
                "│●┌x11 in `ff`───────────────────────────────────────────────────────────────┐ │",
                "│○│x11 \"host\"                                                                │ │",
                "│○│                                                                          │ │",
                // The grammar is one line and the field clips it, as it
                // clips `seccomp`'s: what the prompt is for is the node
                // above, and the whole grammar is in the pane behind it.
                "│○│x11 [\"host\"] [geometry=\"WxH\"] [fullscreen=#true] [grab=#true] [wm=\"<progra│ │",
                "│○│Enter writes it, Esc leaves it alone                                      │ │",
                "│○└──────────────────────────────────────────────────────────────────────────┘ │",
                "│○ !  hidraw                       ││Bare, bubbler starts a rootful Xwayland   │",
                "│○ !  camera                       ││inside the sandbox as a client of the     │",
                "└──────────────────────────────────┘└──────────────────────────────────────────┘",
                "Space grant  Enter write it  e $EDITOR  s save  u undo  ? more  Esc back",
            ]
        );
        // The cursor sits at the end of what is written, inside the field.
        assert_eq!(
            cursor(&app, Rect::new(0, 0, 80, 14)),
            Some(Position { x: 13, y: 5 })
        );
    }

    #[test]
    fn a_report_is_shown_as_it_was_printed() {
        let (_tmp, mut app) = list_editor();
        app.show("lint ff", vec!["one".to_owned(), "two".to_owned()], None);
        assert_eq!(
            screen(&app, 80, 8),
            [
                "bubbler — lint ff",
                "┌lint ff───────────────────────────────────────────────────────────────────────┐",
                "│one                                                                           │",
                "│two                                                                           │",
                "│                                                                              │",
                "│                                                                              │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "j/k scroll  f full  p proxy  Esc back",
            ]
        );
    }

    /// A key and what it does, on one line with only spaces between
    /// them: `line` holds `key` at a word boundary, then a gap, then
    /// the description.
    fn beside(line: &str, key: &str, what: &str) -> bool {
        line.match_indices(key).any(|(at, _)| {
            let before = at == 0 || line.as_bytes()[at - 1] == b' ';
            let rest = &line[at + key.len()..];
            before && rest.starts_with(' ') && rest.trim_start().starts_with(what)
        })
    }

    /// The overlay at the width it used to break at: the keys of a
    /// screen stand in columns, so no line ends on a key whose
    /// description starts the next one.
    #[test]
    fn the_help_overlay_stands_every_key_beside_what_it_does() {
        let (_tmp, mut app) = list_editor();
        app.help = true;
        assert_eq!(
            screen(&app, 100, 30),
            [
                "┌keys──────────────────────────────────────────────────────────────────────────────────────────────┐",
                "│bubbler-ui — every action is a `bubbler` command line                                             │",
                "│                                                                                                  │",
                "│instances                                                                                         │",
                "│Enter grants    r     run       o     open      x     exec      t     try       n     new         │",
                "│d     delete    R     reseed    e     edit      l     lint      L     log       D     desktop     │",
                "│W     wrap      X     explain   p     profiles  ^R    reload    q     quit                        │",
                "│                                                                                                  │",
                "│grants                                                                                            │",
                "│Space grant or revoke        Enter write the node as KDL  e     $EDITOR on config.kdl             │",
                "│s     save                   u     undo                   l     lint                              │",
                "│X     explain                Esc   back                                                           │",
                "│                                                                                                  │",
                "│profiles                                                                                          │",
                "│Enter show it flattened           c     create an instance from it                                │",
                "│e     $EDITOR on your layer       l     lint                                                      │",
                "│Esc   back                                                                                        │",
                "│                                                                                                  │",
                "│viewer                                                                                            │",
                "│j/k scroll                  g/G ends                    f   every argument                        │",
                "│p   the D-Bus proxy's argv  Esc back                                                              │",
                "│                                                                                                  │",
                "│run and open start detached; exec, try and the editors take the terminal                          │",
                "│`q` leaves and `Esc` goes back one screen; `^C` does nothing while this is up, since the terminal │",
                "│is raw and every key reaches the editor                                                           │",
                "│any key closes this                                                                               │",
                "│                                                                                                  │",
                "│                                                                                                  │",
                "│                                                                                                  │",
                "└──────────────────────────────────────────────────────────────────────────────────────────────────┘",
            ]
        );
    }

    /// And at the widths either side of it: every key still has its own
    /// description after it, and no row is wider than the overlay, which
    /// is what would wrap one in two.
    #[test]
    fn the_help_overlay_holds_together_at_every_width() {
        let (_tmp, mut app) = list_editor();
        app.help = true;
        for width in [80u16, 100, 140] {
            let drawn = screen(&app, width, 30);
            for line in &drawn {
                assert!(
                    line.chars().count() <= usize::from(width),
                    "{width}: `{line}` is wider than the terminal"
                );
            }
            // Without the overlay's own border, which is no boundary
            // between one cell and the next.
            let rows: Vec<String> = drawn
                .iter()
                .map(|line| line.replace('\u{2502}', " "))
                .collect();
            for keys in KEYS {
                for (key, what) in keys.full {
                    assert!(
                        rows.iter().any(|line| beside(line, key, what)),
                        "{width}: `{key} {what}` of {} is split up in {drawn:#?}",
                        keys.name
                    );
                }
            }
        }
    }

    #[test]
    fn an_empty_store_says_how_to_fill_it() {
        let (_tmp, app) = editor(&[]);
        assert_eq!(
            screen(&app, 80, 8),
            [
                "bubbler — 0 instances",
                "No instances yet.",
                "",
                "`p` lists the profiles; `c` on one creates an instance from it.",
                "The same thing outside: `bubbler create <name> --profile <profile>`.",
                "",
                "",
                "Enter grants  r run  o open  x exec  d delete  e edit  l lint  ? more  q quit",
            ]
        );
    }
}
