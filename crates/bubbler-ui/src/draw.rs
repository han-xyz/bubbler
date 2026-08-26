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
        footer: "Space grant/disable  Enter write  Del remove  s save  u undo  ? more  Esc back",
        full: &[
            ("Space", "grant / disable (keeps the line) / enable"),
            ("Enter", "write the node as KDL"),
            ("Delete", "remove the entry (Backspace too)"),
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
    if row.disabled() {
        lines.push(Line::styled(
            "disabled — Space enables, Delete removes",
            Style::default().dim(),
        ));
        lines.push(Line::from(""));
    }
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

/// A hint split at the places a row may break: the spaces between its
/// tokens, and never the ones inside a quoted token. `home-share
/// "<path under $HOME>"` holds spaces of its own, and half of a path is
/// the grammar of nothing.
fn tokens(hint: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (at, c) in hint.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if at > start {
                    tokens.push(&hint[start..at]);
                }
                start = at + 1;
            }
            _ => {}
        }
    }
    if start < hint.len() {
        tokens.push(&hint[start..]);
    }
    tokens
}

/// `hint` as rows no wider than `width`, filled a token at a time. A
/// token wider than the row takes a row of its own rather than being
/// cut in two; an empty hint is still one row, so a prompt keeps its
/// shape.
fn wrapped(hint: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows: Vec<String> = Vec::new();
    let mut row = String::new();
    for token in tokens(hint) {
        if row.is_empty() {
            row.push_str(token);
        } else if row.chars().count() + 1 + token.chars().count() <= width {
            row.push(' ');
            row.push_str(token);
        } else {
            rows.push(std::mem::take(&mut row));
            row.push_str(token);
        }
    }
    rows.push(row);
    rows
}

/// How tall a dialog stands: its border and what it holds. A prompt
/// holds the field, a blank line, its grammar — as many rows as the
/// width leaves it — and the line saying which key writes it.
fn dialog_height(dialog: &Dialog, width: u16) -> u16 {
    match dialog {
        Dialog::Ask { hint, .. } => {
            let rows = wrapped(hint, usize::from(width.saturating_sub(2))).len();
            u16::try_from(rows).unwrap_or(u16::MAX).saturating_add(5)
        }
        Dialog::Choose { .. } => 6,
    }
}

/// Where a dialog goes: the middle of the screen, wide enough for a node
/// and tall enough for the question, the field and every row of its
/// grammar.
fn dialog_area(dialog: &Dialog, area: Rect) -> Rect {
    let width = area.width.saturating_sub(4).clamp(20, 76);
    let height = dialog_height(dialog, width).min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

/// The prompt or the question over the screen.
fn dialog(dialog: &Dialog, area: Rect, buf: &mut Buffer) {
    let area = dialog_area(dialog, area);
    Clear.render(area, buf);
    match dialog {
        Dialog::Ask {
            title, hint, input, ..
        } => {
            let block = Block::bordered().title_top(title.clone());
            let inner = block.inner(area);
            block.render(area, buf);
            let (value, _) = input.view(usize::from(inner.width));
            let mut lines = vec![Line::from(value.to_owned()), Line::from("")];
            lines.extend(
                wrapped(hint, usize::from(inner.width))
                    .into_iter()
                    .map(|row| Line::styled(row, Style::default().dim())),
            );
            lines.push(Line::styled(
                "Enter writes it, Esc leaves it alone",
                Style::default().dim(),
            ));
            Paragraph::new(Text::from(lines)).render(inner, buf);
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
    let dialog = app.dialog.as_ref()?;
    let Dialog::Ask { input, .. } = dialog else {
        return None;
    };
    let inner = dialog_area(dialog, area).inner(ratatui::layout::Margin::new(1, 1));
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
        let buffer = drawn(app, width, height);
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

    /// The cells as drawn, styles and all: what a symbol is dimmed with
    /// is not in the text the screen reads back as.
    fn drawn(app: &App, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| frame.render_widget(app, frame.area()))
            .unwrap();
        terminal.backend().buffer().clone()
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
        editor_over("wayland\nx11 \"host\"\nhome-share \"Downloads\" mode=rw\n")
    }

    /// An editor over one instance whose `config.kdl` holds `text`.
    fn editor_over(text: &str) -> (tempfile::TempDir, App) {
        let (tmp, mut app) = editor(&[("ff", "generic")]);
        std::fs::write(
            bubbler_core::instance::config_path(&app.env, "ff"),
            format!("// bubbler profile: generic\n// bubbler config: 2\n{text}"),
        )
        .unwrap();
        app.reload();
        app.say(String::new());
        (tmp, app)
    }

    /// The column `text` starts at on `line`, which is a column of the
    /// buffer because every cell of these screens is one column wide.
    fn column_of(line: &str, text: char) -> u16 {
        u16::try_from(line.chars().take_while(|c| *c != text).count()).expect("a column")
    }

    #[test]
    fn a_disabled_entry_is_a_dimmed_row_of_its_own() {
        let (_tmp, mut app) = editor_over("wayland\n/-home-share \"Downloads\"\nnetwork\n");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let lines = screen(&app, 80, 12);
        let off = lines
            .iter()
            .position(|l| l.contains("home-share"))
            .expect("the disabled row");
        assert!(
            lines[off].starts_with("│○ !  home-share \"Downloads\""),
            "{:?}",
            lines[off]
        );
        assert!(lines[off - 1].starts_with("│●    wayland"), "{lines:?}");
        // The mark says it is off, and the text is dimmed the way the
        // nodes the config does not hold are.
        let cells = drawn(&app, 80, 12);
        let y = u16::try_from(off).expect("a row");
        let cell = cells
            .cell((column_of(&lines[off], 'h'), y))
            .expect("the first cell of the text");
        assert_eq!(cell.symbol(), "h");
        assert!(cell.modifier.contains(Modifier::DIM), "{cell:?}");
        let on = lines
            .iter()
            .position(|l| l.contains("network"))
            .expect("the granted row below it");
        let cell = cells
            .cell((
                column_of(&lines[on], 'n'),
                u16::try_from(on).expect("a row"),
            ))
            .expect("the first cell of the text");
        assert!(!cell.modifier.contains(Modifier::DIM), "{cell:?}");
        // And the pane beside it says what the two keys do with it.
        let detail = app.detail.as_mut().expect("the editor");
        detail.selected = detail
            .rows
            .iter()
            .position(crate::detail::Row::disabled)
            .expect("the disabled row");
        let said = screen(&app, 80, 12).join(" ");
        assert!(
            said.contains("disabled — Space enables, Delete removes"),
            "{said}"
        );
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
                // The row that writes a second share, right after the
                // one the file holds.
                "│○ !  home-share                   ││[wm=\"<program>\"]                          │",
                "│○ !  network                      ││                                          │",
                "│○ !  dri                          ││an X server of the sandbox's own, or the  │",
                "│○ !  pipewire                     ││session's                                 │",
                "│○ !  pulseaudio                   ││                                          │",
                "│○ !! gamepad                      ││Bare, bubbler starts a rootful Xwayland   │",
                "│○ !  hidraw                       ││inside the sandbox as a client of the     │",
                "└──────────────────────────────────┘└──────────────────────────────────────────┘",
                "Space grant/disable  Enter write  Del remove  s save  u undo  ? more  Esc back",
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
                "│●┌x11 in `ff`───────────────────────────────────────────────────────────────┐ │",
                "│●│x11 \"host\"                                                                │ │",
                "│○│                                                                          │ │",
                // The grammar wraps at the spaces between its tokens
                // instead of stopping at the field's edge, and the
                // prompt stands a row taller for it: the last token is
                // `[wm="<program>"]`, not the half of it that fit.
                "│○│x11 [\"host\"] [geometry=\"WxH\"] [fullscreen=#true] [grab=#true]             │ │",
                "│○│[wm=\"<program>\"]                                                          │ │",
                "│○│Enter writes it, Esc leaves it alone                                      │ │",
                "│○└──────────────────────────────────────────────────────────────────────────┘ │",
                "│○ !! gamepad                      ││Bare, bubbler starts a rootful Xwayland   │",
                "│○ !  hidraw                       ││inside the sandbox as a client of the     │",
                "└──────────────────────────────────┘└──────────────────────────────────────────┘",
                "Space grant/disable  Enter write  Del remove  s save  u undo  ? more  Esc back",
            ]
        );
        // The cursor sits at the end of what is written, inside the field.
        assert_eq!(
            cursor(&app, Rect::new(0, 0, 80, 14)),
            Some(Position { x: 13, y: 4 })
        );
    }

    /// A quoted token holds spaces of its own, and the wrap breaks
    /// between tokens only: half a path is the grammar of nothing. A
    /// token wider than the row still takes a row of its own.
    #[test]
    fn wrapping_a_grammar_never_breaks_a_quoted_token() {
        let grammar = bubbler_core::catalogue::grant("home-share")
            .expect("the catalogue holds home-share")
            .grammar;
        assert_eq!(
            wrapped(grammar, 24),
            ["home-share", "\"<path under $HOME>\"", "[mode=ro|rw]"]
        );
        assert_eq!(wrapped(grammar, 8), wrapped(grammar, 24));
        assert_eq!(wrapped("", 40), [""]);
    }

    /// The rows the open dialog holds, without the border it stands in.
    /// What is behind it draws the same grammar, so only what the prompt
    /// itself puts on the screen says whether the prompt clipped it.
    fn dialog_rows(app: &App, width: u16, height: u16) -> Vec<String> {
        let dialog = app.dialog.as_ref().expect("a dialog is open");
        let inner = dialog_area(dialog, Rect::new(0, 0, width, height))
            .inner(ratatui::layout::Margin::new(1, 1));
        screen(app, width, height)
            .into_iter()
            .skip(usize::from(inner.y))
            .take(usize::from(inner.height))
            .map(|line| {
                line.chars()
                    .skip(usize::from(inner.x))
                    .take(usize::from(inner.width))
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect()
    }

    /// The prompt for `node`, open over the detail screen.
    fn prompt_for(node: &str) -> (tempfile::TempDir, App) {
        let (tmp, mut app) = list_editor();
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let detail = app.detail.as_mut().expect("the detail screen is open");
        detail.selected = detail
            .rows
            .iter()
            .position(|row| row.node == node)
            .expect("the catalogue holds the node");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        (tmp, app)
    }

    /// The two grammars that outgrew 80 columns. Every token of them
    /// stands whole in the prompt, `[wm="<program>"]` and `disable }`
    /// included: a grammar cut mid-token is the grammar of nothing.
    const LONG_GRAMMARS: [(&str, &[&str]); 2] = [
        (
            "x11",
            &[
                "x11",
                "[\"host\"]",
                "[geometry=\"WxH\"]",
                "[fullscreen=#true]",
                "[grab=#true]",
                "[wm=\"<program>\"]",
            ],
        ),
        (
            "seccomp",
            &[
                "seccomp",
                "{",
                "allow",
                "\"<syscall>\";",
                "deny",
                "\"<syscall>\"",
                "[errno=\"EPERM\"|\"ENOSYS\"];",
                "disable",
                "}",
            ],
        ),
    ];

    #[test]
    fn a_prompt_wraps_a_long_grammar_rather_than_cutting_a_token_in_two() {
        for (node, tokens) in LONG_GRAMMARS {
            let (_tmp, app) = prompt_for(node);
            let rows = dialog_rows(&app, 80, 24).join("\n");
            for token in tokens {
                assert!(
                    rows.contains(token),
                    "{node}: `{token}` is cut off in\n{rows}"
                );
            }
        }
    }

    /// The same prompt on a terminal too narrow for the grammar twice
    /// over: it wraps into more rows, and the narrowest ones it cannot
    /// hold at all still draw rather than panic.
    #[test]
    fn a_prompt_wraps_on_a_narrow_terminal_as_well() {
        for (node, tokens) in LONG_GRAMMARS {
            let (_tmp, app) = prompt_for(node);
            let rows = dialog_rows(&app, 40, 16).join("\n");
            for token in tokens {
                assert!(
                    rows.contains(token),
                    "{node}: `{token}` is cut off in\n{rows}"
                );
            }
            for (width, height) in [(40u16, 8u16), (24, 12), (20, 6)] {
                let drawn = screen(&app, width, height);
                assert_eq!(drawn.len(), usize::from(height));
                assert!(cursor(&app, Rect::new(0, 0, width, height)).is_some());
            }
        }
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
                "│Space  grant / disable (keeps the line) / enable  Enter  write the node as KDL                    │",
                "│Delete remove the entry (Backspace too)           e      $EDITOR on config.kdl                    │",
                "│s      save                                       u      undo                                     │",
                "│l      lint                                       X      explain                                  │",
                "│Esc    back                                                                                       │",
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
