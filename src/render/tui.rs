use crate::config::Config;
use crate::error::{ExitCode, PlensError, Result};
use crate::model::ScanSummary;
use crate::store::{get_scan, list_history, open_db, HistoryItem};
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::stdout;
use std::time::Duration;

pub struct TuiApp {
    pub history: Vec<HistoryItem>,
    pub selected_index: usize,
    pub list_state: ListState,
    pub selected_scan: Option<ScanSummary>,
    pub filter_query: String,
    pub is_filtering: bool,
    pub show_help: bool,
    pub active_tab: usize, // 0 = Ports, 1 = Findings & Fixes
}

impl TuiApp {
    pub fn new(history: Vec<HistoryItem>) -> Self {
        let mut list_state = ListState::default();
        if !history.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            history,
            selected_index: 0,
            list_state,
            selected_scan: None,
            filter_query: String::new(),
            is_filtering: false,
            show_help: false,
            active_tab: 0,
        }
    }

    pub fn filtered_history(&self) -> Vec<&HistoryItem> {
        if self.filter_query.is_empty() {
            self.history.iter().collect()
        } else {
            let q = self.filter_query.to_lowercase();
            self.history
                .iter()
                .filter(|h| h.targets.to_lowercase().contains(&q) || h.id.to_lowercase().contains(&q))
                .collect()
        }
    }

    pub fn select_next(&mut self) {
        let count = self.filtered_history().len();
        if count > 0 {
            self.selected_index = (self.selected_index + 1) % count;
            self.list_state.select(Some(self.selected_index));
        }
    }

    pub fn select_prev(&mut self) {
        let count = self.filtered_history().len();
        if count > 0 {
            if self.selected_index == 0 {
                self.selected_index = count - 1;
            } else {
                self.selected_index -= 1;
            }
            self.list_state.select(Some(self.selected_index));
        }
    }

    pub fn load_selected_scan(&mut self, config: &Config) {
        let filtered = self.filtered_history();
        if let Some(item) = filtered.get(self.selected_index) {
            if let Ok(conn) = open_db(&Config::db_path()) {
                if let Ok(Some(scan)) = get_scan(&conn, &item.id) {
                    self.selected_scan = Some(scan);
                }
            }
        }
        let _ = config;
    }
}

pub async fn run_tui(config: &Config) -> Result<ExitCode> {
    let conn = open_db(&Config::db_path())?;
    let history = list_history(&conn, None, None, false, 100)?;

    let mut app = TuiApp::new(history);
    app.load_selected_scan(config);

    // Setup terminal
    enable_raw_mode().map_err(|e| PlensError::Other(e.to_string()))?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture).map_err(|e| PlensError::Other(e.to_string()))?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend).map_err(|e| PlensError::Other(e.to_string()))?;

    let res = run_app_loop(&mut terminal, &mut app, config).await;

    // Restore terminal
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture);
    let _ = terminal.show_cursor();

    res
}

async fn run_app_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
    config: &Config,
) -> Result<ExitCode> {
    loop {
        terminal
            .draw(|f| draw_ui(f, app))
            .map_err(|e| PlensError::Other(e.to_string()))?;

        if event::poll(Duration::from_millis(50)).map_err(|e| PlensError::Other(e.to_string()))? {
            if let Event::Key(key) = event::read().map_err(|e| PlensError::Other(e.to_string()))? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if app.is_filtering {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            app.is_filtering = false;
                            app.selected_index = 0;
                            app.list_state.select(Some(0));
                            app.load_selected_scan(config);
                        }
                        KeyCode::Backspace => {
                            app.filter_query.pop();
                        }
                        KeyCode::Char(c) => {
                            app.filter_query.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => return Ok(ExitCode::Ok),
                    KeyCode::Char('?') => app.show_help = !app.show_help,
                    KeyCode::Esc => {
                        if app.show_help {
                            app.show_help = false;
                        } else if !app.filter_query.is_empty() {
                            app.filter_query.clear();
                        }
                    }
                    KeyCode::Char('/') => {
                        app.is_filtering = true;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        app.select_next();
                        app.load_selected_scan(config);
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        app.select_prev();
                        app.load_selected_scan(config);
                    }
                    KeyCode::Tab => {
                        app.active_tab = (app.active_tab + 1) % 2;
                    }
                    KeyCode::Enter => {
                        app.load_selected_scan(config);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &mut TuiApp) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Footer / filter
        ])
        .split(size);

    // 1. Header
    let title = Line::from(vec![
        Span::styled(" PortLens ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("Exposure Auditor | "),
        Span::styled("[Tab] Switch View | [/] Filter | [?] Help | [q] Quit", Style::default().fg(Color::DarkGray)),
    ]);
    let header_block = Paragraph::new(title)
        .block(Block::default().borders(Borders::ALL).title("Status"))
        .style(Style::default());
    f.render_widget(header_block, chunks[0]);

    // 2. Main content split into Left (Scans) and Right (Details)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(chunks[1]);

    // Left: Scans List
    let items: Vec<ListItem> = app
        .filtered_history()
        .iter()
        .map(|item| {
            let grade_color = match item.risk_grade.as_str() {
                "A" | "B" => Color::Green,
                "C" => Color::Yellow,
                _ => Color::Red,
            };
            let text = format!(
                "[{}] {} (Grade {})",
                &item.id[..8.min(item.id.len())],
                item.targets,
                item.risk_grade
            );
            ListItem::new(text).style(Style::default().fg(grade_color))
        })
        .collect();

    let list_title = format!(" Scans ({}) ", items.len());
    let list_widget = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(list_title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list_widget, body_chunks[0], &mut app.list_state);

    // Right: Scan Details
    if let Some(ref scan) = app.selected_scan {
        if app.active_tab == 0 {
            // Tab 0: Ports & Exposure Table
            let mut port_lines = Vec::new();
            port_lines.push(Line::from(vec![
                Span::styled(format!("Target: {} ", scan.targets.join(", ")), Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(format!("Risk: {}/100 (Grade {})", scan.risk_score.score, scan.risk_score.grade), Style::default().fg(Color::Yellow)),
            ]));
            port_lines.push(Line::from(""));
            port_lines.push(Line::from(Span::styled(
                format!("{:<12} {:<8} {:<15} {:<15} {}", "PORT", "STATE", "SERVICE", "VERSION", "VERDICT"),
                Style::default().add_modifier(Modifier::UNDERLINED),
            )));

            for h in &scan.hosts {
                for p in &h.ports {
                    let srv = p.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
                    let ver = p.service.as_ref().and_then(|s| s.version.as_deref()).unwrap_or("-");
                    let v = p.verdict.map(|v| v.to_string()).unwrap_or_else(|| "-".into());

                    let v_color = match v.as_str() {
                        "EXPOSED" => Color::Red,
                        "LOCAL_ONLY" => Color::Green,
                        "FILTERED" => Color::Yellow,
                        _ => Color::White,
                    };

                    port_lines.push(Line::from(vec![
                        Span::raw(format!("{:<12} {:<8} {:<15} {:<15} ", format!("{}/{}", p.number, p.protocol), p.state, srv, ver)),
                        Span::styled(v, Style::default().fg(v_color)),
                    ]));
                }
            }

            let details_block = Paragraph::new(port_lines)
                .block(Block::default().borders(Borders::ALL).title(" Exposed Ports (Tab: Ports) "))
                .wrap(Wrap { trim: true });
            f.render_widget(details_block, body_chunks[1]);
        } else {
            // Tab 1: Findings & Fixes
            let mut finding_lines = Vec::new();
            if scan.findings.is_empty() {
                finding_lines.push(Line::from(Span::styled("✓ No active security exposure findings detected.", Style::default().fg(Color::Green))));
            } else {
                for f in &scan.findings {
                    let sev_color = match f.severity {
                        crate::model::Severity::Critical => Color::Red,
                        crate::model::Severity::High => Color::LightRed,
                        crate::model::Severity::Medium => Color::Yellow,
                        _ => Color::Cyan,
                    };

                    finding_lines.push(Line::from(vec![
                        Span::styled(format!("[{}] ", f.severity), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                        Span::styled(&f.message, Style::default().add_modifier(Modifier::BOLD)),
                    ]));
                    finding_lines.push(Line::from(format!("  Why: {}", f.why)));
                    if let Some(ref fix) = f.fix {
                        if let Some(ref u) = fix.ufw {
                            finding_lines.push(Line::from(Span::styled(format!("  Fix (UFW): {u}"), Style::default().fg(Color::Green))));
                        }
                        if let Some(ref c) = fix.config {
                            finding_lines.push(Line::from(Span::styled(format!("  Fix (Config): {c}"), Style::default().fg(Color::Cyan))));
                        }
                    }
                    finding_lines.push(Line::from(""));
                }
            }

            let findings_block = Paragraph::new(finding_lines)
                .block(Block::default().borders(Borders::ALL).title(" Security Findings & Fixes (Tab: Findings) "))
                .wrap(Wrap { trim: true });
            f.render_widget(findings_block, body_chunks[1]);
        }
    } else {
        let empty = Paragraph::new("Select a scan from history to inspect details.")
            .block(Block::default().borders(Borders::ALL).title(" Details "));
        f.render_widget(empty, body_chunks[1]);
    }

    // 3. Footer
    let footer_text = if app.is_filtering {
        format!("Search filter: {}_ (Press Enter or Esc to confirm)", app.filter_query)
    } else if !app.filter_query.is_empty() {
        format!("Active filter: '{}' (Press Esc to clear)", app.filter_query)
    } else {
        "Ready. Use [j/k] to navigate, [Tab] to toggle view, [/] to filter, [q] to exit.".to_string()
    };
    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(footer, chunks[2]);

    // Help Modal
    if app.show_help {
        let area = centered_rect(60, 45, size);
        f.render_widget(Clear, area);

        let help_text = vec![
            Line::from(Span::styled("PortLens TUI Navigation Help", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("  j / Down Arrow  : Next scan in history"),
            Line::from("  k / Up Arrow    : Previous scan in history"),
            Line::from("  Tab             : Toggle Ports vs Findings tabs"),
            Line::from("  /               : Enter search / filter mode"),
            Line::from("  Esc             : Clear filter / close help modal"),
            Line::from("  ?               : Toggle this help dialog"),
            Line::from("  q               : Quit PortLens UI"),
            Line::from(""),
            Line::from("Press [Esc] or [?] to close."),
        ];

        let help_widget = Paragraph::new(help_text)
            .block(Block::default().borders(Borders::ALL).title(" Help "))
            .alignment(Alignment::Left);
        f.render_widget(help_widget, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
