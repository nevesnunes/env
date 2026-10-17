use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::collections::HashMap;
use std::{
    env,
    error::Error,
    fs::File,
    io::{self, BufRead, BufReader},
};

const STATE_MAX_LINES: u16 = 4;
const DEFAULT_STATUS: &str = "tab: focus | j/k: scroll | q: quit";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Widget {
    STATE = 0,
    FLOW = 1,
    COMMAND = 2,
}

struct ArchX86 {
    ip: &'static str,
    regmap: HashMap<&'static str, u64>,
    regs: [&'static str; 9],
}

impl ArchX86 {
    fn new() -> Self {
        let regs = [
            "EAX", "EBX", "ECX", "EDX", "EBP", "ESP", "ESI", "EDI", "EIP",
        ];

        let regmap = regs
            .iter()
            .enumerate()
            .map(|(i, &reg)| (reg, i as u64))
            .collect();

        Self {
            ip: "EIP",
            regmap,
            regs,
        }
    }
}

struct State {
    arch: ArchX86,
    flow_addresses: Vec<u64>,
    state_updates: HashMap<u64, HashMap<String, String>>,
    memory_reads: HashMap<u64, String>,
    memory_writes: HashMap<u64, String>,
}

impl State {
    fn new() -> Self {
        Self {
            arch: ArchX86::new(),
            flow_addresses: Vec::new(),
            state_updates: HashMap::new(),
            memory_reads: HashMap::new(),
            memory_writes: HashMap::new(),
        }
    }
}

struct App {
    command: String,
    flow_widget_state: ListState,
    focus: Widget,
    selected: usize,
    state_scroll_idx: usize,
    state: State,
    status: String,
}

impl App {
    fn new(state: State) -> Self {
        let selected = 0;
        let mut flow_widget_state = ListState::default();
        flow_widget_state.select(Some(selected));

        Self {
            command: String::new(),
            flow_widget_state,
            focus: Widget::FLOW,
            selected,
            state,
            state_scroll_idx: 0,
            status: DEFAULT_STATUS.into(),
        }
    }

    fn focus_next(&mut self, backwards: bool) {
        let next_focus: u64 = if backwards {
            (self.focus as u64 + 2) % 3
        } else {
            (self.focus as u64 + 1) % 3
        };
        self.focus = match next_focus {
            0 => Some(Widget::STATE),
            1 => Some(Widget::FLOW),
            2 => Some(Widget::COMMAND),
            _ => None,
        }
        .unwrap();
    }

    fn scroll_state(&mut self, down: bool) {
        let total_rows = self.state.arch.regs.len().div_ceil(3);
        let max_scroll = total_rows.saturating_sub(4);

        if down {
            self.state_scroll_idx = (self.state_scroll_idx + 1).min(max_scroll);
        } else {
            self.state_scroll_idx = self.state_scroll_idx.saturating_sub(1);
        }
    }

    fn move_selection(&mut self, down: bool) {
        if self.state.arch.regs.is_empty() {
            self.selected = 0;
            self.flow_widget_state.select(None);
            return;
        }

        if down {
            self.selected = (self.selected + 1).min(self.state.arch.regs.len() - 1);
        } else {
            self.selected = self.selected.saturating_sub(1);
        }

        self.flow_widget_state.select(Some(self.selected));
    }

    fn execute_command(&mut self) {
        self.status = DEFAULT_STATUS.into();
        match self.command.trim() {
            "step" => {
                self.move_selection(true);
            }
            "reverse-step" => {
                self.move_selection(false);
            }
            "" => {}
            _ => {
                self.status = format!("unknown '{}'", self.command.trim());
            }
        }

        self.command.clear();
    }
}

fn init_state(path: &str) -> State {
    let mut state = State::new();

    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line_unwrap = line.unwrap();
        let line = line_unwrap.trim();
        if line.is_empty() {
            continue;
        }

        let mut ip: u64 = 0;
        let pairs: HashMap<String, String> = line
            .split(',')
            .filter_map(|part| {
                let (key, value) = part.split_once('=')?;
                let reg_k_upper = key.to_ascii_uppercase();
                let reg_k = reg_k_upper.trim();
                let reg_v = value.trim().strip_prefix("0x").unwrap();
                if reg_k.eq(state.arch.ip) {
                    ip = u64::from_str_radix(reg_v, 16).unwrap();
                }
                Some((reg_k.to_owned(), reg_v.to_owned()))
            })
            .collect();
        let pairs_regs: HashMap<String, String> = pairs
            .into_iter()
            .filter_map(|pair| {
                if pair.0.to_ascii_uppercase().eq("MR") {
                    state.memory_reads.insert(ip, pair.1.to_owned());
                    None
                } else if pair.0.to_ascii_uppercase().eq("MW") {
                    state.memory_writes.insert(ip, pair.1.to_owned());
                    None
                } else {
                    Some(pair)
                }
            })
            .collect();
        state.flow_addresses.push(ip);
        state.state_updates.insert(ip, pairs_regs.clone());
    }

    state
}

fn styled_block(title: &str, is_focused: bool) -> Block<'_> {
    let styled_title = Span::styled(
        title,
        if is_focused {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        },
    );
    let styled_border = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    Block::default()
        .title(styled_title)
        .borders(Borders::TOP)
        .border_style(styled_border)
}

fn render(frame: &mut Frame, app: &mut App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(STATE_MAX_LINES + 1),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    // Control-Flow widget.
    let items: Vec<ListItem> = app
        .state
        .flow_addresses
        .iter()
        .map(|addr| {
            let mut rw_str = String::new();
            let r = app
                .state
                .memory_reads
                .get(addr)
                .cloned()
                .unwrap_or_default();
            if !r.is_empty() {
                rw_str = format!("r[{}] ", r);
            }
            let w = app
                .state
                .memory_writes
                .get(addr)
                .cloned()
                .unwrap_or_default();
            if !w.is_empty() {
                rw_str = format!("{}w[{}] ", rw_str, w);
            }
            ListItem::new(format!("{:08x} {}", addr, rw_str))
        })
        .collect();

    let highlight_style = if app.focus == Widget::FLOW {
        Style::default()
            .bg(Color::Cyan)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let second_list = List::new(items)
        .block(styled_block("[ Control-Flow ]", app.focus == Widget::FLOW))
        .highlight_style(highlight_style)
        .highlight_symbol("> ");

    frame.render_stateful_widget(second_list, areas[1], &mut app.flow_widget_state);

    // State widget.
    let first_block = styled_block("[ State ]", app.focus == Widget::STATE);
    let first_inner = first_block.inner(areas[0]);
    frame.render_widget(first_block, areas[0]);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(20),
        ])
        .split(first_inner);

    let empty_updates = HashMap::new();
    let curr_addr = app
        .state
        .flow_addresses
        .get(app.flow_widget_state.selected().unwrap())
        .unwrap();
    let curr_updates = app
        .state
        .state_updates
        .get(curr_addr)
        .unwrap_or(&empty_updates);
    for col in 0..3 {
        let lines: Vec<Line> = (0..STATE_MAX_LINES as usize)
            .map(|row| {
                let index = (app.state_scroll_idx + row) * 3 + col;
                let reg = app.state.arch.regs.get(index).cloned().unwrap_or_default();
                if reg.is_empty() {
                    Line::from("")
                } else {
                    let val = curr_updates.get(reg).map_or("0", |v| v.as_str());
                    Line::from(format!("{} {:0>8}", reg, val))
                }
            })
            .collect();

        let paragraph = Paragraph::new(lines).block(Block::default());
        frame.render_widget(paragraph, columns[col]);
    }

    // Command bar widget.
    let status = format!("[ Command ({}) ]", app.status);
    let styled_input = Span::styled(
        format!("> {}", app.command),
        if app.focus == Widget::COMMAND {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        },
    );
    let input = Paragraph::new(styled_input)
        .block(styled_block(status.as_str(), app.focus == Widget::COMMAND));
    frame.render_widget(input, areas[2]);

    if app.focus == Widget::COMMAND {
        let x = areas[2]
            .x
            .saturating_add(2)
            .saturating_add(app.command.chars().count() as u16)
            .min(areas[2].right().saturating_sub(2));

        let y = areas[2].y.saturating_add(1);
        frame.set_cursor_position((x, y));
    }
}

fn run_app(
    terminal: &mut Terminal<impl ratatui::backend::Backend>,
    mut app: App,
) -> Result<(), Box<dyn Error>> {
    loop {
        terminal.draw(|frame| render(frame, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                KeyCode::Tab => {
                    app.focus_next(false);
                    continue;
                }
                KeyCode::BackTab => {
                    app.focus_next(true);
                    continue;
                }
                KeyCode::Esc => break,
                _ => {}
            }

            if app.focus == Widget::COMMAND {
                match key.code {
                    KeyCode::Enter => app.execute_command(),
                    KeyCode::Backspace => {
                        app.command.pop();
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        break;
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.command.push(c);
                    }
                    _ => {}
                }

                continue;
            }

            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('j') | KeyCode::Down => match app.focus {
                    Widget::STATE => app.scroll_state(true),
                    Widget::FLOW => app.move_selection(true),
                    _ => {}
                },
                KeyCode::Char('k') | KeyCode::Up => match app.focus {
                    Widget::STATE => app.scroll_state(false),
                    Widget::FLOW => app.move_selection(false),
                    _ => {}
                },
                _ => {}
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(format!(
            "Usage: {} <trace.log>",
            args.first().map(String::as_str).unwrap_or("trace-viewer")
        )
        .into());
    }
    let state = init_state(&args[1]);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error.into());
    }
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, App::new(state));
    let restore_result = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let cursor_result = terminal.show_cursor();
    let raw_result = disable_raw_mode();

    result?;
    restore_result?;
    cursor_result?;
    raw_result?;

    Ok(())
}
