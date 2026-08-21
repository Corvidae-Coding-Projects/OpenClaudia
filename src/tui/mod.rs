//! TUI module for `OpenClaudia`
//!
//! Provides a rich terminal user interface similar to Claude Code,
//! with two-column layout, tips panel, styled text, markdown rendering,
//! status bar, and theme management.
//!
//! The interactive full-screen TUI is in the `app` submodule and is the
//! default when no subcommand, `--print`, or `--tui-mode` is supplied.

pub mod app;
pub mod components;
pub mod events;
pub mod input;
pub mod messages;

use crossterm::{
    cursor,
    style::{Attribute, Color as CtColor, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::{self, stdout, Write};
use std::path::PathBuf;

/// Maximum accumulated fenced-code source reparsed for contextual highlighting.
///
/// Arborium parses a complete source unit rather than carrying lexical state one
/// line at a time. Keeping a byte- and line-bounded prefix preserves multiline
/// constructs for ordinary code blocks without allowing streaming output to
/// create unbounded quadratic parse work. Content beyond either bound is still
/// rendered through the existing flat-color fallback; it is never dropped.
const MAX_HIGHLIGHT_SOURCE_BYTES: usize = 64 * 1024;
const MAX_HIGHLIGHT_SOURCE_LINES: usize = 1024;

/// Per-code-block syntax highlighter backed by maintained tree-sitter grammars.
///
/// Unsupported language tags are represented by `None` at the call site and
/// retain the existing flat-color fallback instead of failing rendering.
struct CodeHighlighter {
    language: String,
    engine: arborium::AnsiHighlighter,
    source: String,
    line_count: usize,
    disabled: bool,
}

impl CodeHighlighter {
    fn new(language: &str) -> Option<Self> {
        if language.is_empty() {
            return None;
        }
        let mut engine =
            arborium::AnsiHighlighter::new(arborium::theme::builtin::catppuccin_mocha());
        engine.store().get(language)?;
        // The surrounding renderer owns terminal wrapping and indentation.
        // Arborium's terminal-width auto-detection would otherwise wrap a line
        // a second time and make output depend on whether stdout is a TTY.
        engine.options_mut().width = None;
        engine.options_mut().pad_to_width = false;
        Some(Self {
            language: language.to_string(),
            engine,
            source: String::new(),
            line_count: 0,
            disabled: false,
        })
    }

    fn highlight_line(&mut self, line: &str) -> Option<String> {
        if self.disabled {
            return None;
        }
        if self.line_count >= MAX_HIGHLIGHT_SOURCE_LINES {
            self.source.clear();
            self.disabled = true;
            return None;
        }
        let separator_bytes = usize::from(!self.source.is_empty());
        let next_size = self
            .source
            .len()
            .checked_add(separator_bytes)?
            .checked_add(line.len())?;
        if next_size > MAX_HIGHLIGHT_SOURCE_BYTES {
            self.source.clear();
            self.disabled = true;
            return None;
        }
        if separator_bytes == 1 {
            self.source.push('\n');
        }
        self.source.push_str(line);
        self.line_count += 1;
        let highlighted = self.engine.highlight(&self.language, &self.source).ok()?;
        Some(last_ansi_line(&highlighted))
    }
}

/// Extract the final rendered line while preserving any SGR style that began
/// before its newline (for example a multiline comment or string span).
fn last_ansi_line(rendered: &str) -> String {
    let Some(newline) = rendered.rfind('\n') else {
        return rendered.to_string();
    };
    let prefix = &rendered[..newline];
    let tail = &rendered[newline + 1..];
    let Some(active_style) = active_ansi_style(prefix) else {
        return tail.to_string();
    };
    let mut line = String::with_capacity(active_style.len() + tail.len());
    line.push_str(active_style);
    line.push_str(tail);
    line
}

fn active_ansi_style(rendered: &str) -> Option<&str> {
    let mut active = None;
    let mut offset = 0;
    while let Some(relative_start) = rendered[offset..].find("\u{1b}[") {
        let start = offset + relative_start;
        let sequence = &rendered[start..];
        let Some(relative_end) = sequence.find('m') else {
            break;
        };
        let end = start + relative_end + 1;
        let escape = &rendered[start..end];
        if escape == "\u{1b}[0m" || escape == "\u{1b}[m" {
            active = None;
        } else {
            active = Some(escape);
        }
        offset = end;
    }
    active
}

// ─── Brand palette ──────────────────────────────────────────────────────────
//
// Single source of truth for the TUI's RGB brand colors (crosslink #442).
// Submodules (`app`, `messages`) import these instead of re-typing
// `Color::Rgb(…)` literals at every call site — that's how the palette
// drifted in the first place.

/// Purple color for branding (from logo).
pub(crate) const PURPLE: Color = Color::Rgb(147, 112, 219);
/// Gold color for accents (from logo).
pub(crate) const GOLD: Color = Color::Rgb(218, 165, 32);
/// Dim gray for borders and secondary chrome.
pub(crate) const DIM: Color = Color::Rgb(128, 128, 128);
/// Cool blue used for the user role header.
pub(crate) const USER_BLUE: Color = Color::Rgb(100, 180, 255);

/// Braille-dot spinner frames used by the input area while a turn is in flight.
///
/// Lives in `mod.rs` (not `app.rs`) so the brand chrome is colocated with the
/// brand palette (crosslink #442).
pub(crate) const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// ─── Theme support ──────────────────────────────────────────────────────────

/// A color theme for the terminal UI
#[derive(Debug, Clone)]
pub struct Theme {
    /// Theme identifier
    pub name: String,
    /// Primary color (headings, status bar highlights)
    pub primary: CtColor,
    /// Secondary color (accents)
    pub secondary: CtColor,
    /// Code block / inline code color
    pub code_color: CtColor,
    /// Heading color
    pub heading_color: CtColor,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            primary: CtColor::Rgb {
                r: 147,
                g: 112,
                b: 219,
            },
            secondary: CtColor::Rgb {
                r: 218,
                g: 165,
                b: 32,
            },
            code_color: CtColor::Cyan,
            heading_color: CtColor::Rgb {
                r: 147,
                g: 112,
                b: 219,
            },
        }
    }
}

impl Theme {
    /// Build a theme from one of the built-in names
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::default()),
            "ocean" => Some(Self {
                name: "ocean".to_string(),
                primary: CtColor::Rgb {
                    r: 0,
                    g: 150,
                    b: 255,
                },
                secondary: CtColor::Cyan,
                code_color: CtColor::Rgb {
                    r: 0,
                    g: 200,
                    b: 200,
                },
                heading_color: CtColor::Rgb {
                    r: 0,
                    g: 150,
                    b: 255,
                },
            }),
            "forest" => Some(Self {
                name: "forest".to_string(),
                primary: CtColor::Green,
                secondary: CtColor::Rgb {
                    r: 144,
                    g: 238,
                    b: 144,
                },
                code_color: CtColor::Rgb {
                    r: 0,
                    g: 200,
                    b: 100,
                },
                heading_color: CtColor::Green,
            }),
            "sunset" => Some(Self {
                name: "sunset".to_string(),
                primary: CtColor::Rgb {
                    r: 255,
                    g: 140,
                    b: 0,
                },
                secondary: CtColor::Rgb {
                    r: 255,
                    g: 69,
                    b: 0,
                },
                code_color: CtColor::Yellow,
                heading_color: CtColor::Rgb {
                    r: 255,
                    g: 140,
                    b: 0,
                },
            }),
            "mono" => Some(Self {
                name: "mono".to_string(),
                primary: CtColor::White,
                secondary: CtColor::Grey,
                code_color: CtColor::White,
                heading_color: CtColor::White,
            }),
            "neon" => Some(Self {
                name: "neon".to_string(),
                primary: CtColor::Magenta,
                secondary: CtColor::Cyan,
                code_color: CtColor::Rgb {
                    r: 0,
                    g: 255,
                    b: 255,
                },
                heading_color: CtColor::Magenta,
            }),
            _ => None,
        }
    }

    /// Save the current theme name to disk (in user config directory)
    ///
    /// # Errors
    ///
    /// Returns an error if the theme file cannot be written.
    pub fn save(&self) -> io::Result<()> {
        let path = theme_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, &self.name)?;
        Ok(())
    }

    /// Load the saved theme from disk, falling back to default
    #[must_use]
    pub fn load() -> Self {
        let path = theme_path();
        if let Ok(name) = std::fs::read_to_string(&path) {
            let name = name.trim();
            if let Some(theme) = Self::from_name(name) {
                return theme;
            }
        }
        Self::default()
    }
}

/// Return a stable path for the theme file, using the user's config directory
/// (e.g. `~/.config/openclaudia/theme` on Linux, `~/Library/Application Support/openclaudia/theme` on macOS).
/// Falls back to `.openclaudia/theme` relative to CWD if the platform config dir is unavailable.
fn theme_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("openclaudia")
        .join("theme")
}

// ─── Markdown rendering ─────────────────────────────────────────────────────

/// Render markdown-formatted text to the terminal with styling.
///
/// Supports:
/// - **bold** and *italic* inline
/// - `inline code` in cyan/code color
/// - ```fenced code blocks``` with language header
/// - # Headings at various levels
/// - - / * / numbered list items
/// - > block quotes
/// - [link text](url)
pub fn render_markdown(text: &str) {
    render_markdown_themed(text, &Theme::load());
}

/// Render markdown with a specific theme
pub fn render_markdown_themed(text: &str, theme: &Theme) {
    let mut stdout = io::stdout();
    let mut in_code_block = false;
    let mut code_lang = String::new();
    let mut highlighter: Option<CodeHighlighter> = None;

    for line in text.lines() {
        if line.starts_with("```") {
            if in_code_block {
                // End code block
                in_code_block = false;
                code_lang.clear();
                highlighter = None;
                let _ = stdout.execute(ResetColor);
                println!();
            } else {
                // Start code block
                in_code_block = true;
                code_lang = line.trim_start_matches('`').trim().to_string();

                highlighter = CodeHighlighter::new(&code_lang);

                if !code_lang.is_empty() {
                    let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
                    println!("  --- {code_lang} ---");
                    let _ = stdout.execute(ResetColor);
                }
            }
            continue;
        }

        if in_code_block {
            if let Some(ref mut hl) = highlighter {
                render_highlighted_code_line(&mut stdout, line, hl, theme.code_color);
            } else {
                // Fallback: render with flat code color (same as before)
                let _ = stdout.execute(SetForegroundColor(theme.code_color));
                println!("    {line}");
                let _ = stdout.execute(ResetColor);
            }
            continue;
        }

        // Heading detection
        if line.starts_with('#') {
            render_heading(&mut stdout, line, theme);
            continue;
        }

        // Blockquote
        if line.starts_with("> ") || line == ">" {
            let content = line.strip_prefix("> ").unwrap_or("");
            let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
            print!("  | ");
            let _ = stdout.execute(SetForegroundColor(CtColor::White));
            render_inline(&mut stdout, content, theme);
            println!();
            let _ = stdout.execute(ResetColor);
            continue;
        }

        // List items (unordered: -, *, and ordered: 1., 2., etc.)
        let trimmed = line.trim_start();
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            let indent = line.len() - trimmed.len();
            let content = &trimmed[2..];
            print!("{}  \u{2022} ", " ".repeat(indent));
            render_inline(&mut stdout, content, theme);
            println!();
            continue;
        }
        if let Some(rest) = strip_ordered_list_prefix(trimmed) {
            let indent = line.len() - trimmed.len();
            let num_part = &trimmed[..trimmed.len() - rest.len()];
            print!("{}  {}", " ".repeat(indent), num_part);
            render_inline(&mut stdout, rest, theme);
            println!();
            continue;
        }

        // Horizontal rule
        if line.trim() == "---" || line.trim() == "***" || line.trim() == "___" {
            let (cols, _) = terminal::size().unwrap_or((80, 24));
            let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
            println!("{}", "\u{2500}".repeat(cols as usize));
            let _ = stdout.execute(ResetColor);
            continue;
        }

        // Regular line with inline formatting
        render_inline(&mut stdout, line, theme);
        println!();
    }
    let _ = stdout.execute(ResetColor);
    stdout.flush().ok();
}

/// Render a single code line with tree-sitter syntax highlighting.
///
/// Falls back to the theme's `code_color` if highlighting fails.
fn render_highlighted_code_line(
    stdout: &mut io::Stdout,
    line: &str,
    highlighter: &mut CodeHighlighter,
    fallback_color: CtColor,
) {
    if let Some(highlighted) = highlighter.highlight_line(line) {
        let _ = stdout.execute(Print("    "));
        let _ = stdout.execute(Print(highlighted));
        let _ = stdout.execute(ResetColor);
        let _ = stdout.execute(Print("\n"));
    } else {
        let _ = stdout.execute(SetForegroundColor(fallback_color));
        let _ = stdout.execute(Print(format!("    {line}\n")));
        let _ = stdout.execute(ResetColor);
    }
}

/// Render a heading line
fn render_heading(stdout: &mut io::Stdout, line: &str, theme: &Theme) {
    let level = line.chars().take_while(|c| *c == '#').count();
    let text = line[level..].trim_start();

    let _ = stdout.execute(SetAttribute(Attribute::Bold));
    if level <= 2 {
        let _ = stdout.execute(SetForegroundColor(theme.heading_color));
    }

    match level {
        1 => println!("\n{}\n", text.to_uppercase()),
        2 => println!("\n{text}\n"),
        _ => println!("{text}"),
    }

    let _ = stdout.execute(SetAttribute(Attribute::Reset));
    let _ = stdout.execute(ResetColor);
}

/// Render inline formatting: bold, italic, inline code, links
fn render_inline(stdout: &mut io::Stdout, text: &str, theme: &Theme) {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Bold: **text**
        if i + 1 < len && chars[i] == '*' && chars[i + 1] == '*' {
            if let Some(end) = find_closing(&chars, i + 2, "**") {
                let _ = stdout.execute(SetAttribute(Attribute::Bold));
                let inner: String = chars[i + 2..end].iter().collect();
                print!("{inner}");
                let _ = stdout.execute(SetAttribute(Attribute::NoBold));
                i = end + 2;
                continue;
            }
        }

        // Italic: *text* (but not **)
        if chars[i] == '*' && (i + 1 >= len || chars[i + 1] != '*') {
            if let Some(end) = find_closing_char(&chars, i + 1, '*') {
                let _ = stdout.execute(SetAttribute(Attribute::Italic));
                let inner: String = chars[i + 1..end].iter().collect();
                print!("{inner}");
                let _ = stdout.execute(SetAttribute(Attribute::NoItalic));
                i = end + 1;
                continue;
            }
        }

        // Inline code: `text`
        if chars[i] == '`' {
            if let Some(end) = find_closing_char(&chars, i + 1, '`') {
                let _ = stdout.execute(SetForegroundColor(theme.code_color));
                let inner: String = chars[i + 1..end].iter().collect();
                print!("{inner}");
                let _ = stdout.execute(ResetColor);
                i = end + 1;
                continue;
            }
        }

        // Link: [text](url)
        if chars[i] == '[' {
            if let Some((link_text, url, end_pos)) = parse_link(&chars, i) {
                let _ = stdout.execute(SetAttribute(Attribute::Underlined));
                print!("{link_text}");
                let _ = stdout.execute(SetAttribute(Attribute::NoUnderline));
                let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
                print!(" ({url})");
                let _ = stdout.execute(ResetColor);
                i = end_pos;
                continue;
            }
        }

        // Regular character
        print!("{}", chars[i]);
        i += 1;
    }
}

/// Find closing delimiter in char slice (e.g., "**")
fn find_closing(chars: &[char], start: usize, delim: &str) -> Option<usize> {
    let delim_chars: Vec<char> = delim.chars().collect();
    let dlen = delim_chars.len();
    if dlen == 0 {
        return None;
    }
    let mut i = start;
    while i + dlen <= chars.len() {
        if chars[i..i + dlen] == delim_chars[..] {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Find closing single character delimiter
fn find_closing_char(chars: &[char], start: usize, delim: char) -> Option<usize> {
    (start..chars.len()).find(|&i| chars[i] == delim)
}

/// Parse a markdown link [text](url) starting at position i ('[')
fn parse_link(chars: &[char], start: usize) -> Option<(String, String, usize)> {
    // Find closing ']'
    let text_end = find_closing_char(chars, start + 1, ']')?;
    let link_text: String = chars[start + 1..text_end].iter().collect();

    // Expect '(' immediately after ']'
    let paren_start = text_end + 1;
    if paren_start >= chars.len() || chars[paren_start] != '(' {
        return None;
    }

    let url_end = find_closing_char(chars, paren_start + 1, ')')?;
    let url: String = chars[paren_start + 1..url_end].iter().collect();

    Some((link_text, url, url_end + 1))
}

/// Strip an ordered list prefix like "1. ", "12. " and return the remainder
fn strip_ordered_list_prefix(s: &str) -> Option<&str> {
    let mut chars = s.chars();
    // Must start with a digit
    let first = chars.next()?;
    if !first.is_ascii_digit() {
        return None;
    }
    // Consume remaining digits
    let mut dot_pos = 1;
    for ch in chars {
        if ch.is_ascii_digit() {
            dot_pos += 1;
        } else if ch == '.' {
            dot_pos += 1;
            break;
        } else {
            return None;
        }
    }
    // Must have ". " after digits
    if dot_pos < s.len() && s.as_bytes().get(dot_pos) == Some(&b' ') {
        return Some(&s[dot_pos + 1..]);
    }
    None
}

// ─── Status bar ─────────────────────────────────────────────────────────────

/// Draw an inline status line after a response.
///
/// Shows: model name, token count, cost, mode, session duration.
/// Uses `·` separator matching Claude Code's byline style.
pub fn draw_status_bar(model: &str, tokens: usize, cost: Option<f64>, mode: &str, duration: &str) {
    let mut stdout = io::stdout();

    let cost_str = match cost {
        Some(c) if c >= 0.01 => format!("${c:.2}"),
        Some(c) => format!("${c:.4}"),
        None => String::new(),
    };

    #[allow(clippy::cast_precision_loss)] // token counts fit comfortably in f64
    let token_str = if tokens >= 1_000_000 {
        format!("{:.1}M", tokens as f64 / 1_000_000.0)
    } else if tokens >= 1_000 {
        format!("{:.1}k", tokens as f64 / 1_000.0)
    } else {
        format!("{tokens}")
    };

    // Build parts with · separator (Claude Code style)
    let sep = " \u{00B7} ";
    let mut parts = vec![model.to_string()];
    if !cost_str.is_empty() {
        parts.push(cost_str);
    }
    parts.push(format!("In: {token_str}"));
    parts.push(mode.to_string());
    parts.push(duration.to_string());

    let status = parts.join(sep);

    // Print inline with dim styling
    let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
    let _ = stdout.execute(Print(format!("  {status}\n")));
    let _ = stdout.execute(ResetColor);
    stdout.flush().ok();
}

// ─── Streaming markdown renderer ────────────────────────────────────────────

/// A streaming markdown renderer that buffers incoming text tokens.
///
/// Renders completed lines with markdown formatting (headings, bold, italic,
/// code blocks, lists, links, inline code). Incomplete trailing lines are held
/// in a buffer until a newline arrives or `flush()` is called at stream end.
pub struct StreamingMarkdownRenderer {
    /// Buffered text that hasn't been rendered yet (no trailing newline)
    line_buffer: String,
    /// Whether we're inside a fenced code block
    in_code_block: bool,
    /// Language for the current code block (for syntax highlighting)
    code_lang: String,
    /// Syntax highlighter for the current code block
    highlighter: Option<CodeHighlighter>,
    /// The theme to use for rendering
    theme: Theme,
}

/// The dependency-independent subset of [`StreamingMarkdownRenderer`] state.
///
/// The parser cache is intentionally disposable: callers can persist or move
/// this state without binding session state to a third-party grammar engine,
/// then reconstruct highlighting from the fenced language tag.
pub struct MarkdownRenderState {
    line_buffer: String,
    in_code_block: bool,
    code_lang: String,
    theme: Theme,
}

impl StreamingMarkdownRenderer {
    /// Create a new streaming renderer with the loaded theme
    #[must_use]
    pub fn new() -> Self {
        Self {
            line_buffer: String::new(),
            in_code_block: false,
            code_lang: String::new(),
            highlighter: None,
            theme: Theme::load(),
        }
    }

    /// Extract the `Send`-able render state, consuming `self`.
    ///
    /// The parser cache is discarded; it will be reconstructed from `code_lang`
    /// when the renderer is restored via
    /// [`StreamingMarkdownRenderer::from_state`].
    #[must_use]
    pub fn into_state(self) -> MarkdownRenderState {
        MarkdownRenderState {
            line_buffer: self.line_buffer,
            in_code_block: self.in_code_block,
            code_lang: self.code_lang,
            theme: self.theme,
        }
    }

    /// Reconstruct a renderer from previously saved state.
    ///
    /// If the state records an active code block, the syntax highlighter is
    /// rebuilt from the language token so highlighting resumes correctly.
    #[must_use]
    pub fn from_state(state: MarkdownRenderState) -> Self {
        let highlighter = if state.in_code_block {
            CodeHighlighter::new(&state.code_lang)
        } else {
            None
        };
        Self {
            line_buffer: state.line_buffer,
            in_code_block: state.in_code_block,
            code_lang: state.code_lang,
            highlighter,
            theme: state.theme,
        }
    }

    /// Feed a text chunk into the renderer. Complete lines are rendered
    /// immediately; the trailing incomplete line stays buffered.
    pub fn push(&mut self, text: &str) {
        self.line_buffer.push_str(text);

        // Render all complete lines
        while let Some(newline_pos) = self.line_buffer.find('\n') {
            let line = self.line_buffer[..newline_pos].to_string();
            self.line_buffer = self.line_buffer[newline_pos + 1..].to_string();
            self.render_line(&line);
            println!();
        }

        // Flush stdout after each push so partial output appears immediately
        io::stdout().flush().ok();
    }

    /// Flush any remaining buffered text at stream end
    pub fn flush(&mut self) {
        if !self.line_buffer.is_empty() {
            let line = std::mem::take(&mut self.line_buffer);
            self.render_line(&line);
            io::stdout().flush().ok();
        }
    }

    /// Render a single complete line with markdown formatting
    /// Render one line of code-block content, applying syntax highlighting when available.
    fn render_code_block_line(&mut self, line: &str) {
        let mut stdout = io::stdout();
        if let Some(ref mut hl) = self.highlighter {
            if let Some(highlighted) = hl.highlight_line(line) {
                let _ = stdout.execute(Print("    "));
                let _ = stdout.execute(Print(highlighted));
            } else {
                let _ = stdout.execute(SetForegroundColor(self.theme.code_color));
                print!("    {line}");
            }
        } else {
            let _ = stdout.execute(SetForegroundColor(self.theme.code_color));
            print!("    {line}");
        }
        let _ = stdout.execute(ResetColor);
    }

    fn render_line(&mut self, line: &str) {
        let mut stdout = io::stdout();

        // Code fence toggle
        if line.starts_with("```") {
            if self.in_code_block {
                // End code block
                self.in_code_block = false;
                self.code_lang.clear();
                self.highlighter = None;
                let _ = stdout.execute(ResetColor);
            } else {
                // Start code block
                self.in_code_block = true;
                self.code_lang = line.trim_start_matches('`').trim().to_string();

                self.highlighter = CodeHighlighter::new(&self.code_lang);

                if !self.code_lang.is_empty() {
                    let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
                    print!("  --- {} ---", self.code_lang);
                    let _ = stdout.execute(ResetColor);
                }
            }
            return;
        }

        // Inside code block: syntax highlight
        if self.in_code_block {
            self.render_code_block_line(line);
            return;
        }

        // Heading
        if line.starts_with('#') {
            let level = line.chars().take_while(|c| *c == '#').count();
            let text = line[level..].trim_start();
            let _ = stdout.execute(SetAttribute(Attribute::Bold));
            if level <= 2 {
                let _ = stdout.execute(SetForegroundColor(self.theme.heading_color));
            }
            match level {
                1 => print!("{}", text.to_uppercase()),
                _ => print!("{text}"),
            }
            let _ = stdout.execute(SetAttribute(Attribute::Reset));
            let _ = stdout.execute(ResetColor);
            return;
        }

        // Blockquote
        if line.starts_with("> ") || line == ">" {
            let content = line.strip_prefix("> ").unwrap_or("");
            let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
            print!("  | ");
            let _ = stdout.execute(SetForegroundColor(CtColor::White));
            render_inline(&mut stdout, content, &self.theme);
            let _ = stdout.execute(ResetColor);
            return;
        }

        // List items
        let trimmed = line.trim_start();
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            let indent = line.len() - trimmed.len();
            let content = &trimmed[2..];
            print!("{}  \u{2022} ", " ".repeat(indent));
            render_inline(&mut stdout, content, &self.theme);
            return;
        }
        if let Some(rest) = strip_ordered_list_prefix(trimmed) {
            let indent = line.len() - trimmed.len();
            let num_part = &trimmed[..trimmed.len() - rest.len()];
            print!("{}  {}", " ".repeat(indent), num_part);
            render_inline(&mut stdout, rest, &self.theme);
            return;
        }

        // Horizontal rule
        if line.trim() == "---" || line.trim() == "***" || line.trim() == "___" {
            let (cols, _) = terminal::size().unwrap_or((80, 24));
            let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
            print!("{}", "\u{2500}".repeat(cols as usize));
            let _ = stdout.execute(ResetColor);
            return;
        }

        // Regular line with inline formatting
        render_inline(&mut stdout, line, &self.theme);
    }
}

impl Default for StreamingMarkdownRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Thinking display ───────────────────────────────────────────────────────

/// Print a thinking/reasoning chunk in dim styling (indented under the header)
pub fn print_thinking_chunk(text: &str) {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetAttribute(Attribute::Dim));
    let _ = stdout.execute(SetAttribute(Attribute::Italic));
    let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
    print!("{text}");
    let _ = stdout.execute(SetAttribute(Attribute::Reset));
    let _ = stdout.execute(ResetColor);
    stdout.flush().ok();
}

/// Print the thinking header when a thinking block starts (matches Claude Code's ∴ symbol)
pub fn print_thinking_start() {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetAttribute(Attribute::Dim));
    let _ = stdout.execute(SetAttribute(Attribute::Italic));
    let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
    print!("\n  \u{2234} Thinking\u{2026}\n  ");
    let _ = stdout.execute(SetAttribute(Attribute::Reset));
    let _ = stdout.execute(ResetColor);
    stdout.flush().ok();
}

/// Print a summary when a thinking block ends
pub fn print_thinking_end(duration_secs: f64) {
    let mut stdout = io::stdout();
    let _ = stdout.execute(SetAttribute(Attribute::Dim));
    let _ = stdout.execute(SetForegroundColor(CtColor::DarkGrey));
    if duration_secs > 0.5 {
        println!("\n  \u{2234} Thought for {duration_secs:.1}s");
    } else {
        println!();
    }
    let _ = stdout.execute(SetAttribute(Attribute::Reset));
    let _ = stdout.execute(ResetColor);
    stdout.flush().ok();
}

// ─── Original TUI components ────────────────────────────────────────────────

/// Get a random tip for the tips section
#[must_use]
pub fn get_tips() -> Vec<&'static str> {
    vec![
        "Run /init to create a config file with instructions",
        "Use @filename to include file contents in your prompt",
        "Type /help for a list of all commands",
        "Use Tab to toggle between Build and Plan modes",
        "Press Ctrl+C to cancel a running request",
        "Use /export to save your conversation as markdown",
        "Type !command to run shell commands directly",
    ]
}

/// Welcome screen configuration
pub struct WelcomeScreen {
    pub version: String,
    pub provider: String,
    pub model: String,
    pub auth_method: String,
    pub working_dir: String,
    pub username: Option<String>,
}

impl WelcomeScreen {
    #[must_use]
    pub fn new(version: &str, provider: &str, model: &str) -> Self {
        let cwd = std::env::current_dir().map_or_else(
            |_| ".".to_string(),
            |p| {
                // Shorten home dir to ~
                if let Some(home) = dirs::home_dir() {
                    if let Ok(rel) = p.strip_prefix(&home) {
                        return format!("~/{}", rel.display());
                    }
                }
                p.display().to_string()
            },
        );

        Self {
            version: version.to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            auth_method: "API Key".to_string(),
            working_dir: cwd,
            username: get_username(),
        }
    }

    /// Set the auth method for display
    #[must_use]
    pub fn with_auth(mut self, auth: &str) -> Self {
        self.auth_method = auth.to_string();
        self
    }

    /// Render the welcome screen using ratatui
    ///
    /// # Errors
    ///
    /// Returns an error if terminal setup or drawing fails.
    pub fn render(&self) -> io::Result<()> {
        let mut stdout = stdout();

        // Setup terminal for ratatui
        terminal::enable_raw_mode()?;

        // Use scope block to ensure terminal is dropped before reusing stdout
        let height = {
            let backend = CrosstermBackend::new(&mut stdout);
            let mut terminal = Terminal::new(backend)?;
            terminal.draw(|frame| self.draw(frame))?;
            let size = terminal::size()?;
            8.min(size.1)
        }; // terminal dropped here, releasing stdout borrow

        // Restore terminal
        terminal::disable_raw_mode()?;

        // Move cursor below the rendered area
        stdout.execute(cursor::MoveTo(0, height + 1))?;

        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        let size = frame.area();

        // Limit box width
        let box_width = size.width.min(90);
        let box_height = 8;

        // Center the box if terminal is wider
        let x_offset = (size.width.saturating_sub(box_width)) / 2;
        let area = Rect::new(x_offset, 0, box_width, box_height);

        // Version in the box title (purple branding)
        let title = Line::from(vec![
            Span::styled(
                "OpenClaudia",
                Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" v{}", self.version), Style::default().fg(GOLD)),
        ]);

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(PURPLE));

        // Split into two columns
        let inner = block.inner(area);
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(inner);

        // Render block first
        frame.render_widget(block, area);

        // Left column content
        let greeting = self.username.as_ref().map_or_else(
            || "Welcome to OpenClaudia!".to_string(),
            |name| format!("Welcome back, {name}!"),
        );

        let left_text = vec![
            Line::from(Span::styled(
                &greeting,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("Provider: {}", capitalize_first(&self.provider)),
                Style::default().fg(PURPLE),
            )),
            Line::from(Span::styled(
                format!("Model: {}", self.model),
                Style::default().fg(GOLD),
            )),
            Line::from(Span::styled(&self.working_dir, Style::default().fg(DIM))),
        ];
        let left_para = Paragraph::new(left_text).wrap(Wrap { trim: true });
        frame.render_widget(left_para, chunks[0]);

        // Right column content
        let right_text = vec![
            Line::from(Span::styled(
                "Tips for getting started",
                Style::default().fg(GOLD),
            )),
            Line::from(Span::styled(
                get_tips()[0],
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(Span::styled("Recent activity", Style::default().fg(GOLD))),
            Line::from(Span::styled("No recent activity", Style::default().fg(DIM))),
        ];
        let right_para = Paragraph::new(right_text).wrap(Wrap { trim: true });
        frame.render_widget(right_para, chunks[1]);
    }
}

/// Number of rows reserved at the bottom of the terminal for the pinned bar.
const PINNED_ROWS: u16 = 2;

/// Set up ANSI scroll region to reserve the bottom rows for the pinned status bar.
/// All normal output (including rustyline) scrolls within the top region,
/// while the bottom rows stay fixed.
///
/// # Errors
///
/// Returns an error if terminal operations fail.
pub fn setup_pinned_bar() -> io::Result<()> {
    let (_, rows) = terminal::size().unwrap_or((80, 24));
    let scroll_end = rows.saturating_sub(PINNED_ROWS);
    if scroll_end < 3 {
        return Ok(()); // Terminal too small
    }

    let mut stdout = io::stdout();
    // Set scroll region: rows 1 through (rows - PINNED_ROWS)
    write!(stdout, "\x1b[1;{scroll_end}r")?;
    // Move cursor into the scroll region
    write!(stdout, "\x1b[{scroll_end};1H")?;
    stdout.flush()?;

    Ok(())
}

/// Restore the full terminal scroll region (called on exit).
///
/// # Errors
///
/// Returns an error if terminal operations fail.
pub fn teardown_pinned_bar() -> io::Result<()> {
    let mut stdout = io::stdout();
    // Reset scroll region to full terminal
    write!(stdout, "\x1b[r")?;
    stdout.flush()?;
    Ok(())
}

/// Redraw the pinned bottom bar (separator line + status).
/// Saves and restores cursor position so it doesn't disrupt the main content.
///
/// # Errors
///
/// Returns an error if terminal operations fail.
pub fn redraw_pinned_bar(effort: &str) -> io::Result<()> {
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let bar_row = rows.saturating_sub(PINNED_ROWS) + 1;
    if bar_row < 3 {
        return Ok(());
    }

    let mut stdout = io::stdout();

    // Save cursor position
    write!(stdout, "\x1b[s")?;

    // Draw separator line on the bar row
    write!(stdout, "\x1b[{bar_row};1H")?;
    stdout.execute(SetForegroundColor(CtColor::Rgb {
        r: 128,
        g: 128,
        b: 128,
    }))?;
    let line = "\u{2500}".repeat(cols as usize);
    write!(stdout, "{line}")?;
    stdout.execute(ResetColor)?;

    // Draw status text on the row below
    let status_row = bar_row + 1;
    write!(stdout, "\x1b[{status_row};1H")?;
    let left = "? for shortcuts";
    let right = format!("\u{25CF} {effort} \u{00B7} /effort");
    let total = left.len() + right.len();
    let pad = if cols as usize > total {
        " ".repeat(cols as usize - total)
    } else {
        " ".to_string()
    };
    stdout.execute(SetForegroundColor(CtColor::Rgb {
        r: 128,
        g: 128,
        b: 128,
    }))?;
    write!(stdout, "{left}{pad}{right}")?;
    stdout.execute(ResetColor)?;

    // Restore cursor position
    write!(stdout, "\x1b[u")?;
    stdout.flush()?;

    Ok(())
}

/// Render the input prompt area (called before each readline).
/// No longer prints inline — the pinned bar handles the bottom display.
///
/// # Errors
///
/// Returns an error if writing to stdout fails.
pub const fn render_input_prompt(_mode: &str) -> io::Result<()> {
    Ok(())
}

/// Render the bottom status bar.
/// Delegates to `redraw_pinned_bar` which uses absolute positioning.
///
/// # Errors
///
/// Returns an error if writing to stdout fails.
pub fn render_bottom_bar(effort: &str, _mode: &str) -> io::Result<()> {
    redraw_pinned_bar(effort)
}

/// Get the current username from environment
fn get_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

/// Capitalize the first letter of a string
pub(crate) fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Clear the screen and move cursor to top
///
/// # Errors
///
/// Returns an error if terminal commands fail.
pub fn clear_screen() -> io::Result<()> {
    let mut stdout = io::stdout();
    stdout.execute(Clear(ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;
    stdout.flush()?;
    Ok(())
}

// ─── TUI Polish: Visual Helpers ─────────────────────────────────────────────

/// Print a visual separator between conversation turns.
pub fn print_turn_separator() {
    let width = terminal::size().map_or(80, |(w, _)| w as usize);
    let mut out = stdout();
    let _ = out.execute(SetForegroundColor(CtColor::Rgb {
        r: 60,
        g: 60,
        b: 60,
    }));
    let _ = out.execute(Print("─".repeat(width.min(120))));
    let _ = out.execute(Print("\n"));
    let _ = out.execute(ResetColor);
}

/// Print a role header with icon and color (matches Claude Code's visual style).
pub fn print_role_header(role: &str) {
    let (icon, color) = match role {
        "assistant" | "Assistant" => (
            "\u{23BF}", // ⎿ vertical line left (Claude Code style)
            CtColor::Rgb {
                r: 147,
                g: 112,
                b: 219,
            },
        ),
        "user" | "User" => (
            "\u{203A}", // › single right angle quote
            CtColor::Rgb {
                r: 100,
                g: 180,
                b: 255,
            },
        ),
        "tool" | "Tool" => (
            "\u{25CF}", // ● black circle
            CtColor::Rgb {
                r: 218,
                g: 165,
                b: 32,
            },
        ),
        _ => (
            "\u{00B7}", // · middle dot
            CtColor::Rgb {
                r: 128,
                g: 128,
                b: 128,
            },
        ),
    };
    let mut out = stdout();
    let _ = out.execute(SetForegroundColor(color));
    let _ = out.execute(SetAttribute(Attribute::Bold));
    let _ = out.execute(Print(format!("{icon} {role}")));
    let _ = out.execute(SetAttribute(Attribute::Reset));
    let _ = out.execute(ResetColor);
    let _ = out.execute(Print("\n"));
}

/// Print a tool execution start indicator (matches Claude Code's ● symbol).
pub fn print_tool_start(tool_name: &str, description: &str) {
    let mut out = stdout();
    let _ = out.execute(SetForegroundColor(CtColor::Cyan));
    let _ = out.execute(SetAttribute(Attribute::Bold));
    let _ = out.execute(Print(format!("\n  \u{25CF} {tool_name}")));
    let _ = out.execute(SetAttribute(Attribute::Reset));
    if !description.is_empty() {
        let _ = out.execute(SetForegroundColor(CtColor::DarkGrey));
        let _ = out.execute(Print(format!(" ({description})")));
    }
    let _ = out.execute(ResetColor);
    let _ = out.execute(Print("\n"));
}

/// Print tool completion status with duration.
pub fn print_tool_done(tool_name: &str, success: bool, duration_ms: u64) {
    let mut out = stdout();
    let _ = out.execute(Print("  "));
    if success {
        let _ = out.execute(SetForegroundColor(CtColor::Green));
        let _ = out.execute(Print(format!("\u{2713} {tool_name}")));
    } else {
        let _ = out.execute(SetForegroundColor(CtColor::Red));
        let _ = out.execute(Print(format!("\u{2717} {tool_name}")));
    }
    if duration_ms > 0 {
        let _ = out.execute(SetForegroundColor(CtColor::DarkGrey));
        let _ = out.execute(Print(format!(" \u{00B7} {duration_ms}ms")));
    }
    let _ = out.execute(ResetColor);
    let _ = out.execute(Print("\n"));
}

/// Print a context usage bar (green/yellow/red).
pub fn print_context_usage(used_tokens: usize, max_tokens: usize) {
    if max_tokens == 0 {
        return;
    }
    #[allow(clippy::cast_precision_loss)] // token counts are small enough for f32
    #[allow(clippy::cast_precision_loss)] // token counts are well within f32 range
    let pct = (used_tokens as f32 / max_tokens as f32 * 100.0).min(100.0);
    let bar_width: usize = 20;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )] // pct clamped 0..100, bar_width=20
    let filled = (pct / 100.0 * bar_width as f32) as usize;
    let empty = bar_width - filled;
    let color = if pct >= 90.0 {
        CtColor::Red
    } else if pct >= 75.0 {
        CtColor::Yellow
    } else {
        CtColor::Green
    };

    let mut out = stdout();
    let _ = out.execute(SetForegroundColor(CtColor::DarkGrey));
    let _ = out.execute(Print("  Context: ["));
    let _ = out.execute(SetForegroundColor(color));
    let _ = out.execute(Print("█".repeat(filled)));
    let _ = out.execute(SetForegroundColor(CtColor::DarkGrey));
    let _ = out.execute(Print("░".repeat(empty)));
    let _ = out.execute(Print(format!("] {pct:.0}%")));
    let _ = out.execute(ResetColor);
    let _ = out.execute(Print("\n"));
}

/// Print a clean welcome banner (inline fallback, no ratatui).
pub fn print_welcome_banner(version: &str, provider: &str, model: &str, auth_method: &str) {
    let mut out = stdout();
    // Purple branding header
    let _ = out.execute(SetForegroundColor(CtColor::Rgb {
        r: 147,
        g: 112,
        b: 219,
    }));
    let _ = out.execute(SetAttribute(Attribute::Bold));
    let _ = out.execute(Print(format!("  OpenClaudia v{version}")));
    let _ = out.execute(SetAttribute(Attribute::Reset));
    let _ = out.execute(ResetColor);
    let _ = out.execute(Print("\n"));
    // Provider and model on next line
    let _ = out.execute(SetForegroundColor(CtColor::DarkGrey));
    let _ = out.execute(Print(format!(
        "  {provider} \u{00B7} {model} \u{00B7} {auth_method}\n\n"
    )));
    let _ = out.execute(ResetColor);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capitalize_first() {
        assert_eq!(capitalize_first("anthropic"), "Anthropic");
        assert_eq!(capitalize_first("openai"), "Openai");
        assert_eq!(capitalize_first(""), "");
    }

    #[test]
    fn test_get_tips() {
        let tips = get_tips();
        assert!(
            tips.len() >= 3,
            "Should have at least 3 tips, got {}",
            tips.len()
        );
        // Verify tips contain actual user-facing guidance
        assert!(
            tips.iter().any(|t| t.contains("/init")),
            "Tips should mention /init command"
        );
        assert!(
            tips.iter().any(|t| t.contains("/help")),
            "Tips should mention /help command"
        );
    }

    #[test]
    fn module_docs_do_not_advertise_removed_tui_flag() {
        let src = include_str!("mod.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        assert!(
            production.contains("default when no subcommand"),
            "TUI module docs must describe the actual default launch path"
        );
        assert!(
            !production.contains("via `--tui`"),
            "TUI module docs must not advertise the removed --tui flag"
        );
    }

    #[test]
    fn test_theme_from_name() {
        assert!(Theme::from_name("default").is_some());
        assert!(Theme::from_name("ocean").is_some());
        assert!(Theme::from_name("forest").is_some());
        assert!(Theme::from_name("sunset").is_some());
        assert!(Theme::from_name("mono").is_some());
        assert!(Theme::from_name("neon").is_some());
        assert!(Theme::from_name("nonexistent").is_none());
    }

    #[test]
    fn test_theme_default() {
        let theme = Theme::default();
        assert_eq!(theme.name, "default");
    }

    #[test]
    fn maintained_syntax_highlighter_colors_supported_language() {
        let mut highlighter =
            CodeHighlighter::new("rust").expect("the explicit Rust grammar must be registered");
        let rendered = highlighter
            .highlight_line("fn main() { println!(\"hello\"); }")
            .expect("valid Rust source must highlight");
        assert!(
            rendered.contains("\u{1b}["),
            "highlighted terminal source must contain ANSI styling"
        );
        assert!(rendered.contains("main"));
    }

    #[test]
    fn unsupported_syntax_tag_uses_existing_flat_color_fallback() {
        assert!(CodeHighlighter::new("definitely-not-a-language").is_none());
    }

    #[test]
    fn maintained_syntax_highlighter_preserves_multiline_context() {
        let mut contextual =
            CodeHighlighter::new("rust").expect("the explicit Rust grammar must be registered");
        contextual
            .highlight_line("/* opening comment")
            .expect("first comment line must highlight");
        let continued = contextual
            .highlight_line("still inside */ let value = 1;")
            .expect("continued comment line must highlight");

        let mut isolated =
            CodeHighlighter::new("rust").expect("the explicit Rust grammar must be registered");
        let without_context = isolated
            .highlight_line("still inside */ let value = 1;")
            .expect("isolated source must remain renderable");
        assert_ne!(
            continued, without_context,
            "multiline parsing must affect the continued line's styling"
        );
        assert!(continued.contains("\u{1b}["));
        assert!(continued.contains("still inside */"));
    }

    #[test]
    fn maintained_syntax_highlighter_falls_back_after_bounded_source() {
        let mut highlighter =
            CodeHighlighter::new("rust").expect("the explicit Rust grammar must be registered");
        let oversized = "x".repeat(MAX_HIGHLIGHT_SOURCE_BYTES + 1);
        assert!(highlighter.highlight_line(&oversized).is_none());
        assert!(highlighter
            .highlight_line("let still_visible = true;")
            .is_none());
    }

    #[test]
    fn maintained_syntax_highlighter_bounds_reparse_line_count() {
        let mut highlighter =
            CodeHighlighter::new("rust").expect("the explicit Rust grammar must be registered");
        for _ in 0..MAX_HIGHLIGHT_SOURCE_LINES {
            assert!(highlighter.highlight_line("// bounded").is_some());
        }
        assert!(highlighter.highlight_line("let fallback = true;").is_none());
    }

    #[test]
    fn test_strip_ordered_list_prefix() {
        assert_eq!(strip_ordered_list_prefix("1. hello"), Some("hello"));
        assert_eq!(strip_ordered_list_prefix("12. world"), Some("world"));
        assert_eq!(strip_ordered_list_prefix("not a list"), None);
        assert_eq!(strip_ordered_list_prefix("- dash"), None);
    }

    #[test]
    fn test_find_closing() {
        let chars: Vec<char> = "hello**world".chars().collect();
        assert_eq!(find_closing(&chars, 0, "**"), Some(5));
    }

    #[test]
    fn test_find_closing_char() {
        let chars: Vec<char> = "hello`world".chars().collect();
        assert_eq!(find_closing_char(&chars, 0, '`'), Some(5));
    }

    /// Regression for crosslink #442: the brand palette constants must
    /// resolve to the exact RGB triples that were previously inlined at
    /// every call site. If anyone "tweaks" the purple to look slightly
    /// different, this test fails and they re-think it deliberately.
    #[test]
    fn brand_palette_rgb_values_are_stable() {
        assert_eq!(PURPLE, Color::Rgb(147, 112, 219), "PURPLE drifted");
        assert_eq!(GOLD, Color::Rgb(218, 165, 32), "GOLD drifted");
        assert_eq!(DIM, Color::Rgb(128, 128, 128), "DIM drifted");
        assert_eq!(USER_BLUE, Color::Rgb(100, 180, 255), "USER_BLUE drifted");
    }

    /// Regression for crosslink #442: spinner frames live with the brand
    /// palette in `mod.rs`. Keep the canonical Braille-dot sequence so the
    /// spinner animation matches what users expect.
    #[test]
    fn spinner_frames_are_braille_sequence() {
        assert_eq!(SPINNER_FRAMES.len(), 10, "spinner must have 10 frames");
        assert_eq!(SPINNER_FRAMES[0], "⠋", "first frame must be ⠋");
        assert_eq!(SPINNER_FRAMES[9], "⠏", "last frame must be ⠏");
    }

    #[test]
    fn test_parse_link() {
        let chars: Vec<char> = "[click here](https://example.com) rest".chars().collect();
        let result = parse_link(&chars, 0);
        assert!(result.is_some());
        let (text, url, end) = result.unwrap();
        assert_eq!(text, "click here");
        assert_eq!(url, "https://example.com");
        assert_eq!(end, 33);
    }
}
