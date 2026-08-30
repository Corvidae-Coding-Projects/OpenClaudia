//! Text input widget for the TUI.

use ratatui::{buffer::CellWidth, style::Style, text::Line};

use super::safety::{sanitize_terminal_text, TextLimits};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_INPUT_LINES: usize = 128;
const INPUT_DISPLAY_LIMITS: TextLimits = TextLimits::new(
    MAX_INPUT_BYTES,
    256 * 1024,
    MAX_INPUT_LINES,
    MAX_INPUT_BYTES,
);

/// Text input with cursor tracking.
pub struct TextInput {
    pub content: String,
    cursor_pos: usize,
}

impl TextInput {
    /// Current cursor position (byte offset into content).
    #[must_use]
    pub const fn cursor_position(&self) -> usize {
        self.cursor_pos
    }
}

impl TextInput {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content: String::new(),
            cursor_pos: 0,
        }
    }

    pub fn insert(&mut self, ch: char) {
        if self.content.len().saturating_add(ch.len_utf8()) > MAX_INPUT_BYTES
            || (ch == '\n' && self.content.matches('\n').count() + 1 >= MAX_INPUT_LINES)
        {
            return;
        }
        self.content.insert(self.cursor_pos, ch);
        self.cursor_pos += ch.len_utf8();
    }

    pub fn insert_newline(&mut self) {
        self.insert('\n');
    }

    pub fn insert_str(&mut self, text: &str) {
        let remaining_bytes = MAX_INPUT_BYTES.saturating_sub(self.content.len());
        let remaining_newlines = MAX_INPUT_LINES
            .saturating_sub(1)
            .saturating_sub(self.content.matches('\n').count());
        let mut accepted = String::with_capacity(text.len().min(remaining_bytes));
        let mut newlines = 0usize;
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            let normalized = if ch == '\r' {
                if matches!(chars.peek(), Some('\n')) {
                    let _ = chars.next();
                }
                '\n'
            } else {
                ch
            };
            if normalized == '\n' {
                if newlines >= remaining_newlines {
                    break;
                }
                newlines += 1;
            }
            if accepted.len().saturating_add(normalized.len_utf8()) > remaining_bytes {
                break;
            }
            accepted.push(normalized);
        }
        self.content.insert_str(self.cursor_pos, &accepted);
        self.cursor_pos += accepted.len();
    }

    pub fn backspace(&mut self) {
        if self.cursor_pos > 0 {
            let previous = previous_grapheme_boundary(&self.content, self.cursor_pos);
            self.content.drain(previous..self.cursor_pos);
            self.cursor_pos = previous;
        }
    }

    pub fn delete(&mut self) {
        if self.cursor_pos < self.content.len() {
            let next = next_grapheme_boundary(&self.content, self.cursor_pos);
            self.content.drain(self.cursor_pos..next);
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor_pos > 0 {
            self.cursor_pos = previous_grapheme_boundary(&self.content, self.cursor_pos);
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor_pos < self.content.len() {
            self.cursor_pos = next_grapheme_boundary(&self.content, self.cursor_pos);
        }
    }

    pub const fn home(&mut self) {
        self.cursor_pos = 0;
    }

    pub const fn end(&mut self) {
        self.cursor_pos = self.content.len();
    }

    #[must_use]
    pub fn visual_line_count(&self, content_width: u16) -> u16 {
        let width = usize::from(content_width.max(1));
        let display = self.rendered_content();
        let rows = display
            .split('\n')
            .map(|line| visual_rows(line, width))
            .sum::<usize>();
        u16::try_from(rows).unwrap_or(u16::MAX)
    }

    #[must_use]
    pub fn visual_cursor_position(&self, content_width: u16) -> (u16, u16) {
        let width = usize::from(content_width.max(1));
        let before_cursor = &self.content[..self.cursor_pos];
        let before_cursor = sanitize_terminal_text(before_cursor, INPUT_DISPLAY_LIMITS);
        let mut row = 0usize;
        let mut lines = before_cursor.as_str().split('\n').peekable();

        while let Some(line) = lines.next() {
            if lines.peek().is_some() {
                row = row.saturating_add(visual_rows(line, width));
            } else {
                let (wrapped, col) = visual_cursor(line, width);
                row = row.saturating_add(wrapped);
                return (
                    u16::try_from(row).unwrap_or(u16::MAX),
                    u16::try_from(col).unwrap_or(u16::MAX),
                );
            }
        }

        (0, 0)
    }

    /// Take the content and reset.
    pub fn take(&mut self) -> String {
        let s = std::mem::take(&mut self.content);
        self.cursor_pos = 0;
        s
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Inert display projection of the editable value.
    #[must_use]
    pub fn rendered_content(&self) -> String {
        sanitize_terminal_text(&self.content, INPUT_DISPLAY_LIMITS).into_string()
    }
}

fn previous_grapheme_boundary(text: &str, cursor: usize) -> usize {
    let line = Line::raw(&text[..cursor]);
    let mut offset = 0usize;
    let mut previous = 0usize;
    for grapheme in line.styled_graphemes(Style::default()) {
        previous = offset;
        offset += grapheme.symbol.len();
    }
    previous
}

fn next_grapheme_boundary(text: &str, cursor: usize) -> usize {
    let line = Line::raw(&text[cursor..]);
    let boundary = line
        .styled_graphemes(Style::default())
        .next()
        .map_or(text.len(), |grapheme| cursor + grapheme.symbol.len());
    boundary
}

pub(crate) fn pop_last_grapheme(text: &mut String) {
    if text.is_empty() {
        return;
    }
    let previous = previous_grapheme_boundary(text, text.len());
    text.truncate(previous);
}

fn visual_rows(text: &str, width: usize) -> usize {
    let line = Line::raw(text);
    let mut rows = 1usize;
    let mut column = 0usize;
    for grapheme in line.styled_graphemes(Style::default()) {
        let cells = usize::from(grapheme.symbol.cell_width()).min(width);
        if cells > 0 && column.saturating_add(cells) > width {
            rows = rows.saturating_add(1);
            column = 0;
        }
        column = column.saturating_add(cells);
    }
    rows
}

fn visual_cursor(text: &str, width: usize) -> (usize, usize) {
    let line = Line::raw(text);
    let mut rows = 0usize;
    let mut column = 0usize;
    for grapheme in line.styled_graphemes(Style::default()) {
        let cells = usize::from(grapheme.symbol.cell_width()).min(width);
        if cells > 0 && column.saturating_add(cells) > width {
            rows = rows.saturating_add(1);
            column = 0;
        }
        column = column.saturating_add(cells);
    }
    if column >= width {
        (rows.saturating_add(column / width), column % width)
    } else {
        (rows, column)
    }
}

impl Default for TextInput {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_take() {
        let mut input = TextInput::new();
        input.insert('h');
        input.insert('i');
        assert_eq!(input.content, "hi");
        assert_eq!(input.cursor_pos, 2);
        let taken = input.take();
        assert_eq!(taken, "hi");
        assert!(input.is_empty());
    }

    #[test]
    fn test_backspace() {
        let mut input = TextInput::new();
        input.insert('a');
        input.insert('b');
        input.backspace();
        assert_eq!(input.content, "a");
        assert_eq!(input.cursor_pos, 1);
    }

    #[test]
    fn test_cursor_movement() {
        let mut input = TextInput::new();
        input.insert('a');
        input.insert('b');
        input.insert('c');
        input.home();
        assert_eq!(input.cursor_pos, 0);
        input.end();
        assert_eq!(input.cursor_pos, 3);
        input.move_left();
        assert_eq!(input.cursor_pos, 2);
        input.move_right();
        assert_eq!(input.cursor_pos, 3);
    }

    #[test]
    fn test_delete() {
        let mut input = TextInput::new();
        input.insert('a');
        input.insert('b');
        input.home();
        input.delete();
        assert_eq!(input.content, "b");
    }

    #[test]
    fn test_insert_multiline_text_normalizes_crlf() {
        let mut input = TextInput::new();
        input.insert_str("a\r\nb\rc");
        assert_eq!(input.content, "a\nb\nc");
        assert_eq!(input.cursor_pos, input.content.len());
    }

    #[test]
    fn test_visual_cursor_position_tracks_newlines() {
        let mut input = TextInput::new();
        input.insert_str("abc\nde");

        assert_eq!(input.visual_line_count(10), 2);
        assert_eq!(input.visual_cursor_position(10), (1, 2));
    }

    #[test]
    fn test_visual_line_count_accounts_for_wrapping() {
        let mut input = TextInput::new();
        input.insert_str("abcd\nef");

        assert_eq!(input.visual_line_count(3), 3);
        assert_eq!(input.visual_cursor_position(3), (2, 2));
    }
}
