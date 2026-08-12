//! Scrollable message list for the TUI.

use std::collections::VecDeque;
use std::str::FromStr;
use std::time::Instant;

use ratatui::{buffer::CellWidth, prelude::*, widgets::Paragraph};

use super::{GOLD, PURPLE, USER_BLUE};
pub use crate::state::EffortLevel;

// ─── MessageKind ────────────────────────────────────────────────────────────

/// The semantic kind of a [`DisplayMessage`].
///
/// Encodes what type of content the message carries and how it should be
/// rendered. Replaces the previous twin-boolean `(is_error, is_thinking)` flags
/// and the stringly-typed `role` field — invalid state combinations are now
/// unrepresentable at the type level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageKind {
    /// A message typed by the human user.
    User,
    /// A completed assistant response.
    Assistant,
    /// A collapsed thinking summary (e.g. "Thought for 1.2s").
    Thinking,
    /// An informational system message (no error).
    SystemInfo,
    /// An error-level system message.
    SystemError,
    /// Tool invocation header — the tool started but has not yet returned.
    ToolStart {
        /// Tool name shown in the header line.
        name: String,
    },
    /// Tool completed successfully.
    ToolOk {
        /// Tool name shown in the result line.
        name: String,
    },
    /// Tool completed with a failure / non-zero exit.
    ToolErr {
        /// Tool name shown in the result line.
        name: String,
    },
}

impl MessageKind {
    /// Returns `true` when this kind renders with error styling.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::SystemError | Self::ToolErr { .. })
    }

    /// Returns `true` when this kind carries thinking content.
    #[must_use]
    pub const fn is_thinking(&self) -> bool {
        matches!(self, Self::Thinking)
    }

    /// Borrow the tool name when available, without allocating.
    #[must_use]
    pub const fn tool_name(&self) -> Option<&str> {
        match self {
            Self::ToolStart { name } | Self::ToolOk { name } | Self::ToolErr { name } => {
                Some(name.as_str())
            }
            _ => None,
        }
    }
}

// ─── Role ───────────────────────────────────────────────────────────────────

/// Wire-format role for session messages.
///
/// Used exclusively at the serde boundary (session JSON persistence and
/// resume). Internal code compares against enum variants — no string literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    System,
    Tool,
}

impl Role {
    /// Return the lowercase wire-format string for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
            Self::Tool => "tool",
        }
    }
}

/// Parse a role from a wire-format string.
///
/// Unknown roles round-trip to `System` rather than failing, matching
/// the previous fallback behaviour of the `_ =>` arm.
impl FromStr for Role {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "user" => Self::User,
            "assistant" => Self::Assistant,
            "tool" => Self::Tool,
            _ => Self::System,
        })
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Mode ───────────────────────────────────────────────────────────────────

/// The agent operating mode.
///
/// Replaces `TuiSession.mode: String` and `App.mode: String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Mode {
    /// Full-access mode — the agent can write files, run commands, etc.
    #[default]
    Build,
    /// Read-only suggestions-only mode.
    Plan,
}

impl Mode {
    /// Return the display name used in the status bar and system messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "Build",
            Self::Plan => "Plan",
        }
    }

    /// Return a one-line description shown in `/mode` system messages.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Build => "Full access — can make changes",
            Self::Plan => "Read-only — suggestions only",
        }
    }

    /// Toggle between `Build` and `Plan`.
    #[must_use]
    pub const fn toggled(self) -> Self {
        match self {
            Self::Build => Self::Plan,
            Self::Plan => Self::Build,
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Mode {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Plan" => Self::Plan,
            _ => Self::Build,
        })
    }
}

// ─── DisplayMessage ──────────────────────────────────────────────────────────

/// A single display message in the conversation.
///
/// The `kind` field carries all the semantic information that was previously
/// split across `role: String`, `is_error: bool`, `is_thinking: bool`, and
/// `tool_name: Option<String>`.
#[derive(Debug, Clone)]
pub struct DisplayMessage {
    pub kind: MessageKind,
    pub content: String,
}

impl DisplayMessage {
    /// Convenience constructor for a `SystemInfo` message.
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            kind: MessageKind::SystemInfo,
            content: content.into(),
        }
    }

    /// Convenience constructor for a `SystemError` message.
    #[must_use]
    pub fn error(content: impl Into<String>) -> Self {
        Self {
            kind: MessageKind::SystemError,
            content: content.into(),
        }
    }

    /// Convenience constructor for a `User` message.
    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            kind: MessageKind::User,
            content: content.into(),
        }
    }

    /// Convenience constructor for an `Assistant` message.
    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            kind: MessageKind::Assistant,
            content: content.into(),
        }
    }
}

// ─── MessageList ────────────────────────────────────────────────────────────

/// Scrollable message list with streaming support.
pub struct MessageList {
    pub messages: Vec<DisplayMessage>,
    /// Vertical scroll position, measured **in rendered rows backwards from
    /// the bottom of the buffer** — *not* from the top.
    ///
    /// - `scroll_offset == 0`  → the viewport is anchored to the bottom, so the
    ///   newest content (the tail of [`Self::messages`] plus any in-flight
    ///   `streaming_text`) is fully visible. This is the resting/streaming
    ///   state and is what [`Self::scroll_to_bottom`] restores.
    /// - `scroll_offset > 0`   → the viewport has been moved `scroll_offset`
    ///   rows *back in time* (toward older messages). [`Self::scroll_up`]
    ///   increases this value; [`Self::scroll_down`] decreases it.
    ///
    /// This is deliberately a bottom-anchored coordinate because chat UIs
    /// stream new rows at the bottom — rebasing the offset every time a delta
    /// arrives would cause the viewport to drift. Callers that need a
    /// conventional top-anchored row index (where `0 == first row`) should use
    /// [`Self::rows_from_top`] instead of touching this field directly.
    ///
    /// See crosslink #482.
    pub scroll_offset: u16,
    pub streaming_text: String,
    pub is_streaming: bool,
    /// True while thinking/reasoning deltas are arriving for the current
    /// response, before any regular text has streamed in.
    pub is_thinking_now: bool,
    /// When the current thinking block started. Used to render elapsed
    /// seconds next to the `∴ Thinking…` indicator.
    thinking_start: Option<Instant>,
    /// Accumulator for the full thinking stream. Rendered while live so the
    /// user can see progress during long reasoning/tool-planning phases.
    pub thinking_buffer: String,
}

struct VisualGrapheme {
    symbol: String,
    style: Style,
    width: u16,
    is_whitespace: bool,
}

impl MessageList {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            messages: Vec::new(),
            scroll_offset: 0,
            streaming_text: String::new(),
            is_streaming: false,
            is_thinking_now: false,
            thinking_start: None,
            thinking_buffer: String::new(),
        }
    }

    /// Record a thinking-delta chunk. The text is accumulated and rendered
    /// under the live `∴ Thinking…` indicator until the block finalizes.
    pub fn push_thinking(&mut self, text: &str) {
        if self.thinking_start.is_none() {
            self.thinking_start = Some(Instant::now());
        }
        self.is_thinking_now = true;
        self.thinking_buffer.push_str(text);
    }

    /// Finalize the current thinking block: replace the live indicator
    /// with a collapsed `∴ Thought for X.Xs` header message and reset
    /// the timer. Safe to call repeatedly — no-op when not thinking.
    pub fn finish_thinking(&mut self) {
        if !self.is_thinking_now {
            return;
        }
        let duration = self
            .thinking_start
            .map_or(0.0, |start| start.elapsed().as_secs_f64());
        self.messages.push(DisplayMessage {
            kind: MessageKind::Thinking,
            content: format!("Thought for {duration:.1}s"),
        });
        self.is_thinking_now = false;
        self.thinking_start = None;
        self.thinking_buffer.clear();
        self.scroll_to_bottom();
    }

    /// Remove the last `count` messages from the display list.
    ///
    /// Saturates at zero — passing a `count` larger than the current length
    /// truncates the entire list rather than panicking, and `count == 0` is a
    /// no-op.
    pub fn pop_last(&mut self, count: usize) {
        self.messages
            .truncate(self.messages.len().saturating_sub(count));
    }

    /// Number of messages in the display list.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.messages.len()
    }

    /// Returns `true` if there are no messages in the display list.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn add(&mut self, msg: DisplayMessage) {
        self.messages.push(msg);
        self.scroll_to_bottom();
    }

    pub fn append_streaming(&mut self, text: &str) {
        self.streaming_text.push_str(text);
        self.is_streaming = true;
    }

    pub fn finish_streaming(&mut self) {
        if !self.streaming_text.is_empty() {
            self.messages.push(DisplayMessage {
                kind: MessageKind::Assistant,
                content: std::mem::take(&mut self.streaming_text),
            });
        }
        self.is_streaming = false;
    }

    pub const fn scroll_up(&mut self, n: u16) {
        self.scroll_offset = self.scroll_offset.saturating_add(n);
    }

    pub const fn scroll_down(&mut self, n: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(n);
    }

    pub const fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
    }

    /// Convert the bottom-anchored [`Self::scroll_offset`] into a
    /// **top-anchored** row index, given `total` rendered rows in the buffer.
    ///
    /// Callers that think top-down ("how many rows down from row 0 are we?")
    /// can use this instead of inverting the offset by hand. The returned
    /// index is the row number, counted from the top (`0` = first row),
    /// of the *last visible row* — i.e. the bottom edge of the viewport.
    /// The two views describe the same scroll position:
    ///
    /// ```text
    /// scroll_offset == 0          ⇒ rows_from_top(total) == total
    /// scroll_offset == k (k>0)    ⇒ rows_from_top(total) == total - k
    /// ```
    ///
    /// The result saturates at `0` if `scroll_offset` is larger than `total`
    /// — the caller already scrolled past the available content and the
    /// viewport is clamped against it.
    ///
    /// `total` is the total number of *rendered* rows after wrapping/padding;
    /// the caller already knows that quantity at render time, so this helper
    /// stays pure and side-effect free.
    ///
    /// See crosslink #482.
    #[must_use]
    pub fn rows_from_top(&self, total: usize) -> usize {
        total.saturating_sub(usize::from(self.scroll_offset))
    }

    /// Append styled lines for the welcome banner system message.
    fn append_welcome_lines<'a>(out: &mut Vec<Line<'a>>, content: &'a str) {
        for line in content.lines() {
            let styled = if line.starts_with("OpenClaudia v") {
                Line::from(vec![
                    Span::styled(
                        "OpenClaudia",
                        Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&line["OpenClaudia".len()..], Style::default().fg(GOLD)),
                ])
            } else if line.starts_with("Provider:") {
                Line::from(Span::styled(line, Style::default().fg(PURPLE)))
            } else if line.starts_with("Model:") {
                Line::from(Span::styled(line, Style::default().fg(GOLD)))
            } else if line.starts_with("Welcome") {
                Line::from(Span::styled(
                    line,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(Span::styled(line, Style::default().fg(Color::DarkGray)))
            };
            out.push(styled);
        }
    }

    /// Append rendered lines for a system-role message to `out`.
    fn append_system_lines<'a>(out: &mut Vec<Line<'a>>, msg: &'a DisplayMessage) {
        if msg.content.contains("OpenClaudia v") {
            Self::append_welcome_lines(out, &msg.content);
        } else {
            for line in msg.content.lines() {
                out.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                )));
            }
        }
        out.push(Line::from(""));
    }

    /// Append rendered lines for a tool-result message to `out`.
    fn append_tool_lines<'a>(out: &mut Vec<Line<'a>>, msg: &'a DisplayMessage) {
        let tool_name = msg.kind.tool_name().unwrap_or("tool");
        if msg.kind.is_error() {
            out.push(Line::from(Span::styled(
                format!("  \u{2717} {tool_name}"),
                Style::default().fg(Color::Red),
            )));
        } else {
            out.push(Line::from(Span::styled(
                format!("  \u{2713} {tool_name}"),
                Style::default().fg(Color::Green),
            )));
        }
        let preview = if msg.content.len() > 200 {
            format!("{}...", crate::tools::safe_truncate(&msg.content, 197))
        } else {
            msg.content.clone()
        };
        for line in preview.lines().take(5) {
            out.push(Line::from(Span::styled(
                format!("    {line}"),
                Style::default().fg(Color::DarkGray),
            )));
        }
        out.push(Line::from(""));
    }

    /// Append rendered lines for a single message to `out`.
    fn append_message_lines<'a>(out: &mut Vec<Line<'a>>, msg: &'a DisplayMessage) {
        match &msg.kind {
            MessageKind::SystemInfo | MessageKind::SystemError => {
                Self::append_system_lines(out, msg);
            }
            MessageKind::User => {
                out.push(Line::from(Span::styled(
                    "\u{203A} user",
                    Style::default().fg(USER_BLUE).add_modifier(Modifier::BOLD),
                )));
                for line in msg.content.lines() {
                    out.push(Line::from(format!("  {line}")));
                }
                out.push(Line::from(""));
            }
            MessageKind::Assistant => {
                out.push(Line::from(Span::styled(
                    "\u{23BF} Claudia",
                    Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
                )));
                for line in msg.content.lines() {
                    out.push(Line::from(format!("  {line}")));
                }
                out.push(Line::from(""));
            }
            MessageKind::Thinking => {
                out.push(Line::from(Span::styled(
                    format!("  \u{2234} {}", msg.content),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                )));
                out.push(Line::from(""));
            }
            MessageKind::ToolStart { .. }
            | MessageKind::ToolOk { .. }
            | MessageKind::ToolErr { .. } => {
                Self::append_tool_lines(out, msg);
            }
        }
    }

    /// Build ratatui Lines for rendering.
    fn build_lines(&self) -> Vec<Line<'_>> {
        let mut lines: Vec<Line> = Vec::new();

        for msg in &self.messages {
            Self::append_message_lines(&mut lines, msg);
        }

        // Live thinking indicator (while thinking deltas are arriving)
        if self.is_thinking_now {
            let elapsed = self
                .thinking_start
                .map_or(0.0, |s| s.elapsed().as_secs_f64());
            let thinking_style = Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC);
            lines.push(Line::from(Span::styled(
                format!("  \u{2234} Thinking\u{2026} ({elapsed:.1}s)"),
                thinking_style,
            )));
            for line in self.thinking_buffer.lines() {
                lines.push(Line::from(Span::styled(
                    format!("    {line}"),
                    thinking_style,
                )));
            }
            lines.push(Line::from(""));
        }

        // Streaming content
        if self.is_streaming && !self.streaming_text.is_empty() {
            lines.push(Line::from(Span::styled(
                "\u{23BF} Claudia",
                Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
            )));
            for line in self.streaming_text.lines() {
                lines.push(Line::from(format!("  {line}")));
            }
            // Cursor indicator
            lines.push(Line::from(Span::styled(
                "  \u{2588}",
                Style::default().fg(PURPLE),
            )));
        }

        lines
    }

    fn saturating_u16(value: usize) -> u16 {
        u16::try_from(value).unwrap_or(u16::MAX)
    }

    fn visual_line_from_graphemes(
        graphemes: Vec<VisualGrapheme>,
        alignment: Option<Alignment>,
    ) -> Line<'static> {
        let mut spans: Vec<Span<'static>> = Vec::new();
        for grapheme in graphemes {
            if let Some(last) = spans.last_mut() {
                if last.style == grapheme.style {
                    last.content.to_mut().push_str(&grapheme.symbol);
                    continue;
                }
            }
            spans.push(Span::styled(grapheme.symbol, grapheme.style));
        }

        let mut line = Line::from(spans);
        line.alignment = alignment;
        line
    }

    const fn empty_visual_line(source: &Line<'_>) -> Line<'static> {
        Line {
            style: source.style,
            alignment: source.alignment,
            spans: Vec::new(),
        }
    }

    fn wrap_line(source: &Line<'_>, width: u16) -> Vec<Line<'static>> {
        let mut wrapped = Vec::new();
        let mut pending_line = Vec::new();
        let mut pending_word = Vec::new();
        let mut pending_whitespace = VecDeque::new();
        let mut line_width = 0;
        let mut word_width = 0;
        let mut whitespace_width = 0;
        let mut non_whitespace_previous = false;

        for styled in source.styled_graphemes(Style::default()) {
            let grapheme = VisualGrapheme {
                symbol: styled.symbol.to_string(),
                style: styled.style,
                width: styled.symbol.cell_width(),
                is_whitespace: styled.is_whitespace(),
            };

            if grapheme.width > width {
                continue;
            }

            let is_whitespace = grapheme.is_whitespace;
            let word_found = non_whitespace_previous && grapheme.is_whitespace;
            let untrimmed_overflow =
                pending_line.is_empty() && word_width + whitespace_width + grapheme.width > width;

            if word_found || untrimmed_overflow {
                pending_line.extend(std::mem::take(&mut pending_whitespace));
                line_width += whitespace_width;
                pending_line.append(&mut pending_word);
                line_width += word_width;
                whitespace_width = 0;
                word_width = 0;
            }

            let line_full = line_width >= width;
            let pending_word_overflow =
                grapheme.width > 0 && line_width + whitespace_width + word_width >= width;

            if line_full || pending_word_overflow {
                let mut remaining_width = width.saturating_sub(line_width);
                wrapped.push(Self::visual_line_from_graphemes(
                    std::mem::take(&mut pending_line),
                    source.alignment,
                ));
                line_width = 0;

                while let Some(grapheme) = pending_whitespace.front() {
                    if grapheme.width > remaining_width {
                        break;
                    }

                    whitespace_width -= grapheme.width;
                    remaining_width -= grapheme.width;
                    pending_whitespace.pop_front();
                }

                if grapheme.is_whitespace && pending_whitespace.is_empty() {
                    continue;
                }
            }

            if grapheme.is_whitespace {
                whitespace_width += grapheme.width;
                pending_whitespace.push_back(grapheme);
            } else {
                word_width += grapheme.width;
                pending_word.push(grapheme);
            }

            non_whitespace_previous = !is_whitespace;
        }

        pending_line.extend(pending_whitespace);
        pending_line.append(&mut pending_word);

        if !pending_line.is_empty() {
            wrapped.push(Self::visual_line_from_graphemes(
                pending_line,
                source.alignment,
            ));
        }
        if wrapped.is_empty() {
            wrapped.push(Self::empty_visual_line(source));
        }

        wrapped
    }

    fn wrap_lines(lines: &[Line<'_>], width: u16) -> Vec<Line<'static>> {
        if width == 0 {
            return Vec::new();
        }

        lines
            .iter()
            .flat_map(|line| Self::wrap_line(line, width))
            .collect()
    }

    /// Render the message list into a frame area.
    /// Content is anchored to the bottom — empty space is at the top, not below.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        if area.is_empty() {
            return;
        }

        let logical_lines = self.build_lines();
        let mut lines = Self::wrap_lines(&logical_lines, area.width);
        let mut total = lines.len();
        let visible = usize::from(area.height);

        // Pad the top with empty lines so content anchors to the bottom
        if total < visible {
            let pad = visible - total;
            let mut padded = vec![Line::from(""); pad];
            padded.append(&mut lines);
            lines = padded;
            total = visible;
        }

        let scroll = if total > visible {
            (total - visible).saturating_sub(usize::from(self.scroll_offset))
        } else {
            0
        };

        let paragraph = Paragraph::new(lines).scroll((Self::saturating_u16(scroll), 0));

        frame.render_widget(paragraph, area);
    }
}

impl Default for MessageList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn rendered_rows(backend: &TestBackend) -> Vec<String> {
        let area = *backend.buffer().area();
        let mut rows = Vec::with_capacity(usize::from(area.height));
        for y in 0..area.height {
            let mut row = String::new();
            for x in 0..area.width {
                let cell = backend
                    .buffer()
                    .cell((x, y))
                    .expect("test coordinates are inside the buffer");
                row.push_str(cell.symbol());
            }
            rows.push(row);
        }
        rows
    }

    // ── MessageKind tests ────────────────────────────────────────────────────

    #[test]
    fn message_kind_is_error_only_for_error_variants() {
        assert!(!MessageKind::User.is_error());
        assert!(!MessageKind::Assistant.is_error());
        assert!(!MessageKind::Thinking.is_error());
        assert!(!MessageKind::SystemInfo.is_error());
        assert!(!MessageKind::ToolStart {
            name: "bash".into()
        }
        .is_error());
        assert!(!MessageKind::ToolOk {
            name: "bash".into()
        }
        .is_error());

        assert!(MessageKind::SystemError.is_error());
        assert!(MessageKind::ToolErr {
            name: "bash".into()
        }
        .is_error());
    }

    #[test]
    fn message_kind_is_thinking_only_for_thinking_variant() {
        assert!(MessageKind::Thinking.is_thinking());
        assert!(!MessageKind::User.is_thinking());
        assert!(!MessageKind::SystemError.is_thinking());
    }

    #[test]
    fn message_kind_tool_name_accessor() {
        assert_eq!(
            MessageKind::ToolStart {
                name: "read_file".into()
            }
            .tool_name(),
            Some("read_file")
        );
        assert_eq!(
            MessageKind::ToolOk {
                name: "write_file".into()
            }
            .tool_name(),
            Some("write_file")
        );
        assert_eq!(
            MessageKind::ToolErr {
                name: "bash".into()
            }
            .tool_name(),
            Some("bash")
        );
        assert_eq!(MessageKind::User.tool_name(), None);
        assert_eq!(MessageKind::SystemInfo.tool_name(), None);
    }

    // ── Role tests ───────────────────────────────────────────────────────────

    #[test]
    fn role_round_trip_via_as_str_and_from_str() {
        for (wire, expected) in [
            ("user", Role::User),
            ("assistant", Role::Assistant),
            ("system", Role::System),
            ("tool", Role::Tool),
        ] {
            let parsed: Role = wire.parse().unwrap();
            assert_eq!(parsed, expected, "parse failed for {wire}");
            assert_eq!(parsed.as_str(), wire, "as_str mismatch for {wire}");
        }
    }

    #[test]
    fn role_unknown_input_falls_back_to_system() {
        let r: Role = "thinking".parse().unwrap();
        assert_eq!(r, Role::System);
        let r2: Role = "".parse().unwrap();
        assert_eq!(r2, Role::System);
    }

    #[test]
    fn role_display_matches_as_str() {
        for role in [Role::User, Role::Assistant, Role::System, Role::Tool] {
            assert_eq!(role.to_string(), role.as_str());
        }
    }

    // ── Mode tests ───────────────────────────────────────────────────────────

    #[test]
    fn mode_toggle_is_involution() {
        assert_eq!(Mode::Build.toggled(), Mode::Plan);
        assert_eq!(Mode::Plan.toggled(), Mode::Build);
    }

    #[test]
    fn mode_round_trip_from_str() {
        assert_eq!("Build".parse::<Mode>().unwrap(), Mode::Build);
        assert_eq!("Plan".parse::<Mode>().unwrap(), Mode::Plan);
        // Unknown falls back to Build
        assert_eq!("unknown".parse::<Mode>().unwrap(), Mode::Build);
    }

    #[test]
    fn mode_display_matches_as_str() {
        assert_eq!(Mode::Build.to_string(), "Build");
        assert_eq!(Mode::Plan.to_string(), "Plan");
    }

    // ── EffortLevel tests ────────────────────────────────────────────────────

    #[test]
    fn effort_level_cycle_is_periodic() {
        assert_eq!(EffortLevel::None.cycled(), EffortLevel::Minimal);
        assert_eq!(EffortLevel::Minimal.cycled(), EffortLevel::Low);
        assert_eq!(EffortLevel::Low.cycled(), EffortLevel::Medium);
        assert_eq!(EffortLevel::Medium.cycled(), EffortLevel::High);
        assert_eq!(EffortLevel::High.cycled(), EffortLevel::Low);
        assert_eq!(EffortLevel::Max.cycled(), EffortLevel::Low);
        assert_eq!(EffortLevel::Auto.cycled(), EffortLevel::Low);
    }

    #[test]
    fn effort_level_round_trip_from_str() {
        assert_eq!("none".parse::<EffortLevel>().unwrap(), EffortLevel::None);
        assert_eq!(
            "minimal".parse::<EffortLevel>().unwrap(),
            EffortLevel::Minimal
        );
        assert_eq!("low".parse::<EffortLevel>().unwrap(), EffortLevel::Low);
        assert_eq!(
            "medium".parse::<EffortLevel>().unwrap(),
            EffortLevel::Medium
        );
        assert_eq!("high".parse::<EffortLevel>().unwrap(), EffortLevel::High);
        assert_eq!("max".parse::<EffortLevel>().unwrap(), EffortLevel::Max);
        assert_eq!("xhigh".parse::<EffortLevel>().unwrap(), EffortLevel::Max);
        assert_eq!("x".parse::<EffortLevel>().unwrap(), EffortLevel::Max);
        assert_eq!("auto".parse::<EffortLevel>().unwrap(), EffortLevel::Auto);
        assert_eq!("unset".parse::<EffortLevel>().unwrap(), EffortLevel::Auto);
        // Unknown falls back to Medium
        assert_eq!(
            "unknown".parse::<EffortLevel>().unwrap(),
            EffortLevel::Medium
        );
    }

    #[test]
    fn effort_level_display_matches_as_str() {
        for level in [
            EffortLevel::None,
            EffortLevel::Minimal,
            EffortLevel::Low,
            EffortLevel::Medium,
            EffortLevel::High,
            EffortLevel::Max,
            EffortLevel::Auto,
        ] {
            assert_eq!(level.to_string(), level.as_str());
        }
    }

    #[test]
    fn effort_level_provider_cycles_include_supported_extremes() {
        assert_eq!(
            EffortLevel::Medium.cycled_for_provider("openai", "gpt-5.5"),
            EffortLevel::High
        );
        assert_eq!(
            EffortLevel::High.cycled_for_provider("openai", "gpt-5.5"),
            EffortLevel::Max
        );
        assert_eq!(
            EffortLevel::Max.cycled_for_provider("openai", "gpt-5.5"),
            EffortLevel::None
        );
        assert_eq!(
            EffortLevel::High.cycled_for_provider("anthropic", "claude-sonnet-4-6"),
            EffortLevel::Max
        );
        assert_eq!(
            EffortLevel::Medium.cycled_for_provider("deepseek", "deepseek-v4-pro"),
            EffortLevel::High
        );
    }

    // ── MessageList integration tests ────────────────────────────────────────

    #[test]
    fn test_add_and_count() {
        let mut ml = MessageList::new();
        ml.add(DisplayMessage::user("hello"));
        assert_eq!(ml.messages.len(), 1);
    }

    #[test]
    fn test_streaming() {
        let mut ml = MessageList::new();
        ml.append_streaming("hello ");
        ml.append_streaming("world");
        assert!(ml.is_streaming);
        assert_eq!(ml.streaming_text, "hello world");
        ml.finish_streaming();
        assert!(!ml.is_streaming);
        assert_eq!(ml.messages.len(), 1);
        assert_eq!(ml.messages[0].content, "hello world");
        assert_eq!(ml.messages[0].kind, MessageKind::Assistant);
    }

    #[test]
    fn thinking_indicator_lifecycle() {
        let mut ml = MessageList::new();
        // No-op when not thinking.
        ml.finish_thinking();
        assert!(!ml.is_thinking_now);
        assert_eq!(ml.messages.len(), 0);

        // Deltas activate the indicator and accumulate hidden buffer.
        ml.push_thinking("first ");
        ml.push_thinking("second");
        assert!(ml.is_thinking_now);
        assert_eq!(ml.thinking_buffer, "first second");

        // Finalize emits a collapsed summary and clears state.
        ml.finish_thinking();
        assert!(!ml.is_thinking_now);
        assert!(ml.thinking_buffer.is_empty());
        assert_eq!(ml.messages.len(), 1);
        assert_eq!(ml.messages[0].kind, MessageKind::Thinking);
        assert!(ml.messages[0].content.starts_with("Thought for "));
    }

    #[test]
    fn live_thinking_renders_streamed_reasoning_text() {
        let mut ml = MessageList::new();
        ml.push_thinking("checking files\n");
        ml.push_thinking("running tests");

        let live_text = ml
            .build_lines()
            .into_iter()
            .flat_map(|line| line.spans.into_iter().map(|span| span.content.into_owned()))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(live_text.contains("Thinking"));
        assert!(live_text.contains("checking files"));
        assert!(live_text.contains("running tests"));

        ml.finish_thinking();
        let finished_text = ml
            .build_lines()
            .into_iter()
            .flat_map(|line| line.spans.into_iter().map(|span| span.content.into_owned()))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(finished_text.contains("Thought for "));
        assert!(!finished_text.contains("checking files"));
        assert!(!finished_text.contains("running tests"));
    }

    #[test]
    fn pop_last_handles_saturating_and_zero_edges() {
        let mut ml = MessageList::new();
        ml.add(DisplayMessage::user("a"));
        ml.add(DisplayMessage::user("b"));
        ml.add(DisplayMessage::user("c"));
        assert_eq!(ml.messages.len(), 3);

        // Edge 1: count == 0 is a no-op (must not touch the list).
        ml.pop_last(0);
        assert_eq!(ml.messages.len(), 3, "count == 0 must leave list intact");

        // Edge 2: count > len saturates at zero (must not panic).
        ml.pop_last(usize::MAX);
        assert_eq!(
            ml.messages.len(),
            0,
            "count > len must truncate to empty without panicking"
        );

        // Sanity: a normal in-range count still works.
        ml.add(DisplayMessage::user("x"));
        ml.add(DisplayMessage::user("y"));
        ml.add(DisplayMessage::user("z"));
        ml.pop_last(2);
        assert_eq!(ml.messages.len(), 1);
        assert_eq!(ml.messages[0].content, "x");
    }

    #[test]
    fn test_scroll() {
        let mut ml = MessageList::new();
        ml.scroll_up(5);
        assert_eq!(ml.scroll_offset, 5);
        ml.scroll_down(3);
        assert_eq!(ml.scroll_offset, 2);
        ml.scroll_to_bottom();
        assert_eq!(ml.scroll_offset, 0);
    }

    #[test]
    fn render_bottom_anchor_counts_wrapped_visual_rows() {
        let mut ml = MessageList::new();
        ml.add(DisplayMessage::assistant(
            "alpha bravo charlie delta echo foxtrot golf hotel india juliet",
        ));

        let backend = TestBackend::new(16, 4);
        let mut terminal = Terminal::new(backend).expect("test backend should initialize");
        terminal
            .draw(|frame| ml.render(frame, frame.area()))
            .expect("message list should render");

        let rows = rendered_rows(terminal.backend());
        assert!(
            rows.iter().any(|row| row.contains("juliet")),
            "bottom-anchored viewport should include the final wrapped row; rows={rows:?}"
        );
        assert!(
            !rows.iter().any(|row| row.contains("Claudia")),
            "wrapped content taller than the viewport should scroll past the header; rows={rows:?}"
        );
    }

    // ── crosslink #482: scroll_offset semantics contract ────────────────────
    //
    // These tests pin down BOTH coordinate systems for the same scroll state:
    // - The native bottom-anchored `scroll_offset` (0 = newest at bottom).
    // - The top-anchored view exposed via `rows_from_top(total)`.

    #[test]
    fn test_scroll_offset_zero_means_bottom() {
        // Native semantics: offset 0 anchors to the bottom; the top-anchored
        // view reports the full `total` because the last visible row is the
        // very last row of the buffer.
        let ml = MessageList::new();
        assert_eq!(ml.scroll_offset, 0, "fresh list starts at bottom");
        assert_eq!(
            ml.rows_from_top(100),
            100,
            "offset=0 ⇒ last visible row index is `total` (bottom edge)"
        );
    }

    #[test]
    fn test_scroll_offset_positive_means_back_in_time() {
        // Scrolling up increases `scroll_offset` and decreases the
        // top-anchored row index, because we are looking at older rows.
        let mut ml = MessageList::new();
        ml.scroll_up(7);
        assert_eq!(
            ml.scroll_offset, 7,
            "scroll_up moves the offset away from 0"
        );
        assert_eq!(
            ml.rows_from_top(50),
            43,
            "offset=7 of total=50 ⇒ bottom edge is row 43 (50-7)"
        );

        // And both views snap back together at the bottom.
        ml.scroll_to_bottom();
        assert_eq!(ml.scroll_offset, 0);
        assert_eq!(ml.rows_from_top(50), 50);
    }

    #[test]
    fn test_rows_from_top_saturates_when_scrolled_past_top() {
        // If the caller scrolled past the available content (e.g. the buffer
        // shrunk after a `pop_last`) the top-anchored helper saturates at 0
        // rather than wrapping, so it stays a valid index.
        let mut ml = MessageList::new();
        ml.scroll_up(200);
        assert_eq!(ml.scroll_offset, 200);
        assert_eq!(
            ml.rows_from_top(10),
            0,
            "offset > total ⇒ top-anchored index clamps at 0"
        );
        // And the conventional "no scrolling needed" case (total fits in
        // viewport, offset is 0) reports `total`, not 0.
        ml.scroll_to_bottom();
        assert_eq!(ml.rows_from_top(0), 0);
        assert_eq!(ml.rows_from_top(3), 3);
    }
}
