//! Keybindings cheat-sheet overlay.
//!
//! Shows a scrollable list of every keyboard shortcut the TUI
//! supports. Port of Claude Code's `/help` overlay — a single
//! discoverable surface for the bindings that would otherwise be
//! buried in the main keybindings file.
//!
//! Input:
//! - `Up` / `Down` / `PageUp` / `PageDown` / `Home` / `End` scroll.
//! - `Esc` / `q` / `?` close.
//! - Anything else is consumed silently (prevents stray key events
//!   from leaking to the underlying input field while the overlay is
//!   open).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use super::{Overlay, OverlayAction};
use crate::slash_commands::TUI_SLASH_SECTIONS;

/// One line in the cheatsheet — a shortcut and what it does.
struct Shortcut {
    keys: &'static str,
    description: &'static str,
}

/// Keybinding-only sections (Input / Navigation / Thinking). Slash
/// commands are sourced from [`crate::slash_commands::TUI_SLASH_SECTIONS`]
/// so this overlay only advertises commands implemented by the default TUI.
const KEYBIND_SECTIONS: &[(&str, &[Shortcut])] = &[
    (
        "Input",
        &[
            Shortcut {
                keys: "Enter",
                description: "send message",
            },
            Shortcut {
                keys: "Shift+Enter / Alt+Enter / Ctrl+J",
                description: "insert newline",
            },
            Shortcut {
                keys: "Backspace / Delete",
                description: "edit input",
            },
            Shortcut {
                keys: "Left / Right / Home / End",
                description: "move input cursor",
            },
            Shortcut {
                keys: "Ctrl+C",
                description: "cancel current turn / exit when idle",
            },
        ],
    ),
    (
        "Navigation",
        &[
            Shortcut {
                keys: "PageUp / PageDown",
                description: "scroll the transcript",
            },
            Shortcut {
                keys: "Up / Down",
                description: "scroll the transcript",
            },
            Shortcut {
                keys: "Esc",
                description: "close overlays, dismiss prompts",
            },
        ],
    ),
    (
        "Thinking",
        &[
            Shortcut {
                keys: "\"ultrathink\"",
                description: "mention in any user message → max thinking budget (31 999)",
            },
            Shortcut {
                keys: "env MAX_THINKING_TOKENS=N",
                description: "force a specific Anthropic thinking budget",
            },
            Shortcut {
                keys: "env CLAUDE_CODE_EFFORT_LEVEL=…",
                description: "low/medium/high/max/auto/unset — overrides the in-session effort",
            },
        ],
    ),
];

/// Keybindings overlay state. Small — just the scroll offset.
#[derive(Debug, Default)]
pub struct HelpOverlay {
    /// Lines scrolled off the top. Clamped against the rendered line
    /// count inside `handle_key` so overflow is a no-op.
    scroll: u16,
    /// Most recent viewport height (rows). Set on each `render` so
    /// key handling can clamp scroll against the actual visible area.
    last_height: u16,
    effective_bindings: Vec<(String, String)>,
    binding_diagnostics: Vec<String>,
}

impl HelpOverlay {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scroll: 0,
            last_height: 0,
            effective_bindings: Vec::new(),
            binding_diagnostics: Vec::new(),
        }
    }

    /// Attach the collision-checked map used by the live TUI resolver.
    #[must_use]
    pub fn with_keybindings(
        mut self,
        effective_bindings: Vec<(String, String)>,
        diagnostics: Vec<String>,
    ) -> Self {
        self.effective_bindings = effective_bindings;
        self.binding_diagnostics = diagnostics;
        self
    }

    /// Flatten the section tree into one `Vec<Line>` for the paragraph
    /// widget. Allocation-per-render is fine — the cheatsheet is <100
    /// lines and this runs once per frame, at human-input cadence.
    ///
    /// Sources:
    /// - Keybinding sections come from [`KEYBIND_SECTIONS`] (TUI-only).
    /// - Slash-command sections come from
    ///   [`crate::slash_commands::TUI_SLASH_SECTIONS`].
    fn build_lines(&self) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(Span::styled(
            "Keyboard shortcuts",
            Style::default()
                .fg(Color::Rgb(147, 112, 219))
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        let section_title_style = Style::default()
            .fg(Color::Rgb(218, 165, 32))
            .add_modifier(Modifier::BOLD);
        let key_style = Style::default()
            .fg(Color::Rgb(100, 180, 255))
            .add_modifier(Modifier::BOLD);
        let desc_style = Style::default().fg(Color::White);

        if !self.effective_bindings.is_empty() {
            lines.push(Line::from(Span::styled("Configured", section_title_style)));
            for (keys, description) in &self.effective_bindings {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(keys.clone(), key_style),
                    Span::raw("  "),
                    Span::styled(description.clone(), desc_style),
                ]));
            }
            lines.push(Line::from(""));
        }
        if !self.binding_diagnostics.is_empty() {
            lines.push(Line::from(Span::styled(
                "Unavailable configured bindings",
                section_title_style,
            )));
            for diagnostic in &self.binding_diagnostics {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(diagnostic.clone(), Style::default().fg(Color::Red)),
                ]));
            }
            lines.push(Line::from(""));
        }

        for (title, shortcuts) in KEYBIND_SECTIONS {
            lines.push(Line::from(Span::styled(*title, section_title_style)));
            for sc in *shortcuts {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(sc.keys, key_style),
                    Span::raw("  "),
                    Span::styled(sc.description, desc_style),
                ]));
            }
            lines.push(Line::from(""));
        }

        // Slash commands implemented by the default TUI.
        for section in TUI_SLASH_SECTIONS {
            lines.push(Line::from(Span::styled(section.title, section_title_style)));
            for c in section.commands {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(c.invocation, key_style),
                    Span::raw("  "),
                    Span::styled(c.description, desc_style),
                ]));
            }
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled(
            "Esc / q / ? to close",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
        lines
    }

    /// Max scroll offset given the current lines and viewport.
    const fn max_scroll(lines: u16, viewport: u16) -> u16 {
        lines.saturating_sub(viewport)
    }
}

impl Overlay for HelpOverlay {
    fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.last_height = area.height.saturating_sub(2); // borders
        let lines = self.build_lines();
        #[allow(clippy::cast_possible_truncation)] // list is tiny
        let total_lines = lines.len() as u16;
        // Clamp scroll to the current viewport so resize doesn't leave
        // us scrolled past the bottom.
        let max = Self::max_scroll(total_lines, self.last_height);
        if self.scroll > max {
            self.scroll = max;
        }
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(147, 112, 219)))
            .title(" help ");
        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));
        frame.render_widget(paragraph, area);
    }

    fn handle_key(&mut self, key: KeyEvent) -> OverlayAction {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | '?') => OverlayAction::Close,
            // Ctrl+C closes too (matches CC dismiss semantics).
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                OverlayAction::Close
            }
            KeyCode::Up => {
                self.scroll = self.scroll.saturating_sub(1);
                OverlayAction::Consumed
            }
            KeyCode::Down => {
                self.scroll = self.scroll.saturating_add(1);
                OverlayAction::Consumed
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(self.last_height.max(1));
                OverlayAction::Consumed
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(self.last_height.max(1));
                OverlayAction::Consumed
            }
            KeyCode::Home => {
                self.scroll = 0;
                OverlayAction::Consumed
            }
            KeyCode::End => {
                // Actual max is clamped on the next render.
                self.scroll = u16::MAX;
                OverlayAction::Consumed
            }
            _ => OverlayAction::Consumed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn esc_q_question_mark_close_overlay() {
        let mut overlay = HelpOverlay::new();
        assert_eq!(overlay.handle_key(key(KeyCode::Esc)), OverlayAction::Close);
        assert_eq!(
            overlay.handle_key(key(KeyCode::Char('q'))),
            OverlayAction::Close
        );
        assert_eq!(
            overlay.handle_key(key(KeyCode::Char('?'))),
            OverlayAction::Close
        );
        assert_eq!(
            overlay.handle_key(ctrl(KeyCode::Char('c'))),
            OverlayAction::Close
        );
    }

    #[test]
    fn arrows_scroll_and_saturate_at_zero() {
        let mut overlay = HelpOverlay::new();
        assert_eq!(overlay.scroll, 0);
        // Up at zero shouldn't underflow.
        overlay.handle_key(key(KeyCode::Up));
        assert_eq!(overlay.scroll, 0);
        overlay.handle_key(key(KeyCode::Down));
        overlay.handle_key(key(KeyCode::Down));
        assert_eq!(overlay.scroll, 2);
        overlay.handle_key(key(KeyCode::Up));
        assert_eq!(overlay.scroll, 1);
    }

    #[test]
    fn home_resets_end_maxes_out() {
        let mut overlay = HelpOverlay::new();
        overlay.handle_key(key(KeyCode::End));
        assert_eq!(overlay.scroll, u16::MAX);
        overlay.handle_key(key(KeyCode::Home));
        assert_eq!(overlay.scroll, 0);
    }

    #[test]
    fn sections_non_empty() {
        // Guard: if someone deletes the cheatsheet by accident, this
        // test fails rather than shipping an empty overlay. Covers both
        // the keybinding-only sections (local) and the TUI slash-command table.
        assert!(!KEYBIND_SECTIONS.is_empty());
        for (title, shortcuts) in KEYBIND_SECTIONS {
            assert!(!title.is_empty());
            assert!(!shortcuts.is_empty(), "section {title} has no shortcuts");
        }
        assert!(!TUI_SLASH_SECTIONS.is_empty());
        for section in TUI_SLASH_SECTIONS {
            assert!(!section.title.is_empty());
            assert!(
                !section.commands.is_empty(),
                "slash section {} has no entries",
                section.title
            );
        }
    }

    /// The TUI slash-command table must feed the rendered overlay. If
    /// the overlay drifts back to the legacy REPL catalogue, this test
    /// catches it before users see unsupported commands in `/help`.
    #[test]
    fn rendered_lines_include_tui_slash_commands_only() {
        let lines = HelpOverlay::new().build_lines();
        let rendered: String = lines
            .into_iter()
            .flat_map(|l| l.spans.into_iter().map(|s| s.content.into_owned()))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            rendered.contains("TUI Slash Commands"),
            "rendered overlay missing TUI slash section title"
        );
        assert!(
            rendered.contains("/load <id>"),
            "rendered overlay missing a representative TUI command"
        );
        assert!(
            rendered.contains("/model <name>"),
            "rendered overlay missing the default-TUI model switch command"
        );
        assert!(
            !rendered.contains("/connect"),
            "rendered overlay must not advertise legacy REPL-only commands"
        );
        assert!(
            rendered.contains("Shift+Enter / Alt+Enter / Ctrl+J"),
            "rendered overlay must advertise implemented multiline input shortcuts"
        );
        assert!(
            !rendered.contains("Ctrl+L"),
            "rendered overlay must not advertise unimplemented TUI shortcuts"
        );
        assert!(
            !rendered.contains("previous / next input in history"),
            "rendered overlay must describe Up/Down as transcript scrolling"
        );
    }

    #[test]
    fn rendered_lines_include_effective_bindings_and_collision_diagnostics() {
        let lines = HelpOverlay::new()
            .with_keybindings(
                vec![("f6".to_string(), "Show help".to_string())],
                vec!["colliding keybinding chord 'ctrl-x'".to_string()],
            )
            .build_lines();
        let rendered = lines
            .into_iter()
            .flat_map(|line| line.spans.into_iter().map(|span| span.content.into_owned()))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("Configured"));
        assert!(rendered.contains("f6"));
        assert!(rendered.contains("Show help"));
        assert!(rendered.contains("Unavailable configured bindings"));
        assert!(rendered.contains("colliding keybinding chord 'ctrl-x'"));
    }
}
