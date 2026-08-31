//! Shared admission and sanitization for text rendered in a terminal.
//!
//! Terminal text is data.  Callers apply a finite [`TextLimits`] budget before
//! Markdown, diff, wrapping, or widget construction, and this module converts
//! terminal and bidirectional controls to visible inert glyphs.  Host-owned
//! styling is applied only after sanitization.

use std::fmt::Write as _;

/// Marker appended when a rendering budget omits part of a value.
pub const RENDER_TRUNCATION_MARKER: &str = " … [rendering truncated]";

/// Admission limits applied before terminal-oriented parsing or layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextLimits {
    /// Maximum bytes inspected from the untrusted input.
    pub max_input_bytes: usize,
    /// Maximum bytes retained after visible control expansion.
    pub max_output_bytes: usize,
    /// Maximum logical lines retained.
    pub max_lines: usize,
    /// Maximum input bytes retained from one logical line.
    pub max_line_bytes: usize,
}

impl TextLimits {
    /// Construct an explicit rendering budget.
    #[must_use]
    pub const fn new(
        max_input_bytes: usize,
        max_output_bytes: usize,
        max_lines: usize,
        max_line_bytes: usize,
    ) -> Self {
        Self {
            max_input_bytes,
            max_output_bytes,
            max_lines,
            max_line_bytes,
        }
    }
}

/// General event/message projection limit.
pub const EVENT_TEXT_LIMITS: TextLimits = TextLimits::new(64 * 1024, 96 * 1024, 1024, 4096);
/// Complete Markdown document limit, applied before inline parsing.
pub const MARKDOWN_TEXT_LIMITS: TextLimits = TextLimits::new(256 * 1024, 384 * 1024, 4096, 4096);
/// One path, identifier, title, or other single-line label.
pub const LABEL_TEXT_LIMITS: TextLimits = TextLimits::new(2048, 4096, 1, 2048);
/// A streamed reasoning projection retained by the TUI.
pub const THINKING_TEXT_LIMITS: TextLimits = TextLimits::new(64 * 1024, 96 * 1024, 1024, 4096);
/// A streamed assistant projection retained by the TUI.
pub const STREAM_TEXT_LIMITS: TextLimits = TextLimits::new(256 * 1024, 384 * 1024, 4096, 4096);

/// Sanitized terminal text and whether admission omitted any input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedText {
    text: String,
    truncated: bool,
}

impl SanitizedText {
    /// Borrow the inert display value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Consume the wrapper and return the inert display value.
    #[must_use]
    pub fn into_string(self) -> String {
        self.text
    }

    /// Whether an admission limit omitted input.
    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

/// Sanitize multi-line terminal text within an explicit pre-layout budget.
#[must_use]
pub fn sanitize_terminal_text(input: &str, limits: TextLimits) -> SanitizedText {
    sanitize(input, limits, true)
}

/// Sanitize a label or path as one inert visible line.
///
/// Newlines are encoded as control pictures rather than creating forged UI
/// rows.  ANSI/OSC introducers, C0/C1 controls, and bidi controls are likewise
/// visible data.
#[must_use]
pub fn sanitize_terminal_label(input: &str) -> SanitizedText {
    sanitize(input, LABEL_TEXT_LIMITS, false)
}

/// Append a raw protocol fragment without allowing an accumulator to grow
/// beyond `max_bytes`.
///
/// This is for buffers that must remain byte-exact until a later typed parser
/// runs.  Display buffers should use [`sanitize_terminal_text`] instead.
/// Returns `true` when all or part of the fragment was omitted.
pub fn append_raw_bounded(target: &mut String, fragment: &str, max_bytes: usize) -> bool {
    if target.len() >= max_bytes {
        return !fragment.is_empty();
    }
    let remaining = max_bytes - target.len();
    if fragment.len() <= remaining {
        target.push_str(fragment);
        return false;
    }
    let end = floor_char_boundary(fragment, remaining);
    target.push_str(&fragment[..end]);
    true
}

fn sanitize(input: &str, limits: TextLimits, preserve_newlines: bool) -> SanitizedText {
    if limits.max_input_bytes == 0
        || limits.max_output_bytes == 0
        || limits.max_lines == 0
        || limits.max_line_bytes == 0
    {
        return SanitizedText {
            text: bounded_marker(limits.max_output_bytes),
            truncated: !input.is_empty(),
        };
    }

    let content_budget = limits
        .max_output_bytes
        .saturating_sub(RENDER_TRUNCATION_MARKER.len());
    let mut output = String::with_capacity(input.len().min(content_budget));
    let mut inspected_bytes = 0usize;
    let mut line_bytes = 0usize;
    let mut lines = 1usize;
    let mut truncated = false;

    for character in input.chars() {
        let character_bytes = character.len_utf8();
        if inspected_bytes.saturating_add(character_bytes) > limits.max_input_bytes {
            truncated = true;
            break;
        }

        if character == '\n' && preserve_newlines {
            if lines >= limits.max_lines || output.len().saturating_add(1) > content_budget {
                truncated = true;
                break;
            }
            output.push('\n');
            inspected_bytes += 1;
            lines += 1;
            line_bytes = 0;
            continue;
        }

        if line_bytes.saturating_add(character_bytes) > limits.max_line_bytes {
            truncated = true;
            break;
        }

        let visible = visible_character(character, preserve_newlines);
        if output.len().saturating_add(visible.len()) > content_budget {
            truncated = true;
            break;
        }
        output.push_str(&visible);
        inspected_bytes += character_bytes;
        line_bytes += character_bytes;
    }

    if inspected_bytes < input.len() {
        truncated = true;
    }
    if truncated {
        output.push_str(&bounded_marker(
            limits.max_output_bytes.saturating_sub(output.len()),
        ));
    }

    SanitizedText {
        text: output,
        truncated,
    }
}

fn visible_character(character: char, preserve_newlines: bool) -> String {
    match character {
        '\n' if preserve_newlines => "\n".to_string(),
        '\0'..='\u{001f}' => char::from_u32(0x2400 + u32::from(character))
            .unwrap_or('\u{fffd}')
            .to_string(),
        '\u{007f}' => "␡".to_string(),
        '\u{0080}'..='\u{009f}' if character != '\u{0085}' => unicode_escape(character),
        '\u{0085}'
        | '\u{061c}'
        | '\u{200e}'
        | '\u{200f}'
        | '\u{2028}'
        | '\u{2029}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{206f}' => unicode_escape(character),
        _ => character.to_string(),
    }
}

fn unicode_escape(character: char) -> String {
    let mut visible = String::with_capacity(12);
    let _ = write!(visible, "⟦U+{:04X}⟧", u32::from(character));
    visible
}

fn bounded_marker(max_bytes: usize) -> String {
    let end = floor_char_boundary(RENDER_TRUNCATION_MARKER, max_bytes);
    RENDER_TRUNCATION_MARKER[..end].to_string()
}

fn floor_char_boundary(value: &str, requested: usize) -> usize {
    let mut end = requested.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_terminal_and_bidi_controls_render_as_visible_data() {
        let rendered = sanitize_terminal_text(
            "safe\u{1b}]0;forged\u{7}\nright\u{202e}left\r",
            EVENT_TEXT_LIMITS,
        );

        assert!(!rendered.as_str().contains('\u{1b}'));
        assert!(!rendered.as_str().contains('\u{7}'));
        assert!(!rendered.as_str().contains('\u{202e}'));
        assert!(rendered.as_str().contains('␛'));
        assert!(rendered.as_str().contains("⟦U+202E⟧"));
        assert!(rendered.as_str().contains('␍'));
    }

    #[test]
    fn labels_cannot_create_terminal_rows() {
        let rendered = sanitize_terminal_label("first\nsecond\t\u{1b}[31m");

        assert_eq!(rendered.as_str().lines().count(), 1);
        assert!(rendered.as_str().contains('␊'));
        assert!(rendered.as_str().contains('␉'));
        assert!(rendered.as_str().contains('␛'));
    }

    #[test]
    fn admission_stops_before_parsing_oversized_lines() {
        let limits = TextLimits::new(64, 64, 4, 8);
        let rendered = sanitize_terminal_text("12345678EXCESS\nsecond", limits);

        assert!(rendered.was_truncated());
        assert!(rendered.as_str().len() <= limits.max_output_bytes);
        assert!(rendered.as_str().starts_with("12345678"));
        assert!(rendered.as_str().contains("truncated"));
    }

    #[test]
    fn raw_bounded_append_keeps_utf8_valid() {
        let mut target = "a".to_string();
        assert!(append_raw_bounded(&mut target, "éclair", 4));
        assert_eq!(target, "aéc");
        assert_eq!(target.len(), 4);
    }
}
