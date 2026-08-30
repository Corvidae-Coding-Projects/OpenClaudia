//! Color diff rendering for file edits.

use crossterm::style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor};
use crossterm::ExecutableCommand;
use openclaudia::tui::safety::{sanitize_terminal_text, TextLimits};
use similar::{ChangeTag, TextDiff};
use std::io;

const DIFF_INPUT_LIMITS: TextLimits = TextLimits::new(64 * 1024, 96 * 1024, 1024, 4096);
const MAX_RENDERED_DIFF_LINES: usize = 800;

/// Render a word-level color diff between old and new text.
///
/// Diff inputs are admitted and sanitized before `similar` constructs its edit
/// graph.  The fixed input and output-node ceilings make malformed or hostile
/// edits a display concern rather than an unbounded compute path.
///
/// # Errors
///
/// Returns the first terminal write error.
pub fn render_color_diff(path: &str, old_text: &str, new_text: &str) -> io::Result<()> {
    let mut stdout = io::stdout();
    let path = openclaudia::tui::safety::sanitize_terminal_label(path).into_string();
    let old_text = sanitize_terminal_text(old_text, DIFF_INPUT_LIMITS);
    let new_text = sanitize_terminal_text(new_text, DIFF_INPUT_LIMITS);

    // Header
    stdout.execute(SetForegroundColor(Color::DarkGrey))?;
    stdout.execute(Print(format!("  ── {path} ")))?;
    stdout.execute(ResetColor)?;
    stdout.execute(Print("\n"))?;

    // similar 3.x changed `from_lines` from `<T>` to `<Old, New, T>`. Let
    // inference resolve all three (str slices for old/new, char-level T).
    let diff = TextDiff::from_lines(old_text.as_str(), new_text.as_str());
    let mut rendered_lines = 0usize;

    for (idx, group) in diff.grouped_ops(3).iter().enumerate() {
        if rendered_lines >= MAX_RENDERED_DIFF_LINES {
            break;
        }
        if idx > 0 {
            stdout.execute(SetForegroundColor(Color::DarkGrey))?;
            stdout.execute(Print("  ···\n"))?;
            stdout.execute(ResetColor)?;
            rendered_lines += 1;
        }

        for op in group {
            for change in diff.iter_inline_changes(op) {
                if rendered_lines >= MAX_RENDERED_DIFF_LINES {
                    break;
                }
                let (sign, line_color) = match change.tag() {
                    ChangeTag::Delete => ("-", Color::Red),
                    ChangeTag::Insert => ("+", Color::Green),
                    ChangeTag::Equal => (" ", Color::Reset),
                };

                // Line number gutter
                if let Some(line_no) = change.old_index().or_else(|| change.new_index()) {
                    stdout.execute(SetForegroundColor(Color::DarkGrey))?;
                    stdout.execute(Print(format!("  {:>4} ", line_no + 1)))?;
                }

                stdout.execute(SetForegroundColor(line_color))?;
                stdout.execute(Print(sign))?;
                stdout.execute(Print(" "))?;

                // Word-level highlighting within changed lines
                for (emphasized, value) in change.iter_strings_lossy() {
                    if emphasized {
                        match change.tag() {
                            ChangeTag::Delete => {
                                stdout.execute(SetBackgroundColor(Color::DarkRed))?;
                                stdout.execute(SetForegroundColor(Color::White))?;
                            }
                            ChangeTag::Insert => {
                                stdout.execute(SetBackgroundColor(Color::DarkGreen))?;
                                stdout.execute(SetForegroundColor(Color::White))?;
                            }
                            ChangeTag::Equal => {}
                        }
                        stdout.execute(Print(&value))?;
                        stdout.execute(ResetColor)?;
                        stdout.execute(SetForegroundColor(line_color))?;
                    } else {
                        stdout.execute(Print(&value))?;
                    }
                }

                stdout.execute(ResetColor)?;
                // Ensure newline if the change doesn't end with one
                if change.missing_newline() {
                    stdout.execute(Print("\n"))?;
                }
                rendered_lines += 1;
            }
        }
    }

    if rendered_lines >= MAX_RENDERED_DIFF_LINES
        || old_text.was_truncated()
        || new_text.was_truncated()
    {
        stdout.execute(SetForegroundColor(Color::DarkGrey))?;
        stdout.execute(Print("  … [diff rendering truncated]\n"))?;
        stdout.execute(ResetColor)?;
    }
    Ok(())
}
