//! Typed tool-result display.  Presentation follows [`ToolDisplay`] and never
//! scans ordinary text for control or diff markers.

use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::ExecutableCommand;
use openclaudia::tools::{ToolDisplay, ToolResult};
use openclaudia::tui::safety::{
    sanitize_terminal_label, sanitize_terminal_text, EVENT_TEXT_LIMITS,
};
use std::io;

use super::diff;

/// Display a tool result in the terminal with per-tool formatting.
///
/// # Errors
///
/// Returns the first terminal write error.
pub fn display_tool_result(result: &ToolResult) -> io::Result<()> {
    let mut stdout = io::stdout();
    let content = result.content();

    if matches!(result.display(), ToolDisplay::Hidden) || content.is_empty() {
        return Ok(());
    }

    if result.is_error() {
        stdout.execute(SetForegroundColor(Color::Red))?;
        print_limited(&mut stdout, content, 30)?;
        stdout.execute(ResetColor)?;
        return Ok(());
    }

    if let ToolDisplay::Diff {
        summary,
        diff: data,
    } = result.display()
    {
        diff::render_color_diff(&data.path, &data.old_text, &data.new_text)?;
        if !summary.trim().is_empty() {
            let summary = sanitize_terminal_text(summary.trim(), EVENT_TEXT_LIMITS);
            stdout.execute(SetForegroundColor(Color::Green))?;
            stdout.execute(Print(format!("    {}\n", summary.as_str())))?;
            stdout.execute(ResetColor)?;
        }
        return Ok(());
    }

    let max_lines = match result.display() {
        ToolDisplay::Text { max_lines } => *max_lines,
        ToolDisplay::Auto | ToolDisplay::Diff { .. } | ToolDisplay::Hidden => {
            match result.handler() {
                "bash" | "bash_output" => 25,
                "read_file" | "grep" | "glob" | "list_files" => 15,
                "write_file" => 3,
                _ => 20,
            }
        }
    };
    let handler = sanitize_terminal_label(result.handler());
    let color = match handler.as_str() {
        "write_file" | "edit_file" => Color::Green,
        "bash" | "bash_output" => Color::White,
        _ => Color::DarkGrey,
    };

    stdout.execute(SetForegroundColor(color))?;
    print_limited(&mut stdout, content, max_lines)?;
    stdout.execute(ResetColor)?;
    Ok(())
}

fn print_limited(stdout: &mut io::Stdout, content: &str, max_lines: usize) -> io::Result<()> {
    let content = sanitize_terminal_text(content, EVENT_TEXT_LIMITS);
    let mut lines = content.as_str().lines();
    for line in lines.by_ref().take(max_lines) {
        stdout.execute(Print(format!("    {line}\n")))?;
    }
    if lines.next().is_some() || content.was_truncated() {
        stdout.execute(SetForegroundColor(Color::DarkGrey))?;
        stdout.execute(Print("    … (additional output omitted)\n"))?;
    }
    Ok(())
}
