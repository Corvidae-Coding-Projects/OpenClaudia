//! Typed tool-result display.  Presentation follows [`ToolDisplay`] and never
//! scans ordinary text for control or diff markers.

use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::ExecutableCommand;
use openclaudia::tools::{ToolDisplay, ToolResult};
use std::io;

use super::diff;

/// Display a tool result in the terminal with per-tool formatting.
pub fn display_tool_result(result: &ToolResult) {
    let mut stdout = io::stdout();
    let content = result.content();

    if matches!(result.display(), ToolDisplay::Hidden) || content.is_empty() {
        return;
    }

    if result.is_error() {
        let _ = stdout.execute(SetForegroundColor(Color::Red));
        print_limited(&mut stdout, content, 30);
        let _ = stdout.execute(ResetColor);
        return;
    }

    if let ToolDisplay::Diff {
        summary,
        diff: data,
    } = result.display()
    {
        diff::render_color_diff(&data.path, &data.old_text, &data.new_text);
        if !summary.trim().is_empty() {
            let _ = stdout.execute(SetForegroundColor(Color::Green));
            let _ = stdout.execute(Print(format!("    {}\n", summary.trim())));
            let _ = stdout.execute(ResetColor);
        }
        return;
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
    let color = match result.handler() {
        "write_file" | "edit_file" => Color::Green,
        "bash" | "bash_output" => Color::White,
        _ => Color::DarkGrey,
    };

    let _ = stdout.execute(SetForegroundColor(color));
    print_limited(&mut stdout, content, max_lines);
    let _ = stdout.execute(ResetColor);
}

fn print_limited(stdout: &mut io::Stdout, content: &str, max_lines: usize) {
    let lines: Vec<&str> = content.lines().collect();
    let show = max_lines.min(lines.len());
    for line in &lines[..show] {
        let _ = stdout.execute(Print(format!("    {line}\n")));
    }
    if lines.len() > show {
        let _ = stdout.execute(SetForegroundColor(Color::DarkGrey));
        let _ = stdout.execute(Print(format!(
            "    ... ({} more lines)\n",
            lines.len() - show
        )));
    }
}
