use std::fs;
use std::path::Path;

#[cfg(windows)]
fn resolved_process_command(
    run: &openclaudia::tools::ToolRunContext,
    binary: &str,
) -> Result<std::process::Command, String> {
    run.resolve_executable(binary)
        .map(std::process::Command::new)
        .map_err(|error| error.to_string())
}

#[cfg(not(windows))]
fn editor_command_tokens(editor: &str) -> Result<Vec<String>, String> {
    let tokens =
        shlex::split(editor).ok_or_else(|| format!("could not parse editor command: {editor}"))?;
    if tokens.is_empty() {
        return Err("editor command is empty".to_string());
    }
    Ok(tokens)
}

pub fn run_external_editor(
    run: &openclaudia::tools::ToolRunContext,
    editor: &str,
    target_file: &Path,
) -> Result<std::process::ExitStatus, String> {
    #[cfg(windows)]
    {
        let target = target_file.to_string_lossy();
        resolved_process_command(run, "cmd").and_then(|mut command| {
            command.env_clear();
            run.environment_grants().apply_std(&mut command);
            command
                .env("PATH", run.executable_search_path())
                .current_dir(run.working_directory())
                .args(["/C", editor, target.as_ref()])
                .status()
                .map_err(|e| e.to_string())
        })
    }

    #[cfg(not(windows))]
    {
        let mut tokens = editor_command_tokens(editor)?;
        let program = tokens.remove(0);
        let program = run
            .resolve_executable(&program)
            .map_err(|error| error.to_string())?;
        let mut command = std::process::Command::new(program);
        command.env_clear();
        run.environment_grants().apply_std(&mut command);
        command
            .env("PATH", run.executable_search_path())
            .current_dir(run.working_directory())
            .args(tokens)
            .arg(target_file)
            .status()
            .map_err(|e| e.to_string())
    }
}

/// Display structured questions to the user and collect answers.
/// Returns a JSON string mapping question text to selected answer(s).
#[allow(clippy::too_many_lines)]
pub fn handle_user_questions(questions: &[openclaudia::tools::ToolQuestion]) -> String {
    use std::io::{self, Write};

    const MAX_ANSWER_BYTES: usize = 4096;

    let mut answers: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    for q in questions {
        let question_text = openclaudia::tui::safety::sanitize_terminal_text(
            &q.question,
            openclaudia::tui::safety::EVENT_TEXT_LIMITS,
        );
        let header = openclaudia::tui::safety::sanitize_terminal_label(&q.header);

        // Display the question
        println!(
            "\n\x1b[1;36m?\x1b[0m {}  \x1b[90m[{}]\x1b[0m",
            question_text.as_str(),
            header.as_str()
        );

        // Display options
        for (i, opt) in q.options.iter().enumerate() {
            let label = openclaudia::tui::safety::sanitize_terminal_label(&opt.label);
            let desc = openclaudia::tui::safety::sanitize_terminal_text(
                &opt.description,
                openclaudia::tui::safety::EVENT_TEXT_LIMITS,
            );
            println!(
                "  \x1b[1m{}.\x1b[0m {} \x1b[90m- {}\x1b[0m",
                i + 1,
                label.as_str(),
                desc.as_str()
            );
        }
        // Always append "Other" option
        let other_num = q.options.len() + 1;
        println!("  \x1b[1m{other_num}.\x1b[0m Other \x1b[90m(type your answer)\x1b[0m");

        if q.multi_select {
            print!("\x1b[36m> \x1b[0m\x1b[90m(comma-separated numbers) \x1b[0m");
        } else {
            print!("\x1b[36m> \x1b[0m");
        }
        io::stdout().flush().ok();

        let Ok(input) = read_bounded_terminal_line(&mut stdin, MAX_ANSWER_BYTES) else {
            answers.insert(
                q.question.clone(),
                serde_json::Value::String("(no input)".to_string()),
            );
            continue;
        };
        let input = input.trim();

        if q.multi_select {
            let mut selected: Vec<serde_json::Value> = Vec::new();
            for part in input.split(',') {
                let part = part.trim();
                if let Ok(num) = part.parse::<usize>() {
                    if num >= 1 && num <= q.options.len() {
                        if let Some(opt) = q.options.get(num - 1) {
                            selected.push(serde_json::Value::String(opt.label.clone()));
                        }
                    } else if num == other_num {
                        print!("  \x1b[36mYour answer: \x1b[0m");
                        io::stdout().flush().ok();
                        if let Ok(other_input) =
                            read_bounded_terminal_line(&mut stdin, MAX_ANSWER_BYTES)
                        {
                            selected
                                .push(serde_json::Value::String(other_input.trim().to_string()));
                        }
                    }
                }
            }
            answers.insert(q.question.clone(), serde_json::Value::Array(selected));
        } else if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= q.options.len() {
                if let Some(opt) = q.options.get(num - 1) {
                    answers.insert(
                        q.question.clone(),
                        serde_json::Value::String(opt.label.clone()),
                    );
                }
            } else if num == other_num {
                print!("  \x1b[36mYour answer: \x1b[0m");
                io::stdout().flush().ok();
                if let Ok(other_input) = read_bounded_terminal_line(&mut stdin, MAX_ANSWER_BYTES) {
                    answers.insert(
                        q.question.clone(),
                        serde_json::Value::String(other_input.trim().to_string()),
                    );
                }
            } else {
                answers.insert(
                    q.question.clone(),
                    serde_json::Value::String(input.to_string()),
                );
            }
        } else {
            answers.insert(
                q.question.clone(),
                serde_json::Value::String(input.to_string()),
            );
        }
    }

    serde_json::Value::Object(answers).to_string()
}

fn read_bounded_terminal_line<R: std::io::BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<String> {
    let mut bytes = Vec::with_capacity(max_bytes.min(1024));
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let line_end = available.iter().position(|byte| *byte == b'\n');
        let consumed = line_end.map_or(available.len(), |position| position + 1);
        let content_end = line_end.unwrap_or(available.len());
        let remaining = max_bytes.saturating_sub(bytes.len());
        bytes.extend_from_slice(&available[..content_end.min(remaining)]);
        reader.consume(consumed);
        if line_end.is_some() {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Open external editor for composing a message
pub fn open_external_editor(run: &openclaudia::tools::ToolRunContext) -> Option<String> {
    let temp_file = run
        .private_temp_root()
        .join(format!("openclaudia_{}.txt", uuid::Uuid::new_v4()));

    let configured = run
        .environment_grants()
        .with_value("VISUAL", |editor| {
            run_external_editor(run, editor, &temp_file)
        })
        .or_else(|| {
            run.environment_grants().with_value("EDITOR", |editor| {
                run_external_editor(run, editor, &temp_file)
            })
        });
    let status = configured.map_or_else(
        || {
            #[cfg(windows)]
            let editor = "notepad";
            #[cfg(not(windows))]
            let editor = "vim";
            println!("\nOpening {editor}...");
            run_external_editor(run, editor, &temp_file)
        },
        |status| {
            println!("\nOpening configured editor...");
            status
        },
    );

    match status {
        Ok(s) if s.success() => fs::read_to_string(&temp_file).map_or_else(
            |_| {
                println!("No content entered.\n");
                None
            },
            |content| {
                let _ = fs::remove_file(&temp_file);
                let trimmed = content.trim().to_string();
                if trimmed.is_empty() {
                    println!("Editor closed with empty content.\n");
                    None
                } else {
                    Some(trimmed)
                }
            },
        ),
        Ok(_) => {
            eprintln!("Editor exited with error.\n");
            let _ = fs::remove_file(&temp_file);
            None
        }
        Err(e) => {
            let safe = run.environment_grants().sanitize_diagnostic(&e);
            eprintln!("Failed to open editor: {safe}\n");
            None
        }
    }
}

/// Expand `@file` references through the exact run filesystem capability.
pub fn expand_file_references(run: &openclaudia::tools::ToolRunContext, input: &str) -> String {
    use regex::Regex;

    let Ok(re) = Regex::new(r#"@"([^"]+)"|@(\S+)"#) else {
        return input.to_string();
    };

    let mut result = input.to_string();
    let mut replacements = Vec::new();

    for cap in re.captures_iter(input) {
        let Some(full_match) = cap.get(0) else {
            continue;
        };
        let full_match = full_match.as_str();
        let Some(raw_path) = cap.get(1).or_else(|| cap.get(2)) else {
            continue;
        };
        let raw_path = raw_path.as_str();

        match openclaudia::tools::read_capability_text_attachment(run, raw_path) {
            Ok((resolved, content)) => {
                let file_context = format!(
                    "\n<file path=\"{}\">\n{}\n</file>\n",
                    resolved.display(),
                    content.trim()
                );
                replacements.push((full_match.to_string(), file_context));
            }
            Err(error) => {
                eprintln!("Warning: Could not read {raw_path}: {error}");
                replacements.push((
                    full_match.to_string(),
                    format!("[Cannot read {raw_path}: {error}]"),
                ));
            }
        }
    }

    for (from, to) in replacements {
        result = result.replace(&from, &to);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attachment_run(root: &Path) -> std::sync::Arc<openclaudia::tools::ToolRunContext> {
        openclaudia::tools::ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
            .workspace_access(openclaudia::tools::WorkspaceAccess::ReadOnly)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .process(false)
            .network(false)
            .secrets(false)
            .provider("repl-input-test")
            .build()
            .expect("attachment run")
    }

    #[test]
    fn file_references_are_bound_to_the_exact_run_root() {
        let own = tempfile::TempDir::new().expect("own root");
        let foreign = tempfile::TempDir::new().expect("foreign root");
        fs::write(own.path().join("own.txt"), "OWN_ATTACHMENT").expect("own fixture");
        fs::write(foreign.path().join("foreign.txt"), "FOREIGN_SECRET").expect("foreign fixture");
        let run = attachment_run(own.path());

        let own_expansion = expand_file_references(&run, "inspect @own.txt");
        assert!(own_expansion.contains("OWN_ATTACHMENT"));

        let foreign_reference =
            format!("inspect @{}", foreign.path().join("foreign.txt").display());
        let foreign_expansion = expand_file_references(&run, &foreign_reference);
        assert!(!foreign_expansion.contains("FOREIGN_SECRET"));
        assert!(foreign_expansion.contains("Cannot read"));
    }

    #[test]
    fn repl_editor_windows_shell_uses_resolved_cmd() {
        let source = include_str!("input.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"cmd\")")
                && !production.contains("std::process::Command::new(\"cmd\")"),
            "external editor wrapper must not invoke bare cmd"
        );
        assert!(
            production.contains("run.resolve_executable(binary)"),
            "external editor wrapper must resolve cmd through the immutable run"
        );
        assert!(
            !production.contains("Command::new(&editor)")
                && !production.contains("std::process::Command::new(&editor)"),
            "external editor wrapper must parse EDITOR specs instead of treating them as a literal executable"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn editor_command_tokens_preserve_editor_arguments() {
        let tokens = editor_command_tokens(r"code --wait --reuse-window").expect("tokens");
        assert_eq!(tokens, vec!["code", "--wait", "--reuse-window"]);
    }

    #[cfg(not(windows))]
    #[test]
    fn editor_command_tokens_handles_quoted_editor_path() {
        let tokens =
            editor_command_tokens(r#""/opt/Visual Studio Code/bin/code" --wait"#).expect("tokens");
        assert_eq!(tokens, vec!["/opt/Visual Studio Code/bin/code", "--wait"]);
    }

    #[cfg(not(windows))]
    #[test]
    fn editor_command_tokens_rejects_malformed_quotes() {
        let err = editor_command_tokens(r#"code "--wait"#).expect_err("malformed editor spec");
        assert!(
            err.contains("could not parse editor command"),
            "unexpected error: {err}"
        );
    }
}
