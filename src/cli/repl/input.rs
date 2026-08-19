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
            command
                .env_clear()
                .envs(run.environment_grants())
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
        std::process::Command::new(program)
            .env_clear()
            .envs(run.environment_grants())
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
pub fn handle_user_questions(questions: &[serde_json::Value]) -> String {
    use std::io::{self, Write};

    let mut answers: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    for q in questions {
        let question_text = q.get("question").and_then(|v| v.as_str()).unwrap_or("?");
        let header = q.get("header").and_then(|v| v.as_str()).unwrap_or("");
        let options = q
            .get("options")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        // crosslink #585: the validator in `tools::ask_user` canonicalises
        // the input key to `multiSelect` (CC's spelling). Read that first;
        // fall back to the legacy `multi_select` only for callers that bypass
        // the validator (back-compat). Without this fix the flag is silently
        // dropped whenever `ask_user_question` normalises a `multiSelect`
        // input, leaving the renderer stuck in single-select mode.
        let multi_select = q
            .get("multiSelect")
            .or_else(|| q.get("multi_select"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        // Display the question
        println!("\n\x1b[1;36m?\x1b[0m {question_text}  \x1b[90m[{header}]\x1b[0m");

        // Display options
        for (i, opt) in options.iter().enumerate() {
            let label = opt.get("label").and_then(|v| v.as_str()).unwrap_or("?");
            let desc = opt
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            println!(
                "  \x1b[1m{}.\x1b[0m {} \x1b[90m- {}\x1b[0m",
                i + 1,
                label,
                desc
            );
        }
        // Always append "Other" option
        let other_num = options.len() + 1;
        println!("  \x1b[1m{other_num}.\x1b[0m Other \x1b[90m(type your answer)\x1b[0m");

        if multi_select {
            print!("\x1b[36m> \x1b[0m\x1b[90m(comma-separated numbers) \x1b[0m");
        } else {
            print!("\x1b[36m> \x1b[0m");
        }
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            answers.insert(
                question_text.to_string(),
                serde_json::Value::String("(no input)".to_string()),
            );
            continue;
        }
        let input = input.trim();

        if multi_select {
            let mut selected: Vec<serde_json::Value> = Vec::new();
            for part in input.split(',') {
                let part = part.trim();
                if let Ok(num) = part.parse::<usize>() {
                    if num >= 1 && num <= options.len() {
                        if let Some(opt) = options.get(num - 1) {
                            let label = opt.get("label").and_then(|v| v.as_str()).unwrap_or("?");
                            selected.push(serde_json::Value::String(label.to_string()));
                        }
                    } else if num == other_num {
                        print!("  \x1b[36mYour answer: \x1b[0m");
                        io::stdout().flush().ok();
                        let mut other_input = String::new();
                        if io::stdin().read_line(&mut other_input).is_ok() {
                            selected
                                .push(serde_json::Value::String(other_input.trim().to_string()));
                        }
                    }
                }
            }
            answers.insert(
                question_text.to_string(),
                serde_json::Value::Array(selected),
            );
        } else if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= options.len() {
                if let Some(opt) = options.get(num - 1) {
                    let label = opt.get("label").and_then(|v| v.as_str()).unwrap_or("?");
                    answers.insert(
                        question_text.to_string(),
                        serde_json::Value::String(label.to_string()),
                    );
                }
            } else if num == other_num {
                print!("  \x1b[36mYour answer: \x1b[0m");
                io::stdout().flush().ok();
                let mut other_input = String::new();
                if io::stdin().read_line(&mut other_input).is_ok() {
                    answers.insert(
                        question_text.to_string(),
                        serde_json::Value::String(other_input.trim().to_string()),
                    );
                }
            } else {
                answers.insert(
                    question_text.to_string(),
                    serde_json::Value::String(input.to_string()),
                );
            }
        } else {
            answers.insert(
                question_text.to_string(),
                serde_json::Value::String(input.to_string()),
            );
        }
    }

    serde_json::Value::Object(answers).to_string()
}

/// Open external editor for composing a message
pub fn open_external_editor(run: &openclaudia::tools::ToolRunContext) -> Option<String> {
    let editor = run
        .environment_grants()
        .get("VISUAL")
        .or_else(|| run.environment_grants().get("EDITOR"))
        .cloned()
        .unwrap_or_else(|| {
            #[cfg(windows)]
            {
                "notepad".to_string()
            }
            #[cfg(not(windows))]
            {
                "vim".to_string()
            }
        });

    let temp_file = run
        .private_temp_root()
        .join(format!("openclaudia_{}.txt", uuid::Uuid::new_v4()));

    println!("\nOpening {editor}...");

    let status = run_external_editor(run, &editor, &temp_file);

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
            eprintln!("Failed to open editor '{editor}': {e}\n");
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
