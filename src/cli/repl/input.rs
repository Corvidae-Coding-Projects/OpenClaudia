use std::collections::HashSet;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

#[cfg(test)]
use std::fs;

const MAX_REPL_ATTACHMENT_REFERENCES: usize = 8;
const MAX_REPL_ATTACHMENT_FILE_BYTES: usize = 16 * 1024;
const MAX_REPL_ATTACHMENT_TOTAL_BYTES: usize = 32 * 1024;
const MAX_REPL_ATTACHMENT_TOTAL_TOKENS: usize = 32 * 1024;
const REPL_ATTACHMENT_TOKEN_OVERHEAD: usize = 256;
const MAX_REPL_ATTACHMENT_PROJECTED_BYTES: usize = MAX_REPL_ATTACHMENT_TOTAL_BYTES
    + MAX_REPL_ATTACHMENT_REFERENCES * REPL_ATTACHMENT_TOKEN_OVERHEAD;
const MAX_EXTERNAL_EDITOR_INPUT_BYTES: usize = 64 * 1024;
const EXTERNAL_EDITOR_TIMEOUT: Duration = Duration::from_mins(30);
const FILE_REF_PATTERN: &str = r#"(?:^|\s)@"([^"]+)"|(?:^|\s)@([^\s@]+)"#;

static FILE_REF_RE: std::sync::LazyLock<Option<regex::Regex>> =
    std::sync::LazyLock::new(|| match regex::Regex::new(FILE_REF_PATTERN) {
        Ok(regex) => Some(regex),
        Err(error) => {
            tracing::warn!(
                pattern = FILE_REF_PATTERN,
                error = %error,
                "Invalid legacy REPL file-reference regex; @file loading disabled",
            );
            None
        }
    });

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
    let mut tokens = editor_command_tokens(editor)?;
    let program = run
        .resolve_executable(tokens.remove(0))
        .map_err(|error| error.to_string())?;
    let args = tokens.into_iter().map(OsString::from).collect::<Vec<_>>();
    openclaudia::tools::execute_user_editor(
        run,
        &program,
        &args,
        target_file,
        EXTERNAL_EDITOR_TIMEOUT,
    )
    .map(openclaudia::tools::UserEditorExecution::into_status)
    .map_err(|error| error.to_string())
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
    let temp_file = match tempfile::Builder::new()
        .prefix("openclaudia-editor-")
        .suffix(".txt")
        .tempfile_in(run.private_temp_root())
    {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Failed to create run-owned editor input: {error}\n");
            return None;
        }
    };
    let configured = run
        .environment_grants()
        .with_value("VISUAL", str::to_owned)
        .or_else(|| run.environment_grants().with_value("EDITOR", str::to_owned));
    let editor = configured.unwrap_or_else(|| {
        #[cfg(windows)]
        let fallback = "notepad";
        #[cfg(not(windows))]
        let fallback = "vim";
        fallback.to_string()
    });
    println!("\nOpening supervised external editor...");

    match run_external_editor(run, &editor, temp_file.path()) {
        Ok(status) if status.success() => {
            if let Some(receipt) = run.runtime().cancellation().receipt() {
                eprintln!(
                    "External editor input was cancelled before review: {:?}\n",
                    receipt.reason
                );
                return None;
            }
            let snapshot = openclaudia::tools::read_bounded_capability_text_attachment(
                run,
                &temp_file.path().to_string_lossy(),
                MAX_EXTERNAL_EDITOR_INPUT_BYTES,
            );
            if let Some(receipt) = run.runtime().cancellation().receipt() {
                eprintln!(
                    "External editor input was cancelled during review: {:?}\n",
                    receipt.reason
                );
                return None;
            }
            match snapshot {
                Ok((_, content)) if content.trim().is_empty() => {
                    println!("Editor closed with empty content.\n");
                    None
                }
                Ok((_, content)) if attachment_text_is_binary(&content) => {
                    eprintln!("External editor input was rejected as binary control data.\n");
                    None
                }
                Ok((_, content)) => Some(content),
                Err(error) => {
                    let safe = run.sanitize_diagnostic(&error);
                    eprintln!("External editor input was rejected: {safe}\n");
                    None
                }
            }
        }
        Ok(_) => {
            eprintln!("Editor exited with error.\n");
            None
        }
        Err(error) => {
            let safe = run.sanitize_diagnostic(&error);
            eprintln!("Failed to open editor: {safe}\n");
            None
        }
    }
}

/// Prepared legacy input keeps user instruction bytes separate from untrusted
/// file snapshots.
#[derive(Debug)]
pub struct PreparedReplInput {
    instruction: String,
    attachment_projection: Option<openclaudia::context::ContextProjection>,
}

impl PreparedReplInput {
    #[must_use]
    pub fn into_parts(self) -> (String, Option<openclaudia::context::ContextProjection>) {
        (self.instruction, self.attachment_projection)
    }
}

/// Typed refusal from legacy `@file` attachment preparation.
#[derive(Debug, thiserror::Error)]
pub enum ReplAttachmentError {
    #[error("prompt contains {count} file references; the limit is {limit}")]
    TooManyReferences { count: usize, limit: usize },
    #[error("legacy attachment {path:?} was rejected: {reason}")]
    Rejected { path: String, reason: String },
    #[error("legacy attachment budget rejected {path:?}: {reason}")]
    Budget { path: String, reason: String },
    #[error("legacy attachment loading was cancelled: {reason:?}")]
    Cancelled {
        reason: openclaudia::runtime::CancellationReason,
    },
}

fn parse_file_references(input: &str) -> Vec<String> {
    if !input.contains('@') {
        return Vec::new();
    }
    let Some(regex) = (*FILE_REF_RE).as_ref() else {
        return Vec::new();
    };
    regex
        .captures_iter(input)
        .filter_map(|capture| capture.get(1).or_else(|| capture.get(2)))
        .map(|path| path.as_str().to_string())
        .collect()
}

fn attachment_text_is_binary(content: &str) -> bool {
    content.chars().any(|character| {
        character == '\0' || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    })
}

/// Prepare `@file` references as snapshot-bound reference context.
///
/// The returned instruction is byte-for-byte the submitted user text. File
/// content is projected separately with reference authority and cannot gain
/// instruction authority through interpolation.
///
/// # Errors
///
/// Refuses the complete preparation on capability, containment, encoding,
/// binary-data, stable-snapshot, byte/token-budget, or cancellation failure.
#[allow(clippy::too_many_lines)] // Admission, stable reads, budgets, and projection are one fail-closed transaction.
pub fn expand_file_references(
    run: &openclaudia::tools::ToolRunContext,
    input: &str,
) -> Result<PreparedReplInput, ReplAttachmentError> {
    let references = parse_file_references(input);
    if references.is_empty() {
        return Ok(PreparedReplInput {
            instruction: input.to_string(),
            attachment_projection: None,
        });
    }
    if references.len() > MAX_REPL_ATTACHMENT_REFERENCES {
        return Err(ReplAttachmentError::TooManyReferences {
            count: references.len(),
            limit: MAX_REPL_ATTACHMENT_REFERENCES,
        });
    }

    let cancellation = run.runtime().cancellation();
    if let Some(receipt) = cancellation.receipt() {
        return Err(ReplAttachmentError::Cancelled {
            reason: receipt.reason,
        });
    }
    let workspace = &run.runtime().descriptor().workspace;
    let mut raw_paths = HashSet::new();
    let mut canonical_paths = HashSet::new();
    let mut reserved_bytes = 0usize;
    let mut reserved_tokens = 0usize;
    let mut items = Vec::new();

    for raw_path in references {
        if !raw_paths.insert(raw_path.clone()) {
            continue;
        }
        if let Some(receipt) = cancellation.receipt() {
            return Err(ReplAttachmentError::Cancelled {
                reason: receipt.reason,
            });
        }
        let (canonical_path, content) =
            openclaudia::tools::read_bounded_capability_text_attachment(
                run,
                &raw_path,
                MAX_REPL_ATTACHMENT_FILE_BYTES,
            )
            .map_err(|reason| ReplAttachmentError::Rejected {
                path: raw_path.clone(),
                reason,
            })?;
        if !canonical_path.starts_with(workspace.root()) {
            return Err(ReplAttachmentError::Rejected {
                path: raw_path,
                reason: format!(
                    "canonical path is outside workspace {}",
                    workspace.root().display()
                ),
            });
        }
        if !canonical_paths.insert(canonical_path.clone()) {
            continue;
        }
        let relative_path = canonical_path
            .strip_prefix(workspace.root())
            .map_err(|error| ReplAttachmentError::Rejected {
                path: canonical_path.to_string_lossy().into_owned(),
                reason: error.to_string(),
            })?;
        let relative_label = relative_path
            .to_str()
            .ok_or_else(|| ReplAttachmentError::Rejected {
                path: canonical_path.to_string_lossy().into_owned(),
                reason: "workspace-relative path is not valid UTF-8".to_string(),
            })?
            .to_string();
        if attachment_text_is_binary(&content) {
            return Err(ReplAttachmentError::Rejected {
                path: relative_label,
                reason: "content contains binary control data".to_string(),
            });
        }
        let file_bytes = content.len();
        let next_bytes =
            reserved_bytes
                .checked_add(file_bytes)
                .ok_or_else(|| ReplAttachmentError::Budget {
                    path: relative_label.clone(),
                    reason: "aggregate byte reservation overflowed".to_string(),
                })?;
        if next_bytes > MAX_REPL_ATTACHMENT_TOTAL_BYTES {
            return Err(ReplAttachmentError::Budget {
                path: relative_label,
                reason: format!(
                    "aggregate size would be {next_bytes} bytes; limit is {MAX_REPL_ATTACHMENT_TOTAL_BYTES}"
                ),
            });
        }
        let file_tokens = file_bytes.saturating_add(REPL_ATTACHMENT_TOKEN_OVERHEAD);
        let next_tokens = reserved_tokens.checked_add(file_tokens).ok_or_else(|| {
            ReplAttachmentError::Budget {
                path: relative_label.clone(),
                reason: "aggregate token reservation overflowed".to_string(),
            }
        })?;
        if next_tokens > MAX_REPL_ATTACHMENT_TOTAL_TOKENS {
            return Err(ReplAttachmentError::Budget {
                path: relative_label,
                reason: format!(
                    "aggregate reservation would be {next_tokens} tokens; limit is {MAX_REPL_ATTACHMENT_TOTAL_TOKENS}"
                ),
            });
        }
        reserved_bytes = next_bytes;
        reserved_tokens = next_tokens;
        if let Some(receipt) = cancellation.receipt() {
            return Err(ReplAttachmentError::Cancelled {
                reason: receipt.reason,
            });
        }

        let bytes = content.as_bytes();
        let file_generation = openclaudia::runtime::ContentDigest::sha256(bytes);
        let context_id = format!("legacy.attachment.{}.{}", items.len(), file_generation);
        let origin = serde_json::to_string(&serde_json::json!({
            "kind": "workspace_file_snapshot",
            "frontend": "legacy_repl",
            "path": relative_label,
            "workspace_generation": workspace.generation,
            "workspace_digest": workspace.digest,
            "capability_generation": run.generation(),
            "file_generation": file_generation,
            "byte_len": bytes.len(),
            "sensitivity": "workspace",
            "encoding": "utf-8",
            "truncation": "context_budget_if_needed"
        }))
        .map_err(|error| ReplAttachmentError::Rejected {
            path: relative_label.clone(),
            reason: format!("cannot encode attachment provenance: {error}"),
        })?;
        let model_content = if content.is_empty() {
            "[empty UTF-8 file]".to_string()
        } else {
            content
        };
        items.push(
            openclaudia::context::ContextItem::reference(
                context_id,
                openclaudia::context::ReferenceSource::Project,
                origin,
                model_content,
                openclaudia::context::ContextFreshness::Snapshot {
                    generation: workspace.generation.get(),
                },
                500,
            )
            .with_sensitivity(openclaudia::context::ContextSensitivity::Internal),
        );
    }

    let projection = openclaudia::context::ContextProjector::project(
        items,
        openclaudia::context::ContextBudget {
            max_system_bytes: 0,
            max_reference_bytes: MAX_REPL_ATTACHMENT_PROJECTED_BYTES,
            max_total_tokens: MAX_REPL_ATTACHMENT_TOTAL_TOKENS,
            max_item_bytes: MAX_REPL_ATTACHMENT_FILE_BYTES + REPL_ATTACHMENT_TOKEN_OVERHEAD,
        },
    );
    if let Some(omitted) = projection.trace.entries.iter().find(|entry| {
        matches!(
            &entry.disposition,
            openclaudia::context::ContextDisposition::Omitted { .. }
        )
    }) {
        return Err(ReplAttachmentError::Budget {
            path: omitted.origin.clone(),
            reason: "reserved reference context could not be projected".to_string(),
        });
    }
    tracing::info!(
        event = "legacy_repl.attachments.projected",
        capability_generation = run.generation().get(),
        workspace_generation = workspace.generation.get(),
        reserved_bytes,
        reserved_tokens,
        trace = ?projection.trace,
        "Projected descriptor-bound legacy attachments as untrusted reference context",
    );
    Ok(PreparedReplInput {
        instruction: input.to_string(),
        attachment_projection: Some(projection),
    })
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

        let own_expansion =
            expand_file_references(&run, "inspect @own.txt").expect("owned attachment");
        let (instruction, projection) = own_expansion.into_parts();
        assert_eq!(instruction, "inspect @own.txt");
        assert!(projection
            .expect("reference projection")
            .reference
            .contains("OWN_ATTACHMENT"));

        let foreign_reference =
            format!("inspect @{}", foreign.path().join("foreign.txt").display());
        let foreign_error = expand_file_references(&run, &foreign_reference)
            .expect_err("foreign attachment must fail closed");
        let diagnostic = foreign_error.to_string();
        assert!(!diagnostic.contains("FOREIGN_SECRET"));
        assert!(matches!(
            foreign_error,
            ReplAttachmentError::Rejected { .. }
        ));
    }

    #[test]
    fn file_references_reject_binary_and_oversized_content_without_projection() {
        let root = tempfile::TempDir::new().expect("root");
        fs::write(root.path().join("binary.txt"), b"safe\0hidden").expect("binary fixture");
        fs::write(
            root.path().join("oversized.txt"),
            vec![b'x'; MAX_REPL_ATTACHMENT_FILE_BYTES + 1],
        )
        .expect("oversized fixture");
        let run = attachment_run(root.path());

        assert!(matches!(
            expand_file_references(&run, "inspect @binary.txt"),
            Err(ReplAttachmentError::Rejected { .. })
        ));
        assert!(matches!(
            expand_file_references(&run, "inspect @oversized.txt"),
            Err(ReplAttachmentError::Rejected { .. })
        ));
    }

    #[test]
    fn repl_editor_windows_shell_uses_resolved_cmd() {
        let source = include_str!("input.rs");
        let cfg_test = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"cmd\")")
                && !production.contains("std::process::Command::new(\"cmd\")"),
            "external editor wrapper must not invoke bare cmd"
        );
        assert!(
            production.contains(".resolve_executable("),
            "external editor wrapper must resolve the parsed executable through the immutable run"
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
