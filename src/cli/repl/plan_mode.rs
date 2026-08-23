use super::input::{handle_user_questions, run_external_editor};
use super::{AgentMode, Session};
use openclaudia::tools;
use sha2::{Digest as _, Sha256};

struct ApprovedPlanBinding {
    task_id: String,
    generation: u64,
    digest: String,
}

fn approved_plan_digest(plan_content: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = Sha256::digest(plan_content.as_bytes());
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn bind_approved_plan(
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    plan_content: &str,
) -> Result<ApprovedPlanBinding, String> {
    let digest = approved_plan_digest(plan_content);
    let plan_id = format!("plan-{}", chat_session.id());
    let mut manager = task_manager
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let task_id = manager
        .reconcile_approved_plan(&plan_id, digest.clone())?
        .id
        .clone();
    Ok(ApprovedPlanBinding {
        task_id,
        generation: manager.generation().get(),
        digest,
    })
}

/// Restore the agent mode captured at plan-mode entry (crosslink #618).
///
/// Returns the snapshotted `previous_mode` decoded from
/// [`openclaudia::session::PlanModeState::previous_mode`], falling back to
/// `Build` when:
/// * the session entered plan mode before the #618 field existed, or
/// * the snapshot token is unrecognised (forwards-compat: an older binary
///   reading a session saved by a newer one).
///
/// The fallback matches the pre-#618 behaviour so the worst case is a
/// graceful degradation, never a panic or a wrong mode flip.
fn restore_previous_mode(plan_state: Option<&openclaudia::session::PlanModeState>) -> AgentMode {
    plan_state
        .and_then(|s| s.previous_mode.as_deref())
        .map_or(AgentMode::Build, AgentMode::from_token)
}

fn plan_mode_allowed_tools_display() -> String {
    openclaudia::session::PLAN_MODE_ALLOWED_TOOLS.join(", ")
}

/// Handle entering plan mode. Creates plan file and sets up state.
pub fn handle_enter_plan_mode(run: &tools::ToolRunContext, chat_session: &Session) -> String {
    let plan_file = match openclaudia::session::install_interactive_plan_mode(run, chat_session) {
        Ok(plan_file) => plan_file,
        Err(error) => return format!("Failed to enter plan mode: {error}"),
    };

    println!(
        "\n\x1b[1;33m>> Entered Plan Mode\x1b[0m\n\
         \x1b[90mWrite-access tools are now blocked.\n\
         Use write_file to write to: {}\n\
         Call exit_plan_mode when your plan is ready.\x1b[0m\n",
        plan_file.display()
    );

    format!(
        "Plan mode activated. Plan file: {}. \
         Available tools: {}. \
         Use write_file ONLY to write to the plan file at the path shown above. \
         Call exit_plan_mode when you are ready to present the plan for approval.",
        plan_file.display(),
        plan_mode_allowed_tools_display()
    )
}

fn handle_plan_edit(
    run: &tools::ToolRunContext,
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    plan_state: &openclaudia::session::PlanModeState,
    allowed_prompts: &[tools::ToolAllowedPrompt],
) -> (String, bool) {
    use std::io::{self, Write};
    let configured = run.environment_grants().with_value("EDITOR", |editor| {
        run_external_editor(run, editor, &plan_state.plan_file)
    });
    let edit_result = configured.map_or_else(
        || {
            println!("\n\x1b[90mOpening plan in vi...\x1b[0m");
            run_external_editor(run, "vi", &plan_state.plan_file)
        },
        |result| {
            println!("\n\x1b[90mOpening plan in configured editor...\x1b[0m");
            result
        },
    );
    match edit_result {
        Ok(status) if status.success() => {
            let edited_content = match tools::read_capability_text_attachment(
                run,
                &plan_state.plan_file.to_string_lossy(),
            ) {
                Ok((_, content)) => content,
                Err(error) => {
                    return (format!("Failed to read the edited plan: {error}"), false);
                }
            };
            println!("\n\x1b[1;36m## Edited Plan\x1b[0m\n");
            println!("{edited_content}");
            println!();
            print!("\x1b[1;33mApprove edited plan? [y/n]: \x1b[0m");
            io::stdout().flush().ok();
            let mut input2 = String::new();
            if io::stdin().read_line(&mut input2).is_err() {
                return ("Failed to read user input.".to_string(), false);
            }
            if input2.trim().to_lowercase().starts_with('y') {
                let binding = match bind_approved_plan(chat_session, task_manager, &edited_content)
                {
                    Ok(binding) => binding,
                    Err(error) => {
                        return (
                            format!(
                                "Plan approval could not be committed to the canonical task graph: {error}. Still in plan mode."
                            ),
                            false,
                        );
                    }
                };
                let restored = chat_session.inspect_state(|state| {
                    restore_previous_mode(state.conversation.plan_mode.as_ref())
                });
                chat_session.set_agent_mode(restored);
                println!("\n\x1b[1;32m>> Plan Approved - Returning to Build Mode\x1b[0m\n");
                chat_session.update_state(|state, events| {
                    state.conversation.plan_mode = None;
                    state.conversation.approved_plan = Some(edited_content.clone());
                    state.conversation.messages.push(serde_json::json!({
                        "role": "system",
                        "content": format!(
                            "[Approved Implementation Plan (edited by user)]\n\
                             The user has edited and approved the following plan. Execute it step by step.\n\n{}\n\n{}",
                            edited_content,
                            if allowed_prompts.is_empty() { String::new() }
                            else { format!("Allowed operations:\n{}", allowed_prompts.iter().map(|p| format!("- {}: {}", p.tool, p.prompt)).collect::<Vec<_>>().join("\n")) }
                        ),
                        "metadata": {
                            "openclaudia_context_source": "user_approved_plan",
                            "canonical_task_id": binding.task_id,
                            "canonical_task_graph_generation": binding.generation,
                            "approved_plan_digest": binding.digest
                        }
                    }));
                    events.push(openclaudia::state::StateEvent::MessageAppended {
                        role: "system".to_string(),
                    });
                });
                ("Plan edited and approved by user. Full tool access restored. Proceed with implementation according to the edited plan.".to_string(), true)
            } else {
                println!("\n\x1b[1;31m>> Plan Rejected - Staying in Plan Mode\x1b[0m\n");
                (
                    "Edited plan rejected by user. Still in plan mode. Revise and try again."
                        .to_string(),
                    false,
                )
            }
        }
        Ok(_) => (
            "Editor exited with error. Plan unchanged. Still in plan mode.".to_string(),
            false,
        ),
        Err(e) => {
            let safe = run.environment_grants().sanitize_diagnostic(&e);
            println!("\x1b[31mFailed to open editor: {safe}\x1b[0m");
            (
                "Failed to open editor. Still in plan mode.".to_string(),
                false,
            )
        }
    }
}

fn approve_plan(
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    plan_content: &str,
    allowed_prompts: &[tools::ToolAllowedPrompt],
) -> (String, bool) {
    let binding = match bind_approved_plan(chat_session, task_manager, plan_content) {
        Ok(binding) => binding,
        Err(error) => {
            return (
                format!(
                    "Plan approval could not be committed to the canonical task graph: {error}. Still in plan mode."
                ),
                false,
            );
        }
    };
    let restored = chat_session
        .inspect_state(|state| restore_previous_mode(state.conversation.plan_mode.as_ref()));
    chat_session.set_agent_mode(restored);
    println!(
        "\n\x1b[1;32m>> Plan Approved - Returning to Build Mode\x1b[0m\n\
         \x1b[90mFull tool access restored. Plan injected as context.\x1b[0m\n"
    );
    chat_session.update_state(|state, events| {
        state.conversation.plan_mode = None;
        state.conversation.approved_plan = Some(plan_content.to_string());
        state.conversation.messages.push(serde_json::json!({
            "role": "system",
            "content": format!(
                "[Approved Implementation Plan]\n\
                 The user has approved the following plan. Execute it step by step.\n\n{}\n\n{}",
                plan_content,
                if allowed_prompts.is_empty() {
                    String::new()
                } else {
                    format!(
                        "Allowed operations:\n{}",
                        allowed_prompts
                            .iter()
                            .map(|prompt| format!("- {}: {}", prompt.tool, prompt.prompt))
                            .collect::<Vec<_>>()
                            .join("\n")
                    )
                }
            ),
            "metadata": {
                "openclaudia_context_source": "user_approved_plan",
                "canonical_task_id": binding.task_id,
                "canonical_task_graph_generation": binding.generation,
                "approved_plan_digest": binding.digest
            }
        }));
        events.push(openclaudia::state::StateEvent::MessageAppended {
            role: "system".to_string(),
        });
    });
    (
        "Plan approved by user. Full tool access restored. Proceed with implementation according to the plan.".to_string(),
        true,
    )
}

/// Handle exiting plan mode. Reads plan file, shows to user for approval.
/// Returns (`result_text`, `should_exit_plan_mode`).
pub fn handle_exit_plan_mode(
    run: &tools::ToolRunContext,
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    allowed_prompts: &[tools::ToolAllowedPrompt],
) -> (String, bool) {
    use std::io::{self, Write};

    let plan_mode = chat_session.inspect_state(|state| state.conversation.plan_mode.clone());
    let plan_state = match &plan_mode {
        Some(state) if state.active => state.clone(),
        _ => {
            return ("Not currently in plan mode.".to_string(), false);
        }
    };

    let plan_content = match tools::read_capability_text_attachment(
        run,
        &plan_state.plan_file.to_string_lossy(),
    ) {
        Ok((_, content)) => content,
        Err(error) => {
            return (
                format!(
                    "Failed to read plan file {}: {}",
                    plan_state.plan_file.display(),
                    error
                ),
                false,
            );
        }
    };

    println!("\n\x1b[1;36m{}\x1b[0m", "=".repeat(60));
    println!("\x1b[1;36m## Implementation Plan\x1b[0m\n");
    println!("{plan_content}");
    println!("\x1b[1;36m{}\x1b[0m\n", "=".repeat(60));
    print!("\x1b[1;33mApprove? [y/n/edit]: \x1b[0m");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return ("Failed to read user input.".to_string(), false);
    }
    let input = input.trim().to_lowercase();

    match input.as_str() {
        "y" | "yes" => approve_plan(chat_session, task_manager, &plan_content, allowed_prompts),
        "n" | "no" => {
            println!(
                "\n\x1b[1;31m>> Plan Rejected - Staying in Plan Mode\x1b[0m\n\
                 \x1b[90mRevise the plan and try again.\x1b[0m\n"
            );

            (
                "Plan rejected by user. You are still in plan mode. Please revise the plan based on user feedback and call exit_plan_mode again when ready.".to_string(),
                false,
            )
        }
        "edit" | "e" => handle_plan_edit(
            run,
            chat_session,
            task_manager,
            &plan_state,
            allowed_prompts,
        ),
        _ => {
            println!("\x1b[90mUnrecognized input. Staying in plan mode.\x1b[0m");
            (
                "Unrecognized response. Still in plan mode. Call exit_plan_mode again when ready."
                    .to_string(),
                false,
            )
        }
    }
}

/// Restore the runtime capability profile after an approved plan.
///
/// Session state is committed by [`handle_exit_plan_mode`] first; this keeps
/// the runtime authority and persisted behavioral/coordinator mode aligned.
pub fn restore_runtime_after_plan(
    run: &tools::ToolRunContext,
    chat_session: &Session,
    coordinator: bool,
) -> Result<(), String> {
    let mode = if coordinator {
        openclaudia::modes::RuntimeMode::Coordinator
    } else {
        openclaudia::modes::RuntimeMode::Behavioral(chat_session.behavior_mode())
    };
    run.transition_runtime_mode(mode).map(|_| ())
}

/// Check if a tool call is blocked by plan mode and return an error message if so.
pub fn check_plan_mode_restriction(
    chat_session: &Session,
    tool_name: &str,
    tool_args: &str,
) -> Option<String> {
    let plan_mode = chat_session.inspect_state(|state| state.conversation.plan_mode.clone());
    let plan_state = match &plan_mode {
        Some(state) if state.active => state,
        _ => return None,
    };

    let args = match parse_plan_mode_tool_args(tool_name, tool_args) {
        Ok(args) => args,
        Err(msg) => return Some(msg),
    };

    // Use the canonical plan_realpath pinned at entry, NOT the
    // user-facing plan_file: re-resolving plan_file at check time is
    // the cwd-swap bypass crosslink #334 closes.
    if openclaudia::session::is_tool_allowed_in_plan_mode(
        tool_name,
        &plan_state.plan_realpath,
        &args,
    ) {
        None
    } else {
        Some(format!(
            "Tool '{}' is not available in plan mode. \
             Available tools: {}. \
             You can use write_file ONLY to write to the plan file at: {}",
            tool_name,
            plan_mode_allowed_tools_display(),
            plan_state.plan_file.display()
        ))
    }
}

fn parse_plan_mode_tool_args(
    tool_name: &str,
    tool_args: &str,
) -> Result<serde_json::Value, String> {
    let value = serde_json::from_str::<serde_json::Value>(tool_args)
        .map_err(|e| format!("Invalid tool arguments JSON for '{tool_name}': {e}"))?;
    if !value.is_object() {
        return Err(format!(
            "Invalid tool arguments JSON for '{tool_name}': expected a JSON object, got {}",
            json_value_type_name(&value)
        ));
    }
    Ok(value)
}

const fn json_value_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Process a trusted typed follow-up and retain its resolved state in the
/// result passed to provider continuation. Ordinary text is never inspected.
pub fn process_tool_follow_up(
    run: &tools::ToolRunContext,
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    result: &tools::ToolResult,
    coordinator: bool,
) -> tools::ToolResult {
    let (content, response) = match result.follow_up() {
        tools::ToolFollowUp::None => return result.clone(),
        tools::ToolFollowUp::UserQuestion { questions, .. } => {
            let widget_questions: Vec<serde_json::Value> = questions
                .iter()
                .map(tools::ToolQuestion::widget_value)
                .collect();
            let answers = handle_user_questions(&widget_questions);
            let response = serde_json::from_str(&answers)
                .unwrap_or_else(|_| serde_json::Value::String(answers.clone()));
            (answers, response)
        }
        tools::ToolFollowUp::EnterPlanMode { .. } => {
            let message = handle_enter_plan_mode(run, chat_session);
            (message.clone(), serde_json::Value::String(message))
        }
        tools::ToolFollowUp::ExitPlanMode {
            allowed_prompts, ..
        } => {
            let (message, approved) =
                handle_exit_plan_mode(run, chat_session, task_manager, allowed_prompts);
            if approved {
                if let Err(error) = restore_runtime_after_plan(run, chat_session, coordinator) {
                    let message = format!(
                        "Plan was approved, but restoring runtime capabilities failed: {error}"
                    );
                    return result
                        .resolve_follow_up(
                            message.clone(),
                            serde_json::json!({"message": message, "approved": false}),
                        )
                        .expect("trusted pending follow-up must resolve exactly once");
                }
            }
            (
                message.clone(),
                serde_json::json!({"message": message, "approved": approved}),
            )
        }
    };
    result
        .resolve_follow_up(content, response)
        .expect("trusted pending follow-up must resolve exactly once")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openclaudia::session::PlanModeState;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn entering_plan_mode_creates_only_the_exact_session_plan_capability() {
        let project = tempfile::tempdir().expect("plan project");
        let session = Session::new("model", "provider");
        let session_id = openclaudia::state::SessionId::from_raw(session.id())
            .expect("session id must be UUID-shaped");
        let run = tools::ToolRunContext::builder(session_id, project.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(tools::WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .provider("plan-test")
            .build()
            .expect("plan run");

        let result = handle_enter_plan_mode(&run, &session);
        assert!(result.contains("Plan mode activated"), "{result}");
        assert_eq!(
            run.runtime_mode().class,
            openclaudia::modes::RuntimeModeClass::Plan
        );
        assert!(run.agent_plan_file().is_file());
        assert!(run.permits_write(run.agent_plan_file()));
        assert!(run.is_denied_path(&project.path().join(".openclaudia/config.yaml")));
        assert!(run.is_denied_path(&project.path().join(".openclaudia/plans/foreign-session.md")));
        let stored = session
            .inspect_state(|state| state.conversation.plan_mode.clone())
            .expect("plan state");
        assert_eq!(stored.plan_realpath, run.agent_plan_file());

        let second = handle_enter_plan_mode(&run, &session);
        assert!(second.contains("Plan mode activated"), "{second}");
        assert_eq!(
            session.inspect_state(|state| {
                state
                    .conversation
                    .plan_mode
                    .as_ref()
                    .and_then(|plan| plan.previous_mode.clone())
            }),
            Some(AgentMode::Build.as_token().to_string()),
            "idempotent re-entry must retain the original mode"
        );
    }

    fn make_plan_state(prev: Option<&str>) -> PlanModeState {
        let dir = TempDir::new().expect("tempdir");
        let plan = dir.path().join("plan.md");
        std::fs::write(&plan, "# plan\n").expect("write");
        // Leak the dir so the file lives long enough for `state.plan_realpath`
        // to remain valid for the duration of the test. The temp dir is
        // GC'd at process exit.
        Box::leak(Box::new(dir));
        PlanModeState::enter_with_previous_mode(plan, prev.map(str::to_string))
            .expect("enter must succeed")
    }

    fn chat_session_in_plan_mode() -> Session {
        let session = Session::new_with_behavior_mode(
            "claude-sonnet-4-6",
            "anthropic",
            openclaudia::modes::BehaviorMode::default(),
        );
        session.set_agent_mode(AgentMode::Plan);
        session.update_state(|state, _| {
            state.conversation.plan_mode = Some(make_plan_state(None));
        });
        session
    }

    #[test]
    fn check_plan_mode_restriction_reports_malformed_tool_args() {
        let session = chat_session_in_plan_mode();
        let msg = check_plan_mode_restriction(&session, "read_file", "{not json")
            .expect("malformed args must be rejected explicitly");

        assert!(msg.contains("Invalid tool arguments JSON"), "{msg}");
        assert!(msg.contains("read_file"), "{msg}");
    }

    #[test]
    fn check_plan_mode_restriction_reports_non_object_tool_args() {
        let session = chat_session_in_plan_mode();
        let msg = check_plan_mode_restriction(&session, "read_file", "[]")
            .expect("non-object args must be rejected explicitly");

        assert!(msg.contains("expected a JSON object"), "{msg}");
        assert!(msg.contains("array"), "{msg}");
    }

    #[test]
    fn check_plan_mode_restriction_still_allows_read_only_object_args() {
        let session = chat_session_in_plan_mode();
        let path = session.inspect_state(|state| {
            state
                .conversation
                .plan_mode
                .as_ref()
                .expect("plan mode")
                .plan_realpath
                .clone()
        });
        let args = serde_json::json!({"path": path}).to_string();

        assert_eq!(
            check_plan_mode_restriction(&session, "read_file", &args),
            None
        );
    }

    #[test]
    fn check_plan_mode_restriction_message_lists_compiled_allowed_tools() {
        let session = chat_session_in_plan_mode();
        let msg = check_plan_mode_restriction(&session, "bash", "{}")
            .expect("mutating tool must be blocked in plan mode");

        for tool in openclaudia::session::PLAN_MODE_ALLOWED_TOOLS {
            assert!(
                msg.contains(tool),
                "plan-mode denial must mention allowed tool {tool:?}; got {msg:?}"
            );
        }
        assert!(!msg.contains("web_search"));
        assert!(!msg.contains("web_browser"));
        assert!(
            msg.contains("write_file ONLY"),
            "plan-mode denial must keep the plan-file write exception visible: {msg:?}"
        );
    }

    #[test]
    fn approved_plan_binding_is_digest_bound_stable_and_prose_free() {
        let project = tempfile::tempdir().expect("plan project");
        let session = Session::new("model", "provider");
        let session_id = openclaudia::state::SessionId::from_raw(session.id())
            .expect("session id must be UUID-shaped");
        let run = tools::ToolRunContext::builder(session_id, project.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(tools::WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .provider("plan-test")
            .build()
            .expect("plan run");
        let manager = std::sync::Mutex::new(
            openclaudia::session::TaskManager::for_run(&run).expect("task manager"),
        );
        let first =
            bind_approved_plan(&session, &manager, "secret prose step one").expect("first binding");
        let repeated = bind_approved_plan(&session, &manager, "secret prose step one")
            .expect("repeat binding");
        assert_eq!(repeated.task_id, first.task_id);
        assert_eq!(repeated.generation, first.generation);
        assert_eq!(repeated.digest, first.digest);

        let revised = bind_approved_plan(&session, &manager, "secret prose step two")
            .expect("revised binding");
        assert_eq!(revised.task_id, first.task_id);
        assert!(revised.generation > first.generation);
        assert_ne!(revised.digest, first.digest);
        let manager = manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let task = manager.get_task(&first.task_id).expect("plan task");
        assert!(matches!(
            &task.source,
            openclaudia::task_graph::TaskSource::Plan {
                observed_version,
                ..
            } if observed_version == &revised.digest
        ));
        assert!(!task.description.contains("secret prose"));
        assert!(!task.subject.contains("secret prose"));
        drop(manager);
    }

    /// #618 fix: when `previous_mode` is `None` the restore falls back to
    /// `Build` — pre-#618 sessions (saved without the field) keep working.
    #[test]
    fn restore_previous_mode_defaults_to_build_when_none_618() {
        let state = make_plan_state(None);
        assert_eq!(restore_previous_mode(Some(&state)), AgentMode::Build);
    }

    /// #618 fix: a snapshot of "refactor" restores to `AgentMode::Refactor`
    /// — the literal `enter (Refactor) -> exit -> Refactor` assertion the
    /// issue asks for.
    #[test]
    fn restore_previous_mode_round_trips_refactor_618() {
        let state = make_plan_state(Some("refactor"));
        assert_eq!(restore_previous_mode(Some(&state)), AgentMode::Refactor);
    }

    /// #618 fix: every non-Plan `AgentMode` round-trips through the snapshot
    /// — token form is the single source of truth and decoupled from the
    /// session-module enum.
    #[test]
    fn restore_previous_mode_round_trips_all_non_plan_modes_618() {
        for mode in [AgentMode::Build, AgentMode::Extend, AgentMode::Refactor] {
            let state = make_plan_state(Some(mode.as_token()));
            assert_eq!(
                restore_previous_mode(Some(&state)),
                mode,
                "mode {mode:?} must survive the snapshot round-trip"
            );
        }
    }

    /// #618 fix: forward-compat — an unknown token decodes to `Build`
    /// instead of panicking, so an older binary reading a newer session
    /// degrades gracefully.
    #[test]
    fn restore_previous_mode_unknown_token_falls_back_to_build_618() {
        let state = make_plan_state(Some("some_future_mode"));
        assert_eq!(restore_previous_mode(Some(&state)), AgentMode::Build);
    }
}
