use super::input::{handle_user_questions, run_external_editor};
use super::{AgentMode, ChatSession};
use openclaudia::tools;
use std::fs;

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
pub fn handle_enter_plan_mode(chat_session: &mut ChatSession) -> String {
    let plans_dir = std::path::PathBuf::from(".openclaudia/plans");
    if let Err(e) = fs::create_dir_all(&plans_dir) {
        return format!("Failed to create plans directory: {e}");
    }

    let plans_dir = std::fs::canonicalize(&plans_dir).unwrap_or(plans_dir);

    // Sanitize session ID to prevent path traversal (e.g. "../../etc/evil")
    let session_id = chat_session.id();
    let safe_id: String = session_id
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe_id.is_empty() {
        return "Invalid session ID for plan file".to_string();
    }
    let plan_file = plans_dir.join(format!("{safe_id}.md"));

    if !plan_file.exists() {
        let header = format!(
            "# Implementation Plan\n\nSession: {}\nCreated: {}\n\n## Plan\n\n",
            session_id,
            chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
        );
        if let Err(e) = fs::write(&plan_file, &header) {
            return format!("Failed to create plan file: {e}");
        }
    }

    // Pin a TOCTOU-safe identity for the plan file (crosslink #334).
    // PlanModeState::enter performs symlink-metadata + File::open +
    // FD-based metadata + canonicalize, then stores the canonical
    // realpath. If any step fails we refuse to enter plan mode --
    // falling back to a weaker check is the exact bypass #334 closes.
    //
    // Crosslink #618: capture the current `AgentMode` so that
    // `exit_plan_mode` can restore it instead of unconditionally
    // flipping back to `Build`. Plan-mode itself is not a meaningful
    // "previous" mode to restore to (it would be a no-op), so we only
    // record non-Plan modes.
    let previous_mode = if chat_session.mode == AgentMode::Plan {
        None
    } else {
        Some(chat_session.mode.as_token().to_string())
    };
    let plan_state = match openclaudia::session::PlanModeState::enter_with_previous_mode(
        plan_file.clone(),
        previous_mode,
    ) {
        Ok(state) => state,
        Err(e) => {
            return format!("Failed to enter plan mode (plan file identity pin failed): {e}");
        }
    };

    chat_session.update_state(|state, _| state.conversation.plan_mode = Some(plan_state));
    chat_session.mode = AgentMode::Plan;

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
    chat_session: &mut ChatSession,
    plan_state: &openclaudia::session::PlanModeState,
    allowed_prompts_json: &str,
) -> (String, bool) {
    use std::io::{self, Write};
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    println!("\n\x1b[90mOpening plan in {editor}...\x1b[0m");
    let edit_result = run_external_editor(&editor, &plan_state.plan_file);
    match edit_result {
        Ok(status) if status.success() => {
            let edited_content = fs::read_to_string(&plan_state.plan_file).unwrap_or_default();
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
                let allowed_prompts = tools::parse_exit_plan_mode_prompts(allowed_prompts_json);
                let restored = chat_session.inspect_state(|state| {
                    restore_previous_mode(state.conversation.plan_mode.as_ref())
                });
                chat_session.mode = restored;
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
                        )
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
            println!("\x1b[31mFailed to open editor '{editor}': {e}\x1b[0m");
            (
                "Failed to open editor. Still in plan mode.".to_string(),
                false,
            )
        }
    }
}

/// Handle exiting plan mode. Reads plan file, shows to user for approval.
/// Returns (`result_text`, `should_exit_plan_mode`).
pub fn handle_exit_plan_mode(
    chat_session: &mut ChatSession,
    allowed_prompts_json: &str,
) -> (String, bool) {
    use std::io::{self, Write};

    let plan_mode = chat_session.inspect_state(|state| state.conversation.plan_mode.clone());
    let plan_state = match &plan_mode {
        Some(state) if state.active => state.clone(),
        _ => {
            return ("Not currently in plan mode.".to_string(), false);
        }
    };

    let plan_content = match fs::read_to_string(&plan_state.plan_file) {
        Ok(content) => content,
        Err(e) => {
            return (
                format!(
                    "Failed to read plan file {}: {}",
                    plan_state.plan_file.display(),
                    e
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
        "y" | "yes" => {
            let allowed_prompts = tools::parse_exit_plan_mode_prompts(allowed_prompts_json);

            let restored = chat_session.inspect_state(|state| {
                restore_previous_mode(state.conversation.plan_mode.as_ref())
            });
            chat_session.mode = restored;

            println!(
                "\n\x1b[1;32m>> Plan Approved - Returning to Build Mode\x1b[0m\n\
                 \x1b[90mFull tool access restored. Plan injected as context.\x1b[0m\n"
            );

            chat_session.update_state(|state, events| {
                state.conversation.plan_mode = None;
                state.conversation.approved_plan = Some(plan_content.clone());
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
                                    .map(|p| format!("- {}: {}", p.tool, p.prompt))
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            )
                        }
                    )
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
        "edit" | "e" => handle_plan_edit(chat_session, &plan_state, allowed_prompts_json),
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

/// Check if a tool call is blocked by plan mode and return an error message if so.
pub fn check_plan_mode_restriction(
    chat_session: &ChatSession,
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

/// Process a tool result, checking for special markers (`user_question`, plan mode).
/// Returns the (possibly replaced) result content and whether it was a special marker.
pub fn process_tool_result_marker(
    chat_session: &mut ChatSession,
    tool_name: &str,
    result_content: &str,
) -> (String, bool) {
    // crosslink #980: dispatch on the typed control signal rather than the
    // raw marker string. The marker constants exist only for serialisation
    // / wire-format compatibility; the dispatcher matches the enum.
    if let Some(signal) = tools::parse_tool_control_signal(result_content) {
        match signal {
            tools::ToolControlSignal::UserQuestion => {
                if let Some(questions) = tools::parse_user_questions(result_content) {
                    let answers = handle_user_questions(&questions);
                    return (answers, true);
                }
            }
            tools::ToolControlSignal::EnterPlanMode => {
                let msg = handle_enter_plan_mode(chat_session);
                return (msg, true);
            }
            tools::ToolControlSignal::ExitPlanMode => {
                let (msg, _approved) = handle_exit_plan_mode(chat_session, result_content);
                return (msg, true);
            }
        }
    }
    let _ = tool_name; // suppress unused warning
    (result_content.to_string(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openclaudia::session::PlanModeState;
    use tempfile::TempDir;

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

    fn chat_session_in_plan_mode() -> ChatSession {
        let mut session = ChatSession::new(
            "claude-sonnet-4-6",
            "anthropic",
            openclaudia::modes::BehaviorMode::default(),
        );
        session.mode = AgentMode::Plan;
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

        assert_eq!(
            check_plan_mode_restriction(&session, "read_file", "{}"),
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
        assert_eq!(
            msg.contains("web_search"),
            cfg!(feature = "browser"),
            "plan-mode denial must match browser-feature web_search availability"
        );
        assert_eq!(
            msg.contains("web_browser"),
            cfg!(feature = "browser"),
            "plan-mode denial must match browser-feature web_browser availability"
        );
        assert!(
            msg.contains("write_file ONLY"),
            "plan-mode denial must keep the plan-file write exception visible: {msg:?}"
        );
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
