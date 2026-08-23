use super::input::{handle_user_questions, run_external_editor};
use super::Session;
use openclaudia::tools;

#[cfg(test)]
use openclaudia::state::AgentMode;

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
    coordinator: bool,
) -> (String, bool, Option<serde_json::Value>) {
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
                    return (
                        format!("Failed to read the edited plan: {error}"),
                        false,
                        None,
                    );
                }
            };
            println!("\n\x1b[1;36m## Edited Plan\x1b[0m\n");
            println!("{edited_content}");
            println!();
            print!("\x1b[1;33mApprove edited plan? [y/n]: \x1b[0m");
            io::stdout().flush().ok();
            let mut input2 = String::new();
            if io::stdin().read_line(&mut input2).is_err() {
                return ("Failed to read user input.".to_string(), false, None);
            }
            if input2.trim().to_lowercase().starts_with('y') {
                let prepared = match openclaudia::session::prepare_interactive_plan_approval(
                    run,
                    chat_session,
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        return (
                            format!(
                                "Edited plan could not be prepared for approval: {error}. Still in plan mode."
                            ),
                            false,
                            None,
                        );
                    }
                };
                approve_plan(
                    run,
                    chat_session,
                    task_manager,
                    &prepared,
                    allowed_prompts,
                    coordinator,
                )
            } else {
                println!("\n\x1b[1;31m>> Plan Rejected - Staying in Plan Mode\x1b[0m\n");
                (
                    "Edited plan rejected by user. Still in plan mode. Revise and try again."
                        .to_string(),
                    false,
                    None,
                )
            }
        }
        Ok(_) => (
            "Editor exited with error. Plan unchanged. Still in plan mode.".to_string(),
            false,
            None,
        ),
        Err(e) => {
            let safe = run.environment_grants().sanitize_diagnostic(&e);
            println!("\x1b[31mFailed to open editor: {safe}\x1b[0m");
            (
                "Failed to open editor. Still in plan mode.".to_string(),
                false,
                None,
            )
        }
    }
}

fn approve_plan(
    run: &tools::ToolRunContext,
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    prepared: &openclaudia::session::PreparedPlanApproval,
    allowed_prompts: &[tools::ToolAllowedPrompt],
    coordinator: bool,
) -> (String, bool, Option<serde_json::Value>) {
    let restore_mode = if coordinator {
        openclaudia::modes::RuntimeMode::Coordinator
    } else {
        openclaudia::modes::RuntimeMode::Behavioral(chat_session.behavior_mode())
    };
    let receipt = match openclaudia::session::commit_interactive_plan_approval(
        run,
        chat_session,
        task_manager,
        prepared,
        allowed_prompts,
        restore_mode,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            return (
                format!("Plan approval could not be committed: {error}. Still in plan mode."),
                false,
                None,
            );
        }
    };
    println!(
        "\n\x1b[1;32m>> Plan Approved - Exiting Plan Mode\x1b[0m\n\
         \x1b[90mFull tool access restored. Plan injected as context.\x1b[0m\n"
    );
    (
        format!(
            "Plan approved by user as digest {} and task {}. Full tool access restored. Proceed with implementation according to the plan.",
            receipt.plan_digest, receipt.task_id
        ),
        true,
        Some(receipt.context_message),
    )
}

/// Handle exiting plan mode. Reads plan file, shows to user for approval.
/// Returns (`result_text`, `should_exit_plan_mode`, `approved_plan_context`).
pub fn handle_exit_plan_mode(
    run: &tools::ToolRunContext,
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    allowed_prompts: &[tools::ToolAllowedPrompt],
    coordinator: bool,
) -> (String, bool, Option<serde_json::Value>) {
    use std::io::{self, Write};

    let plan_mode = chat_session.inspect_state(|state| state.conversation.plan_mode.clone());
    let plan_state = match &plan_mode {
        Some(state) if state.active => state.clone(),
        _ => {
            return ("Not currently in plan mode.".to_string(), false, None);
        }
    };

    let prepared = match openclaudia::session::prepare_interactive_plan_approval(run, chat_session)
    {
        Ok(prepared) => prepared,
        Err(error) => {
            return (
                format!("Failed to prepare the plan for approval: {error}"),
                false,
                None,
            );
        }
    };
    let plan_content = prepared.plan_content();

    println!("\n\x1b[1;36m{}\x1b[0m", "=".repeat(60));
    println!("\x1b[1;36m## Implementation Plan\x1b[0m\n");
    println!("{plan_content}");
    println!("\x1b[1;36m{}\x1b[0m\n", "=".repeat(60));
    print!("\x1b[1;33mApprove? [y/n/edit]: \x1b[0m");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return ("Failed to read user input.".to_string(), false, None);
    }
    let input = input.trim().to_lowercase();

    match input.as_str() {
        "y" | "yes" => approve_plan(
            run,
            chat_session,
            task_manager,
            &prepared,
            allowed_prompts,
            coordinator,
        ),
        "n" | "no" => {
            println!(
                "\n\x1b[1;31m>> Plan Rejected - Staying in Plan Mode\x1b[0m\n\
                 \x1b[90mRevise the plan and try again.\x1b[0m\n"
            );

            (
                "Plan rejected by user. You are still in plan mode. Please revise the plan based on user feedback and call exit_plan_mode again when ready.".to_string(),
                false,
                None,
            )
        }
        "edit" | "e" => handle_plan_edit(
            run,
            chat_session,
            task_manager,
            &plan_state,
            allowed_prompts,
            coordinator,
        ),
        _ => {
            println!("\x1b[90mUnrecognized input. Staying in plan mode.\x1b[0m");
            (
                "Unrecognized response. Still in plan mode. Call exit_plan_mode again when ready."
                    .to_string(),
                false,
                None,
            )
        }
    }
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
/// result passed to provider continuation. Approved-plan context is returned
/// separately so callers append it after the resolving tool result. Ordinary
/// text is never inspected.
pub fn process_tool_follow_up(
    run: &tools::ToolRunContext,
    chat_session: &Session,
    task_manager: &std::sync::Mutex<openclaudia::session::TaskManager>,
    result: &tools::ToolResult,
    coordinator: bool,
) -> (tools::ToolResult, Option<serde_json::Value>) {
    let mut trailing_context = None;
    let (content, response) = match result.follow_up() {
        tools::ToolFollowUp::None => return (result.clone(), None),
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
            let (message, approved, context) = handle_exit_plan_mode(
                run,
                chat_session,
                task_manager,
                allowed_prompts,
                coordinator,
            );
            trailing_context = context;
            (
                message.clone(),
                serde_json::json!({"message": message, "approved": approved}),
            )
        }
    };
    (
        result
            .resolve_follow_up(content, response)
            .expect("trusted pending follow-up must resolve exactly once"),
        trailing_context,
    )
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
        let approve = |content: &str| {
            handle_enter_plan_mode(&run, &session);
            std::fs::write(run.agent_plan_file(), content).expect("write plan");
            let prepared = openclaudia::session::prepare_interactive_plan_approval(&run, &session)
                .expect("prepare approval");
            openclaudia::session::commit_interactive_plan_approval(
                &run,
                &session,
                &manager,
                &prepared,
                &[],
                openclaudia::modes::RuntimeMode::Behavioral(session.behavior_mode()),
            )
            .expect("commit approval")
        };

        let first = approve("secret prose step one");
        let repeated = approve("secret prose step one");
        assert_eq!(repeated.task_id, first.task_id);
        assert_eq!(repeated.task_graph_generation, first.task_graph_generation);
        assert_eq!(repeated.plan_digest, first.plan_digest);

        let revised = approve("secret prose step two");
        assert_eq!(revised.task_id, first.task_id);
        assert!(revised.task_graph_generation > first.task_graph_generation);
        assert_ne!(revised.plan_digest, first.plan_digest);
        let manager = manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let task = manager.get_task(&first.task_id).expect("plan task");
        assert!(matches!(
            &task.source,
            openclaudia::task_graph::TaskSource::Plan {
                observed_version,
                ..
            } if observed_version == &revised.plan_digest
        ));
        assert!(!task.description.contains("secret prose"));
        assert!(!task.subject.contains("secret prose"));
        drop(manager);
        assert!(
            session.messages_snapshot().is_empty(),
            "the frontend must append approved context after its tool result"
        );
    }

    /// The shared approval transaction, now used by both frontends, retains
    /// the pre-plan behavioral mode rather than always falling back to Build.
    #[test]
    fn shared_approval_restores_all_non_plan_agent_modes_618() {
        for mode in [AgentMode::Build, AgentMode::Extend, AgentMode::Refactor] {
            let project = tempfile::tempdir().expect("plan project");
            let session = Session::new("model", "provider");
            session.set_agent_mode(mode);
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
            handle_enter_plan_mode(&run, &session);
            std::fs::write(run.agent_plan_file(), "# approved\n").expect("write plan");
            let prepared = openclaudia::session::prepare_interactive_plan_approval(&run, &session)
                .expect("prepare approval");
            openclaudia::session::commit_interactive_plan_approval(
                &run,
                &session,
                &manager,
                &prepared,
                &[],
                openclaudia::modes::RuntimeMode::Behavioral(session.behavior_mode()),
            )
            .expect("commit approval");
            assert_eq!(
                session.agent_mode(),
                mode,
                "mode {mode:?} must survive a shared approval transaction"
            );
        }
    }
}
