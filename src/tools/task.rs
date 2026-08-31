use crate::session::TaskManager;
use crate::task_graph::{
    CanonicalTaskStatus, CreateTask, TaskBudgetSpec, TaskGraphGeneration, TaskPriority, TaskSource,
    MAX_TASK_ACTIVE_FORM_BYTES, MAX_TASK_DESCRIPTION_BYTES, MAX_TASK_EDGES, MAX_TASK_ID_BYTES,
    MAX_TASK_SUBJECT_BYTES,
};
use crate::tools::args::ToolArgs as _;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::BuildHasher;

/// Execute the `task_create` tool
pub fn execute_task_create<S: BuildHasher>(
    args: &HashMap<String, Value, S>,
    task_mgr: &mut TaskManager,
) -> (String, bool) {
    // crosslink #675: typed accessors. Wording was already canonical
    // ("Missing 'X' argument") so no test churn.
    let subject = match args.arg_str_strict("subject") {
        Ok(s) => match validate_tool_text("subject", s, MAX_TASK_SUBJECT_BYTES, false) {
            Ok(()) => s.to_string(),
            Err(error) => return (error, true),
        },
        Err(e) => return e.into_tool_error(),
    };
    let description = match args.arg_str_strict("description") {
        Ok(d) => match validate_tool_text("description", d, MAX_TASK_DESCRIPTION_BYTES, true) {
            Ok(()) => d.to_string(),
            Err(error) => return (error, true),
        },
        Err(e) => return e.into_tool_error(),
    };

    let active_form = match args.arg_str_opt_strict("active_form") {
        Ok(Some(active_form)) => match validate_tool_text(
            "active_form",
            active_form,
            MAX_TASK_ACTIVE_FORM_BYTES,
            false,
        ) {
            Ok(()) => Some(active_form.to_string()),
            Err(error) => return (error, true),
        },
        Ok(None) => None,
        Err(e) => return e.into_tool_error(),
    };
    let expected_generation = match args.arg_u64_strict("expected_generation") {
        Ok(value) => TaskGraphGeneration::from_u64(value),
        Err(error) => return error.into_tool_error(),
    };
    let budget = match parse_task_budget(args.get("budget")) {
        Ok(value) => value,
        Err(error) => return (error, true),
    };
    let priority = match parse_task_priority(args.get("priority"), TaskPriority::Medium) {
        Ok(value) => value,
        Err(error) => return (error, true),
    };

    let task = match task_mgr.create_task_from_input(CreateTask {
        expected_generation,
        subject,
        description,
        active_form,
        status: CanonicalTaskStatus::Pending,
        priority,
        budget,
        source: TaskSource::TaskTool,
    }) {
        Ok(task) => task,
        Err(message) => return (message, true),
    };
    let output = format!(
        "Created task: {}\n{}",
        task.id,
        TaskManager::format_task_detail(task)
    );
    (output, false)
}

/// Execute the `task_update` tool
pub fn execute_task_update<S: BuildHasher>(
    args: &HashMap<String, Value, S>,
    task_mgr: &mut TaskManager,
) -> (String, bool) {
    let (task_id, params) = match parse_task_update(args) {
        Ok(parsed) => parsed,
        Err(message) => return (message, true),
    };

    match task_mgr.update_task(task_id, params) {
        Ok(Some(task)) => {
            let output = format!(
                "Updated task: {}\n{}",
                task.id,
                TaskManager::format_task_detail(task)
            );
            (output, false)
        }
        Ok(None) => {
            // Task was deleted successfully
            (format!("Task '{task_id}' deleted"), false)
        }
        Err(msg) => (msg, true),
    }
}

fn parse_task_update<S: BuildHasher>(
    args: &HashMap<String, Value, S>,
) -> Result<(&str, crate::session::TaskUpdateParams), String> {
    let task_id = args
        .arg_str_strict("task_id")
        .map_err(|error| error.to_string())?;
    validate_tool_text("task_id", task_id, MAX_TASK_ID_BYTES, false)?;
    let expected_generation = Some(TaskGraphGeneration::from_u64(
        args.arg_u64_strict("expected_generation")
            .map_err(|error| error.to_string())?,
    ));
    let expected_task_revision = Some(
        args.arg_u64_strict("expected_task_revision")
            .map_err(|error| error.to_string())?,
    );
    let budget = parse_task_budget(args.get("budget"))?;
    let clear_budget = args
        .arg_bool_or_strict("clear_budget", false)
        .map_err(|error| error.to_string())?;
    if clear_budget && budget.is_some() {
        return Err(
            "Invalid task_update fields: 'budget' and 'clear_budget' are mutually exclusive"
                .to_string(),
        );
    }
    let priority = args
        .get("priority")
        .map(|value| parse_task_priority(Some(value), TaskPriority::Medium))
        .transpose()?;
    Ok((
        task_id,
        crate::session::TaskUpdateParams {
            status: parse_task_update_status(args.get("status"))?,
            priority,
            subject: parse_optional_string_field(
                args.get("subject"),
                "subject",
                MAX_TASK_SUBJECT_BYTES,
                false,
            )?,
            description: parse_optional_string_field(
                args.get("description"),
                "description",
                MAX_TASK_DESCRIPTION_BYTES,
                true,
            )?,
            active_form: parse_optional_string_field(
                args.get("active_form"),
                "active_form",
                MAX_TASK_ACTIVE_FORM_BYTES,
                false,
            )?,
            clear_active_form: args
                .arg_bool_or_strict("clear_active_form", false)
                .map_err(|error| error.to_string())?,
            budget,
            clear_budget,
            add_blocks: parse_optional_string_array(args.get("add_blocks"), "add_blocks")?,
            remove_blocks: parse_optional_string_array(args.get("remove_blocks"), "remove_blocks")?,
            add_blocked_by: parse_optional_string_array(
                args.get("add_blocked_by"),
                "add_blocked_by",
            )?,
            remove_blocked_by: parse_optional_string_array(
                args.get("remove_blocked_by"),
                "remove_blocked_by",
            )?,
            expected_generation,
            expected_task_revision,
        },
    ))
}

fn parse_task_priority(
    value: Option<&Value>,
    default: TaskPriority,
) -> Result<TaskPriority, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value.as_str() {
        Some("critical") => Ok(TaskPriority::Critical),
        Some("high") => Ok(TaskPriority::High),
        Some("medium") => Ok(TaskPriority::Medium),
        Some("low") => Ok(TaskPriority::Low),
        Some(other) => Err(format!(
            "Invalid task priority '{other}'. Must be: critical, high, medium, low"
        )),
        None => Err(
            "Invalid task priority '<non-string>'. Must be: critical, high, medium, low"
                .to_string(),
        ),
    }
}

fn parse_task_budget(value: Option<&Value>) -> Result<Option<TaskBudgetSpec>, String> {
    const FIELDS: &[&str] = &[
        "max_turns",
        "max_tokens",
        "max_elapsed_millis",
        "max_cost_microusd",
        "max_child_runs",
        "max_concurrent_calls",
    ];

    let Some(value) = value else {
        return Ok(None);
    };
    let Some(object) = value.as_object() else {
        return Err("Invalid task budget: expected an object".to_string());
    };
    if let Some(unknown) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
        return Err(format!("Invalid task budget field '{unknown}'"));
    }
    let parse = |field: &'static str| -> Result<Option<u64>, String> {
        match object.get(field) {
            None => Ok(None),
            Some(Value::Number(value)) => value
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("Invalid task budget field '{field}': expected integer")),
            Some(_) => Err(format!(
                "Invalid task budget field '{field}': expected integer"
            )),
        }
    };
    Ok(Some(TaskBudgetSpec {
        max_turns: parse("max_turns")?,
        max_tokens: parse("max_tokens")?,
        max_elapsed_millis: parse("max_elapsed_millis")?,
        max_cost_microusd: parse("max_cost_microusd")?,
        max_child_runs: parse("max_child_runs")?,
        max_concurrent_calls: parse("max_concurrent_calls")?,
    }))
}

fn parse_task_update_status(
    value: Option<&Value>,
) -> Result<Option<crate::session::TaskUpdateStatus>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(status) = value.as_str() else {
        return Err(
            "Invalid task status '<non-string>'. Must be: pending, in_progress, completed, failed, canceled, deleted"
                .to_string(),
        );
    };
    crate::session::TaskUpdateStatus::parse(status)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "Invalid task status '{status}'. Must be: pending, in_progress, completed, failed, canceled, deleted"
            )
        })
}

fn validate_tool_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), String> {
    if !allow_empty && value.trim().is_empty() {
        return Err(format!("Invalid task field '{field}': must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(format!(
            "Invalid task field '{field}': exceeds {max_bytes} bytes"
        ));
    }
    Ok(())
}

fn parse_optional_string_field(
    value: Option<&Value>,
    field: &'static str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.as_str().ok_or_else(|| {
        format!("Invalid task_update field '{field}': expected string when supplied")
    })?;
    validate_tool_text(field, value, max_bytes, allow_empty)?;
    Ok(Some(value.to_string()))
}

fn parse_optional_string_array(
    value: Option<&Value>,
    field: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Err(format!(
            "Invalid task_update field '{field}': expected array of strings when supplied"
        ));
    };
    if items.len() > MAX_TASK_EDGES {
        return Err(format!(
            "Invalid task_update field '{field}': exceeds {MAX_TASK_EDGES} task ids"
        ));
    }

    let mut parsed = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let Some(s) = item.as_str() else {
            return Err(format!(
                "Invalid task_update field '{field}[{idx}]': expected string"
            ));
        };
        validate_tool_text(field, s, MAX_TASK_ID_BYTES, false)?;
        parsed.push(s.to_string());
    }
    Ok(Some(parsed))
}

/// Execute the `task_get` tool.
///
/// crosslink #588: a missing `task_id` is a successful lookup of "no such
/// task", not an error — match CC's `TaskGetTool`, which resolves with
/// `null` when the id is unknown. Returning an error here would force the
/// model into a recovery path for what is a legitimate, expected outcome
/// (e.g. polling a task that was deleted). The success payload is the
/// literal JSON `null` so structured consumers can branch on it cheaply.
#[must_use]
pub fn execute_task_get<S: BuildHasher>(
    args: &HashMap<String, Value, S>,
    task_mgr: &mut TaskManager,
) -> (String, bool) {
    let task_id = match args.arg_str_strict("task_id") {
        Ok(task_id) => match validate_tool_text("task_id", task_id, MAX_TASK_ID_BYTES, false) {
            Ok(()) => task_id,
            Err(error) => return (error, true),
        },
        Err(e) => return e.into_tool_error(),
    };

    if let Err(error) = task_mgr.refresh() {
        return (error, true);
    }
    task_mgr.get_task(task_id).map_or_else(
        || (Value::Null.to_string(), false),
        |task| {
            (
                format!(
                    "Canonical graph generation: {}\n{}",
                    task_mgr.generation(),
                    TaskManager::format_task_detail(task)
                ),
                false,
            )
        },
    )
}

/// Execute the `task_list` tool
#[must_use]
pub fn execute_task_list<S: BuildHasher>(
    args: &HashMap<String, Value, S>,
    task_mgr: &mut TaskManager,
) -> (String, bool) {
    if let Err(error) = task_mgr.refresh() {
        return (error, true);
    }
    let limit = match args.get("limit") {
        None => 50,
        Some(Value::Number(value)) => match value.as_u64().and_then(|v| usize::try_from(v).ok()) {
            Some(value) => value,
            None => {
                return (
                    "Invalid 'limit' argument: expected non-negative integer".to_string(),
                    true,
                )
            }
        },
        Some(_) => {
            return (
                "Invalid 'limit' argument: expected non-negative integer".to_string(),
                true,
            )
        }
    };
    let cursor = match args.arg_str_opt_strict("cursor") {
        Ok(value) => value,
        Err(error) => return error.into_tool_error(),
    };
    let ready_only = match args.arg_bool_or_strict("ready_only", false) {
        Ok(value) => value,
        Err(error) => return error.into_tool_error(),
    };
    if ready_only && cursor.is_some() {
        return (
            "Invalid task_list fields: 'cursor' cannot be used with 'ready_only'".to_string(),
            true,
        );
    }
    let page = match if ready_only {
        task_mgr.ready_tasks(limit)
    } else {
        task_mgr.page_tasks(cursor, limit)
    } {
        Ok(page) => page,
        Err(error) => return (error, true),
    };
    let tasks = &page.tasks;

    if tasks.is_empty() {
        return (
            format!("No tasks. Canonical graph generation: {}.", page.generation),
            false,
        );
    }

    let mut output = format!("Canonical graph generation: {}\n", page.generation);
    for task in tasks {
        output.push_str(&TaskManager::format_task_summary(task));
        output.push('\n');
    }

    let completed = tasks
        .iter()
        .filter(|t| t.status == crate::session::TaskStatus::Completed)
        .count();
    let in_progress = tasks
        .iter()
        .filter(|t| t.status == crate::session::TaskStatus::InProgress)
        .count();
    let pending = tasks
        .iter()
        .filter(|t| t.status == crate::session::TaskStatus::Pending)
        .count();
    let failed = tasks
        .iter()
        .filter(|task| task.status == crate::session::TaskStatus::Failed)
        .count();
    let canceled = tasks
        .iter()
        .filter(|task| task.status == crate::session::TaskStatus::Canceled)
        .count();

    let _ = write!(
        output,
        "\n({} total: {} completed, {} failed, {} canceled, {} in progress, {} pending)",
        tasks.len(),
        completed,
        failed,
        canceled,
        in_progress,
        pending
    );
    if let Some(cursor) = page.next_cursor {
        let _ = write!(output, "\nNext cursor: {cursor}");
    }

    (output, false)
}
