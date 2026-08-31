//! End-to-end tests for `session::task::TaskManager::format_*`
//! rendering (status-icon matrix, optional field rendering,
//! Created timestamp shape, `blocks`/`blocked_by` multi-line
//! formatting).
//!
//! Sprint 103 of the verification effort. Sprint 12
//! (`task_manager_e2e`) covered the create/update/delete +
//! dependency-graph semantics; this file walks the
//! `format_task_summary` + `format_task_detail` rendering
//! matrix (all status icons, all optional fields rendered
//! when present + omitted when absent, Created-timestamp
//! shape).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::session::{Task, TaskManager, TaskStatus, TaskUpdateParams, TaskUpdateStatus};

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn fresh_task_with_subject(mgr: &mut TaskManager, subject: &str) -> String {
    let t = mgr
        .create_task(
            subject.to_string(),
            format!("description of {subject}"),
            None,
        )
        .expect("valid task fixture");
    t.id.clone()
}

fn transition(mgr: &mut TaskManager, id: &str, status: TaskUpdateStatus) {
    let params = TaskUpdateParams {
        status: Some(status),
        subject: None,
        description: None,
        active_form: None,
        add_blocks: None,
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(id, params);
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — format_task_summary status icon matrix
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn summary_pending_task_has_open_bracket_space_icon() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "do thing");
    let task = mgr.get_task(&id).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(
        summary.starts_with("[ ]"),
        "pending MUST render with '[ ]' icon; got {summary:?}"
    );
}

#[test]
fn summary_in_progress_task_has_arrow_icon() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "do thing");
    transition(&mut mgr, &id, TaskUpdateStatus::InProgress);
    let task = mgr.get_task(&id).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(
        summary.starts_with("[>]"),
        "in-progress MUST render with '[>]' icon; got {summary:?}"
    );
}

#[test]
fn summary_completed_task_has_x_icon() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "do thing");
    transition(&mut mgr, &id, TaskUpdateStatus::InProgress);
    transition(&mut mgr, &id, TaskUpdateStatus::Completed);
    let task = mgr.get_task(&id).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(
        summary.starts_with("[x]"),
        "completed MUST render with '[x]' icon; got {summary:?}"
    );
}

#[test]
fn summary_failed_and_canceled_tasks_have_distinct_terminal_icons() {
    let mut mgr = TaskManager::new();
    let failed = fresh_task_with_subject(&mut mgr, "failed");
    transition(&mut mgr, &failed, TaskUpdateStatus::Failed);
    assert!(TaskManager::format_task_summary(mgr.get_task(&failed).unwrap()).starts_with("[!]"));

    let canceled = fresh_task_with_subject(&mut mgr, "canceled");
    transition(&mut mgr, &canceled, TaskUpdateStatus::Canceled);
    assert!(TaskManager::format_task_summary(mgr.get_task(&canceled).unwrap()).starts_with("[-]"));
}

#[test]
fn summary_includes_id_subject_and_status_label() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "my-subject");
    let task = mgr.get_task(&id).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(summary.contains(&id));
    assert!(summary.contains("my-subject"));
    // Status label appears in parens.
    assert!(summary.contains('(') && summary.contains(')'));
}

#[test]
fn summary_with_active_form_includes_double_dash_separator() {
    let mut mgr = TaskManager::new();
    let task = mgr
        .create_task(
            "implement".to_string(),
            "x".to_string(),
            Some("Implementing the thing".to_string()),
        )
        .expect("valid task fixture");
    let summary = TaskManager::format_task_summary(task);
    // PINS RENDERING: active form rendered as "-- {form}".
    assert!(
        summary.contains("-- Implementing the thing"),
        "active_form MUST render with '-- ' prefix; got {summary:?}"
    );
}

#[test]
fn summary_without_active_form_has_no_double_dash() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "x");
    let task = mgr.get_task(&id).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(!summary.contains("-- "), "no active form MUST omit ' -- '");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — format_task_summary blocks / blocked_by sections
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn summary_with_blocks_renders_blocks_section() {
    let mut mgr = TaskManager::new();
    let id_a = fresh_task_with_subject(&mut mgr, "A");
    let id_b = fresh_task_with_subject(&mut mgr, "B");
    // A blocks B.
    let params = TaskUpdateParams {
        status: None,
        subject: None,
        description: None,
        active_form: None,
        add_blocks: Some(vec![id_b.clone()]),
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(&id_a, params);
    let task = mgr.get_task(&id_a).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(
        summary.contains("blocks:"),
        "MUST render 'blocks:' section; got {summary:?}"
    );
    assert!(summary.contains(&id_b));
}

#[test]
fn summary_with_blocked_by_renders_blocked_by_section() {
    let mut mgr = TaskManager::new();
    let id_a = fresh_task_with_subject(&mut mgr, "A");
    let id_b = fresh_task_with_subject(&mut mgr, "B");
    let params = TaskUpdateParams {
        status: None,
        subject: None,
        description: None,
        active_form: None,
        add_blocks: Some(vec![id_a.clone()]),
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(&id_b, params);
    // After "B blocks A", A's blocked_by should include B.
    let task = mgr.get_task(&id_a).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(
        summary.contains("blocked_by:"),
        "MUST render 'blocked_by:' section; got {summary:?}"
    );
    assert!(summary.contains(&id_b));
}

#[test]
fn summary_with_multiple_blocks_joins_with_comma() {
    let mut mgr = TaskManager::new();
    let id_a = fresh_task_with_subject(&mut mgr, "A");
    let id_b = fresh_task_with_subject(&mut mgr, "B");
    let id_c = fresh_task_with_subject(&mut mgr, "C");
    let params = TaskUpdateParams {
        status: None,
        subject: None,
        description: None,
        active_form: None,
        add_blocks: Some(vec![id_b, id_c]),
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(&id_a, params);
    let task = mgr.get_task(&id_a).unwrap();
    let summary = TaskManager::format_task_summary(task);
    // Comma-joined.
    assert!(
        summary.contains(", "),
        "MUST join with ', '; got {summary:?}"
    );
}

#[test]
fn summary_without_blocks_or_blocked_by_omits_those_sections() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "lone task");
    let task = mgr.get_task(&id).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(
        !summary.contains("blocks:"),
        "MUST omit 'blocks:' when empty; got {summary:?}"
    );
    assert!(
        !summary.contains("blocked_by:"),
        "MUST omit 'blocked_by:' when empty; got {summary:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — format_task_detail
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn detail_includes_all_required_labels() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "x");
    let task = mgr.get_task(&id).unwrap();
    let detail = TaskManager::format_task_detail(task);
    for label in &[
        "ID:",
        "Subject:",
        "Status:",
        "Priority:",
        "Description:",
        "Created:",
        "Updated:",
    ] {
        assert!(
            detail.contains(label),
            "MUST include label {label:?}; got {detail:?}"
        );
    }
}

#[test]
fn detail_renders_terminal_time_only_for_terminal_statuses() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "terminal");
    assert!(!TaskManager::format_task_detail(mgr.get_task(&id).unwrap()).contains("Terminal:"));
    transition(&mut mgr, &id, TaskUpdateStatus::Failed);
    assert!(TaskManager::format_task_detail(mgr.get_task(&id).unwrap()).contains("Terminal:"));
}

#[test]
fn detail_renders_active_form_when_present() {
    let mut mgr = TaskManager::new();
    let task = mgr
        .create_task(
            "subj".to_string(),
            "desc".to_string(),
            Some("Working on it".to_string()),
        )
        .expect("valid task fixture");
    let detail = TaskManager::format_task_detail(task);
    assert!(detail.contains("Active form:"));
    assert!(detail.contains("Working on it"));
}

#[test]
fn detail_omits_active_form_label_when_absent() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "x");
    let task = mgr.get_task(&id).unwrap();
    let detail = TaskManager::format_task_detail(task);
    assert!(
        !detail.contains("Active form:"),
        "MUST omit 'Active form:' label when None; got {detail:?}"
    );
}

#[test]
fn detail_created_timestamp_uses_documented_format() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "x");
    let task = mgr.get_task(&id).unwrap();
    let detail = TaskManager::format_task_detail(task);
    // PINS TIMESTAMP FORMAT: %Y-%m-%d %H:%M:%S UTC
    assert!(
        detail.contains(" UTC"),
        "Created timestamp MUST end with ' UTC'; got {detail:?}"
    );
}

#[test]
fn detail_renders_blocks_section_when_present() {
    let mut mgr = TaskManager::new();
    let id_a = fresh_task_with_subject(&mut mgr, "A");
    let id_b = fresh_task_with_subject(&mut mgr, "B");
    let params = TaskUpdateParams {
        status: None,
        subject: None,
        description: None,
        active_form: None,
        add_blocks: Some(vec![id_b]),
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(&id_a, params);
    let task = mgr.get_task(&id_a).unwrap();
    let detail = TaskManager::format_task_detail(task);
    assert!(detail.contains("Blocks:"));
}

#[test]
fn detail_omits_blocks_section_when_empty() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "lone");
    let task = mgr.get_task(&id).unwrap();
    let detail = TaskManager::format_task_detail(task);
    assert!(!detail.contains("Blocks:"));
    assert!(!detail.contains("Blocked by:"));
}

#[test]
fn detail_is_multi_line() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "x");
    let task = mgr.get_task(&id).unwrap();
    let detail = TaskManager::format_task_detail(task);
    // At least 5 newline-terminated rows.
    let line_count = detail.lines().count();
    assert!(
        line_count >= 5,
        "MUST be multi-line (>= 5 lines); got {line_count} lines"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Partial update_task params
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn update_subject_only_preserves_description_and_active_form() {
    let mut mgr = TaskManager::new();
    let id = {
        let t = mgr
            .create_task(
                "old subj".to_string(),
                "preserved desc".to_string(),
                Some("preserved form".to_string()),
            )
            .expect("valid task fixture");
        t.id.clone()
    };
    let params = TaskUpdateParams {
        status: None,
        subject: Some("new subj".to_string()),
        description: None,
        active_form: None,
        add_blocks: None,
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(&id, params);
    let task = mgr.get_task(&id).unwrap();
    assert_eq!(task.subject, "new subj");
    assert_eq!(task.description, "preserved desc");
    assert_eq!(task.active_form.as_deref(), Some("preserved form"));
}

#[test]
fn update_description_only_preserves_subject() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "original subj");
    let params = TaskUpdateParams {
        status: None,
        subject: None,
        description: Some("new desc".to_string()),
        active_form: None,
        add_blocks: None,
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(&id, params);
    let task = mgr.get_task(&id).unwrap();
    assert_eq!(task.subject, "original subj");
    assert_eq!(task.description, "new desc");
}

#[test]
fn update_active_form_only_adds_or_replaces_active_form() {
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "subj");
    // Initially None.
    assert!(mgr.get_task(&id).unwrap().active_form.is_none());
    let params = TaskUpdateParams {
        status: None,
        subject: None,
        description: None,
        active_form: Some("Doing thing".to_string()),
        add_blocks: None,
        add_blocked_by: None,
        ..TaskUpdateParams::default()
    };
    let _ = mgr.update_task(&id, params);
    let task = mgr.get_task(&id).unwrap();
    assert_eq!(task.active_form.as_deref(), Some("Doing thing"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — list_tasks ordering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_tasks_preserves_creation_order() {
    let mut mgr = TaskManager::new();
    let id1 = fresh_task_with_subject(&mut mgr, "first");
    let id2 = fresh_task_with_subject(&mut mgr, "second");
    let id3 = fresh_task_with_subject(&mut mgr, "third");
    let list = mgr.list_tasks();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].id, id1);
    assert_eq!(list[1].id, id2);
    assert_eq!(list[2].id, id3);
}

#[test]
fn list_tasks_returns_borrowed_slice() {
    let mgr = TaskManager::new();
    let slice: &[Task] = mgr.list_tasks();
    assert!(slice.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — TaskStatus enum + Display
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_status_default_is_pending() {
    // Documented contract: new tasks start Pending.
    let mut mgr = TaskManager::new();
    let id = fresh_task_with_subject(&mut mgr, "x");
    let task = mgr.get_task(&id).unwrap();
    assert_eq!(task.status, TaskStatus::Pending);
}

#[test]
fn task_status_variants_pairwise_distinct() {
    assert_ne!(TaskStatus::Pending, TaskStatus::InProgress);
    assert_ne!(TaskStatus::InProgress, TaskStatus::Completed);
    assert_ne!(TaskStatus::Pending, TaskStatus::Completed);
    assert_ne!(TaskStatus::Completed, TaskStatus::Failed);
    assert_ne!(TaskStatus::Failed, TaskStatus::Canceled);
}
