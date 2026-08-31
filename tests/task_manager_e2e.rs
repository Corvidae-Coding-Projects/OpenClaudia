//! End-to-end tests for `TaskManager` session-side lifecycle:
//! create → status transitions → dependency edges → delete.
//!
//! Sprint 43 of the verification effort.
//!
//! `tests/coordinator_e2e.rs` (sprint 13) covers the coordinator
//! queue; this file covers the session-level `TaskManager` that
//! drives the model-visible todo list.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::runtime::{Actor, ActorId, ActorRole, RunId};
use openclaudia::session::{Task, TaskManager, TaskStatus, TaskUpdateParams, TaskUpdateStatus};
use openclaudia::task_graph::{TaskActor, TaskPriority};
use std::path::PathBuf;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn add(mgr: &mut TaskManager, subject: &str) -> String {
    mgr.create_task(subject.to_string(), String::new(), None)
        .expect("valid task fixture must be created")
        .id
        .clone()
}

fn status_of(mgr: &TaskManager, id: &str) -> Option<TaskStatus> {
    mgr.get_task(id).map(|task| task.status)
}

fn update_status<'m>(
    mgr: &'m mut TaskManager,
    id: &str,
    s: TaskUpdateStatus,
) -> Result<Option<&'m Task>, String> {
    mgr.update_task(
        id,
        TaskUpdateParams {
            status: Some(s),
            ..TaskUpdateParams::default()
        },
    )
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — TaskUpdateStatus::parse
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_accepts_every_documented_status_string() {
    assert_eq!(
        TaskUpdateStatus::parse("pending"),
        Some(TaskUpdateStatus::Pending)
    );
    assert_eq!(
        TaskUpdateStatus::parse("in_progress"),
        Some(TaskUpdateStatus::InProgress)
    );
    assert_eq!(
        TaskUpdateStatus::parse("completed"),
        Some(TaskUpdateStatus::Completed)
    );
    assert_eq!(
        TaskUpdateStatus::parse("failed"),
        Some(TaskUpdateStatus::Failed)
    );
    assert_eq!(
        TaskUpdateStatus::parse("canceled"),
        Some(TaskUpdateStatus::Canceled)
    );
    assert_eq!(
        TaskUpdateStatus::parse("deleted"),
        Some(TaskUpdateStatus::Deleted)
    );
}

#[test]
fn parse_rejects_unknown_status_strings() {
    for input in &[
        "",
        "PENDING",
        "InProgress",
        "done",
        "removed",
        "in-progress",
    ] {
        assert_eq!(
            TaskUpdateStatus::parse(input),
            None,
            "{input:?} MUST NOT parse"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — create_task
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn create_task_yields_pending_with_incrementing_ids() {
    let mut mgr = TaskManager::new();
    let id1 = add(&mut mgr, "first");
    let id2 = add(&mut mgr, "second");
    let id3 = add(&mut mgr, "third");
    assert_eq!(id1, "task-1");
    assert_eq!(id2, "task-2");
    assert_eq!(id3, "task-3");
    for id in [&id1, &id2, &id3] {
        assert_eq!(status_of(&mgr, id), Some(TaskStatus::Pending));
    }
}

#[test]
fn create_task_starts_with_no_dependencies() {
    let mut mgr = TaskManager::new();
    let id = add(&mut mgr, "alone");
    let task = mgr.get_task(&id).unwrap();
    assert!(task.blocks.is_empty());
    assert!(task.blocked_by.is_empty());
    assert_eq!(task.priority, TaskPriority::Medium);
    assert!(task.terminal_at.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Single-InProgress invariant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn second_in_progress_demotes_first_to_pending() {
    let mut mgr = TaskManager::new();
    let a = add(&mut mgr, "A");
    let b = add(&mut mgr, "B");

    update_status(&mut mgr, &a, TaskUpdateStatus::InProgress).expect("set A InProgress");
    assert_eq!(status_of(&mgr, &a), Some(TaskStatus::InProgress));

    // Now set B to InProgress — A MUST be demoted to Pending.
    update_status(&mut mgr, &b, TaskUpdateStatus::InProgress).expect("set B InProgress");
    assert_eq!(status_of(&mgr, &b), Some(TaskStatus::InProgress));
    assert_eq!(
        status_of(&mgr, &a),
        Some(TaskStatus::Pending),
        "A MUST be demoted when B transitions to InProgress"
    );
}

#[test]
fn current_task_returns_the_in_progress_one() {
    let mut mgr = TaskManager::new();
    let _a = add(&mut mgr, "A");
    let b = add(&mut mgr, "B");
    assert!(mgr.current_task().is_none(), "no in-progress task yet");
    update_status(&mut mgr, &b, TaskUpdateStatus::InProgress).expect("set");
    let current = mgr.current_task().expect("there is a current task");
    assert_eq!(current.id, b);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Blocked-by guard (crosslink #593)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn in_progress_refused_when_blocker_not_completed() {
    let mut mgr = TaskManager::new();
    let upstream = add(&mut mgr, "upstream");
    let dependent = add(&mut mgr, "dependent");
    // Make `dependent` depend on `upstream`.
    mgr.update_task(
        &dependent,
        TaskUpdateParams {
            add_blocked_by: Some(vec![upstream.clone()]),
            ..TaskUpdateParams::default()
        },
    )
    .expect("add dep");

    // Upstream is still Pending — transitioning `dependent` to
    // InProgress MUST error.
    let outcome = update_status(&mut mgr, &dependent, TaskUpdateStatus::InProgress);
    let Err(msg) = outcome else {
        panic!("blocked-by must refuse InProgress; got Ok");
    };
    assert!(
        msg.contains(&upstream) && msg.contains("pending"),
        "error must name the offending upstream + its status; got {msg:?}"
    );

    // The dependent task MUST still be Pending.
    assert_eq!(status_of(&mgr, &dependent), Some(TaskStatus::Pending));
}

#[test]
fn in_progress_admitted_after_blocker_completes() {
    let mut mgr = TaskManager::new();
    let upstream = add(&mut mgr, "upstream");
    let dependent = add(&mut mgr, "dependent");
    mgr.update_task(
        &dependent,
        TaskUpdateParams {
            add_blocked_by: Some(vec![upstream.clone()]),
            ..TaskUpdateParams::default()
        },
    )
    .expect("add dep");
    // Complete the upstream.
    update_status(&mut mgr, &upstream, TaskUpdateStatus::Completed).expect("complete upstream");
    // Now `dependent` may transition.
    update_status(&mut mgr, &dependent, TaskUpdateStatus::InProgress)
        .expect("dependent → in_progress");
    assert_eq!(status_of(&mgr, &dependent), Some(TaskStatus::InProgress));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Delete
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn delete_removes_task_from_list() {
    let mut mgr = TaskManager::new();
    let a = add(&mut mgr, "A");
    let b = add(&mut mgr, "B");
    let out = update_status(&mut mgr, &a, TaskUpdateStatus::Deleted).expect("delete must succeed");
    assert!(
        out.is_none(),
        "Deleted variant MUST return Ok(None); got {:?}",
        out.map(|t| t.id.clone())
    );
    // A is gone.
    assert!(mgr.get_task(&a).is_none());
    // B is unaffected.
    assert!(mgr.get_task(&b).is_some());
    assert_eq!(mgr.list_tasks().len(), 1);
}

#[test]
fn delete_unknown_task_id_errors() {
    let mut mgr = TaskManager::new();
    let outcome = update_status(&mut mgr, "task-9999", TaskUpdateStatus::Deleted);
    let Err(msg) = outcome else {
        panic!("delete on unknown id MUST error");
    };
    assert!(
        msg.contains("task-9999"),
        "msg must name the id; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Dependency edges + reverse-edge sync
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn adding_blocks_edge_creates_reverse_blocked_by_edge() {
    let mut mgr = TaskManager::new();
    let a = add(&mut mgr, "A");
    let b = add(&mut mgr, "B");
    // A blocks B → B is blocked_by A.
    mgr.update_task(
        &a,
        TaskUpdateParams {
            add_blocks: Some(vec![b.clone()]),
            ..TaskUpdateParams::default()
        },
    )
    .expect("add blocks");
    let task_a = mgr.get_task(&a).unwrap();
    let task_b = mgr.get_task(&b).unwrap();
    assert!(task_a.blocks.contains(&b), "A.blocks must include B");
    assert!(
        task_b.blocked_by.contains(&a),
        "B.blocked_by MUST mirror A.blocks (symmetric)"
    );
}

#[test]
fn dependency_to_nonexistent_task_errors() {
    let mut mgr = TaskManager::new();
    let a = add(&mut mgr, "A");
    let outcome = mgr.update_task(
        &a,
        TaskUpdateParams {
            add_blocks: Some(vec!["task-9999".to_string()]),
            ..TaskUpdateParams::default()
        },
    );
    let Err(msg) = outcome else {
        panic!("nonexistent-dep MUST error");
    };
    assert!(
        msg.contains("task-9999"),
        "error must name the bad dep id; got {msg:?}"
    );
}

#[test]
fn dependency_to_self_errors() {
    let mut mgr = TaskManager::new();
    let a = add(&mut mgr, "A");
    let outcome = mgr.update_task(
        &a,
        TaskUpdateParams {
            add_blocks: Some(vec![a.clone()]),
            ..TaskUpdateParams::default()
        },
    );
    assert!(outcome.is_err(), "self-blocks MUST be refused");
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Field updates
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn subject_description_active_form_updates_round_trip() {
    let mut mgr = TaskManager::new();
    let id = add(&mut mgr, "old");
    mgr.update_task(
        &id,
        TaskUpdateParams {
            subject: Some("new subject".to_string()),
            description: Some("new desc".to_string()),
            active_form: Some("Doing thing".to_string()),
            ..TaskUpdateParams::default()
        },
    )
    .expect("update");

    let task = mgr.get_task(&id).unwrap();
    assert_eq!(task.subject, "new subject");
    assert_eq!(task.description, "new desc");
    assert_eq!(task.active_form.as_deref(), Some("Doing thing"));
}

#[test]
fn empty_update_params_leaves_task_unchanged() {
    let mut mgr = TaskManager::new();
    let id = add(&mut mgr, "stable");
    let before = mgr.get_task(&id).unwrap().clone();
    let graph_before = serde_json::to_vec(mgr.graph()).expect("serialize graph before");
    let generation_before = mgr.generation();
    mgr.update_task(&id, TaskUpdateParams::default())
        .expect("noop update");
    let after = mgr.get_task(&id).unwrap();
    assert_eq!(&before, after);
    assert_eq!(mgr.generation(), generation_before);
    assert_eq!(
        serde_json::to_vec(mgr.graph()).expect("serialize graph after"),
        graph_before
    );
}

#[test]
fn persistent_semantic_noop_does_not_republish_storage() {
    let root = tempfile::tempdir().expect("persistent task root");
    let target = PathBuf::from("tasks.json");
    let actor = TaskActor::new(
        Actor {
            id: ActorId::new(),
            role: ActorRole::Planner,
        },
        RunId::new(),
    );
    let mut manager = TaskManager::open(root.path(), target.clone(), "persistent-noop", actor)
        .expect("persistent task manager");
    let task_id = add(&mut manager, "stable persisted task");
    let before_graph = serde_json::to_vec(manager.graph()).expect("graph before no-op");
    let before_file = std::fs::read(root.path().join(&target)).expect("file before no-op");

    manager
        .update_task(&task_id, TaskUpdateParams::default())
        .expect("semantic no-op");

    assert_eq!(
        serde_json::to_vec(manager.graph()).expect("graph after no-op"),
        before_graph
    );
    assert_eq!(
        std::fs::read(root.path().join(target)).expect("file after no-op"),
        before_file
    );
    let receipt = manager.last_receipt().expect("no-op receipt");
    assert!(receipt.graph.affected.is_empty());
    assert!(receipt.persistence.is_none());
}

#[test]
fn durable_reopen_uses_stable_session_lane_not_rotating_run_identity() {
    let root = tempfile::tempdir().expect("persistent task root");
    let target = PathBuf::from("resume-tasks.json");
    let actor_for = |session_id: &str| {
        TaskActor::with_session(
            Actor {
                id: ActorId::new(),
                role: ActorRole::Planner,
            },
            RunId::new(),
            session_id,
        )
    };
    let mut first = TaskManager::open(
        root.path(),
        target.clone(),
        "durable-resume",
        actor_for("stable-session"),
    )
    .expect("first manager");
    let task_id = add(&mut first, "resume me");
    update_status(&mut first, &task_id, TaskUpdateStatus::InProgress)
        .expect("first run starts task");
    drop(first);

    let mut resumed = TaskManager::open(
        root.path(),
        target.clone(),
        "durable-resume",
        actor_for("stable-session"),
    )
    .expect("resumed manager");
    update_status(&mut resumed, &task_id, TaskUpdateStatus::Completed)
        .expect("resumed run completes same session task");
    assert_eq!(status_of(&resumed, &task_id), Some(TaskStatus::Completed));
    drop(resumed);

    let mut foreign = TaskManager::open(
        root.path(),
        target,
        "durable-resume",
        actor_for("foreign-session"),
    )
    .expect("foreign manager can inspect bounded data");
    let before = std::fs::read(root.path().join("resume-tasks.json")).expect("before rejection");
    let error = update_status(&mut foreign, &task_id, TaskUpdateStatus::Pending)
        .expect_err("foreign session must not mutate task");
    assert!(error.contains("another session lane"), "{error}");
    assert_eq!(
        std::fs::read(root.path().join("resume-tasks.json")).expect("after rejection"),
        before
    );
}

#[test]
fn failed_and_canceled_are_terminal_and_returning_to_pending_clears_terminal_time() {
    let mut mgr = TaskManager::new();
    let failed = add(&mut mgr, "failed");
    update_status(&mut mgr, &failed, TaskUpdateStatus::Failed).expect("fail task");
    assert!(mgr.get_task(&failed).unwrap().terminal_at.is_some());
    update_status(&mut mgr, &failed, TaskUpdateStatus::Pending).expect("retry task");
    assert!(mgr.get_task(&failed).unwrap().terminal_at.is_none());

    let canceled = add(&mut mgr, "canceled");
    update_status(&mut mgr, &canceled, TaskUpdateStatus::Canceled).expect("cancel task");
    assert!(mgr.get_task(&canceled).unwrap().terminal_at.is_some());
}

#[test]
fn priority_update_changes_deterministic_ready_order() {
    let mut mgr = TaskManager::new();
    let medium = add(&mut mgr, "medium");
    let critical = add(&mut mgr, "critical");
    mgr.update_task(
        &critical,
        TaskUpdateParams {
            priority: Some(TaskPriority::Critical),
            ..TaskUpdateParams::default()
        },
    )
    .expect("set critical priority");
    let ready = mgr.ready_tasks(10).expect("ready tasks");
    assert_eq!(
        ready
            .tasks
            .iter()
            .map(|task| task.id.as_str())
            .collect::<Vec<_>>(),
        vec![critical.as_str(), medium.as_str()]
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — TaskStatus serialization shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_status_display_matches_serde_snake_case() {
    let cases = &[
        (TaskStatus::Pending, "pending"),
        (TaskStatus::InProgress, "in_progress"),
        (TaskStatus::Completed, "completed"),
        (TaskStatus::Failed, "failed"),
        (TaskStatus::Canceled, "canceled"),
    ];
    for (status, expected) in cases {
        assert_eq!(format!("{status}"), *expected);
        let json = serde_json::to_string(status).expect("serialize");
        assert_eq!(json.trim_matches('"'), *expected);
    }
}

#[test]
fn task_serde_round_trip_preserves_all_fields() {
    let mut mgr = TaskManager::new();
    let id = add(&mut mgr, "round-trip");
    mgr.update_task(
        &id,
        TaskUpdateParams {
            description: Some("desc".to_string()),
            active_form: Some("doing".to_string()),
            ..TaskUpdateParams::default()
        },
    )
    .expect("update");
    let task = mgr.get_task(&id).unwrap().clone();

    let json = serde_json::to_string(&task).expect("serialize");
    let back: Task = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, task);
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — list_tasks + format helpers
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_tasks_preserves_insertion_order() {
    let mut mgr = TaskManager::new();
    for name in &["first", "second", "third", "fourth"] {
        add(&mut mgr, name);
    }
    let listed = mgr.list_tasks();
    assert_eq!(listed.len(), 4);
    for (i, expected) in ["first", "second", "third", "fourth"].iter().enumerate() {
        assert_eq!(
            listed[i].subject, *expected,
            "tasks must surface in insertion order; pos {i}"
        );
    }
}

#[test]
fn format_task_summary_includes_id_and_subject() {
    let mut mgr = TaskManager::new();
    let id = add(&mut mgr, "implement feature X");
    let task = mgr.get_task(&id).unwrap();
    let summary = TaskManager::format_task_summary(task);
    assert!(
        summary.contains(&id),
        "summary must include id; got {summary:?}"
    );
    assert!(
        summary.contains("implement feature X"),
        "summary must include subject; got {summary:?}"
    );
}

#[test]
fn format_task_detail_includes_status_label() {
    let mut mgr = TaskManager::new();
    let id = add(&mut mgr, "task");
    let task = mgr.get_task(&id).unwrap();
    let detail = TaskManager::format_task_detail(task);
    assert!(
        detail.to_lowercase().contains("pending"),
        "detail must mention status; got {detail:?}"
    );
}
