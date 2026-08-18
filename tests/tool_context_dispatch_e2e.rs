//! End-to-end tests for `tools::registry::ToolContext`
//! shape + `ToolRegistry::dispatch` against unknown +
//! known tools.
//!
//! Sprint 132 of the verification effort. Sprint 23 covered
//! handler definitions + permission targets; this file
//! pins the `ToolContext` struct-literal shape (3 optional
//! fields), the `dispatch` None-on-unknown semantics, and
//! the `(String, bool)` return tuple via a real handler.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use serde_json::{json, Value};
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Section A — ToolContext struct-literal construction
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn tool_context_struct_literal_with_all_none_fields() {
    let ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    assert!(ctx.memory_db.is_none());
    assert!(ctx.app_config.is_none());
    assert!(ctx.task_mgr.is_none());
}

const fn accept_mut_ref(c: &mut ToolContext<'_>) {
    // Mutate task_mgr field to satisfy &mut usage.
    c.task_mgr = None;
}

#[test]
fn tool_context_can_be_taken_by_mut_reference_for_dispatch() {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    // Borrow as &mut — the dispatch signature requires it.
    accept_mut_ref(&mut ctx);
}

#[test]
fn tool_context_field_assignment_via_struct_literal_works() {
    // PINS SHAPE: 3 documented fields, all Option types.
    let ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    // Compile-time pin: explicit types on the fields.
    let _: Option<&openclaudia::memory::MemoryDb> = ctx.memory_db;
    let _: Option<&openclaudia::config::AppConfig> = ctx.app_config;
    let _: Option<&mut openclaudia::session::TaskManager> = ctx.task_mgr;
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Registry dispatch on unknown tool
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_unknown_tool_returns_none() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let args: HashMap<String, Value> = HashMap::new();
    let outcome = reg.dispatch("definitely_not_a_real_tool_xyz_sprint132", &args, &mut ctx);
    assert!(outcome.is_none(), "unknown tool MUST return None");
}

#[test]
fn dispatch_empty_string_tool_name_returns_none() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let args = HashMap::new();
    let outcome = reg.dispatch("", &args, &mut ctx);
    assert!(outcome.is_none());
}

#[test]
fn dispatch_whitespace_only_tool_name_returns_none() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let args = HashMap::new();
    let outcome = reg.dispatch("   ", &args, &mut ctx);
    assert!(outcome.is_none(), "whitespace name MUST NOT match");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Registry get vs dispatch consistency
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_returns_some_iff_dispatch_returns_some_for_same_name() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    // PINS CONTRACT: dispatch returns Some iff get returns Some.
    // (Both consult the same internal map.)
    for name in &["bash", "read_file", "tool_search", "no-such-tool"] {
        let get_some = reg.get(name).is_some();
        let dispatch_some = reg.dispatch(name, &HashMap::new(), &mut ctx).is_some();
        assert_eq!(
            get_some, dispatch_some,
            "name {name:?} disagreement between get and dispatch"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Registry singleton accessor
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_singleton_returns_same_reference_across_calls() {
    let r1: &'static _ = registry();
    let r2: &'static _ = registry();
    // Same memory address — single static instance.
    assert!(std::ptr::eq(r1, r2));
}

#[test]
fn registry_get_for_known_tool_returns_some_handler() {
    let reg = registry();
    // bash is a documented core tool.
    assert!(reg.get("bash").is_some());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Dispatch with read-only tool — tool_search
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_tool_search_returns_some_tuple() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("query".to_string(), json!("any-search-string"));
    args.insert("max_results".to_string(), json!(5));
    let outcome = reg.dispatch("tool_search", &args, &mut ctx);
    assert!(
        outcome.is_some(),
        "tool_search MUST be registered and dispatchable"
    );
    let (_text, _is_err) = outcome.unwrap().into_legacy();
    // Returns the documented tuple shape (String, bool).
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Dispatch ignores extra args (forward-compat)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_unknown_tool_with_arbitrary_args_still_returns_none() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("anything".to_string(), json!("value"));
    args.insert("count".to_string(), json!(42));
    args.insert("nested".to_string(), json!({"k": "v"}));
    let outcome = reg.dispatch("__no_such_tool__", &args, &mut ctx);
    assert!(outcome.is_none());
}

#[test]
fn dispatch_known_tool_with_empty_args_invokes_handler() {
    // PINS DOC: dispatch passes args through to handler;
    // handler decides what to do with empty.
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let args = HashMap::new();
    let outcome = reg.dispatch("tool_search", &args, &mut ctx);
    assert!(
        outcome.is_some(),
        "dispatch MUST invoke handler even with empty args"
    );
    let (_text, _is_err) = outcome.unwrap().into_legacy();
    // Result tuple shape preserved.
}
