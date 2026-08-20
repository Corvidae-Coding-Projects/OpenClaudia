//! End-to-end tests for `PluginMcpRegistry` namespace semantics +
//! `DiagnosticRegistry`/`DefaultDiagnosticInjector` rendering.
//!
//! Sprint 48 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::secrets::{EnvironmentGrants, SensitiveHeaders};
use openclaudia::services::lsp_diagnostics::DEFAULT_PER_FILE_CAP;
use openclaudia::services::{
    DefaultDiagnosticInjector, Diagnostic, DiagnosticInjector, DiagnosticRegistry,
    DiagnosticSeverity, McpRegistration, McpServerSpec, NoopDiagnosticInjector, PluginMcpRegistry,
};
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn make_spec(transport: &str) -> McpServerSpec {
    McpServerSpec {
        command: Some("test-bin".to_string()),
        args: vec!["--flag".to_string()],
        env: EnvironmentGrants::new(),
        transport: transport.to_string(),
        url: None,
        headers: SensitiveHeaders::new(),
        headers_helper: None,
        timeout: None,
        always_load: None,
    }
}

fn make_registration(plugin: &str, server: &str) -> McpRegistration {
    McpRegistration {
        plugin_id: plugin.to_string(),
        server_name: server.to_string(),
        spec: make_spec("stdio"),
    }
}

fn diag(line: u32, msg: &str, sev: DiagnosticSeverity) -> Diagnostic {
    Diagnostic {
        line,
        character: 0,
        severity: sev,
        message: msg.to_string(),
        source: None,
    }
}

fn diag_with_source(line: u32, msg: &str, sev: DiagnosticSeverity, src: &str) -> Diagnostic {
    Diagnostic {
        line,
        character: 5,
        severity: sev,
        message: msg.to_string(),
        source: Some(src.to_string()),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — PluginMcpRegistry replace + remove
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_registry_reports_zero_count_and_empty_all() {
    let reg = PluginMcpRegistry::default();
    assert_eq!(reg.count(), 0);
    assert!(reg.all().is_empty());
    assert!(reg.for_plugin("anything").is_empty());
}

#[test]
fn replace_plugin_with_two_servers_yields_count_2() {
    let mut reg = PluginMcpRegistry::default();
    reg.replace_plugin(
        "plugin-a",
        vec![
            make_registration("plugin-a", "server-1"),
            make_registration("plugin-a", "server-2"),
        ],
    );
    assert_eq!(reg.count(), 2);
    assert_eq!(reg.for_plugin("plugin-a").len(), 2);
}

#[test]
fn replace_plugin_with_empty_vec_drops_the_plugin_entry() {
    let mut reg = PluginMcpRegistry::default();
    reg.replace_plugin("p", vec![make_registration("p", "s")]);
    assert_eq!(reg.count(), 1);
    // Replacing with [] drops the entry — documented contract.
    reg.replace_plugin("p", vec![]);
    assert_eq!(reg.count(), 0);
    assert!(reg.for_plugin("p").is_empty());
}

#[test]
fn replace_plugin_atomically_swaps_the_set() {
    let mut reg = PluginMcpRegistry::default();
    reg.replace_plugin(
        "p",
        vec![
            make_registration("p", "old-1"),
            make_registration("p", "old-2"),
        ],
    );
    // Replace with a different set of 3.
    reg.replace_plugin(
        "p",
        vec![
            make_registration("p", "new-1"),
            make_registration("p", "new-2"),
            make_registration("p", "new-3"),
        ],
    );
    let regs = reg.for_plugin("p");
    let names_set: std::collections::HashSet<String> =
        regs.iter().map(|r| r.server_name.clone()).collect();
    assert_eq!(names_set.len(), 3, "exactly 3 new servers");
    assert!(names_set.contains("new-1"));
    assert!(names_set.contains("new-2"));
    assert!(names_set.contains("new-3"));
    // Old servers are gone.
    let serialised = format!("{:?}", reg.for_plugin("p"));
    assert!(!serialised.contains("old-1"));
    assert!(!serialised.contains("old-2"));
}

#[test]
fn remove_plugin_drops_only_that_plugin_entries() {
    let mut reg = PluginMcpRegistry::default();
    reg.replace_plugin("a", vec![make_registration("a", "x")]);
    reg.replace_plugin("b", vec![make_registration("b", "y")]);
    assert_eq!(reg.count(), 2);
    reg.remove_plugin("a");
    assert_eq!(reg.count(), 1);
    assert!(reg.for_plugin("a").is_empty());
    assert_eq!(reg.for_plugin("b").len(), 1);
}

#[test]
fn remove_plugin_no_op_when_plugin_absent() {
    let mut reg = PluginMcpRegistry::default();
    reg.replace_plugin("a", vec![make_registration("a", "x")]);
    reg.remove_plugin("never-installed");
    assert_eq!(reg.count(), 1, "removing nonexistent must not affect a");
}

#[test]
fn all_returns_flat_list_across_plugins() {
    let mut reg = PluginMcpRegistry::default();
    reg.replace_plugin(
        "alpha",
        vec![
            make_registration("alpha", "s1"),
            make_registration("alpha", "s2"),
        ],
    );
    reg.replace_plugin("beta", vec![make_registration("beta", "s3")]);
    let all = reg.all();
    assert_eq!(all.len(), 3);
    let names: std::collections::HashSet<&str> =
        all.iter().map(|r| r.server_name.as_str()).collect();
    assert!(names.contains("s1"));
    assert!(names.contains("s2"));
    assert!(names.contains("s3"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — DiagnosticSeverity wire encoding
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn severity_wire_matches_lsp_spec_integers() {
    assert_eq!(DiagnosticSeverity::Error.wire(), 1);
    assert_eq!(DiagnosticSeverity::Warning.wire(), 2);
    assert_eq!(DiagnosticSeverity::Information.wire(), 3);
    assert_eq!(DiagnosticSeverity::Hint.wire(), 4);
}

#[test]
fn severity_from_wire_decodes_valid_integers() {
    assert_eq!(DiagnosticSeverity::from_wire(1), DiagnosticSeverity::Error);
    assert_eq!(
        DiagnosticSeverity::from_wire(2),
        DiagnosticSeverity::Warning
    );
    assert_eq!(
        DiagnosticSeverity::from_wire(3),
        DiagnosticSeverity::Information
    );
    assert_eq!(DiagnosticSeverity::from_wire(4), DiagnosticSeverity::Hint);
}

#[test]
fn severity_from_wire_defaults_invalid_to_information() {
    // Documented: out-of-range values default to Information.
    for n in [0u8, 5, 10, 255] {
        assert_eq!(
            DiagnosticSeverity::from_wire(n),
            DiagnosticSeverity::Information,
            "wire={n} MUST default to Information"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — DiagnosticRegistry set / get / drain
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_set_and_get_round_trip() {
    let reg = DiagnosticRegistry::new();
    let diags = vec![
        diag(10, "error A", DiagnosticSeverity::Error),
        diag(20, "warning B", DiagnosticSeverity::Warning),
    ];
    reg.set("file://x.rs", diags.clone());
    let got = reg.get("file://x.rs");
    assert_eq!(got, diags);
}

#[test]
fn registry_set_empty_removes_the_uri_entirely() {
    let reg = DiagnosticRegistry::new();
    reg.set("file://x.rs", vec![diag(1, "x", DiagnosticSeverity::Error)]);
    assert_eq!(reg.total(), 1);
    // Publishing an empty list MUST remove the entry (matches
    // LSP publishDiagnostics semantics — empty = "no diagnostics
    // for this file").
    reg.set("file://x.rs", vec![]);
    assert_eq!(reg.total(), 0);
    assert!(reg.get("file://x.rs").is_empty());
}

#[test]
fn registry_set_is_full_replacement_per_uri() {
    let reg = DiagnosticRegistry::new();
    reg.set(
        "file://x.rs",
        vec![diag(1, "first", DiagnosticSeverity::Error)],
    );
    reg.set(
        "file://x.rs",
        vec![
            diag(10, "second", DiagnosticSeverity::Warning),
            diag(20, "third", DiagnosticSeverity::Warning),
        ],
    );
    // Only second + third remain.
    let got = reg.get("file://x.rs");
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].message, "second");
}

#[test]
fn registry_get_unknown_uri_returns_empty() {
    let reg = DiagnosticRegistry::new();
    assert!(reg.get("file://never-set.rs").is_empty());
}

#[test]
fn registry_total_sums_across_uris() {
    let reg = DiagnosticRegistry::new();
    reg.set("a.rs", vec![diag(1, "1", DiagnosticSeverity::Error)]);
    reg.set(
        "b.rs",
        vec![
            diag(2, "2", DiagnosticSeverity::Warning),
            diag(3, "3", DiagnosticSeverity::Hint),
        ],
    );
    assert_eq!(reg.total(), 3);
}

#[test]
fn registry_drain_empties_the_registry_and_returns_all_entries() {
    let reg = DiagnosticRegistry::new();
    reg.set("a.rs", vec![diag(1, "x", DiagnosticSeverity::Error)]);
    reg.set("b.rs", vec![diag(2, "y", DiagnosticSeverity::Warning)]);
    assert_eq!(reg.total(), 2);
    let drained = reg.drain();
    assert_eq!(drained.len(), 2);
    // Post-drain: empty.
    assert_eq!(reg.total(), 0);
    assert!(reg.get("a.rs").is_empty());
    assert!(reg.get("b.rs").is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — DiagnosticRegistry per-file cap
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_default_cap_truncates_excess_diagnostics() {
    let reg = DiagnosticRegistry::new();
    // Build a list slightly over the default cap.
    let oversize: Vec<Diagnostic> = (0..(DEFAULT_PER_FILE_CAP + 10))
        .map(|i| {
            diag(
                u32::try_from(i + 1).unwrap(),
                "msg",
                DiagnosticSeverity::Error,
            )
        })
        .collect();
    reg.set("noisy.rs", oversize);
    let got = reg.get("noisy.rs");
    assert_eq!(
        got.len(),
        DEFAULT_PER_FILE_CAP,
        "stored count MUST be capped at DEFAULT_PER_FILE_CAP"
    );
}

#[test]
fn registry_with_custom_cap_enforces_it() {
    let reg = DiagnosticRegistry::with_cap(3);
    let many: Vec<Diagnostic> = (0..10)
        .map(|i| {
            diag(
                u32::try_from(i + 1).unwrap(),
                "x",
                DiagnosticSeverity::Warning,
            )
        })
        .collect();
    reg.set("f.rs", many);
    assert_eq!(reg.get("f.rs").len(), 3, "custom cap=3 must apply");
}

#[test]
fn registry_with_cap_zero_clamps_to_one() {
    // Documented: cap is `max(input, 1)` so a cap of 0 is
    // pinned to 1.
    let reg = DiagnosticRegistry::with_cap(0);
    let two: Vec<Diagnostic> = (0..2)
        .map(|i| diag(u32::try_from(i + 1).unwrap(), "x", DiagnosticSeverity::Hint))
        .collect();
    reg.set("f.rs", two);
    assert_eq!(reg.get("f.rs").len(), 1);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — NoopDiagnosticInjector
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn noop_injector_always_returns_none_even_with_diagnostics() {
    let injector = NoopDiagnosticInjector;
    let mut diags = HashMap::new();
    diags.insert(
        "a.rs".to_string(),
        vec![diag(1, "won't appear", DiagnosticSeverity::Error)],
    );
    let outcome = injector.render(&diags);
    assert!(
        outcome.is_none(),
        "noop injector MUST suppress every input; got {outcome:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — DefaultDiagnosticInjector rendering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn default_injector_returns_none_on_empty_input() {
    let injector = DefaultDiagnosticInjector;
    let empty = HashMap::new();
    assert!(injector.render(&empty).is_none());
}

#[test]
fn default_injector_wraps_in_lsp_diagnostics_tag() {
    let injector = DefaultDiagnosticInjector;
    let mut diags = HashMap::new();
    diags.insert(
        "src/main.rs".to_string(),
        vec![diag(42, "unused variable", DiagnosticSeverity::Warning)],
    );
    let rendered = injector.render(&diags).expect("non-empty render");
    assert!(rendered.starts_with("<lsp-diagnostics>"));
    assert!(rendered.ends_with("</lsp-diagnostics>"));
    assert!(rendered.contains("src/main.rs"));
    assert!(rendered.contains("warning at 42:0: unused variable"));
}

#[test]
fn default_injector_sorts_files_for_deterministic_output() {
    let injector = DefaultDiagnosticInjector;
    let mut diags = HashMap::new();
    diags.insert(
        "zeta.rs".to_string(),
        vec![diag(1, "z", DiagnosticSeverity::Error)],
    );
    diags.insert(
        "alpha.rs".to_string(),
        vec![diag(1, "a", DiagnosticSeverity::Error)],
    );
    diags.insert(
        "middle.rs".to_string(),
        vec![diag(1, "m", DiagnosticSeverity::Error)],
    );
    let rendered = injector.render(&diags).expect("render");
    let alpha_pos = rendered.find("alpha.rs").expect("alpha");
    let middle_pos = rendered.find("middle.rs").expect("middle");
    let zeta_pos = rendered.find("zeta.rs").expect("zeta");
    assert!(
        alpha_pos < middle_pos && middle_pos < zeta_pos,
        "files MUST be sorted alphabetically for deterministic output; \
         got alpha={alpha_pos}, middle={middle_pos}, zeta={zeta_pos}"
    );
}

#[test]
fn default_injector_includes_source_when_present() {
    let injector = DefaultDiagnosticInjector;
    let mut diags = HashMap::new();
    diags.insert(
        "src/main.rs".to_string(),
        vec![diag_with_source(
            10,
            "use of moved value",
            DiagnosticSeverity::Error,
            "rust-analyzer",
        )],
    );
    let rendered = injector.render(&diags).expect("render");
    assert!(
        rendered.contains("(rust-analyzer)"),
        "rendered MUST tag the source in parens; got {rendered:?}"
    );
}

#[test]
fn default_injector_uses_documented_severity_labels() {
    let injector = DefaultDiagnosticInjector;
    let mut diags = HashMap::new();
    diags.insert(
        "f.rs".to_string(),
        vec![
            diag(1, "an err", DiagnosticSeverity::Error),
            diag(2, "a warn", DiagnosticSeverity::Warning),
            diag(3, "an info", DiagnosticSeverity::Information),
            diag(4, "a hint", DiagnosticSeverity::Hint),
        ],
    );
    let rendered = injector.render(&diags).expect("render");
    // All 4 severity labels must appear (documented as
    // error / warning / info / hint).
    for label in &["error", "warning", "info", "hint"] {
        assert!(
            rendered.contains(label),
            "rendered MUST include severity label {label:?}; got {rendered:?}"
        );
    }
}
