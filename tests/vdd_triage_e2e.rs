//! End-to-end tests for the VDD finding/triage pipeline:
//! `parse_findings_detailed` outcome discrimination + raw-finding
//! to typed-Finding conversion + source-labeled VDD context rendering.
//!
//! Sprint 54 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::vdd::{
    findings_context_observation, parse_findings, parse_findings_detailed, Finding, FindingStatus,
    ParseErrorKind, ParseFindingsOutcome, Severity, StaticAnalysisResult,
};

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn finding(severity: Severity, description: &str) -> Finding {
    Finding {
        id: "fid-1".to_string(),
        severity,
        cwe: None,
        description: description.to_string(),
        file_path: None,
        line_range: None,
        status: FindingStatus::Genuine,
        adversary_reasoning: String::new(),
        iteration: 1,
    }
}

fn observation_content(findings: &[Finding], analysis: &[StaticAnalysisResult]) -> Option<String> {
    findings_context_observation(findings, analysis).map(|item| {
        assert_eq!(
            item.source(),
            openclaudia::context::ContextSource::Reference(
                openclaudia::context::ReferenceSource::Vdd,
            )
        );
        assert_eq!(
            item.authority(),
            openclaudia::context::ContextAuthority::Reference
        );
        item.content().to_string()
    })
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — ParseErrorKind labels
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_error_kind_labels_match_documented_strings() {
    // Documented contract: stable labels for metrics.
    assert_eq!(ParseErrorKind::NotJson.as_str(), "not_json");
    assert_eq!(ParseErrorKind::InvalidSchema.as_str(), "invalid_schema");
    assert_eq!(
        ParseErrorKind::MissingFindingsField.as_str(),
        "missing_findings_field"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — parse_findings_detailed: NoFindings
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn no_findings_assessment_yields_no_findings_variant() {
    let json = r#"{"findings": [], "assessment": "NO_FINDINGS"}"#;
    let outcome = parse_findings_detailed(json, 1);
    assert!(
        matches!(outcome, ParseFindingsOutcome::NoFindings),
        "explicit NO_FINDINGS assessment MUST yield NoFindings; got {outcome:?}"
    );
}

#[test]
fn fenced_json_block_with_no_findings_assessment_parsed() {
    let response = r#"
Here is my review:
```json
{"findings": [], "assessment": "NO_FINDINGS"}
```
That's all.
    "#;
    let outcome = parse_findings_detailed(response, 1);
    assert!(
        matches!(outcome, ParseFindingsOutcome::NoFindings),
        "JSON-in-fenced-block MUST be extracted; got {outcome:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — parse_findings_detailed: Findings
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn raw_findings_array_parses_into_typed_findings() {
    // Documented RawFinding fields: severity, cwe, description,
    // file, lines, reasoning (NOT file_path / line_range /
    // adversary_reasoning — those are post-triage typed names).
    let json = r#"{
        "findings": [
            {
                "severity": "HIGH",
                "cwe": "CWE-89",
                "description": "SQL injection in handler",
                "file": "src/db.rs",
                "lines": [42, 45],
                "reasoning": "user input flows into query"
            },
            {
                "severity": "LOW",
                "description": "minor style issue",
                "reasoning": "cosmetic only"
            }
        ],
        "assessment": "FINDINGS_PRESENT"
    }"#;
    let outcome = parse_findings_detailed(json, 3);
    let ParseFindingsOutcome::Findings(findings) = outcome else {
        panic!("expected Findings variant; got {outcome:?}");
    };
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
    assert_eq!(findings[0].file_path.as_deref(), Some("src/db.rs"));
    assert_eq!(findings[0].line_range, Some((42, 45)));
    assert_eq!(findings[0].iteration, 3, "iteration MUST be propagated");
    assert_eq!(findings[1].severity, Severity::Low);
}

#[test]
fn raw_finding_with_single_line_yields_line_range_of_that_line() {
    let json = r#"{
        "findings": [
            {"severity": "MEDIUM", "description": "x", "file": "f.rs", "lines": [10], "reasoning": "r"}
        ],
        "assessment": "FINDINGS_PRESENT"
    }"#;
    let ParseFindingsOutcome::Findings(findings) = parse_findings_detailed(json, 1) else {
        panic!("expected Findings");
    };
    assert_eq!(findings.len(), 1);
    // Single-element lines array → (n, n) per documented contract.
    assert_eq!(findings[0].line_range, Some((10, 10)));
}

#[test]
fn findings_have_distinct_ids_within_one_iteration() {
    let json = r#"{
        "findings": [
            {"severity": "HIGH", "description": "a", "reasoning": "r1"},
            {"severity": "HIGH", "description": "b", "reasoning": "r2"},
            {"severity": "HIGH", "description": "c", "reasoning": "r3"}
        ],
        "assessment": "FINDINGS_PRESENT"
    }"#;
    let ParseFindingsOutcome::Findings(findings) = parse_findings_detailed(json, 1) else {
        panic!("expected Findings");
    };
    assert_eq!(findings.len(), 3);
    let ids: std::collections::HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids.len(), 3, "ids MUST be pairwise distinct; got {ids:?}");
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — parse_findings_detailed: ParseError variants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unparseable_response_yields_not_json_parse_error() {
    let response = "this is just plain text with no JSON anywhere";
    let outcome = parse_findings_detailed(response, 1);
    assert!(
        matches!(
            outcome,
            ParseFindingsOutcome::ParseError {
                kind: ParseErrorKind::NotJson
            }
        ),
        "non-JSON MUST yield ParseError(NotJson); got {outcome:?}"
    );
}

#[test]
fn json_without_findings_field_yields_missing_findings_parse_error() {
    let json = r#"{"some_other_field": "value"}"#;
    let outcome = parse_findings_detailed(json, 1);
    assert!(
        matches!(
            outcome,
            ParseFindingsOutcome::ParseError {
                kind: ParseErrorKind::MissingFindingsField
            }
        ),
        "JSON without `findings` MUST yield ParseError(MissingFindingsField); got {outcome:?}"
    );
}

#[test]
fn json_with_non_array_findings_yields_invalid_schema_parse_error() {
    let json = r#"{"findings": "not an array"}"#;
    let outcome = parse_findings_detailed(json, 1);
    assert!(
        matches!(
            outcome,
            ParseFindingsOutcome::ParseError {
                kind: ParseErrorKind::InvalidSchema
            }
        ),
        "JSON with non-array `findings` MUST yield ParseError(InvalidSchema); got {outcome:?}"
    );
}

#[test]
fn fenced_json_with_non_array_findings_yields_invalid_schema_parse_error() {
    let response = r#"
The review result is:
```json
{"findings": "not an array"}
```
"#;
    let outcome = parse_findings_detailed(response, 1);
    assert!(
        matches!(
            outcome,
            ParseFindingsOutcome::ParseError {
                kind: ParseErrorKind::InvalidSchema
            }
        ),
        "fenced JSON with non-array `findings` MUST yield ParseError(InvalidSchema); got {outcome:?}"
    );
}

#[test]
fn empty_response_string_yields_not_json_parse_error() {
    let outcome = parse_findings_detailed("", 1);
    assert!(
        matches!(
            outcome,
            ParseFindingsOutcome::ParseError {
                kind: ParseErrorKind::NotJson
            }
        ),
        "empty string MUST yield ParseError(NotJson); got {outcome:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Legacy parse_findings shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn legacy_parse_findings_returns_empty_vec_for_no_findings() {
    let json = r#"{"findings": [], "assessment": "NO_FINDINGS"}"#;
    let findings = parse_findings(json, 1);
    assert!(
        findings.is_empty(),
        "legacy wrapper MUST return empty vec for NO_FINDINGS"
    );
}

#[test]
fn legacy_parse_findings_returns_empty_vec_for_parse_error() {
    let findings = parse_findings("garbage", 1);
    assert!(
        findings.is_empty(),
        "legacy wrapper MUST return empty vec for ParseError"
    );
}

#[test]
fn legacy_parse_findings_returns_typed_findings_for_valid_input() {
    let json = r#"{"findings": [{"severity": "MEDIUM", "description": "x", "reasoning": "r"}], "assessment": "FINDINGS_PRESENT"}"#;
    let findings = parse_findings(json, 7);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
    assert_eq!(findings[0].iteration, 7);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Severity Display + serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn severity_display_uses_uppercase_labels() {
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
    assert_eq!(format!("{}", Severity::High), "HIGH");
    assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
    assert_eq!(format!("{}", Severity::Low), "LOW");
    assert_eq!(format!("{}", Severity::Info), "INFO");
}

#[test]
fn severity_serde_matches_display() {
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let display = format!("{sev}");
        let json = serde_json::to_string(&sev).expect("serialize");
        let unquoted = json.trim_matches('"');
        assert_eq!(unquoted, display, "serde + Display MUST agree for {sev:?}");
    }
}

#[test]
fn severity_ordering_matches_severity_strength() {
    // Documented derive: Ord places Critical first (smallest).
    let mut sevs = vec![
        Severity::Info,
        Severity::Critical,
        Severity::Low,
        Severity::High,
        Severity::Medium,
    ];
    sevs.sort();
    assert_eq!(
        sevs,
        vec![
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — typed VDD context observations
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn no_genuine_findings_and_passing_analysis_produces_no_observation() {
    let findings = vec![];
    let analysis: Vec<StaticAnalysisResult> = vec![];
    assert!(observation_content(&findings, &analysis).is_none());
}

#[test]
fn observation_only_renders_genuine_findings_not_false_positives() {
    let mut fp = finding(Severity::High, "this is a false positive");
    fp.status = FindingStatus::FalsePositive;
    let real = finding(Severity::Critical, "real critical issue");
    let out = observation_content(&[fp, real], &[]).expect("VDD observation");
    assert!(
        out.contains("real critical issue"),
        "genuine finding MUST appear; got {out:?}"
    );
    assert!(
        !out.contains("this is a false positive"),
        "false positive MUST NOT appear; got {out:?}"
    );
}

#[test]
fn observation_uses_vdd_advisory_serialization() {
    let real = finding(Severity::High, "issue X");
    let out = observation_content(&[real], &[]).expect("VDD observation");
    assert!(out.starts_with("<vdd-advisory>"));
}

#[test]
fn observation_includes_severity_label_in_output() {
    let real = finding(Severity::Critical, "kabloom");
    let out = observation_content(&[real], &[]).expect("VDD observation");
    assert!(
        out.contains("CRITICAL"),
        "severity label MUST appear; got {out:?}"
    );
    assert!(
        out.contains("kabloom"),
        "description MUST appear; got {out:?}"
    );
}

#[test]
fn observation_includes_cwe_when_present() {
    let mut f = finding(Severity::High, "issue");
    f.cwe = Some("CWE-79".to_string());
    let out = observation_content(&[f], &[]).expect("VDD observation");
    assert!(out.contains("CWE-79"), "cwe MUST be rendered; got {out:?}");
}

#[test]
fn observation_includes_file_path_when_present() {
    let mut f = finding(Severity::Medium, "issue");
    f.file_path = Some("src/handler.rs".to_string());
    let out = observation_content(&[f], &[]).expect("VDD observation");
    assert!(
        out.contains("src/handler.rs"),
        "file_path MUST be rendered; got {out:?}"
    );
}

#[test]
fn observation_numbers_findings_starting_at_1() {
    let f1 = finding(Severity::High, "first");
    let f2 = finding(Severity::High, "second");
    let f3 = finding(Severity::High, "third");
    let out = observation_content(&[f1, f2, f3], &[]).expect("VDD observation");
    assert!(out.contains("1."), "first finding numbered 1");
    assert!(out.contains("2."));
    assert!(out.contains("3."));
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — FindingStatus serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn finding_status_serde_uses_snake_case() {
    let cases = &[
        (FindingStatus::Genuine, "genuine"),
        (FindingStatus::FalsePositive, "false_positive"),
        (FindingStatus::Disputed, "disputed"),
    ];
    for (status, expected) in cases {
        let json = serde_json::to_string(status).expect("serialize");
        assert_eq!(json.trim_matches('"'), *expected);
    }
}
