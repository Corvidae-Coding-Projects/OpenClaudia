//! End-to-end tests for `transcript` path helpers + envelope
//! construction + append/load round-trips against tempdirs.
//!
//! Sprint 58 (pivot) — the original plan was CLI subcommands but
//! `src/cli/*` lives in the binary crate (main.rs), not the
//! library, and lifting it to the library would require moving
//! several main.rs symbols too. Pivoted to `src/transcript.rs`
//! which is purely library-side, 0 unit tests, and equally
//! security-critical (it persists the agent's per-session
//! transcript with mode-0600 secrecy guarantees).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::transcript::{
    append_entry, entries_after_last_boundary, envelope_for, load_transcript,
    openclaudia_transcript_home_dir, project_dir_for, projects_dir, sanitize_path, transcript_path,
    SerializedMessage,
};
use serde_json::json;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

struct TranscriptHomeGuard {
    _lock: MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

impl TranscriptHomeGuard {
    fn set(path: &Path) -> Self {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = std::env::var_os("OPENCLAUDIA_TRANSCRIPT_HOME_DIR");
        unsafe {
            std::env::set_var("OPENCLAUDIA_TRANSCRIPT_HOME_DIR", path);
        }
        Self {
            _lock: lock,
            previous,
        }
    }
}

impl Drop for TranscriptHomeGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(previous) => std::env::set_var("OPENCLAUDIA_TRANSCRIPT_HOME_DIR", previous),
                None => std::env::remove_var("OPENCLAUDIA_TRANSCRIPT_HOME_DIR"),
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — sanitize_path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sanitize_path_replaces_non_alphanumeric_with_dashes() {
    let out = sanitize_path("/home/user/project");
    // Slashes become dashes; everything else lowercase-preserved.
    // Output also has a -<16hex> suffix appended.
    let dashed_prefix = "-home-user-project";
    assert!(
        out.starts_with(dashed_prefix),
        "sanitized path MUST start with dashed input; got {out:?}"
    );
}

#[test]
fn sanitize_path_appends_16_hex_digest_suffix() {
    let out = sanitize_path("/tmp/x");
    // Last 16 chars after the final dash must be lowercase hex.
    let suffix = out.rsplit('-').next().expect("suffix");
    assert_eq!(suffix.len(), 16, "digest suffix MUST be 16 chars");
    assert!(
        suffix.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "digest suffix MUST be lowercase hex; got {suffix:?}"
    );
}

#[test]
fn sanitize_path_truncates_long_prefix_to_200_chars() {
    let long_input = "/".repeat(300); // 300 slashes
    let out = sanitize_path(&long_input);
    // PREFIX_CAP=200, plus '-' separator, plus 16-char hex.
    // The prefix portion (before the final 16-char hex) MUST
    // be <= 200 chars.
    let prefix_len = out.len() - 17; // -16 hex - 1 dash
    assert!(
        prefix_len <= 200,
        "prefix MUST be capped at 200 chars; got {prefix_len}"
    );
}

#[test]
fn sanitize_path_is_deterministic_for_same_input() {
    let a = sanitize_path("/some/path");
    let b = sanitize_path("/some/path");
    assert_eq!(a, b, "sanitize_path MUST be deterministic");
}

#[test]
fn sanitize_path_distinguishes_different_inputs() {
    // Two inputs that sanitize to the same dashed-prefix but
    // differ in the original: the digest suffix ensures the
    // outputs differ.
    let a = sanitize_path("/foo");
    let b = sanitize_path("\\foo"); // alphanumeric prefix identical post-sanitize
    assert_ne!(
        a, b,
        "different inputs MUST produce different sanitized paths"
    );
}

#[test]
fn sanitize_path_handles_empty_input() {
    let out = sanitize_path("");
    // Output: empty prefix + dash + 16 hex chars.
    assert!(!out.is_empty());
    assert!(out.starts_with('-'));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — projects_dir / project_dir_for / transcript_path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn projects_dir_lives_under_openclaudia_transcript_home() {
    let projects = projects_dir();
    let home = openclaudia_transcript_home_dir();
    assert!(
        projects.starts_with(&home),
        "projects_dir MUST live under the OpenClaudia transcript home; got {projects:?} not under {home:?}"
    );
    assert!(
        projects.ends_with("projects"),
        "projects_dir MUST end with 'projects'; got {projects:?}"
    );
}

#[test]
fn project_dir_for_uses_sanitized_cwd_as_leaf() {
    let cwd = Path::new("/tmp/test-project");
    let pdir = project_dir_for(cwd);
    let leaf = pdir.file_name().unwrap().to_string_lossy().into_owned();
    let expected_leaf = sanitize_path(&cwd.to_string_lossy());
    assert_eq!(leaf, expected_leaf, "leaf MUST equal sanitize_path(cwd)");
}

#[test]
fn transcript_path_includes_session_id_with_jsonl_extension() {
    let cwd = Path::new("/tmp/proj");
    let path = transcript_path(cwd, "abc-123");
    let leaf = path.file_name().unwrap().to_string_lossy().into_owned();
    assert_eq!(leaf, "abc-123.jsonl");
}

#[test]
fn transcript_path_is_under_project_dir() {
    let cwd = Path::new("/tmp/proj");
    let path = transcript_path(cwd, "session-1");
    let parent = path.parent().unwrap();
    assert_eq!(parent, project_dir_for(cwd));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — envelope_for
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn envelope_for_populates_kind_session_id_cwd_and_uuid() {
    let cwd = Path::new("/tmp/x");
    let env = envelope_for("user", cwd, "session-XYZ", Some(json!({"text": "hi"})));
    assert_eq!(env.kind, "user");
    assert_eq!(env.session_id, "session-XYZ");
    assert_eq!(env.cwd, "/tmp/x");
    // UUID-v4: 36 chars (32 hex + 4 dashes).
    assert_eq!(env.uuid.len(), 36);
    // Timestamp: RFC3339-ish, contains 'T'.
    assert!(env.timestamp.contains('T'));
    // Message round-trips.
    assert_eq!(env.message, Some(json!({"text": "hi"})));
}

#[test]
fn envelope_for_two_calls_yield_distinct_uuids() {
    let cwd = Path::new("/tmp/x");
    let a = envelope_for("user", cwd, "s1", None);
    let b = envelope_for("user", cwd, "s1", None);
    assert_ne!(
        a.uuid, b.uuid,
        "consecutive envelopes MUST have distinct uuids"
    );
}

#[test]
fn envelope_for_version_field_is_populated() {
    let cwd = Path::new("/tmp/x");
    let env = envelope_for("assistant", cwd, "s1", None);
    assert!(!env.version.is_empty(), "version field MUST be populated");
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — append_entry + load_transcript round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn append_entry_creates_jsonl_file_and_load_round_trips() {
    let dir = TempDir::new().expect("tempdir");
    let _home = TranscriptHomeGuard::set(dir.path());
    // Redirect owned transcript storage into this fixture.
    let session = "session-test";
    let cwd = dir.path();

    let env = envelope_for("user", cwd, session, Some(json!({"text": "hello"})));
    append_entry(cwd, session, &env).expect("append must succeed");

    // load_transcript reads from the same path append_entry
    // writes to.
    let path = transcript_path(cwd, session);
    let loaded = load_transcript(&path);
    assert_eq!(loaded.len(), 1, "1 appended MUST yield 1 loaded");
    assert_eq!(loaded[0].kind, "user");
    assert_eq!(loaded[0].session_id, session);
    assert_eq!(loaded[0].uuid, env.uuid);
}

#[test]
fn append_entry_preserves_message_payload_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let _home = TranscriptHomeGuard::set(dir.path());
    let cwd = dir.path();
    let session = "payload-test";
    let payload = json!({
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Hello, world!"},
            {"type": "tool_use", "id": "tx", "name": "bash"}
        ]
    });
    let env = envelope_for("assistant", cwd, session, Some(payload.clone()));
    append_entry(cwd, session, &env).expect("append");
    let path = transcript_path(cwd, session);
    let loaded = load_transcript(&path);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].message, Some(payload));
}

#[test]
fn load_transcript_skips_unparseable_lines_without_failing() {
    let dir = TempDir::new().expect("tempdir");
    let _home = TranscriptHomeGuard::set(dir.path());
    let session = "mixed";
    let path = transcript_path(dir.path(), session);
    std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir parent");
    // Write a mixed file: 1 valid JSON line + 1 garbage + 1 valid.
    let env_a = envelope_for("user", dir.path(), session, None);
    let env_b = envelope_for("assistant", dir.path(), session, None);
    let line_a = serde_json::to_string(&env_a).unwrap();
    let line_b = serde_json::to_string(&env_b).unwrap();
    let contents = format!("{line_a}\nNOT JSON HERE\n{line_b}\n\n");
    std::fs::write(&path, contents).expect("write");
    let loaded = load_transcript(&path);
    assert_eq!(
        loaded.len(),
        2,
        "valid lines MUST load, garbage MUST be skipped"
    );
}

#[test]
fn load_transcript_on_missing_file_returns_empty_vec() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("never-existed.jsonl");
    let loaded = load_transcript(&path);
    assert!(loaded.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — append_entry sets mode 0o600 on unix
// ───────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn append_entry_creates_file_with_mode_0o600_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().expect("tempdir");
    let _home = TranscriptHomeGuard::set(dir.path());
    let cwd = dir.path();
    let session = "perm-test";
    let env = envelope_for("user", cwd, session, None);
    append_entry(cwd, session, &env).expect("append");
    let path = transcript_path(cwd, session);
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "transcript file MUST be 0o600 (crosslink #948 / #801); got {mode:o}"
    );
}

#[cfg(unix)]
#[test]
fn append_entry_creates_project_dir_with_mode_0o700_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().expect("tempdir");
    let _home = TranscriptHomeGuard::set(dir.path());
    let cwd = dir.path();
    let session = "dir-perm-test";
    let env = envelope_for("user", cwd, session, None);
    append_entry(cwd, session, &env).expect("append");
    let parent = transcript_path(cwd, session)
        .parent()
        .unwrap()
        .to_path_buf();
    let mode = std::fs::metadata(&parent)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "project dir MUST be 0o700; got {mode:o}");
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — entries_after_last_boundary
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn entries_after_last_boundary_returns_full_slice_when_no_boundary() {
    let dir = TempDir::new().expect("tempdir");
    let cwd = dir.path();
    let entries: Vec<SerializedMessage> = (0..3)
        .map(|_| envelope_for("user", cwd, "s", None))
        .collect();
    let after = entries_after_last_boundary(&entries);
    assert_eq!(after.len(), 3, "no boundary → full slice returned");
}

#[test]
fn entries_after_last_boundary_returns_empty_for_empty_input() {
    let after = entries_after_last_boundary(&[]);
    assert!(after.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — SerializedMessage serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn serialized_message_round_trips_through_jsonl_line() {
    let dir = TempDir::new().expect("tempdir");
    let env = envelope_for(
        "tool_result",
        dir.path(),
        "s-1",
        Some(json!({"ok": true, "data": [1, 2, 3]})),
    );
    let json = serde_json::to_string(&env).expect("serialize");
    let back: SerializedMessage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.kind, env.kind);
    assert_eq!(back.uuid, env.uuid);
    assert_eq!(back.session_id, env.session_id);
    assert_eq!(back.message, env.message);
}
