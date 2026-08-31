//! Explicit, typed technical-memory source discovery.
//!
//! `MEMORY.md` is retained as a compatibility filename, not as a prose or
//! prompt authority. A retained file must be an exact versioned JSON manifest
//! of [`TechnicalLessonDraft`] values. Discovery is rooted in the immutable
//! run capability, reads descriptor-pinned regular files under hard budgets,
//! rejects ambiguous candidates, and never consults an ambient home directory.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::memory::{
    LessonCitationKind, MemoryDigest, TechnicalLesson, TechnicalLessonDraft, WorkspaceMemoryId,
};
use crate::tools::file::secure_fs;
use crate::tools::ToolRunContext;

/// Exact technical-memory source schema accepted by this build.
pub const TECHNICAL_MEMORY_SOURCE_SCHEMA_VERSION: u32 = 1;
/// Maximum bytes read from either retained `MEMORY.md` candidate.
pub const MAX_ENTRYPOINT_BYTES: usize = 512 * 1_024;
/// Maximum lessons in one source generation.
pub const MAX_ENTRYPOINT_LESSONS: usize = 256;
/// Maximum citations across all lessons in one manifest.
pub const MAX_ENTRYPOINT_CITATIONS: usize = 512;
/// Maximum distinct workspace artifacts verified during one refresh.
pub const MAX_ENTRYPOINT_CITATION_FILES: usize = 64;
/// Maximum bytes read from one cited workspace artifact.
pub const MAX_ENTRYPOINT_CITATION_FILE_BYTES: usize = 4 * 1_024 * 1024;
/// Maximum aggregate bytes read while verifying cited artifacts.
pub const MAX_ENTRYPOINT_CITATION_BYTES: usize = 32 * 1_024 * 1024;

const ROOT_SOURCE_PATH: &str = "MEMORY.md";
const CONTROL_SOURCE_PATH: &str = ".openclaudia/MEMORY.md";
const MAX_SOURCE_ID_BYTES: usize = 96;
const MAX_LESSON_ID_BYTES: usize = 96;

/// One exact lesson identity and payload in a source generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalMemoryManifestEntry {
    pub lesson_id: String,
    pub lesson: TechnicalLessonDraft,
}

/// Strict repository-authored source envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalMemoryManifest {
    pub schema_version: u32,
    pub source_id: String,
    pub generation: u64,
    pub lessons: Vec<TechnicalMemoryManifestEntry>,
}

/// Descriptor-bound source snapshot admitted by discovery and schema checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrypointFile {
    /// Workspace-relative compatibility path.
    pub relative_path: String,
    /// Interoperable SHA-256 of the exact source bytes read twice.
    pub source_digest: MemoryDigest,
    /// Canonicalized strict lesson manifest.
    pub manifest: TechnicalMemoryManifest,
}

/// Stable machine-readable reason discovery did not admit a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointIssueCode {
    AmbiguousCandidates,
    InvalidEncoding,
    InvalidManifest,
    Oversized,
    UnstableSnapshot,
    UnsafeFile,
}

/// Bounded source-discovery problem. It never contains host-absolute paths or
/// source bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntrypointIssue {
    pub code: EntrypointIssueCode,
    pub relative_path: Option<String>,
}

/// Result of inspecting the two explicit workspace candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrypointInspection {
    Missing,
    Ready(EntrypointFile),
    Rejected(EntrypointIssue),
    Conflict(EntrypointIssue),
}

/// Discover and parse a strict technical-memory source for this exact run.
///
/// Both `<project>/MEMORY.md` and `<project>/.openclaudia/MEMORY.md` are
/// inspected. Two present candidates are a conflict rather than a precedence
/// rule. A present unsafe/corrupt candidate blocks fallback so a bad local file
/// cannot silently select a different source.
#[must_use]
pub fn load_entrypoint(run: &Arc<ToolRunContext>) -> EntrypointInspection {
    let workspace_id = WorkspaceMemoryId::for_canonical_root(run.project_root());
    let captured_at = chrono::Utc::now().timestamp();
    let mut ready = Vec::new();
    for (relative, control_plane) in [(ROOT_SOURCE_PATH, false), (CONTROL_SOURCE_PATH, true)] {
        match load_candidate(run, relative, control_plane, &workspace_id, captured_at) {
            Ok(Some(source)) => ready.push(source),
            Ok(None) => {}
            Err(issue) => return EntrypointInspection::Rejected(issue),
        }
    }
    match ready.len() {
        0 => EntrypointInspection::Missing,
        1 => EntrypointInspection::Ready(ready.remove(0)),
        _ => EntrypointInspection::Conflict(EntrypointIssue {
            code: EntrypointIssueCode::AmbiguousCandidates,
            relative_path: None,
        }),
    }
}

fn load_candidate(
    run: &ToolRunContext,
    relative: &str,
    control_plane: bool,
    workspace_id: &WorkspaceMemoryId,
    captured_at: i64,
) -> Result<Option<EntrypointFile>, EntrypointIssue> {
    let path = run.project_root().join(relative);
    let opened = if control_plane {
        secure_fs::open_host_control_regular_read(run, &path)
    } else {
        secure_fs::open_regular_read(run, &path)
    };
    let mut file = match opened {
        Ok(file) => file,
        Err(error) if secure_fs::is_not_found_message(&error) => return Ok(None),
        Err(_) => return Err(issue(EntrypointIssueCode::UnsafeFile, relative)),
    };
    let bytes = secure_fs::read_stable_bounded_bytes(&mut file, &path, MAX_ENTRYPOINT_BYTES)
        .map_err(|error| {
            let code = if error.contains("exceeds") {
                EntrypointIssueCode::Oversized
            } else if error.contains("changed while") {
                EntrypointIssueCode::UnstableSnapshot
            } else {
                EntrypointIssueCode::UnsafeFile
            };
            issue(code, relative)
        })?;
    let source_digest = MemoryDigest::sha256(&bytes);
    let manifest =
        parse_manifest(&bytes, workspace_id, captured_at).map_err(|code| issue(code, relative))?;
    Ok(Some(EntrypointFile {
        relative_path: relative.to_string(),
        source_digest,
        manifest,
    }))
}

fn parse_manifest(
    bytes: &[u8],
    workspace_id: &WorkspaceMemoryId,
    captured_at: i64,
) -> Result<TechnicalMemoryManifest, EntrypointIssueCode> {
    std::str::from_utf8(bytes).map_err(|_| EntrypointIssueCode::InvalidEncoding)?;
    let mut manifest: TechnicalMemoryManifest =
        serde_json::from_slice(bytes).map_err(|_| EntrypointIssueCode::InvalidManifest)?;
    if manifest.schema_version != TECHNICAL_MEMORY_SOURCE_SCHEMA_VERSION
        || manifest.generation == 0
        || !valid_source_identifier(&manifest.source_id, MAX_SOURCE_ID_BYTES)
        || manifest.lessons.len() > MAX_ENTRYPOINT_LESSONS
    {
        return Err(EntrypointIssueCode::InvalidManifest);
    }
    let mut previous: Option<&str> = None;
    let mut citation_count = 0_usize;
    for entry in &mut manifest.lessons {
        if !valid_source_identifier(&entry.lesson_id, MAX_LESSON_ID_BYTES)
            || previous.is_some_and(|value| value >= entry.lesson_id.as_str())
        {
            return Err(EntrypointIssueCode::InvalidManifest);
        }
        previous = Some(&entry.lesson_id);
        citation_count = citation_count
            .checked_add(entry.lesson.citations.len())
            .ok_or(EntrypointIssueCode::InvalidManifest)?;
        if citation_count > MAX_ENTRYPOINT_CITATIONS {
            return Err(EntrypointIssueCode::InvalidManifest);
        }
        let lesson = TechnicalLesson::from_candidate(
            workspace_id.clone(),
            entry.lesson.clone(),
            captured_at,
        )
        .map_err(|_| EntrypointIssueCode::InvalidManifest)?;
        entry.lesson = lesson.draft();
    }
    Ok(manifest)
}

fn valid_source_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// Verify every imported citation against an exact descriptor-bound workspace
/// artifact. Imported manifests cannot assert network, issue, commit, command,
/// build, or tool receipts that this host did not independently observe.
pub(crate) fn verify_entrypoint(
    run: &Arc<ToolRunContext>,
    source: &EntrypointFile,
) -> Result<(), EntrypointIssue> {
    let mut verified = BTreeMap::<String, VerifiedArtifact>::new();
    let mut aggregate_bytes = 0_usize;
    for entry in &source.manifest.lessons {
        for citation in &entry.lesson.citations {
            if !matches!(
                citation.kind,
                LessonCitationKind::Configuration
                    | LessonCitationKind::Documentation
                    | LessonCitationKind::SourceFile
                    | LessonCitationKind::Test
            ) || !valid_relative_artifact(&citation.locator)
                || citation.locator == ROOT_SOURCE_PATH
                || citation.locator == CONTROL_SOURCE_PATH
            {
                return Err(issue(
                    EntrypointIssueCode::InvalidManifest,
                    &source.relative_path,
                ));
            }
            if !verified.contains_key(&citation.locator) {
                if verified.len() >= MAX_ENTRYPOINT_CITATION_FILES {
                    return Err(issue(EntrypointIssueCode::Oversized, &source.relative_path));
                }
                let artifact = read_verified_artifact(run, &citation.locator)
                    .map_err(|code| issue(code, &source.relative_path))?;
                aggregate_bytes = aggregate_bytes
                    .checked_add(artifact.byte_count)
                    .ok_or_else(|| issue(EntrypointIssueCode::Oversized, &source.relative_path))?;
                if aggregate_bytes > MAX_ENTRYPOINT_CITATION_BYTES {
                    return Err(issue(EntrypointIssueCode::Oversized, &source.relative_path));
                }
                verified.insert(citation.locator.clone(), artifact);
            }
            let artifact = verified
                .get(&citation.locator)
                .ok_or_else(|| issue(EntrypointIssueCode::UnsafeFile, &source.relative_path))?;
            let expected_version = format!("workspace-file:{}", artifact.digest);
            if citation.digest != artifact.digest || citation.source_version != expected_version {
                return Err(issue(
                    EntrypointIssueCode::InvalidManifest,
                    &source.relative_path,
                ));
            }
            if let Some(line_end) = citation.line_end {
                if usize::try_from(line_end).map_or(true, |line| line > artifact.line_count) {
                    return Err(issue(
                        EntrypointIssueCode::InvalidManifest,
                        &source.relative_path,
                    ));
                }
            }
        }
    }
    Ok(())
}

struct VerifiedArtifact {
    digest: MemoryDigest,
    byte_count: usize,
    line_count: usize,
}

fn read_verified_artifact(
    run: &ToolRunContext,
    relative: &str,
) -> Result<VerifiedArtifact, EntrypointIssueCode> {
    let path = run.project_root().join(relative);
    let mut file =
        secure_fs::open_regular_read(run, &path).map_err(|_| EntrypointIssueCode::UnsafeFile)?;
    let bytes =
        secure_fs::read_stable_bounded_bytes(&mut file, &path, MAX_ENTRYPOINT_CITATION_FILE_BYTES)
            .map_err(|error| {
                if error.contains("exceeds") {
                    EntrypointIssueCode::Oversized
                } else if error.contains("changed while") {
                    EntrypointIssueCode::UnstableSnapshot
                } else {
                    EntrypointIssueCode::UnsafeFile
                }
            })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| EntrypointIssueCode::InvalidEncoding)?;
    let line_count = text.lines().count();
    Ok(VerifiedArtifact {
        digest: MemoryDigest::sha256(&bytes),
        byte_count: bytes.len(),
        line_count,
    })
}

fn valid_relative_artifact(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && !value.is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path.starts_with(PathBuf::from(".openclaudia"))
}

fn issue(code: EntrypointIssueCode, relative_path: &str) -> EntrypointIssue {
    EntrypointIssue {
        code,
        relative_path: Some(relative_path.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn draft() -> serde_json::Value {
        let digest = MemoryDigest::sha256(b"source");
        json!({
            "title": "Use the descriptor-bound source",
            "kind": "security",
            "observation": "Path checks alone race with filesystem replacement.",
            "guidance": "Open beneath the pinned workspace descriptor.",
            "applicability": {"paths": ["src/memory.rs"]},
            "citations": [{
                "kind": "source_file",
                "locator": "src/memory.rs",
                "source_version": format!("workspace-file:{digest}"),
                "digest": digest
            }],
            "confidence": "observed_once",
            "sensitivity": "internal",
            "retention": {"policy": "indefinite"}
        })
    }

    #[test]
    fn parser_rejects_prose_and_duplicate_or_unsorted_ids() {
        let workspace = WorkspaceMemoryId::for_canonical_root(Path::new("/workspace"));
        assert_eq!(
            parse_manifest(b"# remember this", &workspace, 1),
            Err(EntrypointIssueCode::InvalidManifest)
        );
        let manifest = json!({
            "schema_version": 1,
            "source_id": "repo",
            "generation": 1,
            "lessons": [
                {"lesson_id": "z", "lesson": draft()},
                {"lesson_id": "a", "lesson": draft()}
            ]
        });
        assert_eq!(
            parse_manifest(&serde_json::to_vec(&manifest).unwrap(), &workspace, 1),
            Err(EntrypointIssueCode::InvalidManifest)
        );
    }
}
