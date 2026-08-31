//! Publish OpenClaudia-owned schema metadata after session migration.
//!
//! The historical migration wrote an unverified global claim into Claude's
//! shared transcript directory. This replacement treats that directory only
//! as a bounded, read-only compatibility source. Its sanitized observation is
//! recorded in an OpenClaudia-owned manifest that this migration consumes on
//! every startup; foreign bytes and paths never become authority.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::persistence::{
    CommitState, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};

use super::{
    Migration, MigrationContext, MigrationFailure, MigrationFailureKind, MigrationOutcome,
    MigrationStore,
};

const PRODUCER: &str = "openclaudia";
const CURRENT_MANIFEST_SCHEMA: u32 = 1;
const MIN_SESSION_SCHEMA: u32 = crate::state::SessionStateV1::MIN_SUPPORTED_VERSION;
const CURRENT_SESSION_SCHEMA: u32 = crate::state::SessionStateV1::CURRENT_VERSION;
const CURRENT_FOREIGN_TRANSCRIPT_SCHEMA: u64 = 1;
const MAX_FOREIGN_MARKER_BYTES: usize = 64 * 1_024;
const OWNED_MANIFEST_NAME: &str = ".openclaudia-session-schema.json";
const FOREIGN_MARKER_NAME: &str = ".schema-version.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedSchemaManifest {
    producer: String,
    schema_version: u32,
    session_documents: SessionSchemaRange,
    foreign_transcript_import: ForeignTranscriptImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSchemaRange {
    minimum: u32,
    current: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ForeignTranscriptImport {
    /// No foreign transcript directory was present when startup inspected it.
    Absent,
    /// The foreign producer claimed a schema this importer recognizes.
    ClaimedCompatible {
        /// Claimed foreign schema version; this is provenance, not authority.
        schema_version: u64,
        /// Exact marker generation inspected by startup.
        source_generation: StorageGeneration,
    },
    /// The foreign producer claimed a schema newer than this importer.
    ClaimedFuture {
        /// Claimed foreign schema version.
        schema_version: u64,
        /// Exact marker generation inspected by startup.
        source_generation: StorageGeneration,
    },
    /// The marker source was inaccessible, malformed, unsafe, or oversized.
    Rejected {
        /// Exact generation when bytes were safely observed, if available.
        source_generation: Option<StorageGeneration>,
    },
}

pub struct PublishOwnedSessionSchemaV1;

impl PublishOwnedSessionSchemaV1 {
    fn foreign_directory(ctx: &MigrationContext) -> PathBuf {
        ctx.claude_home.join("projects")
    }

    const fn persistence_failure(
        operation: &'static str,
        error: &PersistenceError,
    ) -> MigrationFailure {
        let kind = match error {
            PersistenceError::TooLarge { .. } => MigrationFailureKind::ResourceLimitExceeded,
            PersistenceError::Conflict { .. } => MigrationFailureKind::ConcurrentChange,
            PersistenceError::InvalidRoot { .. } | PersistenceError::InvalidTarget { .. } => {
                MigrationFailureKind::InvalidPersistentState
            }
            PersistenceError::Io { .. }
            | PersistenceError::Unchanged { .. }
            | PersistenceError::UnsupportedPlatform { .. } => {
                MigrationFailureKind::PublicationFailed
            }
        };
        MigrationFailure::new(kind, MigrationStore::OpenClaudiaData, operation)
    }

    const fn invalid(operation: &'static str) -> MigrationFailure {
        MigrationFailure::new(
            MigrationFailureKind::InvalidPersistentState,
            MigrationStore::OpenClaudiaData,
            operation,
        )
    }

    fn foreign_import(ctx: &MigrationContext) -> ForeignTranscriptImport {
        let directory = Self::foreign_directory(ctx);
        let metadata = match std::fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ForeignTranscriptImport::Absent;
            }
            Ok(metadata) => metadata,
            Err(_) => {
                return ForeignTranscriptImport::Rejected {
                    source_generation: None,
                };
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return ForeignTranscriptImport::Rejected {
                source_generation: None,
            };
        }
        let Ok(storage) = PersistentStorage::open(&directory) else {
            return ForeignTranscriptImport::Rejected {
                source_generation: None,
            };
        };
        let Ok(observed) = storage.read(FOREIGN_MARKER_NAME, FileClass::Session) else {
            return ForeignTranscriptImport::Rejected {
                source_generation: None,
            };
        };
        let generation = observed.generation();
        observed.expose_bytes(|bytes| {
            let Some(bytes) = bytes else {
                // Claude does not publish OpenClaudia's historical marker.
                // Exact marker absence is therefore a valid, generation-bound
                // input to the bounded JSONL importer, not evidence that no
                // Claude transcripts may exist.
                return ForeignTranscriptImport::ClaimedCompatible {
                    schema_version: CURRENT_FOREIGN_TRANSCRIPT_SCHEMA,
                    source_generation: generation,
                };
            };
            if bytes.len() > MAX_FOREIGN_MARKER_BYTES {
                return ForeignTranscriptImport::Rejected {
                    source_generation: Some(generation),
                };
            }
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
                return ForeignTranscriptImport::Rejected {
                    source_generation: Some(generation),
                };
            };
            let Some(version) = value
                .as_object()
                .and_then(|object| object.get("transcripts"))
                .and_then(serde_json::Value::as_u64)
            else {
                return ForeignTranscriptImport::Rejected {
                    source_generation: Some(generation),
                };
            };
            if version <= CURRENT_FOREIGN_TRANSCRIPT_SCHEMA {
                ForeignTranscriptImport::ClaimedCompatible {
                    schema_version: version,
                    source_generation: generation,
                }
            } else {
                ForeignTranscriptImport::ClaimedFuture {
                    schema_version: version,
                    source_generation: generation,
                }
            }
        })
    }

    fn desired_manifest(ctx: &MigrationContext) -> OwnedSchemaManifest {
        OwnedSchemaManifest {
            producer: PRODUCER.to_string(),
            schema_version: CURRENT_MANIFEST_SCHEMA,
            session_documents: SessionSchemaRange {
                minimum: MIN_SESSION_SCHEMA,
                current: CURRENT_SESSION_SCHEMA,
            },
            foreign_transcript_import: Self::foreign_import(ctx),
        }
    }

    fn decode_existing(bytes: &[u8]) -> Result<OwnedSchemaManifest, MigrationFailure> {
        let manifest: OwnedSchemaManifest = serde_json::from_slice(bytes)
            .map_err(|_| Self::invalid("decode owned session schema manifest"))?;
        if manifest.schema_version > CURRENT_MANIFEST_SCHEMA {
            return Err(MigrationFailure::new(
                MigrationFailureKind::UnsupportedFutureSchema,
                MigrationStore::OpenClaudiaData,
                "validate owned session schema version",
            ));
        }
        if manifest.schema_version != CURRENT_MANIFEST_SCHEMA
            || manifest.producer != PRODUCER
            || manifest.session_documents.minimum != MIN_SESSION_SCHEMA
            || manifest.session_documents.current != CURRENT_SESSION_SCHEMA
        {
            return Err(Self::invalid("validate owned session schema manifest"));
        }
        let valid_foreign_observation = match &manifest.foreign_transcript_import {
            ForeignTranscriptImport::Absent
            | ForeignTranscriptImport::Rejected {
                source_generation: None | Some(StorageGeneration::Present(_)),
            } => true,
            ForeignTranscriptImport::ClaimedCompatible {
                schema_version,
                source_generation: StorageGeneration::Present(_) | StorageGeneration::Missing,
            } => *schema_version <= CURRENT_FOREIGN_TRANSCRIPT_SCHEMA,
            ForeignTranscriptImport::ClaimedFuture {
                schema_version,
                source_generation: StorageGeneration::Present(_),
            } => *schema_version > CURRENT_FOREIGN_TRANSCRIPT_SCHEMA,
            ForeignTranscriptImport::ClaimedFuture { .. }
            | ForeignTranscriptImport::Rejected {
                source_generation: Some(StorageGeneration::Missing),
            } => false,
        };
        if !valid_foreign_observation {
            return Err(Self::invalid(
                "validate owned foreign transcript import observation",
            ));
        }
        Ok(manifest)
    }
}

/// Read the startup-verified foreign transcript compatibility contract from
/// OpenClaudia-owned storage.
///
/// Importers must still compare the recorded source generation against a fresh
/// descriptor-relative read before consuming foreign content. Only
/// [`ForeignTranscriptImport::ClaimedCompatible`] permits import; every other
/// variant is a non-authorizing observation.
///
/// # Errors
///
/// Returns a typed migration failure when the owned manifest is absent,
/// malformed, unsupported, concurrently changed, or not safely readable.
pub fn read_foreign_transcript_import_contract(
    ctx: &MigrationContext,
) -> Result<ForeignTranscriptImport, MigrationFailure> {
    let storage = PersistentStorage::open(&ctx.openclaudia_data).map_err(|error| {
        PublishOwnedSessionSchemaV1::persistence_failure(
            "open owned session schema contract",
            &error,
        )
    })?;
    let observed = storage
        .read(OWNED_MANIFEST_NAME, FileClass::State)
        .map_err(|error| {
            PublishOwnedSessionSchemaV1::persistence_failure(
                "read owned session schema contract",
                &error,
            )
        })?;
    observed.expose_bytes(|bytes| {
        let bytes = bytes.ok_or_else(|| {
            PublishOwnedSessionSchemaV1::invalid("locate owned session schema contract")
        })?;
        PublishOwnedSessionSchemaV1::decode_existing(bytes)
            .map(|manifest| manifest.foreign_transcript_import)
    })
}

/// Verify that the owned compatibility contract still matches the exact
/// foreign marker generation observed at startup.
///
/// A missing marker is a stable generation: Claude does not create the
/// historical `OpenClaudia` marker, so absence authorizes the same bounded
/// JSONL importer as a recognized legacy marker. Any change after startup
/// fails closed until migrations publish a fresh owned observation.
///
/// # Errors
///
/// Returns a typed migration failure when the owned contract cannot be read.
pub fn foreign_transcript_import_is_current(
    ctx: &MigrationContext,
) -> Result<bool, MigrationFailure> {
    let recorded = read_foreign_transcript_import_contract(ctx)?;
    let current = PublishOwnedSessionSchemaV1::foreign_import(ctx);
    Ok(matches!(
        (recorded, current),
        (
            ForeignTranscriptImport::ClaimedCompatible {
                schema_version: recorded_schema,
                source_generation: recorded_generation,
            },
            ForeignTranscriptImport::ClaimedCompatible {
                schema_version: current_schema,
                source_generation: current_generation,
            }
        ) if recorded_schema == current_schema && recorded_generation == current_generation
    ))
}

impl Migration for PublishOwnedSessionSchemaV1 {
    fn id(&self) -> &'static str {
        "m002-owned-session-schema-v1"
    }

    fn description(&self) -> &'static str {
        "Publish owned session schema and observe foreign transcripts read-only"
    }

    fn store(&self) -> MigrationStore {
        MigrationStore::OpenClaudiaData
    }

    fn run(&self, ctx: &MigrationContext) -> MigrationOutcome {
        let storage = match PersistentStorage::open(&ctx.openclaudia_data) {
            Ok(storage) => storage,
            Err(error) => {
                return MigrationOutcome::Failed(Self::persistence_failure(
                    "open owned session schema store",
                    &error,
                ));
            }
        };
        let observed = match storage.read(OWNED_MANIFEST_NAME, FileClass::State) {
            Ok(observed) => observed,
            Err(error) => {
                return MigrationOutcome::Failed(Self::persistence_failure(
                    "read owned session schema manifest",
                    &error,
                ));
            }
        };
        if let Err(failure) = observed.expose_bytes(|bytes| {
            bytes.map_or(Ok(()), |bytes| Self::decode_existing(bytes).map(|_| ()))
        }) {
            return MigrationOutcome::Failed(failure);
        }
        let Ok(desired) = serde_json::to_vec_pretty(&Self::desired_manifest(ctx)) else {
            return MigrationOutcome::Failed(Self::invalid("encode owned session schema manifest"));
        };
        let changed = observed.expose_bytes(|bytes| bytes != Some(desired.as_slice()));
        let receipt = match storage.commit(
            OWNED_MANIFEST_NAME,
            FileClass::State,
            observed.generation(),
            &desired,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return MigrationOutcome::Failed(Self::persistence_failure(
                    "publish owned session schema manifest",
                    &error,
                ));
            }
        };
        if receipt.state() == CommitState::PublishedDurabilityUncertain {
            return MigrationOutcome::Failed(
                MigrationFailure::new(
                    MigrationFailureKind::DurabilityUncertain,
                    MigrationStore::OpenClaudiaData,
                    "synchronize owned session schema manifest",
                )
                .with_committed_artifacts(usize::from(changed)),
            );
        }
        let verified = match storage.read(OWNED_MANIFEST_NAME, FileClass::State) {
            Ok(verified) => verified,
            Err(error) => {
                return MigrationOutcome::Failed(
                    Self::persistence_failure("verify owned session schema manifest", &error)
                        .with_committed_artifacts(usize::from(changed)),
                );
            }
        };
        let bytes_match = verified.expose_bytes(|bytes| bytes == Some(desired.as_slice()));
        if verified.generation() != receipt.generation() || !bytes_match {
            return MigrationOutcome::Failed(
                MigrationFailure::new(
                    MigrationFailureKind::ConcurrentChange,
                    MigrationStore::OpenClaudiaData,
                    "verify owned session schema generation",
                )
                .with_committed_artifacts(usize::from(changed)),
            );
        }
        if changed {
            MigrationOutcome::Applied {
                changed_artifacts: 1,
            }
        } else {
            MigrationOutcome::Current
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> (tempfile::TempDir, MigrationContext) {
        let root = tempfile::tempdir().expect("migration root");
        let claude_home = root.path().join("claude");
        let openclaudia_data = root.path().join("openclaudia");
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(&claude_home).expect("Claude root");
        std::fs::create_dir_all(&openclaudia_data).expect("OpenClaudia root");
        std::fs::create_dir_all(&workspace).expect("workspace root");
        let context =
            MigrationContext::with_paths_and_workspace(claude_home, openclaudia_data, workspace);
        (root, context)
    }

    #[test]
    fn foreign_marker_is_read_only_and_observation_is_owned() {
        let (_root, context) = context();
        let projects = context.claude_home.join("projects");
        std::fs::create_dir_all(&projects).expect("foreign projects root");
        let marker = projects.join(FOREIGN_MARKER_NAME);
        let original = br#"{"other_producer":7,"transcripts":0}"#;
        std::fs::write(&marker, original).expect("foreign marker");

        assert!(matches!(
            PublishOwnedSessionSchemaV1.run(&context),
            MigrationOutcome::Applied {
                changed_artifacts: 1
            }
        ));
        assert_eq!(
            std::fs::read(&marker).expect("foreign marker retained"),
            original
        );
        let owned: OwnedSchemaManifest = serde_json::from_slice(
            &std::fs::read(context.openclaudia_data.join(OWNED_MANIFEST_NAME))
                .expect("owned manifest"),
        )
        .expect("valid owned manifest");
        assert_eq!(owned.producer, PRODUCER);
        assert_eq!(owned.session_documents.minimum, MIN_SESSION_SCHEMA);
        assert_eq!(owned.session_documents.current, CURRENT_SESSION_SCHEMA);
        assert!(matches!(
            owned.foreign_transcript_import,
            ForeignTranscriptImport::ClaimedCompatible {
                schema_version: 0,
                ..
            }
        ));
        assert!(matches!(
            read_foreign_transcript_import_contract(&context)
                .expect("owned compatibility contract"),
            ForeignTranscriptImport::ClaimedCompatible {
                schema_version: 0,
                ..
            }
        ));
    }

    #[test]
    fn claude_projects_without_openclaudia_marker_use_exact_missing_generation() {
        let (_root, context) = context();
        let projects = context.claude_home.join("projects");
        std::fs::create_dir_all(&projects).expect("foreign projects root");

        assert!(matches!(
            PublishOwnedSessionSchemaV1.run(&context),
            MigrationOutcome::Applied {
                changed_artifacts: 1
            }
        ));
        assert!(matches!(
            read_foreign_transcript_import_contract(&context)
                .expect("owned compatibility contract"),
            ForeignTranscriptImport::ClaimedCompatible {
                schema_version: CURRENT_FOREIGN_TRANSCRIPT_SCHEMA,
                source_generation: StorageGeneration::Missing,
            }
        ));
        assert!(foreign_transcript_import_is_current(&context)
            .expect("fresh missing-marker generation"));

        std::fs::write(projects.join(FOREIGN_MARKER_NAME), br#"{"transcripts":1}"#)
            .expect("late marker mutation");
        assert!(!foreign_transcript_import_is_current(&context)
            .expect("marker mutation makes startup contract stale"));
    }

    #[test]
    fn malformed_foreign_marker_cannot_block_owned_store_or_be_rewritten() {
        let (_root, context) = context();
        let projects = context.claude_home.join("projects");
        std::fs::create_dir_all(&projects).expect("foreign projects root");
        let marker = projects.join(FOREIGN_MARKER_NAME);
        let original = b"{foreign-secret-broken";
        std::fs::write(&marker, original).expect("foreign marker");

        assert!(matches!(
            PublishOwnedSessionSchemaV1.run(&context),
            MigrationOutcome::Applied {
                changed_artifacts: 1
            }
        ));
        assert_eq!(
            std::fs::read(&marker).expect("foreign marker retained"),
            original
        );
        let owned: OwnedSchemaManifest = serde_json::from_slice(
            &std::fs::read(context.openclaudia_data.join(OWNED_MANIFEST_NAME))
                .expect("owned manifest"),
        )
        .expect("valid owned manifest");
        assert!(matches!(
            owned.foreign_transcript_import,
            ForeignTranscriptImport::Rejected { .. }
        ));
    }

    #[test]
    fn future_owned_manifest_fails_without_modification() {
        let (_root, context) = context();
        let path = context.openclaudia_data.join(OWNED_MANIFEST_NAME);
        let original = serde_json::to_vec_pretty(&serde_json::json!({
            "producer": PRODUCER,
            "schema_version": 999,
            "session_documents": {
                "minimum": MIN_SESSION_SCHEMA,
                "current": CURRENT_SESSION_SCHEMA
            },
            "foreign_transcript_import": {"status": "absent"}
        }))
        .expect("future manifest");
        std::fs::write(&path, &original).expect("owned manifest");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("owner-private manifest");
        }

        let MigrationOutcome::Failed(failure) = PublishOwnedSessionSchemaV1.run(&context) else {
            panic!("future owned schema must fail closed");
        };
        assert_eq!(
            failure.kind(),
            MigrationFailureKind::UnsupportedFutureSchema
        );
        assert_eq!(
            std::fs::read(path).expect("future manifest retained"),
            original
        );
    }
}
