//! Reconcile the legacy transcript schema marker without destructive guessing.
//!
//! S-038 owns replacement of this foreign compatibility marker with an
//! `OpenClaudia`-owned import contract. Until then, this migration preserves
//! unknown object fields, rejects malformed/future state, and uses the shared
//! descriptor-safe atomic persistence primitive.

use std::path::PathBuf;

use crate::persistence::{CommitState, FileClass, PersistenceError, PersistentStorage};

use super::{
    Migration, MigrationContext, MigrationFailure, MigrationFailureKind, MigrationOutcome,
    MigrationStore,
};

const CURRENT_TRANSCRIPT_SCHEMA: u64 = 1;
const MARKER_NAME: &str = ".schema-version.json";

pub struct StampTranscriptSchemaV1;

impl StampTranscriptSchemaV1 {
    fn marker_directory(ctx: &MigrationContext) -> PathBuf {
        ctx.claude_home.join("projects")
    }

    const fn persistence_failure(
        operation: &'static str,
        error: &PersistenceError,
    ) -> MigrationFailure {
        let kind = match error {
            PersistenceError::TooLarge { .. } => MigrationFailureKind::ResourceLimitExceeded,
            PersistenceError::Conflict { .. } => MigrationFailureKind::ConcurrentChange,
            PersistenceError::InvalidRoot { .. }
            | PersistenceError::InvalidTarget { .. }
            | PersistenceError::Io { .. }
            | PersistenceError::Unchanged { .. }
            | PersistenceError::UnsupportedPlatform { .. } => {
                MigrationFailureKind::PublicationFailed
            }
        };
        MigrationFailure::new(kind, MigrationStore::ClaudeTranscripts, operation)
    }

    fn replacement(bytes: Option<&[u8]>) -> Result<Option<Vec<u8>>, MigrationFailure> {
        let Some(bytes) = bytes else {
            return serde_json::to_vec_pretty(&serde_json::json!({
                "transcripts": CURRENT_TRANSCRIPT_SCHEMA
            }))
            .map(Some)
            .map_err(|_| {
                MigrationFailure::new(
                    MigrationFailureKind::InvalidPersistentState,
                    MigrationStore::ClaudeTranscripts,
                    "encode initial transcript schema marker",
                )
            });
        };
        let mut value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
            MigrationFailure::new(
                MigrationFailureKind::InvalidPersistentState,
                MigrationStore::ClaudeTranscripts,
                "decode transcript schema marker",
            )
        })?;
        let object = value.as_object_mut().ok_or_else(|| {
            MigrationFailure::new(
                MigrationFailureKind::InvalidPersistentState,
                MigrationStore::ClaudeTranscripts,
                "validate transcript schema marker",
            )
        })?;
        let version = object
            .get("transcripts")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                MigrationFailure::new(
                    MigrationFailureKind::InvalidPersistentState,
                    MigrationStore::ClaudeTranscripts,
                    "read transcript schema version",
                )
            })?;
        if version > CURRENT_TRANSCRIPT_SCHEMA {
            return Err(MigrationFailure::new(
                MigrationFailureKind::UnsupportedFutureSchema,
                MigrationStore::ClaudeTranscripts,
                "validate transcript schema version",
            ));
        }
        if version == CURRENT_TRANSCRIPT_SCHEMA {
            return Ok(None);
        }
        object.insert(
            "transcripts".to_string(),
            serde_json::Value::from(CURRENT_TRANSCRIPT_SCHEMA),
        );
        serde_json::to_vec_pretty(&value).map(Some).map_err(|_| {
            MigrationFailure::new(
                MigrationFailureKind::InvalidPersistentState,
                MigrationStore::ClaudeTranscripts,
                "encode transcript schema marker",
            )
        })
    }
}

impl Migration for StampTranscriptSchemaV1 {
    fn id(&self) -> &'static str {
        "stamp-transcript-schema-v1"
    }

    fn description(&self) -> &'static str {
        "Reconcile legacy transcript schema marker at version 1"
    }

    fn store(&self) -> MigrationStore {
        MigrationStore::ClaudeTranscripts
    }

    fn run(&self, ctx: &MigrationContext) -> MigrationOutcome {
        let directory = Self::marker_directory(ctx);
        match std::fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return MigrationOutcome::Current;
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return MigrationOutcome::Failed(MigrationFailure::new(
                    MigrationFailureKind::InvalidPersistentState,
                    MigrationStore::ClaudeTranscripts,
                    "validate transcript metadata directory",
                ));
            }
            Ok(_) => {}
            Err(error) => {
                return MigrationOutcome::Failed(MigrationFailure::from_io(
                    MigrationFailureKind::InvalidPersistentState,
                    MigrationStore::ClaudeTranscripts,
                    "inspect transcript metadata directory",
                    &error,
                ));
            }
        }
        let storage = match PersistentStorage::open(&directory) {
            Ok(storage) => storage,
            Err(error) => {
                return MigrationOutcome::Failed(Self::persistence_failure(
                    "open transcript metadata store",
                    &error,
                ));
            }
        };
        let observed = match storage.read(MARKER_NAME, FileClass::Session) {
            Ok(observed) => observed,
            Err(error) => {
                return MigrationOutcome::Failed(Self::persistence_failure(
                    "read transcript schema marker",
                    &error,
                ));
            }
        };
        let replacement = match observed.expose_bytes(Self::replacement) {
            Ok(replacement) => replacement,
            Err(failure) => return MigrationOutcome::Failed(failure),
        };
        let changed = replacement.is_some();
        let bytes = match replacement {
            Some(bytes) => bytes,
            None => match observed.expose_bytes(|bytes| bytes.map(<[u8]>::to_vec)) {
                Some(bytes) => bytes,
                None => {
                    return MigrationOutcome::Failed(MigrationFailure::new(
                        MigrationFailureKind::ConcurrentChange,
                        MigrationStore::ClaudeTranscripts,
                        "reconcile missing transcript schema marker",
                    ));
                }
            },
        };
        let receipt = match storage.commit(
            MARKER_NAME,
            FileClass::Session,
            observed.generation(),
            &bytes,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return MigrationOutcome::Failed(Self::persistence_failure(
                    "publish transcript schema marker",
                    &error,
                ));
            }
        };
        if receipt.state() == CommitState::PublishedDurabilityUncertain {
            return MigrationOutcome::Failed(
                MigrationFailure::new(
                    MigrationFailureKind::DurabilityUncertain,
                    MigrationStore::ClaudeTranscripts,
                    "synchronize transcript schema marker",
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
