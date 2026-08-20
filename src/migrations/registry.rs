//! Ordered registry of all migrations run at startup.
//!
//! Keep this list short, require every entry to be independently idempotent,
//! and append new migrations at the end. Never reorder existing entries: the
//! relative order is load-bearing for chained exact-version transforms.

use super::Migration;

/// Return every migration in the order it must run.
pub(super) fn all() -> Vec<Box<dyn Migration>> {
    vec![
        Box::new(super::stamp_transcript_schema_v1::StampTranscriptSchemaV1),
        Box::new(super::session_state_v1::MigrateSessionStateV1),
    ]
}
