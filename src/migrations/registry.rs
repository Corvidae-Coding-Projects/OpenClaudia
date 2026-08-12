//! Ordered registry of all migrations run at startup.
//!
//! Keep this list short and each migration file tiny — Claude Code's
//! `migrations/` directory follows the same pattern, with each file
//! doing exactly one schema change. Append new migrations at the end;
//! never reorder existing ones (the relative order is load-bearing for
//! chained transformations, and the once-only ledger keys assume
//! append-only semantics).

use super::Migration;

/// Return every migration in the order it must run. Called exactly
/// once per startup by [`super::run_all`].
pub(super) fn all() -> Vec<Box<dyn Migration>> {
    vec![
        Box::new(super::stamp_transcript_schema_v1::StampTranscriptSchemaV1),
        Box::new(super::session_state_v1::MigrateSessionStateV1),
    ]
}
