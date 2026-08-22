//! Repository technical-memory source lifecycle.
//!
//! The retained `MEMORY.md` filenames carry strict versioned JSON technical
//! lessons. They are untrusted import evidence, never prose capture, startup
//! context, or system/developer instructions. Explicit canonical tools inspect
//! and refresh these sources into the host-owned workspace memory store.

pub mod entrypoint;

pub use entrypoint::{
    load_entrypoint, EntrypointFile, EntrypointInspection, EntrypointIssue, EntrypointIssueCode,
    TechnicalMemoryManifest, TechnicalMemoryManifestEntry, MAX_ENTRYPOINT_BYTES,
    MAX_ENTRYPOINT_CITATIONS, MAX_ENTRYPOINT_CITATION_BYTES, MAX_ENTRYPOINT_CITATION_FILES,
    MAX_ENTRYPOINT_CITATION_FILE_BYTES, MAX_ENTRYPOINT_LESSONS,
    TECHNICAL_MEMORY_SOURCE_SCHEMA_VERSION,
};
