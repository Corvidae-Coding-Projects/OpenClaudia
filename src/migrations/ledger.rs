//! Completion ledger for once-only migrations.
//!
//! Stored as a small JSON file at `~/.local/share/openclaudia/migrations.json`
//! with the shape `{"applied": ["migration-id-1", "migration-id-2"]}`.
//!
//! # Failure semantics
//!
//! - **Missing file** is the expected first-run state and yields
//!   `Ok(default)` — no error.
//! - **Existing-but-unreadable / unparseable** file surfaces an `Err`.
//!   The caller decides whether to abort or degrade; we no longer
//!   silently coerce corruption to "empty ledger", because that would
//!   make every once-only migration replay on the next boot (#741b).
//! - **Saves are atomic**: write-to-temp + fsync + rename, mirroring
//!   the pattern in `src/plugins/install.rs` and `src/session/mod.rs`.
//!   A crash mid-save leaves the previous good file intact (#741a).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

/// Process-wide nonce shared across all save calls. Combined with the
/// PID it guarantees collision-free temp paths even when multiple
/// threads in the same process race to persist the ledger.
static TMP_NONCE: AtomicU64 = AtomicU64::new(0);

/// On-disk representation — a sorted set keeps the file stable across
/// runs (so `git diff` stays quiet for users who check this in).
#[derive(Debug, Default, Serialize, Deserialize)]
struct LedgerFile {
    #[serde(default)]
    applied: BTreeSet<String>,
}

/// In-memory completion ledger. Cheap to construct — load once per
/// startup, mutate during migration run, save once at the end.
#[derive(Debug, Default)]
pub struct CompletionLedger {
    applied: BTreeSet<String>,
}

impl CompletionLedger {
    /// Load the ledger from `path`.
    ///
    /// # Returns
    ///
    /// - `Ok(default)` when `path` does not exist (ENOENT) — this is
    ///   the expected first-run state, not an error.
    /// - `Err(_)` when the file exists but cannot be read or parsed.
    ///   The corrupt file is left in place for forensic inspection so
    ///   an operator can decide whether to recover or discard it.
    ///
    /// # Errors
    ///
    /// Returns `Err` for any I/O failure other than `NotFound`, and
    /// for any JSON parse failure. Callers that want to degrade to an
    /// empty ledger on corruption must do so explicitly (and log it).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(err) => {
                return Err(
                    anyhow!(err).context(format!("failed to read ledger at {}", path.display()))
                );
            }
        };
        let parsed: LedgerFile = serde_json::from_str(&text).map_err(|err| {
            anyhow!(err).context(format!("ledger at {} is corrupt", path.display()))
        })?;
        Ok(Self {
            applied: parsed.applied,
        })
    }

    /// True if `id` has already been marked complete.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.applied.contains(id)
    }

    /// Record `id` as complete. Idempotent.
    pub fn mark(&mut self, id: &str) {
        self.applied.insert(id.to_string());
    }

    /// Persist the ledger to `path` using an atomic write-then-rename.
    ///
    /// Steps, mirroring the pattern in `src/plugins/install.rs` and
    /// `src/session/mod.rs`:
    /// 1. Serialize to JSON.
    /// 2. Write to a sibling temp file `<path>.tmp.<pid>.<nonce>`.
    /// 3. On Unix, tighten the temp file's mode to `0o600` *before* the
    ///    rename, so the final file is never world-readable even for a
    ///    split instant.
    /// 4. `fsync` the temp file so a crash between write and rename
    ///    cannot leave the new bytes only in the page cache.
    /// 5. `rename(2)` into place — atomic on the same filesystem; the
    ///    previous good file is replaced wholesale or not at all.
    /// 6. On any failure after the temp file is created, best-effort
    ///    `remove_file` so we never leave a stray.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent cannot be created, the JSON
    /// cannot be serialised, or any filesystem step fails.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create ledger parent directory {}",
                    parent.display()
                )
            })?;
        }

        let file = LedgerFile {
            applied: self.applied.clone(),
        };
        let text = serde_json::to_string_pretty(&file).context("failed to serialize ledger")?;

        // PID + process-wide nonce ⇒ no collision even when multiple
        // threads in the same process race to save. Same filesystem as
        // the target is mandatory for `rename(2)` to be atomic.
        let nonce = TMP_NONCE.fetch_add(1, Ordering::SeqCst);
        let tmp = path.with_extension(format!("tmp.{pid}.{nonce}", pid = std::process::id()));

        // Write payload.
        if let Err(err) = std::fs::write(&tmp, &text) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow!(err).context(format!(
                "failed to write ledger temp file {}",
                tmp.display()
            )));
        }

        // Tighten perms BEFORE rename — the final inode inherits these
        // bits, so the published file is never world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Err(err) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            {
                let _ = std::fs::remove_file(&tmp);
                return Err(anyhow!(err).context(format!(
                    "failed to set 0o600 on ledger temp file {}",
                    tmp.display()
                )));
            }
        }

        // fsync — kernel buffers must hit disk before the rename, else
        // a power loss between rename and writeback would leave us
        // pointing at a zero-byte file.
        match std::fs::File::open(&tmp) {
            Ok(f) => {
                if let Err(err) = f.sync_all() {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(anyhow!(err).context(format!(
                        "failed to fsync ledger temp file {}",
                        tmp.display()
                    )));
                }
            }
            Err(err) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(anyhow!(err).context(format!(
                    "failed to reopen ledger temp file {} for fsync",
                    tmp.display()
                )));
            }
        }

        // Atomic rename: readers see either the prior complete file or
        // the new complete file — never a half-written intermediate.
        if let Err(err) = crate::file_error::replace_file_atomic(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow!(err).context(format!(
                "failed to rename ledger temp {} -> {}",
                tmp.display(),
                path.display()
            )));
        }

        Ok(())
    }
}
