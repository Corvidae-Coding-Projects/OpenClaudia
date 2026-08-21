//! Preserved LSP pooling prototype — unavailable in production.
//!
//! Today every LSP tool call in [`crate::tools::lsp`] spawns a fresh
//! language server, drives the initialize handshake, performs one
//! request, and exits.
//!
//! That is correct but expensive: `rust-analyzer` routinely takes
//! 5-15 seconds to walk a project's index, and most interactive
//! sessions hit the LSP tool dozens of times. Reusing a single warm
//! server per language is the standard editor pattern and the same
//! shape CC's `LSPServerManager.ts` uses.
//!
//! The current language-only key is not workspace-, authority-, server-, or
//! generation-safe. Production therefore does not construct this pool;
//! [`crate::services::lifecycle_service_catalog`] assigns safe activation to
//! S-068/S-069. The implementation is preserved and its child ownership is
//! still enforced so library/tests do not leak processes.
//!
//! ## What ships here
//!
//! * [`LspServerManager`] — `Arc<Mutex<HashMap<Language, ChildHandle>>>`
//!   keyed by language id, with `acquire` / `release` lifecycle methods.
//! * [`ChildHandle`] — opaque wrapper around a spawned server's pipes
//!   plus a `last_used` timestamp so the idle reaper can evict stale
//!   entries.
//! * `reap_idle` — prototype sweep that closes servers idle longer than the
//!   configured TTL; aggregate pool size is not yet bounded.
//!
//! ## What is intentionally deferred
//!
//! The tool-side rewiring (replacing `spawn_language_server` in
//! `tools::lsp` with a `manager.acquire(language)` call) is large
//! enough that it is best landed as a follow-up so this commit can
//! be reviewed for the pool contract alone. The current `tools::lsp`
//! continues to spawn-per-call until that follow-up lands; the pool
//! is dispatch-ready but not yet on the hot path.

use anyhow::Result;
use std::collections::HashMap;
use std::process::Child;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Opaque handle to a running language-server child process.
///
/// `Send`-friendly (the inner `Child` is) so callers can keep the
/// handle in a shared map. The `last_used` timestamp lets the reaper
/// decide what to evict; `language` lets logs distinguish concurrent
/// servers.
pub struct ChildHandle {
    /// Identifier the manager keyed this handle under (e.g. `"rust"`).
    pub language: String,
    /// Spawned child process. `Option` so `release` / `kill_all` can
    /// take it back out and wait without consuming the surrounding
    /// `Mutex` guard.
    pub child: Option<Child>,
    /// Wall-clock instant of the most recent `acquire` for this entry.
    pub last_used: Instant,
}

impl ChildHandle {
    /// Build a fresh handle around an already-spawned child.
    #[must_use]
    pub fn new(language: impl Into<String>, child: Child) -> Self {
        Self {
            language: language.into(),
            child: Some(child),
            last_used: Instant::now(),
        }
    }
}

impl Drop for ChildHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Trait used by [`LspServerManager`] to spawn a new server when an
/// `acquire` misses the pool.
///
/// Concrete spawners live in `tools::lsp` so the pool itself stays
/// free of language-detection logic. Tests use a stub spawner that
/// launches `/bin/sleep` (or platform equivalent) so cache and TTL
/// behaviour can be exercised without any real language server.
pub trait LspSpawner: Send + Sync {
    /// Spawn a server for `language`. Returns the [`Child`] with
    /// stdin/stdout piped so the caller can drive the LSP handshake.
    ///
    /// # Errors
    ///
    /// Bubble up any spawn failure — the manager treats it as a hard
    /// miss and the caller decides whether to retry.
    fn spawn(&self, language: &str) -> Result<Child>;
}

/// Default idle TTL after which a pooled server is reaped: 5 minutes.
///
/// This prototype value is exercised only by library/tests until S-068/S-069
/// establish the production process budget and lifecycle.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_mins(5);

/// Pooled, per-language LSP server manager (crosslink #636).
///
/// Thread-safe by construction: every public method takes `&self` and
/// the inner state lives behind a `Mutex`. The mutex is acquired only
/// for the brief lookup/insert; the spawned `Child` is *not* held
/// across the mutex boundary on the hot path — `acquire` returns the
/// handle by removing it from the pool, and `release` puts it back.
pub struct LspServerManager {
    inner: Arc<Mutex<HashMap<String, ChildHandle>>>,
    spawner: Arc<dyn LspSpawner>,
    idle_ttl: Duration,
}

type PoolEntries = HashMap<String, ChildHandle>;

impl LspServerManager {
    /// Build a manager around `spawner` using [`DEFAULT_IDLE_TTL`].
    #[must_use]
    pub fn new(spawner: Arc<dyn LspSpawner>) -> Self {
        Self::with_ttl(spawner, DEFAULT_IDLE_TTL)
    }

    /// Build a manager with a custom idle TTL. The reaper closes any
    /// entry whose `last_used` is older than `ttl`.
    #[must_use]
    pub fn with_ttl(spawner: Arc<dyn LspSpawner>, ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            spawner,
            idle_ttl: ttl,
        }
    }

    fn inner_guard(&self, operation: &'static str) -> Option<MutexGuard<'_, PoolEntries>> {
        match self.inner.lock() {
            Ok(guard) => Some(guard),
            Err(err) => {
                tracing::error!(operation, error = %err, "LSP server pool lock poisoned");
                None
            }
        }
    }

    /// Take a server handle out of the pool, spawning a fresh one on
    /// miss. Callers are expected to `release` it when their LSP
    /// exchange is complete. Dropping an acquired [`ChildHandle`] instead
    /// kills and waits for its child, and the next `acquire` for that language
    /// spawns anew.
    ///
    /// # Errors
    ///
    /// Forwards [`LspSpawner::spawn`] errors.
    pub fn acquire(&self, language: &str) -> Result<ChildHandle> {
        if let Some(mut handle) = self.take(language) {
            handle.last_used = Instant::now();
            return Ok(handle);
        }
        let child = self.spawner.spawn(language)?;
        Ok(ChildHandle::new(language.to_string(), child))
    }

    /// Return a previously-acquired handle to the pool. The handle's
    /// `last_used` is refreshed to "now" so the reaper does not
    /// immediately reclaim it.
    pub fn release(&self, mut handle: ChildHandle) {
        handle.last_used = Instant::now();
        let Some(mut guard) = self.inner_guard("release") else {
            return;
        };
        // Last release wins and the displaced pooled child is reaped. The
        // language-only prototype cannot determine which concurrently spawned
        // server is the authoritative generation; that is one reason it stays
        // unavailable until S-068/S-069.
        let key = handle.language.clone();
        if let Some(mut stale) = guard.insert(key, handle) {
            if let Some(mut child) = stale.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Remove and return the entry for `language`, if any.
    fn take(&self, language: &str) -> Option<ChildHandle> {
        let mut guard = self.inner_guard("take")?;
        guard.remove(language)
    }

    /// Reap entries idle longer than the manager's TTL. Returns the
    /// count of entries evicted — useful for the `JobScheduler`-driven
    /// background-sweep landing.
    #[must_use]
    pub fn reap_idle(&self) -> usize {
        let now = Instant::now();
        let mut reaped = 0usize;
        let ttl = self.idle_ttl;
        let Some(mut guard) = self.inner_guard("reap_idle") else {
            return 0;
        };
        let stale_keys: Vec<String> = guard
            .iter()
            .filter(|(_, h)| now.duration_since(h.last_used) > ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for key in stale_keys {
            if let Some(mut handle) = guard.remove(&key) {
                if let Some(mut child) = handle.child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                reaped += 1;
            }
        }
        reaped
    }

    /// Kill every pooled server. Used at shutdown.
    pub fn kill_all(&self) {
        let Some(mut guard) = self.inner_guard("kill_all") else {
            return;
        };
        for (_, mut handle) in guard.drain() {
            if let Some(mut child) = handle.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Number of currently pooled entries. For tests + diagnostics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner_guard("len").map_or(0, |g| g.len())
    }

    /// `true` when the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for LspServerManager {
    fn drop(&mut self) {
        // Only the LAST Arc holder owns the inner state; if other
        // clones are alive elsewhere we must not race them by killing
        // children they may still be using.
        if Arc::strong_count(&self.inner) <= 1 {
            self.kill_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Stub spawner that launches the cross-platform "sleep forever"
    /// equivalent. We use `sleep 30` on Unix and `timeout 30` on
    /// Windows; both yield a long-lived child we can kill on demand.
    struct SleepSpawner {
        spawn_count: Arc<AtomicUsize>,
    }

    impl SleepSpawner {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let spawn_count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    spawn_count: Arc::clone(&spawn_count),
                },
                spawn_count,
            )
        }
    }

    impl LspSpawner for SleepSpawner {
        fn spawn(&self, _language: &str) -> Result<Child> {
            self.spawn_count.fetch_add(1, Ordering::SeqCst);
            #[cfg(unix)]
            let mut cmd = {
                let mut c = Command::new("sleep");
                c.arg("30");
                c
            };
            #[cfg(windows)]
            let mut cmd = {
                let mut c = Command::new("timeout");
                c.arg("30");
                c
            };
            let child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            Ok(child)
        }
    }

    #[test]
    fn acquire_then_release_reuses_handle() {
        let (spawner, count) = SleepSpawner::new();
        let mgr = LspServerManager::new(Arc::new(spawner));

        let handle1 = mgr.acquire("rust").unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        mgr.release(handle1);
        assert_eq!(mgr.len(), 1);

        // Second acquire must NOT spawn — it reuses the pooled handle.
        let handle2 = mgr.acquire("rust").unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1, "no second spawn");
        mgr.release(handle2);
        mgr.kill_all();
    }

    #[test]
    fn different_languages_get_independent_handles() {
        let (spawner, count) = SleepSpawner::new();
        let mgr = LspServerManager::new(Arc::new(spawner));

        let rust = mgr.acquire("rust").unwrap();
        let go = mgr.acquire("go").unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        mgr.release(rust);
        mgr.release(go);
        assert_eq!(mgr.len(), 2);
        mgr.kill_all();
    }

    #[test]
    fn reap_idle_evicts_old_entries() {
        let (spawner, _count) = SleepSpawner::new();
        // Set TTL to zero so any pooled handle is immediately stale.
        let mgr = LspServerManager::with_ttl(Arc::new(spawner), Duration::ZERO);

        let h = mgr.acquire("rust").unwrap();
        mgr.release(h);
        assert_eq!(mgr.len(), 1);

        // Sleep zero is enough; reaper sees the entry as past TTL.
        std::thread::sleep(Duration::from_millis(5));
        let reaped = mgr.reap_idle();
        assert_eq!(reaped, 1);
        assert!(mgr.is_empty());
    }

    #[test]
    fn kill_all_drains_the_pool() {
        let (spawner, _count) = SleepSpawner::new();
        let mgr = LspServerManager::new(Arc::new(spawner));
        let h = mgr.acquire("rust").unwrap();
        mgr.release(h);
        assert_eq!(mgr.len(), 1);
        mgr.kill_all();
        assert!(mgr.is_empty());
    }
}
