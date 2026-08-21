//! Memory configuration.
//!
//! Per crosslink #604 this carries the optional path to a *team* memory
//! directory that participates alongside the per-user memory database.
//!
//! Parity reference: Claude Code's `teamMemPaths.ts` exposes a shared
//! memory location so multiple users on the same project share core and
//! archival memories. Resolution order is **User overrides Team** —
//! reads merge both stores with user entries winning on duplicate IDs,
//! and writes route to the scope the caller selects. The last-write-wins
//! rule applies when the same logical key is touched in both stores
//! (the caller decides scope).

use serde::Deserialize;
use std::path::PathBuf;

/// Memory configuration.
///
/// All fields are optional; defaulting yields per-user-only behaviour
/// (the team store is simply absent). When `team_memory_path` is set,
/// memory operations participate against the team store in addition to
/// the per-user store, governed by the [`MemoryScope`](crate::team_memory::MemoryScope)
/// passed to each operation.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct MemoryConfig {
    /// Directory containing a shared team memory database.
    ///
    /// When `Some`, the path is opened (creating it if missing) alongside
    /// the per-user memory database. When `None`, all memory ops remain
    /// scoped to the per-user database. Configurable via either the
    /// `[memory]` section of `config.yaml` or the canonical
    /// `OPENCLAUDIA_MEMORY__TEAM_MEMORY_PATH` environment variable. The exact
    /// single-underscore spelling remains a deprecated migration alias.
    #[serde(default)]
    pub team_memory_path: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_no_team_path() {
        let cfg = MemoryConfig::default();
        assert!(cfg.team_memory_path.is_none());
    }

    #[test]
    fn deserialises_team_memory_path_from_yaml() {
        let yaml = "team_memory_path: /srv/shared/memory\n";
        let cfg: MemoryConfig = serde_yaml::from_str(yaml).expect("valid yaml");
        assert_eq!(
            cfg.team_memory_path.as_deref(),
            Some(std::path::Path::new("/srv/shared/memory"))
        );
    }

    #[test]
    fn empty_yaml_yields_default() {
        let cfg: MemoryConfig = serde_yaml::from_str("{}").expect("valid yaml");
        assert!(cfg.team_memory_path.is_none());
    }
}
