//! Memory configuration.
//!
//! Per crosslink #604 this preserves the proposed path to a *team* memory
//! directory. S-053 completed cross-store identity and replay, but production
//! configuration still rejects activation until S-054 establishes authenticated
//! authority, host-owned storage, schema recovery, and safe retrieval.
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
/// (the team store is simply absent). Deserialization preserves the proposed
/// field for migration and library tests, while
/// [`crate::config::load_config`] rejects a configured path rather than
/// silently claiming production activation.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct MemoryConfig {
    /// Directory containing a shared team memory database.
    ///
    /// When `None`, all production memory operations remain scoped to the
    /// project database. A `Some` value is currently rejected by production
    /// configuration loading pending S-054. The proposal can be expressed via either the
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
