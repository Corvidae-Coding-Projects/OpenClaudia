//! Memory configuration.
//!
//! A repository may select one host-approved team identity. Membership,
//! roles, credentials, and revocation remain in the host-owned authority
//! store; configuration can never create them. The former shared-directory
//! proposal is retained only as a rejected migration diagnostic.
//!
//! The private causal-replica implementation is retained for S-104, but its
//! transport and authorization will be driven by signed team identity rather
//! than a repository-selected location.

use serde::Deserialize;
use std::path::PathBuf;

use crate::team_memory::TeamId;

/// Memory configuration.
///
/// All fields are optional; defaulting yields per-user-only behaviour
/// (the team store is simply absent). Deserialization preserves the proposed
/// field for migration and library tests, while
/// [`crate::config::load_config`] rejects a configured path rather than
/// silently claiming production activation.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct MemoryConfig {
    /// Host-approved team selected for this repository.
    ///
    /// The identifier is only a selector. Loading it never creates or widens
    /// membership, and S-104 must authenticate every data operation through
    /// the corresponding host-owned authority file.
    #[serde(default)]
    pub team_id: Option<TeamId>,
    /// Directory containing a shared team memory database.
    ///
    /// When `None`, all production memory operations remain scoped to the
    /// project database. A `Some` value is permanently rejected by production
    /// configuration loading because a filesystem path is not authenticated
    /// authority. The legacy proposal can be expressed via either the
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
        assert!(cfg.team_id.is_none());
        assert!(cfg.team_memory_path.is_none());
    }

    #[test]
    fn deserialises_strict_team_identity_from_yaml() {
        let yaml = "team_id: team-0123456789abcdef0123456789abcdef\n";
        let cfg: MemoryConfig = serde_yaml::from_str(yaml).expect("valid yaml");
        assert_eq!(
            cfg.team_id.as_ref().map(TeamId::as_str),
            Some("team-0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn rejects_path_shaped_team_identity() {
        let error = serde_yaml::from_str::<MemoryConfig>("team_id: /srv/shared/memory\n")
            .expect_err("path cannot deserialize as team identity");
        assert!(error.to_string().contains("invalid team identity"));
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
