//! Marketplace schema types for plugin discovery and distribution.

use serde::{Deserialize, Serialize};

use super::manifest::PluginAuthor;

// ---------------------------------------------------------------------------
// Marketplace schema
// ---------------------------------------------------------------------------

/// Source for a plugin within a marketplace.
///
/// # Deserialization safety
///
/// `PluginSource` is an `untagged` enum whose two variants are structurally
/// disjoint: `Path` matches any bare string; `Structured` matches an object
/// that carries a `"source"` discriminator field (required by
/// `#[serde(tag = "source")]` on [`PluginSourceDef`]).
///
/// The key safety risk is one-directional: a bare string will always parse as
/// `Path` even if the author intended a structured source.  Mitigation: the
/// inner structs of `PluginSourceDef` all carry `deny_unknown_fields`, so a
/// mis-shaped object (e.g. typo in a required field) is rejected immediately
/// rather than partially accepted with defaulted fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PluginSource {
    /// Relative path to plugin root within marketplace
    Path(String),
    /// Structured source definition (requires a `source` discriminator key)
    Structured(PluginSourceDef),
}

/// NPM package source fields.
///
/// `deny_unknown_fields` rejects typos like `packagee` at parse time rather than
/// defaulting the field to `None` and failing silently at install time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmSource {
    /// NPM package name (e.g. `@scope/my-plugin`)
    pub package: String,
    /// Optional version specifier
    #[serde(default)]
    pub version: Option<String>,
    /// Optional custom registry URL
    #[serde(default)]
    pub registry: Option<String>,
}

/// Python package source fields.
///
/// `deny_unknown_fields` rejects typos at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipSource {
    /// `PyPI` package name
    pub package: String,
    /// Optional version specifier
    #[serde(default)]
    pub version: Option<String>,
    /// Optional custom registry URL
    #[serde(default)]
    pub registry: Option<String>,
}

/// Git URL source fields.
///
/// `deny_unknown_fields` rejects typos at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlSource {
    /// Git repository URL
    pub url: String,
    /// Optional git ref (branch, tag, or commit SHA)
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
}

/// GitHub repository source fields.
///
/// `deny_unknown_fields` rejects typos at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSource {
    /// `owner/repo` repository identifier
    pub repo: String,
    /// Optional git ref (branch, tag, or commit SHA)
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
}

/// Structured plugin source definition.
///
/// Uses an internal `source` tag as the discriminator.  Each variant delegates
/// to a dedicated struct carrying `deny_unknown_fields`, so a mis-shaped object
/// (e.g. `{"source": "npm", "packagee": "foo"}`) is rejected at parse time
/// rather than silently accepted with `None` defaulted fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source")]
pub enum PluginSourceDef {
    /// NPM package
    #[serde(rename = "npm")]
    Npm(NpmSource),
    /// Python package
    #[serde(rename = "pip")]
    Pip(PipSource),
    /// Git repository URL
    #[serde(rename = "url")]
    Url(UrlSource),
    /// GitHub repository
    #[serde(rename = "github")]
    GitHub(GitHubSource),
}

/// A plugin entry within a marketplace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePlugin {
    /// Plugin name (kebab-case)
    pub name: String,
    /// Where to fetch the plugin from
    pub source: PluginSource,
    /// Category for organizing plugins
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Tags for searchability
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Require plugin manifest to be present
    #[serde(default = "default_strict")]
    pub strict: bool,
    // Optional manifest fields inlined for non-strict plugins
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

const fn default_strict() -> bool {
    true
}

/// Marketplace metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MarketplaceMetadata {
    /// Base path for relative plugin sources
    #[serde(
        default,
        rename = "pluginRoot",
        skip_serializing_if = "Option::is_none"
    )]
    pub plugin_root: Option<String>,
    /// Marketplace version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Marketplace description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Marketplace manifest (marketplace.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceManifest {
    /// Marketplace name (kebab-case)
    pub name: String,
    /// Marketplace maintainer information
    pub owner: PluginAuthor,
    /// Collection of available plugins
    pub plugins: Vec<MarketplacePlugin>,
    /// Optional marketplace metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MarketplaceMetadata>,
}

/// Marketplace source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source")]
pub enum MarketplaceSource {
    /// GitHub repository
    #[serde(rename = "github")]
    GitHub {
        repo: String,
        #[serde(default)]
        #[serde(rename = "ref")]
        git_ref: Option<String>,
        #[serde(default)]
        path: Option<String>,
    },
    /// Git repository URL
    #[serde(rename = "git")]
    Git {
        url: String,
        #[serde(default)]
        #[serde(rename = "ref")]
        git_ref: Option<String>,
        #[serde(default)]
        path: Option<String>,
    },
    /// Direct URL to marketplace.json
    #[serde(rename = "url")]
    Url {
        url: String,
        #[serde(default)]
        headers: Option<crate::secrets::SensitiveHeaders>,
    },
    /// Local file path
    #[serde(rename = "file")]
    File { path: String },
    /// Local directory containing .claude-plugin/marketplace.json
    #[serde(rename = "directory")]
    Directory { path: String },
}

// ---------------------------------------------------------------------------
// Tests — PluginSource deserialization correctness
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Bare string → Path variant (the common case for local marketplace repos).
    #[test]
    fn plugin_source_string_parses_as_path() {
        let src: PluginSource = serde_json::from_str(r#""./plugins/my-plugin""#).unwrap();
        assert!(matches!(src, PluginSource::Path(ref p) if p == "./plugins/my-plugin"));
    }

    /// Structured npm source parses correctly.
    #[test]
    fn plugin_source_structured_npm_parses_correctly() {
        let json = r#"{"source": "npm", "package": "@scope/my-plugin", "version": "1.2.3"}"#;
        let src: PluginSource = serde_json::from_str(json).unwrap();
        match src {
            PluginSource::Structured(PluginSourceDef::Npm(NpmSource {
                package, version, ..
            })) => {
                assert_eq!(package, "@scope/my-plugin");
                assert_eq!(version.as_deref(), Some("1.2.3"));
            }
            other => panic!("expected Structured(Npm), got {other:?}"),
        }
    }

    /// Structured github source parses correctly.
    #[test]
    fn plugin_source_structured_github_parses_correctly() {
        let json = r#"{"source": "github", "repo": "owner/repo", "ref": "v1.0"}"#;
        let src: PluginSource = serde_json::from_str(json).unwrap();
        match src {
            PluginSource::Structured(PluginSourceDef::GitHub(GitHubSource { repo, git_ref })) => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(git_ref.as_deref(), Some("v1.0"));
            }
            other => panic!("expected Structured(GitHub), got {other:?}"),
        }
    }

    /// Forensic case C — typo in a required field is rejected at parse time.
    ///
    /// Before this fix: `deny_unknown_fields` was absent on `PluginSourceDef`
    /// variant content, so `{"source": "npm", "packagee": "foo"}` would
    /// silently parse and fail only at install time.  Now the unknown field
    /// `packagee` is rejected immediately.
    #[test]
    fn plugin_source_def_unknown_field_is_rejected() {
        let result =
            serde_json::from_str::<PluginSource>(r#"{"source": "npm", "packagee": "foo"}"#);
        assert!(
            result.is_err(),
            "expected error for unknown field 'packagee'; got: {result:?}"
        );
    }

    /// Structured url source parses correctly.
    #[test]
    fn plugin_source_structured_url_parses_correctly() {
        let json = r#"{"source": "url", "url": "https://example.com/plugin.git"}"#;
        let src: PluginSource = serde_json::from_str(json).unwrap();
        assert!(matches!(
            src,
            PluginSource::Structured(PluginSourceDef::Url(UrlSource { ref url, .. }))
                if url == "https://example.com/plugin.git"
        ));
    }
}
