//! Protected, user-owned provider API-key persistence.
//!
//! Interactive setup stores keys in a versioned JSON document beneath the
//! host user's application-data directory. Reads and writes go through the
//! descriptor-safe persistence layer with the credentials file class, so the
//! document is bounded, owner-private, symlink-resistant, and atomically
//! replaced. Project files are never a fallback destination.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{self, AppConfig};
use crate::persistence::{
    CommitState, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};
use crate::providers::ApiKey;

const STORE_SCHEMA_VERSION: u32 = 1;
const STORE_FILE_NAME: &str = "provider_api_keys.json";

/// Failure while locating, reading, validating, or updating saved API keys.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProviderCredentialError {
    /// The host does not expose a user application-data directory.
    #[error("protected user credential storage is unavailable: no application-data directory")]
    DataDirectoryUnavailable,

    /// This platform lacks the descriptor-safe storage backend.
    #[error("protected user credential storage is unavailable on this platform")]
    UnsupportedPlatform,

    /// The requested provider cannot consume a saved remote API key.
    #[error("provider '{0}' is not a supported remote API-key target")]
    InvalidProvider(String),

    /// A key already exists and replacement was not explicitly authorized.
    #[error("a saved API key already exists for provider '{0}'")]
    AlreadyExists(String),

    /// The protected store directory could not be inspected or created.
    #[error("failed to prepare protected credential directory {}: {source}", path.display())]
    Directory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Descriptor-safe file access failed.
    #[error("protected provider credential storage failed: {0}")]
    Persistence(#[from] PersistenceError),

    /// Stored bytes were not a supported, valid credential document.
    #[error("invalid protected provider credential document: {0}")]
    InvalidDocument(String),

    /// A valid credential document could not be encoded.
    #[error("failed to encode protected provider credential document: {0}")]
    Encode(#[from] serde_json::Error),

    /// Hidden terminal entry failed or yielded an invalid key.
    #[error("interactive API-key entry failed: {0}")]
    Terminal(String),

    /// Publication succeeded, but durable directory synchronization could not
    /// be established after the prescribed recovery attempt.
    #[error("provider credential update was published but its durability is uncertain")]
    DurabilityUncertain,
}

/// Result of an authorized save operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    /// No previous key existed for the provider.
    Saved,
    /// An existing provider key was explicitly replaced.
    Replaced,
    /// The requested value already matched the stored value.
    Unchanged,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedCredential {
    api_key: ApiKey,
}

impl Serialize for PersistedCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // This private serializer is the sole persistence boundary where raw
        // ApiKey bytes may be materialized. Generic ApiKey serialization stays
        // redacted everywhere else.
        let mut state = serializer.serialize_struct("PersistedCredential", 1)?;
        state.serialize_field("api_key", &PersistedApiKey(&self.api_key))?;
        state.end()
    }
}

struct PersistedApiKey<'a>(&'a ApiKey);

impl Serialize for PersistedApiKey<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.expose(|raw| serializer.serialize_str(raw))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDocument {
    schema_version: u32,
    #[serde(default)]
    providers: BTreeMap<String, PersistedCredential>,
}

impl Default for PersistedDocument {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            providers: BTreeMap::new(),
        }
    }
}

struct StoreRead {
    generation: StorageGeneration,
    document: PersistedDocument,
}

/// An opened capability for the protected provider credential document.
struct ProviderCredentialStore {
    storage: PersistentStorage,
    target: PathBuf,
}

impl std::fmt::Debug for ProviderCredentialStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderCredentialStore")
            .field("storage", &self.storage)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl ProviderCredentialStore {
    #[cfg(unix)]
    fn open(root: impl AsRef<Path>) -> Result<Self, ProviderCredentialError> {
        Ok(Self {
            storage: PersistentStorage::open(root)?,
            target: PathBuf::from(STORE_FILE_NAME),
        })
    }

    fn read(&self) -> Result<StoreRead, ProviderCredentialError> {
        let read = self.storage.read(&self.target, FileClass::Credentials)?;
        let generation = read.generation();
        let document = read.expose_bytes(|bytes| {
            let Some(bytes) = bytes else {
                return Ok(PersistedDocument::default());
            };
            serde_json::from_slice::<PersistedDocument>(bytes)
                .map_err(|error| ProviderCredentialError::InvalidDocument(error.to_string()))
        })?;
        validate_document(&document)?;
        Ok(StoreRead {
            generation,
            document,
        })
    }

    /// Return whether this store contains a key for the provider.
    pub fn contains(&self, provider: &str) -> Result<bool, ProviderCredentialError> {
        let provider = canonical_remote_provider(provider)?;
        Ok(self.read()?.document.providers.contains_key(provider))
    }

    /// Load all validated canonical provider keys.
    pub fn load(&self) -> Result<BTreeMap<String, ApiKey>, ProviderCredentialError> {
        Ok(self
            .read()?
            .document
            .providers
            .into_iter()
            .map(|(provider, credential)| (provider, credential.api_key))
            .collect())
    }

    /// Save a provider key, requiring explicit authorization to replace an
    /// existing value.
    pub fn save(
        &self,
        provider: &str,
        api_key: ApiKey,
        overwrite: bool,
    ) -> Result<SaveOutcome, ProviderCredentialError> {
        let provider = canonical_remote_provider(provider)?;
        let mut current = self.read()?;
        let outcome = match current.document.providers.get(provider) {
            Some(existing) if existing.api_key == api_key => SaveOutcome::Unchanged,
            Some(_) if !overwrite => {
                return Err(ProviderCredentialError::AlreadyExists(provider.to_string()));
            }
            Some(_) => SaveOutcome::Replaced,
            None => SaveOutcome::Saved,
        };
        if outcome == SaveOutcome::Unchanged {
            return Ok(outcome);
        }

        current
            .document
            .providers
            .insert(provider.to_string(), PersistedCredential { api_key });
        let encoded = Zeroizing::new(serde_json::to_vec_pretty(&current.document)?);
        let receipt = self.storage.commit(
            &self.target,
            FileClass::Credentials,
            current.generation,
            &*encoded,
        )?;
        if receipt.state() == CommitState::PublishedDurabilityUncertain {
            let recovery = self.storage.commit(
                &self.target,
                FileClass::Credentials,
                current.generation,
                &*encoded,
            )?;
            if recovery.state() == CommitState::PublishedDurabilityUncertain {
                return Err(ProviderCredentialError::DurabilityUncertain);
            }
        }
        Ok(outcome)
    }
}

fn validate_document(document: &PersistedDocument) -> Result<(), ProviderCredentialError> {
    if document.schema_version != STORE_SCHEMA_VERSION {
        return Err(ProviderCredentialError::InvalidDocument(format!(
            "unsupported schema version {} (expected {STORE_SCHEMA_VERSION})",
            document.schema_version
        )));
    }
    for provider in document.providers.keys() {
        if canonical_remote_provider(provider)? != provider {
            return Err(ProviderCredentialError::InvalidDocument(format!(
                "provider key '{provider}' is not canonical"
            )));
        }
    }
    Ok(())
}

fn canonical_remote_provider(provider: &str) -> Result<&'static str, ProviderCredentialError> {
    let canonical = config::canonical_provider_config_key(provider)
        .ok_or_else(|| ProviderCredentialError::InvalidProvider(provider.to_string()))?;
    if config::is_local_provider_name(canonical)
        || crate::providers::get_adapter(canonical).is_err()
    {
        return Err(ProviderCredentialError::InvalidProvider(
            provider.to_string(),
        ));
    }
    Ok(canonical)
}

/// Absolute path of the protected user provider credential document.
///
/// # Errors
///
/// Returns [`ProviderCredentialError::DataDirectoryUnavailable`] when the
/// host does not expose a user application-data directory.
pub fn user_store_path() -> Result<PathBuf, ProviderCredentialError> {
    dirs::data_local_dir()
        .map(|root| root.join("openclaudia").join(STORE_FILE_NAME))
        .ok_or(ProviderCredentialError::DataDirectoryUnavailable)
}

/// Whether this build can offer descriptor-safe provider-key persistence.
#[must_use]
pub const fn protected_persistence_supported() -> bool {
    cfg!(unix)
}

#[cfg(unix)]
fn open_default_store_for_read() -> Result<Option<ProviderCredentialStore>, ProviderCredentialError>
{
    let path = match user_store_path() {
        Ok(path) => path,
        Err(ProviderCredentialError::DataDirectoryUnavailable) => return Ok(None),
        Err(error) => return Err(error),
    };
    let root = path
        .parent()
        .expect("credential store path always has an application-data parent");
    match path.try_exists() {
        Ok(false) => Ok(None),
        Ok(true) => ProviderCredentialStore::open(root).map(Some),
        Err(source) => Err(ProviderCredentialError::Directory { path, source }),
    }
}

#[cfg(not(unix))]
fn open_default_store_for_read() -> Result<Option<ProviderCredentialStore>, ProviderCredentialError>
{
    // Existing config/environment authentication remains usable on platforms
    // where protected local persistence cannot uphold its contract.
    Ok(None)
}

#[cfg(unix)]
fn open_default_store_for_write() -> Result<ProviderCredentialStore, ProviderCredentialError> {
    use std::os::unix::fs::DirBuilderExt as _;

    let path = user_store_path()?;
    let root = path
        .parent()
        .expect("credential store path always has an application-data parent");
    let existed = root
        .try_exists()
        .map_err(|source| ProviderCredentialError::Directory {
            path: root.to_path_buf(),
            source,
        })?;
    if !existed {
        let parent = root
            .parent()
            .expect("application data store always has a parent");
        std::fs::create_dir_all(parent).map_err(|source| ProviderCredentialError::Directory {
            path: parent.to_path_buf(),
            source,
        })?;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(root) {
            Ok(()) => {}
            // A concurrent creator is validated by PersistentStorage::open;
            // do not chmod or otherwise mutate an object we did not create.
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(ProviderCredentialError::Directory {
                    path: root.to_path_buf(),
                    source,
                });
            }
        }
    }
    ProviderCredentialStore::open(root)
}

#[cfg(not(unix))]
fn open_default_store_for_write() -> Result<ProviderCredentialStore, ProviderCredentialError> {
    Err(ProviderCredentialError::UnsupportedPlatform)
}

/// Load protected user keys. A missing store is an empty source, while an
/// existing malformed or insecure store is reported instead of ignored.
///
/// # Errors
///
/// Returns an error when an existing store cannot be safely opened, read, or
/// decoded as the current credential schema.
pub fn load_user_api_keys() -> Result<BTreeMap<String, ApiKey>, ProviderCredentialError> {
    open_default_store_for_read()?.map_or_else(|| Ok(BTreeMap::new()), |store| store.load())
}

/// Apply protected user keys only where all higher-priority config sources
/// left a provider key unset.
///
/// # Errors
///
/// Returns an error when an existing protected store is inaccessible,
/// insecure, malformed, or uses an unsupported schema.
pub fn apply_user_api_keys(config: &mut AppConfig) -> Result<usize, ProviderCredentialError> {
    let keys = load_user_api_keys()?;
    Ok(apply_api_keys(&mut config.providers, &keys))
}

fn apply_api_keys(
    providers: &mut std::collections::HashMap<String, crate::config::ProviderConfig>,
    keys: &BTreeMap<String, ApiKey>,
) -> usize {
    let mut applied = 0;
    for (name, provider_config) in providers {
        if provider_config.api_key.is_some() {
            continue;
        }
        let Some(canonical) = config::canonical_provider_config_key(name) else {
            continue;
        };
        if let Some(api_key) = keys.get(canonical) {
            provider_config.api_key = Some(api_key.clone());
            applied += 1;
        }
    }
    applied
}

/// Save one key to the protected user store.
///
/// # Errors
///
/// Returns an error for an unsupported provider, an unavailable or insecure
/// store, a concurrent update, or an existing key without overwrite consent.
pub fn save_user_api_key(
    provider: &str,
    api_key: ApiKey,
    overwrite: bool,
) -> Result<SaveOutcome, ProviderCredentialError> {
    open_default_store_for_write()?.save(provider, api_key, overwrite)
}

/// Return whether a protected user key already exists for a provider.
///
/// # Errors
///
/// Returns an error for an unsupported provider or an existing store that
/// cannot be safely opened, read, or decoded.
pub fn has_saved_user_api_key(provider: &str) -> Result<bool, ProviderCredentialError> {
    open_default_store_for_read()?.map_or_else(|| Ok(false), |store| store.contains(provider))
}

/// Canonical remote targets currently present in the typed provider registry.
#[must_use]
pub fn api_key_targets(config: &AppConfig) -> Vec<String> {
    collect_api_key_targets(config.providers.keys().map(String::as_str))
}

fn collect_api_key_targets<'a>(providers: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut targets = BTreeSet::new();
    for provider in providers {
        let Some(canonical) = config::canonical_provider_config_key(provider) else {
            continue;
        };
        if !config::is_local_provider_name(canonical)
            && crate::providers::get_adapter(canonical).is_ok()
        {
            targets.insert(canonical.to_string());
        }
    }
    targets.into_iter().collect()
}

/// Read one API key from the controlling terminal with echo disabled.
///
/// # Errors
///
/// Returns an error when the controlling terminal cannot be read or when the
/// entered value fails [`ApiKey`] validation.
pub fn prompt_hidden_api_key(provider: &str) -> Result<ApiKey, ProviderCredentialError> {
    let raw = rpassword::prompt_password(format!("{provider} API key (input hidden): "))
        .map_err(|error| ProviderCredentialError::Terminal(error.to_string()))?;
    ApiKey::try_from_string(raw)
        .map_err(|error| ProviderCredentialError::Terminal(format!("{provider}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProviderConfig, ThinkingConfig};
    use crate::secrets::SensitiveHeaders;
    use std::collections::HashMap;

    fn key(raw: &str) -> ApiKey {
        ApiKey::try_from_string(raw.to_string()).expect("valid test key")
    }

    fn provider_config(api_key: Option<ApiKey>) -> ProviderConfig {
        ProviderConfig {
            api_key,
            base_url: "https://example.com".to_string(),
            model: None,
            headers: SensitiveHeaders::new(),
            thinking: ThinkingConfig::default(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_load_replace_and_deny_overwrite_are_transactional() {
        let root = tempfile::tempdir().expect("temp root");
        let store = ProviderCredentialStore::open(root.path()).expect("open store");
        assert_eq!(
            store
                .save("gemini", key("sk-original-provider-key"), false)
                .expect("initial save"),
            SaveOutcome::Saved
        );
        assert!(store.load().expect("load")["google"].matches("sk-original-provider-key"));

        let bytes_before = std::fs::read(root.path().join(STORE_FILE_NAME)).expect("stored bytes");
        let denied = store.save("google", key("sk-denied-replacement"), false);
        assert!(matches!(
            denied,
            Err(ProviderCredentialError::AlreadyExists(_))
        ));
        assert_eq!(
            std::fs::read(root.path().join(STORE_FILE_NAME)).expect("unchanged bytes"),
            bytes_before
        );

        assert_eq!(
            store
                .save("google", key("sk-approved-replacement"), true)
                .expect("replace"),
            SaveOutcome::Replaced
        );
        assert!(store.load().expect("load")["google"].matches("sk-approved-replacement"));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_document_is_private_and_generic_diagnostics_stay_redacted() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temp root");
        let store = ProviderCredentialStore::open(root.path()).expect("open store");
        let api_key = key("sk-private-persisted-key");
        store.save("openai", api_key.clone(), false).expect("save");

        let path = root.path().join(STORE_FILE_NAME);
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let bytes = std::fs::read_to_string(path).expect("stored document");
        assert!(bytes.contains("sk-private-persisted-key"));
        assert!(!format!("{api_key:?}").contains("private-persisted-key"));
        assert!(!serde_json::to_string(&api_key)
            .expect("generic serialization")
            .contains("private-persisted-key"));
    }

    #[test]
    fn stored_keys_fill_only_missing_provider_credentials() {
        let explicit = key("sk-explicit-key");
        let stored = key("sk-stored-key");
        let mut providers = HashMap::new();
        providers.insert(
            "google".to_string(),
            provider_config(Some(explicit.clone())),
        );
        providers.insert("gemini".to_string(), provider_config(None));
        let keys = BTreeMap::from([("google".to_string(), stored)]);

        assert_eq!(apply_api_keys(&mut providers, &keys), 1);
        assert_eq!(providers["google"].api_key.as_ref(), Some(&explicit));
        assert!(providers["gemini"]
            .api_key
            .as_ref()
            .is_some_and(|key| key.matches("sk-stored-key")));
    }

    #[test]
    fn target_list_comes_from_registry_and_excludes_local_providers() {
        let mut providers = HashMap::new();
        providers.insert("gemini".to_string(), provider_config(None));
        providers.insert("google".to_string(), provider_config(None));
        providers.insert("openrouter".to_string(), provider_config(None));
        providers.insert("ollama".to_string(), provider_config(None));
        providers.insert("unknown".to_string(), provider_config(None));
        let targets = collect_api_key_targets(providers.keys().map(String::as_str));

        assert_eq!(targets, ["google", "openrouter"]);
    }
}
