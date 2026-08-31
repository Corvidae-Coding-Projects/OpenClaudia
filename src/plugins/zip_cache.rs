//! Offline plugin distribution via on-disk archive cache (crosslink
//! #656, CC parity with `zipCache.ts`).
//!
//! Background: CC supports installing plugins from a pre-downloaded
//! archive in `~/.claude/plugins/cache/<sha256>.zip` so the install
//! works on air-gapped machines and survives marketplace outages. The
//! cache key is the SHA-256 of the archive bytes; the manifest carries
//! that hash so the host can resolve, verify, and extract without
//! touching the network.
//!
//! Cache reads are content-addressed and extraction is bounded before any
//! package enters the plugin transaction staging area. Archives may contain
//! the package at their root or under one wrapper directory; traversal,
//! links, special entries, duplicate paths, and decompression overruns fail
//! closed.
//!
//! On-disk layout (under `~/.openclaudia/plugins/cache/`):
//!
//! ```text
//! cache/
//!   index.json            ← one entry per cached archive
//!   <sha256>.zip          ← raw archive bytes
//! ```
//!
//! `index.json` is a flat JSON map keyed by sha256. Storing the sha256
//! in the filename redundantly is intentional: a corrupt index lets us
//! rebuild from `ls`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Errors surfaced by the zip-cache module. Returned as a single typed
/// error so callers can distinguish "cache miss" (recoverable, do the
/// online install) from "cache present but corrupt" (must repair).
#[derive(Debug, Error)]
pub enum ZipCacheError {
    /// The requested sha256 is not present in the cache.
    #[error("cache miss: no archive with sha256 {0}")]
    Missing(String),
    /// The archive on disk was found but its bytes hash to a different
    /// sha256. The caller must treat this as tampering and refuse.
    #[error("integrity check failed: archive {sha256} hashes to {actual}")]
    IntegrityMismatch {
        /// The sha256 the caller asked for.
        sha256: String,
        /// The sha256 actually computed off-disk.
        actual: String,
    },
    /// Filesystem error reading or writing the cache.
    #[error("cache I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Index file failed to deserialize.
    #[error("cache index corrupt: {0}")]
    Index(#[from] serde_json::Error),
    /// The archive is malformed or violates package extraction bounds.
    #[error("cached archive rejected: {0}")]
    Archive(String),
}

const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXTRACTED_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4_096;
const MAX_ARCHIVE_DEPTH: usize = 16;

/// One cached archive entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    /// SHA-256 of the archive bytes (hex, lowercase). Doubles as the
    /// filename (`<sha256>.zip`).
    pub sha256: String,
    /// Plugin id this archive provides. Matches
    /// [`crate::plugins::Plugin::id`] post-install.
    pub plugin_id: String,
    /// Semver string from the originating manifest, when known.
    pub version: Option<String>,
    /// Wall-clock seconds since UNIX epoch the entry was written. Used
    /// by `/maintain` to age out stale entries.
    pub installed_at_unix: u64,
}

/// Filename of the index file at the cache root.
pub const INDEX_FILENAME: &str = "index.json";

/// File extension applied to cached archives. Plain `.zip` to match
/// CC's on-disk convention; extracting consumers don't have to guess.
pub const ARCHIVE_EXTENSION: &str = "zip";

/// On-disk cache of archives.
#[derive(Debug)]
pub struct ZipCache {
    root: PathBuf,
}

impl ZipCache {
    /// Bind to `root` (created on demand). `root` is conventionally
    /// `~/.openclaudia/plugins/cache/`.
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Path to the cache index file. Public so /doctor can surface it.
    #[must_use]
    pub fn index_path(&self) -> PathBuf {
        self.root.join(INDEX_FILENAME)
    }

    /// Path the archive for `sha256` would occupy on disk. Returns the
    /// path even when the archive isn't yet present so callers can
    /// `fs::write` to it for fresh adds.
    #[must_use]
    pub fn archive_path(&self, sha256: &str) -> PathBuf {
        self.root.join(format!("{sha256}.{ARCHIVE_EXTENSION}"))
    }

    /// Read the index file. Returns an empty map when the index doesn't
    /// yet exist (first-run behaviour).
    ///
    /// # Errors
    ///
    /// Returns [`ZipCacheError::Io`] for any FS error other than
    /// `NotFound`, and [`ZipCacheError::Index`] when the index file is
    /// present but doesn't deserialize.
    pub fn read_index(&self) -> Result<BTreeMap<String, CacheEntry>, ZipCacheError> {
        let path = self.index_path();
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(serde_json::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(ZipCacheError::Io(e)),
        }
    }

    /// Write the index file, creating parent dirs if needed.
    ///
    /// # Errors
    ///
    /// Returns [`ZipCacheError::Io`] on any filesystem failure, or
    /// [`ZipCacheError::Index`] if serialization fails (which would
    /// indicate a logic error in `CacheEntry`'s derive).
    pub fn write_index(&self, entries: &BTreeMap<String, CacheEntry>) -> Result<(), ZipCacheError> {
        std::fs::create_dir_all(&self.root)?;
        let body = serde_json::to_string_pretty(entries)?;
        std::fs::write(self.index_path(), body)?;
        Ok(())
    }

    /// Insert one archive into the cache: write `bytes` to disk,
    /// upsert `entry` into the index, and atomically flush both. The
    /// caller is responsible for filling `entry.sha256` with the
    /// archive's actual hash (which must match `bytes` — verified
    /// here).
    ///
    /// # Errors
    ///
    /// Returns [`ZipCacheError::IntegrityMismatch`] when
    /// `entry.sha256` disagrees with the computed hash of `bytes`,
    /// [`ZipCacheError::Index`] when the existing index is corrupt, and
    /// [`ZipCacheError::Io`] for any filesystem error.
    pub fn put(&self, entry: CacheEntry, bytes: &[u8]) -> Result<(), ZipCacheError> {
        validate_digest(&entry.sha256)?;
        if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
            return Err(ZipCacheError::Archive(format!(
                "compressed archive exceeds {MAX_ARCHIVE_BYTES} bytes"
            )));
        }
        let actual = sha256_hex(bytes);
        if actual != entry.sha256 {
            return Err(ZipCacheError::IntegrityMismatch {
                sha256: entry.sha256,
                actual,
            });
        }
        let mut idx = self.read_index()?;
        std::fs::create_dir_all(&self.root)?;
        std::fs::write(self.archive_path(&entry.sha256), bytes)?;
        idx.insert(entry.sha256.clone(), entry);
        self.write_index(&idx)?;
        Ok(())
    }

    /// Read an archive out of the cache, verifying integrity. The
    /// expected `sha256` MUST be supplied by the caller (typically out
    /// of the install manifest) so a swap-on-disk attack cannot silently
    /// substitute a different archive under the same id.
    ///
    /// # Errors
    ///
    /// * [`ZipCacheError::Missing`] when the archive isn't cached.
    /// * [`ZipCacheError::IntegrityMismatch`] when the bytes on disk
    ///   don't hash to the expected sha256.
    /// * [`ZipCacheError::Io`] on filesystem failure.
    pub fn get_verified(&self, sha256: &str) -> Result<Vec<u8>, ZipCacheError> {
        validate_digest(sha256)?;
        let path = self.archive_path(sha256);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ZipCacheError::Missing(sha256.to_string()));
            }
            Err(e) => return Err(ZipCacheError::Io(e)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ZipCacheError::Archive(
                "cached archive must be a real regular file".to_string(),
            ));
        }
        if metadata.len() > MAX_ARCHIVE_BYTES {
            return Err(ZipCacheError::Archive(format!(
                "compressed archive exceeds {MAX_ARCHIVE_BYTES} bytes"
            )));
        }
        let bytes = std::fs::read(&path)?;
        let actual = sha256_hex(&bytes);
        if actual != sha256 {
            return Err(ZipCacheError::IntegrityMismatch {
                sha256: sha256.to_string(),
                actual,
            });
        }
        Ok(bytes)
    }

    /// Return the index metadata bound to one cached digest.
    ///
    /// # Errors
    /// Returns a cache miss when the digest has no index entry, or the same
    /// validation/index failures as [`Self::read_index`].
    pub fn entry(&self, sha256: &str) -> Result<CacheEntry, ZipCacheError> {
        validate_digest(sha256)?;
        let entry = self
            .read_index()?
            .remove(sha256)
            .ok_or_else(|| ZipCacheError::Missing(sha256.to_string()))?;
        if entry.sha256 != sha256 {
            return Err(ZipCacheError::Archive(
                "cache index key and entry digest disagree".to_string(),
            ));
        }
        Ok(entry)
    }

    /// Verify and safely materialize a cached package archive into a new
    /// transaction staging directory.
    ///
    /// # Errors
    /// Returns an archive rejection for unsafe paths, links, special entries,
    /// unsupported layouts, duplicate paths, or size/count/depth overruns.
    pub fn materialize_verified(
        &self,
        sha256: &str,
        destination: &Path,
    ) -> Result<(), ZipCacheError> {
        let bytes = self.get_verified(sha256)?;
        if destination.exists() {
            return Err(ZipCacheError::Archive(format!(
                "staging destination already exists: {}",
                destination.display()
            )));
        }
        let result = extract_archive(&bytes, destination);
        if result.is_err() {
            let _ = std::fs::remove_dir_all(destination);
        }
        result
    }

    /// True iff `sha256` is currently present on disk (does NOT
    /// re-verify the bytes — use [`Self::get_verified`] for that).
    #[must_use]
    pub fn contains(&self, sha256: &str) -> bool {
        validate_digest(sha256).is_ok() && self.archive_path(sha256).is_file()
    }
}

fn validate_digest(sha256: &str) -> Result<(), ZipCacheError> {
    if sha256.len() == 64
        && sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ZipCacheError::Archive(
            "cache digest must be 64 lowercase hexadecimal characters".to_string(),
        ))
    }
}

#[derive(Debug)]
struct ArchiveEntry {
    index: usize,
    path: PathBuf,
    size: u64,
    is_dir: bool,
    unix_mode: Option<u32>,
}

fn normalized_entry_path(file: &zip::read::ZipFile<'_, Cursor<&[u8]>>) -> Option<PathBuf> {
    let enclosed = file.enclosed_name()?;
    let mut normalized = PathBuf::new();
    for component in enclosed.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

fn archive_wrapper(entries: &[ArchiveEntry]) -> Result<Option<PathBuf>, ZipCacheError> {
    let root_manifest = entries.iter().any(|entry| {
        !entry.is_dir
            && (entry.path == Path::new("plugin.json")
                || entry.path == Path::new(".claude-plugin/plugin.json"))
    });
    if root_manifest {
        return Ok(None);
    }
    let wrapper = entries
        .iter()
        .find_map(|entry| entry.path.components().next())
        .and_then(|component| match component {
            Component::Normal(name) => Some(PathBuf::from(name)),
            _ => None,
        })
        .ok_or_else(|| ZipCacheError::Archive("archive contains no package entries".to_string()))?;
    if !entries.iter().all(|entry| entry.path.starts_with(&wrapper)) {
        return Err(ZipCacheError::Archive(
            "archive has no single package root".to_string(),
        ));
    }
    let wrapped_manifest = entries.iter().any(|entry| {
        !entry.is_dir
            && (entry.path == wrapper.join("plugin.json")
                || entry.path == wrapper.join(".claude-plugin/plugin.json"))
    });
    if !wrapped_manifest {
        return Err(ZipCacheError::Archive(
            "archive contains no plugin manifest at its package root".to_string(),
        ));
    }
    Ok(Some(wrapper))
}

type InspectedArchive<'a> = (
    zip::ZipArchive<Cursor<&'a [u8]>>,
    Vec<ArchiveEntry>,
    Option<PathBuf>,
);

fn inspect_archive(bytes: &[u8]) -> Result<InspectedArchive<'_>, ZipCacheError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| ZipCacheError::Archive(error.to_string()))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ZipCacheError::Archive(format!(
            "archive contains more than {MAX_ARCHIVE_ENTRIES} entries"
        )));
    }
    let mut entries = Vec::with_capacity(archive.len());
    let mut paths = HashSet::new();
    let mut declared_bytes = 0_u64;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|error| ZipCacheError::Archive(error.to_string()))?;
        if file.encrypted() {
            return Err(ZipCacheError::Archive(
                "encrypted cache entries are unsupported".to_string(),
            ));
        }
        if file.is_symlink() || (!file.is_file() && !file.is_dir()) {
            return Err(ZipCacheError::Archive(format!(
                "archive entry is a link or special file: {}",
                file.name()
            )));
        }
        let path = normalized_entry_path(&file).ok_or_else(|| {
            ZipCacheError::Archive(format!("unsafe archive entry path: {}", file.name()))
        })?;
        if path.components().count() > MAX_ARCHIVE_DEPTH {
            return Err(ZipCacheError::Archive(format!(
                "archive entry exceeds depth {MAX_ARCHIVE_DEPTH}: {}",
                path.display()
            )));
        }
        if !paths.insert(path.clone()) {
            return Err(ZipCacheError::Archive(format!(
                "archive contains duplicate path: {}",
                path.display()
            )));
        }
        if file.size() > MAX_EXTRACTED_FILE_BYTES {
            return Err(ZipCacheError::Archive(format!(
                "archive entry exceeds {MAX_EXTRACTED_FILE_BYTES} bytes: {}",
                path.display()
            )));
        }
        declared_bytes = declared_bytes.checked_add(file.size()).ok_or_else(|| {
            ZipCacheError::Archive("archive expanded size overflowed".to_string())
        })?;
        if declared_bytes > MAX_EXTRACTED_BYTES {
            return Err(ZipCacheError::Archive(format!(
                "archive expands beyond {MAX_EXTRACTED_BYTES} bytes"
            )));
        }
        entries.push(ArchiveEntry {
            index,
            path,
            size: file.size(),
            is_dir: file.is_dir(),
            unix_mode: file.unix_mode(),
        });
    }
    let wrapper = archive_wrapper(&entries)?;
    Ok((archive, entries, wrapper))
}

fn extract_archive(bytes: &[u8], destination: &Path) -> Result<(), ZipCacheError> {
    let (mut archive, entries, wrapper) = inspect_archive(bytes)?;
    std::fs::create_dir(destination)?;
    let mut extracted_bytes = 0_u64;
    for metadata in entries {
        let relative = wrapper.as_ref().map_or(metadata.path.as_path(), |prefix| {
            metadata
                .path
                .strip_prefix(prefix)
                .unwrap_or(metadata.path.as_path())
        });
        if relative.as_os_str().is_empty() {
            continue;
        }
        let output_path = destination.join(relative);
        if metadata.is_dir {
            std::fs::create_dir_all(&output_path)?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut input = archive
            .by_index(metadata.index)
            .map_err(|error| ZipCacheError::Archive(error.to_string()))?;
        let mut output = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output_path)?;
        let copied = std::io::copy(
            &mut input.by_ref().take(MAX_EXTRACTED_FILE_BYTES + 1),
            &mut output,
        )?;
        if copied != metadata.size || copied > MAX_EXTRACTED_FILE_BYTES {
            return Err(ZipCacheError::Archive(format!(
                "archive entry size changed while extracting: {}",
                metadata.path.display()
            )));
        }
        extracted_bytes = extracted_bytes.checked_add(copied).ok_or_else(|| {
            ZipCacheError::Archive("archive extracted size overflowed".to_string())
        })?;
        if extracted_bytes > MAX_EXTRACTED_BYTES {
            return Err(ZipCacheError::Archive(format!(
                "archive expands beyond {MAX_EXTRACTED_BYTES} bytes"
            )));
        }
        output.flush()?;
        #[cfg(unix)]
        if let Some(mode) = metadata.unix_mode {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
    }
    Ok(())
}

/// Compute the lowercase-hex SHA-256 of `bytes`. Shared helper so the
/// cache's write path and the verify path can't disagree on hex casing.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for (name, contents) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("start ZIP entry");
            writer.write_all(contents).expect("write ZIP entry");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn fresh() -> (TempDir, ZipCache) {
        let tmp = TempDir::new().unwrap();
        let cache = ZipCache::new(tmp.path().to_path_buf());
        (tmp, cache)
    }

    fn entry(sha: &str) -> CacheEntry {
        CacheEntry {
            sha256: sha.into(),
            plugin_id: "demo".into(),
            version: Some("1.0.0".into()),
            installed_at_unix: 42,
        }
    }

    #[test]
    fn put_then_get_round_trips() {
        let (_tmp, cache) = fresh();
        let bytes = b"PK\x03\x04 fake zip bytes";
        let sha = sha256_hex(bytes);
        cache.put(entry(&sha), bytes).expect("put succeeds");

        let read = cache.get_verified(&sha).expect("get succeeds");
        assert_eq!(read, bytes);
        assert!(cache.contains(&sha));
    }

    #[test]
    fn materialize_verified_accepts_one_wrapper_and_strips_it() {
        let (_tmp, cache) = fresh();
        let bytes = archive(&[
            (
                "release/.claude-plugin/plugin.json",
                br#"{"name":"cached-plugin","version":"1.0.0"}"#,
            ),
            ("release/commands/run.md", b"run it"),
        ]);
        let sha = sha256_hex(&bytes);
        cache.put(entry(&sha), &bytes).expect("cache archive");
        let destination = cache.root.join("stage");

        cache
            .materialize_verified(&sha, &destination)
            .expect("extract archive");

        assert!(destination.join(".claude-plugin/plugin.json").is_file());
        assert!(destination.join("commands/run.md").is_file());
        assert!(!destination.join("release").exists());
    }

    #[test]
    fn materialize_verified_rejects_traversal_without_residue() {
        let (_tmp, cache) = fresh();
        let bytes = archive(&[
            (".claude-plugin/plugin.json", br#"{"name":"cached-plugin"}"#),
            ("../escape", b"no"),
        ]);
        let sha = sha256_hex(&bytes);
        cache.put(entry(&sha), &bytes).expect("cache archive");
        let destination = cache.root.join("stage");

        let error = cache
            .materialize_verified(&sha, &destination)
            .expect_err("traversal must fail");

        assert!(matches!(error, ZipCacheError::Archive(_)));
        assert!(!destination.exists());
        assert!(!cache.root.join("escape").exists());
    }

    #[test]
    fn get_missing_archive_returns_missing_error() {
        let (_tmp, cache) = fresh();
        let err = cache
            .get_verified("00".repeat(32).as_str())
            .expect_err("missing must error");
        assert!(matches!(err, ZipCacheError::Missing(_)));
    }

    #[test]
    fn put_with_wrong_sha_rejects() {
        let (_tmp, cache) = fresh();
        let bytes = b"some bytes";
        let bad = entry("0".repeat(64).as_str());
        let err = cache.put(bad, bytes).expect_err("mismatch must error");
        match err {
            ZipCacheError::IntegrityMismatch { actual, .. } => {
                assert_eq!(actual, sha256_hex(bytes));
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    #[test]
    fn get_detects_tampered_archive_on_disk() {
        let (_tmp, cache) = fresh();
        let bytes = b"genuine";
        let sha = sha256_hex(bytes);
        cache.put(entry(&sha), bytes).unwrap();
        // Overwrite the file with different bytes — same filename, different hash.
        std::fs::write(cache.archive_path(&sha), b"tampered").unwrap();
        let err = cache.get_verified(&sha).expect_err("tamper must be caught");
        assert!(matches!(err, ZipCacheError::IntegrityMismatch { .. }));
    }

    #[test]
    fn missing_index_reads_as_empty_map() {
        let (_tmp, cache) = fresh();
        let idx = cache.read_index().expect("missing index → empty map");
        assert!(idx.is_empty());
    }

    #[test]
    fn index_round_trips() {
        let (_tmp, cache) = fresh();
        let mut idx = BTreeMap::new();
        let e = entry("a".repeat(64).as_str());
        idx.insert(e.sha256.clone(), e.clone());
        cache.write_index(&idx).unwrap();
        let read = cache.read_index().unwrap();
        assert_eq!(read.get(&e.sha256), Some(&e));
    }

    #[test]
    fn put_rejects_corrupt_index_without_overwriting_it() {
        let (_tmp, cache) = fresh();
        std::fs::create_dir_all(&cache.root).unwrap();
        std::fs::write(cache.index_path(), "{not json").unwrap();

        let bytes = b"fresh archive bytes";
        let sha = sha256_hex(bytes);
        let err = cache
            .put(entry(&sha), bytes)
            .expect_err("corrupt index must fail closed");

        assert!(matches!(err, ZipCacheError::Index(_)));
        assert_eq!(
            std::fs::read_to_string(cache.index_path()).unwrap(),
            "{not json"
        );
        assert!(
            !cache.archive_path(&sha).exists(),
            "put must not leave an unindexed archive after index corruption"
        );
    }

    #[test]
    fn sha256_hex_is_lowercase_64_chars() {
        let h = sha256_hex(b"");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Spot-check against a well-known fixture: SHA-256 of "".
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
