//! Deterministic, bounded skill discovery and content-digest caching.

use super::{
    parse_skill_bytes, ResolvedSkill, SkillCapabilityPolicy, SkillProvenance, SkillRunAccess,
    SkillSource,
};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};

pub const SKILL_CATALOG_SCHEMA_VERSION: u16 = 2;
pub const MAX_SKILL_FILE_BYTES: u64 = 256 * 1024;
pub const MAX_SKILL_COUNT: usize = 128;
const MAX_SKILL_CATALOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 16;

#[derive(Debug, Clone)]
struct SkillRoot {
    path: PathBuf,
    source: SkillSource,
    policy: SkillCapabilityPolicy,
}

#[derive(Debug)]
struct Candidate {
    path: PathBuf,
    relative_path: PathBuf,
    bytes: Vec<u8>,
    digest: String,
}

#[derive(Clone)]
struct CacheEntry {
    key: String,
    skills: Vec<ResolvedSkill>,
}

static CATALOG_CACHE: LazyLock<Mutex<VecDeque<CacheEntry>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

pub fn load_global() -> Vec<ResolvedSkill> {
    let access = SkillRunAccess::global(dirs::home_dir().as_deref());
    load_from_roots(host_roots(&access), 0)
}

pub fn load_for_run(run: &crate::tools::ToolRunContext) -> Vec<ResolvedSkill> {
    let access = run.skill_access();
    let mut roots = host_roots(access);
    if let Some(policy) = access.project().current_policy(run.project_root()) {
        roots.extend(project_roots(
            run.project_root(),
            run.working_directory(),
            &policy,
        ));
        // Managed policy remains first; project roots must precede the user
        // layer so the documented source priority is preserved.
        roots.sort_by_key(|root| match root.source {
            SkillSource::Managed => 0_u8,
            SkillSource::Project => 1,
            SkillSource::User => 2,
        });
    } else if run.project_root().join(".openclaudia/skills").exists() {
        tracing::info!(
            target: "openclaudia::skills",
            event = "project_skills_inert",
            workspace = %run.project_root().display(),
            "Repository skills are present but no current host trust receipt authorizes them"
        );
    }
    load_from_roots(roots, run.generation().get())
}

fn host_roots(access: &SkillRunAccess) -> Vec<SkillRoot> {
    let mut roots = Vec::new();
    if let Some(path) = access.managed_root() {
        roots.push(SkillRoot {
            path: path.to_path_buf(),
            source: SkillSource::Managed,
            policy: SkillCapabilityPolicy::host_owned(),
        });
    }
    if let Some(path) = access.user_root() {
        roots.push(SkillRoot {
            path: path.to_path_buf(),
            source: SkillSource::User,
            policy: SkillCapabilityPolicy::host_owned(),
        });
    }
    roots
}

fn project_roots(
    project_root: &Path,
    working_directory: &Path,
    policy: &SkillCapabilityPolicy,
) -> Vec<SkillRoot> {
    if !working_directory.starts_with(project_root) {
        tracing::error!(
            target: "openclaudia::skills",
            project_root = %project_root.display(),
            working_directory = %working_directory.display(),
            "Refusing project skill discovery outside the run root"
        );
        return Vec::new();
    }
    let mut roots = Vec::new();
    for ancestor in working_directory.ancestors() {
        if !ancestor.starts_with(project_root) {
            break;
        }
        let path = ancestor.join(".openclaudia/skills");
        if let Some(path) = contained_project_skill_root(&path, project_root) {
            roots.push(SkillRoot {
                path,
                source: SkillSource::Project,
                policy: policy.clone(),
            });
        }
        if ancestor == project_root {
            break;
        }
    }
    roots
}

fn contained_project_skill_root(path: &Path, project_root: &Path) -> Option<PathBuf> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(
                target: "openclaudia::skills",
                skill_root = %path.display(),
                %error,
                "Repository skill root is unavailable"
            );
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        tracing::warn!(
            target: "openclaudia::skills",
            skill_root = %path.display(),
            "Repository skill root must be a real directory"
        );
        return None;
    }
    let canonical = match fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(error) => {
            tracing::warn!(
                target: "openclaudia::skills",
                skill_root = %path.display(),
                %error,
                "Repository skill root cannot be canonicalized"
            );
            return None;
        }
    };
    if !canonical.starts_with(project_root) {
        tracing::warn!(
            target: "openclaudia::skills",
            skill_root = %canonical.display(),
            workspace = %project_root.display(),
            "Repository skill root escapes the trusted workspace"
        );
        return None;
    }
    Some(canonical)
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded scan, digest, collision, and cache sequence is one ordering-sensitive transaction"
)]
fn load_from_roots(roots: Vec<SkillRoot>, workspace_generation: u64) -> Vec<ResolvedSkill> {
    let mut hasher = Sha256::new();
    hasher.update(SKILL_CATALOG_SCHEMA_VERSION.to_le_bytes());
    hasher.update(workspace_generation.to_le_bytes());
    let mut scanned = Vec::new();
    let mut aggregate_bytes = 0_u64;
    let mut candidate_count = 0_usize;

    for root in roots {
        hash_root_header(&mut hasher, &root);
        match scan_root(&root.path) {
            Ok(candidates) => {
                for candidate in &candidates {
                    hash_component(
                        &mut hasher,
                        candidate.relative_path.as_os_str().as_encoded_bytes(),
                    );
                    hash_component(&mut hasher, candidate.digest.as_bytes());
                    aggregate_bytes = aggregate_bytes
                        .saturating_add(u64::try_from(candidate.bytes.len()).unwrap_or(u64::MAX));
                    candidate_count = candidate_count.saturating_add(1);
                }
                scanned.push((root, candidates));
            }
            Err(error) => {
                hash_component(&mut hasher, b"unavailable");
                hash_component(&mut hasher, error.as_bytes());
                tracing::warn!(
                    target: "openclaudia::skills",
                    skill_root = %root.path.display(),
                    %error,
                    "Skill root is unavailable and contributes no skills"
                );
            }
        }
    }

    if candidate_count > MAX_SKILL_COUNT || aggregate_bytes > MAX_SKILL_CATALOG_BYTES {
        tracing::warn!(
            target: "openclaudia::skills",
            event = "skill_catalog_limit",
            candidate_count,
            aggregate_bytes,
            max_skill_count = MAX_SKILL_COUNT,
            max_catalog_bytes = MAX_SKILL_CATALOG_BYTES,
            "Skill catalog exceeds its deterministic ceiling and remains unavailable"
        );
        return Vec::new();
    }

    let key = digest_hasher(hasher);
    if let Some(skills) = cache_get(&key) {
        return skills;
    }

    let mut selected_names = BTreeSet::new();
    let mut skills = Vec::new();
    for (root, candidates) in scanned {
        let mut parsed = Vec::new();
        for candidate in candidates {
            match parse_skill_bytes(&candidate.path, &candidate.bytes) {
                Ok(definition) => parsed.push((definition, candidate)),
                Err(error) => tracing::warn!(
                    target: "openclaudia::skills",
                    skill_path = %candidate.path.display(),
                    %error,
                    "Invalid skill package is inert"
                ),
            }
        }
        parsed.sort_by(|left, right| {
            left.0
                .name
                .cmp(&right.0.name)
                .then_with(|| left.1.relative_path.cmp(&right.1.relative_path))
        });
        let mut counts = BTreeMap::<String, usize>::new();
        for (definition, _) in &parsed {
            *counts.entry(definition.name.clone()).or_default() += 1;
        }
        for (definition, candidate) in parsed {
            if counts.get(&definition.name).copied().unwrap_or(0) > 1 {
                tracing::warn!(
                    target: "openclaudia::skills",
                    event = "ambiguous_skill_collision",
                    skill = %definition.name,
                    skill_root = %root.path.display(),
                    "Same-layer duplicate skill name is rejected"
                );
                continue;
            }
            if !selected_names.insert(definition.name.clone()) {
                tracing::info!(
                    target: "openclaudia::skills",
                    event = "skill_shadowed",
                    skill = %definition.name,
                    source = ?root.source,
                    "A higher-priority skill deterministically shadows this package"
                );
                continue;
            }
            skills.push(ResolvedSkill::new(
                definition,
                SkillProvenance {
                    source: root.source,
                    root: root.path.clone(),
                    relative_path: candidate.relative_path,
                    content_digest: candidate.digest,
                    catalog_generation: key.clone(),
                    workspace_generation,
                },
                root.policy.clone(),
            ));
        }
    }
    skills.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.provenance().source.cmp(&right.provenance().source))
            .then_with(|| left.path.cmp(&right.path))
    });
    cache_insert(key, skills.clone());
    skills
}

fn scan_root(root: &Path) -> Result<Vec<Candidate>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize skill root: {error}"))?;
    let metadata = fs::metadata(&canonical_root)
        .map_err(|error| format!("cannot inspect skill root: {error}"))?;
    if !metadata.is_dir() {
        return Err("skill root is not a directory".to_string());
    }
    let entries = fs::read_dir(&canonical_root)
        .map_err(|error| format!("cannot enumerate skill root: {error}"))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot enumerate skill entry: {error}"))?;
        paths.push(entry.path());
        if paths.len() > MAX_SKILL_COUNT {
            return Err(format!(
                "skill root contains more than {MAX_SKILL_COUNT} entries"
            ));
        }
    }
    paths.sort();

    let mut candidates = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect skill entry '{}': {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            tracing::warn!(
                target: "openclaudia::skills",
                skill_path = %path.display(),
                "Symlinked skill entry is inert"
            );
            continue;
        }
        let candidate = if metadata.is_dir() {
            let file = path.join("SKILL.md");
            if !file.exists() {
                continue;
            }
            let file_metadata = fs::symlink_metadata(&file).map_err(|error| {
                format!(
                    "cannot inspect packaged skill '{}': {error}",
                    file.display()
                )
            })?;
            if file_metadata.file_type().is_symlink() || !file_metadata.is_file() {
                tracing::warn!(
                    target: "openclaudia::skills",
                    skill_path = %file.display(),
                    "Packaged skill definition must be a regular non-symlink file"
                );
                continue;
            }
            file
        } else if metadata.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("md")
        {
            path
        } else {
            continue;
        };
        candidates.push(read_candidate(&canonical_root, &candidate)?);
    }
    Ok(candidates)
}

fn read_candidate(root: &Path, path: &Path) -> Result<Candidate, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize skill '{}': {error}", path.display()))?;
    if !canonical.starts_with(root) {
        return Err(format!(
            "skill '{}' escapes its canonical root",
            path.display()
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(&canonical)
        .map_err(|error| format!("cannot open skill '{}': {error}", canonical.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect skill '{}': {error}", canonical.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_SKILL_FILE_BYTES {
        return Err(format!(
            "skill '{}' must be a regular file no larger than {MAX_SKILL_FILE_BYTES} bytes",
            canonical.display()
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_SKILL_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read skill '{}': {error}", canonical.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SKILL_FILE_BYTES {
        return Err(format!(
            "skill '{}' grew beyond {MAX_SKILL_FILE_BYTES} bytes while reading",
            canonical.display()
        ));
    }
    let relative_path = canonical
        .strip_prefix(root)
        .map_err(|_| "canonical skill path escaped its root".to_string())?
        .to_path_buf();
    Ok(Candidate {
        path: canonical,
        relative_path,
        digest: digest_bytes(&bytes),
        bytes,
    })
}

fn hash_root_header(hasher: &mut Sha256, root: &SkillRoot) {
    hasher.update([match root.source {
        SkillSource::Managed => 1,
        SkillSource::Project => 2,
        SkillSource::User => 3,
    }]);
    hash_component(hasher, root.path.as_os_str().as_encoded_bytes());
    let policy =
        serde_json::to_vec(&root.policy).expect("SkillCapabilityPolicy serialization cannot fail");
    hash_component(hasher, &policy);
}

fn hash_component(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes.len().to_le_bytes());
    hasher.update(bytes);
}

fn digest_hasher(hasher: Sha256) -> String {
    render_digest(&hasher.finalize())
}

fn digest_bytes(bytes: &[u8]) -> String {
    render_digest(&Sha256::digest(bytes))
}

fn render_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn cache_guard() -> MutexGuard<'static, VecDeque<CacheEntry>> {
    CATALOG_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn cache_get(key: &str) -> Option<Vec<ResolvedSkill>> {
    let mut cache = cache_guard();
    let position = cache.iter().position(|entry| entry.key == key)?;
    let entry = cache.remove(position)?;
    let skills = entry.skills.clone();
    cache.push_back(entry);
    drop(cache);
    Some(skills)
}

fn cache_insert(key: String, skills: Vec<ResolvedSkill>) {
    let mut cache = cache_guard();
    cache.retain(|entry| entry.key != key);
    cache.push_back(CacheEntry { key, skills });
    while cache.len() > MAX_CACHE_ENTRIES {
        cache.pop_front();
    }
    drop(cache);
}

pub fn invalidate() {
    cache_guard().clear();
}
