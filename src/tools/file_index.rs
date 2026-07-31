//! File index with fuzzy search for fast file lookup in large codebases.
//!
//! Uses a scoring algorithm inspired by fzf-v2/nucleo with:
//! - Boundary bonuses (start of path segment)
//! - `CamelCase` bonuses
//! - Consecutive match bonuses
//! - Gap penalties
//! - First-char bonus

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// Maximum directory depth visited by [`FileIndex::walk_dir`] (crosslink #920).
///
/// Previously the walker recursed; a symlink loop (`/a/b -> /a`) or a
/// monorepo with >1 000 nested dirs would exhaust the default 8 MiB
/// stack. The walker is now iterative, with each queue entry tagged by
/// its tree depth, and we refuse to descend past this cap. 64 is well
/// past any realistic source tree and still leaves headroom on a tiny
/// stack.
const MAX_WALK_DEPTH: usize = 64;

const SCORE_MATCH: i32 = 16;
const BONUS_BOUNDARY: i32 = 8;
const BONUS_CAMEL: i32 = 6;
const BONUS_CONSECUTIVE: i32 = 4;
const BONUS_FIRST_CHAR: i32 = 8;
const PENALTY_GAP_START: i32 = 3;
const PENALTY_GAP_EXTENSION: i32 = 1;

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub path: String,
    pub score: i32,
}

/// One indexed path paired with its precomputed lowercase form.
///
/// crosslink #975: `FileIndex` used to store `paths: Vec<String>` and
/// `lower_paths: Vec<String>` as parallel arrays whose index alignment was
/// enforced only by the convention that `walk_dir` pushed both. A future
/// `remove` method (or any partial update) could trivially break the
/// invariant and produce silently mismatched search scores. The struct
/// pairs the two strings into a single record so the type system enforces
/// "one push per file" and the search iterator no longer zips two slices.
#[derive(Debug, Clone)]
struct IndexedPath {
    display: String,
    lower: String,
}

/// In-memory file index for fuzzy searching.
#[derive(Default)]
pub struct FileIndex {
    paths: Vec<IndexedPath>,
}

impl FileIndex {
    #[must_use]
    pub const fn new() -> Self {
        Self { paths: Vec::new() }
    }

    /// Build index by walking the directory tree, respecting .gitignore.
    #[must_use]
    pub fn build(root: &Path) -> Self {
        let mut index = Self::new();
        // Walk directory, skip hidden dirs, .git, node_modules, target, etc.
        index.walk_dir(root, root);
        index
    }

    /// Walk the tree rooted at `dir`, indexing every file relative to `root`.
    ///
    /// crosslink #920: the walker used to recurse via `walk_dir(root, &path)`,
    /// which stack-overflows on a symlink cycle (`/a/b -> /a`) and risks
    /// blowing the default 8 MiB stack on a legitimately deep monorepo.
    /// The new implementation is iterative:
    ///
    /// 1. A `VecDeque` of `(path, depth)` work items replaces the call stack.
    /// 2. A `HashSet` of canonical paths breaks symlink cycles by skipping
    ///    any directory whose realpath has already been visited.
    /// 3. A hard `MAX_WALK_DEPTH` cap (64) refuses to descend past a
    ///    pathological depth even if cycle detection fails to fire (e.g.
    ///    canonicalize is unavailable on a platform / errors out).
    fn walk_dir(&mut self, root: &Path, dir: &Path) {
        let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
        let mut visited: HashSet<PathBuf> = HashSet::new();

        // Seed with the starting directory. Canonicalize so the visited
        // set keys match what we later record for sub-directories.
        let seed = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        visited.insert(seed);
        queue.push_back((dir.to_path_buf(), 0));

        while let Some((current, depth)) = queue.pop_front() {
            // crosslink #920: hard depth cap. We *stop descending* here,
            // but a deep tree is a soft failure: the existing files at
            // shallower depths remain indexed, which is what the caller
            // expects (best-effort index, not transactional).
            if depth >= MAX_WALK_DEPTH {
                continue;
            }

            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                // Skip hidden, build artifacts, dependency dirs
                if name.starts_with('.')
                    || name == "node_modules"
                    || name == "target"
                    || name == "__pycache__"
                    || name == "dist"
                    || name == "build"
                {
                    continue;
                }

                if path.is_dir() {
                    // crosslink #920: cycle detection. canonicalize resolves
                    // symlinks so `/a/b -> /a` collapses to the same key as
                    // `/a` itself. If canonicalize fails (broken symlink,
                    // permission error) we fall back to the literal path —
                    // the depth cap still ensures termination.
                    let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                    if !visited.insert(canonical) {
                        continue;
                    }
                    queue.push_back((path, depth + 1));
                } else if let Ok(rel) = path.strip_prefix(root) {
                    let rel_str = rel.to_string_lossy().to_string();
                    self.paths.push(IndexedPath {
                        lower: rel_str.to_lowercase(),
                        display: rel_str,
                    });
                }
            }
        }
    }

    /// Search for files matching the query, returning top N results sorted by score.
    #[must_use]
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchResult> {
        if query.is_empty() {
            return Vec::new();
        }
        let query_lower = query.to_lowercase();
        let query_chars: Vec<char> = query_lower.chars().collect();

        let mut results: Vec<SearchResult> = self
            .paths
            .iter()
            .filter_map(|p| {
                let score = Self::score_match(&query_chars, &p.lower, &p.display);
                if score > 0 {
                    Some(SearchResult {
                        path: p.display.clone(),
                        score,
                    })
                } else {
                    None
                }
            })
            .collect();

        results.sort_by_key(|r| std::cmp::Reverse(r.score));
        results.truncate(limit);
        results
    }

    fn score_match(query: &[char], lower_path: &str, original_path: &str) -> i32 {
        let path_chars: Vec<char> = lower_path.chars().collect();
        let orig_chars: Vec<char> = original_path.chars().collect();

        if query.len() > path_chars.len() {
            return 0;
        }

        // Check if all query chars exist in path (in order)
        let mut qi = 0;
        for &pc in &path_chars {
            if qi < query.len() && query[qi] == pc {
                qi += 1;
            }
        }
        if qi < query.len() {
            return 0; // Not all chars matched
        }

        // Score the match
        let mut score: i32 = 0;
        qi = 0;
        let mut last_match_idx: Option<usize> = None;
        let mut consecutive = 0;

        for (pi, &pc) in path_chars.iter().enumerate() {
            if qi < query.len() && query[qi] == pc {
                score += SCORE_MATCH;

                // First char bonus
                if qi == 0 {
                    score += BONUS_FIRST_CHAR;
                }

                // Boundary bonus (after /, \, ., -, _)
                if pi > 0 {
                    let prev = path_chars[pi - 1];
                    if prev == '/' || prev == '\\' || prev == '.' || prev == '-' || prev == '_' {
                        score += BONUS_BOUNDARY;
                    }
                    // CamelCase bonus. `pi > 0` guards `pi - 1` from underflow.
                    if orig_chars[pi].is_uppercase()
                        && orig_chars.get(pi - 1).is_some_and(|c| c.is_lowercase())
                    {
                        score += BONUS_CAMEL;
                    }
                } else {
                    score += BONUS_BOUNDARY; // Start of string
                }

                // Consecutive bonus
                if let Some(last) = last_match_idx {
                    if pi == last + 1 {
                        consecutive += 1;
                        score += BONUS_CONSECUTIVE * consecutive;
                    } else {
                        // Gap penalty. `pi > last` because last_match_idx is set
                        // strictly before incrementing; the subtraction is safe.
                        let gap_usize = pi.saturating_sub(last).saturating_sub(1);
                        let gap = i32::try_from(gap_usize).unwrap_or(i32::MAX);
                        score -= PENALTY_GAP_START + PENALTY_GAP_EXTENSION * (gap - 1).max(0);
                        consecutive = 0;
                    }
                }

                last_match_idx = Some(pi);
                qi += 1;
            }
        }

        // Prefer shorter paths (less noise). Paths are bounded by OS PATH_MAX
        // so the conversion saturates at i32::MAX rather than truncating.
        let path_len_penalty = i32::try_from(path_chars.len()).unwrap_or(i32::MAX) / 10;
        score -= path_len_penalty;

        // Penalize test files slightly
        if lower_path.contains("test") || lower_path.contains("spec") {
            score -= 2;
        }

        score
    }

    /// Get total file count
    #[must_use]
    pub const fn len(&self) -> usize {
        self.paths.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// crosslink #975: helper that builds a `FileIndex` from display paths,
    /// computing the matching lowercase form so tests cannot accidentally
    /// drift the two halves of what used to be parallel `Vec`s.
    fn index_from_paths(paths: &[&str]) -> FileIndex {
        FileIndex {
            paths: paths
                .iter()
                .map(|p| IndexedPath {
                    display: (*p).to_string(),
                    lower: p.to_lowercase(),
                })
                .collect(),
        }
    }

    #[test]
    fn test_score_basic_match() {
        let index = index_from_paths(&["src/main.rs"]);
        let results = index.search("main", 10);
        assert_eq!(results.len(), 1);
        assert!(results[0].score > 0);
    }

    #[test]
    fn test_score_boundary_bonus() {
        let index = index_from_paths(&["src/main.rs", "src/domain/maintain.rs"]);
        let results = index.search("main", 10);
        // "main.rs" should score higher (boundary match after /)
        assert_eq!(results[0].path, "src/main.rs");
    }

    #[test]
    fn test_no_match() {
        let index = index_from_paths(&["src/main.rs"]);
        let results = index.search("xyz", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_empty_query() {
        let index = index_from_paths(&["src/main.rs"]);
        assert!(index.search("", 10).is_empty());
    }

    #[test]
    fn test_case_insensitive() {
        let index = index_from_paths(&["src/MyComponent.tsx"]);
        let results = index.search("mycomp", 10);
        assert_eq!(results.len(), 1);
    }

    // ── crosslink #920: iterative walker, depth cap, cycle detection ────────

    /// #920 — A normal directory tree is indexed end-to-end. Sanity check
    /// that converting the walker to iterative did not regress the basic
    /// "files in subdirectories show up in the index" behavior.
    #[test]
    fn fix920_iterative_walker_indexes_nested_files() {
        use std::fs;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::write(root.join("top.rs"), b"").unwrap();
        fs::write(root.join("a/inner.rs"), b"").unwrap();
        fs::write(root.join("a/b/deep.rs"), b"").unwrap();
        fs::write(root.join("a/b/c/deepest.rs"), b"").unwrap();

        let index = FileIndex::build(root);
        assert!(index.len() >= 4, "expected >=4 files, got {}", index.len());

        // Confirm the deepest file is present.
        let results = index.search("deepest", 10);
        assert!(!results.is_empty(), "deepest.rs must be indexed");
    }

    /// #920 — A symlink cycle (`loop/back -> loop`) terminates instead of
    /// stack-overflowing or running until the depth cap. The walker's
    /// `visited` set catches the cycle on the second descent.
    #[cfg(unix)]
    #[test]
    fn fix920_symlink_cycle_terminates() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let loop_dir = root.join("loop");
        fs::create_dir_all(&loop_dir).unwrap();
        fs::write(loop_dir.join("real.rs"), b"").unwrap();

        // Create `loop/back` -> `loop` (a self-cycle).
        let back = loop_dir.join("back");
        symlink(&loop_dir, &back).unwrap();

        // If cycle detection is broken, this either stack-overflows or
        // (with the depth cap) indexes `real.rs` 64 times.
        let index = FileIndex::build(root);
        let results = index.search("real", 100);

        // The file should appear at most a small, bounded number of times.
        // (We allow >1 because the symlink target *is* canonically distinct
        // from the literal traversal path in some edge cases; what matters
        // is that the walk terminates and the result count is bounded.)
        assert!(
            results.len() <= 4,
            "#920: cycle should produce a bounded result count, got {}",
            results.len(),
        );
        assert!(
            results.iter().any(|r| r.path.contains("real.rs")),
            "#920: cycle must not prevent indexing the legitimate file"
        );
    }

    /// #920 — A pathologically deep tree (>`MAX_WALK_DEPTH`) does not panic /
    /// overflow — it simply stops descending past the cap. Files above the
    /// cap remain indexed.
    #[test]
    fn fix920_depth_cap_prevents_unbounded_descent() {
        use std::fs;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Build a chain root/d/d/d/.../d (well past MAX_WALK_DEPTH).
        let mut p = root.to_path_buf();
        for _ in 0..(MAX_WALK_DEPTH + 16) {
            p = p.join("d");
        }
        // Some filesystems cap PATH_MAX before we hit the iteration limit;
        // tolerate that and just exercise as much depth as we can create.
        let _ = fs::create_dir_all(&p);
        let _ = fs::write(p.join("leaf.rs"), b"");
        // Always-indexable shallow file.
        fs::write(root.join("shallow.rs"), b"").unwrap();

        // The crucial guarantee is that this returns without overflowing
        // the stack. The shallow file must always appear.
        let index = FileIndex::build(root);
        let results = index.search("shallow", 10);
        assert!(!results.is_empty(), "shallow.rs must always be indexed");
    }
}
