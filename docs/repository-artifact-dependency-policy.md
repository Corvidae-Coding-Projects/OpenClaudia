# Repository artifact and dependency policy

This policy is executable through `scripts/check_repository_hygiene.py`, the
root and fuzz `deny.toml` files, both Cargo lockfiles, and the CI workflow.
Prose does not override a failed check.

## Tracked artifacts

The source tree contains source, reviewed configuration, deterministic test
fixtures, and immutable redacted evidence. It must not track:

- Crosslink/Chainlink runtime databases, WAL/SHM files, active session markers,
  daemon identifiers, or equivalent mutable `.openclaudia` state;
- Cargo `target` trees or other compiler output;
- Python `__pycache__` directories or bytecode; or
- a raw copy, renamed archive, or encoded copy of the retired Chainlink store.

The canonical historical record is
`docs/historical-evidence/chainlink-history-v1.json`. Its retention manifest
binds the redacted export to the original Git commit, blob identities, raw byte
digests and sizes. The checker resolves those exact blobs from the recorded
commit, revalidates their sizes and hashes, regenerates the redacted export, and
requires a byte-for-byte match. Each removal receipt must identify a
single-parent commit whose parent contains the recorded blob and whose resulting
tree does not contain the path. The checker also rejects an exact, base64, or
hexadecimal copy of a raw historical artifact under any tracked name. CI
therefore checks out complete history, while the redacted JSON—not Git
history—is the supported review record. History availability outside that
verification environment is not guaranteed.

Production Crosslink operations never copy a retired `.chainlink/issues.db`
into a new live store. If that legacy path exists while `.crosslink/issues.db`
does not, mutation fails before creating `.crosslink/` and leaves the legacy
bytes untouched. This makes the ownership conflict visible instead of silently
creating split-brain mutable state.

To reproduce the export, extract `.chainlink/issues.db` and
`.chainlink/session.json` from commit
`d9858534b984bc163f84b58bac4c703bc4c3d00b` into a private temporary directory,
then run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/export_legacy_chainlink.py \
  --database <temporary-directory>/.chainlink/issues.db \
  --session <temporary-directory>/.chainlink/session.json \
  --output docs/historical-evidence/chainlink-history-v1.json \
  --source-commit d9858534b984bc163f84b58bac4c703bc4c3d00b \
  --database-blob 672465ee72150dd125963c130ffbd52c80ef9039 \
  --session-blob d1deb1f4393c2c8269df33812955e36889cc098c
```

The exporter opens SQLite read-only and immutable, accepts only the reviewed v7
schema, bounds files/rows/text/output, checks integrity and relationships,
orders every row, and applies a versioned credential/identity/host-path
redaction policy. The tracked retention decision deliberately creates no second
raw archive: the immutable redacted export is canonical, while existing Git
objects are used only to reproduce it. Never attach the raw inputs to an issue,
build artifact, or release.

## Dependency and build policy

- Rust 1.98 is the single owned development, build, lint, and CI toolchain.
  `Cargo.toml`, `rust-toolchain.toml`, and every workflow job must agree on that
  version; the repository checker rejects floating or mismatched toolchains.
- `Cargo.lock` and `fuzz/Cargo.lock` are committed. CI uses `--locked`; a lock
  change is an intentional reviewed artifact generation.
- The default profile excludes browser process integration. `--features
  browser` preserves browser/search support for operators who install a
  compatible browser. Runtime executable download is disabled.
- Advisory, unmaintained, license, registry/Git source, wildcard, and duplicate
  checks are defined by `deny.toml` and `fuzz/deny.toml`. Advisories and unknown
  sources fail. Every accepted license is explicit. Both independent lock
  graphs deny duplicate versions, with exact-version exceptions only for their
  currently unavoidable transitive generations. The repository checker keeps
  their common policy equal and rejects broad or tree-wide exceptions; a new
  duplicate therefore fails until its exact generation is reviewed.
- `auto_generate_cdp 0.4.6` is an all-feature-only build dependency of the
  preserved browser adapter. Cargo identifies its `LICENSE.txt` as
  GPL-3.0-or-later; `deny.toml` binds that classification to the exact crate,
  version, `LICENSE.txt` path, and license-file hash, then permits it only for
  that crate. This is a reviewed build-input classification, not a general GPL
  allow rule or legal conclusion. Headless Chrome's offline protocol bundle
  prevents build-time protocol retrieval.
- Syntax highlighting uses an explicit maintained tree-sitter language set.
  Unknown fence tags retain flat-color rendering.

Run policy gates with:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_repository_hygiene.py --repo-root .
cargo metadata --locked --format-version 1 --no-deps
cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 --no-deps
cargo deny --locked check advisories licenses sources bans
cargo deny --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check advisories licenses sources bans
```

## Bounded cache cleanup

Cargo caches are disposable and should be cleaned regularly when disk pressure
or an evidence boundary warrants it. First confirm no Cargo, rustc, Clippy, or
rustdoc process is active. Then use manifest-scoped cleanup:

```bash
cargo clean
cargo clean --manifest-path fuzz/Cargo.toml
```

Run the same command inside a linked worktree only when that worktree owns a
separate target directory. Record target sizes before cleanup when build-space
evidence is required. Never replace these commands with recursive deletion over
the repository, home directory, workspace root, unresolved variables, or
globs. Cleanup happens after required build/test evidence is captured, never
concurrently with a build.
