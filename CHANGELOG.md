# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
for released, user-visible changes.

The previous file was an unreleased dump of issue titles, duplicate entries,
audit findings, and “fixed” assurances. It was not reliable release history and
has been replaced. Git history and the exported historical issue ledger retain
the original record.

## [Unreleased]

### Removed

- Remove the legacy filesystem rule injector from every Rust frontend,
  project initialization, doctor/tips, repository hook activation, generated
  configuration, assets, and dedicated tests. Repository rule files no longer
  enter model context or tool authority.
- Remove automatic project authority from `.openclaudia/output-style.md`;
  output preferences are now user-owned at
  `~/.openclaudia/output-style.md`.

### Changed

- Enforce deny-first permission precedence and replace broad ambient approvals
  with exact, expiring, generation-bound execution receipts (#1007).
- Validate one-use permits atomically with generation and exact-denial refresh
  across live managers (#1016).
- Enforce persisted receipt use/time bounds and fail closed at capability
  generation exhaustion (#1015).
- Align web-search integration expectations with mandatory effect
  classification and downstream argument validation (#1013).
- Terminate ACP sandbox process groups reliably during cancellation, including
  daemonized descendants (#1012).
- Keep the all-feature Windows library build free of unreachable and dead-code
  warnings (#1011).
- Record enterprise tool caps only after authorization and reserve concurrent
  capped calls atomically (#1010).
- Use platform-aware atomic receipt replacement and apply parent-directory
  durability where the host supports it (#1009).

- Relocate neutral file-extension recognition to `src/file_types.rs` for
  auto-learning filters and lifecycle-hook metadata without instruction
  loading behavior.

### Documentation

- Complete a file-by-file audit of all tracked source, tests, fuzz targets,
  scripts, configuration, prompts, documents, and runtime artifacts.
- Add a production remediation design that preserves intended capabilities and
  removes only the deprecated rule injector and unsafe/duplicate mechanisms
  after migration.
- Remove superseded rule, parity, partial-audit, and false-completion Markdown
  snapshots after reading and reconciling every file.
- Replace active product documents with audit-honest status and limitations.
- Record the current default web-search implementation as browser-backed free
  search without implying that its egress/cancellation boundary is complete.

### Cleanup

- Run Cargo cleanup for the root and fuzz workspaces, removing approximately
  82 GiB and 1.3 GiB of build artifacts respectively.

The audit and cleanup entry above remains the record of its documentation-only
pass. Subsequent runtime changes must link to executable acceptance evidence;
issue closure or a passing substring test is insufficient.
