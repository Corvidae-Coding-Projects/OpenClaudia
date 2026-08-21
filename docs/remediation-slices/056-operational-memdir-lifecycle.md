# S-056: Complete the memdir lifecycle

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-094
Workstreams: W5
Depends on: [S-054](./054-memory-authority-and-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Turn the tested memdir loader into an operational, bounded, reviewable memory source.

This slice deliberately selects W5's safe-manual-import branch. It does not
recreate the abandoned background note/extraction/dream-agent design. A retained
`MEMORY.md` is a strict source manifest for cited codebase technical lessons,
not a Markdown note, transcript store, user profile, or prompt fragment.

## Implementation boundary

- Define discovery scope, file identity/version, ignore/link rules, size/count budgets, incremental refresh, deletion, conflicts, citations, and user controls.
- Integrate memdir through canonical retrieval and context provenance rather than startup prompt concatenation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Source contract

The only candidates are `<workspace>/MEMORY.md` and
`<workspace>/.openclaudia/MEMORY.md`. Zero candidates is a typed missing state;
two candidates is a conflict. There is no current-directory search, parent walk,
ambient `HOME` fallback, or first-file precedence. Repository source bytes and
cited artifacts are opened below the immutable run capability without following
links, must be regular single-link files, are read twice through the same
descriptor, and must retain the same identity, size, timestamps, and bytes.

The compatibility filename contains exact JSON shaped as follows (digest values
must be real lowercase SHA-256 values for the cited bytes):

```json
{
  "schema_version": 1,
  "source_id": "openclaudia-repo",
  "generation": 1,
  "lessons": [
    {
      "lesson_id": "descriptor-safe-sqlite",
      "lesson": {
        "title": "Use descriptor-safe SQLite publication",
        "kind": "compatibility",
        "observation": "The store must reject path replacement races.",
        "guidance": "Pin the workspace artifact and publish causal records in one transaction.",
        "applicability": {
          "paths": ["src/memory.rs"],
          "symbols": ["MemoryDb::open_for_workspace"]
        },
        "citations": [
          {
            "kind": "source_file",
            "locator": "src/memory.rs",
            "source_version": "workspace-file:sha256:<64 lowercase hexadecimal digits>",
            "digest": "sha256:<64 lowercase hexadecimal digits>",
            "line_start": 386,
            "line_end": 428
          }
        ],
        "confidence": "verified_by_test",
        "sensitivity": "internal",
        "retention": { "policy": "indefinite" }
      }
    }
  ]
}
```

Unknown fields, prose, invalid UTF-8, noncanonical or unsorted IDs, generation
zero, invalid lesson schemas, and citations without exact byte/version matches
fail closed. Imported citations may name only ordinary workspace source, test,
configuration, or documentation files. They cannot cite the manifest itself,
`.openclaudia` control state, network/tool/command/commit/issue claims, absolute
paths, traversal, links, binary files, or unreadable artifacts.

Hard admission budgets are 512 KiB for the manifest, 256 active lessons, 512
citations, 64 distinct cited files, 4 MiB per cited file, and 32 MiB aggregate
citation bytes. The causal source ledger retains at most 512 active plus retired
lesson identities. Inputs are rejected rather than truncated; therefore no
unmarked prefix can masquerade as the complete source.

## Operational lifecycle

- `memory_source_status` verifies discovery, citations, stored source
  provenance, immutable projection equality, active lesson heads, and retired
  tombstone heads. It returns typed unconfigured/current/missing/rename/restore/
  stale/collision/identity/conflict relations without returning source prose.
- `memory_source_refresh` is an effect-classified canonical tool. Initial import
  omits `expected_source_digest`; any mutation of an existing source uses the
  current digest as a compare-and-swap token. An exact replay is read-only and
  idempotent, including a concurrent identical replay carrying the predecessor
  token.
- Lesson and source-state revisions publish inside one SQLite `BEGIN IMMEDIATE`
  transaction. Stable `source_id`/`lesson_id` pairs derive stable logical IDs.
  Changed lessons are causal corrections, removals are immutable tombstones,
  reappearance from a newer generation restores the same identity, and a path
  rename preserves lesson revisions. The same transaction projects the
  repository-wide active technical-lesson count before mutation, so a refresh
  cannot bypass the 4,096-lesson store ceiling or partially publish at capacity.
- Removing entries or the entire source first returns `prune_required` and the
  exact affected IDs. Deletion occurs only with `prune_missing: true`. Retired
  heads remain in the bounded source state so corruption is visible and later
  restoration cannot adopt an unrelated lineage.
- Imported lessons remain private `candidate` evidence with exact source,
  workspace, actor, store, generation, sensitivity, confidence, retention, and
  citations. Existing `memory_search`, `memory_list`, `memory_update`, and
  `memory_delete` provide explicit retrieval, inspection, correction, expiry
  metadata, and deletion. No file content is promoted to instruction authority.
- The tools use the shared registry/executor in chat, print, and TUI paths; ACP
  routes both through its blocking local-tool boundary. General workers receive
  status/refresh only when the host memory service is present. Explore, plan,
  guide, and coordinator roles receive status only; plan mode refuses refresh.

The source is manually authored and refresh is explicit. Automatic causal
learning remains S-055; evaluated retrieval remains S-105; authenticated team
authority and replication remain S-103/S-104. This keeps those intended
features live without pretending this repository file grants their authority.

## Acceptance

- Create/change/delete/rename, oversized, symlink, corrupt, stale, and concurrent refresh scenarios have typed outcomes.
- Representative retrieval demonstrates cited task value and no automatic instruction authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Verification record

All commands used the pinned Rust/Cargo 1.98.0 toolchain and locked dependency
graph; Rust compilation used four jobs and tests used one test thread.

- `cargo fmt --all -- --check` and `git diff --check`: passed.
- Focused real-executor lifecycle: 12/12, including two independent database
  handles and a late member-identity collision that proves transaction rollback.
- Legacy memdir/elicitation negatives: 17/17; canonical technical memory:
  18/18; registry/effect/resource invariants: 19/19; base/subagent definitions:
  16/16; plan-mode boundary: 15/15; integration catalog: 5/5; ACP routing and
  subagent role/service gating: 1/1 each; interoperable SHA-256 vector: 1/1;
  global active-lesson capacity projection boundary: 1/1.
- Locked all-feature/all-target native check: passed without warnings.
- Strict locked all-feature/all-target Clippy with `-D warnings`: passed.
- Full locked all-feature/all-target `--no-fail-fast` suite: passed. The
  catalog contains 7,786 tests; 7,781 ran successfully, five remain explicitly
  ignored, and no target failed.
- Windows GNU locked all-feature/all-target check: passed. It emitted only the
  tracked target-conditional unused/dead-code warnings; runtime source/citation
  reads remain fail-closed until S-036 supplies the Windows descriptor backend.

Skeptical review corrected four slice defects before this record was frozen:
the 512-identity ledger initially had an undersized serialized-state ceiling,
the tests lacked a late-failure rollback proof, and the added ACP assertions
made one test exceed the repository function-size limit. A final capacity audit
then found that the source transaction relied only on the database trigger for
the global active-lesson ceiling instead of projecting it as a typed preflight.
The fixes enlarged the still-bounded ledger envelope, added the adversarial
collision case, split the ACP assertion at its logical boundary without lint
suppression, and added an in-transaction replacement-aware capacity check plus
boundary and consistency tests.

The final ordered source/test/document artifact manifest has SHA-256
`c01ec8a7cf4afd6418f284ed95a4055d8741b0f90249d97d17ecb49ba32256b0`:

- `README.md`: `bc2df88c110ef2a374620ede7c695fbe8cc62145069644d8b658eba90db10f21`
- `docs/remediation-slices/054-memory-authority-and-schema.md`: `c323fcc128d2ed62d8bfa3d3428ddc0d1f8d339d393ca835f3c9ede430f187ca`
- `docs/remediation-slices/106-host-reviewed-memory-export.md`: `58650fe375f6eeef8b22a9237c6c6f0fae3d08d04de1dd80b95fbade825c9dd8`
- `docs/remediation-slices/README.md`: `49064b83115ce10b7aeafa79cf33b1a1f5127dce25c1adc895a9551957e6e19e`
- `src/acp.rs`: `15680e715c15a48f139a6e756e4bbf3bb89cdcac3041f71026cf727c2a35f46f`
- `src/memdir/entrypoint.rs`: `84fa4da21802643208a55277fd40b8a567c2c62362d1a75c204a62e116beb024`
- `src/memdir/mod.rs`: `c52c74d43cc4cdf1e8307d0a79241e2e56f72147edde7be0871125ac6b1a5f19`
- `src/memory.rs`: `fb91dbe9654019eb5464383dbc4e544bd873a110a14438863c510996bec9d382`
- `src/memory/lesson.rs`: `5125ba4a33cb895f8a7191a604b48dcd88dd141318ced5d5b762a36093a147fb`
- `src/memory/record.rs`: `4c9a12d0e0e09ca1d20bda85da49a4cc9c86f0e6153e302a61c8c8ebe14e5065`
- `src/memory/source.rs`: `32299839c9f25748fdc90885ba202e1519b7624cab2678ea6d236320e319a945`
- `src/session/state.rs`: `557005c48553d76ab5bd606bb5f26068058e0cc8dd474b67ee103a39a16de536`
- `src/subagent.rs`: `0d40d5014b4a56b3a84824c3f206dbf9c9fb373631624d992e902bf5b55b6018`
- `src/tools/file/mod.rs`: `86d9654c1f083a7e27d9bfcd4aeb6831bb75df9adb2c266bfdbf9edbeede569e`
- `src/tools/file/secure_fs.rs`: `323845f2dcb687f251ca95373a4fdaadefca26567a6b7505b29d8f359d35444d`
- `src/tools/memory.rs`: `938ea7c9793103a331fdb18785ec98d557fde74a7da1c7299c23a586ff485e4d`
- `src/tools/mod.rs`: `0a3d1784677d7ad5f41eccd874a2bb157f54ad19309f218c815d722f3654883e`
- `src/tools/registry.rs`: `fa6d404af50048d063e8b89d08fcc573ba681e769854472392af8e3a7cc377ef`
- `tests/get_all_tool_definitions_subagents_e2e.rs`: `4df04f453413d745ad9e6194eb9345acd3855c5cfaabedd997a22537ca84081b`
- `tests/integration_tests.rs`: `e14eb1fa8aa597fef821cf98af9d5f222914ec90aadbb61b04959dfc31d5eace`
- `tests/memdir_elicitation_e2e.rs`: `ce53884ff3c6e98fa175d5461ce0d795a8f6c4dba9d728ffe2f3ba8feeb42a98`
- `tests/registry_global_invariants_e2e.rs`: `92f3f72103b4207f46a5f0c4208b59c0ac1bf21f842c89ebe0d1ff1c0ee93b84`
- `tests/subagent_plan_mode_e2e.rs`: `d6de8548e47fc05daede7f560ac5ca94070e287debb7032bd961fec0937db8e9`
- `tests/technical_memory_source_e2e.rs`: `3b44b7c244178955b1fa3c60fe51740841632a29f8dbcc405432b68b67c4718a`

The slice document is commit-tracked; its stable digest is recorded in the
Crosslink result receipt to avoid self-reference. The newly separated S-106/
#1078 owns host-authorized review and complete portable export rather than
pretending the model-facing bounded list is either authority or export.

Canonical alternate-model VDD remains pending S-088 and prevents this slice
from being marked `Verified`; it does not make the implemented deterministic
gates disappear.
