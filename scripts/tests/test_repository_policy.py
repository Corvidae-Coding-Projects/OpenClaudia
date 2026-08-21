"""Adversarial tests for the S-002 repository and retention policy."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from check_repository_hygiene import (  # noqa: E402
    EXPORT_PATH,
    REQUIRED_IGNORE_LINES,
    RETENTION_PATH,
    WORKFLOW_PATH,
    PolicyError,
    check_repository,
    forbidden_tracked_reason,
)
from export_legacy_chainlink import (  # noqa: E402
    ExportError,
    build_export,
    encode_export,
    sensitive_matches,
)

COMMIT = "1" * 40
DATABASE_BLOB = "2" * 40
SESSION_BLOB = "3" * 40
BYTECODE_BLOB = "4" * 40


def create_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA user_version = 7;
        CREATE TABLE issues (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL,
            priority TEXT NOT NULL,
            parent_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT
        );
        CREATE TABLE labels (issue_id INTEGER NOT NULL, label TEXT NOT NULL);
        CREATE TABLE dependencies (blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL);
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            issue_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE time_entries (
            id INTEGER PRIMARY KEY,
            issue_id INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            duration_seconds INTEGER
        );
        CREATE TABLE relations (
            issue_id_1 INTEGER NOT NULL,
            issue_id_2 INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE milestones (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            closed_at TEXT
        );
        CREATE TABLE milestone_issues (milestone_id INTEGER NOT NULL, issue_id INTEGER NOT NULL);
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            active_issue_id INTEGER,
            handoff_notes TEXT
        );
        INSERT INTO issues VALUES (
            1,
            'Contact maintainer@example.test',
            'api_key=sk-ant-aaaaaaaaaaaa at /home/alice/OpenClaudia',
            'closed',
            'high',
            NULL,
            '2026-01-01T00:00:00Z',
            '2026-01-01T00:01:00Z',
            '2026-01-01T00:01:00Z'
        );
        INSERT INTO labels VALUES (1, 'security');
        INSERT INTO comments VALUES (
            1,
            1,
            'Authorization: Bearer abcdefghijklmnop',
            '2026-01-01T00:00:30Z'
        );
        INSERT INTO sessions VALUES (
            7,
            '2026-01-01T00:00:00Z',
            NULL,
            1,
            'owner=maintainer@example.test'
        );
        """
    )
    connection.commit()
    connection.close()


def create_session(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "active_issue_id": 1,
                "session_id": 7,
                "started_at": "2026-01-01T00:00:00Z",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def make_export(root: Path) -> tuple[dict[str, object], bytes]:
    database = root / "history.db"
    session = root / "session.json"
    create_database(database)
    create_session(session)
    exported = build_export(
        database,
        session,
        source_commit=COMMIT,
        database_blob=DATABASE_BLOB,
        session_blob=SESSION_BLOB,
    )
    return exported, encode_export(exported)


def write_retention(
    root: Path,
    exported: dict[str, object],
    export_raw: bytes,
    *,
    source_commit: str = COMMIT,
    bytecode_blob: str = BYTECODE_BLOB,
    bytecode_sha256: str = "5" * 64,
    bytecode_size: int = 100,
    removed_by_commit: str = COMMIT,
) -> None:
    source = exported["source"]
    assert isinstance(source, dict)
    database = source["database"]
    session = source["session_marker"]
    assert isinstance(database, dict)
    assert isinstance(session, dict)
    summary = exported["summary"]
    assert isinstance(summary, dict)
    record = {
        "schema": "openclaudia.historical-retention",
        "version": 1,
        "decision": "redacted_export_only",
        "raw_artifacts_reintroduced": False,
        "source": {
            "repository_commit": source_commit,
            "artifacts": {
                ".chainlink/issues.db": {
                    "git_blob": database["git_blob"],
                    "sha256": database["sha256"],
                    "size_bytes": database["size_bytes"],
                    "disposition": "removed_from_current_tree",
                    "removed_by_commit": removed_by_commit,
                },
                ".chainlink/session.json": {
                    "git_blob": session["git_blob"],
                    "sha256": session["sha256"],
                    "size_bytes": session["size_bytes"],
                    "disposition": "removed_from_current_tree",
                    "removed_by_commit": removed_by_commit,
                },
                ".claude/hooks/__pycache__/crosslink_config.cpython-313.pyc": {
                    "git_blob": bytecode_blob,
                    "sha256": bytecode_sha256,
                    "size_bytes": bytecode_size,
                    "disposition": "removed_from_current_tree",
                    "removed_by_commit": removed_by_commit,
                },
            },
        },
        "export": {
            "path": EXPORT_PATH.as_posix(),
            "schema": exported["schema"],
            "version": exported["version"],
            "sha256": hashlib.sha256(export_raw).hexdigest(),
            "size_bytes": len(export_raw),
            "table_rows": summary["table_rows"],
        },
        "verification": {
            "checker": "scripts/check_repository_hygiene.py",
            "exporter": "scripts/export_legacy_chainlink.py",
        },
        "policy": {
            "history_availability_not_guaranteed": True,
            "purpose": "Keep a redacted canonical review record without restoring runtime state.",
            "raw_archive_created": False,
            "raw_history_is_not_the_canonical_record": True,
            "redaction_policy_version": 1,
        },
    }
    retention_path = root / RETENTION_PATH
    retention_path.parent.mkdir(parents=True, exist_ok=True)
    retention_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    ).stdout


def create_policy_repository(root: Path) -> tuple[dict[str, object], bytes]:
    run_git(root, "init", "--quiet")
    run_git(root, "config", "user.email", "policy-fixture@example.test")
    run_git(root, "config", "user.name", "Policy Fixture")

    database_path = root / ".chainlink/issues.db"
    session_path = root / ".chainlink/session.json"
    bytecode_path = root / ".claude/hooks/__pycache__/crosslink_config.cpython-313.pyc"
    database_path.parent.mkdir(parents=True, exist_ok=True)
    bytecode_path.parent.mkdir(parents=True, exist_ok=True)
    create_database(database_path)
    create_session(session_path)
    bytecode_raw = b"fixture-cpython-bytecode\0with-an-absolute-build-path"
    bytecode_path.write_bytes(bytecode_raw)
    run_git(root, "add", ".chainlink", ".claude")
    run_git(root, "commit", "--quiet", "-m", "historical fixture")
    source_commit = run_git(root, "rev-parse", "HEAD").decode("ascii").strip()
    database_blob = run_git(root, "rev-parse", f"{source_commit}:.chainlink/issues.db").decode("ascii").strip()
    session_blob = run_git(root, "rev-parse", f"{source_commit}:.chainlink/session.json").decode("ascii").strip()
    bytecode_blob = run_git(
        root,
        "rev-parse",
        f"{source_commit}:.claude/hooks/__pycache__/crosslink_config.cpython-313.pyc",
    ).decode("ascii").strip()
    exported = build_export(
        database_path,
        session_path,
        source_commit=source_commit,
        database_blob=database_blob,
        session_blob=session_blob,
    )
    export_raw = encode_export(exported)
    run_git(root, "rm", "--quiet", "-r", ".chainlink", ".claude")
    run_git(root, "commit", "--quiet", "-m", "remove mutable fixture state")
    removed_by_commit = run_git(root, "rev-parse", "HEAD").decode("ascii").strip()

    export_path = root / EXPORT_PATH
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_path.write_bytes(export_raw)
    write_retention(
        root,
        exported,
        export_raw,
        source_commit=source_commit,
        bytecode_blob=bytecode_blob,
        bytecode_sha256=hashlib.sha256(bytecode_raw).hexdigest(),
        bytecode_size=len(bytecode_raw),
        removed_by_commit=removed_by_commit,
    )
    (root / ".gitignore").write_text(
        "\n".join(sorted(REQUIRED_IGNORE_LINES)) + "\n",
        encoding="utf-8",
    )
    for path in (
        "Cargo.lock",
        "Cargo.toml",
        "docs/repository-artifact-dependency-policy.md",
        "fuzz/Cargo.lock",
        "fuzz/Cargo.toml",
        "deny.toml",
        "fuzz/deny.toml",
        "scripts/export_legacy_chainlink.py",
        "scripts/check_repository_hygiene.py",
        "scripts/tests/test_repository_policy.py",
    ):
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if path in {"deny.toml", "fuzz/deny.toml"}:
            destination.write_bytes((REPOSITORY_ROOT / path).read_bytes())
        else:
            destination.write_text("fixture\n", encoding="utf-8")
    workflow = root / WORKFLOW_PATH
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        """name: Repository policy fixture
on: [push]
permissions:
  contents: read
jobs:
  policy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
          fetch-depth: 0
      - uses: dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772 # v1
        with:
          toolchain: 1.91.0
      - run: |
          python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
          python3 scripts/check_repository_hygiene.py --repo-root .
          cargo metadata --locked --format-version 1 --no-deps
          cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 --no-deps
          cargo install cargo-deny --version 0.20.2 --locked
          cargo deny --locked check advisories licenses sources bans
          cargo deny --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check advisories licenses sources bans
          cargo check --locked --all-features --all-targets
          cargo clippy --locked --all-targets --all-features -- -D warnings
          cargo test --locked --all-targets --all-features -- --test-threads=1
""",
        encoding="utf-8",
    )
    run_git(root, "add", ".")
    return exported, export_raw


class ExportTests(unittest.TestCase):
    def test_export_is_deterministic_and_redacts_sensitive_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, first_raw = make_export(root)
            database = root / "history.db"
            session = root / "session.json"
            second = build_export(
                database,
                session,
                source_commit=COMMIT,
                database_blob=DATABASE_BLOB,
                session_blob=SESSION_BLOB,
            )
            second_raw = encode_export(second)

            self.assertEqual(first_raw, second_raw)
            self.assertEqual(first["summary"]["table_rows"]["issues"], 1)
            self.assertGreaterEqual(first["redaction"]["total"], 4)
            self.assertEqual(sensitive_matches(first_raw.decode("utf-8")), [])
            self.assertIn(b"[REDACTED_EMAIL]", first_raw)
            self.assertIn(b"[REDACTED_CREDENTIAL]", first_raw)
            self.assertIn(b"[REDACTED_HOST_PATH]", first_raw)

    def test_schema_addition_is_rejected_instead_of_silently_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "history.db"
            session = root / "session.json"
            create_database(database)
            create_session(session)
            connection = sqlite3.connect(database)
            connection.execute("ALTER TABLE issues ADD COLUMN unreviewed TEXT")
            connection.commit()
            connection.close()

            with self.assertRaisesRegex(ExportError, "unexpected columns"):
                build_export(
                    database,
                    session,
                    source_commit=COMMIT,
                    database_blob=DATABASE_BLOB,
                    session_blob=SESSION_BLOB,
                )

    def test_unexpected_table_is_rejected_instead_of_silently_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "history.db"
            session = root / "session.json"
            create_database(database)
            create_session(session)
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE unreviewed_evidence (content TEXT NOT NULL)")
            connection.execute(
                "INSERT INTO unreviewed_evidence VALUES (?)",
                ("evidence that must not be omitted",),
            )
            connection.commit()
            connection.close()

            with self.assertRaisesRegex(ExportError, "unexpected user tables"):
                build_export(
                    database,
                    session,
                    source_commit=COMMIT,
                    database_blob=DATABASE_BLOB,
                    session_blob=SESSION_BLOB,
                )

    def test_session_marker_must_match_exported_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "history.db"
            session = root / "session.json"
            create_database(database)
            create_session(session)
            marker = json.loads(session.read_text(encoding="utf-8"))
            marker["active_issue_id"] = 999
            session.write_text(json.dumps(marker), encoding="utf-8")

            with self.assertRaisesRegex(ExportError, "disagrees"):
                build_export(
                    database,
                    session,
                    source_commit=COMMIT,
                    database_blob=DATABASE_BLOB,
                    session_blob=SESSION_BLOB,
                )

    def test_session_marker_rejects_boolean_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "history.db"
            session = root / "session.json"
            create_database(database)
            create_session(session)
            marker = json.loads(session.read_text(encoding="utf-8"))
            marker["active_issue_id"] = True
            session.write_text(json.dumps(marker), encoding="utf-8")

            with self.assertRaisesRegex(ExportError, "identifiers must be integers"):
                build_export(
                    database,
                    session,
                    source_commit=COMMIT,
                    database_blob=DATABASE_BLOB,
                    session_blob=SESSION_BLOB,
                )

    def test_non_finite_database_values_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "history.db"
            session = root / "session.json"
            create_database(database)
            create_session(session)
            connection = sqlite3.connect(database)
            connection.execute(
                "INSERT INTO time_entries VALUES (?, ?, ?, ?, ?)",
                (1, 1, "2026-01-01T00:00:00Z", None, float("inf")),
            )
            connection.commit()
            connection.close()

            with self.assertRaisesRegex(ExportError, "non-finite"):
                build_export(
                    database,
                    session,
                    source_commit=COMMIT,
                    database_blob=DATABASE_BLOB,
                    session_blob=SESSION_BLOB,
                )


class RepositoryPolicyTests(unittest.TestCase):
    def test_valid_policy_repository_produces_digest_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _exported, export_raw = create_policy_repository(root)
            evidence = check_repository(root)

            self.assertEqual(evidence["status"], "verified")
            self.assertEqual(evidence["forbidden_tracked_artifacts"], 0)
            self.assertEqual(
                evidence["historical_export"]["sha256"],
                hashlib.sha256(export_raw).hexdigest(),
            )
            self.assertEqual(evidence["ci_policy"]["full_history_checkouts"], 1)
            self.assertGreater(
                evidence["dependency_policy"]["root_exact_duplicate_exceptions"],
                0,
            )
            self.assertGreater(
                evidence["dependency_policy"]["fuzz_exact_duplicate_exceptions"],
                0,
            )

    def test_required_policy_file_must_be_tracked_not_merely_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            run_git(root, "rm", "--cached", "--quiet", "deny.toml")

            with self.assertRaisesRegex(PolicyError, "policy files are not tracked"):
                check_repository(root)

    def test_non_sensitive_export_forgery_is_rejected_against_git_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            export_path = root / EXPORT_PATH
            exported = json.loads(export_path.read_text(encoding="utf-8"))
            exported["tables"]["issues"][0]["title"] = "plausible but forged history"
            export_raw = (json.dumps(exported, indent=2, sort_keys=True) + "\n").encode("utf-8")
            export_path.write_bytes(export_raw)
            retention_path = root / RETENTION_PATH
            retention = json.loads(retention_path.read_text(encoding="utf-8"))
            retention["export"]["sha256"] = hashlib.sha256(export_raw).hexdigest()
            retention["export"]["size_bytes"] = len(export_raw)
            retention_path.write_text(
                json.dumps(retention, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PolicyError, "does not reproduce"):
                check_repository(root)

    def test_renamed_raw_historical_blob_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exported, _export_raw = create_policy_repository(root)
            source = exported["source"]
            assert isinstance(source, dict)
            database = source["database"]
            assert isinstance(database, dict)
            raw = run_git(root, "cat-file", "blob", str(database["git_blob"]))
            archive = root / "docs/history.bin"
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(raw)
            run_git(root, "add", "docs/history.bin")

            with self.assertRaisesRegex(PolicyError, "reintroduces raw historical artifact"):
                check_repository(root)

    def test_base64_encoded_historical_blob_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exported, _export_raw = create_policy_repository(root)
            source = exported["source"]
            assert isinstance(source, dict)
            session = source["session_marker"]
            assert isinstance(session, dict)
            raw = run_git(root, "cat-file", "blob", str(session["git_blob"]))
            archive = root / "docs/session-history.b64"
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(base64.encodebytes(raw))
            run_git(root, "add", "docs/session-history.b64")

            with self.assertRaisesRegex(PolicyError, "reintroduces raw historical artifact"):
                check_repository(root)

    def test_digest_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            with (root / EXPORT_PATH).open("ab") as handle:
                handle.write(b"\n")

            with self.assertRaisesRegex(PolicyError, "digest does not match"):
                check_repository(root)

    def test_forged_removal_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            run_git(root, "commit", "--quiet", "-m", "unrelated later policy commit")
            unrelated_commit = run_git(root, "rev-parse", "HEAD").decode("ascii").strip()
            retention_path = root / RETENTION_PATH
            retention = json.loads(retention_path.read_text(encoding="utf-8"))
            retention["source"]["artifacts"][".chainlink/issues.db"][
                "removed_by_commit"
            ] = unrelated_commit
            retention_path.write_text(
                json.dumps(retention, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                PolicyError, "parent of removal commit does not contain exactly one"
            ):
                check_repository(root)

    def test_recomputed_digest_cannot_hide_sensitive_export_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            export_path = root / EXPORT_PATH
            exported = json.loads(export_path.read_text(encoding="utf-8"))
            exported["tables"]["comments"][0]["content"] = "api_key=sk-ant-forgedsecretvalue"
            export_raw = (json.dumps(exported, indent=2, sort_keys=True) + "\n").encode("utf-8")
            export_path.write_bytes(export_raw)
            retention_path = root / RETENTION_PATH
            retention = json.loads(retention_path.read_text(encoding="utf-8"))
            retention["export"]["sha256"] = hashlib.sha256(export_raw).hexdigest()
            retention["export"]["size_bytes"] = len(export_raw)
            retention_path.write_text(
                json.dumps(retention, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PolicyError, "sensitive shapes"):
                check_repository(root)

    def test_tracked_runtime_marker_is_rejected_even_when_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            marker = root / ".chainlink/session.json"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("{}\n", encoding="utf-8")
            run_git(root, "add", "-f", ".chainlink/session.json")

            with self.assertRaisesRegex(PolicyError, "active runtime marker"):
                check_repository(root)

    def test_missing_ignore_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            lines = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
            lines.remove("*.py[cod]")
            (root / ".gitignore").write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(PolicyError, "missing required entries"):
                check_repository(root)

    def test_unpinned_ci_action_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            workflow = root / WORKFLOW_PATH
            text = workflow.read_text(encoding="utf-8").replace(
                "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
                "actions/checkout@main",
            )
            workflow.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(PolicyError, "unpinned or malformed action"):
                check_repository(root)

    def test_shallow_ci_checkout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            workflow = root / WORKFLOW_PATH
            text = workflow.read_text(encoding="utf-8").replace("          fetch-depth: 0\n", "")
            workflow.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(PolicyError, "must fetch history"):
                check_repository(root)

    def test_unlocked_ci_cargo_command_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            workflow = root / WORKFLOW_PATH
            text = workflow.read_text(encoding="utf-8").replace(
                "cargo check --locked --all-features --all-targets",
                "cargo check --all-features --all-targets",
            )
            workflow.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(PolicyError, "missing required locked gates|unlocked Cargo command"):
                check_repository(root)

    def test_duplicate_policy_cannot_be_downgraded_to_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            policy = root / "fuzz/deny.toml"
            text = policy.read_text(encoding="utf-8").replace(
                'multiple-versions = "deny"',
                'multiple-versions = "warn"',
                1,
            )
            policy.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(PolicyError, "may differ only|must deny"):
                check_repository(root)

    def test_duplicate_exception_must_pin_an_exact_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            policy = root / "deny.toml"
            text = policy.read_text(encoding="utf-8").replace(
                'base64@0.22.1',
                'base64@0.22',
                1,
            )
            policy.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(PolicyError, "not an exact crate version"):
                check_repository(root)

    def test_fuzz_policy_cannot_inherit_browser_license_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_policy_repository(root)
            policy = root / "fuzz/deny.toml"
            text = policy.read_text(encoding="utf-8").replace(
                "exceptions = []",
                'exceptions = [{ allow = ["GPL-3.0-or-later"], crate = "auto_generate_cdp@0.4.6" }] ',
                1,
            )
            policy.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(PolicyError, "must not inherit"):
                check_repository(root)

    def test_forbidden_path_classifier_is_narrow_and_explicit(self) -> None:
        self.assertEqual(
            forbidden_tracked_reason(".crosslink/issues.db"),
            "mutable runtime database",
        )
        self.assertEqual(forbidden_tracked_reason("target/debug/app"), "build output")
        self.assertEqual(forbidden_tracked_reason("hooks/__pycache__/check.pyc"), "generated Python bytecode")
        self.assertIsNone(forbidden_tracked_reason("tests/fixtures/example.db"))


if __name__ == "__main__":
    unittest.main()
