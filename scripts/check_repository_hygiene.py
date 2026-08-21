#!/usr/bin/env python3
"""Verify OpenClaudia tracked-artifact and historical-retention policy."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from export_legacy_chainlink import (
    EXPORT_SCHEMA,
    EXPORT_VERSION,
    MAX_DATABASE_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_SESSION_BYTES,
    MAX_TEXT_BYTES,
    REDACTION_POLICY_VERSION,
    SENSITIVE_PATTERNS,
    TABLES,
    build_export,
    encode_export,
    sensitive_matches,
)

POLICY_RESULT_SCHEMA = "openclaudia.repository-hygiene-result"
RETENTION_SCHEMA = "openclaudia.historical-retention"
RETENTION_VERSION = 1
EXPORT_PATH = PurePosixPath("docs/historical-evidence/chainlink-history-v1.json")
RETENTION_PATH = PurePosixPath("docs/historical-evidence/chainlink-retention-v1.json")
WORKFLOW_PATH = PurePosixPath(".github/workflows/sandbox-security.yml")
RUST_TOOLCHAIN_PATH = PurePosixPath("rust-toolchain.toml")
ROOT_DENY_PATH = PurePosixPath("deny.toml")
FUZZ_DENY_PATH = PurePosixPath("fuzz/deny.toml")
PINNED_RUST_TOOLCHAIN = "1.98.0"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_WORKFLOW_BYTES = 512 * 1024
MAX_TRACKED_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_TRACKED_PATHS = 100_000
MAX_PATH_BYTES = 4096
GIT_TIMEOUT_SECONDS = 15
MAX_BYTECODE_BYTES = 4 * 1024 * 1024
EXACT_CRATE_VERSION = re.compile(
    r"^[A-Za-z0-9_-]+@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"
)

REQUIRED_IGNORE_LINES = {
    "/target/",
    "__pycache__/",
    "*.py[cod]",
    "/.chainlink/issues.db*",
    "/.chainlink/session.json",
    "/.chainlink/.active-issue",
    ".crosslink/issues.db",
    ".crosslink/session.json",
    ".crosslink/.active-issue",
    ".openclaudia/browser_profile/",
}

REQUIRED_REPOSITORY_FILES = {
    ".gitignore",
    "Cargo.lock",
    "Cargo.toml",
    RUST_TOOLCHAIN_PATH.as_posix(),
    "docs/repository-artifact-dependency-policy.md",
    "fuzz/Cargo.lock",
    "fuzz/Cargo.toml",
    ROOT_DENY_PATH.as_posix(),
    FUZZ_DENY_PATH.as_posix(),
    EXPORT_PATH.as_posix(),
    RETENTION_PATH.as_posix(),
    "scripts/export_legacy_chainlink.py",
    "scripts/check_repository_hygiene.py",
    "scripts/tests/test_repository_policy.py",
    WORKFLOW_PATH.as_posix(),
}

APPROVED_ACTION_PINS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "dtolnay/rust-toolchain": "6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772",
}
USES_LINE = re.compile(
    r"^\s*-\s+uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})(?:\s+#.*)?$"
)


class PolicyError(RuntimeError):
    """Repository policy evidence is malformed or incomplete."""


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def _expect_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise PolicyError(
            f"{label} has unexpected fields; expected {sorted(expected)}, got {sorted(actual)}"
        )


def _reject_json_constant(value: str) -> None:
    raise PolicyError(f"JSON non-finite number {value} is not supported")


def _read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PolicyError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyError(f"{label} must be a regular file, not a symlink or special file")
    if metadata.st_size > maximum:
        raise PolicyError(f"{label} exceeds the {maximum}-byte bound")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise PolicyError(f"cannot read {label}: {error}") from error
    if len(data) != metadata.st_size:
        raise PolicyError(f"{label} changed while it was read")
    return data


def _read_toml(path: Path, label: str) -> dict[str, Any]:
    raw = _read_regular_file(path, MAX_MANIFEST_BYTES, label)
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise PolicyError(f"{label} is not valid UTF-8 TOML: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be a TOML table")
    return value


def _exact_skip_specs(config: Mapping[str, Any], label: str) -> list[str]:
    bans = config.get("bans")
    if not isinstance(bans, dict):
        raise PolicyError(f"{label} must define a bans table")
    if bans.get("multiple-versions") != "deny":
        raise PolicyError(f"{label} must deny duplicate dependency versions")
    if bans.get("wildcards") != "deny":
        raise PolicyError(f"{label} must deny wildcard dependency specifications")
    if bans.get("skip-tree") != []:
        raise PolicyError(f"{label} must not use tree-wide duplicate exceptions")
    skips = bans.get("skip")
    if not isinstance(skips, list):
        raise PolicyError(f"{label} must define an exact duplicate-exception list")
    specs: list[str] = []
    for index, entry in enumerate(skips):
        if not isinstance(entry, dict) or set(entry) != {"crate"}:
            raise PolicyError(f"{label} duplicate exception {index} must contain only crate")
        spec = entry["crate"]
        if not isinstance(spec, str) or EXACT_CRATE_VERSION.fullmatch(spec) is None:
            raise PolicyError(f"{label} duplicate exception {index} is not an exact crate version")
        specs.append(spec)
    if len(specs) != len(set(specs)):
        raise PolicyError(f"{label} contains duplicate duplicate-version exceptions")
    return specs


def _validate_dependency_policy(repo_root: Path) -> dict[str, int]:
    root = _read_toml(repo_root / ROOT_DENY_PATH, "root dependency policy")
    fuzz = _read_toml(repo_root / FUZZ_DENY_PATH, "fuzz dependency policy")
    if root.get("graph") != fuzz.get("graph"):
        raise PolicyError("root and fuzz dependency graph policy must match")
    if root.get("advisories") != fuzz.get("advisories"):
        raise PolicyError("root and fuzz advisory policy must match")
    if root.get("sources") != fuzz.get("sources"):
        raise PolicyError("root and fuzz source policy must match")

    root_bans = root.get("bans")
    fuzz_bans = fuzz.get("bans")
    if not isinstance(root_bans, dict) or not isinstance(fuzz_bans, dict):
        raise PolicyError("root and fuzz dependency policy must define bans tables")
    root_common_bans = {key: value for key, value in root_bans.items() if key != "skip"}
    fuzz_common_bans = {key: value for key, value in fuzz_bans.items() if key != "skip"}
    if root_common_bans != fuzz_common_bans:
        raise PolicyError("root and fuzz ban policy may differ only in exact duplicate exceptions")

    root_skips = _exact_skip_specs(root, "root dependency policy")
    fuzz_skips = _exact_skip_specs(fuzz, "fuzz dependency policy")

    root_licenses = root.get("licenses")
    fuzz_licenses = fuzz.get("licenses")
    if not isinstance(root_licenses, dict) or not isinstance(fuzz_licenses, dict):
        raise PolicyError("root and fuzz dependency policy must define licenses tables")
    for key in ("confidence-threshold", "private"):
        if root_licenses.get(key) != fuzz_licenses.get(key):
            raise PolicyError(f"root and fuzz license policy differ at {key}")
    root_allow = root_licenses.get("allow")
    fuzz_allow = fuzz_licenses.get("allow")
    if not isinstance(root_allow, list) or not isinstance(fuzz_allow, list):
        raise PolicyError("root and fuzz license allowlists must be explicit lists")
    if set(fuzz_allow) != set(root_allow) | {"NCSA"}:
        raise PolicyError("fuzz license policy may add only its libFuzzer NCSA license")

    expected_exception = [
        {"allow": ["GPL-3.0-or-later"], "crate": "auto_generate_cdp@0.4.6"}
    ]
    expected_clarification = [
        {
            "crate": "auto_generate_cdp@0.4.6",
            "expression": "GPL-3.0-or-later",
            "license-files": [{"path": "LICENSE.txt", "hash": 0xC5A651AA}],
        }
    ]
    if root_licenses.get("exceptions") != expected_exception:
        raise PolicyError("root license policy must retain only the reviewed browser build exception")
    if root_licenses.get("clarify") != expected_clarification:
        raise PolicyError("root browser build license clarification is missing or unbound")
    if fuzz_licenses.get("exceptions") != [] or fuzz_licenses.get("clarify") not in (None, []):
        raise PolicyError("fuzz license policy must not inherit the browser-only exception")

    return {
        "root_exact_duplicate_exceptions": len(root_skips),
        "fuzz_exact_duplicate_exceptions": len(fuzz_skips),
    }


def _read_json(path: Path, maximum: int, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, maximum, label)
    try:
        value = json.loads(raw, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be a JSON object")
    return value, raw


def _expect_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be an object")
    return value


def _expect_int(value: Any, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise PolicyError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise PolicyError(f"{label} exceeds the {MAX_TEXT_BYTES}-byte bound")
    return value


def _expect_hex(value: Any, length: int, label: str) -> str:
    text = _expect_string(value, label)
    if len(text) != length or any(character not in "0123456789abcdef" for character in text):
        raise PolicyError(f"{label} must be exactly {length} lowercase hexadecimal characters")
    return text


def _validate_export(export: Mapping[str, Any], raw: bytes) -> dict[str, int]:
    _expect_keys(
        export,
        {
            "active_session_marker",
            "integrity",
            "redaction",
            "schema",
            "source",
            "summary",
            "tables",
            "version",
        },
        "historical export",
    )
    if export.get("schema") != EXPORT_SCHEMA or export.get("version") != EXPORT_VERSION:
        raise PolicyError("historical export schema/version is unsupported")
    integrity = _expect_mapping(export.get("integrity"), "historical export integrity")
    _expect_keys(integrity, {"foreign_key_violations", "sqlite_integrity"}, "export integrity")
    if integrity != {"foreign_key_violations": 0, "sqlite_integrity": "ok"}:
        raise PolicyError("historical export lacks successful SQLite integrity evidence")

    source = _expect_mapping(export.get("source"), "historical export source")
    _expect_keys(source, {"database", "repository_commit", "session_marker"}, "export source")
    _expect_hex(source.get("repository_commit"), 40, "historical source commit")
    database = _expect_mapping(source.get("database"), "historical database source")
    _expect_keys(
        database,
        {"git_blob", "sha256", "size_bytes", "sqlite_user_version"},
        "historical database source",
    )
    session_source = _expect_mapping(source.get("session_marker"), "historical session source")
    _expect_keys(
        session_source,
        {"git_blob", "sha256", "size_bytes"},
        "historical session source",
    )
    for artifact_name, artifact in (("database", database), ("session_marker", session_source)):
        _expect_hex(artifact.get("git_blob"), 40, f"historical {artifact_name} blob")
        _expect_hex(artifact.get("sha256"), 64, f"historical {artifact_name} digest")
        _expect_int(artifact.get("size_bytes"), f"historical {artifact_name} size", 1)
    if database.get("sqlite_user_version") != 7:
        raise PolicyError("historical export does not bind SQLite schema version 7")

    tables = _expect_mapping(export.get("tables"), "historical export tables")
    if set(tables) != set(TABLES):
        raise PolicyError("historical export table set does not match the approved schema")
    row_counts: dict[str, int] = {}
    for table, (columns, _ordering, row_limit) in TABLES.items():
        rows = tables[table]
        if not isinstance(rows, list) or len(rows) > row_limit:
            raise PolicyError(f"historical export table {table} violates its row bound")
        for index, row in enumerate(rows):
            if not isinstance(row, dict) or set(row) != set(columns):
                raise PolicyError(f"historical export {table} row {index} has unexpected columns")
            for column, value in row.items():
                if isinstance(value, str) and len(value.encode("utf-8")) > MAX_TEXT_BYTES:
                    raise PolicyError(f"historical export {table}.{column} exceeds its text bound")
                if isinstance(value, bool) or (
                    value is not None and not isinstance(value, (str, int, float))
                ):
                    raise PolicyError(f"historical export {table}.{column} has an unsupported value")
                if isinstance(value, float) and not math.isfinite(value):
                    raise PolicyError(f"historical export {table}.{column} has a non-finite value")
        row_counts[table] = len(rows)
    if sum(row_counts.values()) > 100_000:
        raise PolicyError("historical export exceeds its total row bound")

    summary = _expect_mapping(export.get("summary"), "historical export summary")
    _expect_keys(summary, {"issue_priority", "issue_status", "table_rows"}, "export summary")
    if summary.get("table_rows") != row_counts:
        raise PolicyError("historical export row summary does not match exported rows")
    for field in ("issue_status", "issue_priority"):
        grouped = _expect_mapping(summary.get(field), f"historical export {field}")
        if any(not isinstance(key, str) or not isinstance(value, int) for key, value in grouped.items()):
            raise PolicyError(f"historical export {field} must map strings to integer counts")
        if sum(grouped.values()) != row_counts["issues"]:
            raise PolicyError(f"historical export {field} counts do not cover every issue")

    redaction = _expect_mapping(export.get("redaction"), "historical export redaction")
    _expect_keys(redaction, {"counts", "policy_version", "total"}, "export redaction")
    if redaction.get("policy_version") != REDACTION_POLICY_VERSION:
        raise PolicyError("historical export uses an unsupported redaction policy")
    counts = _expect_mapping(redaction.get("counts"), "historical export redaction counts")
    known_redactions = {category for category, _pattern in SENSITIVE_PATTERNS}
    if not set(counts).issubset(known_redactions) or any(
        not isinstance(key, str)
        or not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
        for key, value in counts.items()
    ):
        raise PolicyError("historical export redaction counts are malformed")
    if redaction.get("total") != sum(counts.values()):
        raise PolicyError("historical export redaction total does not match category counts")

    active_marker = _expect_mapping(
        export.get("active_session_marker"), "historical active session marker"
    )
    _expect_keys(
        active_marker,
        {"active_issue_id", "session_id", "started_at"},
        "historical active session marker",
    )
    active_issue_id = _expect_int(
        active_marker.get("active_issue_id"), "historical active issue id"
    )
    session_id = _expect_int(active_marker.get("session_id"), "historical active session id")
    started_at = _expect_string(active_marker.get("started_at"), "historical session start")
    matching_sessions = [
        row
        for row in tables["sessions"]
        if row["id"] == session_id
        and row["active_issue_id"] == active_issue_id
        and row["started_at"] == started_at
    ]
    if len(matching_sessions) != 1:
        raise PolicyError("historical active session marker does not match exactly one session row")

    remaining = sensitive_matches(raw.decode("utf-8"))
    if remaining:
        raise PolicyError(f"historical export still contains sensitive shapes: {sorted(set(remaining))}")
    return row_counts


def _validate_retention(
    retention: Mapping[str, Any],
    export: Mapping[str, Any],
    export_raw: bytes,
    row_counts: Mapping[str, int],
) -> None:
    _expect_keys(
        retention,
        {
            "decision",
            "export",
            "policy",
            "raw_artifacts_reintroduced",
            "schema",
            "source",
            "verification",
            "version",
        },
        "historical retention record",
    )
    if retention.get("schema") != RETENTION_SCHEMA or retention.get("version") != RETENTION_VERSION:
        raise PolicyError("historical retention schema/version is unsupported")
    if retention.get("decision") != "redacted_export_only":
        raise PolicyError("historical retention decision must be redacted_export_only")
    if retention.get("raw_artifacts_reintroduced") is not False:
        raise PolicyError("retention record must state that raw artifacts were not reintroduced")

    source = _expect_mapping(retention.get("source"), "retention source")
    _expect_keys(source, {"artifacts", "repository_commit"}, "retention source")
    export_source = _expect_mapping(export.get("source"), "historical export source")
    if source.get("repository_commit") != export_source.get("repository_commit"):
        raise PolicyError("retention source commit does not match the historical export")
    artifacts = _expect_mapping(source.get("artifacts"), "retention artifacts")
    expected_artifacts = {
        ".chainlink/issues.db",
        ".chainlink/session.json",
        ".claude/hooks/__pycache__/crosslink_config.cpython-313.pyc",
    }
    if set(artifacts) != expected_artifacts:
        raise PolicyError("retention record does not enumerate the approved historical artifacts")
    for path, artifact in artifacts.items():
        item = _expect_mapping(artifact, f"retention artifact {path}")
        _expect_keys(
            item,
            {"disposition", "git_blob", "removed_by_commit", "sha256", "size_bytes"},
            f"retention artifact {path}",
        )
        _expect_hex(item.get("git_blob"), 40, f"retention artifact {path} blob")
        _expect_hex(item.get("sha256"), 64, f"retention artifact {path} digest")
        _expect_hex(
            item.get("removed_by_commit"),
            40,
            f"retention artifact {path} removal commit",
        )
        _expect_int(item.get("size_bytes"), f"retention artifact {path} size", 1)
        if item.get("disposition") != "removed_from_current_tree":
            raise PolicyError(f"retention artifact {path} has an unsupported disposition")

    database_source = _expect_mapping(export_source.get("database"), "historical database source")
    session_source = _expect_mapping(export_source.get("session_marker"), "historical session source")
    for path, exported_source in (
        (".chainlink/issues.db", database_source),
        (".chainlink/session.json", session_source),
    ):
        retained = _expect_mapping(artifacts[path], f"retention artifact {path}")
        for field in ("git_blob", "sha256", "size_bytes"):
            if retained.get(field) != exported_source.get(field):
                raise PolicyError(f"retention artifact {path} {field} does not match the export")

    export_record = _expect_mapping(retention.get("export"), "retention export")
    _expect_keys(
        export_record,
        {"path", "schema", "sha256", "size_bytes", "table_rows", "version"},
        "retention export",
    )
    if export_record.get("path") != EXPORT_PATH.as_posix():
        raise PolicyError("retention export path is not canonical")
    if export_record.get("schema") != EXPORT_SCHEMA or export_record.get("version") != EXPORT_VERSION:
        raise PolicyError("retention export schema/version does not match the export")
    if export_record.get("sha256") != sha256_bytes(export_raw):
        raise PolicyError("retention export digest does not match the exported bytes")
    if export_record.get("size_bytes") != len(export_raw):
        raise PolicyError("retention export size does not match the exported bytes")
    if export_record.get("table_rows") != row_counts:
        raise PolicyError("retention export counts do not match the exported rows")

    verification = _expect_mapping(retention.get("verification"), "retention verification")
    if verification != {
        "checker": "scripts/check_repository_hygiene.py",
        "exporter": "scripts/export_legacy_chainlink.py",
    }:
        raise PolicyError("retention verification tools are not the canonical scripts")
    policy = _expect_mapping(retention.get("policy"), "retention policy")
    _expect_keys(
        policy,
        {
            "history_availability_not_guaranteed",
            "purpose",
            "raw_archive_created",
            "raw_history_is_not_the_canonical_record",
            "redaction_policy_version",
        },
        "retention policy",
    )
    if policy.get("raw_archive_created") is not False:
        raise PolicyError("retention policy must not claim an unreviewed raw archive")
    if policy.get("raw_history_is_not_the_canonical_record") is not True:
        raise PolicyError("retention policy must identify the redacted export as canonical")
    if policy.get("history_availability_not_guaranteed") is not True:
        raise PolicyError("retention policy must not promise permanent Git-history availability")
    if policy.get("redaction_policy_version") != REDACTION_POLICY_VERSION:
        raise PolicyError("retention policy redaction version does not match the exporter")
    _expect_string(policy.get("purpose"), "retention policy purpose")
    remaining = sensitive_matches(json.dumps(retention, sort_keys=True))
    if remaining:
        raise PolicyError(f"retention record contains sensitive shapes: {sorted(set(remaining))}")


def _tracked_paths(repo_root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repo_root), "ls-files", "-z"],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PolicyError(f"cannot enumerate tracked repository paths: {error}") from error
    if len(result.stdout) > MAX_TRACKED_OUTPUT_BYTES:
        raise PolicyError("tracked-path output exceeds its byte bound")
    try:
        paths = [part.decode("utf-8") for part in result.stdout.split(b"\0") if part]
    except UnicodeDecodeError as error:
        raise PolicyError("tracked repository contains a non-UTF-8 path") from error
    if len(paths) > MAX_TRACKED_PATHS:
        raise PolicyError("tracked repository exceeds its path-count bound")
    if any(len(path.encode("utf-8")) > MAX_PATH_BYTES for path in paths):
        raise PolicyError("tracked repository contains an overlong path")
    return paths


def _run_git(repo_root: Path, arguments: Sequence[str], maximum: int, label: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repo_root), *arguments],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PolicyError(f"cannot {label}: {error}") from error
    if len(result.stdout) > maximum:
        raise PolicyError(f"{label} output exceeds its {maximum}-byte bound")
    return result.stdout


def _historical_blob(
    repo_root: Path,
    source_commit: str,
    path: str,
    expected_blob: str,
    expected_sha256: str,
    expected_size: int,
    maximum: int,
) -> bytes:
    if expected_size > maximum:
        raise PolicyError(f"historical artifact {path} exceeds its {maximum}-byte bound")
    tree = _run_git(
        repo_root,
        ["ls-tree", "-z", "--full-tree", source_commit, "--", path],
        8192,
        f"resolve historical artifact {path}",
    )
    entries = [entry for entry in tree.split(b"\0") if entry]
    if len(entries) != 1:
        raise PolicyError(f"historical source commit does not contain exactly one {path}")
    try:
        metadata, resolved_path = entries[0].split(b"\t", 1)
        _mode, object_type, object_id = metadata.decode("ascii").split()
        decoded_path = resolved_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise PolicyError(f"historical Git metadata for {path} is malformed") from error
    if object_type != "blob" or decoded_path != path or object_id != expected_blob:
        raise PolicyError(f"historical Git object for {path} does not match the retention record")

    size_raw = _run_git(
        repo_root,
        ["cat-file", "-s", expected_blob],
        128,
        f"inspect historical blob {path}",
    )
    try:
        object_size = int(size_raw.strip())
    except ValueError as error:
        raise PolicyError(f"historical Git object size for {path} is malformed") from error
    if object_size != expected_size or object_size > maximum:
        raise PolicyError(f"historical Git object size for {path} does not match retention")
    raw = _run_git(
        repo_root,
        ["cat-file", "blob", expected_blob],
        maximum,
        f"read historical blob {path}",
    )
    if len(raw) != expected_size or sha256_bytes(raw) != expected_sha256:
        raise PolicyError(f"historical Git object content for {path} does not match retention")
    return raw


def _verify_removal_commit(
    repo_root: Path,
    path: str,
    expected_blob: str,
    removal_commit: str,
) -> None:
    history = _run_git(
        repo_root,
        ["rev-list", "--parents", "-n", "1", removal_commit],
        256,
        f"inspect removal commit for {path}",
    )
    try:
        identifiers = history.decode("ascii").split()
    except UnicodeDecodeError as error:
        raise PolicyError(f"removal history for {path} is malformed") from error
    if len(identifiers) != 2 or identifiers[0] != removal_commit:
        raise PolicyError(f"removal commit for {path} must be a single-parent commit")
    parent = identifiers[1]

    removed_tree = _run_git(
        repo_root,
        ["ls-tree", "-z", "--full-tree", removal_commit, "--", path],
        8192,
        f"inspect removed path {path}",
    )
    if removed_tree:
        raise PolicyError(f"removal commit for {path} still contains the artifact")

    parent_tree = _run_git(
        repo_root,
        ["ls-tree", "-z", "--full-tree", parent, "--", path],
        8192,
        f"inspect parent of removal commit for {path}",
    )
    entries = [entry for entry in parent_tree.split(b"\0") if entry]
    if len(entries) != 1:
        raise PolicyError(f"parent of removal commit does not contain exactly one {path}")
    try:
        metadata, resolved_path = entries[0].split(b"\t", 1)
        _mode, object_type, object_id = metadata.decode("ascii").split()
        decoded_path = resolved_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise PolicyError(f"removal metadata for {path} is malformed") from error
    if object_type != "blob" or decoded_path != path or object_id != expected_blob:
        raise PolicyError(f"parent of removal commit does not contain the recorded blob for {path}")


def _reject_reintroduced_history(
    repo_root: Path,
    tracked: Sequence[str],
    historical: Mapping[str, bytes],
) -> None:
    encoded: dict[str, tuple[bytes, bytes, bytes]] = {
        path: (raw, base64.b64encode(raw), raw.hex().encode("ascii"))
        for path, raw in historical.items()
    }
    maximum = max(len(candidate) for candidates in encoded.values() for candidate in candidates)
    for path in tracked:
        candidate_path = repo_root / path
        try:
            metadata = candidate_path.lstat()
        except OSError as error:
            raise PolicyError(f"cannot inspect tracked path {path}: {error}") from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum + 4096:
            continue
        raw = _read_regular_file(candidate_path, maximum + 4096, f"tracked path {path}")
        compact = b"".join(raw.split())
        for source_path, forms in encoded.items():
            if raw == forms[0] or compact == forms[1] or compact == forms[2]:
                raise PolicyError(
                    f"tracked path {path} reintroduces raw historical artifact {source_path}"
                )


def _verify_historical_source(
    repo_root: Path,
    tracked: Sequence[str],
    retention: Mapping[str, Any],
    export_raw: bytes,
) -> None:
    source = _expect_mapping(retention.get("source"), "retention source")
    source_commit = _expect_hex(source.get("repository_commit"), 40, "historical source commit")
    artifacts = _expect_mapping(source.get("artifacts"), "retention artifacts")
    limits = {
        ".chainlink/issues.db": MAX_DATABASE_BYTES,
        ".chainlink/session.json": MAX_SESSION_BYTES,
        ".claude/hooks/__pycache__/crosslink_config.cpython-313.pyc": MAX_BYTECODE_BYTES,
    }
    historical: dict[str, bytes] = {}
    for path, maximum in limits.items():
        record = _expect_mapping(artifacts.get(path), f"retention artifact {path}")
        expected_blob = _expect_hex(
            record.get("git_blob"), 40, f"retention artifact {path} blob"
        )
        historical[path] = _historical_blob(
            repo_root,
            source_commit,
            path,
            expected_blob,
            _expect_hex(record.get("sha256"), 64, f"retention artifact {path} digest"),
            _expect_int(record.get("size_bytes"), f"retention artifact {path} size", 1),
            maximum,
        )
        _verify_removal_commit(
            repo_root,
            path,
            expected_blob,
            _expect_hex(
                record.get("removed_by_commit"),
                40,
                f"retention artifact {path} removal commit",
            ),
        )

    database_record = _expect_mapping(
        artifacts[".chainlink/issues.db"], "retention database artifact"
    )
    session_record = _expect_mapping(
        artifacts[".chainlink/session.json"], "retention session artifact"
    )
    with tempfile.TemporaryDirectory(prefix="openclaudia-history-verify-") as directory:
        root = Path(directory)
        database_path = root / "issues.db"
        session_path = root / "session.json"
        database_path.write_bytes(historical[".chainlink/issues.db"])
        session_path.write_bytes(historical[".chainlink/session.json"])
        regenerated = build_export(
            database_path,
            session_path,
            source_commit=source_commit,
            database_blob=_expect_string(database_record.get("git_blob"), "database blob"),
            session_blob=_expect_string(session_record.get("git_blob"), "session blob"),
        )
        regenerated_raw = encode_export(regenerated)
    if regenerated_raw != export_raw:
        raise PolicyError("historical export does not reproduce from its recorded Git source")

    _reject_reintroduced_history(repo_root, tracked, historical)


def forbidden_tracked_reason(path: str) -> str | None:
    """Return why a tracked path is forbidden, or None when it is permitted."""
    pure = PurePosixPath(path)
    parts = pure.parts
    lowered = tuple(part.lower() for part in parts)
    if "target" in lowered:
        return "build output"
    if "__pycache__" in lowered or pure.suffix.lower() in {".pyc", ".pyo", ".pyd"}:
        return "generated Python bytecode"
    if not parts:
        return None
    top = lowered[0]
    name = lowered[-1]
    if top in {".chainlink", ".crosslink", ".openclaudia"}:
        if name.endswith((".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3")):
            return "mutable runtime database"
        if name in {"session.json", ".active-issue", "daemon.pid"}:
            return "active runtime marker"
    return None


def _validate_ignores(repo_root: Path) -> None:
    raw = _read_regular_file(repo_root / ".gitignore", 1024 * 1024, "repository ignore policy")
    try:
        lines = {
            line.strip()
            for line in raw.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except UnicodeDecodeError as error:
        raise PolicyError("repository ignore policy is not UTF-8") from error
    missing = sorted(REQUIRED_IGNORE_LINES - lines)
    if missing:
        raise PolicyError(f"repository ignore policy is missing required entries: {missing}")


def _validate_ci_policy(repo_root: Path) -> dict[str, int]:
    raw = _read_regular_file(repo_root / WORKFLOW_PATH, MAX_WORKFLOW_BYTES, "repository policy workflow")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError("repository policy workflow is not UTF-8") from error
    if "pull_request_target:" in text:
        raise PolicyError("repository policy workflow must not run untrusted changes with pull_request_target")
    if not re.search(r"(?m)^permissions:\s*\n\s+contents:\s+read\s*$", text):
        raise PolicyError("repository policy workflow must declare read-only repository permissions")
    toolchains = re.findall(r"(?m)^\s+toolchain:\s+(\S+)\s*$", text)
    if not toolchains or set(toolchains) != {PINNED_RUST_TOOLCHAIN}:
        raise PolicyError(
            f"every CI job must use the single pinned Rust toolchain {PINNED_RUST_TOOLCHAIN}"
        )

    lines = text.splitlines()
    uses_lines = [(index, line) for index, line in enumerate(lines) if "uses:" in line]
    if not uses_lines:
        raise PolicyError("repository policy workflow must use explicitly pinned actions")
    action_counts = {action: 0 for action in APPROVED_ACTION_PINS}
    checkout_count = 0
    full_history_checkout_count = 0
    for index, line in uses_lines:
        matched = USES_LINE.fullmatch(line)
        if matched is None:
            raise PolicyError(f"repository policy workflow has an unpinned or malformed action: {line.strip()}")
        action, revision = matched.groups()
        expected = APPROVED_ACTION_PINS.get(action)
        if expected is None or revision != expected:
            raise PolicyError(f"repository policy workflow action {action} is not at its approved revision")
        action_counts[action] += 1
        if action == "actions/checkout":
            checkout_count += 1
            checkout_block = "\n".join(lines[index + 1 : index + 5])
            if not re.search(r"(?m)^\s+persist-credentials:\s+false\s*$", checkout_block):
                raise PolicyError("every checkout action must disable persisted credentials")
            if not re.search(r"(?m)^\s+fetch-depth:\s+0\s*$", checkout_block):
                raise PolicyError("every checkout action must fetch history for source verification")
            full_history_checkout_count += 1
    if any(count == 0 for count in action_counts.values()):
        raise PolicyError("repository policy workflow is missing an approved required action")

    jobs_marker = "\njobs:\n"
    if jobs_marker not in text:
        raise PolicyError("repository policy workflow has no jobs section")
    jobs_text = text.split(jobs_marker, 1)[1]
    jobs = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", jobs_text)
    timeout_count = len(re.findall(r"(?m)^    timeout-minutes:\s+[1-9][0-9]*\s*$", jobs_text))
    if not jobs or timeout_count != len(jobs):
        raise PolicyError("every repository policy workflow job must have an explicit timeout")

    required_fragments = {
        "python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v",
        "python3 scripts/check_repository_hygiene.py --repo-root .",
        "cargo metadata --locked --format-version 1 --no-deps",
        "cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 --no-deps",
        "cargo install cargo-deny --version 0.20.2 --locked",
        "cargo deny --locked check advisories licenses sources bans",
        "cargo deny --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check advisories licenses sources bans",
        f"toolchain: {PINNED_RUST_TOOLCHAIN}",
        "cargo check --locked --all-features --all-targets",
        "cargo clippy --locked --all-targets --all-features -- -D warnings",
        "cargo test --locked --all-targets --all-features -- --test-threads=1",
    }
    missing = sorted(fragment for fragment in required_fragments if fragment not in text)
    if missing:
        raise PolicyError(f"repository policy workflow is missing required locked gates: {missing}")
    for line in lines:
        command = line.strip()
        if not command.startswith("cargo "):
            continue
        words = command.split()
        if len(words) > 1 and words[1] in {"build", "check", "clippy", "deny", "metadata", "test"}:
            if "--locked" not in words:
                raise PolicyError(f"repository policy workflow has an unlocked Cargo command: {command}")
    return {
        "actions_pinned": len(uses_lines),
        "checkout_credentials_disabled": checkout_count,
        "full_history_checkouts": full_history_checkout_count,
        "jobs_bounded": len(jobs),
    }


def _validate_rust_toolchain_policy(repo_root: Path) -> None:
    toolchain = _read_toml(repo_root / RUST_TOOLCHAIN_PATH, "Rust toolchain policy")
    if toolchain != {
        "toolchain": {
            "channel": PINNED_RUST_TOOLCHAIN,
            "profile": "minimal",
            "components": ["clippy", "rustfmt"],
        }
    }:
        raise PolicyError(
            f"rust-toolchain.toml must pin the canonical {PINNED_RUST_TOOLCHAIN} toolchain"
        )
    manifest = _read_toml(repo_root / "Cargo.toml", "root Cargo manifest")
    package = _expect_mapping(manifest.get("package"), "root Cargo package")
    if package.get("rust-version") != PINNED_RUST_TOOLCHAIN.removesuffix(".0"):
        raise PolicyError(
            f"Cargo.toml rust-version must match Rust {PINNED_RUST_TOOLCHAIN}"
        )


def check_repository(repo_root: Path) -> dict[str, Any]:
    """Check repository policy and return deterministic evidence."""
    repo_root = repo_root.resolve()
    tracked = _tracked_paths(repo_root)
    tracked_set = set(tracked)
    forbidden = [
        {"path": path, "reason": reason}
        for path in tracked
        if (reason := forbidden_tracked_reason(path)) is not None
    ]
    if forbidden:
        raise PolicyError(f"forbidden tracked artifacts: {forbidden}")
    missing_tracked_files = sorted(REQUIRED_REPOSITORY_FILES - tracked_set)
    if missing_tracked_files:
        raise PolicyError(f"repository policy files are not tracked: {missing_tracked_files}")
    missing_files = sorted(path for path in REQUIRED_REPOSITORY_FILES if not (repo_root / path).exists())
    if missing_files:
        raise PolicyError(f"repository policy files are missing: {missing_files}")
    for path in REQUIRED_REPOSITORY_FILES:
        _read_regular_file(repo_root / path, 4 * 1024 * 1024, f"repository policy file {path}")
    _validate_ignores(repo_root)
    _validate_rust_toolchain_policy(repo_root)
    ci_policy = _validate_ci_policy(repo_root)
    dependency_policy = _validate_dependency_policy(repo_root)

    export, export_raw = _read_json(
        repo_root / EXPORT_PATH,
        MAX_OUTPUT_BYTES,
        "historical export",
    )
    row_counts = _validate_export(export, export_raw)
    retention, retention_raw = _read_json(
        repo_root / RETENTION_PATH,
        MAX_MANIFEST_BYTES,
        "historical retention record",
    )
    _validate_retention(retention, export, export_raw, row_counts)
    _verify_historical_source(repo_root, tracked, retention, export_raw)
    return {
        "schema": POLICY_RESULT_SCHEMA,
        "version": 1,
        "status": "verified",
        "tracked_paths_checked": len(tracked),
        "forbidden_tracked_artifacts": 0,
        "required_ignore_entries": len(REQUIRED_IGNORE_LINES),
        "ci_policy": ci_policy,
        "dependency_policy": dependency_policy,
        "historical_export": {
            "sha256": sha256_bytes(export_raw),
            "size_bytes": len(export_raw),
            "table_rows": row_counts,
        },
        "retention_record": {
            "sha256": sha256_bytes(retention_raw),
            "size_bytes": len(retention_raw),
        },
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        evidence = check_repository(arguments.repo_root)
    except PolicyError as error:
        print(
            json.dumps(
                {"schema": POLICY_RESULT_SCHEMA, "version": 1, "status": "rejected", "error": str(error)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
