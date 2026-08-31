#!/usr/bin/env python3
"""Export a bounded, deterministic, redacted legacy Chainlink history record."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

EXPORT_SCHEMA = "openclaudia.legacy-chainlink-export"
EXPORT_VERSION = 1
REDACTION_POLICY_VERSION = 1
MAX_DATABASE_BYTES = 16 * 1024 * 1024
MAX_SESSION_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_TOTAL_ROWS = 100_000

TABLES: dict[str, tuple[tuple[str, ...], str, int]] = {
    "issues": (
        (
            "id",
            "title",
            "description",
            "status",
            "priority",
            "parent_id",
            "created_at",
            "updated_at",
            "closed_at",
        ),
        "id",
        10_000,
    ),
    "labels": (("issue_id", "label"), "issue_id, label", 50_000),
    "dependencies": (("blocker_id", "blocked_id"), "blocker_id, blocked_id", 50_000),
    "comments": (("id", "issue_id", "content", "created_at"), "id", 50_000),
    "time_entries": (
        ("id", "issue_id", "started_at", "ended_at", "duration_seconds"),
        "id",
        50_000,
    ),
    "relations": (("issue_id_1", "issue_id_2", "created_at"), "issue_id_1, issue_id_2", 50_000),
    "milestones": (
        ("id", "name", "description", "status", "created_at", "closed_at"),
        "id",
        10_000,
    ),
    "milestone_issues": (("milestone_id", "issue_id"), "milestone_id, issue_id", 50_000),
    "sessions": (
        ("id", "started_at", "ended_at", "active_issue_id", "handoff_notes"),
        "id",
        10_000,
    ),
}

SESSION_FIELDS = ("active_issue_id", "session_id", "started_at")

SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?(?:id|secret)|password|secret)"
            r"(\s*[:=]\s*[\"']?)(?!\[REDACTED_)([^\s\"',;}]+)"
        ),
    ),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    (
        "token",
        re.compile(
            r"(?<![A-Za-z0-9])(?:sk-(?:ant-|proj-)?|gh[pousr]_|xox[baprs]-|AIza)[A-Za-z0-9._-]{8,}"
        ),
    ),
    (
        "email",
        re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ),
    (
        "windows_home_path",
        re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s\"'<>]+(?:\\[^\s\"'<>]*)?"),
    ),
    (
        "unix_home_path",
        re.compile(r"(?<![A-Za-z0-9])/(?:home|Users)/[^/\s\"'`<>]+(?:/[^\s\"'`<>]*)?"),
    ),
)

REPLACEMENTS = {
    "private_key": "[REDACTED_PRIVATE_KEY]",
    "credential_assignment": "[REDACTED_CREDENTIAL]",
    "bearer_token": "[REDACTED_BEARER_TOKEN]",
    "token": "[REDACTED_TOKEN]",
    "email": "[REDACTED_EMAIL]",
    "windows_home_path": "[REDACTED_HOST_PATH]",
    "unix_home_path": "[REDACTED_HOST_PATH]",
}


class ExportError(RuntimeError):
    """The historical artifact violates the export contract."""


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def _read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ExportError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ExportError(f"{label} must be a regular file, not a symlink or special file")
    if metadata.st_size > maximum:
        raise ExportError(f"{label} exceeds the {maximum}-byte bound")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ExportError(f"cannot read {label}: {error}") from error
    if len(data) != metadata.st_size:
        raise ExportError(f"{label} changed while it was read")
    return data


def redact_text(text: str, counts: dict[str, int]) -> str:
    """Redact known credential, identity, and host-path shapes."""
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ExportError(f"text value exceeds the {MAX_TEXT_BYTES}-byte bound")

    redacted = text
    for category, pattern in SENSITIVE_PATTERNS:
        replacement = REPLACEMENTS[category]

        def replace(match: re.Match[str]) -> str:
            counts[category] = counts.get(category, 0) + 1
            if category == "credential_assignment":
                return f"{match.group(1)}{match.group(2)}{replacement}"
            return replacement

        redacted = pattern.sub(replace, redacted)
    return redacted


def sensitive_matches(text: str) -> list[str]:
    """Return sensitive pattern categories still present in text."""
    return [
        category
        for category, pattern in SENSITIVE_PATTERNS
        if pattern.search(text)
    ]


def _validate_hex(value: str, length: int, label: str) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise ExportError(f"{label} must be exactly {length} lowercase hexadecimal characters")
    return value


def _open_read_only_database(path: Path) -> sqlite3.Connection:
    uri_path = quote(os.fspath(path.resolve()), safe="/")
    try:
        connection = sqlite3.connect(
            f"file:{uri_path}?mode=ro&immutable=1",
            uri=True,
            timeout=1.0,
        )
    except sqlite3.Error as error:
        raise ExportError(f"cannot open historical database read-only: {error}") from error
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    return connection


def _validate_database(connection: sqlite3.Connection) -> int:
    try:
        integrity = connection.execute("PRAGMA integrity_check(1)").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise ExportError("historical database integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ExportError("historical database contains a foreign-key violation")
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        user_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    except sqlite3.Error as error:
        raise ExportError(f"cannot validate historical database: {error}") from error
    if user_version != 7:
        raise ExportError(f"unsupported historical database schema version {user_version}; expected 7")
    if user_tables != set(TABLES):
        raise ExportError(
            "historical database has unexpected user tables; "
            f"expected {sorted(TABLES)}, got {sorted(user_tables)}"
        )
    return user_version


def _validate_table_schema(
    connection: sqlite3.Connection, table: str, expected_columns: Sequence[str]
) -> None:
    try:
        actual = tuple(row[1] for row in connection.execute(f'PRAGMA table_info("{table}")'))
    except sqlite3.Error as error:
        raise ExportError(f"cannot inspect table {table}: {error}") from error
    if actual != tuple(expected_columns):
        raise ExportError(
            f"historical table {table} has unexpected columns {actual!r}; expected {tuple(expected_columns)!r}"
        )


def _redact_value(value: Any, counts: dict[str, int]) -> Any:
    if value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ExportError("historical database contains a non-finite numeric value")
        return value
    if isinstance(value, str):
        return redact_text(value, counts)
    raise ExportError(f"unsupported SQLite value type {type(value).__name__}")


def _export_tables(
    connection: sqlite3.Connection, counts: dict[str, int]
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    exported: dict[str, list[dict[str, Any]]] = {}
    row_counts: dict[str, int] = {}
    total_rows = 0
    for table, (columns, ordering, row_limit) in TABLES.items():
        _validate_table_schema(connection, table, columns)
        column_list = ", ".join(f'"{column}"' for column in columns)
        query = f'SELECT {column_list} FROM "{table}" ORDER BY {ordering}'
        try:
            rows = connection.execute(query).fetchmany(row_limit + 1)
        except sqlite3.Error as error:
            raise ExportError(f"cannot export table {table}: {error}") from error
        if len(rows) > row_limit:
            raise ExportError(f"historical table {table} exceeds its {row_limit}-row bound")
        total_rows += len(rows)
        if total_rows > MAX_TOTAL_ROWS:
            raise ExportError(f"historical database exceeds the {MAX_TOTAL_ROWS}-row total bound")
        exported[table] = [
            {column: _redact_value(row[column], counts) for column in columns} for row in rows
        ]
        row_counts[table] = len(rows)
    return exported, row_counts


def _load_session_marker(path: Path, counts: dict[str, int]) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, MAX_SESSION_BYTES, "historical session marker")
    try:
        marker = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExportError(f"historical session marker is not valid UTF-8 JSON: {error}") from error
    if not isinstance(marker, dict) or tuple(sorted(marker)) != tuple(sorted(SESSION_FIELDS)):
        raise ExportError(f"historical session marker must contain exactly {SESSION_FIELDS!r}")
    if (
        not isinstance(marker["active_issue_id"], int)
        or isinstance(marker["active_issue_id"], bool)
        or not isinstance(marker["session_id"], int)
        or isinstance(marker["session_id"], bool)
    ):
        raise ExportError("historical session identifiers must be integers")
    if not isinstance(marker["started_at"], str):
        raise ExportError("historical session started_at must be a string")
    return {field: _redact_value(marker[field], counts) for field in SESSION_FIELDS}, raw


def _group_counts(rows: Iterable[Mapping[str, Any]], field: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows:
        value = row[field]
        key = "null" if value is None else str(value)
        result[key] = result.get(key, 0) + 1
    return dict(sorted(result.items()))


def build_export(
    database_path: Path,
    session_path: Path,
    *,
    source_commit: str,
    database_blob: str,
    session_blob: str,
) -> dict[str, Any]:
    """Build the canonical export value without writing it."""
    source_commit = _validate_hex(source_commit, 40, "source commit")
    database_blob = _validate_hex(database_blob, 40, "database blob")
    session_blob = _validate_hex(session_blob, 40, "session blob")
    database_raw = _read_regular_file(database_path, MAX_DATABASE_BYTES, "historical database")
    redaction_counts: dict[str, int] = {}
    connection = _open_read_only_database(database_path)
    try:
        user_version = _validate_database(connection)
        tables, row_counts = _export_tables(connection, redaction_counts)
    finally:
        connection.close()
    active_marker, session_raw = _load_session_marker(session_path, redaction_counts)

    session_rows = [row for row in tables["sessions"] if row["id"] == active_marker["session_id"]]
    if len(session_rows) != 1:
        raise ExportError("active session marker does not identify exactly one exported session")
    session_row = session_rows[0]
    if (
        session_row["active_issue_id"] != active_marker["active_issue_id"]
        or session_row["started_at"] != active_marker["started_at"]
    ):
        raise ExportError("active session marker disagrees with the exported session row")

    return {
        "schema": EXPORT_SCHEMA,
        "version": EXPORT_VERSION,
        "source": {
            "repository_commit": source_commit,
            "database": {
                "git_blob": database_blob,
                "sha256": sha256_bytes(database_raw),
                "size_bytes": len(database_raw),
                "sqlite_user_version": user_version,
            },
            "session_marker": {
                "git_blob": session_blob,
                "sha256": sha256_bytes(session_raw),
                "size_bytes": len(session_raw),
            },
        },
        "integrity": {"sqlite_integrity": "ok", "foreign_key_violations": 0},
        "redaction": {
            "policy_version": REDACTION_POLICY_VERSION,
            "counts": dict(sorted(redaction_counts.items())),
            "total": sum(redaction_counts.values()),
        },
        "summary": {
            "table_rows": row_counts,
            "issue_status": _group_counts(tables["issues"], "status"),
            "issue_priority": _group_counts(tables["issues"], "priority"),
        },
        "active_session_marker": active_marker,
        "tables": tables,
    }


def encode_export(export: Mapping[str, Any]) -> bytes:
    """Encode an export using its canonical byte representation."""
    try:
        serialized = json.dumps(
            export,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ExportError(f"historical export is not canonical JSON: {error}") from error
    encoded = (serialized + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ExportError(f"historical export exceeds the {MAX_OUTPUT_BYTES}-byte bound")
    return encoded


def write_export(path: Path, encoded: bytes) -> None:
    """Create or replace the export without following a destination symlink."""
    if path.exists() and path.is_symlink():
        raise ExportError("export destination must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        cleanup_error: OSError | None = None
        try:
            temporary.unlink()
        except FileNotFoundError as missing:
            cleanup_error = missing
        except OSError as cleanup_failure:
            cleanup_error = cleanup_failure
        detail = f"cannot publish historical export: {error}"
        if cleanup_error is not None and not isinstance(cleanup_error, FileNotFoundError):
            detail += f"; temporary cleanup also failed: {cleanup_error}"
        raise ExportError(detail) from error


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--session", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--database-blob", required=True)
    parser.add_argument("--session-blob", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        exported = build_export(
            arguments.database,
            arguments.session,
            source_commit=arguments.source_commit,
            database_blob=arguments.database_blob,
            session_blob=arguments.session_blob,
        )
        encoded = encode_export(exported)
        write_export(arguments.output, encoded)
    except ExportError as error:
        print(json.dumps({"schema": "openclaudia.legacy-export-result", "status": "rejected", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema": "openclaudia.legacy-export-result",
                "status": "exported",
                "output": arguments.output.as_posix(),
                "sha256": sha256_bytes(encoded),
                "size_bytes": len(encoded),
                "table_rows": exported["summary"]["table_rows"],
                "redactions": exported["redaction"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
