"""Scan result persistence service — serialization, storage, and retrieval.

Security guarantees:
- serialize_scan_result() uses EXPLICIT field-by-field conversion.
  It NEVER calls json.dumps on unknown internal objects or uses
  recursive serialization that could leak raw values.
- All Finding/ScanNotice/SkippedFile/ScanError fields are already
  desensitized by P0-4 (mask_untrusted_text in __post_init__).
- result_json contains ONLY the public result model — no Assignment,
  no temp paths, no raw secrets, no internal exception objects.
- save_scan_result() uses parameterized SQL (safe upsert) — no string
  interpolation, immune to SQL injection.
- get_scan_result() and get_scan_summary() return desensitized data
  directly from the persisted result_json.

Schema version:
- Current: 1
- Increment when the result_json structure changes in a breaking way.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from app.db.database import _get_connection, init_db, now_iso
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanError,
    ScanNotice,
    ScanResult,
    Severity,
    SkippedFile,
)

# --- Constants ---

SCHEMA_VERSION = 1

# Stable field order for Finding serialization (deterministic JSON output).
_FINDING_FIELDS = (
    "rule_id",
    "rule_name",
    "severity",
    "confidence",
    "file_path",
    "line_start",
    "line_end",
    "column_start",
    "column_end",
    "snippet_masked",
    "is_blocking",
    "finding_type",
    "description",
    "category",
    "secret_type",
    "message",
    "repair_template_key",
)

# Stable field order for ScanNotice serialization.
_NOTICE_FIELDS = (
    "rule_id",
    "message",
    "file_path",
)

# Stable field order for SkippedFile serialization.
_SKIPPED_FIELDS = (
    "file_path",
    "reason",
)

# Stable field order for ScanError serialization.
_ERROR_FIELDS = (
    "file_path",
    "error_type",
    "error_message",
)

# Stable field order for summary.
_SUMMARY_FIELDS = (
    "total_findings",
    "blocking_findings",
    "total_notices",
    "total_skipped_files",
    "total_scan_errors",
    "total_files_scanned",
    "total_lines_scanned",
)


# ---------------------------------------------------------------------------
# --- Serialization (explicit, no recursive serialization) ---
# ---------------------------------------------------------------------------

def _serialize_enum(value: Any) -> str:
    """Convert an enum to its stable string value.

    All scanner enums inherit from str, so .value gives the stable string.
    """
    if isinstance(value, (Severity, Confidence, FindingType)):
        return value.value
    return str(value)


def _serialize_finding(finding: Finding) -> dict:
    """Convert a single Finding to a dict with stable field ordering.

    Uses getattr with explicit field names — never vars() or __dict__
    to avoid leaking internal state or future private fields.
    """
    result: dict[str, Any] = {}
    for field in _FINDING_FIELDS:
        val = getattr(finding, field)
        # Convert enums to stable string values
        if field in ("severity", "confidence", "finding_type"):
            result[field] = _serialize_enum(val)
        else:
            result[field] = val
    return result


def _serialize_notice(notice: ScanNotice) -> dict:
    """Convert a ScanNotice to a dict with stable field ordering."""
    result: dict[str, Any] = {}
    for field in _NOTICE_FIELDS:
        result[field] = getattr(notice, field)
    return result


def _serialize_skipped(skipped: SkippedFile) -> dict:
    """Convert a SkippedFile to a dict with stable field ordering."""
    result: dict[str, Any] = {}
    for field in _SKIPPED_FIELDS:
        result[field] = getattr(skipped, field)
    return result


def _serialize_error(error: ScanError) -> dict:
    """Convert a ScanError to a dict with stable field ordering."""
    result: dict[str, Any] = {}
    for field in _ERROR_FIELDS:
        result[field] = getattr(error, field)
    return result


def _compute_summary(scan_result: ScanResult) -> dict:
    """Compute summary statistics from a ScanResult.

    Counts are derived from the tuple collections — not from separate
    counters — to ensure consistency.
    """
    findings = scan_result.findings
    blocking_count = sum(1 for f in findings if f.is_blocking)
    return {
        "total_findings": len(findings),
        "blocking_findings": blocking_count,
        "total_notices": len(scan_result.notices),
        "total_skipped_files": len(scan_result.skipped_files),
        "total_scan_errors": len(scan_result.scan_errors),
        "total_files_scanned": scan_result.total_files_scanned,
        "total_lines_scanned": scan_result.total_lines_scanned,
    }


def serialize_scan_result(scan_result: ScanResult) -> dict:
    """Convert a ScanResult to a safe, deterministic dict for persistence.

    This is the ONLY function that should be used to prepare a ScanResult
    for database storage. It:
    - Uses explicit field-by-field conversion (no recursive serialization)
    - Converts enums to stable string values
    - Converts tuples to JSON arrays (via list())
    - Preserves None as null
    - Produces deterministic field ordering
    - Never includes raw secrets (guaranteed by P0-4 desensitization)

    Args:
        scan_result: A ScanResult from scan_directory().

    Returns:
        A dict with the fixed top-level structure:
        {
            "schema_version": 1,
            "findings": [...],
            "notices": [...],
            "skipped_files": [...],
            "scan_errors": [...],
            "summary": {...}
        }
    """
    # Convert tuples to lists (tuples become JSON arrays)
    findings_list = [_serialize_finding(f) for f in scan_result.findings]
    notices_list = [_serialize_notice(n) for n in scan_result.notices]
    skipped_list = [_serialize_skipped(s) for s in scan_result.skipped_files]
    errors_list = [_serialize_error(e) for e in scan_result.scan_errors]

    summary = _compute_summary(scan_result)

    # Build result with fixed key ordering
    return {
        "schema_version": SCHEMA_VERSION,
        "findings": findings_list,
        "notices": notices_list,
        "skipped_files": skipped_list,
        "scan_errors": errors_list,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# --- Database operations ---
# ---------------------------------------------------------------------------

def save_scan_result(task_id: str, scan_result: ScanResult) -> None:
    """Persist a scan result snapshot for a task.

    Uses INSERT OR REPLACE (safe upsert) — if a row for this task_id
    already exists, it is replaced atomically.

    Args:
        task_id:      The task ID this result belongs to.
        scan_result:  The ScanResult from scan_directory().

    Raises:
        sqlite3.Error: If the database operation fails. The caller must
                       handle this and mark the task as failed with
                       SCAN_RESULT_PERSIST_FAILED.
    """
    init_db()
    now = now_iso()

    # Serialize BEFORE opening the transaction — if serialization fails,
    # we don't want a half-open transaction.
    result_dict = serialize_scan_result(scan_result)
    result_json = json.dumps(result_dict, ensure_ascii=False, sort_keys=True)

    summary = result_dict["summary"]

    conn = _get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO scan_results
               (task_id, schema_version, result_json,
                total_findings, blocking_findings, total_notices,
                total_skipped_files, total_scan_errors,
                total_files_scanned, total_lines_scanned,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id,
                SCHEMA_VERSION,
                result_json,
                summary["total_findings"],
                summary["blocking_findings"],
                summary["total_notices"],
                summary["total_skipped_files"],
                summary["total_scan_errors"],
                summary["total_files_scanned"],
                summary["total_lines_scanned"],
                now,  # created_at (first insert) — replaced on upsert
                now,  # updated_at
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan_result(task_id: str) -> Optional[dict]:
    """Get the full persisted scan result for a task.

    Returns None if no result has been persisted for this task_id.
    The returned dict has the same structure as serialize_scan_result().

    Args:
        task_id: The task ID to look up.

    Returns:
        A dict with findings, notices, skipped_files, scan_errors,
        summary, and schema_version — or None if not found.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT result_json FROM scan_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["result_json"])
    finally:
        conn.close()


def get_scan_summary(task_id: str) -> Optional[dict]:
    """Get only the summary portion of a persisted scan result.

    Returns None if no result has been persisted for this task_id.
    The returned dict has stable field ordering matching _SUMMARY_FIELDS.

    Args:
        task_id: The task ID to look up.

    Returns:
        A dict with total_findings, blocking_findings, total_notices,
        total_skipped_files, total_scan_errors, total_files_scanned,
        total_lines_scanned — or None if not found.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            """SELECT total_findings, blocking_findings, total_notices,
                      total_skipped_files, total_scan_errors,
                      total_files_scanned, total_lines_scanned
               FROM scan_results WHERE task_id = ?""",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        # Build dict with stable field ordering
        return {
            field: row[col]
            for col, field in enumerate(_SUMMARY_FIELDS)
        }
    finally:
        conn.close()
