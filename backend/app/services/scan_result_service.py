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

from app.core.security.desensitize import mask_snippet, mask_untrusted_text
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

# Stable field order for summary (includes truncation metadata).
_SUMMARY_FIELDS = (
    "total_findings",
    "blocking_findings",
    "total_notices",
    "total_skipped_files",
    "total_scan_errors",
    "total_files_scanned",
    "total_lines_scanned",
    "returned_findings",
    "findings_truncated",
    "returned_notices",
    "notices_truncated",
    "returned_skipped_files",
    "skipped_files_truncated",
    "returned_scan_errors",
    "scan_errors_truncated",
)

# Risk-priority ordering for severity and confidence.
# Lower number = higher priority = retained first when truncating.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_CONFIDENCE_ORDER = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}


class ScanResultTooLargeError(Exception):
    """Raised when serialized result_json exceeds scan_max_result_json_bytes.

    The caller (background_runner) catches this and maps it to the
    fixed error code SCAN_RESULT_TOO_LARGE.
    """
    pass


# ---------------------------------------------------------------------------
# --- Defensive re-sanitization at the persistence boundary ---
# ---------------------------------------------------------------------------
#
# P0-4 models only sanitize file_path in __post_init__. We CANNOT assume
# that snippet_masked, description, message, notice.message, skipped.reason,
# error_type, or error_message are always safe — a buggy rule, a future
# code change, or a direct dataclass construction could place raw secret
# content into these fields.
#
# These functions re-apply masking at the persistence boundary, providing
# defense in depth. They are idempotent: already-masked values pass through
# unchanged.

def _safe_snippet(value: Optional[str]) -> Optional[str]:
    """Re-apply mask_snippet to a snippet string.

    mask_snippet is the strongest masking — it handles assignment values,
    explicit-format tokens, and connection strings. Used for snippet_masked
    which is the field most likely to contain secret-adjacent content.
    """
    if value is None:
        return value
    return mask_snippet(value)


def _safe_text(value: Optional[str]) -> Optional[str]:
    """Re-apply mask_untrusted_text to an arbitrary string field.

    Used for description, message, notice.message, skipped.reason,
    error_type, error_message — any string that could potentially be
    influenced by repository content.
    """
    if value is None:
        return value
    return mask_untrusted_text(value)


def _safe_path(value: Optional[str]) -> Optional[str]:
    """Re-apply mask_untrusted_text to a file_path string.

    Double defense: file_path is already sanitized in __post_init__,
    but we re-sanitize at the persistence boundary to guarantee
    no secret can enter the database.
    """
    if value is None:
        return value
    return mask_untrusted_text(value)


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

    String fields that could be influenced by repo content are re-sanitized
    via _safe_snippet / _safe_text / _safe_path at the persistence boundary.
    Enums, ints, bools, and None preserve their original types.
    """
    result: dict[str, Any] = {}
    for field in _FINDING_FIELDS:
        val = getattr(finding, field)
        if field in ("severity", "confidence", "finding_type"):
            # Enums → stable string values
            result[field] = _serialize_enum(val)
        elif field == "snippet_masked":
            # Re-apply mask_snippet (strongest masking)
            result[field] = _safe_snippet(val)
        elif field == "file_path":
            # Double defense — re-sanitize path
            result[field] = _safe_path(val)
        elif field in ("description", "message"):
            # Re-sanitize arbitrary text that could contain repo content
            result[field] = _safe_text(val)
        else:
            # rule_id, rule_name, category, secret_type, repair_template_key
            # are rule-defined constants, not influenced by repo content.
            result[field] = val
    return result


def _serialize_notice(notice: ScanNotice) -> dict:
    """Convert a ScanNotice to a dict with stable field ordering.

    message and file_path are re-sanitized at the persistence boundary.
    """
    result: dict[str, Any] = {}
    for field in _NOTICE_FIELDS:
        val = getattr(notice, field)
        if field == "message":
            result[field] = _safe_text(val)
        elif field == "file_path":
            result[field] = _safe_path(val)
        else:
            result[field] = val
    return result


def _serialize_skipped(skipped: SkippedFile) -> dict:
    """Convert a SkippedFile to a dict with stable field ordering.

    reason and file_path are re-sanitized at the persistence boundary.
    """
    result: dict[str, Any] = {}
    for field in _SKIPPED_FIELDS:
        val = getattr(skipped, field)
        if field == "reason":
            result[field] = _safe_text(val)
        elif field == "file_path":
            result[field] = _safe_path(val)
        else:
            result[field] = val
    return result


def _serialize_error(error: ScanError) -> dict:
    """Convert a ScanError to a dict with stable field ordering.

    error_type, error_message, and file_path are re-sanitized at the
    persistence boundary.
    """
    result: dict[str, Any] = {}
    for field in _ERROR_FIELDS:
        val = getattr(error, field)
        if field in ("error_type", "error_message"):
            result[field] = _safe_text(val)
        elif field == "file_path":
            result[field] = _safe_path(val)
        else:
            result[field] = val
    return result


def _truncate_findings(
    findings: tuple[Finding, ...], limit: int
) -> tuple[list[Finding], bool]:
    """Truncate findings to limit using risk-priority retention.

    Priority order (highest first):
    1. is_blocking = True
    2. severity: critical > high > medium > low > info
    3. confidence: high > medium > low
    4. original position (earlier items retained first for same risk)

    This ensures blocking findings are NEVER squeezed out by large
    numbers of low-severity findings.

    Defensive: limit is clamped to max(1, int(limit)) to prevent
    runtime monkeypatch or corrupted config from causing items[:-1]
    (negative) or items[:0] (zero) behavior.

    Returns (truncated_list, was_truncated).
    """
    limit = max(1, int(limit))
    if len(findings) <= limit:
        return list(findings), False
    indexed = list(enumerate(findings))
    indexed.sort(key=lambda x: (
        0 if x[1].is_blocking else 1,
        _SEVERITY_ORDER[x[1].severity],
        _CONFIDENCE_ORDER[x[1].confidence],
        x[0],  # original position — stable tiebreaker
    ))
    return [f for _, f in indexed[:limit]], True


def _truncate_collection(
    items: tuple, limit: int
) -> tuple[list, bool]:
    """Truncate a collection to limit, preserving original order.

    Defensive: limit is clamped to max(1, int(limit)) to prevent
    runtime monkeypatch or corrupted config from causing items[:-1]
    (negative) or items[:0] (zero) behavior.

    Returns (truncated_list, was_truncated).
    """
    limit = max(1, int(limit))
    if len(items) <= limit:
        return list(items), False
    return list(items[:limit]), True


def _compute_summary(
    scan_result: ScanResult,
    findings_list: list,
    notices_list: list,
    skipped_list: list,
    errors_list: list,
    findings_truncated: bool,
    notices_truncated: bool,
    skipped_truncated: bool,
    errors_truncated: bool,
) -> dict:
    """Compute summary statistics from a ScanResult.

    total_* fields reflect the ACTUAL scan detection counts (not truncated).
    returned_* and *_truncated fields reflect what was persisted.
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
        "returned_findings": len(findings_list),
        "findings_truncated": findings_truncated,
        "returned_notices": len(notices_list),
        "notices_truncated": notices_truncated,
        "returned_skipped_files": len(skipped_list),
        "skipped_files_truncated": skipped_truncated,
        "returned_scan_errors": len(errors_list),
        "scan_errors_truncated": errors_truncated,
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
    - Re-sanitizes all string fields at the persistence boundary
    - Truncates collections to task-level limits (risk-priority for findings)
    - summary.total_* = actual scan counts; returned_* = persisted counts

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
    from app.core.config import settings

    # Truncate collections to task-level limits BEFORE serialization
    truncated_findings, findings_truncated = _truncate_findings(
        scan_result.findings,
        settings.scan_max_persisted_findings_per_task,
    )
    truncated_notices, notices_truncated = _truncate_collection(
        scan_result.notices,
        settings.scan_max_persisted_notices_per_task,
    )
    truncated_skipped, skipped_truncated = _truncate_collection(
        scan_result.skipped_files,
        settings.scan_max_persisted_skipped_files_per_task,
    )
    truncated_errors, errors_truncated = _truncate_collection(
        scan_result.scan_errors,
        settings.scan_max_persisted_scan_errors_per_task,
    )

    # Serialize each (possibly truncated) collection
    findings_list = [_serialize_finding(f) for f in truncated_findings]
    notices_list = [_serialize_notice(n) for n in truncated_notices]
    skipped_list = [_serialize_skipped(s) for s in truncated_skipped]
    errors_list = [_serialize_error(e) for e in truncated_errors]

    summary = _compute_summary(
        scan_result,
        findings_list,
        notices_list,
        skipped_list,
        errors_list,
        findings_truncated,
        notices_truncated,
        skipped_truncated,
        errors_truncated,
    )

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

    Uses SQLite native upsert (INSERT ON CONFLICT DO UPDATE) — created_at
    is preserved on update, only updated_at changes.

    Args:
        task_id:      The task ID this result belongs to.
        scan_result:  The ScanResult from scan_directory().

    Raises:
        ScanResultTooLargeError: If serialized result_json exceeds
            scan_max_result_json_bytes. The caller must handle this
            and mark the task as failed with SCAN_RESULT_TOO_LARGE.
        sqlite3.Error: If the database operation fails. The caller must
                       handle this and mark the task as failed with
                       SCAN_RESULT_PERSIST_FAILED.
    """
    from app.core.config import settings

    init_db()
    now = now_iso()

    # Serialize BEFORE opening the transaction — if serialization fails,
    # we don't want a half-open transaction.
    result_dict = serialize_scan_result(scan_result)
    result_json = json.dumps(result_dict, ensure_ascii=False, sort_keys=True)

    # Check byte size limit — refuse to persist oversized snapshots
    if len(result_json.encode("utf-8")) > settings.scan_max_result_json_bytes:
        raise ScanResultTooLargeError(
            "result_json exceeds scan_max_result_json_bytes"
        )

    summary = result_dict["summary"]
    summary_json = json.dumps(
        summary,
        ensure_ascii=False,
        sort_keys=True,
    )

    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO scan_results
               (task_id, schema_version, result_json, summary_json,
                total_findings, blocking_findings, total_notices,
                total_skipped_files, total_scan_errors,
                total_files_scanned, total_lines_scanned,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(task_id) DO UPDATE SET
                   schema_version=excluded.schema_version,
                   result_json=excluded.result_json,
                   summary_json=excluded.summary_json,
                   total_findings=excluded.total_findings,
                   blocking_findings=excluded.blocking_findings,
                   total_notices=excluded.total_notices,
                   total_skipped_files=excluded.total_skipped_files,
                   total_scan_errors=excluded.total_scan_errors,
                   total_files_scanned=excluded.total_files_scanned,
                   total_lines_scanned=excluded.total_lines_scanned,
                   updated_at=excluded.updated_at""",
            (
                task_id,
                SCHEMA_VERSION,
                result_json,
                summary_json,
                summary["total_findings"],
                summary["blocking_findings"],
                summary["total_notices"],
                summary["total_skipped_files"],
                summary["total_scan_errors"],
                summary["total_files_scanned"],
                summary["total_lines_scanned"],
                now,  # created_at — only set on first INSERT, preserved on UPDATE
                now,  # updated_at — always updated
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
    The returned dict includes both total_* (actual scan counts) and
    returned_* / *_truncated (persisted subset metadata).

    Normal path reads ONLY summary_json — a lightweight column that
    never exceeds a few hundred bytes. This avoids loading and parsing
    the full result_json (up to 8 MB) on every status poll.

    Fallback path: for old records created before the summary_json
    column existed (summary_json is NULL or empty), falls back to
    reading result_json. New records must NEVER enter this path —
    save_scan_result always sets summary_json.

    Args:
        task_id: The task ID to look up.

    Returns:
        A dict with total_findings, blocking_findings, total_notices,
        total_skipped_files, total_scan_errors, total_files_scanned,
        total_lines_scanned, returned_findings, findings_truncated,
        returned_notices, notices_truncated, returned_skipped_files,
        skipped_files_truncated, returned_scan_errors,
        scan_errors_truncated — or None if not found.
    """
    init_db()
    conn = _get_connection()
    try:
        # Normal path: read only summary_json (lightweight).
        row = conn.execute(
            "SELECT summary_json FROM scan_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None

        summary_json = row["summary_json"]
        if summary_json:
            # Normal path — summary_json exists and is valid.
            return json.loads(summary_json)

        # Fallback for old records (summary_json is NULL or empty).
        # These are records created before the summary_json column
        # was added. Only in this case do we read the full result_json.
        # New records must NEVER enter this path.
        row = conn.execute(
            "SELECT result_json FROM scan_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        result_dict = json.loads(row["result_json"])
        return result_dict.get("summary")
    finally:
        conn.close()
