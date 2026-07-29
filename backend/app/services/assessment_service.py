"""Security assessment engine — deterministic scoring from persisted scan results.

This module reads ALREADY-PERSISTED, ALREADY-DESENSITIZED scan results
from the scan_results table and computes a deterministic security
assessment score.

SECURITY:
- NEVER reads from temp directories.
- NEVER executes repository code.
- NEVER accesses the network.
- NEVER calls an LLM.
- Only reads the desensitized result_json / summary_json from SQLite.
- assessment_json output contains NO raw secrets, NO temp paths,
  NO internal exception objects.
- The persistence boundary (save_assessment_result) applies a SECOND
  defensive desensitization pass via mask_untrusted_text on all string
  fields, even though P0-5 already desensitized the input.
- The serialization boundary (serialize_assessment_result) enforces
  strict field whitelists — unknown fields are discarded.

DETERMINISM:
- Same (policy_version, persisted ScanResult, summary) → identical output.
- Finding order within a rule_id is deterministically sorted before
  applying repeat multipliers.
- score_breakdown is sorted by rule_id (alphabetical).
- score_caps are sorted by (cap_value ASC, reason_code ASC).
- Only created_at, updated_at, task_id may differ between runs.

TIMESTAMPS:
- assess_scan_result returns None for created_at and updated_at.
- save_assessment_result determines the final timestamps in a single
  persistence flow:
  - First save: created_at = now, updated_at = now.
  - Upsert: created_at preserved from existing row, updated_at = now.
- The same timestamp values are used in both assessment_json and the
  database columns, ensuring consistency.

ASYNC:
- Database reads/writes and assessment computation are synchronous.
- Callers MUST wrap them in asyncio.to_thread() to avoid blocking
  the FastAPI event loop.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from app.core.config import settings
from app.core.security.desensitize import mask_untrusted_text
from app.db.database import _get_connection, init_db, now_iso
from app.services.assessment_policy import (
    ASSESSMENT_SCHEMA_VERSION,
    ASSESSMENT_SCOPE,
    BASE_SCORE,
    BLOCKING_CONFIDENCE_OVERRIDE,
    CONFIDENCE_PERCENT,
    MIN_SCORE,
    POLICY_VERSION,
    RULE_CAP_BY_SEVERITY,
    SEVERITY_BASE_POINTS,
    compute_single_deduction,
    determine_coverage_status,
    determine_triggered_caps,
    determine_verdict,
    get_repeat_percent,
    sort_caps,
    COVERAGE_COMPLETE,
    COVERAGE_PARTIAL,
)

# Severity ordering for deterministic sort (lower = higher priority).
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Confidence ordering for deterministic sort (lower = higher priority).
_CONFIDENCE_ORDER: dict[str, int] = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


class AssessmentResultTooLargeError(Exception):
    """Raised when serialized assessment_json exceeds assessment_max_json_bytes.

    The caller (background_runner) catches this and maps it to the
    fixed error code ASSESSMENT_RESULT_TOO_LARGE.
    """
    pass


class AssessmentInternalError(Exception):
    """Raised when reading or parsing a persisted scan result fails,
    or when assessment computation fails.

    The caller (background_runner) catches this and maps it to the
    fixed error code ASSESSMENT_INTERNAL_ERROR.
    """
    pass


class AssessmentPersistError(Exception):
    """Raised when SQLite assessment persistence fails.

    The caller (background_runner) catches this and maps it to the
    fixed error code ASSESSMENT_PERSIST_FAILED.
    """
    pass


class AssessmentSerializationError(AssessmentInternalError):
    """Raised when a value cannot be safely serialized for persistence.

    This is a subclass of AssessmentInternalError so that callers
    catching AssessmentInternalError will also catch this.

    The exception message NEVER contains:
    - The original value
    - repr(value) or str(value)
    - Type module paths
    - Database information
    - Temp absolute paths
    """
    pass


# ---------------------------------------------------------------------------
# --- Explicit serialization boundary ---
# ---------------------------------------------------------------------------
#
# serialize_assessment_result is the ONLY function that builds the dict
# that gets persisted as assessment_json. It enforces:
# 1. Strict top-level field whitelist (unknown fields are discarded).
# 2. Forced canonical values for schema_version, policy_version,
#    assessment_scope, and task_id (never trusts the input dict).
# 3. Type validation for score, score_before_caps, and verdict.
# 4. Per-field whitelist for all nested structures.
# 5. Strict string type enforcement — only str and None are accepted.
#    Non-str/non-None values raise AssessmentSerializationError.
# 6. Defensive desensitization via mask_untrusted_text on all string
#    fields that could carry untrusted content.
# 7. Safe file path display via sanitize_assessment_file_path.
# 8. Absolute path removal from description text via _clean_path_from_text.
# 9. No vars(), __dict__, asdict, or recursive serialization of unknown
#    objects — every field is explicitly constructed.


def _strict_str(value: Any) -> str:
    """Convert a value to str with strict type checking.

    Only str and None are accepted. None is converted to empty string.
    Non-str and non-None values raise AssessmentSerializationError.

    The exception message does NOT contain:
    - The original value
    - repr(value) or str(value)
    - Type module paths
    - Database information
    - Temp paths
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    raise AssessmentSerializationError(
        "Non-string value rejected by strict serialization boundary"
    )


def _strict_int(value: Any, minimum: int | None = None,
                maximum: int | None = None) -> int:
    """Validate that a value is a strict int (not bool, not str).

    Uses type(value) is int — NOT isinstance — because bool is a
    subclass of int in Python and must be rejected.

    If minimum or maximum is provided, the value must be within
    the inclusive range. Out-of-range values raise
    AssessmentSerializationError — they are NOT clamped.

    The exception message never contains the original value.
    """
    if type(value) is not int:
        raise AssessmentSerializationError(
            "Non-integer value rejected by strict serialization boundary"
        )
    if minimum is not None and value < minimum:
        raise AssessmentSerializationError(
            "Integer value below minimum rejected"
        )
    if maximum is not None and value > maximum:
        raise AssessmentSerializationError(
            "Integer value above maximum rejected"
        )
    return value


def _strict_bool(value: Any) -> bool:
    """Validate that a value is a strict bool.

    Uses type(value) is bool — NOT isinstance — because int values
    like 0 and 1 must NOT be silently converted to bool.

    The exception message never contains the original value.
    """
    if type(value) is not bool:
        raise AssessmentSerializationError(
            "Non-boolean value rejected by strict serialization boundary"
        )
    return value


_VALID_VERDICTS = ("pass", "warning", "blocked")


def _safe_masked_str(value: Any) -> str:
    """Strict string conversion + defensive desensitization.

    Only accepts str or None. Applies mask_untrusted_text after
    strict type validation.

    mask_untrusted_text is idempotent: re-processing an already-masked
    string produces the same output.
    """
    return mask_untrusted_text(_strict_str(value))


def _safe_masked_desc(value: Any) -> str:
    """Strict string + mask_untrusted_text + absolute path removal.

    For description and reason fields that may contain injected
    absolute temp paths. After masking secrets, removes any remaining
    absolute path patterns and replaces them with "<redacted-path>".
    """
    s = _strict_str(value)
    s = mask_untrusted_text(s)
    s = _clean_path_from_text(s)
    return s


# --- Safe file path display ---

_REDACTED_PATH = "<redacted-path>"

# Any path starting with / is a POSIX absolute path — reject all of them,
# not just /tmp, /var/tmp, /home, /Users.
_POSIX_ABSOLUTE_RE = re.compile(r'^/')
# Windows drive paths: C:\... or C:/...
_WINDOWS_DRIVE_RE = re.compile(r'^[A-Za-z]:[/\\]')
# UNC paths: \\server\share or //server/share
_UNC_RE = re.compile(r'^(?:\\\\|//)')
# Windows rooted paths without drive: \rooted\secret
_WINDOWS_ROOTED_RE = re.compile(r'^\\')
# User home paths: ~/... or ~\...
_USER_HOME_RE = re.compile(r'^~[/\\]')


def sanitize_assessment_file_path(value: str | None) -> str:
    """Sanitize a file path for safe display.

    1. Strict string type check (only str and None accepted).
    2. mask_untrusted_text for secret masking.
    3. Only allow repo-relative paths.

    Detects and redacts ALL non-repo-relative paths:
    - Any POSIX absolute path: /etc/passwd, /root/.ssh, /opt/app, /tmp/...
    - Windows drive paths: C:\\..., C:/...
    - UNC paths: \\\\server\\share\\..., //server/share/...
    - Windows rooted paths without drive: \\rooted\\secret
    - User home paths: ~/..., ~\\...
    - Path traversal: any component equal to ..
    - NUL character

    Returns "<redacted-path>" for dangerous paths.
    Does not preserve basename, parent directory, or task ID.

    Idempotent: re-processing an already-redacted value is stable.
    """
    # Step 1: Strict string type check
    s = _strict_str(value)

    # Step 2: Mask secrets in the path
    s = mask_untrusted_text(s)

    # Step 3: Check for NUL character
    if '\x00' in s:
        return _REDACTED_PATH

    # Step 4: Check for dangerous path forms
    if _POSIX_ABSOLUTE_RE.match(s):
        return _REDACTED_PATH
    if _WINDOWS_DRIVE_RE.match(s):
        return _REDACTED_PATH
    if _UNC_RE.match(s):
        return _REDACTED_PATH
    if _WINDOWS_ROOTED_RE.match(s):
        return _REDACTED_PATH
    if _USER_HOME_RE.match(s):
        return _REDACTED_PATH

    # Step 5: Check for path traversal (any component equals ..)
    # Normalize separators to / for consistent checking.
    normalized = s.replace('\\', '/')
    parts = normalized.split('/')
    if '..' in parts:
        return _REDACTED_PATH

    return s


# --- Absolute path removal from text ---

# Single unified regex with longest-prefix-first alternation.
# /var/tmp/ MUST come before /tmp/ to prevent partial matching
# that leaves "/var" as a residual.
# Stop at whitespace, quotes, and angle brackets to avoid over-matching.
_PATH_TEXT_RE = re.compile(
    r'/var/tmp/[^\s"\'<>]*'      # /var/tmp/... (longest prefix first)
    r'|/tmp/[^\s"\'<>]*'          # /tmp/...
    r'|/home/[^\s"\'<>]*'         # /home/...
    r'|/Users/[^\s"\'<>]*'        # /Users/...
    r'|/[A-Za-z][^\s"\'<>]*'      # Any other POSIX absolute: /etc/..., /root/..., /opt/...
    r'|[A-Za-z]:[/\\][^\s"\'<>]*' # Windows drive: C:\..., C:/...
    r'|\\\\[^\s"\'<>]*'           # UNC backslash: \\server\share...
    r'|//[^\s"\'<>]*'             # UNC forward slash: //server/share...
)


def _clean_path_from_text(text: str) -> str:
    """Remove absolute temp paths from text.

    Replaces detected absolute paths with "<redacted-path>".
    Does not preserve basename, parent dir, or task ID.

    Uses a single unified regex with longest-prefix-first alternation
    so that /var/tmp/... is matched as a whole, not partially as
    /tmp/... leaving /var as residue.

    Detects:
    - /var/tmp/..., /tmp/..., /home/..., /Users/..., /etc/..., /root/..., etc.
    - Windows drive absolute paths: C:\\..., C:/...
    - UNC paths: \\\\server\\share\\..., //server/share\\...
    """
    return _PATH_TEXT_RE.sub(_REDACTED_PATH, text)


# --- Per-field whitelist serializers ---

def _serialize_score_breakdown_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Whitelist and mask a single score_breakdown entry.

    Allowed fields:
    - reason_code, rule_id, category, severity (masked strings)
    - finding_count, deduction_before_rule_cap, rule_cap,
      applied_deduction (ints)
    - occurrence_deductions (list of ints)
    - description (masked string with path cleaning)
    """
    if not isinstance(entry, dict):
        raise AssessmentSerializationError(
            "score_breakdown entry must be a dict"
        )

    _occurrence_deductions = entry.get("occurrence_deductions", [])
    if not isinstance(_occurrence_deductions, list):
        raise AssessmentSerializationError(
            "occurrence_deductions must be a list"
        )
    occurrence_deductions = [
        _strict_int(d) for d in _occurrence_deductions
    ]

    return {
        "reason_code": _safe_masked_str(entry.get("reason_code")),
        "rule_id": _safe_masked_str(entry.get("rule_id")),
        "category": _safe_masked_str(entry.get("category")),
        "severity": _safe_masked_str(entry.get("severity")),
        "finding_count": _strict_int(entry.get("finding_count", 0)),
        "occurrence_deductions": occurrence_deductions,
        "deduction_before_rule_cap": _strict_int(
            entry.get("deduction_before_rule_cap", 0)
        ),
        "rule_cap": _strict_int(entry.get("rule_cap", 0)),
        "applied_deduction": _strict_int(entry.get("applied_deduction", 0)),
        "description": _safe_masked_desc(entry.get("description")),
    }


def _serialize_score_cap_entry(cap: dict[str, Any]) -> dict[str, Any]:
    """Whitelist and mask a single score_caps entry.

    Allowed fields:
    - reason_code, description (masked strings with path cleaning)
    - cap_value, score_before_cap, score_after_cap (ints)
    - applied (bool)
    """
    if not isinstance(cap, dict):
        raise AssessmentSerializationError(
            "score_caps entry must be a dict"
        )
    return {
        "reason_code": _safe_masked_str(cap.get("reason_code")),
        "cap_value": _strict_int(cap.get("cap_value", 0)),
        "score_before_cap": _strict_int(cap.get("score_before_cap", 0)),
        "score_after_cap": _strict_int(cap.get("score_after_cap", 0)),
        "applied": _strict_bool(cap.get("applied", False)),
        "description": _safe_masked_desc(cap.get("description")),
    }


def _serialize_blocking_reason_entry(reason: dict[str, Any]) -> dict[str, Any]:
    """Whitelist and mask a single blocking_reasons entry.

    Allowed fields:
    - rule_id, rule_name, severity (masked strings)
    - file_path (sanitized via sanitize_assessment_file_path)
    - description (masked string with path cleaning)
    """
    if not isinstance(reason, dict):
        raise AssessmentSerializationError(
            "blocking_reasons entry must be a dict"
        )
    return {
        "rule_id": _safe_masked_str(reason.get("rule_id")),
        "rule_name": _safe_masked_str(reason.get("rule_name")),
        "severity": _safe_masked_str(reason.get("severity")),
        "file_path": sanitize_assessment_file_path(reason.get("file_path")),
        "description": _safe_masked_desc(reason.get("description")),
    }


def _serialize_coverage(coverage: dict[str, Any]) -> dict[str, Any]:
    """Whitelist and mask the coverage structure.

    Allowed fields:
    - status (string)
    - reasons (list of masked strings with path cleaning)
    - total_findings, scored_findings, total_blocking_findings,
      returned_blocking_reasons, total_scan_errors,
      total_files_scanned, total_skipped_files (ints)
    - findings_truncated, blocking_reasons_truncated (bools)
    """
    if not isinstance(coverage, dict):
        raise AssessmentSerializationError(
            "coverage must be a dict"
        )

    _reasons = coverage.get("reasons", [])
    if not isinstance(_reasons, list):
        raise AssessmentSerializationError(
            "coverage.reasons must be a list"
        )

    return {
        "status": _safe_masked_str(coverage.get("status")),
        "reasons": [_safe_masked_desc(r) for r in _reasons],
        "total_findings": _strict_int(coverage.get("total_findings", 0)),
        "scored_findings": _strict_int(coverage.get("scored_findings", 0)),
        "findings_truncated": _strict_bool(
            coverage.get("findings_truncated", False)
        ),
        "total_blocking_findings": _strict_int(
            coverage.get("total_blocking_findings", 0)
        ),
        "returned_blocking_reasons": _strict_int(
            coverage.get("returned_blocking_reasons", 0)
        ),
        "blocking_reasons_truncated": _strict_bool(
            coverage.get("blocking_reasons_truncated", False)
        ),
        "total_scan_errors": _strict_int(
            coverage.get("total_scan_errors", 0)
        ),
        "total_files_scanned": _strict_int(
            coverage.get("total_files_scanned", 0)
        ),
        "total_skipped_files": _strict_int(
            coverage.get("total_skipped_files", 0)
        ),
    }


def serialize_assessment_result(
    task_id: str,
    assessment: dict[str, Any],
    created_at: Optional[str],
    updated_at: str,
) -> dict[str, Any]:
    """Explicit serialization boundary for AssessmentResult.

    This is the ONLY function that constructs the dict persisted as
    assessment_json. It enforces strict field whitelists and defensive
    desensitization.

    Top-level allowed fields:
    - schema_version, policy_version, assessment_scope (forced from
      policy constants, NOT from the input assessment dict)
    - task_id (from the parameter, NOT from the assessment dict)
    - score, score_before_caps (int, clamped to [0, 100])
    - verdict (only "pass", "warning", "blocked")
    - score_breakdown, score_caps, blocking_reasons, coverage
      (per-field whitelisted and masked)
    - created_at, updated_at (from parameters)

    Unknown fields in the input assessment dict are silently discarded.
    No vars(), __dict__, asdict, or recursive serialization of unknown
    objects is performed.

    Args:
        task_id:     The authoritative task ID (from the caller, NOT
                     from assessment["task_id"]).
        assessment:  The raw assessment dict from assess_scan_result().
        created_at:  The original created_at (None for first save,
                     preserved from DB for upsert).
        updated_at:  The current timestamp for this save.

    Returns:
        A safe, explicitly-constructed dict with only whitelisted fields.

    Raises:
        AssessmentSerializationError: If any top-level or nested value
            has an illegal type (e.g. assessment is not a dict,
            score_breakdown is not a list, a list element is not a dict,
            or a string field contains a non-str/non-None value).
    """
    # --- Type validation for top-level structures ---
    if not isinstance(assessment, dict):
        raise AssessmentSerializationError(
            "Assessment must be a dict"
        )

    _score_breakdown = assessment.get("score_breakdown", [])
    if not isinstance(_score_breakdown, list):
        raise AssessmentSerializationError(
            "score_breakdown must be a list"
        )

    _score_caps = assessment.get("score_caps", [])
    if not isinstance(_score_caps, list):
        raise AssessmentSerializationError(
            "score_caps must be a list"
        )

    _blocking_reasons = assessment.get("blocking_reasons", [])
    if not isinstance(_blocking_reasons, list):
        raise AssessmentSerializationError(
            "blocking_reasons must be a list"
        )

    _coverage = assessment.get("coverage", {})
    if not isinstance(_coverage, dict):
        raise AssessmentSerializationError(
            "coverage must be a dict"
        )

    # --- Force canonical identity fields from policy ---
    # Never trust the input dict for these — they are policy constants.
    # --- Strict type-validate score (no clamp, no silent conversion) ---
    score = _strict_int(assessment.get("score", 0), minimum=0, maximum=100)

    # --- Strict type-validate score_before_caps (no clamp) ---
    score_before_caps = _strict_int(
        assessment.get("score_before_caps", 0), minimum=0, maximum=100
    )

    # --- Validate verdict (reject invalid, do NOT default to blocked) ---
    verdict = assessment.get("verdict")
    if not isinstance(verdict, str) or verdict not in _VALID_VERDICTS:
        raise AssessmentSerializationError(
            "Invalid verdict rejected by strict serialization boundary"
        )

    # --- Explicitly construct the safe dict ---
    # Every field is whitelisted and constructed by hand.
    # No unknown fields can leak through.
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "assessment_scope": ASSESSMENT_SCOPE,
        "task_id": task_id,
        "score": score,
        "score_before_caps": score_before_caps,
        "verdict": verdict,
        "score_breakdown": [
            _serialize_score_breakdown_entry(e)
            for e in _score_breakdown
        ],
        "score_caps": [
            _serialize_score_cap_entry(c)
            for c in _score_caps
        ],
        "blocking_reasons": [
            _serialize_blocking_reason_entry(r)
            for r in _blocking_reasons
        ],
        "coverage": _serialize_coverage(_coverage),
        "created_at": created_at,
        "updated_at": updated_at,
    }


# ---------------------------------------------------------------------------
# --- Finding sorting (deterministic within a rule_id group) ---
# ---------------------------------------------------------------------------

# Fields included in the canonical finding sort key.
# This tuple defines the COMPLETE set of fields that participate in
# deterministic ordering. Any field not listed here is ignored for
# sorting purposes. All listed fields are also included in the
# canonical JSON tiebreaker.
_FINDING_SORT_FIELDS: tuple[str, ...] = (
    "is_blocking",
    "severity",
    "confidence",
    "file_path",
    "line_start",
    "line_end",
    "column_start",
    "column_end",
    "rule_id",
    "rule_name",
    "category",
    "finding_type",
    "secret_type",
    "description",
    "message",
    "repair_template_key",
    "snippet_masked",
)


def _normalize_sort_value(value: Any) -> Any:
    """Normalize a finding sort field value for deterministic ordering.

    Only allows expected JSON-public types:
    - str, int, bool, None

    Calls to __str__, __int__, __bool__ on unknown objects are NOT
    performed. Unknown types raise AssessmentInternalError.

    This prevents a malicious finding with a custom __str__ returning
    a synthetic token from entering sort keys, logs, or the database.
    """
    if value is None:
        return None
    if type(value) is str:
        return value
    if type(value) is int:
        return value
    if type(value) is bool:
        return value
    raise AssessmentInternalError(
        "Unknown type in finding sort field rejected"
    )


def _finding_sort_key(f: dict[str, Any]) -> tuple:
    """Complete deterministic sort key for findings.

    Produces a TOTAL ORDER: no two distinct findings produce the same
    key. None values are converted to fixed, comparable defaults so
    that heterogeneous types never cause TypeError during comparison.

    Sort order (highest priority first):
    1. is_blocking = True first
    2. severity rank: critical > high > medium > low > info
    3. confidence rank: high > medium > low
    4. file_path: alphabetical
    5. line_start: ascending
    6. line_end: ascending
    7. column_start: ascending
    8. column_end: ascending
    9. rule_id: alphabetical
    10. rule_name: alphabetical
    11. category: alphabetical
    12. finding_type: alphabetical
    13. secret_type: alphabetical
    14. description: alphabetical
    15. message: alphabetical
    16. repair_template_key: alphabetical
    17. snippet_masked: alphabetical
    18. canonical JSON string (final tiebreaker, only known public fields)

    This ensures the repeat multiplier (100/75/50/25) is applied in
    a consistent order regardless of input finding order, and that
    blocking_reasons truncation always selects the same subset.

    SECURITY: All sort field values are explicitly type-normalized
    via _normalize_sort_value before entering the canonical JSON
    tiebreaker. json.dumps is called WITHOUT default=str so that
    __str__ is never called on unknown objects.
    """
    severity = f.get("severity") or ""
    confidence = f.get("confidence") or ""

    # Build canonical JSON tiebreaker from known public fields only.
    # Explicitly normalize each value — reject unknown objects.
    canonical = json.dumps(
        {k: _normalize_sort_value(f.get(k)) for k in _FINDING_SORT_FIELDS},
        ensure_ascii=False, sort_keys=True,
    )

    return (
        0 if f.get("is_blocking", False) else 1,
        _SEVERITY_ORDER.get(severity, 99),
        _CONFIDENCE_ORDER.get(confidence, 99),
        f.get("file_path") or "",
        f.get("line_start") or 0,
        f.get("line_end") or 0,
        f.get("column_start") or 0,
        f.get("column_end") or 0,
        f.get("rule_id") or "",
        f.get("rule_name") or "",
        f.get("category") or "",
        f.get("finding_type") or "",
        f.get("secret_type") or "",
        f.get("description") or "",
        f.get("message") or "",
        f.get("repair_template_key") or "",
        f.get("snippet_masked") or "",
        canonical,
    )


def _group_findings_by_rule(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group findings by rule_id, sorting each group deterministically.

    Returns a dict mapping rule_id → sorted list of finding dicts.
    The dict keys are NOT sorted here — the caller sorts the final
    score_breakdown by rule_id.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        rule_id = f.get("rule_id", "")
        if rule_id not in groups:
            groups[rule_id] = []
        groups[rule_id].append(f)

    for rule_id in groups:
        groups[rule_id].sort(key=_finding_sort_key)

    return groups


# ---------------------------------------------------------------------------
# --- Score computation ---
# ---------------------------------------------------------------------------

def _compute_rule_deduction(
    rule_id: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute the total deduction for a single rule_id group.

    Returns a score_breakdown entry with:
    - reason_code: "RULE_DEDUCTION"
    - rule_id, category, severity (highest in group)
    - finding_count
    - occurrence_deductions: list of per-finding deductions
    - deduction_before_rule_cap: sum of occurrence deductions
    - rule_cap: cap based on highest severity
    - applied_deduction: min(deduction_before_rule_cap, rule_cap)
    - description
    """
    # Determine highest severity in the group for rule cap.
    highest_severity = "info"
    for f in findings:
        sev = f.get("severity", "info")
        if _SEVERITY_ORDER.get(sev, 99) < _SEVERITY_ORDER.get(highest_severity, 99):
            highest_severity = sev

    rule_cap = RULE_CAP_BY_SEVERITY.get(highest_severity, 0)

    # Compute per-finding deductions with repeat multipliers.
    occurrence_deductions: list[int] = []
    for idx, f in enumerate(findings):
        severity = f.get("severity", "info")
        base_points = SEVERITY_BASE_POINTS.get(severity, 0)

        # Confidence: blocking findings forced to 100%.
        if f.get("is_blocking", False):
            conf_pct = BLOCKING_CONFIDENCE_OVERRIDE
        else:
            conf_str = f.get("confidence", "low")
            conf_pct = CONFIDENCE_PERCENT.get(conf_str, 50)

        repeat_pct = get_repeat_percent(idx)

        deduction = compute_single_deduction(base_points, conf_pct, repeat_pct)
        occurrence_deductions.append(deduction)

    deduction_before_cap = sum(occurrence_deductions)
    applied_deduction = min(deduction_before_cap, rule_cap)

    # Extract category from the first finding (all findings in a rule
    # share the same category — it's a rule-level constant).
    category = findings[0].get("category", "") if findings else ""

    # Build description.
    if rule_cap == 0:
        description = f"规则 {rule_id} 扣分上限为0（info级别），不产生扣分。"
    elif deduction_before_cap > rule_cap:
        description = (
            f"规则 {rule_id} 累计扣分 {deduction_before_cap} 超过上限 "
            f"{rule_cap}，实际扣分 {applied_deduction}。"
        )
    else:
        description = (
            f"规则 {rule_id} 累计扣分 {deduction_before_cap}，"
            f"未超过上限 {rule_cap}。"
        )

    return {
        "reason_code": "RULE_DEDUCTION",
        "rule_id": rule_id,
        "category": category,
        "severity": highest_severity,
        "finding_count": len(findings),
        "occurrence_deductions": occurrence_deductions,
        "deduction_before_rule_cap": deduction_before_cap,
        "rule_cap": rule_cap,
        "applied_deduction": applied_deduction,
        "description": description,
    }


def _compute_score_breakdown(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Compute the full score_breakdown and total deduction.

    Returns:
        (score_breakdown, total_deduction)
        - score_breakdown is sorted by rule_id (alphabetical).
        - total_deduction is the sum of all applied_deduction values.
    """
    groups = _group_findings_by_rule(findings)

    breakdown: list[dict[str, Any]] = []
    total_deduction = 0

    for rule_id in sorted(groups.keys()):
        entry = _compute_rule_deduction(rule_id, groups[rule_id])
        breakdown.append(entry)
        total_deduction += entry["applied_deduction"]

    return breakdown, total_deduction


# ---------------------------------------------------------------------------
# --- Score caps application ---
# ---------------------------------------------------------------------------

def _apply_score_caps(
    score_before_caps: int,
    summary: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]]:
    """Apply triggered score caps in deterministic order.

    Returns:
        (final_score, score_caps_records)
        Each cap record contains:
        - reason_code, cap_value, score_before_cap, score_after_cap,
          applied (bool), description
    """
    triggered = determine_triggered_caps(summary)
    sorted_caps = sort_caps(triggered)

    cap_records: list[dict[str, Any]] = []
    current_score = score_before_caps

    for cap in sorted_caps:
        score_before = current_score
        score_after = min(current_score, cap.cap_value)
        applied = score_after < score_before

        cap_records.append({
            "reason_code": cap.reason_code,
            "cap_value": cap.cap_value,
            "score_before_cap": score_before,
            "score_after_cap": score_after,
            "applied": applied,
            "description": cap.description,
        })

        current_score = score_after

    return current_score, cap_records


# ---------------------------------------------------------------------------
# --- Blocking reasons ---
# ---------------------------------------------------------------------------

def _build_blocking_reasons(
    findings: list[dict[str, Any]],
    max_reasons: int,
) -> tuple[list[dict[str, Any]], int]:
    """Build the blocking_reasons list from blocking findings.

    Each reason contains ONLY:
    - rule_id, rule_name, severity, file_path, description

    Does NOT include: raw secret, snippet_masked, internal exceptions,
    temp absolute paths.

    Findings are sorted deterministically (same as _finding_sort_key)
    before truncation, so the same input always produces the same
    blocking_reasons subset.

    Args:
        findings: The persisted findings list (may be truncated).
        max_reasons: Maximum number of reasons to include.

    Returns:
        (blocking_reasons, returned_count)
    """
    blocking = [f for f in findings if f.get("is_blocking", False)]
    blocking.sort(key=_finding_sort_key)

    truncated = blocking[:max_reasons]

    reasons: list[dict[str, Any]] = []
    for f in truncated:
        reasons.append({
            "rule_id": f.get("rule_id", ""),
            "rule_name": f.get("rule_name", ""),
            "severity": f.get("severity", "info"),
            "file_path": f.get("file_path", ""),
            "description": f.get("description", ""),
        })

    return reasons, len(reasons)


# ---------------------------------------------------------------------------
# --- Coverage info ---
# ---------------------------------------------------------------------------

def _build_coverage(
    summary: dict[str, Any],
    scored_findings: int,
    blocking_reasons: list[dict[str, Any]],
    total_blocking_findings: int,
) -> dict[str, Any]:
    """Build the coverage info dict.

    coverage_status is "partial" if any of:
    - findings_truncated == True
    - total_scan_errors > 0
    - total_files_scanned == 0

    skipped_files does NOT affect coverage_status.
    """
    findings_truncated = summary.get("findings_truncated", False)
    total_scan_errors = summary.get("total_scan_errors", 0)
    total_files_scanned = summary.get("total_files_scanned", 0)
    total_skipped_files = summary.get("total_skipped_files", 0)
    total_findings = summary.get("total_findings", 0)

    status = determine_coverage_status(
        findings_truncated, total_scan_errors, total_files_scanned
    )

    reasons: list[str] = []
    if findings_truncated:
        reasons.append("扫描发现项被截断，评分基于部分结果。")
    if total_scan_errors > 0:
        reasons.append(f"扫描过程中存在 {total_scan_errors} 个错误。")
    if total_files_scanned == 0:
        reasons.append("未扫描任何文件。")

    returned_blocking_reasons = len(blocking_reasons)
    blocking_reasons_truncated = total_blocking_findings > returned_blocking_reasons

    return {
        "status": status,
        "reasons": reasons,
        "total_findings": total_findings,
        "scored_findings": scored_findings,
        "findings_truncated": findings_truncated,
        "total_blocking_findings": total_blocking_findings,
        "returned_blocking_reasons": returned_blocking_reasons,
        "blocking_reasons_truncated": blocking_reasons_truncated,
        "total_scan_errors": total_scan_errors,
        "total_files_scanned": total_files_scanned,
        "total_skipped_files": total_skipped_files,
    }


# ---------------------------------------------------------------------------
# --- Core assessment function ---
# ---------------------------------------------------------------------------

def assess_scan_result(task_id: str, scan_result: dict[str, Any]) -> dict[str, Any]:
    """Compute a deterministic AssessmentResult from a persisted scan result.

    This is the core assessment function. It takes the ALREADY-DESENSITIZED
    scan result dict (as persisted by P0-5) and produces an AssessmentResult
    dict.

    Does NOT modify the input scan_result.
    Does NOT access temp directories or the network.
    Does NOT execute repository code.
    Does NOT call an LLM.

    Args:
        task_id:     The task ID (for the output record only, does not
                     affect scoring).
        scan_result: The persisted scan result dict with keys:
                     findings, notices, skipped_files, scan_errors, summary.

    Returns:
        An AssessmentResult dict with the fixed structure:
        {
            schema_version, policy_version, assessment_scope,
            task_id, score, score_before_caps, verdict,
            score_breakdown, score_caps, blocking_reasons,
            coverage, created_at, updated_at
        }

    Note: created_at and updated_at are set to None — the persistence
    layer (save_assessment_result) determines the final timestamps.
    """
    findings = scan_result.get("findings", [])
    summary = scan_result.get("summary", {})

    # --- 1. Compute score_breakdown and total deduction ---
    score_breakdown, total_deduction = _compute_score_breakdown(findings)

    # --- 2. Compute score_before_caps ---
    score_before_caps = max(MIN_SCORE, BASE_SCORE - total_deduction)

    # --- 3. Apply score caps ---
    final_score, score_caps = _apply_score_caps(score_before_caps, summary)

    # --- 4. Determine verdict ---
    # Use summary.blocking_findings as the AUTHORITY, not len(findings).
    # Even if the findings list was truncated and no blocking finding
    # is in the persisted list, summary.blocking_findings > 0 still
    # means blocked.
    total_blocking_findings = summary.get("blocking_findings", 0)
    verdict = determine_verdict(final_score, total_blocking_findings)

    # --- 5. Build blocking_reasons ---
    # Runtime defense: clamp to at least 1 so that a misconfigured value
    # of 0 or -1 never bypasses the limit or produces blocking[:-1].
    # Pydantic Field(ge=1) covers normal config validation, but this
    # guard also protects against runtime monkeypatch in tests.
    max_reasons = max(1, int(settings.assessment_max_blocking_reasons))
    blocking_reasons, _ = _build_blocking_reasons(findings, max_reasons)

    # --- 6. Build coverage ---
    coverage = _build_coverage(
        summary,
        scored_findings=len(findings),
        blocking_reasons=blocking_reasons,
        total_blocking_findings=total_blocking_findings,
    )

    # --- 7. Assemble AssessmentResult ---
    # Timestamps are None — the persistence layer (save_assessment_result)
    # determines the final created_at and updated_at in a single
    # persistence flow, ensuring JSON and DB columns are identical.
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "assessment_scope": ASSESSMENT_SCOPE,
        "task_id": task_id,
        "score": final_score,
        "score_before_caps": score_before_caps,
        "verdict": verdict,
        "score_breakdown": score_breakdown,
        "score_caps": score_caps,
        "blocking_reasons": blocking_reasons,
        "coverage": coverage,
        "created_at": None,
        "updated_at": None,
    }


# ---------------------------------------------------------------------------
# --- Database operations ---
# ---------------------------------------------------------------------------

def get_scan_result_with_timestamp(
    task_id: str,
) -> Optional[tuple[dict[str, Any], str]]:
    """Read the persisted scan result and its updated_at timestamp.

    This is the bridge between P0-5 persistence and P0-6 assessment.
    The assessment engine reads ONLY from SQLite — never from temp.

    Returns:
        (scan_result_dict, scan_updated_at) or None if no scan result
        has been persisted for this task_id.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT result_json, updated_at FROM scan_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["result_json"]), row["updated_at"]
    finally:
        conn.close()


def save_assessment_result(
    task_id: str,
    assessment: dict[str, Any],
    source_scan_updated_at: str,
) -> dict[str, Any]:
    """Persist an assessment result to the assessment_results table.

    Uses SQLite native upsert (INSERT ON CONFLICT DO UPDATE):
    - created_at is preserved on update (only set on first INSERT).
    - updated_at is always refreshed.
    - source_scan_updated_at tracks which scan_results version this
      assessment was computed from.

    This function is the EXPLICIT SERIALIZATION BOUNDARY:
    - Calls serialize_assessment_result() to build a safe dict with
      strict field whitelists and defensive desensitization.
    - Forces schema_version, policy_version, assessment_scope, and
      task_id from policy constants / parameters — never trusts the
      input assessment dict.
    - The same created_at and updated_at values are used in both the
      assessment_json and the database columns, ensuring consistency.

    Args:
        task_id:                The authoritative task ID (used for both
                                the DB primary key and the JSON task_id).
        assessment:             The AssessmentResult dict from
                                assess_scan_result(). Its task_id,
                                schema_version, etc. are NOT trusted.
        source_scan_updated_at: The updated_at of the scan_results row
                                this assessment was computed from.

    Returns:
        The final safe persisted dict (as written to assessment_json).
        This is the authoritative version — callers should use this
        return value rather than the pre-save assessment dict.

    Raises:
        AssessmentResultTooLargeError: If serialized assessment_json exceeds
            assessment_max_json_bytes.
        AssessmentPersistError: If the database operation fails.
    """
    init_db()
    now = now_iso()

    conn = _get_connection()
    try:
        # --- Determine created_at ---
        # For upsert, read the original created_at from the existing row.
        # For first save, created_at = now.
        existing = conn.execute(
            "SELECT created_at FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()

        if existing is not None:
            created_at = existing["created_at"]
        else:
            created_at = now

        # --- Explicit serialization boundary ---
        # Build the safe dict with strict whitelists and defensive masking.
        # task_id comes from the parameter, NOT from assessment["task_id"].
        # schema_version, policy_version, assessment_scope come from policy.
        safe_assessment = serialize_assessment_result(
            task_id=task_id,
            assessment=assessment,
            created_at=created_at,
            updated_at=now,
        )

        # --- Serialize to JSON ---
        # json.dumps with sort_keys for deterministic output.
        # Only the already-safe dict is serialized — no vars, __dict__, asdict.
        assessment_json = json.dumps(
            safe_assessment, ensure_ascii=False, sort_keys=True
        )

        # --- Check byte size limit ---
        if len(assessment_json.encode("utf-8")) > settings.assessment_max_json_bytes:
            raise AssessmentResultTooLargeError(
                "assessment_json exceeds assessment_max_json_bytes"
            )

        # --- Execute upsert ---
        # The SAME created_at and updated_at values are used in both the
        # assessment_json and the database columns.
        conn.execute(
            """INSERT INTO assessment_results
               (task_id, schema_version, policy_version, assessment_scope,
                assessment_json, score, verdict, source_scan_updated_at,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(task_id) DO UPDATE SET
                   schema_version=excluded.schema_version,
                   policy_version=excluded.policy_version,
                   assessment_scope=excluded.assessment_scope,
                   assessment_json=excluded.assessment_json,
                   score=excluded.score,
                   verdict=excluded.verdict,
                   source_scan_updated_at=excluded.source_scan_updated_at,
                   updated_at=excluded.updated_at""",
            (
                task_id,
                safe_assessment["schema_version"],
                safe_assessment["policy_version"],
                safe_assessment["assessment_scope"],
                assessment_json,
                safe_assessment["score"],
                safe_assessment["verdict"],
                source_scan_updated_at,
                created_at,  # created_at — preserved on UPDATE
                now,         # updated_at — always updated
            ),
        )
        conn.commit()
    except (AssessmentResultTooLargeError, AssessmentInternalError):
        # Serialization errors (AssessmentSerializationError extends
        # AssessmentInternalError) and size limit errors must NOT be
        # wrapped as AssessmentPersistError — they are internal errors.
        raise
    except Exception as exc:
        # Wrap unexpected DB errors in AssessmentPersistError.
        # Never expose str(exc) or repr(exc) to callers.
        raise AssessmentPersistError("Failed to persist assessment result") from exc
    finally:
        conn.close()

    return safe_assessment


def get_assessment_result(task_id: str) -> Optional[dict[str, Any]]:
    """Read the full persisted assessment result for a task.

    Returns None if no assessment has been persisted for this task_id.
    The returned dict has the same structure as the AssessmentResult
    produced by assess_scan_result().

    Validates the parsed JSON to ensure identity consistency:
    - schema_version == ASSESSMENT_SCHEMA_VERSION
    - policy_version == POLICY_VERSION
    - assessment_scope == ASSESSMENT_SCOPE
    - task_id matches the requested task_id
    - score is an int in [0, 100]
    - verdict is one of pass, warning, blocked

    Args:
        task_id: The task ID to look up.

    Returns:
        The AssessmentResult dict, or None if not found.

    Raises:
        AssessmentInternalError: If the database read fails, JSON parsing
            fails, the top-level is not a dict, or any identity/schema
            validation fails. The exception message never contains the
            raw JSON, database errors, str(exc), or repr(exc).
    """
    # --- Full database error boundary: init_db, connection, execute,
    # fetchone, row field reading, and connection close are ALL inside
    # the try block. Any database exception is caught and mapped to
    # AssessmentInternalError with a fixed safe message.
    conn = None
    raw_json = None
    try:
        init_db()
        conn = _get_connection()
        row = conn.execute(
            "SELECT assessment_json FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            # Close before returning — conn is guaranteed non-None here.
            conn.close()
            return None
        raw_json = row["assessment_json"]
    except Exception:
        raise AssessmentInternalError(
            "Failed to read assessment from database"
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass  # Already raising or returning; ignore close error.

    # --- Parse JSON ---
    try:
        result = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        raise AssessmentInternalError("Failed to parse assessment JSON")

    # --- Validate top-level structure ---
    if not isinstance(result, dict):
        raise AssessmentInternalError("Assessment JSON is not a dict")

    # --- Validate identity fields ---
    if result.get("schema_version") != ASSESSMENT_SCHEMA_VERSION:
        raise AssessmentInternalError("Assessment schema_version mismatch")
    if result.get("policy_version") != POLICY_VERSION:
        raise AssessmentInternalError("Assessment policy_version mismatch")
    if result.get("assessment_scope") != ASSESSMENT_SCOPE:
        raise AssessmentInternalError("Assessment scope mismatch")
    if result.get("task_id") != task_id:
        raise AssessmentInternalError("Assessment task_id mismatch")

    # --- Validate score (strict type: bool is NOT accepted) ---
    score = result.get("score")
    if type(score) is not int or score < 0 or score > 100:
        raise AssessmentInternalError("Assessment score invalid")

    # --- Validate verdict ---
    verdict = result.get("verdict")
    if verdict not in _VALID_VERDICTS:
        raise AssessmentInternalError("Assessment verdict invalid")

    return result


def get_assessment_score_verdict(
    task_id: str,
) -> Optional[tuple[int, str]]:
    """Lightweight read for status polling — returns (score, verdict).

    Reads ONLY the redundant score and verdict columns, avoiding
    a full assessment_json parse on every poll.

    Returns None if no assessment has been persisted.

    Args:
        task_id: The task ID to look up.

    Returns:
        (score, verdict) tuple, or None if not found.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT score, verdict FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        return row["score"], row["verdict"]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# --- Orchestrator: assess + persist ---
# ---------------------------------------------------------------------------

def run_assessment(task_id: str) -> dict[str, Any]:
    """Read persisted scan result, compute assessment, and persist it.

    This is the entry point called by the background runner via
    asyncio.to_thread(). It:

    1. Reads the persisted scan result from scan_results (NOT from temp).
    2. Computes the assessment using assess_scan_result().
    3. Persists the assessment to assessment_results via
       save_assessment_result(), which applies the explicit serialization
       boundary and defensive desensitization.

    Returns the FINAL PERSISTED version (the safe dict from
    save_assessment_result), NOT the pre-save assessment dict. This
    ensures callers see the exact data that was written to the database,
    including correct timestamps and masked fields.

    Args:
        task_id: The task ID to assess.

    Returns:
        The final persisted AssessmentResult dict.

    Raises:
        AssessmentInternalError: If reading or parsing the scan result
            fails, or if assessment computation fails.
        AssessmentResultTooLargeError: If the assessment exceeds size limit.
        AssessmentPersistError: If the database persistence fails.
    """
    # Step 1: Read persisted scan result with timestamp.
    try:
        scan_data = get_scan_result_with_timestamp(task_id)
    except Exception as exc:
        raise AssessmentInternalError(
            "Failed to read persisted scan result"
        ) from exc

    if scan_data is None:
        raise AssessmentInternalError(
            f"No scan result found for task {task_id}"
        )
    scan_result, source_scan_updated_at = scan_data

    # Step 2: Compute assessment.
    try:
        assessment = assess_scan_result(task_id, scan_result)
    except Exception as exc:
        raise AssessmentInternalError(
            "Assessment computation failed"
        ) from exc

    # Step 3: Persist assessment and return the final persisted version.
    # save_assessment_result applies the serialization boundary and
    # returns the safe dict that was actually written to the database.
    persisted = save_assessment_result(
        task_id, assessment, source_scan_updated_at
    )

    return persisted
