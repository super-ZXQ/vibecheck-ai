"""Repair plan engine — deterministic repair plan generation from persisted results.

This module reads ALREADY-PERSISTED, ALREADY-DESENSITIZED scan results
(P0-5) and assessment results (P0-6) from SQLite and computes a
deterministic repair plan.

SECURITY:
- NEVER reads from temp directories.
- NEVER executes repository code.
- NEVER accesses the network.
- NEVER calls an LLM.
- Only reads result_json, summary_json, updated_at from scan_results.
- Only reads assessment_json, updated_at, policy_version from assessment_results.
- NEVER reads repo_url, owner, repo_name, or any raw secrets.
- repair_json output contains NO raw secrets, NO temp paths,
  NO internal exception objects, NO repo_url.
- The persistence boundary applies a SECOND defensive desensitization
  pass via mask_untrusted_text on all string fields.
- The serialization boundary enforces strict field whitelists.

DETERMINISM:
- Same (policy_version, persisted ScanResult, persisted AssessmentResult)
  → identical plan_status, summary, repair_groups, verification_steps,
  agent_prompt.
- Finding order does not affect the output.
- dict key insertion order does not affect the output.
- group_id is stable (RG001, RG002, ... assigned after deterministic sort).
- Only created_at, updated_at, and task_id may differ between runs.

ASYNC:
- Database reads/writes and repair plan computation are synchronous.
- Callers MUST wrap them in asyncio.to_thread() to avoid blocking
  the FastAPI event loop.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Optional

from app.core.config import settings
from app.core.security.desensitize import mask_untrusted_text
from app.db.database import _get_connection, init_db, now_iso
from app.scanner.base import SENSITIVE_DATA_DIMENSION
from app.services.scan_result_service import (
    normalize_scan_result_dimensions,
    normalize_scan_summary_dimensions,
    scope_summary_to_sensitive_data,
)
from app.services.repair_policy import (
    AGENT_PROMPT_FORBIDDEN_FIELDS,
    AGENT_PROMPT_FORBIDDEN_PATTERNS,
    AGENT_PROMPT_REQUIREMENTS,
    BLOCKING_ACTION_SEQUENCE,
    GLOBAL_SINGLETON_ACTIONS,
    PARTIAL_DECLARATION,
    POLICY_VERSION,
    REPAIR_SCHEMA_VERSION,
    REPAIR_SCOPE,
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    compute_aggregation_key,
    compute_group_sort_key,
    get_action,
    get_allowed_commands,
    get_allowed_template_keys_for_rule,
    get_template_actions,
    is_known_rule_id,
    is_known_template_key,
    is_supported_assessment_policy,
    is_valid_action_code,
    ACTION_MANUAL_REVIEW_REQUIRED,
    ACTION_RERUN_SECURITY_SCAN,
    ACTION_RESOLVE_SCAN_ERROR,
    ACTION_REVIEW_SCAN_COVERAGE,
    ACTION_VERIFY_NO_SECRET_REMAINS,
)


# ---------------------------------------------------------------------------
# --- Exception classes ---
# ---------------------------------------------------------------------------

class RepairPlanInternalError(Exception):
    """Raised when reading or parsing persisted results fails, or when
    repair plan computation fails.

    The caller (background_runner) catches this and maps it to the
    fixed error code REPAIR_PLAN_INTERNAL_ERROR.
    """
    pass


class RepairPlanPersistError(Exception):
    """Raised when SQLite repair plan persistence fails.

    The caller (background_runner) catches this and maps it to the
    fixed error code REPAIR_PLAN_PERSIST_FAILED.
    """
    pass


class RepairPlanTooLargeError(Exception):
    """Raised when serialized repair_json exceeds repair_max_json_bytes.

    The caller (background_runner) catches this and maps it to the
    fixed error code REPAIR_PLAN_TOO_LARGE.
    """
    pass


class RepairPlanSerializationError(RepairPlanInternalError):
    """Raised when a value cannot be safely serialized for persistence.

    Subclass of RepairPlanInternalError so callers catching
    RepairPlanInternalError will also catch this.
    """
    pass


# ---------------------------------------------------------------------------
# --- Strict type validators ---
# ---------------------------------------------------------------------------

def _strict_str(value: Any) -> str:
    """Convert a value to str with strict type checking.

    Only str and None are accepted. None is converted to empty string.
    Non-str and non-None values raise RepairPlanSerializationError.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    raise RepairPlanSerializationError(
        "Non-string value rejected by strict serialization boundary"
    )


def _strict_int(value: Any, minimum: int | None = None,
                maximum: int | None = None) -> int:
    """Validate that a value is a strict int (not bool, not str)."""
    if type(value) is not int:
        raise RepairPlanSerializationError(
            "Non-integer value rejected by strict serialization boundary"
        )
    if minimum is not None and value < minimum:
        raise RepairPlanSerializationError(
            "Integer value below minimum rejected"
        )
    if maximum is not None and value > maximum:
        raise RepairPlanSerializationError(
            "Integer value above maximum rejected"
        )
    return value


def _strict_bool(value: Any) -> bool:
    """Validate that a value is a strict bool."""
    if type(value) is not bool:
        raise RepairPlanSerializationError(
            "Non-boolean value rejected by strict serialization boundary"
        )
    return value


def _safe_masked_str(value: Any) -> str:
    """Strict string conversion + defensive desensitization."""
    return mask_untrusted_text(_strict_str(value))


# --- Safe file path display (reuse from assessment_service pattern) ---

_REDACTED_PATH = "<redacted-path>"
_REDACTED_METADATA = "<redacted-metadata>"
_UNKNOWN_RULE = "<unknown-rule>"


def _validate_rule_id_for_output(rid: str) -> str:
    """Validate a single rule_id for inclusion in repair group output.

    Only allows:
    - Known rule_id values from is_known_rule_id (R001-R011)
    - <unknown-rule> sentinel

    Returns the validated rule_id, or raises RepairPlanSerializationError.
    """
    if not isinstance(rid, str) or not rid:
        raise RepairPlanSerializationError(
            "related_rule_ids contains empty or non-string value"
        )
    if rid == _UNKNOWN_RULE:
        return rid
    if not is_known_rule_id(rid):
        raise RepairPlanSerializationError(
            f"related_rule_ids contains invalid rule_id: {rid!r}"
        )
    return rid

_POSIX_ABSOLUTE_RE = re.compile(r'^/')
_WINDOWS_DRIVE_RE = re.compile(r'^[A-Za-z]:[/\\]')
_UNC_RE = re.compile(r'^(?:\\\\|//)')
_WINDOWS_ROOTED_RE = re.compile(r'^\\')
_USER_HOME_RE = re.compile(r'^~[/\\]')

# Unicode categories that must NEVER appear in file paths or prompt metadata:
# - Cc: Control characters (\n, \r, \t, NUL, etc.)
# - Cf: Format characters (U+061C ARABIC LETTER MARK, U+00AD SOFT HYPHEN,
#        U+202E RIGHT-TO-LEFT OVERRIDE, U+2066 LTR ISOLATE, ZWSP, etc.)
# - Zl: Line separator (U+2028)
# - Zp: Paragraph separator (U+2029)
_FORBIDDEN_UNICODE_CATEGORIES: frozenset[str] = frozenset({
    "Cc", "Cf", "Zl", "Zp",
})

# Safe single-line metadata pattern: A-Z, a-z, 0-9, _, -, ., :
_SAFE_METADATA_RE = re.compile(r'^[A-Za-z0-9_\-.:]+$')


def _has_forbidden_unicode(s: str) -> bool:
    """Check if a string contains any forbidden Unicode category characters.

    Uses unicodedata.category for per-character checking, covering:
    - Cc (control): newline, carriage return, tab, NUL, DEL, C1 controls
    - Cf (format): U+061C, U+00AD, U+202E, U+2066, ZWSP, ZWJ, ZWNJ, BOM, etc.
    - Zl (line separator): U+2028
    - Zp (paragraph separator): U+2029
    """
    for ch in s:
        if unicodedata.category(ch) in _FORBIDDEN_UNICODE_CATEGORIES:
            return True
    return False


def sanitize_prompt_metadata(value: Any, field_name: str) -> str:
    """Sanitize metadata before it enters repair groups and agent prompts.

    This is the UNIFIED sanitization function for all metadata fields.

    - rule_id: only known R001-R011 values allowed; unknown → <unknown-rule>
    - secret_type, repair_template_key: only safe single-line chars
      (A-Z, a-z, 0-9, _, -, ., :); otherwise → <redacted-metadata>
    - file_path: delegates to _sanitize_file_path

    All fields reject Unicode categories Cc, Cf, Zl, Zp via
    unicodedata.category per-character checking.

    This function is called on the PRODUCTION PATH (in _extract_finding_fields)
    to ensure no injection can reach repair groups or agent prompts.
    """
    s = _strict_str(value)

    if field_name == "rule_id":
        if not s:
            return ""
        if is_known_rule_id(s):
            return s
        return _UNKNOWN_RULE

    if field_name in ("secret_type", "repair_template_key"):
        if not s:
            return ""
        if _has_forbidden_unicode(s):
            return _REDACTED_METADATA
        if not _SAFE_METADATA_RE.match(s):
            return _REDACTED_METADATA
        return s

    if field_name == "file_path":
        return _sanitize_file_path(s)

    # Default: check for forbidden Unicode categories
    if _has_forbidden_unicode(s):
        return _REDACTED_METADATA
    return s


def _sanitize_file_path(value: Any) -> str:
    """Sanitize and normalize a file path for safe display.

    Only allows repo-relative paths. Rejects:
    - Absolute paths (POSIX, Windows drive, UNC, rooted)
    - Path traversal (..)
    - User home paths (~)
    - NUL bytes
    - Control characters via unicodedata.category (Cc, Cf, Zl, Zp)
    - Backticks (prevent Markdown code-span injection)

    Any control character, backtick, or dangerous pattern causes the path
    to be replaced with <redacted-path> to prevent prompt injection via
    newlines, text direction manipulation, or Markdown escaping.

    Processing order (CRITICAL for idempotency):
    A. Strict input type validation.
    B. mask_untrusted_text on the raw string.
    C. Reject NUL, Cc, Cf, Zl, Zp, backticks.
    D. Unify backslashes to /.
    E. Split path into segments.
    F. Reject any '..' segment.
    G. Remove empty segments and single '.' segments.
    H. Rejoin into canonical_path.
    I. If canonical_path is empty → return empty string.
       (The serialization boundary converts this to
       RepairPlanSerializationError for original empty strings and
       '.'/'./' inputs — see _serialize_repair_group.)
    J. Re-run ALL safety checks on canonical_path:
       - POSIX absolute path check
       - Windows drive path check
       - UNC path check
       - Windows rooted path check
       - User home ~ check
       If any matches → return <redacted-path>.
    K. Return canonical_path.

    Safety checks are run BOTH on the backslash-converted string (step D,
    before empty-segment removal) AND on the canonical_path (step J, after
    segment removal). This two-pass approach catches:
    - Dangerous prefixes stripped by segment removal (// → relative)
    - Dangerous patterns exposed by segment removal (./~ → ~)

    This ordering ensures that removing '.' segments cannot produce a
    dangerous path that escapes safety checks. For example:
        ./~/.ssh/id_rsa   → ~/.ssh/id_rsa → <redacted-path>
        ./C:/secret.txt   → C:/secret.txt → <redacted-path>
        //server/share    → <redacted-path> (caught before segment removal)

    The function is idempotent: for any input, calling it twice yields
    the same result as calling it once.

    Examples:
        src\\config.py       → src/config.py
        ./src/config.py      → src/config.py
        src//config.py       → src/config.py
        ./~/.ssh/id_rsa      → <redacted-path>
        ./C:/secret.txt      → <redacted-path>
    """
    s = _strict_str(value)
    s = mask_untrusted_text(s)
    # C. Reject NUL bytes
    if '\x00' in s:
        return _REDACTED_PATH
    # Reject any forbidden Unicode category character (Cc, Cf, Zl, Zp)
    if _has_forbidden_unicode(s):
        return _REDACTED_PATH
    # Reject backticks — Markdown code-span escaping is unreliable
    if '`' in s:
        return _REDACTED_PATH
    # D. Unify backslashes to /
    normalized = s.replace('\\', '/')
    # Pre-normalization safety check on the converted string.
    # This catches dangerous prefixes that would be lost when empty
    # segments are removed in step G. For example:
    #   //server/share/secret.env  (UNC) → would lose leading //
    #   /etc/passwd                 (POSIX absolute) → would lose leading /
    # After step G removes empty segments, these become relative-looking
    # paths that would pass the post-normalization check. Checking here
    # ensures they are caught before the prefix is stripped.
    if _POSIX_ABSOLUTE_RE.match(normalized):
        return _REDACTED_PATH
    if _WINDOWS_DRIVE_RE.match(normalized):
        return _REDACTED_PATH
    if _UNC_RE.match(normalized):
        return _REDACTED_PATH
    if _WINDOWS_ROOTED_RE.match(normalized):
        return _REDACTED_PATH
    if _USER_HOME_RE.match(normalized):
        return _REDACTED_PATH
    # E. Split path into segments
    parts = normalized.split('/')
    # F. Reject any '..' segment
    if '..' in parts:
        return _REDACTED_PATH
    # G. Remove empty segments and single '.' segments
    normalized_parts = [p for p in parts if p and p != '.']
    # H. Rejoin into canonical_path
    canonical_path = '/'.join(normalized_parts)
    # I. If canonical_path is empty → return empty string
    # The serialization boundary (_serialize_repair_group) converts this
    # to RepairPlanSerializationError — original empty strings, '.', './',
    # and similar paths that normalize to empty must not be silently
    # accepted, as they would lose Finding position information.
    # Note: This returns "" (not <redacted-path>) so the serializer can
    # distinguish "normalizes to empty" (error) from "dangerous path"
    # (redacted). The serializer's `if not sanitized` check catches this.
    if not canonical_path:
        return ""
    # J. Re-run ALL safety checks on canonical_path
    # This catches dangerous patterns that were hidden behind './' or
    # '.\' prefixes, e.g. ./~/.ssh/id_rsa → ~/.ssh/id_rsa
    if _POSIX_ABSOLUTE_RE.match(canonical_path):
        return _REDACTED_PATH
    if _WINDOWS_DRIVE_RE.match(canonical_path):
        return _REDACTED_PATH
    if _UNC_RE.match(canonical_path):
        return _REDACTED_PATH
    if _WINDOWS_ROOTED_RE.match(canonical_path):
        return _REDACTED_PATH
    if _USER_HOME_RE.match(canonical_path):
        return _REDACTED_PATH
    # K. Return canonical_path
    return canonical_path


# --- Path removal from text ---

_PATH_BOUNDARY = r'(?:^|(?<=[\s\[({<"\']))'
_PATH_TEXT_RE = re.compile(
    _PATH_BOUNDARY + r'(/var/tmp/[^\s"\'<>]*'
    r'|/tmp/[^\s"\'<>]*'
    r'|/home/[^\s"\'<>]*'
    r'|/Users/[^\s"\'<>]*'
    r'|/[A-Za-z][^\s"\'<>]*)'
    r'|' + _PATH_BOUNDARY + r'([A-Za-z]:[/\\][^\s"\'<>]*)'
    r'|' + _PATH_BOUNDARY + r'(\\\\[^\s"\'<>]*)'
    r'|' + _PATH_BOUNDARY + r'(//[^\s"\'<>]*)'
)


def _clean_path_from_text(text: str) -> str:
    """Remove absolute temp paths from text while preserving URLs."""
    return _PATH_TEXT_RE.sub(_REDACTED_PATH, text)


def _safe_masked_desc(value: Any) -> str:
    """Strict string + mask + path cleaning."""
    s = _strict_str(value)
    s = mask_untrusted_text(s)
    s = _clean_path_from_text(s)
    return s


# ---------------------------------------------------------------------------
# --- Input boundary: read persisted results from SQLite ---
# ---------------------------------------------------------------------------

def _read_scan_result(task_id: str) -> tuple[dict, dict, str]:
    """Read persisted scan result, summary, and updated_at from SQLite.

    Returns:
        (scan_result_dict, summary_dict, scan_updated_at)

    Raises:
        RepairPlanInternalError: If the scan result is missing, cannot
            be parsed, or has an invalid structure.
    """
    conn = None
    _db_error = False
    try:
        init_db()
        conn = _get_connection()
        row = conn.execute(
            "SELECT result_json, summary_json, updated_at "
            "FROM scan_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise RepairPlanInternalError(
                "No scan result found for task"
            )
        result_json = row["result_json"]
        summary_json = row["summary_json"]
        scan_updated_at = row["updated_at"]
    except RepairPlanInternalError:
        _db_error = True
        raise
    except Exception:
        _db_error = True
        raise RepairPlanInternalError(
            "Failed to read scan result from database"
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                if not _db_error:
                    raise RepairPlanInternalError(
                        "Failed to close database connection"
                    )

    # Parse JSON
    try:
        scan_result = json.loads(result_json)
    except (json.JSONDecodeError, TypeError):
        raise RepairPlanInternalError("Failed to parse scan result JSON")

    try:
        summary = json.loads(summary_json) if summary_json else {}
    except (json.JSONDecodeError, TypeError):
        raise RepairPlanInternalError("Failed to parse scan summary JSON")

    if not isinstance(scan_result, dict):
        raise RepairPlanInternalError("Scan result is not a dict")
    if not isinstance(summary, dict):
        raise RepairPlanInternalError("Scan summary is not a dict")

    return (
        normalize_scan_result_dimensions(scan_result),
        normalize_scan_summary_dimensions(summary),
        scan_updated_at,
    )


def _read_assessment(task_id: str) -> tuple[dict, str, str, str]:
    """Read persisted assessment, updated_at, policy_version, and
    source_scan_updated_at from SQLite.

    Returns:
        (assessment_dict, assessment_updated_at, assessment_policy_version,
         source_scan_updated_at)

    Raises:
        RepairPlanInternalError: If the assessment is missing, cannot
            be parsed, or has an invalid structure.
    """
    conn = None
    _db_error = False
    try:
        init_db()
        conn = _get_connection()
        row = conn.execute(
            "SELECT assessment_json, updated_at, policy_version, "
            "source_scan_updated_at "
            "FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise RepairPlanInternalError(
                "No assessment found for task"
            )
        assessment_json = row["assessment_json"]
        assessment_updated_at = row["updated_at"]
        assessment_policy_version = row["policy_version"]
        source_scan_updated_at = row["source_scan_updated_at"]
    except RepairPlanInternalError:
        _db_error = True
        raise
    except Exception:
        _db_error = True
        raise RepairPlanInternalError(
            "Failed to read assessment from database"
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                if not _db_error:
                    raise RepairPlanInternalError(
                        "Failed to close database connection"
                    )

    # Parse JSON
    try:
        assessment = json.loads(assessment_json)
    except (json.JSONDecodeError, TypeError):
        raise RepairPlanInternalError("Failed to parse assessment JSON")

    if not isinstance(assessment, dict):
        raise RepairPlanInternalError("Assessment is not a dict")

    return (
        assessment, assessment_updated_at, assessment_policy_version,
        source_scan_updated_at,
    )


# ---------------------------------------------------------------------------
# --- Consistency validation ---
# ---------------------------------------------------------------------------

def _validate_consistency(
    task_id: str,
    scan_result: dict,
    summary: dict,
    scan_updated_at: str,
    assessment: dict,
    assessment_updated_at: str,
    assessment_policy_version: str,
    source_scan_updated_at: str,
) -> None:
    """Validate that scan result and assessment are consistent.

    Checks:
    1. assessment.task_id == task_id
    2. source_scan_updated_at (from assessment_results column) ==
       scan_updated_at (from scan_results column)
    3. assessment_policy_version is supported by P0-7

    Raises:
        RepairPlanInternalError: If any check fails. Does NOT generate
            a partial repair plan — the caller must not proceed.
    """
    # Check 1: assessment task_id matches
    if assessment.get("task_id") != task_id:
        raise RepairPlanInternalError("Assessment task_id mismatch")

    # Check 2: source_scan_updated_at (table column) matches scan updated_at
    if source_scan_updated_at != scan_updated_at:
        raise RepairPlanInternalError(
            "Assessment source_scan_updated_at does not match scan updated_at"
        )

    # Check 3: assessment policy version is supported
    if not is_supported_assessment_policy(assessment_policy_version):
        raise RepairPlanInternalError(
            "Unsupported assessment policy version"
        )


# ---------------------------------------------------------------------------
# --- Finding field extraction with strict type validation ---
# ---------------------------------------------------------------------------

def _extract_finding_fields(finding: dict) -> dict:
    """Extract and validate fields from a finding dict.

    Only extracts fields needed for repair plan generation:
    - rule_id, secret_type, repair_template_key, is_blocking
    - severity, confidence, file_path

    All fields are strictly type-validated. Non-str/non-int/non-bool
    values raise RepairPlanInternalError.

    Metadata fields (rule_id, secret_type, repair_template_key,
    file_path) are sanitized via sanitize_prompt_metadata BEFORE
    entering repair groups or agent prompts. This prevents injection
    via newlines, control characters, or Unicode bidi overrides.
    """
    if not isinstance(finding, dict):
        raise RepairPlanInternalError("Finding is not a dict")

    rule_id = finding.get("rule_id", "")
    if rule_id is not None and type(rule_id) is not str:
        raise RepairPlanInternalError("Finding rule_id is not a string")
    rule_id = rule_id or ""

    secret_type = finding.get("secret_type", "")
    if secret_type is not None and type(secret_type) is not str:
        raise RepairPlanInternalError("Finding secret_type is not a string")
    secret_type = secret_type or ""

    repair_template_key = finding.get("repair_template_key", "")
    if repair_template_key is not None and type(repair_template_key) is not str:
        raise RepairPlanInternalError(
            "Finding repair_template_key is not a string"
        )
    repair_template_key = repair_template_key or ""

    is_blocking = finding.get("is_blocking", False)
    if is_blocking is not None and type(is_blocking) is not bool:
        raise RepairPlanInternalError("Finding is_blocking is not a bool")
    is_blocking = bool(is_blocking)

    severity = finding.get("severity", "info")
    if severity is not None and type(severity) is not str:
        raise RepairPlanInternalError("Finding severity is not a string")
    severity = severity or "info"

    confidence = finding.get("confidence", "low")
    if confidence is not None and type(confidence) is not str:
        raise RepairPlanInternalError("Finding confidence is not a string")
    confidence = confidence or "low"

    file_path = finding.get("file_path", "")
    if file_path is not None and type(file_path) is not str:
        raise RepairPlanInternalError("Finding file_path is not a string")
    file_path = file_path or ""

    # Validate integer fields (line_start, line_end, column_start, column_end).
    # These fields are not extracted into the return dict, but they are
    # type-validated to reject malformed input early — a non-int value
    # indicates a corrupted or tampered scan result.
    for _int_field in ("line_start", "line_end", "column_start", "column_end"):
        _iv = finding.get(_int_field)
        if _iv is not None and type(_iv) is not int:
            raise RepairPlanInternalError(
                f"Finding {_int_field} is not an integer"
            )

    # --- Sanitize metadata BEFORE it enters repair groups or prompts ---
    # rule_id: only known R001-R011 values; unknown → <unknown-rule>
    # secret_type, repair_template_key: only safe single-line chars
    # file_path: sanitized via _sanitize_file_path (rejects Cc/Cf/Zl/Zp,
    #   backticks, absolute paths, path traversal)
    rule_id = sanitize_prompt_metadata(rule_id, "rule_id")
    secret_type = sanitize_prompt_metadata(secret_type, "secret_type")
    repair_template_key = sanitize_prompt_metadata(
        repair_template_key, "repair_template_key"
    )
    file_path = sanitize_prompt_metadata(file_path, "file_path")

    return {
        "rule_id": rule_id,
        "secret_type": secret_type,
        "repair_template_key": repair_template_key,
        "is_blocking": is_blocking,
        "severity": severity,
        "confidence": confidence,
        "file_path": file_path,
    }


# ---------------------------------------------------------------------------
# --- Finding → action code expansion ---
# ---------------------------------------------------------------------------

def _expand_finding_actions(
    finding_fields: dict,
) -> tuple[list[tuple[str, dict]], bool, bool]:
    """Expand a finding into (action_code, finding_fields) pairs.

    For blocking findings: uses BLOCKING_ACTION_SEQUENCE (9 actions).
    For non-blocking findings: uses template mapping.
    
    Rule and template validation:
    - Unknown rule_id → needs_manual_review = True
    - Missing/unknown template_key → needs_manual_review = True
    - Known rule_id but template not in allowed set → needs_manual_review = True
    - Blocking findings still get the full blocking sequence, but
      unknown template/rule still sets needs_manual_review = True.

    Returns:
        (pairs, needs_manual_review, rule_template_mismatch)
        pairs: list of (action_code, finding_fields) tuples
        needs_manual_review: True if template key was unknown/missing
        rule_template_mismatch: True if rule_id is unknown or template
            doesn't match the rule's allowed set
    """
    is_blocking = finding_fields["is_blocking"]
    template_key = finding_fields["repair_template_key"]
    rule_id = finding_fields["rule_id"]

    needs_manual_review = False
    rule_template_mismatch = False

    # --- Rule ID validation ---
    if not rule_id or not is_known_rule_id(rule_id):
        # Unknown rule_id
        rule_template_mismatch = True
        needs_manual_review = True

    # --- Template key validation ---
    if not template_key:
        # Missing template key
        needs_manual_review = True
        rule_template_mismatch = True
    elif not is_known_template_key(template_key):
        # Unknown template key
        needs_manual_review = True
        rule_template_mismatch = True
    elif rule_id and is_known_rule_id(rule_id):
        # Known rule_id and known template — check if template is
        # allowed for this rule.
        allowed = get_allowed_template_keys_for_rule(rule_id)
        if allowed is not None and template_key not in allowed:
            # Template doesn't match rule's allowed set
            rule_template_mismatch = True
            needs_manual_review = True

    if is_blocking:
        # Blocking findings ALWAYS use the full blocking sequence,
        # regardless of repair_template_key.
        # But unknown template/rule still flags needs_manual_review.
        actions = BLOCKING_ACTION_SEQUENCE
        return (
            [(ac, finding_fields) for ac in actions],
            needs_manual_review,
            rule_template_mismatch,
        )

    # Non-blocking: use template mapping if known
    if needs_manual_review and not template_key:
        # No valid template — no regular actions
        return [], needs_manual_review, rule_template_mismatch

    template_actions = get_template_actions(template_key)
    if template_actions is None:
        return [], needs_manual_review, rule_template_mismatch

    return (
        [(ac, finding_fields) for ac in template_actions],
        needs_manual_review,
        rule_template_mismatch,
    )


# ---------------------------------------------------------------------------
# --- Aggregation ---
# ---------------------------------------------------------------------------

def _aggregate_groups(
    pairs: list[tuple[str, dict]],
) -> tuple[dict[tuple, dict], dict[str, dict]]:
    """Aggregate (action_code, finding_fields) pairs into repair groups.

    Splits pairs into:
    - Regular groups: aggregated by (action_code, template_key, rule_id, secret_type, blocking)
    - Global singleton groups: aggregated by action_code only

    Returns:
        (regular_groups, singleton_groups)
        regular_groups: dict[aggregation_key → group_data]
        singleton_groups: dict[action_code → group_data]

    Each group_data dict contains:
        action_code, repair_template_key, rule_id, secret_type, blocking,
        findings (list of finding_fields),
        related_files (set), related_rule_ids (set),
        highest_severity, highest_confidence

    BLOCKING SEMANTICS:
    - For regular groups: blocking = the finding's is_blocking value.
    - For singleton groups: blocking = OR of all source findings'
      is_blocking values. If any source finding is blocking,
      the singleton is blocking.
    - Synthetic coverage/manual/error findings have is_blocking=False.
    """
    regular_groups: dict[tuple, dict] = {}
    singleton_groups: dict[str, dict] = {}

    for action_code, ff in pairs:
        if action_code in GLOBAL_SINGLETON_ACTIONS:
            # Global singleton: aggregate by action_code only
            if action_code not in singleton_groups:
                singleton_groups[action_code] = {
                    "action_code": action_code,
                    "repair_template_key": ff["repair_template_key"],
                    "rule_id": ff["rule_id"],
                    "secret_type": ff["secret_type"],
                    # Singleton blocking = finding's is_blocking
                    "blocking": ff["is_blocking"],
                    "findings": [],
                    "related_files": set(),
                    "related_rule_ids": set(),
                    "highest_severity": "info",
                    "highest_confidence": "low",
                }
            group = singleton_groups[action_code]
            # Merge: blocking = OR of existing and new finding
            group["blocking"] = (
                group["blocking"] or ff["is_blocking"]
            )
        else:
            # Regular: aggregate by full key
            agg_key = compute_aggregation_key(
                action_code=action_code,
                repair_template_key=ff["repair_template_key"],
                rule_id=ff["rule_id"],
                secret_type=ff["secret_type"],
                blocking=ff["is_blocking"],
            )
            if agg_key not in regular_groups:
                regular_groups[agg_key] = {
                    "action_code": action_code,
                    "repair_template_key": ff["repair_template_key"],
                    "rule_id": ff["rule_id"],
                    "secret_type": ff["secret_type"],
                    "blocking": ff["is_blocking"],
                    "findings": [],
                    "related_files": set(),
                    "related_rule_ids": set(),
                    "highest_severity": "info",
                    "highest_confidence": "low",
                }
            group = regular_groups[agg_key]

        # Accumulate finding data
        group["findings"].append(ff)
        if ff["file_path"]:
            group["related_files"].add(ff["file_path"])
        if ff["rule_id"]:
            group["related_rule_ids"].add(ff["rule_id"])

        # Update highest severity
        if SEVERITY_ORDER.get(ff["severity"], 99) < SEVERITY_ORDER.get(
            group["highest_severity"], 99
        ):
            group["highest_severity"] = ff["severity"]

        # Update highest confidence
        if CONFIDENCE_ORDER.get(ff["confidence"], 99) < CONFIDENCE_ORDER.get(
            group["highest_confidence"], 99
        ):
            group["highest_confidence"] = ff["confidence"]

    return regular_groups, singleton_groups


# ---------------------------------------------------------------------------
# --- Group building ---
# ---------------------------------------------------------------------------

def _build_group_dict(
    group_data: dict,
    group_id: str,
    max_related_files: int,
) -> tuple[dict, bool]:
    """Build a serializable repair group dict from aggregated group data.

    Applies related_files limit (sorted, deduplicated, truncated).
    Risk-priority retention: higher severity findings' files are kept first.

    Returns:
        (group_dict, related_files_truncated)
    """
    action = get_action(group_data["action_code"])

    # Sort and deduplicate related_files
    all_files = sorted(group_data["related_files"])
    total_related_files = len(all_files)

    # Risk-priority retention: sort findings by severity desc, then
    # collect files from highest severity first.
    sorted_findings = sorted(
        group_data["findings"],
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 99),
            CONFIDENCE_ORDER.get(f["confidence"], 99),
            f["file_path"],
        ),
    )
    priority_files: list[str] = []
    seen: set[str] = set()
    for f in sorted_findings:
        fp = f["file_path"]
        if fp and fp not in seen:
            priority_files.append(fp)
            seen.add(fp)

    # Apply limit, keeping priority files first
    if len(priority_files) > max_related_files:
        returned_files = priority_files[:max_related_files]
        related_files_truncated = True
    else:
        returned_files = priority_files
        related_files_truncated = False

    related_rule_ids = sorted(group_data["related_rule_ids"])

    return {
        "group_id": group_id,
        "action_code": group_data["action_code"],
        "priority": action.priority,
        "blocking": group_data["blocking"],
        "highest_severity": group_data["highest_severity"],
        "highest_confidence": group_data["highest_confidence"],
        "title": action.title,
        "description": action.description,
        "related_rule_ids": related_rule_ids,
        "related_files": returned_files,
        "total_related_files": total_related_files,
        "returned_related_files": len(returned_files),
        "related_files_truncated": related_files_truncated,
        "finding_count": len(group_data["findings"]),
        "steps": list(action.steps),
        "commands": list(action.commands),
        "safety_notes": list(action.safety_notes),
        "verification_steps": list(action.verification_steps),
    }, related_files_truncated


# ---------------------------------------------------------------------------
# --- Sorting and group_id assignment ---
# ---------------------------------------------------------------------------

def _make_synthetic_group_data(action_code: str) -> dict:
    """Create a synthetic group_data dict for a safety action.

    Used when truncation requires adding MANUAL_REVIEW_REQUIRED or
    RERUN_SECURITY_SCAN that were not already present.
    """
    return {
        "action_code": action_code,
        "repair_template_key": "",
        "rule_id": "",
        "secret_type": "",
        "blocking": False,
        "findings": [],
        "related_files": set(),
        "related_rule_ids": set(),
        "highest_severity": "info",
        "highest_confidence": "low",
    }


def _sort_and_assign_ids(
    mandatory_groups: list[dict],
    optional_groups: list[dict],
    max_groups: int,
) -> tuple[list[dict], bool, bool]:
    """Sort groups deterministically and assign group_ids.

    Mandatory groups are ALWAYS preserved. Optional groups fill the
    remaining space up to max_groups.

    Algorithm:
    1. Sort mandatory and optional SEPARATELY.
    2. If mandatory alone exceeds max_groups → raise RepairPlanTooLargeError.
    3. Select all mandatory, then fill remaining slots with optional.
    4. If optional groups or related_files are truncated, add
       MANUAL_REVIEW_REQUIRED + RERUN_SECURITY_SCAN to mandatory
       (if not already present). If that makes mandatory exceed
       max_groups → raise RepairPlanTooLargeError.
    5. Combine selected mandatory + selected optional.
    6. Final deterministic sort — NO re-slicing after this point.
    7. Assign group_ids only after the final set is determined.

    Returns:
        (sorted_groups, groups_truncated, any_files_truncated)
        groups_truncated: True only if optional groups were omitted
    """
    max_related_files = max(1, int(settings.repair_max_related_files_per_group))

    # Compute sort key for each group
    def _sort_key(gd: dict) -> tuple:
        first_file = ""
        if gd["related_files"]:
            sorted_files = sorted(gd["related_files"])
            first_file = sorted_files[0] if sorted_files else ""
        action = get_action(gd["action_code"])
        return compute_group_sort_key(
            blocking=gd["blocking"],
            priority=action.priority,
            highest_severity=gd["highest_severity"],
            highest_confidence=gd["highest_confidence"],
            action_code=gd["action_code"],
            repair_template_key=gd["repair_template_key"],
            rule_id=gd["rule_id"],
            secret_type=gd["secret_type"],
            related_files_first=first_file,
        )

    # 1. Sort mandatory and optional separately
    mandatory_sorted = sorted(mandatory_groups, key=_sort_key)
    optional_sorted = sorted(optional_groups, key=_sort_key)

    # 2. Check if mandatory alone exceeds limit
    if len(mandatory_sorted) > max_groups:
        raise RepairPlanTooLargeError(
            "Mandatory repair groups exceed repair_max_groups"
        )

    # 3. Select optional groups to fill remaining slots
    remaining = max_groups - len(mandatory_sorted)
    selected_optional = optional_sorted[:remaining]
    groups_truncated = len(optional_sorted) > remaining

    # 4. Check for related_files truncation in the selected set
    any_files_truncated = any(
        len(gd["related_files"]) > max_related_files
        for gd in mandatory_sorted + selected_optional
    )

    # 5. If truncation occurred, ensure safety actions are in mandatory
    if groups_truncated or any_files_truncated:
        existing_actions = {gd["action_code"] for gd in mandatory_sorted}
        added = False
        for ac in (ACTION_MANUAL_REVIEW_REQUIRED, ACTION_RERUN_SECURITY_SCAN):
            if ac not in existing_actions:
                mandatory_sorted.append(_make_synthetic_group_data(ac))
                added = True

        if added:
            # Re-sort mandatory after adding
            mandatory_sorted = sorted(mandatory_sorted, key=_sort_key)

            # Re-check if mandatory now exceeds limit
            if len(mandatory_sorted) > max_groups:
                raise RepairPlanTooLargeError(
                    "Mandatory repair groups with safety actions "
                    "exceed repair_max_groups"
                )

            # Recalculate remaining and selected_optional
            remaining = max_groups - len(mandatory_sorted)
            selected_optional = optional_sorted[:remaining]
            groups_truncated = len(optional_sorted) > remaining

    # 6. Combine and final sort — NO re-slicing after this
    selected = mandatory_sorted + selected_optional
    selected.sort(key=_sort_key)

    # 7. Assign group_ids and build final dicts
    sorted_groups: list[dict] = []
    for idx, gd in enumerate(selected):
        group_id = f"RG{idx + 1:03d}"
        group_dict, files_truncated = _build_group_dict(
            gd, group_id, max_related_files
        )
        if files_truncated:
            any_files_truncated = True
        sorted_groups.append(group_dict)

    return sorted_groups, groups_truncated, any_files_truncated


# ---------------------------------------------------------------------------
# --- Partial plan detection ---
# ---------------------------------------------------------------------------

def _detect_partial_conditions(
    summary: dict,
    assessment: dict,
    findings: list,
    has_unknown_template: bool,
    has_blocking: bool,
) -> tuple[bool, list[str]]:
    """Detect partial plan conditions and determine which MANDATORY
    action groups must be added.

    This function is called BEFORE truncation, so it does NOT depend
    on groups_truncated or any_files_truncated. Those conditions are
    checked separately after truncation.

    Returns:
        (is_partial, mandatory_action_codes)
        is_partial: True if any pre-truncation partial condition is met
        mandatory_action_codes: action codes that MUST be added as
            mandatory groups (global singletons)
    """
    is_partial = False
    mandatory_actions: list[str] = []

    # --- Blocking findings → VERIFY_NO_SECRET_REMAINS + RERUN_SECURITY_SCAN ---
    if has_blocking:
        if ACTION_VERIFY_NO_SECRET_REMAINS not in mandatory_actions:
            mandatory_actions.append(ACTION_VERIFY_NO_SECRET_REMAINS)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    # --- findings_truncated → REVIEW_SCAN_COVERAGE + RERUN_SECURITY_SCAN ---
    if summary.get("findings_truncated", False):
        is_partial = True
        if ACTION_REVIEW_SCAN_COVERAGE not in mandatory_actions:
            mandatory_actions.append(ACTION_REVIEW_SCAN_COVERAGE)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    # --- scan errors → RESOLVE_SCAN_ERROR + RERUN_SECURITY_SCAN ---
    total_scan_errors = summary.get("total_scan_errors", 0)
    if isinstance(total_scan_errors, bool) or not isinstance(total_scan_errors, int):
        total_scan_errors = 0
    if total_scan_errors > 0:
        is_partial = True
        if ACTION_RESOLVE_SCAN_ERROR not in mandatory_actions:
            mandatory_actions.append(ACTION_RESOLVE_SCAN_ERROR)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    # --- no files scanned → REVIEW_SCAN_COVERAGE + RERUN_SECURITY_SCAN ---
    total_files = summary.get("total_files_scanned", 0)
    if isinstance(total_files, bool) or not isinstance(total_files, int):
        total_files = 0
    if total_files == 0:
        is_partial = True
        if ACTION_REVIEW_SCAN_COVERAGE not in mandatory_actions:
            mandatory_actions.append(ACTION_REVIEW_SCAN_COVERAGE)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    # --- assessment coverage partial → REVIEW_SCAN_COVERAGE + RERUN ---
    coverage = assessment.get("coverage", {})
    if isinstance(coverage, dict) and coverage.get("status") == "partial":
        is_partial = True
        if ACTION_REVIEW_SCAN_COVERAGE not in mandatory_actions:
            mandatory_actions.append(ACTION_REVIEW_SCAN_COVERAGE)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    # --- assessment findings_truncated → REVIEW_SCAN_COVERAGE + RERUN ---
    if isinstance(coverage, dict) and coverage.get("findings_truncated", False):
        is_partial = True
        if ACTION_REVIEW_SCAN_COVERAGE not in mandatory_actions:
            mandatory_actions.append(ACTION_REVIEW_SCAN_COVERAGE)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    # --- blocking_findings count > actual → REVIEW_SCAN_COVERAGE + RERUN ---
    total_blocking = summary.get("blocking_findings", 0)
    if isinstance(total_blocking, bool) or not isinstance(total_blocking, int):
        total_blocking = 0
    actual_blocking = sum(1 for f in findings if f.get("is_blocking", False))
    if total_blocking > actual_blocking:
        is_partial = True
        if ACTION_REVIEW_SCAN_COVERAGE not in mandatory_actions:
            mandatory_actions.append(ACTION_REVIEW_SCAN_COVERAGE)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    # --- unknown/missing template or rule → MANUAL_REVIEW + RERUN ---
    if has_unknown_template:
        is_partial = True
        if ACTION_MANUAL_REVIEW_REQUIRED not in mandatory_actions:
            mandatory_actions.append(ACTION_MANUAL_REVIEW_REQUIRED)
        if ACTION_RERUN_SECURITY_SCAN not in mandatory_actions:
            mandatory_actions.append(ACTION_RERUN_SECURITY_SCAN)

    return is_partial, mandatory_actions


# ---------------------------------------------------------------------------
# --- Agent prompt generation ---
# ---------------------------------------------------------------------------

def _validate_agent_prompt(prompt: str) -> str:
    """Validate the final agent_prompt against forbidden content.

    Checks the VARIABLE portion of the prompt (everything after the
    fixed safety header and requirements) for:
    - Forbidden field names (repo_url, owner, snippet, etc.)
    - URLs, credential patterns, absolute paths
    - Format/bidi Unicode characters (Cf, Zl, Zp)

    Note: Cc (control) is NOT checked on the full prompt because
    newlines (\n) are legitimate prompt formatting. Cc is already
    checked on metadata fields via sanitize_prompt_metadata.

    If any forbidden content is found, raises RepairPlanInternalError.
    This ensures AGENT_PROMPT_FORBIDDEN_FIELDS and
    AGENT_PROMPT_FORBIDDEN_PATTERNS are used on the PRODUCTION path,
    not just imported in tests.
    """
    # Check for format/bidi characters (Cf, Zl, Zp) in the entire prompt.
    # These should NEVER appear — not even newlines justify them.
    # Cc is excluded because \n is a legitimate Cc character in prompts.
    _prompt_forbidden = frozenset({"Cf", "Zl", "Zp"})
    for ch in prompt:
        if unicodedata.category(ch) in _prompt_forbidden:
            raise RepairPlanInternalError(
                "Agent prompt contains forbidden Unicode format character"
            )

    # Extract the variable portion (after fixed content)
    # The fixed content ends before "## 修复动作摘要"
    marker = "## 修复动作摘要"
    marker_idx = prompt.find(marker)
    if marker_idx < 0:
        # No variable content — only fixed content, which is safe
        variable_part = ""
    else:
        variable_part = prompt[marker_idx + len(marker):]

    # Check for forbidden field names in the variable portion
    for field in AGENT_PROMPT_FORBIDDEN_FIELDS:
        if field in variable_part:
            raise RepairPlanInternalError(
                f"Agent prompt contains forbidden field: {field}"
            )

    # Check for forbidden patterns in the variable portion
    for pattern in AGENT_PROMPT_FORBIDDEN_PATTERNS:
        if re.search(pattern, variable_part):
            raise RepairPlanInternalError(
                "Agent prompt contains forbidden pattern"
            )

    return prompt


def _generate_agent_prompt(
    repair_groups: list[dict],
    plan_status: str,
    max_chars: int,
) -> str:
    """Generate a deterministic agent prompt from repair groups.

    The prompt is split into:
    1. Fixed safety header (always complete)
    2. Partial declaration (if partial, always complete)
    3. 11 fixed safety requirements (always complete)
    4. Variable repair action summary (can be truncated)

    GUARANTEE: Every successful return path produces a prompt with
    len(prompt) <= max_chars. If this is impossible, raises
    RepairPlanTooLargeError — never returns an over-limit prompt.

    The prompt contains ONLY:
    - rule_id, secret_type, repair_template_key (sanitized, single-line)
    - relative file_path (sanitized, no backticks, JSON-quoted)
    - Finding count
    - Repair action summary

    It does NOT contain: repo_url, owner, repo_name, snippet,
    snippet_masked, raw secrets, database paths, or temp paths.

    The final prompt is validated against AGENT_PROMPT_FORBIDDEN_FIELDS
    and AGENT_PROMPT_FORBIDDEN_PATTERNS before returning.
    """
    # --- Build fixed content (always complete) ---
    fixed_lines: list[str] = []
    fixed_lines.append("# VibeCheck 安全修复指引")
    fixed_lines.append("")

    if plan_status == "partial":
        fixed_lines.append(PARTIAL_DECLARATION)
        fixed_lines.append("")

    fixed_lines.append("## 安全要求")
    fixed_lines.append("")
    for req in AGENT_PROMPT_REQUIREMENTS:
        fixed_lines.append(req)

    fixed_content = "\n".join(fixed_lines)

    # 1. Fixed content alone exceeds max_chars → impossible to proceed.
    if len(fixed_content) > max_chars:
        raise RepairPlanTooLargeError(
            "Agent prompt fixed content exceeds max_chars"
        )

    # Initialise prompt to fixed_content — the minimum safe result.
    prompt = fixed_content

    if repair_groups:
        # --- Build variable content (action summary, can be truncated) ---
        variable_header = "\n\n## 修复动作摘要\n\n"
        remaining_chars = (
            max_chars - len(fixed_content) - len(variable_header)
        )

        if remaining_chars > 0:
            # 2. variable_header fits — try to add repair group lines.
            variable_lines: list[str] = []
            current_len = 0

            for group in repair_groups:
                action_code = group.get("action_code", "")
                title = group.get("title", "")
                finding_count = group.get("finding_count", 0)
                rule_ids = group.get("related_rule_ids", [])
                related_files = group.get("related_files", [])

                # Build action summary line — only safe fields
                line_parts = [f"- [{action_code}] {title}"]
                if finding_count > 0:
                    line_parts.append(f"({finding_count}个发现)")
                if rule_ids:
                    rule_str = ", ".join(rule_ids[:10])
                    line_parts.append(f"规则: {rule_str}")
                action_line = " ".join(line_parts)

                line_with_nl = action_line + "\n"
                if current_len + len(line_with_nl) > remaining_chars:
                    break
                variable_lines.append(action_line)
                current_len += len(line_with_nl)

                if related_files:
                    safe_files = [
                        json.dumps(fp, ensure_ascii=False)
                        for fp in related_files[:10]
                    ]
                    files_line = f"  相关文件: {' '.join(safe_files)}"
                    files_with_nl = files_line + "\n"
                    if current_len + len(files_with_nl) > remaining_chars:
                        break
                    variable_lines.append(files_line)
                    current_len += len(files_with_nl)

            if variable_lines:
                prompt = (
                    fixed_content
                    + variable_header
                    + "\n".join(variable_lines)
                )
            else:
                # 3. variable_header fits but no complete group line
                #    fits — return fixed_content + header.rstrip()
                #    only if within max_chars.
                candidate = fixed_content + variable_header.rstrip()
                if len(candidate) <= max_chars:
                    prompt = candidate
                # else: prompt stays as fixed_content
        # else: remaining_chars <= 0 — prompt stays as fixed_content.
        # Do NOT append a header that would exceed max_chars.

    # --- ABSOLUTE GUARANTEE: every successful return path passes
    #     this check. No over-limit prompt can ever be returned. ---
    if len(prompt) > max_chars:
        raise RepairPlanTooLargeError(
            "Agent prompt exceeds max_chars"
        )

    return _validate_agent_prompt(prompt)


# ---------------------------------------------------------------------------
# --- Verification steps generation ---
# ---------------------------------------------------------------------------

def _generate_verification_steps(
    plan_status: str,
    has_blocking: bool,
) -> list[str]:
    """Generate top-level verification steps.

    These are global steps that apply to the entire repair plan.
    """
    steps: list[str] = []

    if has_blocking:
        steps.append("确认所有blocking问题已按顺序完成修复。")
        steps.append("确认旧凭据已撤销，新凭据已通过环境变量注入。")

    steps.append("运行仓库现有文档或CI中规定的测试命令。")

    if plan_status == "partial":
        steps.append(PARTIAL_DECLARATION)

    steps.append("重新向VibeCheck提交仓库进行复检。")

    return steps


# ---------------------------------------------------------------------------
# --- Core repair plan generation ---
# ---------------------------------------------------------------------------

def generate_repair_plan(
    task_id: str,
    scan_result: dict,
    summary: dict,
    scan_updated_at: str,
    assessment: dict,
    assessment_updated_at: str,
    assessment_policy_version: str,
    source_scan_updated_at: str,
) -> dict:
    """Compute a deterministic repair plan from persisted results.

    This is the core generation function. It takes already-desensitized
    scan result, summary, and assessment and produces a RepairPlan dict.

    Does NOT modify any input.
    Does NOT access temp directories or the network.
    Does NOT execute repository code.
    Does NOT call an LLM.

    Args:
        task_id:                    The task ID.
        scan_result:                The persisted scan result dict.
        summary:                    The persisted scan summary dict.
        scan_updated_at:            The scan_results.updated_at.
        assessment:                 The persisted assessment dict.
        assessment_updated_at:      The assessment_results.updated_at.
        assessment_policy_version:  The assessment_results.policy_version.
        source_scan_updated_at:     The assessment_results.source_scan_updated_at.

    Returns:
        A RepairPlan dict with the fixed structure.

    Note: created_at and updated_at are set to None — the persistence
    layer determines the final timestamps.
    """
    # 1. Validate consistency
    _validate_consistency(
        task_id, scan_result, summary, scan_updated_at,
        assessment, assessment_updated_at, assessment_policy_version,
        source_scan_updated_at,
    )

    # 2. Extract findings
    raw_findings = scan_result.get("findings", [])
    if not isinstance(raw_findings, list):
        raise RepairPlanInternalError("Findings is not a list")

    # 3. Extract and validate finding fields
    findings: list[dict] = []
    has_unknown_template = False
    for raw_f in raw_findings:
        if not isinstance(raw_f, dict):
            raise RepairPlanInternalError("Finding is not a dict")
        if raw_f.get("dimension", SENSITIVE_DATA_DIMENSION) != SENSITIVE_DATA_DIMENSION:
            continue
        ff = _extract_finding_fields(raw_f)
        # Sanitize file_path early — before aggregation and prompt
        ff["file_path"] = _sanitize_file_path(ff["file_path"])
        findings.append(ff)

    summary = scope_summary_to_sensitive_data(summary, len(findings))

    # Check for blocking findings
    has_blocking = any(f["is_blocking"] for f in findings)

    # 4. Expand findings into (action_code, finding_fields) pairs
    #    Also validates rule_id and template_key mappings
    all_pairs: list[tuple[str, dict]] = []
    for ff in findings:
        pairs, needs_manual, _mismatch = _expand_finding_actions(ff)
        all_pairs.extend(pairs)
        if needs_manual:
            has_unknown_template = True

    # 5. Detect partial conditions BEFORE any truncation
    is_partial, mandatory_action_codes = _detect_partial_conditions(
        summary, assessment, findings,
        has_unknown_template, has_blocking,
    )

    # 6. Add mandatory synthetic findings for partial conditions
    for ac in mandatory_action_codes:
        # Check if this action is already present from findings
        already_present = any(
            ac == pair[0] for pair in all_pairs
        )
        if not already_present:
            synthetic_finding = {
                "rule_id": "",
                "secret_type": "",
                "repair_template_key": "",
                "is_blocking": False,
                "severity": "info",
                "confidence": "low",
                "file_path": "",
            }
            all_pairs.append((ac, synthetic_finding))

    # 7. Aggregate into groups
    regular_groups, singleton_groups = _aggregate_groups(all_pairs)

    # 8. Split into mandatory and optional groups
    #    Mandatory = global singleton actions (safety-critical) +
    #                regular groups from blocking findings
    #    Optional = regular groups from non-blocking findings only
    #    blocking Finding's complete fixed action sequence must NEVER
    #    be treated as optional — it is always mandatory.
    mandatory_group_data: list[dict] = list(singleton_groups.values()) + [
        g for g in regular_groups.values() if g["blocking"]
    ]
    optional_group_data: list[dict] = [
        g for g in regular_groups.values() if not g["blocking"]
    ]

    # 9. Sort and assign group IDs (single pass, mandatory preserved)
    max_groups = max(1, int(settings.repair_max_groups))
    sorted_groups, groups_truncated, any_files_truncated = (
        _sort_and_assign_ids(
            mandatory_group_data, optional_group_data, max_groups,
        )
    )

    # 10. Post-truncation partial conditions
    if groups_truncated or any_files_truncated:
        is_partial = True

    # 11. Determine plan_status
    plan_status = "partial" if is_partial else "complete"

    # 12. Build summary (recalculated from final sorted_groups)
    blocking_repair_groups = sum(1 for g in sorted_groups if g["blocking"])
    manual_review_required = any(
        g["action_code"] == ACTION_MANUAL_REVIEW_REQUIRED
        for g in sorted_groups
    )
    coverage_warning = is_partial

    repair_summary = {
        "total_repair_groups": len(sorted_groups),
        "blocking_repair_groups": blocking_repair_groups,
        "manual_review_required": manual_review_required,
        "coverage_warning": coverage_warning,
        "groups_truncated": groups_truncated,
    }

    # 13. Generate verification steps
    verification_steps = _generate_verification_steps(
        plan_status, has_blocking
    )

    # 14. Generate agent prompt
    max_prompt_chars = max(1, int(settings.repair_max_agent_prompt_chars))
    agent_prompt = _generate_agent_prompt(
        sorted_groups, plan_status, max_prompt_chars
    )

    # 15. Assemble RepairPlan
    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": task_id,
        "plan_status": plan_status,
        "summary": repair_summary,
        "repair_groups": sorted_groups,
        "verification_steps": verification_steps,
        "agent_prompt": agent_prompt,
        "source_scan_updated_at": scan_updated_at,
        "source_assessment_updated_at": assessment_updated_at,
        "source_assessment_policy_version": assessment_policy_version,
        "created_at": None,
        "updated_at": None,
    }


# ---------------------------------------------------------------------------
# --- Explicit serialization boundary ---
# ---------------------------------------------------------------------------

def _serialize_repair_group(group: dict) -> dict:
    """Whitelist and mask a single repair group.

    Rebuilds ALL policy fields from the frozen RepairAction definition.
    Does NOT trust the input for:
    - priority, title, description, steps, commands, safety_notes,
      verification_steps
    
    These are ALWAYS rebuilt from get_action(action_code).
    
    Only group_id, blocking, severity, confidence, related_rule_ids,
    related_files, and count fields are validated from input.
    
    File paths are sanitized via _sanitize_file_path.
    """
    if not isinstance(group, dict):
        raise RepairPlanSerializationError(
            "Repair group must be a dict"
        )

    # --- Validate action_code and rebuild policy fields ---
    action_code = _safe_masked_str(group.get("action_code"))
    if not is_valid_action_code(action_code):
        raise RepairPlanSerializationError(
            "Invalid action_code rejected by serialization boundary"
        )
    
    # Rebuild from frozen policy — never trust input
    action = get_action(action_code)
    
    # commands MUST come from the fixed allowlist only
    safe_commands = list(get_allowed_commands(action_code))

    _related_rule_ids = group.get("related_rule_ids", [])
    if not isinstance(_related_rule_ids, list):
        raise RepairPlanSerializationError(
            "related_rule_ids must be a list"
        )
    _related_files = group.get("related_files", [])
    if not isinstance(_related_files, list):
        raise RepairPlanSerializationError(
            "related_files must be a list"
        )

    # Validate count consistency (input checks before normalization)
    _input_total = _strict_int(
        group.get("total_related_files", 0), minimum=0
    )
    _input_returned = len(_related_files)
    _input_truncated = _strict_bool(
        group.get("related_files_truncated", False)
    )

    if _input_returned != _strict_int(
        group.get("returned_related_files", 0), minimum=0
    ):
        raise RepairPlanSerializationError(
            "returned_related_files does not match len(related_files)"
        )
    if _input_total < _input_returned:
        raise RepairPlanSerializationError(
            "total_related_files < returned_related_files"
        )
    if _input_truncated != (_input_total > _input_returned):
        raise RepairPlanSerializationError(
            "related_files_truncated inconsistent with counts"
        )

    # --- Normalize related_files: sanitize, reject empty, deduplicate, sort ---
    # Each element must be a non-empty string that sanitizes to a non-empty
    # normalized path. Empty strings are REJECTED, not silently deleted —
    # silent deletion would lose Finding positions.
    _sanitized: list[str] = []
    for f in _related_files:
        if not isinstance(f, str):
            raise RepairPlanSerializationError(
                "related_files contains non-string value"
            )
        if not f:
            raise RepairPlanSerializationError(
                "related_files contains empty string"
            )
        sanitized = _sanitize_file_path(f)
        if not sanitized:
            raise RepairPlanSerializationError(
                "related_files contains path that sanitizes to empty"
            )
        # Defensive idempotency check: _sanitize_file_path must be
        # idempotent. If it is not, the path is not canonical and
        # cannot be safely persisted. This is a defense-in-depth layer
        # on top of the guarantee that _sanitize_file_path itself is
        # idempotent by construction.
        if _sanitize_file_path(sanitized) != sanitized:
            raise RepairPlanSerializationError(
                "related_files path is not canonical"
            )
        _sanitized.append(sanitized)
    _normalized = sorted(set(_sanitized))

    # Recompute counts from the normalized list.
    # If input was not truncated, adjust total to match normalized count
    # (deduplication may have reduced the list).  If input was truncated,
    # preserve the original total (it represents files omitted by the
    # max_related_files limit, not by normalization).
    returned_related = len(_normalized)
    if _input_truncated:
        total_related = max(_input_total, returned_related)
        files_truncated = True
    else:
        total_related = returned_related
        files_truncated = False

    return {
        "group_id": _safe_masked_str(group.get("group_id")),
        "action_code": action_code,
        "priority": action.priority,
        "blocking": _strict_bool(group.get("blocking", False)),
        "highest_severity": _safe_masked_str(group.get("highest_severity")),
        "highest_confidence": _safe_masked_str(group.get("highest_confidence")),
        # Rebuilt from frozen policy:
        "title": action.title,
        "description": _safe_masked_desc(action.description),
        "related_rule_ids": sorted(set(
            _validate_rule_id_for_output(r) for r in _related_rule_ids
        )),
        "related_files": _normalized,
        "total_related_files": total_related,
        "returned_related_files": returned_related,
        "related_files_truncated": files_truncated,
        "finding_count": _strict_int(
            group.get("finding_count", 0), minimum=0
        ),
        # Rebuilt from frozen policy:
        "steps": [_safe_masked_desc(s) for s in action.steps],
        "commands": [_safe_masked_str(c) for c in safe_commands],
        "safety_notes": [_safe_masked_desc(s) for s in action.safety_notes],
        "verification_steps": [
            _safe_masked_desc(s) for s in action.verification_steps
        ],
    }


# ---------------------------------------------------------------------------
# --- Shared snapshot identity validation ---
# ---------------------------------------------------------------------------

def _validate_repair_snapshot_identity(
    *,
    task_id: Any,
    source_scan_updated_at: Any,
    source_assessment_updated_at: Any,
    source_assessment_policy_version: Any,
    created_at: Any,
    updated_at: Any,
    error_cls: type[Exception],
) -> None:
    """Shared top-level identity and version chain validation.

    Used by BOTH the serialization boundary and the read validation
    boundary to enforce identical rules on identity fields.

    Invariants enforced:
    1. task_id: must be a non-empty str with no control characters.
       No implicit str conversion allowed.
    2. source_scan_updated_at, source_assessment_updated_at,
       created_at, updated_at: must each be a non-empty str.
       Rejects None, bool, int, float, list, dict, empty string.
    3. source_assessment_policy_version: must be a non-empty str AND
       is_supported_assessment_policy(...) must return True.

    Args:
        error_cls: The exception class to raise on validation failure.
            RepairPlanSerializationError at serialization time,
            RepairPlanInternalError at read time.

    Raises:
        error_cls: If any invariant is violated.
    """
    def _fail(msg: str) -> None:
        raise error_cls(msg)

    def _validate_non_empty_str(
        value: Any, field_name: str
    ) -> None:
        """Strict validation: must be exactly str (not bool/int/etc)
        and non-empty. No implicit conversion."""
        if type(value) is not str:
            _fail(f"{field_name} is not a str")
        if not value:
            _fail(f"{field_name} is empty")

    # 1. task_id: strict str, non-empty, no control characters
    _validate_non_empty_str(task_id, "task_id")
    if _has_forbidden_unicode(task_id):
        _fail("task_id contains control characters")

    # 2. Non-empty str fields
    _validate_non_empty_str(
        source_scan_updated_at, "source_scan_updated_at"
    )
    _validate_non_empty_str(
        source_assessment_updated_at, "source_assessment_updated_at"
    )
    _validate_non_empty_str(created_at, "created_at")
    _validate_non_empty_str(updated_at, "updated_at")

    # 3. source_assessment_policy_version: non-empty str + supported
    _validate_non_empty_str(
        source_assessment_policy_version,
        "source_assessment_policy_version",
    )
    if not is_supported_assessment_policy(source_assessment_policy_version):
        _fail("source_assessment_policy_version is not supported")


# ---------------------------------------------------------------------------
# --- Shared snapshot semantics validation ---
# ---------------------------------------------------------------------------

def _validate_repair_snapshot_semantics(
    plan_status: str,
    summary: dict,
    repair_groups: list[dict],
    error_cls: type[Exception],
) -> None:
    """Shared snapshot semantics validation used by BOTH the serialization
    boundary and the read validation boundary.

    This function enforces the deterministic invariants that MUST hold
    for any valid repair plan snapshot. It is called:
    - At serialization time (error_cls = RepairPlanSerializationError)
    - At read time (error_cls = RepairPlanInternalError)

    Invariants enforced:
    1. coverage_warning == (plan_status == "partial")
    2. If any partial-trigger action exists (MANUAL_REVIEW_REQUIRED,
       REVIEW_SCAN_COVERAGE, RESOLVE_SCAN_ERROR), then plan_status must
       be "partial" and coverage_warning must be True.
    3. groups_truncated == True requires:
       plan_status == "partial", coverage_warning == True,
       MANUAL_REVIEW_REQUIRED present, RERUN_SECURITY_SCAN present.
    4. Any related_files_truncated == True requires the same four
       conditions as groups_truncated.
    5. plan_status == "complete": no partial-trigger actions,
       no groups_truncated, no related_files_truncated,
       coverage_warning must be False.
    6. plan_status == "partial": must have at least one verifiable
       partial reason (partial-trigger action, groups_truncated,
       or related_files_truncated).

    Args:
        plan_status: "complete" or "partial"
        summary: The summary dict (must contain coverage_warning,
                 groups_truncated as bools)
        repair_groups: List of safe repair group dicts
        error_cls: The exception class to raise on validation failure

    Raises:
        error_cls: If any invariant is violated.
    """
    def _fail(msg: str) -> None:
        raise error_cls(msg)

    coverage_warning = summary.get("coverage_warning")
    groups_truncated = summary.get("groups_truncated")

    # 0. Validate ALL repair_groups elements are dicts BEFORE any
    #    field access. This prevents AttributeError/TypeError/KeyError
    #    from escaping when groups are corrupted.
    for g in repair_groups:
        if not isinstance(g, dict):
            _fail("repair_group is not a dict")

    # 1. coverage_warning == (plan_status == "partial")
    expected_cw = (plan_status == "partial")
    if coverage_warning != expected_cw:
        _fail("coverage_warning does not match plan_status")

    # Compute action_codes from repair_groups (all verified as dicts)
    action_codes = {g["action_code"] for g in repair_groups}

    _partial_trigger_actions = {
        ACTION_MANUAL_REVIEW_REQUIRED,
        ACTION_REVIEW_SCAN_COVERAGE,
        ACTION_RESOLVE_SCAN_ERROR,
    }
    has_partial_trigger = bool(action_codes & _partial_trigger_actions)

    # 2. Partial-trigger actions require partial + coverage_warning
    if has_partial_trigger:
        if plan_status != "partial":
            _fail("partial-trigger action present but plan_status is not partial")
        if not coverage_warning:
            _fail("partial-trigger action present but coverage_warning is false")

    # 3. groups_truncated semantics
    if groups_truncated:
        if plan_status != "partial":
            _fail("groups_truncated is true but plan_status is not partial")
        if not coverage_warning:
            _fail("groups_truncated is true but coverage_warning is false")
        if ACTION_MANUAL_REVIEW_REQUIRED not in action_codes:
            _fail("groups_truncated is true but MANUAL_REVIEW_REQUIRED is missing")
        if ACTION_RERUN_SECURITY_SCAN not in action_codes:
            _fail("groups_truncated is true but RERUN_SECURITY_SCAN is missing")

    # 4. related_files_truncated semantics
    for g in repair_groups:
        if g.get("related_files_truncated") is True:
            if plan_status != "partial":
                _fail("related_files_truncated is true but plan_status is not partial")
            if not coverage_warning:
                _fail("related_files_truncated is true but coverage_warning is false")
            if ACTION_MANUAL_REVIEW_REQUIRED not in action_codes:
                _fail("related_files_truncated is true but MANUAL_REVIEW_REQUIRED is missing")
            if ACTION_RERUN_SECURITY_SCAN not in action_codes:
                _fail("related_files_truncated is true but RERUN_SECURITY_SCAN is missing")
            break

    # 5. plan_status == "complete" constraints
    if plan_status == "complete":
        if has_partial_trigger:
            _fail("complete plan_status but partial-trigger action present")
        if groups_truncated:
            _fail("complete plan_status but groups_truncated is true")
        for g in repair_groups:
            if g.get("related_files_truncated") is True:
                _fail("complete plan_status but related_files_truncated is true")
                break
        if coverage_warning:
            _fail("complete plan_status but coverage_warning is true")

    # 6. plan_status == "partial" must have at least one verifiable reason
    if plan_status == "partial":
        has_files_truncated = any(
            g.get("related_files_truncated") is True
            for g in repair_groups
        )
        if not (has_partial_trigger or groups_truncated or has_files_truncated):
            _fail("partial plan_status but no verifiable partial reason")


def _serialize_summary(
    summary: dict, repair_groups: list[dict], plan_status: str
) -> dict:
    """Whitelist and mask the summary structure.
    
    Recalculates total_repair_groups, blocking_repair_groups, and
    manual_review_required from the final safe repair_groups list.
    Does NOT trust the input summary for these computed fields.

    coverage_warning is rebuilt from plan_status:
        coverage_warning = (plan_status == "partial")
    This enforces the deterministic invariant at the serialization
    boundary — the input summary's coverage_warning is NEVER trusted.

    groups_truncated is strictly read from the input (must be a bool),
    but its semantic consistency with actions is validated separately
    in serialize_repair_plan.
    """
    if not isinstance(summary, dict):
        raise RepairPlanSerializationError("summary must be a dict")
    
    # Recalculate from final safe groups
    total = len(repair_groups)
    blocking = sum(1 for g in repair_groups if g.get("blocking") is True)
    manual = any(
        g.get("action_code") == ACTION_MANUAL_REVIEW_REQUIRED
        for g in repair_groups
    )
    
    # coverage_warning rebuilt from plan_status — NEVER trust input
    coverage_warning = (plan_status == "partial")
    
    return {
        "total_repair_groups": total,
        "blocking_repair_groups": blocking,
        "manual_review_required": manual,
        "coverage_warning": coverage_warning,
        "groups_truncated": _strict_bool(
            summary.get("groups_truncated", False)
        ),
    }


def serialize_repair_plan(
    task_id: str,
    repair_plan: dict,
    source_scan_updated_at: str,
    source_assessment_updated_at: str,
    source_assessment_policy_version: str,
    created_at: str,
    updated_at: str,
) -> dict:
    """Explicit serialization boundary for RepairPlan.

    Constructs the safe dict that gets persisted as repair_json.
    Forces identity fields from policy constants. Enforces strict
    field whitelists and defensive desensitization.

    Source version chain fields are taken from AUTHORITATIVE parameters,
    NOT from the repair_plan dict. This ensures JSON and database
    columns always match.

    Identity validation order:
    1. Strict type validation (must be exact str, no implicit conversion)
    2. Non-empty validation
    3. Policy validation (supported assessment policy version)
    4. Safe masking (mask_untrusted_text)
    5. Save to output dict

    created_at MUST be a non-empty str — the persistence layer resolves
    it to the final timestamp before calling this function.
    """
    if not isinstance(repair_plan, dict):
        raise RepairPlanSerializationError("Repair plan must be a dict")

    # --- Validate top-level identity fields BEFORE any processing ---
    # Strict type → non-empty → policy → safe mask
    _validate_repair_snapshot_identity(
        task_id=task_id,
        source_scan_updated_at=source_scan_updated_at,
        source_assessment_updated_at=source_assessment_updated_at,
        source_assessment_policy_version=source_assessment_policy_version,
        created_at=created_at,
        updated_at=updated_at,
        error_cls=RepairPlanSerializationError,
    )

    # Apply safe masking AFTER validation passes
    safe_task_id = _safe_masked_str(task_id)
    safe_source_scan = _safe_masked_str(source_scan_updated_at)
    safe_source_assess = _safe_masked_str(source_assessment_updated_at)
    safe_source_policy = _safe_masked_str(source_assessment_policy_version)
    safe_created_at = _safe_masked_str(created_at)
    safe_updated_at = _safe_masked_str(updated_at)

    _groups = repair_plan.get("repair_groups", [])
    if not isinstance(_groups, list):
        raise RepairPlanSerializationError("repair_groups must be a list")

    # Validate plan_status
    plan_status = repair_plan.get("plan_status")
    if not isinstance(plan_status, str) or plan_status not in (
        "complete", "partial"
    ):
        raise RepairPlanSerializationError(
            "Invalid plan_status rejected by strict serialization boundary"
        )

    # Serialize groups first (rebuilt from policy)
    safe_groups = [_serialize_repair_group(g) for g in _groups]

    # --- Validate groups_truncated type at serialization boundary ---
    _raw_summary = repair_plan.get("summary", {})
    if not isinstance(_raw_summary, dict):
        _raw_summary = {}

    _input_groups_truncated = _raw_summary.get("groups_truncated", False)
    if type(_input_groups_truncated) is not bool:
        raise RepairPlanSerializationError(
            "groups_truncated is not a strict bool"
        )

    # --- Build safe summary for shared semantic validation ---
    # coverage_warning is rebuilt from plan_status (NEVER trust input)
    _safe_summary = _serialize_summary(
        _raw_summary, safe_groups, plan_status
    )

    # --- Shared snapshot semantics validation ---
    _validate_repair_snapshot_semantics(
        plan_status=plan_status,
        summary=_safe_summary,
        repair_groups=safe_groups,
        error_cls=RepairPlanSerializationError,
    )

    # --- Rebuild agent_prompt from safe_groups (NEVER trust input) ---
    max_prompt_chars = max(1, int(settings.repair_max_agent_prompt_chars))
    safe_agent_prompt = _generate_agent_prompt(
        safe_groups, plan_status, max_prompt_chars
    )

    # Defensive length check at serialization boundary
    if len(safe_agent_prompt) > max_prompt_chars:
        raise RepairPlanSerializationError(
            "Serialized agent_prompt exceeds max_chars"
        )

    # --- Rebuild verification_steps from safe_groups (NEVER trust input) ---
    has_blocking = any(
        g.get("blocking") is True for g in safe_groups
    )
    safe_verification_steps = _generate_verification_steps(
        plan_status, has_blocking
    )

    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": safe_task_id,
        "plan_status": plan_status,
        "summary": _safe_summary,
        "repair_groups": safe_groups,
        "verification_steps": safe_verification_steps,
        "agent_prompt": safe_agent_prompt,
        # Source fields from AUTHORITATIVE parameters, validated + masked
        "source_scan_updated_at": safe_source_scan,
        "source_assessment_updated_at": safe_source_assess,
        "source_assessment_policy_version": safe_source_policy,
        "created_at": safe_created_at,
        "updated_at": safe_updated_at,
    }


# ---------------------------------------------------------------------------
# --- Database operations ---
# ---------------------------------------------------------------------------

def save_repair_result(
    task_id: str,
    repair_plan: dict,
    source_scan_updated_at: str,
    source_assessment_updated_at: str,
    source_assessment_policy_version: str,
) -> dict:
    """Persist a repair plan to the repair_results table.

    Uses SQLite native upsert (INSERT ON CONFLICT DO UPDATE):
    - created_at is preserved on update (only set on first INSERT).
    - updated_at is always refreshed.

    Args:
        task_id:                        The authoritative task ID.
        repair_plan:                    The RepairPlan dict from
                                        generate_repair_plan().
        source_scan_updated_at:         The scan_results.updated_at.
        source_assessment_updated_at:   The assessment_results.updated_at.
        source_assessment_policy_version: The assessment_results.policy_version.

    Returns:
        The final safe persisted dict (as written to repair_json).

    Raises:
        RepairPlanTooLargeError: If serialized repair_json exceeds
            repair_max_json_bytes.
        RepairPlanPersistError: If any database operation fails.
        RepairPlanInternalError: If serialization fails.
    """
    now = now_iso()
    conn = None
    safe_plan = None
    repair_json = None
    _success = False

    try:
        init_db()
        conn = _get_connection()

        # Query existing created_at
        existing = conn.execute(
            "SELECT created_at FROM repair_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()

        if existing is not None:
            created_at = existing["created_at"]
        else:
            created_at = now

        # Explicit serialization — source fields from authoritative params
        safe_plan = serialize_repair_plan(
            task_id=task_id,
            repair_plan=repair_plan,
            source_scan_updated_at=source_scan_updated_at,
            source_assessment_updated_at=source_assessment_updated_at,
            source_assessment_policy_version=source_assessment_policy_version,
            created_at=created_at,
            updated_at=now,
        )

        repair_json = json.dumps(
            safe_plan, ensure_ascii=False, sort_keys=True
        )

        # Check byte size limit
        max_bytes = max(1, int(settings.repair_max_json_bytes))
        if len(repair_json.encode("utf-8")) > max_bytes:
            raise RepairPlanTooLargeError(
                "repair_json exceeds repair_max_json_bytes"
            )

        # Execute upsert and commit
        # Use safe_plan's final validated+masked fields for DB columns
        # to ensure JSON and DB column consistency.
        conn.execute(
            """INSERT INTO repair_results
               (task_id, schema_version, policy_version, repair_scope,
                repair_json, plan_status, total_repair_groups,
                blocking_repair_groups, source_scan_updated_at,
                source_assessment_updated_at,
                source_assessment_policy_version,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(task_id) DO UPDATE SET
                   schema_version=excluded.schema_version,
                   policy_version=excluded.policy_version,
                   repair_scope=excluded.repair_scope,
                   repair_json=excluded.repair_json,
                   plan_status=excluded.plan_status,
                   total_repair_groups=excluded.total_repair_groups,
                   blocking_repair_groups=excluded.blocking_repair_groups,
                   source_scan_updated_at=excluded.source_scan_updated_at,
                   source_assessment_updated_at=excluded.source_assessment_updated_at,
                   source_assessment_policy_version=excluded.source_assessment_policy_version,
                   updated_at=excluded.updated_at""",
            (
                safe_plan["task_id"],
                safe_plan["schema_version"],
                safe_plan["policy_version"],
                safe_plan["repair_scope"],
                repair_json,
                safe_plan["plan_status"],
                safe_plan["summary"]["total_repair_groups"],
                safe_plan["summary"]["blocking_repair_groups"],
                safe_plan["source_scan_updated_at"],
                safe_plan["source_assessment_updated_at"],
                safe_plan["source_assessment_policy_version"],
                safe_plan["created_at"],
                safe_plan["updated_at"],
            ),
        )
        conn.commit()
        _success = True
    except (RepairPlanTooLargeError, RepairPlanInternalError):
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        raise
    except Exception:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        raise RepairPlanPersistError(
            "Failed to persist repair result"
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                if _success:
                    raise RepairPlanPersistError(
                        "Failed to close database connection"
                    )

    return safe_plan


def _validate_persisted_repair_plan(
    result: dict,
    task_id: str,
    db_columns: dict,
) -> dict:
    """Strictly validate a persisted repair plan read from SQLite.

    Validates ALL top-level fields, summary fields, each repair_group,
    agent_prompt, and JSON/DB column consistency.

    Any field corruption raises RepairPlanInternalError.
    The API layer maps this to REPAIR_PLAN_INTERNAL_ERROR (HTTP 500).

    Args:
        result: The parsed repair plan JSON dict.
        task_id: The task_id from the request path.
        db_columns: Dict of database column values:
            plan_status, total_repair_groups, blocking_repair_groups,
            source_scan_updated_at, source_assessment_updated_at,
            source_assessment_policy_version, created_at, updated_at

    Returns:
        The validated result dict.

    Raises:
        RepairPlanInternalError: If ANY validation check fails.
    """
    # --- 1. Top-level field set and types ---
    _expected_top_fields = {
        "schema_version", "policy_version", "repair_scope", "task_id",
        "plan_status", "summary", "repair_groups", "verification_steps",
        "agent_prompt", "source_scan_updated_at",
        "source_assessment_updated_at", "source_assessment_policy_version",
        "created_at", "updated_at",
    }
    _actual_top_fields = set(result.keys())
    if _actual_top_fields != _expected_top_fields:
        raise RepairPlanInternalError(
            "Repair plan top-level field set mismatch"
        )

    # --- 2. Identity fields (strict type + value validation) ---
    # schema_version: must be strict int (reject bool, float, str, None)
    schema_version = result["schema_version"]
    if type(schema_version) is not int or isinstance(schema_version, bool):
        raise RepairPlanInternalError(
            "schema_version is not a strict int"
        )
    if schema_version != REPAIR_SCHEMA_VERSION:
        raise RepairPlanInternalError("schema_version mismatch")

    # policy_version: must be non-empty str
    policy_version = result["policy_version"]
    if not isinstance(policy_version, str) or not policy_version:
        raise RepairPlanInternalError(
            "policy_version is not a non-empty str"
        )
    if policy_version != POLICY_VERSION:
        raise RepairPlanInternalError("policy_version mismatch")

    # repair_scope: must be non-empty str
    repair_scope = result["repair_scope"]
    if not isinstance(repair_scope, str) or not repair_scope:
        raise RepairPlanInternalError(
            "repair_scope is not a non-empty str"
        )
    if repair_scope != REPAIR_SCOPE:
        raise RepairPlanInternalError("repair_scope mismatch")

    # task_id: must be non-empty str and match request task_id
    result_task_id = result["task_id"]
    if not isinstance(result_task_id, str) or not result_task_id:
        raise RepairPlanInternalError(
            "task_id is not a non-empty str"
        )
    if result_task_id != task_id:
        raise RepairPlanInternalError("task_id mismatch")

    # --- 3. plan_status ---
    plan_status = result["plan_status"]
    if not isinstance(plan_status, str) or plan_status not in (
        "complete", "partial"
    ):
        raise RepairPlanInternalError("Invalid plan_status")
    if plan_status != db_columns["plan_status"]:
        raise RepairPlanInternalError("plan_status JSON/DB mismatch")

    # --- 4. Summary validation ---
    summary = result["summary"]
    if not isinstance(summary, dict):
        raise RepairPlanInternalError("summary is not a dict")

    _expected_summary_fields = {
        "total_repair_groups", "blocking_repair_groups",
        "manual_review_required", "coverage_warning", "groups_truncated",
    }
    if set(summary.keys()) != _expected_summary_fields:
        raise RepairPlanInternalError("summary field set mismatch")

    # total_repair_groups: int, reject bool
    total_repair_groups = summary["total_repair_groups"]
    if type(total_repair_groups) is not int or isinstance(
        total_repair_groups, bool
    ):
        raise RepairPlanInternalError(
            "total_repair_groups is not a strict int"
        )

    # blocking_repair_groups: int, reject bool
    blocking_repair_groups = summary["blocking_repair_groups"]
    if type(blocking_repair_groups) is not int or isinstance(
        blocking_repair_groups, bool
    ):
        raise RepairPlanInternalError(
            "blocking_repair_groups is not a strict int"
        )

    # manual_review_required: bool
    manual_review_required = summary["manual_review_required"]
    if type(manual_review_required) is not bool:
        raise RepairPlanInternalError(
            "manual_review_required is not a bool"
        )

    # coverage_warning: bool
    coverage_warning = summary["coverage_warning"]
    if type(coverage_warning) is not bool:
        raise RepairPlanInternalError("coverage_warning is not a bool")

    # coverage_warning must deterministically equal (plan_status == "partial")
    if coverage_warning != (plan_status == "partial"):
        raise RepairPlanInternalError(
            "coverage_warning does not match plan_status"
        )

    # groups_truncated: bool
    groups_truncated = summary["groups_truncated"]
    if type(groups_truncated) is not bool:
        raise RepairPlanInternalError("groups_truncated is not a bool")

    # --- 5. repair_groups validation ---
    repair_groups = result["repair_groups"]
    if not isinstance(repair_groups, list):
        raise RepairPlanInternalError("repair_groups is not a list")

    # --- 5a. Validate ALL elements are dicts BEFORE any field access ---
    for g in repair_groups:
        if not isinstance(g, dict):
            raise RepairPlanInternalError("repair_group is not a dict")

    # Now safe to compute summary from groups — all elements are dicts
    actual_total = len(repair_groups)
    actual_blocking = sum(
        1 for g in repair_groups if g.get("blocking") is True
    )
    actual_manual = any(
        g.get("action_code") == ACTION_MANUAL_REVIEW_REQUIRED
        for g in repair_groups
    )

    if total_repair_groups != actual_total:
        raise RepairPlanInternalError(
            "total_repair_groups does not match len(repair_groups)"
        )
    if blocking_repair_groups != actual_blocking:
        raise RepairPlanInternalError(
            "blocking_repair_groups does not match actual blocking groups"
        )
    if manual_review_required != actual_manual:
        raise RepairPlanInternalError(
            "manual_review_required does not match actual groups"
        )

    # Validate each repair_group
    _expected_group_fields = {
        "group_id", "action_code", "priority", "blocking",
        "highest_severity", "highest_confidence", "title", "description",
        "related_rule_ids", "related_files", "total_related_files",
        "returned_related_files", "related_files_truncated",
        "finding_count", "steps", "commands", "safety_notes",
        "verification_steps",
    }

    for idx, g in enumerate(repair_groups):
        # Type already validated above, but keep defensive check
        if not isinstance(g, dict):
            raise RepairPlanInternalError("repair_group is not a dict")
        if set(g.keys()) != _expected_group_fields:
            raise RepairPlanInternalError(
                "repair_group field set mismatch"
            )

        # group_id: format RG001, RG002, continuous, matches position
        group_id = g["group_id"]
        if not isinstance(group_id, str):
            raise RepairPlanInternalError("group_id is not a string")
        expected_gid = f"RG{idx + 1:03d}"
        if group_id != expected_gid:
            raise RepairPlanInternalError(
                f"group_id mismatch: expected {expected_gid}, got {group_id}"
            )

        # action_code: valid
        action_code = g["action_code"]
        if not isinstance(action_code, str) or not is_valid_action_code(
            action_code
        ):
            raise RepairPlanInternalError("Invalid action_code")

        action = get_action(action_code)

        # priority: strictly equals frozen policy
        priority = g["priority"]
        if type(priority) is not int or isinstance(priority, bool):
            raise RepairPlanInternalError("priority is not a strict int")
        if priority != action.priority:
            raise RepairPlanInternalError(
                "priority does not match frozen policy"
            )

        # blocking: bool
        blocking = g["blocking"]
        if type(blocking) is not bool:
            raise RepairPlanInternalError("blocking is not a bool")

        # highest_severity: in fixed enum
        highest_severity = g["highest_severity"]
        if not isinstance(highest_severity, str):
            raise RepairPlanInternalError("highest_severity is not a string")
        if highest_severity not in SEVERITY_ORDER:
            raise RepairPlanInternalError(
                "highest_severity not in fixed enum"
            )

        # highest_confidence: in fixed enum
        highest_confidence = g["highest_confidence"]
        if not isinstance(highest_confidence, str):
            raise RepairPlanInternalError("highest_confidence is not a string")
        if highest_confidence not in CONFIDENCE_ORDER:
            raise RepairPlanInternalError(
                "highest_confidence not in fixed enum"
            )

        # title: strictly equals frozen policy
        if g["title"] != action.title:
            raise RepairPlanInternalError("title does not match frozen policy")

        # description: strictly equals frozen policy safe result
        expected_desc = _safe_masked_desc(action.description)
        if g["description"] != expected_desc:
            raise RepairPlanInternalError(
                "description does not match frozen policy"
            )

        # related_rule_ids: strict validation
        related_rule_ids = g["related_rule_ids"]
        if not isinstance(related_rule_ids, list):
            raise RepairPlanInternalError("related_rule_ids is not a list")
        # No empty strings allowed
        if any(not rid for rid in related_rule_ids):
            raise RepairPlanInternalError(
                "related_rule_ids contains empty string"
            )
        # Each must be a valid known rule_id or <unknown-rule>
        for rid in related_rule_ids:
            if not isinstance(rid, str):
                raise RepairPlanInternalError(
                    "related_rule_ids contains non-string"
                )
            if _has_forbidden_unicode(rid):
                raise RepairPlanInternalError(
                    "related_rule_ids contains control characters"
                )
            if rid != _UNKNOWN_RULE and not is_known_rule_id(rid):
                raise RepairPlanInternalError(
                    f"related_rule_ids contains invalid rule_id: {rid!r}"
                )
        # No duplicates allowed
        if len(related_rule_ids) != len(set(related_rule_ids)):
            raise RepairPlanInternalError(
                "related_rule_ids contains duplicates"
            )
        # Must be sorted (deterministic order)
        if related_rule_ids != sorted(related_rule_ids):
            raise RepairPlanInternalError(
                "related_rule_ids not in sorted order"
            )

        # related_files: safe repo-relative path list — must be
        # normalized: no empty strings, no duplicates, sorted.
        related_files = g["related_files"]
        if not isinstance(related_files, list):
            raise RepairPlanInternalError("related_files is not a list")
        for fp in related_files:
            if not isinstance(fp, str):
                raise RepairPlanInternalError(
                    "related_files contains non-string"
                )
            # Reject empty strings
            if not fp:
                raise RepairPlanInternalError(
                    "related_files contains empty string"
                )
            # Re-validate each path — must pass _sanitize_file_path unchanged
            if _sanitize_file_path(fp) != fp:
                raise RepairPlanInternalError(
                    "related_files contains unsafe path"
                )
        # Must be deduplicated and sorted (deterministic order)
        if related_files != sorted(set(related_files)):
            raise RepairPlanInternalError(
                "related_files not normalized (duplicates or unsorted)"
            )

        # total_related_files: non-negative int, reject bool
        total_related_files = g["total_related_files"]
        if type(total_related_files) is not int or isinstance(
            total_related_files, bool
        ):
            raise RepairPlanInternalError(
                "total_related_files is not a strict int"
            )
        if total_related_files < 0:
            raise RepairPlanInternalError(
                "total_related_files is negative"
            )

        # returned_related_files == len(related_files)
        returned_related_files = g["returned_related_files"]
        if type(returned_related_files) is not int or isinstance(
            returned_related_files, bool
        ):
            raise RepairPlanInternalError(
                "returned_related_files is not a strict int"
            )
        if returned_related_files != len(related_files):
            raise RepairPlanInternalError(
                "returned_related_files does not match len(related_files)"
            )

        # total_related_files >= returned_related_files
        if total_related_files < returned_related_files:
            raise RepairPlanInternalError(
                "total_related_files < returned_related_files"
            )

        # related_files_truncated: consistent with counts
        related_files_truncated = g["related_files_truncated"]
        if type(related_files_truncated) is not bool:
            raise RepairPlanInternalError(
                "related_files_truncated is not a bool"
            )
        if related_files_truncated != (
            total_related_files > returned_related_files
        ):
            raise RepairPlanInternalError(
                "related_files_truncated inconsistent with counts"
            )

        # finding_count: non-negative int, reject bool
        finding_count = g["finding_count"]
        if type(finding_count) is not int or isinstance(finding_count, bool):
            raise RepairPlanInternalError(
                "finding_count is not a strict int"
            )
        if finding_count < 0:
            raise RepairPlanInternalError("finding_count is negative")

        # steps: strictly equals frozen policy
        expected_steps = [_safe_masked_desc(s) for s in action.steps]
        if g["steps"] != expected_steps:
            raise RepairPlanInternalError(
                "steps do not match frozen policy"
            )

        # commands: strictly equals get_allowed_commands(action_code)
        expected_commands = list(get_allowed_commands(action_code))
        if g["commands"] != expected_commands:
            raise RepairPlanInternalError(
                "commands do not match get_allowed_commands for this action"
            )

        # safety_notes: strictly equals frozen policy
        expected_safety = [_safe_masked_desc(s) for s in action.safety_notes]
        if g["safety_notes"] != expected_safety:
            raise RepairPlanInternalError(
                "safety_notes do not match frozen policy"
            )

        # verification_steps: strictly equals frozen policy
        expected_verify = [
            _safe_masked_desc(s) for s in action.verification_steps
        ]
        if g["verification_steps"] != expected_verify:
            raise RepairPlanInternalError(
                "verification_steps do not match frozen policy"
            )

    # --- 5b. Shared snapshot semantics validation ---
    # Replaces inline action-based and truncation checks with the
    # shared function used by both serialization and read boundaries.
    action_codes = {g["action_code"] for g in repair_groups}

    # manual_review_required must strictly equal
    # (ACTION_MANUAL_REVIEW_REQUIRED in action_codes)
    if manual_review_required != (
        ACTION_MANUAL_REVIEW_REQUIRED in action_codes
    ):
        raise RepairPlanInternalError(
            "manual_review_required does not match action_codes"
        )

    # Shared semantic validation (coverage_warning, partial-trigger,
    # groups_truncated, related_files_truncated, complete/partial
    # constraints — all in one function)
    _validate_repair_snapshot_semantics(
        plan_status=plan_status,
        summary={
            "coverage_warning": coverage_warning,
            "groups_truncated": groups_truncated,
        },
        repair_groups=repair_groups,
        error_cls=RepairPlanInternalError,
    )

    # --- 6. verification_steps (strict equality with rebuilt value) ---
    verification_steps = result["verification_steps"]
    if not isinstance(verification_steps, list):
        raise RepairPlanInternalError("verification_steps is not a list")
    for vs in verification_steps:
        if not isinstance(vs, str):
            raise RepairPlanInternalError(
                "verification_steps contains non-string"
            )

    # Rebuild expected verification_steps from plan_status and groups
    has_blocking = any(
        g.get("blocking") is True for g in repair_groups
    )
    expected_verification_steps = _generate_verification_steps(
        plan_status, has_blocking
    )
    if verification_steps != expected_verification_steps:
        raise RepairPlanInternalError(
            "verification_steps does not match policy-rebuilt value"
        )

    # --- 7. agent_prompt (strict equality with rebuilt value) ---
    agent_prompt = result["agent_prompt"]
    if not isinstance(agent_prompt, str):
        raise RepairPlanInternalError("agent_prompt is not a string")

    max_prompt_chars = max(1, int(settings.repair_max_agent_prompt_chars))
    if len(agent_prompt) > max_prompt_chars:
        raise RepairPlanInternalError(
            "agent_prompt exceeds repair_max_agent_prompt_chars"
        )

    # Rebuild expected agent_prompt from repair_groups and plan_status
    expected_agent_prompt = _generate_agent_prompt(
        repair_groups, plan_status, max_prompt_chars
    )

    # Strict equality — no extra lines, no missing content, no order changes
    if agent_prompt != expected_agent_prompt:
        raise RepairPlanInternalError(
            "agent_prompt does not match policy-rebuilt value"
        )

    # Defense-in-depth: check for forbidden Unicode and patterns
    # (should be caught by equality check, but kept as extra layer)
    _prompt_forbidden = frozenset({"Cf", "Zl", "Zp"})
    for ch in agent_prompt:
        if unicodedata.category(ch) in _prompt_forbidden:
            raise RepairPlanInternalError(
                "agent_prompt contains forbidden Unicode format character"
            )
    marker = "## 修复动作摘要"
    marker_idx = agent_prompt.find(marker)
    variable_part = ""
    if marker_idx >= 0:
        variable_part = agent_prompt[marker_idx + len(marker):]
    for field in AGENT_PROMPT_FORBIDDEN_FIELDS:
        if field in variable_part:
            raise RepairPlanInternalError(
                "agent_prompt contains forbidden field"
            )
    for pattern in AGENT_PROMPT_FORBIDDEN_PATTERNS:
        if re.search(pattern, variable_part):
            raise RepairPlanInternalError(
                "agent_prompt contains forbidden pattern"
            )

    # --- 8. Source version chain and identity fields ---
    # Use shared identity validation — same rules as serialization boundary.
    source_scan_updated_at = result["source_scan_updated_at"]
    source_assessment_updated_at = result["source_assessment_updated_at"]
    source_policy = result["source_assessment_policy_version"]
    created_at = result["created_at"]
    updated_at = result["updated_at"]

    _validate_repair_snapshot_identity(
        task_id=result_task_id,
        source_scan_updated_at=source_scan_updated_at,
        source_assessment_updated_at=source_assessment_updated_at,
        source_assessment_policy_version=source_policy,
        created_at=created_at,
        updated_at=updated_at,
        error_cls=RepairPlanInternalError,
    )

    # --- 9. JSON and DB redundant column consistency (with strict types) ---
    # DB columns must also pass strict type validation
    db_plan_status = db_columns["plan_status"]
    if not isinstance(db_plan_status, str) or not db_plan_status:
        raise RepairPlanInternalError(
            "DB plan_status is not a non-empty str"
        )

    db_total = db_columns["total_repair_groups"]
    if type(db_total) is not int or isinstance(db_total, bool):
        raise RepairPlanInternalError(
            "DB total_repair_groups is not a strict int"
        )

    db_blocking = db_columns["blocking_repair_groups"]
    if type(db_blocking) is not int or isinstance(db_blocking, bool):
        raise RepairPlanInternalError(
            "DB blocking_repair_groups is not a strict int"
        )

    # DB identity columns validated via the SAME shared function used by
    # the serialization boundary and JSON field validation above.
    # This ensures both boundaries enforce identical rules: strict str
    # type, non-empty, no control characters (task_id), and supported
    # policy version (source_assessment_policy_version).
    _validate_repair_snapshot_identity(
        task_id=db_columns["task_id"],
        source_scan_updated_at=db_columns["source_scan_updated_at"],
        source_assessment_updated_at=db_columns["source_assessment_updated_at"],
        source_assessment_policy_version=db_columns["source_assessment_policy_version"],
        created_at=db_columns["created_at"],
        updated_at=db_columns["updated_at"],
        error_cls=RepairPlanInternalError,
    )

    # Value consistency between JSON and DB
    if total_repair_groups != db_total:
        raise RepairPlanInternalError(
            "total_repair_groups JSON/DB mismatch"
        )
    if blocking_repair_groups != db_blocking:
        raise RepairPlanInternalError(
            "blocking_repair_groups JSON/DB mismatch"
        )
    if source_scan_updated_at != db_columns["source_scan_updated_at"]:
        raise RepairPlanInternalError(
            "source_scan_updated_at JSON/DB mismatch"
        )
    if source_assessment_updated_at != db_columns["source_assessment_updated_at"]:
        raise RepairPlanInternalError(
            "source_assessment_updated_at JSON/DB mismatch"
        )
    if source_policy != db_columns["source_assessment_policy_version"]:
        raise RepairPlanInternalError(
            "source_assessment_policy_version JSON/DB mismatch"
        )
    if created_at != db_columns["created_at"]:
        raise RepairPlanInternalError("created_at JSON/DB mismatch")
    if updated_at != db_columns["updated_at"]:
        raise RepairPlanInternalError("updated_at JSON/DB mismatch")

    return result


def get_repair_result(task_id: str) -> Optional[dict]:
    """Read the full persisted repair plan for a task.

    Returns None if no repair plan has been persisted.

    Validates the parsed JSON via _validate_persisted_repair_plan,
    which checks ALL fields, types, frozen policy consistency,
    agent_prompt safety, and JSON/DB column consistency.

    Raises:
        RepairPlanInternalError: If any validation fails.
            The API layer maps this to REPAIR_PLAN_INTERNAL_ERROR.
    """
    conn = None
    _db_error = False
    try:
        init_db()
        conn = _get_connection()
        row = conn.execute(
            "SELECT task_id, repair_json, plan_status, total_repair_groups, "
            "blocking_repair_groups, source_scan_updated_at, "
            "source_assessment_updated_at, "
            "source_assessment_policy_version, "
            "created_at, updated_at "
            "FROM repair_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        raw_json = row["repair_json"]
        db_columns = {
            "task_id": row["task_id"],
            "plan_status": row["plan_status"],
            "total_repair_groups": row["total_repair_groups"],
            "blocking_repair_groups": row["blocking_repair_groups"],
            "source_scan_updated_at": row["source_scan_updated_at"],
            "source_assessment_updated_at": row[
                "source_assessment_updated_at"
            ],
            "source_assessment_policy_version": row[
                "source_assessment_policy_version"
            ],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    except RepairPlanInternalError:
        _db_error = True
        raise
    except Exception:
        _db_error = True
        raise RepairPlanInternalError(
            "Failed to read repair plan from database"
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                if not _db_error:
                    raise RepairPlanInternalError(
                        "Failed to close database connection"
                    )

    # Parse JSON
    try:
        result = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        raise RepairPlanInternalError("Failed to parse repair plan JSON")

    if not isinstance(result, dict):
        raise RepairPlanInternalError("Repair plan JSON is not a dict")

    # --- Strict validation of all fields ---
    # Wrap in try-except to catch any AttributeError, TypeError,
    # KeyError, or ValueError from corrupted input that escapes
    # the explicit checks. Convert ALL to RepairPlanInternalError.
    try:
        return _validate_persisted_repair_plan(result, task_id, db_columns)
    except RepairPlanInternalError:
        raise
    except (AttributeError, TypeError, KeyError, ValueError) as exc:
        raise RepairPlanInternalError(
            "Corrupted repair plan data rejected by validation"
        ) from exc


def get_repair_plan_available(task_id: str) -> bool:
    """Lightweight check for status polling — returns True if a repair
    plan exists for the task.

    Reads ONLY the task_id column — does NOT parse repair_json.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM repair_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# --- Orchestrator: generate + persist ---
# ---------------------------------------------------------------------------

def generate_and_save_repair_plan(task_id: str) -> dict:
    """Read persisted results, compute repair plan, and persist it.

    This is the entry point called by the background runner via
    asyncio.to_thread(). It:

    1. Reads the persisted scan result from scan_results.
    2. Reads the persisted assessment from assessment_results.
    3. Validates consistency.
    4. Computes the repair plan using generate_repair_plan().
    5. Persists the repair plan to repair_results via save_repair_result().

    Returns the FINAL PERSISTED version (the safe dict from
    save_repair_result).

    Raises:
        RepairPlanInternalError: If reading, parsing, or computation fails.
        RepairPlanTooLargeError: If the repair plan exceeds size limit.
        RepairPlanPersistError: If the database persistence fails.
    """
    # Step 1: Read persisted scan result
    scan_result, summary, scan_updated_at = _read_scan_result(task_id)

    # Step 2: Read persisted assessment
    (
        assessment, assessment_updated_at, assessment_policy_version,
        source_scan_updated_at,
    ) = _read_assessment(task_id)

    # Step 3: Compute repair plan
    repair_plan = generate_repair_plan(
        task_id=task_id,
        scan_result=scan_result,
        summary=summary,
        scan_updated_at=scan_updated_at,
        assessment=assessment,
        assessment_updated_at=assessment_updated_at,
        assessment_policy_version=assessment_policy_version,
        source_scan_updated_at=source_scan_updated_at,
    )

    # Step 4: Persist repair plan
    persisted = save_repair_result(
        task_id=task_id,
        repair_plan=repair_plan,
        source_scan_updated_at=scan_updated_at,
        source_assessment_updated_at=assessment_updated_at,
        source_assessment_policy_version=assessment_policy_version,
    )

    return persisted
