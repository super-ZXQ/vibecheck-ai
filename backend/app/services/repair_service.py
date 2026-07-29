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
from typing import Any, Optional

from app.core.config import settings
from app.core.security.desensitize import mask_untrusted_text
from app.db.database import _get_connection, init_db, now_iso
from app.services.repair_policy import (
    AGENT_PROMPT_FORBIDDEN_FIELDS,
    AGENT_PROMPT_FORBIDDEN_PATTERNS,
    AGENT_PROMPT_REQUIREMENTS,
    BLOCKING_ACTION_SEQUENCE,
    GLOBAL_SINGLETON_ACTIONS,
    KNOWN_TEMPLATE_KEYS,
    PARTIAL_DECLARATION,
    POLICY_VERSION,
    REPAIR_SCHEMA_VERSION,
    REPAIR_SCOPE,
    SUPPORTED_ASSESSMENT_POLICY_VERSIONS,
    ACTION_CODES,
    ACTION_PRIORITY,
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    compute_aggregation_key,
    compute_group_sort_key,
    get_action,
    get_allowed_commands,
    get_allowed_template_keys_for_rule,
    get_template_actions,
    is_command_allowed,
    is_known_rule_id,
    is_known_template_key,
    is_supported_assessment_policy,
    is_valid_action_code,
    RULE_ALLOWED_TEMPLATE_KEYS,
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

_POSIX_ABSOLUTE_RE = re.compile(r'^/')
_WINDOWS_DRIVE_RE = re.compile(r'^[A-Za-z]:[/\\]')
_UNC_RE = re.compile(r'^(?:\\\\|//)')
_WINDOWS_ROOTED_RE = re.compile(r'^\\')
_USER_HOME_RE = re.compile(r'^~[/\\]')

# Control characters that must NEVER appear in a file path:
# - \x00 (NUL) through \x1f (C0 controls: \n, \r, \t, etc.)
# - \x7f (DEL)
# - \x80-\x9f (C1 controls)
# - Unicode bidirectional/format controls (LRE, RLE, PDF, LRO, RLO, LRM, RLM,
#   ZWSP, ZWJ, ZWNJ, WJ, BOM, etc.)
_CONTROL_CHAR_RE = re.compile(
    r'[\x00-\x1f\x7f\x80-\x9f'
    r'\u200b-\u200f\u2028-\u202f\u2060-\u206f'
    r'\ufeff]'
)


def _sanitize_file_path(value: Any) -> str:
    """Sanitize a file path for safe display.

    Only allows repo-relative paths. Rejects:
    - Absolute paths (POSIX, Windows drive, UNC, rooted)
    - Path traversal (..)
    - User home paths (~)
    - NUL bytes
    - Control characters (\\n, \\r, \\t, C0/C1, Unicode bidirectional)
    
    Any control character causes the path to be replaced with
    <redacted-path> to prevent prompt injection via newlines or
    text direction manipulation.
    """
    s = _strict_str(value)
    s = mask_untrusted_text(s)
    # Reject NUL bytes
    if '\x00' in s:
        return _REDACTED_PATH
    # Reject any control character (newline, tab, C0/C1, Unicode bidi, etc.)
    if _CONTROL_CHAR_RE.search(s):
        return _REDACTED_PATH
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
    normalized = s.replace('\\', '/')
    parts = normalized.split('/')
    if '..' in parts:
        return _REDACTED_PATH
    return s


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

    return scan_result, summary, scan_updated_at


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

def _sort_and_assign_ids(
    mandatory_groups: list[dict],
    optional_groups: list[dict],
    max_groups: int,
) -> tuple[list[dict], bool, bool]:
    """Sort all groups deterministically and assign group_ids.

    Mandatory groups are ALWAYS preserved. Optional groups fill the
    remaining space up to max_groups.

    If mandatory groups alone exceed max_groups, raises
    RepairPlanTooLargeError — mandatory safety actions must never
    be silently dropped.

    Returns:
        (sorted_groups, groups_truncated, any_files_truncated)
        groups_truncated: True only if optional groups were omitted
    """
    # Check if mandatory groups alone exceed the limit
    if len(mandatory_groups) > max_groups:
        raise RepairPlanTooLargeError(
            "Mandatory repair groups exceed repair_max_groups"
        )

    # Combine mandatory + optional, sort deterministically
    all_group_data = list(mandatory_groups) + list(optional_groups)

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

    all_group_data.sort(key=_sort_key)

    # Apply max_groups limit — mandatory groups are guaranteed to fit
    # because we checked above. Only optional groups can be truncated.
    groups_truncated = len(all_group_data) > max_groups
    if groups_truncated:
        all_group_data = all_group_data[:max_groups]

    # Assign group_ids and build final dicts
    max_related_files = max(1, int(settings.repair_max_related_files_per_group))
    sorted_groups: list[dict] = []
    any_files_truncated = False

    for idx, gd in enumerate(all_group_data):
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

    If max_chars is too small for the fixed content, raises
    RepairPlanTooLargeError — never returns a prompt missing
    safety requirements.

    The prompt contains ONLY:
    - rule_id, secret_type, repair_template_key (with limits)
    - relative file_path (sanitized, single-line)
    - Finding count
    - Repair action summary

    It does NOT contain: repo_url, owner, repo_name, snippet,
    snippet_masked, raw secrets, database paths, or temp paths.
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

    # Check if fixed content alone exceeds max_chars
    if len(fixed_content) > max_chars:
        raise RepairPlanTooLargeError(
            "Agent prompt fixed content exceeds max_chars"
        )

    if not repair_groups:
        # Empty prompt — just fixed content
        return fixed_content

    # --- Build variable content (action summary, can be truncated) ---
    # Build line by line, checking size after each complete line/group.
    variable_header = "\n\n## 修复动作摘要\n\n"
    remaining_chars = max_chars - len(fixed_content) - len(variable_header)
    if remaining_chars <= 0:
        # No room for any variable content — return fixed + header
        return fixed_content + variable_header.rstrip()

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

        # Check if this line fits (including newline)
        line_with_nl = action_line + "\n"
        if current_len + len(line_with_nl) > remaining_chars:
            break  # Stop adding — don't cut mid-line
        variable_lines.append(action_line)
        current_len += len(line_with_nl)

        # Add related files line if present
        if related_files:
            # Sanitize each file path and escape backticks
            safe_files = []
            for fp in related_files[:10]:
                # Escape backticks to prevent Markdown injection
                safe_fp = fp.replace("`", "\\`")
                safe_files.append(safe_fp)
            files_line = f"  相关文件: {' '.join(f'`{sf}`' for sf in safe_files)}"
            files_with_nl = files_line + "\n"
            if current_len + len(files_with_nl) > remaining_chars:
                break  # Stop adding — don't cut mid-line
            variable_lines.append(files_line)
            current_len += len(files_with_nl)

    # Assemble final prompt
    if variable_lines:
        prompt = fixed_content + variable_header + "\n".join(variable_lines)
    else:
        prompt = fixed_content

    return prompt


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
        ff = _extract_finding_fields(raw_f)
        # Sanitize file_path early — before aggregation and prompt
        ff["file_path"] = _sanitize_file_path(ff["file_path"])
        findings.append(ff)

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
    #    Mandatory = global singleton actions (safety-critical)
    #    Optional = regular finding-based groups
    mandatory_group_data: list[dict] = list(singleton_groups.values())
    optional_group_data: list[dict] = list(regular_groups.values())

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

    # Validate count consistency
    total_related = _strict_int(
        group.get("total_related_files", 0), minimum=0
    )
    returned_related = len(_related_files)
    files_truncated = _strict_bool(
        group.get("related_files_truncated", False)
    )
    
    if returned_related != _strict_int(
        group.get("returned_related_files", 0), minimum=0
    ):
        raise RepairPlanSerializationError(
            "returned_related_files does not match len(related_files)"
        )
    if files_truncated != (total_related > returned_related):
        raise RepairPlanSerializationError(
            "related_files_truncated inconsistent with counts"
        )

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
        "related_rule_ids": [_safe_masked_str(r) for r in _related_rule_ids],
        "related_files": [_sanitize_file_path(f) for f in _related_files],
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


def _serialize_summary(summary: dict, repair_groups: list[dict]) -> dict:
    """Whitelist and mask the summary structure.
    
    Recalculates total_repair_groups, blocking_repair_groups, and
    manual_review_required from the final safe repair_groups list.
    Does NOT trust the input summary for these computed fields.
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
    
    return {
        "total_repair_groups": total,
        "blocking_repair_groups": blocking,
        "manual_review_required": manual,
        "coverage_warning": _strict_bool(
            summary.get("coverage_warning", False)
        ),
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
    created_at: Optional[str],
    updated_at: str,
) -> dict:
    """Explicit serialization boundary for RepairPlan.

    Constructs the safe dict that gets persisted as repair_json.
    Forces identity fields from policy constants. Enforces strict
    field whitelists and defensive desensitization.
    
    Source version chain fields are taken from AUTHORITATIVE parameters,
    NOT from the repair_plan dict. This ensures JSON and database
    columns always match.
    """
    if not isinstance(repair_plan, dict):
        raise RepairPlanSerializationError("Repair plan must be a dict")

    _groups = repair_plan.get("repair_groups", [])
    if not isinstance(_groups, list):
        raise RepairPlanSerializationError("repair_groups must be a list")

    _verification_steps = repair_plan.get("verification_steps", [])
    if not isinstance(_verification_steps, list):
        raise RepairPlanSerializationError(
            "verification_steps must be a list"
        )

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

    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": task_id,
        "plan_status": plan_status,
        "summary": _serialize_summary(
            repair_plan.get("summary", {}), safe_groups
        ),
        "repair_groups": safe_groups,
        "verification_steps": [
            _safe_masked_desc(s) for s in _verification_steps
        ],
        "agent_prompt": _safe_masked_desc(repair_plan.get("agent_prompt")),
        # Source fields from AUTHORITATIVE parameters only
        "source_scan_updated_at": _safe_masked_str(source_scan_updated_at),
        "source_assessment_updated_at": _safe_masked_str(
            source_assessment_updated_at
        ),
        "source_assessment_policy_version": _safe_masked_str(
            source_assessment_policy_version
        ),
        "created_at": created_at,
        "updated_at": updated_at,
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
                task_id,
                safe_plan["schema_version"],
                safe_plan["policy_version"],
                safe_plan["repair_scope"],
                repair_json,
                safe_plan["plan_status"],
                safe_plan["summary"]["total_repair_groups"],
                safe_plan["summary"]["blocking_repair_groups"],
                source_scan_updated_at,
                source_assessment_updated_at,
                source_assessment_policy_version,
                created_at,
                now,
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


def get_repair_result(task_id: str) -> Optional[dict]:
    """Read the full persisted repair plan for a task.

    Returns None if no repair plan has been persisted.

    Validates the parsed JSON against:
    - Identity fields (schema_version, policy_version, repair_scope, task_id)
    - plan_status (must be complete/partial)
    - Summary structure and types
    - repair_groups is a list with valid structure
    - commands all come from the allowlist
    - JSON source fields match database columns
    - JSON plan_status matches database column
    - JSON group counts match database redundant columns
    - JSON timestamps match database columns

    Raises:
        RepairPlanInternalError: If any validation fails.
    """
    conn = None
    _db_error = False
    try:
        init_db()
        conn = _get_connection()
        row = conn.execute(
            "SELECT repair_json, plan_status, total_repair_groups, "
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
        db_plan_status = row["plan_status"]
        db_total_groups = row["total_repair_groups"]
        db_blocking_groups = row["blocking_repair_groups"]
        db_source_scan = row["source_scan_updated_at"]
        db_source_assessment = row["source_assessment_updated_at"]
        db_source_policy = row["source_assessment_policy_version"]
        db_created_at = row["created_at"]
        db_updated_at = row["updated_at"]
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

    # --- Identity validation ---
    if result.get("schema_version") != REPAIR_SCHEMA_VERSION:
        raise RepairPlanInternalError("Repair plan schema_version mismatch")
    if result.get("policy_version") != POLICY_VERSION:
        raise RepairPlanInternalError("Repair plan policy_version mismatch")
    if result.get("repair_scope") != REPAIR_SCOPE:
        raise RepairPlanInternalError("Repair plan scope mismatch")
    if result.get("task_id") != task_id:
        raise RepairPlanInternalError("Repair plan task_id mismatch")

    # --- plan_status validation ---
    json_plan_status = result.get("plan_status")
    if json_plan_status not in ("complete", "partial"):
        raise RepairPlanInternalError("Invalid plan_status in repair JSON")
    if json_plan_status != db_plan_status:
        raise RepairPlanInternalError("plan_status JSON/DB mismatch")

    # --- Summary validation ---
    json_summary = result.get("summary", {})
    if not isinstance(json_summary, dict):
        raise RepairPlanInternalError("summary is not a dict")

    # --- repair_groups validation ---
    json_groups = result.get("repair_groups", [])
    if not isinstance(json_groups, list):
        raise RepairPlanInternalError("repair_groups is not a list")

    # Validate each group has valid structure and commands
    for g in json_groups:
        if not isinstance(g, dict):
            raise RepairPlanInternalError("repair_group is not a dict")
        ac = g.get("action_code", "")
        if not isinstance(ac, str) or not is_valid_action_code(ac):
            raise RepairPlanInternalError("Invalid action_code in repair JSON")
        cmds = g.get("commands", [])
        if not isinstance(cmds, list):
            raise RepairPlanInternalError("commands is not a list")
        for cmd in cmds:
            if not isinstance(cmd, str) or not is_command_allowed(cmd):
                raise RepairPlanInternalError(
                    "Disallowed command in repair JSON"
                )

    # --- Count consistency ---
    json_total = json_summary.get("total_repair_groups", 0)
    if not isinstance(json_total, int) or json_total != len(json_groups):
        raise RepairPlanInternalError("total_repair_groups mismatch")
    if json_total != db_total_groups:
        raise RepairPlanInternalError("total_repair_groups JSON/DB mismatch")

    json_blocking = json_summary.get("blocking_repair_groups", 0)
    if not isinstance(json_blocking, int):
        raise RepairPlanInternalError("blocking_repair_groups not int")
    if json_blocking != db_blocking_groups:
        raise RepairPlanInternalError(
            "blocking_repair_groups JSON/DB mismatch"
        )

    # --- Source field consistency ---
    if result.get("source_scan_updated_at") != db_source_scan:
        raise RepairPlanInternalError(
            "source_scan_updated_at JSON/DB mismatch"
        )
    if result.get("source_assessment_updated_at") != db_source_assessment:
        raise RepairPlanInternalError(
            "source_assessment_updated_at JSON/DB mismatch"
        )
    if result.get("source_assessment_policy_version") != db_source_policy:
        raise RepairPlanInternalError(
            "source_assessment_policy_version JSON/DB mismatch"
        )

    # --- Timestamp consistency ---
    if result.get("created_at") != db_created_at:
        raise RepairPlanInternalError("created_at JSON/DB mismatch")
    if result.get("updated_at") != db_updated_at:
        raise RepairPlanInternalError("updated_at JSON/DB mismatch")

    return result


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
