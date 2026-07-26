"""Deterministic assessment policy v1 — sensitive data security dimension.

This module is the SINGLE source of truth for all scoring weights, caps,
and verdict thresholds used by the P0-6 security assessment engine.

IMMUTABILITY CONTRACT:
- Policy values are hardcoded constants. They must NEVER be read from
  environment variables, config files, or runtime parameters.
- The same (policy_version, persisted ScanResult, summary) input MUST
  always produce identical score, verdict, score_breakdown, score_caps,
  coverage, and blocking_reasons.
- Only created_at, updated_at, and task_id may differ between runs.

SCOPE:
- This policy ONLY scores the "sensitive_data_security" dimension.
- It is NOT a comprehensive five-dimension上线 maturity score.
- score represents sensitive information security risk only.

ARITHMETIC:
- All deductions use pure integer arithmetic. No float.
- Rounding formula: (base * conf_pct * repeat_pct + 5000) // 10000
  This is equivalent to rounding to the nearest integer without float.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# --- Policy identity ---
# ---------------------------------------------------------------------------

POLICY_VERSION = "p0-6-v1"
ASSESSMENT_SCOPE = "sensitive_data_security"
ASSESSMENT_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# --- Severity base deduction points ---
# ---------------------------------------------------------------------------

SEVERITY_BASE_POINTS: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


# ---------------------------------------------------------------------------
# --- Confidence percentages (0-100) ---
# ---------------------------------------------------------------------------

CONFIDENCE_PERCENT: dict[str, int] = {
    "high": 100,
    "medium": 75,
    "low": 50,
}

# Blocking findings are ALWAYS scored at 100% confidence, regardless
# of the detected confidence level. This prevents a low-confidence
# blocking finding from reducing the deduction and potentially
# avoiding the blocked verdict.
BLOCKING_CONFIDENCE_OVERRIDE = 100


# ---------------------------------------------------------------------------
# --- Repeat violation multipliers (0-100) ---
# ---------------------------------------------------------------------------
#
# Within a single rule_id, findings are processed in deterministic order.
# The 1st occurrence gets 100%, 2nd gets 75%, 3rd gets 50%, 4th and
# beyond get 25%. This dampens the impact of many repeated violations
# from the same rule without ignoring them entirely.

REPEAT_PERCENTS: tuple[int, ...] = (100, 75, 50, 25)

# Index for occurrences beyond the defined tuple (4th and later).
REPEAT_FLOOR_PERCENT = 25


def get_repeat_percent(occurrence_index: int) -> int:
    """Get the repeat multiplier for the nth occurrence (0-based).

    occurrence_index 0 → 100 (1st finding)
    occurrence_index 1 → 75  (2nd finding)
    occurrence_index 2 → 50  (3rd finding)
    occurrence_index 3+ → 25 (4th and beyond)
    """
    if occurrence_index < len(REPEAT_PERCENTS):
        return REPEAT_PERCENTS[occurrence_index]
    return REPEAT_FLOOR_PERCENT


# ---------------------------------------------------------------------------
# --- Per-rule_id deduction caps ---
# ---------------------------------------------------------------------------
#
# Each rule_id's total deduction is capped based on the highest severity
# in that rule group. This prevents a single rule with many findings
# from dominating the entire score.

RULE_CAP_BY_SEVERITY: dict[str, int] = {
    "critical": 50,
    "high": 40,
    "medium": 24,
    "low": 10,
    "info": 0,
}


# ---------------------------------------------------------------------------
# --- Integer deduction formula ---
# ---------------------------------------------------------------------------

# Rounding offset for integer division: (numerator + 5000) // 10000
# is equivalent to round(numerator / 10000) without float.
_ROUNDING_OFFSET = 5000
_DIVISOR = 10000


def compute_single_deduction(
    base_points: int,
    confidence_percent: int,
    repeat_percent: int,
) -> int:
    """Compute a single finding's deduction using pure integer arithmetic.

    Formula: (base_points * confidence_percent * repeat_percent + 5000) // 10000

    This is equivalent to rounding(base_points * conf * repeat / 10000)
    to the nearest integer, but uses only integer operations.

    Args:
        base_points:        Severity base deduction (25/15/8/3/0).
        confidence_percent: 100/75/50 (forced 100 for blocking).
        repeat_percent:     100/75/50/25 based on occurrence order.

    Returns:
        Integer deduction amount.
    """
    numerator = base_points * confidence_percent * repeat_percent
    return (numerator + _ROUNDING_OFFSET) // _DIVISOR


# ---------------------------------------------------------------------------
# --- Score caps ---
# ---------------------------------------------------------------------------

# Each cap is applied after the base deduction. Multiple caps may trigger;
# they are applied in (cap_value ASC, reason_code ASC) order, each taking
# the minimum of the current score and the cap value.

# Cap reason codes
CAP_BLOCKING_FINDING_PRESENT = "BLOCKING_FINDING_PRESENT"
CAP_FINDINGS_TRUNCATED = "FINDINGS_TRUNCATED"
CAP_SCAN_ERRORS_PRESENT = "SCAN_ERRORS_PRESENT"
CAP_NO_FILES_SCANNED = "NO_FILES_SCANNED"

# Cap definitions: (reason_code, cap_value, description)
# NOTE: These are defined as constants, NOT as env-configurable values.

# Cap 1: blocking findings present → score capped at 49
CAP_BLOCKING = {
    "reason_code": CAP_BLOCKING_FINDING_PRESENT,
    "cap_value": 49,
    "description": "存在阻断级安全问题，分数上限为49。",
}

# Cap 2: findings truncated → score capped at 74
CAP_TRUNCATED = {
    "reason_code": CAP_FINDINGS_TRUNCATED,
    "cap_value": 74,
    "description": "扫描结果被截断，分数上限为74。",
}

# Cap 3: scan errors present → score capped at 74
CAP_ERRORS = {
    "reason_code": CAP_SCAN_ERRORS_PRESENT,
    "cap_value": 74,
    "description": "扫描过程中存在错误，分数上限为74。",
}

# Cap 4: no files scanned → score capped at 74
CAP_NO_FILES = {
    "reason_code": CAP_NO_FILES_SCANNED,
    "cap_value": 74,
    "description": "未扫描任何文件，分数上限为74。",
}


def determine_triggered_caps(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Determine which score caps are triggered by the scan summary.

    Returns a list of cap dicts, each containing:
    - reason_code
    - cap_value
    - description

    The caller is responsible for sorting and applying them in order.

    NOTE: skipped_files does NOT trigger any cap. Binary files, images,
    archives, and other unsupported files are normally skipped and do
    not represent security risks.

    Args:
        summary: The scan result summary dict with keys:
            blocking_findings, findings_truncated, total_scan_errors,
            total_files_scanned.

    Returns:
        List of triggered cap dicts (unsorted).
    """
    triggered: list[dict[str, Any]] = []

    if summary.get("blocking_findings", 0) > 0:
        triggered.append(CAP_BLOCKING)

    if summary.get("findings_truncated", False):
        triggered.append(CAP_TRUNCATED)

    if summary.get("total_scan_errors", 0) > 0:
        triggered.append(CAP_ERRORS)

    if summary.get("total_files_scanned", 0) == 0:
        triggered.append(CAP_NO_FILES)

    return triggered


def sort_caps(caps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort caps deterministically by (cap_value ASC, reason_code ASC).

    This ensures the same set of triggered caps always produces the
    same application order and therefore the same final score.
    """
    return sorted(caps, key=lambda c: (c["cap_value"], c["reason_code"]))


# ---------------------------------------------------------------------------
# --- Verdict thresholds ---
# ---------------------------------------------------------------------------

# Verdict is determined AFTER all caps are applied.
# Judgment order:
# 1. blocking_findings > 0 → "blocked" (regardless of score)
# 2. score <= 49 → "blocked"
# 3. 50 <= score <= 74 → "warning"
# 4. score >= 75 → "pass"

VERDICT_BLOCKED = "blocked"
VERDICT_WARNING = "warning"
VERDICT_PASS = "pass"

BLOCKED_SCORE_THRESHOLD = 49   # score <= 49 → blocked (if no blocking findings)
WARNING_SCORE_THRESHOLD = 74   # score <= 74 → warning (if > 49)


def determine_verdict(score: int, blocking_findings_count: int) -> str:
    """Determine the final verdict based on score and blocking findings.

    Judgment order:
    1. If blocking_findings > 0 → "blocked"
    2. If score <= 49 → "blocked"
    3. If score <= 74 → "warning"
    4. Otherwise → "pass"

    Args:
        score: The final score after all caps.
        blocking_findings_count: The authoritative count from summary
            (NOT len(findings), which may be truncated).

    Returns:
        One of "blocked", "warning", "pass".
    """
    if blocking_findings_count > 0:
        return VERDICT_BLOCKED
    if score <= BLOCKED_SCORE_THRESHOLD:
        return VERDICT_BLOCKED
    if score <= WARNING_SCORE_THRESHOLD:
        return VERDICT_WARNING
    return VERDICT_PASS


# ---------------------------------------------------------------------------
# --- Coverage status ---
# ---------------------------------------------------------------------------

COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"


def determine_coverage_status(
    findings_truncated: bool,
    total_scan_errors: int,
    total_files_scanned: int,
) -> str:
    """Determine coverage status from scan quality indicators.

    Coverage is "partial" if ANY of:
    - findings_truncated == True
    - total_scan_errors > 0
    - total_files_scanned == 0

    skipped_files does NOT cause partial coverage. Binary files, images,
    archives, and other unsupported files are normally skipped and do
    not represent a security risk or coverage gap.

    Args:
        findings_truncated:  Whether the findings list was truncated.
        total_scan_errors:   Number of scan errors.
        total_files_scanned: Number of files successfully scanned.

    Returns:
        "complete" or "partial".
    """
    if findings_truncated:
        return COVERAGE_PARTIAL
    if total_scan_errors > 0:
        return COVERAGE_PARTIAL
    if total_files_scanned == 0:
        return COVERAGE_PARTIAL
    return COVERAGE_COMPLETE


# ---------------------------------------------------------------------------
# --- Base score ---
# ---------------------------------------------------------------------------

BASE_SCORE = 100

# Minimum possible score (floor).
MIN_SCORE = 0
