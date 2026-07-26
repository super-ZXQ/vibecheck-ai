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
- All string fields in blocking_reasons are already desensitized by
  P0-5's persistence boundary — we trust the persisted data.

DETERMINISM:
- Same (policy_version, persisted ScanResult, summary) → identical output.
- Finding order within a rule_id is deterministically sorted before
  applying repeat multipliers.
- score_breakdown is sorted by rule_id (alphabetical).
- score_caps are sorted by (cap_value ASC, reason_code ASC).
- Only created_at, updated_at, task_id may differ between runs.

ASYNC:
- Database reads/writes and assessment computation are synchronous.
- Callers MUST wrap them in asyncio.to_thread() to avoid blocking
  the FastAPI event loop.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from app.core.config import settings
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


# ---------------------------------------------------------------------------
# --- Finding sorting (deterministic within a rule_id group) ---
# ---------------------------------------------------------------------------

def _finding_sort_key(f: dict[str, Any]) -> tuple:
    """Deterministic sort key for findings within the same rule_id.

    Sort order (highest priority first):
    1. is_blocking = True first (blocking findings get 100% confidence
       and should be scored first for repeat multiplier purposes)
    2. severity: critical > high > medium > low > info
    3. confidence: high > medium > low
    4. file_path: alphabetical (deterministic)
    5. line_start: ascending (deterministic, None treated as 0)
    6. rule_id: alphabetical (final tiebreaker)

    This ensures the repeat multiplier (100/75/50/25) is applied in
    a consistent order regardless of input finding order.
    """
    severity = f.get("severity", "info")
    confidence = f.get("confidence", "low")
    return (
        0 if f.get("is_blocking", False) else 1,
        _SEVERITY_ORDER.get(severity, 99),
        _CONFIDENCE_ORDER.get(confidence, 99),
        f.get("file_path", ""),
        f.get("line_start") or 0,
        f.get("rule_id", ""),
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
        score_after = min(current_score, cap["cap_value"])
        applied = score_after < score_before

        cap_records.append({
            "reason_code": cap["reason_code"],
            "cap_value": cap["cap_value"],
            "score_before_cap": score_before,
            "score_after_cap": score_after,
            "applied": applied,
            "description": cap["description"],
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
    max_reasons = settings.assessment_max_blocking_reasons
    blocking_reasons, _ = _build_blocking_reasons(findings, max_reasons)

    # --- 6. Build coverage ---
    coverage = _build_coverage(
        summary,
        scored_findings=len(findings),
        blocking_reasons=blocking_reasons,
        total_blocking_findings=total_blocking_findings,
    )

    # --- 7. Assemble AssessmentResult ---
    now = now_iso()
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
        "created_at": now,
        "updated_at": now,
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
) -> None:
    """Persist an assessment result to the assessment_results table.

    Uses SQLite native upsert (INSERT ON CONFLICT DO UPDATE):
    - created_at is preserved on update (only set on first INSERT).
    - updated_at is always refreshed.
    - source_scan_updated_at tracks which scan_results version this
      assessment was computed from.

    Args:
        task_id:                The task ID.
        assessment:             The AssessmentResult dict.
        source_scan_updated_at: The updated_at of the scan_results row
                                this assessment was computed from.

    Raises:
        AssessmentResultTooLargeError: If serialized assessment_json exceeds
            assessment_max_json_bytes.
        sqlite3.Error: If the database operation fails.
    """
    init_db()
    now = now_iso()

    # Explicit serialization — no vars(), __dict__, asdict, or recursive
    # serialization. json.dumps with sort_keys for deterministic output.
    assessment_json = json.dumps(assessment, ensure_ascii=False, sort_keys=True)

    # Check byte size limit.
    if len(assessment_json.encode("utf-8")) > settings.assessment_max_json_bytes:
        raise AssessmentResultTooLargeError(
            "assessment_json exceeds assessment_max_json_bytes"
        )

    conn = _get_connection()
    try:
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
                assessment["schema_version"],
                assessment["policy_version"],
                assessment["assessment_scope"],
                assessment_json,
                assessment["score"],
                assessment["verdict"],
                source_scan_updated_at,
                now,  # created_at — only set on first INSERT, preserved on UPDATE
                now,  # updated_at — always updated
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_assessment_result(task_id: str) -> Optional[dict[str, Any]]:
    """Read the full persisted assessment result for a task.

    Returns None if no assessment has been persisted for this task_id.
    The returned dict has the same structure as the AssessmentResult
    produced by assess_scan_result().

    Args:
        task_id: The task ID to look up.

    Returns:
        The AssessmentResult dict, or None if not found.
    """
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT assessment_json FROM assessment_results WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["assessment_json"])
    finally:
        conn.close()


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
    3. Persists the assessment to assessment_results.

    If the scan result is missing or the assessment is too large,
    raises an appropriate exception for the caller to handle.

    Args:
        task_id: The task ID to assess.

    Returns:
        The AssessmentResult dict.

    Raises:
        ValueError: If no scan result has been persisted for this task.
        AssessmentResultTooLargeError: If the assessment exceeds size limit.
        sqlite3.Error: If the database operation fails.
    """
    # Step 1: Read persisted scan result with timestamp.
    scan_data = get_scan_result_with_timestamp(task_id)
    if scan_data is None:
        raise ValueError(f"No scan result found for task {task_id}")
    scan_result, source_scan_updated_at = scan_data

    # Step 2: Compute assessment.
    assessment = assess_scan_result(task_id, scan_result)

    # Step 3: Persist assessment.
    save_assessment_result(task_id, assessment, source_scan_updated_at)

    return assessment
