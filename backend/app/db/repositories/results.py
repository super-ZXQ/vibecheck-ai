"""Result persistence repository (scan / assessment / repair / llm)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    AssessmentResultRow,
    LlmAnalysisResultRow,
    RepairResultRow,
    ScanResultRow,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_dt(value):
    """Accept datetime or ISO string for TIMESTAMP columns."""
    if value is None:
        return _now()
    if hasattr(value, "isoformat"):
        return value
    try:
        from datetime import datetime, timezone
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return _now()



async def save_scan_result(
    session: AsyncSession,
    task_id: str,
    *,
    schema_version: int,
    result_json: dict[str, Any],
    summary_json: dict[str, Any],
    totals: dict[str, int],
) -> None:
    now = _now()
    existing = await session.get(ScanResultRow, task_id)
    if existing is None:
        session.add(
            ScanResultRow(
                task_id=task_id,
                schema_version=schema_version,
                result_json=(  # type: ignore[arg-type]
                
                json.dumps(result_json, ensure_ascii=False)
                if isinstance(result_json, dict)
                else result_json
            ),
                summary_json=(  # type: ignore[arg-type]
                
                json.dumps(summary_json, ensure_ascii=False)
                if isinstance(summary_json, dict)
                else summary_json
            ),
                total_findings=totals.get("total_findings", 0),
                blocking_findings=totals.get("blocking_findings", 0),
                total_notices=totals.get("total_notices", 0),
                total_skipped_files=totals.get("total_skipped_files", 0),
                total_scan_errors=totals.get("total_scan_errors", 0),
                total_files_scanned=totals.get("total_files_scanned", 0),
                total_lines_scanned=totals.get("total_lines_scanned", 0),
                created_at=_as_dt(now),
                updated_at=_as_dt(now),
            )
        )
    else:
        existing.schema_version = schema_version
        existing.result_json = (  # type: ignore[assignment]
            json.dumps(result_json, ensure_ascii=False)
            if isinstance(result_json, dict)
            else result_json
        )
        existing.summary_json = (  # type: ignore[assignment]
            json.dumps(summary_json, ensure_ascii=False)
            if isinstance(summary_json, dict)
            else summary_json
        )
        existing.total_findings = totals.get("total_findings", 0)
        existing.blocking_findings = totals.get("blocking_findings", 0)
        existing.total_notices = totals.get("total_notices", 0)
        existing.total_skipped_files = totals.get("total_skipped_files", 0)
        existing.total_scan_errors = totals.get("total_scan_errors", 0)
        existing.total_files_scanned = totals.get("total_files_scanned", 0)
        existing.total_lines_scanned = totals.get("total_lines_scanned", 0)
        existing.updated_at = now
    await session.flush()


async def get_scan_result(session: AsyncSession, task_id: str) -> dict[str, Any] | None:
    import json as _json
    row = await session.get(ScanResultRow, task_id)
    if row is None:
        return None
    raw = row.result_json
    if isinstance(raw, str):
        data = _json.loads(raw)
    elif isinstance(raw, dict):
        data = dict(raw)
    else:
        data = {}
    sj = row.summary_json
    if isinstance(sj, str):
        data["summary"] = _json.loads(sj)
    elif sj:
        data["summary"] = sj
    return data


async def get_scan_summary(session: AsyncSession, task_id: str) -> dict[str, Any] | None:
    import json as _json

    from app.services.scan_result_service import normalize_scan_summary_dimensions

    row = await session.get(ScanResultRow, task_id)
    if row is None:
        return None
    sj = row.summary_json
    summary = None
    if isinstance(sj, dict) and sj:
        summary = dict(sj)
    elif isinstance(sj, str) and sj:
        try:
            parsed = _json.loads(sj)
            if isinstance(parsed, dict):
                summary = parsed
        except Exception:
            summary = None
    if summary is None:
        raw = row.result_json
        if isinstance(raw, str):
            try:
                data = _json.loads(raw)
            except Exception:
                return None
        elif isinstance(raw, dict):
            data = raw
        else:
            return None
        s = data.get("summary") if isinstance(data, dict) else None
        if not isinstance(s, dict):
            return None
        summary = s
    return normalize_scan_summary_dimensions(summary)


async def get_assessment_score_verdict(
    session: AsyncSession, task_id: str
) -> tuple[int, str] | None:
    row = await session.get(AssessmentResultRow, task_id)
    if row is None:
        return None
    return int(row.score), str(row.verdict)


async def get_assessment(session: AsyncSession, task_id: str) -> dict[str, Any] | None:
    import json as _json
    row = await session.get(AssessmentResultRow, task_id)
    if row is None:
        return None
    raw = row.assessment_json
    if isinstance(raw, dict):
        return dict(raw)
    if raw is None:
        return None
    if isinstance(raw, str):
        return _json.loads(raw)
    return dict(raw)


async def save_assessment(
    session: AsyncSession,
    task_id: str,
    *,
    schema_version: int,
    policy_version: str,
    assessment_scope: str,
    assessment_json: dict[str, Any],
    score: int,
    verdict: str,
    source_scan_updated_at: str,
) -> None:
    now = _now()
    existing = await session.get(AssessmentResultRow, task_id)
    if existing is None:
        session.add(
            AssessmentResultRow(
                task_id=task_id,
                schema_version=schema_version,
                policy_version=policy_version,
                assessment_scope=assessment_scope,
                assessment_json=(  # type: ignore[arg-type]
                
                json.dumps(assessment_json, ensure_ascii=False)
                if isinstance(assessment_json, dict)
                else assessment_json
            ),
                score=score,
                verdict=verdict,
                source_scan_updated_at=source_scan_updated_at,
                created_at=_as_dt(now),
                updated_at=_as_dt(now),
            )
        )
    else:
        existing.schema_version = schema_version
        existing.policy_version = policy_version
        existing.assessment_scope = assessment_scope
        existing.assessment_json = (  # type: ignore[assignment]
            json.dumps(assessment_json, ensure_ascii=False)
            if isinstance(assessment_json, dict)
            else assessment_json
        )
        existing.score = score
        existing.verdict = verdict
        existing.source_scan_updated_at = source_scan_updated_at
        existing.updated_at = now
    await session.flush()


async def get_repair_plan_available(session: AsyncSession, task_id: str) -> bool:
    row = await session.get(RepairResultRow, task_id)
    return row is not None


async def get_repair_plan(session: AsyncSession, task_id: str) -> dict[str, Any] | None:
    import json as _json
    row = await session.get(RepairResultRow, task_id)
    if row is None:
        return None
    raw = row.repair_json
    if isinstance(raw, dict):
        return dict(raw)
    if raw is None:
        return None
    if isinstance(raw, str):
        return _json.loads(raw)  # may raise; caller maps to domain error
    return dict(raw)


async def save_repair_plan(
    session: AsyncSession,
    task_id: str,
    *,
    schema_version: int,
    policy_version: str,
    repair_scope: str,
    repair_json: dict[str, Any],
    plan_status: str,
    total_repair_groups: int,
    blocking_repair_groups: int,
    source_scan_updated_at: str,
    source_assessment_updated_at: str,
    source_assessment_policy_version: str,
    created_at: Any | None = None,
    updated_at: Any | None = None,
) -> None:
    now = _as_dt(updated_at) if updated_at is not None else _now()
    existing = await session.get(RepairResultRow, task_id)
    if existing is None:
        session.add(
            RepairResultRow(
                task_id=task_id,
                schema_version=schema_version,
                policy_version=policy_version,
                repair_scope=repair_scope,
                repair_json=(  # type: ignore[arg-type]
                
                json.dumps(repair_json, ensure_ascii=False)
                if isinstance(repair_json, dict)
                else repair_json
            ),
                plan_status=plan_status,
                total_repair_groups=total_repair_groups,
                blocking_repair_groups=blocking_repair_groups,
                source_scan_updated_at=source_scan_updated_at,
                source_assessment_updated_at=source_assessment_updated_at,
                source_assessment_policy_version=source_assessment_policy_version,
                created_at=_as_dt(created_at) if created_at is not None else now,
                updated_at=now,
            )
        )
    else:
        existing.schema_version = schema_version
        existing.policy_version = policy_version
        existing.repair_scope = repair_scope
        existing.repair_json = (  # type: ignore[assignment]
            json.dumps(repair_json, ensure_ascii=False)
            if isinstance(repair_json, dict)
            else repair_json
        )
        existing.plan_status = plan_status
        existing.total_repair_groups = total_repair_groups
        existing.blocking_repair_groups = blocking_repair_groups
        existing.source_scan_updated_at = source_scan_updated_at
        existing.source_assessment_updated_at = source_assessment_updated_at
        existing.source_assessment_policy_version = source_assessment_policy_version
        existing.updated_at = _as_dt(now)
    await session.flush()


async def get_llm_analysis_available(session: AsyncSession, task_id: str) -> bool:
    row = await session.get(LlmAnalysisResultRow, task_id)
    return row is not None


async def get_llm_analysis(session: AsyncSession, task_id: str) -> dict[str, Any] | None:
    import json as _json
    row = await session.get(LlmAnalysisResultRow, task_id)
    if row is None:
        return None
    raw = row.analysis_json
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        return _json.loads(raw)
    return None


async def save_llm_analysis(
    session: AsyncSession,
    task_id: str,
    *,
    schema_version: int,
    analysis_json: dict[str, Any],
    total_analyzed: int,
    total_fallback: int,
    source: str,
    source_scan_updated_at: str,
) -> None:
    now = _now()
    existing = await session.get(LlmAnalysisResultRow, task_id)
    if existing is None:
        session.add(
            LlmAnalysisResultRow(
                task_id=task_id,
                schema_version=schema_version,
                analysis_json=(  # type: ignore[arg-type]
                
                json.dumps(analysis_json, ensure_ascii=False)
                if isinstance(analysis_json, dict)
                else analysis_json
            ),
                total_analyzed=total_analyzed,
                total_fallback=total_fallback,
                source=source,
                source_scan_updated_at=source_scan_updated_at,
                created_at=_as_dt(now),
                updated_at=_as_dt(now),
            )
        )
    else:
        existing.schema_version = schema_version
        existing.analysis_json = (  # type: ignore[assignment]
            json.dumps(analysis_json, ensure_ascii=False)
            if isinstance(analysis_json, dict)
            else analysis_json
        )
        existing.total_analyzed = total_analyzed
        existing.total_fallback = total_fallback
        existing.source = source
        existing.source_scan_updated_at = source_scan_updated_at
        existing.updated_at = now
    await session.flush()


async def load_status_enrichment(task_id: str) -> dict[str, Any]:
    """Lightweight polling enrichment (uses a short-lived session)."""
    from app.db.session import get_session_factory

    factory = get_session_factory()
    async with factory() as session:
        out: dict[str, Any] = {
            "file_count": None,
            "total_size": None,
            "top_level_dir": None,
            "scan_summary": None,
            "report_url": None,
            "security_score": None,
            "security_verdict": None,
            "assessment_url": None,
            "repair_plan_available": False,
            "repair_plan_url": None,
            "llm_analysis_available": False,
            "llm_analysis_url": None,
        }
        summary = await get_scan_summary(session, task_id)
        out["scan_summary"] = summary
        out["report_url"] = f"/api/check/{task_id}/result" if summary is not None else None
        assessment = await get_assessment_score_verdict(session, task_id)
        if assessment is not None:
            out["security_score"] = assessment[0]
            out["security_verdict"] = assessment[1]
            out["assessment_url"] = f"/api/check/{task_id}/assessment"
        if await get_repair_plan_available(session, task_id):
            out["repair_plan_available"] = True
            out["repair_plan_url"] = f"/api/check/{task_id}/repair-plan"
        if await get_llm_analysis_available(session, task_id):
            out["llm_analysis_available"] = True
            out["llm_analysis_url"] = f"/api/check/{task_id}/llm-analysis"
        return out


async def copy_task_results(
    session: AsyncSession, source_task_id: str, dest_task_id: str
) -> bool:
    """Copy desensitized result rows for dedup reuse."""
    now = _now()
    copied = False
    src_scan = await session.get(ScanResultRow, source_task_id)
    if src_scan is not None:
        session.add(
            ScanResultRow(
                task_id=dest_task_id,
                schema_version=src_scan.schema_version,
                result_json=src_scan.result_json,
                summary_json=src_scan.summary_json,
                total_findings=src_scan.total_findings,
                blocking_findings=src_scan.blocking_findings,
                total_notices=src_scan.total_notices,
                total_skipped_files=src_scan.total_skipped_files,
                total_scan_errors=src_scan.total_scan_errors,
                total_files_scanned=src_scan.total_files_scanned,
                total_lines_scanned=src_scan.total_lines_scanned,
                created_at=_as_dt(now),
                updated_at=_as_dt(now),
            )
        )
        copied = True
    src_assess = await session.get(AssessmentResultRow, source_task_id)
    if src_assess is not None:
        session.add(
            AssessmentResultRow(
                task_id=dest_task_id,
                schema_version=src_assess.schema_version,
                policy_version=src_assess.policy_version,
                assessment_scope=src_assess.assessment_scope,
                assessment_json=src_assess.assessment_json,
                score=src_assess.score,
                verdict=src_assess.verdict,
                source_scan_updated_at=src_assess.source_scan_updated_at,
                created_at=_as_dt(now),
                updated_at=_as_dt(now),
            )
        )
    src_repair = await session.get(RepairResultRow, source_task_id)
    if src_repair is not None:
        session.add(
            RepairResultRow(
                task_id=dest_task_id,
                schema_version=src_repair.schema_version,
                policy_version=src_repair.policy_version,
                repair_scope=src_repair.repair_scope,
                repair_json=src_repair.repair_json,
                plan_status=src_repair.plan_status,
                total_repair_groups=src_repair.total_repair_groups,
                blocking_repair_groups=src_repair.blocking_repair_groups,
                source_scan_updated_at=src_repair.source_scan_updated_at,
                source_assessment_updated_at=src_repair.source_assessment_updated_at,
                source_assessment_policy_version=src_repair.source_assessment_policy_version,
                created_at=_as_dt(now),
                updated_at=_as_dt(now),
            )
        )
    src_llm = await session.get(LlmAnalysisResultRow, source_task_id)
    if src_llm is not None:
        session.add(
            LlmAnalysisResultRow(
                task_id=dest_task_id,
                schema_version=src_llm.schema_version,
                analysis_json=src_llm.analysis_json,
                total_analyzed=src_llm.total_analyzed,
                total_fallback=src_llm.total_fallback,
                source=src_llm.source,
                source_scan_updated_at=src_llm.source_scan_updated_at,
                created_at=_as_dt(now),
                updated_at=_as_dt(now),
            )
        )
    await session.flush()
    return copied
