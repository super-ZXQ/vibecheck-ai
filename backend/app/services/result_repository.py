"""Async + sync wrappers around result repository for existing services."""

from __future__ import annotations

import asyncio
import concurrent.futures
from typing import Any, Coroutine, TypeVar

from app.db.repositories import results as result_repo
from app.db.session import get_session_factory

T = TypeVar("T")


def _run(coro: Coroutine[Any, Any, T]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()  # type: ignore[arg-type]


async def _with_session(fn, *args, **kwargs):
    factory = get_session_factory()
    async with factory() as session:
        try:
            result = await fn(session, *args, **kwargs)
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise


def save_scan_result_sync(task_id: str, payload: dict[str, Any]) -> None:
    async def _save():
        await _with_session(
            result_repo.save_scan_result,
            task_id,
            schema_version=payload["schema_version"],
            result_json=payload["result_json"],
            summary_json=payload.get("summary_json") or {},
            totals=payload.get("totals") or {},
        )

    _run(_save())


def get_scan_result_sync(task_id: str) -> dict[str, Any] | None:
    return _run(_with_session(result_repo.get_scan_result, task_id))


def get_scan_summary_sync(task_id: str) -> dict[str, Any] | None:
    return _run(_with_session(result_repo.get_scan_summary, task_id))


def save_assessment_sync(task_id: str, payload: dict[str, Any]) -> None:
    async def _save():
        await _with_session(
            result_repo.save_assessment,
            task_id,
            schema_version=payload["schema_version"],
            policy_version=payload["policy_version"],
            assessment_scope=payload["assessment_scope"],
            assessment_json=payload["assessment_json"],
            score=int(payload["score"]),
            verdict=str(payload["verdict"]),
            source_scan_updated_at=str(payload.get("source_scan_updated_at") or ""),
        )

    _run(_save())


def get_assessment_sync(task_id: str) -> dict[str, Any] | None:
    return _run(_with_session(result_repo.get_assessment, task_id))


def get_assessment_score_verdict_sync(task_id: str) -> tuple[int, str] | None:
    return _run(_with_session(result_repo.get_assessment_score_verdict, task_id))


def save_repair_plan_sync(task_id: str, payload: dict[str, Any]) -> None:
    async def _save():
        await _with_session(
            result_repo.save_repair_plan,
            task_id,
            schema_version=payload["schema_version"],
            policy_version=payload["policy_version"],
            repair_scope=payload["repair_scope"],
            repair_json=payload["repair_json"],
            plan_status=str(payload["plan_status"]),
            total_repair_groups=int(payload.get("total_repair_groups") or 0),
            blocking_repair_groups=int(payload.get("blocking_repair_groups") or 0),
            source_scan_updated_at=str(payload.get("source_scan_updated_at") or ""),
            source_assessment_updated_at=str(
                payload.get("source_assessment_updated_at") or ""
            ),
            source_assessment_policy_version=str(
                payload.get("source_assessment_policy_version") or ""
            ),
            created_at=payload.get("created_at"),
            updated_at=payload.get("updated_at"),
        )

    _run(_save())


def get_repair_plan_sync(task_id: str) -> dict[str, Any] | None:
    try:
        return _run(_with_session(result_repo.get_repair_plan, task_id))
    except Exception:
        # Invalid/corrupted JSONB/text payload → domain error at service layer
        raise


def get_repair_plan_available_sync(task_id: str) -> bool:
    return bool(_run(_with_session(result_repo.get_repair_plan_available, task_id)))


def save_llm_analysis_sync(task_id: str, payload: dict[str, Any]) -> None:
    async def _save():
        await _with_session(
            result_repo.save_llm_analysis,
            task_id,
            schema_version=int(payload.get("schema_version") or 1),
            analysis_json=payload["analysis_json"],
            total_analyzed=int(payload.get("total_analyzed") or 0),
            total_fallback=int(payload.get("total_fallback") or 0),
            source=str(payload.get("source") or "fallback"),
            source_scan_updated_at=str(payload.get("source_scan_updated_at") or ""),
        )

    _run(_save())


def get_llm_analysis_sync(task_id: str) -> dict[str, Any] | None:
    return _run(_with_session(result_repo.get_llm_analysis, task_id))


def get_llm_analysis_available_sync(task_id: str) -> bool:
    return bool(_run(_with_session(result_repo.get_llm_analysis_available, task_id)))


# Public names used by legacy services
get_scan_result = get_scan_result_sync
get_scan_summary = get_scan_summary_sync
get_assessment_score_verdict = get_assessment_score_verdict_sync
get_repair_plan_available = get_repair_plan_available_sync
get_llm_analysis_available = get_llm_analysis_available_sync


def load_status_enrichment(task_id: str) -> dict:
    """Sync wrapper for TaskRecord.to_response enrichment."""
    return _run(result_repo.load_status_enrichment(task_id))


load_status_enrichment_sync = load_status_enrichment
