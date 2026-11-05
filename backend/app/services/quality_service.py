"""Orchestration and persistence for the default-on quality report stage."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.scanner_version import SCANNER_VERSION
from app.db.database import init_db
from app.db.models import QualityCheckResultRow
from app.db.repositories import results as result_repo
from app.db.session import get_session_factory
from app.quality.analyzers.comment_quality import analyze_backend_comments
from app.quality.analyzers.font_audit import analyze_font_licenses
from app.quality.analyzers.frontend_dead_code import analyze_frontend_dead_code
from app.quality.analyzers.route_audit import analyze_backend_routes
from app.quality.models import (
    DIMENSION_BACKEND_COMMENTS,
    DIMENSION_BACKEND_ROUTES,
    DIMENSION_FONT_LICENSE,
    DIMENSION_FRONTEND_DEAD_CODE,
    QUALITY_SCHEMA_VERSION,
    REASON_ANALYZER_ERROR,
    REASON_ANALYZER_TIMEOUT,
    REASON_ANALYZER_UNAVAILABLE,
    REASON_CANCELLED,
    REASON_RESULT_TRUNCATED,
    STATUS_COMPLETED,
    STATUS_NOT_COMPLETED,
    STATUS_PARTIAL,
    QualityBlock,
    QualityReport,
)
from app.quality.repository_index import RepositoryIndex

logger = logging.getLogger(__name__)

# Registry of implemented analyzers.
_ANALYZERS: dict[str, Callable[..., QualityBlock]] = {
    DIMENSION_FRONTEND_DEAD_CODE: analyze_frontend_dead_code,
    DIMENSION_FONT_LICENSE: analyze_font_licenses,
    DIMENSION_BACKEND_ROUTES: analyze_backend_routes,
    DIMENSION_BACKEND_COMMENTS: analyze_backend_comments,
}

# Dimensions whose analyzer accepts the optional BYOK LLM config. Only the
# comment analyzer may call a model; font tri-state is never model-derived.
_LLM_AWARE_DIMENSIONS = frozenset({DIMENSION_BACKEND_COMMENTS})


def _empty_block(dimension: str, reason_code: str, message: str) -> QualityBlock:
    return QualityBlock(
        dimension=dimension,
        status=STATUS_NOT_COMPLETED,
        reason_code=reason_code,
        reason_message=message,
        conclusion={"headline": message, "counts": {}},
        verification={"checks_run": [], "uncovered_risks": [message]},
        coverage={"inputs_missing": ["analyzer"]},
    )


def _mark_truncated(block: QualityBlock) -> None:
    """Truncation is a degradation: completed blocks become partial."""
    block.truncated = True
    block.truncation_reason = "部分明细已按报告容量上限截断。"
    if block.status in (STATUS_COMPLETED, STATUS_NOT_COMPLETED):
        block.status = STATUS_PARTIAL
    if block.reason_code is None:
        block.reason_code = REASON_RESULT_TRUNCATED
        block.reason_message = "报告超出体积上限，已截断明细。"


def _enforce_limits(report: QualityReport) -> str:
    """Bound persisted item/evidence counts and total JSON bytes."""
    for block in report.blocks.values():
        max_items = settings.quality_max_items_per_block
        if len(block.items) > max_items:
            block.items = block.items[:max_items]
            _mark_truncated(block)
        for item in block.items:
            if len(item.evidence) > settings.quality_max_evidence_per_item:
                item.evidence = item.evidence[: settings.quality_max_evidence_per_item]
                _mark_truncated(block)
    payload = json.dumps(
        report.to_dict(), ensure_ascii=False, separators=(",", ":")
    )
    if len(payload.encode("utf-8")) <= settings.quality_max_json_bytes:
        return payload
    for block in report.blocks.values():
        if block.items:
            block.items = block.items[: max(1, len(block.items) // 2)]
            _mark_truncated(block)
    payload = json.dumps(
        report.to_dict(), ensure_ascii=False, separators=(",", ":")
    )
    if len(payload.encode("utf-8")) <= settings.quality_max_json_bytes:
        return payload
    for block in report.blocks.values():
        block.items = []
        block.details = {}
        _mark_truncated(block)
    return json.dumps(report.to_dict(), ensure_ascii=False, separators=(",", ":"))


async def _save_report(task_id: str, report: QualityReport, payload: str) -> bool:
    init_db()
    factory = get_session_factory()
    summary = report.summary()
    try:
        async with factory() as session:
            row = await session.get(QualityCheckResultRow, task_id)
            if row is None:
                row = QualityCheckResultRow(task_id=task_id)
                session.add(row)
            row.schema_version = QUALITY_SCHEMA_VERSION
            row.overall_status = report.overall_status()
            row.block_statuses_json = json.dumps(
                {b.dimension: b.status for b in report.blocks.values()},
                ensure_ascii=False,
            )
            row.quality_json = payload
            row.total_items = summary["total_items"]
            row.manual_items = summary["manual_decision_items"]
            row.fixable_items = summary["fixable_items"]
            row.source_scan_updated_at = report.generated_at
            row.updated_at = datetime.now(timezone.utc)
            if row.created_at is None:
                row.created_at = datetime.now(timezone.utc)
            await session.commit()
        return True
    except Exception:
        logger.warning("quality report persistence failed for task %s", task_id, exc_info=True)
        return False


async def run_quality_checks(
    task_id: str,
    root: Path,
    cancel_check: Callable[[], bool] | None = None,
    scanner_version: str | None = None,
    llm_user_config: dict[str, Any] | None = None,
) -> bool:
    """Run all default-on quality checks and persist a structured report.

    The function never raises: per-analyzer failures are represented as
    explicit block statuses so the task pipeline can keep going. A persistence
    failure is logged and reported through the missing-report API state.
    """
    started = time.monotonic()
    deadline = started + max(5, settings.quality_check_timeout - 3)
    blocks: dict[str, QualityBlock] = {}
    limitations: list[str] = []

    try:
        index = await asyncio.wait_for(
            asyncio.to_thread(RepositoryIndex, root),
            timeout=max(1, deadline - time.monotonic()),
        )
    except TimeoutError:
        index = None
        limitations.append("仓库索引超时，四类质量检查均未完成。")
    except Exception:
        index = None
        limitations.append("仓库索引失败，四类质量检查均未完成。")
        logger.warning("quality repository index failed for task %s", task_id, exc_info=True)

    for dimension in (
        DIMENSION_FRONTEND_DEAD_CODE,
        DIMENSION_FONT_LICENSE,
        DIMENSION_BACKEND_ROUTES,
        DIMENSION_BACKEND_COMMENTS,
    ):
        analyzer = _ANALYZERS.get(dimension)
        if analyzer is None:
            blocks[dimension] = _empty_block(
                dimension,
                REASON_ANALYZER_UNAVAILABLE,
                "分析器未注册，未执行。",
            )
            continue
        if index is None:
            blocks[dimension] = _empty_block(
                dimension,
                REASON_ANALYZER_ERROR,
                "仓库索引不可用，分析未执行。",
            )
            continue
        if cancel_check is not None and cancel_check():
            blocks[dimension] = _empty_block(
                dimension,
                REASON_CANCELLED,
                "任务已取消，分析未完成。",
            )
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            blocks[dimension] = _empty_block(
                dimension,
                REASON_ANALYZER_TIMEOUT,
                "质量检查总预算耗尽，分析未完成。",
            )
            limitations.append("质量检查总预算耗尽。")
            continue
        try:
            if dimension in _LLM_AWARE_DIMENSIONS:
                analyzer_coro = asyncio.to_thread(
                    analyzer, index, llm_user_config=llm_user_config
                )
            else:
                analyzer_coro = asyncio.to_thread(analyzer, index)
            blocks[dimension] = await asyncio.wait_for(
                analyzer_coro,
                timeout=max(1, min(settings.quality_analyzer_timeout, remaining)),
            )
        except TimeoutError:
            blocks[dimension] = _empty_block(
                dimension,
                REASON_ANALYZER_TIMEOUT,
                "分析器超时，未完成。",
            )
            limitations.append("分析器超时。")
        except Exception:
            blocks[dimension] = _empty_block(
                dimension,
                REASON_ANALYZER_ERROR,
                "分析器发生内部错误，未完成。",
            )
            limitations.append("分析器发生内部错误。")
            logger.warning(
                "quality analyzer failed for task %s", task_id, exc_info=True
            )

    report = QualityReport(
        task_id=task_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        scanner_version=scanner_version or SCANNER_VERSION,
        blocks=blocks,
        limitations=limitations,
    )
    try:
        payload = _enforce_limits(report)
        return await _save_report(task_id, report, payload)
    except Exception:
        logger.warning("quality report build failed for task %s", task_id, exc_info=True)
        return False


class QualityReportInternalError(Exception):
    """Raised when a persisted quality report cannot be read or parsed.

    The API maps this to a fixed 500 QUALITY_REPORT_INTERNAL_ERROR so raw
    exceptions never reach the client.
    """


async def get_quality_report_async(task_id: str) -> dict | None:
    """Return the persisted report payload, or None when no row exists."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            return await result_repo.get_quality_report(session, task_id)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise QualityReportInternalError(
                "Failed to parse persisted quality report"
            ) from exc
