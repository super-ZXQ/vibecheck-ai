"""quality_checks stage orchestration and degradation (no database required)."""

from __future__ import annotations

import asyncio
import time

import pytest

from app.core.config import settings
from app.quality.models import (
    DIMENSION_BACKEND_COMMENTS,
    DIMENSION_BACKEND_ROUTES,
    DIMENSION_FONT_LICENSE,
    DIMENSION_FRONTEND_DEAD_CODE,
    REASON_ANALYZER_ERROR,
    REASON_ANALYZER_TIMEOUT,
    REASON_ANALYZER_UNAVAILABLE,
    REASON_CANCELLED,
    REASON_INPUT_MISSING,
    REASON_LLM_DISABLED,
    REASON_NO_BACKEND,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_COMPLETED,
    STATUS_PARTIAL,
)
from app.services import quality_service


@pytest.fixture
def captured(monkeypatch):
    payload: dict = {}

    async def fake_save(task_id, report, body):
        payload["report"] = report
        payload["body"] = body
        return True

    monkeypatch.setattr(quality_service, "_save_report", fake_save)
    return payload


def _run(root, **kwargs):
    return asyncio.run(
        quality_service.run_quality_checks("task-1", root, **kwargs)
    )


def test_all_four_dimensions_present_and_degradation_on_empty(tmp_path, captured):
    ok = _run(tmp_path)
    assert ok is True

    report = captured["report"]
    data = report.to_dict()
    assert set(data["blocks"]) == {
        DIMENSION_FRONTEND_DEAD_CODE,
        DIMENSION_FONT_LICENSE,
        DIMENSION_BACKEND_ROUTES,
        DIMENSION_BACKEND_COMMENTS,
    }

    frontend = data["blocks"][DIMENSION_FRONTEND_DEAD_CODE]
    assert frontend["status"] in {STATUS_NOT_APPLICABLE, STATUS_NOT_COMPLETED}
    assert frontend["reason_code"] in {
        REASON_INPUT_MISSING,
        REASON_ANALYZER_UNAVAILABLE,
    }
    assert frontend["reason_message"]

    font_block = data["blocks"][DIMENSION_FONT_LICENSE]
    assert font_block["status"] == STATUS_NOT_APPLICABLE
    assert font_block["reason_code"] == REASON_INPUT_MISSING

    comment_block = data["blocks"][DIMENSION_BACKEND_COMMENTS]
    assert comment_block["status"] == STATUS_NOT_APPLICABLE
    assert comment_block["reason_code"] == REASON_NO_BACKEND

    route_block = data["blocks"][DIMENSION_BACKEND_ROUTES]
    assert route_block["status"] == STATUS_NOT_APPLICABLE
    assert route_block["reason_code"] == REASON_NO_BACKEND


def test_comment_analyzer_without_byok_is_partial_llm_disabled(tmp_path, captured):
    (tmp_path / "app" / "api").mkdir(parents=True)
    (tmp_path / "app" / "api" / "routes.py").write_text(
        '"""Routes module."""\n'
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n\n"
        "@router.get('/x')\n"
        "async def get_x():\n"
        '    """Return a constant. This handler returns a value."""\n'
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    ok = _run(tmp_path)
    assert ok is True

    block = captured["report"].to_dict()["blocks"][DIMENSION_BACKEND_COMMENTS]
    assert block["status"] == STATUS_PARTIAL
    assert block["reason_code"] == REASON_LLM_DISABLED
    assert block["conclusion"]["llm"] == {"state": "disabled", "byok_configured": False}


def test_byok_config_is_forwarded_only_to_comment_analyzer(tmp_path, captured, monkeypatch):
    seen: dict[str, dict | None] = {}

    def comment_analyzer(index, llm_user_config=None):
        seen["comments"] = llm_user_config
        from app.quality.models import STATUS_NOT_APPLICABLE, QualityBlock

        return QualityBlock(
            dimension=DIMENSION_BACKEND_COMMENTS,
            status=STATUS_NOT_APPLICABLE,
            reason_code=REASON_NO_BACKEND,
        )

    def font_analyzer(index, llm_user_config=None):
        raise AssertionError("font analyzer must not receive an LLM config")

    monkeypatch.setitem(
        quality_service._ANALYZERS, DIMENSION_BACKEND_COMMENTS, comment_analyzer
    )
    monkeypatch.setitem(
        quality_service._ANALYZERS, DIMENSION_FONT_LICENSE, font_analyzer
    )

    ok = _run(
        tmp_path,
        llm_user_config={"api_key": "k", "base_url": "https://x.test", "model": "m"},
    )
    assert ok is True
    assert seen["comments"] == {
        "api_key": "k",
        "base_url": "https://x.test",
        "model": "m",
    }


def test_analyzer_timeout_is_an_explicit_reason_not_a_crash(tmp_path, captured, monkeypatch):
    monkeypatch.setattr(settings, "quality_analyzer_timeout", 1)
    monkeypatch.setitem(
        quality_service._ANALYZERS, DIMENSION_BACKEND_ROUTES, lambda index: time.sleep(2)
    )

    ok = _run(tmp_path)
    assert ok is True

    block = captured["report"].to_dict()["blocks"][DIMENSION_BACKEND_ROUTES]
    assert block["status"] == STATUS_NOT_COMPLETED
    assert block["reason_code"] == REASON_ANALYZER_TIMEOUT
    assert "超时" in block["reason_message"]


def test_analyzer_exception_is_an_explicit_error_block(tmp_path, captured, monkeypatch):
    def boom(index):
        raise RuntimeError("analyzer failed")

    monkeypatch.setitem(quality_service._ANALYZERS, DIMENSION_BACKEND_ROUTES, boom)

    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )

    ok = _run(tmp_path)
    assert ok is True

    block = captured["report"].to_dict()["blocks"][DIMENSION_BACKEND_ROUTES]
    assert block["status"] == STATUS_NOT_COMPLETED
    assert block["reason_code"] == REASON_ANALYZER_ERROR
    assert block["reason_message"]


def test_cancellation_fence_marks_block_cancelled(tmp_path, captured):
    ok = _run(tmp_path, cancel_check=lambda: True)
    assert ok is True

    block = captured["report"].to_dict()["blocks"][DIMENSION_BACKEND_ROUTES]
    assert block["status"] == STATUS_NOT_COMPLETED
    assert block["reason_code"] == REASON_CANCELLED


def test_enforce_limits_truncates_items_and_marks_block(tmp_path, captured, monkeypatch):
    from app.quality.models import (
        DIMENSION_BACKEND_ROUTES as DIM,
    )
    from app.quality.models import (
        STATUS_COMPLETED,
        QualityBlock,
        QualityItem,
        QualityReport,
    )

    monkeypatch.setattr(settings, "quality_max_items_per_block", 2)

    items = [
        QualityItem(
            item_id=f"item-{i}",
            dimension=DIM,
            category="unused_route_candidate",
            conclusion="unused_candidate",
            confidence="medium",
            title=f"route {i}",
        )
        for i in range(5)
    ]
    report = QualityReport(
        task_id="task-1",
        generated_at="2026-01-01T00:00:00+00:00",
        scanner_version="v1",
        blocks={DIM: QualityBlock(dimension=DIM, status=STATUS_COMPLETED, items=items)},
    )

    from app.quality.models import (
        DIMENSION_BACKEND_COMMENTS,
        DIMENSION_FONT_LICENSE,
        DIMENSION_FRONTEND_DEAD_CODE,
        REASON_ANALYZER_UNAVAILABLE,
        STATUS_NOT_COMPLETED,
    )

    for dim in (
        DIMENSION_FRONTEND_DEAD_CODE,
        DIMENSION_FONT_LICENSE,
        DIMENSION_BACKEND_COMMENTS,
    ):
        report.blocks[dim] = QualityBlock(
            dimension=dim,
            status=STATUS_NOT_COMPLETED,
            reason_code=REASON_ANALYZER_UNAVAILABLE,
            reason_message="unavailable",
        )

    payload = quality_service._enforce_limits(report)
    assert len(report.blocks[DIM].items) == 2
    assert report.blocks[DIM].truncated is True
    assert report.blocks[DIM].status == "partial"
    assert "RESULT_TRUNCATED" in payload


def test_frontend_analyzer_node_missing_does_not_affect_other_blocks(
    tmp_path, captured, monkeypatch
):
    from app.quality.analyzers import frontend_dead_code

    monkeypatch.setattr(frontend_dead_code, "_node_binary", lambda: None)
    (tmp_path / "frontend" / "app").mkdir(parents=True)
    (tmp_path / "frontend" / "app" / "page.tsx").write_text(
        "export default function Page() { return null; }\n", encoding="utf-8"
    )

    ok = _run(tmp_path)
    assert ok is True

    data = captured["report"].to_dict()
    frontend = data["blocks"][DIMENSION_FRONTEND_DEAD_CODE]
    assert frontend["status"] == STATUS_NOT_COMPLETED
    assert frontend["reason_code"] == REASON_ANALYZER_UNAVAILABLE
    assert data["blocks"][DIMENSION_FONT_LICENSE]["status"] != STATUS_NOT_COMPLETED


def test_frontend_analyzer_golden_sample():
    import shutil
    from pathlib import Path

    from app.quality.analyzers import frontend_dead_code

    repo_root = Path(__file__).resolve().parents[3]
    if not frontend_dead_code._SCRIPT.exists() or not frontend_dead_code._REQUIRED_MODULE.exists():
        pytest.skip("frontend analyzer Node dependencies are not installed")
    if shutil.which(settings.frontend_analyzer_node_bin) is None:
        pytest.skip("Node runtime is not installed")

    from app.quality.repository_index import RepositoryIndex

    block = frontend_dead_code.analyze_frontend_dead_code(RepositoryIndex(repo_root))
    data = block.to_dict()
    assert data["status"] == "completed"
    assert data["conclusion"]["counts"]["zero_call_functions"] == 2
    assert data["conclusion"]["counts"]["css_classes"] == 4
    names = {item["details"]["name"] for item in data["items"]}
    assert names == {
        "mockSubmitError",
        "mockTaskStatusNetworkError",
        "card-hover",
        "history-status-completed",
        "focus-visible",
        "visually-hidden",
    }
    assert all(item["confidence"] == "high" for item in data["items"])
