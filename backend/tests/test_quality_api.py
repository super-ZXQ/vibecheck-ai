"""GET /api/check/{task_id}/quality-report branch coverage.

The quality report is non-scoring and default-on. These tests pin the
contract:
- missing task and wrong submitter key answer byte-identical 404s
- unfinished tasks answer 409 NOT_READY, never an empty success payload
- failed tasks answer 409 NOT_AVAILABLE even if a residual row exists
- completed tasks without a row (legacy) answer 409 NOT_AVAILABLE
- corrupted JSON answers a fixed 500, not a raw exception
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import (
    QUALITY_REPORT_INTERNAL_ERROR,
    QUALITY_REPORT_NOT_AVAILABLE,
    QUALITY_REPORT_NOT_READY,
)
from app.db import database
from app.services import background_runner, task_manager

A_KEY = "aaaaaaaabbbbbbbbccccccccdddddddd"
B_KEY = "11112222333344445555666677778888"


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.core.config.settings.database_url",
        os.environ.get(
            "TEST_DATABASE_URL",
            "postgresql+asyncpg://vibecheck:vibecheck@127.0.0.1:5432/vibecheck_test",
        ),
    )
    monkeypatch.setattr("app.core.config.settings.tmp_dir", str(tmp_path / "tmp"))
    database._initialized = False
    database.init_db()
    yield tmp_path
    database._initialized = False


@pytest.fixture
def client(test_db):
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_runner():
    background_runner.reset_runner_state()
    yield
    background_runner.reset_runner_state()


def _create_completed_task(submitter_key=None):
    task = task_manager.create_task(
        "https://github.com/test/repo",
        "test",
        "repo",
        submitter_key=submitter_key,
    )
    task_manager.mark_completed(
        task.id, file_count=10, total_size=1000, top_level_dir="test-repo"
    )
    return task.id


def _create_status_task(status: str):
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    if status == "running":
        task_manager.mark_running(task.id, "quality_checks", 85)
    elif status == "failed":
        task_manager.mark_failed(task.id, "INTERNAL_ERROR", "内部错误")
    elif status == "cancelled":
        task_manager.mark_cancelled(task.id)
    elif status == "dead":
        task_manager.mark_dead(task.id, "WORKER_LOST")
    return task.id


def _insert_quality_row(task_id: str, body: str) -> None:
    from datetime import datetime, timezone

    from app.db.models import QualityCheckResultRow
    from app.db.session import get_session_factory

    now = datetime.now(timezone.utc)

    async def _run():
        factory = get_session_factory()
        async with factory() as session:
            session.add(
                QualityCheckResultRow(
                    task_id=task_id,
                    schema_version=1,
                    overall_status="completed",
                    block_statuses_json=json.dumps(
                        {"backend_route_audit": "completed"}
                    ),
                    quality_json=body,
                    total_items=1,
                    manual_items=1,
                    fixable_items=0,
                    source_scan_updated_at="2026-01-01T00:00:00Z",
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()

    asyncio.run(_run())


def _valid_body(task_id: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "task_id": task_id,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "scanner_version": "v1",
            "overall_status": "completed",
            "summary": {
                "total_items": 1,
                "manual_decision_items": 1,
                "fixable_items": 0,
                "auto_fixable_items": 0,
                "blocks_completed": 4,
                "blocks_not_completed": 0,
            },
            "blocks": {},
            "limitations": [],
        },
        ensure_ascii=False,
    )


class TestQualityReportBranches:
    def test_404_missing_task(self, client):
        resp = client.get(f"/api/check/{uuid.uuid4()}/quality-report")
        assert resp.status_code == 404
        assert resp.json()["detail"]["error_code"] == "TASK_NOT_FOUND"

    def test_422_invalid_uuid(self, client):
        resp = client.get("/api/check/not-a-uuid/quality-report")
        assert resp.status_code == 422
        assert resp.json()["detail"]["error_code"] == "INVALID_TASK_ID"

    @pytest.mark.parametrize("status", ["pending", "running"])
    def test_409_not_ready(self, client, status):
        task_id = _create_status_task(status)
        resp = client.get(f"/api/check/{task_id}/quality-report")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_code"] == QUALITY_REPORT_NOT_READY

    def test_409_failed(self, client):
        task_id = _create_status_task("failed")
        resp = client.get(f"/api/check/{task_id}/quality-report")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_code"] == QUALITY_REPORT_NOT_AVAILABLE

    @pytest.mark.parametrize("status", ["cancelled", "dead"])
    def test_409_cancelled_and_dead_use_explicit_contract(self, client, status):
        task_id = _create_status_task(status)
        resp = client.get(f"/api/check/{task_id}/quality-report")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_code"] == QUALITY_REPORT_NOT_AVAILABLE

    @pytest.mark.parametrize("status", ["failed", "cancelled", "dead"])
    def test_terminal_status_with_residual_row_does_not_leak(self, client, status):
        task_id = _create_status_task(status)
        _insert_quality_row(task_id, _valid_body(task_id))
        resp = client.get(f"/api/check/{task_id}/quality-report")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_code"] == QUALITY_REPORT_NOT_AVAILABLE

    def test_409_completed_without_row_is_legacy(self, client):
        task_id = _create_completed_task()
        resp = client.get(f"/api/check/{task_id}/quality-report")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error_code"] == QUALITY_REPORT_NOT_AVAILABLE

    def test_200_completed_with_row(self, client):
        task_id = _create_completed_task()
        _insert_quality_row(task_id, _valid_body(task_id))
        resp = client.get(f"/api/check/{task_id}/quality-report")
        assert resp.status_code == 200
        assert resp.json()["task_id"] == task_id

    def test_500_corrupted_json(self, client):
        task_id = _create_completed_task()
        _insert_quality_row(task_id, "{this is not valid json")
        resp = client.get(f"/api/check/{task_id}/quality-report")
        assert resp.status_code == 500
        assert (
            resp.json()["detail"]["error_code"] == QUALITY_REPORT_INTERNAL_ERROR
        )

    def test_wrong_key_is_byte_identical_to_unknown_task(self, client):
        task_id = _create_completed_task(submitter_key=A_KEY)
        unknown = str(uuid.uuid4())
        wrong_key = client.get(
            f"/api/check/{task_id}/quality-report",
            headers={"X-Submitter-Key": B_KEY},
        )
        missing = client.get(
            f"/api/check/{unknown}/quality-report",
            headers={"X-Submitter-Key": B_KEY},
        )
        assert wrong_key.status_code == missing.status_code == 404
        assert wrong_key.content == missing.content


class TestQualityPollingEnrichment:
    def test_completed_with_row_exposes_url(self, client):
        task_id = _create_completed_task()
        _insert_quality_row(task_id, _valid_body(task_id))
        data = client.get(f"/api/check/{task_id}").json()
        assert data["quality_report_available"] is True
        assert data["quality_report_url"] == (
            f"/api/check/{task_id}/quality-report"
        )

    def test_completed_without_row_is_false(self, client):
        task_id = _create_completed_task()
        data = client.get(f"/api/check/{task_id}").json()
        assert data["quality_report_available"] is False
        assert data["quality_report_url"] is None

    def test_pending_does_not_advertise(self, client):
        task_id = _create_status_task("pending")
        data = client.get(f"/api/check/{task_id}").json()
        assert data.get("quality_report_available") is not True

    def test_failed_does_not_advertise(self, client):
        task_id = _create_status_task("failed")
        data = client.get(f"/api/check/{task_id}").json()
        assert data.get("quality_report_available") is not True

    @pytest.mark.parametrize("status", ["failed", "cancelled", "dead"])
    def test_terminal_status_with_residual_row_is_not_advertised(self, client, status):
        task_id = _create_status_task(status)
        _insert_quality_row(task_id, _valid_body(task_id))
        data = client.get(f"/api/check/{task_id}").json()
        assert data.get("quality_report_available") is not True
        assert data.get("quality_report_url") is None


class _StubReport:
    generated_at = "2026-01-01T00:00:00+00:00"
    blocks: dict = {}

    def summary(self):
        return {
            "total_items": 0,
            "manual_decision_items": 0,
            "fixable_items": 0,
        }

    def overall_status(self):
        return "completed"


def _create_running_owned_task(worker_id: str) -> str:
    task = task_manager.create_task("https://github.com/test/repo", "test", "repo")
    claimed = task_manager.claim_next_pending(worker_id)
    assert claimed is not None and claimed.id == task.id
    return task.id


def _quality_row_exists(task_id: str) -> bool:
    from app.db.models import QualityCheckResultRow
    from app.db.session import get_session_factory

    async def _run():
        async with get_session_factory()() as session:
            return await session.get(QualityCheckResultRow, task_id) is not None

    return asyncio.run(_run())


def _steal_task(task_id: str, new_worker_id: str) -> None:
    from app.db.models import TaskRow
    from app.db.session import get_session_factory

    async def _run():
        async with get_session_factory()() as session:
            row = await session.get(TaskRow, task_id)
            row.worker_id = new_worker_id
            await session.commit()

    asyncio.run(_run())


class TestQualityReportFencing:
    def test_current_claim_token_writes(self, test_db):
        from app.services import quality_service

        task_id = _create_running_owned_task("worker-a")
        ok = asyncio.run(
            quality_service._save_report(
                task_id, _StubReport(), "{}", claim_token="worker-a"
            )
        )
        assert ok is True
        assert _quality_row_exists(task_id) is True

    def test_stolen_task_cannot_write_report(self, test_db):
        from app.services import quality_service

        task_id = _create_running_owned_task("worker-a")
        _steal_task(task_id, "worker-b")
        ok = asyncio.run(
            quality_service._save_report(
                task_id, _StubReport(), "{}", claim_token="worker-a"
            )
        )
        assert ok is False
        assert _quality_row_exists(task_id) is False

    def test_cancelled_task_cannot_write_report(self, test_db):
        from app.services import quality_service

        task_id = _create_running_owned_task("worker-a")
        task_manager.mark_cancelled(task_id)
        ok = asyncio.run(
            quality_service._save_report(
                task_id, _StubReport(), "{}", claim_token="worker-a"
            )
        )
        assert ok is False
        assert _quality_row_exists(task_id) is False

    def test_concurrent_stale_and_current_worker_only_current_writes(self, test_db):
        from app.services import quality_service

        task_id = _create_running_owned_task("worker-b")

        async def _run():
            stale, current = await asyncio.gather(
                quality_service._save_report(
                    task_id, _StubReport(), "{}", claim_token="worker-a"
                ),
                quality_service._save_report(
                    task_id, _StubReport(), "{}", claim_token="worker-b"
                ),
            )
            return stale, current

        stale, current = asyncio.run(_run())
        assert stale is False
        assert current is True
        assert _quality_row_exists(task_id) is True


class TestDedupCopyReport:
    def test_copy_rebinds_task_id_and_generated_at(self, test_db):
        from app.db.models import QualityCheckResultRow
        from app.db.repositories import results as result_repo
        from app.db.session import get_session_factory

        source = _create_completed_task()
        _insert_quality_row(source, _valid_body(source))
        dest = _create_completed_task()

        async def _run():
            async with get_session_factory()() as session:
                copied = await result_repo.copy_task_results(
                    session, source, dest
                )
                await session.commit()
                return copied

        # 只插入了质量报告行，copy_task_results 的布尔返回值表示是否复制了
        # 扫描结果；此处直接校验质量行本身是否完成复制与重绑定。
        asyncio.run(_run())

        async def _load():
            async with get_session_factory()() as session:
                row = await session.get(QualityCheckResultRow, dest)
                return json.loads(row.quality_json)

        payload = asyncio.run(_load())
        assert payload["task_id"] == dest
        assert payload["generated_at"] != "2026-01-01T00:00:00+00:00"
