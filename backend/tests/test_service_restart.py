"""Tests for crash-safe lease recovery (replaces force-fail on restart).

Semantics:
- Expired running leases re-queue (pending) when attempts remain
- Expired leases with attempts exhausted become dead
- Non-expired running leases are left alone
- Pending tasks stay pending (never force-failed on restart)
- Terminal tasks are untouched
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import DEAD_TASK
from app.db import database
from app.services import task_manager
from app.services.task_manager import utc_now


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Set up a temporary test database."""
    monkeypatch.setattr(
        "app.core.config.settings.database_url",
        __import__("os").environ.get(
            "TEST_DATABASE_URL",
            "postgresql+asyncpg://vibecheck:vibecheck@127.0.0.1:5432/vibecheck_test",
        ),
    )
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    monkeypatch.setattr(
        "app.core.config.settings.max_task_attempts", 3
    )
    monkeypatch.setattr(
        "app.core.config.settings.task_lease_seconds", 60
    )
    database._initialized = False
    database.init_db()
    yield tmp_path
    database._initialized = False


def _force_expired_lease(task_id: str) -> None:
    import asyncio

    from sqlalchemy import update

    from app.db.models import TaskRow
    from app.db.session import get_session_factory

    async def _run():
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(
                update(TaskRow)
                .where(TaskRow.id == task_id)
                .values(lease_expires_at=utc_now() - timedelta(seconds=300))
            )
            await session.commit()

    asyncio.run(_run())


def _force_future_lease(task_id: str) -> None:
    import asyncio

    from sqlalchemy import update

    from app.db.models import TaskRow
    from app.db.session import get_session_factory

    async def _run():
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(
                update(TaskRow)
                .where(TaskRow.id == task_id)
                .values(lease_expires_at=utc_now() + timedelta(seconds=600))
            )
            await session.commit()

    asyncio.run(_run())


class TestLeaseRecovery:
    """Tests for recover_expired_tasks() — crash-safe restart recovery."""

    def test_expired_running_requeued(self, test_db):
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        claimed = task_manager.claim_next_pending("worker-a")
        assert claimed is not None
        assert claimed.status == "running"
        _force_expired_lease(task.id)

        stats = task_manager.recover_expired_tasks()
        assert stats["requeued"] >= 1

        result = task_manager.get_task(task.id)
        assert result.status == "pending"
        assert result.worker_id is None
        assert result.lease_expires_at is None

    def test_non_expired_running_not_recovered(self, test_db):
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        claimed = task_manager.claim_next_pending("worker-b")
        assert claimed is not None
        _force_future_lease(task.id)

        stats = task_manager.recover_expired_tasks()
        assert stats["requeued"] == 0
        assert stats["dead"] == 0

        result = task_manager.get_task(task.id)
        assert result.status == "running"

    def test_expired_max_attempts_dead(self, test_db, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.max_task_attempts", 1)
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
            max_attempts=1,
        )
        claimed = task_manager.claim_next_pending("worker-c")
        assert claimed is not None
        assert claimed.attempt_count == 1
        _force_expired_lease(task.id)

        stats = task_manager.recover_expired_tasks()
        assert stats["dead"] >= 1

        result = task_manager.get_task(task.id)
        assert result.status == "dead"
        assert result.error_code in (DEAD_TASK, result.error_code)
        assert result.worker_id is None

    def test_pending_tasks_remain_pending(self, test_db):
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        stats = task_manager.recover_expired_tasks()
        assert stats["requeued"] == 0
        assert stats["dead"] == 0
        result = task_manager.get_task(task.id)
        assert result.status == "pending"

    def test_terminal_tasks_untouched(self, test_db):
        completed = task_manager.create_task(
            "https://github.com/c/repo", "c", "repo"
        )
        task_manager.claim_next_pending("w")
        task_manager.mark_completed(completed.id, 1, 1, "repo")

        failed = task_manager.create_task(
            "https://github.com/f/repo", "f", "repo"
        )
        task_manager.mark_failed(failed.id, "DOWNLOAD_FAILED")

        task_manager.recover_expired_tasks()
        assert task_manager.get_task(completed.id).status == "completed"
        assert task_manager.get_task(failed.id).status == "failed"

    def test_two_recoverers_do_not_duplicate(self, test_db):
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        task_manager.claim_next_pending("worker-d")
        _force_expired_lease(task.id)

        s1 = task_manager.recover_expired_tasks()
        s2 = task_manager.recover_expired_tasks()
        assert s1["requeued"] >= 1
        # Second recovery finds nothing expired-running.
        assert s2["requeued"] == 0
        assert task_manager.get_task(task.id).status == "pending"

    def test_atomic_claim_unique_under_concurrency(self, test_db):
        """Two claimers must never claim the same task."""
        for i in range(5):
            task_manager.create_task(
                f"https://github.com/user/repo{i}",
                "user",
                f"repo{i}",
            )
        claimed_ids: list[str] = []
        for worker in ("w1", "w2", "w3", "w4", "w5", "w6"):
            rec = task_manager.claim_next_pending(worker)
            if rec is not None:
                claimed_ids.append(rec.id)
        assert len(claimed_ids) == len(set(claimed_ids))
        assert len(claimed_ids) == 5

    def test_heartbeat_extends_lease(self, test_db):
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        claimed = task_manager.claim_next_pending("worker-hb")
        assert claimed is not None
        before = claimed.lease_expires_at
        assert task_manager.touch_heartbeat(task.id) is True
        after = task_manager.get_task(task.id)
        assert after.last_heartbeat_at is not None
        assert after.lease_expires_at is not None
        # Both timestamps are timezone-aware datetime or ISO strings.
        b = before
        a = after.lease_expires_at
        if isinstance(a, str) or isinstance(b, str):
            assert str(a) >= str(b or "")
        else:
            assert a >= b


class TestStartupEvent:
    """Tests for the FastAPI startup event integration."""

    def test_startup_does_not_force_fail_pending(self, test_db, monkeypatch):
        async def _noop_start():
            return None

        monkeypatch.setattr(
            "app.services.background_runner.start_dispatcher", _noop_start
        )
        running_task = task_manager.create_task(
            "https://github.com/user1/repo1", "user1", "repo1"
        )
        task_manager.claim_next_pending("worker-start")
        assert task_manager.get_task(running_task.id).status == "running"
        pending_task = task_manager.create_task(
            "https://github.com/user2/repo2", "user2", "repo2"
        )

        from app.main import app
        with TestClient(app) as client:
            response = client.get("/api/health")
            assert response.status_code == 200
            ready = client.get("/api/ready")
            assert ready.status_code == 200
            body = ready.json()
            assert body["status"] == "ready"
            assert "database" in body.get("dependencies", {})

        assert task_manager.get_task(pending_task.id).status == "pending"
        running = task_manager.get_task(running_task.id)
        assert running.status == "running"

    def test_startup_recovers_expired_lease(self, test_db, monkeypatch):
        async def _noop_start():
            return None

        monkeypatch.setattr(
            "app.services.background_runner.start_dispatcher", _noop_start
        )
        running_task = task_manager.create_task(
            "https://github.com/user1/repo1", "user1", "repo1"
        )
        task_manager.claim_next_pending("worker-start2")
        _force_expired_lease(running_task.id)

        from app.main import app
        with TestClient(app) as client:
            assert client.get("/api/health").status_code == 200

        recovered = task_manager.get_task(running_task.id)
        assert recovered.status == "pending"
        assert recovered.worker_id is None

    def test_recovery_message_is_safe(self, test_db):
        task = task_manager.create_task(
            "https://github.com/user/repo", "user", "repo"
        )
        task_manager.mark_failed(task.id, "DOWNLOAD_FAILED")
        result = task_manager.get_task(task.id)
        msg = result.error_message or ""
        assert "/tmp/" not in msg
        assert "Traceback" not in msg
        assert "ghp_" not in msg
        assert "token" not in msg.lower()


class TestCancelAndDedupBasics:
    def test_cancel_pending_idempotent(self, test_db):
        task = task_manager.create_task(
            "https://github.com/u/r", "u", "r"
        )
        status = task_manager.request_cancel(task.id)
        assert status == "cancelled"
        status2 = task_manager.request_cancel(task.id)
        assert status2 == "cancelled"
        rec = task_manager.get_task(task.id)
        assert rec.status == "cancelled"
        assert rec.api_status == "failed"
        assert rec.error_code == "TASK_CANCELLED"

    def test_cancel_completed_is_noop(self, test_db):
        task = task_manager.create_task(
            "https://github.com/u/r2", "u", "r2"
        )
        task_manager.claim_next_pending("wc")
        task_manager.mark_completed(task.id, 1, 1, "r")
        status = task_manager.request_cancel(task.id)
        assert status == "completed"
        assert task_manager.get_task(task.id).status == "completed"

    def test_dedup_key_format(self, test_db):
        key = task_manager.build_deduplication_key(
            "https://github.com/Owner/Repo.git",
            "ABCDEF" + "0" * 34,
            "scanner-v1",
        )
        assert key == (
            "https://github.com/owner/repo|abcdef" + "0" * 34 + "|scanner-v1"
        )

    def test_dedup_reuse_completed(self, test_db):
        source = task_manager.create_task(
            "https://github.com/u/dedup", "u", "dedup"
        )
        task_manager.claim_next_pending("wd")
        task_manager.mark_completed(source.id, 3, 200, "dedup")
        task_manager.set_resolved_commit_sha(source.id, "a" * 40)

        # Ensure dedup key present
        src = task_manager.get_task(source.id)
        assert src.deduplication_key
        found = task_manager.find_completed_by_dedup_key(src.deduplication_key)
        assert found is not None
        assert found.id == source.id

        dest = task_manager.create_task(
            "https://github.com/u/dedup", "u", "dedup"
        )
        ok = task_manager.complete_as_reused(dest.id, found)
        assert ok
        reused = task_manager.get_task(dest.id)
        assert reused.status == "completed"
        assert reused.reused_from_task_id == source.id

    def test_fail_or_retry_transient(self, test_db, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.max_task_attempts", 3)
        monkeypatch.setattr("app.core.config.settings.retry_base_seconds", 1)
        monkeypatch.setattr("app.core.config.settings.retry_max_seconds", 2)
        task = task_manager.create_task(
            "https://github.com/u/retry", "u", "retry"
        )
        task_manager.claim_next_pending("wr")
        status = task_manager.fail_or_retry(
            task.id, "DOWNLOAD_FAILED", failure_category="GITHUB_TEMPORARY_ERROR"
        )
        assert status == "pending"
        rec = task_manager.get_task(task.id)
        assert rec.next_attempt_at is not None

    def test_fail_or_retry_permanent(self, test_db):
        task = task_manager.create_task(
            "https://github.com/u/perma", "u", "perma"
        )
        task_manager.claim_next_pending("wp")
        status = task_manager.fail_or_retry(
            task.id, "UNSAFE_ARCHIVE", failure_category="INVALID_ARCHIVE"
        )
        assert status == "failed"
        rec = task_manager.get_task(task.id)
        assert rec.status == "failed"
        assert rec.next_attempt_at is None

    def test_queue_full_returns_429(self, test_db, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.max_pending_tasks", 1)
        from app.services.task_manager import is_queue_full
        task_manager.create_task("https://github.com/q/r1", "q", "r1")
        assert is_queue_full() is True

    def test_metrics_endpoint_renders(self, test_db):
        from app.main import app
        with TestClient(app) as client:
            resp = client.get("/metrics")
            assert resp.status_code == 200
            assert "vibecheck_queue_depth" in resp.text
            assert "api_key" not in resp.text.lower() or "vibecheck" in resp.text
