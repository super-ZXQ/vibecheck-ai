"""P1 concurrency correctness: admission, fencing, reaper, cleanup bounds."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import settings
from app.db import database
from app.services import background_runner, task_manager
from app.services.task_manager import (
    QueueCapacityError,
    admit_repo_task,
    admit_upload_task,
    claim_next_pending,
    get_pending_count,
    get_task,
    mark_completed,
    mark_dead,
    mark_failed,
    recover_expired_tasks,
    request_cancel,
    touch_heartbeat,
    utc_now,
)


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    monkeypatch.setattr(
        settings,
        "database_url",
        __import__("os").environ.get(
            "TEST_DATABASE_URL",
            "postgresql+asyncpg://vibecheck:vibecheck@127.0.0.1:5432/vibecheck_test",
        ),
    )
    monkeypatch.setattr(settings, "tmp_dir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "max_task_attempts", 3)
    monkeypatch.setattr(settings, "task_lease_seconds", 60)
    monkeypatch.setattr(settings, "max_pending_tasks", 5)
    database._initialized = False
    database.init_db()
    yield tmp_path
    database._initialized = False


class TestAtomicAdmission:
    def test_same_repo_concurrent_single_active(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "max_pending_tasks", 20)
        results = []
        lock = threading.Lock()

        def worker():
            rec, created = admit_repo_task(
                "https://github.com/u/same", "u", "same"
            )
            with lock:
                results.append((rec.id, created))

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(worker) for _ in range(12)]
            for f in futs:
                f.result()

        ids = {rid for rid, _ in results}
        assert len(ids) == 1
        assert sum(1 for _, c in results if c) == 1
        assert sum(1 for _, c in results if not c) == 11

    def test_concurrent_different_repos_never_exceed_capacity(
        self, test_db, monkeypatch
    ):
        monkeypatch.setattr(settings, "max_pending_tasks", 3)
        created = 0
        full = 0
        lock = threading.Lock()

        def worker(i: int):
            nonlocal created, full
            try:
                admit_repo_task(
                    f"https://github.com/u/r{i}", "u", f"r{i}"
                )
                with lock:
                    created += 1
            except QueueCapacityError:
                with lock:
                    full += 1

        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(worker, i) for i in range(20)]
            for f in futs:
                f.result()

        assert get_pending_count() <= 3
        assert created <= 3
        assert full >= 17

    def test_upload_admission_capacity(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "max_pending_tasks", 2)
        for i in range(2):
            admit_upload_task(f"local://upload/{i}", "local", "up")
        with pytest.raises(QueueCapacityError):
            admit_upload_task("local://upload/overflow", "local", "up")
        assert get_pending_count() == 2


class TestLeaseFencing:
    def test_stale_token_cannot_complete(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "development")
        task = task_manager.create_task("https://github.com/u/fence", "u", "fence")
        claimed = claim_next_pending("token-new")
        assert claimed is not None and claimed.id == task.id
        assert mark_completed(task.id, 1, 1, "x", worker_id="token-old") is False
        assert get_task(task.id).status == "running"
        assert mark_completed(task.id, 1, 1, "x", worker_id="token-new") is True
        assert get_task(task.id).status == "completed"

    def test_cancel_cannot_be_overwritten_by_complete(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "development")
        task = task_manager.create_task("https://github.com/u/cxl", "u", "cxl")
        claim_next_pending("tok-c")
        request_cancel(task.id)
        rec = get_task(task.id)
        # Running tasks may only have cancel flag set until worker finalizes.
        assert rec.status in ("running", "cancelled")
        assert rec.cancelled_at is not None or rec.status == "cancelled"
        assert mark_completed(task.id, 1, 1, "x", worker_id="tok-c") is False
        task_manager.mark_cancelled(task.id)
        assert get_task(task.id).status == "cancelled"

    def test_stale_token_cannot_heartbeat(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "development")
        task = task_manager.create_task("https://github.com/u/hb", "u", "hb")
        claim_next_pending("tok-hb")
        assert touch_heartbeat(task.id, "tok-stale") is False
        assert touch_heartbeat(task.id, "tok-hb") is True

    def test_terminal_never_returns_to_running(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "development")
        task = task_manager.create_task("https://github.com/u/term", "u", "term")
        claim_next_pending("tok-t")
        mark_completed(task.id, 1, 1, "x", worker_id="tok-t")
        assert task_manager.mark_running(task.id, "scanning", 10, worker_id="tok-t") is False
        assert get_task(task.id).status == "completed"


class TestRuntimeReaper:
    def test_expired_lease_recovered_without_restart(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "development")
        monkeypatch.setattr(settings, "lease_reaper_seconds", 1)
        monkeypatch.setattr(settings, "task_lease_seconds", 30)
        task = task_manager.create_task("https://github.com/u/reap", "u", "reap")
        claim_next_pending("dead-worker")
        past = (utc_now() - timedelta(seconds=120)).isoformat()
        conn = database._get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET lease_expires_at=? WHERE id=?", (past, task.id)
            )
            conn.commit()
        finally:
            conn.close()
        stats = recover_expired_tasks()
        assert stats["requeued"] == 1
        assert get_task(task.id).status == "pending"

    def test_unexpired_lease_not_reaped(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "development")
        task = task_manager.create_task("https://github.com/u/keep", "u", "keep")
        claim_next_pending("alive")
        future = (utc_now() + timedelta(seconds=300)).isoformat()
        conn = database._get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET lease_expires_at=? WHERE id=?", (future, task.id)
            )
            conn.commit()
        finally:
            conn.close()
        stats = recover_expired_tasks()
        assert stats["requeued"] == 0
        assert get_task(task.id).status == "running"

    @pytest.mark.asyncio
    async def test_dispatcher_loop_runs_the_lease_reaper(self, test_db, monkeypatch):
        """The reaper must fire from inside the dispatcher, not only at startup."""
        calls: list[float] = []

        async def counting_reaper():
            calls.append(time.monotonic())
            return {"requeued": 0, "dead": 0}

        async def fake_worker(task_id, claim_token=None):
            return None

        monkeypatch.setattr(
            background_runner, "recover_expired_tasks_async", counting_reaper
        )
        monkeypatch.setattr(background_runner, "_run_claimed_task", fake_worker)
        monkeypatch.setattr(background_runner, "_stopping", False)
        monkeypatch.setattr(settings, "lease_reaper_seconds", 1)
        monkeypatch.setattr(settings, "dispatcher_poll_seconds", 0.05)

        dispatcher = asyncio.create_task(background_runner._dispatcher_loop())
        try:
            deadline = time.monotonic() + 5
            while len(calls) < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
        finally:
            dispatcher.cancel()
            await asyncio.gather(dispatcher, return_exceptions=True)

        assert len(calls) >= 2, "dispatcher never re-ran the lease reaper"
        assert calls[1] - calls[0] < 2.0, "reaper ignored LEASE_REAPER_SECONDS"


class TestCleanupBoundary:
    def test_cleanup_allows_task_dir_under_tmp_dir(self, test_db, monkeypatch):
        dest = Path(settings.tmp_dir) / "task-ok-cleanup"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "f.txt").write_text("x")
        assert background_runner._cleanup_task_dir("t", dest) is True
        assert not dest.exists()

    def test_cleanup_rejects_outside_tmp_dir(self, test_db, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "production")
        outside = tmp_path / "pytest-not-vibecheck"
        outside.mkdir(parents=True, exist_ok=True)
        (outside / "keep.txt").write_text("keep")
        assert background_runner._cleanup_task_dir("t", outside) is False
        assert outside.exists()

    def test_cleanup_rejects_traversal(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "production")
        assert background_runner._cleanup_task_dir("t", Path("/")) is False
        # `..` escapes settings.tmp_dir, so resolve() lands outside the root.
        escaping = Path(settings.tmp_dir) / ".." / "escape"
        assert escaping.resolve().parent != Path(settings.tmp_dir).resolve()
        assert background_runner._cleanup_task_dir("t", escaping) is False
        # Explicit outside path after resolve
        outside = Path(settings.tmp_dir).resolve().parent / "other-app"
        outside.mkdir(parents=True, exist_ok=True)
        assert background_runner._cleanup_task_dir("t", outside) is False

    def test_cleanup_failure_metric_no_path_leak(
        self, test_db, monkeypatch, caplog
    ):
        monkeypatch.setattr(settings, "app_env", "production")
        secret_path = Path(settings.tmp_dir).parent / "sensitive-name"
        ok = background_runner._cleanup_task_dir("t", secret_path)
        assert ok is False

        # A delete that raises must not leak the path it was given either.
        secret_dir = Path(settings.tmp_dir) / "task-another-sensitive-name"
        secret_dir.mkdir(parents=True, exist_ok=True)

        def explode(dest):
            raise OSError("disk full")

        with patch(
            "app.services.background_runner.cleanup_temp_dir", side_effect=explode
        ):
            assert background_runner._cleanup_task_dir("t", secret_dir) is False

        with caplog.at_level(logging.ERROR, logger="app.services.background_runner"):
            background_runner._cleanup_task_dir("t", secret_path)

        records = [
            r for r in caplog.records
            if r.name == "app.services.background_runner"
        ]
        assert records, "cleanup refusals are expected to log"
        for record in records:
            message = record.getMessage()
            assert "sensitive-name" not in message
            assert "sensitive" not in message
            assert str(secret_path) not in message
        assert secret_dir.exists()  # refused delete left it for the TTL reaper


class TestStaleWorkerAfterRecovery:
    @pytest.mark.asyncio
    async def test_stale_worker_cannot_write_after_reclaim(
        self, test_db, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(settings, "app_env", "test")
        monkeypatch.setattr(settings, "max_task_attempts", 3)
        task = task_manager.create_task("https://github.com/u/stale", "u", "stale")
        old = claim_next_pending("old-token")
        assert old is not None
        # Simulate reaper recovering then new claim
        past = (utc_now() - timedelta(seconds=999)).isoformat()
        conn = database._get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET lease_expires_at=? WHERE id=?", (past, task.id)
            )
            conn.commit()
        finally:
            conn.close()
        recover_expired_tasks()
        new = claim_next_pending("new-token")
        assert new is not None and new.id == task.id
        # Old token cannot complete
        assert mark_completed(task.id, 1, 1, "x", worker_id="old-token") is False
        # New token can
        assert mark_completed(task.id, 1, 1, "x", worker_id="new-token") is True

    @pytest.mark.asyncio
    async def test_zombie_worker_cannot_write_in_requeue_window(
        self, test_db, monkeypatch
    ):
        """Between reaper requeue and the next claim worker_id is NULL.

        A stale worker must not be able to finalize a task it no longer owns
        just because the ownership column was cleared — that would let it
        overwrite the state of whatever claims the task next.
        """
        monkeypatch.setattr(settings, "app_env", "test")
        monkeypatch.setattr(settings, "max_task_attempts", 3)
        task = task_manager.create_task("https://github.com/u/window", "u", "window")
        assert claim_next_pending("zombie-token") is not None

        past = (utc_now() - timedelta(seconds=999)).isoformat()
        conn = database._get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET lease_expires_at=? WHERE id=?", (past, task.id)
            )
            conn.commit()
        finally:
            conn.close()

        assert recover_expired_tasks()["requeued"] == 1
        # No new claimant yet — the row is pending with worker_id cleared.
        reloaded = task_manager.get_task(task.id)
        assert reloaded.status == "pending" and reloaded.worker_id is None

        assert (
            mark_completed(task.id, 1, 1, "x", worker_id="zombie-token") is False
        )
        assert (
            mark_failed(
                task.id, "INTERNAL_ERROR", "zombie", worker_id="zombie-token"
            )
            is False
        )
        assert (
            mark_dead(task.id, "DEAD_TASK", worker_id="zombie-token") is False
        )
        # The task is untouched by the zombie and still claimable.
        assert task_manager.get_task(task.id).status == "pending"
        assert claim_next_pending("next-token") is not None
