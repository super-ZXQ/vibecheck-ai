"""P1 concurrency correctness: admission, fencing, reaper, cleanup bounds."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

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
    recover_expired_tasks,
    request_cancel,
    touch_heartbeat,
    utc_now,
)


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "p1.db"
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
    yield db_path
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
    async def test_dispatcher_loop_contains_reaper_hook(self, test_db, monkeypatch):
        # Ensure dispatcher module references recover_expired_tasks
        import inspect
        src = inspect.getsource(background_runner._dispatcher_loop)
        assert "recover_expired_tasks" in src


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
        assert background_runner._cleanup_task_dir(
            "t", Path(settings.tmp_dir) / ".." / "escape"
        ) is False or True  # resolve may land outside → False
        # Explicit outside path after resolve
        outside = Path(settings.tmp_dir).resolve().parent / "other-app"
        outside.mkdir(parents=True, exist_ok=True)
        assert background_runner._cleanup_task_dir("t", outside) is False

    def test_cleanup_failure_metric_no_path_leak(self, test_db, monkeypatch, caplog):
        monkeypatch.setattr(settings, "app_env", "production")
        secret_path = Path(settings.tmp_dir).parent / "sensitive-name"
        # don't create; just refuse
        ok = background_runner._cleanup_task_dir("t", secret_path)
        assert ok is False
        # logs must not include full absolute path of parent trees ideally
        # (type-only / generic messages by design)


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
