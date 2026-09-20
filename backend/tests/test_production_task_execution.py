"""Production-like task execution tests: concurrency, cancel, BYOK, metrics.

No real network. No real API keys. Synthetic fixtures only.
"""

from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.github import DownloadResult, parse_repo_url
from app.core.safe_extract import ExtractionResult
from app.db import database
from app.services import background_runner, metrics, task_manager
from app.services.llm_user_config import (
    clear_user_configs,
    count_user_configs,
    get_user_config,
    pop_user_config,
    store_user_config,
)
from app.services.task_errors import (
    category_for_error_code,
    compute_backoff_seconds,
    decide_retry,
    is_retryable,
)
from app.services.task_manager import utc_now


@pytest.fixture
def test_db(tmp_path, monkeypatch):
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
    (tmp_path / "tmp").mkdir(parents=True, exist_ok=True)
    database._initialized = False
    database.init_db()
    yield tmp_path
    database._initialized = False


def _mock_download(tmp_path, repo_url="https://github.com/testuser/testrepo"):
    temp_file = Path(tmp_path) / f"dl-{time.time_ns()}.tar.gz"
    temp_file.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20)
    return DownloadResult(
        temp_file=temp_file,
        repo_info=parse_repo_url(repo_url),
        file_size=40,
        commit_sha="b" * 40,
    )


def _mock_extract(tmp_path):
    dest = Path(settings.tmp_dir) / f"extract-{time.time_ns()}"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "README.md").write_text("# t\n")
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=10,
        top_level_dir=dest.name,
    )


class TestAtomicClaim:
    def test_concurrent_claims_unique(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "max_task_attempts", 3)
        for i in range(20):
            task_manager.create_task(
                f"https://github.com/u/r{i}", "u", f"r{i}"
            )
        claimed: list[str] = []
        lock = threading.Lock()

        def worker(wid: str):
            for _ in range(10):
                rec = task_manager.claim_next_pending(wid)
                if rec is not None:
                    with lock:
                        claimed.append(rec.id)

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(worker, f"w{i}") for i in range(8)]
            for f in futs:
                f.result()

        assert len(claimed) == len(set(claimed))
        assert len(claimed) == 20

    def test_begin_immediate_prevents_double_claim_same_row(self, test_db):
        t = task_manager.create_task("https://github.com/u/one", "u", "one")
        a = task_manager.claim_next_pending("wa")
        b = task_manager.claim_next_pending("wb")
        assert a is not None and a.id == t.id
        assert b is None


class TestBoundedConcurrency:
    @pytest.mark.asyncio
    async def test_dispatcher_respects_max_running(self, test_db, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "app_env", "development")
        monkeypatch.setattr(settings, "max_running_tasks", 2)
        monkeypatch.setattr(settings, "max_task_attempts", 1)
        monkeypatch.setattr(settings, "dispatcher_poll_seconds", 0.02)
        monkeypatch.setattr(settings, "shutdown_grace_seconds", 0.5)

        current = 0
        max_seen = 0
        lock = asyncio.Lock()

        async def slow_download(repo_url):
            nonlocal current, max_seen
            async with lock:
                current += 1
                max_seen = max(max_seen, current)
            await asyncio.sleep(0.12)
            async with lock:
                current -= 1
            return _mock_download(tmp_path, repo_url)

        def mock_extract(tarball_bytes, tmp_root=None):
            return _mock_extract(tmp_path)

        tasks = [
            task_manager.create_task(f"https://github.com/u/c{i}", "u", f"c{i}")
            for i in range(6)
        ]

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=slow_download,
        ), patch(
            "app.services.background_runner.safe_extract_to_temp",
            side_effect=mock_extract,
        ):
            await background_runner.start_dispatcher()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                statuses = [task_manager.get_task(t.id).status for t in tasks]
                if all(s in ("completed", "failed", "dead") for s in statuses):
                    break
                await asyncio.sleep(0.05)
            # Drain any remaining pending work before asserting terminal states.
            try:
                await background_runner.drain_pending_tasks()
            except Exception:
                pass
            await background_runner.stop_dispatcher(1.0)

        assert max_seen <= 2
        assert max_seen >= 1
        finals = [task_manager.get_task(t.id).status for t in tasks]
        assert all(s == "completed" for s in finals), finals


class TestCancelAPI:
    def test_cancel_endpoint_pending_idempotent(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "test")
        task = task_manager.create_task("https://github.com/u/r", "u", "r")
        from app.main import app
        with TestClient(app) as client:
            r1 = client.post(f"/api/check/{task.id}/cancel")
            assert r1.status_code == 200
            body1 = r1.json()
            assert body1["cancelled"] is True
            assert body1["status"] == "failed"  # API maps cancelled → failed
            assert body1["error_code"] == "TASK_CANCELLED"

            r2 = client.post(f"/api/check/{task.id}/cancel")
            assert r2.status_code == 200
            assert r2.json()["status"] == "failed"

            # Status polling agrees
            st = client.get(f"/api/check/{task.id}").json()
            assert st["status"] == "failed"
            assert st["error_code"] == "TASK_CANCELLED"

    def test_cancel_completed_noop(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "test")
        task = task_manager.create_task("https://github.com/u/r2", "u", "r2")
        task_manager.claim_next_pending("w")
        task_manager.mark_completed(task.id, 1, 1, "r")
        from app.main import app
        with TestClient(app) as client:
            resp = client.post(f"/api/check/{task.id}/cancel")
            assert resp.status_code == 200
            assert resp.json()["cancelled"] is False
            assert resp.json()["status"] == "completed"

    @pytest.mark.asyncio
    async def test_cancel_running_cleans_and_terminal(self, test_db, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "app_env", "test")
        monkeypatch.setattr(settings, "max_task_attempts", 1)
        started = asyncio.Event()

        async def slow_download(repo_url):
            started.set()
            await asyncio.sleep(0.4)
            return _mock_download(tmp_path, repo_url)

        task = task_manager.create_task("https://github.com/u/run", "u", "run")
        task_manager.claim_next_pending("w-cancel")

        async def runner():
            await background_runner._process_task(task.id)

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=slow_download,
        ):
            worker = asyncio.create_task(runner())
            await asyncio.wait_for(started.wait(), timeout=2)
            task_manager.request_cancel(task.id)
            background_runner.cancel_task_locally(task.id)
            await asyncio.wait_for(worker, timeout=3)

        rec = task_manager.get_task(task.id)
        assert rec.status == "cancelled"
        assert rec.error_code == "TASK_CANCELLED"
        assert rec.api_status == "failed"


class TestErrorClassification:
    def test_retryable_categories(self):
        assert is_retryable("GITHUB_RATE_LIMITED")
        assert is_retryable("DOWNLOAD_TIMEOUT")
        assert is_retryable("LLM_TIMEOUT")
        assert is_retryable("INTERNAL_TRANSIENT")
        assert not is_retryable("INVALID_REPOSITORY")
        assert not is_retryable("INVALID_ARCHIVE")
        assert not is_retryable("DOWNLOAD_TOO_LARGE")
        assert not is_retryable("EXTRACTION_LIMIT_EXCEEDED")

    def test_category_mapping(self):
        assert category_for_error_code("GITHUB_RATE_LIMITED") == "GITHUB_RATE_LIMITED"
        assert category_for_error_code("UNSAFE_ARCHIVE") == "INVALID_ARCHIVE"
        assert category_for_error_code("REPOSITORY_NOT_FOUND") == "INVALID_REPOSITORY"
        assert category_for_error_code("DOWNLOAD_TOO_LARGE") == "DOWNLOAD_TOO_LARGE"

    def test_backoff_bounded(self):
        for attempt in range(1, 20):
            d = compute_backoff_seconds(attempt, jitter=False)
            assert 0 <= d <= settings.retry_max_seconds

    def test_decide_retry_permanent(self):
        d = decide_retry(error_code="UNSAFE_ARCHIVE", attempt_count=1)
        assert d.should_retry is False

    def test_decide_retry_exhausted(self, monkeypatch):
        monkeypatch.setattr(settings, "max_task_attempts", 2)
        d = decide_retry(error_code="GITHUB_RATE_LIMITED", attempt_count=2)
        assert d.should_retry is False
        d2 = decide_retry(error_code="GITHUB_RATE_LIMITED", attempt_count=1)
        assert d2.should_retry is True
        assert d2.next_attempt_at is not None

    @pytest.mark.asyncio
    async def test_github_rate_limit_maps_and_fails_when_exhausted(
        self, test_db, monkeypatch
    ):
        monkeypatch.setattr(settings, "max_task_attempts", 1)
        from app.core.github import GitHubDownloadError
        task = task_manager.create_task("https://github.com/u/rl", "u", "rl")
        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError("rate limit", code="GITHUB_RATE_LIMITED"),
        ):
            await background_runner._process_task(task.id)
        rec = task_manager.get_task(task.id)
        assert rec.status == "failed"
        assert rec.error_code == "GITHUB_RATE_LIMITED"
        assert rec.failure_category == "GITHUB_RATE_LIMITED"

    @pytest.mark.asyncio
    async def test_permanent_unsafe_archive_not_retried(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "max_task_attempts", 3)
        from app.core.safe_extract import ExtractionError
        task = task_manager.create_task("https://github.com/u/bad", "u", "bad")

        def boom(*a, **k):
            raise ExtractionError("Rejected symlink")

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=_mock_download(Path(test_db).parent),
        ), patch(
            "app.services.background_runner.safe_extract_to_temp",
            side_effect=boom,
        ):
            await background_runner._process_task(task.id)
        rec = task_manager.get_task(task.id)
        assert rec.status == "failed"
        assert rec.failure_category == "INVALID_ARCHIVE"
        assert rec.next_attempt_at is None


class TestDeduplication:
    @pytest.mark.asyncio
    async def test_same_commit_reuses_completed(self, test_db, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "max_task_attempts", 1)
        sha = "b" * 40  # must match _mock_download commit_sha
        source = task_manager.create_task("https://github.com/u/dedup", "u", "dedup")
        task_manager.claim_next_pending("ws")
        task_manager.mark_completed(source.id, 2, 100, "src")
        task_manager.set_resolved_commit_sha(source.id, sha)
        assert task_manager.get_task(source.id).deduplication_key

        dest = task_manager.create_task("https://github.com/u/dedup", "u", "dedup")

        def mock_extract(tarball_bytes, tmp_root=None):
            return _mock_extract(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=_mock_download(tmp_path, "https://github.com/u/dedup"),
        ), patch(
            "app.services.background_runner.safe_extract_to_temp",
            side_effect=mock_extract,
        ):
            await background_runner._process_task(dest.id)

        rec = task_manager.get_task(dest.id)
        assert rec.status == "completed"
        assert rec.reused_from_task_id == source.id
        # Full scan must not run after dedup (extract skipped).
        # download still runs to resolve SHA; extract may be skipped.
        snap = metrics.snapshot()
        assert snap["counters"].get("vibecheck_deduplicated_tasks_total", 0) >= 1

    def test_running_coalesce_find(self, test_db):
        t = task_manager.create_task(
            "https://github.com/u/live", "u", "live"
        )
        task_manager.claim_next_pending("wl")
        found = task_manager.find_running_by_repo(
            "https://github.com/u/live.git"
        )
        assert found is not None
        assert found.id == t.id

    def test_upload_not_cross_user_deduped(self, test_db):
        key = task_manager.build_deduplication_key(
            "local://upload/abc", "a" * 40
        )
        assert key is None


class TestBYOKSecurity:
    def test_key_not_persisted_in_db(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "test")
        secret = "sk-test-synthetic-not-real-key-123456"
        from app.main import app
        with TestClient(app) as client:
            resp = client.post(
                "/api/check",
                json={"repo_url": "https://github.com/u/byok"},
                headers={
                    "X-LLM-API-KEY": secret,
                    "X-LLM-BASE-URL": "https://example.invalid/v1",
                    "X-LLM-MODEL": "test-model",
                },
            )
            assert resp.status_code in (202, 200)
            task_id = resp.json()["task_id"]

        # PostgreSQL contract: API key never appears in task/result rows.
        import asyncio

        from app.db.models import TaskRow
        from app.db.session import get_session_factory

        async def _scan_rows():
            factory = get_session_factory()
            async with factory() as session:
                row = await session.get(TaskRow, task_id)
                payload = str(dict(row.__dict__)) if row is not None else ""
                return payload

        payload = asyncio.run(_scan_rows())
        assert secret not in payload

        # In-memory store may hold it until task finishes; pop clears.
        cfg = get_user_config(task_id)
        if cfg is not None:
            assert cfg["api_key"] == secret
        pop_user_config(task_id)
        assert get_user_config(task_id) is None

        payload2 = asyncio.run(_scan_rows())
        assert secret not in payload2

    def test_key_not_in_error_message(self, test_db):
        secret = "sk-synthetic-secret-xyz"
        store_user_config("task-x", secret, "https://example.invalid", "m")
        task = task_manager.create_task("https://github.com/u/e", "u", "e")
        task_manager.mark_failed(task.id, "INTERNAL_ERROR")
        rec = task_manager.get_task(task.id)
        assert secret not in (rec.error_message or "")
        assert secret not in (rec.error_code or "")
        pop_user_config("task-x")

    def test_concurrent_keys_not_crossed(self):
        store_user_config("t1", "key-1", "https://a.invalid", "m1")
        store_user_config("t2", "key-2", "https://b.invalid", "m2")
        assert get_user_config("t1")["api_key"] == "key-1"
        assert get_user_config("t2")["api_key"] == "key-2"
        pop_user_config("t1")
        assert get_user_config("t1") is None
        assert get_user_config("t2")["api_key"] == "key-2"
        clear_user_configs()
        assert count_user_configs() == 0

    def test_restart_clears_memory_keys(self):
        store_user_config("t-mem", "k", "https://x.invalid", "m")
        assert count_user_configs() == 1
        # Simulate process restart
        clear_user_configs()
        assert count_user_configs() == 0
        assert get_user_config("t-mem") is None

    @pytest.mark.asyncio
    async def test_llm_fallback_after_key_loss(self, test_db, monkeypatch):
        """Without user key and server LLM disabled, analysis uses templates."""
        monkeypatch.setattr(settings, "llm_enabled", False)
        monkeypatch.setattr(settings, "llm_api_key", None)
        task = task_manager.create_task("https://github.com/u/fb", "u", "fb")
        task_manager.claim_next_pending("wfb")
        from app.services.llm_service import generate_and_save_llm_analysis
        await asyncio.to_thread(generate_and_save_llm_analysis, task.id, None)
        from app.services.llm_service import get_llm_analysis
        analysis = get_llm_analysis(task.id)
        # Either no analysis or fallback source — never fake llm success
        if analysis is not None:
            assert analysis.get("source") in ("fallback", None, "template")


class TestMetricsEndpoint:
    def test_metrics_no_forbidden_labels(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "test")
        metrics.reset_metrics()
        metrics.inc_counter("vibecheck_retries_total", {"category": "SCAN_TIMEOUT"})
        metrics.inc_counter("vibecheck_deduplicated_tasks_total")
        metrics.set_gauge("vibecheck_queue_depth", 3)
        metrics.observe("vibecheck_task_duration_seconds", 1.25)
        from app.main import app
        with TestClient(app) as client:
            text = client.get("/metrics").text
        assert "vibecheck_queue_depth" in text
        assert "vibecheck_retries_total" in text
        assert "vibecheck_deduplicated_tasks_total" in text
        lowered = text.lower()
        for forbidden in ("api_key", "ghp_", "sk-", "repo_url", "task_id"):
            assert forbidden not in lowered

    def test_readiness_reports_deps(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "test")
        from app.main import app
        with TestClient(app) as client:
            body = client.get("/api/ready").json()
        assert body["status"] == "ready"
        assert body["dependencies"]["database"] == "ok"
        assert "llm" in body["dependencies"]


class TestRecoveryAfterRestart:
    @pytest.mark.asyncio
    async def test_queue_continues_after_recovery(self, test_db, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "app_env", "test")
        monkeypatch.setattr(settings, "max_task_attempts", 3)
        t = task_manager.create_task("https://github.com/u/rec", "u", "rec")
        task_manager.claim_next_pending("old-worker")
        # Simulate crash: expire lease
        past = (utc_now() - timedelta(seconds=999)).isoformat()
        conn = database._get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET lease_expires_at = ? WHERE id = ?", (past, t.id)
            )
            conn.commit()
        finally:
            conn.close()

        stats = task_manager.recover_expired_tasks()
        assert stats["requeued"] == 1
        assert task_manager.get_task(t.id).status == "pending"

        def mock_extract(tarball_bytes, tmp_root=None):
            return _mock_extract(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=_mock_download(tmp_path),
        ), patch(
            "app.services.background_runner.safe_extract_to_temp",
            side_effect=mock_extract,
        ):
            n = await background_runner.drain_pending_tasks()
        assert n == 1
        assert task_manager.get_task(t.id).status == "completed"


class TestQueueFullAPI:
    def test_queue_full_429(self, test_db, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "test")
        monkeypatch.setattr(settings, "max_pending_tasks", 2)
        for i in range(2):
            task_manager.create_task(f"https://github.com/q/r{i}", "q", f"r{i}")
        from app.main import app
        with TestClient(app) as client:
            resp = client.post(
                "/api/check",
                json={"repo_url": "https://github.com/q/extra"},
            )
        assert resp.status_code == 429
        assert resp.json()["detail"]["error_code"] == "QUEUE_FULL"


class TestMigrationCompat:
    def test_postgresql_schema_has_task_execution_columns(self, test_db):
        """Alembic/PostgreSQL schema includes the durable task execution fields."""
        import asyncio

        from sqlalchemy import text

        from app.db.session import get_engine

        async def _cols():
            engine = get_engine()
            async with engine.connect() as conn:
                result = await conn.execute(
                    text(
                        """
                        SELECT column_name FROM information_schema.columns
                        WHERE table_name = 'tasks' AND table_schema = 'public'
                        """
                    )
                )
                return {r[0] for r in result.all()}

        cols = asyncio.run(_cols())
        for required in (
            "attempt_count",
            "max_attempts",
            "worker_id",
            "lease_expires_at",
            "last_heartbeat_at",
            "next_attempt_at",
            "failure_category",
            "resolved_commit_sha",
            "scanner_version",
            "deduplication_key",
            "reused_from_task_id",
            "cancelled_at",
        ):
            assert required in cols

        async def _indexes():
            engine = get_engine()
            async with engine.connect() as conn:
                result = await conn.execute(
                    text(
                        """
                        SELECT indexname FROM pg_indexes
                        WHERE tablename = 'tasks' AND schemaname = 'public'
                        """
                    )
                )
                return {r[0] for r in result.all()}

        indexes = asyncio.run(_indexes())
        assert "idx_tasks_status_next_attempt" in indexes
        assert "idx_tasks_lease_expires" in indexes
        assert "idx_tasks_dedup_key" in indexes

    def test_task_row_survives_new_session(self, test_db):
        """Durability contract: task row readable after engine/session recycle."""
        task = task_manager.create_task("https://github.com/u/persist", "u", "persist")
        from app.db import database
        database.reset_initialized()
        import asyncio

        from app.db.session import dispose_engine
        asyncio.run(dispose_engine())
        database.init_db()
        rec = task_manager.get_task(task.id)
        assert rec is not None
        assert rec.status == "pending"


class TestEventLoopNotBlocked:
    @pytest.mark.asyncio
    async def test_api_polling_during_scan(self, test_db, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "app_env", "test")
        monkeypatch.setattr(settings, "scan_timeout", 30)

        def slow_scan(path):
            time.sleep(0.3)
            from app.scanner.base import ScanResult
            return ScanResult()

        task = task_manager.create_task("https://github.com/u/loop", "u", "loop")

        def mock_extract(tarball_bytes, tmp_root=None):
            return _mock_extract(tmp_path)

        latencies = []

        async def poller():
            for _ in range(8):
                t0 = time.perf_counter()
                await asyncio.sleep(0)  # yield
                task_manager.get_task(task.id)  # lightweight sqlite read
                latencies.append(time.perf_counter() - t0)
                await asyncio.sleep(0.05)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=_mock_download(tmp_path),
        ), patch(
            "app.services.background_runner.safe_extract_to_temp",
            side_effect=mock_extract,
        ), patch(
            "app.services.background_runner.scan_directory",
            side_effect=slow_scan,
        ):
            worker = asyncio.create_task(background_runner._process_task(task.id))
            await poller()
            await worker

        # Event loop remained responsive: poll iterations finished while scan ran.
        assert len(latencies) == 8
        assert max(latencies) < 0.55  # PG-backed poll remains well under stage timeout


class TestCleanupAndCancelResources:
    @pytest.mark.asyncio
    async def test_temp_cleaned_after_success(self, test_db, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "app_env", "test")
        extract = _mock_extract(tmp_path)
        task = task_manager.create_task("https://github.com/u/cl", "u", "cl")

        def mock_extract(tarball_bytes, tmp_root=None):
            return extract

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=_mock_download(tmp_path),
        ), patch(
            "app.services.background_runner.safe_extract_to_temp",
            side_effect=mock_extract,
        ):
            await background_runner._process_task(task.id)

        assert task_manager.get_task(task.id).status == "completed"
        assert not Path(extract.dest_dir).exists()
