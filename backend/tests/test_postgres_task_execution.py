"""PostgreSQL task-execution tests: SKIP LOCKED claim, lease, cancel, dedup."""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest

from app.core.config import settings
from app.db.repositories import tasks as task_repo
from app.db.session import get_session_factory
from app.services import task_manager
from app.services.task_manager import utc_now


async def _session():
    factory = get_session_factory()
    return factory()


async def _reset_tasks() -> None:
    """Truncate task-related tables so tests do not share leftover rows."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from app.db.session import get_engine

    engine = get_engine()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await session.execute(
            text(
                "TRUNCATE TABLE llm_analysis_results, repair_results, "
                "assessment_results, scan_results, tasks CASCADE"
            )
        )
        await session.commit()


async def _claim_id(task_id: str, token: str) -> object | None:
    for _ in range(30):
        rec = await task_manager.claim_next_pending_async(token)
        if rec is None:
            return None
        if rec.id == task_id:
            return rec
    return None


@pytest.mark.asyncio
async def test_concurrent_claim_unique(monkeypatch):
    monkeypatch.setattr(settings, "max_pending_tasks", 50)
    monkeypatch.setattr(settings, "app_env", "test")
    # Isolate: only claim tasks created in this test.
    created_ids = set()
    for i in range(20):
        t = await task_manager.create_task_async(
            f"https://github.com/u/pg-{uuid.uuid4().hex[:8]}", "u", f"pg{i}"
        )
        created_ids.add(t.id)

    claimed: list[str] = []
    lock = asyncio.Lock()

    async def worker(wid: str):
        for _ in range(30):
            rec = await task_manager.claim_next_pending_async(wid)
            if rec is not None and rec.id in created_ids:
                async with lock:
                    claimed.append(rec.id)

    await asyncio.gather(*[worker(f"w{i}") for i in range(8)])
    assert len(claimed) == len(set(claimed))
    assert set(claimed) == created_ids


@pytest.mark.asyncio
async def test_two_workers_do_not_share_same_task(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "test")
    t = await task_manager.create_task_async("https://github.com/u/one", "u", "one")
    a = await task_manager.claim_next_pending_async("tok-a")
    b = await task_manager.claim_next_pending_async("tok-b")
    assert a is not None and a.id == t.id
    assert b is None or b.id != t.id


@pytest.mark.asyncio
async def test_lease_recovery_and_fencing(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "max_task_attempts", 3)
    await _reset_tasks()
    t = await task_manager.create_task_async("https://github.com/u/lease", "u", "lease")
    claimed = await _claim_id(t.id, "tok-live")
    assert claimed is not None

    # Expire lease directly
    factory = get_session_factory()
    async with factory() as session:
        row = await session.get(task_repo.TaskRow, t.id)
        row.lease_expires_at = utc_now() - timedelta(seconds=300)
        await session.commit()

    stats = await task_manager.recover_expired_tasks_async()
    assert stats["requeued"] >= 1
    rec = await task_manager.get_task_async(t.id)
    assert rec.status == "pending"

    new = await _claim_id(t.id, "tok-new")
    assert new is not None
    # Stale token cannot complete
    ok_stale = await task_manager.mark_completed_async(
        t.id, 1, 1, "x", worker_id="tok-live"
    )
    assert ok_stale is False
    ok_new = await task_manager.mark_completed_async(
        t.id, 1, 1, "x", worker_id="tok-new"
    )
    assert ok_new is True


@pytest.mark.asyncio
async def test_heartbeat_requires_owner(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "development")
    await _reset_tasks()
    t = await task_manager.create_task_async("https://github.com/u/hb", "u", "hb")
    await _claim_id(t.id, "tok-hb")
    assert await task_manager.touch_heartbeat_async(t.id, "tok-stale") is False
    assert await task_manager.touch_heartbeat_async(t.id, "tok-hb") is True


@pytest.mark.asyncio
async def test_cancel_idempotent_and_race(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "test")
    t = await task_manager.create_task_async("https://github.com/u/cxl", "u", "cxl")
    await task_manager.claim_next_pending_async("tok-c")
    status = await task_manager.request_cancel_async(t.id)
    assert status in ("running", "cancelled")
    # complete must not overwrite cancel flag
    ok = await task_manager.mark_completed_async(t.id, 1, 1, "x", worker_id="tok-c")
    if status == "running":
        assert ok is False
        task_manager.mark_cancelled(t.id)
    rec = await task_manager.get_task_async(t.id)
    assert rec.status == "cancelled"
    # idempotent
    status2 = await task_manager.request_cancel_async(t.id)
    assert status2 == "cancelled"


@pytest.mark.asyncio
async def test_queue_full_429_semantics(monkeypatch):
    monkeypatch.setattr(settings, "max_pending_tasks", 2)
    factory = get_session_factory()
    for i in range(2):
        async with factory() as session:
            await task_repo.admit_upload_task(
                session, f"local://upload/{i}", "local", "up"
            )
            await session.commit()
    async with factory() as session:
        with pytest.raises(task_repo.QueueCapacityError):
            await task_repo.admit_upload_task(
                session, "local://upload/overflow", "local", "up"
            )
            await session.commit()


@pytest.mark.asyncio
async def test_dedup_key_and_completed_reuse(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "test")
    sha = "b" * 40
    source = await task_manager.create_task_async(
        "https://github.com/u/dedup", "u", "dedup"
    )
    await task_manager.claim_next_pending_async("ws")
    await task_manager.mark_completed_async(source.id, 2, 100, "src")
    await task_manager._with_session(
        task_repo.set_resolved_commit_sha, source.id, sha
    )
    found = task_manager.find_completed_by_repo_sha(
        "https://github.com/u/dedup", sha
    )
    assert found is not None and found.id == source.id
    dest = await task_manager.create_task_async(
        "https://github.com/u/dedup", "u", "dedup"
    )
    ok = await task_manager.complete_as_reused_async(dest.id, found)
    assert ok
    rec = await task_manager.get_task_async(dest.id)
    assert rec.status == "completed"
    assert rec.reused_from_task_id == source.id


@pytest.mark.asyncio
async def test_permanent_error_no_retry(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "max_task_attempts", 3)
    t = await task_manager.create_task_async("https://github.com/u/bad", "u", "bad")
    await task_manager.claim_next_pending_async("wb")
    status = await task_manager.fail_or_retry_async(
        t.id, "UNSAFE_ARCHIVE", failure_category="INVALID_ARCHIVE"
    )
    assert status == "failed"


@pytest.mark.asyncio
async def test_retry_respects_max_attempts(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "max_task_attempts", 2)
    monkeypatch.setattr(settings, "retry_base_seconds", 0)
    monkeypatch.setattr(settings, "retry_max_seconds", 0)
    t = await task_manager.create_task_async(
        f"https://github.com/u/rty-{uuid.uuid4().hex[:8]}", "u", "rty", max_attempts=2
    )
    await task_manager.claim_next_pending_async("wr1")
    s1 = await task_manager.fail_or_retry_async(
        t.id, "DOWNLOAD_FAILED", failure_category="GITHUB_TEMPORARY_ERROR"
    )
    assert s1 == "pending"
    factory = get_session_factory()
    async with factory() as session:
        row = await session.get(task_repo.TaskRow, t.id)
        row.next_attempt_at = None
        await session.commit()
    claimed2 = await task_manager.claim_next_pending_async("wr2")
    assert claimed2 is not None and claimed2.id == t.id
    s2 = await task_manager.fail_or_retry_async(
        t.id, "DOWNLOAD_FAILED", failure_category="GITHUB_TEMPORARY_ERROR"
    )
    assert s2 == "failed"


@pytest.mark.asyncio
async def test_admission_coalesce_same_repo(monkeypatch):
    monkeypatch.setattr(settings, "max_pending_tasks", 20)
    repo = f"https://github.com/u/same-{uuid.uuid4().hex[:8]}"
    factory = get_session_factory()
    async with factory() as session:
        a, created_a = await task_repo.admit_repo_task(session, repo, "u", "same")
        await session.commit()
    async with factory() as session:
        b, created_b = await task_repo.admit_repo_task(session, repo, "u", "same")
        await session.commit()
    assert created_a is True
    assert created_b is False
    assert a.id == b.id


@pytest.mark.asyncio
async def test_byok_not_in_task_row(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "test")
    secret = "sk-test-synthetic-not-real"
    from app.services.llm_user_config import pop_user_config, store_user_config

    t = await task_manager.create_task_async("https://github.com/u/byok", "u", "byok")
    store_user_config(t.id, secret, "https://example.invalid/v1", "m")
    factory = get_session_factory()
    async with factory() as session:
        row = await session.get(task_repo.TaskRow, t.id)
        payload = str(row.__dict__)
        assert secret not in payload
    pop_user_config(t.id)


@pytest.mark.asyncio
async def test_schema_has_required_tables():
    from sqlalchemy import text
    from app.db.session import get_engine

    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                """
                SELECT table_name FROM information_schema.tables
                WHERE table_schema='public'
                """
            )
        )
        names = {r[0] for r in result.all()}
    if engine.dialect.name == "postgresql":
        for required in (
            "tasks",
            "scan_results",
            "assessment_results",
            "repair_results",
            "llm_analysis_results",
        ):
            assert required in names
