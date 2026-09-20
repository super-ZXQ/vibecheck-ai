"""Task manager facade — async PostgreSQL repositories + sync test compatibility.

Public async APIs are preferred (FastAPI routes). Sync wrappers remain for
existing tests that call task_manager.create_task() without await.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from dataclasses import dataclass
from typing import Any, Coroutine, TypeVar

from app.core.config import settings
from app.core.error_codes import get_error_message
from app.db.repositories import results as result_repo
from app.db.repositories import tasks as task_repo
from app.db.repositories.tasks import (
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_DEAD,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STAGE_QUEUED,
    TERMINAL_STATUSES,
    QueueCapacityError,
    TaskRecord,
    admit_repo_task,
    admit_upload_task,
    build_deduplication_key,
    claim_next_pending,
    count_tasks_by_status,
    fail_or_retry,
    find_completed_by_repo_sha,
    find_running_by_repo,
    get_pending_count,
    get_running_count,
    get_task,
    has_claimable_pending,
    is_cancel_requested,
    make_worker_id,
    mark_cancelled,
    mark_completed,
    mark_dead,
    mark_failed,
    mark_running,
    normalize_repo_url,
    recover_expired_tasks,
    request_cancel,
    set_resolved_commit_sha,
    touch_heartbeat,
    utc_now,
)
from app.db.repositories.tasks import IllegalStateTransitionError  # noqa: F401
from app.db.repositories.tasks import _validate_transition  # noqa: F401
from app.core.scanner_version import SCANNER_VERSION  # noqa: F401 — re-export
from app.db.session import get_session_factory
from app.services import metrics as metrics_mod
from app.services.task_errors import category_for_error_code

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def admit_repo_task_async(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    scanner_version: str | None = None,
    max_attempts: int | None = None,
) -> tuple[TaskRecord, bool]:
    """Async admission wrapper for API routes."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            task, created = await task_repo.admit_repo_task(
                session,
                repo_url,
                owner,
                repo_name,
                scanner_version=scanner_version,
                max_attempts=max_attempts,
            )
            await session.commit()
            return task, created
        except QueueCapacityError:
            await session.rollback()
            raise


def admit_repo_task(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    scanner_version: str | None = None,
    max_attempts: int | None = None,
) -> tuple[TaskRecord, bool]:
    """Sync facade for tests/scripts."""
    return _run_sync(
        admit_repo_task_async(
            repo_url,
            owner,
            repo_name,
            scanner_version=scanner_version,
            max_attempts=max_attempts,
        )
    )


async def admit_upload_task_async(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    max_attempts: int | None = None,
) -> TaskRecord:
    factory = get_session_factory()
    async with factory() as session:
        try:
            task = await task_repo.admit_upload_task(
                session, repo_url, owner, repo_name, max_attempts=max_attempts
            )
            await session.commit()
            return task
        except QueueCapacityError:
            await session.rollback()
            raise


def admit_upload_task(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    max_attempts: int | None = None,
) -> TaskRecord:
    return _run_sync(
        admit_upload_task_async(
            repo_url, owner, repo_name, max_attempts=max_attempts
        )
    )

# Stage constants preserved from the SQLite-era behavior contract.
STAGE_ANALYZING = "analyzing"
STAGE_ASSESSING = "assessing"
STAGE_DOWNLOADING = "downloading"
STAGE_EXTRACTING = "extracting"
STAGE_REPAIRING = "repairing"
STAGE_SCANNING = "scanning"
STAGE_FINISHED = "finished"

# Re-export constants used across the codebase.
__all__ = [
    "QueueCapacityError",
    "TaskRecord",
    "STATUS_PENDING",
    "STATUS_RUNNING",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_CANCELLED",
    "STATUS_DEAD",
    "STAGE_QUEUED",
    "TERMINAL_STATUSES",
    "create_task",
    "create_task_async",
    "admit_repo_task",
    "admit_upload_task",
    "claim_next_pending",
    "get_task",
    "get_pending_count",
    "is_queue_full",
    "is_queue_full_async",
    "mark_running",
    "mark_completed",
    "mark_failed",
    "mark_cancelled",
    "fail_or_retry",
    "recover_expired_tasks",
    "request_cancel",
    "touch_heartbeat",
    "build_deduplication_key",
    "make_worker_id",
    "utc_now",
]


def _run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Run a coroutine from sync test code without nested-loop errors."""

    async def _wrapped() -> T:
        factory = get_session_factory()
        async with factory() as session:
            # Coroutines in this module are repository calls expecting a session
            # OR higher-level helpers that open their own session.
            return await coro  # type: ignore[misc]

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]
    # Already inside an event loop: run in a worker thread with its own loop.
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


# --- Async primary APIs ---


async def create_task_async(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    scanner_version: str | None = None,
    max_attempts: int | None = None,
) -> TaskRecord:
    import uuid as _uuid

    from app.db.models import TaskRow
    from app.db.repositories.tasks import utc_now as _now

    factory = get_session_factory()
    async with factory() as session:
        now = _now()
        version = scanner_version or SCANNER_VERSION
        row = TaskRow(
            id=str(_uuid.uuid4()),
            repo_url=repo_url,
            owner=owner,
            repo_name=repo_name,
            status=STATUS_PENDING,
            stage=STAGE_QUEUED,
            progress=0,
            created_at=now,
            updated_at=now,
            attempt_count=0,
            max_attempts=max_attempts or settings.max_task_attempts,
            scanner_version=version,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        try:
            from app.services.cleanup_service import maybe_trigger_cleanup
            maybe_trigger_cleanup()
        except Exception:
            pass
        return TaskRecord.from_row(row)


async def get_task_async(task_id: str) -> TaskRecord | None:
    return await _with_session(task_repo.get_task, task_id)


async def claim_next_pending_async(worker_id: str) -> TaskRecord | None:
    return await _with_session(task_repo.claim_next_pending, worker_id)


async def mark_running_async(
    task_id: str, stage: str, progress: int, *, worker_id: str | None = None
) -> bool:
    return await _with_session(
        task_repo.mark_running, task_id, stage, progress, worker_id=worker_id
    )


async def mark_completed_async(
    task_id: str,
    file_count: int,
    total_size: int,
    top_level_dir: str,
    *,
    reused_from_task_id: str | None = None,
    worker_id: str | None = None,
) -> bool:
    return await _with_session(
        task_repo.mark_completed,
        task_id,
        file_count,
        total_size,
        top_level_dir,
        reused_from_task_id=reused_from_task_id,
        worker_id=worker_id,
    )


async def mark_failed_async(
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> bool:
    return await _with_session(
        task_repo.mark_failed,
        task_id,
        error_code,
        error_message,
        failure_category=failure_category,
        worker_id=worker_id,
    )


async def fail_or_retry_async(
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> str:
    return await _with_session(
        task_repo.fail_or_retry,
        task_id,
        error_code,
        error_message,
        failure_category=failure_category,
        worker_id=worker_id,
    )


async def recover_expired_tasks_async() -> dict[str, int]:
    return await _with_session(task_repo.recover_expired_tasks)


async def request_cancel_async(task_id: str) -> str:
    return await _with_session(task_repo.request_cancel, task_id)


async def touch_heartbeat_async(task_id: str, worker_id: str | None = None) -> bool:
    return await _with_session(task_repo.touch_heartbeat, task_id, worker_id)


async def complete_as_reused_async(
    new_task_id: str, source_task: TaskRecord
) -> bool:
    factory = get_session_factory()
    async with factory() as session:
        await result_repo.copy_task_results(session, source_task.id, new_task_id)
        await task_repo.mark_completed(
            session,
            new_task_id,
            file_count=source_task.file_count or 0,
            total_size=source_task.total_size or 0,
            top_level_dir=source_task.top_level_dir or "reused",
            reused_from_task_id=source_task.id,
            worker_id=None,
        )
        await session.commit()
    metrics_mod.inc_counter("vibecheck_deduplicated_tasks_total")
    return True


async def is_queue_full_async() -> bool:
    return await _with_session(task_repo.get_pending_count) >= settings.max_pending_tasks


async def refresh_queue_metrics_async() -> None:
    factory = get_session_factory()
    async with factory() as session:
        pending = await task_repo.get_pending_count(session)
        running = await task_repo.get_running_count(session)
    metrics_mod.set_gauge("vibecheck_queue_depth", float(pending))
    metrics_mod.set_gauge("vibecheck_active_tasks", float(running))


# --- Sync compatibility wrappers (existing tests / simple scripts) ---


def create_task(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    scanner_version: str | None = None,
    max_attempts: int | None = None,
) -> TaskRecord:
    return _run_sync(
        create_task_async(
            repo_url,
            owner,
            repo_name,
            scanner_version=scanner_version,
            max_attempts=max_attempts,
        )
    )


def get_task(task_id: str) -> TaskRecord | None:
    return _run_sync(get_task_async(task_id))


def claim_next_pending(worker_id: str) -> TaskRecord | None:
    return _run_sync(claim_next_pending_async(worker_id))


def get_pending_count() -> int:
    return _run_sync(_with_session(task_repo.get_pending_count))


def get_running_count() -> int:
    return _run_sync(_with_session(task_repo.get_running_count))


def is_queue_full() -> bool:
    return get_pending_count() >= settings.max_pending_tasks


def mark_running(
    task_id: str, stage: str, progress: int, *, worker_id: str | None = None
) -> bool:
    return _run_sync(mark_running_async(task_id, stage, progress, worker_id=worker_id))


def mark_completed(
    task_id: str,
    file_count: int,
    total_size: int,
    top_level_dir: str,
    *,
    reused_from_task_id: str | None = None,
    worker_id: str | None = None,
) -> bool:
    return _run_sync(
        mark_completed_async(
            task_id,
            file_count,
            total_size,
            top_level_dir,
            reused_from_task_id=reused_from_task_id,
            worker_id=worker_id,
        )
    )


def mark_failed(
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> bool:
    return _run_sync(
        mark_failed_async(
            task_id,
            error_code,
            error_message,
            failure_category=failure_category,
            worker_id=worker_id,
        )
    )


def mark_cancelled(task_id: str) -> bool:
    return _run_sync(_with_session(task_repo.mark_cancelled, task_id))


def mark_dead(
    task_id: str,
    error_code: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> bool:
    return _run_sync(
        _with_session(
            task_repo.mark_dead,
            task_id,
            error_code,
            failure_category=failure_category,
            worker_id=worker_id,
        )
    )


def fail_or_retry(
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> str:
    return _run_sync(
        fail_or_retry_async(
            task_id,
            error_code,
            error_message,
            failure_category=failure_category,
            worker_id=worker_id,
        )
    )


def recover_expired_tasks() -> dict[str, int]:
    return _run_sync(recover_expired_tasks_async())


def request_cancel(task_id: str) -> str:
    return _run_sync(request_cancel_async(task_id))


def touch_heartbeat(task_id: str, worker_id: str | None = None) -> bool:
    return _run_sync(touch_heartbeat_async(task_id, worker_id))


def is_cancel_requested(task_id: str) -> bool:
    return _run_sync(_with_session(task_repo.is_cancel_requested, task_id))


def has_claimable_pending() -> bool:
    return _run_sync(_with_session(task_repo.has_claimable_pending))


def find_running_by_repo(repo_url: str, scanner_version: str | None = None):
    return _run_sync(
        _with_session(task_repo.find_running_by_repo, repo_url, scanner_version)
    )


def find_completed_by_repo_sha(
    repo_url: str, commit_sha: str | None, scanner_version: str | None = None
):
    return _run_sync(
        _with_session(
            task_repo.find_completed_by_repo_sha,
            repo_url,
            commit_sha,
            scanner_version,
        )
    )


def find_completed_by_dedup_key(dedup_key: str):
    return _run_sync(_with_session(task_repo.find_completed_by_dedup_key, dedup_key))


def set_resolved_commit_sha(task_id: str, commit_sha: str | None) -> None:
    _run_sync(_with_session(task_repo.set_resolved_commit_sha, task_id, commit_sha))


def complete_as_reused(new_task_id: str, source_task: TaskRecord) -> bool:
    return _run_sync(complete_as_reused_async(new_task_id, source_task))


def refresh_queue_metrics() -> None:
    _run_sync(refresh_queue_metrics_async())


def count_tasks_by_status() -> dict[str, int]:
    return _run_sync(_with_session(task_repo.count_tasks_by_status))


def get_task_status_counts() -> dict[str, int]:
    return count_tasks_by_status()


def reset_runner_state() -> None:
    """Compatibility no-op for older tests that reset SQLite runner globals."""
    return None


def mark_stale_tasks_as_failed() -> int:
    stats = recover_expired_tasks()
    return int(stats.get("requeued", 0) + stats.get("dead", 0))


@dataclass
class TaskSummary:
    file_count: int
    total_size: int
    top_level_dir: str


# Keep error message helper available via task_manager for older tests.
_ = get_error_message
