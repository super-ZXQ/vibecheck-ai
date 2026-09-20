"""Task repository — PostgreSQL atomic claim, lease, recovery, admission.

Claim semantics (behavior contract preserved from SQLite era):
- Queue order: next_attempt_at (nulls first / due) then created_at ASC
- Atomic claim uses SELECT ... FOR UPDATE SKIP LOCKED (PostgreSQL)
- Lease + heartbeat require worker_id ownership
- Terminal statuses never return to running via unconditional UPDATE
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.error_codes import DEAD_TASK, TASK_CANCELLED, get_error_message
from app.core.scanner_version import SCANNER_VERSION
from app.db.models import TaskRow
from app.services import metrics as metrics_mod
from app.services.task_errors import category_for_error_code, decide_retry

logger = logging.getLogger(__name__)

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_DEAD = "dead"
STAGE_QUEUED = "queued"
STAGE_FINISHED = "finished"

TERMINAL_STATUSES = frozenset(
    {STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD}
)
_API_FAILED_STATUSES = frozenset({STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD})


class QueueCapacityError(Exception):
    """Atomic admission found the pending queue full."""


class IllegalStateTransitionError(Exception):
    """Internal: illegal task status transition."""


def _validate_transition(task_id: str, current_status: str, new_status: str) -> None:
    """Compatibility helper used by legacy tests / callers."""
    legal = {
        STATUS_PENDING: {STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD},
        STATUS_RUNNING: {STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD, STATUS_PENDING},
        STATUS_COMPLETED: set(),
        STATUS_FAILED: set(),
        STATUS_CANCELLED: set(),
        STATUS_DEAD: set(),
    }
    allowed = legal.get(current_status, set())
    if new_status not in allowed:
        raise IllegalStateTransitionError(
            f"Illegal transition for task {task_id}: {current_status} -> {new_status}"
        )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_plus_seconds(seconds: float) -> datetime:
    return utc_now() + timedelta(seconds=seconds)


def make_worker_id(prefix: str = "w") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def normalize_repo_url(repo_url: str) -> str:
    url = (repo_url or "").strip().rstrip("/")
    url = url.removesuffix(".git")
    return url.lower()


def build_deduplication_key(
    repo_url: str,
    resolved_commit_sha: str | None,
    scanner_version: str | None = None,
) -> str | None:
    if not repo_url or not resolved_commit_sha:
        return None
    if repo_url.startswith(("upload://", "local://upload/", "local://")):
        return None
    version = scanner_version or SCANNER_VERSION
    sha = resolved_commit_sha.strip().lower()
    if not sha:
        return None
    return f"{normalize_repo_url(repo_url)}|{sha}|{version}"


@dataclass
class TaskRecord:
    id: str
    repo_url: str
    owner: str
    repo_name: str
    status: str
    stage: str
    progress: int
    error_code: str | None
    error_message: str | None
    file_count: int | None
    total_size: int | None
    top_level_dir: str | None
    created_at: datetime | str
    updated_at: datetime | str
    completed_at: datetime | str | None
    attempt_count: int = 0
    max_attempts: int = 3
    worker_id: str | None = None
    lease_expires_at: datetime | str | None = None
    last_heartbeat_at: datetime | str | None = None
    next_attempt_at: datetime | str | None = None
    failure_category: str | None = None
    resolved_commit_sha: str | None = None
    scanner_version: str | None = None
    deduplication_key: str | None = None
    reused_from_task_id: str | None = None
    cancelled_at: datetime | str | None = None

    @classmethod
    def from_row(cls, row: TaskRow) -> "TaskRecord":
        return cls(
            id=row.id,
            repo_url=row.repo_url,
            owner=row.owner,
            repo_name=row.repo_name,
            status=row.status,
            stage=row.stage,
            progress=int(row.progress or 0),
            error_code=row.error_code,
            error_message=row.error_message,
            file_count=row.file_count,
            total_size=row.total_size,
            top_level_dir=row.top_level_dir,
            created_at=row.created_at,
            updated_at=row.updated_at,
            completed_at=row.completed_at,
            attempt_count=int(row.attempt_count or 0),
            max_attempts=int(row.max_attempts or settings.max_task_attempts),
            worker_id=row.worker_id,
            lease_expires_at=row.lease_expires_at,
            last_heartbeat_at=row.last_heartbeat_at,
            next_attempt_at=row.next_attempt_at,
            failure_category=row.failure_category,
            resolved_commit_sha=row.resolved_commit_sha,
            scanner_version=row.scanner_version,
            deduplication_key=row.deduplication_key,
            reused_from_task_id=row.reused_from_task_id,
            cancelled_at=row.cancelled_at,
        )

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def api_status(self) -> str:
        if self.status in _API_FAILED_STATUSES:
            return STATUS_FAILED
        return self.status

    @property
    def is_cancel_requested(self) -> bool:
        return self.cancelled_at is not None or self.status == STATUS_CANCELLED

    def to_response(self) -> dict:
        resp = {
            "task_id": self.id,
            "status": self.api_status,
            "stage": self.stage,
            "progress": self.progress,
            "owner": self.owner,
            "repo_name": self.repo_name,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "deduplicated": self.reused_from_task_id is not None,
        }
        if self.reused_from_task_id:
            resp["reused_from_task_id"] = self.reused_from_task_id
        if self.api_status == STATUS_FAILED:
            resp["attempt_count"] = self.attempt_count
            resp["failure_category"] = self.failure_category
            if self.status == STATUS_CANCELLED:
                resp["error_code"] = self.error_code or TASK_CANCELLED
                resp["error_message"] = (
                    self.error_message or get_error_message(TASK_CANCELLED)
                )
            if self.status == STATUS_DEAD and not self.error_code:
                resp["error_code"] = DEAD_TASK
                resp["error_message"] = get_error_message(DEAD_TASK)

        if self.api_status == STATUS_COMPLETED:
            from app.services.result_repository import load_status_enrichment

            enrichment = load_status_enrichment_sync(self.id)
            resp.update(enrichment)
        return resp


def load_status_enrichment_sync(task_id: str) -> dict:
    import concurrent.futures

    async def _load():
        from app.db.repositories.results import load_status_enrichment
        return await load_status_enrichment(task_id)

    try:
        import asyncio
        asyncio.get_running_loop()
    except RuntimeError:
        import asyncio
        return asyncio.run(_load())
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: __import__("asyncio").run(_load())).result()


def _claimable_filter(now: datetime):
    return and_(
        TaskRow.status == STATUS_PENDING,
        TaskRow.cancelled_at.is_(None),
        or_(TaskRow.next_attempt_at.is_(None), TaskRow.next_attempt_at <= now),
    )


async def admit_repo_task(
    session: AsyncSession,
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    scanner_version: str | None = None,
    max_attempts: int | None = None,
) -> tuple[TaskRecord, bool]:
    """Atomic coalesce-or-create for public repository tasks."""
    version = scanner_version or SCANNER_VERSION
    normalized = normalize_repo_url(repo_url)
    now = utc_now()

    # Coalesce key for active GitHub tasks before commit SHA is known.
    coalesce_key = f"{normalized}|active|{version}"
    result = await session.execute(
        select(TaskRow).where(
            TaskRow.deduplication_key == coalesce_key,
            TaskRow.status.in_((STATUS_PENDING, STATUS_RUNNING)),
        )
    )
    existing = result.scalars().first()
    if existing is not None:
        return TaskRecord.from_row(existing), False
    # Fallback: URL normalize match among active tasks
    result = await session.execute(
        select(TaskRow).where(
            TaskRow.status.in_((STATUS_PENDING, STATUS_RUNNING)),
            TaskRow.scanner_version == version,
        )
    )
    for row in result.scalars():
        if normalize_repo_url(row.repo_url) == normalized:
            return TaskRecord.from_row(row), False

    # Serialize admission count+insert (PostgreSQL transaction advisory lock).
    try:
        from sqlalchemy import text as _text
        await session.execute(_text("SELECT pg_advisory_xact_lock(747123)"))
    except Exception:
        pass
    pending = await session.execute(
        select(func.count()).select_from(TaskRow).where(TaskRow.status == STATUS_PENDING)
    )
    count = int(pending.scalar_one() or 0)
    if count >= settings.max_pending_tasks:
        raise QueueCapacityError("pending task queue is full")

    task_id = str(uuid.uuid4())
    row = TaskRow(
        id=task_id,
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
        deduplication_key=coalesce_key,
    )
    try:
        session.add(row)
        await session.flush()
    except Exception:
        await session.rollback()
        # Concurrent admit won the unique partial index race — return winner.
        result = await session.execute(
            select(TaskRow).where(
                TaskRow.deduplication_key == coalesce_key,
                TaskRow.status.in_((STATUS_PENDING, STATUS_RUNNING)),
            )
        )
        existing = result.scalars().first()
        if existing is not None:
            return TaskRecord.from_row(existing), False
        raise
    return TaskRecord.from_row(row), True


async def admit_upload_task(
    session: AsyncSession,
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    max_attempts: int | None = None,
) -> TaskRecord:
    now = utc_now()
    try:
        from sqlalchemy import text as _text
        await session.execute(_text("SELECT pg_advisory_xact_lock(747123)"))
    except Exception:
        pass
    pending = await session.execute(
        select(func.count()).select_from(TaskRow).where(TaskRow.status == STATUS_PENDING)
    )
    if int(pending.scalar_one() or 0) >= settings.max_pending_tasks:
        raise QueueCapacityError("pending task queue is full")
    row = TaskRow(
        id=str(uuid.uuid4()),
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
        scanner_version=SCANNER_VERSION,
    )
    session.add(row)
    await session.flush()
    return TaskRecord.from_row(row)


async def get_task(session: AsyncSession, task_id: str) -> TaskRecord | None:
    row = await session.get(TaskRow, task_id)
    return TaskRecord.from_row(row) if row else None


async def get_pending_count(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count()).select_from(TaskRow).where(TaskRow.status == STATUS_PENDING)
    )
    return int(result.scalar_one() or 0)


async def get_running_count(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count()).select_from(TaskRow).where(TaskRow.status == STATUS_RUNNING)
    )
    return int(result.scalar_one() or 0)


async def has_claimable_pending(session: AsyncSession) -> bool:
    now = utc_now()
    result = await session.execute(
        select(TaskRow.id).where(_claimable_filter(now)).limit(1)
    )
    return result.first() is not None


async def claim_next_pending(session: AsyncSession, worker_id: str) -> TaskRecord | None:
    """Atomic claim: SELECT ... FOR UPDATE SKIP LOCKED then UPDATE running."""
    now = utc_now()
    lease_expires = _iso_plus_seconds(settings.task_lease_seconds)

    dialect = session.bind.dialect.name if session.bind is not None else ""
    stmt = (
        select(TaskRow)
        .where(_claimable_filter(now))
        .order_by(TaskRow.next_attempt_at.asc().nulls_first(), TaskRow.created_at.asc())
        .limit(1)
    )
    if dialect == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    else:
        stmt = stmt.with_for_update()

    result = await session.execute(stmt)
    row = result.scalars().first()
    if row is None:
        return None

    # Guarded UPDATE — still correct under concurrent recovery.
    upd = await session.execute(
        update(TaskRow)
        .where(TaskRow.id == row.id, TaskRow.status == STATUS_PENDING)
        .values(
            status=STATUS_RUNNING,
            worker_id=worker_id,
            lease_expires_at=lease_expires,
            last_heartbeat_at=now,
            attempt_count=int(row.attempt_count or 0) + 1,
            next_attempt_at=None,
            updated_at=now,
        )
    )
    if upd.rowcount != 1:
        return None
    await session.flush()
    metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_RUNNING})
    refreshed = await session.get(TaskRow, row.id)
    return TaskRecord.from_row(refreshed) if refreshed else None


async def touch_heartbeat(
    session: AsyncSession, task_id: str, worker_id: str | None
) -> bool:
    now = utc_now()
    lease_expires = _iso_plus_seconds(settings.task_lease_seconds)
    if worker_id is None:
        if settings.app_env != "test":
            return False
        conditions = [
            TaskRow.id == task_id,
            TaskRow.status == STATUS_RUNNING,
            TaskRow.cancelled_at.is_(None),
        ]
    else:
        conditions = [
            TaskRow.id == task_id,
            TaskRow.status == STATUS_RUNNING,
            TaskRow.worker_id == worker_id,
            TaskRow.cancelled_at.is_(None),
        ]
    result = await session.execute(
        update(TaskRow)
        .where(*conditions)
        .values(last_heartbeat_at=now, lease_expires_at=lease_expires, updated_at=now)
    )
    return result.rowcount == 1


async def mark_running(
    session: AsyncSession,
    task_id: str,
    stage: str,
    progress: int,
    *,
    worker_id: str | None = None,
) -> bool:
    now = utc_now()
    row = await session.get(TaskRow, task_id)
    if row is None or row.cancelled_at is not None:
        return False
    if row.status in TERMINAL_STATUSES:
        return False
    if worker_id is not None and row.worker_id != worker_id:
        return False
    conditions = [
        TaskRow.id == task_id,
        TaskRow.status == row.status,
        TaskRow.cancelled_at.is_(None),
    ]
    if worker_id is not None:
        conditions.append(TaskRow.worker_id == worker_id)
    result = await session.execute(
        update(TaskRow)
        .where(*conditions)
        .values(status=STATUS_RUNNING, stage=stage, progress=progress, updated_at=now)
    )
    return result.rowcount == 1


async def mark_completed(
    session: AsyncSession,
    task_id: str,
    file_count: int,
    total_size: int,
    top_level_dir: str,
    *,
    reused_from_task_id: str | None = None,
    worker_id: str | None = None,
) -> bool:
    now = utc_now()
    row = await session.get(TaskRow, task_id)
    if row is None or row.cancelled_at is not None:
        return False
    if row.status in TERMINAL_STATUSES:
        return False
    if worker_id is not None and row.worker_id not in (None, worker_id):
        # Allow complete from pending (dedup reuse) when worker_id matches claim
        # or no worker owns it yet.
        if row.worker_id != worker_id:
            return False
    conditions = [
        TaskRow.id == task_id,
        TaskRow.status.not_in(TERMINAL_STATUSES),
        TaskRow.cancelled_at.is_(None),
    ]
    if worker_id is not None and row.worker_id is not None:
        conditions.append(TaskRow.worker_id == worker_id)
    values: dict[str, Any] = {
        "status": STATUS_COMPLETED,
        "stage": STAGE_FINISHED,
        "progress": 100,
        "file_count": file_count,
        "total_size": total_size,
        "top_level_dir": top_level_dir,
        "worker_id": None,
        "lease_expires_at": None,
        "updated_at": now,
        "completed_at": now,
    }
    if reused_from_task_id:
        values["reused_from_task_id"] = reused_from_task_id
    result = await session.execute(update(TaskRow).where(*conditions).values(**values))
    changed = result.rowcount == 1
    if changed:
        metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_COMPLETED})
    return changed


async def mark_failed(
    session: AsyncSession,
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> bool:
    now = utc_now()
    row = await session.get(TaskRow, task_id)
    if row is None or row.cancelled_at is not None:
        return False
    if row.status in TERMINAL_STATUSES:
        return False
    if worker_id is not None and row.worker_id not in (None, worker_id):
        return False
    conditions = [
        TaskRow.id == task_id,
        TaskRow.status.not_in(TERMINAL_STATUSES),
        TaskRow.cancelled_at.is_(None),
    ]
    if worker_id is not None and row.worker_id is not None:
        conditions.append(TaskRow.worker_id == worker_id)
    category = failure_category or category_for_error_code(error_code)
    result = await session.execute(
        update(TaskRow)
        .where(*conditions)
        .values(
            status=STATUS_FAILED,
            stage=STAGE_FINISHED,
            error_code=error_code,
            error_message=error_message or get_error_message(error_code),
            failure_category=category,
            worker_id=None,
            lease_expires_at=None,
            updated_at=now,
            completed_at=now,
        )
    )
    changed = result.rowcount == 1
    if changed:
        metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_FAILED})
    return changed


async def mark_dead(
    session: AsyncSession,
    task_id: str,
    error_code: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> bool:
    now = utc_now()
    row = await session.get(TaskRow, task_id)
    if row is None or row.cancelled_at is not None or row.status in TERMINAL_STATUSES:
        return False
    if worker_id is not None and row.worker_id not in (None, worker_id):
        return False
    code = error_code or DEAD_TASK
    category = failure_category or category_for_error_code(code)
    conditions = [
        TaskRow.id == task_id,
        TaskRow.status.in_((STATUS_PENDING, STATUS_RUNNING)),
        TaskRow.cancelled_at.is_(None),
    ]
    if worker_id is not None and row.worker_id is not None:
        conditions.append(TaskRow.worker_id == worker_id)
    result = await session.execute(
        update(TaskRow)
        .where(*conditions)
        .values(
            status=STATUS_DEAD,
            stage=STAGE_FINISHED,
            error_code=code,
            error_message=get_error_message(code),
            failure_category=category,
            worker_id=None,
            lease_expires_at=None,
            updated_at=now,
            completed_at=now,
        )
    )
    changed = result.rowcount == 1
    if changed:
        metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_DEAD})
    return changed


async def request_cancel(session: AsyncSession, task_id: str) -> str:
    now = utc_now()
    row = await session.get(TaskRow, task_id)
    if row is None:
        return "missing"
    if row.status in TERMINAL_STATUSES:
        return row.status
    if row.status == STATUS_PENDING:
        result = await session.execute(
            update(TaskRow)
            .where(TaskRow.id == task_id, TaskRow.status == STATUS_PENDING)
            .values(
                status=STATUS_CANCELLED,
                stage=STAGE_FINISHED,
                error_code=TASK_CANCELLED,
                error_message=get_error_message(TASK_CANCELLED),
                cancelled_at=now,
                worker_id=None,
                lease_expires_at=None,
                updated_at=now,
                completed_at=now,
            )
        )
        if result.rowcount == 1:
            metrics_mod.inc_counter(
                "vibecheck_tasks_total", {"status": STATUS_CANCELLED}
            )
            metrics_mod.inc_counter("vibecheck_cancelled_tasks_total")
            return STATUS_CANCELLED
        return row.status
    # running → flag cancel for cooperative stop
    await session.execute(
        update(TaskRow)
        .where(TaskRow.id == task_id, TaskRow.status == STATUS_RUNNING)
        .values(cancelled_at=func.coalesce(TaskRow.cancelled_at, now), updated_at=now)
    )
    return STATUS_RUNNING


async def mark_cancelled(session: AsyncSession, task_id: str) -> bool:
    now = utc_now()
    result = await session.execute(
        update(TaskRow)
        .where(
            TaskRow.id == task_id,
            TaskRow.status.not_in(TERMINAL_STATUSES),
        )
        .values(
            status=STATUS_CANCELLED,
            stage=STAGE_FINISHED,
            error_code=TASK_CANCELLED,
            error_message=get_error_message(TASK_CANCELLED),
            cancelled_at=func.coalesce(TaskRow.cancelled_at, now),
            worker_id=None,
            lease_expires_at=None,
            updated_at=now,
            completed_at=now,
        )
    )
    changed = result.rowcount == 1
    if changed:
        metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_CANCELLED})
        metrics_mod.inc_counter("vibecheck_cancelled_tasks_total")
    return changed


async def is_cancel_requested(session: AsyncSession, task_id: str) -> bool:
    row = await session.get(TaskRow, task_id)
    return bool(row and (row.cancelled_at is not None or row.status == STATUS_CANCELLED))


async def fail_or_retry(
    session: AsyncSession,
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> str:
    row = await session.get(TaskRow, task_id)
    if row is None:
        return STATUS_FAILED
    if row.status in TERMINAL_STATUSES:
        return row.status
    if row.cancelled_at is not None:
        await mark_cancelled(session, task_id)
        return STATUS_CANCELLED

    category = failure_category or category_for_error_code(error_code)
    attempts_made = max(int(row.attempt_count or 0), 1)
    decision = decide_retry(
        error_code=error_code, attempt_count=attempts_made, category=category
    )
    safe_message = error_message or get_error_message(error_code)
    now = utc_now()

    if not decision.should_retry:
        await mark_failed(
            session,
            task_id,
            error_code,
            safe_message,
            failure_category=category,
            worker_id=worker_id,
        )
        return STATUS_FAILED

    conditions = [
        TaskRow.id == task_id,
        TaskRow.status.in_((STATUS_PENDING, STATUS_RUNNING)),
        TaskRow.cancelled_at.is_(None),
    ]
    if worker_id is not None:
        conditions.append(or_(TaskRow.worker_id.is_(None), TaskRow.worker_id == worker_id))
    result = await session.execute(
        update(TaskRow)
        .where(*conditions)
        .values(
            status=STATUS_PENDING,
            stage=STAGE_QUEUED,
            progress=0,
            error_code=error_code,
            error_message=safe_message,
            failure_category=category,
            worker_id=None,
            lease_expires_at=None,
            next_attempt_at=decision.next_attempt_at,
            updated_at=now,
        )
    )
    if result.rowcount == 1:
        metrics_mod.inc_counter("vibecheck_retries_total", {"category": category})
        return STATUS_PENDING
    current = await session.get(TaskRow, task_id)
    return current.status if current else STATUS_FAILED


async def set_resolved_commit_sha(
    session: AsyncSession, task_id: str, commit_sha: str | None
) -> None:
    if not commit_sha:
        return
    row = await session.get(TaskRow, task_id)
    if row is None:
        return
    key = build_deduplication_key(
        row.repo_url, commit_sha, row.scanner_version or SCANNER_VERSION
    )
    await session.execute(
        update(TaskRow)
        .where(TaskRow.id == task_id)
        .values(
            resolved_commit_sha=commit_sha.strip().lower(),
            deduplication_key=key,
            updated_at=utc_now(),
        )
    )


async def find_completed_by_dedup_key(
    session: AsyncSession, dedup_key: str
) -> TaskRecord | None:
    if not dedup_key:
        return None
    result = await session.execute(
        select(TaskRow)
        .where(TaskRow.deduplication_key == dedup_key, TaskRow.status == STATUS_COMPLETED)
        .order_by(TaskRow.completed_at.desc().nullslast())
        .limit(1)
    )
    row = result.scalars().first()
    return TaskRecord.from_row(row) if row else None


async def find_running_by_repo(
    session: AsyncSession,
    repo_url: str,
    scanner_version: str | None = None,
) -> TaskRecord | None:
    if not repo_url or repo_url.startswith("local://"):
        return None
    normalized = normalize_repo_url(repo_url)
    version = scanner_version or SCANNER_VERSION
    result = await session.execute(
        select(TaskRow).where(
            TaskRow.status.in_((STATUS_RUNNING, STATUS_PENDING)),
            TaskRow.scanner_version == version,
        )
    )
    for row in result.scalars():
        if normalize_repo_url(row.repo_url) == normalized:
            return TaskRecord.from_row(row)
    return None


async def find_completed_by_repo_sha(
    session: AsyncSession,
    repo_url: str,
    commit_sha: str | None,
    scanner_version: str | None = None,
) -> TaskRecord | None:
    key = build_deduplication_key(repo_url, commit_sha, scanner_version)
    return await find_completed_by_dedup_key(session, key or "")


async def recover_expired_tasks(session: AsyncSession) -> dict[str, int]:
    """Recover expired running leases; multi-worker safe via FOR UPDATE SKIP LOCKED."""
    now = utc_now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    stats = {"requeued": 0, "dead": 0, "skipped": 0}
    dialect = session.bind.dialect.name if session.bind is not None else ""

    stmt = (
        select(TaskRow)
        .where(
            TaskRow.status == STATUS_RUNNING,
            TaskRow.lease_expires_at.isnot(None),
            TaskRow.lease_expires_at <= now,
        )
        .order_by(TaskRow.lease_expires_at.asc())
    )
    if dialect == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    else:
        stmt = stmt.with_for_update()

    result = await session.execute(stmt)
    rows = list(result.scalars())
    for row in rows:
        if row.cancelled_at is not None:
            await mark_cancelled(session, row.id)
            continue
        attempt_count = int(row.attempt_count or 0)
        max_attempts = int(row.max_attempts or settings.max_task_attempts)
        if attempt_count < max_attempts:
            upd = await session.execute(
                update(TaskRow)
                .where(
                    TaskRow.id == row.id,
                    TaskRow.status == STATUS_RUNNING,
                    TaskRow.lease_expires_at <= now,
                )
                .values(
                    status=STATUS_PENDING,
                    stage=STAGE_QUEUED,
                    progress=0,
                    worker_id=None,
                    lease_expires_at=None,
                    last_heartbeat_at=None,
                    next_attempt_at=None,
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if upd.rowcount:
                stats["requeued"] += 1
            else:
                stats["skipped"] += 1
        else:
            upd = await session.execute(
                update(TaskRow)
                .where(
                    TaskRow.id == row.id,
                    TaskRow.status == STATUS_RUNNING,
                    TaskRow.lease_expires_at <= now,
                )
                .values(
                    status=STATUS_DEAD,
                    stage=STAGE_FINISHED,
                    error_code=func.coalesce(TaskRow.error_code, DEAD_TASK),
                    error_message=func.coalesce(
                        TaskRow.error_message, get_error_message(DEAD_TASK)
                    ),
                    failure_category=func.coalesce(
                        TaskRow.failure_category, "INTERNAL_TRANSIENT"
                    ),
                    worker_id=None,
                    lease_expires_at=None,
                    updated_at=now,
                    completed_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if upd.rowcount:
                stats["dead"] += 1
            else:
                stats["skipped"] += 1
    if stats["requeued"] or stats["dead"]:
        metrics_mod.inc_counter(
            "vibecheck_recoveries_total",
            value=float(stats["requeued"] + stats["dead"]),
        )
    return stats


async def count_tasks_by_status(session: AsyncSession) -> dict[str, int]:
    result = await session.execute(
        select(TaskRow.status, func.count()).group_by(TaskRow.status)
    )
    return {row[0]: int(row[1]) for row in result.all()}
