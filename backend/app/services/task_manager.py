"""Task manager — SQLite as the single source of truth for task status.

Production-like execution model:
- Statuses: pending | running | completed | failed | cancelled | dead
- Atomic claim via BEGIN IMMEDIATE (DB transaction is the correctness boundary)
- Lease + heartbeat for crash recovery
- Bounded retries via next_attempt_at (no long asyncio.sleep holding slots)
- Commit + scanner_version deduplication keys
- Cancel is idempotent; terminal states never become running again

Security:
- error_message is always desensitized before storing.
- No downloaded files, code snippets, API keys, or absolute paths are stored.
- DB errors never surface raw SQL or filesystem paths to API callers.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import settings
from app.core.error_codes import (
    DEAD_TASK,
    TASK_CANCELLED,
    get_error_message,
)
from app.core.scanner_version import SCANNER_VERSION
from app.db.database import (
    _get_connection,
    begin_immediate,
    commit_txn,
    init_db,
    now_iso,
    rollback_txn,
)
from app.services import metrics as metrics_mod
from app.services.task_errors import (
    category_for_error_code,
    decide_retry,
)

logger = logging.getLogger(__name__)

# --- Task status / stage constants ---

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_DEAD = "dead"

# Statuses that are API-terminal when mapped for the frontend.
_API_FAILED_STATUSES = frozenset({STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD})

STAGE_QUEUED = "queued"
STAGE_DOWNLOADING = "downloading"
STAGE_EXTRACTING = "extracting"
STAGE_SCANNING = "scanning"
STAGE_ASSESSING = "assessing"
STAGE_REPAIRING = "repairing"
STAGE_ANALYZING = "analyzing"
STAGE_FINISHED = "finished"

TERMINAL_STATUSES = frozenset(
    {STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD}
)

# --- Legal state transitions ---
# Terminal states are frozen: completed/failed/cancelled/dead never return
# to running. pending may complete directly on dedup reuse.
_LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    STATUS_PENDING: frozenset(
        {STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD}
    ),
    STATUS_RUNNING: frozenset(
        {STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_DEAD, STATUS_PENDING}
    ),
    STATUS_COMPLETED: frozenset(),
    STATUS_FAILED: frozenset(),
    STATUS_CANCELLED: frozenset(),
    STATUS_DEAD: frozenset(),
}

# Worker claim lock reduces SQLite write contention; correctness is still
# enforced by BEGIN IMMEDIATE in claim_next_pending().
_claim_lock = threading.Lock()
_worker_id_counter = 0


class IllegalStateTransitionError(Exception):
    """Raised when a task state transition is not allowed (internal only)."""


class QueueCapacityError(Exception):
    """Raised when an atomic task admission finds the pending queue full."""


def _validate_transition(
    task_id: str, current_status: str, new_status: str,
) -> None:
    allowed = _LEGAL_TRANSITIONS.get(current_status, frozenset())
    if new_status not in allowed:
        raise IllegalStateTransitionError(
            f"Illegal transition for task {task_id}: "
            f"{current_status} -> {new_status}"
        )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def _iso_plus_seconds(seconds: float) -> str:
    return (utc_now() + timedelta(seconds=seconds)).isoformat()


def make_worker_id(prefix: str = "w") -> str:
    global _worker_id_counter
    with _claim_lock:
        _worker_id_counter += 1
        n = _worker_id_counter
    return f"{prefix}-{uuid.uuid4().hex[:8]}-{n}"


def normalize_repo_url(repo_url: str) -> str:
    """Normalize a GitHub URL for deduplication (no trailing slash/.git/case)."""
    url = (repo_url or "").strip().rstrip("/")
    url = url.removesuffix(".git")
    return url.lower()


def build_deduplication_key(
    repo_url: str,
    resolved_commit_sha: str | None,
    scanner_version: str | None = None,
) -> str | None:
    """Build the dedup key: normalized_repo_url|commit_sha|scanner_version."""
    if not repo_url or not resolved_commit_sha:
        return None
    # Local uploads are not reused across users by default.
    if repo_url.startswith(("upload://", "local://upload/", "local://")):
        return None
    version = scanner_version or SCANNER_VERSION
    sha = resolved_commit_sha.strip().lower()
    if not sha:
        return None
    return f"{normalize_repo_url(repo_url)}|{sha}|{version}"


@dataclass
class TaskSummary:
    """Summary of a completed task — no sensitive content."""
    file_count: int
    total_size: int
    top_level_dir: str


@dataclass
class TaskRecord:
    """Full task record from the database."""
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
    created_at: str
    updated_at: str
    completed_at: str | None
    attempt_count: int = 0
    max_attempts: int = 3
    worker_id: str | None = None
    lease_expires_at: str | None = None
    last_heartbeat_at: str | None = None
    next_attempt_at: str | None = None
    failure_category: str | None = None
    resolved_commit_sha: str | None = None
    scanner_version: str | None = None
    deduplication_key: str | None = None
    reused_from_task_id: str | None = None
    cancelled_at: str | None = None

    @classmethod
    def from_row(cls, row: sqlite3.Row | dict) -> TaskRecord:
        def _get(key: str, default: Any = None) -> Any:
            try:
                return row[key]
            except (IndexError, KeyError):
                return default

        return cls(
            id=_get("id"),
            repo_url=_get("repo_url", ""),
            owner=_get("owner", ""),
            repo_name=_get("repo_name", ""),
            status=_get("status", STATUS_PENDING),
            stage=_get("stage", STAGE_QUEUED),
            progress=int(_get("progress") or 0),
            error_code=_get("error_code"),
            error_message=_get("error_message"),
            file_count=_get("file_count"),
            total_size=_get("total_size"),
            top_level_dir=_get("top_level_dir"),
            created_at=_get("created_at") or now_iso(),
            updated_at=_get("updated_at") or now_iso(),
            completed_at=_get("completed_at"),
            attempt_count=int(_get("attempt_count") or 0),
            max_attempts=int(_get("max_attempts") or settings.max_task_attempts),
            worker_id=_get("worker_id"),
            lease_expires_at=_get("lease_expires_at"),
            last_heartbeat_at=_get("last_heartbeat_at"),
            next_attempt_at=_get("next_attempt_at"),
            failure_category=_get("failure_category"),
            resolved_commit_sha=_get("resolved_commit_sha"),
            scanner_version=_get("scanner_version"),
            deduplication_key=_get("deduplication_key"),
            reused_from_task_id=_get("reused_from_task_id"),
            cancelled_at=_get("cancelled_at"),
        )

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def api_status(self) -> str:
        """Frontend-compatible status: cancelled/dead map to failed."""
        if self.status in _API_FAILED_STATUSES:
            return STATUS_FAILED
        return self.status

    @property
    def is_cancel_requested(self) -> bool:
        return self.cancelled_at is not None or self.status == STATUS_CANCELLED

    def to_response(self) -> dict:
        """Convert to API response dict (no sensitive fields)."""
        resp = {
            "task_id": self.id,
            "status": self.api_status,
            "stage": self.stage,
            "progress": self.progress,
            "owner": self.owner,
            "repo_name": self.repo_name,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }
        if self.reused_from_task_id:
            resp["reused_from_task_id"] = self.reused_from_task_id
            resp["deduplicated"] = True
        else:
            resp["deduplicated"] = False
        if self.api_status == STATUS_FAILED:
            # Lightweight extras for observability / API docs
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

        if self.api_status == STATUS_COMPLETED or (
            self.reused_from_task_id is not None and self.status == STATUS_COMPLETED
        ):
            resp["file_count"] = self.file_count
            resp["total_size"] = self.total_size
            resp["top_level_dir"] = self.top_level_dir
            from app.services.scan_result_service import get_scan_summary
            scan_summary = get_scan_summary(self.id)
            resp["scan_summary"] = scan_summary
            resp["report_url"] = (
                f"/api/check/{self.id}/result" if scan_summary is not None else None
            )

            from app.services.assessment_service import get_assessment_score_verdict
            assessment_data = get_assessment_score_verdict(self.id)
            if assessment_data is not None:
                resp["security_score"] = assessment_data[0]
                resp["security_verdict"] = assessment_data[1]
                resp["assessment_url"] = f"/api/check/{self.id}/assessment"
            else:
                resp["security_score"] = None
                resp["security_verdict"] = None
                resp["assessment_url"] = None

            from app.services.repair_service import get_repair_plan_available
            repair_available = get_repair_plan_available(self.id)
            resp["repair_plan_available"] = repair_available
            resp["repair_plan_url"] = (
                f"/api/check/{self.id}/repair-plan" if repair_available else None
            )

            from app.services.llm_service import get_llm_analysis_available
            llm_available = get_llm_analysis_available(self.id)
            resp["llm_analysis_available"] = llm_available
            resp["llm_analysis_url"] = (
                f"/api/check/{self.id}/llm-analysis" if llm_available else None
            )
        return resp


# --- Create ---

def create_task(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    scanner_version: str | None = None,
    max_attempts: int | None = None,
) -> TaskRecord:
    """Create a new pending task in the database."""
    init_db()
    task_id = str(uuid.uuid4())
    now = now_iso()
    version = scanner_version or SCANNER_VERSION
    attempts = max_attempts or settings.max_task_attempts

    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO tasks
               (id, repo_url, owner, repo_name, status, stage, progress,
                error_code, error_message, file_count, total_size, top_level_dir,
                created_at, updated_at, completed_at,
                attempt_count, max_attempts, scanner_version, next_attempt_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL,
                       0, ?, ?, NULL)""",
            (task_id, repo_url, owner, repo_name,
             STATUS_PENDING, STAGE_QUEUED, 0, now, now,
             attempts, version),
        )
        conn.commit()
    finally:
        conn.close()

    from app.services.cleanup_service import maybe_trigger_cleanup
    maybe_trigger_cleanup()

    task = get_task(task_id)
    if task is None:
        raise RuntimeError("Failed to reload newly created task")
    return task


def admit_repo_task(
    repo_url: str,
    owner: str,
    repo_name: str,
    *,
    scanner_version: str | None = None,
) -> tuple[TaskRecord, bool]:
    """Atomically coalesce or admit a public-repository task.

    The active-task lookup, queue-capacity check, and insert share one
    ``BEGIN IMMEDIATE`` transaction.  ``created`` is false when an existing
    pending/running task for the same normalized repository and scanner
    version is returned.
    """
    init_db()
    version = scanner_version or SCANNER_VERSION
    normalized = normalize_repo_url(repo_url)
    now = now_iso()
    task_id = str(uuid.uuid4())
    conn = _get_connection()
    try:
        begin_immediate(conn)
        active_rows = conn.execute(
            """SELECT * FROM tasks
               WHERE status IN (?, ?) AND scanner_version = ?
               ORDER BY created_at ASC""",
            (STATUS_PENDING, STATUS_RUNNING, version),
        ).fetchall()
        for row in active_rows:
            if normalize_repo_url(row["repo_url"]) == normalized:
                existing = TaskRecord.from_row(row)
                commit_txn(conn)
                return existing, False

        pending = conn.execute(
            "SELECT COUNT(*) AS cnt FROM tasks WHERE status = ?",
            (STATUS_PENDING,),
        ).fetchone()
        if int(pending["cnt"] or 0) >= settings.max_pending_tasks:
            rollback_txn(conn)
            raise QueueCapacityError("pending task queue is full")

        conn.execute(
            """INSERT INTO tasks
               (id, repo_url, owner, repo_name, status, stage, progress,
                error_code, error_message, file_count, total_size, top_level_dir,
                created_at, updated_at, completed_at,
                attempt_count, max_attempts, scanner_version, next_attempt_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL,
                       0, ?, ?, NULL)""",
            (
                task_id,
                repo_url,
                owner,
                repo_name,
                STATUS_PENDING,
                STAGE_QUEUED,
                0,
                now,
                now,
                settings.max_task_attempts,
                version,
            ),
        )
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        commit_txn(conn)
        return TaskRecord.from_row(row), True
    except QueueCapacityError:
        raise
    except sqlite3.Error:
        rollback_txn(conn)
        logger.error("atomic repository admission database error")
        raise
    finally:
        conn.close()


def admit_upload_task(repo_url: str, owner: str, repo_name: str) -> TaskRecord:
    """Atomically enforce queue capacity and create a local-upload task."""
    init_db()
    task_id = str(uuid.uuid4())
    now = now_iso()
    conn = _get_connection()
    try:
        begin_immediate(conn)
        pending = conn.execute(
            "SELECT COUNT(*) AS cnt FROM tasks WHERE status = ?",
            (STATUS_PENDING,),
        ).fetchone()
        if int(pending["cnt"] or 0) >= settings.max_pending_tasks:
            rollback_txn(conn)
            raise QueueCapacityError("pending task queue is full")
        conn.execute(
            """INSERT INTO tasks
               (id, repo_url, owner, repo_name, status, stage, progress,
                created_at, updated_at, attempt_count, max_attempts,
                scanner_version)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, 0, ?, ?)""",
            (
                task_id,
                repo_url,
                owner,
                repo_name,
                STATUS_PENDING,
                STAGE_QUEUED,
                now,
                now,
                settings.max_task_attempts,
                SCANNER_VERSION,
            ),
        )
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        commit_txn(conn)
        return TaskRecord.from_row(row)
    except QueueCapacityError:
        raise
    except sqlite3.Error:
        rollback_txn(conn)
        logger.error("atomic upload admission database error")
        raise
    finally:
        conn.close()


# --- Read ---

def get_task(task_id: str) -> TaskRecord | None:
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            return None
        return TaskRecord.from_row(row)
    finally:
        conn.close()


def get_pending_count() -> int:
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM tasks WHERE status = ?",
            (STATUS_PENDING,),
        ).fetchone()
        return int(row["cnt"] or 0)
    finally:
        conn.close()


def get_running_count() -> int:
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM tasks WHERE status = ?",
            (STATUS_RUNNING,),
        ).fetchone()
        return int(row["cnt"] or 0)
    finally:
        conn.close()


def has_claimable_pending() -> bool:
    """True when at least one pending task is due (next_attempt_at elapsed)."""
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        row = conn.execute(
            """SELECT 1 FROM tasks
               WHERE status = ?
                 AND cancelled_at IS NULL
                 AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
               LIMIT 1""",
            (STATUS_PENDING, now),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def get_oldest_pending() -> TaskRecord | None:
    """Get the oldest claimable pending task, if any (non-atomic helper)."""
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        row = conn.execute(
            """SELECT * FROM tasks
               WHERE status = ?
                 AND cancelled_at IS NULL
                 AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
               ORDER BY created_at ASC LIMIT 1""",
            (STATUS_PENDING, now),
        ).fetchone()
        if row is None:
            return None
        return TaskRecord.from_row(row)
    finally:
        conn.close()


def count_tasks_by_status() -> dict[str, int]:
    init_db()
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) as cnt FROM tasks GROUP BY status"
        ).fetchall()
        return {row["status"]: int(row["cnt"] or 0) for row in rows}
    finally:
        conn.close()


def get_task_status_counts() -> dict[str, int]:
    return count_tasks_by_status()


# --- Atomic claim ---

def claim_next_pending(worker_id: str) -> TaskRecord | None:
    """Atomically claim the next due pending task.

    Uses BEGIN IMMEDIATE so two concurrent dispatchers cannot claim the same
    task. Python locks only reduce contention; the DB transaction is the
    correctness boundary.

    On success:
    - status → running
    - worker_id / lease_expires_at / last_heartbeat_at written
    - attempt_count incremented
    """
    init_db()
    now = now_iso()
    lease_expires = _iso_plus_seconds(settings.task_lease_seconds)

    conn = _get_connection()
    try:
        begin_immediate(conn)
        row = conn.execute(
            """SELECT id, attempt_count FROM tasks
               WHERE status = ?
                 AND cancelled_at IS NULL
                 AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
               ORDER BY created_at ASC
               LIMIT 1""",
            (STATUS_PENDING, now),
        ).fetchone()
        if row is None:
            rollback_txn(conn)
            return None

        task_id = row["id"]
        attempt_count = int(row["attempt_count"] or 0)
        cursor = conn.execute(
            """UPDATE tasks
               SET status = ?,
                   worker_id = ?,
                   lease_expires_at = ?,
                   last_heartbeat_at = ?,
                   attempt_count = ?,
                   next_attempt_at = NULL,
                   updated_at = ?
               WHERE id = ? AND status = ?""",
            (
                STATUS_RUNNING,
                worker_id,
                lease_expires,
                now,
                attempt_count + 1,
                now,
                task_id,
                STATUS_PENDING,
            ),
        )
        if cursor.rowcount != 1:
            rollback_txn(conn)
            return None
        commit_txn(conn)
    except sqlite3.Error:
        rollback_txn(conn)
        logger.error("claim_next_pending database error")
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass

    metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_RUNNING})
    return get_task(task_id)


def claim_next_pending_with_guard(worker_id: str) -> TaskRecord | None:
    """Claim under a process-local lock + atomic DB transaction."""
    with _claim_lock:
        return claim_next_pending(worker_id)


# --- Heartbeat ---

def touch_heartbeat(
    task_id: str,
    worker_id: str | None = None,
) -> bool:
    """Extend the lease for a running task owned by ``worker_id``.

    Production callers MUST pass the claim token. When ``worker_id`` is None
    the update is only allowed outside production test-compat paths that
    intentionally skip fencing; otherwise heartbeat cannot renew a stolen lease.
    """
    init_db()
    now = now_iso()
    lease_expires = _iso_plus_seconds(settings.task_lease_seconds)
    # Fencing: never renew without an explicit claim token in non-test envs.
    if worker_id is None and settings.app_env != "test":
        return False
    conn = _get_connection()
    try:
        begin_immediate(conn)
        if worker_id:
            cursor = conn.execute(
                """UPDATE tasks
                   SET last_heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                   WHERE id = ? AND status = ? AND worker_id = ?
                     AND cancelled_at IS NULL""",
                (now, lease_expires, now, task_id, STATUS_RUNNING, worker_id),
            )
        else:
            # Test-only compatibility path.
            cursor = conn.execute(
                """UPDATE tasks
                   SET last_heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                   WHERE id = ? AND status = ? AND cancelled_at IS NULL""",
                (now, lease_expires, now, task_id, STATUS_RUNNING),
            )
        ok = cursor.rowcount == 1
        commit_txn(conn)
        return ok
    except sqlite3.Error:
        rollback_txn(conn)
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --- Update ---

def update_task_status(
    task_id: str,
    status: str,
    stage: str | None = None,
    progress: int | None = None,
) -> None:
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        if stage is not None and progress is not None:
            conn.execute(
                "UPDATE tasks SET status = ?, stage = ?, progress = ?, updated_at = ? WHERE id = ?",
                (status, stage, progress, now, task_id),
            )
        elif stage is not None:
            conn.execute(
                "UPDATE tasks SET status = ?, stage = ?, updated_at = ? WHERE id = ?",
                (status, stage, now, task_id),
            )
        else:
            conn.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, task_id),
            )
        conn.commit()
    finally:
        conn.close()


def mark_running(
    task_id: str,
    stage: str,
    progress: int,
    *,
    worker_id: str | None = None,
) -> bool:
    """Atomically update a running stage, optionally fencing by claim token."""
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        begin_immediate(conn)
        row = conn.execute(
            "SELECT status, worker_id, cancelled_at FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        if row is None or row["cancelled_at"] is not None:
            rollback_txn(conn)
            return False
        try:
            _validate_transition(task_id, row["status"], STATUS_RUNNING)
        except IllegalStateTransitionError:
            rollback_txn(conn)
            return False
        if worker_id is not None and row["worker_id"] != worker_id:
            rollback_txn(conn)
            return False
        cursor = conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, progress = ?, updated_at = ?
               WHERE id = ? AND status = ? AND cancelled_at IS NULL
                 AND (? IS NULL OR worker_id = ?)""",
            (
                STATUS_RUNNING,
                stage,
                progress,
                now,
                task_id,
                row["status"],
                worker_id,
                worker_id,
            ),
        )
        commit_txn(conn)
        return cursor.rowcount == 1
    except sqlite3.Error:
        rollback_txn(conn)
        return False
    finally:
        conn.close()


def mark_completed(
    task_id: str,
    file_count: int,
    total_size: int,
    top_level_dir: str,
    *,
    reused_from_task_id: str | None = None,
    worker_id: str | None = None,
) -> bool:
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        begin_immediate(conn)
        row = conn.execute(
            "SELECT status, worker_id, cancelled_at FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        if row is None or row["cancelled_at"] is not None:
            rollback_txn(conn)
            return False
        try:
            _validate_transition(task_id, row["status"], STATUS_COMPLETED)
        except IllegalStateTransitionError:
            rollback_txn(conn)
            return False
        if worker_id is not None and row["worker_id"] != worker_id:
            rollback_txn(conn)
            return False
        cursor = conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, progress = 100,
                   file_count = ?, total_size = ?, top_level_dir = ?,
                   worker_id = NULL, lease_expires_at = NULL,
                   reused_from_task_id = COALESCE(?, reused_from_task_id),
                   updated_at = ?, completed_at = ?
               WHERE id = ? AND status = ? AND cancelled_at IS NULL
                 AND (? IS NULL OR worker_id = ?)""",
            (STATUS_COMPLETED, STAGE_FINISHED, file_count, total_size,
             top_level_dir, reused_from_task_id, now, now, task_id,
             row["status"], worker_id, worker_id),
        )
        commit_txn(conn)
        changed = cursor.rowcount == 1
    except sqlite3.Error:
        rollback_txn(conn)
        return False
    finally:
        conn.close()
    if changed:
        metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_COMPLETED})
    return changed


def mark_failed(
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> bool:
    init_db()
    now = now_iso()
    safe_message = error_message or get_error_message(error_code)
    category = failure_category or category_for_error_code(error_code)
    conn = _get_connection()
    try:
        begin_immediate(conn)
        row = conn.execute(
            "SELECT status, worker_id, cancelled_at FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        if row is None or row["cancelled_at"] is not None:
            rollback_txn(conn)
            return False
        try:
            _validate_transition(task_id, row["status"], STATUS_FAILED)
        except IllegalStateTransitionError:
            rollback_txn(conn)
            return False
        if worker_id is not None and row["worker_id"] != worker_id:
            rollback_txn(conn)
            return False
        cursor = conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, error_code = ?, error_message = ?,
                   failure_category = ?,
                   worker_id = NULL, lease_expires_at = NULL,
                   updated_at = ?, completed_at = ?
               WHERE id = ? AND status = ? AND cancelled_at IS NULL
                 AND (? IS NULL OR worker_id = ?)""",
            (STATUS_FAILED, STAGE_FINISHED, error_code, safe_message,
             category, now, now, task_id, row["status"], worker_id, worker_id),
        )
        commit_txn(conn)
        changed = cursor.rowcount == 1
    except sqlite3.Error:
        rollback_txn(conn)
        return False
    finally:
        conn.close()
    if changed:
        metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_FAILED})
    return changed


def mark_dead(
    task_id: str,
    error_code: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> bool:
    """Terminal dead state — max attempts exhausted. Conditional + fenced."""
    init_db()
    code = error_code or DEAD_TASK
    now = now_iso()
    category = failure_category or category_for_error_code(code)
    conn = _get_connection()
    try:
        begin_immediate(conn)
        row = conn.execute(
            "SELECT status, worker_id, cancelled_at FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        if row is None or row["cancelled_at"] is not None:
            rollback_txn(conn)
            return False
        if row["status"] in TERMINAL_STATUSES:
            rollback_txn(conn)
            return False
        if worker_id is not None and row["worker_id"] != worker_id:
            rollback_txn(conn)
            return False
        cursor = conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, error_code = ?, error_message = ?,
                   failure_category = ?,
                   worker_id = NULL, lease_expires_at = NULL,
                   updated_at = ?, completed_at = ?
               WHERE id = ? AND status IN (?, ?) AND cancelled_at IS NULL
                 AND (? IS NULL OR worker_id = ?)""",
            (
                STATUS_DEAD,
                STAGE_FINISHED,
                code,
                get_error_message(code),
                category,
                now,
                now,
                task_id,
                STATUS_PENDING,
                STATUS_RUNNING,
                worker_id,
                worker_id,
            ),
        )
        changed = cursor.rowcount == 1
        commit_txn(conn)
    except sqlite3.Error:
        rollback_txn(conn)
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if changed:
        metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_DEAD})
    return changed


def mark_cancelled(task_id: str) -> None:
    """Idempotent cancel. Terminal tasks stay unchanged."""
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        begin_immediate(conn)
        row = conn.execute(
            "SELECT status FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            rollback_txn(conn)
            return
        status = row["status"]
        if status in TERMINAL_STATUSES:
            # Idempotent: cancelling completed/failed/dead/cancelled is a no-op.
            rollback_txn(conn)
            return
        # pending or running → cancelled
        conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, error_code = ?, error_message = ?,
                   cancelled_at = ?, worker_id = NULL, lease_expires_at = NULL,
                   updated_at = ?, completed_at = ?
               WHERE id = ?""",
            (
                STATUS_CANCELLED,
                STAGE_FINISHED,
                TASK_CANCELLED,
                get_error_message(TASK_CANCELLED),
                now,
                now,
                now,
                task_id,
            ),
        )
        commit_txn(conn)
    except sqlite3.Error:
        rollback_txn(conn)
        return
    finally:
        try:
            conn.close()
        except Exception:
            pass
    metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_CANCELLED})
    metrics_mod.inc_counter("vibecheck_cancelled_tasks_total")


def request_cancel(task_id: str) -> str:
    """Request cancellation. Returns the resulting status.

    - pending → cancelled immediately
    - running → set cancelled_at; worker will stop; then cancelled
    - terminal → unchanged (idempotent)
    """
    task = get_task(task_id)
    if task is None:
        return "missing"
    if task.is_terminal:
        return task.status
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        begin_immediate(conn)
        row = conn.execute(
            "SELECT status FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            rollback_txn(conn)
            return "missing"
        current = row["status"]
        if current in TERMINAL_STATUSES:
            rollback_txn(conn)
            return current
        if current == STATUS_PENDING:
            conn.execute(
                """UPDATE tasks
                   SET status = ?, stage = ?, error_code = ?, error_message = ?,
                       cancelled_at = ?, worker_id = NULL, lease_expires_at = NULL,
                       updated_at = ?, completed_at = ?
                   WHERE id = ?""",
                (
                    STATUS_CANCELLED,
                    STAGE_FINISHED,
                    TASK_CANCELLED,
                    get_error_message(TASK_CANCELLED),
                    now, now, now, task_id,
                ),
            )
            commit_txn(conn)
            metrics_mod.inc_counter("vibecheck_tasks_total", {"status": STATUS_CANCELLED})
            metrics_mod.inc_counter("vibecheck_cancelled_tasks_total")
            return STATUS_CANCELLED
        # running: flag cancel; worker finalizes to cancelled
        conn.execute(
            """UPDATE tasks
               SET cancelled_at = COALESCE(cancelled_at, ?), updated_at = ?
               WHERE id = ? AND status = ?""",
            (now, now, task_id, STATUS_RUNNING),
        )
        commit_txn(conn)
        return STATUS_RUNNING
    except sqlite3.Error:
        rollback_txn(conn)
        return task.status
    finally:
        try:
            conn.close()
        except Exception:
            pass


def is_cancel_requested(task_id: str) -> bool:
    task = get_task(task_id)
    return bool(task and task.is_cancel_requested)


# --- Failure / retry ---

def fail_or_retry(
    task_id: str,
    error_code: str,
    error_message: str | None = None,
    *,
    failure_category: str | None = None,
    worker_id: str | None = None,
) -> str:
    """Apply failure with bounded retry policy.

    Transient categories re-queue via next_attempt_at; permanent or exhausted
    attempts go to failed/dead. Returns the resulting status.
    """
    task = get_task(task_id)
    if task is None:
        return STATUS_FAILED
    if task.is_terminal:
        return task.status
    if task.cancelled_at is not None or task.status == STATUS_CANCELLED:
        mark_cancelled(task_id)
        return STATUS_CANCELLED

    category = failure_category or category_for_error_code(error_code)
    # Processing implies at least one attempt even if claim increment
    # was skipped (direct _process_task calls in tests / recovery paths).
    attempts_made = max(int(task.attempt_count or 0), 1)
    decision = decide_retry(
        error_code=error_code,
        attempt_count=attempts_made,
        category=category,
    )
    safe_message = error_message or get_error_message(error_code)
    now = now_iso()

    if not decision.should_retry:
        # Exhausted retries or permanent errors → failed (terminal).
        # lease-expired recovery uses mark_dead separately when attempts
        # are exhausted while the task was running after a crash.
        mark_failed(
            task_id,
            error_code,
            safe_message,
            failure_category=category,
            worker_id=worker_id,
        )
        return STATUS_FAILED

    conn = _get_connection()
    try:
        begin_immediate(conn)
        cursor = conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, progress = 0,
                   error_code = ?, error_message = ?, failure_category = ?,
                   worker_id = NULL, lease_expires_at = NULL,
                   next_attempt_at = ?,
                   updated_at = ?
               WHERE id = ? AND status IN (?, ?) AND cancelled_at IS NULL
                 AND (? IS NULL OR worker_id = ?)""",
            (
                STATUS_PENDING,
                STAGE_QUEUED,
                error_code,
                safe_message,
                category,
                decision.next_attempt_at,
                now,
                task_id,
                STATUS_PENDING,
                STATUS_RUNNING,
                worker_id,
                worker_id,
            ),
        )
        changed = cursor.rowcount == 1
        commit_txn(conn)
    except sqlite3.Error:
        rollback_txn(conn)
        return STATUS_FAILED
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if changed:
        # Count only true re-queues, never permanent failures.
        metrics_mod.inc_counter("vibecheck_retries_total", {"category": category})
        return STATUS_PENDING
    current = get_task(task_id)
    return current.status if current is not None else STATUS_FAILED


def set_resolved_commit_sha(task_id: str, commit_sha: str | None) -> None:
    """Persist resolved commit SHA and refresh deduplication_key."""
    if not commit_sha:
        return
    task = get_task(task_id)
    if task is None:
        return
    key = build_deduplication_key(
        task.repo_url, commit_sha, task.scanner_version or SCANNER_VERSION
    )
    now = now_iso()
    conn = _get_connection()
    try:
        conn.execute(
            """UPDATE tasks
               SET resolved_commit_sha = ?, deduplication_key = ?, updated_at = ?
               WHERE id = ?""",
            (commit_sha.strip().lower(), key, now, task_id),
        )
        conn.commit()
    finally:
        conn.close()


# --- Deduplication ---

def find_completed_by_dedup_key(dedup_key: str) -> TaskRecord | None:
    if not dedup_key:
        return None
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            """SELECT * FROM tasks
               WHERE deduplication_key = ? AND status = ?
               ORDER BY completed_at DESC LIMIT 1""",
            (dedup_key, STATUS_COMPLETED),
        ).fetchone()
        return TaskRecord.from_row(row) if row else None
    finally:
        conn.close()


def find_running_by_repo(
    repo_url: str,
    scanner_version: str | None = None,
) -> TaskRecord | None:
    """Find a running/pending task for the same normalized repo URL."""
    if not repo_url or repo_url.startswith("upload://"):
        return None
    normalized = normalize_repo_url(repo_url)
    version = scanner_version or SCANNER_VERSION
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            """SELECT * FROM tasks
               WHERE status IN (?, ?)
                 AND scanner_version = ?
                 AND lower(rtrim(CASE WHEN repo_url LIKE '%.git'
                         THEN substr(repo_url, 1, length(repo_url)-4)
                         ELSE repo_url END, '/')) = ?
               ORDER BY created_at DESC LIMIT 1""",
            (STATUS_RUNNING, STATUS_PENDING, version, normalized),
        ).fetchone()
        if row is None:
            return None
        return TaskRecord.from_row(row)
    finally:
        conn.close()


def find_completed_by_repo_sha(
    repo_url: str,
    commit_sha: str | None,
    scanner_version: str | None = None,
) -> TaskRecord | None:
    key = build_deduplication_key(repo_url, commit_sha, scanner_version)
    return find_completed_by_dedup_key(key or "")


def copy_task_results(source_task_id: str, dest_task_id: str) -> bool:
    """Copy desensitized result rows from source to dest task.

    Only copies already-public, desensitized JSON snapshots. Never raw
    secrets or temp paths. Returns True if at least the scan result copied.
    """
    init_db()
    now = now_iso()
    copied_scan = False
    conn = _get_connection()
    try:
        for table in (
            "scan_results",
            "assessment_results",
            "repair_results",
            "llm_analysis_results",
        ):
            row = conn.execute(
                f"SELECT * FROM {table} WHERE task_id = ?", (source_task_id,)
            ).fetchone()
            if row is None:
                continue
            cols = [c for c in row.keys() if c != "task_id"]
            if "updated_at" in cols:
                col_list = ", ".join(cols)
                placeholders = ", ".join(["?"] * len(cols))
                updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c != "created_at")
                values = []
                for c in cols:
                    if c == "updated_at":
                        values.append(now)
                    else:
                        values.append(row[c])
                try:
                    conn.execute(
                        f"INSERT OR REPLACE INTO {table} (task_id, {col_list}) "
                        f"VALUES (?, {placeholders}) "
                        f"ON CONFLICT(task_id) DO UPDATE SET {updates}",
                        [dest_task_id, *values],
                    )
                except sqlite3.Error:
                    # Fallback simpler path
                    conn.execute(f"DELETE FROM {table} WHERE task_id = ?", (dest_task_id,))
                    placeholders2 = ", ".join(["?"] * (len(cols) + 1))
                    values2 = [dest_task_id]
                    for c in cols:
                        values2.append(now if c == "updated_at" else row[c])
                    conn.execute(
                        f"INSERT INTO {table} (task_id, {', '.join(cols)}) "
                        f"VALUES ({placeholders2})",
                        values2,
                    )
                if table == "scan_results":
                    copied_scan = True
        conn.commit()
        return copied_scan
    except sqlite3.Error:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.error("Failed to copy task results (internal)")
        return False
    finally:
        conn.close()


def complete_as_reused(
    new_task_id: str,
    source_task: TaskRecord,
) -> bool:
    """Mark new_task_id completed by reusing a completed source task.

    Copies whatever desensitized result rows exist on the source. Reuse is
    valid even when optional stage tables are empty (legacy tasks).
    """
    copy_task_results(source_task.id, new_task_id)
    mark_completed(
        new_task_id,
        file_count=source_task.file_count or 0,
        total_size=source_task.total_size or 0,
        top_level_dir=source_task.top_level_dir or "reused",
        reused_from_task_id=source_task.id,
    )
    metrics_mod.inc_counter("vibecheck_deduplicated_tasks_total")
    return True


# --- Lease recovery ---

def recover_expired_tasks(now: str | None = None) -> dict[str, int]:
    """Recover tasks whose leases expired (crash / restart safe).

    - lease not expired: leave running (do not double-claim)
    - lease expired + attempt_count < max_attempts → pending
    - lease expired + attempt_count >= max_attempts → dead
    - completed/failed/cancelled/dead: untouched
    - pending: untouched (they stay queued; do NOT fail them)

    Clears worker_id and lease on recovery. Safe under concurrent recovery
    because updates are guarded by status + lease_expires_at predicates.
    """
    init_db()
    now_ts = now or now_iso()
    stats = {"requeued": 0, "dead": 0, "skipped": 0}
    conn = _get_connection()
    try:
        begin_immediate(conn)
        rows = conn.execute(
            """SELECT id, attempt_count, max_attempts, lease_expires_at, error_code, failure_category
               FROM tasks
               WHERE status = ?
                 AND lease_expires_at IS NOT NULL
                 AND lease_expires_at <= ?""",
            (STATUS_RUNNING, now_ts),
        ).fetchall()
        for row in rows:
            task_id = row["id"]
            attempt_count = int(row["attempt_count"] or 0)
            max_attempts = int(row["max_attempts"] or settings.max_task_attempts)
            # Skip if cancelled while running
            cancel_row = conn.execute(
                "SELECT cancelled_at FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if cancel_row and cancel_row["cancelled_at"]:
                conn.execute(
                    """UPDATE tasks
                       SET status = ?, stage = ?, error_code = ?,
                           error_message = ?,
                           worker_id = NULL, lease_expires_at = NULL,
                           updated_at = ?, completed_at = ?
                       WHERE id = ? AND status = ?""",
                    (
                        STATUS_CANCELLED,
                        STAGE_FINISHED,
                        TASK_CANCELLED,
                        get_error_message(TASK_CANCELLED),
                        now_ts, now_ts,
                        task_id,
                        STATUS_RUNNING,
                    ),
                )
                continue
            if attempt_count < max_attempts:
                cursor = conn.execute(
                    """UPDATE tasks
                       SET status = ?, stage = ?, progress = 0,
                           worker_id = NULL, lease_expires_at = NULL,
                           last_heartbeat_at = NULL,
                           next_attempt_at = NULL,
                           updated_at = ?
                       WHERE id = ? AND status = ?
                         AND lease_expires_at <= ?""",
                    (STATUS_PENDING, STAGE_QUEUED, now_ts,
                     task_id, STATUS_RUNNING, now_ts),
                )
                if cursor.rowcount:
                    stats["requeued"] += 1
                else:
                    stats["skipped"] += 1
            else:
                cursor = conn.execute(
                    """UPDATE tasks
                       SET status = ?, stage = ?,
                           error_code = COALESCE(error_code, ?),
                           error_message = COALESCE(error_message, ?),
                           failure_category = COALESCE(failure_category, ?),
                           worker_id = NULL, lease_expires_at = NULL,
                           updated_at = ?, completed_at = ?
                       WHERE id = ? AND status = ?
                         AND lease_expires_at <= ?""",
                    (
                        STATUS_DEAD,
                        STAGE_FINISHED,
                        DEAD_TASK,
                        get_error_message(DEAD_TASK),
                        row["failure_category"] or "INTERNAL_TRANSIENT",
                        now_ts, now_ts,
                        task_id,
                        STATUS_RUNNING,
                        now_ts,
                    ),
                )
                if cursor.rowcount:
                    stats["dead"] += 1
                else:
                    stats["skipped"] += 1
        commit_txn(conn)
    except sqlite3.Error:
        rollback_txn(conn)
        logger.error("recover_expired_tasks database error")
        return stats
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if stats["requeued"] or stats["dead"]:
        metrics_mod.inc_counter("vibecheck_recoveries_total", value=float(stats["requeued"] + stats["dead"]))
        if stats["requeued"]:
            metrics_mod.inc_counter(
                "vibecheck_lease_expirations_total", value=float(stats["requeued"])
            )
    return stats


def mark_stale_tasks_as_failed() -> int:
    """Deprecated compatibility helper — no longer used on startup.

    Production startup now calls recover_expired_tasks() so leased tasks can
    resume after a crash instead of being force-failed. This function is kept
    for older tests/scripts and intentionally does NOT fail pending tasks.
    """
    stats = recover_expired_tasks()
    return stats["requeued"] + stats["dead"]


def is_queue_full() -> bool:
    """Check if the pending queue is full."""
    return get_pending_count() >= settings.max_pending_tasks


def refresh_queue_metrics() -> None:
    metrics_mod.set_gauge("vibecheck_queue_depth", float(get_pending_count()))
    metrics_mod.set_gauge("vibecheck_active_tasks", float(get_running_count()))
