"""Task manager — CRUD operations for the tasks table.

SQLite is the SINGLE source of truth for task status.
No task state is held in memory beyond transient references.

Security:
- error_message is always desensitized before storing.
- No downloaded files, code snippets, or sensitive content are stored.
- Only summary metadata (file_count, total_size, top_level_dir) is persisted.
"""

import logging
import uuid
from dataclasses import dataclass
from typing import Optional

from app.core.config import settings
from app.core.error_codes import get_error_message
from app.db.database import _get_connection, now_iso, init_db

logger = logging.getLogger(__name__)


# --- Task status / stage constants ---

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

STAGE_QUEUED = "queued"
STAGE_DOWNLOADING = "downloading"
STAGE_EXTRACTING = "extracting"
STAGE_SCANNING = "scanning"
STAGE_ASSESSING = "assessing"
STAGE_REPAIRING = "repairing"
STAGE_ANALYZING = "analyzing"
STAGE_FINISHED = "finished"

# --- Legal state transitions (P2-3) ---
# Only these transitions are allowed. Any other transition is rejected.
_LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    STATUS_PENDING: frozenset({STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED}),
    STATUS_RUNNING: frozenset({STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED}),
    STATUS_COMPLETED: frozenset(),  # terminal — no transitions allowed
    STATUS_FAILED: frozenset(),     # terminal — no transitions allowed
}


class IllegalStateTransitionError(Exception):
    """Raised when a task state transition is not allowed.

    This is an internal error — callers should catch and log it,
    never expose it to the API.
    """
    pass


def _validate_transition(
    task_id: str, current_status: str, new_status: str,
) -> None:
    """Validate that transitioning from current_status to new_status is legal.

    Raises IllegalStateTransitionError if the transition is not allowed.
    """
    allowed = _LEGAL_TRANSITIONS.get(current_status, frozenset())
    if new_status not in allowed:
        raise IllegalStateTransitionError(
            f"Illegal transition for task {task_id}: "
            f"{current_status} -> {new_status}"
        )


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
    error_code: Optional[str]
    error_message: Optional[str]
    file_count: Optional[int]
    total_size: Optional[int]
    top_level_dir: Optional[str]
    created_at: str
    updated_at: str
    completed_at: Optional[str]

    @classmethod
    def from_row(cls, row) -> "TaskRecord":
        return cls(
            id=row["id"],
            repo_url=row["repo_url"],
            owner=row["owner"],
            repo_name=row["repo_name"],
            status=row["status"],
            stage=row["stage"],
            progress=row["progress"],
            error_code=row["error_code"],
            error_message=row["error_message"],
            file_count=row["file_count"],
            total_size=row["total_size"],
            top_level_dir=row["top_level_dir"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            completed_at=row["completed_at"],
        )

    def to_response(self) -> dict:
        """Convert to API response dict (no sensitive fields).

        For completed tasks with a persisted scan result, includes
        scan_summary and report_url (P0-5).
        For completed tasks WITHOUT a persisted result (e.g. legacy
        tasks from before P0-5), scan_summary is None and report_url
        is None — the result endpoint will return SCAN_RESULT_MISSING.

        For completed tasks with a persisted assessment (P0-6), includes
        security_score, security_verdict, and assessment_url.
        For completed tasks WITHOUT a persisted assessment (e.g. legacy
        P0-5 tasks), these fields are None — the assessment endpoint
        will return ASSESSMENT_NOT_AVAILABLE.
        """
        resp = {
            "task_id": self.id,
            "status": self.status,
            "stage": self.stage,
            "progress": self.progress,
            "owner": self.owner,
            "repo_name": self.repo_name,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }
        if self.status == STATUS_COMPLETED:
            # Include download/extract summary metadata
            resp["file_count"] = self.file_count
            resp["total_size"] = self.total_size
            resp["top_level_dir"] = self.top_level_dir
            # Include scan summary from persisted result (P0-5)
            # Lazy import to avoid circular dependency
            from app.services.scan_result_service import get_scan_summary
            scan_summary = get_scan_summary(self.id)
            resp["scan_summary"] = scan_summary
            # report_url is only set when scan_summary exists.
            # If scan_summary is None (e.g. legacy completed task without
            # a persisted result), report_url is None — the result endpoint
            # will return SCAN_RESULT_MISSING.
            if scan_summary is not None:
                resp["report_url"] = f"/api/check/{self.id}/result"
            else:
                resp["report_url"] = None

            # Include lightweight assessment fields (P0-6)
            # Reads ONLY the redundant score and verdict columns —
            # does NOT parse the full assessment_json.
            # For legacy P0-5 tasks without an assessment, these are None.
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

            # Include lightweight repair plan availability (P0-7)
            # Reads ONLY the task_id column from repair_results —
            # does NOT parse the full repair_json.
            # For tasks without a persisted repair plan (e.g. legacy
            # P0-6 tasks), repair_plan_available is False and
            # repair_plan_url is None.
            from app.services.repair_service import get_repair_plan_available
            repair_available = get_repair_plan_available(self.id)
            resp["repair_plan_available"] = repair_available
            if repair_available:
                resp["repair_plan_url"] = (
                    f"/api/check/{self.id}/repair-plan"
                )
            else:
                resp["repair_plan_url"] = None

            # Include lightweight LLM analysis availability (P1-4)
            # Reads ONLY the task_id column from llm_analysis_results —
            # does NOT parse the full analysis_json.
            from app.services.llm_service import get_llm_analysis_available
            llm_available = get_llm_analysis_available(self.id)
            resp["llm_analysis_available"] = llm_available
            if llm_available:
                resp["llm_analysis_url"] = (
                    f"/api/check/{self.id}/llm-analysis"
                )
            else:
                resp["llm_analysis_url"] = None
        return resp


# --- Create ---

def create_task(repo_url: str, owner: str, repo_name: str) -> TaskRecord:
    """Create a new pending task in the database.

    Returns the created TaskRecord.
    """
    init_db()
    task_id = str(uuid.uuid4())
    now = now_iso()

    conn = _get_connection()
    try:
        conn.execute(
            """INSERT INTO tasks
               (id, repo_url, owner, repo_name, status, stage, progress,
                error_code, error_message, file_count, total_size, top_level_dir,
                created_at, updated_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL)""",
            (task_id, repo_url, owner, repo_name,
             STATUS_PENDING, STAGE_QUEUED, 0, now, now),
        )
        conn.commit()
    finally:
        conn.close()

    # P2-3: Trigger periodic cleanup if enough tasks have been created.
    from app.services.cleanup_service import maybe_trigger_cleanup
    maybe_trigger_cleanup()

    task = get_task(task_id)
    if task is None:
        raise RuntimeError(f"Failed to reload newly created task {task_id}")
    return task


# --- Read ---

def get_task(task_id: str) -> Optional[TaskRecord]:
    """Get a task by ID. Returns None if not found."""
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
    """Count of pending tasks in the queue."""
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM tasks WHERE status = ?",
            (STATUS_PENDING,),
        ).fetchone()
        return row["cnt"]
    finally:
        conn.close()


def get_oldest_pending() -> Optional[TaskRecord]:
    """Get the oldest pending task, if any."""
    init_db()
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tasks WHERE status = ? ORDER BY created_at ASC LIMIT 1",
            (STATUS_PENDING,),
        ).fetchone()
        if row is None:
            return None
        return TaskRecord.from_row(row)
    finally:
        conn.close()


# --- Update ---

def update_task_status(
    task_id: str,
    status: str,
    stage: Optional[str] = None,
    progress: Optional[int] = None,
) -> None:
    """Update a task's status, stage, and/or progress."""
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


def mark_running(task_id: str, stage: str, progress: int) -> None:
    """Mark a task as running with the given stage and progress.

    Validates the state transition:
    - pending → running: allowed
    - running → running: allowed (stage/progress update)
    - completed/failed → running: rejected (terminal states)
    """
    task = get_task(task_id)
    if task is not None:
        try:
            _validate_transition(task_id, task.status, STATUS_RUNNING)
        except IllegalStateTransitionError:
            logger.error(
                "Rejected illegal transition for task %s: "
                "%s -> running", task_id, task.status,
            )
            return
    update_task_status(task_id, STATUS_RUNNING, stage, progress)


def mark_completed(
    task_id: str,
    file_count: int,
    total_size: int,
    top_level_dir: str,
) -> None:
    """Mark a task as completed with summary metadata.

    Validates the state transition:
    - running → completed: allowed
    - pending/completed/failed → completed: rejected
    """
    task = get_task(task_id)
    if task is not None:
        try:
            _validate_transition(task_id, task.status, STATUS_COMPLETED)
        except IllegalStateTransitionError:
            logger.error(
                "Rejected illegal transition for task %s: "
                "%s -> completed", task_id, task.status,
            )
            return
    init_db()
    now = now_iso()
    conn = _get_connection()
    try:
        conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, progress = 100,
                   file_count = ?, total_size = ?, top_level_dir = ?,
                   updated_at = ?, completed_at = ?
               WHERE id = ?""",
            (STATUS_COMPLETED, STAGE_FINISHED, file_count, total_size,
             top_level_dir, now, now, task_id),
        )
        conn.commit()
    finally:
        conn.close()


def mark_failed(task_id: str, error_code: str, error_message: Optional[str] = None) -> None:
    """Mark a task as failed with an error code and desensitized message.

    The error_message is always sanitized via get_error_message() to ensure
    no sensitive content is stored.

    Validates the state transition:
    - pending → failed: allowed
    - running → failed: allowed
    - completed/failed → failed: rejected (terminal states)
    """
    task = get_task(task_id)
    if task is not None:
        try:
            _validate_transition(task_id, task.status, STATUS_FAILED)
        except IllegalStateTransitionError:
            logger.error(
                "Rejected illegal transition for task %s: "
                "%s -> failed", task_id, task.status,
            )
            return
    init_db()
    now = now_iso()
    safe_message = error_message or get_error_message(error_code)
    conn = _get_connection()
    try:
        conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, error_code = ?, error_message = ?,
                   updated_at = ?, completed_at = ?
               WHERE id = ?""",
            (STATUS_FAILED, STAGE_FINISHED, error_code, safe_message,
             now, now, task_id),
        )
        conn.commit()
    finally:
        conn.close()


# --- Service restart hook ---

def mark_stale_tasks_as_failed() -> int:
    """Mark all running and pending tasks as failed on service restart.

    - Running tasks → failed with SERVICE_RESTARTED
    - Pending tasks → failed with SERVICE_RESTARTED (avoid permanent waiters)

    Returns the number of tasks marked as failed.
    """
    init_db()
    from app.core.error_codes import SERVICE_RESTARTED, get_error_message
    now = now_iso()
    safe_message = get_error_message(SERVICE_RESTARTED)
    count = 0

    conn = _get_connection()
    try:
        cursor = conn.execute(
            """UPDATE tasks
               SET status = ?, stage = ?, error_code = ?, error_message = ?,
                   updated_at = ?, completed_at = ?
               WHERE status IN (?, ?)""",
            (STATUS_FAILED, STAGE_FINISHED, SERVICE_RESTARTED, safe_message,
             now, now, STATUS_RUNNING, STATUS_PENDING),
        )
        count = cursor.rowcount
        conn.commit()
    finally:
        conn.close()

    return count


def is_queue_full() -> bool:
    """Check if the pending queue is full."""
    return get_pending_count() >= settings.max_pending_tasks
