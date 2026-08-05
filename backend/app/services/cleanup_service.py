"""Cleanup service — residual temp file cleanup and expired report removal.

P2-3 Robustness:

1. Startup cleanup: removes stale temp files/directories left by crashed
   processes. Called once during FastAPI lifespan startup.

2. Expired report cleanup: deletes tasks (and all related rows) older
   than report_ttl_hours. Called on startup and periodically after every
   cleanup_interval_tasks new task creations.

Security:
- Never follows symlinks during temp cleanup.
- Only deletes files/dirs under settings.tmp_dir (root_resolved check).
- Expired task cleanup deletes rows from all tables atomically.
- Errors are logged but never raised to the caller.
"""

from __future__ import annotations

import logging
import os
import shutil
from datetime import timezone
from pathlib import Path

from app.core.config import settings
from app.db.database import _get_connection, init_db

logger = logging.getLogger(__name__)

# Counter for periodic cleanup trigger.
_task_creation_counter: int = 0


def cleanup_residual_temp_files() -> int:
    """Remove stale temp files and directories from settings.tmp_dir.

    Called on startup to clean up after process crashes. Removes:
    - Download files (download-*.tar.gz)
    - Extraction directories (task-*/)

    Returns the number of items removed.
    """
    tmp_root = Path(settings.tmp_dir)
    if not tmp_root.exists():
        return 0

    # Resolve the root to prevent symlink escapes.
    try:
        root_resolved = tmp_root.resolve()
    except (OSError, RuntimeError):
        logger.warning("Could not resolve tmp_dir: %s", settings.tmp_dir)
        return 0

    removed = 0
    for entry in root_resolved.iterdir():
        try:
            entry_resolved = entry.resolve()
            # Ensure entry is within root.
            entry_resolved.relative_to(root_resolved)
        except (ValueError, OSError, RuntimeError):
            # Skip entries that escape the root or can't be resolved.
            logger.warning("Skipping temp entry outside root: %s", entry.name)
            continue

        # Skip symlinks — never follow them.
        if entry.is_symlink():
            logger.warning("Skipping symlink in tmp_dir: %s", entry.name)
            continue

        try:
            if entry.is_dir():
                shutil.rmtree(entry, onerror=_onerror_log)
                removed += 1
            elif entry.is_file():
                entry.unlink()
                removed += 1
        except Exception:
            logger.warning("Failed to remove stale temp entry: %s", entry.name)

    if removed > 0:
        logger.info("Startup cleanup: removed %d stale temp item(s)", removed)
    return removed


def _onerror_log(func, path, exc_info):
    """shutil.rmtree onerror callback — handle read-only files."""
    try:
        os.chmod(path, 0o700)
        func(path)
    except Exception:
        # If we still can't delete it, log and move on.
        logger.warning("Could not remove read-only temp file: %s", path)


def cleanup_expired_tasks() -> int:
    """Delete tasks older than report_ttl_hours and all related data.

    Deletes from: tasks, scan_results, assessment_results,
    repair_results, llm_analysis_results.

    Returns the number of tasks deleted.
    """
    if settings.report_ttl_hours <= 0:
        # Cleanup disabled.
        return 0

    from datetime import datetime, timedelta

    init_db()
    conn = _get_connection()
    try:
        # Fetch all completed/failed tasks with completed_at.
        rows = conn.execute(
            """SELECT id, completed_at FROM tasks
               WHERE status IN ('completed', 'failed')
               AND completed_at IS NOT NULL""",
        ).fetchall()

        if not rows:
            return 0

        # Filter expired tasks in Python (SQLite julianday has
        # limited ISO 8601 / timezone support).
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=settings.report_ttl_hours
        )
        expired_ids: list[str] = []
        for row in rows:
            try:
                completed_str = row["completed_at"]
                # Handle both "Z" suffix and "+00:00" formats.
                if completed_str.endswith("Z"):
                    completed = datetime.fromisoformat(
                        completed_str
                    )
                else:
                    completed = datetime.fromisoformat(completed_str)
                    if completed.tzinfo is None:
                        completed = completed.replace(tzinfo=timezone.utc)
                if completed < cutoff:
                    expired_ids.append(row["id"])
            except (ValueError, TypeError):
                # Skip unparseable timestamps.
                continue

        if not expired_ids:
            return 0

        count = len(expired_ids)
        placeholders = ",".join("?" * count)

        # Delete from all related tables in a single transaction.
        # Related tables use task_id; the tasks table uses id.
        for table in (
            "llm_analysis_results",
            "repair_results",
            "assessment_results",
            "scan_results",
        ):
            conn.execute(
                f"DELETE FROM {table} WHERE task_id IN ({placeholders})",
                expired_ids,
            )
        conn.execute(
            f"DELETE FROM tasks WHERE id IN ({placeholders})",
            expired_ids,
        )
        conn.commit()

        logger.info("Expired report cleanup: deleted %d task(s)", count)
        return count
    except Exception:
        logger.error("Expired report cleanup failed — database error")
        conn.rollback()
        return 0
    finally:
        conn.close()


def maybe_trigger_cleanup() -> None:
    """Check if periodic cleanup should run based on task creation count.

    Called after each new task creation. Runs cleanup_expired_tasks()
    when the counter reaches cleanup_interval_tasks.
    """
    global _task_creation_counter

    if settings.cleanup_interval_tasks <= 0:
        return

    _task_creation_counter += 1
    if _task_creation_counter >= settings.cleanup_interval_tasks:
        _task_creation_counter = 0
        try:
            cleanup_expired_tasks()
        except Exception:
            logger.warning("Periodic cleanup failed — non-blocking")


def reset_cleanup_counter() -> None:
    """Reset the cleanup counter — for testing only."""
    global _task_creation_counter
    _task_creation_counter = 0
