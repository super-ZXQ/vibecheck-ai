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
    """Delete expired completed/failed tasks via SQLAlchemy async repository."""
    if settings.report_ttl_hours <= 0:
        return 0
    import asyncio
    import concurrent.futures
    from datetime import datetime, timedelta

    from sqlalchemy import delete, select

    from app.db.models import (
        AssessmentResultRow,
        LlmAnalysisResultRow,
        RepairResultRow,
        ScanResultRow,
        TaskRow,
    )
    from app.db.session import get_session_factory

    async def _run() -> int:
        factory = get_session_factory()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.report_ttl_hours)
        async with factory() as session:
            result = await session.execute(
                select(TaskRow.id, TaskRow.completed_at).where(
                    TaskRow.status.in_(("completed", "failed", "cancelled", "dead")),
                    TaskRow.completed_at.isnot(None),
                    TaskRow.completed_at < cutoff,
                )
            )
            ids = [row[0] for row in result.all()]
            if not ids:
                return 0
            for model in (
                LlmAnalysisResultRow,
                RepairResultRow,
                AssessmentResultRow,
                ScanResultRow,
            ):
                await session.execute(delete(model).where(model.task_id.in_(ids)))
            await session.execute(delete(TaskRow).where(TaskRow.id.in_(ids)))
            await session.commit()
            return len(ids)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run())
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, _run()).result()




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
