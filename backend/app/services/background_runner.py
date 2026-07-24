"""Background task runner — processes download + extraction sequentially.

Concurrency model (MVP):
- Only 1 task runs at a time (global asyncio.Lock).
- Pending tasks wait in the SQLite queue.
- After each task completes, the next pending task is automatically picked up.

Error handling:
- All errors are mapped to machine-readable error codes.
- error_message is always desensitized — no tokens, paths, or stacks.
- Temp files are always cleaned up via try/finally.
- No code from the repository is ever executed.
"""

import asyncio
import logging
from pathlib import Path

from app.core.config import settings
from app.core.error_codes import (
    DOWNLOAD_FAILED,
    DOWNLOAD_TOO_LARGE,
    EXTRACTION_LIMIT_EXCEEDED,
    GITHUB_RATE_LIMITED,
    INTERNAL_ERROR,
    PRIVATE_REPOSITORY,
    REPOSITORY_NOT_FOUND,
    UNSAFE_ARCHIVE,
    CLEANUP_FAILED,
    get_error_message,
)
from app.core.github import (
    GitHubDownloadError,
    download_tarball,
    cleanup_download,
)
from app.core.safe_extract import (
    ExtractionError,
    safe_extract_to_temp,
    cleanup_temp_dir,
)
from app.services.task_manager import (
    STAGE_DOWNLOADING,
    STAGE_EXTRACTING,
    mark_running,
    mark_completed,
    mark_failed,
    get_oldest_pending,
    get_task,
)

logger = logging.getLogger(__name__)

# Global lock — ensures only 1 task runs at a time
_lock = asyncio.Lock()
_is_processing = False


def _map_download_error(error: GitHubDownloadError) -> tuple[str, str]:
    """Map a GitHubDownloadError to an (error_code, safe_message) pair."""
    msg = str(error).lower()
    if "not found" in msg or "does not exist" in msg:
        return REPOSITORY_NOT_FOUND, get_error_message(REPOSITORY_NOT_FOUND)
    if "private" in msg:
        return PRIVATE_REPOSITORY, get_error_message(PRIVATE_REPOSITORY)
    if "rate limit" in msg or "429" in msg or "403" in msg:
        return GITHUB_RATE_LIMITED, get_error_message(GITHUB_RATE_LIMITED)
    if "too large" in msg or "content-length" in msg or "streaming" in msg:
        return DOWNLOAD_TOO_LARGE, get_error_message(DOWNLOAD_TOO_LARGE)
    return DOWNLOAD_FAILED, get_error_message(DOWNLOAD_FAILED)


def _map_extraction_error(error: ExtractionError) -> tuple[str, str]:
    """Map an ExtractionError to an (error_code, safe_message) pair."""
    msg = str(error).lower()
    if "too large" in msg or "exceeds limit" in msg or "too many files" in msg:
        return EXTRACTION_LIMIT_EXCEEDED, get_error_message(EXTRACTION_LIMIT_EXCEEDED)
    return UNSAFE_ARCHIVE, get_error_message(UNSAFE_ARCHIVE)


async def _process_task(task_id: str) -> None:
    """Process a single task: download → extract → cleanup → summarize.

    On any failure, marks the task as failed with a desensitized error.
    Temp files are always cleaned up via try/finally.
    """
    download_result = None
    extract_dest = None
    cleanup_failed = False

    try:
        task = get_task(task_id)
        if task is None:
            logger.error("Task %s not found", task_id)
            return

        # --- Stage 1: Download ---
        mark_running(task_id, STAGE_DOWNLOADING, 10)
        try:
            download_result = await download_tarball(task.repo_url)
        except GitHubDownloadError as e:
            error_code, safe_msg = _map_download_error(e)
            mark_failed(task_id, error_code, safe_msg)
            return

        # --- Stage 2: Extract ---
        mark_running(task_id, STAGE_EXTRACTING, 50)
        try:
            # Read the downloaded file into bytes for extraction
            # (max_archive_size is 50MB, acceptable for MVP)
            tarball_bytes = download_result.temp_file.read_bytes()
            extract_result = safe_extract_to_temp(
                tarball_bytes,
                tmp_root=settings.tmp_dir,
            )
            extract_dest = extract_result.dest_dir
        except ExtractionError as e:
            error_code, safe_msg = _map_extraction_error(e)
            mark_failed(task_id, error_code, safe_msg)
            return
        except Exception as e:
            logger.error("Extraction failed for task %s: %s", task_id, type(e).__name__)
            mark_failed(task_id, UNSAFE_ARCHIVE, get_error_message(UNSAFE_ARCHIVE))
            return

        # --- Stage 3: Complete with summary ---
        mark_completed(
            task_id,
            file_count=extract_result.file_count,
            total_size=extract_result.total_size,
            top_level_dir=extract_result.top_level_dir or "unknown",
        )

    except Exception as e:
        logger.error("Unexpected error in task %s: %s", task_id, type(e).__name__)
        mark_failed(task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR))

    finally:
        # --- Always clean up temp files ---
        # Clean up download file
        if download_result is not None:
            try:
                cleanup_download(download_result.temp_file)
            except Exception:
                logger.error("Failed to clean up download file for task %s", task_id)
                cleanup_failed = True

        # Clean up extraction directory
        if extract_dest is not None:
            try:
                cleanup_temp_dir(extract_dest)
            except Exception:
                logger.error("Failed to clean up extraction dir for task %s", task_id)
                cleanup_failed = True

        # If cleanup failed but task was completed, log it (task result is still valid)
        if cleanup_failed:
            logger.warning(
                "Cleanup failed for task %s — temp files may remain", task_id
            )


async def trigger_queue_processing() -> None:
    """Trigger processing of the task queue.

    If no processing is currently running, picks up pending tasks one by one.
    If processing is already running, this is a no-op (the running processor
    will pick up new pending tasks).

    Safe to call multiple times — only one processor runs at a time.
    """
    global _is_processing

    async with _lock:
        if _is_processing:
            return
        _is_processing = True

    try:
        while True:
            next_task = get_oldest_pending()
            if next_task is None:
                break
            await _process_task(next_task.id)
    except Exception as e:
        logger.error("Queue processing error: %s", type(e).__name__)
    finally:
        async with _lock:
            _is_processing = False
        # Re-trigger in case a task was added during the gap
        if get_oldest_pending() is not None:
            asyncio.create_task(trigger_queue_processing())


def reset_runner_state() -> None:
    """Reset the runner state — for testing only."""
    global _is_processing
    _is_processing = False
