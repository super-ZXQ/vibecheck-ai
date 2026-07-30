"""Background task runner — processes download + extract + scan + assess + repair sequentially.

Concurrency model (MVP):
- Only 1 task runs at a time (global asyncio.Lock).
- Pending tasks wait in the SQLite queue.
- After each task completes, the next pending task is automatically picked up.

Pipeline stages (P0-7):
  download → extract → scan → persist scan result → assess → persist
  assessment → generate repair plan → persist repair plan → completed → cleanup

Error handling:
- All errors are mapped to machine-readable error codes.
- error_message is always desensitized — no tokens, paths, or stacks.
- Temp files are always cleaned up via try/finally.
- No code from the repository is ever executed.
- Scanner exceptions are caught and mapped to SCAN_INTERNAL_ERROR.
- Scan persistence exceptions are caught and mapped to SCAN_RESULT_PERSIST_FAILED.
- Oversized scan results are caught and mapped to SCAN_RESULT_TOO_LARGE.
- Assessment exceptions are caught and mapped to ASSESSMENT_INTERNAL_ERROR
  or ASSESSMENT_PERSIST_FAILED or ASSESSMENT_RESULT_TOO_LARGE.
- Repair plan exceptions are caught and mapped to REPAIR_PLAN_INTERNAL_ERROR
  or REPAIR_PLAN_PERSIST_FAILED or REPAIR_PLAN_TOO_LARGE.
- Logs never contain str(exc), repr(exc), repo content, or absolute paths.

Non-blocking I/O (P0-5/P0-6/P0-7):
- scan_directory, save_scan_result, run_assessment, and
  generate_and_save_repair_plan are synchronous, CPU/IO-bound operations.
  They are executed via asyncio.to_thread so the FastAPI event loop
  stays responsive.
- No asyncio.wait_for or hard timeout — relies on P0-4 built-in limits.
- Cleanup (temp file deletion) only runs AFTER the thread completes,
  guaranteed by await on asyncio.to_thread.

Repair plan boundary (P0-7):
- Repair plan reads ONLY from persisted scan_results and
  assessment_results (never from temp directory or memory).
- Repair plan must succeed BEFORE mark_completed.
- If repair plan generation fails, the task is marked failed — even if
  scan_results and assessment_results were already persisted.
  The failed task's repair plan API will NOT return residual data.
"""

import asyncio
import logging
from pathlib import Path

from app.core.config import settings
from app.core.error_codes import (
    ASSESSMENT_INTERNAL_ERROR,
    ASSESSMENT_PERSIST_FAILED,
    ASSESSMENT_RESULT_TOO_LARGE,
    DOWNLOAD_FAILED,
    DOWNLOAD_TOO_LARGE,
    EXTRACTION_LIMIT_EXCEEDED,
    GITHUB_RATE_LIMITED,
    INTERNAL_ERROR,
    PRIVATE_REPOSITORY,
    REPAIR_PLAN_INTERNAL_ERROR,
    REPAIR_PLAN_PERSIST_FAILED,
    REPAIR_PLAN_TOO_LARGE,
    REPOSITORY_NOT_FOUND,
    UNSAFE_ARCHIVE,
    CLEANUP_FAILED,
    SCAN_INTERNAL_ERROR,
    SCAN_RESULT_PERSIST_FAILED,
    SCAN_RESULT_TOO_LARGE,
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
from app.scanner.sensitive import scan_directory
from app.services.assessment_service import (
    AssessmentInternalError,
    AssessmentPersistError,
    AssessmentResultTooLargeError,
    run_assessment,
)
from app.services.repair_service import (
    RepairPlanInternalError,
    RepairPlanPersistError,
    RepairPlanTooLargeError,
    generate_and_save_repair_plan,
)
from app.services.scan_result_service import save_scan_result, ScanResultTooLargeError
from app.services.task_manager import (
    STAGE_ASSESSING,
    STAGE_DOWNLOADING,
    STAGE_EXTRACTING,
    STAGE_REPAIRING,
    STAGE_SCANNING,
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
    """Process a single task: download → extract → scan → assess → repair → complete.

    Pipeline:
    1. Download tarball from GitHub.
    2. Extract to temp directory safely.
    3. Scan extracted directory with P0-4 scanner.
    4. Persist scan result to scan_results table.
    5. Assess: read persisted scan result, compute score, persist assessment.
    6. Generate repair plan: read persisted scan and assessment, compute
       deterministic repair plan, persist to repair_results.
    7. Mark task as completed (only after successful repair plan persistence).

    On any failure, marks the task as failed with a desensitized error.
    Temp files are always cleaned up via try/finally — in success, scan
    failure, persistence failure, assessment failure, and repair plan
    failure paths.
    """
    download_result = None
    extract_dest = None
    extract_result = None
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

        # --- Stage 3: Scan ---
        # scan_directory is synchronous (CPU-bound). Run it in a thread
        # via asyncio.to_thread so the event loop stays responsive.
        # No asyncio.wait_for or hard timeout — relies on P0-4 built-in
        # limits (file size, ignore dirs, finding cap, etc.).
        # The await guarantees the thread has completed before cleanup.
        mark_running(task_id, STAGE_SCANNING, 80)
        try:
            scan_result = await asyncio.to_thread(
                scan_directory,
                Path(extract_dest),
            )
        except Exception as e:
            # Log only the exception type — never str(exc), repr(exc),
            # stack traces, or repo content.
            logger.error(
                "Scan failed for task %s: %s", task_id, type(e).__name__
            )
            mark_failed(
                task_id, SCAN_INTERNAL_ERROR,
                get_error_message(SCAN_INTERNAL_ERROR),
            )
            return

        # --- Stage 4: Persist scan result ---
        # Persist BEFORE marking completed — if persistence fails,
        # the task must NOT be marked as completed.
        # save_scan_result is synchronous (CPU/IO-bound). Run it in a
        # thread via asyncio.to_thread so the event loop stays responsive.
        # The await guarantees the thread has completed before cleanup.
        try:
            await asyncio.to_thread(
                save_scan_result,
                task_id,
                scan_result,
            )
        except ScanResultTooLargeError as e:
            # Serialized result_json exceeded scan_max_result_json_bytes.
            # Log only the exception type — never str(exc) or DB details.
            logger.error(
                "Scan result too large for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, SCAN_RESULT_TOO_LARGE,
                get_error_message(SCAN_RESULT_TOO_LARGE),
            )
            return
        except Exception as e:
            # Log only the exception type — never str(exc) or DB errors.
            logger.error(
                "Scan result persistence failed for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, SCAN_RESULT_PERSIST_FAILED,
                get_error_message(SCAN_RESULT_PERSIST_FAILED),
            )
            return

        # --- Stage 5: Assess ---
        # Assessment reads ONLY from the persisted scan_results table
        # (never from temp directory). It computes a deterministic score
        # and persists it to assessment_results.
        # run_assessment is synchronous (CPU/IO-bound). Run it in a thread
        # via asyncio.to_thread so the event loop stays responsive.
        # The await guarantees the thread has completed before cleanup.
        # Assessment MUST succeed before mark_completed — if it fails,
        # the task is marked failed even though scan_results was persisted.
        # The failed task's assessment API will NOT return residual data.
        mark_running(task_id, STAGE_ASSESSING, 90)
        try:
            await asyncio.to_thread(
                run_assessment,
                task_id,
            )
        except AssessmentResultTooLargeError as e:
            # Serialized assessment_json exceeded assessment_max_json_bytes.
            # Log only the exception type — never str(exc) or DB details.
            logger.error(
                "Assessment result too large for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, ASSESSMENT_RESULT_TOO_LARGE,
                get_error_message(ASSESSMENT_RESULT_TOO_LARGE),
            )
            return
        except AssessmentInternalError as e:
            # Reading or parsing the persisted scan result failed, or
            # assessment computation failed.
            # Log only the exception type — never str(exc) or stack traces.
            logger.error(
                "Assessment internal error for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, ASSESSMENT_INTERNAL_ERROR,
                get_error_message(ASSESSMENT_INTERNAL_ERROR),
            )
            return
        except AssessmentPersistError as e:
            # SQLite assessment_results write failed.
            # Log only the exception type — never str(exc) or DB errors.
            logger.error(
                "Assessment persistence failed for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, ASSESSMENT_PERSIST_FAILED,
                get_error_message(ASSESSMENT_PERSIST_FAILED),
            )
            return
        except Exception as e:
            # Catch-all for any unexpected error not covered above.
            # This is an internal error, NOT a persistence error.
            # SQLite save failures are already caught by
            # AssessmentPersistError above. Other unknown exceptions
            # belong to internal computation or orchestration.
            # Log only the exception type — never str(exc) or DB errors.
            logger.error(
                "Assessment failed for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, ASSESSMENT_INTERNAL_ERROR,
                get_error_message(ASSESSMENT_INTERNAL_ERROR),
            )
            return

        # --- Stage 6: Generate repair plan ---
        # Repair plan reads ONLY from the persisted scan_results and
        # assessment_results tables (never from temp directory or memory).
        # It computes a deterministic repair plan and persists it to
        # repair_results.
        # generate_and_save_repair_plan is synchronous (CPU/IO-bound).
        # Run it in a thread via asyncio.to_thread so the event loop
        # stays responsive.
        # Repair plan MUST succeed before mark_completed — if it fails,
        # the task is marked failed even though scan_results and
        # assessment_results were already persisted.
        # The failed task's repair plan API will NOT return residual data.
        mark_running(task_id, STAGE_REPAIRING, 95)
        try:
            await asyncio.to_thread(
                generate_and_save_repair_plan,
                task_id,
            )
        except RepairPlanTooLargeError as e:
            # Serialized repair_json exceeded repair_max_json_bytes.
            # Log only the exception type — never str(exc) or DB details.
            logger.error(
                "Repair plan too large for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, REPAIR_PLAN_TOO_LARGE,
                get_error_message(REPAIR_PLAN_TOO_LARGE),
            )
            return
        except RepairPlanInternalError as e:
            # Reading or parsing the persisted scan/assessment failed,
            # consistency validation failed, or repair plan computation
            # failed.
            # Log only the exception type — never str(exc) or stack traces.
            logger.error(
                "Repair plan internal error for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, REPAIR_PLAN_INTERNAL_ERROR,
                get_error_message(REPAIR_PLAN_INTERNAL_ERROR),
            )
            return
        except RepairPlanPersistError as e:
            # SQLite repair_results write failed.
            # Log only the exception type — never str(exc) or DB errors.
            logger.error(
                "Repair plan persistence failed for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, REPAIR_PLAN_PERSIST_FAILED,
                get_error_message(REPAIR_PLAN_PERSIST_FAILED),
            )
            return
        except Exception as e:
            # Catch-all for any unexpected error not covered above.
            # Log only the exception type — never str(exc) or DB errors.
            logger.error(
                "Repair plan failed for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, REPAIR_PLAN_INTERNAL_ERROR,
                get_error_message(REPAIR_PLAN_INTERNAL_ERROR),
            )
            return

        # --- Stage 7: Complete with summary ---
        # Only reached after scan result, assessment, AND repair plan are
        # successfully persisted. The scan_summary is fetched from
        # scan_results by to_response(). The security_score and
        # security_verdict are fetched from assessment_results by
        # to_response(). The repair_plan_available and repair_plan_url
        # are fetched from repair_results by to_response().
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
        # Cleanup runs in ALL paths: success, scan failure, persistence
        # failure, and assessment failure.
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
