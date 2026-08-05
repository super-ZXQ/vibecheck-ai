"""Background task runner —processes download + extract + scan + assess + repair sequentially.

Concurrency model (MVP):
- Only 1 task runs at a time (global asyncio.Lock).
- Pending tasks wait in the SQLite queue.
- After each task completes, the next pending task is automatically picked up.

Pipeline stages (P0-7):
  download 鈫?extract 鈫?scan 鈫?persist scan result 鈫?assess 鈫?persist
  assessment 鈫?generate repair plan 鈫?persist repair plan 鈫?completed 鈫?cleanup

Error handling:
- All errors are mapped to machine-readable error codes.
- error_message is always desensitized —no tokens, paths, or stacks.
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
- P2-3: Each stage is wrapped in asyncio.wait_for with a configurable
  timeout. On timeout, the task is marked failed with a specific
  error code (EXTRACT_TIMEOUT, SCAN_TIMEOUT, ASSESSMENT_TIMEOUT,
  REPAIR_PLAN_TIMEOUT) and temp files are cleaned up.
- Cleanup (temp file deletion) only runs AFTER the thread completes,
  guaranteed by await on asyncio.to_thread.

Repair plan boundary (P0-7):
- Repair plan reads ONLY from persisted scan_results and
  assessment_results (never from temp directory or memory).
- Repair plan must succeed BEFORE mark_completed.
- If repair plan generation fails, the task is marked failed —even if
  scan_results and assessment_results were already persisted.
  The failed task's repair plan API will NOT return residual data.
"""

import asyncio
import logging
import os
import tarfile
from pathlib import Path

from app.core.config import settings
from app.core.error_codes import (
    ASSESSMENT_INTERNAL_ERROR,
    ASSESSMENT_PERSIST_FAILED,
    ASSESSMENT_RESULT_TOO_LARGE,
    ASSESSMENT_TIMEOUT,
    DOWNLOAD_FAILED,
    DOWNLOAD_TOO_LARGE,
    EXTRACT_TIMEOUT,
    EXTRACTION_LIMIT_EXCEEDED,
    GITHUB_RATE_LIMITED,
    INTERNAL_ERROR,
    PRIVATE_REPOSITORY,
    REPAIR_PLAN_INTERNAL_ERROR,
    REPAIR_PLAN_PERSIST_FAILED,
    REPAIR_PLAN_TIMEOUT,
    REPAIR_PLAN_TOO_LARGE,
    REPOSITORY_NOT_FOUND,
    SCAN_INTERNAL_ERROR,
    SCAN_RESULT_PERSIST_FAILED,
    SCAN_RESULT_TOO_LARGE,
    SCAN_TIMEOUT,
    UNSAFE_ARCHIVE,
    get_error_message,
)
from app.core.github import (
    DownloadResult,
    GitHubDownloadError,
    cleanup_download,
    download_tarball,
)
from app.core.safe_extract import (
    ExtractionError,
    ExtractionResult,
    cleanup_temp_dir,
    consume_extract,
    reserve_extract,
    safe_extract_to_temp,
)
from app.scanner.sensitive import scan_directory
from app.services.assessment_service import (
    AssessmentInternalError,
    AssessmentPersistError,
    AssessmentResultTooLargeError,
    run_assessment,
)
from app.services.llm_service import generate_and_save_llm_analysis
from app.services.llm_user_config import get_user_config, pop_user_config
from app.services.repair_service import (
    RepairPlanInternalError,
    RepairPlanPersistError,
    RepairPlanTooLargeError,
    generate_and_save_repair_plan,
)
from app.services.scan_result_service import ScanResultTooLargeError, save_scan_result
from app.services.task_manager import (
    STAGE_ANALYZING,
    STAGE_ASSESSING,
    STAGE_DOWNLOADING,
    STAGE_EXTRACTING,
    STAGE_REPAIRING,
    STAGE_SCANNING,
    get_oldest_pending,
    get_task,
    mark_completed,
    mark_failed,
    mark_running,
)
from app.services.upload_service import LOCAL_UPLOAD_PREFIX, upload_source_dir

logger = logging.getLogger(__name__)

# Global lock —ensures only 1 task runs at a time
_lock = asyncio.Lock()
_is_processing = False


def _map_download_error(error: GitHubDownloadError) -> tuple[str, str]:
    """Map a GitHubDownloadError to an (error_code, safe_message) pair.

    Prefers the structured ``code`` attached at the raise site; falls back
    to substring matching of the message for errors constructed elsewhere
    (e.g. by tests or legacy callers).
    """
    code = getattr(error, "code", None)
    if code in {
        REPOSITORY_NOT_FOUND,
        PRIVATE_REPOSITORY,
        GITHUB_RATE_LIMITED,
        DOWNLOAD_TOO_LARGE,
        DOWNLOAD_FAILED,
    }:
        return code, get_error_message(code)

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


def _stat_directory(path: Path) -> ExtractionResult:
    """Compute file count / total size / top-level dir of a staged upload.

    Walks the full tree (no file cap — the size and count limits are
    enforced during extraction/staging, before this is called).
    Runs in a worker thread via asyncio.to_thread.
    """
    count = 0
    total = 0
    top_level: str | None = None
    try:
        for root, _dirs, files in os.walk(path):
            rel = Path(root).relative_to(path)
            parts = rel.parts
            if parts and top_level is None:
                top_level = parts[0]
            for name in files:
                count += 1
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return ExtractionResult(
        dest_dir=str(path),
        file_count=count,
        total_size=total,
        top_level_dir=top_level,
    )


async def _download_and_extract(
    task_id: str, repo_url: str,
) -> tuple[DownloadResult | None, str | None, ExtractionResult | None]:
    """Stage 1 + 2 for URL-sourced tasks: download tarball and extract it.

    On success returns ``(download_result, extract_dest, extract_result)``.
    On failure marks the task as failed with a desensitized error and
    returns ``(None, None, None)``.
    """
    download_result = None
    extract_dest = None

    # --- Stage 1: Download ---
    mark_running(task_id, STAGE_DOWNLOADING, 10)
    try:
        download_result = await download_tarball(repo_url)
    except GitHubDownloadError as e:
        error_code, safe_msg = _map_download_error(e)
        mark_failed(task_id, error_code, safe_msg)
        return download_result, None, None

    # --- Stage 2: Extract ---
    mark_running(task_id, STAGE_EXTRACTING, 50)
    try:
        # Read the downloaded file into bytes for extraction
        # (max_archive_size is 50MB, acceptable for MVP)
        try:
            tarball_bytes = download_result.temp_file.read_bytes()
        except Exception as e:
            logger.error(
                "Failed to read downloaded archive for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(task_id, DOWNLOAD_FAILED, get_error_message(DOWNLOAD_FAILED))
            return download_result, None, None

        # Reserve the destination path + cancel event BEFORE starting
        # the thread so a stage timeout still knows where partial files
        # were written and can signal the thread to abort.
        pending_extract = reserve_extract(settings.tmp_dir)
        extract_dest = str(pending_extract.dest_dir)

        # P2-3: Wrap extraction in asyncio.wait_for with timeout.
        extract_result = await asyncio.wait_for(
            asyncio.to_thread(
                safe_extract_to_temp,
                tarball_bytes,
                tmp_root=settings.tmp_dir,
            ),
            timeout=settings.extract_timeout,
        )
        extract_dest = extract_result.dest_dir
        return download_result, extract_dest, extract_result
    except TimeoutError:
        logger.error("Extraction timed out for task %s", task_id)
        # Signal the orphaned extraction thread to abort promptly, then
        # give it a short window to release file handles before the
        # finally-block cleanup removes the partial directory.
        pending_extract.cancel_event.set()
        await asyncio.sleep(0.5)
        mark_failed(
            task_id, EXTRACT_TIMEOUT,
            get_error_message(EXTRACT_TIMEOUT),
        )
        return download_result, None, None
    except ExtractionError as e:
        error_code, safe_msg = _map_extraction_error(e)
        mark_failed(task_id, error_code, safe_msg)
        return download_result, None, None
    except tarfile.TarError as e:
        logger.error(
            "Archive is malformed for task %s: %s",
            task_id, type(e).__name__,
        )
        mark_failed(task_id, UNSAFE_ARCHIVE, get_error_message(UNSAFE_ARCHIVE))
        return download_result, None, None
    except Exception as e:
        # Genuine I/O or unexpected failures during extraction are NOT
        # proof of a malicious archive —report them as internal errors.
        logger.error(
            "Extraction failed for task %s: %s", task_id, type(e).__name__
        )
        mark_failed(task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR))
        return download_result, None, None


async def _process_task(task_id: str) -> None:
    """Process a single task: download 鈫?extract 鈫?scan 鈫?assess 鈫?repair 鈫?analyze 鈫?complete.

    Pipeline:
    1. Download tarball from GitHub.
    2. Extract to temp directory safely.
    3. Scan extracted directory with P0-4 scanner.
    4. Persist scan result to scan_results table.
    5. Assess: read persisted scan result, compute score, persist assessment.
    6. Generate repair plan: read persisted scan and assessment, compute
       deterministic repair plan, persist to repair_results.
    7. Generate LLM analysis: read persisted scan result, generate
       plain-language explanations for non-blocking findings, persist
       to llm_analysis_results. This stage is NON-BLOCKING —failures
       fall back to templates and never prevent task completion.
    8. Mark task as completed (only after successful repair plan persistence).

    On any failure, marks the task as failed with a desensitized error.
    Temp files are always cleaned up via try/finally —in success, scan
    failure, persistence failure, assessment failure, and repair plan
    failure paths.
    """
    download_result: DownloadResult | None = None
    extract_dest: str | None = None
    extract_result = None
    cleanup_failed = False
    is_upload = False

    try:
        task = get_task(task_id)
        if task is None:
            logger.error("Task %s not found", task_id)
            return

        # Upload-sourced tasks skip GitHub download; their content was
        # already validated and staged under upload-{task_id} by the
        # upload endpoint. All subsequent stages are identical.
        is_upload = task.repo_url.startswith(LOCAL_UPLOAD_PREFIX)

        if is_upload:
            mark_running(task_id, STAGE_EXTRACTING, 50)
            data_dir = upload_source_dir(task_id)
            if not data_dir.is_dir():
                logger.error(
                    "Upload source directory missing for task %s", task_id
                )
                mark_failed(task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR))
                return
            extract_dest = str(data_dir)
            extract_result = await asyncio.to_thread(_stat_directory, data_dir)
        else:
            download_result, extract_dest, extract_result = (
                await _download_and_extract(task_id, task.repo_url)
            )
            if extract_result is None or extract_dest is None:
                return

        # --- Stage 3: Scan ---
        # scan_directory is synchronous (CPU-bound). Run it in a thread
        # via asyncio.to_thread so the event loop stays responsive.
        # P2-3: Wrap in asyncio.wait_for with scan_timeout.
        mark_running(task_id, STAGE_SCANNING, 80)
        try:
            scan_result = await asyncio.wait_for(
                asyncio.to_thread(
                    scan_directory,
                    Path(extract_dest),
                ),
                timeout=settings.scan_timeout,
            )
        except TimeoutError:
            logger.error("Scan timed out for task %s", task_id)
            mark_failed(
                task_id, SCAN_TIMEOUT,
                get_error_message(SCAN_TIMEOUT),
            )
            return
        except Exception as e:
            # Log only the exception type —never str(exc), repr(exc),
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
        # Persist BEFORE marking completed —if persistence fails,
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
            # Log only the exception type —never str(exc) or DB details.
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
            # Log only the exception type —never str(exc) or DB errors.
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
        # Assessment MUST succeed before mark_completed —if it fails,
        # the task is marked failed even though scan_results was persisted.
        # The failed task's assessment API will NOT return residual data.
        mark_running(task_id, STAGE_ASSESSING, 90)
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    run_assessment,
                    task_id,
                ),
                timeout=settings.assess_timeout,
            )
        except TimeoutError:
            logger.error("Assessment timed out for task %s", task_id)
            mark_failed(
                task_id, ASSESSMENT_TIMEOUT,
                get_error_message(ASSESSMENT_TIMEOUT),
            )
            return
        except AssessmentResultTooLargeError as e:
            # Serialized assessment_json exceeded assessment_max_json_bytes.
            # Log only the exception type —never str(exc) or DB details.
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
            # Log only the exception type —never str(exc) or stack traces.
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
            # Log only the exception type —never str(exc) or DB errors.
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
            # Log only the exception type —never str(exc) or DB errors.
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
        # Repair plan MUST succeed before mark_completed —if it fails,
        # the task is marked failed even though scan_results and
        # assessment_results were already persisted.
        # The failed task's repair plan API will NOT return residual data.
        mark_running(task_id, STAGE_REPAIRING, 95)
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    generate_and_save_repair_plan,
                    task_id,
                ),
                timeout=settings.repair_plan_timeout,
            )
        except TimeoutError:
            logger.error("Repair plan timed out for task %s", task_id)
            mark_failed(
                task_id, REPAIR_PLAN_TIMEOUT,
                get_error_message(REPAIR_PLAN_TIMEOUT),
            )
            return
        except RepairPlanTooLargeError as e:
            # Serialized repair_json exceeded repair_max_json_bytes.
            # Log only the exception type —never str(exc) or DB details.
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
            # Log only the exception type —never str(exc) or stack traces.
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
            # Log only the exception type —never str(exc) or DB errors.
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
            # Log only the exception type —never str(exc) or DB errors.
            logger.error(
                "Repair plan failed for task %s: %s",
                task_id, type(e).__name__,
            )
            mark_failed(
                task_id, REPAIR_PLAN_INTERNAL_ERROR,
                get_error_message(REPAIR_PLAN_INTERNAL_ERROR),
            )
            return

        # --- Stage 7: LLM analysis (NON-BLOCKING) ---
        # Generate plain-language explanations and repair instructions
        # for non-blocking findings. This stage reads ONLY from the
        # persisted scan_results table.
        # This stage NEVER fails the task —generate_and_save_llm_analysis
        # catches all internal errors and falls back to templates.
        # LLM analysis is an enhancement, not a requirement. Assessment
        # scoring (P0-6) is completely independent and unaffected.
        mark_running(task_id, STAGE_ANALYZING, 97)
        # A caller-supplied per-task LLM config (X-LLM-* headers) enables
        # the analysis stage with the caller's own credentials even when
        # the server has no LLM configured. Pop after the stage; the
        # finally block also pops it as a release safety net.
        user_llm_config = get_user_config(task_id)
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    generate_and_save_llm_analysis,
                    task_id,
                    user_llm_config,
                ),
                timeout=settings.llm_analysis_timeout,
            )
        except TimeoutError:
            # Non-blocking —LLM analysis timeout doesn't fail the task.
            logger.warning(
                "LLM analysis timed out for task %s (non-blocking, "
                "continuing to completion)",
                task_id,
            )
        except Exception as e:
            # This should never happen —generate_and_save_llm_analysis
            # is designed to never raise. But if it does, log and continue.
            logger.warning(
                "LLM analysis stage failed for task %s: %s "
                "(non-blocking, continuing to completion)",
                task_id, type(e).__name__,
            )
        finally:
            # Release the caller-supplied LLM credentials for this task.
            pop_user_config(task_id)

        # --- Stage 8: Complete with summary ---
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
            top_level_dir=(
                extract_result.top_level_dir
                or ("本地上传" if is_upload else "unknown")
            ),
        )

    except Exception as e:
        logger.error("Unexpected error in task %s: %s", task_id, type(e).__name__)
        mark_failed(task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR))

    finally:
        # --- Always clean up temp files ---
        # Release any unconsumed extraction reservation (e.g. when the
        # extraction thread was interrupted before consuming it).
        consume_extract()

        # Release any caller-supplied LLM credentials that were never
        # consumed (e.g. the task failed before the LLM stage).
        pop_user_config(task_id)

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
                "Cleanup failed for task %s —temp files may remain", task_id
            )


async def trigger_queue_processing() -> None:
    """Trigger processing of the task queue.

    If no processing is currently running, picks up pending tasks one by one.
    If processing is already running, this is a no-op (the running processor
    will pick up new pending tasks).

    Safe to call multiple times —only one processor runs at a time.
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
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(trigger_queue_processing())


def reset_runner_state() -> None:
    """Reset the runner state —for testing only."""
    global _is_processing
    _is_processing = False
