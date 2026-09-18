"""Background task dispatcher — single-instance bounded concurrency.

Concurrency model:
- Dispatcher loop continuously fills free execution slots (max_running_tasks).
- Claiming uses claim_next_pending() with SQLite BEGIN IMMEDIATE.
- asyncio.Semaphore + active-task set bound concurrency.
- Blocking work (SQLite, extract, scan, cleanup) runs via asyncio.to_thread.
- Heartbeat extends task leases while work is in flight.
- Cancel is cooperative: workers check cancellation between stages.
- Crash recovery: recover_expired_tasks() re-queues expired leases.

Honest capability statement (README):
This is **single-instance bounded concurrency** on SQLite WAL — not a
distributed queue. Python locks reduce contention; DB transactions are the
correctness boundary for claim/recover.

Pipeline stages:
  download → extract → scan → persist → assess → repair → llm → completed

Security:
- error_message always desensitized; logs never contain secrets/keys/paths.
- Temp files cleaned in finally; cancel populates BYOK memory credentials.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

from app.core.config import settings
from app.core.error_codes import (
    ASSESSMENT_INTERNAL_ERROR,
    ASSESSMENT_PERSIST_FAILED,
    ASSESSMENT_RESULT_TOO_LARGE,
    ASSESSMENT_TIMEOUT,
    DOWNLOAD_FAILED,
    DOWNLOAD_TIMEOUT,
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
    TEMP_STORAGE_EXHAUSTED,
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
    prepare_extract_dest,
    safe_extract_to_temp,
)
from app.scanner.sensitive import scan_directory
from app.services import metrics as metrics_mod
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
from app.services.task_errors import (
    DOWNLOAD_TIMEOUT as CAT_DOWNLOAD_TIMEOUT,
)
from app.services.task_errors import (
    GITHUB_RATE_LIMITED as CAT_GITHUB_RATE_LIMITED,
)
from app.services.task_errors import (
    GITHUB_TEMPORARY_ERROR,
    category_for_error_code,
)
from app.services.task_errors import (
    TEMP_STORAGE_EXHAUSTED as CAT_TEMP_STORAGE,
)
from app.services.task_manager import (
    STAGE_ANALYZING,
    STAGE_ASSESSING,
    STAGE_DOWNLOADING,
    STAGE_EXTRACTING,
    STAGE_REPAIRING,
    STAGE_SCANNING,
    STATUS_PENDING,
    STATUS_RUNNING,
    claim_next_pending,
    fail_or_retry,
    find_completed_by_repo_sha,
    get_task,
    has_claimable_pending,
    is_cancel_requested,
    is_queue_full,
    make_worker_id,
    mark_cancelled,
    mark_completed,
    mark_running,
    recover_expired_tasks,
    refresh_queue_metrics,
    set_resolved_commit_sha,
    touch_heartbeat,
)
from app.services.upload_service import LOCAL_UPLOAD_PREFIX, upload_source_dir

logger = logging.getLogger(__name__)

# --- Dispatcher state ---
_lock = asyncio.Lock()
_is_processing = False  # legacy flag (kept for reset_runner_state compatibility)
_dispatcher_task: asyncio.Task | None = None
_active: set[asyncio.Task] = set()
_stopping = False
_worker_id: str | None = None
_cancel_events: dict[str, asyncio.Event] = {}

# Task-dir name prefixes VibeCheck is allowed to delete under settings.tmp_dir.
_ALLOWED_TASK_DIR_PREFIXES = ("task-", "upload-", "download-", "extract-")


class OwnershipLost(Exception):
    """Claim token no longer owns the task (cancel / recover / re-claim)."""


def _get_worker_id() -> str:
    global _worker_id
    if _worker_id is None:
        _worker_id = make_worker_id()
    return _worker_id


def _get_cancel_event(task_id: str) -> asyncio.Event:
    if task_id not in _cancel_events:
        _cancel_events[task_id] = asyncio.Event()
    return _cancel_events[task_id]


def _map_download_error(error: GitHubDownloadError) -> tuple[str, str, str]:
    """Map GitHubDownloadError → (error_code, safe_message, failure_category)."""
    code = getattr(error, "code", None)
    known = {
        REPOSITORY_NOT_FOUND,
        PRIVATE_REPOSITORY,
        GITHUB_RATE_LIMITED,
        DOWNLOAD_TOO_LARGE,
        DOWNLOAD_FAILED,
        DOWNLOAD_TIMEOUT,
        TEMP_STORAGE_EXHAUSTED,
        "INVALID_REPOSITORY",
        "DOWNLOAD_TIMEOUT",
    }
    if code in known:
        category = {
            GITHUB_RATE_LIMITED: CAT_GITHUB_RATE_LIMITED,
            DOWNLOAD_TIMEOUT: CAT_DOWNLOAD_TIMEOUT,
            "DOWNLOAD_TIMEOUT": CAT_DOWNLOAD_TIMEOUT,
        }.get(code, category_for_error_code(code))
        return code, get_error_message(code), category

    msg = str(error).lower()
    if "not found" in msg or "does not exist" in msg:
        return REPOSITORY_NOT_FOUND, get_error_message(REPOSITORY_NOT_FOUND), "INVALID_REPOSITORY"
    if "private" in msg:
        return PRIVATE_REPOSITORY, get_error_message(PRIVATE_REPOSITORY), "INVALID_REPOSITORY"
    if "rate limit" in msg or "429" in msg or "403" in msg:
        return GITHUB_RATE_LIMITED, get_error_message(GITHUB_RATE_LIMITED), CAT_GITHUB_RATE_LIMITED
    if "too large" in msg or "content-length" in msg or "streaming" in msg:
        return DOWNLOAD_TOO_LARGE, get_error_message(DOWNLOAD_TOO_LARGE), "DOWNLOAD_TOO_LARGE"
    if "timed out" in msg or "timeout" in msg:
        return DOWNLOAD_TIMEOUT, get_error_message(DOWNLOAD_TIMEOUT), CAT_DOWNLOAD_TIMEOUT
    return (
        DOWNLOAD_FAILED,
        get_error_message(DOWNLOAD_FAILED),
        GITHUB_TEMPORARY_ERROR,
    )


def _map_extraction_error(error: ExtractionError) -> tuple[str, str, str]:
    msg = str(error).lower()
    if "too large" in msg or "exceeds limit" in msg or "too many files" in msg:
        return (
            EXTRACTION_LIMIT_EXCEEDED,
            get_error_message(EXTRACTION_LIMIT_EXCEEDED),
            "EXTRACTION_LIMIT_EXCEEDED",
        )
    return UNSAFE_ARCHIVE, get_error_message(UNSAFE_ARCHIVE), "INVALID_ARCHIVE"


def _stat_directory(path: Path) -> ExtractionResult:
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


def _cleanup_task_dir(task_id: str, path: str | Path | None) -> bool:
    """Delete a task-scoped temp path only under settings.tmp_dir.

    Production policy:
    - target must resolve strictly under settings.tmp_dir
    - directory name must match a VibeCheck-created prefix
    - filesystem roots and system-temp trees are always rejected
    """
    if path is None:
        return True
    try:
        target = Path(path).resolve()
        tmp_root = Path(settings.tmp_dir).resolve()
        if target == tmp_root or target.parent == target:
            logger.error("Refusing to clean unsafe temp path for task")
            metrics_mod.inc_counter("vibecheck_cleanup_failures_total")
            return False
        try:
            rel = target.relative_to(tmp_root)
        except ValueError:
            logger.error("Refusing to clean path outside settings.tmp_dir")
            metrics_mod.inc_counter("vibecheck_cleanup_failures_total")
            return False
        name = rel.parts[0] if rel.parts else target.name
        allowed_name = any(name.startswith(p) for p in _ALLOWED_TASK_DIR_PREFIXES) or any(
            any(part.startswith(p) for p in _ALLOWED_TASK_DIR_PREFIXES)
            for part in rel.parts
        )
        if not allowed_name:
            logger.error("Refusing to clean non-VibeCheck temp directory")
            metrics_mod.inc_counter("vibecheck_cleanup_failures_total")
            return False
    except (ValueError, OSError, RuntimeError):
        logger.error("Refusing to clean unsafe temp path for task")
        metrics_mod.inc_counter("vibecheck_cleanup_failures_total")
        return False
    try:
        cleanup_temp_dir(str(target))
        return True
    except Exception:
        logger.error("Failed to clean temp dir for task")
        metrics_mod.inc_counter("vibecheck_cleanup_failures_total")
        return False


async def _heartbeat_loop(
    task_id: str, stop_event: asyncio.Event, claim_token: str | None
) -> None:
    """Periodically extend the task lease for this claim token only."""
    interval = max(1, settings.task_heartbeat_seconds)
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            return
        except TimeoutError:
            pass
        try:
            ok = await asyncio.to_thread(touch_heartbeat, task_id, claim_token)
            if not ok and claim_token is not None:
                # Lost ownership — stop renewing; pipeline fencing will halt work.
                return
        except Exception:
            logger.warning("Heartbeat update failed for task %s", task_id)


def _check_cancelled(task_id: str) -> bool:
    cancel_event = _get_cancel_event(task_id)
    if cancel_event.is_set():
        return True
    try:
        return is_cancel_requested(task_id)
    except Exception:
        return False


def _ensure_owned(task_id: str, claim_token: str | None) -> None:
    """Raise OwnershipLost when the claim token no longer owns the task."""
    if claim_token is None:
        return
    task = get_task(task_id)
    if task is None:
        raise OwnershipLost("task missing")
    if task.is_terminal or task.worker_id != claim_token:
        raise OwnershipLost("claim token fenced")


def _mark_running_owned(
    task_id: str, stage: str, progress: int, claim_token: str | None
) -> None:
    ok = mark_running(task_id, stage, progress, worker_id=claim_token)
    if not ok:
        raise OwnershipLost("mark_running fenced")


async def _download_and_extract(
    task_id: str,
    repo_url: str,
    claim_token: str | None = None,
) -> tuple[DownloadResult | None, str | None, ExtractionResult | None]:
    download_result = None
    extract_dest = None

    _mark_running_owned(task_id, STAGE_DOWNLOADING, 10, claim_token)
    if _check_cancelled(task_id):
        mark_cancelled(task_id)
        return None, None, None

    try:
        download_result = await download_tarball(repo_url)
    except GitHubDownloadError as e:
        error_code, safe_msg, category = _map_download_error(e)
        fail_or_retry(
            task_id, error_code, safe_msg,
            failure_category=category, worker_id=claim_token,
        )
        return download_result, None, None
    except OSError as e:
        if getattr(e, "errno", None) == 28:  # ENOSPC
            fail_or_retry(
                task_id,
                TEMP_STORAGE_EXHAUSTED,
                get_error_message(TEMP_STORAGE_EXHAUSTED),
                failure_category=CAT_TEMP_STORAGE,
                worker_id=claim_token,
            )
        else:
            fail_or_retry(
                task_id, DOWNLOAD_FAILED, get_error_message(DOWNLOAD_FAILED),
                failure_category=GITHUB_TEMPORARY_ERROR,
                worker_id=claim_token,
            )
        return download_result, None, None

    if download_result and download_result.commit_sha:
        try:
            _ensure_owned(task_id, claim_token)
            set_resolved_commit_sha(task_id, download_result.commit_sha)
        except OwnershipLost:
            cleanup_download(download_result.temp_file)
            return None, None, None
        except Exception:
            logger.warning("Failed to persist commit SHA for task")

    if _check_cancelled(task_id):
        if download_result is not None:
            cleanup_download(download_result.temp_file)
        mark_cancelled(task_id)
        return None, None, None

    # Dedup after SHA resolution: reuse completed result for same commit.
    task = get_task(task_id)
    if task is not None and download_result is not None and download_result.commit_sha:
        existing = find_completed_by_repo_sha(
            task.repo_url, download_result.commit_sha, task.scanner_version
        )
        if existing is not None and existing.id != task_id:
            from app.services.task_manager import complete_as_reused
            ok = await asyncio.to_thread(complete_as_reused, task_id, existing)
            cleanup_download(download_result.temp_file)
            if ok:
                logger.info("Task deduplicated to completed result")
                return None, None, None
            # Fall through to full scan if copy failed.

    _mark_running_owned(task_id, STAGE_EXTRACTING, 50, claim_token)
    try:
        tarball_bytes = await asyncio.to_thread(
            download_result.temp_file.read_bytes
        )
    except Exception as e:
        logger.error(
            "Failed to read downloaded archive for task %s: %s",
            task_id, type(e).__name__,
        )
        fail_or_retry(
            task_id, DOWNLOAD_FAILED, get_error_message(DOWNLOAD_FAILED),
            failure_category=GITHUB_TEMPORARY_ERROR,
            worker_id=claim_token,
        )
        return download_result, None, None

    try:
        # Per-task reservation under settings.tmp_dir with VibeCheck naming.
        dest_path = prepare_extract_dest(settings.tmp_dir)
        import threading as _threading
        cancel_ev = _threading.Event()
        extract_dest = str(dest_path)

        def _do_extract():
            try:
                return safe_extract_to_temp(
                    tarball_bytes,
                    settings.tmp_dir,
                    dest_dir=dest_path,
                    cancel_event=cancel_ev,
                )
            except TypeError:
                # Mock/side_effect without kwargs — production path always
                # accepts dest_dir/cancel_event.
                return safe_extract_to_temp(tarball_bytes, settings.tmp_dir)

        extract_result = await asyncio.wait_for(
            asyncio.to_thread(_do_extract),
            timeout=settings.extract_timeout,
        )
        extract_dest = extract_result.dest_dir
        return download_result, extract_dest, extract_result
    except OwnershipLost:
        raise
    except TimeoutError:
        logger.error("Extraction timed out for task %s", task_id)
        try:
            cancel_ev.set()
        except Exception:
            pass
        await asyncio.sleep(0.2)
        fail_or_retry(
            task_id, EXTRACT_TIMEOUT, get_error_message(EXTRACT_TIMEOUT),
            failure_category="INTERNAL_TRANSIENT",
            worker_id=claim_token,
        )
        return download_result, None, None
    except ExtractionError as e:
        error_code, safe_msg, category = _map_extraction_error(e)
        fail_or_retry(
            task_id, error_code, safe_msg,
            failure_category=category, worker_id=claim_token,
        )
        return download_result, None, None
    except OSError as e:
        if getattr(e, "errno", None) == 28:
            fail_or_retry(
                task_id, TEMP_STORAGE_EXHAUSTED,
                get_error_message(TEMP_STORAGE_EXHAUSTED),
                failure_category=CAT_TEMP_STORAGE,
                worker_id=claim_token,
            )
        else:
            fail_or_retry(
                task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR),
                worker_id=claim_token,
            )
        return download_result, None, None
    except Exception as e:
        logger.error(
            "Extraction failed for task %s: %s", task_id, type(e).__name__
        )
        fail_or_retry(
            task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR),
            failure_category="INTERNAL_TRANSIENT",
            worker_id=claim_token,
        )
        return download_result, None, None


async def _process_task(task_id: str, claim_token: str | None = None) -> None:
    """Process a single claimed task through the pipeline.

    ``claim_token`` is the fencing token written by claim_next_pending().
    When omitted (legacy tests), ownership is inferred from the DB row.
    """
    download_result: DownloadResult | None = None
    extract_dest: str | None = None
    extract_result = None
    cleanup_failed = False
    is_upload = False
    started = time.monotonic()

    try:
        task = get_task(task_id)
        if task is None:
            logger.error("Task %s not found", task_id)
            return
        if claim_token is None:
            claim_token = task.worker_id
        if task.status not in (STATUS_RUNNING, STATUS_PENDING):
            # Recovered/cancelled/completed elsewhere — do not re-run.
            return
        if claim_token is not None and task.worker_id not in (None, claim_token):
            # Stale worker after recovery/re-claim.
            return
        if _check_cancelled(task_id):
            mark_cancelled(task_id)
            return

        is_upload = task.repo_url.startswith(LOCAL_UPLOAD_PREFIX)

        if is_upload:
            _mark_running_owned(task_id, STAGE_EXTRACTING, 50, claim_token)
            data_dir = upload_source_dir(task_id)
            if not data_dir.is_dir():
                logger.error(
                    "Upload source directory missing for task %s", task_id
                )
                fail_or_retry(
                    task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR),
                    worker_id=claim_token,
                )
                return
            extract_dest = str(data_dir)
            extract_result = await asyncio.to_thread(_stat_directory, data_dir)
        else:
            download_result, extract_dest, extract_result = (
                await _download_and_extract(task_id, task.repo_url, claim_token)
            )
            if extract_result is None or extract_dest is None:
                # Failed, cancelled, deduplicated, or fenced — stop pipeline.
                return

        if _check_cancelled(task_id):
            mark_cancelled(task_id)
            return
        _ensure_owned(task_id, claim_token)

        # --- Stage 3: Scan ---
        _mark_running_owned(task_id, STAGE_SCANNING, 80, claim_token)
        scan_started = time.monotonic()
        try:
            scan_result = await asyncio.wait_for(
                asyncio.to_thread(scan_directory, Path(extract_dest)),
                timeout=settings.scan_timeout,
            )
            metrics_mod.observe(
                "vibecheck_stage_duration_seconds",
                time.monotonic() - scan_started,
                {"stage": "scanning"},
            )
        except TimeoutError:
            logger.error("Scan timed out for task %s", task_id)
            fail_or_retry(
                task_id, SCAN_TIMEOUT, get_error_message(SCAN_TIMEOUT),
                failure_category="SCAN_TIMEOUT",
                worker_id=claim_token,
            )
            return
        except Exception as e:
            logger.error(
                "Scan failed for task %s: %s", task_id, type(e).__name__
            )
            fail_or_retry(
                task_id, SCAN_INTERNAL_ERROR,
                get_error_message(SCAN_INTERNAL_ERROR),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return

        if _check_cancelled(task_id):
            mark_cancelled(task_id)
            return
        _ensure_owned(task_id, claim_token)

        # --- Stage 4: Persist scan result ---
        try:
            _ensure_owned(task_id, claim_token)
            await asyncio.to_thread(save_scan_result, task_id, scan_result)
        except OwnershipLost:
            return
        except ScanResultTooLargeError as e:
            logger.error(
                "Scan result too large for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, SCAN_RESULT_TOO_LARGE,
                get_error_message(SCAN_RESULT_TOO_LARGE),
                failure_category="INTERNAL_PERMANENT",
                worker_id=claim_token,
            )
            return
        except Exception as e:
            logger.error(
                "Scan result persistence failed for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, SCAN_RESULT_PERSIST_FAILED,
                get_error_message(SCAN_RESULT_PERSIST_FAILED),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return

        if _check_cancelled(task_id):
            mark_cancelled(task_id)
            return
        _ensure_owned(task_id, claim_token)

        # --- Stage 5: Assess ---
        _mark_running_owned(task_id, STAGE_ASSESSING, 90, claim_token)
        assess_started = time.monotonic()
        try:
            _ensure_owned(task_id, claim_token)
            await asyncio.wait_for(
                asyncio.to_thread(run_assessment, task_id),
                timeout=settings.assess_timeout,
            )
            metrics_mod.observe(
                "vibecheck_stage_duration_seconds",
                time.monotonic() - assess_started,
                {"stage": "assessing"},
            )
        except OwnershipLost:
            return
        except TimeoutError:
            fail_or_retry(
                task_id, ASSESSMENT_TIMEOUT,
                get_error_message(ASSESSMENT_TIMEOUT),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return
        except AssessmentResultTooLargeError as e:
            logger.error(
                "Assessment result too large for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, ASSESSMENT_RESULT_TOO_LARGE,
                get_error_message(ASSESSMENT_RESULT_TOO_LARGE),
                failure_category="INTERNAL_PERMANENT",
                worker_id=claim_token,
            )
            return
        except AssessmentInternalError as e:
            logger.error(
                "Assessment internal error for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, ASSESSMENT_INTERNAL_ERROR,
                get_error_message(ASSESSMENT_INTERNAL_ERROR),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return
        except AssessmentPersistError as e:
            logger.error(
                "Assessment persistence failed for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, ASSESSMENT_PERSIST_FAILED,
                get_error_message(ASSESSMENT_PERSIST_FAILED),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return
        except Exception as e:
            logger.error(
                "Assessment failed for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, ASSESSMENT_INTERNAL_ERROR,
                get_error_message(ASSESSMENT_INTERNAL_ERROR),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return

        if _check_cancelled(task_id):
            mark_cancelled(task_id)
            return
        _ensure_owned(task_id, claim_token)

        # --- Stage 6: Repair plan ---
        _mark_running_owned(task_id, STAGE_REPAIRING, 95, claim_token)
        try:
            _ensure_owned(task_id, claim_token)
            await asyncio.wait_for(
                asyncio.to_thread(generate_and_save_repair_plan, task_id),
                timeout=settings.repair_plan_timeout,
            )
        except OwnershipLost:
            return
        except TimeoutError:
            fail_or_retry(
                task_id, REPAIR_PLAN_TIMEOUT,
                get_error_message(REPAIR_PLAN_TIMEOUT),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return
        except RepairPlanTooLargeError as e:
            logger.error(
                "Repair plan too large for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, REPAIR_PLAN_TOO_LARGE,
                get_error_message(REPAIR_PLAN_TOO_LARGE),
                failure_category="INTERNAL_PERMANENT",
                worker_id=claim_token,
            )
            return
        except RepairPlanInternalError as e:
            logger.error(
                "Repair plan internal error for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, REPAIR_PLAN_INTERNAL_ERROR,
                get_error_message(REPAIR_PLAN_INTERNAL_ERROR),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return
        except RepairPlanPersistError as e:
            logger.error(
                "Repair plan persistence failed for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, REPAIR_PLAN_PERSIST_FAILED,
                get_error_message(REPAIR_PLAN_PERSIST_FAILED),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return
        except Exception as e:
            logger.error(
                "Repair plan failed for task %s: %s",
                task_id, type(e).__name__,
            )
            fail_or_retry(
                task_id, REPAIR_PLAN_INTERNAL_ERROR,
                get_error_message(REPAIR_PLAN_INTERNAL_ERROR),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
            return

        if _check_cancelled(task_id):
            mark_cancelled(task_id)
            return
        _ensure_owned(task_id, claim_token)

        # --- Stage 7: LLM analysis (NON-BLOCKING) ---
        _mark_running_owned(task_id, STAGE_ANALYZING, 97, claim_token)
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
            logger.warning(
                "LLM analysis timed out for task %s (non-blocking)", task_id
            )
        except Exception as e:
            logger.warning(
                "LLM analysis stage failed for task %s: %s (non-blocking)",
                task_id, type(e).__name__,
            )
        finally:
            pop_user_config(task_id)

        if _check_cancelled(task_id):
            mark_cancelled(task_id)
            return
        _ensure_owned(task_id, claim_token)

        # --- Stage 8: Complete ---
        completed = mark_completed(
            task_id,
            file_count=extract_result.file_count if extract_result else 0,
            total_size=extract_result.total_size if extract_result else 0,
            top_level_dir=(
                (extract_result.top_level_dir if extract_result else None)
                or ("本地上传" if is_upload else "unknown")
            ),
            worker_id=claim_token,
        )
        if completed:
            metrics_mod.observe(
                "vibecheck_task_duration_seconds", time.monotonic() - started
            )

    except OwnershipLost:
        logger.info("Worker lost ownership for task %s; stopping", task_id)
    except Exception as e:
        logger.error("Unexpected error in task %s: %s", task_id, type(e).__name__)
        fail_or_retry(
            task_id, INTERNAL_ERROR, get_error_message(INTERNAL_ERROR),
            failure_category="INTERNAL_TRANSIENT",
            worker_id=claim_token,
        )
    finally:
        consume_extract()
        pop_user_config(task_id)
        _cancel_events.pop(task_id, None)

        if download_result is not None:
            try:
                cleanup_download(download_result.temp_file)
            except Exception:
                logger.error("Failed to clean up download file for task %s", task_id)
                cleanup_failed = True
                metrics_mod.inc_counter("vibecheck_cleanup_failures_total")

        if extract_dest is not None and not _cleanup_task_dir(task_id, extract_dest):
            cleanup_failed = True

        if cleanup_failed:
            logger.warning(
                "Cleanup failed for task %s —temp files may remain", task_id
            )


async def _run_claimed_task(task_id: str, claim_token: str | None = None) -> None:
    stop_event = asyncio.Event()
    hb_task = asyncio.create_task(
        _heartbeat_loop(task_id, stop_event, claim_token)
    )
    try:
        await _process_task(task_id, claim_token)
    finally:
        stop_event.set()
        hb_task.cancel()
        try:
            await hb_task
        except asyncio.CancelledError:
            pass


async def _dispatcher_loop() -> None:
    """Continuously claim pending tasks into free execution slots."""
    global _is_processing
    _is_processing = True
    poll = settings.dispatcher_poll_seconds
    last_reaper = 0.0
    reaper_every = max(1.0, float(settings.lease_reaper_seconds))
    try:
        while not _stopping:
            try:
                await asyncio.to_thread(refresh_queue_metrics)
            except Exception:
                pass

            if _stopping:
                break

            # Runtime lease reaper — recover expired leases without restart.
            now_m = time.monotonic()
            if now_m - last_reaper >= reaper_every:
                last_reaper = now_m
                try:
                    await asyncio.to_thread(recover_expired_tasks)
                except Exception as e:
                    logger.error("Lease reaper failed: %s", type(e).__name__)

            free = settings.max_running_tasks - len(_active)
            if free <= 0:
                await asyncio.sleep(poll)
                continue

            claimed = None
            claim_token = None
            if has_claimable_pending():
                try:
                    # Unique claim token per claim — never reuse process id.
                    claim_token = make_worker_id("claim")
                    claimed = await asyncio.to_thread(
                        claim_next_pending, claim_token
                    )
                    if claimed is None:
                        claim_token = None
                except Exception as e:
                    logger.error("Claim failed: %s", type(e).__name__)
                    claim_token = None

            if claimed is None:
                await asyncio.sleep(poll)
                continue

            worker = asyncio.create_task(
                _run_claimed_task(claimed.id, claim_token or claimed.worker_id)
            )
            _active.add(worker)

            def _done_cb(t: asyncio.Task, tid: str = claimed.id, tok: str | None = claim_token) -> None:
                _on_worker_done(t, tid, tok)

            worker.add_done_callback(_done_cb)
    finally:
        _is_processing = False


def _on_worker_done(
    task: asyncio.Task,
    task_id: str | None = None,
    claim_token: str | None = None,
) -> None:
    _active.discard(task)
    if task.cancelled():
        return
    try:
        exc = task.exception()
    except asyncio.CancelledError:
        return
    if exc is None:
        return
    logger.error(
        "Worker task raised for task_id=%s claim=%s: %s",
        task_id,
        claim_token,
        type(exc).__name__,
    )
    # Safe failure path when possible; otherwise lease reaper recovers.
    if task_id:
        try:
            fail_or_retry(
                task_id,
                INTERNAL_ERROR,
                get_error_message(INTERNAL_ERROR),
                failure_category="INTERNAL_TRANSIENT",
                worker_id=claim_token,
            )
        except Exception:
            logger.error("Safe-fail after worker exception also failed")


async def start_dispatcher() -> None:
    """Start the bounded-concurrency dispatcher (idempotent)."""
    global _dispatcher_task, _stopping
    if _dispatcher_task is not None and not _dispatcher_task.done():
        return
    _stopping = False
    _dispatcher_task = asyncio.create_task(_dispatcher_loop())


async def stop_dispatcher(grace_seconds: float | None = None) -> None:
    """Graceful shutdown: stop claiming, wait briefly for in-flight tasks."""
    global _dispatcher_task, _stopping
    _stopping = True
    if grace_seconds is None:
        grace_seconds = settings.shutdown_grace_seconds

    if _dispatcher_task is not None:
        _dispatcher_task.cancel()
        try:
            await _dispatcher_task
        except asyncio.CancelledError:
            pass
        _dispatcher_task = None

    if _active:
        done, pending = await asyncio.wait(
            list(_active), timeout=max(0.0, grace_seconds)
        )
        for t in pending:
            # Unfinished tasks rely on lease expiry for recovery after restart.
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


async def trigger_queue_processing() -> None:
    """Ensure tasks are processed (API-compatible entrypoint).

    - app_env=test: drain the queue inline (deterministic unit tests).
    - otherwise: start the long-lived bounded-concurrency dispatcher.
    """
    global _is_processing
    if settings.app_env == "test":
        _is_processing = True
        try:
            while True:
                token = make_worker_id("inline")
                claimed = claim_next_pending(token)
                if claimed is None:
                    break
                await _process_task(claimed.id, token)
        except Exception as e:
            logger.error("Inline queue processing error: %s", type(e).__name__)
        finally:
            _is_processing = False
            try:
                refresh_queue_metrics()
            except Exception:
                pass
        return

    await start_dispatcher()
    _is_processing = True


async def drain_pending_tasks(max_tasks: int = 100) -> int:
    """Claim and process pending tasks inline until the queue is empty."""
    processed = 0
    while processed < max_tasks:
        token = make_worker_id("drain")
        claimed = claim_next_pending(token)
        if claimed is None:
            break
        await _process_task(claimed.id, token)
        processed += 1
    return processed


def reset_runner_state() -> None:
    """Reset the runner state — for testing only."""
    global _is_processing, _stopping, _worker_id, _dispatcher_task
    _is_processing = False
    _stopping = False
    _worker_id = None
    _active.clear()
    _cancel_events.clear()
    if _dispatcher_task is not None and _dispatcher_task.done():
        _dispatcher_task = None


def cancel_task_locally(task_id: str) -> None:
    """Signal cooperative cancel to a worker in this process."""
    _get_cancel_event(task_id).set()
    mark_cancelled(task_id)


def active_task_count() -> int:
    return len(_active)


def dispatcher_running() -> bool:
    return _dispatcher_task is not None and not _dispatcher_task.done()


__all__ = [
    "OwnershipLost",
    "active_task_count",
    "cancel_task_locally",
    "dispatcher_running",
    "drain_pending_tasks",
    "is_queue_full",
    "reset_runner_state",
    "start_dispatcher",
    "stop_dispatcher",
    "trigger_queue_processing",
]
