"""API routes for project check.

POST /api/check:
- Validates repo URL via parse_repo_url.
- Creates a pending task in SQLite.
- Triggers background processing (download + extract + scan).
- Returns task_id, status, and check_url.

GET /api/check/{task_id}:
- Returns current task status, stage, progress, and errors.
- Completed tasks with a persisted result include scan_summary and
  report_url (P0-5).
- Completed tasks with a persisted assessment include security_score,
  security_verdict, and assessment_url (P0-6).
- Completed tasks with a persisted LLM analysis include
  llm_analysis_available and llm_analysis_url (P1-4).
- Completed tasks WITHOUT a persisted result (legacy) have
  scan_summary=None and report_url=None.
- Completed tasks WITHOUT a persisted assessment (legacy P0-5) have
  security_score=None, security_verdict=None, assessment_url=None.
- Does NOT inline full findings — use the result endpoint for that.
- Does NOT inline full assessment — use the assessment endpoint for that.
- Does NOT inline full LLM analysis — use the llm-analysis endpoint.
- UUID format errors return 422.
- Non-existent tasks return 404.
- Frontend can poll every 2 seconds.

GET /api/check/{task_id}/result (P0-5):
- Returns the full persisted scan result.
- Task not found: 404.
- pending/running, no result: 409 SCAN_RESULT_NOT_READY.
- failed, no result: fixed safe empty response (200).
- completed, result exists: full findings, notices, etc. (200).
- completed, result MISSING: 500 SCAN_RESULT_MISSING (legacy task
  without a persisted scan_results row).
- Never re-scans from temp directory.
- Never returns raw exceptions or absolute paths.

GET /api/check/{task_id}/llm-analysis (P1-4):
- Returns the full persisted LLM analysis for a completed task.
- Task not found: 404.
- pending/running: 409 LLM_ANALYSIS_NOT_READY.
- failed: fixed safe empty response (200).
- completed, analysis exists: 200 full analysis.
- completed, analysis MISSING: 200 safe empty (LLM analysis is
  non-blocking; a task can complete without it).
- Never returns raw secrets, temp paths, or internal exceptions.
"""

import asyncio
import logging
import uuid

from fastapi import APIRouter, File, Form, Header, HTTPException, UploadFile, status
from pydantic import BaseModel

from app.core.config import settings
from app.core.error_codes import (
    EXTRACTION_LIMIT_EXCEEDED,
    INTERNAL_ERROR,
    INVALID_UPLOAD,
    LLM_ANALYSIS_NOT_READY,
    QUEUE_FULL,
    SCAN_RESULT_MISSING,
    SCAN_RESULT_NOT_READY,
    UPLOAD_TOO_LARGE,
    get_error_message,
)
from app.core.github import GitHubDownloadError, parse_repo_url
from app.core.safe_extract import cleanup_temp_dir, prepare_extract_dest
from app.services.background_runner import trigger_queue_processing
from app.services.llm_service import get_llm_analysis
from app.services.llm_user_config import store_user_config
from app.services.scan_result_service import (
    SCHEMA_VERSION,
    get_scan_result,
)
from app.services.task_manager import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    create_task,
    get_task,
    is_queue_full,
)
from app.services.upload_service import (
    LOCAL_UPLOAD_PREFIX,
    UploadError,
    store_archive_upload,
    store_folder_upload,
    upload_source_dir,
)

router = APIRouter()
logger = logging.getLogger(__name__)


# --- Request / Response models ---

class CheckRequest(BaseModel):
    repo_url: str


class CheckResponse(BaseModel):
    task_id: str
    status: str
    check_url: str


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    stage: str
    progress: int
    owner: str | None = None
    repo_name: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    report_url: str | None = None
    file_count: int | None = None
    total_size: int | None = None
    top_level_dir: str | None = None
    scan_summary: dict | None = None
    security_score: int | None = None
    security_verdict: str | None = None
    assessment_url: str | None = None
    repair_plan_available: bool | None = None
    repair_plan_url: str | None = None
    llm_analysis_available: bool | None = None
    llm_analysis_url: str | None = None


# --- Fixed safe empty response for failed tasks without results ---
# Includes all summary fields (total_* and returned_* / *_truncated)
# to maintain a consistent response structure.

_SAFE_EMPTY_RESULT: dict = {
    "schema_version": SCHEMA_VERSION,
    "findings": [],
    "notices": [],
    "skipped_files": [],
    "scan_errors": [],
    "summary": {
        "total_findings": 0,
        "blocking_findings": 0,
        "total_notices": 0,
        "total_skipped_files": 0,
        "total_scan_errors": 0,
        "total_files_scanned": 0,
        "total_lines_scanned": 0,
        "returned_findings": 0,
        "findings_truncated": False,
        "returned_notices": 0,
        "notices_truncated": False,
        "returned_skipped_files": 0,
        "skipped_files_truncated": False,
        "returned_scan_errors": 0,
        "scan_errors_truncated": False,
    },
}


# --- Routes ---

@router.post("/api/check", response_model=CheckResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_check(
    request: CheckRequest,
    x_llm_api_key: str | None = Header(default=None, alias="X-LLM-API-KEY"),
    x_llm_base_url: str | None = Header(default=None, alias="X-LLM-BASE-URL"),
    x_llm_model: str | None = Header(default=None, alias="X-LLM-MODEL"),
):
    """Create a new project check task.

    - Validates the repo URL.
    - Checks if the queue is full (max 5 pending).
    - Creates a pending task.
    - Triggers background processing.
    - Optional X-LLM-* headers bind a caller-supplied LLM config (API key,
      base URL, model) to this task for the LLM analysis stage. Credentials
      live in process memory only — validated, never persisted, never logged,
      never returned, and removed when the task finishes.
    """
    # Validate repo URL
    try:
        repo_info = parse_repo_url(request.repo_url)
    except GitHubDownloadError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "INVALID_REPO_URL",
                "error_message": get_error_message("INVALID_REPO_URL"),
            },
        )

    # Check queue capacity
    if is_queue_full():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error_code": QUEUE_FULL,
                "error_message": get_error_message(QUEUE_FULL),
            },
        )

    # Create pending task
    task = create_task(
        repo_url=repo_info.url,
        owner=repo_info.owner,
        repo_name=repo_info.repo,
    )

    # Trigger background processing (non-blocking)
    store_user_config(task.id, x_llm_api_key, x_llm_base_url, x_llm_model)
    asyncio.create_task(trigger_queue_processing())

    return CheckResponse(
        task_id=task.id,
        status=task.status,
        check_url=f"/api/check/{task.id}",
    )


# --- Upload route ---
# Local uploads (archive / folder) go through the same queue, pipeline and
# result endpoints as GitHub submissions. Content is staged under
# settings.tmp_dir (tmpfs), never persisted, and removed after scanning.

def _upload_error_http_status(code: str) -> int:
    """Map an upload rejection code to an HTTP status."""
    if code in (UPLOAD_TOO_LARGE, EXTRACTION_LIMIT_EXCEEDED):
        return 413  # Request Entity Too Large (content too large)
    return status.HTTP_400_BAD_REQUEST


@router.post("/api/check/upload", response_model=CheckResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_upload_check(
    mode: str = Form(default="archive"),
    file: list[UploadFile] = File(...),
    x_llm_api_key: str | None = Header(default=None, alias="X-LLM-API-KEY"),
    x_llm_base_url: str | None = Header(default=None, alias="X-LLM-BASE-URL"),
    x_llm_model: str | None = Header(default=None, alias="X-LLM-MODEL"),
):
    """Create a new project check task from a local upload.

    Two modes (backend is authoritative):
    - ``archive``: a single .zip / .tar.gz / .tgz file, magic-sniffed and
      safely extracted.
    - ``folder``: multiple files whose filenames are relative paths
      (browser ``webkitRelativePath``); the tree is rebuilt on disk.

    Same queue capacity (5 pending) and limit set as URL submissions.
    Content is validated and staged BEFORE the task is created; a rejected
    upload never creates a task.

    Optional X-LLM-* headers work exactly as on POST /api/check.
    """
    # Check queue capacity (shared with URL submissions).
    if is_queue_full():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error_code": QUEUE_FULL,
                "error_message": get_error_message(QUEUE_FULL),
            },
        )

    if not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": INVALID_UPLOAD,
                "error_message": get_error_message(INVALID_UPLOAD),
            },
        )

    # Stage into an isolated temp dir under tmpfs.
    dest_root = prepare_extract_dest(settings.tmp_dir)
    try:
        if mode == "archive":
            if len(file) != 1:
                raise UploadError(
                    INVALID_UPLOAD, "Archive mode accepts exactly one file"
                )
            await store_archive_upload(file[0], dest_root)
        elif mode == "folder":
            await store_folder_upload(file, dest_root)
        else:
            raise UploadError(INVALID_UPLOAD, f"Unknown upload mode: {mode!r}")
    except UploadError as e:
        cleanup_temp_dir(dest_root)
        raise HTTPException(
            status_code=_upload_error_http_status(e.code),
            detail={
                "error_code": e.code,
                "error_message": get_error_message(e.code),
            },
        )
    except Exception as e:
        cleanup_temp_dir(dest_root)
        logger.error("Unexpected upload failure: %s", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": INTERNAL_ERROR,
                "error_message": get_error_message(INTERNAL_ERROR),
            },
        )

    # Only now create the task (rejected uploads never create tasks).
    try:
        task = create_task(
            repo_url=f"{LOCAL_UPLOAD_PREFIX}{uuid.uuid4().hex}",
            owner="local",
            repo_name="上传项目",
        )
        staged = upload_source_dir(task.id)
        dest_root.rename(staged)
    except Exception as e:
        cleanup_temp_dir(dest_root)
        logger.error("Failed to create upload task: %s", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": INTERNAL_ERROR,
                "error_message": get_error_message(INTERNAL_ERROR),
            },
        )

    store_user_config(task.id, x_llm_api_key, x_llm_base_url, x_llm_model)
    asyncio.create_task(trigger_queue_processing())

    return CheckResponse(
        task_id=task.id,
        status=task.status,
        check_url=f"/api/check/{task.id}",
    )


@router.get("/api/check/{task_id}", response_model=TaskStatusResponse)
async def get_check_status(task_id: str):
    """Get the status of a check task.

    - Invalid UUID format returns 422.
    - Non-existent task returns 404.
    - Completed tasks include scan_summary and report_url.
    - Does NOT inline full findings (use /result endpoint).
    """
    # Validate UUID format
    try:
        uuid.UUID(task_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error_code": "INVALID_TASK_ID",
                "error_message": "任务ID格式无效。",
            },
        )

    # Get task from database
    task = get_task(task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "TASK_NOT_FOUND",
                "error_message": "任务不存在。",
            },
        )

    # to_response() calls get_scan_summary which does synchronous DB
    # access. Wrap in asyncio.to_thread so the event loop is not blocked
    # by SQLite reads (summary_json is lightweight, but the DB call
    # itself should still not run in the event loop thread).
    response_data = await asyncio.to_thread(task.to_response)
    return TaskStatusResponse(**response_data)


@router.get("/api/check/{task_id}/result")
async def get_check_result(task_id: str):
    """Get the full persisted scan result for a completed task.

    Strict state-ordered branching:
    1. task not found → 404
    2. pending/running → 409 SCAN_RESULT_NOT_READY (does NOT read scan_results)
    3. failed → fixed safe empty response (does NOT read scan_results,
       even if a residual record exists from a partial pipeline)
    4. completed → asyncio.to_thread(get_scan_result)
       - result exists → 200 full result
       - result missing → 500 SCAN_RESULT_MISSING
    5. unknown status → 500 INTERNAL_ERROR (never returns success empty)

    The failed check MUST come before any scan_results read. This
    prevents leaking residual findings from a partial pipeline where
    save_scan_result succeeded but mark_completed threw an exception.

    Never re-scans from temp directory.
    Never returns raw exceptions or absolute paths.
    """
    # Validate UUID format
    try:
        uuid.UUID(task_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error_code": "INVALID_TASK_ID",
                "error_message": "任务ID格式无效。",
            },
        )

    # Get task from database
    task = get_task(task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "TASK_NOT_FOUND",
                "error_message": "任务不存在。",
            },
        )

    # --- Case 2: pending/running → 409 (does NOT read scan_results) ---
    if task.status in (STATUS_PENDING, STATUS_RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": SCAN_RESULT_NOT_READY,
                "error_message": get_error_message(SCAN_RESULT_NOT_READY),
            },
        )

    # --- Case 3: failed → fixed safe empty (does NOT read scan_results) ---
    # Even if scan_results has a residual record (e.g. save_scan_result
    # succeeded but mark_completed threw), must NOT return it.
    if task.status == STATUS_FAILED:
        return _SAFE_EMPTY_RESULT

    # --- Case 4: completed → read result via asyncio.to_thread ---
    if task.status == STATUS_COMPLETED:
        result = await asyncio.to_thread(get_scan_result, task_id)
        if result is not None:
            return result
        # Result missing — legacy task or data integrity issue.
        # Must NOT return a success empty report.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": SCAN_RESULT_MISSING,
                "error_message": get_error_message(SCAN_RESULT_MISSING),
            },
        )

    # --- Case 5: unknown status → internal error ---
    # Must NOT return a success empty report.
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error_code": INTERNAL_ERROR,
            "error_message": get_error_message(INTERNAL_ERROR),
        },
    )


# --- LLM analysis safe empty response for failed/pending tasks ---

_SAFE_EMPTY_LLM_ANALYSIS: dict = {
    "schema_version": 1,
    "scope": "non_blocking_findings",
    "total_analyzed": 0,
    "total_llm": 0,
    "total_fallback": 0,
    "source": "none",
    "items": [],
}


@router.get("/api/check/{task_id}/llm-analysis")
async def get_llm_analysis_result(task_id: str):
    """Get the full persisted LLM analysis for a completed task.

    State-ordered branching:
    1. task not found → 404
    2. pending/running → 409 LLM_ANALYSIS_NOT_READY
    3. failed → fixed safe empty response (200)
    4. completed → asyncio.to_thread(get_llm_analysis)
       - analysis exists → 200 full analysis
       - analysis MISSING → 200 safe empty (LLM analysis is non-blocking)
    5. unknown status → 500 INTERNAL_ERROR

    LLM analysis is NON-BLOCKING — a task can complete without it.
    Unlike scan_result and assessment, a missing LLM analysis does NOT
    return an error; it returns a safe empty response.
    """
    # Validate UUID format
    try:
        uuid.UUID(task_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error_code": "INVALID_TASK_ID",
                "error_message": "任务ID格式无效。",
            },
        )

    # Get task from database
    task = get_task(task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "TASK_NOT_FOUND",
                "error_message": "任务不存在。",
            },
        )

    # --- Case 2: pending/running → 409 ---
    if task.status in (STATUS_PENDING, STATUS_RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": LLM_ANALYSIS_NOT_READY,
                "error_message": get_error_message(LLM_ANALYSIS_NOT_READY),
            },
        )

    # --- Case 3: failed → fixed safe empty ---
    if task.status == STATUS_FAILED:
        return _SAFE_EMPTY_LLM_ANALYSIS

    # --- Case 4: completed → read analysis ---
    if task.status == STATUS_COMPLETED:
        analysis = await asyncio.to_thread(get_llm_analysis, task_id)
        if analysis is not None:
            return analysis
        # Analysis missing — non-blocking, return safe empty.
        return _SAFE_EMPTY_LLM_ANALYSIS

    # --- Case 5: unknown status → internal error ---
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error_code": INTERNAL_ERROR,
            "error_message": get_error_message(INTERNAL_ERROR),
        },
    )
