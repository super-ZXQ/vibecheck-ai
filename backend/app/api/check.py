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
- Completed tasks WITHOUT a persisted result (legacy) have
  scan_summary=None and report_url=None.
- Completed tasks WITHOUT a persisted assessment (legacy P0-5) have
  security_score=None, security_verdict=None, assessment_url=None.
- Does NOT inline full findings — use the result endpoint for that.
- Does NOT inline full assessment — use the assessment endpoint for that.
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
"""

import asyncio
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.core.error_codes import (
    INTERNAL_ERROR,
    QUEUE_FULL,
    SCAN_RESULT_MISSING,
    SCAN_RESULT_NOT_READY,
    get_error_message,
)
from app.core.github import GitHubDownloadError, parse_repo_url
from app.services.background_runner import trigger_queue_processing
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

router = APIRouter()


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
async def create_check(request: CheckRequest):
    """Create a new project check task.

    - Validates the repo URL.
    - Checks if the queue is full (max 5 pending).
    - Creates a pending task.
    - Triggers background processing.
    """
    # Validate repo URL
    try:
        repo_info = parse_repo_url(request.repo_url)
    except GitHubDownloadError as e:
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
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
