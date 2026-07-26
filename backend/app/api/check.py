"""API routes for project check.

POST /api/check:
- Validates repo URL via parse_repo_url.
- Creates a pending task in SQLite.
- Triggers background processing (download + extract + scan).
- Returns task_id, status, and check_url.

GET /api/check/{task_id}:
- Returns current task status, stage, progress, and errors.
- Completed tasks include scan_summary and report_url (P0-5).
- Does NOT inline full findings — use the result endpoint for that.
- UUID format errors return 422.
- Non-existent tasks return 404.
- Frontend can poll every 2 seconds.

GET /api/check/{task_id}/result (P0-5):
- Returns the full persisted scan result.
- Task not found: 404.
- Task still processing, no result yet: 409.
- Task failed, no result: fixed safe empty response.
- Result exists: full findings, notices, skipped_files, scan_errors, summary.
- Never re-scans from temp directory.
- Never returns raw exceptions or absolute paths.
"""

import asyncio
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.core.error_codes import (
    QUEUE_FULL,
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


# --- Fixed safe empty response for failed tasks without results ---

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

    return TaskStatusResponse(**task.to_response())


@router.get("/api/check/{task_id}/result")
async def get_check_result(task_id: str):
    """Get the full persisted scan result for a completed task.

    - Invalid UUID format returns 422.
    - Task not found: 404.
    - Task still processing (pending/running), no result: 409.
    - Task failed, no result: fixed safe empty response (200).
    - Result exists: full findings, notices, skipped_files, scan_errors, summary.

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

    # Check if task is still processing
    if task.status in (STATUS_PENDING, STATUS_RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": SCAN_RESULT_NOT_READY,
                "error_message": get_error_message(SCAN_RESULT_NOT_READY),
            },
        )

    # Try to get the persisted scan result
    result = get_scan_result(task_id)

    if result is not None:
        # Result exists — return the full persisted scan result
        return result

    # Task failed (or completed but result not persisted for some reason)
    # Return a fixed safe empty response — no error, no exception details
    return _SAFE_EMPTY_RESULT
