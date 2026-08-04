"""API routes for security assessment results (P0-6).

GET /api/check/{task_id}/assessment:
- Returns the full persisted security assessment for a completed task.
- Task not found: 404.
- pending/running: 409 ASSESSMENT_NOT_READY (does NOT read assessment_results).
- failed: fixed safe empty assessment (does NOT read assessment_results,
  even if a residual record exists from a partial pipeline).
- completed, assessment exists: 200 full AssessmentResult.
- completed, assessment MISSING: 409 ASSESSMENT_NOT_AVAILABLE (legacy
  P0-5 task without a persisted assessment_results row).
- unknown status: 500 ASSESSMENT_INTERNAL_ERROR.
- Never returns raw secrets, temp paths, or internal exceptions.
- Full database read and JSON parse via asyncio.to_thread.

The failed check MUST come before any assessment_results read. This
prevents leaking residual assessments from a partial pipeline where
run_assessment persisted the assessment but mark_completed threw an
exception (which would mark the task as failed).
"""

import asyncio
import uuid

from fastapi import APIRouter, HTTPException, status

from app.core.error_codes import (
    ASSESSMENT_INTERNAL_ERROR,
    ASSESSMENT_NOT_AVAILABLE,
    ASSESSMENT_NOT_READY,
    get_error_message,
)
from app.services.assessment_policy import (
    ASSESSMENT_SCHEMA_VERSION,
    ASSESSMENT_SCOPE,
    POLICY_VERSION,
)
from app.services.assessment_service import (
    get_assessment_result,
    AssessmentInternalError,
)
from app.services.task_manager import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    get_task,
)

router = APIRouter()


# --- Fixed safe empty assessment for failed tasks ---
# Returned when task.status == "failed", regardless of whether a
# residual assessment_results row exists. Includes all AssessmentResult
# fields to maintain a consistent response structure.
# score = 0, verdict = "blocked" — a failed task cannot pass security.
# coverage.status = "partial" with a reason explaining the failure.

def _build_safe_empty_assessment(task_id: str) -> dict:
    """Build a fixed safe empty assessment for failed tasks.

    This is returned instead of any residual assessment that might
    exist in the database from a partial pipeline run.
    """
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "assessment_scope": ASSESSMENT_SCOPE,
        "task_id": task_id,
        "score": 0,
        "score_before_caps": 0,
        "verdict": "blocked",
        "score_breakdown": [],
        "score_caps": [],
        "blocking_reasons": [],
        "coverage": {
            "status": "partial",
            "reasons": ["任务执行失败，无法进行安全评估。"],
            "total_findings": 0,
            "scored_findings": 0,
            "findings_truncated": False,
            "total_blocking_findings": 0,
            "returned_blocking_reasons": 0,
            "blocking_reasons_truncated": False,
            "total_scan_errors": 0,
            "total_files_scanned": 0,
            "total_skipped_files": 0,
        },
        "created_at": None,
        "updated_at": None,
    }


@router.get("/api/check/{task_id}/assessment")
async def get_assessment(task_id: str):
    """Get the full persisted security assessment for a completed task.

    Strict state-ordered branching:
    1. task not found → 404
    2. pending/running → 409 ASSESSMENT_NOT_READY (does NOT read assessment_results)
    3. failed → fixed safe empty assessment (does NOT read assessment_results,
       even if a residual record exists from a partial pipeline)
    4. completed → asyncio.to_thread(get_assessment_result)
       - assessment exists → 200 full AssessmentResult
       - assessment missing → 409 ASSESSMENT_NOT_AVAILABLE
    5. unknown status → 500 ASSESSMENT_INTERNAL_ERROR

    The failed check MUST come before any assessment_results read. This
    prevents leaking residual assessments from a partial pipeline where
    run_assessment succeeded but mark_completed threw an exception.

    Never returns raw secrets, temp paths, or internal exceptions.
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

    # --- Case 2: pending/running → 409 (does NOT read assessment_results) ---
    if task.status in (STATUS_PENDING, STATUS_RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": ASSESSMENT_NOT_READY,
                "error_message": get_error_message(ASSESSMENT_NOT_READY),
            },
        )

    # --- Case 3: failed → fixed safe empty (does NOT read assessment_results) ---
    # Even if assessment_results has a residual record (e.g. run_assessment
    # succeeded but mark_completed threw), must NOT return it.
    if task.status == STATUS_FAILED:
        return _build_safe_empty_assessment(task_id)

    # --- Case 4: completed → read assessment via asyncio.to_thread ---
    if task.status == STATUS_COMPLETED:
        try:
            result = await asyncio.to_thread(get_assessment_result, task_id)
        except AssessmentInternalError:
            # Corrupted or invalid assessment JSON — return fixed 500.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error_code": ASSESSMENT_INTERNAL_ERROR,
                    "error_message": get_error_message(ASSESSMENT_INTERNAL_ERROR),
                },
            )
        if result is not None:
            return result
        # Assessment missing — legacy P0-5 task or data integrity issue.
        # Must NOT return a success empty assessment.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": ASSESSMENT_NOT_AVAILABLE,
                "error_message": get_error_message(ASSESSMENT_NOT_AVAILABLE),
            },
        )

    # --- Case 5: unknown status → internal error ---
    # Must NOT return a success empty assessment.
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error_code": ASSESSMENT_INTERNAL_ERROR,
            "error_message": get_error_message(ASSESSMENT_INTERNAL_ERROR),
        },
    )
