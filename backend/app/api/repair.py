"""API routes for repair plan results (P0-7).

GET /api/check/{task_id}/repair-plan:
- Returns the full persisted repair plan for a completed task.
- Task not found: 404.
- pending/running: 409 REPAIR_PLAN_NOT_READY (does NOT read repair_results).
- failed: fixed safe empty repair plan (does NOT read repair_results,
  even if a residual record exists from a partial pipeline).
- completed, repair plan exists: 200 full RepairPlan.
- completed, repair plan MISSING: 409 REPAIR_PLAN_NOT_AVAILABLE (legacy
  P0-6 task without a persisted repair_results row).
- unknown status: 500 REPAIR_PLAN_INTERNAL_ERROR.
- Never returns raw secrets, temp paths, or internal exceptions.
- Full database read and JSON parse via asyncio.to_thread.

The failed check MUST come before any repair_results read. This
prevents leaking residual repair plans from a partial pipeline where
generate_and_save_repair_plan persisted the plan but mark_completed
threw an exception (which would mark the task as failed).
"""

import asyncio
import uuid

from fastapi import APIRouter, HTTPException, status

from app.core.error_codes import (
    REPAIR_PLAN_INTERNAL_ERROR,
    REPAIR_PLAN_NOT_AVAILABLE,
    REPAIR_PLAN_NOT_READY,
    get_error_message,
)
from app.services.repair_policy import (
    POLICY_VERSION,
    REPAIR_SCHEMA_VERSION,
    REPAIR_SCOPE,
)
from app.services.repair_service import (
    RepairPlanInternalError,
    get_repair_result,
)
from app.services.task_manager import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    get_task,
)

router = APIRouter()


# --- Fixed safe empty repair plan for failed tasks ---
# Returned when task.status == "failed", regardless of whether a
# residual repair_results row exists. Includes all RepairPlan fields
# to maintain a consistent response structure.
# plan_status = "partial" — a failed task cannot have a complete plan.
# All summary values are 0 or false. All lists are empty.

def _build_safe_empty_repair_plan(task_id: str) -> dict:
    """Build a fixed safe empty repair plan for failed tasks.

    This is returned instead of any residual repair plan that might
    exist in the database from a partial pipeline run.
    """
    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "repair_scope": REPAIR_SCOPE,
        "task_id": task_id,
        "plan_status": "partial",
        "summary": {
            "total_repair_groups": 0,
            "blocking_repair_groups": 0,
            "manual_review_required": False,
            "coverage_warning": False,
            "groups_truncated": False,
        },
        "repair_groups": [],
        "verification_steps": [],
        "agent_prompt": "",
        "source_scan_updated_at": None,
        "source_assessment_updated_at": None,
        "source_assessment_policy_version": None,
        "created_at": None,
        "updated_at": None,
    }


@router.get("/api/check/{task_id}/repair-plan")
async def get_repair_plan(task_id: str):
    """Get the full persisted repair plan for a completed task.

    Strict state-ordered branching:
    1. task not found → 404
    2. pending/running → 409 REPAIR_PLAN_NOT_READY (does NOT read repair_results)
    3. failed → fixed safe empty repair plan (does NOT read repair_results,
       even if a residual record exists from a partial pipeline)
    4. completed → asyncio.to_thread(get_repair_result)
       - repair plan exists → 200 full RepairPlan
       - repair plan missing → 409 REPAIR_PLAN_NOT_AVAILABLE
    5. unknown status → 500 REPAIR_PLAN_INTERNAL_ERROR

    The failed check MUST come before any repair_results read. This
    prevents leaking residual repair plans from a partial pipeline where
    generate_and_save_repair_plan succeeded but mark_completed threw an
    exception.

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

    # --- Case 2: pending/running → 409 (does NOT read repair_results) ---
    if task.status in (STATUS_PENDING, STATUS_RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": REPAIR_PLAN_NOT_READY,
                "error_message": get_error_message(REPAIR_PLAN_NOT_READY),
            },
        )

    # --- Case 3: failed → fixed safe empty (does NOT read repair_results) ---
    # Even if repair_results has a residual record (e.g.
    # generate_and_save_repair_plan succeeded but mark_completed threw),
    # must NOT return it.
    if task.status == STATUS_FAILED:
        return _build_safe_empty_repair_plan(task_id)

    # --- Case 4: completed → read repair plan via asyncio.to_thread ---
    if task.status == STATUS_COMPLETED:
        try:
            result = await asyncio.to_thread(get_repair_result, task_id)
        except RepairPlanInternalError:
            # Corrupted or invalid repair plan JSON — return fixed 500.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error_code": REPAIR_PLAN_INTERNAL_ERROR,
                    "error_message": get_error_message(
                        REPAIR_PLAN_INTERNAL_ERROR
                    ),
                },
            )
        if result is not None:
            return result
        # Repair plan missing — legacy P0-6 task or data integrity issue.
        # Must NOT return a success empty repair plan.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": REPAIR_PLAN_NOT_AVAILABLE,
                "error_message": get_error_message(
                    REPAIR_PLAN_NOT_AVAILABLE
                ),
            },
        )

    # --- Case 5: unknown status → internal error ---
    # Must NOT return a success empty repair plan.
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error_code": REPAIR_PLAN_INTERNAL_ERROR,
            "error_message": get_error_message(REPAIR_PLAN_INTERNAL_ERROR),
        },
    )
