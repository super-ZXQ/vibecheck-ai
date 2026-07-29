"""FastAPI application entry point.

P0-3: Task status management + polling interface + service restart hook.

Lifecycle:
- On startup: initialize DB, mark stale running/pending tasks as failed.
- POST /api/check: create a check task (pending → running → completed/failed).
- GET /api/check/{task_id}: poll task status.
- GET /api/health: health check.
"""

import logging

from fastapi import FastAPI

from app.api.check import router as check_router
from app.api.assessment import router as assessment_router
from app.api.repair import router as repair_router
from app.db.database import init_db
from app.services.task_manager import mark_stale_tasks_as_failed

logger = logging.getLogger(__name__)

app = FastAPI(
    title="VibeCheck",
    description="项目上线体检工具 — 面向 Vibe Coding 与 AI 编程初学者",
    version="0.1.0",
)

# Include API routes
app.include_router(check_router)
app.include_router(assessment_router)
app.include_router(repair_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database and mark stale tasks as failed on service restart.

    - Running tasks → failed with SERVICE_RESTARTED
    - Pending tasks → failed with SERVICE_RESTARTED (avoid permanent waiters)
    """
    init_db()
    count = mark_stale_tasks_as_failed()
    if count > 0:
        logger.info(
            "Service restarted: marked %d stale task(s) as failed", count
        )


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "0.1.0"}
