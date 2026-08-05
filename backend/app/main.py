"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.assessment import router as assessment_router
from app.api.check import router as check_router
from app.api.repair import router as repair_router
from app.core.config import Settings, settings
from app.core.security_headers import SecurityHeadersMiddleware
from app.db.database import check_database_ready, init_db
from app.services.task_manager import mark_stale_tasks_as_failed

logger = logging.getLogger(__name__)
APP_VERSION = "0.1.0"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Initialize persistence, clean stale tasks, and remove residual temp files."""
    init_db()
    count = mark_stale_tasks_as_failed()
    if count > 0:
        logger.info(
            "Service restarted: marked %d stale task(s) as failed",
            count,
        )
    # P2-3: Clean up residual temp files from crashed processes.
    from app.services.cleanup_service import (
        cleanup_expired_tasks,
        cleanup_residual_temp_files,
    )
    cleanup_residual_temp_files()
    # P2-3: Delete expired reports on startup.
    expired = cleanup_expired_tasks()
    if expired > 0:
        logger.info("Startup cleanup: expired %d old report(s)", expired)
    yield


def create_app(app_settings: Settings = settings) -> FastAPI:
    """Build the application with explicit environment-dependent controls."""
    production = app_settings.app_env == "production"
    api = FastAPI(
        title="VibeCheck",
        description="项目上线体检工具 — 面向 Vibe Coding 与 AI 编程初学者",
        version=APP_VERSION,
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
        lifespan=lifespan,
    )

    api.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Accept",
            # Caller-supplied per-task LLM config (feature: per-user LLM).
            "X-LLM-API-KEY",
            "X-LLM-BASE-URL",
            "X-LLM-MODEL",
        ],
    )
    api.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=app_settings.trusted_hosts,
    )
    api.add_middleware(
        SecurityHeadersMiddleware,
        production=production,
    )

    api.include_router(check_router)
    api.include_router(assessment_router)
    api.include_router(repair_router)

    @api.get("/api/health", include_in_schema=False)
    async def health_check() -> dict[str, str]:
        """Liveness check with no external or persistence dependency."""
        return {"status": "ok", "version": APP_VERSION}

    @api.get("/api/ready", include_in_schema=False)
    async def readiness_check() -> JSONResponse:
        """Readiness check that fails closed when persistence is unavailable."""
        try:
            check_database_ready()
        except Exception:
            logger.error("Database readiness check failed")
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready"},
            )
        return JSONResponse(content={"status": "ready"})

    return api


app = create_app()
