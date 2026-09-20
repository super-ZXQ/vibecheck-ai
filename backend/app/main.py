"""FastAPI application entry point.

PostgreSQL-backed production entry:
- Startup: async schema ensure, lease recovery, dispatcher start
- Shutdown: stop dispatcher, clear BYOK, dispose engine
- /metrics: Prometheus text (no high-cardinality labels)
- /api/ready: PostgreSQL readiness only; LLM outage is not fatal
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.assessment import router as assessment_router
from app.api.check import router as check_router
from app.api.repair import router as repair_router
from app.core.config import Settings, settings
from app.core.security_headers import SecurityHeadersMiddleware
from app.db.database import init_db_async
from app.db.session import check_database_ready, dispose_engine
from app.services import metrics as metrics_mod

logger = logging.getLogger(__name__)
APP_VERSION = "0.2.0"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Initialize PostgreSQL persistence and background dispatcher on this loop."""
    # Schema ensure MUST run on the uvicorn event loop so the SQLAlchemy
    # async engine binds to the same loop used by request handlers.
    await init_db_async()

    from app.services.task_manager import (
        get_pending_count_async,
        get_running_count_async,
        recover_expired_tasks_async,
    )

    try:
        recovery = await recover_expired_tasks_async()
        if recovery.get("requeued") or recovery.get("dead"):
            logger.info(
                "Service restarted: requeued=%d dead=%d",
                recovery.get("requeued", 0),
                recovery.get("dead", 0),
            )
    except Exception as e:
        logger.error("Lease recovery failed: %s", type(e).__name__)

    # Cleanup helpers are sync wrappers; run them without touching the
    # request-loop SQLAlchemy engine (they use _run_sync internally).
    try:
        import asyncio as _aio

        from app.services.cleanup_service import cleanup_expired_tasks, cleanup_residual_temp_files

        await _aio.to_thread(cleanup_residual_temp_files)
        await _aio.to_thread(cleanup_expired_tasks)
    except Exception as e:
        logger.error("Startup cleanup failed: %s", type(e).__name__)

    from app.services.background_runner import start_dispatcher, stop_dispatcher

    if settings.app_env != "test":
        try:
            await start_dispatcher()
        except Exception as e:
            logger.error("Dispatcher start failed: %s", type(e).__name__)

    try:
        metrics_mod.set_gauge("vibecheck_queue_depth", float(await get_pending_count_async()))
        metrics_mod.set_gauge("vibecheck_active_tasks", float(await get_running_count_async()))
    except Exception:
        pass

    try:
        yield
    finally:
        try:
            await stop_dispatcher()
        except Exception as e:
            logger.error("Dispatcher stop failed: %s", type(e).__name__)
        try:
            from app.services.llm_user_config import clear_user_configs
            clear_user_configs()
        except Exception:
            pass
        try:
            await dispose_engine()
        except Exception:
            pass


def create_app(app_settings: Settings = settings) -> FastAPI:
    """Build the application with explicit environment-dependent controls."""
    production = app_settings.app_env == "production"
    api = FastAPI(
        title="VibeCheck",
        description=(
            "项目上线体检工具 — 安全扫描 + 可靠后台任务 "
            "(PostgreSQL-backed durable bounded task execution)"
        ),
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
        """Readiness: PostgreSQL must be available. LLM outage is not fatal."""
        db_ok = False
        llm_configured = bool(
            app_settings.llm_enabled
            and app_settings.llm_api_key
            and app_settings.llm_base_url
        )
        try:
            # Async engine check on the request event loop.
            await check_database_ready()
            db_ok = True
        except Exception:
            logger.error("Database readiness check failed")

        deps = {
            "database": "ok" if db_ok else "unavailable",
            "llm": "configured" if llm_configured else "not_configured",
        }
        if not db_ok:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "dependencies": deps},
            )
        return JSONResponse(content={"status": "ready", "dependencies": deps})

    @api.get("/metrics", include_in_schema=False)
    async def prometheus_metrics() -> PlainTextResponse:
        """Prometheus metrics. Labels never include repo/task/paths/secrets."""
        try:
            from app.services.llm_user_config import count_user_configs
            from app.services.task_manager import (
                get_pending_count_async,
                get_running_count_async,
            )
            metrics_mod.set_gauge(
                "vibecheck_queue_depth", float(await get_pending_count_async())
            )
            metrics_mod.set_gauge(
                "vibecheck_active_tasks", float(await get_running_count_async())
            )
            metrics_mod.set_gauge(
                "vibecheck_llm_keys_in_memory", float(count_user_configs())
            )
        except Exception:
            pass
        return PlainTextResponse(
            metrics_mod.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return api


app = create_app()
