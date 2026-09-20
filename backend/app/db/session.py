"""Async SQLAlchemy engine/session factory (SQLAlchemy 2 + asyncpg).

Engine is created once and managed by the FastAPI lifespan.
Never logs DATABASE_URL credentials.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _database_url() -> str:
    url = settings.database_url
    # Allow asyncpg URLs directly; rewrite common sync forms.
    if url.startswith("postgresql+asyncpg://"):
        return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("sqlite+aiosqlite://"):
        return url
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    return url


def get_engine() -> AsyncEngine:
    global _engine, _session_factory
    if _engine is None:
        from sqlalchemy.pool import NullPool

        url = _database_url()
        kwargs: dict = {
            "echo": False,
        }
        # Production/demo pool settings — env-overridable, modest defaults.
        if settings.app_env != "test" and not url.startswith("sqlite"):
            kwargs.update(
                {
                    "pool_pre_ping": True,
                    "pool_size": settings.db_pool_size,
                    "max_overflow": settings.db_max_overflow,
                    "pool_recycle": settings.db_pool_recycle_seconds,
                }
            )
        else:
            # Tests: no cross-event-loop pooled connections.
            kwargs["poolclass"] = NullPool
        _engine = create_async_engine(url, **kwargs)
        _session_factory = async_sessionmaker(
            _engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _session_factory is not None
    return _session_factory


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Provide a transactional AsyncSession (commit on success, rollback on error)."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_database_ready() -> None:
    """Raise when PostgreSQL is unreachable or required tables are missing."""
    from sqlalchemy import text

    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                """
                SELECT COUNT(*) AS cnt FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name IN (
                    'tasks', 'scan_results', 'assessment_results',
                    'repair_results', 'llm_analysis_results'
                  )
                """
            )
        )
        row = result.first()
        count = int(row[0]) if row else 0
        if count < 5:
            raise RuntimeError("database schema is not initialized")
