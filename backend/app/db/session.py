"""Async SQLAlchemy engine/session factory (SQLAlchemy 2 + asyncpg).

The application engine is created once on the application event loop and
managed by the FastAPI lifespan. Any other loop that reaches the database
(usually a sync facade running in asyncio.to_thread) gets its own unpooled
engine, because asyncpg connections cannot be shared between loops.
Never logs DATABASE_URL credentials.
"""

from __future__ import annotations

import asyncio
import logging
import weakref
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
_engine_loop: asyncio.AbstractEventLoop | None = None
_foreign: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, tuple[AsyncEngine, async_sessionmaker[AsyncSession]]
] = weakref.WeakKeyDictionary()


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


def _build(*, pooled: bool) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    from sqlalchemy.pool import NullPool

    url = _database_url()
    kwargs: dict = {"echo": False}
    if pooled and settings.app_env != "test" and not url.startswith("sqlite"):
        # Production/demo pool settings — env-overridable, modest defaults.
        kwargs.update(
            {
                "pool_pre_ping": True,
                "pool_size": settings.db_pool_size,
                "max_overflow": settings.db_max_overflow,
                "pool_recycle": settings.db_pool_recycle_seconds,
            }
        )
    else:
        # Tests, SQLite, and foreign loops: no cross-event-loop pooled
        # connections.
        kwargs["poolclass"] = NullPool
    engine = create_async_engine(url, **kwargs)
    return engine, async_sessionmaker(
        engine, expire_on_commit=False, class_=AsyncSession
    )


def _running_loop() -> asyncio.AbstractEventLoop | None:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _current_bundle() -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Return the engine/session pair bound to the calling event loop."""
    global _engine, _session_factory, _engine_loop

    loop = _running_loop()
    if _engine is None:
        _engine, _session_factory = _build(pooled=True)
        _engine_loop = loop
    elif _engine_loop is None and loop is not None:
        # Created outside a loop: the first loop to use it owns it.
        _engine_loop = loop
    if loop is None or _engine_loop is None or loop is _engine_loop:
        assert _engine is not None and _session_factory is not None
        return _engine, _session_factory

    # A different loop is asking for a connection. asyncpg binds each
    # connection (and every Future it awaits) to the loop that opened it, so
    # checking a pooled connection out here raises "attached to a different
    # loop" — and leaves the pool holding a connection nobody can use.
    bundle = _foreign.get(loop)
    if bundle is None:
        bundle = _build(pooled=False)
        _foreign[loop] = bundle
    return bundle


def get_engine() -> AsyncEngine:
    return _current_bundle()[0]


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return _current_bundle()[1]


async def dispose_engine() -> None:
    global _engine, _session_factory, _engine_loop
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
    _engine_loop = None
    for engine, _factory in list(_foreign.values()):
        await engine.dispose()
    _foreign.clear()


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
    """Raise when PostgreSQL is unreachable or migrations are incomplete.

    Required tables are derived from the ORM metadata, so adding a migration
    (e.g. quality_check_results) automatically raises the readiness bar. A
    database that was never migrated fails with an explicit message instead
    of crashing later on the first query.
    """
    from sqlalchemy import text

    from app.db import models  # noqa: F401 — populate Base.metadata
    from app.db.base import Base

    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                """
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                """
            )
        )
        present = {str(row[0]) for row in result}
        required = {table.name for table in Base.metadata.sorted_tables}
        missing = sorted(required - present)
        if missing:
            raise RuntimeError(
                "database schema is not migration-managed or incomplete "
                f"(missing: {', '.join(missing)}) — run `alembic upgrade head`"
            )
