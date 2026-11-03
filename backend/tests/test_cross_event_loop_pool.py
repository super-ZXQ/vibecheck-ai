"""Cross-event-loop connection-pool safety.

Production uses a pooled engine; the test suite runs on NullPool, which hides
the failure class where a sync facade opens a connection on one event loop and
another loop later checks the same connection back out. These tests force the
production pool settings so the hazard is visible.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import text

from app.core.config import settings
from app.db import session as session_mod
from app.services import task_manager


def _quiet_dispose() -> None:
    """Forget the engine; a pooled engine is disposed on its own loop."""
    session_mod._engine = None
    session_mod._session_factory = None
    session_mod._engine_loop = None
    session_mod._foreign.clear()


@pytest.fixture
def production_pool():
    """Rebuild the engine with production pool settings, then restore."""
    if not settings.database_url.startswith("postgresql"):
        pytest.skip("requires a PostgreSQL database_url")

    previous_env = settings.app_env
    _quiet_dispose()
    settings.app_env = "development"
    try:
        yield
    finally:
        settings.app_env = previous_env
        _quiet_dispose()


class TestWorkerThreadFacade:
    def test_thread_facade_leaves_the_pooled_connection_usable(self, production_pool):
        """A facade called off-loop must not poison the main loop's pool."""
        from app.db.session import get_engine

        async def scenario():
            engine = get_engine()
            assert type(engine.pool).__name__ == "AsyncAdaptedQueuePool", (
                "fixture did not produce the production pool"
            )

            owner = f"loop-safety-{uuid.uuid4().hex[:8]}"
            created = await task_manager.create_task_async(
                f"https://github.com/{owner}/repo", owner, "repo"
            )
            try:
                # Stage services still call these facades inside
                # asyncio.to_thread(), where no event loop is running.
                in_thread = await asyncio.to_thread(task_manager.get_task, created.id)
                assert in_thread is not None
                assert in_thread.id == created.id

                # The API path shares the engine on the original loop.
                on_loop = await task_manager.get_task_async(created.id)
                assert on_loop is not None
                assert on_loop.status == "pending"
            finally:
                async with engine.begin() as conn:
                    await conn.execute(
                        text("DELETE FROM tasks WHERE owner = :owner"),
                        {"owner": owner},
                    )
                from app.db.session import dispose_engine

                await dispose_engine()

        asyncio.run(scenario())

    def test_pooled_engine_is_not_shared_across_loops(self, production_pool):
        """Each event loop gets its own connections, never a foreign one."""
        from app.db.session import get_engine

        async def scenario():
            main_engine = get_engine()
            thread_engine = await asyncio.to_thread(
                lambda: asyncio.run(_engine_in_this_loop())
            )
            assert thread_engine is not main_engine
            assert type(main_engine.pool).__name__ == "AsyncAdaptedQueuePool"
            assert type(thread_engine.pool).__name__ != "AsyncAdaptedQueuePool"

            from app.db.session import dispose_engine

            await dispose_engine()

        async def _engine_in_this_loop():
            return get_engine()

        asyncio.run(scenario())
