"""Readiness derives required tables from ORM metadata instead of a hardcoded list."""

from __future__ import annotations

import asyncio

import pytest

from app.db import session as db_session


class _FakeResult:
    def __init__(self, table_names: set[str]) -> None:
        self._rows = [(name,) for name in sorted(table_names)]

    def __iter__(self):
        return iter(self._rows)


class _FakeConnection:
    def __init__(self, table_names: set[str]) -> None:
        self._table_names = table_names

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def execute(self, statement):
        return _FakeResult(self._table_names)


class _FakeEngine:
    def __init__(self, table_names: set[str]) -> None:
        self._table_names = table_names

    def connect(self):
        return _FakeConnection(self._table_names)


def _required_tables() -> set[str]:
    from app.db import models  # noqa: F401
    from app.db.base import Base

    return {table.name for table in Base.metadata.sorted_tables}


def _check(monkeypatch, present: set[str]) -> None:
    monkeypatch.setattr(
        db_session, "get_engine", lambda: _FakeEngine(present)
    )
    asyncio.run(db_session.check_database_ready())


def test_ready_when_all_metadata_tables_exist(monkeypatch):
    _check(monkeypatch, _required_tables())


def test_missing_migrated_table_fails_with_actionable_message(monkeypatch):
    present = _required_tables() - {"quality_check_results"}
    with pytest.raises(RuntimeError, match="quality_check_results"):
        _check(monkeypatch, present)
    with pytest.raises(RuntimeError, match="alembic upgrade head"):
        _check(monkeypatch, present)
