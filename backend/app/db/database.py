"""Database lifecycle compatibility layer (SQLAlchemy 2 async + PostgreSQL).

Production schema is owned by Alembic. create_all is only for smoke/tests.
Legacy sync `_get_connection()` remains for transitional tests and executes
SQL through SQLAlchemy against PostgreSQL (not sqlite3).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.db import models  # noqa: F401
from app.db.base import Base
from app.db.session import (
    check_database_ready as _async_check_ready,
)
from app.db.session import (
    dispose_engine,
    get_engine,
    get_session_factory,
)

logger = logging.getLogger(__name__)

_initialized = False
_DATA_ROOT = Path("/data")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


async def _create_all_async() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def init_db() -> None:
    global _initialized
    if _initialized:
        return
    _run(_create_all_async())
    _initialized = True


def reset_initialized() -> None:
    global _initialized
    _initialized = False


async def reset_engine_async() -> None:
    global _initialized
    await dispose_engine()
    _initialized = False


def reset_engine() -> None:
    _run(reset_engine_async())


def check_database_ready() -> None:
    _run(_async_check_ready())


class _LegacyRow(dict):
    def __getitem__(self, key):  # type: ignore[override]
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class _LegacyResult:
    def __init__(self, rows: list[dict], rowcount: int = 0):
        self._rows = rows
        self.rowcount = rowcount

    def fetchone(self):
        return _LegacyRow(self._rows[0]) if self._rows else None

    def fetchall(self):
        return [_LegacyRow(r) for r in self._rows]



_TS_COLS = {
    "created_at",
    "updated_at",
    "completed_at",
    "lease_expires_at",
    "last_heartbeat_at",
    "next_attempt_at",
    "cancelled_at",
}


def _insert_columns(sql: str) -> list[str]:
    m = re.search(r"INSERT\s+INTO\s+\w+\s*\(([^)]+)\)", sql, re.IGNORECASE | re.DOTALL)
    if not m:
        return []
    raw = m.group(1).replace("\n", " ").replace("\r", " ")
    return [c.strip().strip('`"') for c in raw.split(",") if c.strip()]


def _insert_qmark_columns(sql: str) -> list[str]:
    """Column names corresponding 1:1 to ``?`` placeholders in VALUES.

    INSERT statements may skip columns with literal NULL; positional ``?``
    params must not be mapped onto the raw column list by index.
    """
    cols = _insert_columns(sql)
    m = re.search(r"VALUES\s*\(([^)]+)\)", sql, re.IGNORECASE | re.DOTALL)
    if not m:
        return cols
    vals = [v.strip() for v in m.group(1).replace("\n", " ").split(",")]
    out: list[str] = []
    for i, v in enumerate(vals):
        if v == "?" and i < len(cols):
            out.append(cols[i])
    return out


def _update_timestamp_columns(sql: str) -> set[str]:
    """Column names that appear in SET ... as timestamp targets."""
    found = set()
    for col in _TS_COLS:
        if re.search(rf"\b{col}\s*=", sql, re.IGNORECASE):
            found.add(col)
    return found


def _maybe_datetime(value: Any) -> Any:
    """Coerce ISO timestamp strings for PostgreSQL TIMESTAMPTZ columns."""
    if not isinstance(value, str):
        return value
    s = value.strip()
    if len(s) < 19 or ("T" not in s and " " not in s):
        return value
    try:
        dt = datetime.fromisoformat(s if "+" in s[10:] or s.endswith("Z") is False else s[:-1] + "+00:00") if False else datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return value



def _rewrite_sqlite_upsert(sql: str) -> str:
    """Convert SQLite INSERT OR REPLACE into PostgreSQL upsert."""
    m = re.search(
        r"INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\(([^)]+)\)",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return sql
    cols = [c.strip().strip('`"') for c in m.group(2).replace("\n", " ").split(",")]
    if not cols:
        return sql
    pk = cols[0]
    rest = cols[1:]
    sql2 = re.sub(
        r"INSERT\s+OR\s+REPLACE\s+INTO",
        "INSERT INTO",
        sql,
        count=1,
        flags=re.IGNORECASE,
    )
    if not rest:
        return sql2
    idx = sql2.rfind(")")
    if idx < 0:
        return sql2
    updates = ", ".join(f"{c}=EXCLUDED.{c}" for c in rest)
    return sql2[: idx + 1] + f" ON CONFLICT ({pk}) DO UPDATE SET {updates}" + sql2[idx + 1 :]


def _convert_sql(sql: str, params: Any) -> tuple[str, dict]:
    sql = _rewrite_sqlite_upsert(sql)
    """Convert sqlite-style qmark params to SQLAlchemy named params.

    Only known TIMESTAMP columns receive datetime coercion so TEXT columns
    (source_*_updated_at, repair_json, etc.) keep ISO strings.
    """
    if params is None:
        return sql, {}
    if isinstance(params, dict):
        out = dict(params)
        ts_names = _update_timestamp_columns(sql)
        for k, v in list(out.items()):
            if k in _TS_COLS or k in ts_names:
                out[k] = _maybe_datetime(v)
        return sql, out
    seq = list(params)
    named: dict[str, Any] = {}
    if re.search(r"INSERT\s+INTO", sql, re.IGNORECASE):
        cols = _insert_qmark_columns(sql)
    else:
        # UPDATE ... SET col = ?, col2 = ? — map ? to assignment targets in order
        cols = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\?", sql)
    ts_names = _update_timestamp_columns(sql)
    parts = []
    i = 0
    for ch in sql:
        if ch == "?":
            key = f"p{i}"
            val = seq[i] if i < len(seq) else None
            col = cols[i] if i < len(cols) else ""
            if col in _TS_COLS or col in ts_names:
                val = _maybe_datetime(val)
            named[key] = val
            parts.append(f":{key}")
            i += 1
        else:
            parts.append(ch)
    return "".join(parts), named



class _LegacyConnection:
    """Sync facade executing SQL via SQLAlchemy async engine + asyncio.run."""

    def __init__(self) -> None:
        self.rowcount = 0

    def execute(self, sql: str, params: Any = None) -> _LegacyResult:
        from sqlalchemy import text

        new_sql, named = _convert_sql(sql, params)

        async def _exec():
            engine = get_engine()
            async with engine.begin() as conn:
                result = await conn.execute(text(new_sql), named)
                rows: list[dict] = []
                try:
                    mappings = result.mappings()
                    rows = [dict(m) for m in mappings.all()]
                except Exception:
                    try:
                        rows = [dict(r._mapping) for r in result.all()]
                    except Exception:
                        rows = []
                return rows, result.rowcount or 0

        rows, rc = _run(_exec())
        self.rowcount = rc
        return _LegacyResult(rows, rc)

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None


def _get_connection():
    return _LegacyConnection()


def reset_db() -> None:
    async def _reset() -> None:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    global _initialized
    reset_engine()
    _run(_reset())
    _initialized = True


def validate_production_database_path(database_url: str, data_root: Path | None = None) -> Path:
    from urllib.parse import urlsplit

    parsed = urlsplit(database_url.replace("+asyncpg", ""))
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ValueError("production database_url must use the postgresql scheme")
    return Path("/data")


def _verify_database_list_path(conn, data_root=None) -> None:
    return None


def _is_production_data_path() -> bool:
    return settings.app_env == "production" and settings.database_url.startswith(
        ("postgresql", "postgres")
    )


def _get_db_path() -> str:
    return settings.database_url


def _get_session_factory():
    return get_session_factory()


__all__ = [
    "_get_connection",
    "_get_session_factory",
    "check_database_ready",
    "init_db",
    "now_iso",
    "reset_db",
    "reset_engine",
    "reset_initialized",
    "validate_production_database_path",
]
