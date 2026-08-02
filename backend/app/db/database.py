"""SQLite database layer — the single source of truth for task status.

Design:
- Uses Python's built-in sqlite3 module (no extra dependencies).
- Each operation opens a short-lived connection (SQLite handles this efficiently).
- WAL mode enabled for better concurrency.
- Thread-safe via check_same_thread=False + short-lived connections.
- NEVER stores downloaded repository source files or raw sensitive content.
- scan_results may store explicitly masked display snippets (snippet_masked).
- Masked snippets must never contain original secrets.

Tables:
- tasks:              Task lifecycle records (P0-3).
- scan_results:       Persisted scan result snapshots (P0-5). One row per task_id.
                      result_json contains only desensitized public models from P0-4.
- assessment_results: Persisted security assessment snapshots (P0-6). One row
                      per task_id. assessment_json contains only deterministic
                      scoring output computed from the already-desensitized
                      scan_results. score and verdict are redundant columns for
                      lightweight polling queries. Never contains raw secrets.
- repair_results:     Persisted repair plan snapshots (P0-7). One row per
                      task_id. repair_json contains only deterministic repair
                      plan output computed from the already-desensitized
                      scan_results and assessment_results. plan_status and
                      total/blocking group counts are redundant columns for
                      lightweight polling queries. Never contains raw secrets.
"""

import os
import sqlite3
import threading
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings

# Thread-local storage for connections
_local = threading.local()

# Lock for DDL operations
_init_lock = threading.Lock()
_initialized = False

# Production data root — can be overridden in tests via monkeypatch.
_DATA_ROOT = Path("/data")

_REQUIRED_TABLES = frozenset(
    {
        "tasks",
        "scan_results",
        "assessment_results",
        "repair_results",
    }
)


# ---------------------------------------------------------------------------
# Production database path validation (symlink / traversal defence)
# ---------------------------------------------------------------------------

def validate_production_database_path(
    database_url: str,
    data_root: Path = Path("/data"),
) -> Path:
    """Validate the production database path against symlink and traversal attacks.

    Complements the URL lexical validation in config.py with runtime
    real-path checks.  Returns the resolved database path on success.

    Raises ValueError on any validation failure.  Error messages never
    include the full database path.

    Checks performed:
      1. URL-decode the path and reject encoded path-traversal characters.
      2. Resolve data_root (must exist) and database path (parent must exist).
      3. Require the resolved database path to be inside data_root.
      4. Walk every existing path component from data_root to the database
         file and reject if any component is a symlink — even if the
         symlink target is inside data_root (unified rejection policy).
    """
    # --- Step 1: Extract and URL-decode the path ---
    if not database_url.startswith("sqlite:///"):
        raise ValueError("production database_url must use the sqlite scheme")

    raw_path = database_url.removeprefix("sqlite:///")

    # Reject encoded dangerous characters in the raw URL.
    lower_raw = raw_path.lower()
    for encoded in ("%2e", "%2f", "%5c", "%00"):
        if encoded in lower_raw:
            raise ValueError(
                "production database path contains forbidden encoded character"
            )

    # URL-decode the path.
    decoded_path = urllib.parse.unquote(raw_path)

    # Check decoded path for dangerous content.
    if "\x00" in decoded_path:
        raise ValueError("production database path contains NUL character")
    # On POSIX, backslash is not a path separator and could be used to confuse path validation.  On Windows, backslashes are valid path separators.
    if os.name != "nt" and "\\" in decoded_path:
        raise ValueError("production database path contains backslash")

    # --- Step 2: Use real Path for resolution ---
    database_path = Path(decoded_path)

    if not database_path.is_absolute():
        raise ValueError("production database path must be absolute")

    # Normalize without resolving symlinks so the original path chain remains
    # observable. Reject traversal before checking each component.
    if ".." in database_path.parts:
        raise ValueError("production database path is outside the data root")

    data_root_absolute = Path(os.path.abspath(data_root))
    database_path_absolute = Path(os.path.abspath(database_path))
    try:
        lexical_relative = database_path_absolute.relative_to(
            data_root_absolute
        )
    except ValueError as exc:
        raise ValueError(
            "production database path is outside the data root"
        ) from exc

    # Check the lexical path before resolve() erases symlink components.
    if data_root_absolute.is_symlink():
        raise ValueError(
            "production database path contains a symlink component"
        )
    current = data_root_absolute
    for component in lexical_relative.parts:
        current = current / component
        if current.is_symlink():
            raise ValueError(
                "production database path contains a symlink component"
            )

    # Resolve data_root (must exist) and enforce containment against the real
    # target as a second, independent check.
    data_root_resolved = data_root_absolute.resolve(strict=True)
    database_path_resolved = database_path_absolute.resolve(strict=False)
    try:
        database_path_resolved.relative_to(data_root_resolved)
    except ValueError as exc:
        raise ValueError(
            "production database path is outside the data root"
        ) from exc

    return database_path_resolved


def _verify_database_list_path(
    conn: sqlite3.Connection,
    data_root: Path | None = None,
) -> None:
    """Verify the actual opened database path via PRAGMA database_list.

    After SQLite opens the database, confirm the real file path is still
    inside data_root.  This catches runtime symlink replacement that
    occurs after the initial path validation.

    Raises ValueError if the connection's main database is outside
    data_root.  Error messages never include the full database path.
    """
    if data_root is None:
        data_root = _DATA_ROOT

    data_root_resolved = data_root.resolve(strict=True)

    rows = conn.execute("PRAGMA database_list").fetchall()
    for row in rows:
        if row["name"] == "main":
            db_file = row["file"]
            if not db_file:
                # In-memory database — must not happen in production.
                raise ValueError("production database is in-memory")
            db_path = Path(db_file).resolve(strict=False)
            try:
                db_path.relative_to(data_root_resolved)
            except ValueError:
                raise ValueError(
                    "production database connection opened outside the data root"
                )
            return

    raise ValueError("production database connection has no main database")


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

def _get_db_path() -> str:
    """Extract the filesystem path from the database_url setting."""
    url = settings.database_url
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "")
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "")
    return url


def _is_production_data_path() -> bool:
    """Return True when production mode with a /data SQLite path is active."""
    return (
        settings.app_env == "production"
        and settings.database_url.startswith("sqlite:////data/")
    )


def _get_connection() -> sqlite3.Connection:
    """Create a new SQLite connection with proper settings."""
    if _is_production_data_path():
        validated = validate_production_database_path(
            settings.database_url,
            _DATA_ROOT,
        )
        db_path = str(validated)
    else:
        db_path = _get_db_path()

    # Ensure parent directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")

        if _is_production_data_path():
            _verify_database_list_path(conn, _DATA_ROOT)
            validate_production_database_path(
                settings.database_url,
                _DATA_ROOT,
            )
    except Exception:
        conn.close()
        raise

    return conn


def init_db() -> None:
    """Initialize the database — create tables if they don't exist.

    Safe to call multiple times.
    """
    global _initialized
    with _init_lock:
        if _initialized:
            return
        conn = _get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    repo_url TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    repo_name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    stage TEXT NOT NULL DEFAULT 'queued',
                    progress INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    error_message TEXT,
                    file_count INTEGER,
                    total_size INTEGER,
                    top_level_dir TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at)
            """)
            # --- scan_results: one persisted snapshot per task (P0-5) ---
            # result_json contains ONLY desensitized public models from P0-4.
            # Never stores raw secrets, absolute paths, or internal objects.
            # summary_json (P0-5 review): lightweight summary extracted from
            # result_json, stored separately so status polling never needs to
            # load or parse the full (up to 8 MB) result_json.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    task_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    blocking_findings INTEGER NOT NULL,
                    total_notices INTEGER NOT NULL,
                    total_skipped_files INTEGER NOT NULL,
                    total_scan_errors INTEGER NOT NULL,
                    total_files_scanned INTEGER NOT NULL,
                    total_lines_scanned INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks(id)
                )
            """)
            # --- Migration: add summary_json column if missing ---
            # Old databases created before this change don't have
            # summary_json. We add it as nullable so old records keep
            # working — get_scan_summary falls back to result_json for
            # records with NULL summary_json. New records always set it.
            columns = conn.execute(
                "PRAGMA table_info(scan_results)"
            ).fetchall()
            column_names = [col["name"] for col in columns]
            if "summary_json" not in column_names:
                conn.execute(
                    "ALTER TABLE scan_results ADD COLUMN summary_json TEXT"
                )
            # --- assessment_results: one persisted assessment per task (P0-6) ---
            # assessment_json contains ONLY deterministic scoring output computed
            # from the already-desensitized scan_results. No raw secrets, no
            # temp paths, no internal exception objects.
            # score and verdict are redundant columns so polling queries can
            # read two lightweight values instead of parsing assessment_json.
            # source_scan_updated_at tracks which scan_results version this
            # assessment was computed from.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assessment_results (
                    task_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    policy_version TEXT NOT NULL,
                    assessment_scope TEXT NOT NULL,
                    assessment_json TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    source_scan_updated_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks(id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_assessment_verdict
                ON assessment_results(verdict)
            """)
            # --- repair_results: one persisted repair plan per task (P0-7) ---
            # repair_json contains ONLY deterministic repair plan output
            # computed from the already-desensitized scan_results and
            # assessment_results. No raw secrets, no temp paths, no
            # internal exception objects, no repo_url.
            # plan_status and total/blocking group counts are redundant
            # columns so polling queries can read lightweight values
            # instead of parsing repair_json.
            # source_scan_updated_at and source_assessment_updated_at
            # track which scan_results and assessment_results versions
            # this repair plan was computed from.
            # No repair_status index is created — it has no actual query
            # use at this stage.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS repair_results (
                    task_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    policy_version TEXT NOT NULL,
                    repair_scope TEXT NOT NULL,
                    repair_json TEXT NOT NULL,
                    plan_status TEXT NOT NULL,
                    total_repair_groups INTEGER NOT NULL,
                    blocking_repair_groups INTEGER NOT NULL,
                    source_scan_updated_at TEXT NOT NULL,
                    source_assessment_updated_at TEXT NOT NULL,
                    source_assessment_policy_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks(id)
                )
            """)
            conn.commit()
            _initialized = True
        finally:
            conn.close()


def check_database_ready() -> None:
    """Raise when the database is unavailable or not initialized."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name IN (
                  'tasks',
                  'scan_results',
                  'assessment_results',
                  'repair_results'
              )
            """
        ).fetchall()
        present_tables = {row["name"] for row in rows}
        if present_tables != _REQUIRED_TABLES:
            raise RuntimeError("database schema is not initialized")
    finally:
        conn.close()


def reset_db() -> None:
    """Drop and recreate all tables — for testing only."""
    global _initialized
    with _init_lock:
        conn = _get_connection()
        try:
            # Drop repair_results, assessment_results, and scan_results
            # first (FK references tasks)
            conn.execute("DROP TABLE IF EXISTS repair_results")
            conn.execute("DROP TABLE IF EXISTS assessment_results")
            conn.execute("DROP TABLE IF EXISTS scan_results")
            conn.execute("DROP TABLE IF EXISTS tasks")
            conn.commit()
        finally:
            conn.close()
        _initialized = False
    # Call init_db() OUTSIDE the lock to avoid deadlock
    # (init_db() also acquires _init_lock — threading.Lock is not reentrant)
    init_db()


def now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()
