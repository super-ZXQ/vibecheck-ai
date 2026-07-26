"""SQLite database layer — the single source of truth for task status.

Design:
- Uses Python's built-in sqlite3 module (no extra dependencies).
- Each operation opens a short-lived connection (SQLite handles this efficiently).
- WAL mode enabled for better concurrency.
- Thread-safe via check_same_thread=False + short-lived connections.
- NEVER stores downloaded files, code snippets, or sensitive content.

Tables:
- tasks:       Task lifecycle records (P0-3).
- scan_results: Persisted scan result snapshots (P0-5). One row per task_id.
               result_json contains only desensitized public models from P0-4.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings

# Thread-local storage for connections
_local = threading.local()

# Lock for DDL operations
_init_lock = threading.Lock()
_initialized = False


def _get_db_path() -> str:
    """Extract the filesystem path from the database_url setting."""
    url = settings.database_url
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "")
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "")
    return url


def _get_connection() -> sqlite3.Connection:
    """Create a new SQLite connection with proper settings."""
    db_path = _get_db_path()
    # Ensure parent directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    task_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
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
            conn.commit()
            _initialized = True
        finally:
            conn.close()


def reset_db() -> None:
    """Drop and recreate all tables — for testing only."""
    global _initialized
    with _init_lock:
        conn = _get_connection()
        try:
            # Drop scan_results first (FK references tasks)
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
