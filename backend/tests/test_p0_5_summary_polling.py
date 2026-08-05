"""P0-5 review: summary polling, state ordering, and config invariant tests.

Covers the five test categories required by the P0-5 review:

1. Lightweight summary read — get_scan_summary reads only summary_json,
   never parsing full result_json for new records.
2. Result endpoint event loop — asyncio.to_thread keeps the event loop
   responsive during up to 8 MB SQLite reads.
3. Failed + residual result — failed tasks never return residual
   scan_results, even when save succeeded but mark_completed threw.
4. Config boundaries — Field(ge=1) rejects 0 and -1; defensive
   max(1, int(limit)) prevents runtime bypass.
5. Database compatibility — old databases without summary_json are
   safely migrated; existing data is preserved.
"""

import asyncio
import json
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.error_codes import (
    INTERNAL_ERROR,
)
from app.core.github import DownloadResult, parse_repo_url
from app.core.safe_extract import ExtractionResult
from app.db import database
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanResult,
    Severity,
)
from app.services import background_runner, task_manager
from app.services.scan_result_service import (
    SCHEMA_VERSION,
    get_scan_result,
    get_scan_summary,
    save_scan_result,
)


# ---------------------------------------------------------------------------
# --- Synthetic token (runtime-constructed, format-correct) ---
# ---------------------------------------------------------------------------

_MIXED_CHARS = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
RAW_TOKEN = "ghp_" + _MIXED_CHARS[:36]


# ---------------------------------------------------------------------------
# --- Fixtures ---
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Set up a temporary test database."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(
        "app.core.config.settings.database_url", f"sqlite:///{db_path}"
    )
    monkeypatch.setattr(
        "app.core.config.settings.tmp_dir", str(tmp_path / "tmp")
    )
    database._initialized = False
    database.init_db()
    yield db_path
    database._initialized = False


@pytest.fixture
def client(test_db):
    """Create a TestClient with the test database."""
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_runner():
    """Reset the background runner state before each test."""
    background_runner.reset_runner_state()
    yield
    background_runner.reset_runner_state()


# ---------------------------------------------------------------------------
# --- Helpers ---
# ---------------------------------------------------------------------------

def _make_finding(
    rule_id="R001",
    severity=Severity.LOW,
    is_blocking=False,
    **kwargs,
):
    defaults = dict(
        rule_id=rule_id,
        rule_name="Test Finding",
        severity=severity,
        confidence=Confidence.HIGH,
        file_path="src/config.py",
        line_start=10,
        line_end=10,
        column_start=1,
        column_end=20,
        snippet_masked=None,
        is_blocking=is_blocking,
        finding_type=FindingType.CONTENT,
        description="test description",
        category="test",
        secret_type=None,
        message="test message",
        repair_template_key=None,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_many_findings(count, **kwargs):
    return tuple(
        _make_finding(rule_id=f"R{i:04d}", file_path=f"src/file_{i}.py", **kwargs)
        for i in range(count)
    )


def make_mock_download_result(tmp_path, repo_url="https://github.com/testuser/testrepo"):
    temp_file = Path(tmp_path) / "mock-download.tar.gz"
    temp_file.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 100)
    repo_info = parse_repo_url(repo_url)
    return DownloadResult(
        temp_file=temp_file,
        repo_info=repo_info,
        file_size=temp_file.stat().st_size,
    )


def make_mock_extract_clean(tmp_path):
    dest = Path(tmp_path) / "mock-extract-clean"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "README.md").write_text("# Clean Repo\n\nNo secrets here.\n")
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=30,
        top_level_dir="mock-extract-clean",
    )


def make_mock_extract_with_secret(tmp_path):
    dest = Path(tmp_path) / "secret-repo"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "config.py").write_text(f'token = "{RAW_TOKEN}"\n')
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=len(RAW_TOKEN) + 12,
        top_level_dir="secret-repo",
    )


# ============================================================
# 1. Lightweight summary read tests
# ============================================================

class TestLightweightSummaryRead:
    """Verify get_scan_summary reads only summary_json, not full result_json.

    For new records, the normal path must read ONLY the lightweight
    summary_json column. The full result_json (up to 8 MB) must never
    be loaded or parsed during status polling.
    """

    def test_summary_reads_only_summary_json(self, test_db):
        """get_scan_summary must not parse full result_json for new records.

        Saves a result with many findings (large result_json), then spies
        on json.loads to verify only summary_json (small) is parsed.
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = _make_many_findings(100)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=100, total_lines_scanned=1000,
        )
        save_scan_result(task.id, result)

        # Spy on json.loads to record input lengths
        original_loads = json.loads
        loads_input_lengths = []

        def spy_loads(s, *args, **kwargs):
            if isinstance(s, str):
                loads_input_lengths.append(len(s))
            return original_loads(s, *args, **kwargs)

        with patch(
            "app.services.scan_result_service.json.loads",
            side_effect=spy_loads,
        ):
            summary = get_scan_summary(task.id)

        assert summary is not None
        assert summary["total_findings"] == 100

        # json.loads should have been called exactly once (for summary_json)
        assert len(loads_input_lengths) == 1, (
            f"Expected 1 json.loads call, got {len(loads_input_lengths)}"
        )
        # summary_json should be small (< 1 KB), not the full result_json
        # (which would be many KB with 100 findings)
        assert loads_input_lengths[0] < 1000, (
            f"json.loads input too large ({loads_input_lengths[0]} bytes) — "
            "likely parsed full result_json instead of summary_json"
        )

    def test_summary_works_with_corrupted_result_json(self, test_db):
        """If result_json is corrupted but summary_json is valid, summary works.

        This proves the normal path reads summary_json, not result_json.
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = _make_many_findings(10)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, result)

        # Corrupt result_json but leave summary_json intact
        from app.db.database import _get_connection
        conn = _get_connection()
        try:
            conn.execute(
                "UPDATE scan_results SET result_json = 'THIS IS INVALID JSON' "
                "WHERE task_id = ?",
                (task.id,),
            )
            conn.commit()
        finally:
            conn.close()

        # get_scan_summary must still work via summary_json
        summary = get_scan_summary(task.id)
        assert summary is not None
        assert summary["total_findings"] == 10
        assert summary["returned_findings"] == 10

    def test_status_endpoint_does_not_return_findings(self, client, test_db):
        """GET /api/check/{task_id} must not include findings in response."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        findings = _make_many_findings(50)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=50, total_lines_scanned=500,
        )
        save_scan_result(task.id, result)
        task_manager.mark_completed(task.id, 50, 5000, "test-repo")

        response = client.get(f"/api/check/{task.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["scan_summary"] is not None
        assert data["scan_summary"]["total_findings"] == 50
        assert data["report_url"] == f"/api/check/{task.id}/result"
        # Must NOT have findings field — that's only in the result endpoint
        assert "findings" not in data


# ============================================================
# 2. Result endpoint event loop tests
# ============================================================

class TestResultEndpointEventLoop:
    """Verify the result endpoint uses asyncio.to_thread and doesn't block.

    monkeypatches get_scan_result to block on a threading.Event while
    running in a thread. The asyncio event loop must remain responsive
    to other concurrent tasks during this period.
    """

    @pytest.mark.asyncio
    async def test_event_loop_responsive_during_result_read(self, test_db):
        """While get_scan_result blocks in a thread, event loop stays responsive."""
        from app.api.check import get_check_result

        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        save_scan_result(task.id, result)
        task_manager.mark_completed(task.id, 1, 10, "test-repo")

        read_event = threading.Event()
        read_started = threading.Event()
        loop_was_responsive = False

        original_get_result = get_scan_result

        def blocking_get_result(tid):
            read_started.set()
            read_event.wait(timeout=5)
            return original_get_result(tid)

        async def check_responsiveness():
            nonlocal loop_was_responsive
            await asyncio.sleep(0.05)
            loop_was_responsive = True

        with patch(
            "app.api.check.get_scan_result",
            side_effect=blocking_get_result,
        ):
            # Start the result request in the background
            result_task = asyncio.create_task(get_check_result(task.id))

            # Wait for get_scan_result to start in the thread
            for _ in range(200):
                if read_started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert read_started.is_set(), "get_scan_result did not start"

            # While blocked in thread, verify event loop is responsive
            await check_responsiveness()
            assert loop_was_responsive, (
                "Event loop was blocked during result read — "
                "asyncio.to_thread was not used"
            )

            # Release the blocked thread
            read_event.set()

            # Wait for the result
            response = await result_task
            assert response is not None
            assert "findings" in response
            assert "summary" in response


# ============================================================
# 3. Failed + residual result tests
# ============================================================

class TestFailedWithResidualResult:
    """Verify failed tasks never return residual scan_results.

    Even when save_scan_result succeeded but the task ended up failed
    (e.g. mark_completed threw), the result endpoint must return the
    fixed safe empty response, never the residual findings.
    """

    def test_failed_with_residual_result_returns_safe_empty(self, client, test_db):
        """Failed task with a scan_results record must return safe empty.

        Steps:
        A. Create a task.
        B. Save a real scan_result with findings.
        C. Mark the task as failed.
        D. Call the result endpoint.
        E. Must return fixed safe empty result.
        F. Must not return database residual findings.
        """
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        # B. Save a real scan result with findings
        findings = _make_many_findings(5)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=50,
        )
        save_scan_result(task.id, result)

        # Verify the record exists
        assert get_scan_result(task.id) is not None
        assert len(get_scan_result(task.id)["findings"]) == 5

        # C. Mark as failed
        task_manager.mark_failed(task.id, "SCAN_INTERNAL_ERROR")

        # D. Call result endpoint
        response = client.get(f"/api/check/{task.id}/result")

        # E. Must return fixed safe empty result
        assert response.status_code == 200
        data = response.json()
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0
        assert data["summary"]["blocking_findings"] == 0

        # F. Must not return residual findings
        assert len(data["findings"]) == 0

    @pytest.mark.asyncio
    async def test_failure_window_mark_completed_throws(
        self, client, test_db, tmp_path
    ):
        """Simulate failure window: save succeeds, mark_completed throws.

        - save_scan_result succeeds (scan_results record exists)
        - mark_completed raises an exception
        - Task ends up failed (via outer exception handler)
        - scan_results record exists with real findings
        - Result endpoint must NOT return the residual findings
        """
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_with_secret(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.mark_completed",
                    side_effect=RuntimeError("simulated mark_completed failure"),
                ):
                    await background_runner._process_task(task.id)

        # Task must be failed
        task_record = task_manager.get_task(task.id)
        assert task_record.status == "failed"
        assert task_record.error_code == INTERNAL_ERROR

        # scan_results record exists (save_scan_result succeeded)
        residual = get_scan_result(task.id)
        assert residual is not None, "scan_results record should exist"
        assert len(residual["findings"]) > 0, (
            "Residual record should have real findings from the scan"
        )

        # Result endpoint must NOT return residual findings
        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 200  # Safe empty response
        data = response.json()
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0
        # Must not contain any residual finding data
        assert len(data["findings"]) == 0


# ============================================================
# 4. Config boundary tests
# ============================================================

class TestConfigBoundaries:
    """Verify strict positive validation for all result limit fields.

    - 0 and -1 must be rejected at Settings init (Field ge=1)
    - Default values must be valid
    - Runtime monkeypatch to negative must not bypass truncation
      (defensive max(1, int(limit)))
    - Blocking findings must still be prioritized
    """

    _LIMIT_FIELDS = [
        "scan_max_persisted_findings_per_task",
        "scan_max_persisted_notices_per_task",
        "scan_max_persisted_skipped_files_per_task",
        "scan_max_persisted_scan_errors_per_task",
        "scan_max_result_json_bytes",
    ]

    @pytest.mark.parametrize("field_name", _LIMIT_FIELDS)
    def test_zero_rejected_at_init(self, field_name):
        """Setting any limit field to 0 must fail at Settings init."""
        with pytest.raises(ValidationError):
            Settings(**{field_name: 0})

    @pytest.mark.parametrize("field_name", _LIMIT_FIELDS)
    def test_negative_rejected_at_init(self, field_name):
        """Setting any limit field to -1 must fail at Settings init."""
        with pytest.raises(ValidationError):
            Settings(**{field_name: -1})

    def test_default_values_valid(self):
        """Default config values must be valid and match expected defaults."""
        s = Settings()
        assert s.scan_max_persisted_findings_per_task == 1000
        assert s.scan_max_persisted_notices_per_task == 500
        assert s.scan_max_persisted_skipped_files_per_task == 2000
        assert s.scan_max_persisted_scan_errors_per_task == 500
        assert s.scan_max_result_json_bytes == 8 * 1024 * 1024

    def test_runtime_negative_does_not_bypass_truncation(self, test_db, monkeypatch):
        """limit=-1 must NOT cause items[:-1] behavior.

        Even if monkeypatch bypasses Pydantic validation, the defensive
        max(1, int(limit)) in _truncate_findings must clamp to 1.
        """
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", -1
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = _make_many_findings(5)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=50,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)

        # max(1, -1) = 1, so exactly 1 finding kept
        assert len(retrieved["findings"]) == 1, (
            "limit=-1 should clamp to 1, not produce items[:-1] behavior"
        )
        assert retrieved["summary"]["findings_truncated"] is True
        assert retrieved["summary"]["total_findings"] == 5
        assert retrieved["summary"]["returned_findings"] == 1

    def test_runtime_zero_does_not_bypass_truncation(self, test_db, monkeypatch):
        """limit=0 must NOT bypass truncation design.

        Even if monkeypatch bypasses Pydantic validation, the defensive
        max(1, int(limit)) in _truncate_findings must clamp to 1.
        """
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 0
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = _make_many_findings(5)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=50,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)

        # max(1, 0) = 1, so exactly 1 finding kept
        assert len(retrieved["findings"]) == 1, (
            "limit=0 should clamp to 1, not return empty or all findings"
        )
        assert retrieved["summary"]["findings_truncated"] is True

    def test_blocking_finding_prioritized_with_limit_1(self, test_db, monkeypatch):
        """With limit=1, blocking finding must be retained over non-blocking."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 1
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = (
            _make_finding(
                rule_id="LOW",
                severity=Severity.LOW,
                is_blocking=False,
                file_path="low.py",
            ),
            _make_finding(
                rule_id="BLOCK",
                severity=Severity.CRITICAL,
                is_blocking=True,
                file_path="critical.py",
            ),
        )
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=2, total_lines_scanned=20,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)

        assert len(retrieved["findings"]) == 1
        assert retrieved["findings"][0]["rule_id"] == "BLOCK"
        assert retrieved["summary"]["blocking_findings"] == 1


# ============================================================
# 5. Database compatibility tests
# ============================================================

class TestDatabaseCompatibility:
    """Verify safe migration for old databases without summary_json.

    - New databases have summary_json NOT NULL
    - Old databases get summary_json added via ALTER TABLE
    - Existing tasks and results are not deleted
    - Old records fall back to result_json for summary reads
    - New records use summary_json (never fall back)
    """

    def test_new_db_has_summary_json_column(self, test_db):
        """New database should have summary_json column."""
        from app.db.database import _get_connection
        conn = _get_connection()
        try:
            columns = conn.execute(
                "PRAGMA table_info(scan_results)"
            ).fetchall()
            column_names = [col["name"] for col in columns]
            assert "summary_json" in column_names
        finally:
            conn.close()

    def test_old_db_migrated_adds_summary_json(self, tmp_path, monkeypatch):
        """Old database without summary_json gets it added by init_db.

        Simulates an old database created before the summary_json column
        existed. init_db must safely add the column via ALTER TABLE.
        """
        db_path = tmp_path / "old.db"
        monkeypatch.setattr(
            "app.core.config.settings.database_url", f"sqlite:///{db_path}"
        )

        # Create old-style tables WITHOUT summary_json
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE tasks (
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
            CREATE TABLE scan_results (
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
                updated_at TEXT NOT NULL
            )
        """)
        # Insert existing data
        conn.execute("""
            INSERT INTO tasks (id, repo_url, owner, repo_name, status, stage,
                progress, error_code, error_message, file_count, total_size,
                top_level_dir, created_at, updated_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?)
        """, (
            "old-task-id", "https://github.com/test/repo", "test", "repo",
            "completed", "finished", 100, 5, 500, "test-repo",
            "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
        ))
        old_result = {
            "schema_version": 1,
            "findings": [],
            "summary": {"total_findings": 3, "blocking_findings": 1},
        }
        conn.execute("""
            INSERT INTO scan_results (task_id, schema_version, result_json,
                total_findings, blocking_findings, total_notices,
                total_skipped_files, total_scan_errors,
                total_files_scanned, total_lines_scanned,
                created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "old-task-id", 1, json.dumps(old_result),
            3, 1, 0, 0, 0, 5, 50,
            "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
        ))
        conn.commit()
        conn.close()

        # Run init_db — should add summary_json via ALTER TABLE
        database._initialized = False
        database.init_db()

        # Verify summary_json was added
        conn = sqlite3.connect(str(db_path))
        columns = conn.execute("PRAGMA table_info(scan_results)").fetchall()
        column_names = [col[1] for col in columns]
        assert "summary_json" in column_names

        # Verify existing task was NOT deleted
        row = conn.execute(
            "SELECT id, status FROM tasks WHERE id = ?", ("old-task-id",)
        ).fetchone()
        assert row is not None
        assert row[0] == "old-task-id"
        assert row[1] == "completed"

        # Verify existing result was NOT deleted
        row = conn.execute(
            "SELECT task_id, result_json FROM scan_results WHERE task_id = ?",
            ("old-task-id",),
        ).fetchone()
        assert row is not None
        assert row[0] == "old-task-id"
        assert json.loads(row[1])["summary"]["total_findings"] == 3
        conn.close()

    def test_old_record_falls_back_to_result_json(self, tmp_path, monkeypatch):
        """Old record with NULL summary_json falls back to reading result_json.

        After migration, old records have summary_json = NULL.
        get_scan_summary must fall back to parsing result_json for these.
        """
        db_path = tmp_path / "old_fallback.db"
        monkeypatch.setattr(
            "app.core.config.settings.database_url", f"sqlite:///{db_path}"
        )

        # Create old-style database
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE tasks (
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
            CREATE TABLE scan_results (
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
                updated_at TEXT NOT NULL
            )
        """)
        old_summary = {
            "total_findings": 7,
            "blocking_findings": 2,
            "total_notices": 1,
            "total_skipped_files": 0,
            "total_scan_errors": 0,
            "total_files_scanned": 10,
            "total_lines_scanned": 100,
        }
        old_result = {
            "schema_version": 1,
            "findings": [],
            "summary": old_summary,
        }
        conn.execute("""
            INSERT INTO scan_results (task_id, schema_version, result_json,
                total_findings, blocking_findings, total_notices,
                total_skipped_files, total_scan_errors,
                total_files_scanned, total_lines_scanned,
                created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "fallback-task", 1, json.dumps(old_result),
            7, 2, 1, 0, 0, 10, 100,
            "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
        ))
        conn.commit()
        conn.close()

        # Run migration
        database._initialized = False
        database.init_db()

        # get_scan_summary should fall back to result_json
        summary = get_scan_summary("fallback-task")
        assert summary is not None
        assert summary["total_findings"] == 7
        assert summary["blocking_findings"] == 2

    def test_new_record_does_not_use_fallback(self, test_db):
        """New record with valid summary_json must not read result_json.

        After saving a new record, corrupt result_json. get_scan_summary
        must still work because it reads summary_json, not result_json.
        """
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = _make_many_findings(5)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=50,
        )
        save_scan_result(task.id, result)

        # Corrupt result_json — if get_scan_summary reads it, it would fail
        from app.db.database import _get_connection
        conn = _get_connection()
        try:
            conn.execute(
                "UPDATE scan_results SET result_json = 'CORRUPTED' "
                "WHERE task_id = ?",
                (task.id,),
            )
            conn.commit()
        finally:
            conn.close()

        # get_scan_summary must still work via summary_json
        summary = get_scan_summary(task.id)
        assert summary is not None
        assert summary["total_findings"] == 5

        # get_scan_result would fail (reads corrupted result_json)
        # — this is expected and proves the paths are separated
        with pytest.raises(json.JSONDecodeError):
            get_scan_result(task.id)

    def test_new_save_can_read_summary(self, test_db):
        """New record saved after migration can read summary normally."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = _make_many_findings(3)
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=3, total_lines_scanned=30,
        )
        save_scan_result(task.id, result)

        # Summary should be readable
        summary = get_scan_summary(task.id)
        assert summary is not None
        assert summary["total_findings"] == 3
        assert summary["returned_findings"] == 3
        assert summary["findings_truncated"] is False

        # Full result should also be readable
        full = get_scan_result(task.id)
        assert full is not None
        assert len(full["findings"]) == 3
        assert full["summary"]["total_findings"] == 3
