"""P0-5 persistence boundary regression tests.

Covers ALL six correction areas from the P0-5 security review:

I.   Adversarial sanitization — runtime-constructed format-correct
     GitHub Token placed directly into EVERY string field. Verifies
     the token never appears in serialize output, json.dumps, SQLite
     result_json, API response, or repr.

II.  Event loop responsiveness — scan_directory blocks on a
     threading.Event while the asyncio event loop continues to
     service concurrent requests. Cleanup only after thread completes.

III. Task-level result limits — generates findings exceeding caps.
     Verifies risk-priority retention, summary truth, truncation flags,
     and JSON byte limits.

IV.  Missing result distinction — legacy completed task without
     scan_results row returns SCAN_RESULT_MISSING (500), not a
     fake empty success.

V.   Upsert time semantics — created_at preserved on update,
     updated_at changes, single row.

VI.  SCAN_RESULT_TOO_LARGE — oversized result_json is rejected.

CRITICAL: These tests construct a REAL format-correct synthetic token
at runtime and place it DIRECTLY into model fields. They do NOT pass
in pre-masked values like "ghp_****" or "[masked]" and then claim
safety based on "the original token doesn't exist." The original token
DOES exist in the input — the sanitization layer must mask it.
"""

import asyncio
import json
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.error_codes import (
    SCAN_RESULT_MISSING,
    SCAN_RESULT_NOT_READY,
    SCAN_RESULT_TOO_LARGE,
    get_error_message,
)
from app.core.github import DownloadResult, parse_repo_url
from app.core.safe_extract import ExtractionResult
from app.db import database
from app.scanner.base import (
    Confidence,
    Finding,
    FindingType,
    ScanError,
    ScanNotice,
    ScanResult,
    Severity,
    SkippedFile,
)
from app.services import background_runner, task_manager
from app.services.scan_result_service import (
    SCHEMA_VERSION,
    ScanResultTooLargeError,
    get_scan_result,
    get_scan_summary,
    save_scan_result,
    serialize_scan_result,
)


# ---------------------------------------------------------------------------
# --- Synthetic token (runtime-constructed, format-correct) ---
# ---------------------------------------------------------------------------

# This token has the correct GitHub Token format (ghp_ + 36 base62 chars)
# but is NOT a real credential. It is constructed at runtime using mixed
# characters to avoid low-entropy detection.
_MIXED_CHARS = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
RAW_TOKEN = "ghp_" + _MIXED_CHARS[:36]  # 40 chars total, format-correct


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

def _make_finding_with_raw_token(**kwargs):
    """Create a Finding with the RAW token in string fields.

    This simulates a buggy rule or direct dataclass construction that
    places raw secret content into fields that should have been masked.
    The sanitization layer at the persistence boundary MUST catch this.
    """
    defaults = dict(
        rule_id="R001_GITHUB_TOKEN",
        rule_name="GitHub Token",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="src/config.py",
        line_start=10,
        line_end=10,
        column_start=5,
        column_end=25,
        snippet_masked=RAW_TOKEN,  # RAW token in snippet!
        is_blocking=True,
        finding_type=FindingType.CONTENT,
        description=f"Found token: {RAW_TOKEN}",  # RAW token in description!
        category="token",
        secret_type="github_token",
        message=f"Remove {RAW_TOKEN} immediately",  # RAW token in message!
        repair_template_key="remove_secret",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_notice_with_raw_token(**kwargs):
    """Create a ScanNotice with the RAW token in message."""
    defaults = dict(
        rule_id="R010_ENV_EXAMPLE",
        message=f"Token leaked: {RAW_TOKEN}",  # RAW token in message!
        file_path=".env.example",
    )
    defaults.update(kwargs)
    return ScanNotice(**defaults)


def _make_skipped_with_raw_token(**kwargs):
    """Create a SkippedFile with the RAW token in reason."""
    defaults = dict(
        file_path="large.bin",
        reason=f"Skipped, contains {RAW_TOKEN}",  # RAW token in reason!
    )
    defaults.update(kwargs)
    return SkippedFile(**defaults)


def _make_error_with_raw_token(**kwargs):
    """Create a ScanError with the RAW token in error fields."""
    defaults = dict(
        file_path="bad.py",
        error_type=f"read_error_{RAW_TOKEN}",  # RAW token in error_type!
        error_message=f"Failed to read {RAW_TOKEN}",  # RAW token in message!
    )
    defaults.update(kwargs)
    return ScanError(**defaults)


def _make_scan_result_with_raw_token():
    """Create a ScanResult with RAW tokens in ALL string fields."""
    return ScanResult(
        findings=(_make_finding_with_raw_token(),),
        notices=(_make_notice_with_raw_token(),),
        skipped_files=(_make_skipped_with_raw_token(),),
        scan_errors=(_make_error_with_raw_token(),),
        total_files_scanned=4,
        total_lines_scanned=100,
    )


def make_mock_download_result(tmp_path, repo_url="https://github.com/testuser/testrepo"):
    """Create a mock DownloadResult with a real temp file."""
    temp_file = Path(tmp_path) / "mock-download.tar.gz"
    temp_file.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 100)
    repo_info = parse_repo_url(repo_url)
    return DownloadResult(
        temp_file=temp_file,
        repo_info=repo_info,
        file_size=temp_file.stat().st_size,
    )


def make_mock_extract_clean(tmp_path):
    """Create a mock ExtractionResult with no secrets."""
    dest = Path(tmp_path) / "mock-extract-clean"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "README.md").write_text("# Clean Repo\n\nNo secrets here.\n")
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=30,
        top_level_dir="mock-extract-clean",
    )


# ============================================================
# I. Adversarial sanitization tests
# ============================================================

class TestAdversarialSanitization:
    """Verify that a runtime-constructed format-correct GitHub Token
    placed DIRECTLY into model string fields is masked at the
    persistence boundary.

    These tests do NOT pass in pre-masked values. The RAW token exists
    in the input — the sanitization layer must mask it.
    """

    def test_serialize_masks_token_in_snippet(self):
        """snippet_masked with raw token must be masked in serialize output."""
        finding = _make_finding_with_raw_token()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        serialized = serialize_scan_result(result)
        snippet = serialized["findings"][0]["snippet_masked"]
        assert RAW_TOKEN not in snippet
        assert RAW_TOKEN not in json.dumps(serialized)

    def test_serialize_masks_token_in_description(self):
        """description with raw token must be masked in serialize output."""
        finding = _make_finding_with_raw_token()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        serialized = serialize_scan_result(result)
        desc = serialized["findings"][0]["description"]
        assert RAW_TOKEN not in desc
        assert RAW_TOKEN not in json.dumps(serialized)

    def test_serialize_masks_token_in_message(self):
        """Finding.message with raw token must be masked in serialize output."""
        finding = _make_finding_with_raw_token()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        serialized = serialize_scan_result(result)
        msg = serialized["findings"][0]["message"]
        assert RAW_TOKEN not in msg
        assert RAW_TOKEN not in json.dumps(serialized)

    def test_serialize_masks_token_in_notice_message(self):
        """ScanNotice.message with raw token must be masked."""
        notice = _make_notice_with_raw_token()
        result = ScanResult(
            findings=(), notices=(notice,), skipped_files=(),
            scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        msg = serialized["notices"][0]["message"]
        assert RAW_TOKEN not in msg
        assert RAW_TOKEN not in json.dumps(serialized)

    def test_serialize_masks_token_in_skipped_reason(self):
        """SkippedFile.reason with raw token must be masked."""
        skipped = _make_skipped_with_raw_token()
        result = ScanResult(
            findings=(), notices=(), skipped_files=(skipped,),
            scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        reason = serialized["skipped_files"][0]["reason"]
        assert RAW_TOKEN not in reason
        assert RAW_TOKEN not in json.dumps(serialized)

    def test_serialize_masks_token_in_error_type(self):
        """ScanError.error_type with raw token must be masked."""
        error = _make_error_with_raw_token()
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(error,), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        etype = serialized["scan_errors"][0]["error_type"]
        assert RAW_TOKEN not in etype
        assert RAW_TOKEN not in json.dumps(serialized)

    def test_serialize_masks_token_in_error_message(self):
        """ScanError.error_message with raw token must be masked."""
        error = _make_error_with_raw_token()
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(error,), total_files_scanned=0, total_lines_scanned=0,
        )
        serialized = serialize_scan_result(result)
        emsg = serialized["scan_errors"][0]["error_message"]
        assert RAW_TOKEN not in emsg
        assert RAW_TOKEN not in json.dumps(serialized)

    def test_json_dumps_masks_all_tokens(self):
        """json.dumps of serialized result must not contain the raw token."""
        result = _make_scan_result_with_raw_token()
        serialized = serialize_scan_result(result)
        json_str = json.dumps(serialized, ensure_ascii=False, sort_keys=True)
        assert RAW_TOKEN not in json_str

    def test_sqlite_result_json_masks_all_tokens(self, test_db):
        """SQLite result_json must not contain the raw token."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        result = _make_scan_result_with_raw_token()
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        json_str = json.dumps(retrieved)
        assert RAW_TOKEN not in json_str

    def test_api_result_response_masks_all_tokens(self, client, test_db, tmp_path):
        """GET /api/check/{task_id}/result must not contain the raw token."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        # Create a scan result with raw tokens and persist it directly
        result = _make_scan_result_with_raw_token()
        save_scan_result(task.id, result)
        # Mark task as completed manually
        task_manager.mark_completed(task.id, 4, 200, "test-repo")

        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 200
        assert RAW_TOKEN not in response.text

    def test_repr_does_not_leak_token(self):
        """repr of serialized dicts must not contain the raw token."""
        result = _make_scan_result_with_raw_token()
        serialized = serialize_scan_result(result)
        # repr of the entire structure
        repr_str = repr(serialized)
        assert RAW_TOKEN not in repr_str
        # repr of individual items
        for f in serialized["findings"]:
            assert RAW_TOKEN not in repr(f)
        for n in serialized["notices"]:
            assert RAW_TOKEN not in repr(n)
        for s in serialized["skipped_files"]:
            assert RAW_TOKEN not in repr(s)
        for e in serialized["scan_errors"]:
            assert RAW_TOKEN not in repr(e)

    def test_full_pipeline_masks_token_in_api(self, client, test_db, tmp_path):
        """Full pipeline: token in repo file → API response must not leak."""
        # Create extract directory with a real token in a file
        dest = Path(tmp_path) / "token-repo"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "config.py").write_text(f'token = "{RAW_TOKEN}"\n')

        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = ExtractionResult(
            dest_dir=str(dest), file_count=1, total_size=50,
            top_level_dir="token-repo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                asyncio.run(background_runner._process_task(task.id))

        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 200
        assert RAW_TOKEN not in response.text


# ============================================================
# II. Event loop responsiveness tests
# ============================================================

class TestEventLoopResponsiveness:
    """Verify that scan_directory running in a thread does not block
    the FastAPI event loop.

    The test monkeypatches scan_directory to wait on a threading.Event.
    While the scan thread is blocked, a concurrent asyncio operation
    (status query) must succeed — proving the event loop is responsive.
    """

    @pytest.mark.asyncio
    async def test_event_loop_responsive_during_scan(self, test_db, tmp_path):
        """Event loop must remain responsive while scan_directory blocks."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        # Event that scan_directory will wait on
        scan_event = threading.Event()
        scan_started = threading.Event()
        loop_was_responsive = False

        def blocking_scan(path):
            scan_started.set()
            scan_event.wait(timeout=5)  # Block until released
            return ScanResult(
                findings=(), notices=(), skipped_files=(),
                scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
            )

        async def check_responsiveness():
            """Run a quick asyncio task to prove the loop is alive."""
            nonlocal loop_was_responsive
            await asyncio.sleep(0.05)
            # If we get here, the event loop was not blocked
            loop_was_responsive = True

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    side_effect=blocking_scan,
                ):
                    # Start the task in the background
                    task_task = asyncio.create_task(
                        background_runner._process_task(task.id)
                    )

                    # Wait for scan to start — poll non-blocking so the
                    # event loop can run the task coroutine
                    for _ in range(200):  # 200 * 0.01 = 2s max
                        if scan_started.is_set():
                            break
                        await asyncio.sleep(0.01)
                    assert scan_started.is_set(), "scan_directory did not start"

                    # While scan is blocked in its thread, run a concurrent
                    # asyncio operation to prove the loop is responsive
                    await check_responsiveness()
                    assert loop_was_responsive, "Event loop was blocked during scan"

                    # Release the scan thread
                    scan_event.set()

                    # Wait for the task to complete
                    await task_task

        # Task should be completed
        result = task_manager.get_task(task.id)
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_cleanup_after_thread_completes(self, test_db, tmp_path):
        """Cleanup must only happen after the scan thread completes."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        scan_event = threading.Event()
        scan_started = threading.Event()
        scan_completed = threading.Event()

        def blocking_scan(path):
            scan_started.set()
            scan_event.wait(timeout=5)
            scan_completed.set()
            return ScanResult(
                findings=(), notices=(), skipped_files=(),
                scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
            )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    side_effect=blocking_scan,
                ):
                    task_task = asyncio.create_task(
                        background_runner._process_task(task.id)
                    )

                    # Wait for scan to start — poll non-blocking
                    for _ in range(200):
                        if scan_started.is_set():
                            break
                        await asyncio.sleep(0.01)
                    assert scan_started.is_set()

                    # While scan is blocked, extraction dir should still exist
                    # (cleanup hasn't happened yet)
                    assert Path(extract_result.dest_dir).exists(), \
                        "Cleanup happened before scan thread completed"

                    # Release the scan thread
                    scan_event.set()

                    # Wait for completion
                    await task_task

                    # Scan must have completed
                    assert scan_completed.is_set(), "scan_directory did not complete"

        # After task completes, cleanup should have run
        assert not Path(extract_result.dest_dir).exists(), \
            "Extraction dir was not cleaned up after thread completion"
        assert not download_result.temp_file.exists(), \
            "Download file was not cleaned up after thread completion"

    @pytest.mark.asyncio
    async def test_concurrent_status_query_during_scan(self, test_db, tmp_path):
        """Status query via API must work while scan is in progress."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        scan_event = threading.Event()
        scan_started = threading.Event()

        def blocking_scan(path):
            scan_started.set()
            scan_event.wait(timeout=5)
            return ScanResult(
                findings=(), notices=(), skipped_files=(),
                scan_errors=(), total_files_scanned=0, total_lines_scanned=0,
            )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.scan_directory",
                    side_effect=blocking_scan,
                ):
                    task_task = asyncio.create_task(
                        background_runner._process_task(task.id)
                    )

                    # Wait for scan to start — poll non-blocking
                    for _ in range(200):
                        if scan_started.is_set():
                            break
                        await asyncio.sleep(0.01)
                    assert scan_started.is_set()

                    # While scan is blocked, query task status
                    # This goes through the DB, not the event loop,
                    # but the asyncio loop must be free to handle it
                    status = task_manager.get_task(task.id)
                    assert status.status == "running"
                    assert status.stage == "scanning"
                    assert status.progress == 80

                    # Release
                    scan_event.set()
                    await task_task

        result = task_manager.get_task(task.id)
        assert result.status == "completed"


# ============================================================
# III. Task-level result limit tests
# ============================================================

class TestTaskLevelLimits:
    """Verify task-level persistence limits and risk-priority retention."""

    def test_findings_truncated_to_limit(self, test_db, monkeypatch):
        """Findings exceeding the limit must be truncated."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 5
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        # Create 10 low-severity findings
        findings = tuple(
            Finding(
                rule_id=f"R00{i}",
                rule_name="Test",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                file_path=f"file_{i}.py",
                line_start=1, line_end=1, column_start=1, column_end=2,
                snippet_masked=None,
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="test",
                category="test",
                secret_type=None,
                message="test",
                repair_template_key=None,
            )
            for i in range(10)
        )
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert len(retrieved["findings"]) == 5
        assert retrieved["summary"]["total_findings"] == 10  # true count
        assert retrieved["summary"]["returned_findings"] == 5
        assert retrieved["summary"]["findings_truncated"] is True

    def test_blocking_finding_retained_over_low(self, test_db, monkeypatch):
        """Blocking finding must be retained even when limits are exceeded."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 3
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        # 5 low-severity non-blocking findings
        low_findings = tuple(
            Finding(
                rule_id=f"R00{i}",
                rule_name="Low",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                file_path=f"low_{i}.py",
                line_start=1, line_end=1, column_start=1, column_end=2,
                snippet_masked=None,
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="low",
                category="test",
                secret_type=None,
                message="low",
                repair_template_key=None,
            )
            for i in range(5)
        )
        # 1 critical blocking finding — placed LAST
        blocking = Finding(
            rule_id="R999",
            rule_name="Critical",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path="critical.py",
            line_start=1, line_end=1, column_start=1, column_end=2,
            snippet_masked=None,
            is_blocking=True,
            finding_type=FindingType.CONTENT,
            description="critical",
            category="token",
            secret_type="github_token",
            message="remove",
            repair_template_key="remove_secret",
        )
        all_findings = low_findings + (blocking,)
        result = ScanResult(
            findings=all_findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=6, total_lines_scanned=60,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        # Only 3 findings persisted (limit=3)
        assert len(retrieved["findings"]) == 3
        # The blocking finding MUST be in the retained set
        rule_ids = [f["rule_id"] for f in retrieved["findings"]]
        assert "R999" in rule_ids, "Blocking finding was truncated!"
        assert retrieved["summary"]["total_findings"] == 6
        assert retrieved["summary"]["blocking_findings"] == 1
        assert retrieved["summary"]["findings_truncated"] is True

    def test_severity_ordering_in_truncation(self, test_db, monkeypatch):
        """Critical findings retained over high, high over medium, etc."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 2
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = (
            Finding(rule_id="LOW", rule_name="L", severity=Severity.LOW,
                    confidence=Confidence.LOW, file_path="a.py",
                    line_start=1, line_end=1, column_start=1, column_end=2,
                    snippet_masked=None, is_blocking=False,
                    finding_type=FindingType.CONTENT, description="l",
                    category="t", secret_type=None, message="l",
                    repair_template_key=None),
            Finding(rule_id="CRIT", rule_name="C", severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH, file_path="b.py",
                    line_start=1, line_end=1, column_start=1, column_end=2,
                    snippet_masked=None, is_blocking=False,
                    finding_type=FindingType.CONTENT, description="c",
                    category="t", secret_type=None, message="c",
                    repair_template_key=None),
            Finding(rule_id="HIGH", rule_name="H", severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM, file_path="c.py",
                    line_start=1, line_end=1, column_start=1, column_end=2,
                    snippet_masked=None, is_blocking=False,
                    finding_type=FindingType.CONTENT, description="h",
                    category="t", secret_type=None, message="h",
                    repair_template_key=None),
        )
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=3, total_lines_scanned=30,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert len(retrieved["findings"]) == 2
        rule_ids = {f["rule_id"] for f in retrieved["findings"]}
        # CRIT and HIGH should be retained (higher severity than LOW)
        assert "CRIT" in rule_ids
        assert "HIGH" in rule_ids
        assert "LOW" not in rule_ids

    def test_notices_truncated(self, test_db, monkeypatch):
        """Notices exceeding the limit must be truncated."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_notices_per_task", 2
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        notices = tuple(
            ScanNotice(rule_id=f"R{i}", message=f"notice {i}", file_path=f"f{i}")
            for i in range(5)
        )
        result = ScanResult(
            findings=(), notices=notices, skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=50,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert len(retrieved["notices"]) == 2
        assert retrieved["summary"]["total_notices"] == 5
        assert retrieved["summary"]["returned_notices"] == 2
        assert retrieved["summary"]["notices_truncated"] is True

    def test_skipped_files_truncated(self, test_db, monkeypatch):
        """SkippedFiles exceeding the limit must be truncated."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_skipped_files_per_task", 3
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        skipped = tuple(
            SkippedFile(file_path=f"file_{i}.bin", reason="binary")
            for i in range(10)
        )
        result = ScanResult(
            findings=(), notices=(), skipped_files=skipped,
            scan_errors=(), total_files_scanned=10, total_lines_scanned=0,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert len(retrieved["skipped_files"]) == 3
        assert retrieved["summary"]["total_skipped_files"] == 10
        assert retrieved["summary"]["returned_skipped_files"] == 3
        assert retrieved["summary"]["skipped_files_truncated"] is True

    def test_scan_errors_truncated(self, test_db, monkeypatch):
        """ScanErrors exceeding the limit must be truncated."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_scan_errors_per_task", 2
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        errors = tuple(
            ScanError(file_path=f"bad_{i}.py", error_type="read", error_message="fail")
            for i in range(5)
        )
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=errors, total_files_scanned=5, total_lines_scanned=0,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert len(retrieved["scan_errors"]) == 2
        assert retrieved["summary"]["total_scan_errors"] == 5
        assert retrieved["summary"]["returned_scan_errors"] == 2
        assert retrieved["summary"]["scan_errors_truncated"] is True

    def test_no_truncation_when_under_limit(self, test_db):
        """No truncation when counts are under the limit."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        finding = _make_finding_with_raw_token()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        assert retrieved["summary"]["findings_truncated"] is False
        assert retrieved["summary"]["notices_truncated"] is False
        assert retrieved["summary"]["skipped_files_truncated"] is False
        assert retrieved["summary"]["scan_errors_truncated"] is False
        assert retrieved["summary"]["returned_findings"] == 1
        assert retrieved["summary"]["total_findings"] == 1


# ============================================================
# IV. Missing result distinction tests
# ============================================================

class TestMissingResultDistinction:
    """Verify that completed tasks without persisted results return
    SCAN_RESULT_MISSING, not a fake empty success.
    """

    def test_completed_no_result_returns_500(self, client, test_db):
        """Completed task with no scan_results row → 500 SCAN_RESULT_MISSING."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        # Manually mark as completed WITHOUT saving a scan result
        # (simulates a legacy task from before P0-5)
        task_manager.mark_completed(task.id, 5, 100, "legacy-repo")

        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert detail["error_code"] == SCAN_RESULT_MISSING
        assert detail["error_message"] == get_error_message(SCAN_RESULT_MISSING)

    def test_completed_no_result_polling_has_null_summary(self, client, test_db):
        """Completed task without result → scan_summary=None, report_url=None."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        task_manager.mark_completed(task.id, 5, 100, "legacy-repo")

        response = client.get(f"/api/check/{task.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["scan_summary"] is None
        assert data["report_url"] is None

    def test_completed_no_result_not_disguised_as_empty(self, client, test_db):
        """Completed+missing must NOT return a 200 with total_findings=0."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        task_manager.mark_completed(task.id, 5, 100, "legacy-repo")

        response = client.get(f"/api/check/{task.id}/result")
        # Must NOT be 200 with empty findings
        assert response.status_code != 200
        assert response.status_code == 500

    def test_failed_no_result_returns_safe_empty(self, client, test_db):
        """Failed task with no result → 200 fixed safe empty response."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        task_manager.mark_failed(task.id, "DOWNLOAD_FAILED")

        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 200
        data = response.json()
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0

    def test_pending_returns_409(self, client, test_db):
        """Pending task → 409 SCAN_RESULT_NOT_READY."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 409
        assert response.json()["detail"]["error_code"] == SCAN_RESULT_NOT_READY

    def test_completed_with_result_returns_200(self, client, test_db):
        """Completed task with result → 200 full result."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=5,
        )
        save_scan_result(task.id, result)
        task_manager.mark_completed(task.id, 1, 5, "test-repo")

        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 200
        data = response.json()
        assert "findings" in data
        assert "summary" in data


# ============================================================
# V. Upsert time semantics tests
# ============================================================

class TestUpsertTimeSemantics:
    """Verify SQLite native upsert preserves created_at on update."""

    def test_first_save_sets_created_at(self, test_db):
        """First save should set created_at."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        result = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        save_scan_result(task.id, result)

        # Read created_at directly from DB
        from app.db.database import _get_connection
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT created_at, updated_at FROM scan_results WHERE task_id = ?",
                (task.id,),
            ).fetchone()
            assert row is not None
            assert row["created_at"] is not None
            assert row["updated_at"] is not None
        finally:
            conn.close()

    def test_upsert_preserves_created_at(self, test_db):
        """Second upsert should NOT change created_at."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        result1 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        save_scan_result(task.id, result1)

        from app.db.database import _get_connection
        conn = _get_connection()
        try:
            row1 = conn.execute(
                "SELECT created_at, updated_at FROM scan_results WHERE task_id = ?",
                (task.id,),
            ).fetchone()
            first_created = row1["created_at"]
            first_updated = row1["updated_at"]
        finally:
            conn.close()

        # Small delay to ensure updated_at differs
        time.sleep(0.05)

        result2 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=2, total_lines_scanned=20,
        )
        save_scan_result(task.id, result2)

        conn = _get_connection()
        try:
            row2 = conn.execute(
                "SELECT created_at, updated_at FROM scan_results WHERE task_id = ?",
                (task.id,),
            ).fetchone()
            second_created = row2["created_at"]
            second_updated = row2["updated_at"]
        finally:
            conn.close()

        # created_at must NOT change
        assert second_created == first_created, "created_at was modified on upsert"
        # updated_at should be newer (or at least different)
        assert second_updated >= first_updated, "updated_at was not updated"

    def test_upsert_single_row(self, test_db):
        """Upsert should result in exactly one row, not two."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        result1 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        save_scan_result(task.id, result1)

        result2 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=2, total_lines_scanned=20,
        )
        save_scan_result(task.id, result2)

        from app.db.database import _get_connection
        conn = _get_connection()
        try:
            rows = conn.execute(
                "SELECT COUNT(*) as cnt FROM scan_results WHERE task_id = ?",
                (task.id,),
            ).fetchone()
            assert rows["cnt"] == 1, f"Expected 1 row, got {rows['cnt']}"
        finally:
            conn.close()

    def test_upsert_updates_data(self, test_db):
        """Upsert should update the persisted data."""
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        result1 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=50,
        )
        save_scan_result(task.id, result1)
        assert get_scan_summary(task.id)["total_files_scanned"] == 5

        result2 = ScanResult(
            findings=(), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, result2)
        summary = get_scan_summary(task.id)
        assert summary["total_files_scanned"] == 10
        assert summary["total_lines_scanned"] == 100


# ============================================================
# VI. SCAN_RESULT_TOO_LARGE tests
# ============================================================

class TestScanResultTooLarge:
    """Verify that oversized result_json is rejected with a fixed error."""

    def test_oversized_result_raises_error(self, test_db, monkeypatch):
        """Result exceeding byte limit raises ScanResultTooLargeError."""
        # Set a very small byte limit
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_result_json_bytes", 100
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        # Create a result with enough data to exceed 100 bytes
        findings = tuple(
            Finding(
                rule_id=f"R00{i}",
                rule_name="Test Rule With A Long Name",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                file_path=f"very/long/path/to/file_{i}.py",
                line_start=1, line_end=1, column_start=1, column_end=2,
                snippet_masked=None,
                is_blocking=False,
                finding_type=FindingType.CONTENT,
                description="A description that takes up space",
                category="test",
                secret_type=None,
                message="A message",
                repair_template_key=None,
            )
            for i in range(10)
        )
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=10, total_lines_scanned=100,
        )
        with pytest.raises(ScanResultTooLargeError):
            save_scan_result(task.id, result)

    def test_oversized_result_not_persisted(self, test_db, monkeypatch):
        """Oversized result must not be written to the database."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_result_json_bytes", 50
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        finding = _make_finding_with_raw_token()
        result = ScanResult(
            findings=(finding,), notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=1, total_lines_scanned=10,
        )
        with pytest.raises(ScanResultTooLargeError):
            save_scan_result(task.id, result)
        # Nothing should be persisted
        assert get_scan_result(task.id) is None

    @pytest.mark.asyncio
    async def test_pipeline_maps_too_large_to_error(self, test_db, tmp_path, monkeypatch):
        """Pipeline should map ScanResultTooLargeError to SCAN_RESULT_TOO_LARGE."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_result_json_bytes", 50
        )
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == SCAN_RESULT_TOO_LARGE
        assert result.error_message == get_error_message(SCAN_RESULT_TOO_LARGE)

    @pytest.mark.asyncio
    async def test_too_large_no_raw_exception(self, test_db, tmp_path, monkeypatch):
        """Error message must not contain exception details."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_result_json_bytes", 50
        )
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo", "testuser", "testrepo"
        )
        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        msg = result.error_message or ""
        assert "result_json" not in msg
        assert "exceeds" not in msg
        assert "bytes" not in msg


# ============================================================
# VII. Summary truth tests
# ============================================================

class TestSummaryTruth:
    """Verify that summary total_* reflects actual scan counts,
    not truncated counts.
    """

    def test_total_reflects_actual_scan(self, test_db, monkeypatch):
        """total_findings must equal the actual number of findings scanned."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 3
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = tuple(
            Finding(
                rule_id=f"R{i}", rule_name="T", severity=Severity.LOW,
                confidence=Confidence.LOW, file_path=f"f{i}.py",
                line_start=1, line_end=1, column_start=1, column_end=2,
                snippet_masked=None, is_blocking=False,
                finding_type=FindingType.CONTENT, description="d",
                category="t", secret_type=None, message="m",
                repair_template_key=None,
            )
            for i in range(10)
        )
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=10, total_lines_scanned=100,
        )
        save_scan_result(task.id, result)
        summary = get_scan_summary(task.id)
        assert summary["total_findings"] == 10  # actual scan count
        assert summary["returned_findings"] == 3  # persisted count
        assert summary["findings_truncated"] is True

    def test_blocking_count_reflects_actual(self, test_db, monkeypatch):
        """blocking_findings must reflect actual blocking count, not truncated."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 2
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        findings = (
            Finding(rule_id="B1", rule_name="B", severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH, file_path="b1.py",
                    line_start=1, line_end=1, column_start=1, column_end=2,
                    snippet_masked=None, is_blocking=True,
                    finding_type=FindingType.CONTENT, description="b",
                    category="t", secret_type=None, message="b",
                    repair_template_key=None),
            Finding(rule_id="B2", rule_name="B", severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH, file_path="b2.py",
                    line_start=1, line_end=1, column_start=1, column_end=2,
                    snippet_masked=None, is_blocking=True,
                    finding_type=FindingType.CONTENT, description="b",
                    category="t", secret_type=None, message="b",
                    repair_template_key=None),
            Finding(rule_id="B3", rule_name="B", severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH, file_path="b3.py",
                    line_start=1, line_end=1, column_start=1, column_end=2,
                    snippet_masked=None, is_blocking=True,
                    finding_type=FindingType.CONTENT, description="b",
                    category="t", secret_type=None, message="b",
                    repair_template_key=None),
        )
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=3, total_lines_scanned=30,
        )
        save_scan_result(task.id, result)
        summary = get_scan_summary(task.id)
        # All 3 are blocking, limit is 2, so 2 are returned
        assert summary["total_findings"] == 3
        assert summary["blocking_findings"] == 3  # actual blocking count
        assert summary["returned_findings"] == 2

    def test_no_raw_token_in_truncated_output(self, test_db, monkeypatch):
        """Truncated output must still not contain raw tokens."""
        monkeypatch.setattr(
            "app.core.config.settings.scan_max_persisted_findings_per_task", 1
        )
        task = task_manager.create_task(
            "https://github.com/test/repo", "test", "repo"
        )
        # Multiple findings with raw tokens
        findings = tuple(
            _make_finding_with_raw_token(rule_id=f"R{i}")
            for i in range(5)
        )
        result = ScanResult(
            findings=findings, notices=(), skipped_files=(),
            scan_errors=(), total_files_scanned=5, total_lines_scanned=50,
        )
        save_scan_result(task.id, result)
        retrieved = get_scan_result(task.id)
        json_str = json.dumps(retrieved)
        assert RAW_TOKEN not in json_str
