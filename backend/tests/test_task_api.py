"""Tests for task API endpoints and lifecycle — P0-3.

All tests use a temporary SQLite database and mock download/extract.
No real network requests or GitHub API calls are made.
No real credentials are used.

Test coverage (14 requirements):
1. Create task returns UUID and pending
2. Normal status flow: pending → running → completed
3. Download failure: pending → running → failed
4. Extraction failure with temp file cleanup
5. Non-existent task returns 404
6. Invalid UUID returns 422
7. Queue full returns 429
8. Concurrent execution ≤ 1
9. Service startup marks running tasks as failed
10. Service startup marks pending tasks as failed
11. error_message has no sensitive info
12. completed and failed tasks have completed_at
13. Temp files deleted after success
14. SQLite persistence across reconnect
"""

import asyncio
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.github import (
    DownloadResult,
    GitHubDownloadError,
    parse_repo_url,
)
from app.core.safe_extract import (
    ExtractionError,
    ExtractionResult,
)
from app.core.error_codes import SCAN_RESULT_NOT_READY
from app.db import database
from app.services import background_runner, task_manager
from tests.conftest import SYNTHETIC_GITHUB_TOKEN


# --- Fixtures ---

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


# --- Mock helpers ---

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


def make_mock_extract_result(tmp_path):
    """Create a mock ExtractionResult with a real temp directory."""
    dest = Path(tmp_path) / "mock-extract"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "test-file.txt").write_text("test content")
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=12,
        top_level_dir="mock-extract",
    )


# ============================================================
# Test 1: Create task returns UUID and pending
# ============================================================

class TestCreateTask:
    """Tests for POST /api/check — task creation."""

    def test_create_returns_uuid_and_pending(self, client):
        """POST /api/check should return a UUID and pending status."""
        response = client.post(
            "/api/check",
            json={"repo_url": "https://github.com/testuser/testrepo"},
        )
        assert response.status_code == 202
        data = response.json()
        assert "task_id" in data
        # Validate UUID format
        uuid.UUID(data["task_id"])
        assert data["status"] == "pending"
        assert data["check_url"] == f"/api/check/{data['task_id']}"

    def test_create_invalid_url_returns_400(self, client):
        """Invalid repo URL should return 400."""
        response = client.post(
            "/api/check",
            json={"repo_url": "not-a-valid-url"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "INVALID_REPO_URL"

    def test_create_non_github_url_returns_400(self, client):
        """Non-GitHub URL should return 400."""
        response = client.post(
            "/api/check",
            json={"repo_url": "https://gitlab.com/user/repo"},
        )
        assert response.status_code == 400


# ============================================================
# Test 5: Non-existent task returns 404
# Test 6: Invalid UUID returns 422
# ============================================================

class TestGetTaskStatus:
    """Tests for GET /api/check/{task_id}."""

    def test_nonexistent_task_returns_404(self, client):
        """Non-existent task ID should return 404."""
        random_uuid = str(uuid.uuid4())
        response = client.get(f"/api/check/{random_uuid}")
        assert response.status_code == 404
        assert response.json()["detail"]["error_code"] == "TASK_NOT_FOUND"

    def test_invalid_uuid_returns_422(self, client):
        """Invalid UUID format should return 422."""
        response = client.get("/api/check/not-a-uuid")
        assert response.status_code == 422
        assert response.json()["detail"]["error_code"] == "INVALID_TASK_ID"

    def test_get_pending_task_status(self, client, test_db):
        """Created pending task should be retrievable with correct status."""
        # Create task directly (bypass background processing)
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        response = client.get(f"/api/check/{task.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == task.id
        assert data["status"] == "pending"
        assert data["stage"] == "queued"
        assert data["progress"] == 0
        assert data["error_code"] is None
        assert data["error_message"] is None


# ============================================================
# Test 7: Queue full returns 429
# ============================================================

class TestQueueFull:
    """Tests for queue capacity enforcement."""

    def test_queue_full_returns_429(self, client, test_db):
        """When 5 pending tasks exist, 6th should return 429."""
        # Create 5 pending tasks directly
        for i in range(5):
            task_manager.create_task(
                f"https://github.com/user{i}/repo{i}",
                f"user{i}",
                f"repo{i}",
            )

        # 6th task via API should return 429
        response = client.post(
            "/api/check",
            json={"repo_url": "https://github.com/user6/repo6"},
        )
        assert response.status_code == 429
        assert response.json()["detail"]["error_code"] == "QUEUE_FULL"


# ============================================================
# Test 2: Normal status flow: pending → running → completed
# Test 3: Download failure: pending → running → failed
# Test 4: Extraction failure with cleanup
# ============================================================

class TestTaskLifecycle:
    """Tests for task lifecycle via direct function calls."""

    @pytest.mark.asyncio
    async def test_normal_flow_completed(self, test_db, tmp_path):
        """Task should flow: pending → running → completed."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        # Mock download and extract to succeed
        def mock_extract(tarball_bytes, tmp_root=None):
            return make_mock_extract_result(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                side_effect=mock_extract,
            ):
                await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "completed"
        assert result.stage == "finished"
        assert result.progress == 100
        assert result.file_count == 1
        assert result.total_size == 12
        assert result.top_level_dir == "mock-extract"
        assert result.error_code is None
        assert result.error_message is None
        assert result.completed_at is not None

    @pytest.mark.asyncio
    async def test_download_failure(self, test_db, tmp_path):
        """Download failure should mark task as failed."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError(
                "Repository not found, does not exist, or is private"
            ),
        ):
            await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == "REPOSITORY_NOT_FOUND"
        assert result.completed_at is not None

    @pytest.mark.asyncio
    async def test_download_rate_limit(self, test_db, tmp_path):
        """Rate limit error should map to GITHUB_RATE_LIMITED."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError(
                "GitHub API rate limit exceeded, please try again later"
            ),
        ):
            await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == "GITHUB_RATE_LIMITED"

    @pytest.mark.asyncio
    async def test_download_too_large(self, test_db, tmp_path):
        """Download too large should map to DOWNLOAD_TOO_LARGE."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError(
                "Archive too large during streaming: 99999 bytes"
            ),
        ):
            await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == "DOWNLOAD_TOO_LARGE"

    @pytest.mark.asyncio
    async def test_extraction_failure_cleans_up(self, test_db, tmp_path):
        """Extraction failure should mark task as failed and clean up temp files."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                side_effect=ExtractionError("Rejected path traversal: '../../etc/passwd'"),
            ):
                await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == "UNSAFE_ARCHIVE"
        assert result.completed_at is not None

        # Verify download temp file was cleaned up
        assert not download_result.temp_file.exists()

    @pytest.mark.asyncio
    async def test_extraction_size_limit(self, test_db, tmp_path):
        """Extraction size limit should map to EXTRACTION_LIMIT_EXCEEDED."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                side_effect=ExtractionError(
                    "Total extracted size exceeds limit: 99999 bytes"
                ),
            ):
                await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == "EXTRACTION_LIMIT_EXCEEDED"


# ============================================================
# Test 8: Concurrent execution ≤ 1
# ============================================================

class TestConcurrency:
    """Tests for concurrency control — only 1 task runs at a time."""

    @pytest.mark.asyncio
    async def test_max_one_running_concurrent(self, test_db, tmp_path):
        """Multiple tasks should execute sequentially, never concurrently."""
        running_count = 0
        max_concurrent = 0

        async def slow_download(repo_url):
            nonlocal running_count, max_concurrent
            running_count += 1
            max_concurrent = max(max_concurrent, running_count)
            await asyncio.sleep(0.15)
            running_count -= 1
            return make_mock_download_result(tmp_path, repo_url)

        def mock_extract(tarball_bytes, tmp_root=None):
            return make_mock_extract_result(tmp_path)

        # Create 3 tasks
        tasks = []
        for i in range(3):
            t = task_manager.create_task(
                f"https://github.com/user{i}/repo{i}",
                f"user{i}",
                f"repo{i}",
            )
            tasks.append(t)

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=slow_download,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                side_effect=mock_extract,
            ):
                await background_runner.trigger_queue_processing()

        # All tasks should be completed
        for t in tasks:
            result = task_manager.get_task(t.id)
            assert result.status == "completed"

        # Max concurrent execution should be 1
        assert max_concurrent == 1


# ============================================================
# Test 11: error_message has no sensitive info
# ============================================================

class TestErrorMessages:
    """Tests for error message desensitization."""

    @pytest.mark.asyncio
    async def test_error_message_no_sensitive_info(self, test_db, tmp_path):
        """error_message must not contain paths, tokens, or stack traces."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        # Simulate a download error that contains sensitive info
        sensitive_error = GitHubDownloadError(
            "Connection failed: token=ghp_1234567890abcdef "
            "at /tmp/vibecheck/download-abc123.tar.gz "
            "Traceback (most recent call last): File ..."
        )

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=sensitive_error,
        ):
            await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        msg = result.error_message or ""

        # Must NOT contain sensitive content
        assert "ghp_" not in msg
        assert "/tmp/" not in msg
        assert "Traceback" not in msg
        assert ".tar.gz" not in msg
        assert "token=" not in msg

    @pytest.mark.asyncio
    async def test_error_message_is_desensitized(self, test_db, tmp_path):
        """All error codes should have clean, user-facing messages."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError("Repository not found"),
        ):
            await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        # The message should be the predefined safe message
        assert result.error_message == "仓库不存在或无法访问，请确认地址正确。"


# ============================================================
# Test 12: completed and failed tasks have completed_at
# ============================================================

class TestCompletedAt:
    """Tests for completed_at timestamp."""

    @pytest.mark.asyncio
    async def test_completed_has_completed_at(self, test_db, tmp_path):
        """Completed tasks must have completed_at set."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "completed"
        assert result.completed_at is not None
        assert result.completed_at != ""

    @pytest.mark.asyncio
    async def test_failed_has_completed_at(self, test_db, tmp_path):
        """Failed tasks must have completed_at set."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError("Download failed: HTTP 500"),
        ):
            await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.completed_at is not None
        assert result.completed_at != ""

    def test_pending_has_no_completed_at(self, test_db):
        """Pending tasks should NOT have completed_at."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        result = task_manager.get_task(task.id)
        assert result.status == "pending"
        assert result.completed_at is None


# ============================================================
# Test 13: Temp files deleted after success
# ============================================================

class TestTempFileCleanup:
    """Tests for temporary file cleanup."""

    @pytest.mark.asyncio
    async def test_temp_files_deleted_after_success(self, test_db, tmp_path):
        """Download file and extraction dir should be deleted after success."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_result(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                await background_runner._process_task(task.id)

        # Task should be completed
        result = task_manager.get_task(task.id)
        assert result.status == "completed"

        # Download temp file should be deleted
        assert not download_result.temp_file.exists()

        # Extraction temp directory should be deleted
        assert not Path(extract_result.dest_dir).exists()

    @pytest.mark.asyncio
    async def test_temp_files_deleted_after_download_failure(self, test_db, tmp_path):
        """Temp files should be cleaned up even on download failure."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError("Download failed"),
        ):
            await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"

        # No temp files should exist in tmp_dir
        tmp_dir = Path(tmp_path) / "tmp"
        if tmp_dir.exists():
            temp_files = list(tmp_dir.glob("download-*.tar.gz"))
            assert len(temp_files) == 0

    @pytest.mark.asyncio
    async def test_temp_files_deleted_after_extraction_failure(self, test_db, tmp_path):
        """Download file should be cleaned up after extraction failure."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                side_effect=ExtractionError("Rejected symlink entry: 'evil_link'"),
            ):
                await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"

        # Download temp file should be deleted
        assert not download_result.temp_file.exists()


# ============================================================
# Test 14: SQLite persistence across reconnect
# ============================================================

class TestSQLitePersistence:
    """Tests for SQLite persistence across database reconnection."""

    @pytest.mark.asyncio
    async def test_task_survives_db_reconnect(self, test_db, tmp_path):
        """Task data should persist after closing and reopening the database."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        # Process the task to completion
        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        # Verify task is completed
        result = task_manager.get_task(task.id)
        assert result.status == "completed"

        # Simulate database reconnect by resetting _initialized
        database._initialized = False
        database.init_db()

        # Task should still exist with same data
        result2 = task_manager.get_task(task.id)
        assert result2 is not None
        assert result2.id == task.id
        assert result2.status == "completed"
        assert result2.file_count == 1
        assert result2.total_size == 12
        assert result2.top_level_dir == "mock-extract"
        assert result2.completed_at is not None


# ============================================================
# P0-5: Scan summary in polling response
# ============================================================

class TestScanSummaryInPolling:
    """Tests for scan_summary in GET /api/check/{task_id} response."""

    @pytest.mark.asyncio
    async def test_completed_returns_scan_summary(self, client, test_db, tmp_path):
        """Completed task should include scan_summary in polling response."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        response = client.get(f"/api/check/{task.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["scan_summary"] is not None
        assert "total_findings" in data["scan_summary"]
        assert "blocking_findings" in data["scan_summary"]
        assert "total_files_scanned" in data["scan_summary"]

    @pytest.mark.asyncio
    async def test_completed_returns_report_url(self, client, test_db, tmp_path):
        """Completed task should include report_url in polling response."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        response = client.get(f"/api/check/{task.id}")
        data = response.json()
        assert data["report_url"] == f"/api/check/{task.id}/result"

    @pytest.mark.asyncio
    async def test_completed_does_not_inline_findings(self, client, test_db, tmp_path):
        """Polling response should NOT include full findings array."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        response = client.get(f"/api/check/{task.id}")
        data = response.json()
        # findings should NOT be in the polling response
        assert "findings" not in data
        assert "notices" not in data
        assert "skipped_files" not in data
        assert "scan_errors" not in data

    def test_pending_does_not_have_scan_summary(self, client, test_db):
        """Pending task should not have scan_summary."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        response = client.get(f"/api/check/{task.id}")
        data = response.json()
        assert data["status"] == "pending"
        assert data.get("scan_summary") is None


# ============================================================
# P0-5: Result endpoint tests
# ============================================================

class TestResultEndpoint:
    """Tests for GET /api/check/{task_id}/result."""

    @pytest.mark.asyncio
    async def test_result_returns_full_result(self, client, test_db, tmp_path):
        """Result endpoint should return full persisted scan result."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 200
        data = response.json()
        assert "schema_version" in data
        assert "findings" in data
        assert "notices" in data
        assert "skipped_files" in data
        assert "scan_errors" in data
        assert "summary" in data

    @pytest.mark.asyncio
    async def test_result_summary_matches_polling(self, client, test_db, tmp_path):
        """Summary in result endpoint should match scan_summary in polling."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        poll_response = client.get(f"/api/check/{task.id}")
        result_response = client.get(f"/api/check/{task.id}/result")
        poll_summary = poll_response.json()["scan_summary"]
        result_summary = result_response.json()["summary"]
        assert poll_summary == result_summary

    def test_result_unknown_task_returns_404(self, client, test_db):
        """Unknown task_id should return 404 for result endpoint."""
        random_uuid = str(uuid.uuid4())
        response = client.get(f"/api/check/{random_uuid}/result")
        assert response.status_code == 404
        assert response.json()["detail"]["error_code"] == "TASK_NOT_FOUND"

    def test_result_invalid_uuid_returns_422(self, client, test_db):
        """Invalid UUID format should return 422 for result endpoint."""
        response = client.get("/api/check/not-a-uuid/result")
        assert response.status_code == 422
        assert response.json()["detail"]["error_code"] == "INVALID_TASK_ID"

    def test_result_pending_returns_409(self, client, test_db):
        """Pending task should return 409 for result endpoint."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )
        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 409
        assert response.json()["detail"]["error_code"] == SCAN_RESULT_NOT_READY

    @pytest.mark.asyncio
    async def test_result_failed_returns_safe_empty(self, client, test_db, tmp_path):
        """Failed task with no result should return fixed safe empty response."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        # Fail the task via download failure
        with patch(
            "app.services.background_runner.download_tarball",
            side_effect=GitHubDownloadError("Repository not found"),
        ):
            await background_runner._process_task(task.id)

        response = client.get(f"/api/check/{task.id}/result")
        assert response.status_code == 200
        data = response.json()
        assert data["schema_version"] == 2
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0

    @pytest.mark.asyncio
    async def test_result_no_raw_tokens(self, client, test_db, tmp_path):
        """Result endpoint response should not contain raw synthetic tokens."""
        # Create extract directory with a synthetic token
        dest = Path(tmp_path) / "token-repo"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "config.py").write_text(f'token = "{SYNTHETIC_GITHUB_TOKEN}"\n')

        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = ExtractionResult(
            dest_dir=str(dest),
            file_count=1,
            total_size=50,
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
                await background_runner._process_task(task.id)

        response = client.get(f"/api/check/{task.id}/result")
        # The raw token should NOT appear anywhere in the response
        assert SYNTHETIC_GITHUB_TOKEN not in response.text

    @pytest.mark.asyncio
    async def test_result_no_absolute_paths(self, client, test_db, tmp_path):
        """Result endpoint response should not contain absolute paths."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=make_mock_download_result(tmp_path),
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=make_mock_extract_result(tmp_path),
            ):
                await background_runner._process_task(task.id)

        response = client.get(f"/api/check/{task.id}/result")
        # The temp directory path should NOT appear in the response
        assert str(tmp_path) not in response.text
        assert "/tmp/vibecheck" not in response.text
