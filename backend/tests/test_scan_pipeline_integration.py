"""Tests for scan pipeline integration and failure handling (P0-5).

Covers:
C. Pipeline integration tests:
   - Download and extract use mocks (no real network)
   - Synthetic token placed in extract directory
   - scan_directory is executed
   - Result is persisted
   - Task reaches completed
   - report_url is correct
   - Cleanup is executed

D. Failure tests:
   - scan_directory raises exception → SCAN_INTERNAL_ERROR
   - save_scan_result raises exception → SCAN_RESULT_PERSIST_FAILED
   - Task marked as failed
   - Fixed error codes used
   - No str(exc) in error message
   - Cleanup still executes
"""

import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.core.error_codes import (
    SCAN_INTERNAL_ERROR,
    SCAN_RESULT_PERSIST_FAILED,
    get_error_message,
)
from app.core.github import DownloadResult, GitHubDownloadError, parse_repo_url
from app.core.safe_extract import ExtractionResult
from app.db import database
from app.scanner.base import (
    BASIC_SECURITY_DIMENSION,
    DEPLOYABILITY_PRODUCTION_DIMENSION,
    SENSITIVE_DATA_DIMENSION,
    ScanResult,
)
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


def make_mock_extract_with_token(tmp_path):
    """Create a mock ExtractionResult with a synthetic token in a file."""
    dest = Path(tmp_path) / "mock-extract-token"
    dest.mkdir(parents=True, exist_ok=True)
    # Place a synthetic GitHub token in a file
    config_file = dest / "config.py"
    config_file.write_text(f'token = "{SYNTHETIC_GITHUB_TOKEN}"\n')
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=len(config_file.read_bytes()),
        top_level_dir="mock-extract-token",
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
# C. Pipeline integration tests
# ============================================================

class TestPipelineIntegration:
    """Tests for the full scan pipeline integration."""

    @pytest.mark.asyncio
    async def test_scan_finds_token_and_persists(self, test_db, tmp_path):
        """Pipeline should scan extracted files and persist findings."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_with_token(tmp_path)

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
        assert result.stage == "finished"
        assert result.progress == 100

        # Scan result should be persisted
        from app.services.scan_result_service import get_scan_result, get_scan_summary
        scan_result = get_scan_result(task.id)
        assert scan_result is not None
        assert len(scan_result["findings"]) > 0
        assert scan_result["summary"]["total_findings"] > 0

        # Summary should have correct counts
        summary = get_scan_summary(task.id)
        assert summary["total_findings"] > 0
        assert summary["total_files_scanned"] >= 1

    @pytest.mark.asyncio
    async def test_scan_clean_repo_persists_non_security_advice(self, test_db, tmp_path):
        """A security-clean repository may still have deployability advice."""
        task = task_manager.create_task(
            "https://github.com/testuser/cleanrepo",
            "testuser",
            "cleanrepo",
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
        assert result.status == "completed"

        from app.services.scan_result_service import get_scan_summary
        summary = get_scan_summary(task.id)
        assert summary["dimension_counts"][SENSITIVE_DATA_DIMENSION] == 0
        assert summary["dimension_counts"][DEPLOYABILITY_PRODUCTION_DIMENSION] == 3
        assert summary["dimension_counts"][BASIC_SECURITY_DIMENSION] == 0
        assert summary["blocking_findings"] == 0

    @pytest.mark.asyncio
    async def test_report_url_correct(self, test_db, tmp_path):
        """Completed task response should have correct report_url."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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
        resp = result.to_response()
        assert resp["report_url"] == f"/api/check/{task.id}/result"

    @pytest.mark.asyncio
    async def test_cleanup_executed_on_success(self, test_db, tmp_path):
        """Temp files should be cleaned up after successful scan."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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

        # Download temp file should be deleted
        assert not download_result.temp_file.exists()
        # Extraction temp directory should be deleted
        assert not Path(extract_result.dest_dir).exists()

    @pytest.mark.asyncio
    async def test_scan_stage_visible_in_progress(self, test_db, tmp_path):
        """Task should pass through scanning stage (stage=scanning, progress=80)."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        # Track stage updates
        stage_updates = []
        original_mark_running = task_manager.mark_running

        def tracking_mark_running(task_id, stage, progress):
            stage_updates.append((stage, progress))
            original_mark_running(task_id, stage, progress)

        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.mark_running",
                    side_effect=tracking_mark_running,
                ):
                    await background_runner._process_task(task.id)

        # Should have passed through scanning stage
        stages = [s for s, _ in stage_updates]
        assert "scanning" in stages
        # Scanning stage should have progress=80
        scan_updates = [(s, p) for s, p in stage_updates if s == "scanning"]
        assert scan_updates[0][1] == 80


# ============================================================
# D. Failure tests
# ============================================================

class TestScanFailure:
    """Tests for scanner failure handling."""

    @pytest.mark.asyncio
    async def test_scan_exception_marks_failed(self, test_db, tmp_path):
        """Scanner exception should mark task as failed with SCAN_INTERNAL_ERROR."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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
                with patch(
                    "app.services.background_runner.scan_directory",
                    side_effect=RuntimeError("Unexpected internal error"),
                ):
                    await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == SCAN_INTERNAL_ERROR

    @pytest.mark.asyncio
    async def test_scan_exception_no_str_exc(self, test_db, tmp_path):
        """Error message should not contain str(exc)."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        exc_msg = "Very specific internal error with details"
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
                    side_effect=RuntimeError(exc_msg),
                ):
                    await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert exc_msg not in (result.error_message or "")
        assert result.error_message == get_error_message(SCAN_INTERNAL_ERROR)

    @pytest.mark.asyncio
    async def test_scan_failure_cleanup_executed(self, test_db, tmp_path):
        """Cleanup should still execute after scan failure."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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
                with patch(
                    "app.services.background_runner.scan_directory",
                    side_effect=RuntimeError("scan error"),
                ):
                    await background_runner._process_task(task.id)

        # Download temp file should be deleted
        assert not download_result.temp_file.exists()
        # Extraction temp directory should be deleted
        assert not Path(extract_result.dest_dir).exists()

    @pytest.mark.asyncio
    async def test_scan_failure_no_result_persisted(self, test_db, tmp_path):
        """No scan result should be persisted after scan failure."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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
                with patch(
                    "app.services.background_runner.scan_directory",
                    side_effect=RuntimeError("scan error"),
                ):
                    await background_runner._process_task(task.id)

        from app.services.scan_result_service import get_scan_result
        assert get_scan_result(task.id) is None


class TestPersistenceFailure:
    """Tests for scan result persistence failure handling."""

    @pytest.mark.asyncio
    async def test_persist_exception_marks_failed(self, test_db, tmp_path):
        """Persistence exception should mark task as failed with SCAN_RESULT_PERSIST_FAILED."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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
                with patch(
                    "app.services.background_runner.save_scan_result",
                    side_effect=Exception("DB connection lost"),
                ):
                    await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status == "failed"
        assert result.error_code == SCAN_RESULT_PERSIST_FAILED

    @pytest.mark.asyncio
    async def test_persist_exception_no_str_exc(self, test_db, tmp_path):
        """Error message should not contain str(exc) from persistence failure."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
        )

        download_result = make_mock_download_result(tmp_path)
        extract_result = make_mock_extract_clean(tmp_path)

        exc_msg = "Database error: connection to localhost:5432 refused"
        with patch(
            "app.services.background_runner.download_tarball",
            return_value=download_result,
        ):
            with patch(
                "app.services.background_runner.safe_extract_to_temp",
                return_value=extract_result,
            ):
                with patch(
                    "app.services.background_runner.save_scan_result",
                    side_effect=Exception(exc_msg),
                ):
                    await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert exc_msg not in (result.error_message or "")
        assert result.error_message == get_error_message(SCAN_RESULT_PERSIST_FAILED)

    @pytest.mark.asyncio
    async def test_persist_failure_task_not_completed(self, test_db, tmp_path):
        """Task should NOT be marked completed if persistence fails."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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
                with patch(
                    "app.services.background_runner.save_scan_result",
                    side_effect=Exception("persist error"),
                ):
                    await background_runner._process_task(task.id)

        result = task_manager.get_task(task.id)
        assert result.status != "completed"
        assert result.status == "failed"

    @pytest.mark.asyncio
    async def test_persist_failure_cleanup_executed(self, test_db, tmp_path):
        """Cleanup should still execute after persistence failure."""
        task = task_manager.create_task(
            "https://github.com/testuser/testrepo",
            "testuser",
            "testrepo",
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
                with patch(
                    "app.services.background_runner.save_scan_result",
                    side_effect=Exception("persist error"),
                ):
                    await background_runner._process_task(task.id)

        # Download temp file should be deleted
        assert not download_result.temp_file.exists()
        # Extraction temp directory should be deleted
        assert not Path(extract_result.dest_dir).exists()
