"""Tests for POST /api/check/upload — local archive / folder uploads.

All archives are SYNTHETIC, constructed in-memory. No real credentials,
network resources or GitHub API calls are involved.

Coverage:
1. ZIP upload creates a pending task and scans to completion
2. tar.gz upload creates a pending task and scans to completion
3. Folder upload (relative-path multipart) scans to completion
4. Fake archive (wrong magic) → 400 INVALID_UPLOAD
5. Extension/content mismatch → 400 INVALID_UPLOAD
6. Path traversal ZIP → 400 UNSAFE_ARCHIVE
7. Symlink ZIP → 400 UNSAFE_ARCHIVE
8. Oversized archive → 413 UPLOAD_TOO_LARGE
9. Oversized extracted file → 413 EXTRACTION_LIMIT_EXCEEDED
10. Folder with traversal path → 400 INVALID_UPLOAD
11. Folder single file over cap → 413 UPLOAD_TOO_LARGE
12. Queue full → 429 QUEUE_FULL
13. Unknown mode → 400 INVALID_UPLOAD
14. Staged upload content is removed after processing
"""

import io
import stat
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.db import database
from app.services import background_runner, task_manager
from app.services.upload_service import upload_source_dir
from tests.conftest import make_normal_tarball

# --- Fixtures (mirror test_task_api) ---

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


@pytest.fixture(autouse=True)
def no_background_trigger(monkeypatch):
    """Keep the endpoint from racing the manually-driven pipeline.

    The upload endpoint spawns ``trigger_queue_processing`` as a background
    task; tests drive ``_process_task`` directly and would otherwise race
    the spawned processor on the same task.
    """

    async def _noop():
        return None

    monkeypatch.setattr("app.api.check.trigger_queue_processing", _noop)


# --- Synthetic ZIP builders ---

def make_zip(entries, compress=True) -> bytes:
    """Build a ZIP archive from [(name, content_bytes), ...]."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries:
            zf.writestr(
                name, content,
                compress_type=zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED,
            )
    return buf.getvalue()


def make_symlink_zip() -> bytes:
    """Build a ZIP containing a symlink entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("safe.txt", b"safe\n")
        info = zipfile.ZipInfo("evil_link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, b"/etc/passwd")
    return buf.getvalue()


def make_project_zip() -> bytes:
    """A normal project zip with a synthetic secret and a config file."""
    return make_zip([
        ("demo-project/README.md", b"# Demo Project\n"),
        ("demo-project/config.py", b"API_KEY = 'sk-live-test-1234567890abcdef'\n"),
        ("demo-project/src/main.py", b'print("hello world")\n'),
    ])


# --- Upload success paths ---

class TestUploadSuccess:
    """ZIP / tar.gz / folder uploads that run to completion."""

    @pytest.mark.asyncio
    async def test_zip_upload_completes_full_pipeline(self, client, test_db):
        """A ZIP upload is staged, processed, and reports results."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("demo.zip", make_project_zip(), "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 202
        data = response.json()
        task_id = data["task_id"]
        assert data["status"] == "pending"
        assert data["check_url"] == f"/api/check/{task_id}"

        task = task_manager.get_task(task_id)
        assert task.repo_url.startswith("local://upload/")
        assert task.owner == "local"
        # Staged content exists before processing.
        assert upload_source_dir(task_id).is_dir()

        await background_runner._process_task(task_id)

        task = task_manager.get_task(task_id)
        assert task.status == "completed"
        assert task.file_count == 3
        assert task.top_level_dir == "demo-project"

        result = client.get(f"/api/check/{task_id}/result")
        assert result.status_code == 200
        body = result.json()
        assert body["summary"]["total_files_scanned"] == 3
        assert body["summary"]["total_findings"] > 0

    @pytest.mark.asyncio
    async def test_targz_upload_completes(self, client, test_db):
        """tar.gz uploads are extracted with the safe tarball path."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("repo.tar.gz", make_normal_tarball(), "application/gzip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 202
        task_id = response.json()["task_id"]

        await background_runner._process_task(task_id)

        task = task_manager.get_task(task_id)
        assert task.status == "completed"
        assert task.file_count == 2  # README.md and main.py
        assert task.top_level_dir == "test-repo"

    @pytest.mark.asyncio
    async def test_folder_upload_completes(self, client, test_db):
        """Folder mode rebuilds the tree and scans it."""
        files = [
            ("file", ("proj/README.md", b"# Local Project\n", "text/plain")),
            ("file", ("proj/src/util.py", b"def helper(): return 1\n", "text/plain")),
        ]
        response = client.post(
            "/api/check/upload",
            files=files,
            data={"mode": "folder"},
        )
        assert response.status_code == 202
        task_id = response.json()["task_id"]

        await background_runner._process_task(task_id)

        task = task_manager.get_task(task_id)
        assert task.status == "completed"
        assert task.file_count == 2
        assert task.top_level_dir == "proj"


# --- Rejections ---

class TestUploadRejections:
    """Malformed, malicious and oversized uploads are rejected upfront."""

    def test_fake_archive_rejected(self, client):
        """Content that is not a ZIP/gzip is rejected."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("repo.zip", b"this is definitely not a zip file", "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "INVALID_UPLOAD"

    def test_extension_content_mismatch_rejected(self, client):
        """A ZIP payload named .tar.gz is rejected (magic is authoritative)."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("repo.tar.gz", make_project_zip(), "application/gzip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "INVALID_UPLOAD"

    def test_unsupported_extension_rejected(self, client):
        """Non-whitelisted extensions are rejected before sniffing."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("repo.exe", b"\x1f\x8b\x08\x00junk", "application/octet-stream")},
            data={"mode": "archive"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "INVALID_UPLOAD"

    def test_traversal_zip_rejected(self, client):
        """ZIP entries with ../ are rejected as unsafe."""
        evil = make_zip([("safe.txt", b"ok"), ("../../etc/passwd", b"hacked")])
        response = client.post(
            "/api/check/upload",
            files={"file": ("evil.zip", evil, "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "UNSAFE_ARCHIVE"

    def test_symlink_zip_rejected(self, client):
        """ZIP entries with unix symlink modes are rejected as unsafe."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("evil.zip", make_symlink_zip(), "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "UNSAFE_ARCHIVE"

    def test_oversized_archive_rejected(self, client, monkeypatch):
        """Archive over max_archive_size → 413 UPLOAD_TOO_LARGE."""
        monkeypatch.setattr("app.core.config.settings.max_archive_size", 1024)
        big = make_zip([("big.bin", b"\x00" * (4 * 1024))], compress=False)
        response = client.post(
            "/api/check/upload",
            files={"file": ("big.zip", big, "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 413
        assert response.json()["detail"]["error_code"] == "UPLOAD_TOO_LARGE"

    def test_extraction_limit_exceeded_rejected(self, client, monkeypatch):
        """A file exceeding max_single_file_size → 413 EXTRACTION_LIMIT_EXCEEDED."""
        monkeypatch.setattr("app.core.config.settings.max_single_file_size", 100)
        bloated = make_zip([("huge.bin", b"\x00" * 20000)], compress=False)
        response = client.post(
            "/api/check/upload",
            files={"file": ("huge.zip", bloated, "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 413
        assert response.json()["detail"]["error_code"] == "EXTRACTION_LIMIT_EXCEEDED"

    def test_folder_traversal_rejected(self, client):
        """Folder mode rejects relative paths that traverse."""
        files = [("file", ("../../evil.txt", b"x", "text/plain"))]
        response = client.post(
            "/api/check/upload",
            files=files,
            data={"mode": "folder"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "INVALID_UPLOAD"

    def test_folder_file_over_cap_rejected(self, client, monkeypatch):
        """Folder mode enforces the single-file cap while streaming."""
        monkeypatch.setattr("app.core.config.settings.max_single_file_size", 16)
        files = [("file", ("proj/big.bin", b"\x00" * 1000, "application/octet-stream"))]
        response = client.post(
            "/api/check/upload",
            files=files,
            data={"mode": "folder"},
        )
        assert response.status_code == 413
        assert response.json()["detail"]["error_code"] == "UPLOAD_TOO_LARGE"

    def test_unknown_mode_rejected(self, client):
        """An unknown mode value is rejected."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("repo.zip", make_project_zip(), "application/zip")},
            data={"mode": "weird"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error_code"] == "INVALID_UPLOAD"

    def test_queue_full_returns_429(self, client, test_db):
        """Uploads share the pending queue with URL submissions."""
        for i in range(5):
            task_manager.create_task(
                f"https://github.com/user{i}/repo{i}",
                f"user{i}",
                f"repo{i}",
            )
        response = client.post(
            "/api/check/upload",
            files={"file": ("repo.zip", make_project_zip(), "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 429
        assert response.json()["detail"]["error_code"] == "QUEUE_FULL"


# --- Cleanup ---

class TestUploadCleanup:
    """Staged upload content never outlives the task."""

    def test_rejected_upload_leaves_no_staged_dir(self, client, test_db):
        """A rejected upload creates no task and leaves no content."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("repo.zip", b"not a zip", "application/zip")},
            data={"mode": "archive"},
        )
        assert response.status_code == 400
        # No task was created.
        assert task_manager.get_pending_count() == 0

    @pytest.mark.asyncio
    async def test_completed_upload_removes_staged_content(self, client, test_db):
        """The staged upload directory is deleted after processing."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("demo.zip", make_project_zip(), "application/zip")},
            data={"mode": "archive"},
        )
        task_id = response.json()["task_id"]
        staged = upload_source_dir(task_id)
        assert staged.is_dir()

        await background_runner._process_task(task_id)

        task = task_manager.get_task(task_id)
        assert task.status == "completed"
        assert not staged.exists()

    @pytest.mark.asyncio
    async def test_scan_failure_cleans_upload_dir(self, client, test_db, monkeypatch):
        """Staged content is removed even when the scan stage fails."""
        response = client.post(
            "/api/check/upload",
            files={"file": ("demo.zip", make_project_zip(), "application/zip")},
            data={"mode": "archive"},
        )
        task_id = response.json()["task_id"]

        def boom(_path):
            raise RuntimeError("scan exploded")

        monkeypatch.setattr("app.services.background_runner.scan_directory", boom)
        await background_runner._process_task(task_id)

        task = task_manager.get_task(task_id)
        assert task.status == "failed"
        assert not upload_source_dir(task_id).exists()
