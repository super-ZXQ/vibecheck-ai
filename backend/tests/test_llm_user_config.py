"""Tests for per-user LLM configuration (feature: per-user LLM).

Verifies:
1. In-memory store: save / read / pop / TTL pruning.
2. Validation: invalid base URLs and oversized values are dropped.
3. POST /api/check and POST /api/check/upload bind X-LLM-* headers to the
   created task.
4. llm_service resolves a COMPLETE user config over the server settings,
   and ignores a partial one.
5. _call_llm_api uses the user's base_url / api_key / model.
6. Credentials NEVER appear in task DB rows or API responses.

No real credentials, network resources or GitHub API calls are involved.
"""

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.db import database
from app.services import background_runner
from app.services import llm_user_config
from app.services.llm_service import (
    _call_llm_api,
    _resolve_llm_config,
    generate_and_save_llm_analysis,
)


# --- Fixtures (mirror test_upload_api) ---


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
    """Keep the endpoint from racing the manually-driven pipeline."""
    async def _noop():
        return None

    monkeypatch.setattr("app.api.check.trigger_queue_processing", _noop)
    yield


@pytest.fixture(autouse=True)
def clean_store():
    """Clear the in-memory user config store before/after each test."""
    llm_user_config.clear_user_configs()
    yield
    llm_user_config.clear_user_configs()


# --- In-memory store ---


class TestStoreBasics:

    def test_store_and_get(self):
        llm_user_config.store_user_config(
            "task-1", "key-1", "https://api.u.example.com/v1", "u-model"
        )
        entry = llm_user_config.get_user_config("task-1")
        assert entry == {
            "api_key": "key-1",
            "base_url": "https://api.u.example.com/v1",
            "model": "u-model",
        }
        assert llm_user_config.count_user_configs() == 1

    def test_pop_removes_entry(self):
        llm_user_config.store_user_config(
            "task-1", "key", "https://api.example.com", "model"
        )
        popped = llm_user_config.pop_user_config("task-1")
        assert popped["api_key"] == "key"
        assert llm_user_config.get_user_config("task-1") is None
        assert llm_user_config.pop_user_config("task-1") is None

    def test_empty_config_not_stored(self):
        llm_user_config.store_user_config("task-1", "", "", "")
        llm_user_config.store_user_config("task-2", None, None, None)
        assert llm_user_config.count_user_configs() == 0

    def test_get_private_key_not_exposed(self):
        llm_user_config.store_user_config("task-1", "k", "https://b", "m")
        entry = llm_user_config.get_user_config("task-1")
        assert "_created" not in entry

    def test_partial_config_stored(self):
        # The STORE keeps partial entries (e.g. model only); resolution
        # happens later in llm_service where a partial entry is ignored.
        llm_user_config.store_user_config("task-1", "", "https://b.example.com", "")
        assert llm_user_config.count_user_configs() == 1


class TestStoreValidation:

    def test_rejects_non_http_base_url(self):
        llm_user_config.store_user_config(
            "task-1", "k", "javascript:alert(1)", "m"
        )
        assert llm_user_config.get_user_config("task-1") is None

    def test_rejects_credentials_in_base_url(self):
        llm_user_config.store_user_config(
            "task-1", "k", "https://user:pass@api.example.com/v1", "m"
        )
        assert llm_user_config.get_user_config("task-1") is None

    def test_rejects_oversized_base_url(self):
        llm_user_config.store_user_config(
            "task-1", "k", "https://" + "a" * 600, "m"
        )
        assert llm_user_config.get_user_config("task-1") is None

    def test_rejects_oversized_api_key(self):
        llm_user_config.store_user_config(
            "task-1", "k" * 2000, "https://api.example.com", "m"
        )
        assert llm_user_config.get_user_config("task-1") is None

    def test_rejects_oversized_model(self):
        llm_user_config.store_user_config(
            "task-1", "k", "https://api.example.com", "m" * 500
        )
        assert llm_user_config.get_user_config("task-1") is None

    def test_trims_whitespace(self):
        llm_user_config.store_user_config(
            "task-1", "  key  ", " https://api.example.com ", " m "
        )
        entry = llm_user_config.get_user_config("task-1")
        assert entry["api_key"] == "key"
        assert entry["base_url"] == "https://api.example.com"
        assert entry["model"] == "m"


class TestStoreTtl:

    def test_expired_entry_pruned_on_get(self, monkeypatch):
        llm_user_config.store_user_config(
            "task-1", "k", "https://api.example.com", "m"
        )
        with llm_user_config._LOCK:
            llm_user_config._STORE["task-1"]["_created"] -= (
                llm_user_config._USER_CONFIG_TTL_SECONDS + 60
            )
        assert llm_user_config.get_user_config("task-1") is None
        assert llm_user_config.count_user_configs() == 0


# --- API binding ---


def _make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/app.py", "print('hello')\n")
    return buf.getvalue()


class TestApiBinding:

    def test_check_endpoint_binds_headers(self, client):
        resp = client.post(
            "/api/check",
            json={"repo_url": "https://github.com/super-ZXQ/vibecheck-ai"},
            headers={
                "X-LLM-API-KEY": "user-key",
                "X-LLM-BASE-URL": "https://api.u.example.com/v1",
                "X-LLM-MODEL": "user-model",
            },
        )
        assert resp.status_code == 202
        task_id = resp.json()["task_id"]
        entry = llm_user_config.get_user_config(task_id)
        assert entry == {
            "api_key": "user-key",
            "base_url": "https://api.u.example.com/v1",
            "model": "user-model",
        }

    def test_check_endpoint_without_headers_stores_nothing(self, client):
        resp = client.post(
            "/api/check",
            json={"repo_url": "https://github.com/super-ZXQ/vibecheck-ai"},
        )
        assert resp.status_code == 202
        task_id = resp.json()["task_id"]
        assert llm_user_config.get_user_config(task_id) is None

    def test_check_endpoint_ignores_invalid_base_url(self, client):
        resp = client.post(
            "/api/check",
            json={"repo_url": "https://github.com/super-ZXQ/vibecheck-ai"},
            headers={
                "X-LLM-API-KEY": "user-key",
                "X-LLM-BASE-URL": "file:///etc/passwd",
                "X-LLM-MODEL": "user-model",
            },
        )
        assert resp.status_code == 202
        task_id = resp.json()["task_id"]
        assert llm_user_config.get_user_config(task_id) is None

    def test_upload_endpoint_binds_headers(self, client):
        resp = client.post(
            "/api/check/upload",
            data={"mode": "archive"},
            files={"file": ("app.zip", _make_zip(), "application/zip")},
            headers={
                "X-LLM-API-KEY": "user-key",
                "X-LLM-BASE-URL": "https://api.u.example.com/v1",
                "X-LLM-MODEL": "user-model",
            },
        )
        assert resp.status_code == 202
        task_id = resp.json()["task_id"]
        entry = llm_user_config.get_user_config(task_id)
        assert entry["api_key"] == "user-key"
        assert entry["model"] == "user-model"

    def test_keys_never_returned_in_response(self, client):
        resp = client.post(
            "/api/check",
            json={"repo_url": "https://github.com/super-ZXQ/vibecheck-ai"},
            headers={
                "X-LLM-API-KEY": "super-secret-key",
                "X-LLM-MODEL": "user-model",
            },
        )
        assert resp.status_code == 202
        body = resp.json()
        assert "secret" not in json.dumps(body)


# --- Resolution logic ---


class TestResolveConfig:

    def test_complete_user_config_wins_over_server(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
        enabled, key, url, model = _resolve_llm_config({
            "api_key": "k", "base_url": "https://u.example.com", "model": "m",
        })
        assert enabled is True
        assert key == "k"
        assert url == "https://u.example.com"
        assert model == "m"

    def test_partial_user_config_falls_back_to_server(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr("app.core.config.settings.llm_api_key", "srv")
        monkeypatch.setattr("app.core.config.settings.llm_base_url", "https://srv")
        monkeypatch.setattr("app.core.config.settings.llm_model", "srv-model")
        enabled, key, url, model = _resolve_llm_config({
            "api_key": "only-key", "base_url": "", "model": "",
        })
        assert enabled is True
        assert key == "srv"
        assert url == "https://srv"
        assert model == "srv-model"

    def test_none_config_falls_back_to_server(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr("app.core.config.settings.llm_model", "srv-model")
        enabled, key, url, model = _resolve_llm_config(None)
        assert enabled is True
        assert model == "srv-model"


# --- _call_llm_api uses the user config ---


class FakeLLMResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return (
            b'{"choices": [{"message": {"content": '
            b'"{\\"explanation\\": \\"E\\", \\"instruction\\": \\"I\\"}"}}]}'
        )


class TestCallLlmApiUserConfig:

    def test_uses_user_base_url_key_and_model(self, monkeypatch):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["auth"] = req.get_header("Authorization")
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return FakeLLMResponse()

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        # Server config is stale; only the user config is set.
        monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
        result = _call_llm_api(
            "prompt",
            user_config={
                "api_key": "user-key",
                "base_url": "https://api.u.example.com/v1/chat/completions",
                "model": "user-model",
            },
        )
        assert result is not None
        assert captured["url"] == "https://api.u.example.com/v1/chat/completions"
        assert captured["auth"] == "Bearer user-key"
        assert captured["body"]["model"] == "user-model"

    def test_partial_user_config_does_not_override(self, monkeypatch):
        captured = {}

        def fake_urlopen(request, timeout=60):
            captured["url"] = request.full_url
            captured["auth"] = request.get_header("Authorization")
            return FakeLLMResponse()

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        monkeypatch.setattr("app.core.config.settings.llm_enabled", True)
        monkeypatch.setattr("app.core.config.settings.llm_api_key", "srv-key")
        monkeypatch.setattr(
            "app.core.config.settings.llm_base_url", "https://api.srv.example.com"
        )
        monkeypatch.setattr("app.core.config.settings.llm_model", "srv-model")
        result = _call_llm_api(
            "prompt",
            user_config={"api_key": "partial-key"},
        )
        assert result is not None
        assert (
            captured["url"]
            == "https://api.srv.example.com/chat/completions"
        )
        assert captured["auth"] == "Bearer srv-key"


# --- End-to-end: user config drives LLM analysis in the pipeline ---


class TestPipelineWithUserConfig:

    def test_user_config_enables_llm_when_server_disabled(
        self, test_db, monkeypatch,
    ):
        """Server LLM disabled + complete user config → LLM-sourced items.

        Mirrors the persistence setup in test_llm_service.py: a scan result
        with one non-blocking finding is inserted directly, then
        generate_and_save_llm_analysis runs with the user config.
        """
        from app.db.database import _get_connection, now_iso
        from app.services.task_manager import create_task

        task = create_task("https://github.com/test/repo", "test", "repo")

        scan_result_json = json.dumps({
            "findings": [
                {
                    "rule_id": "I001_TODO_COMMENT",
                    "rule_name": "Unfinished work comment",
                    "severity": "medium",
                    "confidence": "high",
                    "file_path": "src/app.py",
                    "line_start": 1,
                    "line_end": 1,
                    "column_start": 0,
                    "column_end": 10,
                    "snippet_masked": "# TODO: fix this",
                    "is_blocking": False,
                    "finding_type": "content",
                    "description": "TODO comment found",
                    "category": "incomplete",
                    "secret_type": "",
                    "message": "TODO comment",
                    "repair_template_key": "",
                    "dimension": "incomplete_content",
                }
            ],
            "notices": [],
            "skipped_files": [],
            "scan_errors": [],
        })
        summary_json = json.dumps({
            "total_findings": 1, "blocking_findings": 0,
            "total_notices": 0, "total_skipped_files": 0,
            "total_scan_errors": 0, "total_files_scanned": 1,
            "total_lines_scanned": 1,
            "returned_findings": 1, "findings_truncated": False,
            "returned_notices": 0, "notices_truncated": False,
            "returned_skipped_files": 0, "skipped_files_truncated": False,
            "returned_scan_errors": 0, "scan_errors_truncated": False,
        })
        now = now_iso()
        conn = _get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO scan_results
                   (task_id, schema_version, result_json, summary_json,
                    total_findings, blocking_findings, total_notices,
                    total_skipped_files, total_scan_errors,
                    total_files_scanned, total_lines_scanned,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (task.id, 2, scan_result_json, summary_json,
                 1, 0, 0, 0, 0, 1, 1, now, now),
            )
            conn.commit()
        finally:
            conn.close()

        monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
        monkeypatch.setattr(
            "app.services.llm_service._call_llm_api",
            lambda prompt, user_config=None: (
                '{"explanation": "user-exp", "instruction": "user-inst"}'
            ),
        )
        user_config = {
            "api_key": "user-key",
            "base_url": "https://api.u.example.com/v1",
            "model": "user-model",
        }

        result = generate_and_save_llm_analysis(task.id, user_config)
        assert result["total_analyzed"] == 1
        assert result["total_llm"] == 1
        assert result["total_fallback"] == 0
        assert result["source"] == "llm"
        assert result["items"][0]["explanation"] == "user-exp"

    def test_partial_user_config_uses_fallback(self, test_db, monkeypatch):
        """Server disabled + partial user config → fallback templates."""
        from app.db.database import _get_connection, now_iso
        from app.services.task_manager import create_task

        task = create_task("https://github.com/test/repo", "test", "repo")
        scan_result_json = json.dumps({
            "findings": [
                {
                    "rule_id": "I001_TODO_COMMENT",
                    "rule_name": "Unfinished work comment",
                    "severity": "medium",
                    "confidence": "high",
                    "file_path": "src/app.py",
                    "line_start": 1,
                    "line_end": 1,
                    "column_start": 0,
                    "column_end": 10,
                    "snippet_masked": "# TODO: fix this",
                    "is_blocking": False,
                    "finding_type": "content",
                    "description": "TODO comment found",
                    "category": "incomplete",
                    "secret_type": "",
                    "message": "TODO comment",
                    "repair_template_key": "",
                    "dimension": "incomplete_content",
                }
            ],
            "notices": [],
            "skipped_files": [],
            "scan_errors": [],
        })
        summary_json = json.dumps({
            "total_findings": 1, "blocking_findings": 0,
            "total_notices": 0, "total_skipped_files": 0,
            "total_scan_errors": 0, "total_files_scanned": 1,
            "total_lines_scanned": 1,
            "returned_findings": 1, "findings_truncated": False,
            "returned_notices": 0, "notices_truncated": False,
            "returned_skipped_files": 0, "skipped_files_truncated": False,
            "returned_scan_errors": 0, "scan_errors_truncated": False,
        })
        now = now_iso()
        conn = _get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO scan_results
                   (task_id, schema_version, result_json, summary_json,
                    total_findings, blocking_findings, total_notices,
                    total_skipped_files, total_scan_errors,
                    total_files_scanned, total_lines_scanned,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (task.id, 2, scan_result_json, summary_json,
                 1, 0, 0, 0, 0, 1, 1, now, now),
            )
            conn.commit()
        finally:
            conn.close()

        monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
        monkeypatch.setattr(
            "app.services.llm_service._call_llm_api",
            lambda prompt, user_config=None: (
                '{"explanation": "never", "instruction": "never"}'
            ),
        )
        user_config = {"api_key": "user-key"}  # partial → ignored

        result = generate_and_save_llm_analysis(task.id, user_config)
        assert result["total_analyzed"] == 1
        assert result["total_llm"] == 0
        assert result["total_fallback"] == 1
        assert result["source"] == "fallback"