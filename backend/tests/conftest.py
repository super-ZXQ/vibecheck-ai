"""Pytest fixtures — PostgreSQL isolation + extract helpers."""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
import uuid
from pathlib import Path

import pytest

_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
_MIXED_UPPER = "ABCDEF1234567890GHIJKLMNOP"
SYNTHETIC_GITHUB_TOKEN = "ghp_" + _MIXED[:36]
SYNTHETIC_AWS_KEY = "AKIA" + _MIXED_UPPER[:16]
SYNTHETIC_GOOGLE_KEY = "AIza" + _MIXED[:35]
SYNTHETIC_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA" + "D" * 400 + "\n"
    "-----END RSA PRIVATE KEY-----"
)
SYNTHETIC_PASSWORD = 'DB_PASSWORD="s3cur3P@ssw0rd123!"'

PG_URL = (
    "postgresql+asyncpg://vibecheck:vibecheck@127.0.0.1:5432/vibecheck_test"
)


def _test_database_url() -> str:
    return (
        os.environ.get("TEST_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
        or PG_URL
    )


def _dispose_engine_quiet() -> None:
    import app.db.session as session_mod

    engine = session_mod._engine
    session_mod._engine = None
    session_mod._session_factory = None
    if engine is None:
        return
    try:
        import asyncio

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(engine.dispose())
        finally:
            loop.close()
    except Exception:
        pass


_SESSION_SCHEMAS_READY = False


def clean_tables(*tables: str) -> None:
    """Truncate only the named business tables (targeted isolation)."""
    import asyncio

    from sqlalchemy import text

    from app.db.session import get_engine

    names = list(tables) or [
        "llm_analysis_results",
        "repair_results",
        "assessment_results",
        "scan_results",
        "tasks",
    ]
    # Preserve FK order (children first)
    order = [
        "llm_analysis_results",
        "repair_results",
        "assessment_results",
        "scan_results",
        "tasks",
    ]
    ordered = [n for n in order if n in names] + [
        n for n in names if n not in order
    ]
    sql = "TRUNCATE TABLE " + ", ".join(ordered) + " CASCADE"

    async def _run():
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.execute(text(sql))

    asyncio.run(_run())


def _ensure_schema() -> None:
    """Create schema once per process; do not dispose engine every test."""
    global _SESSION_SCHEMAS_READY
    from app.db import database
    from app.db.session import get_engine

    if not _SESSION_SCHEMAS_READY:
        _dispose_engine_quiet()
        database.reset_initialized()
        database.init_db()
        get_engine()
        _SESSION_SCHEMAS_READY = True
        # Existing PG databases may still have JSONB result columns; TEXT
        # matches the public persistence contract (raw JSON string).
        try:
            import asyncio as _aio

            from sqlalchemy import text as _text

            from app.db.session import get_engine as _ge
            async def _alter():
                eng = _ge()
                async with eng.begin() as conn:
                    for stmt in (
                        "ALTER TABLE repair_results ALTER COLUMN repair_json TYPE TEXT",
                        "ALTER TABLE assessment_results ALTER COLUMN assessment_json TYPE TEXT",
                        "ALTER TABLE scan_results ALTER COLUMN result_json TYPE TEXT",
                        "ALTER TABLE scan_results ALTER COLUMN summary_json TYPE TEXT",
                        "ALTER TABLE llm_analysis_results ALTER COLUMN analysis_json TYPE TEXT",
                    ):
                        try:
                            await conn.execute(_text(stmt))
                        except Exception:
                            pass
            _aio.run(_alter())
        except Exception:
            pass
    else:
        database._initialized = True


@pytest.fixture(autouse=True)
def _backend_test_defaults(monkeypatch, tmp_path):
    from app.core.config import settings
    from app.db import database
    from app.services.background_runner import reset_runner_state
    from app.services.llm_user_config import clear_user_configs

    monkeypatch.setattr(settings, "database_url", _test_database_url())
    monkeypatch.setattr(settings, "tmp_dir", str(tmp_path / "tmp"))
    Path(settings.tmp_dir).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "max_task_attempts", 1)
    monkeypatch.setattr(settings, "max_running_tasks", 2)
    monkeypatch.setattr(settings, "task_lease_seconds", 60)
    monkeypatch.setattr(settings, "task_heartbeat_seconds", 5)
    monkeypatch.setattr(settings, "lease_reaper_seconds", 5)
    monkeypatch.setattr(settings, "retry_base_seconds", 1)
    monkeypatch.setattr(settings, "retry_max_seconds", 2)
    monkeypatch.setattr(settings, "shutdown_grace_seconds", 0.0)
    monkeypatch.setattr(settings, "max_pending_tasks", 5)
    try:
        clear_user_configs()
    except Exception:
        pass
    try:
        reset_runner_state()
    except Exception:
        pass
    try:
        _ensure_schema()
        # Targeted isolation: clear task/result tables used by most suites.
        clean_tables(
            "llm_analysis_results",
            "repair_results",
            "assessment_results",
            "scan_results",
            "tasks",
        )
    except Exception:
        database.reset_initialized()
        database.init_db()
    yield
    try:
        reset_runner_state()
    except Exception:
        pass
    try:
        clear_user_configs()
    except Exception:
        pass
    database.reset_initialized()
    _dispose_engine_quiet()


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    from app.db import database

    database.init_db()
    yield Path(_test_database_url())


def settings_database_url() -> str:
    from app.core.config import settings
    return settings.database_url


def unique_repo(owner: str = "u", name: str = "r") -> str:
    return f"https://github.com/{owner}/{name}-{uuid.uuid4().hex[:8]}"


def make_extract_under_tmp(name: str = "task-mock-extract"):
    from app.core.config import settings
    from app.core.safe_extract import ExtractionResult

    dest = Path(settings.tmp_dir) / name
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "README.md").write_text("# mock\n")
    return ExtractionResult(
        dest_dir=str(dest),
        file_count=1,
        total_size=30,
        top_level_dir="mock-extract",
    )


def make_normal_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        dir_info = tarfile.TarInfo(name="test-repo/")
        dir_info.type = tarfile.DIRTYPE
        dir_info.mode = 0o755
        tar.addfile(dir_info)
        readme_content = b"# Test Repo\n\nThis is a test repository.\n"
        readme_info = tarfile.TarInfo(name="test-repo/README.md")
        readme_info.size = len(readme_content)
        readme_info.mode = 0o644
        tar.addfile(readme_info, io.BytesIO(readme_content))
        src_content = b'print("hello world")\n'
        src_info = tarfile.TarInfo(name="test-repo/main.py")
        src_info.size = len(src_content)
        src_info.mode = 0o644
        tar.addfile(src_info, io.BytesIO(src_content))
    return buf.getvalue()


def make_traversal_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
        evil_content = b"hacked\n"
        evil_info = tarfile.TarInfo(name="../../etc/passwd")
        evil_info.size = len(evil_content)
        evil_info.mode = 0o644
        tar.addfile(evil_info, io.BytesIO(evil_content))
    return buf.getvalue()


def make_symlink_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
        sym_info = tarfile.TarInfo(name="evil_link")
        sym_info.type = tarfile.SYMTYPE
        sym_info.linkname = "/etc/passwd"
        sym_info.mode = 0o777
        tar.addfile(sym_info)
    return buf.getvalue()


def make_hardlink_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
        lnk_info = tarfile.TarInfo(name="evil_hardlink")
        lnk_info.type = tarfile.LNKTYPE
        lnk_info.linkname = "safe.txt"
        lnk_info.mode = 0o644
        tar.addfile(lnk_info)
    return buf.getvalue()


def make_device_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
        chr_info = tarfile.TarInfo(name="evil_char_dev")
        chr_info.type = tarfile.CHRTYPE
        chr_info.devmajor = 1
        chr_info.devminor = 3
        chr_info.mode = 0o666
        tar.addfile(chr_info)
        blk_info = tarfile.TarInfo(name="evil_blk_dev")
        blk_info.type = tarfile.BLKTYPE
        blk_info.devmajor = 8
        blk_info.devminor = 0
        blk_info.mode = 0o660
        tar.addfile(blk_info)
    return buf.getvalue()


def make_fifo_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
        fifo_info = tarfile.TarInfo(name="evil_fifo")
        fifo_info.type = tarfile.FIFOTYPE
        fifo_info.mode = 0o600
        tar.addfile(fifo_info)
    return buf.getvalue()


def make_oversized_tarball(file_size: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"\x00" * file_size
        info = tarfile.TarInfo(name="big_file.bin")
        info.size = file_size
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def make_many_files_tarball(count: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"x"
        for i in range(count):
            info = tarfile.TarInfo(name=f"file_{i}.txt")
            info.size = 1
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def make_absolute_path_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"evil\n"
        info = tarfile.TarInfo(name="/etc/evil")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def make_null_byte_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"evil\n"
        info = tarfile.TarInfo(name="safe\x00evil.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


@pytest.fixture
def tmp_dest_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)
