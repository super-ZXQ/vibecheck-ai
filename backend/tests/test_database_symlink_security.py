"""Tests for production database path validation — symlink and traversal defence.

These tests verify the runtime real-path validation added to database.py:
  - URL-encoded path traversal (%2e, %2f, %5c, %00)
  - Symlink components anywhere from data_root to the database file
  - Symlink targets inside data_root are also rejected (unified policy)
  - PRAGMA database_list post-connection path verification
  - Error messages never leak the full database path
"""

import os
import sqlite3
from pathlib import Path

import pytest

from app.db.database import (
    _verify_database_list_path,
    validate_production_database_path,
)


# ---------------------------------------------------------------------------
# Platform detection — symlink tests are skipped where unsupported.
# ---------------------------------------------------------------------------

def _can_symlink() -> bool:
    """Return True if the platform supports os.symlink."""
    try:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            link = Path(d) / "link"
            os.symlink(target, link)
        return True
    except (OSError, NotImplementedError):
        return False


CAN_SYMLINK = _can_symlink()
skip_no_symlink = pytest.mark.skipif(
    not CAN_SYMLINK,
    reason="symlink creation not supported on this platform",
)


# ---------------------------------------------------------------------------
# validate_production_database_path
# ---------------------------------------------------------------------------

class TestValidateProductionDatabasePath:
    """Unit tests for the standalone path validation function."""

    def test_normal_data_path_passes(self, tmp_path):
        """A normal database file inside data_root passes validation."""
        data_root = tmp_path / "data"
        data_root.mkdir()
        db_path = data_root / "vibecheck.db"
        db_path.touch()

        result = validate_production_database_path(
            f"sqlite:///{db_path}",
            data_root=data_root,
        )
        assert result == db_path.resolve()

    def test_nested_subdirectory_path_passes(self, tmp_path):
        """A database file in a subdirectory of data_root passes."""
        data_root = tmp_path / "data"
        data_root.mkdir()
        sub = data_root / "tenant"
        sub.mkdir()
        db_path = sub / "vibecheck.db"
        db_path.touch()

        result = validate_production_database_path(
            f"sqlite:///{db_path}",
            data_root=data_root,
        )
        assert result == db_path.resolve()

    # --- URL-encoded path traversal ---

    def test_encoded_dot_dot_rejected(self, tmp_path):
        """URL-encoded %2e%2e (..) is rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        with pytest.raises(ValueError, match="forbidden encoded character"):
            validate_production_database_path(
                "sqlite:////data/%2e%2e/vibecheck.db",
                data_root=data_root,
            )

    def test_encoded_dot_dot_mixed_case_rejected(self, tmp_path):
        """URL-encoded %2E%2E (mixed case) is also rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        with pytest.raises(ValueError, match="forbidden encoded character"):
            validate_production_database_path(
                "sqlite:////data/%2E%2E/vibecheck.db",
                data_root=data_root,
            )

    def test_encoded_forward_slash_rejected(self, tmp_path):
        """URL-encoded %2f (/) is rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        with pytest.raises(ValueError, match="forbidden encoded character"):
            validate_production_database_path(
                "sqlite:////data%2fvibecheck.db",
                data_root=data_root,
            )

    def test_encoded_backslash_rejected(self, tmp_path):
        """URL-encoded %5c (backslash) is rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        with pytest.raises(ValueError, match="forbidden encoded character"):
            validate_production_database_path(
                "sqlite:////data%5cvibecheck.db",
                data_root=data_root,
            )

    def test_encoded_nul_rejected(self, tmp_path):
        """URL-encoded %00 (NUL) is rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        with pytest.raises(ValueError, match="forbidden encoded character"):
            validate_production_database_path(
                "sqlite:////data/vibecheck%00.db",
                data_root=data_root,
            )

    # --- Path traversal without encoding (caught by resolve + relative_to) ---

    def test_dot_dot_traversal_rejected(self, tmp_path):
        """Unencoded .. path traversal is rejected by containment check."""
        data_root = tmp_path / "data"
        data_root.mkdir()
        # Create the parent so resolve(strict=False) works
        (data_root / "..").resolve()

        with pytest.raises(ValueError, match="outside the data root"):
            validate_production_database_path(
                f"sqlite:///{data_root}/../escape.db",
                data_root=data_root,
            )

    # --- Symlink tests ---

    @skip_no_symlink
    def test_database_file_is_symlink_outside_data(self, tmp_path):
        """Database file itself is a symlink pointing outside data_root."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        outside_file = tmp_path / "outside.db"
        outside_file.touch()

        symlink_db = data_root / "vibecheck.db"
        os.symlink(outside_file, symlink_db)

        with pytest.raises(ValueError, match="symlink"):
            validate_production_database_path(
                f"sqlite:///{symlink_db}",
                data_root=data_root,
            )

    @skip_no_symlink
    def test_intermediate_directory_is_symlink_outside(self, tmp_path):
        """Intermediate directory inside data_root is a symlink to outside."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "vibecheck.db").touch()

        symlink_dir = data_root / "subdir"
        os.symlink(outside_dir, symlink_dir)

        with pytest.raises(ValueError, match="symlink"):
            validate_production_database_path(
                f"sqlite:///{symlink_dir / 'vibecheck.db'}",
                data_root=data_root,
            )

    @skip_no_symlink
    def test_symlink_pointing_inside_data_also_rejected(self, tmp_path):
        """Symlink that points inside data_root is still rejected (unified policy)."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        real_dir = data_root / "real_dir"
        real_dir.mkdir()
        (real_dir / "vibecheck.db").touch()

        symlink_dir = data_root / "link_dir"
        os.symlink(real_dir, symlink_dir)

        with pytest.raises(ValueError, match="symlink"):
            validate_production_database_path(
                f"sqlite:///{symlink_dir / 'vibecheck.db'}",
                data_root=data_root,
            )

    # --- Containment and format checks ---

    def test_path_outside_data_root_rejected(self, tmp_path):
        """A path outside data_root is rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        outside = tmp_path / "outside.db"
        outside.touch()

        with pytest.raises(ValueError, match="outside the data root"):
            validate_production_database_path(
                f"sqlite:///{outside}",
                data_root=data_root,
            )

    def test_non_absolute_path_rejected(self, tmp_path):
        """Non-absolute paths are rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        with pytest.raises(ValueError, match="absolute"):
            validate_production_database_path(
                "sqlite:///relative.db",
                data_root=data_root,
            )

    def test_non_sqlite_scheme_rejected(self, tmp_path):
        """Non-sqlite URLs are rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        with pytest.raises(ValueError, match="sqlite"):
            validate_production_database_path(
                "postgresql:///data/vibecheck.db",
                data_root=data_root,
            )

    def test_nonexistent_data_root_rejected(self, tmp_path):
        """Non-existent data_root is rejected (strict resolve)."""
        data_root = tmp_path / "nonexistent"

        with pytest.raises((FileNotFoundError, ValueError)):
            validate_production_database_path(
                "sqlite:////data/vibecheck.db",
                data_root=data_root,
            )

    # --- Error message safety ---

    def test_error_message_does_not_leak_path(self, tmp_path):
        """Error messages must not contain the full database path."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        outside = tmp_path / "secret_leaked_path_db.db"
        outside.touch()

        with pytest.raises(ValueError) as exc_info:
            validate_production_database_path(
                f"sqlite:///{outside}",
                data_root=data_root,
            )

        error_msg = str(exc_info.value)
        assert "secret_leaked_path_db" not in error_msg
        assert str(outside) not in error_msg


# ---------------------------------------------------------------------------
# _verify_database_list_path (PRAGMA database_list)
# ---------------------------------------------------------------------------

class TestVerifyDatabaseListPath:
    """Tests for the post-connection PRAGMA database_list verification."""

    def test_valid_connection_passes(self, tmp_path):
        """A connection to a database inside data_root passes."""
        data_root = tmp_path / "data"
        data_root.mkdir()
        db_path = data_root / "vibecheck.db"

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            _verify_database_list_path(conn, data_root=data_root)
        finally:
            conn.close()

    def test_connection_outside_data_root_rejected(self, tmp_path):
        """A connection to a database outside data_root is rejected."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        outside = tmp_path / "outside.db"
        conn = sqlite3.connect(str(outside))
        conn.row_factory = sqlite3.Row
        try:
            with pytest.raises(ValueError, match="outside the data root"):
                _verify_database_list_path(conn, data_root=data_root)
        finally:
            conn.close()

    def test_error_message_does_not_leak_path(self, tmp_path):
        """PRAGMA database_list error must not leak the database path."""
        data_root = tmp_path / "data"
        data_root.mkdir()

        outside = tmp_path / "leaked_secret_path.db"
        conn = sqlite3.connect(str(outside))
        conn.row_factory = sqlite3.Row
        try:
            with pytest.raises(ValueError) as exc_info:
                _verify_database_list_path(conn, data_root=data_root)

            error_msg = str(exc_info.value)
            assert "leaked_secret_path" not in error_msg
        finally:
            conn.close()

    @skip_no_symlink
    def test_symlinked_database_detected_post_connection(self, tmp_path):
        """A symlinked database file is detected via PRAGMA database_list.

        This tests the scenario where a symlink is created AFTER the initial
        path validation but BEFORE a new connection opens — the PRAGMA
        database_list check catches the real opened path.
        """
        data_root = tmp_path / "data"
        data_root.mkdir()

        # Create the real database outside data_root
        outside_db = tmp_path / "outside_real.db"
        conn_outside = sqlite3.connect(str(outside_db))
        conn_outside.close()

        # Create a symlink inside data_root pointing to the outside database
        symlink_db = data_root / "vibecheck.db"
        os.symlink(outside_db, symlink_db)

        # Open a connection through the symlink
        conn = sqlite3.connect(str(symlink_db))
        conn.row_factory = sqlite3.Row
        try:
            with pytest.raises(ValueError, match="outside the data root"):
                _verify_database_list_path(conn, data_root=data_root)
        finally:
            conn.close()
