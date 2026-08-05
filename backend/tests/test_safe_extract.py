"""Tests for safe tarball extraction.

All test tarballs are constructed in-memory with SYNTHETIC data.
No real credentials or network resources are involved.
"""

import pytest

from app.core.safe_extract import (
    ExtractionError,
    _validate_member_name,
    cleanup_temp_dir,
    safe_extract,
)
from tests.conftest import (
    make_absolute_path_tarball,
    make_device_tarball,
    make_fifo_tarball,
    make_hardlink_tarball,
    make_many_files_tarball,
    make_normal_tarball,
    make_oversized_tarball,
    make_symlink_tarball,
    make_traversal_tarball,
)

# --- Normal extraction ---

class TestNormalExtraction:
    """Test that normal, safe tarballs extract correctly."""

    def test_normal_tarball_extracts(self, tmp_dest_dir):
        """A normal tarball should extract without errors."""
        tarball = make_normal_tarball()
        result = safe_extract(tarball, tmp_dest_dir)

        assert result.file_count == 2  # README.md and main.py
        assert result.total_size > 0
        assert result.top_level_dir == "test-repo"

        # Verify files exist
        assert (tmp_dest_dir / "test-repo" / "README.md").exists()
        assert (tmp_dest_dir / "test-repo" / "main.py").exists()
        # Directory entry should exist
        assert (tmp_dest_dir / "test-repo").is_dir()

    def test_file_contents_are_correct(self, tmp_dest_dir):
        """Extracted file contents should match the tarball."""
        tarball = make_normal_tarball()
        safe_extract(tarball, tmp_dest_dir)

        readme = (tmp_dest_dir / "test-repo" / "README.md").read_text()
        assert "# Test Repo" in readme

        main_py = (tmp_dest_dir / "test-repo" / "main.py").read_text()
        assert "hello world" in main_py


# --- Path traversal ---

class TestPathTraversal:
    """Test that path traversal attacks are blocked."""

    def test_traversal_rejected(self, tmp_dest_dir):
        """Path traversal entries (../../etc/passwd) must be rejected."""
        tarball = make_traversal_tarball()
        with pytest.raises(ExtractionError, match="path traversal"):
            safe_extract(tarball, tmp_dest_dir)

    def test_absolute_path_rejected(self, tmp_dest_dir):
        """Absolute paths (/etc/evil) must be rejected."""
        tarball = make_absolute_path_tarball()
        with pytest.raises(ExtractionError, match="absolute path"):
            safe_extract(tarball, tmp_dest_dir)

    def test_null_byte_rejected(self, tmp_dest_dir):
        """Null bytes in filenames must be rejected by the validator.

        Note: Python's tarfile truncates names at null bytes when reading,
        so we test _validate_member_name directly to ensure defense-in-depth.
        """
        with pytest.raises(ExtractionError, match="null byte"):
            _validate_member_name("safe\x00evil.txt")

    def test_traversal_cleans_up(self, tmp_dest_dir):
        """On failure, the destination directory should be cleaned up."""
        tarball = make_traversal_tarball()
        with pytest.raises(ExtractionError):
            safe_extract(tarball, tmp_dest_dir)

        # Directory should be removed after failure
        assert not tmp_dest_dir.exists() or not any(tmp_dest_dir.iterdir())


# --- Dangerous file types ---

class TestDangerousFileTypes:
    """Test that dangerous file types are rejected."""

    def test_symlink_rejected(self, tmp_dest_dir):
        """Symlinks must be rejected."""
        tarball = make_symlink_tarball()
        with pytest.raises(ExtractionError, match="symlink"):
            safe_extract(tarball, tmp_dest_dir)

    def test_hardlink_rejected(self, tmp_dest_dir):
        """Hardlinks must be rejected."""
        tarball = make_hardlink_tarball()
        with pytest.raises(ExtractionError, match="hardlink"):
            safe_extract(tarball, tmp_dest_dir)

    def test_device_files_rejected(self, tmp_dest_dir):
        """Device files (char and block) must be rejected."""
        tarball = make_device_tarball()
        with pytest.raises(ExtractionError, match="device"):
            safe_extract(tarball, tmp_dest_dir)

    def test_fifo_rejected(self, tmp_dest_dir):
        """FIFO entries must be rejected."""
        tarball = make_fifo_tarball()
        with pytest.raises(ExtractionError, match="FIFO"):
            safe_extract(tarball, tmp_dest_dir)

    def test_all_dangerous_types_cleans_up(self, tmp_dest_dir):
        """All dangerous type rejections should clean up the directory."""
        for make_func in [
            make_symlink_tarball,
            make_hardlink_tarball,
            make_device_tarball,
            make_fifo_tarball,
        ]:
            tarball = make_func()
            with pytest.raises(ExtractionError):
                safe_extract(tarball, tmp_dest_dir)
            # Directory should be removed after failure
            assert not tmp_dest_dir.exists() or not any(tmp_dest_dir.iterdir())


# --- Size and count limits ---

class TestSizeAndCountLimits:
    """Test that cumulative size and count limits are enforced."""

    def test_single_file_too_large(self, tmp_dest_dir):
        """A single file exceeding the size limit must be rejected."""
        tarball = make_oversized_tarball(file_size=1024)
        with pytest.raises(ExtractionError, match="File too large"):
            safe_extract(
                tarball,
                tmp_dest_dir,
                max_single_file_size=512,
                max_total_size=10 * 1024 * 1024,
                max_file_count=100,
                max_archive_size=10 * 1024 * 1024,
            )

    def test_total_size_exceeds_limit(self, tmp_dest_dir):
        """Cumulative total size exceeding the limit must be rejected."""
        tarball = make_oversized_tarball(file_size=2048)
        with pytest.raises(ExtractionError, match="Total extracted size"):
            safe_extract(
                tarball,
                tmp_dest_dir,
                max_single_file_size=10 * 1024,
                max_total_size=1024,  # Lower than file size
                max_file_count=100,
                max_archive_size=10 * 1024 * 1024,
            )

    def test_file_count_exceeds_limit(self, tmp_dest_dir):
        """File count exceeding the limit must be rejected."""
        tarball = make_many_files_tarball(count=50)
        with pytest.raises(ExtractionError, match="Too many files"):
            safe_extract(
                tarball,
                tmp_dest_dir,
                max_single_file_size=10 * 1024,
                max_total_size=10 * 1024 * 1024,
                max_file_count=10,  # Lower than file count
                max_archive_size=10 * 1024 * 1024,
            )

    def test_archive_too_large(self, tmp_dest_dir):
        """Archive exceeding the size limit must be rejected before extraction."""
        tarball = make_oversized_tarball(file_size=2048)
        with pytest.raises(ExtractionError, match="Archive too large"):
            safe_extract(
                tarball,
                tmp_dest_dir,
                max_archive_size=100,  # Very small limit
                max_single_file_size=10 * 1024,
                max_total_size=10 * 1024 * 1024,
                max_file_count=100,
            )

    def test_size_limits_cleans_up(self, tmp_dest_dir):
        """Size limit violations should clean up the directory."""
        tarball = make_oversized_tarball(file_size=2048)
        with pytest.raises(ExtractionError):
            safe_extract(
                tarball,
                tmp_dest_dir,
                max_single_file_size=512,
                max_total_size=10 * 1024 * 1024,
                max_file_count=100,
                max_archive_size=10 * 1024 * 1024,
            )
        assert not tmp_dest_dir.exists() or not any(tmp_dest_dir.iterdir())


# --- Cleanup ---

class TestCleanup:
    """Test cleanup functionality."""

    def test_cleanup_temp_dir(self, tmp_dest_dir):
        """cleanup_temp_dir should remove the directory."""
        # Create a file in the directory
        (tmp_dest_dir / "test.txt").write_text("test")

        cleanup_temp_dir(tmp_dest_dir)
        assert not tmp_dest_dir.exists()

    def test_cleanup_nonexistent_dir(self):
        """cleanup_temp_dir should not error on non-existent directory."""
        cleanup_temp_dir("/nonexistent/path/that/does/not/exist")
        # Should not raise an exception
