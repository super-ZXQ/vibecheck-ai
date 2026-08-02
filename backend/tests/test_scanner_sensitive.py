"""Tests for the scanner core (scan_directory) and file-level rules.

Tests cover:
- EnvExampleFileRule returning ScanNotice (not a Finding)
- ProductionEnvWithSecretRule dedup suppression
- scan_directory: end-to-end detection, binary skip, large file skip,
  ignored dir skip, symlink skip, POSIX paths, overlapping dedup

ALL test strings are SYNTHETIC. No real credentials are used.

Test count: 9
"""

import os
import sys
from pathlib import Path

import pytest

from app.scanner.base import (
    Finding,
    FindingType,
    SENSITIVE_DATA_DIMENSION,
    ScanNotice,
    ScanResult,
    Severity,
)
from app.scanner.default_rules import DEFAULT_RULES
from app.scanner.rules import (
    EnvExampleFileRule,
    GitHubTokenRule,
    ProductionEnvWithSecretRule,
)
from app.scanner.sensitive import scan_directory


# --- Runtime-constructed mixed-character synthetic values (NOT real credentials) ---
_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
SYNTH_GITHUB_TOKEN = "ghp_" + _MIXED[:36]
SYNTH_PASSWORD = "s3cur3P@ssw0rd!"


# ============================================================================
# --- File-level rule tests (2 tests) ---
# ============================================================================

class TestEnvExampleFileRule:
    """Tests for R010 EnvExampleFileRule -- returns ScanNotice, not Finding."""

    def test_env_example_returns_notice(self):
        """ .env.example file returns a ScanNotice, not a security Finding."""
        rule = EnvExampleFileRule()
        result = rule.check_file(".env.example", 200)

        assert result is not None
        assert isinstance(result, ScanNotice)
        assert result.rule_id == "R010_ENV_EXAMPLE_FILE"
        assert ".env.example" in result.message

        # .env.sample should also return a notice
        result2 = rule.check_file(".env.sample", 200)
        assert isinstance(result2, ScanNotice)

        # A normal file should return None
        result3 = rule.check_file("config.py", 200)
        assert result3 is None


class TestProductionEnvDedup:
    """Tests for R011 ProductionEnvWithSecretRule dedup suppression."""

    def test_production_env_with_secret_dedup(self):
        """R011 on the SAME LINE as R001 is suppressed (column overlap).
        R011 on a DIFFERENT line is kept.
        """
        # Line 1: GITHUB_TOKEN with a format token — R001 and R011 both find it
        # Line 2: MY_CUSTOM_CONFIG — R011 doesn't flag it (not sensitive name)
        lines = [
            f'GITHUB_TOKEN = "{SYNTH_GITHUB_TOKEN}"',
            "MY_CUSTOM_CONFIG = some_production_value",
        ]

        # Run both rules
        github_rule = GitHubTokenRule()
        prod_rule = ProductionEnvWithSecretRule()

        findings = []
        findings.extend(github_rule.scan_content(".env.production", lines))
        findings.extend(prod_rule.scan_content(".env.production", lines))

        # Before dedup, there should be at least 2 findings (1 from R001, 1+ from R011)
        assert len(findings) >= 2

        # After dedup, R011 on the same line as R001 should be suppressed
        from app.scanner.sensitive import _deduplicate_findings
        deduped = _deduplicate_findings(findings)

        # R011 findings on the same line as R001 should be suppressed
        r011_on_line1 = [
            f for f in deduped
            if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET" and f.line_start == 1
        ]
        assert len(r011_on_line1) == 0

        # R001 finding should be preserved
        r001_findings = [f for f in deduped if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001_findings) == 1


# ============================================================================
# --- scan_directory tests (7 tests) ---
# ============================================================================

class TestScanDirectory:
    """Tests for the scan_directory function."""

    def test_scan_directory_finds_token(self, tmp_path):
        """End-to-end: scanner finds a GitHub token in a file."""
        # Create a file with a synthetic token
        (tmp_path / "config.py").write_text(
            f'GITHUB_TOKEN = "{SYNTH_GITHUB_TOKEN}"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        assert isinstance(result, ScanResult)
        assert result.total_files_scanned == 1
        assert len(result.findings) >= 1

        # At least one finding should be from R001
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        # Original token must not appear in any snippet
        for f in result.findings:
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked

    def test_scan_directory_skips_binary(self, tmp_path):
        """Binary files (.png) are skipped."""
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        (tmp_path / "readme.md").write_text("# Hello\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        # PNG should be in skipped_files
        skipped_png = [s for s in result.skipped_files if s.file_path.endswith(".png")]
        assert len(skipped_png) == 1
        assert skipped_png[0].reason == "binary"

        # Only readme.md should be scanned
        assert result.total_files_scanned == 1

    def test_scan_directory_skips_large_files(self, tmp_path, monkeypatch):
        """Files larger than scan_max_file_size are skipped."""
        # Temporarily lower the size limit
        from app.core.config import settings
        monkeypatch.setattr(settings, "scan_max_file_size", 100)

        (tmp_path / "big.txt").write_text("x" * 200, encoding="utf-8")
        (tmp_path / "small.txt").write_text("hello\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        skipped_big = [s for s in result.skipped_files if "big.txt" in s.file_path]
        assert len(skipped_big) == 1
        assert skipped_big[0].reason == "too_large"
        assert result.total_files_scanned == 1  # only small.txt

    def test_scan_directory_skips_ignored_dirs(self, tmp_path):
        """Ignored directories (node_modules) are skipped."""
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "package.js").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        # node_modules should not be scanned
        assert result.total_files_scanned == 1  # only app.py
        # No findings from the token in node_modules
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 0

    @pytest.mark.skipif(sys.platform == 'win32', reason='Symlinks require admin on Windows')
    def test_scan_directory_skips_symlinks(self, tmp_path):
        """Symlink files and directories are skipped during scanning.

        This test runs on Linux/macOS where symlinks can be created without
        admin privileges. On Windows it is skipped.
        """
        # Create a real file with a token
        real_file = tmp_path / "real_config.py"
        real_file.write_text(f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8")

        # Create a symlink to it
        symlink_file = tmp_path / "link_config.py"
        os.symlink(str(real_file), str(symlink_file))

        # Create a symlink directory
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "secret.py").write_text(
            f'key="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        symlink_dir = tmp_path / "link_dir"
        os.symlink(str(real_dir), str(symlink_dir))

        result = scan_directory(tmp_path)

        # Only real_config.py and real_dir/secret.py should be scanned
        # (symlink_file and symlink_dir should be skipped)
        all_finding_paths = {f.file_path for f in result.findings}
        assert "link_config.py" not in all_finding_paths
        # link_dir contents should not appear
        for path in all_finding_paths:
            assert not path.startswith("link_dir/")

    def test_scan_directory_posix_paths(self, tmp_path):
        """All returned paths use POSIX format (forward slashes)."""
        # Create a nested directory structure
        nested = tmp_path / "src" / "config"
        nested.mkdir(parents=True)
        (nested / "settings.py").write_text(
            f'password = "{SYNTH_PASSWORD}"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # All finding paths should use forward slashes
        for f in result.findings:
            if f.dimension != SENSITIVE_DATA_DIMENSION:
                continue
            assert "\\" not in f.file_path
            assert "/" in f.file_path or f.file_path == "settings.py"

        # The nested file should be found with POSIX path
        nested_findings = [
            f for f in result.findings
            if "settings.py" in f.file_path
        ]
        assert len(nested_findings) >= 1
        assert nested_findings[0].file_path == "src/config/settings.py"

    def test_scan_directory_dedup_overlapping(self, tmp_path):
        """Overlapping findings on the same line are deduplicated by priority."""
        # A line with a GitHub token also matches the generic token assignment rule
        # Both R001 and R007 would find something, but R001 has higher priority
        (tmp_path / "config.py").write_text(
            f'token = "{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # Find all findings on line 1 of config.py
        line1_findings = [
            f for f in result.findings
            if f.file_path == "config.py" and f.line_start == 1
        ]

        # R001 should be present (higher priority)
        r001 = [f for f in line1_findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1

        # R007 might or might not be present depending on overlap,
        # but if present, it should NOT overlap with R001
        r007 = [f for f in line1_findings if f.rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"]
        for f in r007:
            # If R007 exists, its column range should not overlap with R001
            r001_finding = r001[0]
            if (f.column_start is not None and r001_finding.column_start is not None):
                assert not (
                    f.column_start < r001_finding.column_end
                    and r001_finding.column_start < f.column_end
                )


# ============================================================================
# --- Bytes-first binary detection tests (4 tests) ---
# ============================================================================

class TestBytesFirstBinaryDetection:
    """Verify bytes-first binary detection: NUL bytes, UTF-8-SIG BOM,
    CRLF line endings, and invalid UTF-8 handling.

    The scanner reads files as bytes first, checks for NUL bytes and
    binary indicators before decoding, uses utf-8-sig for BOM handling,
    and skips invalid UTF-8 as binary.
    """

    def test_unknown_ext_with_nul_is_binary(self, tmp_path):
        """Unknown extension file with NUL byte is judged as binary.

        The file has a .xyz extension (not in binary_extensions list),
        contains a NUL byte but the rest is valid UTF-8. The NUL byte
        must cause it to be skipped as binary — not scanned.
        """
        # .xyz is NOT in scan_binary_extensions
        content = b'password = "some_value"\x00\nmore text\n'
        (tmp_path / "data.xyz").write_bytes(content)

        result = scan_directory(tmp_path)

        # File must be skipped as binary
        skipped = [s for s in result.skipped_files if "data.xyz" in s.file_path]
        assert len(skipped) == 1
        assert skipped[0].reason == "binary"

        # No findings should come from this file
        assert result.total_files_scanned == 0

    def test_utf8_sig_bom_secret_detected(self, tmp_path):
        """UTF-8-SIG file (with BOM) detects secret on first line.

        The utf-8-sig decoder strips the BOM, so line numbering starts
        correctly at line 1 for the first content line.
        """
        # Write a file with UTF-8 BOM + secret on first line
        bom = b'\xef\xbb\xbf'
        content = bom + f'GITHUB_TOKEN = "{SYNTH_GITHUB_TOKEN}"\n'.encode("utf-8")
        (tmp_path / "config.py").write_bytes(content)

        result = scan_directory(tmp_path)

        # Secret should be detected on line 1
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        assert r001[0].line_start == 1
        # Original token must not appear in snippet
        assert SYNTH_GITHUB_TOKEN not in r001[0].snippet_masked

    def test_crlf_line_numbers_correct(self, tmp_path):
        """CRLF file line numbers are correct.

        splitlines() handles both \\n and \\r\\n, so line numbers
        must be correct regardless of line ending style.
        """
        # Write a file with CRLF line endings
        lines = [
            '# comment line',
            f'TOKEN = "{SYNTH_GITHUB_TOKEN}"',
            '# another comment',
        ]
        content = '\r\n'.join(lines) + '\r\n'
        (tmp_path / "config.py").write_bytes(content.encode("utf-8"))

        result = scan_directory(tmp_path)

        # Secret should be on line 2 (after comment on line 1)
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        assert r001[0].line_start == 2
        assert SYNTH_GITHUB_TOKEN not in r001[0].snippet_masked

    def test_invalid_utf8_skipped_as_binary(self, tmp_path):
        """Invalid UTF-8 file (no NUL) is skipped as binary with safe error info.

        The file contains bytes that cannot be decoded as UTF-8 but has
        NO NUL byte — testing the UTF-8 decode failure path directly.
        It must be skipped as binary — not produce an error with
        raw bytes, str(exc), repr(exc), or absolute paths.
        """
        # Write bytes that are invalid UTF-8 (0xff 0xfe is not valid UTF-8)
        # NO NUL byte — tests the UTF-8 decode failure path
        content = b'\xff\xfe\xff some text that looks like text'
        (tmp_path / "weird.dat").write_bytes(content)

        result = scan_directory(tmp_path)

        # File must be skipped as binary (invalid UTF-8 decode)
        skipped = [s for s in result.skipped_files if "weird.dat" in s.file_path]
        assert len(skipped) == 1
        assert skipped[0].reason == "binary"

        # No errors should be produced (binary skip, not read error)
        errors = [e for e in result.scan_errors if "weird.dat" in e.file_path]
        assert len(errors) == 0

        # No findings
        assert result.total_files_scanned == 0
