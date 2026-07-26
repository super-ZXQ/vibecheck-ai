"""Security-focused tests for the sensitive information scanner.

These tests verify that NO complete synthetic secret ever appears in:
- Finding objects (any field)
- Log output
- Exception text
- Serialized JSON
- repr() output

They also verify:
- Truncation boundary safety (no partial secret fragments)
- No line limit (secrets in later lines are found)
- Path containment validation
- Error message safety (no absolute paths or exception text)
- Rule attribute correctness (blocking vs non-blocking)
- Private key type coverage
- Deterministic scan order
- .git directory is ignored
- Symlink handling on Linux

ALL test strings are SYNTHETIC -- correct format but NO actual validity.

Test count: 20
"""

import builtins
import dataclasses
import json
import logging
import os
import sys

import pytest

from app.scanner.base import Confidence, Severity
from app.scanner.rules import PrivateKeyRule
from app.scanner.sensitive import scan_directory


# --- Runtime-constructed mixed-character synthetic values (NOT real credentials) ---
_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
_MIXED_UPPER = "ABCDEF1234567890GHIJKLMNOP"
SYNTH_GITHUB_TOKEN = "ghp_" + _MIXED[:36]
SYNTH_AWS_KEY = "AKIA" + _MIXED_UPPER[:16]
SYNTH_AWS_SECRET = ("AbCdEf1234" * 4)[:40]
SYNTH_GOOGLE_KEY = "AIza" + _MIXED[:35]
SYNTH_PASSWORD = "s3cur3P@ssw0rd!"

# Low-entropy placeholder tokens (all same char after prefix)
LOW_GITHUB = "ghp_" + "A" * 36
LOW_AWS_KEY = "AKIA" + "X" * 16
LOW_AWS_SECRET = "X" * 40
LOW_GOOGLE = "AIza" + "X" * 35


# ============================================================================
# --- Secret containment tests (tests 1-5) ---
# ============================================================================

class TestSecretContainment:
    """Verify that complete synthetic secrets never appear in any output."""

    def test_secret_not_in_finding_object(self, tmp_path):
        """Test 1: Complete synthetic key does not appear in ANY field of any Finding."""
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        for f in result.findings:
            # Check every string field of the Finding
            for field_name in dataclasses.fields(f):
                value = getattr(f, field_name.name)
                if isinstance(value, str):
                    assert SYNTH_GITHUB_TOKEN not in value, \
                        f"Secret found in Finding field '{field_name.name}'"

    def test_secret_not_in_logs(self, tmp_path, caplog):
        """Test 2: Complete synthetic key does not appear in log output."""
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        with caplog.at_level(logging.DEBUG):
            result = scan_directory(tmp_path)

        for record in caplog.records:
            assert SYNTH_GITHUB_TOKEN not in record.message
            assert SYNTH_GITHUB_TOKEN not in record.getText()

    def test_secret_not_in_exception_text(self, tmp_path, monkeypatch):
        """Test 3: Complete synthetic key does not appear in exception text
        captured by the scanner's error handling."""
        # Create a file with a secret
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        # Patch open to raise an exception containing the file content
        original_open = builtins.open

        def failing_open(file, *args, **kwargs):
            f = original_open(file, *args, **kwargs)
            try:
                content = f.read()
            finally:
                f.close()
            # Deliberately include content in exception to test safety
            raise OSError(f"Failed to read file content: {content}")

        monkeypatch.setattr(builtins, "open", failing_open)

        result = scan_directory(tmp_path)

        # Error messages must NOT contain the secret or exception text
        for error in result.scan_errors:
            assert SYNTH_GITHUB_TOKEN not in error.error_message
            assert "Failed to read" not in error.error_message

    def test_secret_not_in_serialized_json(self, tmp_path):
        """Test 4: Complete synthetic key does not appear in serialized JSON."""
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        # Serialize findings to JSON
        findings_list = [
            {field.name: str(getattr(f, field.name)) for field in dataclasses.fields(f)}
            for f in result.findings
        ]
        json_str = json.dumps(findings_list)
        assert SYNTH_GITHUB_TOKEN not in json_str

        # Also check the full ScanResult serialization
        full_dict = {
            "findings": findings_list,
            "total_files_scanned": result.total_files_scanned,
            "total_lines_scanned": result.total_lines_scanned,
        }
        full_json = json.dumps(full_dict)
        assert SYNTH_GITHUB_TOKEN not in full_json

    def test_repr_does_not_contain_secret(self, tmp_path):
        """Test 5: Finding and ScanResult repr() do not contain complete key."""
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        for f in result.findings:
            assert SYNTH_GITHUB_TOKEN not in repr(f)

        assert SYNTH_GITHUB_TOKEN not in repr(result)


# ============================================================================
# --- Masking and truncation tests (tests 6-7) ---
# ============================================================================

class TestMaskingSafety:
    """Verify masking handles edge cases safely."""

    def test_two_different_secret_types_same_line(self, tmp_path):
        """Test 6: Two different secret types on the same line are both masked."""
        line = f'token="{SYNTH_GITHUB_TOKEN}" key="{SYNTH_AWS_KEY}"'
        (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        # At least one finding should exist
        assert len(result.findings) >= 1

        # Neither original secret should appear in any snippet
        for f in result.findings:
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
            assert SYNTH_AWS_KEY not in f.snippet_masked

    def test_secret_spanning_truncation_boundary(self, tmp_path):
        """Test 7: Secret spanning the snippet truncation boundary leaks nothing.

        A GitHub token is placed so that it starts before position 200 and
        ends after position 200. Since masking happens on the full line
        BEFORE truncation, no fragment of the original token can survive.
        """
        # Position the token so it starts at char 195 and ends at char 235
        # (spanning the 200-char truncation boundary)
        prefix = "x" * 195
        suffix = "y" * 100
        line = f'{prefix}{SYNTH_GITHUB_TOKEN}{suffix}'
        (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        # Check all findings
        r001_findings = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001_findings) == 1

        snippet = r001_findings[0].snippet_masked
        # The full original token must not appear
        assert SYNTH_GITHUB_TOKEN not in snippet
        # No partial fragment of the token should appear
        # Check that no 10-char substring of the mixed token body survives
        assert _MIXED[:10] not in snippet


# ============================================================================
# --- Full scan coverage tests (tests 8-9) ---
# ============================================================================

class TestFullScanCoverage:
    """Verify the scanner covers all content without line limits."""

    def test_secret_on_line_5001_plus(self, tmp_path):
        """Test 8: Secret located after line 5000 is still detected.

        The old 5000-line limit has been removed. Files under
        scan_max_file_size are scanned in full.
        """
        # Create a file with 5001+ lines, secret on the last line
        lines = ["# comment line"] * 5000
        lines.append(f'TOKEN = "{SYNTH_GITHUB_TOKEN}"')
        content = "\n".join(lines) + "\n"
        (tmp_path / "big_config.py").write_text(content, encoding="utf-8")

        result = scan_directory(tmp_path)

        # The token should be found
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        # Line number should be 5001
        assert r001[0].line_start == 5001

    @pytest.mark.skipif(sys.platform == 'win32', reason='Symlinks require admin on Windows')
    def test_path_outside_root_skipped(self, tmp_path):
        """Test 9: File resolving outside scan root is skipped.

        A symlink is created pointing to a file outside the scan root.
        The scanner must not follow it or produce findings from it.
        """
        # Create a file OUTSIDE the scan root with a secret
        outside_dir = tmp_path.parent / "outside_secret_dir"
        outside_dir.mkdir(exist_ok=True)
        outside_file = outside_dir / "outside_config.py"
        outside_file.write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        try:
            # Create a symlink inside the scan root pointing outside
            symlink_inside = tmp_path / "link_to_outside.py"
            os.symlink(str(outside_file), str(symlink_inside))

            result = scan_directory(tmp_path)

            # No findings should come from the outside file
            all_paths = {f.file_path for f in result.findings}
            assert "link_to_outside.py" not in all_paths
            # The token should not appear in any finding
            for f in result.findings:
                assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
        finally:
            # Cleanup
            if outside_file.exists():
                outside_file.unlink()
            if outside_dir.exists():
                outside_dir.rmdir()


# ============================================================================
# --- Error safety tests (test 10) ---
# ============================================================================

class TestErrorSafety:
    """Verify error messages are safe (no sensitive data)."""

    def test_scan_errors_no_absolute_path_or_exception(self, tmp_path, monkeypatch):
        """Test 10: scan_errors do not contain absolute paths or str(exception)."""
        # Create a file with a secret
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        # Patch open to raise OSError with sensitive info in the message
        original_open = builtins.open

        def failing_open(file, *args, **kwargs):
            raise OSError(f"Permission denied: {file} content={SYNTH_GITHUB_TOKEN}")

        monkeypatch.setattr(builtins, "open", failing_open)

        result = scan_directory(tmp_path)

        # Check all scan_errors
        assert len(result.scan_errors) >= 1
        for error in result.scan_errors:
            # No absolute paths
            assert str(tmp_path) not in error.error_message
            assert "C:" not in error.error_message
            assert "/" not in error.error_message
            # No exception text
            assert "Permission denied" not in error.error_message
            assert SYNTH_GITHUB_TOKEN not in error.error_message
            assert "OSError" not in error.error_message
            # Only fixed reason codes
            assert error.error_type in ("stat_error", "read_error", "outside_root")


# ============================================================================
# --- Rule attribute tests (tests 11-14) ---
# ============================================================================

class TestRuleAttributes:
    """Verify rule blocking attributes are correct."""

    def test_env_production_non_placeholder_blocking(self, tmp_path):
        """Test 11: .env.production with non-placeholder secret is blocking.

        Uses a value that triggers R011 (ProductionEnvWithSecret) directly,
        without matching any specific format rule (R001-R008).
        """
        (tmp_path / ".env.production").write_text(
            "SECRET_KEY=prod_sk_abc123def456ghi789\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # Should have at least one blocking finding from R011
        blocking_findings = [f for f in result.findings if f.is_blocking]
        assert len(blocking_findings) >= 1

        # R011 should be present (not suppressed by specific rules)
        r011 = [f for f in result.findings if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"]
        assert len(r011) >= 1
        assert r011[0].is_blocking is True

    def test_env_production_all_placeholders_not_blocking(self, tmp_path):
        """Test 12: .env.production with all placeholder values is not blocking."""
        (tmp_path / ".env.production").write_text(
            "API_KEY=changeme\n"
            "DB_PASSWORD=foobar\n"
            "SECRET=example\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # No blocking findings should be produced
        blocking_findings = [f for f in result.findings if f.is_blocking]
        assert len(blocking_findings) == 0

    def test_env_example_not_in_security_findings(self, tmp_path):
        """Test 13: .env.example with only placeholder values does not produce findings.

        Template env files still generate a ScanNotice, but placeholder values
        like your_api_key_here do not match any high-confidence format rule
        (R001-R005), so no security Finding is produced.
        """
        (tmp_path / ".env.example").write_text(
            "API_KEY=your_api_key_here\n"
            "DB_PASSWORD=your_password_here\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # No security findings should reference .env.example
        for f in result.findings:
            assert ".env.example" not in f.file_path

        # A notice should be present
        notices = [n for n in result.notices if ".env.example" in (n.file_path or "")]
        assert len(notices) >= 1

    def test_masked_documentation_examples_not_blocking(self, tmp_path):
        """Test 14: Already-masked examples in documentation do not trigger blocking."""
        (tmp_path / "README.md").write_text(
            "# Configuration Guide\n"
            "# Set your password:\n"
            "# password = <REDACTED>\n"
            "# Set your token:\n"
            '# token = "ghp_...XXXX"\n'
            "# Set your API key:\n"
            '# api_key = "***"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # No blocking findings should be produced
        blocking_findings = [f for f in result.findings if f.is_blocking]
        assert len(blocking_findings) == 0


# ============================================================================
# --- Token and private key coverage tests (tests 15-16) ---
# ============================================================================

class TestTokenAndKeyCoverage:
    """Verify token and private key detection coverage."""

    def test_token_with_test_chars_still_detected(self, tmp_path):
        """Test 15: Format token containing 'test' characters is still detected."""
        # A GitHub token that contains "test" in the character sequence
        token_with_test = "ghp_" + "test" + _MIXED[:32]  # 4 + 36 = 40 chars total
        (tmp_path / "config.py").write_text(
            f'token="{token_with_test}"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        # Original token must not appear in snippet
        assert token_with_test not in r001[0].snippet_masked

    def test_all_private_key_types_covered(self):
        """Test 16: EC, PKCS8, DSA, and PGP private key markers are all detected."""
        rule = PrivateKeyRule()

        key_types = [
            ("EC", "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"),
            ("PKCS8", "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
            ("DSA", "-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----"),
            ("PGP", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"),
        ]

        for key_type, begin, end in key_types:
            lines = [
                begin,
                "MIIEowIBAAKCAQEA" + "D" * 400,
                end,
            ]
            findings = rule.scan_content(f"key_{key_type.lower()}.pem", lines)

            assert len(findings) == 1, f"Failed to detect {key_type} private key"
            f = findings[0]
            assert f.rule_id == "R005_PRIVATE_KEY"
            assert f.severity == Severity.CRITICAL
            assert f.is_blocking is True
            assert f.snippet_masked == "<PRIVATE_KEY_REDACTED>"
            assert f.line_start == 1
            assert f.line_end == 3


# ============================================================================
# --- Multi-finding and determinism tests (tests 17-18) ---
# ============================================================================

class TestMultiFindingAndDeterminism:
    """Verify multiple findings and deterministic scan order."""

    def test_multiple_issues_preserved_with_correct_lines(self, tmp_path):
        """Test 17: Multiple issues in the same file are all preserved with correct line numbers."""
        (tmp_path / "config.py").write_text(
            f'GITHUB_TOKEN = "{SYNTH_GITHUB_TOKEN}"\n'      # Line 1: R001
            f'AWS_KEY = "{SYNTH_AWS_KEY}"\n'                 # Line 2: R002
            'password = "real_secret_123"\n'                 # Line 3: R006
            'print("hello world")\n'                         # Line 4: no finding
            f'token2 = "{SYNTH_GITHUB_TOKEN}"\n',            # Line 5: R001
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # Check line numbers
        line_numbers = sorted(f.line_start for f in result.findings)
        assert 1 in line_numbers  # Line 1: GitHub token
        assert 2 in line_numbers  # Line 2: AWS key
        assert 5 in line_numbers  # Line 5: second GitHub token

        # Verify specific findings
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 2  # Two GitHub tokens on lines 1 and 5
        r001_lines = sorted(f.line_start for f in r001)
        assert r001_lines == [1, 5]

        r002 = [f for f in result.findings if f.rule_id == "R002_AWS_ACCESS_KEY"]
        assert len(r002) == 1
        assert r002[0].line_start == 2

    def test_consecutive_scans_produce_identical_order(self, tmp_path):
        """Test 18: Consecutive scans of the same directory produce identical finding order."""
        (tmp_path / "config.py").write_text(
            f'GITHUB_TOKEN = "{SYNTH_GITHUB_TOKEN}"\n'
            f'AWS_KEY = "{SYNTH_AWS_KEY}"\n'
            'password = "real_secret_123"\n'
            f'token2 = "{SYNTH_GITHUB_TOKEN}"\n',
            encoding="utf-8",
        )

        # Run scan 3 times
        results = [scan_directory(tmp_path) for _ in range(3)]

        # Convert each result to a tuple of (rule_id, file_path, line_start) for comparison
        signatures = []
        for r in results:
            sig = tuple(
                (f.rule_id, f.file_path, f.line_start, f.column_start)
                for f in r.findings
            )
            signatures.append(sig)

        # All three signatures must be identical
        assert signatures[0] == signatures[1]
        assert signatures[1] == signatures[2]


# ============================================================================
# --- .git and symlink tests (tests 19-20) ---
# ============================================================================

class TestGitAndSymlinkHandling:
    """Verify .git is ignored and symlinks are handled on Linux."""

    def test_git_directory_ignored(self, tmp_path):
        """Test 19: .git directory is ignored — Git history is NOT scanned."""
        # Create a .git directory with a file containing a secret
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        # Also create a normal file
        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        # .git should not be scanned
        assert result.total_files_scanned == 1  # only app.py

        # No findings should come from .git
        for f in result.findings:
            assert not f.file_path.startswith(".git/")
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked

    @pytest.mark.skipif(sys.platform == 'win32', reason='Symlinks require admin on Windows; must run on Linux')
    def test_symlinks_handled_on_linux(self, tmp_path):
        """Test 20: Symlink files and directories are properly handled on Linux.

        This test MUST run (not skip) on Linux. Symlink files and directories
        are skipped during scanning to prevent path traversal attacks.
        """
        # Create a real file with a token
        real_file = tmp_path / "real_config.py"
        real_file.write_text(f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8")

        # Create a symlink file pointing to the real file
        symlink_file = tmp_path / "symlink_config.py"
        os.symlink(str(real_file), str(symlink_file))

        # Create a real directory with a secret file
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "secret.py").write_text(
            f'key="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        # Create a symlink directory pointing to the real directory
        symlink_dir = tmp_path / "symlink_dir"
        os.symlink(str(real_dir), str(symlink_dir))

        result = scan_directory(tmp_path)

        # Symlink file should not be scanned
        all_paths = {f.file_path for f in result.findings}
        assert "symlink_config.py" not in all_paths

        # Symlink directory contents should not be scanned
        for path in all_paths:
            assert not path.startswith("symlink_dir/")

        # Real files should be scanned (findings from real_config.py and real_dir/secret.py)
        assert "real_config.py" in all_paths
        assert "real_dir/secret.py" in all_paths


# ============================================================================
# --- Env template high-confidence scanning tests (tests 21-23) ---
# ============================================================================

class TestEnvTemplateHighConfidenceScan:
    """Verify high-confidence rules still scan template env files."""

    def test_env_example_placeholders_only_no_finding(self, tmp_path):
        """Test 21: .env.example with only placeholders has ScanNotice, no Finding."""
        (tmp_path / ".env.example").write_text(
            "API_KEY=your_api_key_here\n"
            "DB_PASSWORD=your_password_here\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # ScanNotice present
        notices = [n for n in result.notices if ".env.example" in (n.file_path or "")]
        assert len(notices) >= 1

        # No security findings
        assert len(result.findings) == 0

    def test_env_example_with_github_token_produces_finding(self, tmp_path):
        """Test 22: .env.example with real GitHub token produces R001 Finding.

        High-confidence format rules (R001-R005) must still scan template
        files to catch real secrets accidentally committed to templates.
        """
        (tmp_path / ".env.example").write_text(
            f'GITHUB_TOKEN="{SYNTH_GITHUB_TOKEN}"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # ScanNotice still present
        notices = [n for n in result.notices if ".env.example" in (n.file_path or "")]
        assert len(notices) >= 1

        # R001 finding produced
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        assert r001[0].is_blocking is True
        assert str(r001[0].confidence) == "high" or r001[0].confidence.value == "high"
        # Original token must not appear in snippet
        assert SYNTH_GITHUB_TOKEN not in r001[0].snippet_masked

    def test_env_example_with_private_key_produces_finding(self, tmp_path):
        """Test 23: .env.example with private key marker produces R005 Finding."""
        (tmp_path / ".env.example").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA" + "D" * 400 + "\n"
            "-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # ScanNotice still present
        notices = [n for n in result.notices if ".env.example" in (n.file_path or "")]
        assert len(notices) >= 1

        # R005 finding produced
        r005 = [f for f in result.findings if f.rule_id == "R005_PRIVATE_KEY"]
        assert len(r005) == 1
        assert r005[0].is_blocking is True
        assert r005[0].snippet_masked == "<PRIVATE_KEY_REDACTED>"


# ============================================================================
# --- R011 tightened production env tests (tests 24-25) ---
# ============================================================================

class TestR011TightenedRules:
    """Verify R011 only blocks on sensitive variable names with real secrets."""

    def test_production_env_non_sensitive_config_not_blocking(self, tmp_path):
        """Test 24: Non-sensitive config values do not trigger blocking.

        APP_ENV, LOG_LEVEL, REGION, FEATURE_FLAG, API_HOST are common
        non-sensitive production config values. R011 must not block them.
        """
        (tmp_path / ".env.production").write_text(
            "APP_ENV=production\n"
            "LOG_LEVEL=info\n"
            "REGION=us-east-1\n"
            "FEATURE_FLAG=enabled\n"
            "API_HOST=api.internal\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # No blocking findings should be produced
        blocking_findings = [f for f in result.findings if f.is_blocking]
        assert len(blocking_findings) == 0

        # Specifically, no R011 findings at all
        r011 = [f for f in result.findings if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"]
        assert len(r011) == 0

    def test_production_env_sensitive_names_blocking(self, tmp_path):
        """Test 25: Sensitive variable names with real values trigger blocking.

        JWT_SECRET and CLIENT_SECRET with non-placeholder, non-env-reference
        values should produce R011 blocking findings.
        """
        (tmp_path / ".env.production").write_text(
            "JWT_SECRET=runtime_constructed_jwt_value_abc123\n"
            "CLIENT_SECRET=runtime_constructed_client_secret_xyz789\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # R011 should produce blocking findings
        r011 = [f for f in result.findings if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"]
        assert len(r011) == 2
        for f in r011:
            assert f.is_blocking is True

        # Verify descriptions use FIXED text — raw key names must NOT appear
        for f in r011:
            assert "JWT_SECRET" not in f.description
            assert "CLIENT_SECRET" not in f.description
            assert "JWT_SECRET" not in f.message
            assert "CLIENT_SECRET" not in f.message
            assert "hardcoded secret" in f.description


# ============================================================================
# --- Path containment function tests (tests 26-27) ---
# ============================================================================

class TestPathContainmentFunction:
    """Directly test the _is_path_inside_root function."""

    def test_path_inside_root_returns_true(self, tmp_path):
        """Test 26: File inside scan root returns (True, posix_path)."""
        from app.scanner.sensitive import _is_path_inside_root

        # Create a file inside tmp_path
        inner_file = tmp_path / "src" / "config.py"
        inner_file.parent.mkdir(parents=True)
        inner_file.write_text("print('hello')\n", encoding="utf-8")

        root_resolved = tmp_path.resolve()
        is_inside, posix_path = _is_path_inside_root(str(inner_file), root_resolved)

        assert is_inside is True
        assert posix_path is not None
        assert "\\" not in posix_path  # POSIX format
        assert posix_path == "src/config.py"

    @pytest.mark.skipif(sys.platform == 'win32', reason='Symlinks require admin on Windows; must run on Linux')
    def test_path_outside_root_returns_false(self, tmp_path):
        """Test 27: File resolving outside scan root returns (False, None).

        A symlink is created inside the scan root pointing to a file outside.
        The resolved path falls outside root_resolved, so the function
        must return (False, None).
        """
        from app.scanner.sensitive import _is_path_inside_root

        # Create a file OUTSIDE the scan root
        outside_dir = tmp_path.parent / "outside_test_dir_0127"
        outside_dir.mkdir(exist_ok=True)
        outside_file = outside_dir / "outside_config.py"
        outside_file.write_text("print('outside')\n", encoding="utf-8")

        try:
            # Create a symlink inside the scan root pointing outside
            symlink_inside = tmp_path / "link_to_outside.py"
            os.symlink(str(outside_file), str(symlink_inside))

            root_resolved = tmp_path.resolve()
            is_inside, posix_path = _is_path_inside_root(str(symlink_inside), root_resolved)

            # The symlink resolves outside the root
            assert is_inside is False
            assert posix_path is None
        finally:
            if outside_file.exists():
                outside_file.unlink()
            if outside_dir.exists():
                outside_dir.rmdir()


# ============================================================================
# --- Final review gap tests (tests 28+) ---
# ============================================================================

class TestQuotedValueMasking:
    """Tests for unified assignment value parser — quoted values with spaces."""

    def test_double_quoted_value_with_spaces(self, tmp_path):
        """password="alpha beta gamma" masks the ENTIRE value, not just alpha."""
        synth_pw = "alpha beta gamma"
        (tmp_path / "config.py").write_text(
            f'password="{synth_pw}"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r006 = [f for f in result.findings if f.rule_id == "R006_PASSWORD_ASSIGNMENT"]
        assert len(r006) == 1

        # No part of the original value may appear in any field
        for f in result.findings:
            for field in dataclasses.fields(f):
                val = getattr(f, field.name)
                if isinstance(val, str):
                    assert "alpha" not in val
                    assert "beta" not in val
                    assert "gamma" not in val

    def test_single_quoted_value_with_spaces(self, tmp_path):
        """token='abc def ghi' masks the ENTIRE value."""
        synth_val = "abc def ghi"
        (tmp_path / "config.py").write_text(
            f"token='{synth_val}'\n", encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # R007 should detect it
        r007 = [f for f in result.findings if f.rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"]
        assert len(r007) == 1

        # No part of the original value in any field
        for f in result.findings:
            for field in dataclasses.fields(f):
                val = getattr(f, field.name)
                if isinstance(val, str):
                    assert "abc" not in val
                    assert "def" not in val
                    assert "ghi" not in val

    def test_multiple_quoted_values_same_line(self, tmp_path):
        """Multiple quoted values with spaces on the same line are all masked."""
        line = 'password="alpha beta" token="gamma delta"'
        (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        # No part of any original value in any snippet or field
        forbidden = ["alpha", "beta", "gamma", "delta"]
        for f in result.findings:
            for field in dataclasses.fields(f):
                val = getattr(f, field.name)
                if isinstance(val, str):
                    for word in forbidden:
                        assert word not in val, f"'{word}' found in {field.name}"

    def test_quoted_value_not_in_repr_or_json(self, tmp_path):
        """Quoted value with spaces does not appear in repr or JSON."""
        synth_pw = "alpha beta gamma"
        (tmp_path / "config.py").write_text(
            f'password="{synth_pw}"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        for f in result.findings:
            assert "alpha" not in repr(f)
            assert "beta" not in repr(f)
            assert "gamma" not in repr(f)

        # JSON serialization
        findings_list = [
            {field.name: str(getattr(f, field.name)) for field in dataclasses.fields(f)}
            for f in result.findings
        ]
        json_str = json.dumps(findings_list)
        assert "alpha" not in json_str
        assert "beta" not in json_str
        assert "gamma" not in json_str


class TestR011CoexistenceWithSpecificRules:
    """Tests that R011 coexists with specific rules on different lines."""

    def test_github_token_and_jwt_secret_both_present(self, tmp_path):
        """File with GITHUB_TOKEN and JWT_SECRET must have BOTH R001 and R011."""
        (tmp_path / ".env.production").write_text(
            f'GITHUB_TOKEN={SYNTH_GITHUB_TOKEN}\n'
            'JWT_SECRET=runtime_constructed_secret_value\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # R001 must be present (from GITHUB_TOKEN line)
        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        assert r001[0].line_start == 1

        # R011 must be present (from JWT_SECRET line)
        r011 = [f for f in result.findings if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"]
        assert len(r011) == 1
        assert r011[0].line_start == 2

    def test_same_value_r001_suppresses_r011(self):
        """When R001 and R011 hit the SAME value on the same line, only R001 remains."""
        from app.scanner.rules import GitHubTokenRule, ProductionEnvWithSecretRule
        from app.scanner.sensitive import _deduplicate_findings

        lines = [f'GITHUB_TOKEN="{SYNTH_GITHUB_TOKEN}"']

        findings = []
        findings.extend(GitHubTokenRule().scan_content(".env.production", lines))
        findings.extend(ProductionEnvWithSecretRule().scan_content(".env.production", lines))

        # Before dedup, both R001 and R011 exist
        assert any(f.rule_id == "R001_GITHUB_TOKEN" for f in findings)
        assert any(f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET" for f in findings)

        deduped = _deduplicate_findings(findings)

        # After dedup, only R001 remains (same line, overlapping columns)
        r001 = [f for f in deduped if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1

        r011 = [f for f in deduped if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"]
        assert len(r011) == 0


class TestFindingContract:
    """Verify Finding has the required new fields and no raw secret fields."""

    def test_finding_has_new_fields(self, tmp_path):
        """Finding objects have category, secret_type, message, repair_template_key."""
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        assert len(result.findings) >= 1
        f = result.findings[0]

        # New fields must exist and be non-empty strings
        assert hasattr(f, "category")
        assert hasattr(f, "secret_type")
        assert hasattr(f, "message")
        assert hasattr(f, "repair_template_key")
        assert isinstance(f.category, str) and f.category
        assert isinstance(f.secret_type, str) and f.secret_type
        assert isinstance(f.message, str) and f.message
        assert isinstance(f.repair_template_key, str) and f.repair_template_key

    def test_finding_no_raw_secret_fields(self, tmp_path):
        """Finding must NOT have raw_value, raw_snippet, original_secret fields."""
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)
        f = result.findings[0]

        field_names = {field.name for field in dataclasses.fields(f)}
        forbidden_fields = {"raw_value", "raw_snippet", "original_secret"}
        assert forbidden_fields.isdisjoint(field_names)

    def test_all_rules_fill_new_fields(self):
        """Every rule that produces a Finding fills the new contract fields."""
        from app.scanner.rules import (
            AWSAccessKeyRule,
            AWSSecretKeyRule,
            ConnectionStringRule,
            EnvFilePresentRule,
            GenericTokenAssignmentRule,
            GitHubTokenRule,
            GoogleAPIKeyRule,
            PasswordAssignmentRule,
            PrivateKeyRule,
            ProductionEnvWithSecretRule,
        )
        from app.scanner.base import Confidence

        # Test data for each rule
        test_cases = [
            (GitHubTokenRule(), "scan_content", ["config.py", [f'TOKEN="{SYNTH_GITHUB_TOKEN}"']]),
            (AWSAccessKeyRule(), "scan_content", ["config.py", [f"KEY={SYNTH_AWS_KEY}"]]),
            (AWSSecretKeyRule(), "scan_content", ["config.py", [f"aws_secret_access_key={SYNTH_AWS_SECRET}"]]),
            (GoogleAPIKeyRule(), "scan_content", ["config.py", [f'KEY="AIza{_MIXED[:35]}"']]),
            (PrivateKeyRule(), "scan_content", ["key.pem", [
                "-----BEGIN RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEA" + "D"*400,
                "-----END RSA PRIVATE KEY-----",
            ]]),
            (PasswordAssignmentRule(), "scan_content", ["config.py", ['password="real_secret_123"']]),
            (GenericTokenAssignmentRule(), "scan_content", ["config.py", ['secret="my_api_secret_value"']]),
            (ConnectionStringRule(), "scan_content", ["config.py", ['URL="postgres://admin:s3cr3tpw@host:5432/db"']]),
            (EnvFilePresentRule(), "check_file", [".env", 100]),
        ]

        for rule, method_name, args in test_cases:
            method = getattr(rule, method_name)
            result = method(*args)
            if isinstance(result, list):
                findings = result
            else:
                findings = [result] if result else []

            assert len(findings) > 0, f"{rule.rule_id} produced no findings"
            for f in findings:
                assert f.category, f"{rule.rule_id} missing category"
                assert f.secret_type, f"{rule.rule_id} missing secret_type"
                assert f.message, f"{rule.rule_id} missing message"
                assert f.repair_template_key, f"{rule.rule_id} missing repair_template_key"

        # Test R011 separately (needs production env file)
        r011_rule = ProductionEnvWithSecretRule()
        r011_findings = r011_rule.scan_content(
            ".env.production", ["JWT_SECRET=runtime_constructed_value"]
        )
        assert len(r011_findings) > 0
        for f in r011_findings:
            assert f.category
            assert f.secret_type
            assert f.message
            assert f.repair_template_key


class TestAdjacentPrivateKeys:
    """Tests for adjacent private key blocks — loop index fix."""

    def test_two_adjacent_rsa_keys(self):
        """Two adjacent RSA private key blocks are both detected with correct lines."""
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",   # line 1
            "MIIEowIBAAKCAQEA" + "D" * 400,       # line 2
            "-----END RSA PRIVATE KEY-----",       # line 3
            "-----BEGIN RSA PRIVATE KEY-----",     # line 4
            "MIIEowIBAAKCAQEA" + "E" * 400,        # line 5
            "-----END RSA PRIVATE KEY-----",        # line 6
        ]

        findings = rule.scan_content("keys.pem", lines)

        assert len(findings) == 2
        # First key: lines 1-3
        assert findings[0].line_start == 1
        assert findings[0].line_end == 3
        # Second key: lines 4-6
        assert findings[1].line_start == 4
        assert findings[1].line_end == 6

    def test_adjacent_different_key_types(self):
        """Adjacent RSA and OPENSSH keys are both detected."""
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",           # line 1
            "MIIEowIBAAKCAQEA" + "D" * 400,               # line 2
            "-----END RSA PRIVATE KEY-----",               # line 3
            "-----BEGIN OPENSSH PRIVATE KEY-----",         # line 4
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA",          # line 5
            "-----END OPENSSH PRIVATE KEY-----",            # line 6
        ]

        findings = rule.scan_content("keys.pem", lines)

        assert len(findings) == 2
        assert findings[0].line_start == 1
        assert findings[0].line_end == 3
        assert findings[1].line_start == 4
        assert findings[1].line_end == 6


class TestConnectionStringPasswordExtraction:
    """Tests for accurate connection string password extraction (R008)."""

    def test_placeholder_password_low_severity(self, tmp_path):
        """postgres://user:changeme@host/db produces low/non-blocking R008."""
        (tmp_path / "config.py").write_text(
            'DATABASE_URL="postgres://admin:changeme@db.example.com:5432/mydb"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # R008 SHOULD fire with low severity for placeholder passwords
        r008 = [f for f in result.findings if f.rule_id == "R008_CONNECTION_STRING"]
        assert len(r008) == 1
        f = r008[0]
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False
        # Password must not appear in snippet
        assert "changeme" not in f.snippet_masked

    def test_real_password_produces_r008(self, tmp_path):
        """postgres://user:real_password@host/db produces R008."""
        synth_pw = "SynthR3alPassw0rd2024"
        (tmp_path / "config.py").write_text(
            f'DATABASE_URL="postgres://admin:{synth_pw}@db.example.com:5432/mydb"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r008 = [f for f in result.findings if f.rule_id == "R008_CONNECTION_STRING"]
        assert len(r008) == 1
        assert r008[0].is_blocking is False  # R008 is non-blocking

    def test_password_fully_replaced_in_snippet(self, tmp_path):
        """Snippet has password fully replaced with ***."""
        synth_pw = "SynthR3alPassw0rd2024"
        (tmp_path / "config.py").write_text(
            f'DATABASE_URL="postgres://admin:{synth_pw}@db.example.com:5432/mydb"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r008 = [f for f in result.findings if f.rule_id == "R008_CONNECTION_STRING"]
        assert len(r008) == 1

        snippet = r008[0].snippet_masked
        assert synth_pw not in snippet
        assert "***" in snippet


class TestCrossPlatformPathContainment:
    """True cross-platform path containment test — no symlinks, no skipif."""

    def test_inside_and_outside_without_symlinks(self, tmp_path):
        """Directly test _is_path_inside_root for inside and outside files.

        Creates root/inside.txt and root-level outside.txt (sibling of root).
        Runs on BOTH Windows and Linux — no symlinks, no skipif.
        """
        from app.scanner.sensitive import _is_path_inside_root

        # Create root directory
        root = tmp_path / "root"
        root.mkdir()

        # Create inside.txt inside root
        inside_file = root / "inside.txt"
        inside_file.write_text("inside\n", encoding="utf-8")

        # Create outside.txt as a SIBLING of root (not inside root)
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("outside\n", encoding="utf-8")

        root_resolved = root.resolve()

        # inside.txt must return (True, "inside.txt")
        is_inside, posix_path = _is_path_inside_root(str(inside_file), root_resolved)
        assert is_inside is True
        assert posix_path == "inside.txt"

        # outside.txt must return (False, None)
        is_inside, posix_path = _is_path_inside_root(str(outside_file), root_resolved)
        assert is_inside is False
        assert posix_path is None


class TestStableSorting:
    """Tests for deterministic scan result ordering."""

    def test_different_creation_order_same_result(self, tmp_path):
        """Files created in different order produce the same finding order."""
        from app.scanner.sensitive import scan_directory

        # Create directory A with files in one order
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        (dir_a / "z_file.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        (dir_a / "a_file.py").write_text(
            f'password="secret_value_123"\n', encoding="utf-8",
        )
        (dir_a / "m_file.py").write_text(
            f'AWS_KEY="{SYNTH_AWS_KEY}"\n', encoding="utf-8",
        )

        # Create directory B with files in reverse order
        dir_b = tmp_path / "dir_b"
        dir_b.mkdir()
        (dir_b / "m_file.py").write_text(
            f'AWS_KEY="{SYNTH_AWS_KEY}"\n', encoding="utf-8",
        )
        (dir_b / "a_file.py").write_text(
            f'password="secret_value_123"\n', encoding="utf-8",
        )
        (dir_b / "z_file.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )

        result_a = scan_directory(dir_a)
        result_b = scan_directory(dir_b)

        # Both should have the same number of findings
        assert len(result_a.findings) == len(result_b.findings)

        # The ORDER must be identical (sorted by file_path, line_start, etc.)
        sig_a = tuple(
            (f.rule_id, f.file_path, f.line_start, f.column_start)
            for f in result_a.findings
        )
        sig_b = tuple(
            (f.rule_id, f.file_path, f.line_start, f.column_start)
            for f in result_b.findings
        )
        assert sig_a == sig_b

        # Verify the order is by file_path first
        file_paths = [f.file_path for f in result_a.findings]
        assert file_paths == sorted(file_paths)


class TestRuleSemantics:
    """Tests for corrected rule confidence and blocking semantics."""

    def test_r003_high_confidence_blocking(self):
        """R003 (AWS Secret Key) is high confidence and blocking after strict context match."""
        from app.scanner.rules import AWSSecretKeyRule
        from app.scanner.base import Confidence

        rule = AWSSecretKeyRule()
        lines = [f"aws_secret_access_key={SYNTH_AWS_SECRET}"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == Confidence.HIGH
        assert f.is_blocking is True

    def test_r011_high_confidence_blocking(self, tmp_path):
        """R011 is high confidence and blocking after production file + sensitive name + non-placeholder."""
        from app.scanner.base import Confidence

        (tmp_path / ".env.production").write_text(
            "JWT_SECRET=runtime_constructed_secret_value\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r011 = [f for f in result.findings if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"]
        assert len(r011) == 1
        assert r011[0].confidence == Confidence.HIGH
        assert r011[0].is_blocking is True

    def test_r006_r008_medium_confidence_non_blocking(self):
        """R006-R008 remain medium confidence and non-blocking."""
        from app.scanner.rules import (
            PasswordAssignmentRule,
            GenericTokenAssignmentRule,
            ConnectionStringRule,
        )
        from app.scanner.base import Confidence

        # R006
        r006 = PasswordAssignmentRule()
        r006_findings = r006.scan_content("config.py", ['password="real_secret_123"'])
        assert len(r006_findings) == 1
        assert r006_findings[0].confidence == Confidence.MEDIUM
        assert r006_findings[0].is_blocking is False

        # R007
        r007 = GenericTokenAssignmentRule()
        r007_findings = r007.scan_content("config.py", ['secret="my_api_secret_value"'])
        assert len(r007_findings) == 1
        assert r007_findings[0].confidence == Confidence.MEDIUM
        assert r007_findings[0].is_blocking is False

        # R008
        r008 = ConnectionStringRule()
        r008_findings = r008.scan_content("config.py", ['URL="postgres://admin:s3cr3tpw@host:5432/db"'])
        assert len(r008_findings) == 1
        assert r008_findings[0].confidence == Confidence.MEDIUM
        assert r008_findings[0].is_blocking is False

    def test_false_positive_variable_names_no_r011(self, tmp_path):
        """SECRETARY_EMAIL, TOKENIZER_MODEL, PASSWORDLESS_MODE do NOT trigger R011."""
        (tmp_path / ".env.production").write_text(
            "SECRETARY_EMAIL=secretary@example.com\n"
            "TOKENIZER_MODEL=gpt2-large\n"
            "PASSWORDLESS_MODE=enabled\n",
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r011 = [f for f in result.findings if f.rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"]
        assert len(r011) == 0


# ============================================================================
# --- Masking escape regression tests (10 tests) ---
# ============================================================================

class TestMaskingEscapeRegression:
    """10 regression tests for masking escape prevention.

    Each test verifies a specific escape vector is closed:
    1. mask indicator substring (..., ***) does not bypass masking
    2. os./process.env approximate strings do not bypass masking
    3. unquoted # value does not leak suffix
    4. JSON double-quoted key is recognized
    5. TOML single/double-quoted key is recognized
    6. $-prefixed real password is recognized (not treated as env ref)
    7. genuine environment variable reference does not false-positive
    8. same-line second secret is fully masked
    9. repeated-character format placeholder is non-blocking
    10. mixed-character explicit format value is still blocking
    """

    def test_mask_indicator_substring_no_escape(self, tmp_path):
        """Regression 1: password='alpha...omega' and 'abc***def' produce Findings.
        The ... and *** substrings must NOT be treated as already-masked indicators.
        Both snippets, repr, and JSON must not contain the original values.
        """
        (tmp_path / "config.py").write_text(
            'password="alpha...omega"\n'
            'password="abc***def"\n',
            encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        # Must produce Findings
        r006 = [f for f in result.findings if f.rule_id == "R006_PASSWORD_ASSIGNMENT"]
        assert len(r006) >= 2

        for f in r006:
            # Snippet must not contain original values
            assert "alpha" not in f.snippet_masked
            assert "omega" not in f.snippet_masked
            assert "abc" not in f.snippet_masked
            assert "def" not in f.snippet_masked
            # repr must not contain original values
            assert "alpha" not in repr(f)
            assert "omega" not in repr(f)
            assert "abc" not in repr(f)
            assert "def" not in repr(f)

        # JSON serialization must not contain original values
        import json as _json
        findings_json = _json.dumps([
            {field.name: str(getattr(f, field.name)) for field in dataclasses.fields(f)}
            for f in r006
        ])
        assert "alpha" not in findings_json
        assert "omega" not in findings_json
        assert "abc" not in findings_json
        assert "def" not in findings_json

    def test_os_process_env_approximate_no_escape(self, tmp_path):
        """Regression 2: os.supersecret and process.environmentSecret are masked.

        These are NOT valid env references and must NOT bypass masking.
        """
        (tmp_path / "config.py").write_text(
            'password="os.supersecret"\n'
            'password="process.environmentSecret"\n',
            encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        r006 = [f for f in result.findings if f.rule_id == "R006_PASSWORD_ASSIGNMENT"]
        assert len(r006) >= 2

        for f in r006:
            assert "os.supersecret" not in f.snippet_masked
            assert "supersecret" not in f.snippet_masked
            assert "process.environmentSecret" not in f.snippet_masked
            assert "environmentSecret" not in f.snippet_masked

    def test_unquoted_hash_no_suffix_leak(self, tmp_path):
        """Regression 3: password=alpha#omega -- snippet has no alpha or omega."""
        (tmp_path / "config.py").write_text(
            "password=alpha#omega\n"
            "token=abc#def\n",
            encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        all_findings = [f for f in result.findings if f.rule_id in (
            "R006_PASSWORD_ASSIGNMENT", "R007_GENERIC_TOKEN_ASSIGNMENT"
        )]
        assert len(all_findings) >= 2

        for f in all_findings:
            assert "alpha" not in f.snippet_masked
            assert "omega" not in f.snippet_masked
            assert "abc" not in f.snippet_masked
            assert "def" not in f.snippet_masked

    def test_json_double_quoted_key_recognized(self, tmp_path):
        """Regression 4: "password": "alpha beta gamma" produces R006."""
        (tmp_path / "config.json").write_text(
            '"password": "alpha beta gamma"\n',
            encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        r006 = [f for f in result.findings if f.rule_id == "R006_PASSWORD_ASSIGNMENT"]
        assert len(r006) == 1
        f = r006[0]
        # Column range points to full value
        line = '"password": "alpha beta gamma"'
        value_at_range = line[f.column_start:f.column_end]
        assert value_at_range == "alpha beta gamma"
        # Snippet fully masked
        assert "alpha" not in f.snippet_masked
        assert "beta" not in f.snippet_masked
        assert "gamma" not in f.snippet_masked

    def test_toml_quoted_key_recognized(self, tmp_path):
        """Regression 5: 'token': 'abc def ghi' and "api_key" = "value" produce findings."""
        (tmp_path / "config.toml").write_text(
            "'token': 'abc def ghi'\n"
            '"api_key" = "some value"\n',
            encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        r007 = [f for f in result.findings if f.rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"]
        assert len(r007) >= 2

        for f in r007:
            assert "abc" not in f.snippet_masked
            assert "def" not in f.snippet_masked
            assert "ghi" not in f.snippet_masked
            assert "some value" not in f.snippet_masked

    def test_dollar_prefixed_real_password_detected(self, tmp_path):
        """Regression 6: password='$uperSecret123' (lowercase $u) is detected as real secret."""
        (tmp_path / "config.py").write_text(
            'password = "$uperSecret123"\n'
            'password = "\\${LITERAL_VALUE}"\n',
            encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        r006 = [f for f in result.findings if f.rule_id == "R006_PASSWORD_ASSIGNMENT"]
        assert len(r006) >= 2

        for f in r006:
            assert "$uperSecret123" not in f.snippet_masked
            assert "LITERAL_VALUE" not in f.snippet_masked

    def test_genuine_env_reference_no_false_positive(self, tmp_path):
        """Regression 7: $VAR, ${VAR}, process.env.NAME, os.getenv('NAME') are NOT secrets."""
        (tmp_path / "config.py").write_text(
            "password = $DB_PASSWORD\n"
            "password = ${DB_PASSWORD}\n"
            "password = ${DB_PASSWORD:-default}\n"
            "password = process.env.DB_PASSWORD\n"
            'password = os.getenv("DB_PASSWORD")\n',
            encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        r006 = [f for f in result.findings if f.rule_id == "R006_PASSWORD_ASSIGNMENT"]
        assert len(r006) == 0

    def test_same_line_second_secret_fully_masked(self, tmp_path):
        """Regression 8: token='<format>' password='os.supersecret' -- both masked."""
        line = f'token="{SYNTH_GITHUB_TOKEN}" password="os.supersecret"'
        (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")
        result = scan_directory(tmp_path)

        # All findings on line 1
        line1_findings = [f for f in result.findings if f.line_start == 1]
        assert len(line1_findings) >= 1

        for f in line1_findings:
            # Neither secret should appear in snippet
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
            assert "os.supersecret" not in f.snippet_masked
            assert "supersecret" not in f.snippet_masked

    def test_repeated_char_placeholder_non_blocking(self, tmp_path):
        """Regression 9: ghp_+X*36 (all same char) is downgraded to non-blocking."""
        low_entropy_token = "ghp_" + "X" * 36
        (tmp_path / "config.py").write_text(
            f'token="{low_entropy_token}"\n', encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        f = r001[0]
        assert f.is_blocking is False
        assert f.severity == Severity.LOW
        # Original token must not appear in snippet
        assert low_entropy_token not in f.snippet_masked

    def test_mixed_char_format_value_still_blocking(self, tmp_path):
        """Regression 10: mixed-character GitHub token is still critical/blocking."""
        (tmp_path / "config.py").write_text(
            f'token="{SYNTH_GITHUB_TOKEN}"\n', encoding="utf-8",
        )
        result = scan_directory(tmp_path)

        r001 = [f for f in result.findings if f.rule_id == "R001_GITHUB_TOKEN"]
        assert len(r001) == 1
        f = r001[0]
        assert f.is_blocking is True
        assert f.severity == Severity.CRITICAL
        assert SYNTH_GITHUB_TOKEN not in f.snippet_masked


# ============================================================================
# --- R011 Finding field leakage tests (1 test) ---
# ============================================================================

class TestR011FindingFieldLeakage:
    """Verify R011 Finding never leaks the raw key or token in any field.

    Constructs a variable name that embeds a format-correct synthetic
    GitHub token (PASSWORD_<token>), writes it to .env.production,
    then checks ALL Finding fields (description, message, snippet_masked,
    repr, asdict JSON) for the complete token.
    """

    def test_password_token_variable_no_leak(self, tmp_path):
        """PASSWORD_<synthetic_token> in .env.production — no field leaks the token."""
        # Construct variable name: PASSWORD_<synthetic GitHub token>
        synth_var = f"PASSWORD_{SYNTH_GITHUB_TOKEN}"
        (tmp_path / ".env.production").write_text(
            f'{synth_var}=some_hardcoded_value\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # Collect ALL findings (R011 and any others)
        all_findings = list(result.findings)
        assert len(all_findings) > 0

        # Check every finding's fields
        for f in all_findings:
            # description must not contain the full token
            assert SYNTH_GITHUB_TOKEN not in f.description, (
                f"Token leaked in description: {f.rule_id}"
            )
            # message must not contain the full token
            assert SYNTH_GITHUB_TOKEN not in f.message, (
                f"Token leaked in message: {f.rule_id}"
            )
            # snippet_masked must not contain the full token
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked, (
                f"Token leaked in snippet_masked: {f.rule_id}"
            )
            # repr must not contain the full token
            assert SYNTH_GITHUB_TOKEN not in repr(f), (
                f"Token leaked in repr: {f.rule_id}"
            )
            # asdict JSON must not contain the full token
            f_dict = dataclasses.asdict(f)
            f_json = json.dumps(f_dict, default=str)
            assert SYNTH_GITHUB_TOKEN not in f_json, (
                f"Token leaked in asdict JSON: {f.rule_id}"
            )


# ============================================================================
# --- R008 weak password fallback tests (2 tests) ---
# ============================================================================

class TestR008WeakPasswordFallback:
    """Verify R008 generates low/non-blocking findings for weak passwords.

    Weak passwords like foobar, secret, changeme in connection strings
    must still produce R008 Findings (not disappear), but with
    low severity / low confidence / non-blocking.
    """

    def test_foobar_password_low_severity(self, tmp_path):
        """postgres://user:foobar@host/db produces low/non-blocking R008."""
        (tmp_path / "config.py").write_text(
            'DATABASE_URL="postgres://admin:foobar@db.example.com:5432/mydb"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r008 = [f for f in result.findings if f.rule_id == "R008_CONNECTION_STRING"]
        assert len(r008) == 1
        f = r008[0]
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False
        # Password must not appear in snippet
        assert "foobar" not in f.snippet_masked

    def test_secret_password_low_severity(self, tmp_path):
        """postgres://user:secret@host/db produces low/non-blocking R008."""
        (tmp_path / "config.py").write_text(
            'DATABASE_URL="postgres://admin:secret@db.example.com:5432/mydb"\n',
            encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        r008 = [f for f in result.findings if f.rule_id == "R008_CONNECTION_STRING"]
        assert len(r008) == 1
        f = r008[0]
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False
        # Password must not appear in snippet
        assert "secret" not in f.snippet_masked


# ============================================================================
# --- Path sanitization tests (6 tests) ---
# ============================================================================

class TestPathSanitization:
    """Verify file_path in all result objects is sanitized via mask_untrusted_text.

    File names and directory names are untrusted input — they may embed
    format-correct secrets. All result objects (Finding, ScanNotice,
    SkippedFile, ScanError) must use sanitized paths. Checks file_path,
    repr, and dataclasses.asdict JSON for all result objects.
    """

    def test_filename_with_github_token_sanitized(self, tmp_path):
        """Filename containing a synthetic GitHub token is sanitized in findings."""
        filename = f"{SYNTH_GITHUB_TOKEN}.py"
        (tmp_path / filename).write_text(
            'password = "some_value"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # Check ALL findings
        for f in result.findings:
            assert SYNTH_GITHUB_TOKEN not in f.file_path
            assert SYNTH_GITHUB_TOKEN not in repr(f)
            f_dict = dataclasses.asdict(f)
            assert SYNTH_GITHUB_TOKEN not in json.dumps(f_dict, default=str)

        # Check ALL skipped files
        for s in result.skipped_files:
            assert SYNTH_GITHUB_TOKEN not in s.file_path
            assert SYNTH_GITHUB_TOKEN not in repr(s)
            s_dict = dataclasses.asdict(s)
            assert SYNTH_GITHUB_TOKEN not in json.dumps(s_dict, default=str)

        # Check ALL errors
        for e in result.scan_errors:
            assert SYNTH_GITHUB_TOKEN not in e.file_path
            assert SYNTH_GITHUB_TOKEN not in repr(e)
            e_dict = dataclasses.asdict(e)
            assert SYNTH_GITHUB_TOKEN not in json.dumps(e_dict, default=str)

    def test_directory_with_aws_key_sanitized(self, tmp_path):
        """Directory name containing a synthetic AWS key is sanitized."""
        dir_name = SYNTH_AWS_KEY
        secret_dir = tmp_path / dir_name
        secret_dir.mkdir()
        (secret_dir / "config.py").write_text(
            'password = "some_value"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        for f in result.findings:
            assert SYNTH_AWS_KEY not in f.file_path
            assert SYNTH_AWS_KEY not in repr(f)
            f_dict = dataclasses.asdict(f)
            assert SYNTH_AWS_KEY not in json.dumps(f_dict, default=str)

    def test_large_file_skip_path_sanitized(self, tmp_path, monkeypatch):
        """Large file with token in filename — skipped path is sanitized."""
        from app.core.config import settings
        monkeypatch.setattr(settings, "scan_max_file_size", 50)

        filename = f"{SYNTH_GITHUB_TOKEN}.txt"
        (tmp_path / filename).write_text("x" * 100, encoding="utf-8")

        result = scan_directory(tmp_path)

        for s in result.skipped_files:
            assert SYNTH_GITHUB_TOKEN not in s.file_path
            assert SYNTH_GITHUB_TOKEN not in repr(s)
            s_dict = dataclasses.asdict(s)
            assert SYNTH_GITHUB_TOKEN not in json.dumps(s_dict, default=str)

    def test_binary_file_skip_path_sanitized(self, tmp_path):
        """Binary file with token in filename — skipped path is sanitized."""
        filename = f"{SYNTH_GITHUB_TOKEN}.png"
        (tmp_path / filename).write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        result = scan_directory(tmp_path)

        for s in result.skipped_files:
            assert SYNTH_GITHUB_TOKEN not in s.file_path
            assert SYNTH_GITHUB_TOKEN not in repr(s)
            s_dict = dataclasses.asdict(s)
            assert SYNTH_GITHUB_TOKEN not in json.dumps(s_dict, default=str)

    def test_read_error_path_sanitized(self, tmp_path, monkeypatch):
        """Read error file with token in filename — error path is sanitized."""
        filename = f"{SYNTH_GITHUB_TOKEN}.py"
        (tmp_path / filename).write_text("print('hello')\n", encoding="utf-8")

        original_open = builtins.open

        def failing_open(file, *args, **kwargs):
            if "rb" in str(args) and SYNTH_GITHUB_TOKEN in str(file):
                raise OSError("Permission denied")
            return original_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", failing_open)

        result = scan_directory(tmp_path)

        for e in result.scan_errors:
            assert SYNTH_GITHUB_TOKEN not in e.file_path
            assert SYNTH_GITHUB_TOKEN not in repr(e)
            assert SYNTH_GITHUB_TOKEN not in e.error_message
            e_dict = dataclasses.asdict(e)
            assert SYNTH_GITHUB_TOKEN not in json.dumps(e_dict, default=str)

    def test_plain_path_preserved(self, tmp_path):
        """Plain file path (no secrets) is preserved as relative POSIX path."""
        nested = tmp_path / "src" / "config"
        nested.mkdir(parents=True)
        (nested / "settings.py").write_text(
            'password = "some_value"\n', encoding="utf-8",
        )

        result = scan_directory(tmp_path)

        # The path should be preserved as-is (relative POSIX)
        for f in result.findings:
            assert f.file_path == "src/config/settings.py"


# ============================================================================
# --- Overlapping masking range leakage tests (4 tests) ---
# ============================================================================

class TestOverlappingMaskingLeakage:
    """Verify tokens embedded inside connection strings are fully masked.

    The old _apply_ranges merged overlapping ranges by keeping the outer
    connection string's masked_value, which only masked the password —
    leaving tokens in username/host/path visible. The phased approach
    (tokens first, then connection strings) fixes this.
    """

    def test_token_in_connection_string_username_masked(self):
        """Token in connection string username is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        conn = f"postgres://{SYNTH_GITHUB_TOKEN}:pass@host/db"
        result = mask_untrusted_text(conn)
        assert SYNTH_GITHUB_TOKEN not in result
        assert "pass" not in result or "***" in result

    def test_token_in_connection_string_snippet_masked(self, tmp_path):
        """Token in connection string in a file is masked in snippet_masked."""
        conn = f'DATABASE_URL="postgres://{SYNTH_GITHUB_TOKEN}:pass@host/db"'
        (tmp_path / "config.py").write_text(conn + "\n", encoding="utf-8")

        result = scan_directory(tmp_path)

        r008 = [f for f in result.findings if f.rule_id == "R008_CONNECTION_STRING"]
        assert len(r008) == 1
        # Neither the token nor the password should appear in snippet
        assert SYNTH_GITHUB_TOKEN not in r008[0].snippet_masked
        assert "pass" not in r008[0].snippet_masked or "pass" not in r008[0].snippet_masked.replace("***", "")
        # repr and JSON must also be safe
        assert SYNTH_GITHUB_TOKEN not in repr(r008[0])
        f_json = json.dumps(dataclasses.asdict(r008[0]), default=str)
        assert SYNTH_GITHUB_TOKEN not in f_json

    def test_token_in_connection_string_host_masked(self):
        """Token in connection string host is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        conn = f"postgres://user:pass@{SYNTH_AWS_KEY}/db"
        result = mask_untrusted_text(conn)
        assert SYNTH_AWS_KEY not in result

    def test_token_in_connection_string_password_masked(self):
        """Token in connection string password is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        conn = f"postgres://user:{SYNTH_GITHUB_TOKEN}@host/db"
        result = mask_untrusted_text(conn)
        assert SYNTH_GITHUB_TOKEN not in result

    def test_mask_snippet_token_in_conn_string(self):
        """mask_snippet masks tokens inside connection strings."""
        from app.core.security.desensitize import mask_snippet
        line = f'DATABASE_URL="postgres://{SYNTH_GITHUB_TOKEN}:pass@host/db"'
        result = mask_snippet(line)
        assert SYNTH_GITHUB_TOKEN not in result
        assert "pass" not in result or "***" in result

    def test_aws_token_in_connection_string_masked(self):
        """AWS token in connection string username is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        conn = f"redis://{SYNTH_AWS_KEY}:secret@host:6379"
        result = mask_untrusted_text(conn)
        assert SYNTH_AWS_KEY not in result


# ============================================================================
# --- Result model file_path self-guarantee tests (5 tests) ---
# ============================================================================

class TestResultModelFilePathSelfGuarantee:
    """Verify result models sanitize file_path in __post_init__.

    Even when rules are called directly (not through scan_directory),
    file_path must never contain a raw explicit-format secret.
    """

    def test_finding_direct_construction_sanitizes_path(self):
        """Finding constructed directly sanitizes file_path."""
        from app.scanner.base import Finding, FindingType, Severity, Confidence
        f = Finding(
            rule_id="R001_GITHUB_TOKEN",
            rule_name="GitHub Token",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path=f"src/{SYNTH_GITHUB_TOKEN}.py",
            line_start=1,
            line_end=1,
            column_start=0,
            column_end=10,
            snippet_masked="<REDACTED>",
            is_blocking=True,
            finding_type=FindingType.CONTENT,
            description="test",
            category="token",
            secret_type="github_token",
            message="test",
            repair_template_key="rotate",
        )
        assert SYNTH_GITHUB_TOKEN not in f.file_path
        assert SYNTH_GITHUB_TOKEN not in repr(f)
        f_json = json.dumps(dataclasses.asdict(f), default=str)
        assert SYNTH_GITHUB_TOKEN not in f_json

    def test_scan_notice_direct_construction_sanitizes_path(self):
        """ScanNotice constructed directly sanitizes file_path."""
        from app.scanner.base import ScanNotice
        n = ScanNotice(
            rule_id="R010",
            message="test",
            file_path=f"dir/{SYNTH_AWS_KEY}/file",
        )
        assert SYNTH_AWS_KEY not in n.file_path
        assert SYNTH_AWS_KEY not in repr(n)
        n_json = json.dumps(dataclasses.asdict(n), default=str)
        assert SYNTH_AWS_KEY not in n_json

    def test_skipped_file_direct_construction_sanitizes_path(self):
        """SkippedFile constructed directly sanitizes file_path."""
        from app.scanner.base import SkippedFile
        s = SkippedFile(
            file_path=f"{SYNTH_GITHUB_TOKEN}.png",
            reason="binary",
        )
        assert SYNTH_GITHUB_TOKEN not in s.file_path
        assert SYNTH_GITHUB_TOKEN not in repr(s)
        s_json = json.dumps(dataclasses.asdict(s), default=str)
        assert SYNTH_GITHUB_TOKEN not in s_json

    def test_scan_error_direct_construction_sanitizes_path(self):
        """ScanError constructed directly sanitizes file_path."""
        from app.scanner.base import ScanError
        e = ScanError(
            file_path=f"{SYNTH_AWS_KEY}.py",
            error_type="read_error",
            error_message="Unable to read file content",
        )
        assert SYNTH_AWS_KEY not in e.file_path
        assert SYNTH_AWS_KEY not in repr(e)
        e_json = json.dumps(dataclasses.asdict(e), default=str)
        assert SYNTH_AWS_KEY not in e_json

    def test_direct_rule_call_sanitizes_path(self):
        """Directly calling GitHubTokenRule.scan_content sanitizes file_path."""
        from app.scanner.rules import GitHubTokenRule
        rule = GitHubTokenRule()
        findings = rule.scan_content(
            f"src/{SYNTH_GITHUB_TOKEN}.py",
            [f'token = "{SYNTH_GITHUB_TOKEN}"'],
        )
        assert len(findings) >= 1
        for f in findings:
            assert SYNTH_GITHUB_TOKEN not in f.file_path
            assert SYNTH_GITHUB_TOKEN not in repr(f)
            f_json = json.dumps(dataclasses.asdict(f), default=str)
            assert SYNTH_GITHUB_TOKEN not in f_json

    def test_direct_env_example_rule_call_sanitizes_path(self):
        """Directly calling EnvExampleFileRule.check_file sanitizes path."""
        from app.scanner.rules import EnvExampleFileRule
        from app.scanner.base import ScanNotice
        rule = EnvExampleFileRule()
        # Parent directory contains a token
        result = rule.check_file(f"dir/{SYNTH_GITHUB_TOKEN}/.env.example", 100)
        assert result is not None
        assert isinstance(result, ScanNotice)
        assert SYNTH_GITHUB_TOKEN not in result.file_path
        assert SYNTH_GITHUB_TOKEN not in repr(result)

    def test_plain_path_unchanged_in_direct_construction(self):
        """Plain path (no secrets) is unchanged in direct construction."""
        from app.scanner.base import SkippedFile
        s = SkippedFile(file_path="src/config/settings.py", reason="binary")
        assert s.file_path == "src/config/settings.py"


# ============================================================================
# --- Incomplete private key Finding count tests (3 tests) ---
# ============================================================================

class TestIncompletePrivateKeyCount:
    """Verify incomplete private key blocks produce at most 1 Finding.

    - Many consecutive BEGINs without END: at most 1 incomplete Finding.
    - Two consecutive complete keys: 2 Findings.
    - 10000 consecutive BEGINs: O(n), at most 1 Finding, blocking.
    """

    def test_many_begins_produce_one_finding(self):
        """500 consecutive BEGINs without END produce exactly 1 Finding."""
        from app.scanner.rules import PrivateKeyRule
        rule = PrivateKeyRule()
        lines = ["-----BEGIN RSA PRIVATE KEY-----"] * 500
        findings = rule.scan_content("many_begins.pem", lines)
        assert len(findings) == 1
        assert findings[0].is_blocking is True
        assert findings[0].snippet_masked == "<PRIVATE_KEY_REDACTED>"
        assert "Incomplete" in findings[0].description

    def test_two_complete_keys_still_two_findings(self):
        """Two consecutive complete private keys produce two Findings."""
        from app.scanner.rules import PrivateKeyRule
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEA" + "D" * 400,
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "MHcCAQEE" + "E" * 100,
            "-----END EC PRIVATE KEY-----",
        ]
        findings = rule.scan_content("two_keys.pem", lines)
        assert len(findings) == 2
        for f in findings:
            assert f.is_blocking is True
            assert "Incomplete" not in f.description

    def test_10000_begins_linear_one_finding(self):
        """10000 consecutive BEGINs: O(n), at most 1 Finding, blocking."""
        import time
        from app.scanner.rules import PrivateKeyRule
        rule = PrivateKeyRule()
        n = 10000
        lines = ["-----BEGIN RSA PRIVATE KEY-----"] * n
        start = time.monotonic()
        findings = rule.scan_content("huge.pem", lines)
        elapsed = time.monotonic() - start
        # At most 1 incomplete Finding
        assert len(findings) == 1
        assert findings[0].is_blocking is True
        assert findings[0].snippet_masked == "<PRIVATE_KEY_REDACTED>"
        # No private key body in any field
        for f in findings:
            f_json = json.dumps(dataclasses.asdict(f), default=str)
            assert "MIIEowIBAAKCAQEA" not in f_json
        # Should complete quickly (O(n), not O(n²))
        # 10000 lines should take well under 5 seconds
        assert elapsed < 5.0, f"Scan took {elapsed:.2f}s for {n} lines"

    def test_begin_begin_end_keeps_first_begin(self):
        """BEGIN/BEGIN/END produces ONE Finding from line 1 to line 3.

        With the revised pending semantics, while a BEGIN is pending the
        scanner ONLY looks for the matching END — the second BEGIN is
        IGNORED. The Finding spans from the FIRST BEGIN (line 1) to the
        END (line 3).
        """
        from app.scanner.rules import PrivateKeyRule
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",   # line 1
            "-----BEGIN RSA PRIVATE KEY-----",   # line 2 (ignored)
            "-----END RSA PRIVATE KEY-----",     # line 3
        ]
        findings = rule.scan_content("dup_begin.pem", lines)
        assert len(findings) == 1
        f = findings[0]
        assert f.line_start == 1
        assert f.line_end == 3
        assert f.is_blocking is True
        assert f.snippet_masked == "<PRIVATE_KEY_REDACTED>"
        assert "Incomplete" not in f.description


# ============================================================================
# --- Multiple connection strings on one line (leakage fix) ---
# ============================================================================

class TestMultipleConnectionStringsOneLine:
    """Verify multiple connection strings on the same line are masked separately.

    The old greedy \\S+ host pattern swallowed the second connection string,
    causing only the first password to be masked. The shared separator-safe
    matcher stops at quotes, commas, semicolons, brackets, braces, and
    whitespace — so each connection string is matched independently.
    """

    def test_two_conn_strings_comma_separated(self):
        """Two connection strings separated by a comma: both passwords masked."""
        from app.core.security.desensitize import mask_untrusted_text, mask_snippet
        line = (
            f'postgres://u1:password1@host1/db,'
            f'mysql://u2:password2@host2/db'
        )
        # mask_untrusted_text
        result = mask_untrusted_text(line)
        assert "password1" not in result
        assert "password2" not in result
        # mask_snippet
        result2 = mask_snippet(line)
        assert "password1" not in result2
        assert "password2" not in result2

    def test_two_conn_strings_semicolon_separated(self):
        """Two connection strings separated by a semicolon: both passwords masked."""
        from app.core.security.desensitize import mask_untrusted_text
        line = (
            f'postgres://u1:password1@host1/db;'
            f'mysql://u2:password2@host2/db'
        )
        result = mask_untrusted_text(line)
        assert "password1" not in result
        assert "password2" not in result

    def test_compact_json_object_two_conn_strings(self):
        """Compact JSON object with two connection strings: both passwords masked."""
        from app.core.security.desensitize import mask_untrusted_text, mask_snippet
        line = (
            '{"primary":"postgres://u1:password1@host1/db",'
            '"backup":"mysql://u2:password2@host2/db"}'
        )
        result = mask_untrusted_text(line)
        assert "password1" not in result
        assert "password2" not in result
        result2 = mask_snippet(line)
        assert "password1" not in result2
        assert "password2" not in result2

    def test_compact_json_array_two_conn_strings(self):
        """Compact JSON array with two connection strings: both passwords masked."""
        from app.core.security.desensitize import mask_untrusted_text
        line = (
            '["postgres://u1:password1@host1/db",'
            '"mysql://u2:password2@host2/db"]'
        )
        result = mask_untrusted_text(line)
        assert "password1" not in result
        assert "password2" not in result

    def test_two_conn_strings_space_separated(self):
        """Two connection strings separated by whitespace: both passwords masked."""
        from app.core.security.desensitize import mask_untrusted_text
        line = (
            f'postgres://u1:password1@host1/db '
            f'mysql://u2:password2@host2/db'
        )
        result = mask_untrusted_text(line)
        assert "password1" not in result
        assert "password2" not in result

    def test_token_in_second_conn_string_fields(self):
        """Token embedded in the SECOND connection string's user/pass/host/path."""
        from app.core.security.desensitize import mask_untrusted_text, mask_snippet
        # Token in username of second conn string
        line = (
            f'postgres://u1:pw1@host1/db,'
            f'mysql://{SYNTH_GITHUB_TOKEN}:password2@host2/db'
        )
        result = mask_untrusted_text(line)
        assert SYNTH_GITHUB_TOKEN not in result
        assert "password2" not in result
        # Token in password of second conn string
        line2 = (
            f'postgres://u1:pw1@host1/db,'
            f'mysql://u2:{SYNTH_GITHUB_TOKEN}@host2/db'
        )
        result2 = mask_untrusted_text(line2)
        assert SYNTH_GITHUB_TOKEN not in result2
        # Token in host of second conn string
        line3 = (
            f'postgres://u1:pw1@host1/db,'
            f'mysql://u2:pw2@{SYNTH_GITHUB_TOKEN}/db'
        )
        result3 = mask_untrusted_text(line3)
        assert SYNTH_GITHUB_TOKEN not in result3
        # Token in path of second conn string
        line4 = (
            f'postgres://u1:pw1@host1/db,'
            f'mysql://u2:pw2@host2/{SYNTH_GITHUB_TOKEN}'
        )
        result4 = mask_untrusted_text(line4)
        assert SYNTH_GITHUB_TOKEN not in result4
        # mask_snippet too
        result5 = mask_snippet(line)
        assert SYNTH_GITHUB_TOKEN not in result5

    def test_r008_two_findings_two_conn_strings(self):
        """R008 produces TWO Findings for two connection strings on one line."""
        from app.scanner.rules import ConnectionStringRule
        rule = ConnectionStringRule()
        line = (
            f'DB_URL = "postgres://u1:password1@host1/db,'
            f'mysql://u2:password2@host2/db"'
        )
        findings = rule.scan_content("config.py", [line])
        assert len(findings) == 2
        for f in findings:
            assert "password1" not in f.snippet_masked
            assert "password2" not in f.snippet_masked
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
            # repr and JSON safety
            assert "password1" not in repr(f)
            assert "password2" not in repr(f)
            f_json = json.dumps(dataclasses.asdict(f), default=str)
            assert "password1" not in f_json
            assert "password2" not in f_json


# ============================================================================
# --- Token amplification: snippet caching + Finding limit ---
# ============================================================================

class TestTokenAmplificationBound:
    """Verify large token inputs don't cause CPU/result amplification.

    - Snippet is computed at most ONCE per line (not per Finding).
    - Finding count is capped at scan_max_findings_per_rule_per_file.
    - Overall execution is approximately linear.
    - No raw token appears in any returned object.
    """

    def test_snippet_computed_once_per_line(self):
        """mask_snippet is called at most ONCE per line, not per Finding."""
        from app.scanner.rules import GitHubTokenRule, _make_masked_snippet
        import app.scanner.rules as rules_mod

        call_count = 0
        original = rules_mod._make_masked_snippet

        def counting_make_snippet(line_text, max_length=200):
            nonlocal call_count
            call_count += 1
            return original(line_text, max_length)

        rules_mod._make_masked_snippet = counting_make_snippet
        try:
            rule = GitHubTokenRule()
            # 50 tokens on one line
            line = " ".join([SYNTH_GITHUB_TOKEN] * 50)
            findings = rule.scan_content("many_tokens.py", [line])
            # Should produce findings (capped at limit=100, so all 50)
            assert len(findings) == 50
            # Snippet should be computed exactly ONCE for this line
            assert call_count == 1, (
                f"Expected snippet to be computed once, got {call_count} calls"
            )
        finally:
            rules_mod._make_masked_snippet = original

    def test_finding_count_capped_at_limit(self):
        """Single line with 1000 tokens: Finding count <= configured limit."""
        from app.core.config import settings
        from app.scanner.rules import GitHubTokenRule
        rule = GitHubTokenRule()
        line = " ".join([SYNTH_GITHUB_TOKEN] * 1000)
        findings = rule.scan_content("huge.py", [line])
        limit = settings.scan_max_findings_per_rule_per_file
        assert len(findings) <= limit
        assert len(findings) == limit

    def test_10000_tokens_linear_and_capped(self):
        """10000 tokens on one line: linear, capped, no raw token in output."""
        from app.core.config import settings
        from app.scanner.rules import GitHubTokenRule
        rule = GitHubTokenRule()
        n = 10000
        line = " ".join([SYNTH_GITHUB_TOKEN] * n)
        findings = rule.scan_content("massive.py", [line])
        limit = settings.scan_max_findings_per_rule_per_file
        # Capped
        assert len(findings) <= limit
        assert len(findings) == limit
        # No raw token in any Finding
        for f in findings:
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
            assert SYNTH_GITHUB_TOKEN not in repr(f)
            f_json = json.dumps(dataclasses.asdict(f), default=str)
            assert SYNTH_GITHUB_TOKEN not in f_json

    def test_snippet_cache_with_multiple_lines(self):
        """Snippet cache works across multiple lines — one call per line."""
        from app.scanner.rules import GitHubTokenRule, _make_masked_snippet
        import app.scanner.rules as rules_mod

        call_count = 0
        original = rules_mod._make_masked_snippet

        def counting_make_snippet(line_text, max_length=200):
            nonlocal call_count
            call_count += 1
            return original(line_text, max_length)

        rules_mod._make_masked_snippet = counting_make_snippet
        try:
            rule = GitHubTokenRule()
            # 5 lines, each with 3 tokens
            lines = [" ".join([SYNTH_GITHUB_TOKEN] * 3) for _ in range(5)]
            findings = rule.scan_content("multi.py", lines)
            # 5 lines * 3 tokens = 15 findings (under limit of 100)
            assert len(findings) == 15
            # One snippet call per line = 5 calls
            assert call_count == 5, (
                f"Expected 5 snippet calls (one per line), got {call_count}"
            )
        finally:
            rules_mod._make_masked_snippet = original


# ============================================================================
# --- Risk-priority bounded retention tests ---
# ============================================================================

class TestRiskPriorityRetention:
    """Verify high-risk findings are preserved when under result caps.

    100 low-entropy placeholder tokens must NOT evict the 101st real
    blocking token. The BoundedFindingCollector always keeps the
    highest-risk findings, replacing low-risk ones when the limit is
    reached.
    """

    def test_100_low_github_then_1_high_risk(self):
        """100 low-entropy GitHub tokens + 1 real token: real one is kept."""
        from app.scanner.rules import GitHubTokenRule

        rule = GitHubTokenRule()
        # 100 low-entropy placeholders
        low_lines = [f"token = '{LOW_GITHUB}'" for _ in range(100)]
        # 1 real high-entropy token on line 101
        high_line = f"token = '{SYNTH_GITHUB_TOKEN}'"
        lines = low_lines + [high_line]

        findings = rule.scan_content("many_tokens.py", lines)
        limit = 100

        # Should have exactly limit findings
        assert len(findings) <= limit
        assert len(findings) == limit

        # At least one finding should be blocking (the real token)
        blocking = [f for f in findings if f.is_blocking]
        assert len(blocking) >= 1

        # The blocking finding should point to line 101
        assert any(f.line_start == 101 for f in blocking)

        # No raw token should appear in any finding
        for f in findings:
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
            assert SYNTH_GITHUB_TOKEN not in repr(f)

    def test_100_low_aws_access_then_1_high_risk(self):
        """100 low-entropy AWS access keys + 1 real key: real one is kept."""
        from app.scanner.rules import AWSAccessKeyRule

        rule = AWSAccessKeyRule()
        low_lines = [f"key = {LOW_AWS_KEY}" for _ in range(100)]
        high_line = f"key = {SYNTH_AWS_KEY}"
        lines = low_lines + [high_line]

        findings = rule.scan_content("many_keys.py", lines)
        limit = 100

        assert len(findings) <= limit
        assert len(findings) == limit

        blocking = [f for f in findings if f.is_blocking]
        assert len(blocking) >= 1
        assert any(f.line_start == 101 for f in blocking)

        for f in findings:
            assert SYNTH_AWS_KEY not in f.snippet_masked
            assert SYNTH_AWS_KEY not in repr(f)

    def test_100_low_aws_secret_then_1_high_risk(self):
        """100 low-entropy AWS secret keys + 1 real secret: real one is kept."""
        from app.scanner.rules import AWSSecretKeyRule

        rule = AWSSecretKeyRule()
        low_lines = [f"aws_secret_access_key = {LOW_AWS_SECRET}" for _ in range(100)]
        high_line = f"aws_secret_access_key = {SYNTH_AWS_SECRET}"
        lines = low_lines + [high_line]

        findings = rule.scan_content("many_secrets.py", lines)
        limit = 100

        assert len(findings) <= limit
        assert len(findings) == limit

        blocking = [f for f in findings if f.is_blocking]
        assert len(blocking) >= 1
        assert any(f.line_start == 101 for f in blocking)

        for f in findings:
            assert SYNTH_AWS_SECRET not in f.snippet_masked
            assert SYNTH_AWS_SECRET not in repr(f)

    def test_100_low_google_then_1_high_risk(self):
        """100 low-entropy Google API keys + 1 real key: real one is kept."""
        from app.scanner.rules import GoogleAPIKeyRule

        rule = GoogleAPIKeyRule()
        low_lines = [f"key = '{LOW_GOOGLE}'" for _ in range(100)]
        high_line = f"key = '{SYNTH_GOOGLE_KEY}'"
        lines = low_lines + [high_line]

        findings = rule.scan_content("many_google_keys.py", lines)
        limit = 100

        assert len(findings) <= limit
        assert len(findings) == limit

        blocking = [f for f in findings if f.is_blocking]
        assert len(blocking) >= 1
        assert any(f.line_start == 101 for f in blocking)

        for f in findings:
            assert SYNTH_GOOGLE_KEY not in f.snippet_masked
            assert SYNTH_GOOGLE_KEY not in repr(f)

    def test_limit_1_low_then_high_keeps_high(self, monkeypatch):
        """With limit=1: first low, second blocking — blocking is kept."""
        from app.core.config import settings
        from app.scanner.rules import GitHubTokenRule

        monkeypatch.setattr(settings, "scan_max_findings_per_rule_per_file", 1)

        rule = GitHubTokenRule()
        # Line 1: low-entropy (non-blocking)
        # Line 2: real token (blocking)
        lines = [
            f"token = '{LOW_GITHUB}'",
            f"token = '{SYNTH_GITHUB_TOKEN}'",
        ]

        findings = rule.scan_content("limit1.py", lines)

        # Only 1 finding (limit=1)
        assert len(findings) == 1

        # The retained finding MUST be the blocking one
        f = findings[0]
        assert f.is_blocking is True
        assert f.severity == Severity.CRITICAL
        assert f.line_start == 2  # points to the real token

        # No raw token in output
        assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
        assert SYNTH_GITHUB_TOKEN not in repr(f)

    def test_cross_line_high_risk_at_last_line(self):
        """100 low tokens at file start, real token at last line: still BLOCKED."""
        from app.scanner.rules import GitHubTokenRule

        rule = GitHubTokenRule()
        # 100 lines of low-entropy tokens
        low_lines = [f"t = '{LOW_GITHUB}'" for _ in range(100)]
        # Real token on the last line (line 101)
        lines = low_lines + [f"t = '{SYNTH_GITHUB_TOKEN}'"]

        findings = rule.scan_content("cross_line.py", lines)

        # Must have at least one blocking finding
        blocking = [f for f in findings if f.is_blocking]
        assert len(blocking) >= 1

        # The blocking finding must point to the last line
        last_line = len(lines)
        assert any(f.line_start == last_line for f in blocking)

        # No raw token in output
        for f in findings:
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
            assert SYNTH_GITHUB_TOKEN not in repr(f)

    def test_scan_directory_e2e_with_low_and_high(self, tmp_path):
        """End-to-end: repo with many low-entropy tokens + 1 real token."""
        from pathlib import Path

        # Create a file with 100 low-entropy tokens and 1 real token
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        config_file = repo_dir / "config.py"

        lines = [f"token_{i} = '{LOW_GITHUB}'" for i in range(100)]
        lines.append(f"real_token = '{SYNTH_GITHUB_TOKEN}'")
        config_file.write_text("\n".join(lines), encoding="utf-8")

        result = scan_directory(Path(repo_dir))

        # result.findings must contain at least one blocking finding
        blocking = [f for f in result.findings if f.is_blocking]
        assert len(blocking) >= 1

        # No raw token in any finding
        for f in result.findings:
            assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
            assert SYNTH_GITHUB_TOKEN not in repr(f)

    def test_10000_tokens_snippet_calls_constant(self):
        """10000 tokens: Finding count capped, snippet calls stay constant."""
        import app.scanner.rules as rules_mod
        from app.core.config import settings
        from app.scanner.rules import GitHubTokenRule

        call_count = 0
        original = rules_mod._make_masked_snippet

        def counting_make_snippet(line_text, max_length=200):
            nonlocal call_count
            call_count += 1
            return original(line_text, max_length)

        rules_mod._make_masked_snippet = counting_make_snippet
        try:
            rule = GitHubTokenRule()
            # 10000 low-entropy tokens on one line + 1 real token
            low_part = " ".join([LOW_GITHUB] * 10000)
            high_part = SYNTH_GITHUB_TOKEN
            line = f"{low_part} {high_part}"

            findings = rule.scan_content("massive.py", [line])
            limit = settings.scan_max_findings_per_rule_per_file

            # Finding count capped
            assert len(findings) <= limit
            assert len(findings) == limit

            # Snippet calls: exactly 1 (one line, cached)
            # should_accept() prevents snippet computation for evicted candidates
            assert call_count == 1, (
                f"Expected 1 snippet call (cached per line), got {call_count}"
            )

            # At least one blocking finding (the real token)
            blocking = [f for f in findings if f.is_blocking]
            assert len(blocking) >= 1

            # No raw token in output
            for f in findings:
                assert SYNTH_GITHUB_TOKEN not in f.snippet_masked
                assert SYNTH_GITHUB_TOKEN not in repr(f)
                f_json = json.dumps(dataclasses.asdict(f), default=str)
                assert SYNTH_GITHUB_TOKEN not in f_json
        finally:
            rules_mod._make_masked_snippet = original

    def test_config_limit_0_clamped_to_1(self):
        """Config value of 0 is clamped to 1 by the validator."""
        from app.core.config import Settings

        s = Settings(scan_max_findings_per_rule_per_file=0)
        assert s.scan_max_findings_per_rule_per_file >= 1
        assert s.scan_max_findings_per_rule_per_file == 1

    def test_config_limit_negative_clamped_to_1(self):
        """Config value of -5 is clamped to 1 by the validator."""
        from app.core.config import Settings

        s = Settings(scan_max_findings_per_rule_per_file=-5)
        assert s.scan_max_findings_per_rule_per_file == 1
