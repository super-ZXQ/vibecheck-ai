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

from app.scanner.base import Severity
from app.scanner.rules import PrivateKeyRule
from app.scanner.sensitive import scan_directory


# --- Synthetic test constants (NOT real credentials) ---
SYNTH_GITHUB_TOKEN = "ghp_" + "A" * 36
SYNTH_AWS_KEY = "AKIA" + "B" * 16
SYNTH_PASSWORD = "s3cur3P@ssw0rd!"


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
        # The token is "ghp_" + "A"*36, so check that no long run of A's survives
        assert "A" * 10 not in snippet  # No 10+ consecutive A's from the token


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
        token_with_test = "ghp_" + "test" + "A" * 32  # 4 + 36 = 40 chars total
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

        # Verify both sensitive variable names are covered
        descriptions = [f.description for f in r011]
        assert any("JWT_SECRET" in d for d in descriptions)
        assert any("CLIENT_SECRET" in d for d in descriptions)


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
