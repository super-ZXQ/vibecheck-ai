"""Tests for individual scanner rules.

ALL test strings are SYNTHETIC -- correct format but NO actual validity.
No real credentials are used.

Test count: 15
"""

import pytest

from app.scanner.base import Finding, FindingType, ScanNotice, Severity, Confidence
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
)


# --- Synthetic test constants (NOT real credentials) ---
SYNTH_GITHUB_TOKEN = "ghp_" + "A" * 36
SYNTH_AWS_KEY = "AKIA" + "B" * 16
SYNTH_GOOGLE_KEY = "AIza" + "C" * 35
SYNTH_AWS_SECRET = "D" * 40
SYNTH_PASSWORD = "s3cur3P@ssw0rd!"


# ============================================================================
# --- Token/Key detection rules (6 tests) ---
# ============================================================================

class TestGitHubTokenRule:
    """Tests for R001 GitHubTokenRule."""

    def test_github_token_detected(self):
        """Valid-format GitHub token is detected as critical/blocking."""
        rule = GitHubTokenRule()
        lines = [f'TOKEN = "{SYNTH_GITHUB_TOKEN}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R001_GITHUB_TOKEN"
        assert f.severity == Severity.CRITICAL
        assert f.is_blocking is True
        assert f.line_start == 1
        assert f.column_start is not None
        assert f.column_end is not None
        # Original token must not appear in snippet
        assert SYNTH_GITHUB_TOKEN not in f.snippet_masked

    def test_github_token_short_not_detected(self):
        """Short token (ghp_ + 10 chars) is NOT detected."""
        rule = GitHubTokenRule()
        lines = ['token = "ghp_' + "A" * 10 + '"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0


class TestAWSAccessKeyRule:
    """Tests for R002 AWSAccessKeyRule."""

    def test_aws_access_key_detected(self):
        """Valid-format AWS access key is detected."""
        rule = AWSAccessKeyRule()
        lines = [f"AWS_KEY = '{SYNTH_AWS_KEY}'"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R002_AWS_ACCESS_KEY"
        assert f.severity == Severity.CRITICAL
        assert f.is_blocking is True
        assert SYNTH_AWS_KEY not in f.snippet_masked


class TestAWSSecretKeyRule:
    """Tests for R003 AWSSecretKeyRule (context-aware)."""

    def test_aws_secret_key_with_context(self):
        """40-char base64 with aws_secret_access_key context is detected."""
        rule = AWSSecretKeyRule()
        lines = [f"aws_secret_access_key = {SYNTH_AWS_SECRET}"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R003_AWS_SECRET_KEY"
        assert f.is_blocking is True
        assert SYNTH_AWS_SECRET not in f.snippet_masked

    def test_aws_secret_key_without_context_not_detected(self):
        """Random 40-char base64 without context is NOT detected."""
        rule = AWSSecretKeyRule()
        lines = [f"hash = {SYNTH_AWS_SECRET}"]
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0


class TestGoogleAPIKeyRule:
    """Tests for R004 GoogleAPIKeyRule."""

    def test_google_api_key_detected(self):
        """Valid-format Google API key is detected."""
        rule = GoogleAPIKeyRule()
        lines = [f'GOOGLE_KEY = "{SYNTH_GOOGLE_KEY}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R004_GOOGLE_API_KEY"
        assert f.severity == Severity.CRITICAL
        assert SYNTH_GOOGLE_KEY not in f.snippet_masked


# ============================================================================
# --- Private key detection (3 tests) ---
# ============================================================================

class TestPrivateKeyRule:
    """Tests for R005 PrivateKeyRule."""

    def test_private_key_rsa_detected(self):
        """RSA private key with BEGIN/END is detected."""
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEA" + "D" * 400,
            "-----END RSA PRIVATE KEY-----",
        ]
        findings = rule.scan_content("id_rsa", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R005_PRIVATE_KEY"
        assert f.severity == Severity.CRITICAL
        assert f.is_blocking is True
        assert f.snippet_masked == "<PRIVATE_KEY_REDACTED>"
        assert f.line_start == 1
        assert f.line_end == 3

    def test_private_key_openssh_detected(self):
        """OPENSSH private key with BEGIN/END is detected."""
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA",
            "-----END OPENSSH PRIVATE KEY-----",
        ]
        findings = rule.scan_content("id_ed25519", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R005_PRIVATE_KEY"
        assert f.snippet_masked == "<PRIVATE_KEY_REDACTED>"
        assert f.line_start == 1
        assert f.line_end == 3

    def test_private_key_missing_end_blocking(self):
        """BEGIN without END is still blocking, snippet is <PRIVATE_KEY_REDACTED>."""
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEA" + "D" * 400,
            "# no end marker here",
        ]
        findings = rule.scan_content("broken_key", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.is_blocking is True
        assert f.snippet_masked == "<PRIVATE_KEY_REDACTED>"
        # Description should mention incomplete
        assert "Incomplete" in f.description or "without" in f.description.lower()


# ============================================================================
# --- Assignment rules (4 tests) ---
# ============================================================================

class TestPasswordAssignmentRule:
    """Tests for R006 PasswordAssignmentRule."""

    def test_password_assignment_detected(self):
        """Hardcoded password assignment is detected as high, non-blocking."""
        rule = PasswordAssignmentRule()
        lines = [f'password = "{SYNTH_PASSWORD}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R006_PASSWORD_ASSIGNMENT"
        assert f.severity == Severity.HIGH
        assert f.is_blocking is False
        assert SYNTH_PASSWORD not in f.snippet_masked

    def test_password_placeholder_downgrade(self):
        """Placeholder value (changeme) is downgraded to low/low/non-blocking."""
        rule = PasswordAssignmentRule()
        lines = ["password = changeme"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False

    def test_password_env_reference_skipped(self):
        """Env var reference (${VAR}) is NOT detected as a secret."""
        rule = PasswordAssignmentRule()
        lines = ["password = ${DB_PASSWORD}"]
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0


class TestGenericTokenAssignmentRule:
    """Tests for R007 GenericTokenAssignmentRule."""

    def test_generic_token_assignment_detected(self):
        """Generic secret assignment is detected, non-blocking."""
        rule = GenericTokenAssignmentRule()
        lines = ['secret = "my_api_secret_value"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert f.is_blocking is False
        assert "my_api_secret_value" not in f.snippet_masked


# ============================================================================
# --- Connection string (1 test) ---
# ============================================================================

class TestConnectionStringRule:
    """Tests for R008 ConnectionStringRule."""

    def test_connection_string_detected(self):
        """Connection string with embedded password is detected, non-blocking."""
        rule = ConnectionStringRule()
        conn = "postgres://admin:s3cr3tpw@db.example.com:5432/mydb"
        lines = [f'DATABASE_URL = "{conn}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R008_CONNECTION_STRING"
        assert f.is_blocking is False
        # Password must not appear in snippet
        assert "s3cr3tpw" not in f.snippet_masked


# ============================================================================
# --- File-level rules (1 test) ---
# ============================================================================

class TestEnvFilePresentRule:
    """Tests for R009 EnvFilePresentRule."""

    def test_env_file_present_rule(self):
        """ .env file is detected as medium severity, non-blocking."""
        rule = EnvFilePresentRule()
        result = rule.check_file(".env", 100)

        assert result is not None
        assert isinstance(result, Finding)
        f = result
        assert f.rule_id == "R009_ENV_FILE_PRESENT"
        assert f.severity == Severity.MEDIUM
        assert f.is_blocking is False
        assert f.finding_type == FindingType.FILE
        assert f.line_start is None
        assert f.column_start is None
