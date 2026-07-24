"""Tests for individual scanner rules.

ALL test strings are SYNTHETIC -- correct format but NO actual validity.
No real credentials are used.

Test count: 28
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
    ProductionEnvWithSecretRule,
)


# --- Runtime-constructed mixed-character synthetic values (NOT real credentials) ---
_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
_MIXED_UPPER = "ABCDEF1234567890GHIJKLMNOP"
SYNTH_GITHUB_TOKEN = "ghp_" + _MIXED[:36]
SYNTH_AWS_KEY = "AKIA" + _MIXED_UPPER[:16]
SYNTH_GOOGLE_KEY = "AIza" + _MIXED[:35]
SYNTH_AWS_SECRET = ("AbCdEf1234" * 4)[:40]
SYNTH_PASSWORD = "s3cur3P@ssw0rd!"
# Low-entropy placeholder token (all same char after prefix)
SYNTH_LOW_ENTROPY_TOKEN = "ghp_" + "X" * 36
SYNTH_LOW_ENTROPY_AWS_KEY = "AKIA" + "X" * 16
SYNTH_LOW_ENTROPY_GOOGLE_KEY = "AIza" + "X" * 35
SYNTH_LOW_ENTROPY_AWS_SECRET = "X" * 40


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

    def test_github_token_low_entropy_downgraded(self):
        """Low-entropy token (all same char) is downgraded to low/low/non-blocking."""
        rule = GitHubTokenRule()
        lines = [f'TOKEN = "{SYNTH_LOW_ENTROPY_TOKEN}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R001_GITHUB_TOKEN"
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False

    def test_github_token_mixed_char_still_blocking(self):
        """Mixed-character token is NOT downgraded -- remains critical/blocking."""
        rule = GitHubTokenRule()
        lines = [f'TOKEN = "{SYNTH_GITHUB_TOKEN}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH
        assert f.is_blocking is True


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

    def test_aws_access_key_low_entropy_downgraded(self):
        """Low-entropy AWS key (all same char) is downgraded."""
        rule = AWSAccessKeyRule()
        lines = [f"KEY = {SYNTH_LOW_ENTROPY_AWS_KEY}"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False


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

    def test_aws_secret_key_low_entropy_downgraded(self):
        """Low-entropy AWS secret (all same char) is downgraded."""
        rule = AWSSecretKeyRule()
        lines = [f"aws_secret_access_key = {SYNTH_LOW_ENTROPY_AWS_SECRET}"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False


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

    def test_google_api_key_low_entropy_downgraded(self):
        """Low-entropy Google API key (all same char) is downgraded."""
        rule = GoogleAPIKeyRule()
        lines = [f'KEY = "{SYNTH_LOW_ENTROPY_GOOGLE_KEY}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert f.is_blocking is False


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

    def test_password_dollar_lowercase_detected(self):
        """password=$uperSecret123 (lowercase $u) IS detected -- not env ref."""
        rule = PasswordAssignmentRule()
        lines = ['password = "$uperSecret123"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        assert "$uperSecret123" not in findings[0].snippet_masked


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


# ============================================================================
# --- JSON/TOML quoted key tests (3 tests) ---
# ============================================================================

class TestQuotedJSONTomlKeys:
    """Tests for quoted JSON/TOML attribute name support."""

    def test_json_double_quoted_key_password(self):
        """"password": "alpha beta gamma" produces R006 with correct columns."""
        rule = PasswordAssignmentRule()
        line = '"password": "alpha beta gamma"'
        lines = [line]
        findings = rule.scan_content("config.json", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R006_PASSWORD_ASSIGNMENT"
        # Column range must point to the full value
        assert f.column_start is not None
        assert f.column_end is not None
        # Extract the value at the column range from the original line
        value_at_range = line[f.column_start:f.column_end]
        assert value_at_range == "alpha beta gamma"
        # Snippet must be fully masked
        assert "alpha" not in f.snippet_masked
        assert "beta" not in f.snippet_masked
        assert "gamma" not in f.snippet_masked

    def test_toml_single_quoted_key_token(self):
        """'token': 'abc def ghi' produces R007 with correct columns."""
        rule = GenericTokenAssignmentRule()
        line = "'token': 'abc def ghi'"
        lines = [line]
        findings = rule.scan_content("config.toml", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        # Column range must point to the full value
        value_at_range = line[f.column_start:f.column_end]
        assert value_at_range == "abc def ghi"
        # Snippet must be fully masked
        assert "abc" not in f.snippet_masked
        assert "def" not in f.snippet_masked
        assert "ghi" not in f.snippet_masked

    def test_quoted_key_with_equals_api_key(self):
        """"api_key" = "some value" produces R007 with correct columns."""
        rule = GenericTokenAssignmentRule()
        line = '"api_key" = "some value"'
        lines = [line]
        findings = rule.scan_content("config.toml", lines)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        value_at_range = line[f.column_start:f.column_end]
        assert value_at_range == "some value"
        assert "some value" not in f.snippet_masked

    def test_existing_python_assignment_no_regression(self):
        """Existing Python-style password= still works after JSON/TOML support."""
        rule = PasswordAssignmentRule()
        lines = [f'password = "{SYNTH_PASSWORD}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        assert SYNTH_PASSWORD not in findings[0].snippet_masked

    def test_existing_env_assignment_no_regression(self):
        """Existing .env-style KEY=value still works."""
        rule = GenericTokenAssignmentRule()
        lines = ["TOKEN=my_secret_token_value"]
        findings = rule.scan_content(".env", lines)

        assert len(findings) == 1
        assert "my_secret_token_value" not in findings[0].snippet_masked


# ============================================================================
# --- Unquoted # value tests (2 tests) ---
# ============================================================================

class TestUnquotedHashValue:
    """Tests for # in unquoted values -- full value including # is masked."""

    def test_password_alpha_hash_omega(self):
        """password=alpha#omega -- snippet has no alpha or omega."""
        rule = PasswordAssignmentRule()
        lines = ["password=alpha#omega"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        assert "alpha" not in findings[0].snippet_masked
        assert "omega" not in findings[0].snippet_masked

    def test_token_abc_hash_def(self):
        """token=abc#def -- snippet has no abc or def."""
        rule = GenericTokenAssignmentRule()
        lines = ["token=abc#def"]
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        assert "abc" not in findings[0].snippet_masked
        assert "def" not in findings[0].snippet_masked


# ============================================================================
# --- Strict env reference tests (3 tests) ---
# ============================================================================

class TestStrictEnvReference:
    """Tests for strict environment variable reference detection."""

    def test_dollar_lowercase_password_detected(self):
        """password='$uperSecret123' (quoted) is detected as real secret."""
        rule = PasswordAssignmentRule()
        lines = ['password = "$uperSecret123"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        assert "$uperSecret123" not in findings[0].snippet_masked

    def test_dollar_brace_literal_detected(self):
        """password='\\${LITERAL_VALUE}' (quoted, escaped) is detected as real secret."""
        rule = PasswordAssignmentRule()
        lines = ['password = "\\${LITERAL_VALUE}"']
        findings = rule.scan_content("config.py", lines)

        assert len(findings) == 1
        # The escaped value becomes ${LITERAL_VALUE} -- still masked
        assert "LITERAL_VALUE" not in findings[0].snippet_masked

    def test_real_env_references_not_detected(self):
        """Genuine env references ($VAR, ${VAR}, etc.) are NOT detected."""
        rule = PasswordAssignmentRule()
        lines = [
            "password = $DB_PASSWORD",
            "password = ${DB_PASSWORD}",
            "password = ${DB_PASSWORD:-default}",
        ]
        for line in lines:
            findings = rule.scan_content("config.py", [line])
            assert len(findings) == 0, f"False positive on: {line}"
