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


# ============================================================================
# --- Compound key regression tests (15 scenarios) ---
# ============================================================================

class TestCompoundKeyRegression:
    """Regression tests for compound sensitive variable name detection.

    These tests verify that the unified assignment parser (iter_assignments)
    and segment-based key classification (classify_key) correctly identify
    compound sensitive variable names like DB_PASSWORD, OPENAI_API_KEY,
    JWT_SECRET, etc., while NOT matching non-sensitive names like
    SECRETARY_EMAIL, TOKENIZER_MODEL, PASSWORDLESS_MODE.
    """

    # --- Test 1: DB_PASSWORD -> R006 ---
    def test_01_db_password_produces_r006(self):
        """DB_PASSWORD hardcoded produces R006."""
        rule = PasswordAssignmentRule()
        lines = ['DB_PASSWORD = "s3cur3DbP@ss"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R006_PASSWORD_ASSIGNMENT"
        assert "s3cur3DbP@ss" not in findings[0].snippet_masked

    # --- Test 2: DATABASE_PASSWORD -> R006 ---
    def test_02_database_password_produces_r006(self):
        """DATABASE_PASSWORD hardcoded produces R006."""
        rule = PasswordAssignmentRule()
        lines = ['DATABASE_PASSWORD = "myDbP@ss123"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R006_PASSWORD_ASSIGNMENT"
        assert "myDbP@ss123" not in findings[0].snippet_masked

    # --- Test 3: OPENAI_API_KEY -> R007 ---
    def test_03_openai_api_key_produces_r007(self):
        """OPENAI_API_KEY hardcoded produces R007."""
        rule = GenericTokenAssignmentRule()
        lines = ['OPENAI_API_KEY = "sk-proj-abc123def456"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert "sk-proj-abc123def456" not in findings[0].snippet_masked

    # --- Test 4: MY_API_KEY -> R007 ---
    def test_04_my_api_key_produces_r007(self):
        """MY_API_KEY hardcoded produces R007."""
        rule = GenericTokenAssignmentRule()
        lines = ['MY_API_KEY = "key_12345abcdef"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert "key_12345abcdef" not in findings[0].snippet_masked

    # --- Test 5: JWT_SECRET -> R007 (normal file) or R011 (production env) ---
    def test_05a_jwt_secret_produces_r007(self):
        """JWT_SECRET hardcoded in normal file produces R007."""
        rule = GenericTokenAssignmentRule()
        lines = ['JWT_SECRET = "myJwtS3cr3tVal"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert "myJwtS3cr3tVal" not in findings[0].snippet_masked

    def test_05b_jwt_secret_in_production_produces_r011(self):
        """JWT_SECRET hardcoded in .env.production produces R011 (blocking)."""
        rule = ProductionEnvWithSecretRule()
        lines = ['JWT_SECRET = "myJwtS3cr3tVal"']
        findings = rule.scan_content(".env.production", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R011_PRODUCTION_ENV_WITH_SECRET"
        assert findings[0].is_blocking is True
        assert "myJwtS3cr3tVal" not in findings[0].snippet_masked

    # --- Test 6: GITHUB_TOKEN non-format value -> R007 (not R001) ---
    def test_06_github_token_non_format_produces_r007(self):
        """GITHUB_TOKEN with non-ghp_ value produces R007, not R001."""
        r007 = GenericTokenAssignmentRule()
        lines = ['GITHUB_TOKEN = "some_plain_text_value"']
        r007_findings = r007.scan_content("config.py", lines)
        assert len(r007_findings) == 1
        assert r007_findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        # R001 must NOT catch it (no ghp_ format)
        r001 = GitHubTokenRule()
        assert len(r001.scan_content("config.py", lines)) == 0
        assert "some_plain_text_value" not in r007_findings[0].snippet_masked

    # --- Test 7: AWS_SECRET_ACCESS_KEY strict format -> R003 ---
    def test_07_aws_secret_access_key_strict_format_produces_r003(self):
        """AWS_SECRET_ACCESS_KEY with 40-char base64 produces R003 (blocking)."""
        rule = AWSSecretKeyRule()
        lines = [f'AWS_SECRET_ACCESS_KEY = {SYNTH_AWS_SECRET}']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R003_AWS_SECRET_KEY"
        assert findings[0].is_blocking is True
        assert SYNTH_AWS_SECRET not in findings[0].snippet_masked

    # --- Test 8: PASSWORDLESS_MODE -> no finding ---
    def test_08_passwordless_mode_no_finding(self):
        """PASSWORDLESS_MODE does not produce any finding."""
        for rule_class in [PasswordAssignmentRule, GenericTokenAssignmentRule, AWSSecretKeyRule]:
            rule = rule_class()
            lines = ['PASSWORDLESS_MODE = "true"']
            findings = rule.scan_content("config.py", lines)
            assert len(findings) == 0, f"{rule_class.__name__} false positive on PASSWORDLESS_MODE"

    # --- Test 9: TOKENIZER_MODEL -> no finding ---
    def test_09_tokenizer_model_no_finding(self):
        """TOKENIZER_MODEL does not produce any finding."""
        for rule_class in [PasswordAssignmentRule, GenericTokenAssignmentRule, AWSSecretKeyRule]:
            rule = rule_class()
            lines = ['TOKENIZER_MODEL = "gpt-4"']
            findings = rule.scan_content("config.py", lines)
            assert len(findings) == 0, f"{rule_class.__name__} false positive on TOKENIZER_MODEL"

    # --- Test 10: SECRETARY_EMAIL -> no finding ---
    def test_10_secretary_email_no_finding(self):
        """SECRETARY_EMAIL does not produce any finding."""
        for rule_class in [PasswordAssignmentRule, GenericTokenAssignmentRule, AWSSecretKeyRule]:
            rule = rule_class()
            lines = ['SECRETARY_EMAIL = "admin@example.com"']
            findings = rule.scan_content("config.py", lines)
            assert len(findings) == 0, f"{rule_class.__name__} false positive on SECRETARY_EMAIL"

    # --- Test 11: password=${DB_PASSWORD:-default} -> no false positive ---
    def test_11_password_env_ref_default_no_false_positive(self):
        """password=${DB_PASSWORD:-default} does not produce R006 (env ref)."""
        rule = PasswordAssignmentRule()
        lines = ['password = ${DB_PASSWORD:-default}']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    # --- Test 12: unrelated=${DB_PASSWORD:-default} -> no false key in value ---
    def test_12_unrelated_env_ref_no_false_key(self):
        """unrelated=${DB_PASSWORD:-default} -- DB_PASSWORD inside value is NOT a second key."""
        # If iter_assignments incorrectly parsed DB_PASSWORD as a key inside the value,
        # R006 would fire. It must NOT.
        rule = PasswordAssignmentRule()
        lines = ['unrelated = ${DB_PASSWORD:-default}']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    # --- Test 13: same line password="a" token="b" -> both parsed ---
    def test_13_same_line_two_assignments_both_detected(self):
        """password="hunter2pass" token="tokensecret99" -- both assignments detected."""
        r006 = PasswordAssignmentRule()
        r007 = GenericTokenAssignmentRule()
        lines = ['password="hunter2pass" token="tokensecret99"']
        r006_findings = r006.scan_content("config.py", lines)
        r007_findings = r007.scan_content("config.py", lines)
        assert len(r006_findings) == 1
        assert r006_findings[0].rule_id == "R006_PASSWORD_ASSIGNMENT"
        assert "hunter2pass" not in r006_findings[0].snippet_masked
        assert len(r007_findings) == 1
        assert r007_findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert "tokensecret99" not in r007_findings[0].snippet_masked

    # --- Test 14: JSON/TOML quoted compound keys recognized ---
    def test_14a_json_quoted_compound_key_db_password(self):
        """"db_password": "secret123val" produces R006."""
        rule = PasswordAssignmentRule()
        line = '"db_password": "secret123val"'
        lines = [line]
        findings = rule.scan_content("config.json", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R006_PASSWORD_ASSIGNMENT"
        assert "secret123val" not in findings[0].snippet_masked

    def test_14b_toml_quoted_compound_key_openai_api_key(self):
        """'openai_api_key' = 'mykeyvalue123' produces R007."""
        rule = GenericTokenAssignmentRule()
        line = "'openai_api_key' = 'mykeyvalue123'"
        lines = [line]
        findings = rule.scan_content("config.toml", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert "mykeyvalue123" not in findings[0].snippet_masked

    # --- Test 15: snippet full-chain leak prevention still passes ---
    def test_15_compound_key_snippet_no_leak(self):
        """Compound key values are fully masked in snippet -- no leak."""
        from app.core.security.desensitize import mask_snippet
        line = f'DB_PASSWORD = "{SYNTH_PASSWORD}"'
        result = mask_snippet(line)
        assert SYNTH_PASSWORD not in result
        assert "<REDACTED>" in result

    def test_15b_openai_api_key_snippet_no_leak(self):
        """OPENAI_API_KEY value is fully masked in snippet -- no leak."""
        from app.core.security.desensitize import mask_snippet
        line = 'OPENAI_API_KEY = "sk-proj-mykey123abc"'
        result = mask_snippet(line)
        assert "sk-proj-mykey123abc" not in result
        assert "<REDACTED>" in result

    # --- Additional non-sensitive compound name tests ---
    def test_api_keyboard_layout_no_finding(self):
        """API_KEYBOARD_LAYOUT does not produce any finding."""
        for rule_class in [PasswordAssignmentRule, GenericTokenAssignmentRule, AWSSecretKeyRule]:
            rule = rule_class()
            lines = ['API_KEYBOARD_LAYOUT = "qwerty"']
            findings = rule.scan_content("config.py", lines)
            assert len(findings) == 0, f"{rule_class.__name__} false positive on API_KEYBOARD_LAYOUT"

    def test_access_tokenizer_no_finding(self):
        """ACCESS_TOKENIZER does not produce any finding."""
        for rule_class in [PasswordAssignmentRule, GenericTokenAssignmentRule, AWSSecretKeyRule]:
            rule = rule_class()
            lines = ['ACCESS_TOKENIZER = "bert-base"']
            findings = rule.scan_content("config.py", lines)
            assert len(findings) == 0, f"{rule_class.__name__} false positive on ACCESS_TOKENIZER"


# ============================================================================
# --- Operator distinction rule-level tests ---
# ============================================================================

class TestOperatorDistinctionRules:
    """Verify rules do not produce findings for non-assignment syntax."""

    def test_password_colon_str_no_finding(self):
        """password: str does not produce R006 (type annotation, not assignment)."""
        rule = PasswordAssignmentRule()
        lines = ["password: str"]
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    def test_token_colon_optional_no_finding(self):
        """token: Optional[str] does not produce R007."""
        rule = GenericTokenAssignmentRule()
        lines = ["token: Optional[str]"]
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    def test_def_login_password_colon_str_no_finding(self):
        """def login(password: str): does not produce any finding."""
        rule = PasswordAssignmentRule()
        lines = ["def login(password: str):"]
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    def test_double_equals_no_finding(self):
        """password == "admin" does not produce R006 (comparison)."""
        rule = PasswordAssignmentRule()
        lines = ['password == "admin"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    def test_walrus_operator_no_finding(self):
        """password := get_password() does not produce R006 (walrus)."""
        rule = PasswordAssignmentRule()
        lines = ["password := get_password()"]
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    def test_quoted_colon_password_produces_r006(self):
        """"password": "hardcoded value" produces R006 (JSON assignment)."""
        rule = PasswordAssignmentRule()
        lines = ['"password": "hardcoded value"']
        findings = rule.scan_content("config.json", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R006_PASSWORD_ASSIGNMENT"
        assert "hardcoded value" not in findings[0].snippet_masked

    def test_quoted_colon_api_key_produces_r007(self):
        """'api_key': 'hardcoded value' produces R007 (TOML assignment)."""
        rule = GenericTokenAssignmentRule()
        lines = ["'api_key': 'hardcoded value'"]
        findings = rule.scan_content("config.toml", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert "hardcoded value" not in findings[0].snippet_masked

    def test_unquoted_equals_password_produces_r006(self):
        """password="hardcoded value" produces R006 (normal assignment)."""
        rule = PasswordAssignmentRule()
        lines = ['password="hardcoded value"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R006_PASSWORD_ASSIGNMENT"
        assert "hardcoded value" not in findings[0].snippet_masked


# ============================================================================
# --- AWS fallback and name tightening tests ---
# ============================================================================

class TestAWSFallbackAndNameTightening:
    """Verify R003 strict format, R007 fallback, and AWS name tightening."""

    def test_aws_secret_short_value_produces_r007(self):
        """AWS_SECRET_ACCESS_KEY=short-hardcoded-secret produces R007 (not R003)."""
        r003 = AWSSecretKeyRule()
        r007 = GenericTokenAssignmentRule()
        lines = ['AWS_SECRET_ACCESS_KEY = "short-hardcoded-secret"']

        # R003 must NOT fire (value is not 40-char base64)
        r003_findings = r003.scan_content("config.py", lines)
        assert len(r003_findings) == 0

        # R007 MUST fire (fallback for non-strict AWS secret value)
        r007_findings = r007.scan_content("config.py", lines)
        assert len(r007_findings) == 1
        assert r007_findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert r007_findings[0].is_blocking is False
        assert "short-hardcoded-secret" not in r007_findings[0].snippet_masked

    def test_aws_secret_strict_format_only_r003(self):
        """AWS_SECRET_ACCESS_KEY=<40-char> -- R003 fires, R007 skips."""
        r003 = AWSSecretKeyRule()
        r007 = GenericTokenAssignmentRule()
        lines = [f'AWS_SECRET_ACCESS_KEY = {SYNTH_AWS_SECRET}']

        # R003 MUST fire (strict format)
        r003_findings = r003.scan_content("config.py", lines)
        assert len(r003_findings) == 1
        assert r003_findings[0].rule_id == "R003_AWS_SECRET_KEY"
        assert r003_findings[0].is_blocking is True

        # R007 must NOT fire (value meets R003 strict format, R007 skips)
        r007_findings = r007.scan_content("config.py", lines)
        assert len(r007_findings) == 0

    def test_aws_secret_env_ref_no_hardcoded_finding(self):
        """AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} -- no hardcoded finding."""
        r003 = AWSSecretKeyRule()
        r007 = GenericTokenAssignmentRule()
        lines = ["AWS_SECRET_ACCESS_KEY = ${AWS_SECRET_ACCESS_KEY}"]

        # Neither R003 nor R007 should fire (env reference)
        assert len(r003.scan_content("config.py", lines)) == 0
        assert len(r007.scan_content("config.py", lines)) == 0

    def test_aws_client_secret_no_r003(self):
        """AWS_CLIENT_SECRET does NOT produce R003 (not exact AWS name)."""
        rule = AWSSecretKeyRule()
        lines = [f'AWS_CLIENT_SECRET = {SYNTH_AWS_SECRET}']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    def test_my_secret_access_key_backup_no_r003(self):
        """MY_SECRET_ACCESS_KEY_BACKUP does NOT produce R003."""
        rule = AWSSecretKeyRule()
        lines = [f'MY_SECRET_ACCESS_KEY_BACKUP = {SYNTH_AWS_SECRET}']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0

    def test_secret_database_access_key_no_r003(self):
        """SECRET_DATABASE_ACCESS_KEY does NOT produce R003."""
        rule = AWSSecretKeyRule()
        lines = [f'SECRET_DATABASE_ACCESS_KEY = {SYNTH_AWS_SECRET}']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 0


# ============================================================================
# --- Unquoted compound key rule tests (3 tests) ---
# ============================================================================

class TestUnquotedCompoundKeyRules:
    """Verify rules correctly handle hyphen/dot compound keys."""

    def test_hyphen_api_key_produces_r007(self):
        """my-api-key = "value" produces R007."""
        rule = GenericTokenAssignmentRule()
        lines = ['my-api-key = "hardcoded_value_123"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"
        assert "hardcoded_value_123" not in findings[0].snippet_masked

    def test_dot_api_key_produces_r007(self):
        """openai.api.key = "value" produces R007."""
        rule = GenericTokenAssignmentRule()
        lines = ['openai.api.key = "hardcoded_value_456"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R007_GENERIC_TOKEN_ASSIGNMENT"

    def test_dot_password_produces_r006(self):
        """db.password = "value" produces R006."""
        rule = PasswordAssignmentRule()
        lines = ['db.password = "hardcoded_password_789"']
        findings = rule.scan_content("config.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "R006_PASSWORD_ASSIGNMENT"


# ============================================================================
# --- Private key linear complexity tests (4 tests) ---
# ============================================================================

class TestPrivateKeyLinearComplexity:
    """Verify private key scanning is O(n) — no quadratic behavior."""

    def test_two_consecutive_complete_keys(self):
        """Two consecutive complete private keys produce two Findings."""
        rule = PrivateKeyRule()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEA" + "D" * 400,
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "MHcCAQEE" + "E" * 100,
            "-----END EC PRIVATE KEY-----",
        ]
        findings = rule.scan_content("id_rsa", lines)
        assert len(findings) == 2
        # Both should be complete (not incomplete)
        for f in findings:
            assert "Incomplete" not in f.description
            assert f.is_blocking is True

    def test_many_begins_without_end_linear(self):
        """Many BEGINs without END do NOT cause quadratic scanning.

        Uses a CountingStr wrapper to verify that str.contains (via 'in')
        is called at most a constant multiple of the number of lines.
        """
        call_count = 0

        class CountingStr:
            """Wrapper that counts 'in' (contains) operations."""
            def __init__(self, s):
                self._s = s
            def __contains__(self, item):
                nonlocal call_count
                call_count += 1
                return item in self._s
            def __getattr__(self, name):
                return getattr(self._s, name)

        rule = PrivateKeyRule()
        n = 500
        lines = ["-----BEGIN RSA PRIVATE KEY-----"] * n
        # Wrap each line to count contains calls
        wrapped = [CountingStr(l) for l in lines]
        findings = rule.scan_content("test_keys", wrapped)

        # Should produce n findings (all incomplete)
        assert len(findings) == n
        # All should be blocking
        for f in findings:
            assert f.is_blocking is True
            assert f.snippet_masked == "<PRIVATE_KEY_REDACTED>"
        # contains calls should be O(n), not O(n²)
        # With nested loops it would be ~n²/2. With linear it should be ~2n.
        assert call_count <= n * 10, (
            f"Expected O(n) contains calls, got {call_count} for {n} lines"
        )

    def test_missing_end_still_blocking(self):
        """BEGIN without END still produces a blocking Finding."""
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
        assert "Incomplete" in f.description

    def test_complete_key_body_not_in_output(self):
        """Private key body content NEVER appears in any Finding field."""
        rule = PrivateKeyRule()
        body_content = "MIIEowIBAAKCAQEA" + "D" * 400
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----",
            body_content,
            "-----END RSA PRIVATE KEY-----",
        ]
        findings = rule.scan_content("id_rsa", lines)
        assert len(findings) == 1
        f = findings[0]
        # Body must not appear in any field
        assert body_content not in f.snippet_masked
        assert body_content not in f.description
        assert body_content not in f.message
        assert body_content not in repr(f)
