"""Tests for the desensitization module (mask_secret + mask_snippet).

ALL test strings are SYNTHETIC -- they have the correct format but NO actual
permissions or validity. No real credentials are used in any test.

Test count: 28
"""

import json
import string

import pytest

from app.core.security.desensitize import (
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    CONNECTION_STRING,
    GENERIC,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    PASSWORD,
    PRIVATE_KEY,
    is_already_masked,
    is_env_reference,
    is_low_entropy,
    mask_secret,
    mask_snippet,
    parse_assignment_value,
)


# --- Runtime-constructed mixed-character synthetic values (NOT real credentials) ---
# Built from character pools to avoid hardcoding valid-looking tokens and
# to ensure mixed characters (not low-entropy single-char repeats).
_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
_MIXED_UPPER = "ABCDEF1234567890GHIJKLMNOP"
SYNTH_GITHUB_TOKEN = "ghp_" + _MIXED[:36]
SYNTH_AWS_KEY = "AKIA" + _MIXED_UPPER[:16]
SYNTH_GOOGLE_KEY = "AIza" + _MIXED[:35]
SYNTH_AWS_SECRET = ("AbCdEf1234" * 4)[:40]
SYNTH_PASSWORD = "s3cur3P@ssw0rd!"
SYNTH_CONN_STR = "postgres://user:secretpass@host:5432/db"


# ============================================================================
# --- mask_secret tests (9 tests) ---
# ============================================================================

class TestMaskSecret:
    """Tests for mask_secret function -- single value masking."""

    def test_mask_secret_private_key(self):
        """Private key type always returns <PRIVATE_KEY_REDACTED>."""
        result = mask_secret("some_private_key_content", PRIVATE_KEY)
        assert result == "<PRIVATE_KEY_REDACTED>"

    def test_mask_secret_github_token_long(self):
        """Long GitHub token keeps first 4 and last 4 chars."""
        result = mask_secret(SYNTH_GITHUB_TOKEN, GITHUB_TOKEN)
        assert result == f"ghp_...{SYNTH_GITHUB_TOKEN[-4:]}"
        # Original token must not appear in result
        assert SYNTH_GITHUB_TOKEN not in result

    def test_mask_secret_github_token_short(self):
        """Short key (<=8 chars) is fully redacted."""
        result = mask_secret("ghp_ABCD", GITHUB_TOKEN)
        assert result == "<REDACTED>"

    def test_mask_secret_aws_access_key(self):
        """AWS access key keeps first 4 and last 4 chars."""
        result = mask_secret(SYNTH_AWS_KEY, AWS_ACCESS_KEY)
        assert result == f"AKIA...{SYNTH_AWS_KEY[-4:]}"
        assert SYNTH_AWS_KEY not in result

    def test_mask_secret_aws_secret_key(self):
        """AWS secret key is fully redacted."""
        result = mask_secret(SYNTH_AWS_SECRET, AWS_SECRET_KEY)
        assert result == "<REDACTED>"

    def test_mask_secret_google_api_key(self):
        """Google API key keeps first 4 and last 4 chars."""
        result = mask_secret(SYNTH_GOOGLE_KEY, GOOGLE_API_KEY)
        assert result == f"AIza...{SYNTH_GOOGLE_KEY[-4:]}"
        assert SYNTH_GOOGLE_KEY not in result

    def test_mask_secret_password(self):
        """Password type is fully redacted."""
        result = mask_secret(SYNTH_PASSWORD, PASSWORD)
        assert result == "<REDACTED>"
        assert SYNTH_PASSWORD not in result

    def test_mask_secret_connection_string(self):
        """Connection string password is replaced with ***."""
        result = mask_secret(SYNTH_CONN_STR, CONNECTION_STRING)
        assert "secretpass" not in result
        assert "***" in result
        # Host and scheme should be preserved
        assert "postgres://user:" in result
        assert "@host:5432/db" in result

    def test_mask_secret_generic(self):
        """Generic type is fully redacted."""
        result = mask_secret("some_secret_value", GENERIC)
        assert result == "<REDACTED>"


# ============================================================================
# --- mask_snippet tests (3 tests) ---
# ============================================================================

class TestMaskSnippet:
    """Tests for mask_snippet function -- multi-secret line masking."""

    def test_mask_snippet_single_secret(self):
        """Single GitHub token in a line is masked."""
        line = f'GITHUB_TOKEN = "{SYNTH_GITHUB_TOKEN}"'
        result = mask_snippet(line)
        # The original token must not appear
        assert SYNTH_GITHUB_TOKEN not in result
        # The masked version should be present
        assert f"ghp_...{SYNTH_GITHUB_TOKEN[-4:]}" in result

    def test_mask_snippet_multiple_secrets(self):
        """Multiple different secrets in one line are all masked."""
        line = f'token="{SYNTH_GITHUB_TOKEN}" key="{SYNTH_AWS_KEY}"'
        result = mask_snippet(line)
        # Neither original secret should appear
        assert SYNTH_GITHUB_TOKEN not in result
        assert SYNTH_AWS_KEY not in result
        # Both masked versions should be present
        assert f"ghp_...{SYNTH_GITHUB_TOKEN[-4:]}" in result
        assert f"AKIA...{SYNTH_AWS_KEY[-4:]}" in result

    def test_mask_snippet_idempotent(self):
        """Re-masking an already-masked line does not expose extra chars."""
        original = f'password="{SYNTH_PASSWORD}"'
        masked_once = mask_snippet(original)
        masked_twice = mask_snippet(masked_once)
        # The original password must not appear in either pass
        assert SYNTH_PASSWORD not in masked_once
        assert SYNTH_PASSWORD not in masked_twice
        # Double-masking should be stable (not expose more)
        assert masked_twice == masked_once


# ============================================================================
# --- is_already_masked strict tests (4 tests) ---
# ============================================================================

class TestIsAlreadyMasked:
    """Verify is_already_masked only recognizes EXACT canonical values."""

    def test_exact_redacted_is_masked(self):
        """Exact <REDACTED> is recognized as already masked."""
        assert is_already_masked("<REDACTED>") is True

    def test_exact_private_key_redacted_is_masked(self):
        """Exact <PRIVATE_KEY_REDACTED> is recognized as already masked."""
        assert is_already_masked("<PRIVATE_KEY_REDACTED>") is True

    def test_all_asterisks_is_masked(self):
        """All-asterisk value is recognized as already masked."""
        assert is_already_masked("***") is True
        assert is_already_masked("********") is True

    def test_system_masked_format_is_masked(self):
        """System-generated first4...last4 format is recognized as already masked."""
        assert is_already_masked("ghp_...AAAA") is True

    def test_alpha_dotdotdot_omega_NOT_masked(self):
        """'alpha...omega' is NOT already masked (substring ... check forbidden)."""
        assert is_already_masked("alpha...omega") is False

    def test_abc_asterisk_def_NOT_masked(self):
        """'abc***def' is NOT already masked (substring *** check forbidden)."""
        assert is_already_masked("abc***def") is False

    def test_redacted_in_value_NOT_masked(self):
        """'prefix<REDACTED>suffix' is NOT already masked (substring check forbidden)."""
        assert is_already_masked("prefix<REDACTED>suffix") is False


# ============================================================================
# --- is_env_reference strict tests (4 tests) ---
# ============================================================================

class TestIsEnvReference:
    """Verify is_env_reference uses strict full-match patterns only."""

    def test_dollar_var_is_env_ref(self):
        """$VAR (uppercase) is recognized as env reference."""
        assert is_env_reference("$DB_PASSWORD") is True

    def test_dollar_brace_var_is_env_ref(self):
        """${VAR} is recognized as env reference."""
        assert is_env_reference("${DB_PASSWORD}") is True

    def test_dollar_brace_default_is_env_ref(self):
        """${VAR:-default} is recognized as env reference."""
        assert is_env_reference("${DB_PASSWORD:-default}") is True

    def test_process_env_dot_is_env_ref(self):
        """process.env.NAME is recognized as env reference."""
        assert is_env_reference("process.env.DB_PASSWORD") is True

    def test_os_environ_is_env_ref(self):
        """os.environ["NAME"] is recognized as env reference."""
        assert is_env_reference('os.environ["DB_PASSWORD"]') is True

    def test_os_getenv_is_env_ref(self):
        """os.getenv("NAME") is recognized as env reference."""
        assert is_env_reference('os.getenv("DB_PASSWORD")') is True

    def test_dollar_lowercase_NOT_env_ref(self):
        """'$uperSecret123' is NOT an env reference (lowercase after $)."""
        assert is_env_reference("$uperSecret123") is False

    def test_os_dot_supersecret_NOT_env_ref(self):
        """'os.supersecret' is NOT an env reference (not os.environ/getenv)."""
        assert is_env_reference("os.supersecret") is False

    def test_process_environmentSecret_NOT_env_ref(self):
        """'process.environmentSecret' is NOT an env reference."""
        assert is_env_reference("process.environmentSecret") is False

    def test_quoted_value_NOT_env_ref(self):
        """Quoted values are NEVER env references (they are literal strings)."""
        assert is_env_reference("$DB_PASSWORD", is_quoted=True) is False
        assert is_env_reference("${VAR}", is_quoted=True) is False


# ============================================================================
# --- is_low_entropy tests (2 tests) ---
# ============================================================================

class TestIsLowEntropy:
    """Verify is_low_entropy detects repetitive placeholder bodies."""

    def test_repeated_char_is_low_entropy(self):
        """All-same-character body is low-entropy."""
        assert is_low_entropy("ghp_" + "X" * 36, prefix_len=4) is True

    def test_mixed_char_NOT_low_entropy(self):
        """Mixed-character body is NOT low-entropy."""
        assert is_low_entropy(SYNTH_GITHUB_TOKEN, prefix_len=4) is False


# ============================================================================
# --- parse_assignment_value tests (5 tests) ---
# ============================================================================

class TestParseAssignmentValue:
    """Tests for the unified assignment value parser."""

    def test_unquoted_value_with_hash(self):
        """Unquoted value with # is NOT split -- full value including # returned."""
        line = "password=alpha#omega"
        result = parse_assignment_value(line, 8)
        assert result is not None
        value_start, value_end, value, is_quoted = result
        assert value == "alpha#omega"
        assert is_quoted is False

    def test_unquoted_value_with_hash_token(self):
        """Unquoted token value with # is NOT split."""
        line = "token=abc#def"
        result = parse_assignment_value(line, 5)
        assert result is not None
        value_start, value_end, value, is_quoted = result
        assert value == "abc#def"
        assert is_quoted is False

    def test_json_double_quoted_key(self):
        """JSON-style "key": "value" is parsed correctly."""
        line = '"password": "alpha beta gamma"'
        # Key "password" starts at pos 1, ends at pos 9
        result = parse_assignment_value(line, 9)
        assert result is not None
        value_start, value_end, value, is_quoted = result
        assert value == "alpha beta gamma"
        assert is_quoted is True

    def test_toml_single_quoted_key(self):
        """TOML-style 'key': 'value' is parsed correctly."""
        line = "'token': 'abc def ghi'"
        # Key 'token' starts at pos 1, ends at pos 6
        result = parse_assignment_value(line, 6)
        assert result is not None
        value_start, value_end, value, is_quoted = result
        assert value == "abc def ghi"
        assert is_quoted is True

    def test_quoted_key_with_equals(self):
        """Quoted key with = operator: "api_key" = "some value"."""
        line = '"api_key" = "some value"'
        # Key "api_key" starts at pos 1, ends at pos 8
        result = parse_assignment_value(line, 8)
        assert result is not None
        value_start, value_end, value, is_quoted = result
        assert value == "some value"
        assert is_quoted is True


# ============================================================================
# --- mask_snippet escape prevention tests (5 tests) ---
# ============================================================================

class TestMaskSnippetEscapePrevention:
    """Verify mask_snippet does not let secrets escape through various tricks."""

    def test_alpha_dotdotdot_omega_masked(self):
        """password='alpha...omega' is masked -- ... substring doesn't bypass."""
        line = 'password="alpha...omega"'
        result = mask_snippet(line)
        assert "alpha" not in result
        assert "omega" not in result
        assert "<REDACTED>" in result

    def test_abc_asterisk_def_masked(self):
        """password='abc***def' is masked -- *** substring doesn't bypass."""
        line = 'password="abc***def"'
        result = mask_snippet(line)
        assert "abc" not in result
        assert "def" not in result
        assert "<REDACTED>" in result

    def test_os_supersecret_masked(self):
        """password='os.supersecret' is masked -- os. prefix doesn't bypass."""
        line = 'password="os.supersecret"'
        result = mask_snippet(line)
        assert "os.supersecret" not in result
        assert "supersecret" not in result
        assert "<REDACTED>" in result

    def test_process_environmentSecret_masked(self):
        """password='process.environmentSecret' is masked."""
        line = 'password="process.environmentSecret"'
        result = mask_snippet(line)
        assert "process.environmentSecret" not in result
        assert "environmentSecret" not in result
        assert "<REDACTED>" in result

    def test_unquoted_hash_value_masked(self):
        """password=alpha#omega -- full value including # is masked."""
        line = "password=alpha#omega"
        result = mask_snippet(line)
        assert "alpha" not in result
        assert "omega" not in result
        assert "<REDACTED>" in result

    def test_same_line_two_secrets_both_masked(self):
        """token='<format>' password='os.supersecret' -- both masked."""
        line = f'token="{SYNTH_GITHUB_TOKEN}" password="os.supersecret"'
        result = mask_snippet(line)
        assert SYNTH_GITHUB_TOKEN not in result
        assert "os.supersecret" not in result
        assert "supersecret" not in result
