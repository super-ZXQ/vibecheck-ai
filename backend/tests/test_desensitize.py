"""Tests for the desensitization module (mask_secret + mask_snippet).

ALL test strings are SYNTHETIC -- they have the correct format but NO actual
permissions or validity. No real credentials are used in any test.

Test count: 12
"""

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
    mask_secret,
    mask_snippet,
)


# --- Synthetic test constants (format-correct, NOT real credentials) ---
SYNTH_GITHUB_TOKEN = "ghp_" + "A" * 36
SYNTH_AWS_KEY = "AKIA" + "B" * 16
SYNTH_GOOGLE_KEY = "AIza" + "C" * 35
SYNTH_AWS_SECRET = "D" * 40
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
        assert result == "ghp_...AAAA"
        # Original token must not appear in result
        assert SYNTH_GITHUB_TOKEN not in result

    def test_mask_secret_github_token_short(self):
        """Short key (<=8 chars) is fully redacted."""
        result = mask_secret("ghp_ABCD", GITHUB_TOKEN)
        assert result == "<REDACTED>"

    def test_mask_secret_aws_access_key(self):
        """AWS access key keeps first 4 and last 4 chars."""
        result = mask_secret(SYNTH_AWS_KEY, AWS_ACCESS_KEY)
        assert result == "AKIA...BBBB"
        assert SYNTH_AWS_KEY not in result

    def test_mask_secret_aws_secret_key(self):
        """AWS secret key is fully redacted."""
        result = mask_secret(SYNTH_AWS_SECRET, AWS_SECRET_KEY)
        assert result == "<REDACTED>"

    def test_mask_secret_google_api_key(self):
        """Google API key keeps first 4 and last 4 chars."""
        result = mask_secret(SYNTH_GOOGLE_KEY, GOOGLE_API_KEY)
        assert result == "AIza...CCCC"
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
        assert "ghp_...AAAA" in result

    def test_mask_snippet_multiple_secrets(self):
        """Multiple different secrets in one line are all masked."""
        line = f'token="{SYNTH_GITHUB_TOKEN}" key="{SYNTH_AWS_KEY}"'
        result = mask_snippet(line)
        # Neither original secret should appear
        assert SYNTH_GITHUB_TOKEN not in result
        assert SYNTH_AWS_KEY not in result
        # Both masked versions should be present
        assert "ghp_...AAAA" in result
        assert "AKIA...BBBB" in result

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
