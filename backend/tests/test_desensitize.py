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
    CATEGORY_AWS_SECRET,
    CATEGORY_PASSWORD,
    CATEGORY_SECRET,
    CONNECTION_STRING,
    GENERIC,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    PASSWORD,
    PRIVATE_KEY,
    classify_key,
    is_already_masked,
    is_env_reference,
    is_low_entropy,
    iter_assignments,
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
        """Single GitHub token in a line is masked.

        With phased masking, GITHUB_TOKEN is classified as sensitive
        (CATEGORY_SECRET), so Phase 1 masks the value with <REDACTED>.
        The original token must not appear in the result.
        """
        line = f'GITHUB_TOKEN = "{SYNTH_GITHUB_TOKEN}"'
        result = mask_snippet(line)
        # The original token must not appear
        assert SYNTH_GITHUB_TOKEN not in result
        # The value is masked as <REDACTED> (sensitive assignment)
        assert "<REDACTED>" in result

    def test_mask_snippet_multiple_secrets(self):
        """Multiple different secrets in one line are all masked.

        With phased masking:
        - 'token' is classified as sensitive → Phase 1 masks with <REDACTED>
        - 'key' is NOT classified as sensitive → Phase 2 catches AKIA format
          and masks with first4...last4 format
        """
        line = f'token="{SYNTH_GITHUB_TOKEN}" key="{SYNTH_AWS_KEY}"'
        result = mask_snippet(line)
        # Neither original secret should appear
        assert SYNTH_GITHUB_TOKEN not in result
        assert SYNTH_AWS_KEY not in result
        # Token value masked as <REDACTED> (sensitive assignment, Phase 1)
        assert "<REDACTED>" in result
        # AWS key masked with first4...last4 format (Phase 2 explicit format)
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
        value_start, value_end, value, is_quoted, operator = result
        assert value == "alpha#omega"
        assert is_quoted is False
        assert operator == "="

    def test_unquoted_value_with_hash_token(self):
        """Unquoted token value with # is NOT split."""
        line = "token=abc#def"
        result = parse_assignment_value(line, 5)
        assert result is not None
        value_start, value_end, value, is_quoted, operator = result
        assert value == "abc#def"
        assert is_quoted is False
        assert operator == "="

    def test_json_double_quoted_key(self):
        """JSON-style "key": "value" is parsed correctly with colon operator."""
        line = '"password": "alpha beta gamma"'
        # Key "password" starts at pos 1, ends at pos 9 (closing quote)
        result = parse_assignment_value(line, 9, is_quoted_key=True)
        assert result is not None
        value_start, value_end, value, is_quoted, operator = result
        assert value == "alpha beta gamma"
        assert is_quoted is True
        assert operator == ":"

    def test_toml_single_quoted_key(self):
        """TOML-style 'key': 'value' is parsed correctly with colon operator."""
        line = "'token': 'abc def ghi'"
        # Key 'token' starts at pos 1, ends at pos 6 (closing quote)
        result = parse_assignment_value(line, 6, is_quoted_key=True)
        assert result is not None
        value_start, value_end, value, is_quoted, operator = result
        assert value == "abc def ghi"
        assert is_quoted is True
        assert operator == ":"

    def test_quoted_key_with_equals(self):
        """Quoted key with = operator: "api_key" = "some value"."""
        line = '"api_key" = "some value"'
        # Key "api_key" starts at pos 1, ends at pos 8 (closing quote)
        result = parse_assignment_value(line, 8, is_quoted_key=True)
        assert result is not None
        value_start, value_end, value, is_quoted, operator = result
        assert value == "some value"
        assert is_quoted is True
        assert operator == "="


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


# ============================================================================
# --- Compound key classification tests (classify_key) ---
# ============================================================================

class TestCompoundKeyClassification:
    """Verify classify_key correctly identifies compound sensitive keys
    and rejects non-sensitive compound names using segment matching."""

    # --- Password category (R006) ---
    def test_password_classified(self):
        assert classify_key("password") == CATEGORY_PASSWORD

    def test_db_password_classified(self):
        assert classify_key("DB_PASSWORD") == CATEGORY_PASSWORD

    def test_database_password_classified(self):
        assert classify_key("DATABASE_PASSWORD") == CATEGORY_PASSWORD

    def test_mysql_pwd_classified(self):
        assert classify_key("MYSQL_PWD") == CATEGORY_PASSWORD

    def test_admin_passwd_classified(self):
        assert classify_key("ADMIN_PASSWD") == CATEGORY_PASSWORD

    def test_camelcase_dbPassword_classified(self):
        """camelCase dbPassword splits to [DB, PASSWORD] -> password."""
        assert classify_key("dbPassword") == CATEGORY_PASSWORD

    def test_dotted_db_password_classified(self):
        """db.password splits to [DB, PASSWORD] -> password."""
        assert classify_key("db.password") == CATEGORY_PASSWORD

    # --- Secret category (R007) ---
    def test_secret_classified(self):
        assert classify_key("secret") == CATEGORY_SECRET

    def test_jwt_secret_classified(self):
        assert classify_key("JWT_SECRET") == CATEGORY_SECRET

    def test_client_secret_classified(self):
        assert classify_key("CLIENT_SECRET") == CATEGORY_SECRET

    def test_token_classified(self):
        assert classify_key("token") == CATEGORY_SECRET

    def test_access_token_classified(self):
        assert classify_key("ACCESS_TOKEN") == CATEGORY_SECRET

    def test_github_token_classified(self):
        assert classify_key("GITHUB_TOKEN") == CATEGORY_SECRET

    def test_api_key_classified(self):
        assert classify_key("api_key") == CATEGORY_SECRET

    def test_my_api_key_classified(self):
        assert classify_key("MY_API_KEY") == CATEGORY_SECRET

    def test_openai_api_key_classified(self):
        assert classify_key("OPENAI_API_KEY") == CATEGORY_SECRET

    def test_camelcase_apiKey_classified(self):
        """camelCase apiKey splits to [API, KEY] -> secret via pair."""
        assert classify_key("apiKey") == CATEGORY_SECRET

    # --- AWS secret category (R003) ---
    def test_aws_secret_access_key_classified(self):
        assert classify_key("AWS_SECRET_ACCESS_KEY") == CATEGORY_AWS_SECRET

    def test_secret_access_key_classified(self):
        assert classify_key("SECRET_ACCESS_KEY") == CATEGORY_AWS_SECRET

    def test_aws_secret_classified(self):
        assert classify_key("AWS_SECRET") == CATEGORY_AWS_SECRET

    # --- Non-sensitive compound names (must return None) ---
    def test_secretary_email_not_classified(self):
        assert classify_key("SECRETARY_EMAIL") is None

    def test_tokenizer_model_not_classified(self):
        assert classify_key("TOKENIZER_MODEL") is None

    def test_passwordless_mode_not_classified(self):
        assert classify_key("PASSWORDLESS_MODE") is None

    def test_api_keyboard_layout_not_classified(self):
        assert classify_key("API_KEYBOARD_LAYOUT") is None

    def test_access_tokenizer_not_classified(self):
        assert classify_key("ACCESS_TOKENIZER") is None


# ============================================================================
# --- iter_assignments compound key tests ---
# ============================================================================

class TestIterAssignmentsCompound:
    """Verify iter_assignments correctly parses compound keys and edge cases."""

    def test_simple_unquoted_key(self):
        """password = "value" yields one assignment."""
        line = 'password = "value"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "password"
        assert assignments[0].value == "value"
        assert assignments[0].is_quoted is True

    def test_compound_uppercase_key(self):
        """DB_PASSWORD = "value" yields one assignment."""
        line = 'DB_PASSWORD = "value"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "DB_PASSWORD"
        assert assignments[0].value == "value"

    def test_const_prefix_keyword_skipped(self):
        """const OPENAI_API_KEY = "v" -- const has no =, skipped; key is OPENAI_API_KEY."""
        line = 'const OPENAI_API_KEY = "v"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "OPENAI_API_KEY"
        assert assignments[0].value == "v"

    def test_json_double_quoted_key(self):
        """"api_key": "value" yields one assignment."""
        line = '"api_key": "value"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "api_key"
        assert assignments[0].value == "value"

    def test_toml_single_quoted_key(self):
        """'jwt_secret' = 'value' yields one assignment."""
        line = "'jwt_secret' = 'value'"
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "jwt_secret"
        assert assignments[0].value == "value"

    def test_multiple_assignments_same_line(self):
        """password="a" token="b" yields two assignments."""
        line = 'password="a" token="b"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 2
        assert assignments[0].key_raw == "password"
        assert assignments[0].value == "a"
        assert assignments[1].key_raw == "token"
        assert assignments[1].value == "b"

    def test_env_ref_in_value_not_re_scanned(self):
        """unrelated=${DB_PASSWORD:-default} -- DB_PASSWORD inside value is NOT a second key."""
        line = "unrelated=${DB_PASSWORD:-default}"
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "unrelated"
        assert assignments[0].value == "${DB_PASSWORD:-default}"

    def test_password_env_ref_single_assignment(self):
        """password=${DB_PASSWORD:-default} -- only one assignment, no false key."""
        line = "password=${DB_PASSWORD:-default}"
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "password"
        assert assignments[0].value == "${DB_PASSWORD:-default}"

    def test_quoted_value_content_not_re_scanned(self):
        """Quoted value containing key-like text is NOT parsed as a second key."""
        line = 'unrelated="password=evil"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "unrelated"
        assert assignments[0].value == "password=evil"

    def test_key_normalized_field(self):
        """Assignment.key_normalized is uppercase with _ separators."""
        line = 'dbPassword = "val"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        assert assignments[0].key_normalized == "DB_PASSWORD"


# ============================================================================
# --- Operator distinction tests (parse_assignment_value) ---
# ============================================================================

class TestOperatorDistinction:
    """Verify parse_assignment_value strictly distinguishes assignment operators
    from comparison, walrus, and arrow operators."""

    def test_unquoted_single_equals_accepted(self):
        """password = "value" -- single = is accepted for unquoted key."""
        line = 'password = "hardcoded value"'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is not None
        _, _, value, _, operator = result
        assert value == "hardcoded value"
        assert operator == "="

    def test_unquoted_no_space_equals_accepted(self):
        """password="value" -- single = without space is accepted."""
        line = 'password="hardcoded value"'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is not None
        _, _, value, _, operator = result
        assert value == "hardcoded value"
        assert operator == "="

    def test_double_equals_rejected(self):
        """password == "admin" -- == is rejected (comparison)."""
        line = 'password == "admin"'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is None

    def test_not_equal_rejected(self):
        """password != "admin" -- != is rejected (starts with !)."""
        line = 'password != "admin"'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is None

    def test_greater_equal_rejected(self):
        """password >= "admin" -- >= is rejected (starts with >)."""
        line = 'password >= "admin"'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is None

    def test_less_equal_rejected(self):
        """password <= "admin" -- <= is rejected (starts with <)."""
        line = 'password <= "admin"'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is None

    def test_walrus_operator_rejected_unquoted(self):
        """password := get_password() -- := rejected for unquoted key."""
        line = 'password := get_password()'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is None

    def test_walrus_operator_rejected_quoted(self):
        """'password' := get_password() -- := rejected even for quoted key."""
        line = "'password' := get_password()"
        result = parse_assignment_value(line, 10, is_quoted_key=True)
        assert result is None

    def test_arrow_operator_rejected(self):
        """password => "value" -- => is rejected (arrow)."""
        line = 'password => "value"'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is None

    def test_unquoted_colon_rejected(self):
        """password: str -- colon rejected for unquoted key (type annotation)."""
        line = 'password: str'
        result = parse_assignment_value(line, 8, is_quoted_key=False)
        assert result is None

    def test_quoted_colon_accepted(self):
        """'password': 'value' -- colon accepted for quoted key (TOML)."""
        line = "'password': 'hardcoded value'"
        result = parse_assignment_value(line, 10, is_quoted_key=True)
        assert result is not None
        _, _, value, _, operator = result
        assert value == "hardcoded value"
        assert operator == ":"

    def test_quoted_double_colon_accepted(self):
        """"password": "value" -- colon accepted for quoted key (JSON)."""
        line = '"password": "hardcoded value"'
        result = parse_assignment_value(line, 10, is_quoted_key=True)
        assert result is not None
        _, _, value, _, operator = result
        assert value == "hardcoded value"
        assert operator == ":"


# ============================================================================
# --- Operator distinction via iter_assignments (end-to-end) ---
# ============================================================================

class TestIterAssignmentsOperatorRejection:
    """Verify iter_assignments does not yield assignments for non-assignment syntax."""

    def test_password_colon_str_no_assignment(self):
        """password: str produces NO assignment (type annotation)."""
        assignments = list(iter_assignments("password: str"))
        assert len(assignments) == 0

    def test_token_colon_optional_no_assignment(self):
        """token: Optional[str] produces NO assignment."""
        assignments = list(iter_assignments("token: Optional[str]"))
        assert len(assignments) == 0

    def test_def_login_password_colon_str_no_assignment(self):
        """def login(password: str): produces NO assignment."""
        assignments = list(iter_assignments("def login(password: str):"))
        assert len(assignments) == 0

    def test_double_equals_no_assignment(self):
        """password == "admin" produces NO assignment (comparison)."""
        assignments = list(iter_assignments('password == "admin"'))
        assert len(assignments) == 0

    def test_walrus_no_assignment(self):
        """password := get_password() produces NO assignment."""
        assignments = list(iter_assignments("password := get_password()"))
        assert len(assignments) == 0

    def test_quoted_colon_produces_assignment(self):
        """"password": "hardcoded value" produces one assignment."""
        assignments = list(iter_assignments('"password": "hardcoded value"'))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "password"
        assert assignments[0].value == "hardcoded value"
        assert assignments[0].operator == ":"

    def test_quoted_single_colon_produces_assignment(self):
        """'api_key': 'hardcoded value' produces one assignment."""
        assignments = list(iter_assignments("'api_key': 'hardcoded value'"))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "api_key"
        assert assignments[0].value == "hardcoded value"
        assert assignments[0].operator == ":"

    def test_unquoted_equals_produces_assignment(self):
        """password="hardcoded value" produces one assignment."""
        assignments = list(iter_assignments('password="hardcoded value"'))
        assert len(assignments) == 1
        assert assignments[0].key_raw == "password"
        assert assignments[0].value == "hardcoded value"
        assert assignments[0].operator == "="


# ============================================================================
# --- AWS name tightening tests (classify_key) ---
# ============================================================================

class TestAWSNameTightening:
    """Verify classify_key uses exact normalized names for AWS, not broad sets."""

    def test_aws_client_secret_not_aws_category(self):
        """AWS_CLIENT_SECRET is NOT CATEGORY_AWS_SECRET (may be SECRET)."""
        assert classify_key("AWS_CLIENT_SECRET") != CATEGORY_AWS_SECRET

    def test_my_secret_access_key_backup_not_aws_category(self):
        """MY_SECRET_ACCESS_KEY_BACKUP is NOT CATEGORY_AWS_SECRET."""
        assert classify_key("MY_SECRET_ACCESS_KEY_BACKUP") != CATEGORY_AWS_SECRET

    def test_secret_database_access_key_not_aws_category(self):
        """SECRET_DATABASE_ACCESS_KEY is NOT CATEGORY_AWS_SECRET."""
        assert classify_key("SECRET_DATABASE_ACCESS_KEY") != CATEGORY_AWS_SECRET

    def test_aws_secret_access_key_exact_match(self):
        """AWS_SECRET_ACCESS_KEY IS CATEGORY_AWS_SECRET (exact match)."""
        assert classify_key("AWS_SECRET_ACCESS_KEY") == CATEGORY_AWS_SECRET

    def test_secret_access_key_exact_match(self):
        """SECRET_ACCESS_KEY IS CATEGORY_AWS_SECRET (exact match)."""
        assert classify_key("SECRET_ACCESS_KEY") == CATEGORY_AWS_SECRET

    def test_aws_secret_exact_match(self):
        """AWS_SECRET IS CATEGORY_AWS_SECRET (exact match)."""
        assert classify_key("AWS_SECRET") == CATEGORY_AWS_SECRET


# ============================================================================
# --- mask_snippet conservative masking (env ref still masked) ---
# ============================================================================

class TestMaskSnippetConservativeEnvRef:
    """Verify mask_snippet masks env references for sensitive keys (display safety)."""

    def test_github_token_and_password_env_ref_both_masked(self):
        """GITHUB_TOKEN='<token>' password=${DB_PASSWORD} -- both masked."""
        line = f'GITHUB_TOKEN="{SYNTH_GITHUB_TOKEN}" password=${{DB_PASSWORD}}'
        result = mask_snippet(line)
        # Token must not appear
        assert SYNTH_GITHUB_TOKEN not in result
        # Env ref must also not appear (masked by display safety layer)
        assert "${DB_PASSWORD}" not in result
        assert "DB_PASSWORD" not in result

    def test_password_env_ref_masked_in_snippet(self):
        """password=${DB_PASSWORD} -- value masked even though it's an env ref."""
        line = "password=${DB_PASSWORD}"
        result = mask_snippet(line)
        assert "${DB_PASSWORD}" not in result
        assert "DB_PASSWORD" not in result
        assert "<REDACTED>" in result


# ============================================================================
# --- Assignment repr protection tests (5 tests) ---
# ============================================================================

class TestAssignmentReprProtection:
    """Verify Assignment never exposes key_raw, key_normalized, or value.

    Uses a runtime-constructed variable name containing a format-correct
    synthetic GitHub token (PASSWORD_<token>) to simulate a malicious
    repository embedding a token in a variable name. This tests that
    repr, logging, exceptions, and asdict never leak the token through
    the key itself.

    SECURITY: Assignment is a NON-dataclass. dataclasses.asdict(assignment)
    must raise TypeError, preventing accidental serialization of sensitive
    fields.
    """

    _SECRET_VALUE = "super_secret_value_12345"
    # Malicious variable name: PASSWORD_ + format-correct synthetic token
    _MALICIOUS_KEY = f"PASSWORD_{SYNTH_GITHUB_TOKEN}"

    def _make_assignment(self) -> "Assignment":
        from app.core.security.desensitize import Assignment
        return Assignment(
            key_raw=self._MALICIOUS_KEY,
            key_normalized=self._MALICIOUS_KEY.upper(),
            value_start=10,
            value_end=30,
            value=self._SECRET_VALUE,
            is_quoted=True,
            operator="=",
        )

    def test_repr_excludes_raw_value_and_keys(self):
        """repr(Assignment) must NOT contain key_raw, key_normalized, or value.

        Only value_start, value_end, is_quoted, and operator are shown.
        """
        a = self._make_assignment()
        r = repr(a)
        # value must not appear
        assert self._SECRET_VALUE not in r
        # key_raw must not appear (contains synthetic token)
        assert self._MALICIOUS_KEY not in r
        assert SYNTH_GITHUB_TOKEN not in r
        # key_normalized must not appear
        assert self._MALICIOUS_KEY.upper() not in r
        # Only safe metadata fields should be present
        assert "value_start=" in r
        assert "value_end=" in r
        assert "is_quoted=" in r
        assert "operator=" in r

    def test_logging_excludes_raw_value_and_keys(self, caplog):
        """logging output of Assignment must NOT contain value or keys."""
        import logging
        a = self._make_assignment()
        logger = logging.getLogger("test_assignment")
        with caplog.at_level(logging.DEBUG, logger="test_assignment"):
            logger.info("Assignment: %r", a)
        assert self._SECRET_VALUE not in caplog.text
        assert self._MALICIOUS_KEY not in caplog.text
        assert SYNTH_GITHUB_TOKEN not in caplog.text

    def test_exception_excludes_raw_value_and_keys(self):
        """Exception carrying Assignment must NOT contain value or keys in str."""
        a = self._make_assignment()
        try:
            raise ValueError(f"Bad assignment: {a!r}")
        except ValueError as e:
            assert self._SECRET_VALUE not in str(e)
            assert self._MALICIOUS_KEY not in str(e)
            assert SYNTH_GITHUB_TOKEN not in str(e)

    def test_asdict_raises_type_error(self):
        """dataclasses.asdict(assignment) raises TypeError (non-dataclass).

        Assignment is intentionally NOT a dataclass. This prevents accidental
        leakage of key_raw, key_normalized, and value through dict
        serialization. This test MUST actually call dataclasses.asdict.
        """
        import dataclasses as _dc
        a = self._make_assignment()
        with pytest.raises(TypeError):
            _dc.asdict(a)

    def test_assignment_is_read_only(self):
        """Assignment attributes cannot be modified after creation."""
        a = self._make_assignment()
        with pytest.raises(AttributeError):
            a.value = "tampered"
        with pytest.raises(AttributeError):
            a.key_raw = "tampered"


# ============================================================================
# --- Low-entropy short-period detection tests (5 tests) ---
# ============================================================================

class TestLowEntropyShortPeriod:
    """Verify is_low_entropy detects short-period repetition patterns."""

    def test_period_2_abab_detected(self):
        """ABAB pattern (period 2) is low-entropy."""
        assert is_low_entropy("ghp_" + "AB" * 18, prefix_len=4) is True

    def test_period_4_abcdabcd_detected(self):
        """ABCDABCD pattern (period 4) is low-entropy."""
        assert is_low_entropy("ghp_" + "ABCD" * 9, prefix_len=4) is True

    def test_period_3_abcabc_detected(self):
        """ABCABC pattern (period 3) is low-entropy."""
        assert is_low_entropy("ghp_" + "ABC" * 12, prefix_len=4) is True

    def test_period_4_numeric_repeat_detected(self):
        """12341234 pattern (period 4) is low-entropy."""
        assert is_low_entropy("ghp_" + "1234" * 9, prefix_len=4) is True

    def test_mixed_random_not_low_entropy(self):
        """Random mixed characters are NOT low-entropy."""
        assert is_low_entropy(SYNTH_GITHUB_TOKEN, prefix_len=4) is False


# ============================================================================
# --- Unquoted compound key parsing tests (5 tests) ---
# ============================================================================

class TestUnquotedCompoundKeys:
    """Verify iter_assignments parses hyphen/dot compound keys correctly."""

    def test_hyphen_compound_key_parsed(self):
        """my-api-key = "value" is parsed as a single key."""
        line = 'my-api-key = "hardcoded value"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        a = assignments[0]
        assert a.key_raw == "my-api-key"
        assert a.value == "hardcoded value"
        assert a.operator == "="

    def test_dot_compound_key_parsed(self):
        """openai.api.key = "value" is parsed as a single key."""
        line = 'openai.api.key = "hardcoded value"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        a = assignments[0]
        assert a.key_raw == "openai.api.key"
        assert a.value == "hardcoded value"

    def test_db_password_dot_parsed(self):
        """db.password = "value" is parsed as a single key."""
        line = 'db.password = "hardcoded value"'
        assignments = list(iter_assignments(line))
        assert len(assignments) == 1
        a = assignments[0]
        assert a.key_raw == "db.password"
        assert a.value == "hardcoded value"

    def test_hyphen_key_classified_as_secret(self):
        """my-api-key is classified as CATEGORY_SECRET."""
        assert classify_key("my-api-key") == CATEGORY_SECRET

    def test_dot_key_classified_as_secret(self):
        """openai.api.key is classified as CATEGORY_SECRET."""
        assert classify_key("openai.api.key") == CATEGORY_SECRET


# ============================================================================
# --- mask_untrusted_text tests (6 tests) ---
# ============================================================================

class TestMaskUntrustedText:
    """Verify mask_untrusted_text sanitizes explicit-format secrets in paths.

    File names and directory names are untrusted input — they may embed
    format-correct secrets. mask_untrusted_text masks these without
    relying on key=value semantics.
    """

    def test_plain_path_unchanged(self):
        """Plain POSIX path without secrets is returned unchanged."""
        from app.core.security.desensitize import mask_untrusted_text
        result = mask_untrusted_text("src/config/settings.py")
        assert result == "src/config/settings.py"

    def test_filename_with_github_token_masked(self):
        """Filename containing a synthetic GitHub token is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        path = f"src/{SYNTH_GITHUB_TOKEN}.py"
        result = mask_untrusted_text(path)
        assert SYNTH_GITHUB_TOKEN not in result
        # Masked version should contain the prefix and ... indicator
        assert "ghp_" in result
        assert "..." in result

    def test_directory_with_aws_key_masked(self):
        """Directory name containing a synthetic AWS access key is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        path = f"configs/{SYNTH_AWS_KEY}/settings.py"
        result = mask_untrusted_text(path)
        assert SYNTH_AWS_KEY not in result
        assert "AKIA" in result
        assert "..." in result

    def test_google_api_key_masked(self):
        """Google API key in path is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        path = f"keys/{SYNTH_GOOGLE_KEY}.json"
        result = mask_untrusted_text(path)
        assert SYNTH_GOOGLE_KEY not in result

    def test_connection_string_masked(self):
        """Connection string in path is masked."""
        from app.core.security.desensitize import mask_untrusted_text
        path = f"db/{SYNTH_CONN_STR}"
        result = mask_untrusted_text(path)
        assert "secretpass" not in result
        assert "***" in result

    def test_empty_string_unchanged(self):
        """Empty string is returned as-is."""
        from app.core.security.desensitize import mask_untrusted_text
        assert mask_untrusted_text("") == ""
