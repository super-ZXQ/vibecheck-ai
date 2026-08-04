"""Repository archive capacity configuration boundaries."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_default_single_file_limit_supports_common_repository_data_assets(
    monkeypatch,
):
    monkeypatch.delenv("MAX_SINGLE_FILE_SIZE", raising=False)
    configured = Settings(_env_file=None)
    assert configured.max_single_file_size == 25 * 1024 * 1024


def test_single_file_limit_has_a_hard_configuration_ceiling():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, max_single_file_size=50 * 1024 * 1024 + 1)


def test_single_file_limit_accepts_a_smaller_operator_override():
    configured = Settings(_env_file=None, max_single_file_size=10 * 1024 * 1024)
    assert configured.max_single_file_size == 10 * 1024 * 1024
