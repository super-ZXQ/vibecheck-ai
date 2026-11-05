"""Unit-test overrides.

The repository-level ``tests/conftest.py`` provisions a PostgreSQL schema for
every test (autouse). Pure analysis/unit tests do not touch the database, so
this package-level override keeps them runnable on machines without PG.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _backend_test_defaults():
    """No-op override: unit tests never need the shared PG fixture."""
    yield
