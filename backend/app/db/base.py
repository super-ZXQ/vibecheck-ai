"""SQLAlchemy 2.x declarative base and table metadata."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all VibeCheck ORM models."""
