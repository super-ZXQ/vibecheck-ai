"""SQLAlchemy 2 ORM models for PostgreSQL.

Behavior contract from the SQLite era is preserved:
- Task statuses: pending/running/completed/failed/cancelled/dead
- Lease, heartbeat, attempt, dedup, cancel fields
- Result tables store only desensitized JSON snapshots
- BYOK API keys are NEVER columns
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.db.base import Base

# Use JSONB on PostgreSQL, generic JSON elsewhere (aiosqlite unit tests).
JSONType = JSON().with_variant(JSONB, "postgresql")


def utc_now_sql() -> Any:
    return text("NOW() AT TIME ZONE 'utc'")


class TaskRow(Base):
    __tablename__ = "tasks"
    __table_args__ = (
        Index("idx_tasks_status_next_attempt", "status", "next_attempt_at"),
        Index("idx_tasks_lease_expires", "lease_expires_at"),
        Index("idx_tasks_dedup_key", "deduplication_key"),
        Index("idx_tasks_dedup_status", "deduplication_key", "status"),
        Index("idx_tasks_created", "created_at"),
        # Partial uniqueness for active GitHub tasks with a dedup key.
        Index(
            "uq_tasks_active_dedup",
            "deduplication_key",
            unique=True,
            postgresql_where=text(
                "status IN ('pending','running') AND deduplication_key IS NOT NULL"
            ),
            sqlite_where=text(
                "status IN ('pending','running') AND deduplication_key IS NOT NULL"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repo_url: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    repo_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    file_count: Mapped[int | None] = mapped_column(Integer)
    total_size: Mapped[int | None] = mapped_column(BigInteger)
    top_level_dir: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    worker_id: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_category: Mapped[str | None] = mapped_column(String(64))
    resolved_commit_sha: Mapped[str | None] = mapped_column(String(64))
    scanner_version: Mapped[str | None] = mapped_column(String(128))
    deduplication_key: Mapped[str | None] = mapped_column(Text)
    reused_from_task_id: Mapped[str | None] = mapped_column(String(36))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanResultRow(Base):
    __tablename__ = "scan_results"

    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tasks.id"), primary_key=True
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    result_json: Mapped[Any] = mapped_column(Text, nullable=False)
    summary_json: Mapped[Any] = mapped_column(Text)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False)
    blocking_findings: Mapped[int] = mapped_column(Integer, nullable=False)
    total_notices: Mapped[int] = mapped_column(Integer, nullable=False)
    total_skipped_files: Mapped[int] = mapped_column(Integer, nullable=False)
    total_scan_errors: Mapped[int] = mapped_column(Integer, nullable=False)
    total_files_scanned: Mapped[int] = mapped_column(Integer, nullable=False)
    total_lines_scanned: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AssessmentResultRow(Base):
    __tablename__ = "assessment_results"
    __table_args__ = (Index("idx_assessment_verdict", "verdict"),)

    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tasks.id"), primary_key=True
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_scope: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_json: Mapped[Any] = mapped_column(Text, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    source_scan_updated_at: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RepairResultRow(Base):
    __tablename__ = "repair_results"

    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tasks.id"), primary_key=True
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    repair_scope: Mapped[str] = mapped_column(String(64), nullable=False)
    repair_json: Mapped[Any] = mapped_column(Text, nullable=False)
    plan_status: Mapped[str] = mapped_column(String(32), nullable=False)
    total_repair_groups: Mapped[int] = mapped_column(Integer, nullable=False)
    blocking_repair_groups: Mapped[int] = mapped_column(Integer, nullable=False)
    source_scan_updated_at: Mapped[str] = mapped_column(Text, nullable=False)
    source_assessment_updated_at: Mapped[str] = mapped_column(Text, nullable=False)
    source_assessment_policy_version: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LlmAnalysisResultRow(Base):
    __tablename__ = "llm_analysis_results"
    __table_args__ = (Index("idx_llm_analysis_source", "source"),)

    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tasks.id"), primary_key=True
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    analysis_json: Mapped[Any] = mapped_column(Text, nullable=False)
    total_analyzed: Mapped[int] = mapped_column(Integer, nullable=False)
    total_fallback: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_scan_updated_at: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# Silence unused import warnings for type checkers that need Boolean.
_ = (Boolean,)
