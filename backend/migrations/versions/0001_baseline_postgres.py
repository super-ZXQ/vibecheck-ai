"""baseline postgres schema

Revision ID: 0001_baseline
Revises:
Create Date: 2026-09-18

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("repo_url", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=False),
        sa.Column("repo_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("stage", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("file_count", sa.Integer(), nullable=True),
        sa.Column("total_size", sa.BigInteger(), nullable=True),
        sa.Column("top_level_dir", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("worker_id", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_category", sa.String(length=64), nullable=True),
        sa.Column("resolved_commit_sha", sa.String(length=64), nullable=True),
        sa.Column("scanner_version", sa.String(length=128), nullable=True),
        sa.Column("deduplication_key", sa.Text(), nullable=True),
        sa.Column("reused_from_task_id", sa.String(length=36), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_tasks_status_next_attempt", "tasks", ["status", "next_attempt_at"])
    op.create_index("idx_tasks_lease_expires", "tasks", ["lease_expires_at"])
    op.create_index("idx_tasks_dedup_key", "tasks", ["deduplication_key"])
    op.create_index("idx_tasks_dedup_status", "tasks", ["deduplication_key", "status"])
    op.create_index("idx_tasks_created", "tasks", ["created_at"])
    op.create_index(
        "uq_tasks_active_dedup",
        "tasks",
        ["deduplication_key"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('pending','running') AND deduplication_key IS NOT NULL"
        ),
    )

    op.create_table(
        "scan_results",
        sa.Column("task_id", sa.String(length=36), sa.ForeignKey("tasks.id"), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("summary_json", sa.Text(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=False),
        sa.Column("blocking_findings", sa.Integer(), nullable=False),
        sa.Column("total_notices", sa.Integer(), nullable=False),
        sa.Column("total_skipped_files", sa.Integer(), nullable=False),
        sa.Column("total_scan_errors", sa.Integer(), nullable=False),
        sa.Column("total_files_scanned", sa.Integer(), nullable=False),
        sa.Column("total_lines_scanned", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "assessment_results",
        sa.Column("task_id", sa.String(length=36), sa.ForeignKey("tasks.id"), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("assessment_scope", sa.String(length=64), nullable=False),
        sa.Column("assessment_json", sa.Text(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("source_scan_updated_at", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_assessment_verdict", "assessment_results", ["verdict"])

    op.create_table(
        "repair_results",
        sa.Column("task_id", sa.String(length=36), sa.ForeignKey("tasks.id"), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("repair_scope", sa.String(length=64), nullable=False),
        sa.Column("repair_json", sa.Text(), nullable=False),
        sa.Column("plan_status", sa.String(length=32), nullable=False),
        sa.Column("total_repair_groups", sa.Integer(), nullable=False),
        sa.Column("blocking_repair_groups", sa.Integer(), nullable=False),
        sa.Column("source_scan_updated_at", sa.Text(), nullable=False),
        sa.Column("source_assessment_updated_at", sa.Text(), nullable=False),
        sa.Column("source_assessment_policy_version", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "llm_analysis_results",
        sa.Column("task_id", sa.String(length=36), sa.ForeignKey("tasks.id"), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("analysis_json", sa.Text(), nullable=False),
        sa.Column("total_analyzed", sa.Integer(), nullable=False),
        sa.Column("total_fallback", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_scan_updated_at", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_llm_analysis_source", "llm_analysis_results", ["source"])


def downgrade() -> None:
    op.drop_table("llm_analysis_results")
    op.drop_table("repair_results")
    op.drop_table("assessment_results")
    op.drop_table("scan_results")
    op.drop_table("tasks")
