"""add quality check results

Revision ID: 0004_quality_results
Revises: 0003_hashed_submitter_key
Create Date: 2026-11-04

The quality report is produced by the default-on ``quality_checks`` stage and
is stored separately from scan results so its conclusions never affect the
security score or verdict.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_quality_results"
down_revision: str | None = "0003_hashed_submitter_key"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "quality_check_results",
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("overall_status", sa.String(length=32), nullable=False),
        sa.Column("block_statuses_json", sa.Text(), nullable=False),
        sa.Column("quality_json", sa.Text(), nullable=False),
        sa.Column("total_items", sa.Integer(), nullable=False),
        sa.Column("manual_items", sa.Integer(), nullable=False),
        sa.Column("fixable_items", sa.Integer(), nullable=False),
        sa.Column("source_scan_updated_at", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("task_id"),
    )


def downgrade() -> None:
    op.drop_table("quality_check_results")
