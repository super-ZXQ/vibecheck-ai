"""tasks.submitter_key: anonymous per-submitter task ownership

Revision ID: 0002_submitter_key
Revises: 0001_baseline
Create Date: 2026-11-03

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_submitter_key"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tasks",
        sa.Column("submitter_key", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tasks", "submitter_key")
