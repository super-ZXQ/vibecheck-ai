"""hash submitter keys at rest

Revision ID: 0003_hashed_submitter_key
Revises: 0002_submitter_key
Create Date: 2026-11-03

Replaces every stored plaintext X-Submitter-Key with its SHA-256 digest, and
rewrites active coalescing keys because their last segment embeds the same
value. Browsers keep access unchanged: the server hashes the header it
receives before comparing. The transformation is one-way, so downgrade cannot
restore the raw keys.
"""
from typing import Sequence, Union

import hashlib

import sqlalchemy as sa
from alembic import op

revision: str = "0003_hashed_submitter_key"
down_revision: Union[str, None] = "0002_submitter_key"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Must match app/core/task_access.py::_KEY_HASH_PREFIX.
_HASH_PREFIX = b"vibecheck-submitter-key:v1:"


def _digest(key: str) -> str:
    return hashlib.sha256(_HASH_PREFIX + key.encode("utf-8")).hexdigest()


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT id, submitter_key, deduplication_key FROM tasks "
            "WHERE submitter_key IS NOT NULL"
        )
    ).fetchall()
    for task_id, raw_key, dedup_key in rows:
        digest = _digest(raw_key)
        new_dedup = dedup_key
        if dedup_key:
            prefix, separator, scope = dedup_key.rpartition("|")
            if separator and scope == raw_key:
                new_dedup = f"{prefix}|{digest}"
        conn.execute(
            sa.text(
                "UPDATE tasks SET submitter_key = :digest, "
                "deduplication_key = :dedup WHERE id = :task_id"
            ),
            {"digest": digest, "dedup": new_dedup, "task_id": task_id},
        )


def downgrade() -> None:
    # One-way: the digest cannot be turned back into the browser key. Rolling
    # back code without a database backup leaves owned tasks unreachable.
    pass
