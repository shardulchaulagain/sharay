"""Cross-process origin pacing leases and coordination columns.

Revision ID: 0003_origin_pacing_leases
Revises: 0002_origin_cooldowns
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_origin_pacing_leases"
down_revision = "0002_origin_cooldowns"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("origin_cooldowns", sa.Column("active_worker_id", sa.String(100), nullable=True))
    op.add_column("origin_cooldowns", sa.Column("acquired_at", sa.Float(), nullable=True))
    op.add_column("origin_cooldowns", sa.Column("last_completed_at", sa.Float(), nullable=True))


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
