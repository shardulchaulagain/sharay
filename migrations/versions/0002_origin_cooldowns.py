"""Preserve approved origin cooldowns without changing existing assessment records."""

from alembic import op

revision = "0002_origin_cooldowns"
down_revision = "0001_desktop"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE TABLE origin_cooldowns (origin TEXT NOT NULL PRIMARY KEY, interval FLOAT NOT NULL)")


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
