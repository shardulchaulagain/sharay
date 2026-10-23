"""Opt-in TOTP MFA columns on users.

Revision ID: 0004_user_totp
Revises: 0003_origin_pacing_leases
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_user_totp"
down_revision = "0003_origin_pacing_leases"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("totp_secret", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("totp_backup_hashes", sa.JSON(), nullable=True))


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
