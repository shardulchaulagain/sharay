"""Encrypted test credentials for authenticated testing.

Revision ID: 0007_credentials
Revises: 0006_project_members
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_credentials"
down_revision = "0006_project_members"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False, index=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("header_name", sa.String(80), nullable=True),
        sa.Column("encrypted_value", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("organization_id", "name"),
    )


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
