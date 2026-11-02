"""Add identity grouping to credentials for dual-identity (IDOR/BOLA) testing.

Revision ID: 0008_credential_identity
Revises: 0007_credentials
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_credential_identity"
down_revision = "0007_credentials"
branch_labels = None
depends_on = None


def upgrade():
    # Nullable: existing credentials keep folding into the single default auth context.
    op.add_column("credentials", sa.Column("identity", sa.String(80), nullable=True))
    op.add_column("credentials", sa.Column("subject_id", sa.String(128), nullable=True))


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
