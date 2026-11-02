"""Persisted AI investigation result on assessments.

Revision ID: 0005_assessment_ai_investigation
Revises: 0004_user_totp
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_assessment_ai_investigation"
down_revision = "0004_user_totp"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("assessments", sa.Column("ai_investigation", sa.JSON(), nullable=True))


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
