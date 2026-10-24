"""Project membership for per-project RBAC.

Revision ID: 0006_project_members
Revises: 0005_assessment_ai_investigation
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_project_members"
down_revision = "0005_assessment_ai_investigation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "project_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False, index=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column("added_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("project_id", "user_id"),
    )
    # Backfill: every existing project's owner is a member so current access is preserved.
    op.execute(
        "INSERT INTO project_members (id, project_id, user_id, added_at) "
        "SELECT lower(hex(randomblob(16))), id, owner_id, created_at FROM projects"
    )


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
