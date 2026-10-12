"""Frozen initial SQLite desktop schema. Additions require a new migration."""

from alembic import op

revision = "0001_desktop"
down_revision = None
branch_labels = None
depends_on = None

DDL = [
    'CREATE TABLE login_attempts (\n\t"key" VARCHAR(64) NOT NULL, \n\tfailures INTEGER NOT NULL, \n\twindow_started FLOAT NOT NULL, \n\tPRIMARY KEY ("key")\n)',
    "CREATE TABLE organizations (\n\tid VARCHAR(36) NOT NULL, \n\tname VARCHAR(160) NOT NULL, \n\tPRIMARY KEY (id)\n)",
    "CREATE TABLE audit_events (\n\tid INTEGER NOT NULL, \n\torganization_id VARCHAR(36) NOT NULL, \n\tactor VARCHAR(80) NOT NULL, \n\taction VARCHAR(100) NOT NULL, \n\tresource_id VARCHAR(80) NOT NULL, \n\tdetail JSON NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tprevious_hash VARCHAR(64) NOT NULL, \n\tevent_hash VARCHAR(64) NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(organization_id) REFERENCES organizations (id)\n)",
    "CREATE TABLE users (\n\tid VARCHAR(36) NOT NULL, \n\torganization_id VARCHAR(36) NOT NULL, \n\tusername VARCHAR(80) NOT NULL, \n\tpassword_hash TEXT NOT NULL, \n\trole VARCHAR(30) NOT NULL, \n\tactive BOOLEAN NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(organization_id) REFERENCES organizations (id), \n\tUNIQUE (username)\n)",
    "CREATE TABLE projects (\n\tid VARCHAR(36) NOT NULL, \n\torganization_id VARCHAR(36) NOT NULL, \n\towner_id VARCHAR(36) NOT NULL, \n\tname VARCHAR(160) NOT NULL, \n\tdescription TEXT NOT NULL, \n\tarchived BOOLEAN NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(organization_id) REFERENCES organizations (id), \n\tFOREIGN KEY(owner_id) REFERENCES users (id)\n)",
    "CREATE TABLE recovery_tokens (\n\ttoken_hash VARCHAR(64) NOT NULL, \n\tuser_id VARCHAR(36) NOT NULL, \n\texpires_at FLOAT NOT NULL, \n\tused BOOLEAN NOT NULL, \n\tPRIMARY KEY (token_hash), \n\tFOREIGN KEY(user_id) REFERENCES users (id)\n)",
    "CREATE TABLE sessions (\n\ttoken_hash VARCHAR(64) NOT NULL, \n\tuser_id VARCHAR(36) NOT NULL, \n\tcsrf VARCHAR(64) NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\texpires_at FLOAT NOT NULL, \n\tPRIMARY KEY (token_hash), \n\tFOREIGN KEY(user_id) REFERENCES users (id)\n)",
    "CREATE TABLE targets (\n\tid VARCHAR(36) NOT NULL, \n\torganization_id VARCHAR(36) NOT NULL, \n\tproject_id VARCHAR(36) NOT NULL, \n\turl TEXT NOT NULL, \n\tscope JSON NOT NULL, \n\tscope_version INTEGER NOT NULL, \n\tverification_status VARCHAR(40) NOT NULL, \n\tauthorized_by VARCHAR(36), \n\tapproved_at FLOAT, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(organization_id) REFERENCES organizations (id), \n\tFOREIGN KEY(project_id) REFERENCES projects (id), \n\tFOREIGN KEY(authorized_by) REFERENCES users (id)\n)",
    "CREATE TABLE assessments (\n\tid VARCHAR(36) NOT NULL, \n\torganization_id VARCHAR(36) NOT NULL, \n\tproject_id VARCHAR(36) NOT NULL, \n\ttarget_id VARCHAR(36) NOT NULL, \n\tcreated_by VARCHAR(36) NOT NULL, \n\tidempotency_key VARCHAR(100) NOT NULL, \n\tprofile VARCHAR(30) NOT NULL, \n\tstatus VARCHAR(40) NOT NULL, \n\tstage VARCHAR(100) NOT NULL, \n\tscope_snapshot JSON NOT NULL, \n\tscope_version INTEGER NOT NULL, \n\tretest_of VARCHAR(36), \n\tcancel_requested BOOLEAN NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tstarted_at FLOAT, \n\tfinished_at FLOAT, \n\terror TEXT, \n\tchecks JSON NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (organization_id, idempotency_key), \n\tFOREIGN KEY(organization_id) REFERENCES organizations (id), \n\tFOREIGN KEY(project_id) REFERENCES projects (id), \n\tFOREIGN KEY(target_id) REFERENCES targets (id), \n\tFOREIGN KEY(created_by) REFERENCES users (id), \n\tFOREIGN KEY(retest_of) REFERENCES assessments (id)\n)",
    "CREATE TABLE findings (\n\tid VARCHAR(36) NOT NULL, \n\torganization_id VARCHAR(36) NOT NULL, \n\tproject_id VARCHAR(36) NOT NULL, \n\ttarget_id VARCHAR(36) NOT NULL, \n\tfingerprint VARCHAR(200) NOT NULL, \n\ttitle VARCHAR(250) NOT NULL, \n\tcategory VARCHAR(80) NOT NULL, \n\tseverity VARCHAR(30) NOT NULL, \n\tconfidence VARCHAR(40) NOT NULL, \n\tstatus VARCHAR(40) NOT NULL, \n\tdescription TEXT NOT NULL, \n\tremediation TEXT NOT NULL, \n\taffected_url TEXT NOT NULL, \n\tfirst_seen FLOAT NOT NULL, \n\tlast_seen FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (target_id, fingerprint), \n\tFOREIGN KEY(organization_id) REFERENCES organizations (id), \n\tFOREIGN KEY(project_id) REFERENCES projects (id), \n\tFOREIGN KEY(target_id) REFERENCES targets (id)\n)",
    "CREATE TABLE finding_evidence (\n\tid VARCHAR(36) NOT NULL, \n\tfinding_id VARCHAR(36) NOT NULL, \n\tassessment_id VARCHAR(36) NOT NULL, \n\tdata JSON NOT NULL, \n\tevidence_hash VARCHAR(64) NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(finding_id) REFERENCES findings (id), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)",
    "CREATE TABLE finding_history (\n\tid VARCHAR(36) NOT NULL, \n\tfinding_id VARCHAR(36) NOT NULL, \n\tstatus VARCHAR(40) NOT NULL, \n\tactor VARCHAR(80) NOT NULL, \n\treason TEXT NOT NULL, \n\tcreated_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(finding_id) REFERENCES findings (id)\n)",
    "CREATE TABLE observations (\n\tid VARCHAR(36) NOT NULL, \n\torganization_id VARCHAR(36) NOT NULL, \n\tassessment_id VARCHAR(36) NOT NULL, \n\tdata JSON NOT NULL, \n\tevidence_hash VARCHAR(64) NOT NULL, \n\tobserved_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(organization_id) REFERENCES organizations (id), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)",
    "CREATE INDEX ix_audit_events_organization_id ON audit_events (organization_id)",
    "CREATE INDEX ix_users_organization_id ON users (organization_id)",
    "CREATE INDEX ix_projects_organization_id ON projects (organization_id)",
    "CREATE INDEX ix_recovery_tokens_user_id ON recovery_tokens (user_id)",
    "CREATE INDEX ix_sessions_user_id ON sessions (user_id)",
    "CREATE INDEX ix_targets_organization_id ON targets (organization_id)",
    "CREATE INDEX ix_targets_project_id ON targets (project_id)",
    "CREATE INDEX ix_assessments_organization_id ON assessments (organization_id)",
    "CREATE INDEX ix_assessments_project_id ON assessments (project_id)",
    "CREATE INDEX ix_assessments_status ON assessments (status)",
    "CREATE INDEX ix_findings_organization_id ON findings (organization_id)",
    "CREATE INDEX ix_findings_project_id ON findings (project_id)",
    "CREATE INDEX ix_finding_evidence_assessment_id ON finding_evidence (assessment_id)",
    "CREATE INDEX ix_finding_evidence_finding_id ON finding_evidence (finding_id)",
    "CREATE INDEX ix_finding_history_finding_id ON finding_history (finding_id)",
    "CREATE INDEX ix_observations_assessment_id ON observations (assessment_id)",
    "CREATE INDEX ix_observations_organization_id ON observations (organization_id)",
    "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END",
    "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END",
]


def upgrade():
    for statement in DDL:
        op.execute(statement)


def downgrade():
    raise RuntimeError("Destructive downgrade requires reviewed backup and explicit operator approval")
