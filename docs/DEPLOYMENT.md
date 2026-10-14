# Local operations and future server deployment

Run the exact installation/startup commands in README. `SHARAY.command` opens the native desktop app after owner provisioning. `desktop --browser` is an explicit alternative; `serve` starts only the loopback API and dedicated worker. The UI must be built first. A port collision aborts startup rather than attaching a window to an unknown service. Closing the desktop stops the API and worker; queued work is durable and running work interrupted without completion is marked failed/cancelled on recovery.

The data directory defaults to `.aegis/`, mode 0700; database files are 0600. It stores password hashes, hashed session/recovery tokens, approved scope snapshots, bounded redacted observations, findings and linked audit records. Do not place it in a synced/public folder. It is not encrypted at rest. OS account access and disk encryption are operator responsibilities. No authenticated target credentials are accepted.

## Backup, restore and retention

The local database now has consistent online snapshots through SQLite's backup API, including committed WAL data. Use an existing private destination directory outside the repository:

```sh
.venv/bin/python -m sharay --data-dir /absolute/private/data backup /absolute/private/backups/sharay.db
.venv/bin/python -m sharay --data-dir /absolute/private/recovered restore /absolute/private/backups/sharay.db
```

Both destinations must be new: backup refuses an existing file, and restore refuses an existing data directory. Symlinks in source, sidecar or destination paths and their ancestors are rejected; on macOS use canonical `/private/var/...` paths rather than `/var/...`. Files are mode0600 and the restored directory0700. Output contains only status, byte count and SHA256. Snapshots are validated for SQLite integrity, foreign keys, current shipped migration heads, complete schema (columns, constraints, indexes and audit triggers) against the shipped migrations, and the existing audit hash chain. Corrupt, unsupported or failed snapshots are not published. The default30-second deadline is cooperative, with a300-second maximum; it is not an OS execution limit or a protection against a concurrent privileged filesystem attacker. Power-loss durability is not established.

The snapshot contains the complete database, including account hashes, sessions, approvals, scope history, findings and cooldown intervals. It is unencrypted; use a private encrypted backup destination. The hash is an integrity reference, not proof of authenticity, and the audit chain is not external tamper protection. The command does not back up other data-directory files or environment/provider credentials. Stop the original application and worker before using a restored directory so two copies do not resume the same queued work. Restore starts no services and changes no records or credentials. Point SHARAY_DATA_DIR at the recovered directory and review audit/history through the authenticated UI before resuming work. Seven synthetic recovery regressions exercise committed WAL/all-table preservation, CLI output, permissions, corruption, audit tampering, unsupported revisions, deadlines and refusal paths; production recovery and encrypted-destination drills remain untested.

Evidence retention is currently indefinite in the local database; there is no automatic purge. Assessments store no response bodies and no raw cookie/header values. Comprehensive retention/deletion policies, artifact storage and report version history remain incomplete. Archiving a project changes its availability for new work; it does not erase evidence.

## Upgrades

Preserve a private backup, update pinned dependencies deliberately, recreate the environment, run unit/integration/security checks and frontend build, then apply forward Alembic migrations. The initial migration contains frozen SQLite DDL; add a new migration for schema changes. Destructive downgrade is disabled. The macOS/Python lockfile is environment-specific and is not a verified Linux/server lockfile.

## Server-phase gaps

Docker is absent in the development environment. No Compose/server deployment is presented as runnable. PostgreSQL, Redis, S3-compatible artifacts, non-root container workers with enforced destination egress and filesystem/memory isolation, TLS termination, secure HTTPS cookies, monitoring, secret management, reliable distributed queues and backup/restore drills must be implemented before Internet exposure. External scanner adapters must remain disabled until those controls are tested. Scanner installation/licensing/version compatibility requires review. Production deployment requires human approval of the prepared release.

Local HTTP cookies have HttpOnly and SameSite=Strict; Secure is false because loopback runs HTTP. Mutating requests require the exact local Origin and authenticated writes require a session CSRF token. This configuration is specific to a single-machine desktop; it must not be reused for a public service.

## Troubleshooting and incident response

`preflight` reports missing integrations without executing them. `/api/v1/health/live` reports process liveness; `/api/v1/health/ready` checks the database and owned worker process. A stopped worker makes readiness fail. Cancel an assessment from its view; the bounded current request can take up to three seconds to stop. If the worker terminates, restart the local app and review the recorded interruption before retesting. Audit integrity detects changed hash links; it cannot protect against a privileged local administrator who can replace the whole database.

For suspected unauthorized local access, close SHARAY, preserve private evidence, secure the OS account and inspect audit history. Credential rotation or destructive cleanup requires a deliberate operator action. Password reset invalidates sessions. Do not upload assessment records to third-party providers without an explicit privacy configuration.
