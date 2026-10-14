"""Requester acceptance: private consistent backups and restoration to new directories."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select

from aegis.audit import audit, verify_audit
from aegis.auth import provision_owner
from aegis.config import Settings
from aegis.database import create_database
from aegis.models import OriginCooldown, Project


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name).resolve()
        self.data = self.root / "data"
        self.engine, self.sessions = create_database(Settings(self.data, start_worker=False))
        with self.sessions() as db:
            owner = provision_owner(db, "backupowner", "Synthetic-backup-password-761!")
            self.org = owner.organization_id
            db.add(Project(organization_id=self.org, owner_id=owner.id, name="Recovery fixture"))
            db.add(OriginCooldown(origin="http://127.0.0.1:8913", interval=0.2))
            audit(db, self.org, "backupowner", "backup.fixture", "synthetic", {"count": 1})
            db.commit()

    def tearDown(self):
        self.engine.dispose()
        self.folder.cleanup()

    def functions(self):
        from aegis.backup import backup_database, restore_database

        return backup_database, restore_database

    def test_live_wal_snapshot_and_restore_preserve_committed_records_and_audit(self):
        backup, restore = self.functions()
        source = sqlite3.connect(self.data / "aegis.db")
        try:
            self.assertTrue((self.data / "aegis.db-wal").exists())
            source.execute("BEGIN IMMEDIATE")
            source.execute("UPDATE projects SET name='Uncommitted'")
            destination = self.root / "snapshot.db"
            result = backup(self.data, destination)
            self.assertEqual(result["sha256"], hashlib.sha256(destination.read_bytes()).hexdigest())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            recovered = self.root / "restored"
            restore(destination, recovered)
            self.assertEqual(recovered.stat().st_mode & 0o777, 0o700)
            self.assertEqual((recovered / "aegis.db").stat().st_mode & 0o777, 0o600)
            engine, sessions = create_database(Settings(recovered, start_worker=False), migrate=False)
            try:
                with sessions() as db:
                    self.assertTrue(verify_audit(db))
                    self.assertEqual(db.scalar(select(Project)).name, "Recovery fixture")
                    self.assertEqual(db.scalar(select(OriginCooldown)).interval, 0.2)
                copied = sqlite3.connect(recovered / "aegis.db")
                try:
                    tables = source.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                    source.rollback()
                    for (table,) in tables:
                        self.assertEqual(
                            source.execute(f'SELECT * FROM "{table}"').fetchall(),
                            copied.execute(f'SELECT * FROM "{table}"').fetchall(),
                        )
                finally:
                    copied.close()
            finally:
                engine.dispose()
        finally:
            source.rollback()
            source.close()

    def test_existing_destinations_and_symlinks_fail_without_overwriting(self):
        backup, restore = self.functions()
        existing = self.root / "existing.db"
        existing.write_bytes(b"keep")
        with self.assertRaises(ValueError):
            backup(self.data, existing)
        self.assertEqual(existing.read_bytes(), b"keep")
        link = self.root / "link.db"
        link.symlink_to(existing)
        with self.assertRaises(ValueError):
            backup(self.data, link)
        data_link = self.root / "data-link"
        data_link.symlink_to(self.data, target_is_directory=True)
        with self.assertRaises(ValueError):
            backup(data_link, self.root / "unused.db")
        snapshot = self.root / "snapshot.db"
        backup(self.data, snapshot)
        snapshot_link = self.root / "snapshot-link.db"
        snapshot_link.symlink_to(snapshot)
        with self.assertRaises(ValueError):
            restore(snapshot_link, self.root / "unused-dir")
        with self.assertRaises(ValueError):
            restore(snapshot, self.data)
        with self.assertRaises(ValueError):
            restore(snapshot, data_link)
        self.assertFalse((self.root / "unused-dir").exists())

    def test_corrupt_or_tampered_audit_backup_is_rejected_and_no_restore_remains(self):
        backup, restore = self.functions()
        corrupt = self.root / "corrupt.db"
        corrupt.write_bytes(b"not a database: synthetic-private-token")
        with self.assertRaises(ValueError) as caught:
            restore(corrupt, self.root / "bad-restore")
        self.assertNotIn("synthetic-private-token", str(caught.exception))
        self.assertFalse((self.root / "bad-restore").exists())
        snapshot = self.root / "snapshot.db"
        backup(self.data, snapshot)
        with closing(sqlite3.connect(snapshot)) as db, db:
            # Deliberately corrupt only this synthetic snapshot; live audit writes remain guarded.
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit_events SET detail=?", (json.dumps({"tampered": True}),))
        with self.assertRaises(ValueError):
            restore(snapshot, self.root / "tampered-restore")
        self.assertFalse((self.root / "tampered-restore").exists())

    def test_missing_source_and_invalid_deadlines_do_not_create_a_database(self):
        backup, _ = self.functions()
        with self.assertRaises(ValueError):
            backup(self.root / "missing", self.root / "snapshot.db")
        for value in (0, -1, True, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                backup(self.data, self.root / "snapshot.db", max_seconds=value)
        self.assertFalse((self.root / "snapshot.db").exists())

    def test_unrecognized_migration_revision_is_not_restored(self):
        backup, restore = self.functions()
        snapshot = self.root / "future.db"
        backup(self.data, snapshot)
        with closing(sqlite3.connect(snapshot)) as db, db:
            db.execute("UPDATE alembic_version SET version_num='unknown-future-revision'")
        with self.assertRaises(ValueError):
            restore(snapshot, self.root / "unsupported-restore")
        self.assertFalse((self.root / "unsupported-restore").exists())

    def test_cli_recovery_and_expired_operation_report_only_safe_metadata(self):
        from aegis.__main__ import main

        backup, restore = self.functions()
        snapshot = self.root / "cli.db"
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--data-dir", str(self.data), "backup", str(snapshot)]), 0)
        self.assertEqual(set(json.loads(output.getvalue())), {"backup", "sha256", "bytes"})
        output = StringIO()
        recovered = self.root / "cli-restore"
        with redirect_stdout(output):
            self.assertEqual(main(["--data-dir", str(recovered), "restore", str(snapshot)]), 0)
        self.assertEqual(set(json.loads(output.getvalue())), {"restore", "sha256", "bytes"})
        errors = StringIO()
        with redirect_stderr(errors):
            self.assertEqual(main(["restore", str(snapshot)]), 2)
        self.assertIn("explicit new --data-dir", errors.getvalue())
        for operation, args, leftover in [
            (backup, (self.data, self.root / "expired.db"), self.root / "expired.db"),
            (restore, (snapshot, self.root / "expired-restore"), self.root / "expired-restore"),
        ]:
            with patch("aegis.backup.time.monotonic", side_effect=[0] + [2] * 50):
                with self.assertRaises(ValueError):
                    operation(*args, max_seconds=1)
            self.assertFalse(leftover.exists())


if __name__ == "__main__":
    unittest.main()
