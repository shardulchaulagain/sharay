"""CLI integration tests for status, probe, findings, and scan."""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sqlalchemy import select

from aegis.auth import provision_owner
from aegis.cli import cmd_findings, cmd_probe, cmd_scan, cmd_status
from aegis.config import Settings
from aegis.database import create_database
from aegis.models import Assessment, Finding, User


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.settings = Settings(Path(self.temp_dir.name), 8765)
        engine, _ = create_database(self.settings)
        engine.dispose()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cmd_status_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = cmd_status(self.settings, as_json=True)
        self.assertEqual(rc, 0)
        output = json.loads(f.getvalue())
        self.assertIn("preflight", output)
        self.assertEqual(output["database"], "accessible")
        self.assertIn("counts", output)

    def test_cmd_status_text(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = cmd_status(self.settings, as_json=False)
        self.assertEqual(rc, 0)
        self.assertIn("SHARAY DEFENSIVE ASSESSMENT PLATFORM", f.getvalue())
        self.assertIn("ACTIVE SCANNER ENGINES", f.getvalue())

    def test_cmd_findings_json_empty(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = cmd_findings(self.settings, as_json=True)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(f.getvalue()), [])

    def test_cmd_probe_invalid_url_rejected(self):
        rc = cmd_probe("not_a_valid_url")
        self.assertNotEqual(rc, 0)


class CliScanAuthorizationTests(unittest.TestCase):
    """F04/A4: CLI authorization must precede execution, with no hardcoded owner."""

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.settings = Settings(Path(self.temp_dir.name), 8765)
        engine, _ = create_database(self.settings)
        engine.dispose()

    def _provision_owner(self):
        engine, sessions = create_database(self.settings)
        try:
            with sessions() as db:
                owner = provision_owner(db, "operator", "S3cureOperatorPass!2026", "Org")
                db.commit()
                return owner.id
        finally:
            engine.dispose()

    def _run(self, **kwargs):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = cmd_scan(self.settings, "https://example.com/", **kwargs)
        return rc, f.getvalue()

    def test_no_owner_refuses_without_hardcoded_provision(self):
        # No owner exists; the CLI must refuse, not auto-provision a baked-in owner, and must not scan.
        with (
            patch("aegis.cli.resolve_pinned", return_value="93.184.216.34"),
            patch("aegis.cli.scan_comprehensive") as scan,
        ):
            rc, _ = self._run(authorized=True)
        self.assertEqual(rc, 1)
        scan.assert_not_called()
        engine, sessions = create_database(self.settings)
        try:
            with sessions() as db:
                self.assertEqual(db.scalar(select(User)), None)  # nothing auto-provisioned
        finally:
            engine.dispose()

    def test_live_target_without_authorization_does_not_execute(self):
        self._provision_owner()
        with (
            patch("aegis.cli.resolve_pinned", return_value="93.184.216.34"),
            patch("aegis.cli.scan_comprehensive") as scan,
        ):
            rc, _ = self._run(authorized=False)
        self.assertEqual(rc, 1)
        scan.assert_not_called()  # authorization precedes execution

    def test_authorized_scan_records_authorization_then_persists_worker_status(self):
        owner_id = self._provision_owner()
        fake_result = {
            "outcome": "completed",
            "observations": [],
            "checks": [],
            "findings": [
                {
                    "fingerprint": "fp-xss-1",
                    "title": "Reflected XSS",
                    "category": "cross_site_scripting",
                    "severity": "high",
                    "lifecycle_state": "REPRODUCED",
                    "affected_url": "https://example.com/?q=x",
                }
            ],
        }
        with (
            patch("aegis.cli.resolve_pinned", return_value="93.184.216.34"),
            patch("aegis.cli.scan_comprehensive", return_value=fake_result) as scan,
        ):
            rc, _ = self._run(authorized=True)
        self.assertEqual(rc, 0)
        scan.assert_called_once()
        engine, sessions = create_database(self.settings)
        try:
            with sessions() as db:
                asmt = db.scalar(select(Assessment))
                self.assertIsNotNone(asmt)
                self.assertEqual(asmt.created_by, owner_id)
                self.assertIsNotNone(asmt.scope_version)
                finding = db.scalar(select(Finding).where(Finding.fingerprint == "fp-xss-1"))
                # REPRODUCED must persist as confirmed -- identical to the worker, not flat "suspected".
                self.assertEqual(finding.status, "confirmed")
        finally:
            engine.dispose()

    def test_persistence_failure_is_not_swallowed(self):
        self._provision_owner()
        # A finding missing its fingerprint makes persistence raise; the command must fail (exit 2),
        # never report success with a note.
        bad_result = {"outcome": "completed", "observations": [], "checks": [], "findings": [{"title": "x"}]}
        with (
            patch("aegis.cli.resolve_pinned", return_value="93.184.216.34"),
            patch("aegis.cli.scan_comprehensive", return_value=bad_result),
        ):
            rc, _ = self._run(authorized=True)
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
