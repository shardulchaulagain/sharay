"""CLI integration tests for status, probe, findings, and scan."""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from aegis.cli import cmd_findings, cmd_probe, cmd_status
from aegis.config import Settings
from aegis.database import create_database


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


if __name__ == "__main__":
    unittest.main()
