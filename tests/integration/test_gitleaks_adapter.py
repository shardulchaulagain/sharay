"""Gitleaks command line and suppression check; the real-binary test runs only where the tool is installed."""

import json
import random
import string
import tempfile
import unittest
from pathlib import Path

from packages.scanner_adapters.integrations import gitleaks
from services.scanner_worker import attest, run_isolated

BINARY = Path(__file__).resolve().parents[2] / "tools" / "bin" / "gitleaks-8.30.1" / "gitleaks"


class CommandLineTests(unittest.TestCase):
    def test_the_command_line_cannot_be_reconfigured_by_the_scanned_tree(self):
        argv = gitleaks.build_argv("/opt/tools/gitleaks", "/work/tree", max_seconds=30)
        self.assertEqual((argv[0], argv[1], argv[-1]), ("/opt/tools/gitleaks", "dir", "/work/tree"))
        for flag in (
            f"--config={gitleaks.PINNED_CONFIG}",
            "--ignore-gitleaks-allow",
            "--redact",
            "--exit-code=0",
            "--report-format=json",
            "--report-path=-",
            "--timeout=28",
        ):
            self.assertIn(flag, argv)
        self.assertIn("useDefault = true", Path(gitleaks.PINNED_CONFIG).read_text())

    def test_the_same_secret_keeps_its_identity_when_the_staging_folder_changes(self):
        def one(root, line=2, commit=""):
            item = {"RuleID": "github-pat", "File": f"{root}/src/app.js", "StartLine": line}
            item["Fingerprint"] = f"{commit}{root}/src/app.js:github-pat:{line}"
            return gitleaks.parse(json.dumps([item]).encode(), root)["findings"][0]["fingerprint"]

        self.assertEqual(one("/tmp/run-a/tree"), one("/tmp/run-b/tree"))
        self.assertNotEqual(one("/tmp/run-a/tree"), one("/tmp/run-a/tree", line=3))
        self.assertNotEqual(
            one("/tmp/run-a/tree"), one("/tmp/run-a/tree", commit="0123abcd:")
        )  # history scans stay distinct

    def test_paths_and_budget_are_checked(self):
        good = ("/opt/tools/gitleaks", "/work/tree")
        for executable, target in (
            ("gitleaks", good[1]),
            (good[0], "tree"),
            (good[0], "--config=/x"),
            (good[0], "/work/\x00"),
            (7, good[1]),
        ):
            with self.assertRaises(ValueError):
                gitleaks.build_argv(executable, target)
        for seconds in (4, 301, "60", True, 60.0):
            with self.assertRaises(ValueError):
                gitleaks.build_argv(*good, max_seconds=seconds)
        with self.assertRaises(ValueError):
            gitleaks.build_argv(*good, config="relative.toml")

    def test_suppression_files_are_found_anywhere_in_the_tree_without_following_links(self):
        with tempfile.TemporaryDirectory() as folder:
            root, outside = Path(folder, "tree"), Path(folder, "outside")
            (root / "a" / "b").mkdir(parents=True)
            outside.mkdir()
            (outside / ".gitleaksignore").write_text("x")
            (root / ".gitleaks.toml").write_text("x")
            (root / "a" / "b" / ".gitleaksignore").write_text("x")
            (root / "a" / ".gitleaksignore.bak").write_text("x")
            (root / "a" / ".gitleaks.toml").mkdir()  # a folder with the name is not a config
            (root / "linked").symlink_to(outside)
            self.assertEqual(gitleaks.suppression_files(root), [".gitleaks.toml", "a/b/.gitleaksignore"])
            self.assertEqual(gitleaks.suppression_files(root / "a" / ".gitleaks.toml"), [])


@unittest.skipUnless(BINARY.is_file(), "Gitleaks 8.30.1 is not installed here; a skip is not a pass.")
class RealBinaryTests(unittest.TestCase):
    """What the pinned, verified binary really does inside the sandbox, on synthetic secrets only."""

    @classmethod
    def setUpClass(cls):
        if not attest()["available"]:
            raise unittest.SkipTest("Seatbelt sandbox cannot be applied in this environment.")

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve() / "tree"
        rng = random.Random(20261012)
        letters = string.ascii_letters + string.digits
        self.tokens = ["ghp_" + "".join(rng.choice(letters) for _ in range(36)) for _ in range(2)]
        self.key = "\n".join("".join(rng.choice(letters) for _ in range(64)) for _ in range(12))
        files = {
            "src/app.js": f'const token = "{self.tokens[0]}";\n',
            "notes/allow.py": f'token = "{self.tokens[1]}"  # gitleaks:allow\n',
            "deploy/id_rsa": f"-----BEGIN RSA PRIVATE KEY-----\n{self.key}\n-----END RSA PRIVATE KEY-----\n",
            "clean/main.py": "print('nothing here')\n",
        }
        for name, content in files.items():
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(content)

    def scan(self):
        argv = gitleaks.build_argv(str(BINARY), str(self.root), max_seconds=40)
        folders = [str(self.root), str(Path(gitleaks.PINNED_CONFIG).parent)]
        result = run_isolated(
            argv,
            exec_paths=[str(BINARY.parent)],
            read_paths=folders,
            max_seconds=45,
            max_output_bytes=1048576,
        )
        self.assertEqual(
            (result.outcome, result.exit_code, result.output_truncated),
            ("completed", 0, False),
            result.stderr,
        )
        for secret in (*self.tokens, self.key.split("\n")[0]):
            self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        return gitleaks.parse(result.stdout, source_root=str(self.root))

    def test_real_output_parses_and_allow_comments_do_not_hide_a_secret(self):
        found = {(finding["rule"], finding["file"]) for finding in self.scan()["findings"]}
        expected = {
            ("github-pat", "src/app.js"),
            ("github-pat", "notes/allow.py"),
            ("private-key", "deploy/id_rsa"),
        }
        self.assertEqual(found, expected)

    def test_a_tree_that_brings_its_own_configuration_does_not_blind_the_scan(self):
        (self.root / ".gitleaks.toml").write_text("title = \"target\"\n[allowlist]\npaths = ['''.*''']\n")
        self.assertEqual(len(self.scan()["findings"]), 3)
        self.assertEqual(gitleaks.suppression_files(self.root), [".gitleaks.toml"])

    def test_an_ignore_file_in_the_tree_is_always_reported_whatever_the_tool_then_does(self):
        (self.root / ".gitleaksignore").write_text("anything\n")
        self.scan()  # still runs and parses; whether findings survive is the tool's behaviour, not ours
        self.assertEqual(gitleaks.suppression_files(self.root), [".gitleaksignore"])
        self.assertNotIn("x", json.dumps(gitleaks.suppression_files(self.root / "clean")))


if __name__ == "__main__":
    unittest.main()
