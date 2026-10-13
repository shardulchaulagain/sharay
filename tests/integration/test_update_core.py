"""Self-update core: only a verified, evaluated, newer file from the official source becomes active."""

import ast
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import services.update_worker as core
from services.update_worker import UpdateRefused, activate, load, parse_candidate, regressions, rollback

SECRET = "synthetic-secret-value"
PASSED = {"gates_passed": True, "regressions": []}
BASE = "https://github.com/gitleaks/gitleaks/releases/download/"


class UpdateCoreTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.ledger = self.root / "ledger.json"
        self.outside = self.root / "outside.txt"
        self.outside.write_text("keep")

    def artifact(self, content: bytes = b"synthetic release archive", name: str = "artifact.bin") -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def candidate(self, version="8.30.1", content=b"synthetic release archive", **changes):
        values = {
            "component": "gitleaks",
            "version": version,
            "url": f"{BASE}v{version}/gitleaks_{version}_darwin_arm64.tar.gz",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        return parse_candidate(values | changes)

    def refused(self, candidate, artifact=None, evaluation=PASSED, text=""):
        before = self.ledger.read_bytes() if self.ledger.exists() else None
        with self.assertRaisesRegex(UpdateRefused, text) as caught:
            activate(self.ledger, candidate, artifact or self.artifact(), evaluation)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(self.ledger.read_bytes() if self.ledger.exists() else None, before)
        self.assertEqual(self.outside.read_text(), "keep")

    def test_a_verified_evaluated_candidate_becomes_active_and_a_newer_one_keeps_the_old_for_rollback(self):
        first = activate(self.ledger, self.candidate(), self.artifact(), PASSED)
        self.assertEqual((first.version, len(first.sha256)), ("8.30.1", 64))
        self.assertEqual(stat.S_IMODE(os.lstat(self.ledger).st_mode), 0o600)
        newer = b"synthetic newer archive"
        activate(self.ledger, self.candidate("8.31.0", newer), self.artifact(newer), PASSED)
        ledger = load(self.ledger)
        self.assertEqual(
            (ledger.active["gitleaks"].version, ledger.previous["gitleaks"].version), ("8.31.0", "8.30.1")
        )
        self.assertEqual([event["action"] for event in ledger.history], ["activated", "activated"])
        self.assertFalse(self.ledger.with_name("ledger.json.tmp").exists())

    def test_a_file_that_is_not_exactly_what_the_source_published_is_refused(self):
        good = self.candidate()
        self.refused(good, self.artifact(b"synthetic release archivE"), text="SHA-256")
        self.refused(good, self.artifact(b"synthetic release archive plus"), text="published size")
        self.refused(good, self.root / "missing.bin", text="could not be opened")
        self.refused(good, self.root, text="published size")  # a directory
        # Even a directory whose reported size equals the published size is never read as a file.
        same_size = self.candidate(size=os.lstat(self.root).st_size)
        self.refused(same_size, self.root, text="published size")
        link = self.root / "link.bin"
        link.symlink_to(self.artifact())
        self.refused(good, link, text="could not be opened")
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        self.refused(good, fifo, text="published size")  # and it does not hang

    def test_only_the_components_official_source_is_accepted(self):
        name = "v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz"
        for url in (
            f"https://github.com/someone-else/gitleaks/releases/download/{name}",
            f"http://github.com/gitleaks/gitleaks/releases/download/{name}",
            f"https://github.com.example.test/gitleaks/gitleaks/releases/download/{name}",
            f"https://user:{SECRET}@github.com/gitleaks/gitleaks/releases/download/{name}",
            f"{BASE}../../../../someone-else/x/releases/download/{name}",
            f"{BASE}{name}?token={SECRET}",
            f"{BASE}{name}#{SECRET}",
            f"{BASE}v8.30.1//x.tar.gz",
            f"{BASE}%2e%2e/%2e%2e/someone-else/x.tar.gz",
            f"{BASE}v8.30.1/%2fx.tar.gz",
            f"{BASE}./v8.30.1/x.tar.gz",
            f"{BASE}v8.30.1/.hidden",
            f"{BASE}v8.30.1/x.tar.gz/",
            f"{BASE}v8.30.1/x;y.tar.gz",
            f"{BASE}v8.30.1/x y.tar.gz",
            f"{BASE}v8.30.1/@{SECRET}",
            BASE,
            "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei.zip",  # another component's
        ):
            with self.subTest(url=url.replace(SECRET, "…")):
                self.refused(self.candidate(url=url), text="official source")

    def test_older_equal_and_unevaluated_candidates_are_refused(self):
        activate(self.ledger, self.candidate(), self.artifact(), PASSED)
        for version in ("8.30.1", "8.30.0", "8.9.9", "7.99.99"):
            with self.subTest(version=version):
                self.refused(self.candidate(version), text="not newer")
        newer = self.candidate("8.30.2")
        for evaluation in (
            {},
            {"gates_passed": True},
            {"gates_passed": False, "regressions": []},
            {"gates_passed": "true", "regressions": []},
            {"gates_passed": 1, "regressions": []},
            {"gates_passed": True, "regressions": ["cookie-case:missed:cookie_httponly"]},
            {"gates_passed": True, "regressions": None},
            {"gates_passed": True, "regressions": ()},
            None,
            "passed",
        ):
            with self.subTest(evaluation=evaluation):
                self.refused(newer, evaluation=evaluation, text="without regression")
        self.assertEqual(load(self.ledger).active["gitleaks"].version, "8.30.1")

    def test_a_malformed_candidate_is_refused_without_echoing_it(self):
        good = {
            "component": "gitleaks",
            "version": "8.30.1",
            "url": BASE + "v8.30.1/x.tar.gz",
            "sha256": "a" * 64,
            "size": 10,
        }
        for label, values in {
            "templates are not a component": good | {"component": "nuclei-templates"},
            "unknown component": good | {"component": SECRET},
            "version word": good | {"version": "latest"},
            "version with text": good | {"version": f"8.30.1-{SECRET}"},
            "version as number": good | {"version": 8.3},
            "uppercase digest": good | {"sha256": "A" * 64},
            "short digest": good | {"sha256": "a" * 63},
            "size as boolean": good | {"size": True},
            "size zero": good | {"size": 0},
            "size beyond the limit": good | {"size": core.MAX_ARTIFACT_BYTES + 1},
            "extra key": good | {"scope": ["*"]},
            "not a mapping": [SECRET],
        }.items():
            with self.subTest(label), self.assertRaises(UpdateRefused) as caught:
                parse_candidate(values)
            self.assertEqual(str(caught.exception), "The update candidate is not valid.")
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)

    def test_rollback_restores_the_replaced_version_and_withdraws_the_failed_one(self):
        activate(self.ledger, self.candidate(), self.artifact(), PASSED)
        newer = b"synthetic newer archive"
        activate(self.ledger, self.candidate("8.31.0", newer), self.artifact(newer), PASSED)
        for reason in ("", "   ", "x" * 301, "line\nbreak", None):
            with self.subTest(reason=reason), self.assertRaises(UpdateRefused):
                rollback(self.ledger, "gitleaks", reason)
        self.assertEqual(load(self.ledger).active["gitleaks"].version, "8.31.0")
        restored = rollback(self.ledger, "gitleaks", "parser tests failed on real output")
        self.assertEqual(restored.version, "8.30.1")
        ledger = load(self.ledger)
        self.assertEqual(
            (ledger.active["gitleaks"].version, ledger.withdrawn["gitleaks"]), ("8.30.1", ["8.31.0"])
        )
        self.assertEqual(ledger.history[-1]["action"], "rolled_back")
        # The withdrawn version does not come back by itself, even though it is newer and verifies.
        self.refused(self.candidate("8.31.0", newer), self.artifact(newer), text="rolled back")
        # Rolling back the first version ever leaves nothing active rather than something unverified.
        self.assertIsNone(rollback(self.ledger, "gitleaks", "second failure"))
        self.assertNotIn("gitleaks", load(self.ledger).active)
        for component, reason in (
            ("gitleaks", "nothing active"),
            ("nuclei", "never activated"),
            ("gitleaks", ""),
        ):
            with self.assertRaises(UpdateRefused):
                rollback(self.ledger, component, reason)

    def test_a_damaged_ledger_stops_updates_instead_of_being_replaced(self):
        for content in (
            b"not json",
            b"[]",
            json.dumps({"active": {"gitleaks": {"version": "latest"}}}).encode(),
            b" " * (core.MAX_LEDGER_BYTES + 1),
        ):
            self.ledger.write_bytes(content)
            self.refused(self.candidate(), text="ledger is unreadable")
            with self.assertRaisesRegex(UpdateRefused, "ledger is unreadable"):
                rollback(self.ledger, "gitleaks", "x")
        self.ledger.unlink()
        # A well-formed ledger is still refused when it is oversized or reached through a link.
        valid = self.root / "valid.json"
        activate(valid, self.candidate(), self.artifact(), PASSED)
        self.ledger.write_bytes(valid.read_bytes() + b" " * core.MAX_LEDGER_BYTES)
        self.refused(self.candidate("8.31.0"), text="ledger is unreadable")
        self.ledger.unlink()
        os.mkfifo(self.ledger)
        with self.assertRaisesRegex(UpdateRefused, "ledger is unreadable"):  # and it does not hang
            activate(self.ledger, self.candidate("8.31.0"), self.artifact(), PASSED)
        self.ledger.unlink()
        self.ledger.symlink_to(self.root / "nowhere.json")  # a dangling link is not "no ledger yet"
        self.refused(self.candidate("8.31.0"), text="ledger is unreadable")
        self.ledger.unlink()
        self.ledger.symlink_to(valid)
        self.refused(self.candidate("8.31.0"), text="ledger is unreadable")
        self.assertEqual(load(valid).active["gitleaks"].version, "8.30.1")

    def test_regressions_are_disagreements_the_baseline_did_not_have(self):
        def report(cases, incomplete=()):
            return {
                "cases": [{"id": i, "unexpected": u, "missed": m} for i, u, m in cases],
                "incomplete_scans": list(incomplete),
            }

        baseline = report([("a", [], ["x"]), ("b", [], [])])
        self.assertEqual(regressions(baseline, baseline), [])
        self.assertEqual(regressions(baseline, report([("a", [], []), ("b", [], [])])), [])  # an improvement
        worse = report([("a", ["y"], ["x"]), ("b", [], ["z"])], incomplete=["c"])
        self.assertEqual(regressions(baseline, worse), ["a:unexpected:y", "b:missed:z", "c:incomplete"])
        # A candidate whose report lost cases, or is empty, has not agreed with anything.
        self.assertEqual(regressions(baseline, report([("b", [], [])])), ["a:missing"])
        self.assertEqual(regressions(baseline, report([])), ["a:missing", "b:missing"])
        self.assertEqual(
            regressions(baseline, report([("a", [], ["x"]), ("b", [], []), ("new", [], [])])), []
        )

    def test_the_core_imports_no_network_client_and_nothing_that_holds_scope(self):
        tree = ast.parse(Path(core.__file__).read_text())
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                modules.add((node.module or "").split(".")[0])
        self.assertEqual(
            modules, {"hashlib", "hmac", "os", "re", "stat", "datetime", "pathlib", "typing", "pydantic"}
        )
        self.assertNotIn("nuclei-templates", core.SOURCES)


if __name__ == "__main__":
    unittest.main()
