import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "engineering" / "check.py"
spec = importlib.util.spec_from_file_location("engineering_check", MODULE)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class EvidenceTests(unittest.TestCase):
    def run_fixture(self, source):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "tests").mkdir()
            (root / "tests" / "test_fixture.py").write_text(source)
            return check.run_gate(
                {
                    "name": "unit",
                    "command": ["{python}", str(MODULE.parent / "run_tests.py")],
                    "timeout_seconds": 5,
                },
                root,
                True,
            )

    def test_unit_diagnostics_use_base_ids_and_real_counts(self):
        result = self.run_fixture("""import unittest
class Fixture(unittest.TestCase):
    def test_failure(self):
        self.fail('private failure message')
    def test_error(self):
        raise RuntimeError('private error message')
    def test_subtests(self):
        for kind in ('failure', 'error'):
            for index in range(2):
                with self.subTest(secret='ghp_' + 'A' * 36, kind=kind, index=index):
                    if kind == 'failure':
                        self.fail('private subtest message')
                    raise RuntimeError('private subtest error')
    @unittest.skip('private skip message')
    def test_skipped(self):
        pass
    @unittest.expectedFailure
    def test_expected_failure(self):
        self.fail('private expected message')
    @unittest.expectedFailure
    def test_unexpected_success(self):
        pass
""")
        self.assertEqual((result["status"], result["exit_code"]), ("failed", 1))
        data = result["test_diagnostics"]
        self.assertEqual(data["status"], "available")
        self.assertEqual(
            [
                data[key]
                for key in (
                    "tests_run",
                    "failures",
                    "errors",
                    "skipped",
                    "expected_failures",
                    "unexpected_successes",
                )
            ],
            [6, 3, 3, 1, 1, 1],
        )
        self.assertEqual(
            data["failure_test_ids"],
            [
                "test_fixture.Fixture.test_failure",
                "test_fixture.Fixture.test_subtests",
                "test_fixture.Fixture.test_unexpected_success",
            ],
        )
        self.assertEqual(
            data["error_test_ids"], ["test_fixture.Fixture.test_error", "test_fixture.Fixture.test_subtests"]
        )
        self.assertFalse(data["ids_truncated"])
        encoded = json.dumps(result)
        for forbidden in ("private", "ghp_" + "A" * 36, "secret=", "Traceback", "RuntimeError"):
            self.assertNotIn(forbidden, encoded)

    def test_unit_diagnostics_suppress_unsafe_identifier_tokens_and_controls(self):
        result = self.run_fixture("""import unittest
class Fixture(unittest.TestCase):
    def id(self):
        if self._testMethodName == 'test_token':
            return 'fixture.' + 'ghp_' + 'A' * 36 + '.test'
        if self._testMethodName == 'test_embedded_token':
            return 'fixture.test_' + 'ghp_' + 'A' * 36 + '.test'
        if self._testMethodName == 'test_long':
            return 'fixture.' + 'a' * 201 + '.test'
        return 'fixture.control' + chr(10) + '.test'
    def test_token(self): self.fail('private')
    def test_embedded_token(self): self.fail('private')
    def test_long(self): self.fail('private')
    def test_control(self): self.fail('private')
""")
        data = result["test_diagnostics"]
        self.assertEqual((data["tests_run"], data["failures"]), (4, 4))
        self.assertEqual(data["failure_test_ids"], [])
        self.assertTrue(data["ids_truncated"])
        self.assertNotIn("ghp_" + "A" * 36, json.dumps(result))

    def test_unit_diagnostics_id_cap_does_not_truncate_failure_count(self):
        result = self.run_fixture("""import unittest
def fail(self): self.fail('private')
Fixture = type('Fixture', (unittest.TestCase,), {
    '__module__': __name__, **{'test_%03d' % i: fail for i in range(101)}})
""")
        data = result["test_diagnostics"]
        self.assertEqual((data["tests_run"], data["failures"]), (101, 101))
        self.assertEqual(len(data["failure_test_ids"]), 100)
        self.assertTrue(data["ids_truncated"])

    def test_empty_suite_diagnostics_remain_failed_not_successful(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "tests").mkdir()
            result = check.run_gate(
                {"name": "empty", "command": ["{python}", str(MODULE.parent / "run_tests.py")]}, root, True
            )
        self.assertEqual((result["status"], result["exit_code"]), ("failed", 2))
        self.assertEqual(result["test_diagnostics"]["tests_run"], 0)
        self.assertEqual(result["test_diagnostics"]["status"], "available")

    def test_nested_empty_runner_cannot_write_outer_sidecar(self):
        result = self.run_fixture(f"""import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
class Fixture(unittest.TestCase):
    def test_nested_empty_runner(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'tests').mkdir()
            child = subprocess.run([sys.executable, {str(MODULE.parent / "run_tests.py")!r}],
                                   cwd=folder, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=2)
            self.assertEqual(child.returncode, 2)
            probe = subprocess.run([sys.executable, '-c',
                "import os;assert 'SHARAY_TEST_RESULT_PATH' not in os.environ"],
                cwd=folder, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            self.assertEqual(probe.returncode, 0)
        self.assertNotIn('SHARAY_TEST_RESULT_PATH', os.environ)
    def test_regular(self):
        self.assertTrue(True)
""")
        self.assertEqual((result["status"], result["exit_code"]), ("passed", 0))
        data = result["test_diagnostics"]
        self.assertEqual(data["status"], "available")
        self.assertEqual(data["tests_run"], 2)
        self.assertEqual((data["failures"], data["errors"]), (0, 0))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "No-follow file checks required")
    def test_writer_preserves_nonprivate_nonempty_and_linked_files(self):
        from engineering import run_tests

        data = {
            "schema_version": 1,
            **dict.fromkeys(run_tests.COUNT_FIELDS, 0),
            "failure_test_ids": [],
            "error_test_ids": [],
            "ids_truncated": False,
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            nonprivate = root / "nonprivate"
            nonprivate.touch(mode=0o644)
            nonprivate.chmod(0o644)
            run_tests.write_metadata(data, nonprivate)
            self.assertEqual(nonprivate.read_bytes(), b"")
            nonempty = root / "nonempty"
            nonempty.write_bytes(b"preserve")
            nonempty.chmod(0o600)
            run_tests.write_metadata(data, nonempty)
            self.assertEqual(nonempty.read_bytes(), b"preserve")
            original = root / "original"
            original.touch(mode=0o600)
            linked = root / "linked"
            os.link(original, linked)
            run_tests.write_metadata(data, linked)
            self.assertEqual(original.read_bytes(), b"")
            self.assertEqual(linked.read_bytes(), b"")
            valid = root / "valid"
            valid.touch(mode=0o600)
            run_tests.write_metadata(data, valid)
            self.assertEqual(json.loads(valid.read_bytes()), data)

    def test_missing_or_malformed_sidecar_is_unavailable(self):
        valid = {
            "schema_version": 1,
            "tests_run": 1,
            "failures": 1,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
            "failure_test_ids": ["fixture.Test.test_failure"],
            "error_test_ids": [],
            "ids_truncated": False,
        }
        invalid = [
            b"",
            b"not-json",
            b"\xff",
            b" " * (check.MAX_RESULT_BYTES + 1),
            json.dumps({**valid, "tests_run": True}).encode(),
            json.dumps({**valid, "message": "private"}).encode(),
            json.dumps({**valid, "failure_test_ids": ["fixture." + "ghp_" + "A" * 36 + ".test"]}).encode(),
            json.dumps({**valid, "failure_test_ids": ["fixture.Test.test_failure"] * 2}).encode(),
            json.dumps(valid)
            .replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
            .encode(),
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "result.json"
            path.write_bytes(json.dumps(valid).encode())
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            self.assertEqual(check.read_test_diagnostics(path, identity)["status"], "available")
            for raw in invalid:
                with self.subTest(length=len(raw)):
                    path.write_bytes(raw)
                    self.assertEqual(check.read_test_diagnostics(path, identity), {"status": "unavailable"})
            path.unlink()
            self.assertEqual(check.read_test_diagnostics(path, identity), {"status": "unavailable"})
        with tempfile.TemporaryDirectory() as folder:
            result = check.run_gate(
                {"name": "no-metadata", "command": ["{python}", "-c", "pass"]}, Path(folder), True
            )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["test_diagnostics"], {"status": "unavailable"})

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "mkfifo"), "POSIX file checks required")
    def test_swapped_fifo_symlink_directory_sidecars_never_block_or_read_targets(self):
        for replacement in ("fifo", "symlink", "directory", "regular"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                sentinel = root / "sentinel"
                sentinel.write_text("private target")
                source = (
                    "import os\nfrom pathlib import Path\np=Path(os.environ['SHARAY_TEST_RESULT_PATH'])\n"
                    "p.unlink()\n"
                )
                source += {
                    "fifo": "os.mkfifo(p)\n",
                    "symlink": f"p.symlink_to({str(sentinel)!r})\n",
                    "directory": "p.mkdir()\n",
                    "regular": "p.write_text('{}')\n",
                }[replacement]
                result = check.run_gate(
                    {"name": "swap", "command": ["{python}", "-c", source], "timeout_seconds": 2}, root, True
                )
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["test_diagnostics"], {"status": "unavailable"})
                self.assertLess(result["duration_seconds"], 2)
                self.assertEqual(sentinel.read_text(), "private target")
                self.assertNotIn("private target", json.dumps(result))

    def test_metadata_storage_failure_does_not_block_gate(self):
        from unittest.mock import patch

        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(check.tempfile, "mkstemp", side_effect=OSError()),
        ):
            result = check.run_gate(
                {"name": "no-storage", "command": ["{python}", "-c", "pass"]}, Path(folder), True
            )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["test_diagnostics"], {"status": "unavailable"})

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "mkfifo"), "POSIX file checks required")
    def test_runner_metadata_writer_refuses_fifo_and_symlink_and_closes_descriptors(self):
        from unittest.mock import patch

        from engineering import run_tests

        data = {
            "schema_version": 1,
            **dict.fromkeys(run_tests.COUNT_FIELDS, 0),
            "failure_test_ids": [],
            "error_test_ids": [],
            "ids_truncated": False,
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sentinel = root / "sentinel"
            sentinel.write_text("private target")
            symlink = root / "link"
            symlink.symlink_to(sentinel)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            for path in (symlink, fifo):
                with self.subTest(kind=path.name):
                    run_tests.write_metadata(data, path)
                    self.assertEqual(sentinel.read_text(), "private target")
            path = root / "regular"
            path.touch(mode=0o600)
            with (
                patch.object(run_tests.os, "fstat", side_effect=OSError("private")),
                patch.object(run_tests.os, "close", wraps=os.close) as close,
            ):
                run_tests.write_metadata(data, path)
                close.assert_called_once()
            run_tests.write_metadata(data, path)
            self.assertEqual(json.loads(path.read_text()), data)

    def test_sidecar_parent_swap_cleanup_preserves_gate_result_and_sentinel(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sentinel = root / "sentinel"
            sentinel.mkdir()
            (sentinel / "keep").write_text("private target")
            marker = root / "parent_path"
            source = (
                "import os\nfrom pathlib import Path\np=Path(os.environ['SHARAY_TEST_RESULT_PATH'])\n"
                f"Path({str(marker)!r}).write_text(str(p.parent))\n"
                "p.unlink()\np.parent.rmdir()\n"
                f"p.parent.symlink_to({str(sentinel)!r}, target_is_directory=True)\n"
            )
            result = check.run_gate(
                {"name": "swap-parent", "command": ["{python}", "-c", source], "timeout_seconds": 2},
                root,
                True,
            )
            self.assertEqual((result["status"], result["exit_code"]), ("passed", 0))
            self.assertEqual(result["test_diagnostics"], {"status": "unavailable"})
            self.assertEqual((sentinel / "keep").read_text(), "private target")
            self.assertFalse(Path(marker.read_text()).exists())
            self.assertFalse(Path(marker.read_text()).is_symlink())

    def test_diagnostics_cleanup_failure_does_not_replace_gate_result(self):
        from unittest.mock import patch

        real_cleanup = check.tempfile.TemporaryDirectory.cleanup
        directories = []

        def unavailable(directory):
            directories.append(directory)
            raise OSError("private failure details")

        with tempfile.TemporaryDirectory() as folder:
            try:
                with patch.object(check.tempfile.TemporaryDirectory, "cleanup", unavailable):
                    result = check.run_gate(
                        {"name": "cleanup-failure", "command": ["{python}", "-c", "pass"]}, Path(folder), True
                    )
                self.assertEqual((result["status"], result["exit_code"]), ("passed", 0))
                self.assertEqual(result["diagnostics_cleanup"], "unavailable")
                self.assertNotIn("private failure", json.dumps(result))
            finally:
                for directory in directories:
                    real_cleanup(directory)

    def test_caller_default_paths_are_independent_and_explicit_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            self.assertEqual(check.main(["--root", str(root), "--caller", "codex"]), 0)
            codex_path = root / ".engineering" / "reports" / "codex" / "latest.json"
            codex_bytes = codex_path.read_bytes()
            self.assertEqual(check.main(["--root", str(root), "--caller", "claude"]), 0)
            self.assertEqual(codex_path.read_bytes(), codex_bytes)
            claude = json.loads((root / ".engineering" / "reports" / "claude" / "latest.json").read_text())
            self.assertEqual(claude["caller"], "claude")
            self.assertEqual(claude["caller_attribution"], "supplied argument, not authentication")
            self.assertEqual(check.main(["--root", str(root)]), 0)
            default = json.loads((root / ".engineering" / "reports" / "latest.json").read_text())
            self.assertNotIn("caller", default)
            explicit = root / "custom"
            self.assertEqual(
                check.main(["--root", str(root), "--caller", "human", "--output", str(explicit)]), 0
            )
            self.assertEqual(json.loads((explicit / "latest.json").read_text())["caller"], "human")
            self.assertFalse((explicit / "human").exists())

    def test_inventory_includes_hidden_files_and_excludes_dependency_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / ".env").write_text("secret-value-never-read")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.js").write_text("")
            (root / "file.txt").write_text("hi")
            listing = check.inventory(root)
            self.assertEqual([f["path"] for f in listing["files"]], [".env", "file.txt"])
            self.assertEqual(listing["excluded"], ["node_modules"])
            self.assertNotIn("secret-value", json.dumps(listing))

    def test_symlink_directory_not_traversed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "loop").symlink_to(root, target_is_directory=True)
            self.assertEqual(check.inventory(root)["excluded"], ["loop"])

    def test_shell_string_and_invalid_timeouts_rejected(self):
        for command, timeout in [("echo test", 1), (["echo"], 0), (["echo"], True), ([], 1)]:
            with self.assertRaises(ValueError):
                check.validate_gates(
                    {"gates": [{"name": "test", "command": command, "timeout_seconds": timeout}]}
                )

    def test_duplicate_gates_rejected(self):
        gate = {"name": "test", "command": ["echo"]}
        with self.assertRaises(ValueError):
            check.validate_gates({"gates": [gate, gate]})

    def test_audit_never_executes_gates(self):
        with tempfile.TemporaryDirectory() as folder:
            gate = {"name": "test", "command": ["{python}", "-c", "raise RuntimeError()"]}
            self.assertEqual(check.run_gate(gate, Path(folder))["status"], "not_run")

    def test_gate_exit_failure_and_missing_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            for code, status in [(0, "passed"), (7, "failed")]:
                gate = {"name": "test", "command": ["{python}", "-c", f"raise SystemExit({code})"]}
                result = check.run_gate(gate, Path(folder), True)
                self.assertEqual((result["status"], result["exit_code"]), (status, code))
            result = check.run_gate(
                {"name": "missing", "command": ["/missing/aegis-executable"]}, Path(folder), True
            )
            self.assertEqual(result["status"], "blocked")

    def test_timeout_stops_process(self):
        with tempfile.TemporaryDirectory() as folder:
            gate = {
                "name": "slow",
                "command": ["{python}", "-c", "import time;time.sleep(10)"],
                "timeout_seconds": 0.05,
            }
            self.assertEqual(check.run_gate(gate, Path(folder), True)["status"], "timeout")

    def test_credentials_not_inherited_and_output_discarded(self):
        from unittest.mock import patch

        with (
            tempfile.TemporaryDirectory() as folder,
            patch.dict("os.environ", {"AEGIS_SECRET": "test-secret"}),
        ):
            gate = {
                "name": "env",
                "command": [
                    "{python}",
                    "-c",
                    "import os;assert 'AEGIS_SECRET' not in os.environ;print('test-secret')",
                ],
            }
            result = check.run_gate(gate, Path(folder), True)
            self.assertEqual(result["status"], "passed")
            self.assertNotIn("test-secret", json.dumps(result))

    def test_html_embedded_data_cannot_close_script(self):
        html = check.render({"path": "</script><img src=x onerror=alert(1)>"}, "__REPORT_JSON__")
        self.assertNotIn("<", html)
        self.assertEqual(json.loads(html)["path"], "</script><img src=x onerror=alert(1)>")

    def test_report_history_and_gate_failure_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "engineering").mkdir()
            (root / "engineering" / "gates.json").write_text(
                json.dumps(
                    {"gates": [{"name": "failing", "command": ["{python}", "-c", "raise SystemExit(1)"]}]}
                )
            )
            output = root / ".engineering" / "reports"
            self.assertEqual(check.main(["--root", str(root), "--output", str(output), "--run-gates"]), 1)
            first = json.loads((output / "latest.json").read_text())
            self.assertEqual(first["gates"][0]["status"], "failed")
            self.assertTrue((output / "index.html").exists())
            self.assertEqual(check.main(["--root", str(root), "--output", str(output)]), 0)
            second = json.loads((output / "latest.json").read_text())
            self.assertEqual(second["gates"][0]["status"], "not_run")
            self.assertEqual(len(list(output.glob("*Z.json"))), 2)

    def test_execution_without_gates_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(check.main(["--root", folder, "--run-gates"]), 2)

    def test_symlink_gate_config_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / "engineering").mkdir()
            (root / "outside.json").write_text('{"gates": []}')
            (root / "engineering" / "gates.json").symlink_to(root / "outside.json")
            self.assertEqual(check.main(["--root", str(root)]), 2)

    def test_test_runner_rejects_empty_suite(self):
        import subprocess

        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "tests").mkdir()
            result = subprocess.run(
                [sys.executable, str(MODULE.parent / "run_tests.py")],
                cwd=folder,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("No tests discovered", result.stderr)

    def test_output_symlinks_cannot_overwrite_external_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            sentinel = root / "sentinel"
            sentinel.write_text("keep")
            output = root / "reports"
            output.mkdir()
            (output / "latest.json").symlink_to(sentinel)
            self.assertEqual(check.main(["--root", str(root), "--output", str(output)]), 2)
            self.assertEqual(sentinel.read_text(), "keep")
            (root / "linked").symlink_to(output, target_is_directory=True)
            with self.assertRaises(ValueError):
                check.report_directory(root / "linked" / "new", root)

    def test_output_outside_root_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            with self.assertRaises(ValueError):
                check.report_directory(root.parent / "outside", root)

    def test_output_hardlink_replaced_without_modifying_original(self):
        import os

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sentinel = root / "original"
            sentinel.write_text("keep")
            os.link(sentinel, root / "latest.json")
            check.write_report(root, "latest.json", "new")
            self.assertEqual(sentinel.read_text(), "keep")

    def test_custom_report_directory_excluded_from_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "reports"
            output.mkdir()
            (output / "latest.json").write_text("{}")
            self.assertEqual(check.inventory(root, output)["files"], [])

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "POSIX signals required")
    def test_interruption_terminates_gate_process(self):
        import signal
        import subprocess
        from unittest.mock import patch

        real_popen, children = subprocess.Popen, []

        def start(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        def interrupt(*args):
            raise KeyboardInterrupt()

        old = signal.signal(signal.SIGALRM, interrupt)
        try:
            with tempfile.TemporaryDirectory() as folder, patch.object(check.subprocess, "Popen", start):
                signal.setitimer(signal.ITIMER_REAL, 0.05)
                with self.assertRaises(KeyboardInterrupt):
                    check.run_gate(
                        {"name": "sleep", "command": ["{python}", "-c", "import time;time.sleep(10)"]},
                        Path(folder),
                        True,
                    )
                self.assertIsNotNone(children[0].poll())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)

    @unittest.skipUnless(sys.platform in ("darwin", "linux"), "POSIX process groups required")
    def test_group_cleanup_when_leader_already_exited(self):
        import signal
        from unittest.mock import patch

        gate = {"name": "quick", "command": ["{python}", "-c", "pass"]}
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(check.os, "killpg", wraps=check.os.killpg) as kill,
        ):
            result = check.run_gate(gate, Path(folder), True)
            self.assertEqual(result["status"], "passed")
            kill.assert_called_once()
            self.assertEqual(kill.call_args.args[1], signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
