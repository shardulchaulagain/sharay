"""The Seatbelt runner's boundary, observed from inside it against local fixtures only."""

import errno
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from services.scanner_worker import NOT_ENFORCED, PROBED, IsolationError, attest, run_isolated

PYTHON = os.path.realpath(sys.executable)
PREFIX = Path(sys.base_prefix)
ROOT = Path(__file__).resolve().parents[2]
# Runs each expression in turn and prints 0 or the errno it raised.
ATTEMPTS = """
import json, os, socket, subprocess, sys
results = []
for action in ACTIONS:
    try:
        action()
        results.append(0)
    except OSError as exc:
        results.append(exc.errno)
print(json.dumps(results))
"""


def run_python(code: str, **options):
    # The interpreter is the tool here, so its prefix is runtime (exec), not data.
    return run_isolated([PYTHON, "-I", "-c", code], exec_paths=[PREFIX], **options)


def attempts(actions: str, **options) -> list[int]:
    result = run_python(ATTEMPTS.replace("ACTIONS", actions), max_seconds=10, **options)
    if result.outcome != "completed":
        raise AssertionError((result.outcome, result.stdout, result.stderr))
    return json.loads(result.stdout)


class IsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.attestation = attest()
        if not cls.attestation["available"]:
            # Not a pass: nested sandboxes and non-macOS hosts cannot apply the profile.
            raise unittest.SkipTest("Seatbelt sandbox cannot be applied in this environment.")

    def temporary_folder(self) -> Path:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        return Path(folder.name).resolve()

    def test_attestation_lists_only_probed_controls_and_never_live_egress(self):
        self.assertEqual(self.attestation["backend"], "macos-seatbelt")
        self.assertEqual(set(self.attestation["enforced"]), set(PROBED))
        self.assertEqual(self.attestation["not_enforced"], list(NOT_ENFORCED))
        for missing in (
            "live_destination_egress",
            "escape_containment_for_forking_tools",
        ):
            self.assertIn(missing, NOT_ENFORCED)
            self.assertNotIn(missing, self.attestation["enforced"])

    def test_only_the_exact_granted_address_port_and_protocol_is_reachable(self):
        with (
            socket.socket() as allowed,
            socket.socket() as blocked,
            socket.socket(socket.AF_INET6) as other_family,
        ):
            for listener in (allowed, blocked):
                listener.bind(("127.0.0.1", 0))
                listener.listen()
            granted, refused = allowed.getsockname()[1], blocked.getsockname()[1]
            other_family.bind(("::1", granted))
            other_family.listen()
            # 192.0.2.1 is RFC 5737 documentation space; the kernel must refuse before any packet.
            actions = f"""[
    lambda: socket.create_connection(("127.0.0.1", {granted}), 1).close(),
    lambda: socket.create_connection(("::1", {granted}), 1).close(),
    lambda: socket.create_connection(("127.0.0.1", {refused}), 1).close(),
    lambda: socket.create_connection(("192.0.2.1", 80), 1).close(),
    lambda: socket.socket().bind(("127.0.0.1", 0)),
    lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", {granted})),
]"""
            ipv4 = run_python(ATTEMPTS.replace("ACTIONS", actions), egress=[("127.0.0.1", granted)])
            ipv6 = run_python(ATTEMPTS.replace("ACTIONS", actions), egress=[("::1", granted)])
        denied = errno.EPERM
        # Same port, other address family, and UDP to the granted port are all refused.
        self.assertEqual(json.loads(ipv4.stdout), [0, denied, denied, denied, denied, denied], ipv4.stderr)
        self.assertEqual(json.loads(ipv6.stdout), [denied, 0, denied, denied, denied, denied], ipv6.stderr)
        self.assertIn("exact_loopback_address", ipv4.enforced)

    def test_filesystem_is_confined_to_scratch_and_scratch_is_removed(self):
        secret = self.temporary_folder() / "outside.txt"
        secret.write_text("synthetic")
        result = run_python(
            ATTEMPTS.replace(
                "ACTIONS",
                f"""[
    lambda: open({str(secret)!r}).read(),
    lambda: open({str(secret)!r} + ".new", "w"),
    lambda: os.listdir({str(secret.parent)!r}),
    lambda: open({str(Path(__file__).resolve())!r}).read(),
    lambda: open("inside.txt", "w").write("x"),
    # Known gap, pinned on purpose: metadata of a known path is visible even though its content is not.
    lambda: os.stat({str(secret)!r}),
]""",
            )
            + "print(os.getcwd())",
            allow_scratch_writes=True,
            max_seconds=10,
        )
        self.assertEqual(result.outcome, "completed", result.stderr)
        outcomes, scratch = result.stdout.decode().splitlines()
        self.assertEqual(json.loads(outcomes), [errno.EPERM] * 4 + [0, 0])
        self.assertFalse(Path(str(secret) + ".new").exists())
        self.assertFalse(Path(scratch).exists())

    def test_scratch_a_tool_locked_is_still_removed_without_touching_symlink_targets(self):
        outside = self.temporary_folder() / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("synthetic")
        outside.chmod(0o500)
        self.addCleanup(outside.chmod, 0o700)
        code = f"""
import os, stat
print(os.getcwd())
os.makedirs("locked/inner")
open("locked/inner/fact", "w").close()
open("frozen", "w").close()
os.symlink({str(outside)!r}, "folder-link")
os.symlink({str(outside / "keep.txt")!r}, "file-link")
os.chflags("frozen", stat.UF_IMMUTABLE)
for path in ("locked/inner", "locked", "."):
    os.chmod(path, 0)
"""
        result = run_python(code, allow_scratch_writes=True, max_seconds=10)
        self.assertEqual((result.outcome, result.scratch_removed), ("completed", True), result.stderr)
        self.assertFalse(Path(result.stdout.decode().strip()).exists())
        # Unlocking went through neither symlink: the outside folder keeps its mode and its file.
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o500)
        self.assertEqual((outside / "keep.txt").read_text(), "synthetic")

    def test_a_scratch_directory_that_cannot_be_removed_is_never_a_completed_run(self):
        with mock.patch("services.scanner_worker.shutil.rmtree", side_effect=OSError("synthetic")):
            result = run_python("import os; print(os.getcwd())")
        scratch = Path(result.stdout.decode().strip())
        self.addCleanup(lambda: scratch.exists() and __import__("shutil").rmtree(scratch))
        self.assertEqual((result.outcome, result.exit_code, result.scratch_removed), ("failed", 0, False))
        self.assertTrue(scratch.exists())

    def test_data_paths_are_readable_but_never_executable(self):
        data = self.temporary_folder()
        (data / "data.txt").write_text("synthetic")
        tool = data / "tool"
        tool.write_text(f"#!{PYTHON} -I\nprint('EXECUTED')\n")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        code = f"""
import os, shutil
print(open({str(data / "data.txt")!r}).read())
shutil.copy({str(tool)!r}, "dropped")
os.chmod("dropped", 0o700)
for path in ({str(tool)!r}, os.path.abspath("dropped"), "/usr/bin/true"):
    try:
        os.execv(path, [path])
    except OSError as exc:
        print(exc.errno)
"""
        result = run_python(code, read_paths=[data, "/usr/bin"], allow_scratch_writes=True, max_seconds=10)
        self.assertEqual(result.outcome, "completed", result.stderr)
        # A tool in a data path, one the run dropped into scratch, and a system binary under a
        # read-only grant all fail to start.
        self.assertEqual(result.stdout.decode().split(), ["synthetic"] + [str(errno.EPERM)] * 3)

    def test_a_tool_cannot_create_processes_unless_fork_is_granted(self):
        actions = f"""[
    os.fork,
    lambda: subprocess.run([{PYTHON!r}, "-I", "-c", "pass"]),
    lambda: os.posix_spawn({PYTHON!r}, [{PYTHON!r}, "-I", "-c", "pass"], {{}}),
    os.setsid,
]"""
        self.assertEqual(attempts(actions), [errno.EPERM] * 4)
        contained = run_python("pass")
        self.assertIn("process_escape_containment", contained.enforced)
        self.assertIn("process_count_limit", contained.enforced)
        self.assertNotIn("loopback_port_egress", contained.enforced)
        forking = run_python(
            "import subprocess, sys; subprocess.run([sys.executable, '-I', '-c', 'pass'])", allow_fork=True
        )
        self.assertEqual(forking.outcome, "completed", forking.stderr)
        self.assertNotIn("process_escape_containment", forking.enforced)
        self.assertNotIn("process_count_limit", forking.enforced)

    def test_deadline_kills_the_whole_group_even_when_sigterm_is_ignored(self):
        code = f"""
import signal, subprocess, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([{PYTHON!r}, "-I", "-c", "import time; time.sleep(60)"])
print(child.pid, flush=True)
time.sleep(60)
"""
        result = run_python(code, allow_fork=True, max_seconds=1, terminate_after_seconds=0.3)
        self.assertEqual(result.outcome, "timeout")
        self.assertLess(result.duration_ms, 5000)
        grandchild = int(result.stdout)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        self.fail("A grandchild process survived the deadline.")

    def test_a_single_process_tool_cannot_leave_its_group_and_is_killed(self):
        code = """
import os, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
for change in (os.setsid, lambda: os.setpgid(0, 0), lambda: os.setpgid(0, os.getppid())):
    try:
        change()
    except OSError:
        pass
print(os.getpgid(0) == os.getpid(), flush=True)
time.sleep(60)
"""
        result = run_python(code, max_seconds=1, terminate_after_seconds=0.3)
        # Still its own group leader after every attempt, so the group SIGKILL reached it.
        self.assertEqual((result.outcome, result.stdout.strip(), result.exit_code), ("timeout", b"True", -9))

    def test_limits_clamp_to_the_hard_caps_inherited_from_the_worker(self):
        # A separate process, so the worker's own caps (NOFILE 128, CPU 300) never touch the test runner.
        code = """
import resource
resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
from services.scanner_worker import attest, run_isolated
print(run_isolated(["/usr/bin/true"], max_seconds=300).outcome, attest()["available"])
"""
        completed = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60
        )
        self.assertEqual(
            (completed.returncode, completed.stdout.split()), (0, ["completed", "True"]), completed.stderr
        )

    def test_cancellation_stops_a_running_tool(self):
        stop_at = time.monotonic() + 0.3
        result = run_python("import time; time.sleep(60)", cancelled=lambda: time.monotonic() >= stop_at)
        self.assertEqual(result.outcome, "cancelled")
        self.assertLess(result.duration_ms, 5000)

    def test_output_is_bounded_and_only_overflow_counts_as_truncated(self):
        exact = run_python("import sys; sys.stdout.write('x' * 4096)", max_output_bytes=4096)
        self.assertEqual(
            (exact.outcome, len(exact.stdout), exact.output_truncated), ("completed", 4096, False)
        )
        for size in (4097, 1048576):
            over = run_python(f"import sys; sys.stdout.write('x' * {size})", max_output_bytes=4096)
            self.assertEqual((len(over.stdout), over.output_truncated), (4096, True), size)
        # The kernel, not only the parent's bounded read, caps what a tool can write to disk.
        written = attempts(
            '[lambda: open("big", "wb").write(b"x" * 1048576)]'
            # Known gap, pinned on purpose: the cap is per file, so many small files still fit.
            ' + [lambda n=n: open(f"part{n}", "wb").write(b"x" * 4096) for n in range(8)]',
            allow_scratch_writes=True,
            max_output_bytes=4096,
        )
        self.assertEqual(written, [errno.EFBIG] + [0] * 8)
        self.assertIn("scratch_quota_for_writing_tools", NOT_ENFORCED)

    def test_nothing_is_writable_unless_scratch_writes_are_granted(self):
        actions = """[
    lambda: open("file", "w"),
    lambda: os.mkdir("folder"),
    lambda: os.symlink("/etc", "link"),
    lambda: open(os.path.join(os.environ["TMPDIR"], "temp"), "w"),
]"""
        self.assertEqual(attempts(actions), [errno.EPERM] * 4)
        self.assertEqual(attempts(actions, allow_scratch_writes=True), [0] * 4)
        self.assertIn("aggregate_scratch_quota", run_python("pass").enforced)
        self.assertNotIn("aggregate_scratch_quota", run_python("pass", allow_scratch_writes=True).enforced)

    def test_environment_is_not_inherited(self):
        os.environ["SHARAY_TEST_PARENT_ONLY"] = "synthetic"
        self.addCleanup(os.environ.pop, "SHARAY_TEST_PARENT_ONLY")
        result = run_python("import os; print(sorted(os.environ))")
        self.assertEqual(result.outcome, "completed", result.stderr)
        self.assertNotIn("SHARAY_TEST_PARENT_ONLY", result.stdout.decode())

    def test_a_threaded_caller_can_launch_safely(self):
        release = threading.Event()
        bystander = threading.Thread(target=release.wait)
        bystander.start()
        self.addCleanup(bystander.join)
        self.addCleanup(release.set)
        outcomes = []
        worker = threading.Thread(target=lambda: outcomes.append(run_python("print('ok')").outcome))
        worker.start()
        worker.join(15)
        self.assertEqual(outcomes, ["completed"])

    def test_requests_the_backend_cannot_enforce_are_rejected(self):
        for argv, options in (
            (f"{PYTHON} -c pass", {}),
            (["python3", "-c", "pass"], {}),
            ([], {}),
            ([PYTHON, "-c", "pass"], {"egress": [("192.0.2.10", 443)]}),
            ([PYTHON, "-c", "pass"], {"egress": [("localhost", 80)]}),
            ([PYTHON, "-c", "pass"], {"egress": [("127.0.0.2", 80)]}),
            ([PYTHON, "-c", "pass"], {"egress": [("127.0.0.1", 0)]}),
            ([PYTHON, "-c", "pass"], {"max_seconds": 301}),
            ([PYTHON, "-c", "pass"], {"max_seconds": True}),
            ([PYTHON, "-c", "pass"], {"max_seconds": float("nan")}),
            ([PYTHON, "-c", "pass"], {"max_output_bytes": 1.5}),
            ([PYTHON, "-c", "pass"], {"max_output_bytes": True}),
            ([PYTHON, "-c", "pass"], {"terminate_after_seconds": "1"}),
            ([PYTHON, "-c", "pass"], {"allow_fork": 1}),
            ([PYTHON, "-c", "pass"], {"allow_scratch_writes": "yes"}),
            ([PYTHON, "-c", "pass"], {"read_paths": ["/nonexistent-sharay-path"]}),
            ([PYTHON, "-c", "pass"], {"exec_paths": ["/nonexistent-sharay-path"]}),
        ):
            with self.subTest(argv=argv, options=options), self.assertRaises(IsolationError):
                run_isolated(argv, **options)


if __name__ == "__main__":
    unittest.main()
