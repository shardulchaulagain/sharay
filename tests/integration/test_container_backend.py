"""L1 rootless-container backend: locked-down request building, availability, fail-closed egress."""

import tempfile
import unittest
from unittest.mock import patch

from services.scanner_worker import IsolationError
from services.scanner_worker import container as cb


class ContainerBackendTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.input = self._dir.name

    def test_build_argv_is_locked_down(self):
        argv = cb.build_run_argv("podman", "alpine:3.19", ["echo", "hi"], input_dir=self.input)
        joined = " ".join(argv)
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
            self.assertIn(flag, argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--memory", argv)
        self.assertIn("type=bind,src=", joined)
        self.assertTrue(joined.endswith("alpine:3.19 echo hi"))

    def test_any_egress_destination_is_refused_fail_closed(self):
        with self.assertRaisesRegex(IsolationError, "not enforceable"):
            cb.build_run_argv(
                "podman", "alpine:3.19", ["echo"], input_dir=self.input, destinations=[("127.0.0.1", 8080)]
            )

    def test_malformed_requests_are_rejected(self):
        bad = [
            dict(image="Bad Image Name", tool_argv=["x"]),
            dict(image="alpine", tool_argv=[]),
            dict(image="alpine", tool_argv="echo hi"),  # shell string
            dict(image="alpine", tool_argv=["x\0y"]),  # NUL
            dict(image="alpine", tool_argv=["x"], memory_mb=4),  # too small
            dict(image="alpine", tool_argv=["x"], cpus=99),  # too many
            dict(image="alpine", tool_argv=["x"], max_seconds=0),
        ]
        for kw in bad:
            with self.assertRaises(IsolationError):
                cb.build_run_argv("podman", input_dir=self.input, **kw)
        with self.assertRaises(IsolationError):
            cb.build_run_argv("podman", "alpine", ["x"], input_dir="/no/such/dir-xyz")

    def test_runtime_probe_is_fail_closed(self):
        rt = cb.container_runtime()
        self.assertTrue(rt is None or isinstance(rt, str))  # never a false positive
        # With no runtime, run_contained must refuse rather than run unisolated.
        with patch.object(cb, "container_runtime", return_value=None):
            with self.assertRaisesRegex(IsolationError, "No container runtime"):
                cb.run_contained("alpine", ["echo"], input_dir=self.input)

    def test_attest_shape(self):
        a = cb.attest()
        self.assertEqual(a["backend"], "rootless-container")
        self.assertIn("no_network", a["enforced"])

    def test_egress_ruleset_is_default_drop_allow_one(self):
        rules = cb.build_egress_ruleset("SHARAY_EGRESS", "10.88.0.0/16", "203.0.113.5", 443)
        up = [" ".join(c) for c in rules["up"]]
        self.assertTrue(any("203.0.113.5 -p tcp --dport 443 -j ACCEPT" in r for r in up))
        self.assertTrue(any(r.endswith("-j DROP") for r in up))  # everything else dropped
        self.assertTrue(any("-j SHARAY_EGRESS" in r for r in up))
        # teardown undoes the FORWARD hooks and removes the chain
        down = [" ".join(c) for c in rules["down"]]
        self.assertTrue(any("-X SHARAY_EGRESS" in r for r in down))

    def test_run_with_egress_shell_quotes_argv_no_injection(self):
        import shlex
        from types import SimpleNamespace

        scripts = []

        def recorder(script, timeout=60.0):
            scripts.append(script)
            return SimpleNamespace(returncode=0, stdout="")

        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", recorder):
                cb.run_with_egress("busybox", ["echo", "a; id #pwn"], allow_ip="203.0.113.5", allow_port=443)
        run_script = next(s for s in scripts if "podman run" in s)
        self.assertIn(shlex.quote("a; id #pwn"), run_script)  # payload stays one quoted argument
        self.assertNotIn("echo a; id", run_script)  # never an unquoted second command

    def test_run_with_egress_preserves_tool_args_that_look_like_setup_flags(self):
        import shlex
        from types import SimpleNamespace

        scripts = []
        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(
                cb,
                "_machine_ssh",
                lambda s, timeout=60.0: scripts.append(s) or SimpleNamespace(returncode=0, stdout=""),
            ):
                cb.run_with_egress(
                    "busybox",
                    ["echo", "--workdir", "type=bind-x", "--network=none"],
                    allow_ip="203.0.113.5",
                    allow_port=443,
                )
        run_script = next(s for s in scripts if "podman run" in s)
        toks = shlex.split(run_script)
        # the whole tool_argv survives, in order, right after the image
        self.assertEqual(
            toks[toks.index("busybox") + 1 :][:4], ["echo", "--workdir", "type=bind-x", "--network=none"]
        )

    def test_run_with_egress_tears_down_even_when_setup_times_out(self):
        import subprocess
        from types import SimpleNamespace

        calls = []

        def ssh(script, timeout=60.0):
            calls.append(script)
            if len(calls) == 1:  # the egress-allowlist setup times out
                raise subprocess.TimeoutExpired(cmd=["podman", "machine", "ssh"], timeout=timeout)
            return SimpleNamespace(returncode=0, stdout="")

        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", ssh):
                with self.assertRaises(subprocess.TimeoutExpired):
                    cb.run_with_egress("busybox", ["echo"], allow_ip="203.0.113.5", allow_port=443)
        self.assertGreaterEqual(len(calls), 2)  # setup attempted, then teardown
        self.assertIn("SHARAY_EGRESS", calls[-1])  # the firewall chain is always removed

    def test_run_with_egress_runs_no_tool_when_setup_exhausts_budget(self):
        from types import SimpleNamespace

        scripts = []

        def ssh(script, timeout=60.0):
            scripts.append(script)
            return SimpleNamespace(returncode=0, stdout="")

        # Clock jumps past the budget during setup: started, remaining-calc, duration_ms.
        clock = iter([0.0, 100.0, 100.0, 100.0])
        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", ssh):
                with patch.object(cb.time, "monotonic", lambda: next(clock)):
                    res = cb.run_with_egress(
                        "busybox", ["nmap"], allow_ip="203.0.113.5", allow_port=443, max_seconds=1
                    )
        self.assertEqual(res.outcome, "failed")
        self.assertEqual(res.exit_code, 124)
        self.assertFalse(any("podman run" in s for s in scripts))  # tool never dispatched on spent clock
        self.assertTrue(any("SHARAY_EGRESS" in s for s in scripts))  # allowlist still torn down

    def test_run_with_egress_nonzero_teardown_is_never_completed(self):
        from types import SimpleNamespace

        calls = []

        def ssh(script, timeout=60.0):
            calls.append(script)
            if len(calls) == 3:  # teardown (after setup, then tool) fails to remove the allowlist
                return SimpleNamespace(returncode=1, stdout="")
            return SimpleNamespace(returncode=0, stdout="scan output")

        with patch.object(cb, "container_runtime", return_value="/opt/homebrew/bin/podman"):
            with patch.object(cb, "_machine_ssh", ssh):
                res = cb.run_with_egress("busybox", ["nmap"], allow_ip="203.0.113.5", allow_port=443)
        self.assertEqual(res.outcome, "failed")  # cleanup failure demotes an otherwise-successful run
        self.assertFalse(res.scratch_removed)
        self.assertIn(b"teardown failed", res.stderr)

    def test_egress_ruleset_rejects_a_hostname_or_bad_port(self):
        with self.assertRaises(IsolationError):
            cb.build_egress_ruleset("c", "10.88.0.0/16", "example.com", 443)  # not a literal IP
        with self.assertRaises(IsolationError):
            cb.build_egress_ruleset("c", "10.88.0.0/16", "203.0.113.5", 0)


if __name__ == "__main__":
    unittest.main()
