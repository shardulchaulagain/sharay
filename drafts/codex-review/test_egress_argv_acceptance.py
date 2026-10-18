"""Codex requester contract: container setup must never rewrite tool arguments."""

import shlex
import subprocess
import unittest
from unittest.mock import patch

from services.scanner_worker import container


class EgressArgvAcceptance(unittest.TestCase):
    def test_tool_argv_stays_literal_and_complete(self):
        for args in (
            ["echo", "/input"],
            ["echo", "--mount", "type=bind-data", "--workdir"],
            ["echo", "--network=none", "MARK$(hostname);id>&2#END", ""],
        ):
            with self.subTest(args=args):
                calls = []

                def vm(script):
                    calls.append(script)
                    return subprocess.CompletedProcess([], 0, stdout="fixture", stderr="")

                with (
                    patch.object(container, "container_runtime", return_value="/synthetic/podman"),
                    patch.object(container, "_machine_ssh", side_effect=vm),
                ):
                    container.run_with_egress("busybox", args, allow_ip="203.0.113.5", allow_port=443)
                tokens = shlex.split(calls[1])
                self.assertEqual(tokens[-len(args) - 2 :], ["busybox", *args, "2>&1"])


if __name__ == "__main__":
    unittest.main()
