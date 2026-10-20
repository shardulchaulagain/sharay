"""Console diagnostics exercise only explicit loopback fixtures or mocked transport."""

import subprocess
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from aegis.interactive import SessionError, terminal_manager
from packages.security_policies import PolicyError


class ConsoleCommandsTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        requests = self.requests
        self.slow_started, self.slow_release = threading.Event(), threading.Event()
        slow_started, slow_release = self.slow_started, self.slow_release

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                requests.append(self.path)
                if self.path == "/slow":
                    slow_started.set()
                    slow_release.wait(3)
                self.send_response(302 if self.path in {"/redirect", "/escape"} else 200)
                if self.path == "/redirect":
                    self.send_header("Location", "/landing")
                if self.path == "/escape":
                    self.send_header("Location", "/private")
                self.send_header("X-Console-Fixture", "observed")
                self.send_header("Set-Cookie", "synthetic-secret=hidden")
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        now = datetime.now(UTC)
        self.scope = {
            "hosts": ["127.0.0.1"],
            "allowed_origins": [self.url],
            "allowed_paths": ["/"],
            "excluded_paths": ["/private"],
            "allowed_cidrs": ["127.0.0.1/32"],
            "categories": ["http_headers", "tls", "dns"],
            "request_rate": 5000.0,
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
        }
        self.session = terminal_manager.create_session(
            organization_id="fixture-org",
            target_id="fixture-target",
            target_url=self.url + "/",
            target_ip="127.0.0.1",
            created_by="fixture-operator",
        )
        self.retest = Mock(return_value="Queued fixture assessment")

    def tearDown(self):
        self.slow_release.set()
        self.session.terminate(reason="test_complete")
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def run_command(self, command):
        return self.session.execute(
            command,
            scope=self.scope,
            owned=False,
            retest=self.retest,
            operator={"username": "fixture", "id": "fixture-operator", "role": "analyst"},
        )

    def drain(self):
        output = bytearray()
        for _ in range(100):
            chunk = self.session.read_available()
            if not chunk:
                break
            output.extend(chunk)
        return output.decode()

    def test_probe_follows_in_scope_redirect_and_redacts_credentials(self):
        result = self.run_command(f"probe {self.url}/redirect")
        self.assertIn("HTTP 200", result)
        self.assertIn("X-Console-Fixture: observed", result)
        self.assertIn("Set-Cookie: [REDACTED]", result)
        self.assertNotIn("synthetic-secret", result)
        self.assertEqual(self.requests, ["/redirect", "/landing"])

    def test_ctrl_c_interrupts_a_blocked_local_http_response(self):
        command = f"probe {self.url}/slow\n".encode()
        thread = threading.Thread(
            target=self.session.write, args=(command,), kwargs={"handler": self.run_command}
        )
        thread.start()
        try:
            self.assertTrue(self.slow_started.wait(1))
            self.session.write(b"\x03")
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertTrue(
                any(event.get("action") == "command_cancelled" for event in self.session.flight_log)
            )
            self.assertNotIn("HTTP 200", self.drain())
        finally:
            self.slow_release.set()
            thread.join(4)

    def test_interrupt_during_rate_pacing_prevents_network_io(self):
        self.scope["request_rate"] = 0.2
        self.session.last_request = time.monotonic()
        started = threading.Event()

        def command_handler(command):
            started.set()
            return self.run_command(command)

        with patch("aegis.interactive._connect") as connect:
            thread = threading.Thread(
                target=self.session.write, args=(b"beacon\n",), kwargs={"handler": command_handler}
            )
            thread.start()
            try:
                self.assertTrue(started.wait(1))
                self.session.write(b"\x03")
                thread.join(1)
                self.assertFalse(thread.is_alive())
                connect.assert_not_called()
            finally:
                self.session.interrupt()
                thread.join(2)

    def test_excluded_redirect_scope_origin_and_category_are_refused_before_io(self):
        with self.assertRaisesRegex(PolicyError, "excluded"):
            self.run_command(f"probe {self.url}/escape")
        self.assertEqual(self.requests, ["/escape"])
        with patch("aegis.interactive._connection") as connection:
            for command in [
                f"probe {self.url}/private",
                "probe https://outside.invalid/",
                "dns outside.invalid",
                "ssl outside.invalid",
            ]:
                with self.assertRaises(PolicyError):
                    self.run_command(command)
            self.scope["categories"] = ["dns"]
            with self.assertRaisesRegex(PolicyError, "category"):
                self.run_command(f"probe {self.url}/")
            connection.assert_not_called()

    def test_beacon_reports_observed_latency_and_missing_firewall_attestation(self):
        result = self.run_command("beacon")
        self.assertIn("Target TCP connection: observed", result)
        self.assertIn("OS/container egress firewall: NOT CHECKED", result)
        self.assertIn("Role: analyst", self.run_command("whoami"))
        self.assertIn("Excluded paths: /private", self.run_command("whoami"))
        self.assertIn("DNS query not applicable", self.run_command("dns 127.0.0.1"))
        self.assertEqual(self.run_command("retest fixture-finding"), "Queued fixture assessment")
        self.retest.assert_called_once_with("fixture-finding")

    def test_dns_uses_real_dns_tool_argv_and_reports_failures(self):
        self.session.target_url = "https://example.com/"
        self.session.target_ip = "93.184.216.34"
        self.scope.update(
            hosts=["example.com"], allowed_origins=["https://example.com"], allowed_cidrs=["93.184.216.34/32"]
        )
        process = Mock(returncode=0)
        process.communicate.return_value = ("example.com. 60 IN A 93.184.216.34\n", "")
        process.poll.return_value = 0
        with patch(
            "aegis.interactive.subprocess.Popen",
            return_value=process,
        ) as run:
            self.assertIn(
                "93.184.216.34",
                self.session.execute(
                    "dns example.com", scope=self.scope, owned=True, operator={}, retest=self.retest
                ),
            )
            self.assertEqual([call.args[0][-1] for call in run.call_args_list], ["A", "AAAA"])
            self.assertTrue(all(call.args[0][0] == "dig" for call in run.call_args_list))
        process.returncode = 9
        process.communicate.return_value = ("", "DNS timed out")
        with patch("aegis.interactive.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(SessionError, "exited 9.*DNS timed out"):
                self.session.execute(
                    "dns example.com", scope=self.scope, owned=True, operator={}, retest=self.retest
                )
        process.poll.return_value = None
        process.communicate.side_effect = [subprocess.TimeoutExpired("dig", 3), ("", "")]
        with patch("aegis.interactive.subprocess.Popen", return_value=process):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.session.execute(
                    "dns example.com", scope=self.scope, owned=True, operator={}, retest=self.retest
                )
        process.kill.assert_called_once()
        self.assertIsNone(self.session._process)

    def test_tls_uses_pinned_destination_and_scope_hostname(self):
        self.session.target_url = "https://example.com/"
        self.session.target_ip = "93.184.216.34"
        self.scope.update(
            hosts=["example.com"], allowed_origins=["https://example.com"], allowed_cidrs=["93.184.216.34/32"]
        )
        with (
            patch("aegis.interactive._connection") as connection,
            patch(
                "aegis.interactive._tls_observation",
                return_value={"protocol": "TLSv1.3", "certificate_verified": True},
            ),
        ):
            result = self.session.execute(
                "ssl example.com", scope=self.scope, owned=True, operator={}, retest=self.retest
            )
            self.assertIn("TLSv1.3", result)
            destination = connection.call_args.args[0]
            self.assertEqual(destination.host, "example.com")
            self.assertEqual(destination.ip, "93.184.216.34")
            connection.return_value.close.assert_called_once()

    def test_expiry_address_ranges_unknown_commands_and_shell_escape_are_refused(self):
        with patch("aegis.interactive._connection") as connection:
            self.session.target_ip = "127.0.0.2"
            with self.assertRaisesRegex(PolicyError, "address ranges"):
                self.run_command(f"probe {self.url}/")
            self.session.target_ip = "127.0.0.1"
            self.scope["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
            with self.assertRaisesRegex(PolicyError, "expired"):
                self.run_command(f"probe {self.url}/")
            connection.assert_not_called()
        with patch("aegis.interactive.subprocess.Popen") as run:
            self.session.write(b"echo test; /bin/sh\n")
            self.assertIn("Unknown command", self.drain())
            run.assert_not_called()
        self.assertEqual(self.session.pid, -1)

    def test_chunked_input_clear_and_multiple_stream_readers(self):
        self.drain()
        self.session.write(b"he")
        self.session.write(b"lp\n")
        for _ in range(50):
            time.sleep(0.02)
            self.session.read_available()
            if b"sharay> " in self.session.output_buffer:
                break
        cursor, first = self.session.output_since(0)
        _, second = self.session.output_since(0)
        self.assertEqual(first, second)
        self.assertIn(b"Commands: probe", first)
        self.assertGreater(cursor, 0)
        self.session.write(b"clear\n")
        self.assertIn("\x1b[2J\x1b[H", self.drain())
        master, slave = self.session.master_fd, self.session.slave_fd
        self.session.terminate()
        self.assertGreaterEqual(master, 0)
        self.assertGreaterEqual(slave, 0)
        self.assertEqual((self.session.master_fd, self.session.slave_fd), (-1, -1))


if __name__ == "__main__":
    unittest.main()
