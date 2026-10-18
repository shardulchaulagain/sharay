"""Unit and integration tests for Operator Takeover Terminal Engine."""

import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from aegis.interactive import SessionError, TerminalManager, terminal_manager


class InteractiveTerminalTests(unittest.TestCase):
    def console(self):
        session = terminal_manager.create_session(
            organization_id="console-regressions",
            target_id="fixture",
            target_url="http://127.0.0.1/",
            target_ip="127.0.0.1",
            created_by="fixture",
        )
        self.addCleanup(session.terminate)
        return session

    def test_running_command_accepts_interrupt_and_discards_its_stale_result(self):
        session = self.console()
        started, release = threading.Event(), threading.Event()

        def handler(_command):
            started.set()
            release.wait(2)
            return "stale result"

        thread = threading.Thread(target=session.write, args=(b"beacon\n",), kwargs={"handler": handler})
        thread.start()
        try:
            self.assertTrue(started.wait(1))
            session.write(b"\x03")
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        _, output = session.output_since(0)
        self.assertIn(b"^C", output)
        self.assertNotIn(b"stale result", output)
        self.assertTrue(any(event.get("action") == "command_cancelled" for event in session.flight_log))
        session.write(b"help\n")
        self.assertIn(b"Commands: probe", session.output_since(0)[1])

    def test_input_decodes_utf8_and_crlf_across_chunks(self):
        session = self.console()
        commands = []
        data = "probe /caf\u00e9\r\n".encode()
        for byte in data:
            session.write(bytes([byte]), handler=lambda command: commands.append(command) or "ok")
        self.assertEqual(commands, ["probe /caf\u00e9"])
        self.assertEqual(sum(event.get("action") == "command_completed" for event in session.flight_log), 1)

    def test_terminated_output_remains_readable_and_termination_is_idempotent(self):
        session = self.console()
        session.emit("final fixture output\r\n")
        session.terminate("fixture")
        session.terminate("duplicate")
        self.assertIn(b"final fixture output", session.output_since(0)[1])
        self.assertEqual(sum(event.get("action") == "session_terminated" for event in session.flight_log), 1)

    def test_concurrent_session_creation_enforces_limit_and_closes_all_fds(self):
        import os
        import pty

        manager = TerminalManager()
        original = pty.openpty

        def slow_open():
            time.sleep(0.01)
            return original()

        def create(_index):
            try:
                return manager.create_session(
                    organization_id="concurrent",
                    target_id="fixture",
                    target_url="http://127.0.0.1/",
                    target_ip="127.0.0.1",
                    created_by="fixture",
                )
            except SessionError:
                return None

        with (
            patch("aegis.interactive.pty.openpty", side_effect=slow_open),
            ThreadPoolExecutor(max_workers=20) as pool,
        ):
            sessions = [session for session in pool.map(create, range(20)) if session]
        try:
            self.assertEqual(len(sessions), 10)
        finally:
            for session in sessions:
                descriptors = session.master_fd, session.slave_fd
                session.terminate()
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_session_lifecycle_and_pty_io(self):
        session = terminal_manager.create_session(
            organization_id="test_org",
            target_id="target_001",
            target_url="https://example.com/",
            target_ip="93.184.216.34",
            created_by="user_admin",
            cols=100,
            rows=30,
        )
        try:
            self.assertTrue(session.is_alive())
            self.assertEqual(session.organization_id, "test_org")
            self.assertEqual(session.target_ip, "93.184.216.34")

            # Read the console banner
            time.sleep(0.05)
            banner_out = session.read_available()
            self.assertGreater(len(banner_out), 0)
            self.assertIn(b"SHARAY OPERATOR TAKEOVER CONSOLE", banner_out)

            # Test writing input and reading response
            session.write(b"help\n")
            time.sleep(0.08)
            echo_out = session.read_available()
            self.assertIn(b"Commands: probe <url>", echo_out)

            # Test window resizing
            session.resize(120, 40)

            # Verify flight log recorded events
            self.assertGreater(len(session.flight_log), 0)
            self.assertTrue(any(event["direction"] == "stdin" for event in session.flight_log))

            # Verify listing includes session
            listed = terminal_manager.list_sessions("test_org")
            self.assertTrue(any(s["id"] == session.id for s in listed))
        finally:
            session.terminate(reason="test_completion")
            self.assertFalse(session.is_alive())
            self.assertEqual(session.state, "terminated")

    def test_unauthorized_org_cannot_access_session(self):
        session = terminal_manager.create_session(
            organization_id="org_alpha",
            target_id="target_002",
            target_url="https://alpha.example/",
            target_ip="192.0.2.1",
            created_by="admin_alpha",
        )
        try:
            # Different org should get None
            retrieved = terminal_manager.get_session(session.id, "org_beta")
            self.assertIsNone(retrieved)

            # Same org should get the session
            valid = terminal_manager.get_session(session.id, "org_alpha")
            self.assertIsNotNone(valid)
        finally:
            session.terminate(reason="test_completion")

    def test_three_state_ownership_lock_human_preemption_and_agent_lockout(self):
        from aegis.interactive import OwnershipState, SessionError

        session = terminal_manager.create_session(
            organization_id="test_org_lock",
            target_id="target_lock_1",
            target_url="https://lock.example/",
            target_ip="192.0.2.10",
            created_by="user_admin",
        )
        try:
            # Session starts in HUMAN_OWNED by default
            self.assertEqual(session.ownership_state, OwnershipState.HUMAN_OWNED.value)

            # Human write succeeds
            session.write(b"echo 'human_1'\n", sender="human")
            self.assertEqual(session.ownership_state, OwnershipState.HUMAN_OWNED.value)

            # Agent write is blocked while human owns console
            with self.assertRaises(SessionError) as ctx:
                session.write(b"echo 'agent_fail'\n", sender="agent")
            self.assertIn(
                "Agent write blocked: human operator currently owns the console", str(ctx.exception)
            )

            # Explicit release to agent
            session.release_to_agent()
            self.assertEqual(session.ownership_state, OwnershipState.AGENT_OWNED.value)

            # Agent write succeeds now
            session.write(b"echo 'agent_success'\n", sender="agent")

            # Human write instantly preempts agent ownership back to HUMAN_OWNED
            session.write(b"echo 'human_preempt'\n", sender="human")
            self.assertEqual(session.ownership_state, OwnershipState.HUMAN_OWNED.value)

            # Agent is blocked again immediately after human preemption
            with self.assertRaises(SessionError):
                session.write(b"echo 'agent_fail_again'\n", sender="agent")
        finally:
            session.terminate(reason="test_completion")

    def test_three_state_ownership_idle_auto_reclaim(self):
        from aegis.interactive import OwnershipState

        session = terminal_manager.create_session(
            organization_id="test_org_reclaim",
            target_id="target_reclaim_1",
            target_url="https://reclaim.example/",
            target_ip="192.0.2.20",
            created_by="user_admin",
        )
        try:
            session.idle_reclaim_seconds = 0.05
            session.write(b"echo 'human_idle_test'\n", sender="human")
            self.assertEqual(session.ownership_state, OwnershipState.HUMAN_OWNED.value)

            # Sleep past idle timeout
            time.sleep(0.06)

            # Agent write should auto-reclaim ownership without raising SessionError
            session.write(b"echo 'agent_auto_reclaimed'\n", sender="agent")
            self.assertEqual(session.ownership_state, OwnershipState.AGENT_OWNED.value)
        finally:
            session.terminate(reason="test_completion")

    def test_three_state_ownership_shared_mode(self):
        from aegis.interactive import OwnershipState

        session = terminal_manager.create_session(
            organization_id="test_org_shared",
            target_id="target_shared_1",
            target_url="https://shared.example/",
            target_ip="192.0.2.30",
            created_by="user_admin",
        )
        try:
            session.set_shared()
            self.assertEqual(session.ownership_state, OwnershipState.SHARED.value)

            # Both agent and human can write freely in SHARED mode
            session.write(b"echo 'agent_in_shared'\n", sender="agent")
            session.write(b"echo 'human_in_shared'\n", sender="human")
            self.assertEqual(session.ownership_state, OwnershipState.SHARED.value)

            # Verify listing returns ownership_state
            listed = terminal_manager.list_sessions("test_org_shared")
            matching = [s for s in listed if s["id"] == session.id]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0]["ownership_state"], OwnershipState.SHARED.value)
        finally:
            session.terminate(reason="test_completion")

    def test_http_and_curl_diagnostic_commands_and_playbook(self):
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        session = self.console()
        scope = {
            "hosts": ["127.0.0.1"],
            "allowed_origins": ["http://127.0.0.1"],
            "allowed_paths": ["/"],
            "excluded_paths": [],
            "allowed_cidrs": ["127.0.0.1/32"],
            "categories": ["http_headers", "dns", "tls"],
            "request_rate": 10.0,
            "max_concurrency": 1,
            "starts_at": (now - timedelta(minutes=5)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        }
        operator = {"id": "op_test", "username": "operator", "role": "admin"}

        # Test playbook dispatch
        playbook_res = session.execute(
            "playbook finding_123",
            scope=scope,
            operator=operator,
            owned=True,
            retest=lambda fid: f"retested {fid}",
            playbook=lambda fid: f"Playbook generated for {fid}",
        )
        self.assertEqual(playbook_res, "Playbook generated for finding_123")

        # Test help command lists new tools
        help_res = session.execute(
            "help",
            scope=scope,
            operator=operator,
            owned=True,
            retest=lambda fid: "retest",
        )
        self.assertIn("http", help_res)
        self.assertIn("curl", help_res)
        self.assertIn("playbook", help_res)

        from packages.security_policies import PolicyError

        # Test syntax validation for http without URL
        with self.assertRaises(SessionError):
            session.execute("http", scope=scope, operator=operator, owned=True, retest=lambda fid: "")

        # Test syntax validation for curl without URL
        with self.assertRaises(SessionError):
            session.execute("curl", scope=scope, operator=operator, owned=True, retest=lambda fid: "")

        # Test invalid DNS record type rejection
        with self.assertRaises(PolicyError):
            session.execute(
                "dns 127.0.0.1 INVALID", scope=scope, operator=operator, owned=True, retest=lambda fid: ""
            )


if __name__ == "__main__":
    unittest.main()
