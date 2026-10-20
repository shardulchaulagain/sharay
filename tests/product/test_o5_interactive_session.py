"""Sector O5: real interactive MSF session driver + per-run console secrets.

- MetasploitInteractiveSession opens one session and drives multiple commands against it
  (stateful), then clean-closes -- the "drive live sessions" capability, not one-shot checks.
- The console's collaborative-session secret is per-run random, not a committed constant.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import unittest

from aegis.interactive import MultiOperatorSessionCoordinator
from packages.scanner_adapters.integrations.msf_rpc import (
    MetasploitInteractiveSession,
    OperatorConsentReceipt,
    connect,
)


class InteractiveSessionDriverTest(unittest.TestCase):
    def test_stateful_session_runs_many_commands_then_closes(self):
        state = {"last_cmd": "", "writes": 0, "stopped": False}
        outputs = {"id": "uid=0(root) gid=0(root)", "uname -a": "Linux target 5.15.0 x86_64"}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n))
                m, params = req["method"], req.get("params", [])
                if m == "auth.login":
                    result = {"token": "T"}
                elif m == "module.check":
                    result = {"code": "vulnerable"}
                elif m == "module.execute":
                    result = {"job_id": 7}
                elif m == "session.list":
                    result = {"1": {"type": "shell"}}
                elif m == "session.shell_write":
                    assert params[0] == "1"  # always the same opened session
                    state["last_cmd"] = params[1].strip()
                    state["writes"] += 1
                    result = {}
                elif m == "session.shell_read":
                    result = {"data": outputs.get(state["last_cmd"], "ok")}
                elif m == "session.stop":
                    state["stopped"] = True
                    result = {"result": "success"}
                else:
                    result = {}
                out = json.dumps({"jsonrpc": "2.0", "result": result, "id": req["id"]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        srv.allow_reuse_address = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            client = connect(f"http://127.0.0.1:{port}/api/v1/json-rpc", "msf", "pw")
            consent = OperatorConsentReceipt(
                operator_id="op", target_url="http://t/", approved_module="exploit/multi/http/x"
            )
            with MetasploitInteractiveSession.open(
                client, "exploit/multi/http/x", {"RHOSTS": "127.0.0.1"}, consent
            ) as sess:
                self.assertEqual(sess.session_id, "1")
                self.assertIn("uid=0(root)", sess.run("id"))
                self.assertIn("Linux target", sess.run("uname -a"))
                self.assertEqual(len(sess.history), 2)  # stateful: two commands, one session
            self.assertTrue(state["stopped"], "session must be cleanly closed")
            self.assertGreaterEqual(state["writes"], 2)
        finally:
            srv.shutdown()
            srv.server_close()


class ConsoleSecretTest(unittest.TestCase):
    def test_collaboration_secret_is_per_run_not_constant(self):
        a = MultiOperatorSessionCoordinator("s1", "origin")
        b = MultiOperatorSessionCoordinator("s2", "origin")
        self.assertNotEqual(a.hmac_secret, b.hmac_secret)  # per-instance random
        self.assertNotIn(b"sharay_operator_key_2026", a.hmac_secret)  # not the committed constant


if __name__ == "__main__":
    unittest.main()
