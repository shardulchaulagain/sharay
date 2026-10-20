"""Paired Vulnerable and Patched Lab Handlers for Ground-Truth Testing.

Implements realistic, safe local endpoints representing OWASP Top 10 vulnerabilities
and their exact remediated counterparts.
"""

from __future__ import annotations

import html
import http.server
import re
import urllib.parse
from pathlib import Path


class VulnerableLabHandler(http.server.BaseHTTPRequestHandler):
    """Intentionally vulnerable local test handler."""

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/products":
            # 1. SQL Injection (Union / Error based)
            q = params.get("q", [""])[0]
            if "'" in q or "UNION" in q.upper():
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'[{"username": "admin", "password_hash": "$2b$12$e8Y8Qe0QfO0a"}]')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'[{"id": 1, "name": "Standard Product"}]')

        elif parsed.path == "/search":
            # 2. Cross-Site Scripting (Reflected unescaped)
            term = params.get("term", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<h1>Search results for: {term}</h1>".encode("utf-8"))

        elif parsed.path == "/tools/ping":
            # 3. Command Injection
            host = params.get("host", [""])[0]
            if ";" in host or "|" in host or "&" in host or "`" in host or "$(" in host:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(
                    b"PING 127.0.0.1 (127.0.0.1): 56 data bytes\nuid=1000(app) gid=1000(app)\nsharay_canary_cmd_executed"
                )
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"PING 127.0.0.1: 0% packet loss")

        elif parsed.path == "/view":
            # 4. Path Traversal / LFI
            filename = params.get("file", [""])[0]
            if ".." in filename or "/etc/passwd" in filename:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(
                    b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                )
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Standard file contents")

        elif parsed.path == "/fetch":
            # 5. SSRF (Unchecked internal network fetch)
            url = params.get("url", [""])[0]
            if "169.254" in url or "localhost" in url or "127.0.0.1" in url or "internal" in url:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    b'{"ami-id": "ami-12345678", "security-credentials": {"role": "app-iam-role"}}'
                )
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"External content fetched successfully")

        elif parsed.path == "/api/user/profile":
            # 6. IDOR (Missing session/tenant check)
            uid = params.get("id", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                f'{{"user_id": "{uid}", "email": "user{uid}@target.corp", "role": "admin" if uid == "1" else "user"}}'.encode(
                    "utf-8"
                )
            )

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class PatchedLabHandler(http.server.BaseHTTPRequestHandler):
    """Hardened/Remediated counterpart with defensive controls."""

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/products":
            # Patched: Parameterized search / no reflection of query tokens
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"[]")

        elif parsed.path == "/search":
            # Patched: Strict HTML Entity Escaping (html.escape)
            term = params.get("term", [""])[0]
            safe_term = html.escape(term, quote=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(f"<h1>Search results for: {safe_term}</h1>".encode("utf-8"))

        elif parsed.path == "/tools/ping":
            # Patched: Strict IPv4 regex validation
            host = params.get("host", [""])[0]
            if not re.fullmatch(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", host):
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid IP destination format")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"PING {host}: 0% packet loss".encode("utf-8"))

        elif parsed.path == "/view":
            # Patched: Safe basename resolution within isolated public folder
            filename = params.get("file", [""])[0]
            clean_name = Path(filename).name
            if ".." in filename or clean_name != filename or clean_name.startswith("."):
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Access denied: path traversal attempt rejected")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Standard file contents")

        elif parsed.path == "/fetch":
            # Patched: Block private/loopback/cloud metadata ranges
            url = params.get("url", [""])[0]
            blocked = ["127.0.0.1", "localhost", "169.254", "10.", "172.16", "192.168"]
            if any(b in url for b in blocked):
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"SSRF Guard: Private/loopback destination rejected")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"External content fetched successfully")

        elif parsed.path == "/api/user/profile":
            # Patched: Session-scoped ownership check
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer valid_user_session_"):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized session"}')
                return
            # Only return the caller's own profile
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"user_id": "caller", "email": "caller@target.corp", "role": "user"}')

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass
