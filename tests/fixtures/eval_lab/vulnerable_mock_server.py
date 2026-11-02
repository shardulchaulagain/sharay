"""In-process vulnerable mock server for hermetic evaluation and ground-truth testing (K1).

Simulates deliberate, deterministic vulnerabilities across web and API surfaces:
1. SQL Injection on /vulnerabilities/sqli/?id=... (CWE-89)
2. OS Command Injection on /ping.php?ip=... (CWE-78)
3. SSRF on /fetch.php?url=... (CWE-918)
4. Sensitive File Disclosure on /phpinfo.php and /.env (CWE-200)
5. Missing Defensive Headers (CWE-693, CWE-1021, CWE-319)
"""

from __future__ import annotations

import http.server
import threading
import urllib.parse
from typing import Any


class VulnerableMockHandler(http.server.BaseHTTPRequestHandler):
    """Deterministic HTTP request handler with seeded security vulnerabilities."""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard logging to keep test console clean
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. SQL Injection Endpoint
        if path == "/vulnerabilities/sqli/":
            param_id = query.get("id", [""])[0]
            if "'" in param_id or "union" in param_id.lower():
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                # Reflect injected canary or SQL syntax error
                self.wfile.write(b"<html><body><h1>User Query Result</h1>")
                if "sharay_canary" in param_id:
                    self.wfile.write(f"<p>ID: {param_id}</p>".encode())
                else:
                    self.wfile.write(
                        b"<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>"
                    )
                self.wfile.write(b"</body></html>")
                return
            # Normal baseline
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>User Query Result</h1><p>User: admin, First Name: Admin, Surname: User</p></body></html>"
            )
            return

        # 2. OS Command Injection Endpoint
        if path == "/ping.php":
            ip_val = query.get("ip", [""])[0]
            if ";" in ip_val or "|" in ip_val or "&" in ip_val:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                if "sharay_canary_cmd" in ip_val:
                    self.wfile.write(
                        b"<html><body><pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\nsharay_canary_cmd\n</pre></body></html>"
                    )
                else:
                    self.wfile.write(
                        b"<html><body><pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\nroot:x:0:0:root:/root:/bin/bash\n</pre></body></html>"
                    )
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><body><pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.035 ms\n</pre></body></html>"
            )
            return

        # 3. SSRF Endpoint
        if path == "/fetch.php":
            url_val = query.get("url", [""])[0]
            if "127.0.0.1" in url_val or "localhost" in url_val:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><p>Fetched internal response: Failed to connect to 127.0.0.1 port 80: Connection refused</p></body></html>"
                )
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><p>Fetched remote resource successfully.</p></body></html>")
            return

        # 4. Sensitive File Disclosures
        if path == "/phpinfo.php":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.2.14</h1><p>Configuration File Path: /etc/php</p></body></html>"
            )
            return

        if path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(
                b"DATABASE_URL=postgres://app:SecretPass123@db:5432/production\nSECRET_KEY=sharay_super_secret_jwt_key_999\n"
            )
            return

        # Default root
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Vulnerable Test Lab</h1><a href='/vulnerabilities/sqli/'>SQLi</a><a href='/ping.php'>Ping</a><a href='/fetch.php'>Fetch</a></body></html>"
        )


class VulnerableMockServer:
    """Threaded test server wrapper."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.server = http.server.HTTPServer((host, port), VulnerableMockHandler)
        self.host, self.port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


__all__ = ["VulnerableMockServer", "VulnerableMockHandler"]
