"""Modern WebSocket handshake and security analyzer.

Audits candidate WebSocket endpoints for Cross-Site WebSocket Hijacking (CSWSH - CWE-1385)
by verifying whether the server enforces strict origin checks during the HTTP Upgrade handshake.
"""

from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
import time
from typing import Any

from packages.security_policies import Destination

_DEFAULT_WEBSOCKET_PATHS = [
    "/ws",
    "/websocket",
    "/socket.io/",
    "/cable",
    "/chat/ws",
    "/api/ws",
]


def _probe_websocket_upgrade(
    destination: Destination,
    allow_ip: str,
    path: str,
    origin_header: str,
    timeout: float = 3.5,
) -> tuple[int, dict[str, str], float]:
    """Execute raw HTTP 101 Switching Protocols handshake probe with specified Origin header."""
    is_https = destination.scheme == "https"
    target_host = destination.host
    target_port = destination.port

    req_headers = {
        "Host": target_host,
        "User-Agent": "SHARAY-WebSocketScanner/1.0",
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
        "Origin": origin_header,
    }

    started = time.monotonic()
    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    if is_https:
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((allow_ip, target_port), timeout=timeout)
        conn_sock = tls_ctx.wrap_socket(sock, server_hostname=target_host)
        conn = http.client.HTTPSConnection(target_host, target_port, timeout=timeout)
        conn.sock = conn_sock
    else:
        conn = http.client.HTTPConnection(allow_ip, target_port, timeout=timeout)

    try:
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        elapsed_ms = (time.monotonic() - started) * 1000
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, elapsed_ms
    finally:
        conn.close()


def audit_websocket_endpoint(
    destination: Destination,
    allow_ip: str,
    discovered_endpoints: list[str] | None = None,
    timeout: float = 3.5,
) -> dict[str, Any]:
    """Audit discovered endpoints for WebSocket protocol support and Cross-Site WebSocket Hijacking (CSWSH)."""
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    candidate_paths = list(_DEFAULT_WEBSOCKET_PATHS)
    if discovered_endpoints:
        for ep in discovered_endpoints:
            low = ep.lower()
            if "ws" in low or "socket" in low or "stream" in low:
                if ep not in candidate_paths:
                    candidate_paths.append(ep)

    tested_endpoints: list[str] = []
    evil_origin = "https://evil-attacker.example.org"

    for path in candidate_paths:
        tested_endpoints.append(path)
        endpoint_url = f"{destination.origin}{path}"

        try:
            status, headers, _ = _probe_websocket_upgrade(
                destination, allow_ip, path, origin_header=evil_origin, timeout=timeout
            )
        except Exception:
            continue

        # If server returns 101 Switching Protocols or echoes Sec-WebSocket-Accept for an arbitrary cross-origin:
        is_upgraded = status == 101 or "sec-websocket-accept" in headers
        if is_upgraded:
            repro_curl = (
                f"curl -s -k -N -i '{endpoint_url}' "
                f"-H 'Upgrade: websocket' "
                f"-H 'Connection: Upgrade' "
                f"-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "
                f"-H 'Sec-WebSocket-Version: 13' "
                f"-H 'Origin: {evil_origin}'"
            )
            findings.append(
                {
                    "category": "broken_access_control",
                    "severity": "high",
                    "title": f"Cross-Site WebSocket Hijacking (CSWSH) on {path}",
                    "description": (
                        f"WebSocket endpoint {path} accepted handshake from arbitrary third-party Origin '{evil_origin}' "
                        f"(HTTP 101 Switching Protocols). Attackers can hijack authenticated WebSocket sessions cross-origin."
                    ),
                    "target_url": endpoint_url,
                    "fingerprint": hashlib.sha256(f"cswsh_{destination.host}_{path}".encode()).hexdigest(),
                    "cwe_id": "CWE-1385",
                    "confidence": "high",
                    "status": "confirmed",
                    "lifecycle_state": "REPRODUCED",
                    "remediation": "Validate the 'Origin' request header against a strict allowlist during WebSocket handshake.",
                    "poc": {
                        "method": "GET",
                        "url": endpoint_url,
                        "curl_command": repro_curl,
                        "tested_origin": evil_origin,
                        "handshake_status": status,
                    },
                    "evidence": [{"status": status, "upgraded": True, "origin": evil_origin}],
                }
            )

    checks.append(
        {
            "category": "websocket_security_assessment",
            "endpoints_probed": len(tested_endpoints),
            "findings_count": len(findings),
            "status": "completed",
        }
    )

    return {
        "findings": findings,
        "checks": checks,
    }


__all__ = [
    "audit_websocket_endpoint",
]
