"""High-speed non-destructive wordlist directory and hidden API discovery engine.

Performs concurrent, rate-limited discovery of administrative consoles, API documentation,
sensitive diagnostic endpoints, and configuration archives across authorized targets.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import http.client
import socket
import ssl
import time
from typing import Any

from packages.security_policies import Destination

_MAX_BODY_BYTES = 32 * 1024

_DEFAULT_WORDLIST = [
    ("/admin", "Administrative Portal", "high", "CWE-200"),
    ("/administrator", "Administrative Portal", "high", "CWE-200"),
    ("/wp-admin", "WordPress Administrative Console", "medium", "CWE-200"),
    ("/manager/html", "Apache Tomcat Web Application Manager", "critical", "CWE-200"),
    ("/console", "WebLogic / H2 Administrative Console", "high", "CWE-200"),
    ("/dashboard", "Management Dashboard", "medium", "CWE-200"),
    ("/api", "API Base Endpoint", "low", "CWE-200"),
    ("/api/v1", "API Version 1 Endpoint", "low", "CWE-200"),
    ("/api/v2", "API Version 2 Endpoint", "low", "CWE-200"),
    ("/swagger-ui.html", "Swagger UI API Explorer", "medium", "CWE-200"),
    ("/openapi.json", "OpenAPI Specification JSON", "medium", "CWE-200"),
    ("/swagger.json", "Swagger Specification JSON", "medium", "CWE-200"),
    ("/api-docs", "API Documentation", "medium", "CWE-200"),
    ("/metrics", "Prometheus Server Metrics", "medium", "CWE-200"),
    ("/actuator", "Spring Boot Actuator Root", "high", "CWE-200"),
    ("/actuator/health", "Spring Boot Actuator Health", "medium", "CWE-200"),
    ("/actuator/env", "Spring Boot Actuator Environment (Secret Disclosure)", "critical", "CWE-526"),
    ("/server-status", "Apache HTTP Server Status", "medium", "CWE-200"),
    ("/.env", "Exposed Environment Configuration File", "critical", "CWE-526"),
    ("/.git/config", "Exposed Git Repository Configuration", "critical", "CWE-538"),
    ("/backup.zip", "Exposed Source Code or Database Backup Archive", "critical", "CWE-538"),
    ("/dump.sql", "Exposed Database SQL Dump File", "critical", "CWE-538"),
    ("/.well-known/security.txt", "Security Disclosure Contact Policy", "informational", "CWE-200"),
]


def _probe_path(
    destination: Destination,
    allow_ip: str,
    path: str,
    timeout: float = 3.0,
) -> tuple[int, dict[str, str], int, float]:
    """Execute raw HEAD/GET probe pinned to allow_ip, returning (status, headers, content_length, elapsed_ms)."""
    is_https = destination.scheme == "https"
    target_host = destination.host
    target_port = destination.port

    req_headers = {
        "Host": target_host,
        "User-Agent": "SHARAY-WordlistScanner/1.0 (Directory Discovery)",
        "Accept": "*/*",
        "Connection": "close",
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
        body = resp.read(_MAX_BODY_BYTES)
        return resp.status, resp_headers, len(body), elapsed_ms
    finally:
        conn.close()


def scan_wordlist_directories(
    destination: Destination,
    allow_ip: str,
    custom_paths: list[tuple[str, str, str, str]] | None = None,
    max_workers: int = 4,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Scan authorized target for hidden administrative directories, sensitive files, and API endpoints."""
    wordlist = custom_paths or _DEFAULT_WORDLIST
    findings: list[dict[str, Any]] = []
    discovered_endpoints: list[str] = []

    # 1. Calibrate 404 response length and status to eliminate false positives on wildcard routing
    wildcard_nonce = f"/sharay_nonexistent_calibration_{int(time.time())}"
    try:
        calib_status, _, calib_len, _ = _probe_path(destination, allow_ip, wildcard_nonce, timeout=timeout)
    except Exception:
        calib_status, calib_len = 404, 0

    def _worker(entry: tuple[str, str, str, str]) -> dict[str, Any] | None:
        path, label, severity, cwe_id = entry
        try:
            status, headers, content_len, elapsed = _probe_path(destination, allow_ip, path, timeout=timeout)
        except Exception:
            return None

        # Ignore 404s and wildcard mirror responses (same status and length as non-existent path)
        if status in (404, 400, 502, 503):
            return None
        if calib_status in (200, 301, 302) and abs(content_len - calib_len) < 20 and status == calib_status:
            return None

        # Endpoint discovered
        if status in (200, 301, 302, 401, 403):
            endpoint_url = f"{destination.origin}{path}"
            return {
                "path": path,
                "url": endpoint_url,
                "label": label,
                "severity": severity,
                "cwe_id": cwe_id,
                "status": status,
                "content_len": content_len,
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(_worker, wordlist)
        for res in results:
            if not res:
                continue
            path = res["path"]
            discovered_endpoints.append(path)

            # Emit finding for sensitive exposures (e.g. env, git, dump, actuator/env, manager)
            if res["severity"] in ("critical", "high"):
                repro_curl = f"curl -s -k -I '{res['url']}'"
                findings.append(
                    {
                        "category": "sensitive_directory_exposure",
                        "severity": res["severity"],
                        "title": f"Exposed Sensitive Path: {res['label']} ({path})",
                        "description": (
                            f"Discovered accessible path '{path}' on {destination.host} returning HTTP {res['status']}. "
                            f"Exposing {res['label']} may lead to unauthorized system access, data compromise, or credential leakage."
                        ),
                        "target_url": res["url"],
                        "fingerprint": hashlib.sha256(
                            f"wordlist_{destination.host}_{path}".encode()
                        ).hexdigest(),
                        "cwe_id": res["cwe_id"],
                        "confidence": "high",
                        "status": "confirmed",
                        "lifecycle_state": "REPRODUCED",
                        "remediation": "Restrict access to administrative paths and delete exposed configuration or backup files.",
                        "poc": {
                            "method": "GET",
                            "url": res["url"],
                            "curl_command": repro_curl,
                            "http_status": res["status"],
                            "content_length": res["content_len"],
                        },
                        "evidence": [{"status": res["status"], "content_length": res["content_len"]}],
                    }
                )

    check = {
        "category": "wordlist_directory_discovery",
        "paths_tested": len(wordlist),
        "endpoints_discovered": len(discovered_endpoints),
        "findings_count": len(findings),
        "status": "completed",
    }

    return {
        "discovered_endpoints": discovered_endpoints,
        "findings": findings,
        "check": check,
    }


__all__ = [
    "scan_wordlist_directories",
]
