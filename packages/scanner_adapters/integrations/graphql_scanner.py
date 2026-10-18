"""Modern GraphQL API security analyzer.

Performs non-destructive audits of GraphQL endpoints discovered by the crawler:
1. Schema Introspection verification (CWE-200 Information Disclosure).
2. Batch Query Amplification Denial-of-Service verification (CWE-776 / CWE-400).
3. Field Suggestion Schema Leak verification (CWE-200).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlencode

from packages.security_policies import Destination

_MAX_BODY_BYTES = 128 * 1024
_DEFAULT_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/gql",
    "/query",
]


def _request_graphql(
    destination: Destination,
    allow_ip: str,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: float = 3.5,
) -> tuple[int, dict[str, str], str, float]:
    """Execute raw HTTP request pinned to allow_ip."""
    is_https = destination.scheme == "https"
    target_host = destination.host
    target_port = destination.port

    req_headers = {
        "Host": target_host,
        "User-Agent": "SHARAY-GraphQLScanner/1.0 (API Security Audit)",
        "Accept": "application/json, text/plain, */*",
        "Connection": "close",
    }
    if headers:
        req_headers.update(headers)
    if body and "Content-Length" not in req_headers:
        req_headers["Content-Length"] = str(len(body.encode("utf-8")))

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
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        elapsed_ms = (time.monotonic() - started) * 1000
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        resp_body = resp.read(_MAX_BODY_BYTES).decode("utf-8", errors="replace")
        return resp.status, resp_headers, resp_body, elapsed_ms
    finally:
        conn.close()


def audit_graphql_endpoint(
    destination: Destination,
    allow_ip: str,
    discovered_endpoints: list[str] | None = None,
    timeout: float = 3.5,
) -> dict[str, Any]:
    """Execute active security audits across candidate and discovered GraphQL endpoints."""
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    candidate_paths = list(_DEFAULT_GRAPHQL_PATHS)
    if discovered_endpoints:
        for ep in discovered_endpoints:
            low = ep.lower()
            if "graphql" in low or "gql" in low:
                if ep not in candidate_paths:
                    candidate_paths.append(ep)

    tested_endpoints: list[str] = []

    for ep in candidate_paths:
        tested_endpoints.append(ep)
        endpoint_url = f"{destination.origin}{ep}"

        # 1. Introspection Query Audit
        intro_query = {
            "query": (
                "query IntrospectionCheck { "
                "  __schema { "
                "    queryType { name } "
                "    mutationType { name } "
                "    types { name kind description } "
                "  } "
                "}"
            )
        }
        intro_json = json.dumps(intro_query)
        try:
            status, _, body, _ = _request_graphql(
                destination,
                allow_ip,
                "POST",
                ep,
                headers={"Content-Type": "application/json"},
                body=intro_json,
                timeout=timeout,
            )
        except Exception:
            status = 0
            body = ""

        is_graphql = False
        type_count = 0
        mutation_name = None

        if status == 200 and "__schema" in body:
            is_graphql = True
            try:
                data = json.loads(body)
                schema = data.get("data", {}).get("__schema", {})
                types = schema.get("types", [])
                type_count = len(types)
                mutation_info = schema.get("mutationType")
                if mutation_info:
                    mutation_name = mutation_info.get("name")
            except Exception:
                pass

            repro_curl = (
                f"curl -s -k -X POST '{endpoint_url}' -H 'Content-Type: application/json' -d '{intro_json}'"
            )
            findings.append(
                {
                    "category": "information_disclosure",
                    "severity": "medium",
                    "title": f"GraphQL Introspection Enabled on {ep}",
                    "description": (
                        f"GraphQL endpoint {ep} allows full schema introspection. Disclosed {type_count} "
                        f"types and mutation root '{mutation_name or 'None'}'. This enables attackers "
                        f"to map complete backend models, hidden queries, and mutation parameters."
                    ),
                    "target_url": endpoint_url,
                    "fingerprint": hashlib.sha256(
                        f"graphql_intro_{destination.host}_{ep}".encode()
                    ).hexdigest(),
                    "cwe_id": "CWE-200",
                    "confidence": "high",
                    "status": "confirmed",
                    "lifecycle_state": "REPRODUCED",
                    "remediation": "Disable introspection queries in production environments (e.g. set introspection: false).",
                    "poc": {
                        "method": "POST",
                        "url": endpoint_url,
                        "curl_command": repro_curl,
                        "type_count": type_count,
                        "mutation_root": mutation_name,
                    },
                    "evidence": [{"status": status, "types_discovered": type_count}],
                }
            )

        if not is_graphql:
            # Check if it responded as GraphQL error (e.g. GET or missing query)
            try:
                g_status, _, g_body, _ = _request_graphql(
                    destination,
                    allow_ip,
                    "GET",
                    f"{ep}?{urlencode({'query': '{__typename}'})}",
                    timeout=timeout,
                )
                if g_status == 200 and "__typename" in g_body:
                    is_graphql = True
            except Exception:
                pass

        if not is_graphql:
            continue

        # 2. Batch Query Amplification Denial-of-Service Audit
        # Issue array of 15 queries in a single HTTP request
        batch_queries = [{"query": "{ __typename }"} for _ in range(15)]
        batch_json = json.dumps(batch_queries)
        try:
            b_status, _, b_body, _ = _request_graphql(
                destination,
                allow_ip,
                "POST",
                ep,
                headers={"Content-Type": "application/json"},
                body=batch_json,
                timeout=timeout,
            )
            if b_status == 200:
                parsed_batch = json.loads(b_body)
                if isinstance(parsed_batch, list) and len(parsed_batch) == 15:
                    repro_curl = (
                        f"curl -s -k -X POST '{endpoint_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{batch_json}'"
                    )
                    findings.append(
                        {
                            "category": "denial_of_service",
                            "severity": "high",
                            "title": f"GraphQL Batch Query Amplification on {ep}",
                            "description": (
                                f"Endpoint {ep} evaluated 15 batched GraphQL queries within a single HTTP request. "
                                f"Unrestricted query batching enables resource exhaustion and brute-force amplification."
                            ),
                            "target_url": endpoint_url,
                            "fingerprint": hashlib.sha256(
                                f"graphql_batch_{destination.host}_{ep}".encode()
                            ).hexdigest(),
                            "cwe_id": "CWE-776",
                            "confidence": "high",
                            "status": "confirmed",
                            "lifecycle_state": "REPRODUCED",
                            "remediation": "Disable batch queries or enforce strict batch request limits (e.g., max 2 queries per request).",
                            "poc": {
                                "method": "POST",
                                "url": endpoint_url,
                                "curl_command": repro_curl,
                                "batch_size_confirmed": 15,
                            },
                            "evidence": [{"status": b_status, "batch_responses_count": len(parsed_batch)}],
                        }
                    )
        except Exception:
            pass

        # 3. Field Suggestion Information Leak Audit
        suggestion_payload = {"query": "{ __sharay_canary_field_does_not_exist }"}
        try:
            s_status, _, s_body, _ = _request_graphql(
                destination,
                allow_ip,
                "POST",
                ep,
                headers={"Content-Type": "application/json"},
                body=json.dumps(suggestion_payload),
                timeout=timeout,
            )
            if "Did you mean" in s_body or "suggest" in s_body.lower():
                repro_curl = (
                    f"curl -s -k -X POST '{endpoint_url}' "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{json.dumps(suggestion_payload)}'"
                )
                findings.append(
                    {
                        "category": "information_disclosure",
                        "severity": "low",
                        "title": f"GraphQL Field Suggestion Information Leak on {ep}",
                        "description": (
                            f"Endpoint {ep} suggests valid schema field names upon receiving queries for invalid fields. "
                            f"This facilitates schema discovery even when introspection is disabled."
                        ),
                        "target_url": endpoint_url,
                        "fingerprint": hashlib.sha256(
                            f"graphql_suggest_{destination.host}_{ep}".encode()
                        ).hexdigest(),
                        "cwe_id": "CWE-200",
                        "confidence": "high",
                        "status": "confirmed",
                        "lifecycle_state": "REPRODUCED",
                        "remediation": "Disable field suggestions in production GraphQL engine configurations.",
                        "poc": {
                            "method": "POST",
                            "url": endpoint_url,
                            "curl_command": repro_curl,
                        },
                        "evidence": [{"status": s_status, "suggestion_detected": True}],
                    }
                )
        except Exception:
            pass

    checks.append(
        {
            "category": "graphql_security_assessment",
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
    "audit_graphql_endpoint",
]
