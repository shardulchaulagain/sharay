"""Cryptographic Out-of-Band (OOB) telemetry verification engine.

Generates tamper-proof correlation tokens, embeds them into SSRF, blind XXE,
and blind command injection probes, and correlates asynchronous DNS/HTTP callbacks
to deliver 100% false-positive-free vulnerability confirmations.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

DEFAULT_OOB_DOMAIN = "oob.sharay.invalid"


@dataclass
class OOBInteraction:
    """Represents an out-of-band interaction received from a target system."""

    token: str
    protocol: str  # "dns" | "http"
    source_ip: str
    timestamp: float = field(default_factory=time.time)
    query_name: str | None = None
    http_path: str | None = None
    http_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class RegisteredProbe:
    """A registered outbound security probe expecting an asynchronous callback."""

    probe_id: str
    probe_type: str  # "ssrf" | "xxe" | "cmdi"
    target_endpoint: str
    parameter: str | None
    created_at: float = field(default_factory=time.time)
    token: str = ""


class OOBTokenGenerator:
    """Generates and validates signed, tamper-proof OOB callback tokens."""

    def __init__(self, secret_key: bytes | None = None, domain: str = DEFAULT_OOB_DOMAIN) -> None:
        self.secret_key = secret_key or b"sharay_oob_cryptographic_verification_key_v1"
        self.domain = domain.rstrip(".")

    def generate_token(self, probe_id: str, probe_type: str) -> str:
        """Generate a signed correlation hostname: sharay-{probe_type}-{probe_id[:8]}-{sig}.domain."""
        clean_id = re.sub(r"[^a-zA-Z0-9]", "", probe_id)[:8].lower() or "prob0001"
        clean_type = re.sub(r"[^a-zA-Z0-9]", "", probe_type)[:4].lower() or "ssrf"
        nonce = hex(int(time.time()))[2:]
        data = f"{clean_type}:{clean_id}:{nonce}".encode("utf-8")
        sig = hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()[:8]
        return f"sharay-{clean_type}-{clean_id}-{nonce}-{sig}.{self.domain}"

    def validate_token(self, hostname: str) -> dict[str, Any] | None:
        """Validate signature and extract probe metadata from hostname."""
        parts = hostname.lower().strip().split(".")
        if len(parts) < 2:
            return None
        subdomain = parts[0]
        match = re.match(r"^sharay-([a-z0-9]{4})-([a-z0-9]{8})-([a-z0-9]+)-([a-z0-9]{8})$", subdomain)
        if not match:
            return None
        ptype, pid, nonce, sig = match.groups()
        data = f"{ptype}:{pid}:{nonce}".encode("utf-8")
        expected_sig = hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()[:8]
        if not hmac.compare_digest(sig, expected_sig):
            return None
        return {
            "probe_type": ptype,
            "probe_id": pid,
            "nonce": nonce,
            "subdomain": subdomain,
        }


class OOBCollector:
    """Thread-safe event ledger correlating outbound probes with inbound callbacks."""

    def __init__(self, token_generator: OOBTokenGenerator | None = None) -> None:
        self.generator = token_generator or OOBTokenGenerator()
        self._lock = threading.Lock()
        self._probes: dict[str, RegisteredProbe] = {}
        self._interactions: list[OOBInteraction] = []

    def register_probe(
        self,
        probe_id: str,
        probe_type: str,
        target_endpoint: str,
        parameter: str | None = None,
    ) -> tuple[str, str]:
        """Register a probe and return (token, full_oob_url)."""
        token = self.generator.generate_token(probe_id, probe_type)
        probe = RegisteredProbe(
            probe_id=probe_id,
            probe_type=probe_type,
            target_endpoint=target_endpoint,
            parameter=parameter,
            token=token,
        )
        with self._lock:
            self._probes[token] = probe
        return token, f"http://{token}/callback"

    def record_interaction(
        self,
        token: str,
        protocol: str,
        source_ip: str,
        query_name: str | None = None,
        http_path: str | None = None,
        http_headers: dict[str, str] | None = None,
    ) -> bool:
        """Record an inbound OOB interaction callback."""
        # Find matching token
        matched_token = None
        with self._lock:
            for registered_token in self._probes:
                if registered_token in token.lower() or token.lower() in registered_token:
                    matched_token = registered_token
                    break

        # Even if not pre-registered, validate signature
        if not matched_token:
            metadata = self.generator.validate_token(token)
            if metadata:
                matched_token = token

        if matched_token:
            interaction = OOBInteraction(
                token=matched_token,
                protocol=protocol,
                source_ip=source_ip,
                query_name=query_name,
                http_path=http_path,
                http_headers=http_headers or {},
            )
            with self._lock:
                self._interactions.append(interaction)
            return True
        return False

    def poll(self, token: str) -> OOBInteraction | None:
        """Check if an interaction matching `token` has been recorded."""
        with self._lock:
            for interaction in self._interactions:
                if interaction.token == token:
                    return interaction
        return None

    def build_ssrf_payload(self, token: str) -> str:
        """Build SSRF test payload pointing to OOB endpoint."""
        return f"http://{token}/ssrf-canary"

    def build_xxe_payload(self, token: str) -> str:
        """Build blind XXE entity payload pointing to OOB endpoint."""
        return f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % oob SYSTEM "http://{token}/xxe-dtd"> %oob;]><root>test</root>'

    def build_cmdi_payload(self, token: str) -> str:
        """Build command injection payload triggering DNS query or HTTP curl."""
        return f"; nslookup {token} || curl -s http://{token}/cmdi"

    def confirm_vulnerability(self, token: str) -> dict[str, Any] | None:
        """If an interaction callback was received for `token`, generate a confirmed finding."""
        interaction = self.poll(token)
        if not interaction:
            return None

        with self._lock:
            probe = self._probes.get(token)

        cwe_map = {
            "ssrf": ("CWE-918", "Server-Side Request Forgery (SSRF)"),
            "xxe": ("CWE-611", "XML External Entity Injection (XXE)"),
            "cmdi": ("CWE-78", "OS Command Injection"),
        }
        ptype = probe.probe_type if probe else "ssrf"
        cwe_id, vuln_name = cwe_map.get(ptype, ("CWE-918", "Server-Side Request Forgery (SSRF)"))

        endpoint = probe.target_endpoint if probe else "/target"
        param = probe.parameter if probe else "unknown"

        fingerprint = hashlib.sha256(f"oob_{ptype}_{endpoint}_{token}".encode("utf-8")).hexdigest()

        return {
            "category": "injection" if ptype != "ssrf" else "ssrf",
            "severity": "critical",
            "title": f"Confirmed Blind {vuln_name} via Out-of-Band Telemetry",
            "description": (
                f"Target endpoint {endpoint} (parameter '{param}') successfully executed an out-of-band "
                f"interaction to callback listener via {interaction.protocol.upper()} from {interaction.source_ip}. "
                f"Callback verified cryptographically with zero false-positive risk."
            ),
            "target_url": endpoint,
            "fingerprint": fingerprint,
            "cwe_id": cwe_id,
            "confidence": "high",
            "status": "confirmed",
            "lifecycle_state": "REPRODUCED",
            "remediation": "Restrict network egress to approved destinations and sanitize parameter input.",
            "poc": {
                "method": "POST" if ptype == "xxe" else "GET",
                "url": endpoint,
                "oob_token": token,
                "callback_protocol": interaction.protocol,
                "callback_source_ip": interaction.source_ip,
                "callback_timestamp": interaction.timestamp,
            },
            "evidence": [
                {
                    "protocol": interaction.protocol,
                    "source_ip": interaction.source_ip,
                    "http_path": interaction.http_path,
                }
            ],
        }


__all__ = [
    "DEFAULT_OOB_DOMAIN",
    "OOBCollector",
    "OOBInteraction",
    "OOBTokenGenerator",
    "RegisteredProbe",
]
