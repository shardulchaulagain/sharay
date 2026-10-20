"""Signed, Versioned Detection-Pack System (Sector 2.5).

Provides:
- Signed, versioned detection pack format with cryptographic Ed25519 asymmetric signatures.
- Matchers evaluating HTTP status, header, and body words/regexes.
- NucleiTemplateImporter translating community Nuclei YAML/JSON templates into verified SHARAY templates.
- DetectionPackManager loading, cryptographically verifying, and executing templates out-of-band.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from packages.crypto.ed25519 import (
    derive_public_key,
    ed25519_verify_hex,
    sign,
)


class MatcherType(str, Enum):
    STATUS = "status"
    WORD = "word"
    REGEX = "regex"
    DSL = "dsl"


@dataclass
class PackMatcher:
    """Matcher rule defining positive detection criteria."""

    matcher_type: MatcherType
    words: list[str] = field(default_factory=list)
    regexes: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    part: str = "body"  # "body" | "header" | "status"
    condition: str = "or"  # "and" | "or"

    def evaluate(self, status: int, headers: dict[str, str], body: str) -> bool:
        target_text = body if self.part == "body" else "\n".join(f"{k}: {v}" for k, v in headers.items())

        if self.matcher_type == MatcherType.STATUS:
            return status in self.status_codes

        if self.matcher_type == MatcherType.WORD:
            matches = [w.lower() in target_text.lower() for w in self.words]
            return all(matches) if self.condition == "and" else any(matches)

        if self.matcher_type == MatcherType.REGEX:
            matches = [bool(re.search(r, target_text, re.IGNORECASE)) for r in self.regexes]
            return all(matches) if self.condition == "and" else any(matches)

        return False


@dataclass
class DetectionTemplate:
    """A signed, executable security check template."""

    id: str
    name: str
    author: str
    version: str
    severity: str
    category: str
    cwe_id: str
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    matchers: list[PackMatcher] = field(default_factory=list)
    signature: str = ""
    public_key_hex: str = ""

    def canonical_bytes(self) -> bytes:
        """Produce deterministic canonical representation for cryptographic signing."""
        data = {
            "id": self.id,
            "name": self.name,
            "author": self.author,
            "version": self.version,
            "severity": self.severity,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "method": self.method,
            "path": self.path,
            "headers": sorted(self.headers.items()),
            "body": self.body,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_ed25519(self, private_key_bytes: bytes) -> str:
        """Compute Ed25519 signature over template canonical bytes."""
        pub_key = derive_public_key(private_key_bytes)
        sig = sign(private_key_bytes, self.canonical_bytes())
        self.signature = sig.hex()
        self.public_key_hex = pub_key.hex()
        return self.signature

    def verify_ed25519(self, public_key_hex: str | None = None) -> bool:
        """Verify template integrity against Ed25519 public key."""
        target_pub_hex = public_key_hex or self.public_key_hex
        if not self.signature or not target_pub_hex:
            return False
        return ed25519_verify_hex(self.signature, self.canonical_bytes(), target_pub_hex)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "author": self.author,
            "version": self.version,
            "severity": self.severity,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "request": {
                "method": self.method,
                "path": self.path,
                "headers": self.headers,
                "body": self.body,
            },
            "matchers": [
                {
                    "type": m.matcher_type.value,
                    "words": m.words,
                    "regexes": m.regexes,
                    "status": m.status_codes,
                    "part": m.part,
                    "condition": m.condition,
                }
                for m in self.matchers
            ],
            "signature": self.signature,
            "public_key_hex": self.public_key_hex,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetectionTemplate:
        req = data.get("request", {})
        matchers = []
        for m in data.get("matchers", []):
            matchers.append(
                PackMatcher(
                    matcher_type=MatcherType(m.get("type", "word")),
                    words=m.get("words", []),
                    regexes=m.get("regexes", []),
                    status_codes=m.get("status", []),
                    part=m.get("part", "body"),
                    condition=m.get("condition", "or"),
                )
            )

        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            author=data.get("author", "unknown"),
            version=data.get("version", "1.0.0"),
            severity=data.get("severity", "medium"),
            category=data.get("category", "vulnerability"),
            cwe_id=data.get("cwe_id", "CWE-200"),
            method=req.get("method", "GET"),
            path=req.get("path", "/"),
            headers=req.get("headers", {}),
            body=req.get("body"),
            matchers=matchers,
            signature=data.get("signature", ""),
            public_key_hex=data.get("public_key_hex", ""),
        )


class NucleiTemplateImporter:
    """Converts standard Nuclei YAML/JSON security templates into SHARAY DetectionTemplates."""

    @classmethod
    def from_nuclei_dict(cls, data: dict[str, Any]) -> DetectionTemplate:
        info = data.get("info", {})
        tid = data.get("id", "imported-nuclei-check")
        name = info.get("name", tid)
        author = info.get("author", "community")
        version = info.get("version", "1.0.0")
        severity = info.get("severity", "medium").lower()

        # Classification / CWE
        classif = info.get("classification", {})
        cwe_raw = classif.get("cwe-id", ["CWE-200"])
        cwe_id = cwe_raw[0].upper() if isinstance(cwe_raw, list) and cwe_raw else "CWE-200"

        # HTTP request definition
        http_defs = data.get("http", data.get("requests", []))
        if not http_defs:
            raise ValueError(f"Nuclei template {tid} has no HTTP request definitions")

        first_req = http_defs[0]
        method = first_req.get("method", "GET").upper()
        raw_paths = first_req.get("path", ["/"])
        path = raw_paths[0].replace("{{BaseURL}}", "") if isinstance(raw_paths, list) and raw_paths else "/"
        if not path.startswith("/"):
            path = "/" + path

        headers = first_req.get("headers", {})
        body = first_req.get("body")

        # Matchers
        matchers: list[PackMatcher] = []
        for m in first_req.get("matchers", []):
            m_type_str = m.get("type", "word")
            part = m.get("part", "body")
            cond = m.get("condition", "or")

            if m_type_str == "status":
                matchers.append(
                    PackMatcher(
                        matcher_type=MatcherType.STATUS,
                        status_codes=m.get("status", [200]),
                        part="status",
                    )
                )
            elif m_type_str == "word":
                matchers.append(
                    PackMatcher(
                        matcher_type=MatcherType.WORD,
                        words=m.get("words", []),
                        part=part,
                        condition=cond,
                    )
                )
            elif m_type_str == "regex":
                matchers.append(
                    PackMatcher(
                        matcher_type=MatcherType.REGEX,
                        regexes=m.get("regex", []),
                        part=part,
                        condition=cond,
                    )
                )

        return DetectionTemplate(
            id=tid,
            name=name,
            author=author,
            version=version,
            severity=severity,
            category=data.get("tags", ["vulnerability"])[0]
            if isinstance(data.get("tags"), list) and data.get("tags")
            else "vulnerability",
            cwe_id=cwe_id,
            method=method,
            path=path,
            headers=headers,
            body=body,
            matchers=matchers,
        )


class DetectionPackManager:
    """Manages loading, cryptographic signing verification, and execution of detection packs."""

    def __init__(self, pack_dir: Path | None = None, trusted_public_keys: list[str] | None = None) -> None:
        self.pack_dir = pack_dir
        self.trusted_public_keys: set[str] = set(trusted_public_keys or [])
        self._templates: dict[str, DetectionTemplate] = {}

    def trust_public_key(self, public_key_hex: str) -> None:
        self.trusted_public_keys.add(public_key_hex.lower())

    def register_template(self, template: DetectionTemplate) -> None:
        self._templates[template.id] = template

    def get_template(self, tid: str, verify_sig: bool = True) -> DetectionTemplate | None:
        tpl = self._templates.get(tid)
        if not tpl:
            return None
        if verify_sig:
            if not tpl.verify_ed25519():
                raise ValueError(f"Detection template '{tid}' failed Ed25519 signature verification")
            if self.trusted_public_keys and tpl.public_key_hex.lower() not in self.trusted_public_keys:
                raise ValueError(f"Detection template '{tid}' signed by untrusted key {tpl.public_key_hex}")
        return tpl

    def list_templates(self) -> list[str]:
        return sorted(self._templates.keys())

    def export_pack_bundle(self) -> str:
        """Export all registered templates as a signed JSON bundle."""
        bundle = {
            "version": "1.0.0",
            "templates": [t.to_dict() for t in self._templates.values()],
        }
        return json.dumps(bundle, indent=2)

    def import_pack_bundle(self, bundle_json: str, enforce_signatures: bool = True) -> list[str]:
        """Import a JSON pack bundle and register its templates."""
        data = json.loads(bundle_json)
        imported_ids = []
        for t_data in data.get("templates", []):
            tpl = DetectionTemplate.from_dict(t_data)
            if enforce_signatures:
                if not tpl.verify_ed25519():
                    raise ValueError(f"Imported template '{tpl.id}' has an invalid Ed25519 signature")
                if self.trusted_public_keys and tpl.public_key_hex.lower() not in self.trusted_public_keys:
                    raise ValueError(f"Imported template '{tpl.id}' signed by untrusted key")
            self.register_template(tpl)
            imported_ids.append(tpl.id)
        return imported_ids

    def execute_template(
        self,
        template_id: str,
        request_fn: Callable[..., tuple[int, dict[str, str], str, float]],
        target_origin: str,
        allow_ip: str,
    ) -> dict[str, Any] | None:
        """Execute signed template against target and generate confirmed finding on positive match."""
        tpl = self.get_template(template_id, verify_sig=bool(self.trusted_public_keys))
        if not tpl:
            return None

        # Execute request
        status, resp_headers, resp_body, _ = request_fn(
            target_origin, allow_ip, tpl.method, tpl.path, headers=tpl.headers, body=tpl.body
        )

        # Evaluate matchers
        if not tpl.matchers:
            matched = status == 200
        else:
            matched = all(m.evaluate(status, resp_headers, resp_body) for m in tpl.matchers)

        if matched:
            repro_url = f"{target_origin.rstrip('/')}{tpl.path}"
            return {
                "category": tpl.category,
                "severity": tpl.severity,
                "title": f"[{tpl.id.upper()}] {tpl.name}",
                "description": f"Target endpoint {tpl.path} matched detection pack {tpl.id} (v{tpl.version}) signature.",
                "target_url": repro_url,
                "affected_url": repro_url,
                "fingerprint": hashlib.sha256(
                    f"pack_{tpl.id}_{target_origin}_{tpl.path}".encode()
                ).hexdigest(),
                "cwe_id": tpl.cwe_id,
                "confidence": "high",
                "status": "confirmed",
                "lifecycle_state": "REPRODUCED",
                "remediation": f"Remediate according to security advisory for {tpl.name}.",
                "poc": {
                    "method": tpl.method,
                    "url": repro_url,
                    "headers": tpl.headers,
                    "payload": tpl.body or "",
                    "curl_command": f'curl -s -k -X {tpl.method} "{repro_url}"',
                    "reproduction_steps": f"Send {tpl.method} request to {repro_url} and verify matcher signatures in response.",
                },
                "evidence": [{"status": status, "snippet": resp_body[:200].strip()}],
            }
        return None


__all__ = [
    "DetectionPackManager",
    "DetectionTemplate",
    "MatcherType",
    "NucleiTemplateImporter",
    "PackMatcher",
]
