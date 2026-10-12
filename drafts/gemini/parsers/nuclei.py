"""Nuclei structured JSON/JSONL output parser (L3).

Drafted by Gemini for Claude and Codex.
Untrusted until reviewed by Claude and verified with tests.

Rules:
- Strictly bounded input size.
- Catches RecursionError and fails closed on malformed lines.
- Sanitizes matched-at URL: strips userinfo (credentials), query string, and fragments.
- Extracts template id, name, severity, matched URL, and matcher name.
- Strictly strips raw request, response, curl command, and extracted payloads.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MAX_JSON_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FINDINGS = 5000
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def _clean_text(value: str | None, max_len: int = 500) -> str:
    if not value:
        return ""
    return _UNPRINTABLE.sub("", str(value))[:max_len]


def _clean_url(url_str: str) -> str:
    """Sanitize matched-at URL: strictly removes username, password, query parameters, and fragments."""
    cleaned = _clean_text(url_str, max_len=1000)
    try:
        parsed = urlsplit(cleaned)
    except ValueError as exc:
        raise ValueError("Nuclei matched-at URL is malformed.") from exc

    if not parsed.scheme or not parsed.hostname:
        raise ValueError("Nuclei matched-at URL is missing scheme or hostname.")

    # Reconstruct netloc with hostname and optional port ONLY (no credentials)
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    # Return scheme, netloc, and path only; query and fragment are empty
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def parse_nuclei_jsonl(data: bytes | str) -> list[dict[str, Any]]:
    """Parse Nuclei line-delimited JSON (JSONL). Fails closed on invalid lines and strips raw HTTP traffic."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    if len(data) > MAX_JSON_BYTES:
        raise ValueError("Nuclei report exceeds the parsing budget.")

    findings: list[dict[str, Any]] = []
    lines = [line.strip() for line in data.splitlines() if line.strip()]

    for line in lines:
        if len(findings) >= MAX_FINDINGS:
            break

        try:
            item = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ValueError("Nuclei report contains malformed or excessively nested line.") from exc

        if not isinstance(item, dict):
            raise ValueError("Nuclei line must be a JSON object.")

        template_id = _clean_text(item.get("template-id") or item.get("templateID"), max_len=100)
        raw_matched = item.get("matched-at") or item.get("matched")
        if not isinstance(raw_matched, str):
            raise ValueError("Nuclei item has missing or invalid matched-at field.")
        matched_at = _clean_url(raw_matched)

        matcher_name = _clean_text(item.get("matcher-name"), max_len=100)

        info_raw = item.get("info")
        info_dict: dict[str, Any] = info_raw if isinstance(info_raw, dict) else {}
        name = _clean_text(info_dict.get("name"), max_len=200)
        severity = _clean_text(info_dict.get("severity"), max_len=20).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"

        if not template_id or not matched_at:
            raise ValueError("Nuclei item is missing template-id or matched-at.")

        fp_basis = f"{template_id}:{matched_at}:{matcher_name}:{severity}".encode("utf-8")
        fingerprint = hashlib.sha256(fp_basis).hexdigest()[:16]

        findings.append(
            {
                "template_id": template_id,
                "name": name or template_id,
                "severity": severity,
                "matched_at": matched_at,
                "matcher_name": matcher_name or None,
                "fingerprint": fingerprint,
            }
        )

    return findings
