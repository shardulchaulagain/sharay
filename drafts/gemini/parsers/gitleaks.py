"""Gitleaks structured output parser (L6).

Drafted by Gemini for Claude and Codex.
Untrusted until reviewed by Claude and verified with tests.

Rules:
- Strictly bounded input size.
- Catches RecursionError and fails closed on malformed or deeply nested JSON.
- Rejects non-dict items and path traversal ('..') in File.
- Never echoes the secret, match, commit message, or snippet.
- Retains rule_id, normalized file, line, and an immutable SHA256 fingerprint only.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

MAX_JSON_BYTES = 5 * 1024 * 1024  # 5 MB maximum report size
MAX_FINDINGS = 5000
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def _clean_text(value: str | None, max_len: int = 200) -> str:
    if not value:
        return ""
    return _UNPRINTABLE.sub("", str(value))[:max_len]


def _clean_path(path_str: str) -> str:
    cleaned = _clean_text(path_str, max_len=500).replace("\\", "/")
    # Reject path traversal outside tree
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if ".." in parts or "\0" in cleaned:
        raise ValueError("Gitleaks report contains an unsafe or traversal file path.")
    return PurePosixPath(*parts).as_posix() if parts else "root"


def parse_gitleaks_json(data: bytes | str) -> list[dict[str, Any]]:
    """Parse Gitleaks JSON report. Strips all secret values and matching line content."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    if len(data) > MAX_JSON_BYTES:
        raise ValueError("Gitleaks report exceeds the parsing budget.")

    try:
        raw_items = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("Gitleaks report is not valid or exceeds nesting limit.") from exc

    if not isinstance(raw_items, list):
        raise ValueError("Gitleaks report must be a JSON array of findings.")

    findings: list[dict[str, Any]] = []
    for item in raw_items:
        if len(findings) >= MAX_FINDINGS:
            break
        if not isinstance(item, dict):
            raise ValueError("Gitleaks report entry must be a JSON object.")

        rule_id = _clean_text(item.get("RuleID") or item.get("Description"), max_len=100)
        raw_file = item.get("File")
        if not isinstance(raw_file, str):
            raise ValueError("Gitleaks report entry has missing or invalid File.")
        file_path = _clean_path(raw_file)

        start_line = item.get("StartLine")
        if not isinstance(start_line, int) or start_line < 1:
            raise ValueError("Gitleaks report entry has invalid StartLine.")

        raw_fp = _clean_text(item.get("Fingerprint"), max_len=128)
        if not rule_id:
            raise ValueError("Gitleaks report entry has missing RuleID.")

        # Compute synthetic stable fingerprint without referencing secret material
        fingerprint_basis = f"{rule_id}:{file_path}:{start_line}:{raw_fp}".encode("utf-8")
        stable_fingerprint = hashlib.sha256(fingerprint_basis).hexdigest()[:16]

        findings.append(
            {
                "rule_id": rule_id,
                "file": file_path,
                "line": start_line,
                "fingerprint": stable_fingerprint,
                "basis": "gitleaks static pattern match",
            }
        )

    return findings
