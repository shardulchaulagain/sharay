"""Semgrep structured JSON output parser (L6).

Drafted by Gemini for Claude and Codex.
Untrusted until reviewed by Claude and verified with tests.

Rules:
- Strictly bounded input size.
- Catches RecursionError and fails closed on deeply nested or invalid JSON.
- Extracts rule id, file path, line, severity, and sanitized message.
- Strictly strips code lines, snippets, and surrounding context.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

MAX_JSON_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FINDINGS = 5000
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def _clean_text(value: str | None, max_len: int = 500) -> str:
    if not value:
        return ""
    return _UNPRINTABLE.sub("", str(value))[:max_len]


def _clean_path(path_str: str) -> str:
    cleaned = _clean_text(path_str, max_len=500).replace("\\", "/")
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if ".." in parts or "\0" in cleaned:
        raise ValueError("Semgrep output contains an unsafe or traversal file path.")
    return PurePosixPath(*parts).as_posix() if parts else "root"


def parse_semgrep_json(data: bytes | str) -> list[dict[str, Any]]:
    """Parse Semgrep JSON output. Excludes all source code snippets ('lines')."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    if len(data) > MAX_JSON_BYTES:
        raise ValueError("Semgrep output exceeds the parsing budget.")

    try:
        report = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("Semgrep output is not valid or exceeds nesting limit.") from exc

    if not isinstance(report, dict) or "results" not in report:
        raise ValueError("Semgrep report must be a JSON object with a 'results' key.")

    raw_results = report["results"]
    if not isinstance(raw_results, list):
        raise ValueError("Semgrep 'results' must be a list.")

    findings: list[dict[str, Any]] = []
    for item in raw_results:
        if len(findings) >= MAX_FINDINGS:
            break
        if not isinstance(item, dict):
            raise ValueError("Semgrep result item must be a JSON object.")

        check_id = _clean_text(item.get("check_id"), max_len=150)
        raw_path = item.get("path")
        if not isinstance(raw_path, str):
            raise ValueError("Semgrep finding path must be a string.")
        file_path = _clean_path(raw_path)

        start_raw = item.get("start")
        start_dict: dict[str, Any] = start_raw if isinstance(start_raw, dict) else {}
        line = start_dict.get("line")
        if not isinstance(line, int) or line < 1:
            line = 1

        extra_raw = item.get("extra")
        extra_dict: dict[str, Any] = extra_raw if isinstance(extra_raw, dict) else {}
        severity = _clean_text(extra_dict.get("severity"), max_len=20).lower()
        if severity not in ("error", "warning", "info"):
            severity = "info"

        message = _clean_text(extra_dict.get("message"), max_len=300)
        metadata_raw = extra_dict.get("metadata")
        metadata_dict: dict[str, Any] = metadata_raw if isinstance(metadata_raw, dict) else {}
        cwe = _clean_text(str(metadata_dict.get("cwe") or ""), max_len=100)

        if not check_id or not file_path:
            raise ValueError("Semgrep finding must contain check_id and path.")

        fp_basis = f"{check_id}:{file_path}:{line}:{severity}".encode("utf-8")
        fingerprint = hashlib.sha256(fp_basis).hexdigest()[:16]

        findings.append(
            {
                "rule_id": check_id,
                "file": file_path,
                "line": line,
                "severity": severity,
                "message": message,
                "cwe": cwe or None,
                "fingerprint": fingerprint,
            }
        )

    return findings
