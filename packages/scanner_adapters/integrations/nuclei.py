"""Nuclei JSON-lines output parser (L3): template, severity and where it matched; no traffic.

Parser only: no command line is built and Nuclei has never run here. Field names follow the
tool's documented JSONL output (template-id, info.name, info.severity, matched-at,
matcher-name). Requests, responses, curl commands and extracted results are never read.
The output has no error section: whether the run completed is the caller's job to take
from the tool's exit status.
Structure adapted from Gemini's reviewed draft.
"""

import ipaddress
import re

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    MAX_REPORT_BYTES,
    fingerprint,
    http_location,
    label,
    load_json,
    port_suffix,
    shown,
    text,
)

SEVERITIES = {"critical", "high", "medium", "low", "info"}
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_BRACKETED = re.compile(r"^\[([0-9A-Fa-f:.]{2,45})\](?::([0-9]{1,5}))?$")


def _port(value: int | None) -> str:
    return port_suffix(value, "Nuclei matched-at")


def _location(value: object) -> str:
    """Where a template matched: an http(s) URL without credentials or query, or host:port.

    Validated on the original text and rebuilt only from its parsed parts; anything that
    is not one of those two forms rejects the output rather than being reshaped.
    """
    raw = text(value, "Nuclei matched-at", 1000)
    if "://" not in raw:
        # Network and DNS templates report a bare host or host:port; IPv6 comes bare or bracketed.
        bracketed = _BRACKETED.match(raw)
        literal = bracketed.group(1) if bracketed else raw
        try:
            is_v6 = ipaddress.ip_address(literal).version == 6
        except ValueError:
            is_v6 = False
        if is_v6:
            digits = bracketed.group(2) if bracketed else None
            return f"[{literal}]{_port(int(digits))}" if digits else literal
        name, _, digits = raw.partition(":")
        if not _HOST.match(name) or (":" in raw and not digits.isdigit()):
            raise ValueError("Nuclei matched-at is not a URL or host:port.")
        return name + _port(int(digits) if digits else None)
    return http_location(raw, "Nuclei matched-at")


def parse(data: bytes) -> dict:
    """Return {"findings": [...], "truncated": bool}; any malformed line rejects the output."""
    if not isinstance(data, bytes) or len(data) > MAX_REPORT_BYTES:
        raise ValueError("Nuclei output is not bytes within the parsing budget.")
    lines = [line for line in data.splitlines() if line.strip()]
    findings: list[dict] = []
    for line in lines:  # every line is validated, even past the retention cap
        item = load_json(line, "Nuclei output line")
        if not isinstance(item, dict):
            raise ValueError("Nuclei output line is not an object.")
        template = text(item.get("template-id"), "Nuclei template-id")
        where = _location(item.get("matched-at"))
        info: dict = item["info"] if isinstance(item.get("info"), dict) else {}
        level = info.get("severity")
        severity = level.lower() if isinstance(level, str) else ""
        matcher = item.get("matcher-name")
        matcher = text(matcher, "Nuclei matcher-name") if matcher is not None else None
        if not isinstance(info.get("name", ""), str):
            raise ValueError("Nuclei info.name is not text.")
        if len(findings) < MAX_FINDINGS:
            findings.append(
                {
                    "template": shown(template),
                    # Display only; never part of the identity.
                    "name": label(info.get("name")) or shown(template),
                    "severity": severity if severity in SEVERITIES else "unknown",
                    "matched_at": shown(where),
                    "matcher": shown(matcher) if matcher else None,
                    "fingerprint": fingerprint(template, where, matcher or ""),
                }
            )
    return {"findings": findings, "truncated": len(lines) > MAX_FINDINGS}


__all__ = ["parse"]
