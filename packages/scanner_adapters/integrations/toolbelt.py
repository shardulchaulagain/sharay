"""Sector O7: specialized offensive tool belt (ffuf, dalfox, katana, interactsh).

Each tool runs in the egress-locked container sandbox against exactly the authorized target
(pinned to `allow_ip`, bounded rate/time, no destructive flags). Output is parsed into the house
Finding shape (status `suspected` -- tool output, confirmed later by the reproducer) or, for
katana/interactsh, into URLs / OOB interactions. Pure argv-building and parsing are testable
offline; actual execution needs the tool image plus the podman egress runner.

sqlmap (packages.scanner_adapters.integrations.sqlmap) and semgrep (...integrations.semgrep) are
separate existing adapters; this module adds the remaining named tools and a dispatcher.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Sequence

_IMAGES = {
    "ffuf": "docker.io/secsi/ffuf:latest",
    "dalfox": "docker.io/hahwul/dalfox:latest",
    "katana": "docker.io/projectdiscovery/katana:latest",
    "interactsh": "docker.io/projectdiscovery/interactsh-client:latest",
}

_INTERESTING_FFUF_STATUS = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


# --- ffuf: content / path discovery ------------------------------------------------------------


def build_ffuf_argv(
    url: str, host: str, allow_ip: str, wordlist: str = "/wordlist.txt", rate: int = 40
) -> list[str]:
    base = url.rstrip("/")
    return [
        "-u",
        f"{base}/FUZZ",
        "-w",
        wordlist,
        "-mc",
        "200,201,204,301,302,307,401,403,405,500",
        "-rate",
        str(max(1, min(int(rate), 200))),
        "-t",
        "20",
        "-timeout",
        "5",
        "-of",
        "json",
        "-o",
        "/dev/stdout",
        "-s",
    ]


def parse_ffuf(data: bytes, default_target_url: str = "") -> dict[str, Any]:
    try:
        doc = json.loads(data.decode("utf-8", "replace") or "{}")
    except ValueError:
        doc = {}
    findings: list[dict[str, Any]] = []
    for r in doc.get("results", []) if isinstance(doc, dict) else []:
        status = r.get("status")
        if status not in _INTERESTING_FFUF_STATUS:
            continue
        path = (r.get("input") or {}).get("FUZZ", "")
        url = r.get("url") or f"{default_target_url.rstrip('/')}/{path}"
        sev = (
            "high"
            if status in (200, 401, 403)
            and any(k in str(path).lower() for k in ("admin", "backup", "config", ".git", ".env", "secret"))
            else "info"
        )
        findings.append(
            {
                "category": "content_discovery",
                "severity": sev,
                "title": f"Discovered content: /{path} ({status})",
                "description": f"ffuf found /{path} returning HTTP {status} (length {r.get('length')}).",
                "remediation": "Confirm the path should be exposed; restrict or remove sensitive endpoints.",
                "affected_url": url,
                "fingerprint": _fp("ffuf", url, str(status)),
                "confidence": "medium",
                "status": "suspected",
                "attributes": {"tool": "ffuf", "path": path, "status": status, "length": r.get("length")},
            }
        )
    return {"findings": findings}


# --- dalfox: XSS ------------------------------------------------------------------------------


def build_dalfox_argv(url: str) -> list[str]:
    return ["url", url, "--format", "json", "--no-color", "--skip-bav", "--timeout", "5", "--worker", "10"]


_DALFOX_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def parse_dalfox(data: bytes, default_target_url: str = "") -> dict[str, Any]:
    text = data.decode("utf-8", "replace").strip()
    items: list[dict[str, Any]] = []
    try:
        doc = json.loads(text or "[]")
        items = doc if isinstance(doc, list) else doc.get("pocs", [])
    except ValueError:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except ValueError:
                    pass
    findings: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        data_url = it.get("data") or it.get("poc") or default_target_url
        sev = _DALFOX_SEV.get(str(it.get("severity", "")).lower(), "high")
        findings.append(
            {
                "category": "cross_site_scripting",
                "severity": sev,
                "title": f"XSS candidate ({it.get('type', 'reflected')}) via dalfox",
                "description": f"dalfox flagged a {it.get('type', 'reflected')} XSS: {it.get('evidence') or it.get('message_str', '')}"[
                    :500
                ],
                "remediation": "Context-encode untrusted output and apply a strict CSP.",
                "affected_url": data_url,
                "fingerprint": _fp("dalfox", str(data_url), str(it.get("type", ""))),
                "confidence": "medium",
                "status": "suspected",
                "cwe_id": "CWE-79",
                "attributes": {"tool": "dalfox", "type": it.get("type"), "cwe": it.get("cwe")},
                "poc": {
                    "method": it.get("method", "GET"),
                    "parameter": it.get("param"),
                    "payload": it.get("payload"),
                    "url": data_url,
                },
            }
        )
    return {"findings": findings}


# --- katana: deep crawl (URL discovery, not findings) -----------------------------------------


def build_katana_argv(url: str, depth: int = 3) -> list[str]:
    return ["-u", url, "-d", str(max(1, min(int(depth), 5))), "-jc", "-silent", "-jsonl", "-rl", "50"]


def parse_katana(data: bytes) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        u = (
            rec.get("endpoint")
            or (rec.get("request") or {}).get("endpoint")
            or (rec.get("request") or {}).get("url")
        )
        if isinstance(u, str) and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


# --- interactsh: external OOB collaborator ingestion ------------------------------------------


def parse_interactsh(data: bytes) -> list[dict[str, Any]]:
    """Parse interactsh-client -json output into interaction records for the OOB collector."""
    out: list[dict[str, Any]] = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        out.append(
            {
                "protocol": rec.get("protocol", "http"),
                "unique_id": rec.get("unique-id") or rec.get("full-id", ""),
                "source_ip": rec.get("remote-address", ""),
                "raw_request": rec.get("raw-request", ""),
            }
        )
    return out


# --- dispatcher --------------------------------------------------------------------------------


def run_toolbelt(
    destination: Any,
    allow_ip: str,
    tools: Sequence[str],
    *,
    run: Callable[..., Any],
    wordlist_volume: str | None = None,
    max_seconds: float = 120,
) -> dict[str, Any]:
    """Run the selected tools over the egress-locked runner; return findings + discovered urls.

    `run` is the container runner (run_with_egress or a test double). A tool whose run raises or
    returns no parseable output is skipped honestly, never fabricated.
    """
    url, host, port = destination.url, destination.host, destination.port
    result: dict[str, Any] = {"findings": [], "urls": [], "checks": []}

    def _run(tool: str, argv: list[str], extra: dict[str, Any] | None = None):
        try:
            return run(
                _IMAGES[tool],
                argv,
                allow_ip=allow_ip,
                allow_port=port,
                add_host=f"{host}:{allow_ip}",
                max_seconds=max_seconds,
                **(extra or {}),
            )
        except Exception as exc:  # unavailable image/runner -> honest skip
            result["checks"].append(
                {
                    "category": f"toolbelt_{tool}",
                    "status": "skipped",
                    "detail": f"{tool} unavailable ({type(exc).__name__}).",
                }
            )
            return None

    if "ffuf" in tools:
        res = _run(
            "ffuf",
            build_ffuf_argv(url, host, allow_ip),
            {"mount_volume": wordlist_volume} if wordlist_volume else None,
        )
        if res is not None:
            parsed = parse_ffuf(getattr(res, "stdout", b"") or b"", default_target_url=url)
            result["findings"].extend(parsed["findings"])
            result["checks"].append(
                {
                    "category": "toolbelt_ffuf",
                    "status": "completed",
                    "detail": f"ffuf: {len(parsed['findings'])} path(s).",
                }
            )
    if "dalfox" in tools:
        res = _run("dalfox", build_dalfox_argv(url))
        if res is not None:
            parsed = parse_dalfox(getattr(res, "stdout", b"") or b"", default_target_url=url)
            result["findings"].extend(parsed["findings"])
            result["checks"].append(
                {
                    "category": "toolbelt_dalfox",
                    "status": "completed",
                    "detail": f"dalfox: {len(parsed['findings'])} XSS candidate(s).",
                }
            )
    if "katana" in tools:
        res = _run("katana", build_katana_argv(url))
        if res is not None:
            urls = parse_katana(getattr(res, "stdout", b"") or b"")
            result["urls"].extend(urls)
            result["checks"].append(
                {
                    "category": "toolbelt_katana",
                    "status": "completed",
                    "detail": f"katana: {len(urls)} URL(s).",
                }
            )
    return result


__all__ = [
    "build_ffuf_argv",
    "parse_ffuf",
    "build_dalfox_argv",
    "parse_dalfox",
    "build_katana_argv",
    "parse_katana",
    "parse_interactsh",
    "run_toolbelt",
]
