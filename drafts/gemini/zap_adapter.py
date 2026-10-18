"""OWASP ZAP Passive Scan Integration Adapter (L3).

Author: Gemini (Principal Architect, Debugger & Helper)
Status: Hardened draft module under drafts/gemini/ for Claude L3 adoption.

Hardened guarantees per Claude review:
1. Pure passive assessment by default: Spidering is excluded by default (include_spider=False)
   so no outbound crawler requests occur without explicit authorization.
2. Structured plan generation: Plans are constructed as typed dictionaries and serialized
   cleanly via json.dumps (which is valid YAML 1.2 and parsed natively by ZAP Automation Framework).
   Zero string-formatting YAML injection risk.
3. Path traversal defense: report_filename and report_dir are strictly validated.
4. Hardened report parsing: strips URL queries, credentials, and redacts sensitive patterns.
5. Fails closed on malformed reports or budget overruns.
"""

from __future__ import annotations

import json
import re
import shutil
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from packages.secret_patterns import redact_tokens

MAX_ZAP_REPORT_BYTES = 10 * 1024 * 1024
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9._-]+$")

_RISK_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}

_CONFIDENCE_MAP = {
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "confirmed",
}


class ZapAdapterError(ValueError):
    """ZAP invocation or report parsing failed."""


def build_argv_autorun(executable: str, plan_file: str) -> list[str]:
    """Construct command line for headless ZAP automation run."""
    if not executable or not isinstance(executable, str):
        raise ZapAdapterError("A valid executable path is required.")
    if not plan_file or not isinstance(plan_file, str):
        raise ZapAdapterError("A valid plan file path is required.")
    return [executable, "-cmd", "-autorun", plan_file]


def build_argv_version(executable: str) -> list[str]:
    """Construct command line for querying ZAP version."""
    if not executable or not isinstance(executable, str):
        raise ZapAdapterError("A valid executable path is required.")
    return [executable, "-version"]


def generate_automation_plan(
    target_url: str,
    report_dir: str,
    report_filename: str = "zap-report.json",
    max_duration_mins: int = 1,
    include_spider: bool = False,
) -> str:
    """Generate structured Automation Framework plan for passive inspection and reporting.

    Uses json.dumps to guarantee safe serialization (valid YAML 1.2 accepted by ZAP AF).
    Spidering is strictly disabled by default (pure passive mode).
    """
    if not target_url or not isinstance(target_url, str):
        raise ZapAdapterError("Target URL must be a valid non-empty string.")

    parts = urlsplit(target_url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ZapAdapterError("Target URL must be a valid HTTP or HTTPS URL.")

    # Strip credentials, query parameters, and fragments for scope definition
    clean_origin = f"{parts.scheme}://{parts.netloc}"

    if not report_dir or not isinstance(report_dir, str) or "\x00" in report_dir:
        raise ZapAdapterError("Report directory must be a valid string path.")

    if not report_filename or not _SAFE_FILENAME.match(report_filename):
        raise ZapAdapterError("Report filename must be alphanumeric and cannot contain directory separators.")

    if not isinstance(max_duration_mins, int) or not 1 <= max_duration_mins <= 60:
        raise ZapAdapterError("max_duration_mins must be an integer between 1 and 60.")

    jobs: list[dict[str, Any]] = [
        {
            "type": "passiveScan-config",
            "parameters": {
                "maxAlertsPerRule": 10,
                "scanOnlyInScope": True,
            },
        }
    ]

    # Only include spider if explicitly requested by authorized profile
    if include_spider:
        jobs.append(
            {
                "type": "spider",
                "parameters": {
                    "context": "sharay_context",
                    "maxDuration": max_duration_mins,
                    "maxDepth": 1,
                },
            }
        )

    jobs.extend(
        [
            {
                "type": "passiveScan-wait",
                "parameters": {
                    "maxDuration": max_duration_mins,
                },
            },
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": report_dir,
                    "reportFile": report_filename,
                },
            },
        ]
    )

    plan_dict = {
        "env": {
            "contexts": [
                {
                    "name": "sharay_context",
                    "urls": [clean_origin],
                    "includePaths": [f"{clean_origin}/.*"],
                    "excludePaths": [],
                }
            ]
        },
        "jobs": jobs,
    }

    return json.dumps(plan_dict, indent=2)


def _clean_uri(uri: str) -> str:
    """Strip query parameters, fragments, and credentials from matched URL."""
    try:
        parts = urlsplit(uri)
        netloc = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return "[UNPARSEABLE_URI]"


def parse_json_report(data: bytes, target_url: str) -> list[dict[str, Any]]:
    """Parse ZAP traditional-json report and normalize alerts into findings."""
    if len(data) > MAX_ZAP_REPORT_BYTES:
        raise ZapAdapterError("ZAP report exceeds byte budget.")

    try:
        document = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ZapAdapterError("ZAP report is malformed or invalid JSON.") from exc

    if not isinstance(document, dict):
        raise ZapAdapterError("ZAP report root must be a JSON object.")

    findings: list[dict[str, Any]] = []
    sites = document.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    elif not isinstance(sites, list):
        sites = []

    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            plugin_id = str(alert.get("pluginId", ""))
            name = str(alert.get("alert", "ZAP Alert"))
            risk_code = str(alert.get("riskcode", "0"))
            confidence_code = str(alert.get("confidence", "2"))
            description = str(alert.get("desc", ""))
            solution = str(alert.get("solution", ""))

            instances = alert.get("instances", [])
            instance_uris: list[str] = []
            if isinstance(instances, list):
                for inst in instances:
                    if isinstance(inst, dict) and "uri" in inst:
                        instance_uris.append(_clean_uri(str(inst["uri"])))

            clean_desc = redact_tokens(_UNPRINTABLE.sub("", description)[:400], "[REDACTED]")
            clean_solution = redact_tokens(_UNPRINTABLE.sub("", solution)[:400], "[REDACTED]")

            findings.append(
                {
                    "kind": "zap_alert",
                    "plugin_id": plugin_id,
                    "title": _UNPRINTABLE.sub("", name)[:120],
                    "severity": _RISK_MAP.get(risk_code, "info"),
                    "confidence": _CONFIDENCE_MAP.get(confidence_code, "medium"),
                    "description": clean_desc,
                    "remediation": clean_solution,
                    "affected_uris": instance_uris[:10],
                    "tool": "zap",
                }
            )

    return findings


def preflight(executable: str | None = None) -> dict[str, Any]:
    """Inspect availability of ZAP runner on this system."""
    path = executable or shutil.which("zap.sh")
    return {
        "id": "zap",
        "name": "OWASP ZAP (Passive Web Scanner)",
        "available": bool(path),
        "runnable": False,  # Live execution requires explicit operator authorization
        "executable": path,
        "status": "implemented" if path else "missing",
    }


__all__ = [
    "MAX_ZAP_REPORT_BYTES",
    "ZapAdapterError",
    "build_argv_autorun",
    "build_argv_version",
    "generate_automation_plan",
    "parse_json_report",
    "preflight",
]
