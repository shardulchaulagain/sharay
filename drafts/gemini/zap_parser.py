"""OWASP ZAP JSON report parser (L3): alerts, risk, confidence and endpoints; no traffic.

Parser only: no ZAP daemon or docker process is launched here. Supports both ZAP's
traditional multi-site report JSON ("site": [...]) and the ZAP API flat alert format
("alerts": [...]). Requests, response bodies, attack payloads and raw evidence strings
are never retained to preserve zero-credential isolation.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    MAX_REPORT_BYTES,
    fingerprint,
    label,
    load_json,
    shown,
    text,
)

RISK_MAP = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}

CONFIDENCE_MAP = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "false_positive",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "false positive": "false_positive",
    "false_positive": "false_positive",
}

_PORT = re.compile(r"^[0-9]{1,5}$")


def _sanitize_uri(value: object) -> str:
    """Validate and normalize a ZAP target URI, stripping query params, fragments and userinfo."""
    raw = text(value, "ZAP alert URI", 1000)
    try:
        parsed = urlsplit(raw)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError("ZAP alert URI is not a valid URL.") from None
    if parsed.scheme not in ("http", "https") or not host:
        raise ValueError("ZAP alert URI is not an http or https URL.")
    if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80):
        port = None
    authority = f"[{host}]" if ":" in host else host
    port_str = f":{port}" if port is not None else ""
    path = parsed.path or "/"
    return f"{parsed.scheme}://{authority}{port_str}{path}"


def _parse_alert(alert: dict[str, Any], site_uri: str | None = None) -> list[dict[str, Any]]:
    """Parse a single ZAP alert into one or more normalized findings (one per instance)."""
    if not isinstance(alert, dict):
        raise ValueError("ZAP alert is not an object.")

    plugin_id = str(alert.get("pluginId", alert.get("pluginid", "")))
    plugin_id = text(plugin_id, "ZAP pluginId", 50)

    alert_name = text(alert.get("alert", alert.get("name", "Unknown Alert")), "ZAP alert name", 300)

    risk_raw = str(alert.get("riskcode", alert.get("risk", "0"))).strip().lower()
    severity = RISK_MAP.get(risk_raw, "info")

    conf_raw = str(alert.get("confidence", "2")).strip().lower()
    confidence = CONFIDENCE_MAP.get(conf_raw, "medium")

    cwe_id = alert.get("cweid")
    cwe_str = str(cwe_id).strip() if cwe_id is not None and str(cwe_id).strip() not in ("", "-1") else None

    wasc_id = alert.get("wascid")
    wasc_str = (
        str(wasc_id).strip() if wasc_id is not None and str(wasc_id).strip() not in ("", "-1") else None
    )

    solution = label(alert.get("solution"), 400)

    instances = alert.get("instances")
    findings: list[dict[str, Any]] = []

    if isinstance(instances, list) and instances:
        for inst in instances:
            if not isinstance(inst, dict):
                continue
            uri_raw = inst.get("uri", site_uri)
            if not uri_raw:
                continue
            clean_uri = _sanitize_uri(uri_raw)
            param = inst.get("param")
            param_str = text(param, "ZAP parameter", 150) if param else ""
            method = str(inst.get("method", "GET")).strip().upper()
            method_str = (
                method if method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH") else "GET"
            )

            findings.append(
                {
                    "plugin_id": shown(plugin_id),
                    "name": label(alert_name) or shown(plugin_id),
                    "severity": severity,
                    "confidence": confidence,
                    "matched_at": shown(clean_uri),
                    "parameter": shown(param_str) if param_str else None,
                    "method": method_str,
                    "cwe_id": shown(cwe_str) if cwe_str else None,
                    "wasc_id": shown(wasc_str) if wasc_str else None,
                    "solution": solution,
                    "fingerprint": fingerprint("zap", plugin_id, clean_uri, param_str, method_str),
                }
            )
    else:
        # Flat alert representation with uri at alert level
        uri_raw = alert.get("uri", site_uri)
        if not uri_raw:
            raise ValueError("ZAP alert is missing both URI and instances.")
        clean_uri = _sanitize_uri(uri_raw)
        param = alert.get("param")
        param_str = text(param, "ZAP parameter", 150) if param else ""

        findings.append(
            {
                "plugin_id": shown(plugin_id),
                "name": label(alert_name) or shown(plugin_id),
                "severity": severity,
                "confidence": confidence,
                "matched_at": shown(clean_uri),
                "parameter": shown(param_str) if param_str else None,
                "method": "GET",
                "cwe_id": shown(cwe_str) if cwe_str else None,
                "wasc_id": shown(wasc_str) if wasc_str else None,
                "solution": solution,
                "fingerprint": fingerprint("zap", plugin_id, clean_uri, param_str, "GET"),
            }
        )

    return findings


def parse(data: bytes) -> dict[str, Any]:
    """Parse OWASP ZAP JSON report bytes; return {'findings': [...], 'truncated': bool}."""
    if not isinstance(data, bytes) or len(data) > MAX_REPORT_BYTES:
        raise ValueError("ZAP output is not bytes within the parsing budget.")

    root = load_json(data, "ZAP report")
    if not isinstance(root, dict):
        raise ValueError("ZAP report root is not an object.")

    findings: list[dict[str, Any]] = []
    total_parsed = 0

    if "site" in root:
        sites = root["site"]
        if not isinstance(sites, list):
            raise ValueError("ZAP 'site' is not a list.")
        for site in sites:
            if not isinstance(site, dict):
                raise ValueError("ZAP site entry is not an object.")
            site_name = site.get("@name")
            alerts = site.get("alerts", [])
            if not isinstance(alerts, list):
                raise ValueError("ZAP site 'alerts' is not a list.")
            for alert in alerts:
                parsed_alerts = _parse_alert(alert, site_name)
                for item in parsed_alerts:
                    total_parsed += 1
                    if len(findings) < MAX_FINDINGS:
                        findings.append(item)
    elif "alerts" in root:
        alerts = root["alerts"]
        if not isinstance(alerts, list):
            raise ValueError("ZAP 'alerts' is not a list.")
        for alert in alerts:
            parsed_alerts = _parse_alert(alert)
            for item in parsed_alerts:
                total_parsed += 1
                if len(findings) < MAX_FINDINGS:
                    findings.append(item)
    else:
        raise ValueError("ZAP report structure missing both 'site' and 'alerts' roots.")

    return {
        "findings": findings,
        "truncated": total_parsed > MAX_FINDINGS,
    }


__all__ = ["parse"]
