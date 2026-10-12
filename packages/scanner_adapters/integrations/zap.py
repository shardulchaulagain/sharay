"""OWASP ZAP report parser (L3): alert, risk, confidence and where it was raised; no traffic.

Parser only: no command line is built and ZAP has never run here. Field names follow the
tool's documented "Traditional JSON Report": site[].alerts[] with pluginid, alertRef, alert,
riskcode, confidence, cweid, wascid, solution and instances[] with uri, method, param.
Descriptions, attacks, evidence, other-info and references are never read. The API's flat
alert list and the single-object "site" of old releases are different shapes and are
rejected, not guessed at. The report has no error section: whether the scan completed is
the caller's job to take from the tool's exit status.
Structure adapted from Gemini's reviewed draft.
"""

import re

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    fingerprint,
    http_location,
    label,
    load_json,
    shown,
    text,
)

RISKS = {"0": "info", "1": "low", "2": "medium", "3": "high"}
CONFIDENCES = {"0": "false_positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}
_PLUGIN = re.compile(r"^[0-9]{1,10}$")
_REFERENCE = re.compile(r"^[0-9]{1,10}(-[0-9]{1,5})?$")
_METHOD = re.compile(r"^[A-Z]{1,20}$")


def _code(value: object, what: str, known: dict[str, str]) -> str:
    # The field must be there as text; a code this parser does not know is "unknown", never a real level.
    if not isinstance(value, str):
        raise ValueError(f"{what} is missing or not text.")
    return known.get(value, "unknown")


def _taxonomy(value: object, what: str) -> str | None:
    # ZAP writes "-1" (and sometimes "0") when an alert has no CWE or WASC entry.
    if value is None or value in ("-1", "0", ""):
        return None
    if not isinstance(value, str) or not _PLUGIN.match(value):
        raise ValueError(f"{what} is not a number.")
    return value


def parse(data: bytes) -> dict:
    """Return {"findings": [...], "truncated": bool}; one malformed entry anywhere rejects the report."""
    report = load_json(data, "ZAP report")
    sites = report.get("site") if isinstance(report, dict) else None
    if not isinstance(sites, list) or not all(isinstance(site, dict) for site in sites):
        raise ValueError("ZAP report has no list of sites.")
    findings: list[dict] = []
    total = 0
    for site in sites:
        alerts = site.get("alerts")
        if not isinstance(alerts, list) or not all(isinstance(alert, dict) for alert in alerts):
            raise ValueError("ZAP site has no list of alerts.")
        for alert in alerts:
            plugin = alert.get("pluginid")
            if not isinstance(plugin, str) or not _PLUGIN.match(plugin):
                raise ValueError("ZAP pluginid is not a number.")
            # alertRef tells apart the several alerts one rule can raise; older releases omit it.
            reference = alert.get("alertRef", plugin)
            if not isinstance(reference, str) or not _REFERENCE.match(reference):
                raise ValueError("ZAP alertRef is not a rule reference.")
            name = alert.get("name", alert.get("alert"))
            if not isinstance(name, str):
                raise ValueError("ZAP alert name is not text.")
            severity = _code(alert.get("riskcode"), "ZAP riskcode", RISKS)
            confidence = _code(alert.get("confidence"), "ZAP confidence", CONFIDENCES)
            cwe = _taxonomy(alert.get("cweid"), "ZAP cweid")
            wasc = _taxonomy(alert.get("wascid"), "ZAP wascid")
            instances = alert.get("instances")
            if not isinstance(instances, list) or not instances:
                raise ValueError("ZAP alert has no instances.")
            for instance in instances:  # every instance is validated, even past the retention cap
                if not isinstance(instance, dict):
                    raise ValueError("ZAP alert instance is not an object.")
                where = http_location(instance.get("uri"), "ZAP instance uri")
                method = instance.get("method")
                if not isinstance(method, str) or not _METHOD.match(method):
                    raise ValueError("ZAP instance method is not an HTTP method.")
                parameter = instance.get("param", "")
                if parameter != "":
                    parameter = text(parameter, "ZAP instance param")
                total += 1
                if len(findings) < MAX_FINDINGS:
                    findings.append(
                        {
                            "plugin_id": plugin,
                            "alert_ref": reference,
                            # Display only; never part of the identity.
                            "name": label(name) or plugin,
                            "severity": severity,
                            "confidence": confidence,
                            "matched_at": shown(where),
                            "method": method,
                            "parameter": shown(parameter) or None,
                            "cwe_id": cwe,
                            "wasc_id": wasc,
                            "solution": label(alert.get("solution"), 400),
                            "fingerprint": fingerprint("zap", reference, where, method, parameter),
                        }
                    )
    return {"findings": findings, "truncated": total > MAX_FINDINGS}


__all__ = ["parse"]
