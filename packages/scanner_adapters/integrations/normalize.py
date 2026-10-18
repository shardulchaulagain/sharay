"""Adapter-to-Finding normalization bridge between L3/L6 parsers and C3/C6 `aegis/models.py:Finding`.

Translates tool-specific parser dicts (`gitleaks`, `semgrep`, `nuclei`, `zap`, `metasploit`)
into the exact column contract of `aegis.models.Finding` (`fingerprint`, `title`, `category`,
`severity`, `confidence`, `status`, `description`, `remediation`, `affected_url`) and attaches
correlated validation techniques. Pure translation: no network, no model, no DB handle; the
caller (C-side worker) persists the returned rows. Structure adapted from Gemini's reviewed draft.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from packages.scanner_adapters.integrations._parsing import fingerprint
from packages.scanner_adapters.integrations.metasploit import correlate_validation_techniques

ToolSource = Literal["gitleaks", "semgrep", "nuclei", "zap", "metasploit", "iac", "osv", "secrets"]

_IAC_CONFIDENCE = {"confirmed": "high", "high": "high", "medium": "medium", "low": "low"}

_SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "info": "info",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CWE_NUMBER = re.compile(r"CWE-(\d{1,5})", re.I)


def _extract_cwe_int(raw_cwe: Any) -> int | None:
    if isinstance(raw_cwe, int):
        return raw_cwe
    if isinstance(raw_cwe, str):
        if raw_cwe.isdigit():
            return int(raw_cwe)
        match = _CWE_NUMBER.search(raw_cwe)
        if match:
            return int(match.group(1))
    if isinstance(raw_cwe, list) and raw_cwe:
        return _extract_cwe_int(raw_cwe[0])
    return None


def normalize_parsed_finding(
    tool: ToolSource,
    item: dict[str, Any],
    *,
    default_target_url: str = "",
) -> dict[str, Any]:
    """Translate one validated parser item into the exact column contract of `aegis.models.Finding`
    plus `recommended_validations` from the 10-class validation catalog.
    """
    if tool == "gitleaks":
        rule = str(item["rule"])
        file_path = str(item["file"])
        line = int(item["line"])
        fp = str(item["fingerprint"])
        return {
            "fingerprint": f"gitleaks:{fp}",
            "title": f"Secret detected by rule {rule}"[:250],
            "category": "secret_exposure",
            "severity": "high",
            "confidence": "medium",
            "status": "suspected",
            "description": f"Gitleaks rule {rule} matched in {file_path} at line {line}.",
            "remediation": "Rotate the exposed credential and remove it from source control.",
            "affected_url": f"file://{file_path}#L{line}",
            "recommended_validations": [],
        }

    if tool == "semgrep":
        rule = str(item["rule"])
        file_path = str(item["file"])
        line = int(item["line"])
        raw_sev = str(item.get("severity", "unknown")).lower()
        severity = _SEMGREP_SEVERITY_MAP.get(raw_sev, "medium")
        cwe_int = _extract_cwe_int(item.get("cwe"))
        validations = correlate_validation_techniques(rule, cwe=cwe_int)
        category = validations[0]["vuln_class"] if validations else "static_code_finding"
        fp = str(item["fingerprint"])
        return {
            "fingerprint": f"semgrep:{fp}",
            "title": f"Static analysis match: {rule}"[:250],
            "category": category,
            "severity": severity,
            "confidence": "medium",
            "status": "suspected",
            "description": f"Semgrep check {rule} matched in {file_path} at line {line}.",
            "remediation": "Review the flagged code construct and apply context-appropriate parameterization or encoding.",
            "affected_url": f"file://{file_path}#L{line}",
            "recommended_validations": validations,
        }

    if tool == "nuclei":
        template = str(item["template"])
        name = str(item.get("name") or template)
        raw_sev = str(item.get("severity", "unknown")).lower()
        severity = raw_sev if raw_sev in _VALID_SEVERITIES else "medium"
        matched_at = str(item.get("matched_at") or default_target_url)
        matcher = item.get("matcher")
        validations = correlate_validation_techniques(template)
        category = validations[0]["vuln_class"] if validations else "template_match"
        fp = str(item["fingerprint"])
        return {
            "fingerprint": f"nuclei:{fp}",
            "title": name[:250],
            "category": category,
            "severity": severity,
            "confidence": "medium",
            "status": "suspected",
            "description": f"Nuclei template {template}"
            + (f" ({matcher})" if matcher else "")
            + f" matched at {matched_at}.",
            "remediation": "Verify the finding with an approved SHARAY validation module and apply vendor or configuration remediation.",
            "affected_url": matched_at,
            "recommended_validations": validations,
        }

    if tool == "zap":
        name = str(item.get("name") or item["plugin_id"])
        raw_sev = str(item.get("severity", "unknown")).lower()
        severity = raw_sev if raw_sev in _VALID_SEVERITIES else "info"
        raw_conf = str(item.get("confidence", "unknown")).lower()
        # A scanner's own "confirmed" label is treated as "high" confidence until SHARAY validation runs.
        confidence = (
            "high" if raw_conf in {"high", "confirmed"} else ("low" if raw_conf == "low" else "medium")
        )
        matched_at = str(item.get("matched_at") or default_target_url)
        cwe_int = _extract_cwe_int(item.get("cwe_id"))
        validations = correlate_validation_techniques(name, cwe=cwe_int)
        category = validations[0]["vuln_class"] if validations else "web_passive"
        fp = str(item["fingerprint"])
        return {
            "fingerprint": f"zap:{fp}",
            "title": name[:250],
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "status": "false_positive" if raw_conf == "false_positive" else "suspected",
            "description": f"ZAP alert {item['alert_ref']} on {item['method']} {matched_at}"
            + (f" (parameter: {item['parameter']})" if item.get("parameter") else "")
            + ".",
            "remediation": str(
                item.get("solution") or "Apply the recommended HTTP/application hardening control."
            ),
            "affected_url": matched_at,
            "recommended_validations": validations,
        }

    if tool == "metasploit":
        module = str(item["module"])
        locator = str(item.get("locator") or default_target_url)
        outcome = str(item["outcome"])
        summary = str(item.get("summary") or module)
        fp = str(item["fingerprint"])
        return {
            "fingerprint": f"metasploit:{fp}",
            "title": f"Metasploit verification: {module}"[:250],
            "category": "auxiliary_verification",
            "severity": "high" if outcome == "confirmed_reproducible" else "medium",
            "confidence": "high" if outcome == "confirmed_reproducible" else "medium",
            # Parser output never enters as 'confirmed': only the verifier, after provenance checks,
            # may elevate a hypothesis. A tool's own outcome is evidence, not a confirmed finding.
            "status": "suspected",
            "description": f"Module {module} against {locator} reported outcome={outcome}: {summary}",
            "remediation": "Restrict exposed service access and apply vendor patch or configuration control.",
            "affected_url": locator,
            "recommended_validations": [],
        }

    if tool == "iac":
        rule_id = str(item["rule_id"])
        file_path = str(item["path"])
        line_no = item.get("line")
        has_line = isinstance(line_no, int) and not isinstance(line_no, bool)
        severity = str(item.get("severity", "medium"))
        severity = severity if severity in _VALID_SEVERITIES else "medium"
        return {
            # Include the title: K8s findings have no line, so two containers in one manifest hitting
            # the same rule would otherwise share a fingerprint and collide on Finding's uniqueness.
            "fingerprint": f"iac:{fingerprint(rule_id, file_path, str(line_no), str(item.get('title') or ''))}",
            "title": str(item.get("title") or rule_id)[:250],
            "category": str(item.get("category") or "container_security")[:80],
            "severity": severity,
            "confidence": _IAC_CONFIDENCE.get(str(item.get("confidence", "medium")), "medium"),
            # Config analysis is static evidence; only the verifier may elevate past 'suspected'.
            "status": "suspected",
            "description": str(item.get("description") or rule_id),
            "remediation": str(item.get("remediation") or "Review and harden the configuration."),
            "affected_url": f"file://{file_path}" + (f"#L{line_no}" if has_line else ""),
            "recommended_validations": [],
        }

    if tool == "osv":
        package = str(item["package"])
        version = str(item["version"])
        advisory = str(item["advisory"])
        fixed = item.get("fixed")
        manifest = str(item.get("manifest") or "")
        severity = str(item.get("severity", "")).lower()
        severity = severity if severity in _VALID_SEVERITIES else "unknown"
        summary = str(item.get("summary") or "").strip()
        return {
            "fingerprint": f"osv:{item['fingerprint']}",
            "title": f"{advisory}: {package} {version}"[:250],
            "category": "vulnerable_dependency",
            "severity": severity,
            # A declared version falling in an advisory range is not proof the flaw is reachable.
            "confidence": "medium",
            "status": "suspected",
            "description": (f"{summary} " if summary else "")
            + f"Declared {package} {version} is within the affected range of {advisory}.",
            "remediation": f"Upgrade {package} to {fixed} or later."
            if fixed
            else "Upgrade to a version outside the advisory's affected range.",
            "affected_url": f"file://{manifest}" if manifest else f"pkg:{package}@{version}",
            "recommended_validations": [],
        }

    if tool == "secrets":
        rule = str(item["rule"])
        file_path = str(item["file"])  # already redacted by the detector
        line = int(item["line"])
        secret_fp = str(item["fingerprint"])
        return {
            # Compose the identity: the same token in two files must stay two findings.
            "fingerprint": f"secrets:{fingerprint(rule, file_path, line, secret_fp)}",
            "title": f"Secret-shaped value ({rule}) in source"[:250],
            "category": "secret_exposure",
            "severity": "high",
            "confidence": "medium",
            "status": "suspected",
            "description": f"A {rule} secret-shaped value appears in {file_path} at line {line}.",
            "remediation": "Rotate the exposed credential and remove it from source control history.",
            "affected_url": f"file://{file_path}#L{line}",
            "recommended_validations": [],
        }

    raise ValueError(f"Unsupported tool source: {tool}")


__all__ = ["ToolSource", "normalize_parsed_finding"]
