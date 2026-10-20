"""SARIF 2.1.0 and Formula-Safe CSV Exporters.

Sector 6: Reporting & Evidence.
Provides:
1. Native OASIS SARIF v2.1.0 JSON export for CI/CD, GitHub Code Scanning & ticketing.
2. Formula-injection-safe CSV export for spreadsheet & issue trackers.
"""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Any, Dict, List


def _sanitize_csv_cell(value: Any) -> str:
    """Neutralize spreadsheet formula injection (=, +, -, @, \\t, \\r)."""
    text = str(value) if value is not None else ""
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


class SarifExporter:
    """Exports assessment findings in official OASIS SARIF v2.1.0 JSON format."""

    SEVERITY_LEVEL_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    @classmethod
    def export(cls, assessment_data: Dict[str, Any], tool_version: str = "2.0.0") -> str:
        findings = assessment_data.get("findings", [])
        target_url = (
            assessment_data.get("target_url")
            or assessment_data.get("scope_snapshot", {}).get("target_url", "")
            or "https://target.local"
        )
        assessment_id = assessment_data.get("id", "assessment-unknown")

        rules: List[Dict[str, Any]] = []
        rule_indices: Dict[str, int] = {}
        results: List[Dict[str, Any]] = []

        for f in findings:
            fingerprint = f.get("fingerprint") or f.get("id") or "SHARAY-RULE-GENERIC"
            category = f.get("category", "security_finding")
            title = f.get("title", "Observed Security Finding")
            severity = str(f.get("severity", "medium")).lower()
            level = cls.SEVERITY_LEVEL_MAP.get(severity, "warning")
            cwe = f.get("cwe_id", "CWE-699")

            rule_id = f"SHARAY/{category.upper()}"
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append(
                    {
                        "id": rule_id,
                        "name": title,
                        "shortDescription": {"text": title},
                        "fullDescription": {"text": f.get("description", title)},
                        "help": {
                            "text": f"Remediation: {f.get('remediation', 'Apply defense in depth.')}",
                            "markdown": f"### Remediation\n\n{f.get('remediation', 'Apply defense in depth.')}",
                        },
                        "defaultConfiguration": {"level": level},
                        "properties": {
                            "tags": ["security", category, cwe],
                            "precision": "high" if f.get("confidence") == "high" else "medium",
                        },
                    }
                )

            rule_idx = rule_indices[rule_id]
            affected_url = f.get("affected_url") or target_url
            autopy = f.get("autopyverifier", {}) or {}
            reproduced = bool(autopy and autopy.get("exit_code") == 0)

            result_obj: Dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": level,
                "message": {"text": f"{title}: {f.get('description', '')}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": affected_url},
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                ],
                "properties": {
                    "fingerprint": fingerprint,
                    "severity": severity,
                    "confidence": f.get("confidence", "high"),
                    "status": f.get("status", "suspected"),
                    "lifecycle_state": f.get("lifecycle_state", "CANDIDATE"),
                    "evidence_hash": f.get("evidence_hash", ""),
                    "autopyverifier_reproduced": reproduced,
                },
            }
            results.append(result_obj)

        sarif_doc = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SHARAY",
                            "version": tool_version,
                            "informationUri": "https://sharay.dev",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "properties": {"assessment_id": assessment_id},
                        }
                    ],
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_doc, indent=2)


class CsvExporter:
    """Exports assessment findings as a clean, formula-injection-safe CSV."""

    HEADERS = [
        "Finding ID",
        "Title",
        "Severity",
        "Confidence",
        "Category",
        "Status",
        "Lifecycle State",
        "Affected URL",
        "AutoPyVerifier Reproduced",
        "Evidence Hash",
        "Remediation",
    ]

    @classmethod
    def export(cls, assessment_data: Dict[str, Any]) -> str:
        findings = assessment_data.get("findings", [])
        target_url = assessment_data.get("target_url") or ""

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(cls.HEADERS)

        for f in findings:
            autopy = f.get("autopyverifier", {}) or {}
            reproduced = "YES" if (autopy and autopy.get("exit_code") == 0) else "NO"
            row = [
                _sanitize_csv_cell(f.get("fingerprint") or f.get("id", "")),
                _sanitize_csv_cell(f.get("title", "")),
                _sanitize_csv_cell(str(f.get("severity", "medium")).upper()),
                _sanitize_csv_cell(f.get("confidence", "high")),
                _sanitize_csv_cell(f.get("category", "")),
                _sanitize_csv_cell(f.get("status", "suspected")),
                _sanitize_csv_cell(f.get("lifecycle_state", "CANDIDATE")),
                _sanitize_csv_cell(f.get("affected_url") or target_url),
                _sanitize_csv_cell(reproduced),
                _sanitize_csv_cell(f.get("evidence_hash", "")),
                _sanitize_csv_cell(f.get("remediation", "")),
            ]
            writer.writerow(row)

        return output.getvalue()
