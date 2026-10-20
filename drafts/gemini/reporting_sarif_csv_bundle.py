"""SARIF 2.1.0 Exporter, CSV Exporter, and Hash-Sealed Evidence Bundle Engine.

Sector 6: Reporting & Evidence (Milestone P1.6).
Provides:
1. Native SARIF 2.1.0 JSON export for CI/CD, GitHub Code Scanning & ticketing.
2. Formula-injection-safe CSV export for spreadsheet & issue trackers.
3. Downloadable, cryptographic SHA-256 Merkle-sealed evidence archive (.zip).
4. Evidence bundle verification proving forensic integrity fail-closed.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        target_url = assessment_data.get("target_url") or assessment_data.get("scope_snapshot", {}).get("target_url", "")
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
                rules.append({
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
                })

            rule_idx = rule_indices[rule_id]
            affected_url = f.get("affected_url") or target_url or "https://target.local"
            autopy = f.get("autopyverifier", {})
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
            autopy = f.get("autopyverifier", {})
            reproduced = "YES" if (autopy and autopy.get("exit_code") == 0) else "NO"
            row = [
                _sanitize_csv_cell(f.get("fingerprint") or f.get("id", "")),
                _sanitize_csv_cell(f.get("title", "")),
                _sanitize_csv_cell(f.get("severity", "medium").upper()),
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


class EvidenceBundleBuilder:
    """Packages raw assessment captures and PoCs into a tamper-evident, sealed ZIP bundle."""

    @classmethod
    def build_bundle(
        cls,
        assessment_id: str,
        assessment_data: Dict[str, Any],
        raw_captures: Optional[List[Dict[str, Any]]] = None,
        autopy_scripts: Optional[Dict[str, str]] = None,
    ) -> bytes:
        buf = io.BytesIO()
        file_hashes: Dict[str, str] = {}

        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 1. Findings snapshot
            findings_bytes = json.dumps(
                assessment_data.get("findings", []), indent=2, sort_keys=True
            ).encode("utf-8")
            zf.writestr("findings.json", findings_bytes)
            file_hashes["findings.json"] = _sha256(findings_bytes)

            # 2. Raw request/response observations
            captures = raw_captures or assessment_data.get("observations", [])
            obs_bytes = json.dumps(captures, indent=2, sort_keys=True).encode("utf-8")
            zf.writestr("requests/observations.json", obs_bytes)
            file_hashes["requests/observations.json"] = _sha256(obs_bytes)

            # 3. AutoPyVerifier standalone scripts
            scripts = autopy_scripts or {}
            for name, code in scripts.items():
                script_path = f"autopyverifier/{name}.py"
                code_bytes = code.encode("utf-8")
                zf.writestr(script_path, code_bytes)
                file_hashes[script_path] = _sha256(code_bytes)

            # 4. Merkle Root Hash calculation
            sorted_hashes = [file_hashes[p] for p in sorted(file_hashes.keys())]
            merkle_root = hashlib.sha256("".join(sorted_hashes).encode("utf-8")).hexdigest()

            # 5. Cryptographic Manifest & Seal
            manifest = {
                "assessment_id": assessment_id,
                "created_at": time.time(),
                "file_count": len(file_hashes),
                "files": file_hashes,
                "merkle_root_seal": merkle_root,
                "provenance_standard": "SHARAY-SEAL-V2",
            }
            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
            zf.writestr("manifest.json", manifest_bytes)

        return buf.getvalue()

    @classmethod
    def verify_bundle(cls, bundle_bytes: bytes) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Cryptographically verifies that every file in the bundle matches its sealed hash."""
        try:
            with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as zf:
                if "manifest.json" not in zf.namelist():
                    return False, "Missing manifest.json in evidence bundle", None

                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                declared_files = manifest.get("files", {})
                declared_root = manifest.get("merkle_root_seal", "")

                computed_hashes: Dict[str, str] = {}
                for path, expected_hash in declared_files.items():
                    if path not in zf.namelist():
                        return False, f"Missing declared file in bundle: {path}", None
                    actual_hash = _sha256(zf.read(path))
                    if actual_hash != expected_hash:
                        return False, f"Hash mismatch for {path}: expected {expected_hash}, got {actual_hash}", None
                    computed_hashes[path] = actual_hash

                # Recompute Merkle root
                sorted_hashes = [computed_hashes[p] for p in sorted(computed_hashes.keys())]
                recomputed_root = hashlib.sha256("".join(sorted_hashes).encode("utf-8")).hexdigest()

                if recomputed_root != declared_root:
                    return False, f"Merkle root seal mismatch: declared {declared_root}, got {recomputed_root}", None

                return True, "Evidence bundle verification succeeded: all hashes intact.", manifest
        except Exception as exc:
            return False, f"Corrupted or invalid zip archive: {exc}", None
