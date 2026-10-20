"""Source Code, Secret & Dependency Scanners Pipeline (Sector 2.6).

Normalizes raw outputs from Semgrep (SAST), Gitleaks (Secrets), and OSV (Dependencies)
into unified, audited, and envelope-compliant SHARAY Finding dictionaries.
"""

from __future__ import annotations

import hashlib
from typing import Any, Sequence

from packages.scanner_adapters.integrations import gitleaks, osv, semgrep


class SourceScannerPipeline:
    """Orchestrates parsing, envelope normalization, deduplication, and audit logging for source scanners."""

    @staticmethod
    def normalize_semgrep(raw_output: bytes | str, project_path: str = "") -> list[dict[str, Any]]:
        """Normalize Semgrep JSON report into SHARAY finding envelopes."""
        data_bytes = raw_output.encode("utf-8") if isinstance(raw_output, str) else raw_output
        parsed = semgrep.parse(data_bytes, source_root=project_path)
        normalized: list[dict[str, Any]] = []

        for item in parsed.get("findings", []):
            rule_id = item.get("rule", "semgrep_rule")
            file_path = item.get("file", item.get("path", ""))
            line = item.get("line", 0)
            sev = item.get("severity", "medium").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "medium"

            cwes = item.get("cwe", [])
            primary_cwe = cwes[0] if cwes else "CWE-20"
            fp = hashlib.sha256(f"sast:semgrep:{rule_id}:{file_path}:{line}".encode()).hexdigest()

            normalized.append(
                {
                    "category": "sast_vulnerability",
                    "severity": sev,
                    "title": f"SAST: {rule_id} in {file_path}",
                    "description": f"Static analysis identified rule match '{rule_id}' at line {line} of {file_path}.",
                    "target_url": f"file://{file_path}#L{line}",
                    "affected_path": file_path,
                    "line_number": line,
                    "fingerprint": fp,
                    "cwe_id": primary_cwe,
                    "confidence": "high",
                    "status": "suspected",
                    "tool": "semgrep",
                    "remediation": f"Review rule '{rule_id}' recommendations and sanitize source inputs.",
                }
            )
        return normalized

    @staticmethod
    def normalize_gitleaks(raw_output: bytes | str, project_path: str = "") -> list[dict[str, Any]]:
        """Normalize Gitleaks JSON findings without exposing secret values."""
        data_bytes = raw_output.encode("utf-8") if isinstance(raw_output, str) else raw_output
        parsed = gitleaks.parse(data_bytes, source_root=project_path)
        normalized: list[dict[str, Any]] = []

        for item in parsed.get("findings", []):
            rule_id = item.get("rule", "generic_secret")
            file_path = item.get("file", item.get("path", ""))
            line = item.get("line", 0)
            fp = hashlib.sha256(f"secret:gitleaks:{rule_id}:{file_path}:{line}".encode()).hexdigest()

            normalized.append(
                {
                    "category": "unsecured_credentials",
                    "severity": "high",
                    "title": f"Hardcoded Secret Detected ({rule_id})",
                    "description": (
                        f"Gitleaks detected a hardcoded credential matching pattern '{rule_id}' "
                        f"in {file_path} at line {line}. Secret values are redacted."
                    ),
                    "target_url": f"file://{file_path}#L{line}",
                    "affected_path": file_path,
                    "line_number": line,
                    "fingerprint": fp,
                    "cwe_id": "CWE-798",
                    "confidence": "high",
                    "status": "suspected",
                    "tool": "gitleaks",
                    "remediation": "Revoke the exposed credential immediately and replace with environment secrets.",
                }
            )
        return normalized

    @staticmethod
    def normalize_osv(
        advisory_bytes: bytes,
        packages: Sequence[tuple[str, str, str]],  # (ecosystem, name, version)
    ) -> list[dict[str, Any]]:
        """Match declared packages against OSV advisories and generate findings."""
        pkg_dicts = [{"ecosystem": eco, "name": pkg, "version": ver} for eco, pkg, ver in packages]
        matched = osv.match(advisory_bytes, pkg_dicts)
        normalized: list[dict[str, Any]] = []

        for item in matched.get("findings", []):
            vuln_id = item.get("advisory", "OSV-UNKNOWN")
            pkg_name = item.get("package", "")
            installed_ver = item.get("version", "")
            ecosystem = item.get("ecosystem", "")
            fp = (
                item.get("fingerprint")
                or hashlib.sha256(f"dependency:{ecosystem}:{pkg_name}:{vuln_id}".encode()).hexdigest()
            )

            remediation = (
                f"Upgrade {pkg_name} to {item.get('fixed')} or later per advisory {vuln_id}."
                if item.get("fixed")
                else f"Upgrade {pkg_name} to a non-vulnerable fixed version per advisory {vuln_id}."
            )

            normalized.append(
                {
                    "category": "vulnerable_dependency",
                    "severity": item.get("severity", "high"),
                    "title": f"Vulnerable Dependency: {pkg_name}@{installed_ver} ({vuln_id})",
                    "description": (
                        item.get("summary")
                        or f"The declared package {pkg_name} version {installed_ver} ({ecosystem}) "
                        f"falls within the affected version range of published advisory {vuln_id}."
                    ),
                    "target_url": f"pkg:{ecosystem}/{pkg_name}@{installed_ver}",
                    "fingerprint": fp,
                    "cwe_id": "CWE-1395",
                    "confidence": "high",
                    "status": "suspected",
                    "tool": "osv",
                    "remediation": remediation,
                }
            )
        return normalized

    @classmethod
    def process_all(
        cls,
        *,
        semgrep_json: bytes | str | None = None,
        gitleaks_json: bytes | str | None = None,
        osv_advisory_json: bytes | None = None,
        declared_packages: Sequence[tuple[str, str, str]] = (),
        audit_db: Any | None = None,
        assessment_id: str = "",
        org_id: str = "default",
    ) -> list[dict[str, Any]]:
        """Process multiple source scans, normalize envelopes, and record in audit log."""
        all_findings: list[dict[str, Any]] = []

        if semgrep_json:
            all_findings.extend(cls.normalize_semgrep(semgrep_json))
        if gitleaks_json:
            all_findings.extend(cls.normalize_gitleaks(gitleaks_json))
        if osv_advisory_json and declared_packages:
            all_findings.extend(cls.normalize_osv(osv_advisory_json, declared_packages))

        if audit_db is not None:
            try:
                from aegis.audit import audit

                audit(
                    audit_db,
                    org=org_id,
                    actor="source_scanner",
                    action="source_scanners.ingested",
                    resource=assessment_id or "repo",
                    detail={"findings_count": len(all_findings)},
                )
            except Exception:
                pass

        return all_findings


__all__ = ["SourceScannerPipeline"]
