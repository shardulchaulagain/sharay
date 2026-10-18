"""C5/C6 Worker Wiring Bridge for L3/L6 Parsers and Source Analyzers (`aegis/worker.py`).

Connects all L-half modules documented in `docs/integrations/WIRING.md`:
- `services.source_analysis_worker.dependencies.inventory`
- `services.source_analysis_worker.sbom.parse_cyclonedx`
- `packages.scanner_adapters.integrations.osv.match`
- `services.source_analysis_worker.secrets.detect`
- `services.source_analysis_worker.containers.scan` & `scan_k8s_manifest_dict`
- `packages.scanner_adapters.integrations` (`gitleaks`, `semgrep`, `nuclei`, `zap`, `metasploit`)
- `drafts.gemini.finding_normalizer.normalize_parsed_finding` (or `packages.scanner_adapters.integrations.normalize`)

Critical C5/C6 Invariant Enforced:
In `aegis/worker.py:148`, `run_one()` currently hardcodes `state = "confirmed"` and `actor = "safe_http"`.
When persisting L-half parser/analyzer findings, `persist_normalized_findings()` preserves each
normalized finding's `status` (`"suspected"` or `"false_positive"`, never `"confirmed"`) and
records the originating tool as `FindingHistory.actor`, so external parser output never bypasses
the verifier.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.models import Assessment, Finding, FindingEvidence, FindingHistory, Observation
from packages.reporting import redact
from packages.scanner_adapters.integrations import osv
from packages.scanner_adapters.integrations.normalize import ToolSource, normalize_parsed_finding
from services.source_analysis_worker import containers, dependencies, sbom, secrets

_ALLOWED_INITIAL_STATUSES = {"suspected", "false_positive"}


def evidence_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def analyze_staged_source_tree(
    root: Path | str,
    *,
    sbom_bytes: bytes | None = None,
    osv_advisories_bytes: bytes | None = None,
    k8s_manifests: list[tuple[dict[str, Any], str]] | None = None,
) -> dict[str, Any]:
    """Run pure L6 analyzers over a staged directory and optional SBOM/OSV/K8s inputs.

    Performs no network access, no package installation, and no subprocess execution.
    Returns `{"observations": [...], "normalized_findings": [...], "checks": [...]}`.
    """
    tree_root = Path(root).resolve()
    observations: list[dict[str, Any]] = []
    normalized_findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    # 1. Dependency manifest inventory + optional CycloneDX SBOM -> OSV advisory matching
    dep_inv = dependencies.inventory(tree_root)
    observations.append({"kind": "dependency_inventory", "summary": dep_inv})
    checks.append(
        {
            "category": "dependency_inventory",
            "status": "completed",
            "detail": f"Scanned {len(dep_inv['manifests'])} manifests ({len(dep_inv['packages'])} pinned packages).",
        }
    )

    combined_packages: list[dict[str, str]] = list(dep_inv["packages"])
    if sbom_bytes is not None:
        sbom_inv = sbom.parse_cyclonedx(sbom_bytes)
        observations.append({"kind": "sbom_inventory", "summary": sbom_inv})
        combined_packages.extend(sbom_inv["components"])
        checks.append(
            {
                "category": "sbom_cyclonedx",
                "status": "completed",
                "detail": f"Parsed {len(sbom_inv['components'])} CycloneDX components.",
            }
        )

    if osv_advisories_bytes is not None and combined_packages:
        osv_out = osv.match(osv_advisories_bytes, combined_packages)
        observations.append({"kind": "osv_match", "summary": osv_out})
        for item in osv_out["findings"]:
            norm = normalize_parsed_finding("osv", item)
            norm["actor"] = "osv"
            normalized_findings.append(norm)
        checks.append(
            {
                "category": "osv_advisory_match",
                "status": "completed",
                "detail": f"Matched {len(osv_out['findings'])} advisories against declared components.",
            }
        )

    # 2. Built-in secret pattern detection
    sec_out = secrets.detect(tree_root)
    observations.append({"kind": "secret_detection", "summary": sec_out})
    for match_item in sec_out["matches"]:
        norm = normalize_parsed_finding("secrets", match_item)
        norm["actor"] = "secrets"
        normalized_findings.append(norm)
    checks.append(
        {
            "category": "secret_detection",
            "status": "completed",
            "detail": f"Scanned {sec_out['files_scanned']} files ({len(sec_out['matches'])} secret matches).",
        }
    )

    # 3. Container / IaC analysis (Dockerfiles + pre-parsed K8s manifests)
    iac_out = containers.scan(tree_root)
    iac_findings = list(iac_out["findings"])
    for doc, path_label in k8s_manifests or []:
        iac_findings.extend(containers.scan_k8s_manifest_dict(doc, path_label))
    observations.append(
        {
            "kind": "container_iac_scan",
            "summary": {
                "files": iac_out["files"],
                "k8s_manifests_scanned": len(k8s_manifests or []),
                "findings_count": len(iac_findings),
                "unreadable": iac_out["unreadable"],
                "truncated": iac_out["truncated"],
            },
        }
    )
    for iac_item in iac_findings:
        norm = normalize_parsed_finding("iac", iac_item)
        norm["actor"] = "iac"
        normalized_findings.append(norm)
    checks.append(
        {
            "category": "container_iac",
            "status": "completed",
            "detail": f"Evaluated container/IaC configuration ({len(iac_findings)} findings).",
        }
    )

    return {
        "observations": observations,
        "normalized_findings": normalized_findings,
        "checks": checks,
    }


def persist_normalized_findings(
    db: Session,
    *,
    assessment: Assessment,
    observations: list[dict[str, Any]],
    normalized_findings: list[dict[str, Any]],
) -> tuple[list[Observation], list[Finding]]:
    """Persist redacted L-half observations and normalized findings into `aegis.models`.

    Guarantees:
    - Parser/analyzer findings enter with `status="suspected"` (or `"false_positive"` for ZAP
      false-positive alerts), never `"confirmed"`.
    - Deduplicates by `(target_id, fingerprint)` while preserving existing `"confirmed"` status
      if a finding was already confirmed by the verifier, or transitioning `"fixed"` -> `"reopened"`.
    """
    saved_observations: list[Observation] = []
    for raw_obs in observations:
        clean_obs = redact(raw_obs)
        obs_row = Observation(
            organization_id=assessment.organization_id,
            assessment_id=assessment.id,
            data=clean_obs,
            evidence_hash=evidence_hash(clean_obs),
        )
        db.add(obs_row)
        db.flush()
        saved_observations.append(obs_row)

    saved_findings: list[Finding] = []
    seen_fingerprints: set[str] = set()
    for raw_finding in normalized_findings:
        clean = redact(raw_finding)
        fp = str(clean["fingerprint"])
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)

        actor = str(clean.get("actor") or fp.split(":", 1)[0] or "analyzer")
        initial_status = str(clean.get("status", "suspected"))
        if initial_status not in _ALLOWED_INITIAL_STATUSES:
            initial_status = "suspected"

        existing = db.scalar(
            select(Finding).where(
                Finding.target_id == assessment.target_id,
                Finding.fingerprint == fp,
            )
        )
        if existing is not None:
            if existing.status == "fixed" and initial_status != "false_positive":
                state = "reopened"
            else:
                state = existing.status
            existing.last_seen = time.time()
            existing.status = state
            finding_row = existing
        else:
            state = initial_status
            finding_row = Finding(
                organization_id=assessment.organization_id,
                project_id=assessment.project_id,
                target_id=assessment.target_id,
                fingerprint=fp,
                title=str(clean["title"])[:250],
                category=str(clean["category"])[:80],
                severity=str(clean["severity"]),
                confidence=str(clean["confidence"]),
                status=state,
                description=str(clean["description"]),
                remediation=str(clean["remediation"]),
                affected_url=str(clean["affected_url"]),
            )
            db.add(finding_row)
            db.flush()

        snapshot = {
            **{k: v for k, v in clean.items() if k != "actor"},
            "status": state,
            "observation_ids": [o.id for o in saved_observations],
        }
        db.add(
            FindingEvidence(
                finding_id=finding_row.id,
                assessment_id=assessment.id,
                data=snapshot,
                evidence_hash=evidence_hash(snapshot),
            )
        )
        db.add(
            FindingHistory(
                finding_id=finding_row.id,
                status=state,
                actor=actor[:80],
                reason=f"Normalized {actor} finding recorded in assessment {assessment.id}",
            )
        )
        saved_findings.append(finding_row)

    return saved_observations, saved_findings


def normalize_batch(
    tool: ToolSource,
    items: list[dict[str, Any]],
    *,
    default_target_url: str = "",
) -> list[dict[str, Any]]:
    """Normalize a list of parser items from `tool` and tag each with `actor=tool`."""
    results: list[dict[str, Any]] = []
    for item in items:
        row = normalize_parsed_finding(tool, item, default_target_url=default_target_url)
        row["actor"] = tool
        results.append(row)
    return results


def aggregate_recon_observations(
    *,
    tls_certs: list[tuple[dict[str, Any], float | None]] | None = None,
    dns_answers: list[dict[str, Any]] | None = None,
    nmap_hosts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run L5 TLS/DNS parsers and merge discovered assets with provenance via `recon.collect_assets`."""
    from packages.scanner_adapters.integrations import dns, recon, tls

    observations: list[dict[str, Any]] = []
    recon_inputs: list[dict[str, Any]] = []

    for cert_dict, now_epoch in tls_certs or []:
        parsed_tls = tls.parse_peer_certificate(cert_dict, now_epoch=now_epoch)
        observations.append({"kind": "tls_recon", "summary": parsed_tls})
        recon_inputs.append(
            {
                "source": "tls",
                "hostnames": parsed_tls["sans"]["dns"],
                "ips": parsed_tls["sans"]["ip"],
            }
        )

    if dns_answers is not None:
        parsed_dns = dns.parse_records(dns_answers)
        observations.append({"kind": "dns_recon", "summary": parsed_dns})
        recon_inputs.append(
            {
                "source": "dns",
                "hostnames": parsed_dns["assets"]["hostnames"],
                "ips": parsed_dns["assets"]["ips"],
            }
        )

    if nmap_hosts:
        nmap_hostnames: list[str] = []
        nmap_ips: list[str] = []
        for host in nmap_hosts:
            if isinstance(host.get("address"), str) and host["address"]:
                nmap_ips.append(host["address"])
            for hname in host.get("hostnames", []):
                if isinstance(hname, str) and hname:
                    nmap_hostnames.append(hname)
        recon_inputs.append(
            {
                "source": "nmap",
                "hostnames": nmap_hostnames,
                "ips": nmap_ips,
            }
        )

    merged_assets = recon.collect_assets(recon_inputs)
    observations.append({"kind": "recon_assets", "summary": merged_assets})
    return {
        "observations": observations,
        "assets": merged_assets["assets"],
        "truncated": merged_assets["truncated"],
    }


def ai_integration_status(environment: dict[str, str] | None = None) -> dict[str, Any]:
    """Return honest L7 AI provider status for `/api/v1/integrations` without exposing secrets."""
    import services.ai_analysis_worker.vendors as _vendors  # noqa: F401
    from services.ai_analysis_worker import AIUnavailable
    from services.ai_analysis_worker.providers import build, config_from_environment, secret

    try:
        cfg = config_from_environment(environment)
    except AIUnavailable as exc:
        return {
            "status": "misconfigured",
            "provider": "none",
            "model": "",
            "share_assessment_data": False,
            "reason": str(exc),
        }

    if cfg.provider == "none":
        return {
            "status": "disabled",
            "provider": "none",
            "model": "",
            "share_assessment_data": False,
            "reason": "No provider configured; no evidence transmitted",
        }

    try:
        build(cfg)
        if cfg.api_key_env:
            secret(cfg, environment)
    except AIUnavailable as exc:
        return {
            "status": "gated",
            "provider": cfg.provider,
            "model": cfg.model,
            "share_assessment_data": cfg.share_assessment_data,
            "reason": str(exc),
        }

    return {
        "status": "ready",
        "provider": cfg.provider,
        "model": cfg.model,
        "share_assessment_data": cfg.share_assessment_data,
        "reason": "Provider configured and data sharing explicitly enabled by operator.",
    }


__all__ = [
    "aggregate_recon_observations",
    "ai_integration_status",
    "analyze_staged_source_tree",
    "evidence_hash",
    "normalize_batch",
    "persist_normalized_findings",
]
