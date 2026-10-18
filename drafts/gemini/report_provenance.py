"""Cryptographically verifiable SHARAY report provenance and end-to-end assessment reconstruction.

Drafted by Gemini (writer: gemini) for Codex's C7 reporting pipeline (`packages/reporting/reports.py`).
Provides:
1. Canonical SHA-256 Merkle/section digest binding (`sharay.provenance.v1`) over scope, active
   tool pins, findings, root causes, diagnostic session durations, 3-state impact calibrations,
   cleanup verification, and evidence hashes.
2. Optional keyed HMAC-SHA256 provenance tag (`verify_report_provenance`) to detect any tampering
   with findings, severities, session durations, or scope after report export.
3. End-to-end assessment and bug-bounty report reconstruction (`build_assessment_reconstruction`),
   incorporating root cause, session duration (`duration_seconds`), observed vs. theoretical vs.
   not_yet_tested impact, and cleanup verification with recursive secret redaction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from packages.reporting import redact

PROVENANCE_SCHEMA = "sharay.provenance.v1"


def _canonical_json(value: Any) -> bytes:
    """Serialize any JSON-compatible structure deterministically."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _records(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def build_assessment_reconstruction(raw_data: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct a complete, secret-redacted assessment & bug-bounty record from stored state."""
    if not isinstance(raw_data, dict):
        raise ValueError("Assessment reconstruction input must be a dictionary")
    clean = _mapping(redact(raw_data))
    assessment = _mapping(clean.get("assessment"))
    scope = _mapping(clean.get("scope") or assessment.get("scope_snapshot"))
    findings = [_mapping(item) for item in _records(clean.get("findings"))]
    sessions = [_mapping(item) for item in _records(clean.get("sessions"))]
    validations = [_mapping(item) for item in _records(clean.get("validations"))]
    impacts = [_mapping(item) for item in _records(clean.get("impacts"))]
    cleanup_records = [_mapping(item) for item in _records(clean.get("cleanup_records"))]

    sessions_by_finding: dict[str, list[dict[str, Any]]] = {}
    total_session_seconds = 0.0
    for sess in sessions:
        finding_id = str(sess.get("finding_id") or "")
        duration = float(sess.get("duration_seconds") or 0.0)
        if duration < 0:
            raise ValueError("Session duration_seconds cannot be negative")
        total_session_seconds = round(total_session_seconds + duration, 3)
        summary = {
            "session_id": str(sess.get("session_id") or sess.get("id") or "unavailable"),
            "finding_id": finding_id or None,
            "session_kind": str(sess.get("session_kind") or "unavailable"),
            "state": str(sess.get("state") or "unavailable"),
            "established_at": sess.get("established_at"),
            "terminated_at": sess.get("terminated_at"),
            "duration_seconds": round(duration, 3),
            "privilege_context": _mapping(sess.get("privilege_context")),
            "action_count": len(_records(sess.get("action_log"))),
        }
        sessions_by_finding.setdefault(finding_id, []).append(summary)

    impacts_by_finding: dict[str, list[dict[str, Any]]] = {}
    for item in impacts:
        finding_id = str(item.get("finding_id") or "")
        state = str(item.get("state") or "not_yet_tested")
        if state not in {"theoretical", "observed", "not_yet_tested"}:
            raise ValueError(f"Invalid impact state: {state}")
        impacts_by_finding.setdefault(finding_id, []).append(
            {
                "dimension": str(item.get("dimension") or "unspecified"),
                "state": state,
                "summary": str(item.get("summary") or ""),
                "evidence_hash": str(item.get("evidence_hash") or ""),
            }
        )

    validations_by_finding: dict[str, list[dict[str, Any]]] = {}
    for val in validations:
        finding_id = str(val.get("finding_id") or "")
        validations_by_finding.setdefault(finding_id, []).append(
            {
                "module_id": str(val.get("module_id") or "unavailable"),
                "vulnerability_class": str(val.get("vulnerability_class") or "unavailable"),
                "outcome": str(val.get("outcome") or "unavailable"),
                "preconditions_met": list(_records(val.get("preconditions_met"))),
                "evidence_hash": str(val.get("evidence_hash") or ""),
            }
        )

    bug_bounty_submissions: list[dict[str, Any]] = []
    for finding in findings:
        fid = str(finding.get("id") or "")
        f_sessions = sessions_by_finding.get(fid, [])
        f_impacts = impacts_by_finding.get(fid, [])
        f_validations = validations_by_finding.get(fid, [])
        finding_duration = round(sum(item["duration_seconds"] for item in f_sessions), 3)
        observed_impacts = [i for i in f_impacts if i["state"] == "observed"]
        theoretical_impacts = [i for i in f_impacts if i["state"] == "theoretical"]
        untested_impacts = [i for i in f_impacts if i["state"] == "not_yet_tested"]

        bug_bounty_submissions.append(
            {
                "finding_id": fid or "unavailable",
                "title": str(finding.get("title") or "Untitled finding"),
                "category": str(finding.get("category") or "unavailable"),
                "status": str(finding.get("status") or "needs_triage"),
                "severity": str(finding.get("severity") or "provisional"),
                "confidence": str(finding.get("confidence") or "unavailable"),
                "cwe": finding.get("cwe"),
                "cvss_v4_vector": finding.get("cvss_vector"),
                "affected_asset": str(
                    finding.get("affected_url") or finding.get("affected_asset") or "unavailable"
                ),
                "root_cause": str(
                    finding.get("root_cause")
                    or finding.get("description")
                    or "Root cause requires source or configuration review."
                ),
                "reproduction_steps": list(_records(finding.get("reproduction_steps"))),
                "validations": f_validations,
                "access_session_summary": {
                    "sessions_established": len(f_sessions),
                    "total_duration_seconds": finding_duration,
                    "sessions": f_sessions,
                },
                "impact_breakdown": {
                    "observed": observed_impacts,
                    "theoretical": theoretical_impacts,
                    "not_yet_tested": untested_impacts,
                },
                "remediation": str(finding.get("remediation") or "Unavailable"),
            }
        )

    pending_cleanup = [item for item in cleanup_records if str(item.get("status") or "") != "verified_clean"]
    return {
        "assessment_id": assessment.get("id"),
        "scope_version": scope.get("version", assessment.get("scope_version")),
        "total_sessions_established": len(sessions),
        "total_session_duration_seconds": total_session_seconds,
        "cleanup_status": (
            "verified_clean"
            if cleanup_records and not pending_cleanup
            else ("pending_cleanup" if pending_cleanup else "no_artifacts_recorded")
        ),
        "cleanup_records": [
            {
                "artifact_id": str(item.get("artifact_id") or ""),
                "session_id": str(item.get("session_id") or ""),
                "artifact_kind": str(item.get("artifact_kind") or ""),
                "location": str(item.get("location") or ""),
                "status": str(item.get("status") or "pending_cleanup"),
                "verified_at": item.get("verified_at"),
            }
            for item in cleanup_records
        ],
        "bug_bounty_submissions": bug_bounty_submissions,
    }


def compute_provenance_envelope(
    report_data: dict[str, Any],
    *,
    signing_key: bytes | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Compute a tamper-evident SHARAY provenance manifest over a prepared report dictionary."""
    if not isinstance(report_data, dict):
        raise ValueError("Report data must be a dictionary")
    clean = _mapping(redact(report_data))
    assessment = _mapping(clean.get("assessment"))
    scope = _mapping(clean.get("scope") or assessment.get("scope_snapshot"))
    tools = [
        {
            "name": str(_mapping(t).get("name") or ""),
            "version": str(_mapping(t).get("version") or ""),
            "sha256": str(_mapping(t).get("sha256") or ""),
        }
        for t in _records(clean.get("tools"))
    ]
    reconstruction = build_assessment_reconstruction(clean)
    evidence_hashes = sorted(
        {
            str(h)
            for h in _records(_mapping(clean.get("report_metadata")).get("evidence_hashes"))
            if isinstance(h, str) and h
        }
    )

    section_digests = {
        "assessment": _sha256_hex(
            _canonical_json(
                {
                    "id": assessment.get("id"),
                    "project_id": assessment.get("project_id"),
                    "target_id": assessment.get("target_id"),
                    "status": assessment.get("status"),
                    "profile": assessment.get("profile"),
                    "created_at": assessment.get("created_at"),
                    "started_at": assessment.get("started_at"),
                    "finished_at": assessment.get("finished_at"),
                }
            )
        ),
        "scope": _sha256_hex(_canonical_json(scope)),
        "tools": _sha256_hex(_canonical_json(tools)),
        "findings": _sha256_hex(_canonical_json(_records(clean.get("findings")))),
        "reconstruction": _sha256_hex(_canonical_json(reconstruction)),
        "evidence_hashes": _sha256_hex(_canonical_json(evidence_hashes)),
    }

    manifest_core = {
        "schema": PROVENANCE_SCHEMA,
        "generator": "SHARAY",
        "assessment_id": assessment.get("id"),
        "scope_version": scope.get("version", assessment.get("scope_version")),
        "synthetic": bool(clean.get("synthetic", False)),
        "section_digests": section_digests,
    }
    manifest_sha256 = _sha256_hex(_canonical_json(manifest_core))

    signature_mode = "unsigned_sha256_manifest"
    hmac_sha256: str | None = None
    if signing_key is not None:
        if not isinstance(signing_key, (bytes, bytearray)) or len(signing_key) < 16:
            raise ValueError("Provenance signing_key must be at least 16 bytes")
        signature_mode = "hmac_sha256"
        hmac_sha256 = hmac.new(
            bytes(signing_key),
            _canonical_json({**manifest_core, "manifest_sha256": manifest_sha256}),
            hashlib.sha256,
        ).hexdigest()

    return {
        **manifest_core,
        "generated_at": str(
            _mapping(clean.get("report_metadata")).get("generated_at")
            or clean.get("generated_at")
            or datetime.now(timezone.utc).isoformat()
        ),
        "manifest_sha256": manifest_sha256,
        "signature_mode": signature_mode,
        "key_id": key_id if signing_key is not None else None,
        "hmac_sha256": hmac_sha256,
        "reconstruction": reconstruction,
    }


def verify_report_provenance(
    report_data: dict[str, Any],
    envelope: dict[str, Any],
    *,
    signing_key: bytes | None = None,
) -> dict[str, Any]:
    """Verify that report_data matches a SHARAY provenance envelope without any tampered sections."""
    if not isinstance(envelope, dict) or envelope.get("schema") != PROVENANCE_SCHEMA:
        return {
            "verified": False,
            "mismatched_sections": ["schema"],
            "reason": "Unsupported provenance schema",
        }

    expected = compute_provenance_envelope(
        report_data,
        signing_key=signing_key,
        key_id=envelope.get("key_id"),
    )
    recorded_sections = _mapping(envelope.get("section_digests"))
    expected_sections = _mapping(expected.get("section_digests"))
    mismatched: list[str] = []
    for section_name, expected_digest in expected_sections.items():
        actual_digest = str(recorded_sections.get(section_name) or "")
        if not hmac.compare_digest(actual_digest, str(expected_digest)):
            mismatched.append(section_name)

    if mismatched:
        return {
            "verified": False,
            "mismatched_sections": sorted(mismatched),
            "reason": "One or more report sections differ from the recorded SHARAY provenance digests",
        }

    recorded_manifest = str(envelope.get("manifest_sha256") or "")
    if not hmac.compare_digest(recorded_manifest, str(expected["manifest_sha256"])):
        return {
            "verified": False,
            "mismatched_sections": ["manifest_sha256"],
            "reason": "Manifest root digest mismatch",
        }

    if envelope.get("signature_mode") == "hmac_sha256" or signing_key is not None:
        if signing_key is None:
            return {
                "verified": False,
                "mismatched_sections": ["hmac_sha256"],
                "reason": "Signing key required to verify HMAC-signed provenance envelope",
            }
        recorded_hmac = str(envelope.get("hmac_sha256") or "")
        expected_hmac = str(expected.get("hmac_sha256") or "")
        if not recorded_hmac or not hmac.compare_digest(recorded_hmac, expected_hmac):
            return {
                "verified": False,
                "mismatched_sections": ["hmac_sha256"],
                "reason": "HMAC signature mismatch",
            }

    return {
        "verified": True,
        "mismatched_sections": [],
        "manifest_sha256": expected["manifest_sha256"],
        "signature_mode": expected["signature_mode"],
    }


__all__ = [
    "PROVENANCE_SCHEMA",
    "build_assessment_reconstruction",
    "compute_provenance_envelope",
    "verify_report_provenance",
]
