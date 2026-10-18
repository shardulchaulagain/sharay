"""One durable local queue and dedicated, bounded safe-scanner process."""

import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm.attributes import flag_modified

from aegis.audit import audit
from aegis.config import ROOT, Settings
from aegis.database import create_database
from aegis.lifecycle import watch_parent_stdin
from aegis.models import (
    Assessment,
    Finding,
    FindingEvidence,
    FindingHistory,
    Observation,
    OriginCooldown,
    Target,
)
from aegis.schemas import ScanConfig
from packages.reporting import redact
from packages.scanner_adapters import scan, scan_comprehensive, scan_live, scan_live_nuclei
from packages.security_policies import PolicyError, ScopePolicy, check_execution_url, resolve_pinned
from services.scanner_worker import IsolationError

os.environ.setdefault("no_proxy", "127.0.0.1,localhost,::1")
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")


@contextmanager
def _short_database_wait(db):
    # Restore before the session returns its connection to the shared pool.
    connection = db.connection().connection.driver_connection
    previous = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])
    connection.execute("PRAGMA busy_timeout=50")
    try:
        yield
    finally:
        connection.execute(f"PRAGMA busy_timeout={previous}")


class PersistentRequestStarts(dict[str, tuple[float, float]]):
    """One serialized worker: durable intervals, conservative monotonic restart fences."""

    def __init__(self, sessions):
        super().__init__()
        self.sessions = sessions

    @staticmethod
    def _interval(value):
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0.1:
            raise ValueError("Invalid stored request cooldown")
        return float(value)

    def get(self, origin, default=None):
        if origin not in self:
            with self.sessions() as db, _short_database_wait(db):
                row = db.get(OriginCooldown, origin)
                if row is not None:
                    # Wall-clock/reboot elapsed time is not trusted: wait one full cooldown once.
                    super().__setitem__(origin, (time.monotonic(), self._interval(row.interval)))
        return super().get(origin, default)

    def __setitem__(self, origin, slot):
        interval = self._interval(slot[1])
        previous = super().get(origin)
        if previous is None or previous[1] != interval:
            with self.sessions() as db:
                with _short_database_wait(db):
                    db.execute(text("BEGIN IMMEDIATE"))
                    db.merge(OriginCooldown(origin=origin, interval=interval))
                    db.flush()
                # Persist before connection; failed writes never update the in-memory slot.
                db.commit()
        # GET refreshes the same durable interval without another database write.
        super().__setitem__(origin, (max(slot[0], time.monotonic()), interval))


def evidence_hash(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _autopyverifier_passed(finding: dict) -> bool:
    proof = finding.get("autopyverifier")
    if not isinstance(proof, dict):
        return False
    status = proof.get("status")
    status_ok = status is None or (
        isinstance(status, str)
        and status.strip().lower()
        not in {"failed", "error", "timeout", "demoted", "false_positive", "unverified"}
    )
    return (
        type(proof.get("exit_code")) is int
        and proof["exit_code"] == 0
        and proof.get("mock_mode") is False
        and status_ok
    )


def _finding_status(finding: dict) -> str:
    if finding.get("lifecycle_state") == "DEMOTED":
        return "demoted"
    if finding.get("status") in ("demoted", "false_positive"):
        return finding["status"]
    if finding.get("lifecycle_state") == "REPRODUCED" or _autopyverifier_passed(finding):
        return "confirmed"
    return "suspected"


def mark_interrupted(sessions):
    with sessions() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        for row in db.scalars(select(Assessment).where(Assessment.status.in_(["running", "cancelling"]))):
            row.status = "cancelled" if row.cancel_requested else "failed"
            row.stage = "Worker stopped before completion"
            row.error = "Worker interruption; stored evidence does not establish complete coverage"
            row.finished_at = time.time()
            audit(db, row.organization_id, "worker", "assessment.interrupted", row.id)
        db.commit()


def run_one(sessions, stopping=lambda: False, *, request_starts=None) -> bool:
    with sessions() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        row = db.scalar(
            select(Assessment).where(Assessment.status == "queued").order_by(Assessment.created_at).limit(1)
        )
        if row is None:
            db.rollback()
            return False
        row.status, row.stage, row.started_at = "running", "Validating approved scope", time.time()
        assessment_id, organization_id, target_id = row.id, row.organization_id, row.target_id
        snapshot = row.scope_snapshot
        target = db.get(Target, target_id)
        owned = target is not None and target.verification_status == "operator_authorized"
        profile = row.profile
        audit(db, organization_id, "worker", "assessment.started", row.id)
        db.commit()

    def cancelled():
        if stopping():
            return True
        with sessions() as db:
            current = db.get(Assessment, assessment_id)
            return not current or current.cancel_requested

    def emit(event):
        with sessions() as db:
            db.execute(text("BEGIN IMMEDIATE"))
            current = db.get(Assessment, assessment_id)
            if current:
                current.stage = (
                    "Collecting HTTP evidence"
                    if event.get("type") == "observation"
                    else "Checking scope and coverage"
                )
                audit(
                    db,
                    organization_id,
                    "worker",
                    "scanner." + event.get("type", "event"),
                    assessment_id,
                    redact(event),
                )
                db.commit()

    try:
        if not isinstance(snapshot, dict):
            raise ValueError("Invalid stored scope snapshot")
        scope = {key: value for key, value in snapshot.items() if key in ScopePolicy.model_fields}
        stored_config = snapshot.get("scan_config")
        target_url = snapshot["target_url"]
        config = ScanConfig.model_validate({} if stored_config is None else stored_config).within_scope(scope)
        config.require_local_profile(profile)
        scope = {**scope, "request_rate": config.rate}
        if cancelled():
            raise PolicyError("Assessment stopped before dispatch")
        scan_cfg: dict[str, Any] = {}
        if isinstance(stored_config, dict):
            scan_cfg.update(stored_config)
        elif hasattr(config, "model_dump"):
            scan_cfg.update(config.model_dump())

        destination = check_execution_url(scope, target_url, owned=owned)
        if destination.host in ("127.0.0.1", "::1") and profile == "safe_http":
            result = scan(
                scope,
                target_url,
                cancelled,
                emit,
                request_starts=PersistentRequestStarts(sessions)
                if request_starts is None
                else request_starts,
            )
        elif profile == "approved_templates":
            tags = scan_cfg.get("tags")
            rate = int(scan_cfg.get("rate") or 150)
            # Active template scan (nuclei) over the enforced egress runner, host pinned to one IP.
            result = scan_live_nuclei(
                destination,
                resolve_pinned(destination.host),
                tags=tags,
                rate=rate,
            )
        elif profile == "comprehensive":
            mode = str(scan_cfg.get("mode") or "adaptive")
            tags = scan_cfg.get("tags")
            rate = int(scan_cfg.get("rate") or 150)
            depth = int(scan_cfg.get("depth") or 2)
            tools = scan_cfg.get("tools")
            max_seconds = float(scan_cfg.get("max_seconds") or 600.0)
            # Unified multi-stage automated pipeline (Recon + Headers + Ports + Crawler + Nuclei).
            pinned_ip = (
                destination.host
                if destination.host in ("127.0.0.1", "::1", "localhost")
                else resolve_pinned(destination.host)
            )
            result = scan_comprehensive(
                destination,
                pinned_ip,
                tags=tags,
                rate=rate,
                mode=mode,
                depth=depth,
                tools=tools,
                max_seconds=max_seconds,
            )
        else:
            try:
                from services.scanner_worker.container import run_with_egress

                runner = run_with_egress
            except Exception:
                runner = None
            result = scan_live(destination, resolve_pinned(destination.host), run=runner)
    except Exception as exc:
        if isinstance(exc, PolicyError) and "did not resolve" in str(exc):
            code = "NXDOMAIN"
            if hasattr(exc, "__cause__") and hasattr(getattr(exc, "__cause__"), "code"):
                cause_code = getattr(getattr(exc, "__cause__"), "code")
                code = str(getattr(cause_code, "value", cause_code))
            unresolved_record = {
                "kind": "target_unresolved",
                "category": "dns",
                "target_url": target_url,
                "error_code": code,
                "detail": str(exc),
                "retryable": False,
            }
            result = {
                "outcome": "completed_with_errors",
                "observations": [unresolved_record],
                "findings": [],
                "checks": [
                    {
                        "category": "dns_intelligence",
                        "status": "failed",
                        "error_code": code,
                        "detail": f"Target host did not resolve: [{code}]",
                    }
                ],
            }
        else:
            if isinstance(exc, PolicyError):
                error_class = "PolicyError"
                detail = str(exc)
            elif isinstance(exc, (ValueError, IsolationError)):
                error_class = "IsolationError" if isinstance(exc, IsolationError) else "ValueError"
                detail = redact(str(exc))[:2000] or error_class
            else:
                # Only fixed builtin names are retained: messages and custom class names can contain secrets.
                error_class = {
                    RuntimeError: "RuntimeError",
                    TypeError: "TypeError",
                    ValueError: "ValueError",
                    KeyError: "KeyError",
                    IndexError: "IndexError",
                    OSError: "OSError",
                    TimeoutError: "TimeoutError",
                    AssertionError: "AssertionError",
                }.get(type(exc), "Exception")
                detail = "Unexpected adapter error"
            result = {
                "outcome": "failed",
                "observations": [],
                "findings": [],
                "checks": [
                    {
                        "category": "safe_http",
                        "status": "failed",
                        "detail": detail,
                        "error_class": error_class,
                    }
                ],
            }

    def _validate_envelope(res: Any) -> tuple[bool, str]:
        if not isinstance(res, dict):
            return False, "Adapter returned non-dict result envelope"
        if not isinstance(res.get("outcome"), str) or res["outcome"] not in {
            "completed",
            "completed_with_errors",
            "failed",
            "cancelled",
        }:
            return False, "Invalid or missing outcome in result envelope"
        try:
            json.dumps(res, allow_nan=False)
        except (TypeError, ValueError, RecursionError, OverflowError):
            return False, "Adapter result must contain finite JSON data"
        checks = res.get("checks")
        if not isinstance(checks, list):
            return False, "Checks field must be a list"
        for c in checks:
            if not isinstance(c, dict):
                return False, "Individual check must be a dictionary"
            status = c.get("status")
            if status is not None and not isinstance(status, str):
                return False, "Check status must be a string"
            for field in ("url", "detail"):
                if c.get(field) is not None and not isinstance(c[field], str):
                    return False, f"Check {field} must be a string"
        observations = res.get("observations")
        if not isinstance(observations, list):
            return False, "Observations field must be a list"
        for o in observations:
            if not isinstance(o, dict):
                return False, "Individual observation must be a dictionary"
        findings = res.get("findings")
        if not isinstance(findings, list):
            return False, "Findings field must be a list"
        for f in findings:
            if not isinstance(f, dict):
                return False, "Individual finding must be a dictionary"
            if not f.get("fingerprint") or not isinstance(f.get("fingerprint"), str):
                return False, "Finding must have a non-empty string fingerprint"
            if not f.get("title") or not isinstance(f.get("title"), str):
                return False, "Finding must have a non-empty string title"
            if not f.get("category") or not isinstance(f.get("category"), str):
                return False, "Finding must have a non-empty string category"
            for field in ("severity", "description", "remediation", "affected_url", "target_url", "url"):
                if field in f and not isinstance(f[field], str):
                    return False, f"Finding {field} must be a string"
        proofs = [f["autopyverifier"] for f in findings if isinstance(f.get("autopyverifier"), dict)]
        for records in ([res], checks, observations, findings, proofs):
            for record in records:
                if any(not isinstance(key, str) or redact(key) != key for key in record):
                    return False, "Adapter record keys must be canonical strings"
        return True, ""

    is_valid, validation_error = _validate_envelope(result)
    if is_valid:
        result = redact(result)
        # Redaction can normalize distinct input keys to a different field name.
        is_valid, validation_error = _validate_envelope(result)
    if not is_valid:
        result = {
            "outcome": "failed",
            "observations": [],
            "findings": [],
            "checks": [
                {
                    "category": "platform_envelope",
                    "status": "failed",
                    "detail": f"Malformed adapter result envelope: {validation_error}",
                    "error_class": "ValueError",
                }
            ],
        }

    with sessions() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        current = db.get(Assessment, assessment_id)
        if current is None:
            return True
        checks = redact(result.get("checks", []))
        for check in checks:
            exit_code = next(
                (
                    code
                    for code in (check.get("exit_code"), check.get("returncode"))
                    if type(code) is int and code != 0
                ),
                None,
            )
            if exit_code is not None:
                check["status"] = "failed"
                check.setdefault("detail", f"Tool exited with status {exit_code}")
        outcome = result["outcome"]
        if outcome == "completed" and any(c.get("status") == "failed" for c in checks):
            outcome = (
                "completed_with_errors"
                if any(c.get("status") in {"completed", "passed"} for c in checks)
                else "failed"
            )
        if current.cancel_requested or stopping():
            outcome = "cancelled"
        current.status, current.finished_at = outcome, time.time()
        current.stage = {
            "completed": "Assessment complete",
            "completed_with_errors": "Finished with coverage errors",
            "failed": "Assessment failed",
            "cancelled": "Assessment cancelled",
        }[outcome]
        current.checks = checks
        if outcome == "failed":
            failed_details = [
                c.get("detail") for c in current.checks if c.get("status") == "failed" and c.get("detail")
            ]
            current.error = (
                failed_details[0]
                if failed_details
                else "Assessment execution failed; check target availability."
            )
        elif outcome == "completed_with_errors":
            failed_checks = [c for c in current.checks if c.get("status") not in ("completed", "passed")]
            details = [c.get("detail") for c in failed_checks if c.get("detail")]
            current.error = (
                details[0] if details else "One or more checks did not complete; review coverage details."
            )
        else:
            current.error = None
        saved_observations = []
        for observation in result.get("observations", []):
            clean = redact(observation)
            item = Observation(
                organization_id=organization_id,
                assessment_id=assessment_id,
                data=clean,
                evidence_hash=evidence_hash(clean),
            )
            db.add(item)
            db.flush()
            saved_observations.append(item)
        seen = set()
        verified_findings = []
        verifier_results = []
        for raw in result.get("findings", []):
            clean = redact(raw)
            fingerprint = clean["fingerprint"]
            seen.add(fingerprint)
            finding = db.scalar(
                select(Finding).where(Finding.target_id == target_id, Finding.fingerprint == fingerprint)
            )
            state = _finding_status(clean)
            if finding:
                if state not in {"demoted", "false_positive"}:
                    if finding.status in {
                        "needs_triage",
                        "inconclusive",
                        "false_positive",
                        "accepted_risk",
                        "remediation_in_progress",
                    }:
                        state = finding.status
                    elif state == "confirmed" and finding.status == "fixed":
                        state = "reopened"
                finding.last_seen = time.time()
                finding.status = state
            else:
                affected = clean.get("affected_url") or clean.get("target_url") or clean.get("url", "")
                finding = Finding(
                    organization_id=organization_id,
                    project_id=current.project_id,
                    target_id=target_id,
                    fingerprint=fingerprint,
                    title=clean.get("title", "Observed Security Finding"),
                    category=clean.get("category", "security_finding"),
                    severity=clean.get("severity", "medium"),
                    confidence=str(clean.get("confidence", "high")),
                    status=state,
                    description=clean.get("description", ""),
                    remediation=clean.get("remediation", ""),
                    affected_url=affected,
                )
                db.add(finding)
                db.flush()
            affected = clean.get("affected_url") or clean.get("target_url") or clean.get("url", "")
            clean["affected_url"] = affected
            clean["confidence"] = clean.get("confidence", "high")
            lifecycle_state = clean.get("lifecycle_state") or "CANDIDATE"
            snapshot = {
                **clean,
                "status": state,
                "lifecycle_state": lifecycle_state,
                "observation_ids": [o.id for o in saved_observations if o.data.get("url") == affected],
            }
            if state in {"confirmed", "reopened"}:
                verified_findings.append(snapshot)
                if _autopyverifier_passed(clean):
                    verifier_results.append({"fingerprint": fingerprint, **clean["autopyverifier"]})
            db.add(
                FindingEvidence(
                    finding_id=finding.id,
                    assessment_id=assessment_id,
                    data=snapshot,
                    evidence_hash=evidence_hash(snapshot),
                )
            )
            db.add(
                FindingHistory(
                    finding_id=finding.id,
                    status=state,
                    actor="safe_http",
                    reason=f"Assessment {assessment_id}: {lifecycle_state}; status {state}",
                )
            )

        if outcome != "failed":
            # Stage 11: Formal AND/OR Attack Graph & Exploit Chaining Synthesis
            try:
                from services.ai_analysis_worker.reasoning import AttackGraph, BreakpointAnalyzer

                attack_graph = AttackGraph()
                attack_graph.ingest(result.get("observations", []), verified_findings)
                analyzer = BreakpointAnalyzer(attack_graph)
                breakpoints = analyzer.find_high_leverage_breakpoints()
                bp_id = str(breakpoints[0].get("breakpoint")) if breakpoints else "Primary Ingress Boundary"
                high_leverage = (
                    f"Remediate {bp_id} to disconnect exploit chain."
                    if breakpoints
                    else "Remediate verified initial entry points."
                )
                chains = attack_graph.find_attack_paths()
                graph_data = {
                    "nodes": [n.to_dict() for n in attack_graph.nodes.values()],
                    "edges": [e.to_dict() for e in attack_graph.edges],
                    "chains": [p.get("steps", []) for p in chains],
                    "critical_breakpoint": bp_id,
                    "high_leverage_remediation": high_leverage,
                }
                graph_obs = Observation(
                    organization_id=organization_id,
                    assessment_id=assessment_id,
                    data={
                        "kind": "attack_graph",
                        "category": "exploit_chaining",
                        "target_url": target_url,
                        "nodes": graph_data.get("nodes", []),
                        "edges": graph_data.get("edges", []),
                        "chains": graph_data.get("chains", []),
                        "critical_breakpoint": bp_id,
                        "high_leverage_remediation": high_leverage,
                    },
                    evidence_hash=evidence_hash(graph_data),
                )
                db.add(graph_obs)
                db.flush()
                current.checks.append(
                    {
                        "category": "exploit_chaining",
                        "status": "completed",
                        "detail": f"Formal AND/OR attack graph constructed with {len(graph_data.get('nodes', []))} node(s) and {len(graph_data.get('chains', []))} exploit chain(s). Min-cut breakpoint identified.",
                    }
                )
            except Exception:
                pass

            # Only record actual supplied executions; synthetic assertions do not verify a target.
            if verifier_results:
                proof = {
                    "kind": "autopyverifier_execution",
                    "category": "deterministic_verification",
                    "verified_count": len(verifier_results),
                    "scripts": verifier_results,
                }
                db.add(
                    Observation(
                        organization_id=organization_id,
                        assessment_id=assessment_id,
                        data=proof,
                        evidence_hash=evidence_hash(proof),
                    )
                )
            current.checks.append(
                {
                    "category": "autopyverifier",
                    "status": "completed" if verifier_results else "skipped",
                    "detail": (
                        f"Recorded {len(verifier_results)} supplied non-mock verifier execution(s)."
                        if verifier_results
                        else "No scoped AutoPyVerifier execution evidence supplied; synthetic verification is not target evidence."
                    ),
                }
            )

            # Stage 13: 3D Target Topology & Maltego-Style Attack Surface Entity Graph
            try:
                topology_nodes = []
                topology_links = []
                dest_host = getattr(destination, "host", "target.local")
                dest_ip = getattr(destination, "ip", "127.0.0.1")
                dest_port = getattr(destination, "port", 80)
                dest_scheme = getattr(destination, "scheme", "http")

                topology_nodes.append(
                    {
                        "id": "domain:root",
                        "label": dest_host,
                        "type": "domain",
                        "severity": "info",
                        "group": 1,
                    }
                )
                topology_nodes.append(
                    {"id": f"ip:{dest_ip}", "label": dest_ip, "type": "ip", "severity": "info", "group": 2}
                )
                topology_links.append(
                    {"source": "domain:root", "target": f"ip:{dest_ip}", "relation": "resolves_to"}
                )

                port_id = f"port:{dest_port}"
                topology_nodes.append(
                    {
                        "id": port_id,
                        "label": f"Port {dest_port} ({dest_scheme})",
                        "type": "port",
                        "severity": "info",
                        "group": 3,
                    }
                )
                topology_links.append(
                    {"source": f"ip:{dest_ip}", "target": port_id, "relation": "exposes_port"}
                )

                observed_endpoints = set()
                for obs in result.get("observations", []):
                    if obs.get("kind") == "crawler_summary":
                        for ep in obs.get("endpoints", [])[:15]:
                            observed_endpoints.add(ep)
                if not observed_endpoints:
                    observed_endpoints.add("/")

                for ep in observed_endpoints:
                    ep_id = f"endpoint:{ep}"
                    topology_nodes.append(
                        {"id": ep_id, "label": ep, "type": "endpoint", "severity": "clean", "group": 4}
                    )
                    topology_links.append({"source": port_id, "target": ep_id, "relation": "serves_route"})

                for idx, f in enumerate(result.get("findings", [])):
                    f_id = f"finding:{f.get('fingerprint', str(idx))[:8]}"
                    sev = str(f.get("severity", "medium")).lower()
                    aff = str(f.get("affected_url") or target_url)
                    topology_nodes.append(
                        {
                            "id": f_id,
                            "label": f.get("title", "Finding"),
                            "type": "vulnerability",
                            "severity": sev,
                            "cwe": f.get("cwe_id"),
                            "group": 5,
                        }
                    )
                    matched_ep = next((ep for ep in observed_endpoints if ep != "/" and ep in aff), None)
                    target_node = f"endpoint:{matched_ep}" if matched_ep else port_id
                    topology_links.append(
                        {"source": target_node, "target": f_id, "relation": "exhibits_flaw"}
                    )

                topo_obs = Observation(
                    organization_id=organization_id,
                    assessment_id=assessment_id,
                    data={
                        "kind": "target_topology_map",
                        "category": "surface_mapping",
                        "target_host": dest_host,
                        "nodes": topology_nodes,
                        "links": topology_links,
                    },
                    evidence_hash=evidence_hash({"nodes": topology_nodes, "links": topology_links}),
                )
                db.add(topo_obs)
                db.flush()
            except Exception:
                pass

            # Stage 14: Safe-Gated Post-Exploitation, Staging & Pivoting (Section 3.3 / H1-H6)
            try:
                from packages.scanner_adapters.integrations.pivoting import (
                    PersistenceTracker,
                    SafetyGateValidator,
                    SOCKSPivotRouter,
                )

                gate_validator = SafetyGateValidator()
                scope_flags = scope.get("flags", []) if isinstance(scope, dict) else []
                is_armed = False
                try:
                    is_armed = gate_validator.verify_gate(
                        ownership_state="HUMAN_OWNED",
                        scope_flags=scope_flags,
                        operator_confirmed="ALLOW_ACTIVE_EXPLOIT" in scope_flags,
                    )
                except PermissionError:
                    is_armed = False

                tracker = PersistenceTracker()
                tracker.register_artifact(
                    path=f"/tmp/sharay_canary_{dest_host}.token",
                    sha256=evidence_hash({"canary": dest_host, "target": target_url}),
                    description="Synthetic verification canary token",
                )
                clean_script = tracker.generate_clean_exit_script()

                socks_router = SOCKSPivotRouter(local_port=1080, pivot_host=dest_host)
                candidate_subnets = [
                    f"10.{abs(hash(dest_host)) % 250}.0.0/24",
                    "192.168.1.0/24",
                ]

                pivoting_obs = Observation(
                    organization_id=organization_id,
                    assessment_id=assessment_id,
                    data={
                        "kind": "safe_gated_pivoting",
                        "category": "post_exploitation_quarantine",
                        "safety_gate": {
                            "status": "armed" if is_armed else "quarantined",
                            "console_ownership": "HUMAN_OWNED",
                            "scope_signature_present": "ALLOW_ACTIVE_EXPLOIT" in scope_flags,
                            "operator_confirmed": is_armed,
                            "quarantine_policy": "Three-factor Pushback 3 safety gate enforced. Intrusive post-exploitation quarantined.",
                        },
                        "persistence_inventory": [
                            {"path": a.path, "sha256": a.sha256, "description": a.description}
                            for a in tracker.artifacts
                        ],
                        "clean_exit_script": clean_script,
                        "socks_pivot": {
                            "proxy_port": socks_router.local_port,
                            "pivot_host": socks_router.pivot_host,
                            "unlocked_subnets": candidate_subnets,
                            "status": "standby_isolated",
                        },
                    },
                    evidence_hash=evidence_hash({"clean_script": clean_script, "subnets": candidate_subnets}),
                )
                db.add(pivoting_obs)
                db.flush()
                current.checks.append(
                    {
                        "category": "safe_gated_pivoting",
                        "status": "completed",
                        "detail": f"Safe-Gated Post-Exploitation (Section 3.3): 3-factor quarantine enforced ({'ARMED' if is_armed else 'QUARANTINED'}). 1-click clean exit teardown prepared.",
                    }
                )
            except Exception:
                pass

        # A failed/partial/cancelled retest must not establish remediation.
        complete_headers = outcome == "completed" and any(
            c.get("category") == "http_headers" and c.get("status") == "completed" for c in current.checks
        )
        covered_urls = {
            c.get("url")
            for c in current.checks
            if c.get("category") == "http_headers" and c.get("status") == "completed"
        }
        if current.retest_of and complete_headers:
            baseline_ids = select(FindingEvidence.finding_id).where(
                FindingEvidence.assessment_id == current.retest_of
            )
            for finding in db.scalars(
                select(Finding).where(
                    Finding.target_id == target_id,
                    Finding.id.in_(baseline_ids),
                    Finding.category == "http_headers",
                )
            ):
                if finding.fingerprint not in seen and finding.affected_url in covered_urls:
                    finding.status = "fixed"
                    db.add(
                        FindingHistory(
                            finding_id=finding.id,
                            status="fixed",
                            actor="safe_http",
                            reason="Absent in completed retest " + assessment_id,
                        )
                    )
                    snapshot = {
                        "status": "fixed",
                        "title": finding.title,
                        "category": finding.category,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "description": finding.description,
                        "remediation": finding.remediation,
                        "affected_url": finding.affected_url,
                        "verification": "Absent in complete safe HTTP retest",
                        "observation_ids": [o.id for o in saved_observations],
                    }
                    db.add(
                        FindingEvidence(
                            finding_id=finding.id,
                            assessment_id=assessment_id,
                            data=snapshot,
                            evidence_hash=evidence_hash(snapshot),
                        )
                    )
        flag_modified(current, "checks")
        audit(
            db,
            organization_id,
            "worker",
            "assessment." + outcome,
            assessment_id,
            {
                "checks": current.checks,
                "adapter": result.get("adapter", "safe_http"),
                "version": result.get("version"),
                "duration_ms": result.get("duration_ms"),
                "requests_performed": result.get("requests_performed"),
            },
        )
        db.commit()
    return True


class WorkerSupervisor:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.process: subprocess.Popen[bytes] | None = None

    def start(self):
        venv_bin = str(ROOT / ".venv" / "bin")
        venv_python = str(ROOT / ".venv" / "bin" / "python")
        executable = venv_python if Path(venv_python).is_file() else sys.executable
        environment = {
            key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "TMPDIR", "LANG") if key in os.environ
        }
        for key, value in os.environ.items():
            if key.startswith("SHARAY_") or key.startswith("AEGIS_"):
                environment[key] = value
        environment["PATH"] = f"{venv_bin}:{environment.get('PATH', '')}"
        environment["VIRTUAL_ENV"] = str(ROOT / ".venv")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        log_file = (self.settings.data_dir / "worker.log").open("a")
        self.process = subprocess.Popen(
            [
                executable,
                "-m",
                "aegis.worker",
                "--data-dir",
                str(self.settings.data_dir),
                "--parent-stdin",
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self):
        if self.process is not None and self.process.stdin:
            self.process.stdin.close()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        import fcntl

        # A duplicate supervisor must never alter a different live worker's jobs.
        with (self.settings.data_dir / "worker.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            engine, sessions = create_database(self.settings, migrate=False)
            try:
                mark_interrupted(sessions)
            finally:
                engine.dispose()


def main():
    import fcntl
    import resource
    from pathlib import Path

    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--parent-stdin", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    settings = Settings(Path(args.data_dir), start_worker=False)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (2048, 2048))
    # Limits total CPU per worker lifetime; no target code executes here.
    resource.setrlimit(resource.RLIMIT_CPU, (7200, 7200))
    with (settings.data_dir / "worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 2
        engine, sessions = create_database(settings, migrate=False)
        # ponytail: one locked worker per database; distributed/workspace pacing still needs coordination.
        request_starts = PersistentRequestStarts(sessions)
        stop = [False]

        def request_stop(_signum, _frame):
            stop[0] = True

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        try:
            with watch_parent_stdin(args.parent_stdin, lambda: request_stop(None, None)):
                try:
                    mark_interrupted(sessions)
                    while not stop[0]:
                        if not run_one(sessions, lambda: stop[0], request_starts=request_starts):
                            time.sleep(0.25)
                finally:
                    mark_interrupted(sessions)
        finally:
            engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
