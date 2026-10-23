"""SHARAY CLI commands: scan, probe, status, and findings inspection."""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text

from aegis.config import Settings
from aegis.database import create_database
from aegis.models import Assessment, Finding, FindingEvidence, Observation, Project, Target, User
from aegis.worker import _finding_status, evidence_hash
from packages.reporting import redact
from packages.scanner_adapters import preflight, scan_comprehensive, scan_live, scan_live_nuclei
from packages.scanner_adapters.workspace import InteractiveWorkspace
from packages.security_policies import (
    Destination,
    PolicyError,
    ScopePolicy,
    check_execution_url,
    normalize_url,
    resolve_pinned,
)


def _format_table(headers: list[str], rows: list[list[str]]) -> str:
    """Format tabular data cleanly for standard terminal output."""
    if not rows:
        return "No entries found."
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    separator = "  ".join("-" * w for w in widths)
    lines = [fmt.format(*headers), separator]
    for row in rows:
        lines.append(fmt.format(*[str(c) for c in row]))
    return "\n".join(lines)


def cmd_status(settings: Settings, as_json: bool = False) -> int:
    """Report SHARAY system health, container runtime, scanner readiness, and database metrics."""
    engine, sessions = create_database(settings)
    metrics: dict[str, Any] = {
        "preflight": preflight(),
        "database": "accessible",
        "data_dir": str(settings.data_dir),
        "port": settings.port,
        "counts": {"projects": 0, "targets": 0, "assessments": 0, "findings": 0},
    }
    try:
        with sessions() as db:
            metrics["counts"]["projects"] = db.scalar(select(func.count(Project.id))) or 0
            metrics["counts"]["targets"] = db.scalar(select(func.count(Target.id))) or 0
            metrics["counts"]["assessments"] = db.scalar(select(func.count(Assessment.id))) or 0
            metrics["counts"]["findings"] = db.scalar(select(func.count(Finding.id))) or 0

            # Findings by severity
            sev_query = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
            metrics["findings_by_severity"] = dict(db.execute(sev_query).all())
    except Exception as exc:
        metrics["database"] = f"error: {exc}"
    finally:
        engine.dispose()

    if as_json:
        print(json.dumps(metrics, indent=2))
        return 0

    print("================================================================================")
    print("                    SHARAY DEFENSIVE ASSESSMENT PLATFORM                       ")
    print("================================================================================")
    print(f"Data directory : {metrics['data_dir']}")
    print(f"Server Port    : {metrics['port']}")
    print(f"Database       : {metrics['database']}")
    print(
        f"Inventory      : {metrics['counts']['projects']} Projects | {metrics['counts']['targets']} Targets | {metrics['counts']['assessments']} Assessments | {metrics['counts']['findings']} Findings"
    )

    tpl_path = Path("/Users/shardul/nuclei-templates")
    tpl_count = len(list(tpl_path.glob("**/*.yaml"))) if tpl_path.is_dir() else 0
    print(
        f"Nuclei Templates: {tpl_count} official templates loaded at {tpl_path}"
        if tpl_count
        else "Nuclei Templates: fallback container volume"
    )

    if metrics.get("findings_by_severity"):
        sevs = ", ".join(f"{k.upper()}: {v}" for k, v in sorted(metrics["findings_by_severity"].items()))
        print(f"Active Findings: {sevs}")

    print("\n[ACTIVE SCANNER ENGINES & INTEGRATIONS]")
    from aegis.api import active_integrations

    integrations = active_integrations()
    headers = ["Engine / Tool", "Status", "Version", "Scope & Capabilities"]
    rows = []
    for tool in integrations:
        name = tool.get("name") or tool.get("id", "unknown")
        status = tool.get("status", "unknown")
        ver = tool.get("version", "n/a")
        scope = tool.get("scope", "")
        rows.append([str(name)[:30], str(status).upper(), str(ver)[:10], str(scope)[:35]])
    print(_format_table(headers, rows))
    print("================================================================================")
    return 0


def cmd_probe(
    target_url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: float = 10.0,
    as_json: bool = False,
    authorized: bool = False,
) -> int:
    """Execute an interactive operator takeover probe against a target URL."""
    try:
        norm_url = normalize_url(target_url)
    except PolicyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    from urllib.parse import urlsplit

    parsed = urlsplit(norm_url)
    dest_host = parsed.hostname or ""
    dest_origin = f"{parsed.scheme}://{parsed.netloc}"

    # Parity with execution: a loopback lab needs its CIDR approved; a live target needs asserted
    # ownership (--authorized). The workspace applies check_execution_url, so a private/internal
    # host is refused here exactly as the scan worker refuses it (F01/E07).
    loopback_cidr = {"127.0.0.1": "127.0.0.1/32", "::1": "::1/128"}.get(dest_host)
    scope = ScopePolicy.model_validate(
        {
            "hosts": [dest_host],
            "allowed_origins": [dest_origin],
            "allowed_paths": ["/"],
            "allowed_cidrs": [loopback_cidr] if loopback_cidr else [],
            "categories": ["http_headers"],
            "starts_at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        }
    )

    workspace = InteractiveWorkspace(default_timeout=timeout)
    print(f"[*] Sending operator probe: {method} {norm_url} (timeout={timeout}s)...")
    try:
        res = workspace.execute_probe(
            scope=scope,
            target_url=norm_url,
            method=method,
            headers=headers or {},
            body=body,
            owned=authorized,
        )
    except Exception as exc:
        print(f"[!] Probe failed: {exc}", file=sys.stderr)
        return 2

    if as_json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    print(f"[+] Status Code : {res.status_code}")
    print(f"[+] Latency     : {res.duration_ms} ms")
    print(f"[+] Fingerprint : {res.fingerprint}")
    print("\n--- Response Headers ---")
    for k, v in res.response_headers.items():
        print(f"  {k}: {v}")
    if res.response_body:
        print("\n--- Response Body Snippet ---")
        print(res.response_body[:500])
        if len(res.response_body) > 500:
            print(f"... [truncated, total {len(res.response_body)} bytes]")
    return 0


def cmd_scan(
    settings: Settings,
    target_url: str,
    profile: str = "comprehensive",
    severities: str = "medium,high,critical",
    project_name: str = "CLI Assessments",
    mode: str = "adaptive",
    tags: str | None = None,
    rate: int = 150,
    depth: int = 2,
    as_json: bool = False,
    authorized: bool = False,
) -> int:
    """Run an automated assessment pipeline directly from the command line."""
    try:
        norm_url = normalize_url(target_url)
    except PolicyError as exc:
        print(f"Scope Error: {exc}", file=sys.stderr)
        return 1

    from urllib.parse import urlsplit

    parsed = urlsplit(norm_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    dest = Destination(norm_url, parsed.scheme, host, port, parsed.path, origin, host)
    try:
        pinned_ip = resolve_pinned(dest.host)
    except PolicyError as exc:
        print(f"DNS/SSRF Error: {exc}", file=sys.stderr)
        return 1

    loopback_cidr = {"127.0.0.1": "127.0.0.1/32", "::1": "::1/128"}.get(dest.host)
    scope_dict = {
        "hosts": [dest.host],
        "allowed_origins": [dest.origin],
        "allowed_paths": ["/"],
        "allowed_cidrs": [loopback_cidr] if loopback_cidr else [],
        "categories": ["http_headers"],
        "starts_at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=23)).isoformat(),
    }

    engine, sessions = create_database(settings)
    try:
        # Authorization MUST precede offensive execution (F04): record the owner, the target
        # authorization and the assessment (binding the exact scope version) and validate the
        # destination with the execution contract BEFORE any probe is sent. A live target is scanned
        # only when the operator asserts verified ownership (--authorized); a loopback target is a
        # verified lab. No owner is auto-provisioned with a baked-in credential.
        with sessions() as db:
            db.execute(text("BEGIN IMMEDIATE"))
            owner = db.scalar(select(User).where(User.role == "owner")) or db.scalar(select(User))
            if not owner:
                print(
                    "Error: no owner account exists. Create one through onboarding before scanning.",
                    file=sys.stderr,
                )
                return 1
            org_id, owner_id = owner.organization_id, owner.id
            proj = db.scalar(
                select(Project).where(Project.name == project_name, Project.organization_id == org_id)
            )
            if not proj:
                proj = Project(
                    organization_id=org_id,
                    owner_id=owner_id,
                    name=project_name,
                    description="Automated CLI assessment runs",
                )
                db.add(proj)
                db.flush()

            tgt = db.scalar(select(Target).where(Target.project_id == proj.id, Target.url == norm_url))
            if tgt is None:
                if loopback_cidr:
                    v_status, authorized_by, approved_at = "verified_lab", None, None
                elif authorized:
                    v_status, authorized_by, approved_at = "operator_authorized", owner_id, time.time()
                else:
                    print(
                        "Error: a live (non-loopback) target requires --authorized to assert verified "
                        "ownership before scanning.",
                        file=sys.stderr,
                    )
                    return 1
                tgt = Target(
                    organization_id=org_id,
                    project_id=proj.id,
                    url=norm_url,
                    scope=ScopePolicy.model_validate(scope_dict).model_dump(mode="json"),
                    verification_status=v_status,
                    authorized_by=authorized_by,
                    approved_at=approved_at,
                )
                db.add(tgt)
                db.flush()

            owned = tgt.verification_status == "operator_authorized"
            try:
                check_execution_url(tgt.scope, norm_url, owned=owned)
            except PolicyError as exc:
                print(f"Authorization Error: {exc}", file=sys.stderr)
                return 1

            asmt = Assessment(
                organization_id=org_id,
                project_id=proj.id,
                target_id=tgt.id,
                created_by=owner_id,
                idempotency_key=f"cli-{int(time.time() * 1000)}",
                scope_version=tgt.scope_version,
                scope_snapshot={
                    **tgt.scope,
                    "target_url": norm_url,
                    "authorized_by": owner.username,
                    "approved_at": time.time(),
                },
                profile=profile,
                status="running",
                stage="authorized; scanning",
                created_at=time.time(),
                started_at=time.time(),
            )
            db.add(asmt)
            db.flush()
            assessment_id, target_id, project_id = asmt.id, tgt.id, proj.id
            db.commit()

        print(f"[*] Target       : {norm_url}")
        print(f"[*] Resolved IP  : {pinned_ip} (DNS-pinned & firewall-locked)")
        print(f"[*] Profile      : {profile.upper()}")
        print(f"[*] Mode         : {mode.upper()} (Context-aware adaptive synthesis)")
        print(f"[*] Severities   : {severities}")
        if tags:
            print(f"[*] Custom Tags  : {tags}")
        print(f"[*] Assessment   : {assessment_id} (authorization recorded before execution)")
        print("[*] Launching multi-stage automated assessment pipeline...\n")

        started_mono = time.monotonic()
        if profile == "safe_http":
            print("[+] Stage: Executing HTTP security header & cookie inspection...")
            res = scan_live(dest, pinned_ip)
        elif profile == "approved_templates":
            print("[+] Stage: Executing Nuclei active vulnerability scanning...")
            res = scan_live_nuclei(dest, pinned_ip, severities=severities, tags=tags, rate=rate)
        else:
            print("[1/6] Passive Recon & TLS Inspection...")
            print("[2/6] Target Port & Service Verification...")
            print("[3/6] HTTP Security Headers & Cookie Hardening...")
            print("[4/6] In-Scope Web Crawler & Endpoint Discovery...")
            print("[5/6] Target Intelligence & Adaptive Strategy Synthesis...")
            print("[6/6] Active Behavioral Differential Testing & Nuclei Scanning...")
            all_tools = ["nmap", "crawler", "sensitive", "diff", "nuclei", "zap", "metasploit"]
            res = scan_comprehensive(
                dest,
                pinned_ip,
                severities=severities,
                tags=tags,
                rate=rate,
                mode=mode,
                depth=depth,
                tools=all_tools,
            )

        elapsed = round(time.monotonic() - started_mono, 2)
        print(f"\n[+] Assessment completed in {elapsed}s (Outcome: {res.get('outcome', 'unknown')})")

        # Persist results into the pre-created assessment. A persistence failure is reported and
        # fails the command -- it is never swallowed into a success-looking note. Finding status is
        # derived exactly as the worker derives it (REPRODUCED/verified -> confirmed), never a flat
        # "suspected".
        try:
            with sessions() as db:
                db.execute(text("BEGIN IMMEDIATE"))
                record = db.get(Assessment, assessment_id)
                if record is None:
                    raise RuntimeError(f"assessment {assessment_id} vanished before persistence")
                record.status = res.get("outcome", "completed")
                record.stage = "Assessment complete"
                record.checks = redact(res.get("checks", []))
                record.finished_at = time.time()
                for obs in res.get("observations", []):
                    clean_obs = redact(obs)
                    db.add(
                        Observation(
                            organization_id=org_id,
                            assessment_id=assessment_id,
                            data=clean_obs,
                            evidence_hash=evidence_hash(clean_obs),
                        )
                    )
                for f in res.get("findings", []):
                    clean_f = redact(f)
                    fp = clean_f["fingerprint"]
                    state = _finding_status(clean_f)
                    existing = db.scalar(
                        select(Finding).where(Finding.target_id == target_id, Finding.fingerprint == fp)
                    )
                    if existing:
                        if state not in {"demoted", "false_positive"}:
                            if existing.status in {
                                "needs_triage",
                                "inconclusive",
                                "false_positive",
                                "accepted_risk",
                                "remediation_in_progress",
                            }:
                                state = existing.status
                            elif state == "confirmed" and existing.status == "fixed":
                                state = "reopened"
                        existing.last_seen = time.time()
                        existing.status = state
                        finding_id = existing.id
                    else:
                        new_finding = Finding(
                            organization_id=org_id,
                            project_id=project_id,
                            target_id=target_id,
                            fingerprint=fp,
                            title=clean_f["title"],
                            category=clean_f.get("category", "template_match"),
                            severity=clean_f.get("severity", "medium"),
                            confidence=str(clean_f.get("confidence", "medium")),
                            status=state,
                            description=clean_f.get("description", ""),
                            remediation=clean_f.get("remediation", ""),
                            affected_url=clean_f.get("affected_url", norm_url),
                            first_seen=time.time(),
                            last_seen=time.time(),
                        )
                        db.add(new_finding)
                        db.flush()
                        finding_id = new_finding.id

                    db.add(
                        FindingEvidence(
                            finding_id=finding_id,
                            assessment_id=assessment_id,
                            data=clean_f,
                            evidence_hash=evidence_hash(clean_f),
                        )
                    )
                db.commit()
                print(
                    f"[+] Assessment persisted to database under Project '{project_name}' (ID: {assessment_id})"
                )
        except Exception as exc:
            print(f"[!] Assessment ran but results could not be persisted: {exc}", file=sys.stderr)
            return 2
    finally:
        engine.dispose()

    if as_json:
        print(json.dumps(res, indent=2))
        return 0

    # Print Open Ports table
    port_observations = [o for o in res.get("observations", []) if o.get("kind") == "network_service"]
    if port_observations:
        print("\n================================================================================")
        print(
            f"                       OPEN NETWORK PORTS ({len(port_observations)})                         "
        )
        print("================================================================================")
        p_headers = ["Port", "Protocol", "State", "Service", "Banner", "Latency"]
        p_rows = []
        for p in port_observations:
            p_rows.append(
                [
                    str(p.get("port", "")),
                    p.get("protocol", "tcp").upper(),
                    p.get("state", "open").upper(),
                    p.get("service", "unknown"),
                    p.get("banner", "N/A")[:30],
                    f"{p.get('latency_ms', 'N/A')}ms",
                ]
            )
        print(_format_table(p_headers, p_rows))

    # Print DNS summary if present
    dns_observations = [o for o in res.get("observations", []) if o.get("kind") == "dns_records"]
    if dns_observations:
        d = dns_observations[0]
        print(f"\n[*] DNS IPv4 : {', '.join(d.get('ipv4_addresses', [])) or 'None'}")
        print(f"[*] DNS IPv6 : {', '.join(d.get('ipv6_addresses', [])) or 'None'}")
        if d.get("cdn_waf_indicators"):
            print(f"[*] Edge/WAF : {', '.join(d.get('cdn_waf_indicators'))}")

    findings = res.get("findings", [])
    print("\n================================================================================")
    print(f"                         FINDINGS DETECTED ({len(findings)})                          ")
    print("================================================================================")
    if findings:
        headers = ["Severity", "Category", "Title", "Affected Target"]
        rows = []
        for f in findings:
            rows.append(
                [
                    f.get("severity", "unknown").upper(),
                    f.get("category", "general")[:20],
                    f.get("title", "")[:40],
                    f.get("affected_url", "")[:30],
                ]
            )
        print(_format_table(headers, rows))
    else:
        print("No security vulnerabilities or policy defects identified.")

    print("\n================================================================================")
    print("                          EXECUTION CHECKS & EVIDENCE                           ")
    print("================================================================================")
    checks = res.get("checks", [])
    if checks:
        for chk in checks:
            status_icon = (
                "[OK]" if chk.get("status") == "completed" else f"[{chk.get('status', 'FAIL').upper()}]"
            )
            print(f"{status_icon:<6} {chk.get('category', ''):<20} : {chk.get('detail', '')}")
    print("================================================================================")
    return 0


def cmd_findings(settings: Settings, severity: str | None = None, as_json: bool = False) -> int:
    """List recorded findings from the SHARAY database."""
    engine, sessions = create_database(settings)
    try:
        with sessions() as db:
            query = select(Finding).order_by(Finding.last_seen.desc())
            if severity:
                sevs = [s.strip().lower() for s in severity.split(",")]
                query = query.where(Finding.severity.in_(sevs))
            findings = db.scalars(query).all()

            if as_json:
                data = [
                    {
                        "fingerprint": f.fingerprint,
                        "title": f.title,
                        "severity": f.severity,
                        "category": f.category,
                        "status": f.status,
                        "affected_url": f.affected_url,
                        "last_seen": f.last_seen,
                    }
                    for f in findings
                ]
                print(json.dumps(data, indent=2))
                return 0

            print("================================================================================")
            print(f"                     RECORDED FINDINGS ({len(findings)})                        ")
            print("================================================================================")
            if findings:
                headers = ["Severity", "Status", "Category", "Title", "Affected URL"]
                rows = [
                    [
                        f.severity.upper(),
                        f.status.upper(),
                        f.category[:18],
                        f.title[:35],
                        f.affected_url[:30],
                    ]
                    for f in findings
                ]
                print(_format_table(headers, rows))
            else:
                print("No recorded findings matching the criteria.")
            print("================================================================================")
            return 0
    finally:
        engine.dispose()
