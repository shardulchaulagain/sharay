"""Integration test: L3/L6 parser output -> aegis.models.Finding via the normalize bridge."""

from __future__ import annotations

import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from aegis.models import Base, Finding, Organization, Project, Target, User
from packages.scanner_adapters.integrations import gitleaks, nuclei, semgrep, zap
from packages.scanner_adapters.integrations.metasploit import parse_metasploit_auxiliary_report
from packages.scanner_adapters.integrations.normalize import normalize_parsed_finding
from services.source_analysis_worker.containers import scan_dockerfile_content, scan_k8s_manifest_dict


def test_all_five_parsers_normalize_and_persist_into_finding_table() -> None:
    gitleaks_out = gitleaks.parse(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "File": "src/config.py",
                    "StartLine": 12,
                    "Fingerprint": "src/config.py:aws-access-token:12",
                }
            ]
        ).encode()
    )
    semgrep_out = semgrep.parse(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.sqlalchemy.sqli",
                        "path": "app/db.py",
                        "start": {"line": 44},
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                        },
                    }
                ],
                "errors": [],
                "paths": {"scanned": ["app/db.py"], "skipped": []},
            }
        ).encode()
    )
    nuclei_out = nuclei.parse(
        json.dumps(
            {
                "template-id": "ssrf",
                "info": {"name": "Webhook SSRF Detection", "severity": "high"},
                "matched-at": "https://127.0.0.1:8443/webhook",
                "matcher-name": "loopback-hit",
            }
        ).encode()
    )
    zap_out = zap.parse(
        json.dumps(
            {
                "site": [
                    {
                        "alerts": [
                            {
                                "pluginid": "40012",
                                "alertRef": "40012-1",
                                "name": "Cross Site Scripting (Reflected)",
                                "riskcode": "3",
                                "confidence": "2",
                                "cweid": "79",
                                "wascid": "8",
                                "solution": "Encode user-supplied output.",
                                "instances": [
                                    {
                                        "uri": "https://127.0.0.1:8443/search",
                                        "method": "GET",
                                        "param": "q",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ).encode()
    )
    msf_out = parse_metasploit_auxiliary_report(
        json.dumps(
            {
                "results": [
                    {
                        "module": "auxiliary/scanner/http/title",
                        "target_url": "https://127.0.0.1:8443/admin",
                        "outcome": "confirmed_reproducible",
                        "session_established": False,
                        "summary": "Admin panel unauthenticated access verified",
                    }
                ]
            }
        ).encode()
    )

    normalized = [
        normalize_parsed_finding("gitleaks", gitleaks_out["findings"][0]),
        normalize_parsed_finding("semgrep", semgrep_out["findings"][0]),
        normalize_parsed_finding("nuclei", nuclei_out["findings"][0]),
        normalize_parsed_finding("zap", zap_out["findings"][0]),
        normalize_parsed_finding("metasploit", msf_out["findings"][0]),
    ]

    # Verify CWE/category correlation attached validation techniques for SQLi, SSRF, and XSS
    assert normalized[1]["category"] == "sql_injection"
    assert len(normalized[1]["recommended_validations"]) == 2
    assert normalized[2]["category"] == "ssrf"
    assert len(normalized[2]["recommended_validations"]) == 1
    assert normalized[3]["category"] == "xss"
    assert len(normalized[3]["recommended_validations"]) == 1
    # Parser output must enter as 'suspected' even for a confirmed_reproducible outcome:
    # only the verifier may elevate to 'confirmed' after provenance checks.
    assert normalized[4]["status"] == "suspected"

    # Persist all 5 normalized findings directly into SQLite `Finding` table
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        org = Organization(id="org-1", name="Lab")
        user = User(
            id="u-1",
            organization_id="org-1",
            username="shardul",
            password_hash="hash",
            role="owner",
        )
        proj = Project(id="p-1", organization_id="org-1", owner_id="u-1", name="Proj")
        tgt = Target(
            id="t-1",
            organization_id="org-1",
            project_id="p-1",
            url="https://127.0.0.1:8443",
            scope={},
        )
        db.add_all([org, user, proj, tgt])
        db.flush()

        for item in normalized:
            row_data = {k: v for k, v in item.items() if k != "recommended_validations"}
            db.add(
                Finding(
                    organization_id="org-1",
                    project_id="p-1",
                    target_id="t-1",
                    **row_data,
                )
            )
        db.commit()

        stored = list(db.scalars(select(Finding)))
        assert len(stored) == 5


def test_container_iac_findings_normalize_and_persist_into_finding_table() -> None:
    raw = scan_dockerfile_content("FROM python:latest\nRUN echo hi\n", "svc/Dockerfile")
    normalized = [normalize_parsed_finding("iac", f) for f in raw]
    assert normalized, "the insecure Dockerfile should produce findings"
    for item in normalized:
        assert item["status"] == "suspected"  # config analysis never self-confirms
        assert item["fingerprint"].startswith("iac:")
        assert item["affected_url"].startswith("file://svc/Dockerfile")
        assert item["confidence"] in {"low", "medium", "high"}  # not the raw 'confirmed'

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                Organization(id="org-1", name="Lab"),
                User(id="u-1", organization_id="org-1", username="s", password_hash="h", role="owner"),
                Project(id="p-1", organization_id="org-1", owner_id="u-1", name="Proj"),
                Target(
                    id="t-1",
                    organization_id="org-1",
                    project_id="p-1",
                    url="https://127.0.0.1:8443",
                    scope={},
                ),
            ]
        )
        db.flush()
        for item in normalized:
            row = {k: v for k, v in item.items() if k != "recommended_validations"}
            db.add(Finding(organization_id="org-1", project_id="p-1", target_id="t-1", **row))
        db.commit()
        assert len(list(db.scalars(select(Finding)))) == len(normalized)


def test_two_k8s_containers_hitting_one_rule_get_distinct_fingerprints() -> None:
    # K8s findings carry no line number; the container name (in the title) must keep fingerprints
    # unique so sibling containers do not collide on Finding's (target_id, fingerprint) constraint.
    doc = {
        "kind": "Pod",
        "metadata": {"name": "p"},
        "spec": {"containers": [{"name": "app"}, {"name": "sidecar"}]},
    }
    writable = [
        f for f in scan_k8s_manifest_dict(doc, "m.yaml") if f["rule_id"] == "K8S_WRITABLE_ROOT_FILESYSTEM"
    ]
    assert len(writable) == 2
    fingerprints = {normalize_parsed_finding("iac", f)["fingerprint"] for f in writable}
    assert len(fingerprints) == 2


def test_osv_and_secrets_sources_normalize_into_finding_rows() -> None:
    import json
    import tempfile
    from pathlib import Path

    from packages.scanner_adapters.integrations.osv import match
    from services.source_analysis_worker.secrets import detect

    # OSV: a declared package inside an advisory range.
    advisory = json.dumps(
        {
            "id": "OSV-TEST-2",
            "summary": "A flaw",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
                }
            ],
        }
    ).encode()
    osv_findings = match(advisory, [{"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}])[
        "findings"
    ]
    osv_rows = [normalize_parsed_finding("osv", f) for f in osv_findings]
    assert osv_rows and osv_rows[0]["status"] == "suspected"
    assert osv_rows[0]["fingerprint"].startswith("osv:")
    assert osv_rows[0]["category"] == "vulnerable_dependency"

    # Secrets: the same token in two files must stay two distinct findings.
    import string

    token = "AKIA" + string.ascii_uppercase[3:19]  # 16 varied chars, not a placeholder
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / "a.txt").write_text(f"key = {token}\n")
        (root / "b.txt").write_text(f"key = {token}\n")
        matches = detect(root)["matches"]
    secret_rows = [normalize_parsed_finding("secrets", m) for m in matches]
    assert len(secret_rows) == 2
    assert len({r["fingerprint"] for r in secret_rows}) == 2  # distinct despite identical token
    assert all(r["status"] == "suspected" and r["fingerprint"].startswith("secrets:") for r in secret_rows)
    assert all(token not in json.dumps(r) for r in secret_rows)  # the secret itself is never echoed
