"""Unit and integration tests for SARIF 2.1.0, CSV export, and sealed evidence bundles.

Sector 6: Reporting & Evidence.
Proves:
1. SARIF 2.1.0 schema validity, rule indexing, and severity mapping.
2. CSV tabular output and formula-injection defenses (=, +, -, @).
3. Evidence bundle packaging, Merkle root seal generation, and tamper detection.
4. Native integration with render_report for sarif, csv, and bundle/zip formats.
"""

import io
import json
import zipfile

import pytest

from packages.reporting import (
    CsvExporter,
    EvidenceBundleBuilder,
    SarifExporter,
    render_report,
)


@pytest.fixture
def sample_assessment():
    return {
        "id": "assess-uuid-42",
        "target_url": "https://api.victim.com",
        "findings": [
            {
                "id": "f-1",
                "fingerprint": "fp-sqli-01",
                "title": "SQL Injection in /api/v1/users",
                "category": "sqli",
                "severity": "critical",
                "confidence": "high",
                "status": "confirmed",
                "lifecycle_state": "REPRODUCED",
                "affected_url": "https://api.victim.com/api/v1/users?id=1",
                "cwe_id": "CWE-89",
                "description": "Error-based SQL injection in id parameter.",
                "remediation": "Use parameterized prepared statements.",
                "evidence_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "autopyverifier": {"exit_code": 0, "status": "reproduced"},
            },
            {
                "id": "f-2",
                "fingerprint": "fp-hdr-01",
                "title": "Missing Strict-Transport-Security",
                "category": "http_headers",
                "severity": "low",
                "confidence": "high",
                "status": "suspected",
                "lifecycle_state": "CANDIDATE",
                "affected_url": "https://api.victim.com",
                "cwe_id": "CWE-319",
                "description": "HSTS header omitted.",
                "remediation": "Add Strict-Transport-Security header.",
                "evidence_hash": "f9e8d7c6b5a432109876543210abcdef",
            },
            {
                "id": "f-3",
                "fingerprint": "fp-calc-01",
                "title": "=cmd|' /C calc'!A0",
                "category": "injection",
                "severity": "medium",
                "confidence": "medium",
                "status": "suspected",
                "description": "Adversarial formula payload reflection.",
                "remediation": "Sanitize inputs.",
            },
        ],
        "observations": [
            {"kind": "http_response", "url": "https://api.victim.com", "status": 200},
        ],
    }


def test_sarif_export_schema_and_rules(sample_assessment):
    """Verify SARIF 2.1.0 JSON format and rule associations."""
    sarif_str = SarifExporter.export(sample_assessment, tool_version="2.0.0")
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    assert "https://docs.oasis-open.org/sarif" in sarif["$schema"]

    runs = sarif.get("runs", [])
    assert len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "SHARAY"
    assert driver["version"] == "2.0.0"

    rules = driver["rules"]
    assert len(rules) >= 2
    rule_ids = {r["id"] for r in rules}
    assert "SHARAY/SQLI" in rule_ids
    assert "SHARAY/HTTP_HEADERS" in rule_ids

    results = runs[0]["results"]
    assert len(results) == 3

    # Check SQLi result
    sqli_res = next(r for r in results if r["ruleId"] == "SHARAY/SQLI")
    assert sqli_res["level"] == "error"
    assert sqli_res["properties"]["autopyverifier_reproduced"] is True
    assert sqli_res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://api.victim.com/api/v1/users?id=1"
    )

    # Check HSTS low severity result
    hsts_res = next(r for r in results if r["ruleId"] == "SHARAY/HTTP_HEADERS")
    assert hsts_res["level"] == "note"


def test_csv_export_and_formula_injection_defense(sample_assessment):
    """Verify CSV rows and anti-formula injection sanitization."""
    csv_str = CsvExporter.export(sample_assessment)
    lines = csv_str.strip().splitlines()

    # Header line
    assert lines[0] == (
        "Finding ID,Title,Severity,Confidence,Category,Status,Lifecycle State,Affected URL,"
        "AutoPyVerifier Reproduced,Evidence Hash,Remediation"
    )

    # Check formula payload sanitization: '=cmd|...' must be escaped as ''=cmd|...'
    formula_line = next(line for line in lines if "calc" in line)
    assert "'=cmd|' /C calc'!A0" in formula_line


def test_evidence_bundle_creation_and_tamper_detection(sample_assessment):
    """Verify evidence bundle generation, Merkle seal, and fail-closed tamper detection."""
    autopy_scripts = {"reproduce_sqli": "import urllib.request\nprint('SQLi PoC verified')\n"}

    # 1. Build bundle
    bundle_bytes = EvidenceBundleBuilder.build_bundle(
        assessment_id="assess-uuid-42",
        assessment_data=sample_assessment,
        autopy_scripts=autopy_scripts,
    )
    assert len(bundle_bytes) > 0

    # 2. Verify legitimate bundle
    valid, msg, manifest = EvidenceBundleBuilder.verify_bundle(bundle_bytes)
    assert valid is True
    assert "intact" in msg
    assert manifest is not None
    assert manifest["assessment_id"] == "assess-uuid-42"
    assert "findings.json" in manifest["files"]
    assert "autopyverifier/reproduce_sqli.py" in manifest["files"]
    assert len(manifest["merkle_root_seal"]) == 64

    # 3. Simulate adversarial tampering (modify findings.json inside the ZIP)
    tampered_buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as zin:
        with zipfile.ZipFile(tampered_buf, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "findings.json":
                    # Inject unauthorized alteration
                    data = data.replace(b"critical", b"low")
                zout.writestr(item, data)

    tampered_bytes = tampered_buf.getvalue()

    # 4. Verification must fail on tampered archive
    valid, err_msg, _ = EvidenceBundleBuilder.verify_bundle(tampered_bytes)
    assert valid is False
    assert "Hash mismatch for findings.json" in err_msg


def test_render_report_sarif_csv_bundle(sample_assessment):
    """Verify render_report natively handles sarif, csv, and bundle/zip."""
    # 1. SARIF via render_report
    sarif_bytes, sarif_mime = render_report(sample_assessment, "sarif")
    assert sarif_mime == "application/sarif+json"
    sarif_obj = json.loads(sarif_bytes.decode("utf-8"))
    assert sarif_obj["version"] == "2.1.0"

    # 2. CSV via render_report
    csv_bytes, csv_mime = render_report(sample_assessment, "csv")
    assert csv_mime == "text/csv; charset=utf-8"
    assert b"Finding ID,Title,Severity" in csv_bytes

    # 3. Bundle via render_report
    zip_bytes, zip_mime = render_report(sample_assessment, "bundle")
    assert zip_mime == "application/zip"
    valid, _, _ = EvidenceBundleBuilder.verify_bundle(zip_bytes)
    assert valid is True
