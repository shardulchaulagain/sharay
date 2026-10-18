"""Report classification and protocol reproduction must follow stored evidence."""

import re
import shlex
import unittest
from html import unescape
from urllib.parse import parse_qs, urlsplit

from aegis.models import Assessment, Finding, FindingEvidence
from aegis.serialization import finding_view
from packages.reporting import render_report
from tests.product import test_finding_verification_gate as verification_fixture


def finding(title, **fields):
    return {
        "title": title,
        "category": "injection",
        "severity": "high",
        "confidence": "high",
        "status": "confirmed",
        "affected_url": "https://example.test/",
        **fields,
    }


def report(*findings):
    return render_report(
        {
            "assessment": {"id": "report-proof", "status": "completed_with_errors"},
            "target": {"url": "https://example.test/"},
            "findings": list(findings),
            "checks": [{"category": "zap", "status": "failed", "error": "ValueError: invalid config"}],
            "generated_at": "2026-10-16T12:00:00Z",
        },
        "html",
    )[0].decode()


def command_for(item):
    html = report(item)
    return unescape(re.search(r"<dt>Proof of Concept \(PoC\)</dt><dd><pre>(.*?)</pre>", html, re.S)[1])


class ReportVerificationTests(unittest.TestCase):
    def test_latest_snapshot_and_effective_status_control_verification(self):
        rejected = [
            finding(
                "Current suspected SQL injection",
                status="suspected",
                evidence=[{"data": {"status": "confirmed", "lifecycle_state": "REPRODUCED"}}],
            ),
            finding(
                "Current candidate SQL injection",
                lifecycle_state="REPRODUCED",
                evidence=[{"data": {"status": "suspected", "lifecycle_state": "CANDIDATE"}}],
            ),
            finding(
                "Current failed verifier SQL injection",
                autopyverifier={"exit_code": 0, "mock_mode": False},
                evidence=[{"data": {"autopyverifier": {"exit_code": 1, "mock_mode": False}}}],
            ),
            finding(
                "Malformed latest snapshot SQL injection",
                lifecycle_state="REPRODUCED",
                evidence=[{"data": {"lifecycle_state": "REPRODUCED"}}, {"data": None}],
            ),
            finding(
                "Latest snapshot lacks proof SQL injection",
                lifecycle_state="REPRODUCED",
                evidence=[{"data": {"status": "confirmed"}}],
            ),
            finding(
                "Noncanonical verifier SQL injection",
                AutoPyVerifier={"exit_code": 0, "mock_mode": False},
            ),
            finding(
                "Noncanonical snapshot verifier SQL injection",
                evidence=[{"data": {"AutoPyVerifier": {"exit_code": 0, "mock_mode": False}}}],
            ),
        ]
        historical = finding(
            "Historical reproduced SQL injection",
            current_status="demoted",
            evidence=[{"data": {"status": "confirmed", "lifecycle_state": "REPRODUCED"}}],
        )
        html = unescape(report(*rejected, historical))
        verified_section = html.split("<h2>Verified Security Vulnerabilities</h2>")[1].split(
            "<h2>Security Configuration & Hardening Posture</h2>"
        )[0]
        for item in rejected:
            with self.subTest(title=item["title"]):
                self.assertNotIn(item["title"], verified_section)
        self.assertIn(historical["title"], verified_section)

    def test_reopened_verified_findings_preserve_reproduction(self):
        for status in ("reopened", "accepted_risk", "remediation_in_progress"):
            with self.subTest(status=status):
                item = finding(
                    "Reproduced SQL injection with analyst disposition",
                    status=status,
                    evidence=[{"data": {"status": status, "lifecycle_state": "REPRODUCED"}}],
                )
                html = unescape(report(item))
                verified_section = html.split("<h2>Verified Security Vulnerabilities</h2>")[1].split(
                    "<h2>Security Configuration & Hardening Posture</h2>"
                )[0]
                self.assertIn(item["title"], verified_section)

    def test_failed_or_malformed_verifier_status_cannot_qualify(self):
        for status in (
            "FAILED",
            " Error ",
            "TIMEOUT",
            "DEMOTED",
            "false_positive",
            "unverified",
            [],
            {},
            False,
            0,
        ):
            with self.subTest(status=status):
                item = finding(
                    "Invalid verifier status SQL injection",
                    autopyverifier={"exit_code": 0, "mock_mode": False, "status": status},
                )
                html = report(item)
                self.assertIn(
                    "0</pre>",
                    html.split("<h2>Verified Security Vulnerabilities</h2>")[1].split("</section>")[0],
                )
                self.assertIn("Exploitation is not verified", html)

    def test_malformed_observation_details_preserve_export_availability(self):
        observations = [
            {"kind": "network_service", "service": None},
            {"kind": "dns_records", "ipv4_addresses": [None, 42], "cdn_waf_indicators": {}},
            {"kind": "crawler_summary", "endpoints": [None, {}], "parameters": [42]},
            {"kind": "attack_graph", "nodes": None, "edges": None, "chains": [None, [42]]},
            {"kind": "autopyverifier_execution", "scripts": None},
            {
                "kind": "safe_gated_pivoting",
                "safety_gate": None,
                "socks_pivot": None,
                "persistence_inventory": None,
            },
        ]
        for format in ("json", "html", "markdown", "pdf"):
            with self.subTest(format=format):
                raw, _ = render_report({"observations": observations}, format)
                self.assertTrue(raw)

    def test_missing_observation_values_do_not_invent_network_state(self):
        raw, _ = render_report(
            {"observations": [{"kind": "network_service", "port": 443}, {"kind": "dns_records"}]},
            "html",
        )
        html = raw.decode()
        self.assertNotIn("(open)", html)
        self.assertNotIn("Direct Origin", html)

    def test_only_real_reproduction_reaches_verified_section(self):
        verified = [
            finding("Replayed SQL injection", lifecycle_state="REPRODUCED"),
            finding("Stored snapshot SQL injection", evidence=[{"data": {"lifecycle_state": "REPRODUCED"}}]),
            finding("Verifier SQL injection", autopyverifier={"exit_code": 0, "mock_mode": False}),
            finding("CSP bypass XSS", category="cross_site_scripting", lifecycle_state="REPRODUCED"),
        ]
        rejected = [
            finding("Legacy confirmed SQL injection", poc={"payload": "canary"}),
            finding("Demoted SQL injection", lifecycle_state="DEMOTED"),
            finding("False positive SQL injection", status="false_positive", lifecycle_state="REPRODUCED"),
            finding(
                "Stored demotion SQL injection",
                lifecycle_state="REPRODUCED",
                evidence=[{"data": {"lifecycle_state": "DEMOTED"}}],
            ),
            finding("Mock SQL injection", autopyverifier={"exit_code": 0, "mock_mode": True}),
            finding("Unmarked SQL injection", autopyverifier={"exit_code": 0}),
            finding("Boolean exit SQL injection", autopyverifier={"exit_code": False, "mock_mode": False}),
            *[
                finding(
                    f"Verifier {status} SQL injection",
                    autopyverifier={"exit_code": 0, "mock_mode": False, "status": status},
                )
                for status in ("failed", "error", "timeout")
            ],
        ]
        configuration = finding("Missing CSP", category="http_headers", lifecycle_state="REPRODUCED")
        html = unescape(report(*verified, *rejected, configuration))
        verified_section = html.split("<h2>Verified Security Vulnerabilities</h2>")[1].split(
            "<h2>Security Configuration & Hardening Posture</h2>"
        )[0]
        posture_section = html.split("<h2>Security Configuration & Hardening Posture</h2>")[1].split(
            "<h2>Unverified or Demoted Findings</h2>"
        )[0]
        unverified_section = html.split("<h2>Unverified or Demoted Findings</h2>")[1]
        for item in verified:
            self.assertIn(item["title"], verified_section)
        for item in rejected:
            self.assertNotIn(item["title"], verified_section)
            self.assertIn(item["title"], unverified_section)
        self.assertNotIn(configuration["title"], verified_section)
        self.assertIn(configuration["title"], posture_section)
        self.assertIn("4 verified vulnerability finding(s)", html)
        self.assertIn("ValueError: invalid config", html)

    def test_protocol_commands_and_http_arguments_are_literal(self):
        dmarc = finding("Missing DMARC", category="email_spoofing_risk", affected_url="dns://example.test")
        self.assertEqual(shlex.split(command_for(dmarc)), ["dig", "+short", "TXT", "_dmarc.example.test"])
        spf = finding("Missing SPF", category="dns", affected_url="dns://example.test")
        self.assertEqual(shlex.split(command_for(spf)), ["dig", "+short", "TXT", "example.test"])
        tls = finding("Certificate expired", category="tls", affected_url="https://example.test:8443/")
        tls_args = shlex.split(command_for(tls))
        self.assertEqual(tls_args[:4], ["openssl", "s_client", "-connect", "example.test:8443"])
        self.assertIn("-verify_return_error", tls_args)
        ipv6 = finding("Certificate expired", category="tls", affected_url="https://[::1]:9443/")
        self.assertIn("[::1]:9443", shlex.split(command_for(ipv6)))
        url = "https://example.test/path'$(touch /tmp/not-executed);?normal=value"
        item = finding("Quoted URL", affected_url=url)
        arguments = shlex.split(command_for(item).replace("\\\n", ""))
        self.assertEqual(arguments[-2:], ["--", url])
        self.assertNotIn("-k", arguments)
        self.assertIn("--location", arguments)
        item["poc"] = {"parameter": "id", "payload": "1' OR '1'='1", "curl_command": "curl dns://wrong.test"}
        arguments = shlex.split(command_for(item).replace("\\\n", ""))
        self.assertEqual(parse_qs(urlsplit(arguments[-1]).query)["id"], ["1' OR '1'='1"])
        self.assertNotIn("dns://wrong.test", command_for(item))
        malformed = finding("Missing DMARC", category="dns", affected_url="dns://-bad.test")
        self.assertTrue(command_for(malformed).startswith("No command generated"))
        snapshot = finding(
            "Snapshot SQL injection",
            evidence=[{"data": {"poc": {"parameter": "id", "payload": "snapshot canary"}}}],
        )
        arguments = shlex.split(command_for(snapshot).replace("\\\n", ""))
        self.assertEqual(parse_qs(urlsplit(arguments[-1]).query)["id"], ["snapshot canary"])

    def test_metadata_and_wrapped_observations_use_stored_values(self):
        data = {
            "assessment": {"profile": "comprehensive"},
            "scope": {"verification_status": "operator_authorized"},
            "observations": [
                {"id": "dns-evidence", "data": {"kind": "dns_records", "domain": "example.test"}}
            ],
        }
        raw, _ = render_report(data, "json")
        self.assertIn(b'"assessment_mode": "comprehensive"', raw)
        self.assertIn(b'"scope_authorization": "operator_authorized"', raw)
        self.assertIn(b'"data": {', raw)
        html, _ = render_report(data, "html")
        self.assertIn(b"DNS and Perimeter Intelligence", html)
        self.assertIn(b"example.test", html)

    def test_evidence_and_impacts_are_readable_without_fabricated_execution(self):
        html = unescape(
            report(
                finding(
                    "Pending SQL injection",
                    evidence=[
                        {
                            "data": {
                                "request": {"method": "GET", "status_code": 503},
                                "lifecycle_state": "CANDIDATE",
                            }
                        }
                    ],
                    business_impact="Not assessed",
                )
            )
        )
        self.assertIn("Evidence / 1 / data / request / method", html)
        self.assertIn("<pre>GET</pre>", html)
        self.assertNotIn('"method": "GET"', html)
        self.assertIn("Technical Impact", html)
        self.assertIn("Business Impact", html)
        self.assertIn("Exploitation is not verified", html)
        self.assertNotIn("<pre>Not assessed</pre>", html)
        for fabricated in (
            "100% verified",
            "HTTP/1.1 200 OK",
            "3/3 canary runs",
            "teardown verified",
            "Visual Replication Screenshot",
        ):
            self.assertNotIn(fabricated, html)


class ReportEvidenceOrderingTests(unittest.TestCase):
    setUp = verification_fixture.FindingVerificationGateTests.setUp

    def test_assessment_completion_order_controls_latest_report_proof(self):
        for latest in (
            {"status": "demoted", "lifecycle_state": "DEMOTED"},
            {"status": "confirmed"},
        ):
            with self.subTest(latest=latest), self.sessions() as db:
                row = Finding(
                    organization_id=self.org_id,
                    project_id=self.project_id,
                    target_id=self.target_id,
                    fingerprint="reverse-insertion-" + latest["status"],
                    **finding("Completion ordered SQL injection", description="Synthetic", remediation="Fix"),
                )
                db.add(row)
                db.flush()
                assessments = []
                for completed_at, payload in (
                    (200, latest),
                    (100, {"status": "confirmed", "lifecycle_state": "REPRODUCED"}),
                ):
                    assessment = Assessment(
                        organization_id=self.org_id,
                        project_id=self.project_id,
                        target_id=self.target_id,
                        created_by=self.user_id,
                        idempotency_key=f"reverse-{row.id}-{completed_at}",
                        status="completed",
                        created_at=completed_at - 50,
                        finished_at=completed_at,
                        scope_snapshot=self.scope,
                        scope_version=1,
                    )
                    db.add(assessment)
                    db.flush()
                    assessments.append(assessment.id)
                    db.add(
                        FindingEvidence(
                            finding_id=row.id,
                            assessment_id=assessment.id,
                            data=payload,
                            evidence_hash="synthetic-ordering-evidence",
                        )
                    )
                    db.flush()
                current = finding_view(db, row)
                self.assertEqual(
                    [entry["assessment_id"] for entry in current["evidence"]],
                    list(reversed(assessments)),
                )
                html = unescape(report(current))
                verified_section = html.split("<h2>Verified Security Vulnerabilities</h2>")[1].split(
                    "<h2>Security Configuration & Hardening Posture</h2>"
                )[0]
                self.assertNotIn(row.title, verified_section)
                historical = finding_view(db, row, assessments[-1])
                self.assertEqual(len(historical["evidence"]), 1)
                historical_html = unescape(report(historical))
                self.assertIn("1 verified vulnerability finding(s)", historical_html)


if __name__ == "__main__":
    unittest.main()
