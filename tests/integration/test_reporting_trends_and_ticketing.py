"""Live test suite for Differential Trend Reporting, MTTR Analytics & Ticketing Integrations (Sector 6).

Verifies:
1. Differential report computation: new, resolved, reopened, and persistent finding tracking.
2. Mean-Time-To-Remediation (MTTR) calculation and posture delta tracking.
3. Executive dashboard generator: severity mix, attack surface coverage, and risk rating.
4. GitHub & Jira ticketing push with automatic deduplication by finding fingerprint.
"""

from __future__ import annotations

from packages.reporting import (
    AssessmentTrendEngine,
    ExecutiveDashboardGenerator,
    FindingRecord,
    TicketingPushEngine,
)


class TestReportingTrendsAndTicketing:
    def test_differential_trend_reporting_and_mttr(self):
        # Assessment 1: Findings A and B
        f_a = FindingRecord(
            finding_id="F-1",
            vuln_type="SQLi",
            target_origin="https://target.corp",
            endpoint="/search",
            parameter="q",
            severity="HIGH",
            cvss_score=8.5,
            description="SQL injection in search",
            first_detected_at=1000.0,
            last_detected_at=1000.0,
        )
        f_b = FindingRecord(
            finding_id="F-2",
            vuln_type="XSS",
            target_origin="https://target.corp",
            endpoint="/profile",
            parameter="bio",
            severity="MEDIUM",
            cvss_score=6.1,
            description="Stored XSS in bio",
            first_detected_at=1000.0,
            last_detected_at=1000.0,
        )

        # Assessment 2: Finding A resolved, Finding B still persistent, Finding C newly detected
        f_c = FindingRecord(
            finding_id="F-3",
            vuln_type="CMDi",
            target_origin="https://target.corp",
            endpoint="/ping",
            parameter="host",
            severity="CRITICAL",
            cvss_score=9.8,
            description="Command injection in ping tool",
            first_detected_at=2000.0,
            last_detected_at=2000.0,
        )

        diff = AssessmentTrendEngine.compute_differential(
            prev_assessment_id="ASS-101",
            prev_findings=[f_a, f_b],
            curr_assessment_id="ASS-102",
            curr_findings=[f_b, f_c],
            now=2000.0,
        )

        assert len(diff.new_findings) == 1
        assert diff.new_findings[0].vuln_type == "CMDi"

        assert len(diff.resolved_findings) == 1
        assert diff.resolved_findings[0].vuln_type == "SQLi"

        assert len(diff.persistent_findings) == 1
        assert diff.persistent_findings[0].vuln_type == "XSS"

        # MTTR: Finding A was open from t=1000 to t=2000 (1000s)
        assert diff.mttr_seconds == 1000.0

    def test_reopened_finding_tracking(self):
        # A finding that was resolved in the past now reappears
        f_old = FindingRecord(
            finding_id="F-99",
            vuln_type="SSRF",
            target_origin="https://target.corp",
            endpoint="/fetch",
            parameter="url",
            severity="HIGH",
            cvss_score=8.6,
            description="SSRF in fetch",
            first_detected_at=1000.0,
            last_detected_at=3000.0,
        )
        resolved_fps = {f_old.fingerprint}

        diff = AssessmentTrendEngine.compute_differential(
            prev_assessment_id="ASS-200",
            prev_findings=[],  # was absent in previous
            curr_assessment_id="ASS-201",
            curr_findings=[f_old],
            historical_resolved_fingerprints=resolved_fps,
            now=3000.0,
        )

        assert len(diff.reopened_findings) == 1
        assert diff.reopened_findings[0].fingerprint == f_old.fingerprint
        assert len(diff.new_findings) == 0

    def test_executive_dashboard_generation(self):
        findings = [
            FindingRecord("1", "RCE", "https://app.corp", "/cmd", "c", "CRITICAL", 9.8, "RCE", 0, 0),
            FindingRecord("2", "SQLi", "https://app.corp", "/login", "u", "HIGH", 8.8, "SQLi", 0, 0),
            FindingRecord("3", "InfoLeak", "https://app.corp", "/version", None, "INFO", 0.0, "Info", 0, 0),
        ]
        dashboard = ExecutiveDashboardGenerator.generate_dashboard(
            findings=findings,
            total_endpoints_discovered=50,
            total_endpoints_tested=48,
            target_name="Fintech Core API",
        )

        assert dashboard["target_name"] == "Fintech Core API"
        assert dashboard["severity_distribution"]["CRITICAL"] == 1
        assert dashboard["severity_distribution"]["HIGH"] == 1
        assert dashboard["severity_distribution"]["INFO"] == 1
        assert dashboard["attack_surface"]["coverage_percent"] == 96.0
        assert dashboard["risk_rating"] in ("ELEVATED", "CRITICAL")
        assert "Fintech Core API" in dashboard["executive_summary"]

    def test_ticketing_push_and_deduplication(self):
        engine = TicketingPushEngine()
        f1 = FindingRecord("F-1", "SQLi", "https://app.corp", "/search", "q", "HIGH", 8.5, "SQLi", 0, 0)

        # First push creates ticket
        t1 = engine.push_finding_ticket(f1, platform="github")
        assert t1["status"] == "CREATED"
        assert t1["ticket_id"] == "TICK-101"
        assert "[SHARAY-HIGH] SQLi on /search" in t1["payload"]["title"]

        # Duplicate push of the exact same finding updates the ticket, avoids duplicate creation
        t1_dup = engine.push_finding_ticket(f1, platform="github")
        assert t1_dup["status"] == "UPDATED"
        assert t1_dup["ticket_id"] == "TICK-101"
        assert t1_dup["update_count"] == 2

        # Different finding creates new ticket
        f2 = FindingRecord("F-2", "XSS", "https://app.corp", "/comment", "c", "MEDIUM", 6.1, "XSS", 0, 0)
        t2 = engine.push_finding_ticket(f2, platform="jira")
        assert t2["status"] == "CREATED"
        assert t2["ticket_id"] == "TICK-102"
        assert t2["payload"]["fields"]["project"]["key"] == "SEC"
