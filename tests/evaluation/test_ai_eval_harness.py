"""AI Evaluation Benchmark Harness & Remediation Patch Validation Tests.

Sector 5: AI Reasoning Layer.
Validates:
1. Curated benchmark corpus for AI root-cause synthesis scoring.
2. Provider accuracy scorecard (Root-Cause precision/recall, CWE alignment, OWASP category match).
3. Automated AST and configuration syntax validation for generated code patches.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from services.ai_analysis_worker.reasoning import generate_defensive_root_cause_analysis
from services.ai_analysis_worker.remediation import RemediationValidator


@dataclass
class BenchmarkScenario:
    scenario_id: str
    name: str
    target_url: str
    findings: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    expected_cwe: str
    expected_owasp: str
    expected_root_cause_keywords: list[str]
    expected_min_cut_nodes: list[str]


class AIEvaluationHarness:
    """Benchmark harness evaluating AI analysis synthesis accuracy."""

    def __init__(self) -> None:
        self.scenarios: list[BenchmarkScenario] = []
        self._load_curated_benchmarks()

    def _load_curated_benchmarks(self) -> None:
        # Scenario 1: Spring4Shell Remote Code Execution Chain
        self.scenarios.append(
            BenchmarkScenario(
                scenario_id="BM-01-SPRING4SHELL",
                name="Spring Cloud Function DataBinder SpEL Injection",
                target_url="https://app.corp.internal/functionRouter",
                findings=[
                    {
                        "fingerprint": "fp-ssti-01",
                        "title": "Spring Expression Language (SpEL) Code Injection",
                        "category": "ssti",
                        "severity": "critical",
                        "description": "Unsanitized spring.cloud.function.routing-expression header evaluated via SpEL.",
                    },
                    {
                        "fingerprint": "fp-hdr-01",
                        "title": "Missing Content-Security-Policy",
                        "category": "http_headers",
                        "severity": "low",
                        "description": "CSP header missing on responses.",
                    },
                ],
                observations=[
                    {"kind": "open_port", "port": 8080, "service": "http-alt"},
                    {"kind": "software_indicator", "vendor": "Spring Framework", "version": "5.3.17"},
                ],
                expected_cwe="CWE-94",
                expected_owasp="A03:2021-Injection",
                expected_root_cause_keywords=["expression", "injection", "input", "validation", "parameter"],
                expected_min_cut_nodes=["endpoint:/functionRouter", "vuln:ssti"],
            )
        )

        # Scenario 2: SSRF to Cloud Metadata Service (IMDSv1)
        self.scenarios.append(
            BenchmarkScenario(
                scenario_id="BM-02-SSRF-IMDS",
                name="Server-Side Request Forgery via Image Fetcher",
                target_url="https://media.corp.internal/fetch?url=http://169.254.169.254/latest/meta-data/",
                findings=[
                    {
                        "fingerprint": "fp-ssrf-01",
                        "title": "Out-of-Band SSRF via URL Parameter",
                        "category": "ssrf",
                        "severity": "high",
                        "description": "Host forwards HTTP requests to internal IP addresses without egress filtering.",
                    }
                ],
                observations=[
                    {"kind": "cloud_provider", "provider": "AWS", "imds_version": "v1"},
                ],
                expected_cwe="CWE-918",
                expected_owasp="A10:2021-Server-Side Request Forgery",
                expected_root_cause_keywords=["ssrf", "request", "boundary", "validation", "allowlist"],
                expected_min_cut_nodes=["endpoint:/fetch", "vuln:ssrf"],
            )
        )

        # Scenario 3: Broken Object Level Authorization (BOLA/IDOR)
        self.scenarios.append(
            BenchmarkScenario(
                scenario_id="BM-03-BOLA-IDOR",
                name="BOLA in User Account Profile Update",
                target_url="https://api.corp.internal/v1/users/42/settings",
                findings=[
                    {
                        "fingerprint": "fp-idor-01",
                        "title": "BOLA / IDOR Horizontal Privilege Escalation",
                        "category": "broken_access_control",
                        "severity": "high",
                        "description": "User token for User 10 can update settings of User 42 without authorization check.",
                    }
                ],
                observations=[],
                expected_cwe="CWE-639",
                expected_owasp="A01:2021-Broken Access Control",
                expected_root_cause_keywords=["authorization", "access", "control", "privilege"],
                expected_min_cut_nodes=["endpoint:/v1/users/{id}/settings", "vuln:idor"],
            )
        )

    def evaluate_ai_synthesis(
        self,
        scenario: BenchmarkScenario,
        synthesis_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Scores an AI root-cause analysis against benchmark ground truth."""
        root_causes = synthesis_result.get("root_causes", [])
        if not root_causes and "category" in synthesis_result:
            root_causes = [synthesis_result]

        # 1. CWE Match
        cwe_found = False
        for rc in root_causes:
            if rc.get("cwe_id") == scenario.expected_cwe:
                cwe_found = True
                break

        # 2. OWASP Category Match
        owasp_found = False
        for rc in root_causes:
            if scenario.expected_owasp.lower() in str(rc.get("owasp_category", "")).lower():
                owasp_found = True
                break

        # 3. Keyword Semantic Alignment
        text_corpus = " ".join(
            [
                str(rc.get("mechanism", ""))
                + " "
                + str(rc.get("strategic_fix", ""))
                + " "
                + str(rc.get("category", ""))
                for rc in root_causes
            ]
        ).lower()
        matched_keywords = [kw for kw in scenario.expected_root_cause_keywords if kw in text_corpus]
        keyword_score = len(matched_keywords) / max(1, len(scenario.expected_root_cause_keywords))

        # Overall Accuracy Score
        score = (1.0 if cwe_found else 0.0) * 0.4 + (1.0 if owasp_found else 0.0) * 0.3 + keyword_score * 0.3

        return {
            "scenario_id": scenario.scenario_id,
            "cwe_accuracy": 1.0 if cwe_found else 0.0,
            "owasp_accuracy": 1.0 if owasp_found else 0.0,
            "keyword_alignment": round(keyword_score, 2),
            "overall_score": round(score, 2),
            "passed": score >= 0.60,
        }


def test_ai_eval_harness_benchmark_scoring():
    """Verify evaluation harness across curated scenarios."""
    harness = AIEvaluationHarness()
    assert len(harness.scenarios) == 3

    for scenario in harness.scenarios:
        analysis = generate_defensive_root_cause_analysis(scenario.findings)
        scorecard = harness.evaluate_ai_synthesis(scenario, analysis)
        assert scorecard["passed"] is True, f"Benchmark {scenario.scenario_id} failed: {scorecard}"
        assert scorecard["overall_score"] >= 0.60


def test_remediation_patch_validator_python_valid_and_invalid():
    """Verify Python AST compilation for generated code patches."""
    valid_patch = """
def sanitize_input(user_param: str) -> str:
    import html
    return html.escape(user_param.strip())
"""
    res = RemediationValidator.validate_patch(valid_patch, language="python")
    assert res.is_valid is True
    assert res.deployable is True
    assert res.syntax_error is None

    invalid_patch = """
def broken_syntax(param:
    return param
"""
    res_bad = RemediationValidator.validate_patch(invalid_patch, language="python")
    assert res_bad.is_valid is False
    assert res_bad.deployable is False
    assert "Line 2" in (res_bad.syntax_error or "")


def test_remediation_patch_validator_json_and_config():
    """Verify JSON and web server config syntax validation."""
    valid_json = '{"security_headers": {"x_frame_options": "DENY"}}'
    assert RemediationValidator.validate_patch(valid_json, "json").is_valid is True

    invalid_json = '{"security_headers": { unquoted_key: 123 }'
    assert RemediationValidator.validate_patch(invalid_json, "json").is_valid is False

    valid_nginx = """
server {
    listen 443 ssl;
    server_name example.com;
    add_header X-Frame-Options "DENY" always;
}
"""
    assert RemediationValidator.validate_patch(valid_nginx, "nginx").is_valid is True

    unbalanced_nginx = """
server {
    listen 443 ssl;
    add_header X-Frame-Options "DENY";
"""
    res_unbal = RemediationValidator.validate_patch(unbalanced_nginx, "nginx")
    assert res_unbal.is_valid is False
    assert "Mismatched braces" in (res_unbal.syntax_error or "")


def test_remediation_patch_validator_unified_diff():
    """Verify unified diff format checking."""
    valid_diff = """--- a/app.py
+++ b/app.py
@@ -10,3 +10,3 @@
-    query = f"SELECT * FROM users WHERE id = {user_id}"
+    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    res = RemediationValidator.validate_patch(valid_diff, "diff")
    assert res.is_valid is True
    assert res.deployable is True

    invalid_diff = "Just change line 10 to use cursor.execute"
    res_bad = RemediationValidator.validate_patch(invalid_diff, "diff")
    assert res_bad.is_valid is False
