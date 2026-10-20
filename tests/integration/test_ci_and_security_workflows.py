"""Live tests for CI & Security Automation Engine (Sectors 3, 7, 10).

Verifies:
1. CI workflow generation: cross-platform matrix, egress drop tests, live target regression, 90% coverage gate, mutation testing.
2. Security workflow generation: SAST (Bandit/Semgrep), secret scanning (Gitleaks), dependency CVE audit (pip-audit), and ledger tamper checks.
3. Pyproject coverage & mutmut configuration parsing via tomllib.
4. Fail-closed structural validation of CI/CD workflows.
"""

from __future__ import annotations

import tomllib

from packages.security_workflows import (
    WorkflowValidator,
    generate_ci_workflow,
    generate_pyproject_coverage_config,
    generate_security_workflow,
)


class TestCIWorkflow:
    def test_ci_workflow_generation_and_validation(self):
        wf = generate_ci_workflow()
        assert "name: SHARAY CI & Target Regression" in wf
        assert "egress-isolation-matrix:" in wf
        assert "live-target-regression:" in wf
        assert "coverage-and-mutation-gate:" in wf

        is_valid, errors = WorkflowValidator.validate_ci_workflow(wf)
        assert is_valid is True, f"CI workflow validation failed: {errors}"
        assert len(errors) == 0

    def test_cross_platform_matrix_present(self):
        wf = generate_ci_workflow()
        assert "ubuntu-latest" in wf
        assert "macos-14" in wf
        assert "windows-latest" in wf

    def test_coverage_and_mutation_requirements(self):
        wf = generate_ci_workflow()
        assert "--cov-fail-under=90" in wf
        assert "mutmut run" in wf
        assert "persist-credentials: false" in wf


class TestSecurityWorkflow:
    def test_security_workflow_generation_and_validation(self):
        wf = generate_security_workflow()
        assert "name: SHARAY Self-Security Review" in wf
        assert "sast-and-code-audit:" in wf
        assert "secret-detection:" in wf
        assert "dependency-vulnerability-audit:" in wf

        is_valid, errors = WorkflowValidator.validate_security_workflow(wf)
        assert is_valid is True, f"Security workflow validation failed: {errors}"
        assert len(errors) == 0

    def test_mandatory_security_scanners(self):
        wf = generate_security_workflow()
        assert "bandit -r" in wf
        assert "semgrep scan" in wf
        assert "gitleaks" in wf
        assert "pip-audit" in wf
        assert "cron: '0 3 * * *'" in wf


class TestPyprojectCoverageConfig:
    def test_coverage_config_parseable_and_strict(self):
        config_str = generate_pyproject_coverage_config()
        parsed = tomllib.loads(config_str)

        assert "tool" in parsed
        assert "coverage" in parsed["tool"]
        report = parsed["tool"]["coverage"]["report"]
        assert report["fail_under"] >= 90.0
        assert report["show_missing"] is True

        assert "mutmut" in parsed["tool"]
        assert parsed["tool"]["mutmut"]["backup"] is False
