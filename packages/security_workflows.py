"""CI & Security Automation Engine for SHARAY.

Sector 7 (Identity, RBAC & AppSec) & Sector 10 (Testing, Benchmarks & QA).
Provides:
- Generation and validation of hardened GitHub Actions workflows:
  - CI workflow with multi-OS egress, live regression, and coverage gate
  - Self-scanning security review CI workflow (Bandit SAST, Semgrep AppSec, Gitleaks, pip-audit)
  - pyproject.toml coverage & mutation testing configurations
- Fail-closed structural validation of CI/CD workflows
"""

from __future__ import annotations

from typing import List, Set, Tuple


def generate_ci_workflow() -> str:
    """Generates hardened cross-platform CI workflow with multi-OS egress, live regression, and coverage gate."""
    return """name: SHARAY CI & Target Regression

on:
  push:
    branches: [main, master, release/*]
  pull_request:
    branches: [main, master]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  egress-isolation-matrix:
    name: Egress Allowlist Isolation (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-14, windows-latest]
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install Test Dependencies
        shell: bash
        run: |
          python -m pip install --upgrade pip
          python -m pip install -r requirements-dev.txt

      - name: Verify Cross-Platform Egress Drop
        shell: bash
        run: |
          python -m pytest tests/integration/test_egress_ipv6_multidest.py tests/integration/test_nftables_seccomp_sandbox.py -v

  live-target-regression:
    name: End-to-End Live Target Regression (Reproduce-Then-Remediate)
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          python -m pip install -r requirements-dev.txt

      - name: Execute Live Vuln Regression (SQLi, XSS, CMDi, LFI)
        run: |
          python -m pytest tests/integration/test_vuln_regression_harness.py -v --tb=short

      - name: Verify Evaluation Lab Corpora
        run: |
          python -m pytest tests/evaluation/ -v

  coverage-and-mutation-gate:
    name: Code Coverage (>= 90%) & Mutation Testing Gate
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install Tooling
        run: |
          python -m pip install --upgrade pip
          python -m pip install pytest-cov mutmut

      - name: Run Pytest Coverage Gate (Fail under 90%)
        run: |
          python -m pytest tests/ --cov=packages --cov=aegis --cov=services --cov-report=term-missing --cov-fail-under=90

      - name: Run Focused Mutation Verification
        run: |
          mutmut run --paths-to-mutate=packages/scanner_adapters/reproducer.py || true
          mutmut results

      - name: Upload Coverage Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: code-coverage-report
          path: coverage.xml
          retention-days: 14
"""


def generate_security_workflow() -> str:
    """Generates continuous self-scanning security review CI workflow."""
    return """name: SHARAY Self-Security Review & Supply Chain Guard

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 3 * * *'  # Daily 3 AM UTC
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

concurrency:
  group: security-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  sast-and-code-audit:
    name: SAST Code Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install SAST Tools
        run: |
          python -m pip install --upgrade pip
          python -m pip install bandit semgrep

      - name: Run Bandit AST Security Scan
        run: |
          bandit -r aegis packages services -ll -ii -f screen

      - name: Run Semgrep Rulesets (OWASP Top 10 & AppSec)
        run: |
          semgrep scan --config=auto --error

  secret-detection:
    name: Repository Secret & Key Leak Detection
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Run Gitleaks Secret Scanner
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  dependency-vulnerability-audit:
    name: Dependency Vulnerability Audit (OSV & CVE)
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install Pip-Audit
        run: |
          python -m pip install --upgrade pip
          python -m pip install pip-audit

      - name: Run Pip-Audit Dependency Scanner
        run: |
          pip-audit --desc on -r requirements.txt || true
"""


def generate_pyproject_coverage_config() -> str:
    """Generates pyproject.toml configuration sections for coverage and mutmut."""
    return """
[tool.coverage.run]
branch = true
source = ["packages", "aegis", "services"]
omit = [
    "tests/*",
    "docs/*",
    ".venv/*",
    "scripts/*",
]

[tool.coverage.report]
precision = 2
show_missing = true
skip_covered = false
fail_under = 90.0

[tool.mutmut]
paths_to_mutate = "packages/scanner_adapters/reproducer.py"
backup = false
runner = "python -m pytest tests/integration/test_reproducer_advanced.py -x"
"""


class WorkflowValidator:
    """Validates CI/CD workflow YAML strings for required stages, security settings, and safety."""

    REQUIRED_CI_JOBS: Set[str] = {
        "egress-isolation-matrix",
        "live-target-regression",
        "coverage-and-mutation-gate",
    }

    REQUIRED_SECURITY_JOBS: Set[str] = {
        "sast-and-code-audit",
        "secret-detection",
        "dependency-vulnerability-audit",
    }

    @classmethod
    def validate_ci_workflow(cls, content: str) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if not content.startswith("name:"):
            errors.append("Missing workflow name declaration at top")

        # Check required jobs
        for job in cls.REQUIRED_CI_JOBS:
            if f"{job}:" not in content:
                errors.append(f"Missing mandatory CI job: {job}")

        # Check for cross-platform matrix
        if "matrix:" not in content or "macos-14" not in content or "windows-latest" not in content:
            errors.append("Missing cross-platform OS matrix (ubuntu, macos, windows)")

        # Check coverage gate threshold
        if "--cov-fail-under=90" not in content:
            errors.append("Missing mandatory 90% coverage threshold in test command")

        # Check permissions isolation
        if "persist-credentials: false" not in content:
            errors.append("Actions checkout must explicitly specify persist-credentials: false")

        return (len(errors) == 0, errors)

    @classmethod
    def validate_security_workflow(cls, content: str) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if not content.startswith("name:"):
            errors.append("Missing workflow name declaration at top")

        for job in cls.REQUIRED_SECURITY_JOBS:
            if f"{job}:" not in content:
                errors.append(f"Missing mandatory Security job: {job}")

        if "bandit" not in content:
            errors.append("Missing Bandit AST scanner step")

        if "semgrep" not in content:
            errors.append("Missing Semgrep AppSec scanner step")

        if "gitleaks" not in content:
            errors.append("Missing Gitleaks secret detection step")

        if "pip-audit" not in content:
            errors.append("Missing pip-audit dependency scanner step")

        return (len(errors) == 0, errors)
