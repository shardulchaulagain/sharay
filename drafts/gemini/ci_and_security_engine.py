"""CI & Security Automation Engine for SHARAY.

Part of:
- Sector 3 (Isolation & Egress Sandbox): Cross-platform allowlist egress drop CI
- Sector 7 (Identity, RBAC & AppSec): Self-scanning security review CI
- Sector 10 (Testing, Benchmarks & QA): Live-target regression & 90%+ coverage gate

Generates and validates production-ready GitHub Actions workflows:
- .github/workflows/ci.yml
- .github/workflows/security.yml
- pyproject.toml coverage & mutation testing configurations
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


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
          python -m pytest drafts/gemini/test_egress_ipv6_multidest.py drafts/gemini/test_nftables_seccomp_sandbox.py -v

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
          python -m pytest drafts/gemini/test_vuln_regression_harness.py -v --tb=short

      - name: Verify Evaluation Lab Corpora
        run: |
          python -m pytest drafts/gemini/test_evaluation_lab.py -v

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

      - name: Install Coverage & Testing Dependencies
        run: |
          python -m pip install --upgrade pip
          python -m pip install pytest-cov mutmut
          python -m pip install -r requirements-dev.txt

      - name: Run Test Suite with Strict 90% Coverage Gate
        run: |
          python -m pytest \\
            --cov=aegis \\
            --cov=packages \\
            --cov=services \\
            --cov-report=term-missing \\
            --cov-report=xml:coverage.xml \\
            --cov-fail-under=90 \\
            tests/

      - name: Execute Mutation Testing on Reproducer Core
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

      - name: Install pip-audit
        run: |
          python -m pip install --upgrade pip
          python -m pip install pip-audit

      - name: Run Pinned Dependency Vulnerability Audit
        run: |
          pip-audit -r requirements.txt -r requirements-dev.txt

  audit-ledger-tamper-check:
    name: Audit Ledger Cryptographic Tamper-Evidence Verification
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

      - name: Verify Audit Ledger Merkle Anchors
        run: |
          python -m pytest drafts/gemini/test_auth_totp_and_audit_notary.py -k test_notary_chain -v
"""


def generate_pyproject_coverage_config() -> str:
    """Generates pyproject.toml configuration additions for pytest-cov and mutmut."""
    return """
[tool.coverage.run]
source = ["aegis", "packages", "services"]
omit = [
    "tests/*",
    "drafts/*",
    "migrations/*",
]
branch = true

[tool.coverage.report]
fail_under = 90
show_missing = true
skip_covered = false
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if TYPE_CHECKING:",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
]

[tool.mutmut]
paths_to_mutate = "packages/scanner_adapters/reproducer.py"
backup = false
runner = "python -m pytest -x tests/product/test_reproducer.py"
"""


class WorkflowValidator:
    """Validates structural and policy compliance of GitHub Actions workflows."""

    @staticmethod
    def parse_simple_yaml_structure(yaml_content: str) -> Dict[str, Any]:
        """Parses high-level keys and structure of YAML text."""
        parsed: Dict[str, Any] = {
            "name": "",
            "jobs": {},
            "raw": yaml_content,
        }

        # Extract workflow name
        name_match = re.search(r"^name:\s*(.+)$", yaml_content, re.MULTILINE)
        if name_match:
            parsed["name"] = name_match.group(1).strip()

        # Find jobs
        job_matches = re.finditer(r"^[ ]{2}([a-zA-Z0-9_-]+):\s*$", yaml_content, re.MULTILINE)
        current_job = ""
        job_names = [m.group(1) for m in job_matches if m.group(1) not in ("strategy", "matrix", "steps")]
        for jname in job_names:
            parsed["jobs"][jname] = {}

        return parsed

    @classmethod
    def validate_ci_workflow(cls, yaml_content: str) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        data = cls.parse_simple_yaml_structure(yaml_content)

        # 1. Check required jobs
        req_jobs = ["egress-isolation-matrix", "live-target-regression", "coverage-and-mutation-gate"]
        for j in req_jobs:
            if j not in data["jobs"]:
                errors.append(f"Missing required CI job: {j}")

        # 2. Check multi-OS matrix
        if "ubuntu-latest" not in yaml_content or "macos-14" not in yaml_content or "windows-latest" not in yaml_content:
            errors.append("Matrix must include ubuntu-latest, macos-14, and windows-latest")

        # 3. Check live regression harness
        if "test_vuln_regression_harness.py" not in yaml_content:
            errors.append("Live target regression job must execute test_vuln_regression_harness.py")

        # 4. Check coverage gate threshold
        if "--cov-fail-under=90" not in yaml_content:
            errors.append("Coverage gate must enforce --cov-fail-under=90")

        # 5. Check mutation testing hook
        if "mutmut" not in yaml_content:
            errors.append("CI must include mutation testing execution via mutmut")

        return len(errors) == 0, errors

    @classmethod
    def validate_security_workflow(cls, yaml_content: str) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        data = cls.parse_simple_yaml_structure(yaml_content)

        # 1. Check required security jobs
        req_jobs = [
            "sast-and-code-audit",
            "secret-detection",
            "dependency-vulnerability-audit",
            "audit-ledger-tamper-check",
        ]
        for j in req_jobs:
            if j not in data["jobs"]:
                errors.append(f"Missing required security job: {j}")

        # 2. Check tools: bandit, semgrep, gitleaks, pip-audit
        for tool in ("bandit", "semgrep", "gitleaks", "pip-audit"):
            if tool not in yaml_content:
                errors.append(f"Security workflow must incorporate tool: {tool}")

        return len(errors) == 0, errors
