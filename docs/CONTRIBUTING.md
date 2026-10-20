# SHARAY Contributor Guide & Adapter / Plugin SDK Reference

Welcome to the SHARAY engineering project. SHARAY is a defensive security auditing, active verification, and automated vulnerability research platform built on one non-negotiable architectural invariant: **"Claim Nothing Without Proof."**

This document provides complete instructions for setting up your development environment, authoring custom detection packs, building scanner adapter plugins, and adhering to our multi-layered verification and security gates.

---

## 1. Architectural Invariants

Every contribution to SHARAY must conform to three architectural pillars:

1. **Stateful Cryptographic Verification (The 6-State Verification Machine):**
   - No vulnerability is presented as "Confirmed" without an automated, reproducible proof-of-concept or statistical differential oracle.
   - Findings strictly transition through:
     $$\text{suspected} \longrightarrow \text{verifying} \longrightarrow \begin{cases} \text{confirmed\_reproducible} \\ \text{supporting\_signal} \\ \text{inconclusive} \\ \text{validation\_failed} \end{cases}$$
2. **Fail-Closed Isolation & Egress Control:**
   - Scanner adapters and target reproducers must execute inside rootless unprivileged sandboxes with strict network namespaces.
   - Egress is strictly blocked by `nftables`/`iptables`/`pf` except for explicitly declared destination CIDRs. All rules applied and torn down are cryptographically attested in an immutable audit ledger.
3. **Evidence Integrity & Provenance:**
   - Every finding, network observation, and AI reasoning narrative must bind back to raw request/response SHA-256 evidence digests anchored in a Merkle tree.

---

## 2. Development Environment Setup

### Prerequisites
- **Python:** 3.11 or 3.13 (recommended: Python 3.13)
- **Container Engine:** Podman (recommended for rootless execution) or Docker
- **Frontend Runtime:** Node.js 20+ and npm / pnpm
- **Native Utilities:** `git`, `curl`, `make`

### Workspace Initialization
```bash
# 1. Clone the repository
git clone https://github.com/organization/aegis.git
cd aegis

# 2. Initialize Python virtual environment
python3.13 -m venv .venv
source .venv/bin/activate

# 3. Install core and development dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov ruff mypy bandit semgrep mutmut

# 4. Initialize frontend workspace (optional for backend-only contributors)
cd apps/web
npm install
cd ../..
```

---

## 3. Code Standards & CI Verification Gates

All pull requests must pass our automated verification suite prior to review:

```bash
# 1. Formatting and linting
ruff format --check .
ruff check .

# 2. Strict static type analysis
mypy --strict packages/ services/ drafts/gemini/

# 3. Unit and integration test suite with coverage enforcement (>= 90%)
pytest --cov=packages --cov=services --cov-report=term-missing --cov-fail-under=90

# 4. Security self-audit pipeline
bandit -r packages/ services/ -ll
semgrep --config p/security-audit packages/ services/
gitleaks detect --source . --verbose
```

---

## 4. Detection Pack Authoring Guide

Detection packs are signed, modular bundles containing rules, payload templates, and verification probes.

### Directory Structure
```
packs/
└── custom-cwe-89-sqli/
    ├── manifest.json
    ├── manifest.json.sig
    ├── rules.py
    └── probes/
        └── time_based_oracle.py
```

### Manifest Specification (`manifest.json`)
```json
{
  "pack_id": "cwe-89-sqli-advanced",
  "version": "1.2.0",
  "author": "Security Engineering Team",
  "schema_version": "2.1.0",
  "target_categories": ["A03:2021-Injection"],
  "cwe_ids": ["CWE-89"],
  "cvss_v3_base_score": 8.5,
  "signing_key_id": "sharay-ed25519-pack-key-01",
  "rules": [
    {
      "id": "rule-blind-timing-extract",
      "severity": "high",
      "non_destructive": true,
      "requires_oob": false
    }
  ]
}
```

### Cryptographic Pack Signing
All detection packs must be signed using Ed25519 before they can be loaded by the engine:
```bash
python -m drafts.gemini.detection_packs_engine sign \
  --pack-dir packs/custom-cwe-89-sqli \
  --private-key-file keys/developer_ed25519.key
```

---

## 5. Scanner Adapter Plugin SDK

To integrate a new tool or protocol scanner, implement the `BaseScannerAdapter` interface:

```python
from __future__ import annotations
from typing import Any, Dict, List
from packages.scanner_adapters.base import BaseScannerAdapter, AdapterObservation

class CustomGraphQLScannerAdapter(BaseScannerAdapter):
    """Integrates a specialized GraphQL introspection and mutation scanner."""

    adapter_name = "graphql_security_probe"
    adapter_version = "1.0.0"

    def execute_scan(
        self,
        target_url: str,
        options: Dict[str, Any],
        egress_proxy_url: str,
    ) -> List[AdapterObservation]:
        """Runs the scanner bounded by execution timeouts and egress constraints."""
        observations: List[AdapterObservation] = []

        # Execute safe, rate-limited queries via egress proxy
        response = self.safe_http_client.get(
            f"{target_url}/graphql",
            params={"query": "{ __schema { types { name } } }"},
            proxy=egress_proxy_url,
            timeout=5.0,
        )

        if response.status_code == 200 and "__schema" in response.text:
            observations.append(
                AdapterObservation(
                    observation_id=self.generate_observation_id(),
                    target_url=target_url,
                    vuln_type="graphql_introspection_enabled",
                    severity="low",
                    evidence_payload=response.text[:1024],
                    evidence_sha256=self.hash_bytes(response.content),
                    non_destructive=True,
                )
            )

        return observations
```

---

## 6. Multi-Operator & Audit Ledger Integration

Every scan operation automatically anchors entries in the cryptographic audit ledger:
- Egress rules applied and torn down are attested with HMAC-SHA256 digests.
- Keystrokes in interactive PTY verification sessions are signed and can be replayed via Asciinema v2 files.
- Never bypass the `AuditLedger` logging pipeline when adding privileged endpoints.

---

## 7. Coordination & PR Submission Workflow

SHARAY uses an append-only coordination protocol to prevent merge collisions between engineers and autonomous agents:

```bash
# 1. Claim your task in the session log
.venv/bin/python -m scripts.session_log \
  --agent codex \
  --kind claim \
  --summary "Implement GraphQL batching attack detection adapter" \
  --path packages/scanner_adapters/graphql.py

# 2. Implement the change and run tests
pytest tests/unit/test_graphql_adapter.py

# 3. Log completed verification checkpoint
.venv/bin/python -m scripts.session_log \
  --agent codex \
  --kind verification \
  --summary "Verified GraphQL batching detection with 100% test coverage" \
  --path packages/scanner_adapters/graphql.py \
  --check "pytest tests/unit/test_graphql_adapter.py (10/10 passed)"

# 4. Submit Pull Request with signed commits
git commit -S -m "feat(adapters): add GraphQL security probe and batching detector"
git push origin feat/graphql-probe
```

---
*SHARAY Core Team — Build Evidence. Claim Nothing Without Proof.*
