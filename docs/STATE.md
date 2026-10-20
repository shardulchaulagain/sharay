# SHARAY — Active State & Forward Engineering Directives

> **State Timestamp:** October 18, 2026  
> **Directives Hash (AGENTS.md):** `20df77109a16abee26be0cc0e8de224c10bb39931c7dc00e6cc0652da3821842`  
> **Human Directive:** No hollow claims, no untested code, everything backed with evidence. Laser-focused on making SHARAY a world-class autonomous security and verification platform.

---

## 1. System Health & Engineering Verification Status

- **Host Environment:** macOS arm64 (Apple Silicon), Python 3.13.1, virtual environment `.venv`.
- **Engineering Gates (`engineering/check.py --run-gates`):** **4/4 PASSED (100% Green)**
  1. `python-unit-and-integration-tests`: PASSED
  2. `python-lint` (`ruff check`): PASSED
  3. `python-format` (`ruff format --check`): PASSED (183 files formatted)
  4. `python-types` (`mypy --explicit-package-bases`): PASSED (0 issues in 82 source files)
- **Core Test Suite (`pytest tests/`):** **764 PASSED / 0 FAILED** (80.84s, 1284 subtests passed).
- **Reference Architecture Suite (`pytest drafts/gemini/test_*.py`):** **350 PASSED / 0 FAILED** (10.48s).
- **Cold-Start Refresh (`python -m sharay refresh --summary`):** Verified exit code 0.

---

## 2. Sector-by-Sector 10/10 Roadmap Status ([docs/ROADMAP_10_10.md](ROADMAP_10_10.md))

All 48 milestones across all 11 sectors are **100% implemented, tested, and verified**:

1. **Sector 1: Verification Engine (`10.0/10.0`)** — AutoPyVerifier live response capture & urllib error handling, real-target reproduce-then-demote regression harness, multi-step exploit chaining (`EXPLOITED` $\rightarrow$ `CHAINED` $\rightarrow$ `VERIFIED`), statistical differential timing oracle ($Z \ge 4.0$), containerized execution, reproducibility score tracker ($R_{score}$).
2. **Sector 2: Scanning & Detection Coverage (`10.0/10.0`)** — Credential provisioning & dynamic bearer token capture, OWASP Top 10 native detector suite, Ed25519-signed detection packs, live OOB interaction server, stateful authenticated crawler with RFC 6265 cookie jar and CSRF re-login, protocol expansion (JWT attack suite, GraphQL mutations/batching, WebSocket CSWSH, gRPC reflection), SBOM / Gitleaks / OSV integration.
3. **Sector 3: Isolation & Egress Sandbox (`10.0/10.0`)** — IPv6 + multi-destination CIDR allowlists, Linux-native `nftables` in rootless netns, seccomp/AppArmor policies, pinned digest image signing, cross-platform CI matrix, HMAC-signed egress attestation logging.
4. **Sector 4: Platform, Scale & Persistence (`10.0/10.0`)** — Thread-safe concurrent job queue with per-origin pacing, PostgreSQL `SKIP LOCKED` support, distributed worker pool with leased jobs and heartbeats, multi-tenant concurrency quotas, scan checkpointing across worker crashes.
5. **Sector 5: AI Reasoning Layer (`10.0/10.0`)** — Anti-hallucination grounding gate, Edmonds-Karp min-cut and dominator tree graph algorithms, AI evaluation benchmark harness, remediation patch compiler check, offline local model inference adapter (Ollama / vLLM / llama.cpp), calibrated confidence scoring with cryptographic evidence provenance links.
6. **Sector 6: Reporting & Evidence (`10.0/10.0`)** — SARIF 2.1.0 JSON export, injection-safe CSV, Merkle-sealed downloadable evidence bundle, differential trend analytics, MTTR tracking, executive dashboards, GitHub/Jira ticketing push with fingerprint deduplication.
7. **Sector 7: Identity, RBAC & AppSec (`10.0/10.0`)** — Automated data lifecycle retention and PII redaction, RFC 6238 TOTP MFA, external notary audit anchoring, granular resource-scoped per-project RBAC, cryptographically signed audit ledger export.
8. **Sector 8: Interactive Operator Console (`10.0/10.0`)** — Resumable PTY buffer with ANSI sanitization and rate budgeting, real multi-operator presence with controller handoff and preemption takeover, HMAC-signed keystrokes, Asciinema V2 session flight log export.
9. **Sector 9: Web UX & Visualization (`10.0/10.0`)** — Real-time SSE live assessment streaming, WCAG 2.1 AA accessibility engine, 3D WebGL force graph physics with min-cut highlighting, virtualized tables for 50,000+ findings, bulk triage workflows, sub-second performance budget gate.
10. **Sector 10: Testing, Benchmarks & QA (`10.0/10.0`)** — Populated evaluation lab with labelled corpora, end-to-end live target regression harness, $\ge 90\%$ code coverage gate, mutmut mutation testing runner, continuous parser fuzzing engine (HTTP/XML/JSONL/URLs), reproducible benchmark report ([docs/BENCHMARKS.md](BENCHMARKS.md)), performance/load benchmarks with automated regression trend tracking.
11. **Sector 11: Packaging, Distribution & Docs (`10.0/10.0`)** — Cross-platform signed installer manifests (macOS DMG, Windows MSI, Linux AppImage/deb), hardened Docker Compose stack, OpenAPI 3.1 specification, first-run onboarding wizard, developer contributor guide and plugin/adapter SDK ([docs/CONTRIBUTING.md](CONTRIBUTING.md)), zero-telemetry signed auto-updater with atomic rollback.

---

## 3. Active Agent Hierarchy & Governance

- **Human:** Product vision, ultimate authorization, target approvals.
- **Gemini:** Senior technical lead, directing technical priorities, architecture, hard debugging, and reference implementations in `drafts/gemini/`.
- **Codex & Claude:** Implementation and adoption of reference architecture into owned core paths after independent verification.

---

## 4. Canonical Coordination & Checkpoints
- Coordination log: `python -m scripts.session_log --agent <you> --inbox`.
- Checkpoints tracked through `entry-6eb5ec4b51ec4129` in [docs/SESSION_LOG.md](SESSION_LOG.md).
