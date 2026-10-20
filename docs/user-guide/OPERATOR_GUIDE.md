# SHARAY Production Operator & Administrator Guide

**Version:** 2.0.0  
**Classification:** Operational Security & Architecture Documentation  
**Audience:** Security Engineers, Penetration Testers, DevSecOps Administrators, Compliance Officers

---

## 1. Architectural Overview & Security Guarantees

SHARAY is a local-first, zero-trust autonomous vulnerability assessment and offensive security automation platform. It is engineered from first principles around five immutable engineering invariants:

1. **Zero Silent Scope Expansion:** Every target destination is pinned by CIDR allowlists, DNS resolve pinning (`resolve_pinned`), and strict egress sandboxing (`nftables`, `iptables`, and macOS Seatbelt).
2. **Deterministic Courtroom-Grade Evidence:** Every finding must be verified by real protocol execution or AutoPyVerifier scripts. Keystrokes, raw request/response captures, and operator terminal logs are cryptographically sealed with HMAC-SHA256 and Merkle trees.
3. **Defense-in-Depth Isolation:** Containerized tool runners run rootless under unprivileged user contexts (`UID 10001`), with `cap_drop: ALL` and restricted cgroups v2 resource ceilings.
4. **Anti-Hallucination AI Grounding:** AI analysis engines are barred from hypothesizing unverified vulnerabilities. All narratives must map directly to sha256-hashed raw network evidence.
5. **Zero Telemetry & Local Data Sovereignty:** Assessments, credentials, and logs never phone home. Auto-updates and vulnerability feeds are verified offline against signed release manifests.

```
                      +---------------------------------------+
                      |       SHARAY Web UI & Console         |
                      |  (WebGL 3D Graph / Virtualized Table) |
                      +-------------------+-------------------+
                                          | REST / SSE / WS
                                          v
+---------------------+       +-----------------------+       +---------------------+
| PostgreSQL / SQLite | <---> |   SHARAY FastAPI Core | <---> | Distributed Workers |
|   (Audit Ledger)    |       |   (RBAC / Scope Gate) |       |  (Rootless Sandbox) |
+---------------------+       +-----------+-----------+       +---------------------+
                                          |
                                          v
                              +-----------------------+
                              | Egress Sandbox Engine |
                              | (CIDR Lock / Seatbelt)|
                              +-----------+-----------+
                                          |
                                          v
                                 Target Environment
```

---

## 2. Deployment Architectures

### 2.1 Native macOS Desktop Application
For individual security practitioners and local workstation audits:
- Launch `SHARAY.app` or run `./SHARAY.command` in the terminal.
- Listens exclusively on loopback `127.0.0.1:8000`.
- Utilizes Apple Silicon Seatbelt sandboxing profile (`/usr/bin/sandbox-exec`) to confine process boundaries.

### 2.2 Production Docker Compose Stack
For enterprise and team deployments requiring centralized persistence and high-throughput scanning farms:

```bash
# Launch the complete self-hosted stack
docker compose up -d
```

The stack provisions:
- **`db`**: Hardened PostgreSQL 16 Alpine container attached exclusively to `sharay_internal` network with no external internet egress.
- **`server`**: Rootless unprivileged web API server exporting port `8000` with automated healthchecks.
- **`worker`**: Background scanning node with dropped capabilities (`cap_drop: ALL`) and pinned network egress.

---

## 3. First-Run Guided Onboarding Wizard

When starting a fresh SHARAY installation, the web console guides the operator through a 5-stage setup sequence:

1. **Welcome Stage:** Displays architecture invariants and prompts initialization.
2. **Owner Account Creation:** Generates the initial administrative owner credential ($\ge 12$ characters) and sets up optional RFC 6238 TOTP MFA.
3. **Container Engine Verification:** Probes for rootless `podman` or `docker` with cgroups v2 support and non-root execution capabilities.
4. **Egress Firewall Attestation:** Fires synthetic non-whitelisted probe packets to confirm that the host or container firewall drops unauthorized traffic fail-closed.
5. **Seed Assessment:** Spawns a synthetic or lab assessment to verify database persistence, finding ingestion, and reporting pipelines.

Once completed, the onboarding state locks and unlocks the full operator workspace.

---

## 4. Interactive Operator Console & Collaboration

The interactive console provides an egress-confined pseudo-terminal (PTY) interface for hands-on penetration testing.

### 4.1 Resumable PTY Buffer & ANSI Sanitization
- Terminal streams are buffered in ring-buffers with byte offsets.
- Client disconnections automatically preserve terminal state and resume without stream loss upon reconnect.
- Output streams pass through a strict binary-safe ANSI parser that strips terminal escape injection vulnerabilities (e.g., OSC title changes, DCS device controls, APC/PM macro payloads).

### 4.2 Multi-Operator Collaboration & Takeover
Multiple operators can collaborate in real time on a live target session:
- **Primary Controller:** Has write authority to send keystrokes to the target PTY.
- **Secondary Viewers:** Receive synchronized real-time terminal output streams.
- **Voluntary Transfer:** Primary controller can hand off control via `POST /api/v1/interactive/sessions/{id}/collaborate/transfer`.
- **Administrative Takeover:** Security administrators can override and assume primary control with required audit justification via `POST /api/v1/interactive/sessions/{id}/collaborate/takeover`.
- **Signed Per-Keystroke Attribution:** Every input keystroke is recorded with operator ID, timestamp, and HMAC-SHA256 signature in the flight ledger.

### 4.3 Asciinema V2 Replay & Courtroom Evidence
Sessions can be exported at any time into standard Asciinema V2 JSONL format:
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  https://localhost:8000/api/v1/interactive/sessions/<SESSION_ID>/asciinema \
  -o session_evidence.cast
```
The resulting `.cast` file is deterministically replayable in standard terminal players (`asciinema play`) or browser web widgets.

---

## 5. Web UX, 3D Topology & Bulk Triage

### 5.1 3D WebGL Force-Directed Attack Graph
- Navigates complex attack surfaces, network perimeters, and host relationships in 3-dimensional space.
- Implements spatial velocity physics, charge repulsion, and link spring forces.
- Highlights min-cut attack path breakpoints identified by Edmonds-Karp and dominator tree graph algorithms.

### 5.2 Virtualized Finding Catalog
- Capable of rendering catalogs exceeding 100,000 findings with constant DOM memory usage ($O(1)$).
- Provides instant multi-field sorting, regex search, and severity filtering.
- Supports bulk triage status updates (`OPEN`, `IN_REVIEW`, `CONFIRMED`, `RESOLVED`, `FALSE_POSITIVE`) with audit logging.

---

## 6. Zero-Telemetry Auto-Updates & Security Maintenance

SHARAY updates its core binary and vulnerability detection packs without transmitting telemetry:
1. **Feed Check:** The operator queries `POST /api/v1/system/update/check` with a downloaded release manifest.
2. **Signature Attestation:** The update manager verifies the publisher's digital signature against embedded notary keys.
3. **Atomic Swap:** Upon approval, the binary is staged into `<bin>.update.tmp`, backed up to `<bin>.bak`, and atomically replaced via `os.replace`.
4. **Automated Rollback:** If the replacement binary fails integrity or startup validation, the previous version is restored instantly.
