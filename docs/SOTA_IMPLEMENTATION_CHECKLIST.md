# SHARAY SOTA Capability Implementation Checklist

This checklist tracks the implementation of all components required to elevate SHARAY from a defensive/offensive detection scanner into a state-of-the-art (SOTA) autonomous validation platform, as formalized in `OSP-ARCH-001` and `OSP-ARCH-002`.

Implementation is executed in strict sequence according to priority and architectural dependencies.

---

## [x] Phase 1: Sprint 1 — Correctness & Deterministic Validation Foundations (P0)

### 1.1 Target Normaliser (A1)
- [x] Create pure, idempotent `TargetNormaliser` module in `packages/security_policies/normalizer.py`.
- [x] Implement URL scheme, port, path, query, and credential stripping.
- [x] Scrub CRLF (`\r\n`), trailing whitespace, zero-width characters (`\u200b`, `\ufeff`), non-breaking spaces, and en-dashes (`\u2013`, `\u2014`).
- [x] Punycode Internationalized Domain Names (IDN) (`idna.encode`).
- [x] Short-circuit literal IPv4 and IPv6 addresses via `ipaddress.ip_address` to bypass unnecessary DNS queries.
- [x] Expand CIDR blocks (e.g. `10.0.0.0/29`) and hyphenated IP ranges (e.g. `192.168.1.1-10`) into discrete target lists.
- [x] Author 30-case comprehensive test fixture suite in `tests/product/test_target_normalizer.py` verifying 100% pass rate.

### 1.2 Typed Resolver Service & Fallback Ladder (A2)
- [x] Implement `ResolverService` with typed error taxonomy: `NXDOMAIN`, `SERVFAIL`, `NODATA`, `FORMERR`, `NO_RESOLVER`, `UDP_BLOCKED`, `DNSSEC_BOGUS`, `SPLIT_HORIZON`.
- [x] Implement fallback ladder: System resolver (`getaddrinfo`) -> DNS over HTTPS (DoH: Cloudflare/Google) -> Last-known-good cache.
- [x] Separate resolve budget from connect budget with configurable jittered backoff.
- [x] Update `resolve_pinned()` in `packages/security_policies/__init__.py` to return typed resolution models.

### 1.3 Per-Target Failure Isolation Guard (A3)
- [x] Update `aegis/worker.py` to catch per-target resolution failures and emit structured `TARGET_UNRESOLVED` records without aborting peer targets.
- [x] Verify that a target list with 1 unresolvable host and N valid hosts scans all N valid targets to completion with 0 run aborts.

### 1.4 Asynchronous Report Pipeline & Subprocess Isolation (J1 & J2)
- [x] Decouple PDF/HTML report rendering from FastAPI request thread: `POST /api/v1/reports/{id}` queues background job and returns `202 Accepted {job_id}`.
- [x] Add `GET /api/v1/reports/jobs/{job_id}` status polling and `GET /api/v1/reports/jobs/{job_id}/download` signed URL stream.
- [x] Render report inside isolated sandboxed subprocess with hard resident-memory limit (512 MB) and wall-clock SIGKILL timeout.
- [x] Add per-report idempotency lock (J5) to prevent concurrent render stampedes.
- [x] Implement startup canary health check verifying ReportLab renderer binary presence.

### 1.5 Finding State Machine & 3x Deterministic Reproducer (C1, C2, C3)
- [x] Enforce 6-state finding machine in `aegis/worker.py` and `aegis/schemas.py`: `OBSERVED -> CANDIDATE -> REPRODUCED -> EXPLOITED -> CHAINED -> VERIFIED`.
- [x] Implement 3x byte-identical request reproducer: 3 identical probe replays required to transition `CANDIDATE -> REPRODUCED`.
- [x] Implement negative control probe: re-probe parameter with benign token; if alert fires on negative control, demote finding immediately as false positive.
- [x] Differential oracle verification (C4): compare status, length, timing distribution, reflection, and token diff.

### 1.6 Hermetic Evaluation Lab Fixtures (K1 & K2)
- [x] Stand up containerized test lab fixtures (DVWA, OWASP Juice Shop, vulnerable API) in `tests/fixtures/eval_lab/`.
- [x] Author ground-truth vulnerability catalog JSON manifest for automated regression scoring.
- [x] Automated evaluation metrics runner (K3) asserting Precision >= 95% and FPR <= 5%.

---

## [x] Phase 2: Sprint 2 — Interactive Console & Headless Driver (P1)

### 2.1 Operator Console Three-State Ownership Lock (D2)
- [x] Implement `AGENT_OWNED | HUMAN_OWNED | SHARED` state machine in `aegis/interactive.py`.
- [x] Enforce instant human preemption: human input immediately locks out agent writes.
- [x] Agent re-acquires lock only upon explicit human release or inactivity timeout.

### 2.2 Pre-Notification Active Exploit Gate (D4)
- [x] Build modal countdown dialog in `apps/web/app/terminal.tsx` before any active exploit attempt.
- [x] Operator confirm button and emergency abort control with auto-proceed timeout option.

### 2.3 Headless Chromium / Playwright Driver (I3)
- [x] Deploy containerized headless Chromium / Playwright driver in `services/scanner_worker/`.
- [x] Client-side JavaScript execution, single-page application (SPA) dynamic route discovery.
- [x] DOM-based XSS validation via `window.alert` interception and DOM sink tracking.

### 2.4 Route Discovery & Schema Ingestion (B4)
- [x] Ingest OpenAPI / Swagger, GraphQL introspection, and WSDL into crawler.
- [x] Compare schema coverage against dynamic spider coverage.

### 2.5 Business-Logic & Authorization Matrix Probes (B5)
- [x] Dual-identity session context switching (User A vs User B).
- [x] Automated IDOR and privilege escalation sweeps.

---

## [x] Phase 3: Sprint 3 — Attack Graph Chaining & Deterministic Payload Forge (P0/P1)

### 3.1 Formal AND/OR Attack Graph & Exploit Chaining (F1–F7)
- [x] Upgrade `services/ai_analysis_worker/reasoning.py` to formal AND/OR attack graph (AND = exploits, OR = conditions).
- [x] Separate graph builders for Web, Network, Cloud IAM, and Containers (F2).
- [x] Noisy-AND / Noisy-OR probabilistic confidence propagation (F5).
- [x] Automated sequential cold-replay runner (F7): replay multi-step chains from clean target state.
- [x] Breakpoint analysis (F8): min-cut algorithm identifying highest-leverage single remediation edge.

### 3.2 Deterministic AST Payload Forge & WAF Mutations (E1–E3)
- [x] Context-free grammars for SQLi, Command Injection, SSRF, SSTI, XXE (E1).
- [x] Syntax-preserving AST mutation matrices: comment splicing (`/*!50000SELECT*/`), Unicode/hex encoding, whitespace substitution (E2).
- [x] Automated WAF vendor fingerprinting (Cloudflare, AWS WAF, ModSecurity) selecting targeted transform profiles (E3).
- [x] Deterministic PRNG seed logging (E5) ensuring 100% reproducible fuzzing sequences.

### 3.3 Safe-Gated Post-Exploitation & Pivoting (H1–H6)
- [x] Quarantined behind explicit operator arming switch (`ALLOW_ACTIVE_EXPLOIT`).
- [x] Automated payload stagers and reverse shell PTY upgrade (H1, H2).
- [x] Dynamic SOCKS proxy pivot creation with automatic route injection into attack graph (H4).
- [x] Target persistence inventory and automated 1-click clean exit teardown (H5).

---

## [x] Phase 4: Sprint 4 — Distilled Reasoning Model & Verifier Gates (P2)

### 4.1 Distilled Code Reasoning Engine (G2 & G3)
- [x] Parameter-efficient fine-tuned / distilled code model (e.g. Qwen 2.5 Coder 7B / Llama 3.3 8B) with constrained grammar decoding.
- [x] AutoPyVerifier pattern: synthesized Python verification scripts executed in isolated sandboxes to confirm hypotheses.

### 4.2 Consensus Voting, Best-of-N Search & Escalation Gate (G4, G5, G6)
- [x] Temperature-sampled candidate reasoning trajectories scored by executable verifiers.
- [x] Entropy gate: high-variance cases escalate automatically to frontier APIs (Gemini 1.5 Pro / Claude 3.5 Sonnet).
- [x] Cache resolved trajectories for model retraining.

### 4.3 Continuous Improvement from Operator Feedback (G7)
- [x] Ingest terminal keystrokes and manual overrides from flight logs into evaluation dataset.
- [x] Automated retraining pipeline gated on frozen evaluation benchmarks.

---

## [x] Phase 5: Sprint 5 — Multi-Engine Offensive Penetration Testing Suite (P0/P1)

### 5.1 Request Body & Multi-Method Fuzzing Engine (M1)
- [x] Implement `BodyFuzzer` in `packages/scanner_adapters/integrations/body_fuzzer.py` supporting `application/x-www-form-urlencoded`, `multipart/form-data`, and `application/json`.
- [x] Ingest HTML forms discovered by `crawler.py` and auto-generate parameter fuzzing sets for both query parameters and body values.
- [x] Implement HTTP verb tampering matrix (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `TRACE`) across all discovered endpoints to discover hidden administrative handlers and bypass verb-level access controls.

### 5.2 Blind & Time-Based Injection Oracles (M2)
- [x] Implement statistical time-based blind SQLi oracle with baseline jitter calibration (3 baseline measurements: $\mu, \sigma$; trigger condition $t_{probe} \ge \mu + 3\sigma + 4.5\text{s}$) across PostgreSQL, MySQL, and MSSQL (SQLite dropped: its only time vector is an unbounded RANDOMBLOB memory bomb).
- [x] Implement time-based OS command injection oracle (evaluating `; sleep 5`, `| sleep 5`, `$(sleep 5)`).
- [x] Implement boolean-based blind differential oracle comparing token count, response length, and DOM similarity between truthy and falsy expressions (`AND 1=1` vs `AND 1=2`).

### 5.3 Server-Side Template Injection (SSTI) & NoSQL Injection (M3)
- [x] Implement mathematical polyglot canary injection (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`) detecting unescaped arithmetic evaluation (`49`).
- [x] Engine-specific SSTI fingerprinting (Jinja2, Twig, Smarty, SpringEL, Freemarker).
- [x] MongoDB/NoSQL query operator and parameter injection (`{"$ne": null}`, `[$regex]=.*`).

---

## [x] Phase 6: Sprint 6 — Deep Protocol, Authentication & Out-of-Band (OOB) Telemetry Engine (P1)

### 6.1 Authenticated Session Engine & Multi-Role Access Matrix (N1)
- [x] Support `auth_config` in `Target.scope`: session cookie jars, rotating Bearer tokens, custom API headers (`X-API-Key`), and automated form-based login (`login_url`, `username`, `password`, `success_indicator`).
- [x] Automatic session health check and transparent re-authentication on 401/403 or redirect to login.
- [x] Simultaneous multi-role access evaluation (Identity A vs Identity B vs Unauthenticated) for automated Broken Object Level Authorization (BOLA/IDOR) and horizontal/vertical privilege escalation sweeps.

### 6.2 Out-of-Band (OOB) Telemetry Verification (N2)
- [x] Cryptographic OOB token generator (`sharay-{finding_id[:8]}-{timestamp}.oob.domain.invalid`).
- [x] Embed unique correlation tokens into SSRF, blind XXE, and blind command execution probes.
- [x] Correlate asynchronous DNS queries and HTTP callbacks to deliver 100% false-positive-free vulnerability confirmations.

### 6.3 Modern API Security: GraphQL & WebSockets (N3)
- [x] GraphQL security analyzer: introspection query verification (`__schema`), batch query amplification denial-of-service, and mutation parameter fuzzing.
- [x] WebSocket handshake and framing inspector: test for missing `Origin` header validation and Cross-Site WebSocket Hijacking (CSWSH).

### 6.4 Specialized Scanner Integrations (N4)
- [x] High-speed wordlist directory and hidden API discovery integration (`ffuf` / `feroxbuster`).
- [x] Bounded non-destructive SQLMap auxiliary integration (`--batch --dbs --level=2`) for confirmed SQLi parameter proof.


