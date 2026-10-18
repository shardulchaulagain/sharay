# SHARAY Capabilities Roadmap & Implementation Checklist

This checklist tracks the implementation of remaining platform capabilities from the grand product specification and user requirements. Items are ordered according to the agreed execution plan:
1. **Phase 1 (Item 2)**: Scan Customization Controls in the Web UI.
2. **Phase 2 (Item 1)**: Operator Takeover & Interactive Web Terminal.
3. **Phase 3 (Item 3)**: Additional Containerized Live Tools (Nmap, ZAP, Metasploit).
4. **Phase 4 (Item 4)**: Live AI Verification & Adversarial Reasoning Layer.
5. **Phase 5 (Item 5)**: Enterprise / Distributed Server Backend.

---

## [x] Phase 1 (Item 2): Scan Customization Controls in the Web UI

Allow security operators to visually configure scan profiles, depth, aggression, and specific tools before launching an assessment.

- [x] **1.1 UI Modal / Drawer Component (`apps/web/`)**:
  - [x] Add "Scan Strategy & Customization Controls" interactive panel to Launch view (`apps/web/app/projects.tsx`).
  - [x] Mode selector: `Passive` (recon & headers only), `Standard` (headers + crawler), `Adaptive` (context-aware Nuclei), `Aggressive` (all checks + deep differential).
  - [x] Crawler Depth slider (1 to 5 levels, live label display).
  - [x] Request Rate Limit slider (10 to 300 req/sec, live value display).
  - [x] Nuclei Template Tag filter input (e.g. `cve,misconfig,panel,tech`).
  - [x] Tool enable/disable toggles (Web Spider, Sensitive File Hunter, Differential Tester, Multi-Endpoint Nuclei).
- [x] **1.2 Frontend-to-Backend API Hookup**:
  - [x] Pass `ScanConfig` payload (`mode`, `tags`, `rate`, `depth`, `tools`) from `Launch` component.
  - [x] Verified `POST /api/v1/assessments` stores `scan_config` into `scope_snapshot` and worker passes options to `scan_comprehensive` and `scan_live_nuclei`.
- [x] **1.3 Assessment History & Details View**:
  - [x] Display exact scan configuration (Mode, Crawler Depth, Rate Cap, Target Tags) in `AssessmentDetail` configuration panel (`apps/web/app/assessments.tsx`).
  - [x] Display crawler discovery facts, endpoints, parameters, and sensitive file findings in check coverage and findings.
- [x] **1.4 Tests & Verification**:
  - [x] Next.js static build compiled successfully (0 errors).
  - [x] 26 frontend tests and 0 lint/accessibility errors in `npm test` and `npm run lint`.
  - [x] All 525 Python tests and 4 engineering gates passed (`check.py --run-gates` exit 0).

---

## [x] Phase 2 (Item 1): Operator Takeover & Interactive Web Terminal

Provide security operators with an in-browser interactive terminal to inspect targets, verify vulnerabilities non-destructively, and take over validated sessions.

- [x] **2.1 Backend Interactive Session Engine (`aegis/interactive.py`, `aegis/api.py`)**:
  - [x] Implement pseudo-terminal (PTY) session manager in Python (`pty.openpty()`, non-blocking I/O, `fcntl.ioctl` window resizing).
  - [x] High-performance HTTP chunked streaming route (`GET /api/v1/interactive/sessions/{id}/stream`) and interactive input handler (`POST .../input`) with token authentication and organization-scoped authorization.
  - [x] Enforce container isolation: interactive diagnostic shells spawn bounded to single-destination IP pinning and egress restriction.
  - [x] Session timeout, non-blocking safe process teardown (closing master fd, SIGHUP, WNOHANG waitpid loop), and immutable keystroke/output flight recorder.
- [x] **2.2 Frontend Terminal Component (`apps/web/app/terminal.tsx`, `apps/web/app/projects.tsx`, `apps/web/app/globals.css`)**:
  - [x] Built `OperatorTerminal` React component with live HTTP stream reader, keyboard event handling (Enter, Backspace, Ctrl+C, Ctrl+D, Ctrl+L, Arrow keys).
  - [x] "Takeover Console" action button on authorized targets in Project Workspace.
  - [x] Resizable/maximizable overlay window displaying live monospace terminal stream.
  - [x] Connection status indicator (pulsing green / red dot), clear display, and emergency "Terminate Session" control.
- [x] **2.3 Verification & Tests**:
  - [x] Unit test suite in `tests/integration/test_interactive.py` passing in 0.17s (`test_session_lifecycle_and_pty_io`, `test_unauthorized_org_cannot_access_session`).
  - [x] Next.js static production build verified (`npm run build` exit 0).
  - [x] All 26 frontend tests passed (`npm test` exit 0).
  - [x] All 4 engineering gates passed (`check.py --run-gates` exit 0).

---

## [x] Phase 3 (Item 3): Additional Containerized Live Tools (Nmap, ZAP, Metasploit)

Integrate the remaining industry-standard scanners into the live container runner alongside Nuclei.

- [x] **3.1 Live Nmap Runner (`scan_live_nmap`)**:
  - [x] Containerized runner executing `nmap` with `-sT -Pn -n` against pinned target IP.
  - [x] Strict XML output parsing and integration with `TargetIntelligence` (feeding discovered open ports to crawler and differential tester).
- [x] **3.2 Live OWASP ZAP Runner (`scan_live_zap`)**:
  - [x] Headless ZAP daemon / zap-baseline scanner over single-destination egress firewall.
  - [x] Structured Automation Framework plan generation and passive alert parsing.
  - [x] Normalization of ZAP alerts to unified `Finding` model via `normalize_parsed_finding("zap", ...)`.
- [x] **3.3 Metasploit Auxiliary Validation Runner (`scan_live_metasploit_auxiliary`)**:
  - [x] Execute non-destructive auxiliary verification modules (`auxiliary/scanner/...`) for exact CVE confirmation.
  - [x] Strict deny-by-default for destructive exploitation modules (raises `ValueError` for non-auxiliary modules).
  - [x] Normalization of auxiliary outcomes to unified `Finding` model via `normalize_parsed_finding("metasploit", ...)`.
- [x] **3.4 Comprehensive Pipeline Unification (`scan_comprehensive`)**:
  - [x] 10-stage unified pipeline executing tools in order: TLS Inspection -> Asset Inventory -> Port & Service (Nmap) -> HTTP Headers -> Web Crawler -> Target Intelligence Synthesis -> Differential Testing -> Nuclei CVE Scanner -> OWASP ZAP -> Metasploit Auxiliary.
  - [x] UI tool selection checkboxes added to Launch component for Nmap, ZAP, and Metasploit.
  - [x] Comprehensive integration test verified in `tests/integration/test_comprehensive_pipeline.py`.
  - [x] All 4 engineering gates passed exit 0.

---

## [x] Phase 4 (Item 4): Live AI Verification & Adversarial Reasoning Layer

Connect live LLM providers for intelligent vulnerability verification, hypothesis generation, and false positive reduction.

- [x] **4.1 AI Provider Integration (`services/ai_analysis_worker/vendors.py`, `providers.py`)**:
  - [x] Switchable providers: Google Gemini (`google`), Anthropic Claude (`anthropic`), OpenAI (`openai`).
  - [x] Hermetic transport over standard HTTPS using `urllib` with zero third-party dependencies.
  - [x] Strict token redaction pipeline: authorization headers, cookies, and target secrets are stripped (`[REDACTED]`) before prompting external models.
- [x] **4.2 Adversarial Attack Graph Modeling (`services/ai_analysis_worker/reasoning.py`)**:
  - [x] Directed acyclic graph (`AttackGraph`, `AttackNode`, `AttackEdge`) ingesting assets, ports, crawled endpoints, parameters, and findings.
  - [x] Automated discovery and prioritization of multi-step exploit paths.
  - [x] Automated formulation of bounded non-destructive test hypotheses citing specific observation references.
- [x] **4.3 Automated Finding Verification & Confidence Scoring**:
  - [x] `score_finding_adversarially`: produces calibrated confidence (`high`, `medium`, `low`), false-positive risk metrics, and explainability narratives.
  - [x] Multi-agent challenge engine (`ChallengeVerdict`, `apply_adversarial_challenge`) and token accounting in `services/ai_analysis_worker/verifier.py`.
  - [x] Verification unit test suite in `tests/integration/test_ai_reasoning.py` passing 100%.

---

## [x] Phase 5 (Item 5): Enterprise / Distributed Server Backend

Scale SHARAY from a local desktop application to a distributed enterprise platform.

- [x] **5.1 Database & Queue Migration (`aegis/config.py`, `aegis/database.py`)**:
  - [x] PostgreSQL database support with production connection pooling (`pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`) alongside local SQLite WAL mode via `SHARAY_DATABASE_URL`.
  - [x] Alembic forward migrations for database upgrades.
  - [x] Distributed queue architecture supporting Celery/Redis workers via decoupled worker execution profiles.
- [x] **5.2 Evidence Storage (`aegis/storage.py`)**:
  - [x] Content-addressed evidence storage engine (`EvidenceStore`, `LocalEvidenceStore`, `S3EvidenceStore`).
  - [x] S3/MinIO compatible object store for raw HTTP traces, PCAPs, and screenshot artifacts.
  - [x] SHA-256 fingerprint verification and isolated metadata logging (`.meta.json`).
  - [x] Unit test suite in `tests/integration/test_storage.py` passing 100%.
- [x] **5.3 Enterprise Governance**:
  - [x] Multi-tenant organization hierarchies and role-based access control (`owner`, `security_administrator`, `operator`, `viewer`) enforced at API and database boundaries.
  - [x] Granular workspace permissions, immutable audit logging, and cryptographic scope authorization gating.

---

## [x] Phase 6: Multi-Engine Offensive Penetration Testing & Active Exploitation Suite

Scale SHARAY's scanning engine from passive/semi-active HTTP inspection into a comprehensive automated penetration testing suite.

- [x] **6.1 Request Body & Multi-Method Fuzzing Engine (`body_fuzzer.py`)**:
  - [x] Implement `BodyFuzzer` in `packages/scanner_adapters/integrations/body_fuzzer.py` supporting `application/x-www-form-urlencoded`, `multipart/form-data`, and `application/json`.
  - [x] Automatic form ingestion: convert all `<form>` objects discovered by `crawler.py` into executable test cases fuzzing both URL queries and POST body values.
  - [x] HTTP method tampering matrix (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `TRACE`) across all discovered endpoints to discover hidden administrative handlers and bypass method-level access controls.
- [x] **6.2 Blind & Time-Based Injection Oracles**:
  - [x] Statistical time-based blind SQLi oracle with baseline jitter calibration (3 baseline measurements: $\mu, \sigma$; trigger condition $t_{probe} \ge \mu + 3\sigma + 4.5\text{s}$) across PostgreSQL, MySQL, and MSSQL.
  - [x] Time-based OS command injection oracle (evaluating `; sleep 5`, `| sleep 5`, `$(sleep 5)`).
  - [x] Boolean-based blind differential oracle comparing token count, response length, and DOM similarity between truthy and falsy expressions (`AND 1=1` vs `AND 1=2`).
- [x] **6.3 Server-Side Template Injection (SSTI) & NoSQL Injection**:
  - [x] Mathematical polyglot canary injection (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`) detecting unescaped arithmetic evaluation (`49`).
  - [x] Engine-specific SSTI fingerprinting (Jinja2, Twig, Smarty, SpringEL, Freemarker).
  - [x] MongoDB/NoSQL query operator and parameter injection (`{"$ne": null}`, `[$regex]=.*`).

---

## [x] Phase 7: Deep Protocol, Authentication & Out-of-Band (OOB) Telemetry Engine

Equip SHARAY with authenticated multi-role assessment capabilities, out-of-band telemetry verification, and modern API protocol analyzers.

- [x] **7.1 Authenticated Session Engine & Multi-Role Access Matrix**:
  - [x] Support `auth_config` in `Target.scope`: session cookie jars, rotating Bearer tokens, custom API headers (`X-API-Key`), and automated form-based login (`login_url`, `username`, `password`, `success_indicator`).
  - [x] Automatic session health check and transparent re-authentication on 401/403 or redirect to login.
  - [x] Simultaneous multi-role access evaluation (Identity A vs Identity B vs Unauthenticated) for automated Broken Object Level Authorization (BOLA/IDOR) and horizontal/vertical privilege escalation sweeps.
- [x] **7.2 Out-of-Band (OOB) Telemetry Verification**:
  - [x] Cryptographic OOB token generator (`sharay-{finding_id[:8]}-{timestamp}.oob.domain.invalid`).
  - [x] Embed unique correlation tokens into SSRF, blind XXE, and blind command execution probes.
  - [x] Correlate asynchronous DNS queries and HTTP callbacks to deliver 100% false-positive-free vulnerability confirmations.
- [x] **7.3 Modern API Security: GraphQL & WebSockets**:
  - [x] GraphQL security analyzer: introspection query verification (`__schema`), batch query amplification denial-of-service, and mutation parameter fuzzing.
  - [x] WebSocket handshake and framing inspector: test for missing `Origin` header validation and Cross-Site WebSocket Hijacking (CSWSH).
- [x] **7.4 Specialized Scanner Integrations**:
  - [x] High-speed wordlist directory and hidden API discovery integration (`ffuf` / `feroxbuster`).
  - [x] Bounded non-destructive SQLMap auxiliary integration (`--batch --dbs --level=2`) for confirmed SQLi parameter proof.


