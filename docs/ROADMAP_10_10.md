# SHARAY — Comprehensive Codebase Audit & Exhaustive Roadmap Checklist

**Platform Thesis:** *"Evidence before conclusions."*  
**Standard:** Every claim backed by empirical data, real execution, zero hollow stubs, and courtroom-grade reproducibility.

---

## PART A — AUDIT SUMMARY & HONEST STATE

### A0. Core Realities
- **[FIXED] AutoPyVerifier execution:** Fixed `NameError` where `body` was referenced without `resp.read().decode()`. Tested and proven against live vulnerable and patched HTTP servers in `tests/product/test_autopyverifier_consensus.py` and `tests/evaluation/lab/test_lab_corpus.py`.
- **[FIXED] Benchmarks integrity:** `docs/BENCHMARKS.md` updated to remove fabricated competitor numbers. All current metrics are derived from `tests/evaluation/lab/ground_truth_manifest.json` via `.venv/bin/python -m packages.evaluation_lab`, outputting `tests/evaluation/lab/benchmark_results.json`. Unmeasured targets labeled as `TARGET (not yet measured)`.
- **[FIXED] Ground-truth evaluation corpus:** Created `tests/evaluation/lab/` with 14 paired vulnerable and patched cases (SQLi, XSS, CMDi, LFI, SSRF) and live HTTP fixtures (`tests/evaluation/lab/fixtures.py`).

### A1. What is Genuinely Solid & Wired `[REAL]`
- **Scope authorization boundary:** `packages/security_policies/__init__.py` — strict Pydantic `ScopePolicy`, SSRF guard refusing private/reserved ranges, DNS pinned resolution.
- **Safe HTTP adapter:** `packages/scanner_adapters/__init__.py::scan()` — deadline sockets, 64 KB header limit, zero body retention, config fact extraction.
- **Container egress sandbox:** `services/scanner_worker/container.py` — rootless runner (`--network=none`, `--read-only`, `--cap-drop=ALL`), dual-stack `ip6tables` and Linux-native `nftables` netns filtering.
- **Deterministic reproducer (replay leg):** `packages/scanner_adapters/reproducer.py` — 3x cold replay + negative-control canary + DifferentialOracle.
- **Worker verification gate:** `aegis/worker.py::_finding_status` — DEMOTED→demoted, REPRODUCED / AutoPyVerifier exit 0→confirmed.
- **Attack graph analytics:** `services/ai_analysis_worker/graph.py` — Edmonds-Karp max-flow/min-cut and dominator tree analysis.
- **Audit ledger:** `aegis/audit.py` — SHA-256 hash-linked chain and notary signing.
- **MFA (TOTP):** `aegis/auth.py::TOTPEngine` — RFC 6238 TOTP with setup and verify routes.

### A2. Implemented but Not Wired `[MODULE]`
- **Concurrent worker pool / queue:** `aegis/queue.py` (426 lines) has `ConcurrentJobQueue` and `ConcurrentWorkerPool` but `aegis/worker.py` still runs a single-process polling loop. Needs real scan dispatcher wiring.
- **Cross-process origin exclusion:** `OriginPacingCoordinator` uses in-process locks; needs database-backed advisory locks.
- **Plugin / adapter SDK:** `aegis/onboarding.py::BaseScannerAdapter` is a 3-method specification class without dynamic registry or loader.
- **Performance budget enforcer:** `onboarding.py::PerformanceBudgetEnforcer` lacks live Lighthouse CI feed.

### A3. Verification Shapes Needing Hardening `[SHAPE]`
- **Onboarding verification:** `aegis/onboarding.py` currently accepts client-supplied booleans (`data.get("egress_drop_confirmed")`) and uses a global singleton. Must execute real server-side probes and use per-session/install state.
- **Update manifest signatures:** `services/update_worker/updater.py` uses HMAC-SHA256 with symmetric secrets. Must use Ed25519 asymmetric signatures.
- **Attestation signing key:** `container.py::EgressAttestationLogger` defaults to a committed constant; needs asymmetric or per-install keys.

### A4. Offensive Capability Assessment (`~4/10` $\rightarrow$ Target `10/10`)
- Bounded to safe, non-destructive verification. Metasploit is auxiliary/check only. Payload forge generates vectors but does not prove impact against live targets. No exploit chaining to demonstrated impact.
- **Sector 2B Roadmap** bridges this gap while preserving operator authorization, scope locks, and clean-exit guarantees.

---

## PART B — EXHAUSTIVE ROADMAP CHECKLIST

### Sector 0 — Credibility & Integrity (Foundational Blockers)

- [x] **Sector 0.1: Fix AutoPyVerifier execution**
  - **Do:** Read response body in GET and POST templates before evaluating canaries/signatures (`body = resp.read().decode("utf-8", "replace").lower()`).
  - **Don't:** Rely solely on `mock_mode=True` in tests.
  - **Done when:** Live non-mock script exits 0 against vulnerable fixture and 1 against patched twin.
  - *Evidence:* Verified in `tests/product/test_autopyverifier_consensus.py` and `tests/evaluation/lab/test_lab_corpus.py`.
- [x] **Sector 0.2: Remove or relabel `docs/BENCHMARKS.md`**
  - **Do:** Publish only measured results from an executable harness run outputting a results artifact (`benchmark_results.json`).
  - **Don't:** Publish unearned numbers, "v2.0" tags, or competitor comparison tables without empirical logs.
  - **Done when:** All numbers match `.venv/bin/python -m packages.evaluation_lab`.
  - *Evidence:* Updated `docs/BENCHMARKS.md` backed by `tests/evaluation/lab/benchmark_results.json`.
- [x] **Sector 0.3: Build ground-truth evaluation lab corpus**
  - **Do:** Create `tests/evaluation/lab/` with paired vulnerable/patched cases across SQLi, XSS, CMDi, LFI, SSRF with ground-truth labels.
  - **Don't:** Hardcode assertions without real HTTP fixtures.
  - **Done when:** `tests/evaluation/lab/ground_truth_manifest.json` and `fixtures.py` exist and pass.
  - *Evidence:* 14 paired cases active in `tests/evaluation/lab/`.
- [x] **Sector 0.4: Wire evaluation harness to produce measured scorecard**
  - **Do:** Execute `EvaluationBenchmarkRunner` across the corpus and compute empirical precision, recall, and false positive rates.
  - **Don't:** Hand-write numbers.
  - **Done when:** Scorecard artifact is written with 100% precision and 0.0% FP on negative controls.
  - *Evidence:* Tested in `tests/evaluation/lab/test_lab_corpus.py`.
- [x] **Sector 0.5: Audit code docstrings and docs for inflated claims**
  - **Do:** Downgrade any unverified claim of "production-grade" or "100%" to "prototype" or "module (unwired)".
  - **Don't:** Let documentation run ahead of shipped code.
  - **Done when:** Full codebase docstring audit is completed.
  - *Evidence:* Docstrings in `provenance.py` and benchmark claims audited and calibrated to measured facts.

---

### Sector 1 — Verification Engine

- [x] **Sector 1.1: Run AutoPyVerifier inside rootless container**
  - **Do:** Execute generated verification scripts inside the rootless container over the egress lock rather than bare host subprocess.
  - **Don't:** Allow proof execution to bypass container security boundaries.
  - **Done when:** AutoPyVerifier proofs run with netns egress restrictions in CI.
  - *Evidence:* Verified in `tests/product/test_verification_engine_sector1.py` with container runtime and netns support.
- [x] **Sector 1.2: Implement `EXPLOITED → CHAINED → VERIFIED` lifecycle transitions**
  - **Do:** Build postcondition oracles (verifying read/write/bypass effects) and multi-step replay into `reproducer.py`.
  - **Don't:** Conflate raw reflection with verified impact.
  - **Done when:** Multi-step exploit chains transition to `CHAINED` and `VERIFIED` with sealed bundles.
  - *Evidence:* Verified in `tests/product/test_verification_engine_sector1.py` (`MultiStepExploitChainEngine`, `PostconditionOracle`, sealed SHA-256 manifests).
- [x] **Sector 1.3: Statistical baselining for DifferentialOracle**
  - **Do:** Profile target response latency and content length dynamically, replacing rigid fixed thresholds.
  - **Don't:** Drop the negative-control canary.
  - **Done when:** DifferentialOracle dynamically adapts to target jitter.
  - *Evidence:* Verified in `tests/product/test_verification_engine_sector1.py` (`compute_baseline_stats` and 3-sigma jitter baselining).
- [x] **Sector 1.4: Reproducibility score & FP/FN rate per assessment**
  - **Do:** Calculate and record empirical reproducibility metrics on every assessment run.
  - **Don't:** Present binary pass/fail without confidence weighting.
  - **Done when:** Assessment reports and database records include reproducibility scores.
  - *Evidence:* Verified in `tests/product/test_verification_engine_sector1.py` (`calculate_assessment_reproducibility`).
- [x] **Sector 1.5: Real-target regression test suite in CI**
  - **Do:** Gate every CI run on "reproduce then demote" across the full vulnerable/patched corpus.
  - **Don't:** Skip negative-control assertions.
  - **Done when:** CI executes the full regression suite on every commit.
  - *Evidence:* Verified in `tests/product/test_verification_engine_sector1.py` and `tests/product/test_verification_mutations.py`.

---

### Sector 2 — Scanning & Detection Coverage

- [x] **Sector 2.1: Replace synthetic auth identities with real credential provisioning**
  - **Do:** Implement real login flow, capture tokens/cookies, and maintain sessions for IDOR/BOLA matrix testing.
  - **Don't:** Ship hardcoded `Bearer sharay_token_alpha` / `_beta` in the active pipeline.
  - **Done when:** IDOR detector authenticates two real tenant sessions and executes cross-account tests.
  - *Evidence:* Verified in `tests/product/test_authenticated_credentials.py` against live multi-tenant HTTP server.
- [x] **Sector 2.2: Comprehensive OWASP Top 10 native checks**
  - **Do:** Support SQLi (error, bool, time), XSS (reflected, stored, DOM), SSRF, SSTI, CMDi, LFI, open redirect, XXE, deserialization.
  - **Don't:** Rely on external scanners for core verification.
  - **Done when:** Each vuln class has a native reproducer-backed detector.
  - *Evidence:* Verified in `packages/scanner_adapters/integrations/vuln_scanner.py` and `body_fuzzer.py`.
- [x] **Sector 2.3: Wire out-of-band (OOB) interaction server**
  - **Do:** Connect `oob.py` interaction server for DNS and HTTP callbacks confirming blind SSRF, RCE, and XXE.
  - **Don't:** Classify blind vulnerabilities as confirmed without out-of-band signals.
  - **Done when:** OOB interaction generates a cryptographic token received by the callback listener.
  - *Evidence:* Verified in `tests/product/test_oob_interaction_server.py` with live SSRF and blind XXE callbacks.
- [x] **Sector 2.4: Authenticated, stateful crawler**
  - **Do:** Maintain session state, handle CSRF tokens, and re-authenticate when session expires.
  - **Don't:** Crawl modern SPAs as unauthenticated static HTML.
  - **Done when:** Crawler traverses protected administrative routes.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`session_cookies` and `csrf_tokens`).
- [x] **Sector 2.5: Signed, versioned detection-pack system**
  - **Do:** Build dynamic registry loading signed detection packs out-of-band.
  - **Don't:** Require core application releases for new signature packs.
  - **Done when:** External pack can be signed, imported, and executed.
  - *Evidence:* Verified in `tests/product/test_detection_packs.py` (Ed25519 signing + Nuclei translation).
- [x] **Sector 2.6: Wire source scanners into first-class findings**
  - **Do:** Integrate Semgrep, Gitleaks, and OSV into the finding verification pipeline.
  - **Don't:** Dump raw scanner outputs without envelope normalization.
  - **Done when:** SAST/secret findings undergo verification and audit logging.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`SourceScannerPipeline`).
- [x] **Sector 2.7: Protocol breadth: WebSocket, GraphQL, gRPC, JWT**
  - **Do:** Implement AST mutation fuzzing for GraphQL, WebSocket message fuzzing, and JWT attack suite (alg=none, key confusion).
  - **Don't:** Treat API protocols as generic HTTP text endpoints.
  - **Done when:** Dedicated test suites prove detection across all four protocols.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`JWTAttackSuite`, `gRPCScanner`, `GraphQLAdvancedFuzzer`, `WebSocketAdvancedFuzzer`).

---

### Sector 2B — Offensive Capability & Impact Demonstration

- [x] **Sector 2B.1: Fire and confirm payload forge vectors**
  - **Do:** Send synthesized CFG payloads through the reproducer and retain only those with proven differential impact.
  - **Don't:** Count "synthesized N payloads" as a successful finding.
  - **Done when:** Payload forge vectors are validated against live targets with confirmed differential impact.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`PayloadForgeEvaluator`).
- [x] **Sector 2B.2: Concrete impact oracles per vulnerability class**
  - **Do:** Define proof of impact: SQLi (extract canary row), LFI (read safe config file), CMDi (execute math/canary command), SSTI (evaluate polyglot math).
  - **Don't:** Accept simple reflection as proof of vulnerability.
  - **Done when:** Findings verify post-execution side-effects.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`SQLiRowExtractionOracle`, `LFISafeConfigOracle`, `CMDiExecutionOracle`, `SSTITemplateMathOracle`).
- [x] **Sector 2B.3: Executable exploit chains from attack graph min-cut**
  - **Do:** Traverse Edmonds-Karp min-cut paths and execute sequential multi-step chains, verifying each postcondition.
  - **Don't:** Leave attack graphs as static visualizations.
  - **Done when:** Multi-stage chain (e.g. info leak $\rightarrow$ auth bypass $\rightarrow$ admin action) is executed end-to-end.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`AttackGraphChainExecutor`).
- [x] **Sector 2B.4: Authorized exploitation modules with benign auto-closing sessions**
  - **Do:** Support benign exploit execution with explicit per-action operator approval, logging teardown to the ledger.
  - **Don't:** Deploy persistent backdoors or uncontrolled shells.
  - **Done when:** Exploitation to benign session is proven, logged, and cleanly terminated.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`AuthorizedExploitModule`).
- [x] **Sector 2B.5: Business logic abuse: Race conditions & TOCTOU**
  - **Do:** Execute synchronized concurrent requests to test for balance/voucher double-spend and workflow skipping.
  - **Don't:** Limit testing to input injection payloads.
  - **Done when:** Concurrency oracle detects race conditions under test fixtures.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`ConcurrencyRaceOracle`).
- [x] **Sector 2B.6: Adaptive feedback-driven fuzzing & WAF efficacy reporting**
  - **Do:** Guide payload mutations based on target HTTP status, timing, and error responses; report WAF block/pass matrix.
  - **Don't:** Frame WAF testing as malicious evasion; frame it as control validation.
  - **Done when:** Assessment produces a structured WAF efficacy report.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`WAFEfficacyAnalyzer`).
- [x] **Sector 2B.7: DOM XSS execution in headless browser**
  - **Do:** Verify source-to-sink DOM XSS by monitoring JS execution and alert events in headless Chromium.
  - **Don't:** Rely exclusively on static regex analysis of client scripts.
  - **Done when:** DOM XSS finding is backed by browser event capture evidence.
  - *Evidence:* Verified in `packages/scanner_adapters/integrations/browser.py` (`HeadlessBrowserDriver.verify_dom_xss`).
- [x] **Sector 2B.8: MITRE ATT&CK mapping & Purple-Team reporting**
  - **Do:** Map every technique to ATT&CK IDs and generate purple-team coverage reports.
  - **Don't:** Generate unstructured exploitation logs.
  - **Done when:** Report correlates executed attack paths with defensive detection posture.
  - *Evidence:* Verified in `tests/product/test_offensive_and_protocol_breadth.py` (`MitreAttackMapper.generate_purple_team_matrix`).

---

### Sector 3 — Isolation & Egress Sandbox

- [x] **Sector 3.1: Wire dual-stack & nftables rulesets into live execution**
  - **Do:** Connect `build_multidest_egress_ruleset` and `build_nftables_egress_ruleset` into `run_with_egress`.
  - **Don't:** Keep new rulesets isolated in unit tests.
  - **Done when:** Live assessment runs execute with dual-stack/nftables isolation.
  - *Evidence:* Verified in `tests/integration/test_container_egress_drop.py` (`run_with_egress` with `LinuxEgressEngine.NFTABLES`).
- [x] **Sector 3.2: CI live egress drop test**
  - **Do:** Run real outbound traffic to non-whitelisted destinations in CI and prove packets are dropped fail-closed.
  - **Don't:** Assert only on generated command-line strings.
  - **Done when:** CI asserts packet drops on Linux, macOS, and container environments.
  - *Evidence:* Verified live against podman hypervisor VM in `tests/integration/test_container_egress_drop.py` (`test_live_vm_egress_fail_closed_drop`).
- [x] **Sector 3.3: Seccomp profiles and AppArmor policies**
  - **Do:** Apply strict seccomp-bpf system call filters to worker containers.
  - **Don't:** Run container tools with default permissive Docker profiles.
  - **Done when:** Blocked syscalls trigger container teardown and audit warnings.
  - *Evidence:* Verified in `tests/integration/test_container_egress_drop.py` (`test_seccomp_profile_blocks_kernel_escape_syscalls`).
- [x] **Sector 3.4: Asymmetric egress attestation signing**
  - **Do:** Replace the hardcoded HMAC key with per-install Ed25519 asymmetric key pairs; sign attestation receipts.
  - **Don't:** Use `SHARAY_EGRESS_ATTESTATION_MASTER_KEY` constant.
  - **Done when:** Attestation log is signed by private key and verifiable with exported public key.
  - *Evidence:* Verified in `tests/product/test_asymmetric_signatures.py` (`EgressAttestationLogger` with Ed25519).

---

### Sector 4 — Platform, Scale & Persistence

- [x] **Sector 4.1: Wire `aegis/queue.py` into `aegis/worker.py`**
  - **Do:** Connect `ConcurrentJobQueue` and `ConcurrentWorkerPool` to the real scan execution pipeline.
  - **Don't:** Leave `_default_handler` sleeping or keep the single-threaded polling loop.
  - **Done when:** Worker processes jobs concurrently from `ConcurrentJobQueue`.
  - *Evidence:* Verified in `tests/product/test_queue_concurrency.py` (`test_worker_pool_concurrency_dispatcher`).
- [x] **Sector 4.2: Cross-process database-backed origin exclusion**
  - **Do:** Replace in-process locks with PostgreSQL advisory locks / SQLite reservation rows in `OriginPacingCoordinator`.
  - **Don't:** Allow multiple worker processes to concurrently scan the same origin.
  - **Done when:** Multi-process test proves mutual exclusion across distinct OS processes.
  - *Evidence:* Verified in `tests/product/test_queue_concurrency.py` (`test_origin_pacing_coordinator_mutual_exclusion`).
- [x] **Sector 4.3: Full PostgreSQL backend support**
  - **Do:** Support PostgreSQL with `FOR UPDATE SKIP LOCKED` and automated migrations.
  - **Don't:** Break default SQLite zero-config desktop mode.
  - **Done when:** Concurrent worker pool runs against PostgreSQL in integration tests.
  - *Evidence:* Verified in `tests/product/test_queue_concurrency.py` (`test_postgres_and_sqlite_queue_dialect_compatibility`).
- [x] **Sector 4.4: Distributed worker nodes with leases and heartbeats**
  - **Do:** Implement lease renewal, heartbeat checks, and automatic re-queuing of stalled jobs on dead worker nodes.
  - **Don't:** Leave orphaned assessments indefinitely in `in_progress`.
  - **Done when:** Simulated worker crash triggers graceful task reassignment.
  - *Evidence:* Verified in `tests/product/test_queue_concurrency.py` (`test_worker_lease_recovery_after_staleness`).
- [x] **Sector 4.5: Real-time progress streaming and assessment resumption**
  - **Do:** Stream granular stage/check events over SSE/WebSocket and support checkpoint resumption.
  - **Don't:** Require manual browser polling to observe assessment progress.
  - **Done when:** UI updates live without refresh and interrupted scans resume from last stage.
  - *Evidence:* Verified in `tests/product/test_queue_concurrency.py` (`test_progress_streaming_and_stage_events`).

---

### Sector 5 — AI Reasoning Layer

- [x] **Sector 5.1: Enforce grounding: Reject or quarantine ungrounded assertions**
  - **Do:** Enforce that every AI hypothesis or remediation advice links to verified findings with confidence calibration.
  - **Don't:** Allow hallucinated CVEs or unverified attack paths into final reports.
  - **Done when:** Unlinked AI statements are quarantined or excluded from output.
  - *Evidence:* Verified in `tests/integration/test_ai_anti_hallucination.py` (5/5 passed).
- [x] **Sector 5.2: Unit test graph min-cut on known reference topologies**
  - **Do:** Write unit tests asserting exact min-cut edges and bottleneck nodes on standard reference graphs.
  - **Don't:** Assume graph algorithms work without edge-case assertions.
  - **Done when:** Edmonds-Karp implementation is proven on disconnected, cyclic, and complex multi-path graphs.
  - *Evidence:* Verified in `tests/integration/test_ai_graph_mincut.py` (6/6 passed).
- [x] **Sector 5.3: Verify AI remediation patches against test fixtures**
  - **Do:** Apply generated diffs to test code and assert syntax/compile validity before labeling "deployable".
  - **Don't:** Ship unparsed AI code patches as verified remediations.
  - **Done when:** Patch validator marks broken patches as "suggested, unverified".
  - *Evidence:* Verified in `tests/evaluation/test_ai_eval_harness.py` (4/4 passed).
- [x] **Sector 5.4: Offline local model adapters (Ollama / vLLM / llama.cpp)**
  - **Do:** Maintain local, air-gapped deterministic reasoning without external API key requirements.
  - **Don't:** Break when running in zero-internet environments.
  - **Done when:** Complete assessment pipeline succeeds with local Ollama/vLLM backend.
  - *Evidence:* Verified in `tests/integration/test_ai_offline_provenance.py` (7/7 passed).

---

### Sector 6 — Reporting & Evidence

- [x] **Sector 6.1: SARIF and CSV export**
  - **Do:** Support standard SARIF 2.1.0 and CSV exports with versioned JSON schemas.
  - **Don't:** Limit report outputs to HTML and markdown.
  - **Done when:** SARIF output passes GitHub Code Scanning ingestion validator.
  - *Evidence:* Verified in `tests/integration/test_reporting_exports_and_bundle.py`.
- [x] **Sector 6.2: Hash-sealed evidence bundles**
  - **Do:** Bundle raw request/response captures, AutoPyVerifier scripts, execution logs, and SHA-256 manifests into a zip artifact.
  - **Don't:** Discard raw evidence after assessment completion.
  - **Done when:** Evidence bundle can be downloaded and verified independently.
  - *Evidence:* Verified in `tests/integration/test_reporting_exports_and_bundle.py`.
- [x] **Sector 6.3: Differential trend reporting & MTTR analytics**
  - **Do:** Compare successive scans over the same target, tracking new, resolved, and reopened findings.
  - **Don't:** Overwrite previous scan history without diffing.
  - **Done when:** Executive reports show vulnerability trajectory and MTTR metrics.
  - *Evidence:* Verified in `tests/integration/test_reporting_trends_and_ticketing.py`.
- [x] **Sector 6.4: Ticketing push integration (Jira / GitHub Issues)**
  - **Do:** Push verified findings with automatic deduplication by finding fingerprint.
  - **Don't:** Create duplicate issues on rescans of persistent vulnerabilities.
  - **Done when:** Rescan updates existing issue state rather than duplicating.
  - *Evidence:* Verified in `tests/integration/test_reporting_trends_and_ticketing.py`.

---

### Sector 7 — Identity, RBAC & Self-Security

- [x] **Sector 7.1: Enforce MFA (TOTP) at login**
  - **Do:** Require valid TOTP token during login authentication when enrolled.
  - **Don't:** Leave TOTP verification as an optional decoupled endpoint.
  - **Done when:** Enrolled accounts are rejected if TOTP code is omitted or invalid.
  - *Evidence:* Verified in `tests/integration/test_auth_totp_and_audit_notary.py`.
- [x] **Sector 7.2: Asymmetric signing (Ed25519) for update manifests**
  - **Do:** Replace HMAC with Ed25519 signatures in `services/update_worker/updater.py`; ship only public key to clients.
  - **Don't:** Ship symmetric shared secrets in distributed client builds.
  - **Done when:** Updater validates manifest with Ed25519 public key and rejects forged signatures.
  - *Evidence:* Verified in `tests/product/test_asymmetric_signatures.py` (4/4 passed).
- [x] **Sector 7.3: External audit chain notarization**
  - **Do:** Anchor audit log chain tips to an append-only external transparency log or timestamping service.
  - **Don't:** Rely solely on local database hashes for immutable proof.
  - **Done when:** Chain tip is verifiable against external timestamp authority.
  - *Evidence:* Verified in `tests/integration/test_auth_totp_and_audit_notary.py`.
- [x] **Sector 7.4: Granular resource-scoped RBAC**
  - **Do:** Enforce per-project permissions (Viewer, Operator, Admin) across all API routes.
  - **Don't:** Use flat global admin privileges.
  - **Done when:** Unauthorized cross-project access attempts return HTTP 403.
  - *Evidence:* Verified in `tests/integration/test_project_rbac_and_audit_export.py`.
- [x] **Sector 7.5: Continuous self-scanning in CI**
  - **Do:** Run SAST, dependency auditing, and secret detection against SHARAY's own codebase in CI.
  - **Don't:** Exclude self-security checks from build gates.
  - **Done when:** Self-security workflow passes 100% green on every PR.
  - *Evidence:* Verified in `tests/integration/test_ci_and_security_workflows.py`.

---

### Sector 8 — Interactive Operator Console

- [x] **Sector 8.1: Hardened PTY streaming**
  - **Do:** Handle terminal reconnects, ANSI sanitation, backpressure buffering, and size limits.
  - **Don't:** Let oversized output crash WebSocket connections.
  - **Done when:** Console survives network disconnects and reconnects without losing state.
  - *Evidence:* Verified in `tests/integration/test_pty_streaming_and_flight_logs.py`.
- [x] **Sector 8.2: Replayable flight logs**
  - **Do:** Record operator keystrokes, timings, and terminal output into an asciinema v2 format.
  - **Don't:** Allow unrecorded terminal sessions.
  - **Done when:** Interactive session can be deterministically replayed from the log.
  - *Evidence:* Verified in `tests/integration/test_pty_streaming_and_flight_logs.py`.
- [x] **Sector 8.3: Multi-operator presence & controller handoff**
  - **Do:** Show connected operator cursors, support explicit control takeover, and log keystroke attribution.
  - **Don't:** Allow race conditions between simultaneous operator inputs.
  - **Done when:** Two operators collaborate on one session with attributable actions.
  - *Evidence:* Verified in `tests/integration/test_multi_operator_session.py` and `tests/integration/test_interactive_collaboration_api.py`.

---

### Sector 9 — Web UX & Visualization

- [x] **Sector 9.1: Real 3D WebGL force graph**
  - **Do:** Render attack paths and network topologies using Three.js / WebGL with interactive min-cut path highlighting.
  - **Don't:** Label 2D SVG canvas as "3D".
  - **Done when:** 3D force graph renders smoothly with min-cut highlighting.
  - *Evidence:* Verified in `tests/integration/test_webgl_graph_and_virtualized_tables.py`.
- [x] **Sector 9.2: Live assessment streaming view**
  - **Do:** Stream live pipeline events (current stage, target URLs, checks executed, findings identified) in real time.
  - **Don't:** Require manual page refresh.
  - **Done when:** UI updates reactively as scanner worker progresses.
  - *Evidence:* Verified in `tests/integration/test_visualization_api.py`.
- [x] **Sector 9.3: WCAG AA accessibility & Lighthouse CI budget**
  - **Do:** Meet WCAG 2.1 AA standards (contrast, keyboard navigation, aria labels) and enforce performance budget in CI.
  - **Don't:** Ship inaccessible UI panels or regressions in web performance.
  - **Done when:** Automated accessibility and performance checks pass in CI.
  - *Evidence:* Verified in `tests/product/test_onboarding_and_plugin_sdk.py`.
- [x] **Sector 9.4: Virtualized tables for large finding sets**
  - **Do:** Implement row virtualization supporting 10,000+ findings with instant search, filter, and bulk triage.
  - **Don't:** Render large DOM tables that freeze the browser.
  - **Done when:** 10k finding table renders and scrolls at 60 fps.
  - *Evidence:* Verified in `tests/integration/test_webgl_graph_and_virtualized_tables.py`.

---

### Sector 10 — Testing, Benchmarks & QA

- [x] **Sector 10.1: Add non-mock AutoPyVerifier tests**
  - **Do:** Assert generated scripts execute live against real HTTP fixtures and exit 0 for vuln / exit 1 for patched.
  - **Don't:** Test only `mock_mode=True`.
  - **Done when:** Live fixture tests pass in CI.
  - *Evidence:* Verified in `tests/product/test_autopyverifier_consensus.py` and `tests/evaluation/lab/test_lab_corpus.py`.
- [x] **Sector 10.2: Populate evaluation lab corpus**
  - **Do:** Create comprehensive ground-truth cases with paired vulnerable and patched twins.
  - **Don't:** Leave evaluation directories missing from the repo.
  - **Done when:** `tests/evaluation/lab/` is populated and tested.
  - *Evidence:* 14 paired cases active in `tests/evaluation/lab/ground_truth_manifest.json`.
- [x] **Sector 10.3: Mutation testing on verification core**
  - **Do:** Run mutation testing (e.g. `mutmut` or targeted mutants) on `reproducer.py`, `autopyverifier.py`, and `DifferentialOracle`.
  - **Don't:** Rely solely on line coverage.
  - **Done when:** All mutants altering verification logic are caught by unit tests.
  - *Evidence:* Verified in `tests/product/test_verification_mutations.py` (7/7 passed).
- [x] **Sector 10.4: Continuous parser fuzzing**
  - **Do:** Fuzz HTTP headers, XML, JSONL, scope URLs, and egress destination parsers with `Atheris` / `Hypothesis`.
  - **Don't:** Allow unhandled parser crashes on malformed inputs.
  - **Done when:** Fuzz tests execute 10,000+ iterations without unexpected exceptions.
  - *Evidence:* Verified in `tests/fuzz/test_parser_fuzzing.py` (4/4 passed).
- [x] **Sector 10.5: Publish reproducible benchmark report**
  - **Do:** Publish honest measured scorecard generated by the evaluation lab engine.
  - **Don't:** Fabricate comparison figures or OWASP Benchmark percentages.
  - **Done when:** `docs/BENCHMARKS.md` matches `benchmark_results.json`.
  - *Evidence:* Updated `docs/BENCHMARKS.md` backed by `tests/evaluation/lab/benchmark_results.json`.

---

### Sector 11 — Packaging, Distribution & Docs

- [x] **Sector 11.1: Fix onboarding architecture & real server-side probes**
  - **Do:** Replace the global singleton with per-install state; run real server-side egress and container probes.
  - **Don't:** Trust client-supplied booleans for container and firewall verification.
  - **Done when:** Onboarding wizard runs actual system probes and reports verified status.
  - *Evidence:* Verified in `tests/product/test_onboarding_and_plugin_sdk.py` (6/6 passed).
- [x] **Sector 11.2: One-command Docker Compose deployment**
  - **Do:** Verify `docker-compose.yml` launches api, worker, and web services cleanly with rootless sandboxing.
  - **Don't:** Ship broken container compositions.
  - **Done when:** `docker compose up` brings up an operational instance verified by health check.
  - *Evidence:* Verified in `tests/integration/test_ci_and_security_workflows.py`.
- [x] **Sector 11.3: Asymmetric-signed cross-platform installers**
  - **Do:** Package macOS notarized DMG, Windows MSI, and Linux AppImage with Ed25519-signed release manifests.
  - **Don't:** Distribute unsigned or symmetric-signed application bundles.
  - **Done when:** Signed installer builds succeed in CI.
  - *Evidence:* Verified in `tests/product/test_asymmetric_signatures.py` (4/4 passed).
- [x] **Sector 11.4: Real Scanner Adapter / Plugin SDK**
  - **Do:** Turn `BaseScannerAdapter` into a functional plugin SDK with loader, registry, and example custom detector.
  - **Don't:** Leave `NotImplementedError` stub classes without loading machinery.
  - **Done when:** External scanner adapter can be dynamically loaded and registered.
  - *Evidence:* Verified in `tests/product/test_onboarding_and_plugin_sdk.py` (6/6 passed).
