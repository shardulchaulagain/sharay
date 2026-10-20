# SHARAY — Offensive Capability Audit & Roadmap to World-Class (Toward 0-Day)

Deep-research audit of the attack side, 2026-10-19. Grounded in a direct read of the offensive
modules (`metasploit.py`, `payload_forge.py`, `adaptive.py`, `reproducer.py`, `interactive.py`,
`crawler.py`, scanner bounds). Cites `file:line`.

**Scope & safety.** SHARAY is an authorized offensive+defensive platform. Everything here stays inside
its existing controls: operator-authorized targets only, scope policy, single-destination egress lock,
safe-gate, per-action confirmation for anything state-changing, non-destructive by default, clean-exit,
one authorized scope at a time. "0-day capability" means vulnerability *research* (fuzzing, differential
analysis, source-assisted taint) on authorized targets and components, for responsible disclosure — not
weaponization, C2, persistence, or mass targeting. Those lines do not move.

The goal: **miss nothing known, then find the unknown.** That ordering is correct — 0-day falls
out of a tool that (a) has complete known-vuln coverage, (b) generates and *adapts* payloads from live
target behavior, (c) has a strong impact oracle, and (d) can fuzz for novel behavior.

---

## PART A — OFFENSIVE AUDIT: The Honest State

### A1. Metasploit is NOT deployed at full capacity `[SHAPE]`
- `metasploit.py:3` parser-only: no command line built, no live shell/session represented.
- Hardcoded catalog of 21 modules (`metasploit.py:443`). Metasploit ships ~2,400 exploits + ~1,200 auxiliary + ~400 post modules (<1% visible).
- Every catalog entry is `default_action: "check"` (`metasploit.py:450`). No exploitation-to-session occurs.
- Missing: msfrpcd/RPC automation, module tree search, msfvenom benign payload generation, post-exploitation evidence collection, session routing/pivoting.

### A2. Payload generation is static, and "AST mutation" is a misnomer `[SHAPE]`
- `CFGPayloadGenerator` (`payload_forge.py:23-88`) is fixed string lists, not a context-free grammar.
- `mutate_ast` (`:139`) is regex string substitution, not AST/semantic grammar mutation.
- WAF evasion is hardcoded string replaces for 3 vendors (`WAFTransformProfile`, `:189`).
- SSTI, XXE, NoSQL, LDAP, XPath, deserialization, prototype-pollution, template payloads are absent or rudimentary.
- Generation is open-loop: payloads synthesized and recorded without response feedback.

### A3. "Adaptive" methodology is tag-selection, not response-driven `[SHAPE]`
- `adaptive.py` fingerprinting emits Nuclei tags via substring matching (`adaptive.py:110`).
- No feedback loop observing response deltas (reflection, status, filter behavior) to adjust injection context or bypass route.

### A4. Target reproduction: good bones, but stateless and shallow `[REAL but limited]`
- `reproducer.py` has 3x replay, canary, and statistical jitter baselining.
- Stateless HTTP-diff: lacks login/session/JWT/cookie/CSRF handling for authenticated or workflow-gated vulnerabilities.
- No headless browser JS-rendered DOM XSS confirmation.
- Out-of-band callbacks use unresolving placeholder domains rather than an active collaborator server.

### A5. The console is a one-shot command dispatcher, not a session `[SHAPE]`
- `interactive.py` executes fresh one-shot containers per command (`run_with_egress ... exit -y`).
- No persistent stateful PTY/shell session or interactive driveable meterpreter.
- Hardcoded HMAC secrets in `interactive.py:255`.

### A6. Scale: built for tiny targets, not big sites `[LIMIT]`
- Safe profile capped at `MAX_REQUESTS = 5`, `MAX_SECONDS = 15`.
- Crawler capped at `max_pages=30`, `max_depth=2`.
- Small subset sampled (e.g., first 5 endpoints in auth matrix).

### A7. The tool belt is nearly empty `[MISSING]`
- Bundled/PATH only has nuclei and gitleaks.
- Missing industry-standard specialized tools: sqlmap, ffuf, katana, arjun, commix, testssl, dalfox, schemathesis/RESTler, interactsh.

### A8. Offensive rating: ~4/10
- Exceptional safety and verification foundation, but offense is static, check-only, and under-tooled.

---

## PART B — ROADMAP CHECKLIST (Offense-Focused, Evidence-Backed)

### Sector O1 — Complete KNOWN-Vuln Coverage
- [ ] **O1.1: Version-to-CPE-to-CVE Intelligence Engine**
  - Implement automated CPE extraction from server headers, meta tags, and component assets.
  - Query local and offline NVD + OSV + GitHub Advisory feeds (`packages/cve_intelligence.py`).
  - Generate verifiable, version-grounded CVE findings (avoid banner-substring false positives).
- [ ] **O1.2: Complete Nuclei Template Suite Integration**
  - Execute full community + custom + fuzzing template suites across all discovered endpoints.
- [ ] **O1.3: Dynamic Module-Tree Mapping**
  - Map detected technologies and CPEs to full exploit module trees.
- [ ] **O1.4: Assessment Coverage Ledger**
  - Emit an explicit verification ledger per assessment detailing all applicable known classes/CVEs, tests conducted, and outcomes.

### Sector O2 — Metasploit at Full Capacity
- [ ] **O2.1: msfrpcd Programmatic RPC Driver**
  - Stand up `packages/scanner_adapters/integrations/msf_rpc.py` to communicate via MSF RPC.
- [ ] **O2.2: Dynamic Module Tree Search**
  - Programmatically search Metasploit's ~2,400 exploits and ~1,200 auxiliary modules by CVE, service, and tech stack.
- [ ] **O2.3: Gated Check -> Exploit -> Benign Session Execution**
  - Safe-gate protected execution: run `check` first, require explicit operator authorization, execute non-destructive payload (e.g., `id`/`getuid`), capture proof receipt, and cleanly terminate.
- [ ] **O2.4: msfvenom Benign Payload Generation**
  - Programmatic benign payload generation for authorized verification tests.
- [ ] **O2.5: Safe Post-Exploitation Enumeration Modules**
  - Read-only environment and configuration discovery within authorized scope.
- [ ] **O2.6: Isolated Session Pivoting Engine**
  - Replace simulated SOCKS router with real containerized session-routed scanning of authorized adjacent scopes.

### Sector O3 — Real Payload Engine (Grammar + Semantic AST Mutation)
- [ ] **O3.1: True Context-Free Grammar (CFG) Engine**
  - Production-rule grammar engine for SQLi, SSTI (Jinja2, Twig, FreeMarker, ERB, Velocity), XXE (parameter entities, OOB DTD), NoSQL, LDAP, XPath, Deserialization, SSRF, Prototype Pollution, and GraphQL.
- [ ] **O3.2: Semantic AST Mutation Engine**
  - Real parse-tree AST transformations (keyword synonyms, equivalent operators, comment/whitespace insertion, encoding nodes) with deterministic random seeding.
- [ ] **O3.3: Context-Aware Injection Placement & Encoders**
  - Detect reflection contexts (HTML body, attribute, JS string, URL query, shell) and apply chained encoders (single/double URL, HTML entity, unicode, base64, hex).

### Sector O4 — Response-Driven Adaptive Methodology
- [ ] **O4.1: Closed-Loop Feedback Engine**
  - Parse response deltas (status codes, body length, latency, reflection, error strings) to dynamically choose the next payload.
- [ ] **O4.2: WAF Probe-and-Adapt Learning Loop**
  - Probe target with benign markers to learn exact WAF keyword/symbol filters, then synthesize adaptive bypass encodings.
- [ ] **O4.3: Dynamic Oracle Selection**
  - Automatically select reflection, boolean-differential, time-based, error-based, or OOB oracles based on target responsiveness.
- [ ] **O4.4: Entropy-Guided Input Fuzzing**
  - Prioritize inputs and parameters that cause behavioral changes or state shifts.

### Sector O5 — Real Interactive Console
- [ ] **O5.1: Persistent Stateful PTY/Shell Channels**
  - Maintain persistent session processes in isolated containers preserving working directory, environment, and command history.
- [ ] **O5.2: Live Session Driving & Takeover**
  - Attach/detach to authorized live sessions with clean exit guarantees.
- [ ] **O5.3: Hardened Flight Logging & Dynamic Secrets**
  - Eliminate hardcoded HMAC secrets (`interactive.py:255`), using per-session cryptographic keys and asciinema export.

### Sector O6 — Stateful Deep Target Reproduction
- [ ] **O6.1: Authenticated Session Maintenance in Reproducer**
  - Integrate session cookie jars, bearer token rotation, and CSRF token re-extraction into `DeterministicReproducer`.
- [ ] **O6.2: Headless Browser DOM Verification**
  - Validate DOM XSS and client-side execution via headless Chromium callback interception.
- [ ] **O6.3: Live Out-of-Band (OOB) Collaborator Server**
  - Stand up self-hosted live DNS/HTTP collaborator server with HMAC correlation tokens to verify blind SSRF/RCE/XXE.
- [ ] **O6.4: Multi-Step Chained Exploit Verification**
  - Automated postcondition validation across multi-stage exploit chains.

### Sector O7 — Specialized Tool Belt Orchestration
- [ ] **O7.1: Containerized Tool Belt Runners**
  - Orchestrate `sqlmap`, `commix`, `dalfox`, `ffuf`, `katana`, `arjun`, `testssl.sh`, and `naabu` in egress-locked containers.
- [ ] **O7.2: Unified Finding Normalization**
  - Normalize tool outputs into SHARAY Finding envelopes and verify via reproducer.

### Sector O8 — 0-Day Discovery Capability
- [ ] **O8.1: Stateful API Fuzzing**
  - Grammar and schema-guided fuzzing (OpenAPI/GraphQL) to uncover unhandled exceptions, state corruption, and 500 errors.
- [ ] **O8.2: Differential Parser Confusion Engine**
  - Detect parser desynchronization (HTTP request smuggling, encoding ambiguities, delimiter confusion).
- [ ] **O8.3: Anomaly Scoring Oracle**
  - Statistical deviation detection flagging anomalous responses for human review.
- [ ] **O8.4: Source-Assisted Taint Analysis Verification**
  - When source is available, map Semgrep/CodeQL taint flows to active dynamic reproduction tests.

### Sector O9 — Scale for Large Attack Surfaces
- [ ] **O9.1: High-Capacity Web Crawler**
  - Uncapped breadth crawling, robots/sitemap parsing, and route deduplication.
- [ ] **O9.2: Attack Surface Prioritization**
  - Prioritize high-value attack surface (auth, file upload, API parameters, admin consoles).
- [ ] **O9.3: Distributed Worker Pool Dispatch**
  - Multi-worker concurrent crawling and scanning coordinated across origin pacing leases.

### Sector O10 — Offensive QA & Verification Proof
- [ ] **O10.1: Vulnerable Range CI Testbed**
  - Verification test harnesses against local vulnerable fixtures (Juice Shop, DVWA, custom test targets).
- [ ] **O10.2: Exploitation & Clean-Exit Benchmarks**
  - Quantified benchmark suites measuring verification precision, recall, and clean-exit receipts.
