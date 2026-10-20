# SHARAY — Full Codebase Audit & Roadmap Checklist

Audit date: 2026-10-19. Based on a direct read of the working tree (~37,600 lines of first-party
Python/TS across `aegis/`, `packages/`, `services/`, `apps/web/`, plus `scripts/`, `engineering/`,
`fixtures/`, `migrations/`). Findings cite `file:line` where verified by execution or reading, and
mark inference as inference. No source was modified to produce this document.

How to read this: **Part A** is the honest state of what exists. **Part B** is an exhaustive,
sector-by-sector checklist — every item with a **Do**, a **Don't**, and a **Done when**. No time
estimates. Check items off as you land them.

Legend: **[REAL]** implemented and wired into the running product · **[MODULE]** implemented but
not wired / not reachable in the product · **[SHAPE]** looks implemented but doesn't do what it
claims · **[BROKEN]** present but fails · **[STUB]** honestly unimplemented · **[MISSING]** absent.

---

## PART A — AUDIT

### A0. The one theme that matters

The platform's pitch is *"evidence before conclusions."* The biggest risk in the codebase right
now is the opposite: **claims are running ahead of evidence.** There is a large volume of
competent-looking module code that implements the *shape* of a feature but is either not wired,
"verifies" by trusting client input, or uses signature-shaped crypto that isn't secure. Two items
actively damage trust and must be fixed before anything else:

1. **The verification engine does not execute.** `[BROKEN]` `services/ai_analysis_worker/autopyverifier.py`
   synthesizes scripts that reference `body` without ever assigning `body = resp.read()`. Verified by
   running a generated non-mock script: `defines body? False / uses body? True`, and on a real 200
   response it raises `NameError`, is caught, and returns `VERIFICATION_FAILED`. AutoPyVerifier can
   never return exit 0 against a live target, so the headline "executable proof" path is dead
   (`autopyverifier.py:87,90,121,124`). The 3x-replay reproducer (`reproducer.py`) is a *separate*,
   working path — only the AutoPyVerifier leg is broken.

2. **`docs/BENCHMARKS.md` is fabricated.** It presents "a reproducible, empirical benchmark" with
   SHARAY at **99.4% precision, 0.0% FP, 84.2% OWASP Benchmark, 100% confirmed-PoC ratio** beating
   ZAP/Nuclei/Arachni. But the cited corpus `tests/evaluation/lab/` **does not exist** (verified:
   `ls` fails), no results artifact exists, the numbers appear nowhere in the eval harness, and the
   "100% confirmed PoC" is credited to the AutoPyVerifier component that cannot run. This is invented
   data presented as measured — the single most corrosive thing this specific product can ship.

Everything below is detail in service of those two facts and the work around them.

### A1. What is genuinely solid and wired `[REAL]`

These are the parts a user actually exercises, and they are well-built:

- **Scope authorization boundary.** `packages/security_policies/__init__.py` — strict Pydantic
  `ScopePolicy` (`extra="forbid"`, 24h TTL, booleans pinned to safe literals), paranoid
  `normalize_url`, `check_execution_url` with an SSRF guard that refuses private/loopback/reserved
  ranges, and `resolve_pinned` that refuses the whole DNS answer set if any address is non-public.
- **Safe HTTP adapter.** `packages/scanner_adapters/__init__.py::scan()` — deadline sockets, 64 KB
  header budget, zero body retention, configuration-fact extraction (not raw header storage),
  re-validates scope before every connection.
- **Container egress sandbox — now dual-stack.** `services/scanner_worker/container.py` — fail-closed
  rootless runner (`--network=none`, `--read-only`, `--cap-drop=ALL`, `no-new-privileges`), plus new
  `build_multidest_egress_ruleset` (IPv4 + IPv6 via `ip6tables`), `build_nftables_egress_ruleset`
  (Linux-native), `parse_target_destinations`/`TargetDestination`. Always-teardown, `shlex.quote`d
  tokens. `+834` lines with `+220` new tests.
- **Deterministic reproducer (replay leg).** `packages/scanner_adapters/reproducer.py` — 3x
  byte-identical replay + negative-control canary + `DifferentialOracle`. Demotes on flap or when the
  negative control fires. This leg works and is the real false-positive killer.
- **Worker verification gate.** `aegis/worker.py::_finding_status` — DEMOTED→demoted,
  REPRODUCED/AutoPyVerifier-exit-0→confirmed, else suspected; `_autopyverifier_passed` requires int
  exit 0 + `mock_mode is False`. Envelope validation + redaction before persistence.
- **Attack-graph analytics — now real.** `services/ai_analysis_worker/graph.py` — genuine Edmonds-Karp
  max-flow / min-cut (BFS augmenting paths, residual edges) and an iterative dominator tree, invoked
  by `reasoning.py::BreakpointAnalyzer` (`reasoning.py:1407,1412`). This replaces the old heuristic.
- **Audit ledger.** `aegis/audit.py` — SHA-256 hash-linked chain + `verify_audit`, plus a new
  `AuditNotaryService.notarize_chain` (HMAC-signed anchor), wired at `api.py:1704`.
- **MFA (TOTP).** `aegis/auth.py::TOTPEngine` (real HMAC OTP, `otpauth://` URI, backup codes), wired
  at `api.py:527 /auth/totp/setup` and `:541 /verify`.
- **RBAC/sessions/recovery, reporting (PDF/HTML/MD/JSON with redaction + protocol PoCs + vuln/posture
  partitioning), interactive operator console, 10-stage pipeline, provenance/grounding structures in
  reasoning** — all present and wired as described in the research paper.

### A2. Implemented but NOT wired — "production-grade" in the docstring, dead in the product `[MODULE]`

- **Concurrent worker pool / queue.** `aegis/queue.py` (426 lines) is a well-written
  `ConcurrentJobQueue` + `ConcurrentWorkerPool` + `OriginPacingCoordinator` with Postgres
  `FOR UPDATE SKIP LOCKED` and SQLite fallback. **Not referenced anywhere outside itself** (verified:
  grep finds no importer); `aegis/worker.py` still runs the old single-process
  `select(...).where(status=="queued").limit(1)` loop. Two further gaps even if wired: (a) the
  `ConcurrentWorkerPool._default_handler` just `sleep(0.01)` — there is no real scan dispatcher
  connected; (b) `OriginPacingCoordinator` mutual-exclusion is an **in-process** dict+lock, so it does
  **not** coordinate origin exclusion across multiple processes, contradicting the "multi-worker" claim.
- **Plugin / adapter SDK.** `aegis/onboarding.py::BaseScannerAdapter` is three `raise NotImplementedError`
  methods with no loader, registry, or discovery. It's a spec class, not an SDK.
- **Performance budget enforcer.** `onboarding.py::PerformanceBudgetEnforcer` evaluates metrics handed
  to it, but nothing in CI feeds it real Lighthouse numbers (inference: no Lighthouse job found).

### A3. Looks like verification but verifies nothing `[SHAPE]`

- **Onboarding "egress firewall test".** `aegis/onboarding.py:89` sets `egress_verified` from
  `data.get("egress_drop_confirmed", False)` — a **client-supplied boolean**. It never calls
  `run_with_egress` to actually prove the allowlist drops traffic. Same for `container_verified`,
  `cgroups_v2`, `rootless`. For a platform built on "verify, don't trust," an onboarding step that
  trusts the browser is the wrong pattern. Also `onboarding_wizard` is a **module-level global
  singleton** (`onboarding.py:118`) shared across all users/orgs/requests — onboarding state is not
  per-install or per-session.
- **Auto-update signing.** `services/update_worker/updater.py` verifies release manifests with
  **HMAC-SHA256 using a shared secret** (`verify_manifest_signature`, line 48-56). The docstring says
  "HMAC-SHA256 / Ed25519" but only HMAC exists. A symmetric secret that must ship in the client to
  verify can also forge — this is not a secure update-distribution signature. Needs asymmetric
  (Ed25519) with only the public key on the client. Also not wired to any running update channel.
- **Egress attestation key.** `container.py::EgressAttestationLogger` defaults to a **hardcoded public
  constant** `"SHARAY_EGRESS_ATTESTATION_MASTER_KEY"` as the HMAC key (line ~836). An HMAC whose key is
  a committed constant provides no integrity. Same symmetric-crypto confusion as above.
- **Audit notary anchoring.** `AuditNotaryService` signs with an in-process random/supplied secret —
  it is still *local* tamper-evidence, not *external* notarization (a local admin with the key or DB
  access can re-sign). "Externally anchored" is not yet true.

### A4. Still-synthetic detection `[SHAPE]`

- **IDOR / authorization matrix uses hardcoded identities.** `packages/scanner_adapters/__init__.py:2143,2149`
  still injects `Authorization: Bearer sharay_token_alpha` / `_token_beta`. These are not real tenant
  sessions, so the cross-tenant IDOR test exercises nothing on a real target. This was flagged last
  round and is unchanged.
- **Native active checks remain a thin slice** vs. Burp/Nuclei breadth. New integrations exist
  (`oob.py`, `websocket_scanner.py`, `graphql_scanner.py`, `sqlmap.py`, `differential.py`,
  `vuln_scanner.py`) but coverage, real-target proof, and reproducer-backing per class are not
  established.

### A4b. Offensive capability — honest assessment: NOT top-class (`~4/10`)

SHARAY markets itself as a penetration-testing platform, so the attack side deserves its own verdict.
It is **deliberately bounded to safe, non-destructive verification** — a defensible philosophy, but it
means the offense is scaffold-depth, not world-class:

- **Metasploit is parser + auxiliary/check only.** `metasploit.py:3` states outright: *"Parser only: no
  Metasploit command line is built and nothing has run here... non-destructive checks only; unrestricted
  shell/console access is never represented here."* Real execution (orchestrator + console `msf`) runs
  `auxiliary/` and `check` modules in a container. There is **no exploitation-to-session**, which is
  correct for safe-default but is not "offense."
- **Payload forge generates, it does not confirm.** `payload_forge.py` synthesizes CFG payloads (SQLi/
  CMDi/SSRF), AST mutations, and WAF-evasion variants (string substitution for Cloudflare/AWS/ModSec),
  but Stage 7d records *"synthesized N payloads"* as an observation — the payloads are largely **not
  fired and proven** against the target end-to-end. It is a payload *library*, not an exploitation engine.
- **Pivoting / lateral movement is modeled, not operational.** `pivoting.py::SOCKSPivotRouter` only
  `inject_routes_into_graph` (adds nodes to the attack graph) and reports `standby_isolated`; it does not
  establish a proxy or move laterally. Persistence tracking exists for clean-exit, not for action.
- **WAF evasion is static substitution**, not adaptive/feedback-driven bypass testing.
- **No authenticated attack surface, no OOB-confirmed blind exploitation wired, no exploit chaining to
  demonstrated impact, no adversary emulation.** The reproducer confirms *some* classes, but the offense
  does not close the loop from payload → fired → impact proven → chained.

Verdict: the *verification* machinery is excellent; the *offense feeding it* is thin. World-class offense
here does **not** mean removing the safety model — it means proving exploitability with real impact,
inside SHARAY's existing authorization + scope + safe-gate controls. See new **Sector 2B** in Part B.
The intentional ceilings (safe-default, authorization-gated, non-destructive, clean-exit) stay; the
depth and the "prove it actually works" rigor go up.

### A5. Honestly-labeled stubs `[STUB]` (fine — leave as-is until needed)

- `aegis/storage.py` — S3 evidence storage raises `NotImplementedError` with clear messages; the local
  store works. This is honest and acceptable.

### A6. Security / correctness issues to fix

- `[BROKEN]` AutoPyVerifier `body` NameError (A0.1).
- `[SHAPE]` Symmetric HMAC used as distribution/attestation "signatures" with shipped/constant keys
  (A3): auto-update, egress attestation. Treat as integrity theater until asymmetric.
- `[SHAPE]` Onboarding trusts client-asserted verification booleans (A3).
- `[SHAPE]` Global mutable singleton for onboarding state (A3) — concurrency/isolation bug.
- `[SHAPE]` In-process-only origin exclusion in `queue.py` would let two processes hammer one origin.
- `[INTEGRITY]` Fabricated benchmark (A0.2).
- Hardcoded synthetic auth tokens in the live pipeline (A4).

### A7. Test state

Unit/integration/product suites are extensive. A full run during this audit: **886 passed, 1284 subtests
passed, 0 failures (89s)**. That is strong discipline — but a green suite does **not** mean the product
works, and here it hides two of the biggest findings: the AutoPyVerifier `body` bug is not caught because
tests only exercise `mock_mode=True` (which returns a different, working script), so the broken *real*
path is untested; and the fabricated benchmark has no test to contradict it. **The verification engine's
real execution path, and the dead `queue.py` worker pool, have effectively no product-level test
coverage.** Green CI is a reason to trust the plumbing, not the claims.

### A8. Rating (unchanged in number, shifted in reason)

Architecture/ambition **~8.5–9**; deployable/trustworthy **~5**; blended **~6/10**. Last round the gap
was "missing breadth"; now it is "claims outrunning evidence." Fix A0.1 + A0.2, wire A2, and replace
A3's crypto, and the honest blended rating moves to ~7.5–8.

---

## PART B — ROADMAP CHECKLIST (exhaustive, untimed)

### Sector 0 — Integrity & credibility (do these before anything else)

- [ ] **Fix AutoPyVerifier execution.** In `synthesize_script`, read the response body in both GET and
  POST templates: add `body = resp.read().decode("utf-8", "replace").lower()` inside the
  `with opener.open(...) as resp:` block, before `body` is referenced.
  - Do: keep the existing canary/signature logic; just define `body`. Add a test that generates a
    non-mock script and runs it green against `fixtures/safe_targets` returning a reflected canary.
  - Don't: leave `mock_mode=True` as the only tested path; don't claim AutoPyVerifier works until a
    real script returns exit 0 in CI.
  - Done when: a generated non-mock GET and POST script each exit 0 against a vulnerable fixture and
    exit 1 against its patched twin, in CI.
- [ ] **Remove or relabel `docs/BENCHMARKS.md`.** Either delete it, or replace every number with
  "TARGET (not yet measured)" and remove the comparison table until a real run exists.
  - Do: regenerate it only from an actual harness run that writes a results artifact.
  - Don't: publish precision/FP/OWASP numbers, a "v2.0" label, or competitor comparisons that no run
    produced. Don't credit results to AutoPyVerifier until Sector 0.1 lands.
  - Done when: the doc's numbers are reproducible by running one documented command that emits the
    same figures.
- [ ] **Build the eval corpus the benchmark references.** Create `tests/evaluation/lab/` with paired
  vulnerable/patched fixtures (SQLi, XSS, CMDi, LFI, SSRF, IDOR) and ground-truth labels.
  - Done when: `tests/evaluation/lab/` exists, is loaded by the harness, and every case has a labelled
    expected verdict.
- [ ] **Wire the eval harness to produce measured numbers.** Promote `drafts/gemini/ai_eval_harness.py`
  into the product, run it over the corpus, and emit precision/recall/FP per detector.
  - Don't: hand-write the scorecard.
- [ ] **Audit every "production-grade"/"v2.0"/"100%" claim in code docstrings and docs** and downgrade
  any that isn't wired + tested to "prototype" or "module (unwired)."

### Sector 1 — Verification engine

- [ ] Run AutoPyVerifier scripts **inside the rootless container** over the egress lock, not a bare
  `subprocess` on the host, so proof execution shares the sandbox.
- [ ] Implement the `EXPLOITED → CHAINED → VERIFIED` transitions (not just `REPRODUCED`): postcondition
  oracles (read/write/bypass observed), multi-step replay, and a sealed evidence bundle (request/
  response captures + replay log + script + output, hashed).
- [ ] Replace the `DifferentialOracle` fixed thresholds (score>=35, 4000ms, 25% length) with per-target
  statistical baselining and noise profiling; keep thresholds as fallbacks.
  - Don't: remove the negative-control canary — it is the core FP killer.
- [ ] Record and surface a reproducibility score and FP/FN rate per assessment.
- [ ] Add a regression harness: for each vuln class, "reproduce then demote" must hold across the
  vulnerable/patched corpus, gated in CI.
- Done when: every `confirmed` finding carries a sealed, re-runnable evidence bundle and the real
  verification path is green in CI with measured FP/FN.

### Sector 2 — Scanning & detection coverage

- [ ] **Replace synthetic auth identities** (`__init__.py:2143,2149`) with a real credential-provisioning
  flow: login, capture token/cookie, reuse the session; only then run the IDOR/BOLA matrix.
  - Don't: ship hardcoded `Bearer sharay_token_*` in the live pipeline.
- [ ] Bring native active checks to full OWASP Top 10 breadth, each reproducer-backed: SQLi (error/
  boolean/time), reflected+stored+DOM XSS, SSRF (OOB-confirmed), SSTI, command injection, path
  traversal, open redirect, XXE, insecure deserialization.
- [ ] Stand up an **out-of-band (OOB) interaction server** (`oob.py` exists — wire it) for blind SSRF/
  RCE/XXE confirmation; feed hits into the reproducer.
- [ ] Add **authenticated, stateful crawling** (cookies, CSRF tokens, re-login) so the crawler and
  active stages reach protected surface.
- [ ] Build a **signed, versioned detection-pack system**: first-party templates + import of Nuclei
  templates, loaded out-of-band so coverage grows without core releases. (Use a real adapter registry,
  not the empty `BaseScannerAdapter`.)
- [ ] Wire the source scanners already present (`gitleaks`, `semgrep`, `osv`, SBOM) into first-class
  findings under the same verification contract.
- [ ] Protocol breadth: finish `websocket_scanner.py` / `graphql_scanner.py` mutations, add gRPC and
  JWT attacks.
- Done when: coverage is measured on a public benchmark at parity with leading scanners, every detector
  is reproducer-backed, and detection packs ship out-of-band.

### Sector 2B — Offensive capability (make the attack side world-class)

Goal: move from *detect + generate* to *exploit + prove impact + chain*, **without touching SHARAY's
safety model**. Everything below runs only against operator-authorized, in-scope targets, over the
egress lock, non-destructively by default, with a clean-exit, and is recorded in the ledger. The point
is offensive *rigor* — proving a finding is really exploitable — not building weapons.

**Guardrails that stay (cross-cutting Don'ts for this whole sector):**
- [ ] Never bypass or weaken the operator-authorization gate, scope policy, egress lock, or safe-gate.
- [ ] Never build real command-and-control, implants, or self-propagation; never leave persistence/
  backdoors behind (keep the clean-exit + persistence-tracker model and prove teardown).
- [ ] Default to non-destructive; any state-changing action (write/delete/exploit-to-session) requires
  an explicit per-action operator confirmation and is reversible or sandboxed.
- [ ] No mass/indiscriminate targeting; one authorized target scope at a time.
- [ ] WAF-bypass work is to *measure WAF efficacy for the client*, not to evade defenders maliciously.

**Verified exploitation (close the payload → fired → impact-proven loop):**
- [ ] Make `payload_forge` payloads actually **fire and confirm**: for each generated vector, send it,
  run it through the reproducer (3x + negative canary), and only keep ones with proven differential
  impact. Stop recording "synthesized N payloads" as if it were a result.
- [ ] For each OWASP class, define an **impact oracle** (not just a reflection match): SQLi → extract a
  benign canary row / prove `information_schema` read; LFI → read a known safe file; CMDi → run a benign
  marker command and prove shell execution (not reflection); SSTI → prove template evaluation; XXE →
  prove entity resolution; open redirect → prove the 3xx to an external host.
- [ ] **OOB confirmation for blind classes:** wire `oob.py` as a real interaction server (DNS/HTTP
  callback) so blind SSRF/RCE/XXE/SQLi are confirmed by an out-of-band hit, then reproduced.
  - Done when: every "confirmed" injection carries proof of *impact*, not proof of *reflection*.

**Exploit chaining to demonstrated impact (use the graph you already built):**
- [ ] Turn the Edmonds-Karp attack graph (`graph.py`) into an **executable chain runner**: take a
  min-cut path (e.g. exposed endpoint → IDOR → token → privilege escalation) and replay the whole chain,
  asserting each postcondition, to demonstrate end-to-end impact.
- [ ] Record chained exploits as `CHAINED`/`VERIFIED` lifecycle states (Sector 1) with a sealed bundle.
  - Don't: claim a chain works without replaying every step with its postcondition.

**Real exploitation modules (authorized, gated, non-destructive by default):**
- [ ] Extend the Metasploit integration beyond auxiliary/check: allow `exploit` modules **with an
  explicit operator confirmation per run**, non-payload or benign-payload (e.g. prove a shell opens,
  capture `id`, then cleanly close) — never a persistent/destructive payload, always within scope and
  the egress lock.
- [ ] Integrate sqlmap/commix-grade depth for injection (the `sqlmap.py` adapter exists — make it
  reproducer-backed and bounded), and nuclei fuzzing templates.
  - Done when: an authorized target can be exploited to a proven, benign, auto-closed session on demand,
    fully logged, with teardown verified.

**Authenticated & business-logic offense:**
- [ ] **Provision real identities** (replace hardcoded `Bearer sharay_token_*`): log in as two real
  tenants and drive the IDOR/BOLA matrix against actual sessions.
- [ ] Add business-logic abuse: mass assignment, parameter tampering, **race conditions** (concurrent
  request TOCTOU), workflow/step-skipping, price/quantity manipulation on authorized test apps.
- [ ] JWT attacks (alg=none, key confusion, weak secret), OAuth/SSO misconfig, session fixation.
  - Done when: authenticated and multi-identity attack surface is exercised with proven cross-tenant or
    privilege impact.

**Adaptive fuzzing & WAF efficacy (replace static substitution):**
- [ ] Make fuzzing **feedback-driven**: use response signals (status, length, timing, error strings) to
  guide mutation (coverage-guided / grammar-feedback), instead of a fixed payload list.
- [ ] Turn WAF evasion into a **WAF-efficacy report**: systematically measure which payload classes the
  target WAF blocks vs. lets through, and report that to the client as a finding.
  - Don't: frame evasion as defeating detection for its own sake — frame it as testing the control.

**Client-side & modern-surface offense:**
- [ ] DOM XSS: go from source→sink detection to **confirmed JS execution** in a headless browser
  (prove `alert`/callback fired), then reproduce.
- [ ] GraphQL (mutations, batching, introspection abuse), WebSocket, gRPC, SSRF→cloud-metadata (IMDS)
  with the hop-limit/token checks already catalogued in `metasploit.py`.

**Adversary emulation (purple-team differentiator):**
- [ ] Map every technique to **MITRE ATT&CK** IDs and let an operator run an ATT&CK-chain playbook
  (Caldera-style) against an authorized target, producing a coverage/detection report.
- [ ] Produce a purple-team artifact: "here is the TTP chain we ran, what succeeded, and what your
  defenses caught" — this is where an authorized platform beats a raw scanner.
  - Done when: SHARAY runs a labelled ATT&CK chain and reports both exploitation success and defensive
    coverage.

**Offensive QA:**
- [ ] Stand up an intentionally-vulnerable range (Juice Shop, DVWA, WebGoat, VAmPI, a vulnerable AD/API
  lab) and prove, in CI, that SHARAY exploits-and-confirms each class and cleans up — then benchmark the
  *exploitation* rate (not just detection) against sqlmap/Metasploit/Burp.
  - Done when: offensive capability has a measured, reproducible exploitation benchmark on a public range.

- Overall done when: the attack side closes the loop (payload → fired → impact proven → chained →
  cleaned up → reported with ATT&CK mapping) for the OWASP Top 10 plus auth/business-logic, every result
  reproducer-backed, entirely inside the authorization + egress + safe-gate model.

### Sector 3 — Isolation & egress sandbox

- [ ] **Wire the new dual-stack / multi-dest / nftables egress rulesets** into `run_with_egress` so a
  real assessment uses them (confirm they are reached, not just defined).
- [ ] CI that **proves** the allowlist drops non-whitelisted destinations (incl. DNS, IPv6) on each
  supported OS — a live negative test, not a unit assertion on argv.
- [ ] Add a **seccomp** profile and AppArmor/SELinux policy per tool image; evaluate gVisor/Kata for a
  kernel boundary on untrusted targets.
- [ ] **Sign scanner images** and pin by digest; verify before run. (Asymmetric — see Sector 7.)
- [ ] Fix the **egress attestation key**: do not default to the hardcoded constant
  `SHARAY_EGRESS_ATTESTATION_MASTER_KEY`; require a per-install key and move to asymmetric signing if
  the receipt is meant to be externally trustworthy.
- Done when: single- and multi-destination egress are CI-proven to drop everything else on Linux/macOS
  (+WSL), IPv4+IPv6, with signed images and per-run attestation that a third party can verify.

### Sector 4 — Platform, scale & persistence

- [ ] **Wire `aegis/queue.py` into the real worker**, or delete it. Replace the single-process loop in
  `worker.py` with `ConcurrentJobQueue` + a real `job_handler` that dispatches the scanner.
  - Do: connect `ConcurrentWorkerPool`'s handler to `run_one`'s scan logic.
  - Don't: leave `_default_handler` (which just sleeps) as the pool's behavior.
- [ ] Make **origin exclusion cross-process**: move `OriginPacingCoordinator`'s mutual exclusion from an
  in-memory dict to a DB-backed claim (advisory lock / row lock), or document it as single-process only.
- [ ] Add the **PostgreSQL backend** path end-to-end (the dialect adapter exists) and test leasing under
  real concurrency; keep SQLite as the desktop default.
- [ ] Distributed worker nodes with leases + heartbeats (the primitives exist in `queue.py`) — prove
  dead-worker reaping requeues safely.
- [ ] Fine-grained live progress streamed to the UI (per-stage %, check events); per-tenant quotas /
  backpressure; resumable assessments.
- Done when: many concurrent assessments run across nodes on Postgres without hammering any origin,
  with live progress, quotas, and safe crash recovery — using the code that currently sits unused.

### Sector 5 — AI reasoning layer

- [ ] **Enforce grounding, don't just annotate it.** `provenance.py` + the `GroundingVerdict` exist;
  make the investigate path **reject or visibly quarantine** any AI claim without a provenance link to a
  verified finding/observation, not merely attach a confidence.
- [ ] Confirm the min-cut/dominator output (`graph.py` Edmonds-Karp — looks correct) is unit-tested on
  known graphs with known cuts.
- [ ] Make AI remediation patches **compile/apply-check against a fixture** before being labelled
  "deployable"; otherwise label them "suggested, unverified."
- [ ] Build an AI eval harness with curated cases (root-cause/remediation/CWE) and regression-gate it.
- [ ] Keep the offline/air-gapped deterministic fallback (`_deterministic_fallback_reasoning`) as the
  default; never require a provider key for core function.
- Done when: every AI assertion is traceable to sealed evidence or is clearly marked ungrounded, graph
  analytics are unit-proven, and the AI layer has a published eval score.

### Sector 6 — Reporting & evidence

- [ ] Add **SARIF** and **CSV** exports (for CI/ticketing) with a versioned JSON schema.
- [ ] Attach a downloadable, **hash-sealed evidence bundle** per confirmed finding (ties to Sector 1).
- [ ] Differential / trend reports across assessments (what changed, MTTR, reopened findings).
- [ ] Executive dashboard page (severity mix, posture trend, coverage map).
- [ ] Ticketing push (Jira / GitHub Issues) deduped by fingerprint.
- Done when: reports export to SARIF/CSV/JSON/PDF with sealed bundles and trend analytics, all
  reproducible from stored hashes.

### Sector 7 — Identity, RBAC & self-security

- [ ] **Finish MFA end-to-end:** enforce the TOTP second factor at **login** (the engine + setup/verify
  routes exist; confirm login actually requires it when enrolled). Add WebAuthn; add SSO (OIDC/SAML) for
  teams.
- [ ] **Replace symmetric "signatures" with asymmetric (Ed25519)** for: auto-update manifests
  (`updater.py`) and any externally-trusted attestation/notary receipt. Ship only the public key.
  - Don't: call an HMAC with a shipped/constant key a "signature."
- [ ] **External notarization** of the audit chain: periodically anchor the chain tip to an append-only
  external log (or transparency log) so a local admin cannot silently rewrite history.
- [ ] **Data lifecycle:** configurable retention + secure deletion/redaction of evidence and PII + export.
- [ ] Run SHARAY's own SAST/dependency/secret scan + security review in CI against itself
  (`.github/workflows/security.yml` exists — confirm it actually runs and gates).
- [ ] Granular, resource-scoped per-project RBAC.
- Done when: enforced MFA/SSO, asymmetric update + attestation signing, an externally-anchored audit
  chain, enforceable retention/deletion, and SHARAY continuously scanning itself.

### Sector 8 — Interactive operator console

- [ ] Harden PTY streaming: reconnect/resume, backpressure, binary-safe ANSI, large-output budgeting.
- [ ] Replayable, attributable **flight logs** (record + deterministically replay a session as evidence).
- [ ] Real multi-operator sessions: presence, takeover handoff, read-only viewers, per-keystroke
  attribution in the ledger.
- [ ] Expand the scoped command surface with autocomplete/history and a human-confirm AI copilot.
- Done when: a reconnectable, multi-operator console produces replayable, attributable flight logs that
  stand as evidence.

### Sector 9 — Web UX & visualization

- [ ] Replace the 2D force graph labelled "3D" with a real WebGL/3D graph, with interactive min-cut
  highlighting fed by `graph.py`.
- [ ] Live assessment view: stream stage/check/finding events (no manual refresh).
- [ ] Full accessibility pass (WCAG AA) with tests; **wire `PerformanceBudgetEnforcer` to a real
  Lighthouse CI job** (today it evaluates numbers nothing produces).
- [ ] Virtualized tables + fast search/filter/sort for large finding/audit sets; saved views; bulk triage.
- [ ] Build the **onboarding wizard UI** against a fixed backend (see Sector 11) — and make its egress/
  container steps show results of a **real** probe, not a checkbox.
- Done when: a flagship, accessible, real-time UI streams assessments, renders a true 3D graph, and stays
  fast on thousands of findings, with a Lighthouse gate in CI.

### Sector 10 — Testing, benchmarks & QA

- [ ] Add the **missing test for the real verification path** (non-mock AutoPyVerifier) — this is the gap
  that let A0.1 ship.
- [ ] Populate the eval lab (Sector 0) and publish measured precision/recall/FP per detector.
- [ ] End-to-end live-target regression in CI (fixtures + intentionally-vulnerable apps): reproduce then
  remediate.
- [ ] Measure + badge code coverage; add **mutation testing on the verification core** (reproducer,
  gate, oracle).
- [ ] Continuously fuzz the parsers (headers, XML, JSONL, scope URLs, egress destination parsing).
- [ ] Publish a **reproducible** benchmark report comparing SHARAY vs. baseline scanners (replaces the
  fabricated one).
- Done when: public, reproducible benchmarks show real detection parity + near-zero FP, the eval lab is
  full, and the verification core is coverage- and mutation-tested.

### Sector 11 — Packaging, distribution & docs

- [ ] **Fix onboarding architecture:** make state per-install/per-session (not the global singleton at
  `onboarding.py:118`), and make the container/egress steps run **real** probes server-side.
- [ ] Verify `Dockerfile` + `docker-compose.yml` actually bring up serve+worker+UI in one command; add
  it to CI.
- [ ] Ship **asymmetric-signed**, cross-platform installers (macOS notarized, Windows, Linux AppImage/
  deb) with a bundled runtime; wire the auto-update channel (after Sector 7's Ed25519 fix).
- [ ] Hosted, versioned API reference (the OpenAPI route exists) + user/operator guides (docs/api,
  docs/sdk, docs/user-guide exist — confirm they're complete and published).
- [ ] Turn `BaseScannerAdapter` into a working plugin SDK: a loader, a registry, discovery, and one
  example third-party adapter end-to-end.
- Done when: a new user scans a lab in minutes via a signed installer or one-command deploy, onboarding
  reflects real probes, and the plugin SDK can load an external adapter.

---

## What NOT to do (cross-cutting)

- **Don't ship numbers, versions, or "100%/production-grade" labels that no run produced.** For this
  product specifically, an unearned claim is worse than a missing feature — it contradicts the thesis.
- **Don't call a symmetric HMAC with a shipped/constant key a "signature."** Use Ed25519 where a third
  party must trust the artifact.
- **Don't let a feature "verify" by trusting a client-supplied boolean.** Verify server-side, with a
  real probe, or label it "self-reported."
- **Don't leave well-written modules unwired while advertising their capability.** Either integrate
  `queue.py`, the adapter SDK, and the performance enforcer, or mark them clearly as not-yet-wired.
- **Don't weaken the parts that are genuinely good:** the scope contract, the negative-control canary,
  fail-closed egress teardown, zero body retention, redaction-before-storage, and the hash-linked ledger
  are the platform's credibility — keep them strict.

## The short version

The rare, hard half — a principled, auditable verification architecture — exists and in places is
excellent (scope boundary, dual-stack egress, real min-cut, the replay reproducer, the audit chain).
The work now is to **make the claims true**: fix the one broken proof path, delete/earn the benchmark,
wire the modules that are already written, and replace signature-shaped crypto with the real thing.
Do Sector 0 and the "wire it" items in Sectors 3–4, and the platform stops over-promising and starts
being exactly what it claims to be.
