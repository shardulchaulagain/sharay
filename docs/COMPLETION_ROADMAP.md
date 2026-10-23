# SHARAY Completion Roadmap & Checklist

Merged from the external offensive+defensive research audit (Codex, 22 Oct 2026, commit `43a039b`)
and Claude's own overlapping source audit. This is the **living checklist**: each item is reproduced
first (evidence of the real defect), fixed, covered by a permanent regression test, then verified.
Nothing is checked off without verifiable evidence recorded in-line.

Goal: a working SHARAY with no reproduced correctness defects — UI-based scans first-class, CLI at
parity, operator console verified — where every offensive action and defensive conclusion derives
from one trusted contract (approved scope + action identity + limits + real execution + captured
evidence + authorized state transition).

Legend: ☐ todo · ◐ in progress · ☑ done (evidence recorded). Each item cites the audit finding
(Fnn), counterexample (Enn) and source anchor (Snn).

---

## P0 — Make the current contracts trustworthy (correctness & trust)

### P0-A · Single execution authorization & budget contract  (F01–F04)
- [x] **A1 · Rate ceiling clamp (F02/E03).** `ScanConfig.within_scope` now clamps the effective rate
  to the approved `scope.request_rate` (a request can only lower it). Evidence: reproduced 1/s→150/s
  before; after fix requested 150⇒1.0, None⇒approved, 2@approved5⇒2.0; regression
  `tests/product/test_authorization_contract.py::RateCeilingTests` (4 pass); 45 pacing/policy tests
  still green. `aegis/schemas.py:111`. _(Still open: port/Nuclei concurrency vs ceiling — tracked in A3.)_
- [ ] **A2 · Private-destination parity (F01/E07).** UI workspace, CLI, worker, browser, RPC and
  verifier all reject the same denied destination/path/expiry the execution validator rejects.
  Anchor S01, S09 `workspace.py:96`, S03.
- [ ] **A3 · Scope + cancellation survive dispatch (F03).** Comprehensive scan receives the full
  `ScopePolicy` + cancel callback; excluded-path contract enforced for crawler/sensitive/browser/
  reproducer paths. Anchor S04, S06–S11.
- [ ] **A4 · CLI approval provenance (F04).** CLI records target authorization + assessment BEFORE
  scanning; no hardcoded owner in a normal path; finding-status persistence identical to the worker.
  Anchor S05.

### P0-B · Correct impact & session provenance  (F05, F13)
- [ ] **B1 · Class-specific confirmation (F05/E01).** A benign reflection/echo must NOT become
  `confirmed/REPRODUCED`; confirmation binds a class-specific postcondition. Anchor S07, S04.
- [x] **B2 · RPC session provenance & teardown (F13/E11).** `execute_benign_verification` and
  `MetasploitInteractiveSession.open` now: (1) verify the module options target the consent-approved
  RHOST (`_verify_consent_target`, `PermissionError` on mismatch); (2) require a `vulnerable`/`appears`
  precheck before `module.execute` (no execute after a safe precheck); (3) snapshot `session.list`
  before/after and bind only to a NEW session whose host metadata matches the approved target —
  `close()`/`open` fail closed (`MsfRpcUnavailable`) when no correlated session exists; (4) `close()`
  returns the real teardown result (False if `session.stop` errors). `approved_rhost` is in the signed
  consent hash; the console (`aegis/interactive.py`) pins RHOSTS/RHOST/RPORT to the authorized target.
  Also tightened `_select_correlated_session`: a lone new session is accepted only when its target is
  genuinely unknown, never when its own host metadata names a different host (reproduced provenance
  hole). Evidence: safe-precheck⇒refused, `module.execute` never called; unrelated/pre-existing
  session (host 10.0.0.250 ≠ approved 10.0.0.5)⇒`MsfRpcUnavailable`; options RHOSTS mismatch⇒
  `PermissionError`; happy path⇒session 9, `close()`⇒True; `session.stop` raises⇒`close()`⇒False.
  Regressions `tests/product/test_msf_rpc_sector_o2.py::SessionProvenanceRegressions` (5) +
  `test_o5_interactive_session.py` (stateful, approved_rhost) — 16 pass; mypy clean; full suite 1024
  pass / 1301 subtests. `packages/scanner_adapters/integrations/msf_rpc.py`, `aegis/interactive.py`.

### P0-C · One evidence-based finding state machine  (F06)
- [x] **C1 · Bulk-triage cannot invent confirmed (F06).** The bulk endpoint now rejects CONFIRMED/
  RESOLVED (evidence required, matching the individual endpoint) and maps OPEN/IN_REVIEW/
  FALSE_POSITIVE to real finding statuses via `BULK_TRIAGE_STATUS_MAP` — also fixing latent status
  corruption (it previously wrote raw `confirmed`/`resolved`/`in_review`). Evidence: before, bulk
  CONFIRMED⇒200; after, CONFIRMED/RESOLVED⇒422, FALSE_POSITIVE⇒200 `new_status=false_positive`;
  regression in `tests/product/test_visualization_api.py` (11 pass). `aegis/api.py`.

### P0-D · Final-boundary signatures & isolation  (F09–F12)
- [x] **D1 · Update applies only with a valid signature (F09/E05).** `apply_update_staged` now
  verifies the manifest signature at the write boundary before any file I/O, and the embedded
  default HMAC secret is removed (trust root must come from a key or `SHARAY_UPDATE_SECRET`, else it
  fails closed). Evidence: before, invalid signature + correct hash ⇒ applied; after, no-key⇒reject,
  wrong-sig⇒reject, correct-sig⇒apply; API `/system/update/apply` rejects a tampered signature with
  400. Regressions in `tests/integration/test_turnkey_onboarding_and_autoupdate.py` and
  `tests/product/test_onboarding_api.py`. `services/update_worker/updater.py`.
- [ ] **D2 · Signed detection packs cover behavior (F10/E09).** Matcher/behavioral fields are in the
  signed canonical bytes; altering a matcher invalidates the signature. Anchor S34.
- [ ] **D3 · Fail-closed isolation (F11/F12).** No silent host fallback when the sandbox/VM is
  unavailable; cosign verify needs a real verifier; attestation records controls actually applied.
  Anchor S08, S10, S35.

### P0-E · Repair metrics, gates & execution claims  (F07, F08, F18–F20)
- [x] **E1 · Null detector must fail the eval gate (F18/E02).** Precision no longer defaults to 1.0
  with zero positive predictions (now 0.0); the PASS gate now requires `overall_recall >=
  MIN_BENCHMARK_RECALL` (1.0 on the handcrafted corpus). Evidence: before, NULL⇒prec 1.0/recall
  0.0/**PASS**; after, NULL⇒0.0/0.0/**FAIL**, NOISY⇒FPR 1.0/**FAIL**, REFERENCE⇒1.0/1.0/**PASS**;
  regressions in `tests/evaluation/test_evaluation_lab.py` (10 pass). `packages/evaluation_lab.py`.
- [ ] **E2 · Sound benchmark scorer (F19/E08).** No empty-CWE matches; duplicates do not inflate
  TPs; recall ∈ [0,1]; FPR well-defined. Anchor S19.
- [ ] **E3 · Completion derives from execution (F07/E06).** Empty AI analysis cannot report
  `posture_score=100` + completed phases; port fallback cannot fabricate an open service; stage
  exceptions are not `completed`. "No findings" ≠ "clean coverage". Anchor S30, S06, S04.
- [x] **E4 · Remediation validator honesty (F08/E04).** `validate_patch` is now suggestion-only:
  `deployable` is never True from heuristics; a hunk-less diff, nonsensical config and unknown
  languages are rejected (`is_valid=False`); valid python/json/config/diff are `is_valid` but
  suggestion-only. Evidence: before, hunk-less diff + nonsensical nginx + unknown language all
  `deployable=True`; after, all `is_valid=False`; real diff/python `is_valid=True, deployable=False`;
  regressions `tests/integration/test_remediation_validation.py` (3/11) + corrected
  `tests/evaluation/test_ai_eval_harness.py`. `services/ai_analysis_worker/remediation.py`.
- [ ] **E5 · Test gate runs the intended tests (F20).** The active gate discovers the pytest-style
  tests currently omitted; non-existent generated test paths removed. Anchor S38–S40.

---

## P1 — Wire configuration, credentials, source lifecycle & operations

- [ ] **P1-1 · Every UI scan option dispatches & records (wiring ledger).** No displayed option is
  rejected by the API `Literal` list; each produces a recorded result. Anchor S45, S02.
- [ ] **P1-2 · Source analysis joins the normal lifecycle.** Source findings persist as
  assessment/findings/evidence and appear in reports & retests (not returned ad hoc). Anchor S21.
- [ ] **P1-3 · SAST/SCA/SBOM assembled workflow.** Semgrep dispatch, OSV advisory source + freshness,
  CycloneDX SBOM analysis wired with tool/version/feed identity recorded. Anchor S21, S53–S54.
- [ ] **P1-4 · Authenticated testing.** Approved credential refs → identity-specific jobs with
  stored redacted evidence. Anchor S06, S12.
- [ ] **P1-5 · AI investigations persist.** Typed plan → policy → operator approval → execution →
  usage/outcome survive restart. Anchor S29.
- [ ] **P1-6 · Working deployment.** One supported deployment from clean env: login → authorized
  scan → report → restart → recovery. Dockerfile command matches the real CLI; Postgres path real or
  removed. Anchor S26, S42–S44, S48.
- [ ] **P1-7 · Durable integrations.** Retention actually mutates the DB; ticketing hits a real
  provider or is labelled local; notary trust root configured. Anchor S36, S37, S24.
- [ ] **P1-8 · MFA / project RBAC enforced.** TOTP persists + gates login; project membership
  enforced on normal API access. Anchor S22–S23, S31, S49.

---

## P2 — Purple-team loop & research validity

- [ ] **P2-1 · Attack → sensor/detection → fix → retest closure** with negative controls. Anchor S12, S16, S20.
- [ ] **P2-2 · Controlled comparative evaluation** with held-out targets, ablations, uncertainty,
  matched budgets (Cybench/CVE-Bench/OWASP-Benchmark/ASVS/ATT&CK as frameworks, not scores).

---

## Cross-cutting acceptance (the "working SHARAY" bar)
- [ ] **X1 · UI scans end-to-end.** From the operator UI: register target → authorize → launch →
  live status → findings → report, verified in a real browser against a loopback fixture.
- [ ] **X2 · CLI parity.** `cmd_scan` reaches the same contract (auth precedes scan, same clamps).
- [◐] **X3 · Operator console functionality.** _Console TLS probe/verify fixed_ (user-reported SSL
  error): the workspace probe and the reproducer now connect to an authorized HTTPS target without
  cert verification (self-signed/expired/mismatched certs are observations, not connection errors),
  matching the scanner's TLS inspection; `tls_verified` recorded. Evidence: self-signed HTTPS
  loopback server ⇒ probe status 200 / reproducer status 200 (was SSLCertVerificationError / status
  0); regression `tests/integration/test_console_tls_probe.py`. `packages/scanner_adapters/
  workspace.py`, `reproducer.py`. Console `msf session` consent/session semantics now hardened (B2):
  RHOSTS/RHOST/RPORT pinned to the authorized target, execution gated on a vulnerable precheck, the
  driven session provably correlated to this run. _(Remaining for full X3: end-to-end console
  walk-through under X1/X2.)_
- [ ] **X4 · Full suite + gates green** (unit/integration/product + web lint/typecheck/build + mypy +
  ruff), with the previously-omitted tests included.
- [ ] **X5 · No reproduced counterexample remains** — every E01–E11 is a permanent passing regression.

---

## Evidence log
(Reproductions and fixes are appended here per item as they are completed.)
