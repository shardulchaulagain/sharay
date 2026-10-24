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
- [x] **A2 · Private-destination parity (F01/E07).** The workspace probe (`workspace.py`) used
  registration validation (`validate_scope`/`check_url`) plus an ordinary connection, so it accepted
  a private non-loopback destination the scan worker's `check_execution_url` rejects. `execute_probe`
  now applies `check_execution_url(owned=...)` — the identical execution contract (approved loopback
  lab, or an owned public target; never a private/internal address) — for the target URL and the
  merged-query URL. `owned` is threaded from the API (`verification_status == "operator_authorized"`)
  and the CLI (new `--authorized` flag; loopback probes supply their `/32`·`/128` CIDR). Worker and
  interactive console already enforced `check_execution_url`; the browser and reproducer run inside
  the scan on the already-validated `destination.url`, so no independent entrypoint stays weaker.
  Evidence: for `http://10.0.0.5/`, `check_url` ACCEPTS but `check_execution_url` and `execute_probe`
  both REJECT (owned True and False); the loopback console-TLS probe still succeeds. Regression
  `tests/product/test_authorization_contract.py::WorkspaceDestinationParityTests`. Full suite 1037
  pass / 1301 subtests; mypy + ruff clean. `packages/scanner_adapters/workspace.py`, `aegis/cli.py`,
  `aegis/__main__.py`, `aegis/api.py`.
- [x] **A3 · Scope + cancellation survive dispatch (F03).** `scan_comprehensive` received only the
  `Destination` + options — no `ScopePolicy` and no cancel callback — so it could neither enforce the
  excluded-path contract nor stop mid-run. It now takes `scope` and `cancelled` (wired from the
  worker, which already holds both, and from the CLI). (1) Every crawler-discovered endpoint, URL and
  form action is filtered through the plain `check_url` path/exclusion contract BEFORE the active
  stages iterate them, so an out-of-scope or excluded path is never probed (not merely filtered from
  results); the count excluded is recorded as a `scope_enforcement` check. (2) A cancellation request
  short-circuits the heavy active stages (crawler, differential, nuclei, metasploit) and the
  reproducer re-probe loop, and the run finalizes with outcome `cancelled`. Evidence: `cancelled`
  True at dispatch ⇒ outcome `cancelled`, crawler never invoked; scope `allowed_paths=["/app"]` with
  discovered `/app/ok` + `/admin/secret` ⇒ only `/app/ok` kept, `scope_enforcement` check emitted.
  Regressions in `tests/integration/test_comprehensive_pipeline.py` (2). Full suite 1045 pass / 1301
  subtests; mypy + ruff clean. `packages/scanner_adapters/__init__.py`, `aegis/worker.py`,
  `aegis/cli.py`. Follow-up (done): cancellation now guards every active stage (crawler, differential,
  7b/7f/7c/7d native+fuzzing+authz+payload, OOB, anomaly, nuclei, toolbelt, ZAP, metasploit, opt-in
  audits, reproducer loop); `crawler.crawl` takes `probe_sensitive` so the active sensitive-file
  probe is NOT dispatched unless the `sensitive` tool is enabled (was always probing /.git, /.env,
  backups regardless), and exposed-file results are scope-filtered. Regressions
  `tests/integration/test_crawler.py::CrawlerSensitiveProbeGatingTests` (2). Full suite 1047 pass.
- [x] **A4 · CLI approval provenance (F04).** `cmd_scan` scanned first, then auto-provisioned an
  owner with a baked-in password (`admin-cli-owner-pass-123`), auto-marked every new target
  `operator_authorized`, persisted finding status as a flat `"suspected"`, and swallowed any
  persistence failure into a success-looking "[*] Note:". Rewritten so authorization precedes
  execution: in one transaction it resolves a real owner (refuses with guidance if none — no
  hardcoded provisioning), records the target authorization (loopback ⇒ `verified_lab`; a live
  target only with the new `--authorized` flag, else refused) and the assessment (binding
  `scope_version`), and validates the destination via `check_execution_url(owned=...)` — all before
  any probe. Results persist into that pre-created assessment with finding status from the worker's
  `_finding_status` (REPRODUCED/verified ⇒ `confirmed`, with the same no-downgrade rules), and a
  persistence failure now returns exit 2 instead of a note. Evidence: no owner ⇒ exit 1, nothing
  provisioned, scanner never called; live target without `--authorized` ⇒ exit 1, scanner never
  called; authorized loopback-style run ⇒ assessment recorded (owner-bound, scope_version set) and a
  REPRODUCED finding persisted as `confirmed`; a fingerprint-less finding ⇒ exit 2. Regressions
  `tests/integration/test_cli.py::CliScanAuthorizationTests` (4). Full suite 1042 pass / 1301
  subtests; mypy + ruff clean. `aegis/cli.py`, `aegis/__main__.py`.

### P0-B · Correct impact & session provenance  (F05, F13)
- [x] **B1 · Class-specific confirmation (F05/E01).** A reflected canary no longer confirms when it
  is merely our own injected input echoed back as inert text (the `DifferentialOracle` gave any
  reflection +50, enough to reach `REPRODUCED` alone). It now contributes only +5 (observational,
  non-confirming) when the canary is a substring of the active payload AND carries no markup
  metacharacter; it keeps the full +50 for an unescaped markup reflection (executable XSS context) or
  an independent effect signature (a DB-error string, a `/etc/passwd` marker) that the payload did not
  contain. Evidence: a search box echoing `sharay_canary_7f3a` ⇒ before REPRODUCED/confirmed, after
  DEMOTED; `"><sharay_canary>` reflected unescaped ⇒ REPRODUCED; SQL-error (`"syntax"`) and an LFI
  passwd line the oracle's literal markers miss (`root:!:0:0:`, canary `"root:"`) ⇒ still REPRODUCED.
  Regression `tests/product/test_reproducer.py::BenignReflectionRegressions` (3) + four prior tests
  that had codified the unsound echo path rewritten to confirm via a real postcondition. Full suite
  1027 pass / 1301 subtests; mypy + ruff clean. `packages/scanner_adapters/reproducer.py`.
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
- [x] **D2 · Signed detection packs cover behavior (F10/E09).** `DetectionTemplate.canonical_bytes`
  signed only the request metadata (id/name/method/path/headers/body) — not the `matchers`, which
  ARE the detection behavior — so a matcher could be swapped (e.g. a precise word matcher turned
  into regex `.*`) while the Ed25519 signature stayed valid. The matchers (type, words, regexes,
  status codes, part, condition, and their order) are now part of the signed canonical bytes.
  Evidence: before, tampering a matcher ⇒ `verify_ed25519()` still True; after, matcher/condition
  tamper ⇒ False, and re-signing is required to verify again. Regression
  `tests/product/test_detection_packs.py::test_matcher_tampering_invalidates_signature`; the 3 prior
  pack tests still pass. Full suite 1043 pass / 1301 subtests; mypy + ruff clean.
  `packages/detection_packs.py`.
- [◐] **D3 · Fail-closed isolation (F11/F12).** _Cosign fail-open closed:_
  `ImagePinningEngine.verify_cosign_signature` returned `True` whenever no verifier callback was
  supplied — assuming a valid image signature with nothing having checked it. It now fails closed:
  with no `verifier_fn` configured it raises `IsolationError` ("No cosign verifier is configured;
  refusing to assume a valid image signature"); a real/stub verifier's verdict is reflected
  (True/False), and the missing-trusted-key guard is unchanged. Evidence: before, `(pinned, key)` ⇒
  True; after, `(pinned, key)` ⇒ `IsolationError`, `(pinned, key, lambda:…True)` ⇒ True,
  `…False` ⇒ False. Regression in `tests/integration/test_container_backend.py` (24 pass). Full
  suite 1043 pass / 1301 subtests; mypy + ruff clean. `services/scanner_worker/container.py`.
  _(Remaining: `attest()` advertises controls from the runtime binary name rather than a
  `podman info`/per-run capability probe; VM-branch host fallback; Chromium `--no-sandbox` — each
  needs a live container/VM/browser to verify a fix, so deferred to the deployment-validation pass.)_

### P0-E · Repair metrics, gates & execution claims  (F07, F08, F18–F20)
- [x] **E1 · Null detector must fail the eval gate (F18/E02).** Precision no longer defaults to 1.0
  with zero positive predictions (now 0.0); the PASS gate now requires `overall_recall >=
  MIN_BENCHMARK_RECALL` (1.0 on the handcrafted corpus). Evidence: before, NULL⇒prec 1.0/recall
  0.0/**PASS**; after, NULL⇒0.0/0.0/**FAIL**, NOISY⇒FPR 1.0/**FAIL**, REFERENCE⇒1.0/1.0/**PASS**;
  regressions in `tests/evaluation/test_evaluation_lab.py` (10 pass). `packages/evaluation_lab.py`.
- [x] **E2 · Sound benchmark scorer (F19/E08).** The fixture scorer (`tests/fixtures/eval_lab/
  evaluator.py`) yielded impossible metrics: an empty-string CWE substring-matched every item, a
  substring CWE matched (`CWE-7`⊂`CWE-79`), each duplicate finding added another TP, so one
  ground-truth item + three unrelated findings gave recall=3.0, F1=1.5, **PASS**; the FPR had no true
  negatives. Rewritten: matching is keyed on location (endpoint + parameter) with CWE as an exact
  identity that only blocks on conflict (never empty, never substring); a TP is a distinct
  ground-truth item detected (redundant findings for one item count once), so recall ∈ [0,1] by
  construction; added an always-defined `false_discovery_rate` and a true `false_positive_rate`
  measured over an optional benign corpus (None when absent, never fabricated from positives); the
  gate uses precision + FDR + measured FPR. Evidence: the impossible case now gives tp=0, recall=0.0,
  **FAIL**; `CWE-7`≠`CWE-79`; three findings for one vuln ⇒ tp=1/recall=1.0; the mock-server corpus
  still scores tp=4/precision=1.0/recall=0.8/fpr=0.0/**PASS**. Regressions
  `tests/product/test_eval_lab.py::BenchmarkScorerSoundnessTests` (4) + updated end-to-end assertions;
  catalog gains a `benign` corpus. Full suite 1036 pass / 1301 subtests; mypy + ruff clean.
- [x] **E3 · Completion derives from execution (F07/E06).** Three fabrications removed: (1) an AI
  analysis with no graph nodes, observations or findings reported `posture_score=100` + all five
  kill-chain phases `completed` — now posture is `None` with `assessed=False`/`coverage="none"`,
  phases are `not_executed`, and the executive summary states posture is UNKNOWN; an assessed target
  with no findings still scores 100 (ran-and-clean), a HIGH finding 85. (2) The port stage fabricated
  an `open` `network_service` when the scan found none (and in its `except` handler) — it now records
  "no open TCP services observed" honestly and never invents one. (3) Eighteen stage `except`
  handlers recorded `status="completed"` while naming the caught exception — all now `failed` with
  truthful detail (the reporting layer already excludes `failed` from coverage). UI: `posture_score`
  renders "Not assessed" instead of "null / 100"; kill-chain cards color/label by real status.
  Evidence: empty analysis ⇒ `posture_score=None`, phases `not_executed`; port scan returning no obs
  ⇒ no `sharay_port_verifier` observation; port scan raising ⇒ `network_inventory` check `failed`.
  Regressions `tests/integration/test_ai_reasoning.py::CompletionDerivesFromExecutionTests` (3) +
  `test_comprehensive_pipeline.py` port-stage tests (2). Full suite 1032 pass / 1301 subtests; mypy +
  ruff clean; web `tsc --noEmit` clean. `services/ai_analysis_worker/reasoning.py`,
  `packages/scanner_adapters/__init__.py`, `apps/web/app/{assessments,workspace,api}.tsx`/`.ts`.
- [x] **E4 · Remediation validator honesty (F08/E04).** `validate_patch` is now suggestion-only:
  `deployable` is never True from heuristics; a hunk-less diff, nonsensical config and unknown
  languages are rejected (`is_valid=False`); valid python/json/config/diff are `is_valid` but
  suggestion-only. Evidence: before, hunk-less diff + nonsensical nginx + unknown language all
  `deployable=True`; after, all `is_valid=False`; real diff/python `is_valid=True, deployable=False`;
  regressions `tests/integration/test_remediation_validation.py` (3/11) + corrected
  `tests/evaluation/test_ai_eval_harness.py`. `services/ai_analysis_worker/remediation.py`.
- [x] **E5 · Test gate runs the intended tests (F20).** The gate's runner used
  `unittest.defaultTestLoader.discover("tests")`, which collects only `unittest.TestCase` subclasses
  and silently skipped 80 pytest-style tests (48 module-level `def test_*` functions + non-TestCase
  classes): discovery counted 957 while pytest collects 1037. `engineering/run_tests.py` now also
  runs the whole tree under pytest in its own process (clean per-process state, so a TestCase run by
  both runners does not trip caches like onboarding-session isolation), and the gate fails if either
  runner fails; the redacted unittest diagnostics sidecar is unchanged. Gate timeout raised 360→600s
  for the double run; `AGENTS.md` now documents pytest as the complete runner. Evidence: a
  module-level pytest-style failing test (invisible to `discover`) now fails the gate (exit 1) and a
  passing one passes (exit 0); the authoritative `engineering/run_tests.py` exits 0 with "Ran 957 …
  OK" and "1037 passed / 1301 subtests". Regression
  `tests/test_engineering.py::EvidenceTests::test_pytest_style_tests_are_not_skipped_by_the_gate`;
  32 engineering-contract tests still pass. (Active `gates.json` paths all exist; the "generated"
  coverage/mutation jobs the audit flagged live only in unwired drafts.) `engineering/run_tests.py`,
  `engineering/gates.json`, `AGENTS.md`.

---

## P1 — Wire configuration, credentials, source lifecycle & operations

- [x] **P1-1 · Every UI scan option dispatches & records (wiring ledger).** The operator UI
  (`apps/web/app/projects.tsx`) offers `cve`, `graphql`, `websocket` and `wordlist` tool toggles and
  the scanner dispatches them (CVE stage + stages 11–13, each recording a check), but the API
  `ScanConfig.tools` `Literal` omitted all four — selecting any of them failed launch validation
  (422). Added the four to the Literal (max_length 18→19). UI profiles (safe_http/approved_templates/
  comprehensive) and modes (passive/standard/adaptive/aggressive) already matched. Evidence: before,
  `ScanConfig(tools=["cve"])` ⇒ ValidationError; after, each of the 4 and the full 16-tool UI
  selection validate, and an unknown tool is still rejected. Regression
  `tests/product/test_authorization_contract.py::UiToolOptionParityTests`. Full suite 1052 pass /
  1316 subtests; mypy + ruff clean. `aegis/schemas.py`.
- [◐] **P1-2 · Source analysis joins the normal lifecycle.** `/source-analysis` returned findings
  ad hoc and only recorded an audit event — they never reached the Findings list, reports or retests.
  `SourceAnalysisInput` now takes an optional `target_id`; when given, the endpoint creates a
  `source_analysis`-profile `Assessment` under that target and persists the source findings as
  `Finding` + `FindingEvidence` (worker-parity status via `_finding_status`, secret values redacted),
  so they appear in the normal lifecycle. Omitting `target_id` keeps the ad-hoc result. Evidence:
  POST with `target_id` ⇒ a source-profile assessment + a persisted `secret_exposure` finding under
  the target; without it ⇒ no assessment created. Regression
  `tests/product/test_source_analysis_lifecycle.py` (2). Full suite 1059 pass. `aegis/api.py`,
  `aegis/schemas.py`. _(Remaining: a target picker in the standalone Source-analysis UI page.)_ Anchor S21.
- [x] **P1-3 · SAST/SCA/SBOM assembled workflow.** _SAST (Semgrep) is now wired and verified:_
  `analyze_source_tree` runs Semgrep over the authorized tree with a pinned, committed SHARAY ruleset
  (`services/source_analysis_worker/semgrep_rules.yml`), normalizes results through
  `SourceScannerPipeline.normalize_semgrep`, and records tool + version + ruleset identity in the
  check (e.g. "Semgrep 1.182.1 … reported N SAST finding(s)"). Semgrep is treated as an optional
  external tool (resolved from `SHARAY_SEMGREP_BIN`, the venv, or PATH) — absent ⇒ SAST is skipped
  honestly, never silently omitted — and the `/overview` tool catalog reports it available only when
  present (like gitleaks). SAST findings join the lifecycle via P1-2's target persistence. Evidence:
  an `eval()` + `subprocess(shell=True)` tree ⇒ findings with CWE-95 and CWE-78; a clean tree ⇒ no
  SAST findings; check `completed`. Regression `tests/integration/test_semgrep_sast.py` (skips when
  semgrep is absent). Full suite 1064 pass. `services/source_analysis_worker/assess.py`,
  `.../semgrep_rules.yml`, `aegis/api.py`. _SCA (OSV) now wired too:_ `analyze_source_tree` matches
  the declared dependencies against an operator-supplied OSV feed (`SHARAY_OSV_ADVISORIES`, a JSON
  file of OSV records) offline via `SourceScannerPipeline.normalize_osv`, recording the feed identity
  and freshness (file mtime) in the check; absent feed ⇒ SCA skipped honestly; the `/overview`
  catalog gains an `osv_sca` entry gated on the feed. Evidence: `requests==2.19.0` + an advisory
  fixing it in 2.20.0 ⇒ one `vulnerable_dependency` finding; no feed ⇒ skipped, no findings.
  Regression `tests/integration/test_source_sca_osv.py`. _SBOM (CycloneDX) now ingested too:_ a
  committed `bom.json`/`sbom.json`/`*.cdx.json` is parsed in-process (`sbom.parse_cyclonedx`) and its
  components join the SCA match set, so a transitive dependency present only in the SBOM (e.g.
  `lodash@4.17.11`) is matched against the OSV feed; the `/overview` catalog gains an `sbom_cyclonedx`
  entry. Full suite 1067 pass; mypy + ruff clean. `services/source_analysis_worker/{assess,sbom}.py`,
  `aegis/api.py`. Anchor S21, S53–S54.
- [x] **P1-4 · Authenticated testing.** _Done:_ Fernet-encrypted credential store (plaintext never
  persisted), `/api/v1/credentials` CRUD, scope policy accepts `authenticated` + bounded
  `credential_refs`, worker resolves refs into the crawler's cookies/headers, identity names stored
  as redacted evidence. UI credential panel still pending (backend fully wired). Anchor S06, S12.
- [◐] **P1-5 · AI investigations persist.** `run_ai_investigation` computed the analysis (optionally
  via an LLM provider) but never stored it, and `get_ai_investigation` recomputed on every view — so
  the result (and any provider narrative/usage) did not survive restart and could be re-billed. Added
  `Assessment.ai_investigation` (JSON; Alembic `0005_assessment_ai_investigation`); `run` now persists
  the full payload and `get` returns the stored one (`persisted: true`) when present, recomputing a
  deterministic view only when none was ever run. Evidence: POST investigate ⇒ row.ai_investigation
  set; a fresh app instance (restart, new engine/same DB) ⇒ GET returns the persisted result.
  Regression `tests/product/test_ai_investigation_persists.py`. Full suite 1057 pass; mypy + ruff
  clean. `aegis/api.py`, `aegis/models.py`. _(Remaining: a typed plan → policy → operator-approval
  gate before execution, and provider token/cost accounting in the stored payload.)_ Anchor S29.
- [◐] **P1-6 · Working deployment.** One supported deployment from clean env: login → authorized
  scan → report → restart → recovery. _Done:_ the container command now matches the real CLI —
  `serve --port … --host …` (rejected by argparse, exit 2, so the container never started — E10) is
  now `--port 8000 serve` (parent option before the subcommand; no `--host`, serve binds loopback),
  fixed in both the committed `Dockerfile` and `ProductionDeploymentConfig.generate_dockerfile()`,
  with a regression that replays the CMD through the real parser. _(Remaining: the Postgres compose
  path — real or removed, incl. its hardcoded default password — and an end-to-end clean-env deploy
  run, which needs a live container.)_ Anchor S26, S42–S44, S48.
- [◐] **P1-7 · Durable integrations.** _Retention now mutates the DB:_ the `/lifecycle/retention`
  endpoint discarded `enforce_retention`'s result and reported a purge that never happened. It now
  deletes each expired assessment with its observations and finding-evidence rows (org-scoped) in the
  request transaction. Evidence: a 120-day-old assessment + its observation are gone after the call
  (`purged_assessments_count=1`), a fresh one remains. Regression
  `tests/product/test_retention_mutates_db.py`. _PII redaction now also lands:_ the endpoint passed
  observations without their `data`, so the age-gated redaction was a no-op; it now passes `data` and
  writes the redacted payload back to each kept observation older than the evidence cutoff. Evidence:
  an observation containing `alice@example.com` observed 20 days ago ⇒ the DB row's data holds
  `[REDACTED_EMAIL]`, not the address (`redacted_records_count ≥ 1`). Full suite 1062 pass.
  `aegis/api.py`. _(Remaining: ticketing-to-a-real-provider or labelled-local, and notary trust
  root — both need an external provider/key.)_ Anchor S36, S37, S24.
- [x] **P1-8 · MFA / project RBAC enforced.** _MFA now persists and gates login:_ TOTP was cosmetic
  — `totp_setup` never stored the secret, `totp_verify` checked a secret passed in the request, and
  `sign_in` had no MFA check. Now the `User` model carries `totp_secret`/`totp_enabled`/
  `totp_backup_hashes` (Alembic `0004_user_totp`); `totp_setup` persists a pending secret +
  backup-code hashes, `totp_verify` enables MFA against the stored secret, and `sign_in` requires a
  valid TOTP or single-use backup code for enrolled accounts (a bad/missing code is a failed login
  against the lockout budget; non-enrolled accounts are unaffected). The UI login form gained an
  optional MFA code field. Evidence: non-enrolled login needs no code; enrolled login rejects
  missing/`000000`, accepts the live TOTP, accepts a backup code and consumes it (2→1, no reuse).
  Regression `tests/product/test_mfa_login_gate.py` (3). Full suite 1056 pass; mypy + ruff + web tsc
  clean. `aegis/{models,auth,api,schemas}.py`, `migrations/versions/0004_user_totp.py`,
  `apps/web/app/login.tsx`. _Project RBAC now enforced:_ a new `ProjectMember` model (Alembic
  `0006_project_members`, which backfills each project's owner) is checked centrally in `owned()` —
  org admins (owner, security_administrator) see every project, while analyst/viewer reach a
  project-scoped resource (project, target, assessment, finding) only when they belong to its
  project; the `/projects` list is filtered the same way, the project creator is auto-added as a
  member, and `GET/POST/DELETE /projects/{id}/members` manage membership (admins only). Evidence: a
  non-member analyst gets `[]`/404 for a project, 200 after being granted membership, 404 again after
  revoke; a project creator is auto-member. Regression `tests/product/test_project_rbac.py` (2); the
  two role-denial tests updated to the RBAC semantics; the additive-migration test excludes the
  migration-backfilled table. Full suite 1061 pass / 1316 subtests; mypy + ruff clean.
  `aegis/{models,api}.py`, `migrations/versions/0006_project_members.py`. _(Remaining: a member-management
  UI on the project page.)_ Anchor S22–S23, S31, S49.

---

## P2 — Purple-team loop & research validity

- [ ] **P2-1 · Attack → sensor/detection → fix → retest closure** with negative controls. Anchor S12, S16, S20.
- [ ] **P2-2 · Controlled comparative evaluation** with held-out targets, ablations, uncertainty,
  matched budgets (Cybench/CVE-Bench/OWASP-Benchmark/ASVS/ATT&CK as frameworks, not scores).

---

## Cross-cutting acceptance (the "working SHARAY" bar)
- [x] **X1 · UI scans end-to-end.** Verified in a real browser against the live stack (`aegis serve`
  serving the Next.js UI + loopback API on one origin) and a loopback HTTP fixture: login → create
  project → register target `http://127.0.0.1:9011/` → review scope → record authorization (→
  `Verified Lab`) → approve & launch → live status (`Running`) → `Completed` with **4 observations /
  4 findings** (missing CSP, X-Content-Type-Options, Referrer-Policy, frame protection) → report
  export returns 200 (JSON 45 KB with assessment/checks/findings/observations/scope). **This
  walkthrough surfaced a real bug that broke every UI scan** (`6984ac1`): the worker's
  `PersistentRequestStarts._interval` rejected any cooldown < 0.1s, so a scope at the default
  `request_rate=150` (interval ≈ 0.0067s) crashed into a generic "malformed response" failure at 0s;
  now only a corrupt (non-finite/non-positive) cooldown is rejected, and the same assessment
  completes with findings. Regression `test_worker_pacing.py::test_high_rate_scope_scans_without_crashing`.
- [x] **X2 · CLI parity.** Delivered by A4 + A3: `cmd_scan` now records the owner/target
  authorization and the assessment (binding `scope_version`) and validates the destination via
  `check_execution_url(owned=...)` BEFORE any probe; the rate ceiling clamps identically (A1,
  `ScanConfig.within_scope`), finding status is derived by the worker's `_finding_status`, and the
  scope is threaded into `scan_comprehensive` (A3). Verified by
  `test_cli.py::CliScanAuthorizationTests` (auth precedes execution; worker-parity status; no-swallow).
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
- [◐] **X4 · Full suite + gates green** (unit/integration/product + web lint/typecheck/build + mypy +
  ruff), with the previously-omitted tests included. **`check.py --run-gates` bundle is green:**
  `{python-unit-and-integration-tests: passed, python-lint: passed, python-format: passed,
  python-types: passed}` (test gate diagnostics `tests_run=967, failures=0, errors=0, skipped=0`; the
  runner also runs the full 1047-test pytest leg, E5). Web side clean: `tsc --noEmit` exit 0, `eslint`
  exit 0 (1 pre-existing non-blocking warning), `oxlint` exit 0. Fixed en route: 4 pre-existing lint
  errors in `scripts/run_live_scan.py` and format drift in 3 edited files. _(Remaining: `next build`
  not run — heavier, deferred to the deployment-validation pass.)_
- [x] **X5 · No reproduced counterexample remains** — every E01–E11 is a permanent passing
  regression: E01 benign reflection (B1), E02 null detector (E1), E03 rate ceiling (A1), E04 patch
  validator (E4), E05 invalid update (D1), E06 empty-AI completion (E3), E07 private destination
  (A2), E08 alternate scorer (E2), E09 signed matcher (D2), E10 Docker CLI command mismatch
  (`test_packaging_and_deploy.py::test_container_command_matches_real_cli_grammar`), E11 RPC session
  (B2). Each reproduced first, then pinned by a test that fails on the old behavior.

---

## Evidence log
(Reproductions and fixes are appended here per item as they are completed.)
