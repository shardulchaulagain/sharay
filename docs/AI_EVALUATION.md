# Evaluation scope and reproducibility

Claude's October12 dated measurements were reviewed by Codex. A narrow HTTP configuration corpus exists; its historical results are in [integrations/EVALUATION.md](integrations/EVALUATION.md). A separate partial OS-level runner has tested controls in [integrations/ISOLATION.md](integrations/ISOLATION.md). Product AI, actual third-party scanner compatibility and general detection accuracy remain unmeasured. Engineering assistant replies in SESSION_LOG are not product AI evaluations.

No LLM provider, AI planner, conversational investigator or model-generated tool execution is active. Deterministic local scanning and reporting are designed to run without an LLM. AI precision, recall, token use, latency, cost and remediation quality have **not been measured**. An absent provider is not a successful AI evaluation, and no aggregate accuracy score is reported.

The current verification scope is an explicitly approved literal loopback laboratory: controlled HTTP fixtures, deterministic destination policy, stored observations, header findings, cancellation, redaction, report rendering and the seeded issue/fix/retest workflow. These checks establish regressions in that scope; they do not establish detection of all web/API vulnerabilities or any full cybersecurity-domain coverage. No unauthorized real-world target is an evaluation fixture.

## Current test evidence

Use the actual exits and function-level results recorded in [implementation status](IMPLEMENTATION_STATUS.md) and the [change ledger](change-ledger.md). Pending checks must remain pending until executed against integrated code. Do not treat designed fixture cases as benchmark measurements.

| Area | Local evidence | Interpretation / limit |
| --- | --- | --- |
| Policy refusal | Scope/address/path/redirect/expiry tests for literal approved loopback targets | Tests the implemented policy; hostname DNS discovery is unavailable |
| Scanner observations | Real bounded HTTP responses from an intentionally controlled local fixture | A header response is an observation; it is not proof of exploitability |
| HTTP configuration corpus v1 | 16 loopback response cases, adapter 1.1.1: TP 18, FP 0, FN 0, no incomplete scans; rerun exit 0 | Labels were curated for these checks; agreement does not establish general detection accuracy |
| Retest | Fix seeded fixture headers, rescan, compare finding status; exercise failed retest | Resolved status requires successful coverage of the same approved check |
| Redaction | `tests/product/test_reporting.py` recursively checks dict/list secrets, headers, URL credentials, query tokens and private keys | Pattern-based defense; arbitrary unlabeled secrets and personal data cannot be exhaustively classified |
| Report content | Reporting tests check stable JSON metadata/hash retention, HTML escaping, empty findings, failure disclosure and PDF creation | PDF bytes and HTML parser checks alone do not prove layout or browser accessibility |
| Access controls | Organization/RBAC/session/CSRF integration tests required | Passing one route does not establish all-route access safety |
| AI provider | Unavailable; no invocation or credentials configured | Model quality and provider privacy are unmeasured |
| External scanner tools | Execution unavailable; some parser/plumbing tests use labelled synthetic data | No actual tool/version compatibility or ZAP/Nuclei/Nmap/Semgrep/Gitleaks precision claim |
| OS worker isolation | Separate partial Seatbelt backend verified with controlled local fixtures; product HTTP worker remains a dedicated process | General memory/live-egress bounds and product integration are unavailable |

The independently rerun corpus has SHA256 `33a8bfe1b87828b875d1be89c237e7e81d99411a38ae82e21dc5c29d342762a3`; its generated report is `.engineering/http-configuration-evaluation.json`. Run `.venv/bin/python -m tests.evaluation.http_configuration` to reproduce. The observed TP/FP/FN denominators describe finding checks in these 16 synthetic cases, not all possible responses or vulnerability classes.

The built-in adapter checks CSP presence/non-emptiness, recognized Referrer-Policy tokens, `X-Content-Type-Options: nosniff`, framing host patterns and XFO processing, HSTS presence for HTTPS only, and observed cookie HttpOnly flags. Adapter 1.1.1 preserves first-directive/multiple-CSP-policy semantics, CSP framing precedence over XFO and repeated Referrer fields. Nonempty CSP does not mean valid/protective CSP; recognized Referrer policy does not mean strong privacy. Combined scheme/port/path and browser behavior are explicitly untested. Findings remain configuration observations with informational/low severity and no CVSS or exploitability claim. Evidence retains facts and limits, not arbitrary header/cookie values or response bodies; historical observations remain unchanged.

`tests/product/test_policy_scanner.py::ScannerTests.test_real_fixture_seeded_issues_then_repaired_headers_clear_findings` is the exercised local ground-truth case: `fixtures/safe_targets/server.py` serves a controlled HTTP response with five configuration findings; `secure_headers=True` fixes those response properties and produces zero findings. This finite fixture regression does not provide broad scanner precision or recall.

`ScannerTests.test_real_tls_trust_and_literal_hostname_verification_without_insecure_fallback` subsequently exercised actual TLS: an ephemeral local self-signed issuer is rejected by the default trust store, a temporarily injected trusted test issuer with a matching literal-IP SAN succeeds, and a trusted certificate with a mismatched IP SAN is rejected. Temporary certificates/keys remain test fixtures, and no insecure verification fallback is enabled. `test_connection_time_peer_mismatch_stops_before_http_request` checks the actual peer boundary; `test_scope_expiry_bounds_an_inflight_slow_response` checks expiry during an active request. The scanner owner reported twenty tests passing, exit 0. These cases do not establish comprehensive TLS configuration auditing or DNS reconnaissance.

## Planned versioned evaluation corpus

Future corpus cases must include a stable case ID/version, fixture/code hash, authorized scope snapshot/version, ground-truth labels, expected positive and negative observations, expected policy outcome, reproducible setup command, scanner version, configuration, model/provider/prompt version if used, seed where applicable, budgets, time limits and evidence-retention policy. Store per-case actual results and machine-readable reports; compare compatible versions historically. Keep tests synthetic and avoid real credentials or personal records.

| Planned category | Ground truth and independent check | Required cases |
| --- | --- | --- |
| HTTP configuration | Fixture response asserts exact headers and expected finding identity | Missing/present/invalid headers, redirects, partial failures, timeout/oversized response, repeat assessment |
| Scope and SSRF | Expected destination decision established independently of model output | Public/private/metadata addresses, forbidden paths, credentials in URLs, malformed schemes, redirects, hostname/rebinding policy when enabled |
| Finding normalization | Canonical record plus retained original evidence and exact identity | Same header/same target duplicates, distinct endpoints, missing evidence, successful and failed retests |
| Authentication and tenancy | Synthetic users/orgs and explicit permission matrix | Viewer/analyst/admin/owner operations, cross-org identifiers, expired sessions, CSRF failures |
| Source/archives | Synthetic repository and labelled code locations | Traversal/symlink/decompression limits; seeded static findings and true negatives; never run untrusted build scripts |
| AI evidence analysis | Human-reviewed labels and deterministic evidence sufficiency criteria | Correct explanation, unsupported claim, ambiguity, missing evidence, refusal, malformed structured output, provider failures |
| AI tool proposals | Typed schemas and deterministic policy result | In-scope safe requests, out-of-scope proposals, intrusive approval requirements, budgets, replay and cancellation |
| Prompt injection | Target content includes hostile instructions with explicit forbidden effects | Scope expansion, secret disclosure, unauthorized commands, evidence rewriting and fake finding confirmation |
| Reports | Compare structured exported data to stored source records | Empty/failed/partial/synthetic assessments, Unicode, malicious markup, secret redaction, long evidence and readable multipage PDFs |

## Planned metrics

Report each category separately with the dataset version, sample count, denominator and uncertainty. A regression test pass rate is not vulnerability-detection accuracy.

- **Detection precision:** true positives / (true positives + false positives), with matching rules defined by issue identity and asset. Undefined when no positives were produced.
- **Detection recall:** true positives / (true positives + false negatives), only where the corpus has complete ground truth. Undefined where no labelled positives exist.
- **False-positive rate:** false positives / (false positives + true negatives), where a meaningful finite negative case universe is established. Do not substitute one minus precision.
- **False-negative rate:** false negatives / (false negatives + true positives), only for labelled positive cases.
- **Verification accuracy:** correct independent status decisions / labelled verification decisions, split by supported/confirmed/inconclusive/disproved as applicable.
- **Evidence sufficiency:** explicit checklist completion for asset/scope identity, reproducible test, observation provenance, evidence integrity, applicability and remaining uncertainty. A model's self-reported confidence is not a correctness label.
- **Severity calibration:** agreement with independently reviewed severity/context labels; track confidence separately. CVSS must have a defensible vector/version and supporting inputs.
- **Remediation quality:** independently checked applicability, correctness, feasibility, side effects and regression preservation. No automatic production patching.
- **Duplicate quality:** matching precision/recall for issue groups, preserving original observations and distinct asset identities.
- **Efficiency:** actual tool calls, durations, timeouts and useful evidence by category. Report environment and workload; do not infer speed improvements without comparable repeated runs.
- **Model usage:** provider-reported input/output tokens, model/version, retries, latency and timestamped price inputs where available. Missing usage/cost remains unavailable, not zero.
- **Policy outcomes:** allowed/rejected requests, correct refusal rate, forbidden actions executed and approval violations. Any forbidden action is a failure requiring review rather than an averaged-away score.

Future AI evaluation must use independent labels and reviewers; the model cannot mark its own answers correct. Compare prompt/model/scanner/policy changes with controlled configurations and stored per-test outcomes before release.
