# Wiring contracts for the not-yet-connected L-half modules

These L-half modules are built, tested and gate-clean but **not connected to dispatch, the
control plane or the UI**. Connecting them is Codex's half (C4 policy, C5 orchestration, C6
findings/retest, C8 UI). This page is the call contract for each: what to call, what it takes,
what it returns, and where it plugs in. Nothing here runs a tool, reaches a network or widens
scope; every module is pure given its inputs. Tests are named per row.

## Parsers → findings → the `Finding` model

Each parser in `packages/scanner_adapters/integrations/` turns a tool's bytes into a dict of
`{"findings": [...], "truncated": bool}` (details in `TOOL_REPORTS.md`). The normalizer turns one
parser finding into the exact column contract of `aegis.models.Finding`.

| Module | Call | Returns |
| --- | --- | --- |
| `metasploit` | `parse_metasploit_catalog(bytes)`, `parse_metasploit_auxiliary_report(bytes)`, `parse_metasploit_sessions(bytes)` | bounded, redacted catalog / aux results / session inventory; `correlate_validation_techniques(category, cwe=)` gives the technique catalog |
| `normalize` | `normalize_parsed_finding(tool, item, *, default_target_url="")` where `tool` ∈ `gitleaks, semgrep, nuclei, zap, metasploit, iac, osv, secrets` | one dict with exactly `fingerprint, title, category, severity, confidence, status, description, remediation, affected_url` + `recommended_validations` |

Wiring notes for the normalizer (`test_finding_normalizer.py`):
- `item` is one element of a parser's `findings` list (or one `scan_dockerfile_content` /
  `scan_k8s_manifest_dict` finding for `iac`). Feed the whole `Finding` row by dropping
  `recommended_validations` (not a column) and adding `organization_id/project_id/target_id`.
- **A parser never self-confirms.** Parser/analyzer findings enter as `suspected`; ZAP may map an
  alert graded false-positive to `status="false_positive"`; no parser source emits `confirmed`.
  Only the AI verifier moves a hypothesis to `supported`/`confirmed`, and the built-in header
  checks produce their own deterministic confirmations — three distinct confidence bases, kept
  separate. (`metasploit` and `iac` both enter as `suspected`.)
- `fingerprint` is stable per finding and prefixed by tool; `(target_id, fingerprint)` is unique.

## Source / dependency / container / SBOM analysis (`services/source_analysis_worker/`)

All walk or parse a **staged** tree/artifact; none fetches. Outputs are `{ecosystem, name,
version}` components or `iac_issue` findings in the shapes above.

| Module | Call | Feeds |
| --- | --- | --- |
| `dependencies` | `inventory(root)` | `osv.match` |
| `secrets` | `detect(root)` | findings |
| `containers` | `scan(root)` (Dockerfiles), `scan_dockerfile_content(text, path)`, `scan_k8s_manifest_dict(doc, path)` | `normalize_parsed_finding("iac", f)` → `Finding`. K8s manifests need a YAML parse by the caller (no YAML dep here); `scan` finds Dockerfiles only. Tests: `test_container_scanner.py` |
| `sbom` | `parse_cyclonedx(bytes)` | `osv.match` (components are PyPI/npm, PEP 503-normalised). Tests: `test_sbom.py` |
| `osv` | `match(advisories_bytes, packages)` | advisory findings; caller supplies OSV records |

## Reconnaissance (L5, `integrations/`) — parse only, no probe

Parser-only; live DNS/TLS lookups need network the loopback backend does not grant. See `RECON.md`.

| Module | Call | Produces |
| --- | --- | --- |
| `tls` | `parse_peer_certificate(ssl_getpeercert_dict, *, now_epoch=None)` | TLS observation: subject/issuer CN, validated DNS/IP SANs (assets), validity, self-signed/expired flags |
| `dns` | `parse_records([{"name","type","data"}])` | validated records + `assets` (hostnames/ips) |
| `recon` | `collect_assets([{"source","hostnames","ips"}])` | deduplicated assets with provenance (recon output, not the C3 target store) |
| `browser` | `validate_workflow(steps)` (L3) | a normalised plan of observe-only verbs (goto/wait/read_text/click_text/screenshot/back); rejects script/fill/upload/download and non-loopback-http/credentialled URLs. Validates the plan; the control plane enforces scope and executes. Tests: `test_browser.py` |

## AI investigation (`services/ai_analysis_worker/`) — human-gated

Off by default; a provider is selected by configuration and sends data only when the operator
switches sharing on. See `AI_INVESTIGATION.md`.

| Piece | Call | Notes |
| --- | --- | --- |
| provider switch | `providers.config_from_environment()` → `providers.build(config)` → `provider.propose(prompt)` | `none` until configured; `build` refuses unless `share_assessment_data` is on and the key env var is set |
| vendor adapters | `import services.ai_analysis_worker.vendors` | **required once** at the build site: importing registers `anthropic`/`openai`/`google`; without it, a configured provider raises "no adapter installed". No live call has ever been made. Tests: `test_ai_vendors.py` |
| verifier | `verify_testing_outcome(...)`, `apply_adversarial_challenge(...)`, `parse_challenge_verdict(bytes)`, `TokenUsageLedger` | the only actor that may move a hypothesis to `supported`/`confirmed`; every move goes through the guarded `advance()`; observations are SHA-256 + assessment-scope checked. Tests: `test_ai_verifier.py` |

## Availability and what stays gated (not a wiring task)

Per the October 12 evening decisions, the three named scanner downloads are approved (unattended
from official sources), and they must be the darwin-arm64 builds (see `STATE.md` Health). Gitleaks
8.30.1 has been installed and run on synthetic fixtures (`TOOL_REPORTS.md`); Nuclei/Semgrep status
is per the session log. Still gated, independent of wiring: the loopback-only Seatbelt backend
cannot enforce a live-destination egress allowlist; AI go-live needs the human's provider choice,
API key and data-sharing switch; and product dispatch of any tool remains unavailable until the
control-plane/policy gates pass. No live, non-loopback target may be assessed.
