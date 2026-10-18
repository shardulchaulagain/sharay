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
| `normalize` | `normalize_parsed_finding(tool, item, *, default_target_url="")` where `tool` ∈ `gitleaks, semgrep, nuclei, zap, metasploit, iac` | one dict with exactly `fingerprint, title, category, severity, confidence, status, description, remediation, affected_url` + `recommended_validations` |

Wiring notes for the normalizer (`test_finding_normalizer.py`):
- `item` is one element of a parser's `findings` list (or one `scan_dockerfile_content` /
  `scan_k8s_manifest_dict` finding for `iac`). Feed the whole `Finding` row by dropping
  `recommended_validations` (not a column) and adding `organization_id/project_id/target_id`.
- **`status` is `suspected` for all parser findings except ZAP alerts explicitly marked
  `confidence == "false_positive"`, which preserve `status == "false_positive"`**
  (`packages/scanner_adapters/integrations/normalize.py:145`). A parser never self-confirms:
  external parser claims enter as `suspected` (distinct from the C-side worker's deterministic
  `safe_http` header checks in `aegis/worker.py`, and distinct from AI hypothesis states in
  `services/ai_analysis_worker/verifier.py`, where only `verify_testing_outcome` /
  `apply_adversarial_challenge` may elevate a hypothesis to `supported`/`confirmed` after
  provenance and digest checks).
- `fingerprint` is stable per finding and prefixed by tool; `(target_id, fingerprint)` is unique.

## Source / dependency / container / SBOM analysis (`services/source_analysis_worker/`)

All walk or parse a **staged** tree/artifact; none fetches. Outputs are `{ecosystem, name,
version}` components or `iac_issue` findings in the shapes above.

| Module | Call | Feeds |
| --- | --- | --- |
| `dependencies` | `inventory(root)` | `osv.match` |
| `secrets` | `detect(root)` | findings (`test_secret_detection.py`) |
| `containers` | `scan(root)` (Dockerfiles), `scan_dockerfile_content(text, path)`, `scan_k8s_manifest_dict(doc, path)` | `normalize_parsed_finding("iac", f)` → `Finding`. K8s manifests need a YAML parse by the caller (no YAML dep here); `scan` finds Dockerfiles only. Tests: `test_container_scanner.py` |
| `sbom` | `parse_cyclonedx(bytes)` | `osv.match` (components are PyPI/npm, PEP 503-normalised and validated against PEP 440 / SemVer 2.0.0). Tests: `test_sbom.py` |
| `osv` | `match(advisories_bytes, packages)` | advisory findings; caller supplies OSV records |

## AI investigation (`services/ai_analysis_worker/`) — human-gated

Off by default; a provider is selected by configuration and sends data only when the operator
switches sharing on. See `AI_INVESTIGATION.md`.

| Piece | Call | Notes |
| --- | --- | --- |
| provider switch | `providers.config_from_environment()` → `providers.build(config)` → `provider.propose(prompt)` | `none` until configured; `build` refuses unless `share_assessment_data` is on and the key env var is set |
| vendor adapters | `import services.ai_analysis_worker.vendors` | **required once** at the build site: importing registers `anthropic`/`openai`/`google`; without it, a configured provider raises "no adapter installed". No live call has ever been made. Tests: `test_ai_vendors.py` |
| verifier | `verify_testing_outcome(...)`, `apply_adversarial_challenge(...)`, `parse_challenge_verdict(bytes)`, `TokenUsageLedger` | the only actor that may move an AI hypothesis to `supported`/`confirmed`; every move goes through the guarded `advance()`; observations are SHA-256 + assessment-scope checked. Tests: `test_ai_verifier.py` |

## Current binary, isolation and provider status (not a wiring task)

- **Verified local scanner binaries/wheels (approved in `MAIN_PROMPT.txt` evening decisions):**
  Gitleaks 8.30.1, Nuclei 3.11.1 (`65791ee`, `docs/integrations/NUCLEI_EVALUATION.md`), and
  Semgrep 1.151.0 (`docs/integrations/SELF_UPDATE.md`) were downloaded, SHA-256 verified, and
  evaluated in `services/scanner_worker` (Nuclei requires `allow_fork=True` +
  `allow_scratch_writes=True` and `-DisableUpdateCheck` under Seatbelt).
- **Remaining uninstalled binaries:** Nmap, OWASP ZAP, and Metasploit (`msfconsole`) are not
  installed on this host and require separate per-tool human approval before download.
- **Host isolation & provider gates:** The macOS Seatbelt runner enforces `exact_loopback_address`
  and `loopback_port_egress` but cannot enforce `live_destination_egress` or `memory_limit`
  (`setrlimit` rejected by kernel), so general external scanner dispatch remains disabled; AI
  go-live requires the human's provider choice, API key, and `share_assessment_data` switch.
