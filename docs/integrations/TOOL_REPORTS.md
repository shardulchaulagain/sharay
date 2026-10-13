# Scanner report parsers (L3/L6) — Gitleaks, Semgrep, Nuclei, ZAP, Nmap

Parsers in `packages/scanner_adapters/integrations/` turn a tool's machine-readable report into findings or observations. **No tool is installed and none has run**: every sample is hand-written from the tool's documented format and has never been compared with real output. Nothing here is connected to dispatch. Tests: `tests/integration/test_tool_report_parsers.py`, `test_nmap_adapter.py`.

| Parser | Retains | Never reads |
| --- | --- | --- |
| `gitleaks.parse` | rule, file, line, fingerprint | the secret, the matching line, commit author and message |
| `semgrep.parse` | rule, file, line, severity, CWE; plus `complete`, error count, scanned/skipped path counts | code lines, rule messages (they can contain matched code), error messages |
| `nuclei.parse` | template, name, severity, where it matched (http/https URL without credentials or query, or host[:port], IPv6 supported), matcher, fingerprint | requests, responses, curl commands, extracted results |
| `zap.parse` | rule number and variant (`pluginid`, `alertRef`), name, risk, confidence, URL without credentials or query, HTTP method, parameter name, CWE and WASC numbers, ZAP's own remediation text, fingerprint | attack strings, evidence, descriptions, other-info, references |
| `nmap.parse_xml` | port, state, service name guess, how it was identified | version banners (no version probing is requested) |

Shared rules (`_parsing.py`), most of them from Codex's and Gemini's reviews recorded in the session log:

- A value is validated as written and rejected if it does not fit. Nothing is trimmed or repaired, so two different locations can never become one stored identity. Absolute paths are accepted only beneath a `source_root` the caller supplies.
- One malformed entry anywhere rejects the whole report, including entries beyond the 5,000 that are retained; `truncated` says when more valid entries existed.
- Every retained string passes through the product's redaction, and the fingerprint is a hash of the original value, so a credential inside a rule name or path is not stored but two different ones remain two findings. Redaction is pattern-based.
- Reports are bytes of at most 10 MiB; `NaN` and `Infinity` are not JSON; deep nesting is refused; error text is fixed.
- ZAP: only the documented "Traditional JSON Report" (`site[].alerts[].instances[]`) is accepted. The API's flat alert list and the single-object `site` written by old releases are rejected rather than guessed at, and an alert with no instances rejects the report. A risk or confidence code the parser does not know is stored as `unknown`, never as a real level. Adapted from Gemini's draft (`drafts/gemini/zap_parser.py`), which defaulted a missing risk to `info`, a missing confidence to `medium` and an unknown method to `GET`, skipped malformed instances, and accepted a flat format whose field names did not match ZAP's.
- Semgrep's `complete` is false when the tool reported any error. Gitleaks, Nuclei and ZAP reports carry no error section, so completion must come from the tool's exit status.

## First real run: Gitleaks 8.30.1 (October 12, 2026)

The human approved the download. The archive (7,897,593 bytes, from the project's GitHub releases) was checked against the publisher's SHA-256 by `services/update_worker.verify_file`, extracted inside the sandbox by `run_staged_extraction`, validated from the parent side, and recorded in the update ledger. The binary runs only through the isolation runner, without network. It lives under `tools/`, which is not committed. **Still not connected to the product**: no operator can start a Gitleaks scan.

What real output showed, all on synthetic secrets generated for the test:

- The parser accepts real reports unchanged and keeps no secret text; with `--redact` the tool's own output holds none either.
- **A scanned tree can switch the scanner off.** Its own `.gitleaks.toml` reduced four findings to none, silently, with exit status 0. `gitleaks:allow` comments hid a token. `build_argv` therefore always passes a pinned configuration (`gitleaks.toml` beside the parser: the tool's default rules and nothing from the tree) and `--ignore-gitleaks-allow`; both are covered by tests that run the real binary.
- **A `.gitleaksignore` inside the tree still suppresses findings and no flag was found that stops it**, including `--gitleaks-ignore-path`. `suppression_files(root)` lists such files; a scan of a tree where it returns anything must be reported as incomplete, never as clean. The built-in detector is not affected by any of these files.
- The tool's own fingerprint contains the absolute path of the scanned folder, so the stored identity changed whenever the staging folder did. The parser now removes the trusted root before hashing; the same secret keeps one identity across retests.
- Reports arrive on standard output, which the runner caps at 1 MiB. A larger report is cut off and the parser then rejects it; it fails loudly, but a file-based report path is needed before large trees.

Measured on the two secret-detection corpora, at file level (any report in a file against a secret expected in it):

| Corpus | Tool | Secrets found | False alarms |
| --- | --- | --- | --- |
| v1 (12 secrets, 12 look-alikes) | Gitleaks 8.30.1 | 7 of 12 | 1 |
| v1 | built-in detector | 12 of 12 | 0 |
| v2 (12 secrets, 18 look-alikes) | Gitleaks 8.30.1 | 9 of 12 | 6 |
| v2 | built-in detector | 12 of 12 | 0 |

Read this with care: the built-in detector was developed against these corpora, so its score is not independent, and the corpus secrets are short synthetic strings that an entropy-based tool may rightly pass over. Several "false alarms" are test or publishable keys that the corpus labels as harmless and Gitleaks reports anyway, which is a difference of policy, not an error. The honest conclusion is that the two disagree on 15 of 54 files and each disagreement needs a label checked by a second author.

The real-binary tests in `tests/integration/test_gitleaks_adapter.py` skip where the tool is not installed, which includes CI. A skip there is not a pass.


## Second real download: Nuclei 3.11.1 (October 12, 2026)

Downloaded on the human's pre-approval and verified like Gitleaks: `nuclei_3.11.1_macOS_arm64.zip` (43,571,292 bytes) checked against the publisher SHA-256 by `verify_file`, extracted inside the sandbox (a 136,853,122-byte Go binary), validated, placed read-only under `tools/` (not committed). It runs under the isolation runner. **Not evaluated and not pinned**: it has only run `-version`, not a real scan against a corpus, so the update ledger's evaluation gate is deliberately not satisfied.

Findings for the future L3 adapter, from the real binary:

- Nuclei writes a config directory under `HOME/Library/Application Support/nuclei` at startup. Under the deny-default sandbox this is refused; `-version` still prints, `-health-check` exits 1. The adapter will need a scratch-writable config home, and `run_isolated` has no environment/`HOME` option yet.
- Nuclei has no network in the sandbox, so it cannot fetch or update templates. Templates must be pre-staged and verified as their own component (see `SELF_UPDATE.md`: templates are review-gated, never auto-fetched, because community templates can add intrusive probes). No Nuclei scan has been run.
