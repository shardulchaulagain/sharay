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
