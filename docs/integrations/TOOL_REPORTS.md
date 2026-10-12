# Scanner report parsers (L3/L6) — Gitleaks, Semgrep, Nuclei, Nmap

Parsers in `packages/scanner_adapters/integrations/` turn a tool's machine-readable report into findings or observations. **No tool is installed and none has run**: every sample is hand-written from the tool's documented format and has never been compared with real output. Nothing here is connected to dispatch. Tests: `tests/integration/test_tool_report_parsers.py`, `test_nmap_adapter.py`.

| Parser | Retains | Never reads |
| --- | --- | --- |
| `gitleaks.parse` | rule, file, line, fingerprint | the secret, the matching line, commit author and message |
| `semgrep.parse` | rule, file, line, severity, CWE; plus `complete`, error count, scanned/skipped path counts | code lines, rule messages (they can contain matched code), error messages |
| `nuclei.parse` | template, name, severity, where it matched (http/https URL without credentials or query, or host[:port], IPv6 supported), matcher, fingerprint | requests, responses, curl commands, extracted results |
| `nmap.parse_xml` | port, state, service name guess, how it was identified | version banners (no version probing is requested) |

Shared rules (`_parsing.py`), most of them from Codex's and Gemini's reviews recorded in the session log:

- A value is validated as written and rejected if it does not fit. Nothing is trimmed or repaired, so two different locations can never become one stored identity. Absolute paths are accepted only beneath a `source_root` the caller supplies.
- One malformed entry anywhere rejects the whole report, including entries beyond the 5,000 that are retained; `truncated` says when more valid entries existed.
- Every retained string passes through the product's redaction, and the fingerprint is a hash of the original value, so a credential inside a rule name or path is not stored but two different ones remain two findings. Redaction is pattern-based.
- Reports are bytes of at most 10 MiB; `NaN` and `Infinity` are not JSON; deep nesting is refused; error text is fixed.
- Semgrep's `complete` is false when the tool reported any error. Gitleaks and Nuclei reports carry no error section, so completion must come from the tool's exit status.
