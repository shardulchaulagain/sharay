# Attack & Robustness Report: openapi.ingest and secrets.detect

**Author**: Gemini (Principal Architect)  
**Date**: October 12, 2026  
**Target Code**: `packages/scanner_adapters/integrations/openapi.py` and `services/source_analysis_worker/secrets.py`  
**Test Suite**: `drafts/gemini/attack-tests/test_attack.py` (6 tests ran, exit code 0)

---

## 1. Vulnerabilities in `packages/scanner_adapters/integrations/openapi.py`

### Finding 1: Unsanitized Path Key Leaked in `unresolved` When Item is Non-Dict
- **Vulnerability**: In `openapi.py` line 119:
  ```python
  if not isinstance(template, str) or not template.startswith("/") or not isinstance(item, dict):
      unresolved(template, "path is not a /template with an object...")
  ```
  If an API description contains an invalid path item whose key carries query parameters or tokens (e.g. `"/v1/resource?token=PLANTED_SECRET"`), the entire template string is passed to `unresolved` and echoed in the output report.
- **Proof**: `test_openapi_echoes_planted_token_in_path_key_when_item_invalid` proved that `PLANTED_SECRET_TOKEN_IN_PATH` appeared in `result["unresolved"]`.
- **Fix**: Sanitize `template` through `_clean_path` or strip query parameters (`urlsplit(template).path`) before passing to `unresolved()`, or pass a fixed generic label `"path_item"`.

### Finding 2: Malformed Operation Security Falsely Reported as "No Authentication"
- **Vulnerability**: In `openapi.py` line 152:
  ```python
  own_security = _requirements(operation.get("security"))
  effective = own_security if "security" in operation else default
  if not effective:
      state = "none"
      observe("operation_declares_no_authentication", **where)
  ```
  If an operation has a malformed `security` field (e.g. string `"bearer"` or integer `123`), `_requirements()` returns `None`. Line 152 sets `effective = None`. Then line 156 evaluates `if not effective: state = "none"`!
  This causes a protected endpoint whose security definition is syntactically malformed to be classified as having **NO AUTHENTICATION**, misinforming the operator.
- **Proof**: `test_openapi_malformed_security_reported_as_no_authentication` proved that an endpoint under a global `apiKey` requirement was marked `authentication="none"` when `operation["security"]` was malformed.
- **Fix**: When `own_security is None` and `"security" in operation`, set `state = "unresolved_security"` or fall back to `default`, never `"none"`.

---

## 2. Vulnerabilities in `services/source_analysis_worker/secrets.py`

### Finding 3: False Positive on Hyphenated English Words Following `xoxb-`
- **Vulnerability**: In `secrets.py` line 30:
  `("slack_token", re.compile(rb"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])"))`
  Because the regex admits hyphens inside the token body and `_placeholder` only checks if the last 16 characters have ≤3 unique bytes, any normal hyphenated English phrase starting with `xoxb-` (e.g. documentation prose like `xoxb-this-is-a-harmless-doc-sample-phrase`) is falsely classified as a live Slack token.
- **Proof**: `test_secrets_false_positive_on_hyphenated_english_phrase` produced 1 finding with rule `slack_token` on normal text.
- **Fix**: Restrict Slack token character sets to strict hex or numeric components (`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`).

### Finding 4: Coverage Gaps for Modern AI Provider Keys
- **Vulnerability**: `RULES` detects private keys, AWS, GitHub, Slack, Google, and Stripe live keys, but completely omits OpenAI (`sk-proj-...`) and Anthropic (`sk-ant-...`) keys, which are among the most common secrets exposed in modern codebases.
- **Proof**: `test_secrets_misses_openai_and_anthropic_keys` produced 0 findings on seeded live-format keys.
- **Fix**: Add regex patterns for `openai_api_key` (`rb"sk-(?:proj-)?[A-Za-z0-9_-]{48,}"`) and `anthropic_api_key` (`rb"sk-ant-[A-Za-z0-9_-]{40,}"`).

### Finding 5: Plaintext Credential Leakage via File Names
- **Vulnerability**: In `secrets.py` line 54:
  `shown = _clean(path.relative_to(root).as_posix())`
  If a developer or repository stores keys in file names (e.g. `backup_AKIAIOSFODNN7EXAMPLE.json`), `shown` contains the credential in plaintext, which is echoed directly into `result["matches"]` and `result["skipped"]`.
- **Proof**: `test_secrets_leak_via_file_name` confirmed `AKIAIOSFODNN7EXAMPLE` was retained in the match report.
- **Fix**: Route `shown` through token redaction before adding to match and skipped lists.

### Finding 6: Quadratic Line Number Counting Overhead
- **Vulnerability**: In `secrets.py` line 80:
  `"line": data.count(b"\n", 0, match.start()) + 1`
  On a file with many matches (e.g. 2,000 matches in a 1 MB file), counting `b"\n"` from byte 0 for every match scans ~1 GB of buffer memory.
- **Proof**: `test_secrets_quadratic_line_counting_on_dense_file` demonstrated repeated rescanning of byte buffers.
- **Fix**: Precompute newline offsets once using a bisect array or incremental search from the previous match offset.
