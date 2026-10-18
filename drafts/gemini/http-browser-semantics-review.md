Reviewed: MAIN_PROMPT.txt, AGENTS.md, GEMINI.md, docs/TEAM_ASSIGNMENTS.md, docs/IMPLEMENTATION_STATUS.md, docs/SESSION_LOG.md, packages/scanner_adapters/__init__.py, tests/product/test_header_semantics.py, tests/evaluation/corpus/http_configuration.v2.json, tests/evaluation/test_http_configuration.py, https://fetch.spec.whatwg.org/#x-content-type-options-header, https://fetch.spec.whatwg.org/#concept-header-list-get-decode-split, https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20#section-5.6, https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20#section-5.7

Executed checks in this session:
- Ran `.venv/bin/python -m pytest tests/product/test_header_semantics.py tests/evaluation/test_http_configuration.py -k "not MeasuredAdapter"`: exit 0, 22 passed, 7 deselected in 0.65s.
- Ran `.venv/bin/python -m pytest tests/product/test_header_semantics.py tests/evaluation/test_http_configuration.py -k "not LiveCorpusEvaluationTests"`: exit 1 in sandbox because `MeasuredAdapterTests` and `MeasuredAdapterOnCorpusV2Tests` bind a local `127.0.0.1:0` loopback socket blocked by the sandbox (`incomplete_scans` populated).

1. Fix: Parse `X-Content-Type-Options` using the WHATWG Fetch "determine nosniff" algorithm (`get, decode, and split` across all `X-Content-Type-Options` headers in appearance order, inspecting `values[0]`) instead of comparing the last header's full string.
   Evidence: Reasoned from reading `packages/scanner_adapters/__init__.py:248` and `299`, and verified against https://fetch.spec.whatwg.org/#x-content-type-options-header and https://fetch.spec.whatwg.org/#concept-header-list-get-decode-split. Currently, `lowered = {name.lower(): value for name, value in headers}` (line 248) overwrites earlier `X-Content-Type-Options` headers with the last header, and line 299 checks `lowered.get("x-content-type-options", "").strip().lower() == "nosniff"`. Under WHATWG Fetch "determine nosniff", the user agent runs `get, decode, and split` on `X-Content-Type-Options`: it concatenates all `X-Content-Type-Options` header values in appearance order with `", "`, splits on unquoted `","` while preserving HTTP quoted-strings (`"..."` with `\` escapes, without the `extract-value` flag so outer quotes remain part of `temporaryValue`), strips only leading/trailing HTTP tab or space (`0x09` HTAB or `0x20` SP) from each split item, and returns true iff `values` is non-empty and `values[0]` is an ASCII case-insensitive match for `"nosniff"`. This explains all three XCTO disagreements in `tests/evaluation/corpus/http_configuration.v2.json` and `tests/evaluation/test_http_configuration.py:29-39`:
   - `xcto-nosniff-repeated-in-one-header` (`"nosniff, nosniff"`) and `xcto-nosniff-first-then-other` (`"nosniff, invalid"`): `values[0]` is `"nosniff"` (effective in browsers; current adapter reports false positive `missing_nosniff`).
   - `xcto-other-header-before-nosniff-header` (`["X-Content-Type-Options", "invalid"]` followed by `["X-Content-Type-Options", "nosniff"]`) and `xcto-other-first-then-nosniff` (`"invalid, nosniff"`): `values[0]` is `"invalid"` (ineffective in browsers; current adapter misses `xcto-other-header-before-nosniff-header` because `lowered` keeps only the second header).
   - `xcto-quoted-nosniff` (`"'nosniff'"`) and `"\"nosniff\""`: `values[0]` retains its quotes under `get, decode, and split` (step 5.2.1 collects the HTTP quoted string without `extract-value`), so `values[0]` does not match `"nosniff"` (ineffective in browsers).
   Benefit: Eliminates both v2 XCTO false positives (`xcto-nosniff-repeated-in-one-header`, `xcto-nosniff-first-then-other`) and the v2 XCTO false negative (`xcto-other-header-before-nosniff-header`) while preserving `MAX_HEADER_COUNT` and `MAX_HEADER_VALUE_CHARS` bounds.
   Proposal: Add a bounded helper `_has_nosniff(headers: Sequence[tuple[str, str]]) -> bool` in `packages/scanner_adapters/__init__.py` and call it at line 299 (`"nosniff": _has_nosniff(normalized)`):
   ```python
   def _first_fetch_header_value(raw_values: Sequence[str]) -> str | None:
       combined = ", ".join(raw_values)
       if not raw_values:
           return None
       buf: list[str] = []
       i = 0
       n = len(combined)
       while i < n:
           ch = combined[i]
           if ch == ",":
               break
           if ch == '"':
               buf.append(ch)
               i += 1
               while i < n:
                   c = combined[i]
                   buf.append(c)
                   i += 1
                   if c == "\\" and i < n:
                       buf.append(combined[i])
                       i += 1
                   elif c == '"':
                       break
               continue
           buf.append(ch)
           i += 1
       return "".join(buf).strip(" \t")


   def _has_nosniff(headers: Sequence[tuple[str, str]]) -> bool:
       values = [value for name, value in headers if name.lower() == "x-content-type-options"]
       first = _first_fetch_header_value(values)
       return first is not None and first.lower() == "nosniff"
   ```
   Verify by: `.venv/bin/python -m pytest tests/product/test_header_semantics.py tests/evaluation/test_http_configuration.py`
   Owner: codex   Confidence: high

2. Fix: Replace `http.cookies.SimpleCookie` in `_cookie_flags` with an RFC 6265bis Section 5.6 single-cookie-per-header parser so valid browser cookies with JSON values, brackets in names, nameless values, empty names, or unknown attributes are not misclassified as `parse_error`.
   Evidence: Reasoned from reading `packages/scanner_adapters/__init__.py:182-202` and `367`, and verified against https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20#section-5.6 (Steps 1-6 and attribute parsing Steps 1-8, Sections 5.6.5-5.6.7) and https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20#section-5.7 (Steps 2, 12, 14, 17, 22). Currently, `_cookie_flags` passes each `Set-Cookie` header to `SimpleCookie()`, which enforces legacy RFC 2109 `Cookie` token syntax instead of RFC 6265bis Section 5.6 `set-cookie-string` rules. When `SimpleCookie` raises `CookieError` or yields no morsels, `_cookie_flags` returns `[{"parse_error": True}]` without an `"httponly"` key, and line 367 (`any(not flags.get("httponly", True) for flags in facts["cookie_flags"])`) defaults missing `"httponly"` to `True`, silently suppressing `cookie_httponly` findings. Under RFC 6265bis Section 5.6:
   - Each `Set-Cookie` header represents at most one cookie (`name-value-pair` is everything before the first `;`, and `unparsed-attributes` is everything from the first `;` onward; Section 5.6 Step 2).
   - A `Set-Cookie` string is aborted/ignored at parse time only if: (a) it contains a CTL character excluding HTAB (`%x00-08 / %x0A-1F / %x7F`, Section 5.6 Step 1); (b) after splitting `name-value-pair` on the first `=` (or setting `name = ""` and `value = name-value-pair` if `=` is absent, Section 5.6 Step 3) and stripping leading/trailing WSP (`" \t"`, Section 5.6 Step 4), both `name` and `value` are empty (Section 5.7 Step 2); (c) `len(name) + len(value) > 4096` octets (Section 5.6 Step 5); or (d) `name == ""` and `value` starts case-insensitively with `"__secure-"` or `"__host-"` (Section 5.7 Step 22).
   - For each `;`-delimited segment in `unparsed-attributes` (Section 5.6 attribute algorithm Steps 1-8): split on the first `=` (if present) into `attribute-name` and `attribute-value`, strip leading/trailing `" \t"`, ignore the attribute if `len(attribute-value) > 1024` octets (Step 6), match `attribute-name` ASCII case-insensitively: `"secure"` sets `secure = True` (Section 5.6.5), `"httponly"` sets `httponly = True` (Section 5.6.6), `"samesite"` sets `samesite` when `attribute-value` case-insensitively matches `"strict"`, `"lax"`, or `"none"` with last-valid-attribute winning (Section 5.6.7 and Section 5.7 Step 17), and ignore unrecognized attributes like `Priority=High` (Section 5.6 Step 7).
   Benefit: Eliminates all five v2 cookie false negatives (`cookie-json-value-without-httponly`, `cookie-without-equals-sign`, `cookie-empty-name-without-httponly`, `cookie-bracket-name-without-httponly`, `cookie-unknown-attribute-without-httponly`), preserves `{"parse_error": True}` for genuinely rejected headers (such as `Set-Cookie: ""` in `test_header_semantics.py:136`), and never stores cookie names or values.
   Proposal: Replace `_cookie_flags` in `packages/scanner_adapters/__init__.py:182-202` with:
   ```python
   def _has_cookie_ctl(value: str) -> bool:
       return any((ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7F for ch in value)


   def _cookie_flags(raw_cookie: str) -> list[dict[str, object]]:
       if _has_cookie_ctl(raw_cookie):
           return [{"parse_error": True}]
       name_value_pair, sep, unparsed_attrs = raw_cookie.partition(";")
       if "=" in name_value_pair:
           raw_name, _, raw_val = name_value_pair.partition("=")
           name = raw_name.strip(" \t")
           value = raw_val.strip(" \t")
       else:
           name = ""
           value = name_value_pair.strip(" \t")
       if not name and not value:
           return [{"parse_error": True}]
       if len(name.encode("utf-8")) + len(value.encode("utf-8")) > 4096:
           return [{"parse_error": True}]
       if not name and value.lower().startswith(("__secure-", "__host-")):
           return [{"parse_error": True}]
       secure = False
       httponly = False
       samesite = ""
       if sep:
           for segment in unparsed_attrs.split(";"):
               if "=" in segment:
                   attr_name, _, attr_val = segment.partition("=")
               else:
                   attr_name, attr_val = segment, ""
               attr_name = attr_name.strip(" \t").lower()
               attr_val = attr_val.strip(" \t")
               if len(attr_val.encode("utf-8")) > 1024 or not attr_name:
                   continue
               if attr_name == "secure":
                   secure = True
               elif attr_name == "httponly":
                   httponly = True
               elif attr_name == "samesite":
                   lowered_ss = attr_val.lower()
                   if lowered_ss in {"strict", "lax", "none"}:
                       samesite = lowered_ss
                   else:
                       samesite = ""
       return [{"secure": secure, "httponly": httponly, "samesite": samesite}]
   ```
   Verify by: `.venv/bin/python -m pytest tests/product/test_header_semantics.py tests/evaluation/test_http_configuration.py`
   Owner: codex   Confidence: high

3. Observation: Keep RFC 6265bis Section 5.6 header parsing separate from Section 5.7 storage-model rejection (`__Host-`, `__Secure-`, `SameSite=None` without `Secure`) in `_cookie_flags` so misconfigured session cookies still trigger `cookie_httponly`.
   Evidence: Reasoned from reading `tests/evaluation/corpus/http_configuration.v2.json:817-833` (`cookie-bracket-name-without-httponly`: `Set-Cookie: __Host-session[id]=abc; Path=/; SameSite=Lax`, `expected_checks: ["cookie_httponly"]`) and RFC 6265bis Section 5.7 Steps 19-21 (https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20#section-5.7). Notice that in `SameSite` attribute processing (Section 5.6.7 Step 1 + Section 5.7 Step 17), a later invalid `SameSite=Invalid` attribute appends `SameSite=Default` to `cookie-attribute-list`, overriding an earlier `SameSite=Lax` (handled in the proposal above by resetting `samesite = ""` when a later `SameSite` attribute has an unrecognized value). However, if `_cookie_flags` discarded cookies that fail Section 5.7 storage-model checks (such as `__Host-` lacking `Secure`), `cookie-bracket-name-without-httponly` would be ignored instead of flagging `cookie_httponly`. Keeping `_cookie_flags` scoped to Section 5.6 + Section 5.7 Steps 2/17/22 makes `V2_FALSE_ALARMS` and `V2_MISSES` in `tests/evaluation/test_http_configuration.py:29-39` both drop to `set()` (0 false positives, 0 false negatives across all 36 v2 cases).
   Benefit: Preserves full compatibility with `http_configuration.v2.json` and allows Codex to tighten `V2_FALSE_ALARMS = set()` and `V2_MISSES = set()` in `tests/evaluation/test_http_configuration.py`.
   Proposal: Use the Section 5.6 parser in Item 2 and update `V2_FALSE_ALARMS` and `V2_MISSES` in `tests/evaluation/test_http_configuration.py` to empty sets once verified.
   Verify by: `.venv/bin/python -m tests.evaluation.http_configuration` and `.venv/bin/python -m pytest tests/evaluation/test_http_configuration.py`
   Owner: codex   Confidence: high

Not reviewed: Frontend UI components and Rust `services/scan_worker` crates.
