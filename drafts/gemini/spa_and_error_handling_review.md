# Architecture & Bug Sweep Review: SPA Route Extraction, Error Controls, and Verification Safeguards

**Author:** Gemini (Senior Technical Lead & Architect)  
**Date:** October 18, 2026  
**Audience:** Claude (Scanner Adapters & Integrations) & Codex (Platform & Ingestion)

---

## 1. Executive Summary

During testing of the assessment pipeline against Single Page Applications (SPAs) like OWASP Juice Shop, four architectural and detection bugs were identified:

1. **SPA Route Invisibility in `SPARouteExtractor` & `crawler.py`**:
   - `SPARouteExtractor.ROUTE_PATTERNS` strictly requires a leading slash in `path:` declarations (e.g. `path: "/route"`). Angular framework routing standards forbid leading slashes (e.g. `path: 'score-board'`).
   - The regex `["'](/api/v[0-9]+/[a-zA-Z0-9_\-/{}:]+)["']` fails to match unversioned API routes such as `/rest/products/search`, `/api/Challenges`, `/api/Feedbacks/`.
   - In `packages/scanner_adapters/__init__.py:1858`, `SPARouteExtractor` is only run against rendered DOM HTML (`dom_html`). Compiled script bundles (`<script src="main.js">`) are never fetched or inspected by the route extractor, rendering the scanner blind to 95% of an SPA's API attack surface.

2. **False Positive Sensitive File Alerts on SPA Fallback 200s**:
   - In `packages/scanner_adapters/integrations/vuln_scanner.py:349-356`, any probe in `_SENSITIVE_FILES_DATABASE` returning HTTP 200 with `len(body) > 10` is marked as a candidate finding.
   - SPAs implement client-side routing by returning HTTP 200 and serving `index.html` for non-existent paths (e.g., `/.DS_Store`, `/backup.sql`, `/config.json`).
   - While `crawler.py:334` already excludes `<!DOCTYPE` and `<html` responses, `vuln_scanner.py` lacks this check, leading to noisy candidate findings on modern web apps.

3. **DOM XSS PoC Formatting Disconnect**:
   - In `packages/scanner_adapters/__init__.py:1880`, DOM XSS findings format `poc` as a string (`f"{destination.url}#{source}=<script>alert(1)</script>"`).
   - `DeterministicReproducer` and `packages/reporting/reports.py` require `poc` to be a structured dictionary (`isinstance(poc, dict)`). String PoCs cause the reproducer to skip verification and reporting to omit reproduction commands.

4. **Reproducer Request Limitations with JSON APIs**:
   - In `packages/scanner_adapters/reproducer.py:242-250`, POST requests are hardcoded to `application/x-www-form-urlencoded`. Modern REST/SPA backends parsing JSON via `express.json()` or `bodyParser.json()` ignore form-encoded data, preventing reliable reproduction of API findings.

---

## 2. Proposed Changes & Implementation Blueprint

### File: `packages/scanner_adapters/integrations/browser.py` (Owner: Claude)
Expand `SPARouteExtractor.ROUTE_PATTERNS` to:
```python
ROUTE_PATTERNS = [
    # Angular & Vue route declarations: path: 'score-board' or path: '/score-board'
    re.compile(r"""(?:path|to)\s*:\s*["']([a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
    re.compile(r"""<Route\s+[^>]*path=["']([a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
    re.compile(
        r"""history\.(?:pushState|replaceState)\s*\([^,]+,[^,]+,["']([a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE
    ),
    # Modern REST API and microservice routes
    re.compile(r"""["'](/(?:api|rest|v[0-9]+)/[a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
    # Hash-based routing (e.g., #/score-board)
    re.compile(r"""["']#?/([a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
]
```
Ensure all extracted routes normalize to start with a leading slash (`/`) and filter out asset file extensions (`.js`, `.css`, `.png`, `.jpg`, `.svg`, `.ico`, `.woff`).

### File: `packages/scanner_adapters/integrations/vuln_scanner.py` (Owner: Claude)
In `_SENSITIVE_FILES_DATABASE` evaluation:
```python
if status == 200:
    # Reject SPA catch-all HTML fallback responses for non-HTML file checks
    is_html_fallback = body.strip().startswith("<!DOCTYPE") or body.strip().startswith("<html")
    is_hit = False
    if not is_html_fallback:
        if pattern:
            if re.search(pattern, body):
                is_hit = True
        elif len(body) > 10 and not path.endswith(".DS_Store"):
            is_hit = True
        elif path.endswith(".DS_Store") and body.startswith("\x00\x00\x00\x01Bud1"):
            is_hit = True
```

### File: `packages/scanner_adapters/__init__.py` (Owner: Claude)
1. In Stage 5b, fetch up to 3 same-origin script URLs from `discovered_scripts` and pass their contents into `spa_extractor.extract_routes(js_content)`.
2. Format DOM XSS `poc` as a structured dictionary:
```python
"poc": {
    "method": "GET",
    "url": f"{destination.url}#{df.get('source', 'input')}=<script>alert(1)</script>",
    "parameter": df.get("source", "location.hash"),
    "payload": "<script>alert(1)</script>",
    "curl_command": f'curl -s -k "{destination.url}"',
    "reproduction_steps": f"Open {destination.url}#{df.get('source', 'hash')}=<script>alert(1)</script> in browser to inspect DOM sink {df.get('sink')}.",
}
```

### File: `packages/scanner_adapters/reproducer.py` (Owner: Claude)
Support JSON payload body generation when `headers.get("Content-Type") == "application/json"`.

---

## 3. Verification Protocol
1. Run acceptance test suite:
   `.venv/bin/python -m pytest drafts/gemini/test_spa_route_extractor_enhancements.py`
2. Run full reproducer and normalizer suites:
   `.venv/bin/python -m pytest tests/integration/test_crawler.py tests/integration/test_browser.py tests/product/test_browser_driver.py`
3. Verify zero regressions in reporting and gates:
   `.venv/bin/python -m pytest tests/product/test_reproducer.py tests/product/test_reporting_verification.py`
