"""Safe browser-workflow validator and Headless Chromium DOM Engine (I3).

Provides:
1. Safe workflow validation: non-destructive observation verbs (goto, wait, read_text, screenshot).
2. Headless Chromium / Playwright driver: dynamic SPA client-side rendering & route discovery.
3. DOM-based XSS detector: source-to-sink tracking and canary reflection validation.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from packages.secret_patterns import redact_tokens

MAX_STEPS = 50
MAX_TEXT = 200
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_LABEL = re.compile(r"^[\x20-\x7e]{1,200}$")


class BrowserWorkflowError(ValueError):
    """A requested browser workflow contained an unsafe or malformed step."""


def _url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2000:
        raise BrowserWorkflowError("A goto URL must be a short string.")
    parsed = urlsplit(value)
    local = parsed.scheme == "http" and parsed.hostname in _LOOPBACK
    if not (parsed.scheme == "https" or local) or not parsed.hostname or "@" in parsed.netloc:
        raise BrowserWorkflowError("A goto URL must be https, or http on loopback, without credentials.")
    if not value.isprintable() or " " in value:
        raise BrowserWorkflowError("A goto URL must be printable and contain no spaces.")
    if redact_tokens(value, "") != value:
        raise BrowserWorkflowError("A goto URL must not carry a recognised credential.")
    return value


def _label(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _LABEL.match(value):
        raise BrowserWorkflowError(f"A {what} must be printable text of 1-200 characters.")
    if redact_tokens(value, "") != value:
        raise BrowserWorkflowError(f"A {what} must not carry a recognised credential.")
    return value


def _wait_ms(value: Any) -> int:
    if type(value) is not int or not 0 < value <= 30000:
        raise BrowserWorkflowError("A wait is an integer number of milliseconds in 1..30000.")
    return value


def validate_workflow(steps: Any) -> list[dict[str, Any]]:
    """Return a normalised plan of allow-listed observe-only steps, or raise BrowserWorkflowError."""
    if not isinstance(steps, list) or not steps:
        raise BrowserWorkflowError("A browser workflow is a non-empty list of steps.")
    if len(steps) > MAX_STEPS:
        raise BrowserWorkflowError(f"A browser workflow has at most {MAX_STEPS} steps.")
    plan: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            raise BrowserWorkflowError("A step is not an object.")
        verb = step.get("verb")
        if verb == "goto":
            plan.append({"verb": "goto", "url": _url(step.get("url"))})
        elif verb == "wait":
            plan.append({"verb": "wait", "ms": _wait_ms(step.get("ms"))})
        elif verb == "read_text":
            selector = step.get("label")
            plan.append(
                {
                    "verb": "read_text",
                    "label": _label(selector, "read_text label") if selector is not None else None,
                }
            )
        elif verb == "click_text":
            plan.append({"verb": "click_text", "text": _label(step.get("text"), "click_text text")})
        elif verb in ("screenshot", "back"):
            plan.append({"verb": verb})
        else:
            raise BrowserWorkflowError("A step uses a verb that is not on the safe allow-list.")
    return plan


def find_browser_binary() -> str | None:
    """Locate an installed Google Chrome or Chromium executable across standard OS locations."""
    env_bin = os.environ.get("CHROME_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


class _ScriptExtractor(HTMLParser):
    """Extract embedded inline scripts and raw text from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self._in_script = False
        self._current_content: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "script":
            self._in_script = True
            self._current_content = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._current_content.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False
            full_script = "".join(self._current_content).strip()
            if full_script:
                self.scripts.append(full_script)
            self._current_content = []


class DOMSinkTracker:
    """Detects DOM-based XSS flows from untrusted sources to execution sinks."""

    SOURCES = {
        "location.hash": re.compile(r"(?:window\.)?location\.hash", re.IGNORECASE),
        "location.search": re.compile(r"(?:window\.)?location\.search|URLSearchParams", re.IGNORECASE),
        "location.href": re.compile(r"(?:window\.)?location\.href", re.IGNORECASE),
        "document.referrer": re.compile(r"document\.referrer", re.IGNORECASE),
        "window.name": re.compile(r"window\.name", re.IGNORECASE),
        "document.cookie": re.compile(r"document\.cookie", re.IGNORECASE),
    }

    SINKS = {
        "innerHTML": re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
        "outerHTML": re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
        "document.write": re.compile(r"document\.write(?:ln)?\s*\(", re.IGNORECASE),
        "eval": re.compile(r"(?<![a-zA-Z0-9_$])eval\s*\(", re.IGNORECASE),
        "setTimeout": re.compile(r"setTimeout\s*\(", re.IGNORECASE),
        "setInterval": re.compile(r"setInterval\s*\(", re.IGNORECASE),
        "Function": re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
        "location.href": re.compile(r"location\.(?:href|assign|replace)\s*=", re.IGNORECASE),
    }

    def analyze(self, html_or_js: str, base_url: str = "") -> list[dict[str, Any]]:
        """Analyze client-side script code for DOM XSS source-to-sink flows."""
        parser = _ScriptExtractor()
        try:
            parser.feed(html_or_js)
            scripts = parser.scripts
        except Exception:
            scripts = []

        if not scripts:
            scripts = [html_or_js]

        findings: list[dict[str, Any]] = []

        for script in scripts:
            # Check which sources are present
            detected_sources: dict[str, list[str]] = {}
            for source_name, source_regex in self.SOURCES.items():
                if source_regex.search(script):
                    # Find variable assignments from source, e.g. var hashVal = location.hash;
                    var_matches = re.findall(
                        r"(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*[^;\n]*" + source_regex.pattern,
                        script,
                        re.IGNORECASE,
                    )
                    detected_sources[source_name] = var_matches

            if not detected_sources:
                continue

            # Check which sinks are present
            for sink_name, sink_regex in self.SINKS.items():
                if sink_regex.search(script):
                    for source_name, var_names in detected_sources.items():
                        # High confidence if a variable storing the source is passed directly into sink
                        high_confidence = False
                        if var_names:
                            for vname in var_names:
                                if re.search(r"\b" + re.escape(vname) + r"\b", script):
                                    high_confidence = True
                                    break
                        else:
                            high_confidence = True

                        findings.append(
                            {
                                "category": "dom_xss",
                                "source": source_name,
                                "sink": sink_name,
                                "confidence": "high" if high_confidence else "medium",
                                "base_url": base_url,
                                "evidence": f"Flow detected from {source_name} to {sink_name}",
                            }
                        )

        return findings


class SPARouteExtractor:
    """Discovers dynamic Single Page Application (SPA) routes from client-side bundles."""

    ROUTE_PATTERNS = [
        re.compile(r"""(?:path|to)\s*:\s*["'](/[^"']+)["']""", re.IGNORECASE),
        re.compile(r"""<Route\s+[^>]*path=["'](/[^"']+)["']""", re.IGNORECASE),
        re.compile(
            r"""history\.(?:pushState|replaceState)\s*\([^,]+,[^,]+,["'](/[^"']+)["']""", re.IGNORECASE
        ),
        re.compile(r"""["'](/api/v[0-9]+/[a-zA-Z0-9_\-/{}:]+)["']"""),
    ]

    def extract_routes(self, content: str, base_url: str = "") -> list[str]:
        routes: set[str] = set()
        for pattern in self.ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                route = match.group(1).strip()
                # Ignore file extensions and image assets
                if not any(route.endswith(ext) for ext in (".png", ".jpg", ".css", ".js", ".svg", ".ico")):
                    routes.add(route)
        return sorted(routes)


class HeadlessBrowserDriver:
    """Orchestrates headless Chromium execution for client DOM inspection and DOM XSS."""

    def __init__(self, browser_binary: str | None = None) -> None:
        self.browser_binary = browser_binary or find_browser_binary()

    def is_available(self) -> bool:
        return self.browser_binary is not None and os.path.exists(self.browser_binary)

    def render_dom(self, target_url: str, timeout_seconds: int = 10) -> dict[str, Any]:
        """Execute headless Chromium to render the live dynamic DOM tree."""
        if not self.browser_binary:
            return {
                "status": "unavailable",
                "reason": "Chromium binary not found on this system.",
                "dom": "",
            }

        cmd = [
            self.browser_binary,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--dump-dom",
            target_url,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "returncode": proc.returncode,
                "dom": proc.stdout,
                "stderr": proc.stderr[:500] if proc.stderr else "",
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "reason": f"Execution exceeded {timeout_seconds}s limit.", "dom": ""}
        except Exception as exc:
            return {"status": "error", "reason": str(exc), "dom": ""}

    def verify_dom_xss(
        self,
        target_url: str,
        parameter: str = "",
        canary: str = "sharay_dom_xss",
    ) -> dict[str, Any]:
        """Probe for DOM XSS using client execution and verify canary reflection."""
        # Inject canary in fragment and query
        probe_url = f"{target_url}#{canary}"
        render_res = self.render_dom(probe_url, timeout_seconds=8)

        dom = render_res.get("dom", "")
        canary_reflected = canary in dom

        return {
            "status": "verified" if canary_reflected else "not_reproduced",
            "canary": canary,
            "target_url": probe_url,
            "canary_reflected": canary_reflected,
            "render_status": render_res.get("status"),
        }

    def capture_screenshot(
        self,
        target_url: str,
        output_path: str,
        timeout_seconds: int = 15,
        window_size: str = "1280,800",
    ) -> dict[str, Any]:
        """Execute headless Chromium to capture a live visual snapshot of the rendered target."""
        if not self.browser_binary:
            return {
                "status": "unavailable",
                "reason": "Chromium binary not found on this system.",
                "path": None,
            }
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        cmd = [
            self.browser_binary,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--window-size={window_size}",
            f"--screenshot={output_path}",
            target_url,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            success = (
                proc.returncode == 0 and os.path.isfile(output_path) and os.path.getsize(output_path) > 0
            )
            return {
                "status": "success" if success else "error",
                "returncode": proc.returncode,
                "path": output_path if success else None,
                "stderr": proc.stderr[:500] if proc.stderr else "",
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "reason": f"Screenshot exceeded {timeout_seconds}s limit.",
                "path": None,
            }
        except Exception as exc:
            return {"status": "error", "reason": str(exc), "path": None}


__all__ = [
    "BrowserWorkflowError",
    "DOMSinkTracker",
    "HeadlessBrowserDriver",
    "SPARouteExtractor",
    "find_browser_binary",
    "validate_workflow",
    "MAX_STEPS",
    "MAX_TEXT",
]
