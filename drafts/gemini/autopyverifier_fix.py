"""Reference implementation of AutoPyVerifier with live response capture and HTTP error handling (P0)."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any


class FixedAutoPyVerifier:
    """Synthesizes and runs isolated Python verification scripts to confirm hypotheses (G3)."""

    def synthesize_script(
        self,
        *,
        target_url: str,
        vuln_type: str,
        canary: str,
        payload: str | None = None,
        parameter: str = "id",
        mock_mode: bool = False,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> str:
        """Synthesize a self-contained, executable Python script verifying the hypothesis."""
        if mock_mode:
            return f'''# Auto-generated verification script for {vuln_type}
def verify():
    # Synthetic verification harness
    test_canary = "{canary}"
    simulated_response = f"Database query result with {{test_canary}} present."
    assert test_canary in simulated_response, f"Canary '{{test_canary}}' not reflected in target response."
    print("VERIFICATION_SUCCESS: Canary reflected.")

if __name__ == "__main__":
    verify()
'''

        is_post = method.upper() == "POST"
        extra = dict(extra_params or {})
        test_payload = payload if payload is not None else canary
        hdrs = {"User-Agent": "SHARAY-AutoPyVerifier/1.0"}
        if "4280" in target_url or "vulnerabilities" in target_url or "dvwa" in target_url.lower():
            sec = os.environ.get("SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high"))
            hdrs["Cookie"] = f"security={sec}"
        if headers:
            hdrs.update(headers)
        if is_post and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        hdrs_repr = repr(hdrs)
        extra_repr = repr(extra)
        payload_repr = repr(test_payload)
        canary_repr = repr(canary or "")
        url_repr = repr(target_url)

        if is_post:
            return f'''# Auto-generated verification script for {vuln_type}
import sys
import urllib.error
import urllib.parse
import urllib.request

def verify():
    target_base = {url_repr}
    canary_token = {canary_repr}
    test_payload = {payload_repr}
    extra_data = {extra_repr}
    form_data = {{{repr(parameter)}: test_payload, **extra_data}}
    req_data = urllib.parse.urlencode(form_data).encode("utf-8")
    req_headers = {hdrs_repr}
    req = urllib.request.Request(target_base, data=req_data, headers=req_headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}})) if ("127.0.0.1" in target_base or "localhost" in target_base) else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=5.0) as resp:
            body = resp.read().decode("utf-8", errors="replace").lower()
            token = canary_token.lower()
            if "sharay_canary_cmd" in token and ("echo sharay_canary_cmd" in body or "echo+sharay_canary_cmd" in body or "_post[" in body or "_request[" in body):
                assert False, "Canary was only reflected as raw input string, not executed by operating system shell."
            signatures = [token, "sql syntax", "warning: mysql", "mariadb", "root:x:0:0:", "root:*:0:0:", "www-data", "sharay_canary"]
            matched = any(s in body for s in signatures if s)
            assert matched, f"Neither canary token nor exploit signature was observed in target response."
            print("VERIFICATION_SUCCESS: Target vulnerability confirmed with live evidence.")
    except urllib.error.HTTPError as http_exc:
        body = http_exc.read().decode("utf-8", errors="replace").lower()
        token = canary_token.lower()
        signatures = [token, "sql syntax", "warning: mysql", "mariadb", "root:x:0:0:", "root:*:0:0:", "www-data", "sharay_canary"]
        matched = any(s in body for s in signatures if s)
        assert matched, f"HTTP {{http_exc.code}} received without canary or exploit signature in response."
        print("VERIFICATION_SUCCESS: Target vulnerability confirmed in error response.")
    except Exception as exc:
        print(f"VERIFICATION_FAILED: {{exc}}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    verify()
'''

        return f'''# Auto-generated verification script for {vuln_type}
import sys
import urllib.error
import urllib.parse
import urllib.request

def verify():
    target_base = {url_repr}
    canary_token = {canary_repr}
    test_payload = {payload_repr}
    extra_params = {extra_repr}
    query_dict = {{{repr(parameter)}: test_payload, **extra_params}}
    query_str = urllib.parse.urlencode(query_dict)
    sep = "&" if "?" in target_base else "?"
    test_url = f"{{target_base}}{{sep}}{{query_str}}"
    req_headers = {hdrs_repr}
    req = urllib.request.Request(test_url, headers=req_headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}})) if ("127.0.0.1" in target_base or "localhost" in target_base) else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=5.0) as resp:
            body = resp.read().decode("utf-8", errors="replace").lower()
            token = canary_token.lower()
            if "sharay_canary_cmd" in token and ("echo sharay_canary_cmd" in body or "echo+sharay_canary_cmd" in body or "_get[" in body or "_request[" in body):
                assert False, "Canary was only reflected as raw input string, not executed by operating system shell."
            signatures = [token, "sql syntax", "warning: mysql", "mariadb", "root:x:0:0:", "root:*:0:0:", "www-data", "sharay_canary"]
            matched = any(s in body for s in signatures if s)
            assert matched, f"Neither canary token nor exploit signature was observed in target response."
            print("VERIFICATION_SUCCESS: Target vulnerability confirmed with live evidence.")
    except urllib.error.HTTPError as http_exc:
        body = http_exc.read().decode("utf-8", errors="replace").lower()
        token = canary_token.lower()
        signatures = [token, "sql syntax", "warning: mysql", "mariadb", "root:x:0:0:", "root:*:0:0:", "www-data", "sharay_canary"]
        matched = any(s in body for s in signatures if s)
        assert matched, f"HTTP {{http_exc.code}} received without canary or exploit signature in response."
        print("VERIFICATION_SUCCESS: Target vulnerability confirmed in error response.")
    except Exception as exc:
        print(f"VERIFICATION_FAILED: {{exc}}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    verify()
'''

    def execute_in_sandbox(self, script_content: str, timeout_seconds: int = 5) -> dict[str, Any]:
        """Execute the synthesized verification script in an isolated sub-process sandbox."""
        cmd = [sys.executable, "-c", script_content]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
            return {
                "status": "verified" if res.returncode == 0 else "failed",
                "returncode": res.returncode,
                "stdout": res.stdout.strip(),
                "error": res.stderr.strip(),
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "failed",
                "returncode": 124,
                "stdout": "",
                "error": f"Execution timed out after {timeout_seconds} seconds.",
            }
