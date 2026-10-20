"""AutoPyVerifier, Consensus Voting & Entropy Escalation Engine (G2–G7).

Provides:
1. AutoPyVerifier: programmatic synthesis of standalone Python verification scripts
   executed in isolated sandboxes to empirically validate vulnerability hypotheses (G3).
2. ConsensusSearchEngine: Best-of-N temperature-sampled trajectory evaluation and
   Shannon entropy gating, escalating ambiguous cases to frontier models (G4, G5, G6).
3. FlightLogDatasetIngester: continuous training dataset compilation from flight logs (G7).
"""

from __future__ import annotations

import math
import os
import subprocess
import sys
from typing import Any, Sequence


class AutoPyVerifier:
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
            return f"""# Auto-generated verification script for {vuln_type}
import sys
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
            body = resp.read().decode("utf-8", "replace").lower()
            token = canary_token.lower()
            if "sharay_canary_cmd" in token and ("echo sharay_canary_cmd" in body or "echo+sharay_canary_cmd" in body or "_post[" in body or "_request[" in body):
                assert False, "Canary was only reflected as raw input string, not executed by operating system shell."
            signatures = [token, "sql syntax", "warning: mysql", "mariadb", "root:x:0:0:", "root:*:0:0:", "www-data", "sharay_canary"]
            matched = any(s in body for s in signatures if s)
            assert matched, f"Neither canary token nor exploit signature was observed in target response."
            print("VERIFICATION_SUCCESS: Target vulnerability confirmed with live evidence.")
    except Exception as exc:
        print(f"VERIFICATION_FAILED: {{exc}}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    verify()
"""

        return f"""# Auto-generated verification script for {vuln_type}
import sys
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
            body = resp.read().decode("utf-8", "replace").lower()
            token = canary_token.lower()
            if "sharay_canary_cmd" in token and ("echo sharay_canary_cmd" in body or "echo+sharay_canary_cmd" in body or "_get[" in body or "_request[" in body):
                assert False, "Canary was only reflected as raw input string, not executed by operating system shell."
            signatures = [token, "sql syntax", "warning: mysql", "mariadb", "root:x:0:0:", "root:*:0:0:", "www-data", "sharay_canary"]
            matched = any(s in body for s in signatures if s)
            assert matched, f"Neither canary token nor exploit signature was observed in target response."
            print("VERIFICATION_SUCCESS: Target vulnerability confirmed with live evidence.")
    except Exception as exc:
        print(f"VERIFICATION_FAILED: {{exc}}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    verify()
"""

    def execute_in_sandbox(
        self,
        script: str,
        timeout_seconds: int = 5,
        target_destinations: Sequence[tuple[str, int]] | None = None,
        use_container: bool | None = None,
    ) -> dict[str, Any]:
        """Execute the synthesized verification script in an isolated sandbox (Sector 1.1).

        When container isolation is requested or configured (SHARAY_CONTAINER_VERIFIER=1),
        executes inside the rootless container netns sandbox with locked egress.
        Otherwise executes in a hardened subprocess sandbox with sanitized environment.
        """
        if use_container or (use_container is None and os.environ.get("SHARAY_CONTAINER_VERIFIER") == "1"):
            try:
                from services.scanner_worker.container import _machine_ssh, container_runtime

                rt = container_runtime()
                if rt is not None and "podman" in rt:
                    import shlex

                    quoted_script = shlex.quote(script)
                    vm_cmd = f"python3 -c {quoted_script}"
                    res = _machine_ssh(vm_cmd, timeout=float(timeout_seconds))
                    if res.returncode == 0:
                        return {
                            "status": "verified",
                            "returncode": 0,
                            "stdout": res.stdout.strip(),
                            "isolation": "rootless_container_vm",
                        }
                    return {
                        "status": "failed",
                        "returncode": res.returncode,
                        "stdout": res.stdout.strip(),
                        "error": res.stderr.strip() or res.stdout.strip(),
                        "isolation": "rootless_container_vm",
                    }
            except Exception:
                pass  # Fall back to hardened subprocess sandbox

        # Hardened host process sandbox: scrubbed environment, no inherited secrets
        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
        }
        cmd = [sys.executable, "-c", script]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env=clean_env,
            )
            if proc.returncode == 0:
                return {
                    "status": "verified",
                    "returncode": 0,
                    "stdout": proc.stdout.strip(),
                    "isolation": "host_subprocess_sandbox",
                }
            return {
                "status": "failed",
                "returncode": proc.returncode,
                "stdout": proc.stdout.strip(),
                "error": proc.stderr.strip() or proc.stdout.strip(),
                "isolation": "host_subprocess_sandbox",
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "returncode": -1,
                "error": f"Execution timed out after {timeout_seconds}s.",
            }
        except Exception as exc:
            return {
                "status": "error",
                "returncode": -1,
                "error": str(exc),
            }


class ConsensusSearchEngine:
    """Best-of-N candidate consensus voting and Shannon entropy escalation gate (G4–G6)."""

    def evaluate_candidates(
        self,
        candidates: list[dict[str, Any]],
        entropy_threshold: float = 0.8,
    ) -> dict[str, Any]:
        """Compute consensus distribution, Shannon entropy, and trigger frontier escalation if variance is high."""
        if not candidates:
            return {
                "consensus_decision": None,
                "agreement_ratio": 0.0,
                "entropy": 0.0,
                "escalated": False,
            }

        total = len(candidates)
        # Count frequency of distinct hypotheses/verdicts
        counts: dict[str, int] = {}
        for c in candidates:
            key = str(c.get("hypothesis", c.get("verdict", "")))
            counts[key] = counts.get(key, 0) + 1

        # Calculate probabilities and Shannon entropy
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        top_choice, top_count = max(counts.items(), key=lambda kv: kv[1])
        agreement_ratio = top_count / total

        # Check if entropy exceeds threshold (high ambiguity)
        escalate = entropy >= entropy_threshold
        escalation_target = "Gemini 1.5 Pro / Claude 3.5 Sonnet" if escalate else None

        return {
            "consensus_decision": top_choice,
            "agreement_ratio": round(agreement_ratio, 3),
            "entropy": round(entropy, 3),
            "escalated": escalate,
            "escalation_target": escalation_target,
            "candidate_count": total,
            "distribution": {k: round(v / total, 3) for k, v in counts.items()},
        }


class FlightLogDatasetIngester:
    """Ingests human operator terminal keystrokes and overrides into model fine-tuning records (G7)."""

    def ingest(
        self,
        flight_log: list[dict[str, Any]],
        session_id: str = "",
    ) -> list[dict[str, Any]]:
        """Filter and format operator inputs from terminal flight log into training dataset items."""
        records: list[dict[str, Any]] = []
        for entry in flight_log:
            direction = entry.get("direction")
            if direction == "stdin":
                cmd_text = entry.get("preview", "").strip()
                if cmd_text:
                    records.append(
                        {
                            "session_id": session_id,
                            "timestamp": entry.get("timestamp", ""),
                            "sender": entry.get("sender", "human"),
                            "command": cmd_text,
                        }
                    )
        return records


__all__ = [
    "AutoPyVerifier",
    "ConsensusSearchEngine",
    "FlightLogDatasetIngester",
]
