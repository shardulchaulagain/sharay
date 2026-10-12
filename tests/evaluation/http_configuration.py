"""Measure the safe HTTP adapter against a labelled corpus (L8).

Each case is one response served by a loopback fixture this module starts; the adapter's
reported checks are compared with the case's labels. The numbers describe this finite
corpus only. Run: python -m tests.evaluation.http_configuration
"""

import hashlib
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from packages.scanner_adapters import ADAPTER_VERSION, scan

CORPUS = Path(__file__).parent / "corpus" / "http_configuration.v1.json"


def _ratio(numerator: int, denominator: int) -> float | None:
    # Undefined stays undefined: an empty denominator is not a perfect score.
    return round(numerator / denominator, 4) if denominator else None


def _totals(cases: list[dict]) -> dict:
    tp, fp, fn = (sum(len(case[key]) for case in cases) for key in ("correct", "unexpected", "missed"))
    return {
        "cases": len(cases),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
    }


def evaluate(corpus_path: Path = CORPUS, scanner: Callable = scan) -> dict:
    """Serve every case on loopback, scan it, and return a machine-readable report."""
    raw = corpus_path.read_bytes()
    corpus = json.loads(raw)
    headers = {case["id"]: case["response_headers"] for case in corpus["cases"]}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for name, value in headers.get(self.path.removeprefix("/case/"), []):
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    now = datetime.now(UTC)
    # The same explicit loopback laboratory scope the product tests use.
    scope = {
        "hosts": ["127.0.0.1"],
        "allowed_origins": [origin],
        "allowed_paths": ["/case"],
        "allowed_cidrs": ["127.0.0.1/32"],
        "categories": ["http_headers"],
        "request_rate": 5,
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
    }
    results = []
    try:
        for case in corpus["cases"]:
            outcome = scanner(scope, f"{origin}/case/{case['id']}", lambda: False, lambda _event: None)
            expected = set(case["expected"])
            observed = {finding["evidence"]["check"] for finding in outcome["findings"]}
            results.append(
                {
                    "id": case["id"],
                    "subset": case["subset"],
                    # A scan that did not complete is recorded as such, never scored as agreement.
                    "scan_outcome": outcome["outcome"],
                    "expected": sorted(expected),
                    "observed": sorted(observed),
                    "correct": sorted(expected & observed),
                    "unexpected": sorted(observed - expected),
                    "missed": sorted(expected - observed),
                }
            )
    finally:
        server.shutdown()
        server.server_close()
    subsets = sorted({case["subset"] for case in results})
    return {
        "corpus": {
            "id": corpus["id"],
            "version": corpus["version"],
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "adapter": {"id": "safe_http", "version": ADAPTER_VERSION},
        "generated_at": now.isoformat(timespec="seconds"),
        "incomplete_scans": [case["id"] for case in results if case["scan_outcome"] != "completed"],
        "totals": _totals(results),
        "by_subset": {
            name: _totals([case for case in results if case["subset"] == name]) for name in subsets
        },
        "cases": results,
        "limits": "Finite synthetic corpus on plain HTTP loopback; not a general precision or recall claim.",
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
