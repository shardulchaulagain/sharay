"""Measure the built-in secret detector against a labelled corpus (L8).

Each case is written to a temporary tree, the detector runs over it, and the rules reported
per file are compared with the labels. The numbers describe this finite synthetic corpus
only. Run: python -m tests.evaluation.secret_detection
"""

import hashlib
import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from services.source_analysis_worker.secrets import detect
from tests.evaluation.http_configuration import _totals

CORPUS = Path(__file__).parent / "corpus" / "secret_detection.v1.json"


def evaluate(corpus_path: Path = CORPUS, detector: Callable = detect) -> dict:
    """Materialize the corpus, scan it once, and return a machine-readable report."""
    raw = corpus_path.read_bytes()
    corpus = json.loads(raw)
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder).resolve() / "tree"
        for case in corpus["cases"]:
            path = root / case["file"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(case["content_pieces"]))
        outcome = detector(root)
    reported: dict[str, set[str]] = {}
    for match in outcome["matches"]:
        reported.setdefault(match["file"], set()).add(match["rule"])
    results = []
    for case in corpus["cases"]:
        expected, observed = set(case["expected"]), reported.get(case["file"], set())
        results.append(
            {
                "id": case["id"],
                "subset": case["subset"],
                "expected": sorted(expected),
                "observed": sorted(observed),
                "correct": sorted(expected & observed),
                "unexpected": sorted(observed - expected),
                "missed": sorted(expected - observed),
            }
        )
    subsets = sorted({case["subset"] for case in results})
    return {
        "corpus": {
            "id": corpus["id"],
            "version": corpus["version"],
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        # A file the detector could not read is not a scored case.
        "files_scanned": outcome["files_scanned"],
        "files_skipped": len(outcome["skipped"]),
        "totals": _totals(results),
        "by_subset": {
            name: _totals([case for case in results if case["subset"] == name]) for name in subsets
        },
        "cases": results,
        "limits": "Finite synthetic corpus of provider-token shapes; not a general detection-rate claim.",
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
