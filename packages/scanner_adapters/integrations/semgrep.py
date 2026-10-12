"""Semgrep JSON output parser (L6): rule, location, severity and scan coverage; no code.

Parser only: no command line is built and Semgrep has never run here. Field names follow
the tool's documented `--json` output (results[].check_id, path, start.line, extra.severity,
extra.metadata.cwe; errors[]; paths.scanned/skipped). `extra.lines` is source code and
`extra.message` and error messages can carry matched code, so none of them is read.
Adapted from Gemini's reviewed draft.
"""

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    fingerprint,
    line_number,
    load_json,
    relative_path,
    shown,
    text,
)

SEVERITIES = {"critical", "high", "medium", "low", "error", "warning", "info"}


def _count(container: dict, key: str, what: str) -> int:
    value = container.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"Semgrep {what} is not a list.")
    return len(value)


def parse(data: bytes, source_root: str = "") -> dict:
    """Return findings plus a coverage summary; one malformed part anywhere rejects the output.

    `complete` is False when the tool reported any error, so a failed or partial scan with
    no results can never be mistaken for a clean one. Skipped paths are counted, not judged.
    """
    report = load_json(data, "Semgrep output")
    results = report.get("results") if isinstance(report, dict) else None
    if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
        raise ValueError("Semgrep output has no list of result objects.")
    paths = report.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("Semgrep paths is not an object.")
    errors = _count(report, "errors", "errors")
    findings: list[dict] = []
    for item in results:  # every result is validated, even past the retention cap
        rule = text(item.get("check_id"), "Semgrep check_id")
        path = relative_path(item.get("path"), "Semgrep path", source_root)
        start = item.get("start")
        line = line_number(start.get("line") if isinstance(start, dict) else None, "Semgrep start line")
        extra: dict = item["extra"] if isinstance(item.get("extra"), dict) else {}
        level = extra.get("severity")
        severity = level.lower() if isinstance(level, str) else ""
        metadata: dict = extra["metadata"] if isinstance(extra.get("metadata"), dict) else {}
        weaknesses = metadata.get("cwe", [])
        weaknesses = [weaknesses] if isinstance(weaknesses, str) else weaknesses
        if not isinstance(weaknesses, list):
            raise ValueError("Semgrep cwe is not text or a list.")
        cwe = [shown(text(weakness, "Semgrep cwe")) for weakness in weaknesses[:5]]
        if len(findings) < MAX_FINDINGS:
            findings.append(
                {
                    "rule": shown(rule),
                    "file": shown(path),
                    "line": line,
                    # An unrecognized severity is reported as unknown, never silently downgraded.
                    "severity": severity if severity in SEVERITIES else "unknown",
                    "cwe": cwe,
                    "fingerprint": fingerprint(rule, path, line),
                }
            )
    return {
        "findings": findings,
        "truncated": len(results) > MAX_FINDINGS,
        "complete": errors == 0,
        "errors": errors,
        "paths_scanned": _count(paths, "scanned", "scanned paths"),
        "paths_skipped": _count(paths, "skipped", "skipped paths"),
    }


__all__ = ["parse"]
