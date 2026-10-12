"""Gitleaks JSON report parser (L6): where a secret was reported, never the secret.

Parser only: no command line is built and Gitleaks has never run here. Field names follow
the tool's documented report (RuleID, File, StartLine, Fingerprint; Secret and Match are
never read). The report has no error section: whether the scan itself completed is the
caller's job to take from the tool's exit status. Adapted from Gemini's reviewed draft.
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


def parse(data: bytes, source_root: str = "") -> dict:
    """Return {"findings": [...], "truncated": bool}; one malformed entry anywhere rejects the report."""
    report = load_json(data, "Gitleaks report")
    if not isinstance(report, list) or not all(isinstance(item, dict) for item in report):
        raise ValueError("Gitleaks report is not a list of objects.")
    findings: list[dict] = []
    for item in report:  # every entry is validated, even past the retention cap
        rule = text(item.get("RuleID"), "Gitleaks RuleID")
        path = relative_path(item.get("File"), "Gitleaks File", source_root)
        line = line_number(item.get("StartLine"), "Gitleaks StartLine")
        # The tool's own fingerprint (commit:file:rule:line) is hashed, not stored.
        tool_id = item.get("Fingerprint") if isinstance(item.get("Fingerprint"), str) else ""
        if len(findings) < MAX_FINDINGS:
            identity = fingerprint(rule, path, line, tool_id)
            findings.append({"rule": shown(rule), "file": shown(path), "line": line, "fingerprint": identity})
    return {"findings": findings, "truncated": len(report) > MAX_FINDINGS}


__all__ = ["parse"]
