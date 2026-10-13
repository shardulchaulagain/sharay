"""Gitleaks JSON report parser (L6): where a secret was reported, never the secret.

Field names follow the tool's report (RuleID, File, StartLine, Fingerprint; Secret and Match
are never read); checked against real output of Gitleaks 8.30.1 on October 12, 2026. The
report has no error section: whether the scan itself completed is the caller's job to take
from the tool's exit status. Parser adapted from Gemini's reviewed draft.

`build_argv` exists because a scanned tree can reconfigure the scanner. Measured on 8.30.1:
a tree's own .gitleaks.toml silenced every finding until --config named another file;
"gitleaks:allow" comments hid matches until --ignore-gitleaks-allow; and a .gitleaksignore
inside the tree still suppressed findings with no flag to turn it off. So a scan of a tree
for which `suppression_files` returns anything must never be reported as complete.
Nothing here is connected to dispatch.
"""

import os
from pathlib import Path

from packages.scanner_adapters.integrations._parsing import (
    MAX_FINDINGS,
    fingerprint,
    line_number,
    load_json,
    relative_path,
    shown,
    text,
)

# This tool's own default rules and nothing from the scanned tree.
PINNED_CONFIG = str(Path(__file__).with_name("gitleaks.toml"))
SUPPRESSION_FILES = (".gitleaksignore", ".gitleaks.toml")


def build_argv(executable: str, target: str, config: str = PINNED_CONFIG, max_seconds: int = 60) -> list[str]:
    """Command line for one directory scan: report on stdout, secrets redacted, tree cannot reconfigure it."""
    for value in (executable, target, config):
        if not isinstance(value, str) or not os.path.isabs(value) or not value.isprintable():
            raise ValueError("Gitleaks paths must be absolute printable text.")
    if type(max_seconds) is not int or not 5 <= max_seconds <= 300:
        raise ValueError("The Gitleaks time budget must be 5 to 300 seconds.")
    return [
        executable,
        "dir",
        "--no-banner",
        "--no-color",
        "--log-level=error",
        "--redact",  # the report then carries no secret text at all
        "--exit-code=0",  # findings are not a failure; a non-zero status means the scan broke
        "--report-format=json",
        "--report-path=-",
        f"--config={config}",
        "--ignore-gitleaks-allow",
        "--max-target-megabytes=5",
        f"--timeout={max_seconds - 2}",
        target,
    ]


def suppression_files(root: Path | str) -> list[str]:
    """Files inside a scanned tree that can silence Gitleaks; any makes the scan incomplete."""
    root = Path(root)
    found = [
        Path(folder, name).relative_to(root).as_posix()
        for folder, _folders, files in os.walk(root)  # never follows directory links
        for name in files
        if name in SUPPRESSION_FILES
    ]
    return [shown(name) for name in sorted(found)[:100]]


def parse(data: bytes, source_root: str = "") -> dict:
    """Return {"findings": [...], "truncated": bool}; one malformed entry anywhere rejects the report."""
    report = load_json(data, "Gitleaks report")
    if not isinstance(report, list) or not all(isinstance(item, dict) for item in report):
        raise ValueError("Gitleaks report is not a list of objects.")
    findings: list[dict] = []
    root = source_root.replace("\\", "/").rstrip("/")
    for item in report:  # every entry is validated, even past the retention cap
        rule = text(item.get("RuleID"), "Gitleaks RuleID")
        path = relative_path(item.get("File"), "Gitleaks File", source_root)
        line = line_number(item.get("StartLine"), "Gitleaks StartLine")
        # The tool's own fingerprint (commit:file:rule:line) is hashed, not stored.
        tool_id = item.get("Fingerprint") if isinstance(item.get("Fingerprint"), str) else ""
        # Real directory scans put the absolute path in it; without this the same secret in a
        # different staging folder would look like a new finding at every retest.
        tool_id = tool_id.replace(root + "/", "") if root else tool_id
        if len(findings) < MAX_FINDINGS:
            identity = fingerprint(rule, path, line, tool_id)
            findings.append({"rule": shown(rule), "file": shown(path), "line": line, "fingerprint": identity})
    return {"findings": findings, "truncated": len(report) > MAX_FINDINGS}


__all__ = ["PINNED_CONFIG", "SUPPRESSION_FILES", "build_argv", "parse", "suppression_files"]
