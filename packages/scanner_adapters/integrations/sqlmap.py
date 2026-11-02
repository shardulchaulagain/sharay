"""Bounded non-destructive SQLMap auxiliary integration adapter.

Executes non-destructive SQLMap verification commands (--batch --dbs --level=2)
against confirmed SQL injection injection points, strictly prohibiting destructive
exploitation options (--os-shell, --os-cmd, --file-write, etc.).
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from typing import Any

from packages.security_policies import Destination

_FORBIDDEN_SQLMAP_FLAGS = {
    "--os-shell",
    "--os-cmd",
    "--os-pwn",
    "--os-smbrelay",
    "--os-bof",
    "--priv-esc",
    "--msf-path",
    "--sql-shell",
    "--file-write",
    "--file-dest",
    "--sql-file",
    "--sql-query",
    "--drop",
    "--dump-all",
}


def build_safe_sqlmap_command(
    target_url: str,
    parameter: str | None = None,
    cookie: str | None = None,
    level: int = 2,
    risk: int = 1,
) -> list[str]:
    """Construct a strictly bounded, non-destructive SQLMap verification command."""
    bounded_level = max(1, min(level, 3))
    bounded_risk = max(1, min(risk, 1))  # strictly cap risk to 1 (non-destructive)

    cmd = [
        "sqlmap",
        "-u",
        target_url,
        "--batch",
        "--dbs",
        f"--level={bounded_level}",
        f"--risk={bounded_risk}",
        "--flush-session",
        "--threads=2",
        "--timeout=10",
        "--retries=2",
        "--random-agent",
    ]
    if parameter:
        cmd.extend(["-p", parameter])
    if cookie:
        cmd.extend(["--cookie", cookie])
    return cmd


def build_exploit_sqlmap_command(
    target_url: str,
    parameter: str | None = None,
    cookie: str | None = None,
    exploit_type: str = "dump",
    level: int = 3,
    risk: int = 3,
) -> list[str]:
    """Full-exploitation SQLMap command (W5 -- no capability gate; the operator's authorized target scope
    is the only boundary). `exploit_type`: 'dump' extracts table data, 'os_shell' attempts OS command
    execution, 'read' reads a server file. The command is pinned to the authorized target_url."""
    cmd = [
        "sqlmap", "-u", target_url, "--batch",
        f"--level={max(1, min(int(level), 5))}", f"--risk={max(1, min(int(risk), 3))}",
        "--threads=4", "--timeout=15", "--retries=2", "--random-agent", "--flush-session",
    ]
    cmd.append({"os_shell": "--os-shell", "read": "--file-read=/etc/passwd"}.get(exploit_type, "--dump"))
    if parameter:
        cmd.extend(["-p", parameter])
    if cookie:
        cmd.extend(["--cookie", cookie])
    return cmd


def validate_exploit_sqlmap_command(cmd: list[str], authorized_target: str) -> None:
    """The one invariant for exploitation: the target (-u) must equal the operator-authorized target, so
    the tool never attacks a different host. Capability flags (--dump/--os-shell/--file-read) are allowed."""
    if cmd[:1] != ["sqlmap"]:
        raise ValueError("Not a sqlmap command")
    try:
        target = cmd[cmd.index("-u") + 1]
    except (ValueError, IndexError):
        raise ValueError("sqlmap exploit command must pin an explicit -u target") from None
    if target != authorized_target:
        raise ValueError(f"sqlmap target '{target}' is not the authorized target '{authorized_target}'")


def validate_sqlmap_command(cmd: list[str]) -> None:
    """Validate that the command contains zero destructive exploitation options."""
    for arg in cmd:
        for forbidden in _FORBIDDEN_SQLMAP_FLAGS:
            if forbidden in arg.lower():
                raise ValueError(f"Forbidden destructive SQLMap option detected: '{arg}'")


def parse_sqlmap_output(stdout: str) -> dict[str, Any]:
    """Parse standard SQLMap stdout into structured DBMS metadata and confirmed databases."""
    dbms = None
    technologies = []
    databases = []

    # Parse DBMS
    dbms_match = re.search(r"back-end DBMS:\s*([^\r\n]+)", stdout, re.IGNORECASE)
    if dbms_match:
        dbms = dbms_match.group(1).strip()

    # Parse web server & tech
    tech_match = re.search(r"web application technology:\s*([^\r\n]+)", stdout, re.IGNORECASE)
    if tech_match:
        technologies = [t.strip() for t in tech_match.group(1).split(",")]

    # Parse databases list
    # e.g.:
    # available databases [2]:
    # [*] information_schema
    # [*] dvwa
    dbs_match = re.search(
        r"available databases \[\d+\]:\s*\n((?:\s*\[\*\]\s*[^\r\n]+\n?)+)", stdout, re.IGNORECASE
    )
    if dbs_match:
        raw_list = dbs_match.group(1)
        databases = [
            line.replace("[*]", "").strip() for line in raw_list.strip().splitlines() if line.strip()
        ]

    is_vulnerable = bool(
        dbms
        or databases
        or "is vulnerable" in stdout.lower()
        or "sqlmap identified the following injection point" in stdout.lower()
    )

    return {
        "is_vulnerable": is_vulnerable,
        "dbms": dbms,
        "technologies": technologies,
        "available_databases": databases,
    }


def run_sqlmap_auxiliary_check(
    destination: Destination,
    allow_ip: str,
    target_url: str,
    parameter: str | None = None,
    cookie: str | None = None,
    runner_fn: Any = None,
) -> dict[str, Any]:
    """Execute SQLMap in non-destructive verification mode and return structured results."""
    cmd = build_safe_sqlmap_command(target_url, parameter=parameter, cookie=cookie)
    validate_sqlmap_command(cmd)

    if runner_fn is not None:
        stdout, exit_code = runner_fn(cmd)
    else:
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            stdout = res.stdout
            exit_code = res.returncode
        except Exception as e:
            stdout = str(e)
            exit_code = 1

    parsed = parse_sqlmap_output(stdout)
    findings: list[dict[str, Any]] = []

    if parsed["is_vulnerable"]:
        dbms_label = parsed["dbms"] or "Database"
        repro_cmd = " ".join(cmd)
        findings.append(
            {
                "category": "injection",
                "severity": "critical",
                "title": f"SQLMap Auxiliary Confirmed SQLi on {target_url} ({dbms_label})",
                "description": (
                    f"SQLMap auxiliary engine verified SQL injection vulnerability on {target_url}. "
                    f"Identified backend DBMS: {dbms_label}. "
                    f"Enumerated non-destructive databases: {parsed['available_databases']}."
                ),
                "target_url": target_url,
                "fingerprint": hashlib.sha256(
                    f"sqlmap_{destination.host}_{target_url}_{parameter}".encode()
                ).hexdigest(),
                "cwe_id": "CWE-89",
                "confidence": "high",
                "status": "confirmed",
                "lifecycle_state": "REPRODUCED",
                "remediation": "Enforce strict parameterized queries and prepared statements.",
                "poc": {
                    "method": "GET",
                    "url": target_url,
                    "command": repro_cmd,
                    "dbms": parsed["dbms"],
                    "available_databases": parsed["available_databases"],
                },
                "evidence": [
                    {
                        "dbms": parsed["dbms"],
                        "databases": parsed["available_databases"],
                        "exit_code": exit_code,
                    }
                ],
            }
        )

    return {
        "findings": findings,
        "parsed_metadata": parsed,
        "check": {
            "category": "sqlmap_auxiliary_verification",
            "target_url": target_url,
            "status": "completed" if exit_code == 0 or parsed["is_vulnerable"] else "failed",
            "findings_count": len(findings),
        },
    }


__all__ = [
    "build_safe_sqlmap_command",
    "build_exploit_sqlmap_command",
    "validate_exploit_sqlmap_command",
    "parse_sqlmap_output",
    "run_sqlmap_auxiliary_check",
    "validate_sqlmap_command",
]
