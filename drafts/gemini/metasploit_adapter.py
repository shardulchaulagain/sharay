"""Bounded Metasploit Framework Integration Adapter (L4).

Author: Gemini (Principal Architect, Debugger & Helper)
Status: Hardened draft module under drafts/gemini/ for Claude L4 adoption.

Hardened guarantees per Claude review:
1. Non-interactive headless command: msfconsole -q -n -x, stdin DEVNULL.
2. Dynamic approved catalog integration: Modules must be passed via approved_module_refs
   (derived from stored ExecutionReadiness / catalog records conforming to packages/shared_schemas).
3. Intrusive & UDP modules removed: openssl_heartbleed and udp_probe strictly excluded.
4. Injection immunity: Strict regex validation on module name and address. Rejects semicolons,
   newlines, control chars, spaces, quotes, and command substitution characters.
5. Strict parameter validation: Canonical literal IPv4/IPv6, integer port [1-65535], bounded timeout.
6. Redaction: Banners and observations pass through shared secret pattern filters.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
from typing import Any, Sequence

from packages.secret_patterns import redact_tokens

# Default vetted non-intrusive TCP auxiliary scanners (no intrusive payloads, no UDP)
DEFAULT_NON_INTRUSIVE_MODULES: frozenset[str] = frozenset({
    "auxiliary/scanner/http/http_version",
    "auxiliary/scanner/http/title",
    "auxiliary/scanner/http/options",
    "auxiliary/scanner/ssl/ssl_version",
    "auxiliary/scanner/ssh/ssh_version",
})

# Module pattern conforming to packages/shared_schemas.Reference path conventions
_MODULE_SAFE_RE = re.compile(r"^auxiliary/scanner/[a-zA-Z0-9_/-]+$")
_FORBIDDEN_CHARS = re.compile(r"[;\r\n\t\s'\"`$(){}\[\]|&<>]")
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_VERSION_RE = re.compile(r"Framework Version:\s*([0-9a-zA-Z._-]+)", re.IGNORECASE)


class MetasploitAdapterError(ValueError):
    """Metasploit invocation proposal or output validation failed."""


def validate_module_name(
    module: str,
    approved_module_refs: frozenset[str] | set[str] | Sequence[str] | None = None,
) -> str:
    """Validate that an auxiliary module name is safe, syntactically valid, and approved."""
    if not isinstance(module, str) or not module.strip():
        raise MetasploitAdapterError("Module name must be a non-empty string.")

    if _FORBIDDEN_CHARS.search(module):
        raise MetasploitAdapterError(
            f"Module '{module}' contains illegal control, whitespace, or delimiter characters."
        )

    if not _MODULE_SAFE_RE.match(module):
        raise MetasploitAdapterError(
            f"Module '{module}' must match auxiliary/scanner/[a-zA-Z0-9_/-]+ and start with auxiliary/scanner/."
        )

    # Reject known intrusive or non-TCP modules
    lower = module.lower()
    if "heartbleed" in lower or "exploit" in lower or "udp" in lower or "dos" in lower:
        raise MetasploitAdapterError(
            f"Module '{module}' is classified as intrusive, UDP, or exploit-validation; excluded from safe inventory."
        )

    # Check against caller-provided approved records or fallback defaults
    allowed_set = set(approved_module_refs) if approved_module_refs is not None else DEFAULT_NON_INTRUSIVE_MODULES
    if module not in allowed_set:
        raise MetasploitAdapterError(
            f"Module '{module}' is not present in the approved auxiliary module catalog."
        )

    return module


def validate_target_address(address: str) -> str:
    """Validate that target address is a strict canonical literal IPv4 or IPv6."""
    if not isinstance(address, str) or not address.strip():
        raise MetasploitAdapterError("Target address must be a non-empty string.")

    if _FORBIDDEN_CHARS.search(address):
        raise MetasploitAdapterError("Target address contains illegal characters.")

    try:
        parsed_ip = ipaddress.ip_address(address.strip())
        if str(parsed_ip) != address or "%" in address:
            raise ValueError()
    except ValueError as exc:
        raise MetasploitAdapterError("Target address must be a canonical literal IP.") from exc

    return address


def build_argv_catalog(executable: str) -> list[str]:
    """Construct command line for querying framework version without target interaction."""
    if not executable or not isinstance(executable, str):
        raise MetasploitAdapterError("A valid executable path is required.")
    return [executable, "-q", "-v"]


def build_argv_auxiliary(
    executable: str,
    module: str,
    address: str,
    port: int,
    max_seconds: int = 30,
    approved_module_refs: frozenset[str] | set[str] | Sequence[str] | None = None,
) -> list[str]:
    """Construct a single-shot, non-interactive execution command for an approved auxiliary module.

    All interpolated values are strictly typed and regex-validated before insertion into the console script.
    """
    if not executable or not isinstance(executable, str):
        raise MetasploitAdapterError("A valid executable path is required.")

    valid_module = validate_module_name(module, approved_module_refs=approved_module_refs)
    valid_address = validate_target_address(address)

    if type(port) is not int or not 1 <= port <= 65535:
        raise MetasploitAdapterError("Target port must be an integer between 1 and 65535.")

    if type(max_seconds) is not int or not 5 <= max_seconds <= 120:
        raise MetasploitAdapterError("Execution timeout must be an integer between 5 and 120 seconds.")

    # Strict script string avoiding any shell interpolation
    # -n disables database; THREADS 1 bounds concurrency; exit -y guarantees exit
    commands = (
        f"use {valid_module}; "
        f"set RHOSTS {valid_address}; "
        f"set RPORT {port}; "
        f"set THREADS 1; "
        f"run; "
        f"exit -y"
    )

    return [
        executable,
        "-q",
        "-n",
        "-x",
        commands,
    ]


def parse_version(stdout: str) -> str | None:
    """Extract clean framework version from msfconsole -v output."""
    match = _VERSION_RE.search(stdout)
    if match:
        return match.group(1).strip()
    return None


def parse_auxiliary_output(
    stdout: str,
    address: str,
    port: int,
    module: str,
) -> list[dict[str, Any]]:
    """Parse output lines from an approved auxiliary scan and normalize into observations."""
    observations: list[dict[str, Any]] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Look for status indicators: [+] (success/finding), [*] (info), [-] (failure)
        if line.startswith("[+]"):
            detail = line[3:].strip()
            clean_detail = redact_tokens(_UNPRINTABLE.sub("", detail)[:300], "[REDACTED]")
            observations.append({
                "kind": "auxiliary_observation",
                "category": "service_verification",
                "address": address,
                "port": port,
                "module": module,
                "status": "positive",
                "detail": clean_detail,
                "tool": "metasploit",
            })
        elif line.startswith("[*]"):
            detail = line[3:].strip()
            # Only record informational lines that mention the target address
            if address in detail:
                clean_detail = redact_tokens(_UNPRINTABLE.sub("", detail)[:300], "[REDACTED]")
                observations.append({
                    "kind": "auxiliary_observation",
                    "category": "service_verification",
                    "address": address,
                    "port": port,
                    "module": module,
                    "status": "info",
                    "detail": clean_detail,
                    "tool": "metasploit",
                })

    return observations


def preflight(executable: str | None = None) -> dict[str, Any]:
    """Check availability of Metasploit executable on this system."""
    path = executable or shutil.which("msfconsole")
    return {
        "id": "metasploit",
        "name": "Metasploit Framework (Bounded Auxiliary)",
        "available": bool(path),
        "runnable": False,  # Live execution requires explicit operator authorization and container/VM backend
        "executable": path,
        "status": "implemented" if path else "missing",
    }


__all__ = [
    "DEFAULT_NON_INTRUSIVE_MODULES",
    "MetasploitAdapterError",
    "build_argv_auxiliary",
    "build_argv_catalog",
    "parse_auxiliary_output",
    "parse_version",
    "preflight",
    "validate_module_name",
    "validate_target_address",
]
