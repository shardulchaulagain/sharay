"""Nmap network inventory (L2): one fixed command line, strict XML parsing, observations only.

Status: not yet exercised with a real nmap binary. The parser's sample is hand-written
(header checked against nmap's xml.cc and the official book example), and the default
read path is a guess, so the shared contracts keep this adapter `planned`. nmap writes
control characters as numeric references that strict XML rejects; such output fails closed.
An open port is an observed fact, never a finding.
"""

import ipaddress
import re
import shutil
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from services.scanner_worker import run_isolated

MAX_PORTS = 100
MAX_XML_BYTES = 1048576
_DOCTYPE = b"<!DOCTYPE nmaprun>"
# Current nmap (xml.cc) writes the first form plus a bare DOCTYPE; the official book's
# older example has the second and no DOCTYPE. Both pin the bytes to an ASCII-compatible
# encoding, so a UTF-16 or exotic-codec document cannot hide markup from the checks below.
_DECLARATIONS = (b'<?xml version="1.0" encoding="UTF-8"?>', b'<?xml version="1.0"?>')
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def build_argv(
    executable: str, address: str, ports: Sequence[int], max_seconds: int, max_rate: float
) -> list[str]:
    """The only command line this adapter can produce: typed values, no free text, no scripts."""
    parsed = ipaddress.ip_address(address)  # rejects hostnames, ranges and option-like strings
    if str(parsed) != address or "%" in address:
        raise ValueError("The address must be one canonical literal IP address.")
    if (
        not 1 <= len(ports) <= MAX_PORTS
        or len(set(ports)) != len(ports)
        or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
    ):
        raise ValueError(f"Ports must be 1-{MAX_PORTS} unique integers from 1 to 65535.")
    # Both come from the approved scope: total seconds, and packets per second (may be below 1).
    if (
        type(max_seconds) is not int
        or type(max_rate) not in (int, float)
        or not (3 <= max_seconds <= 300 and 0 < max_rate <= 5)
    ):
        raise ValueError("Time and rate budgets are outside the supported bounds.")
    # -sT needs no raw sockets (non-root); -Pn and -n send no ping and no DNS query.
    # No -sV: version probes are extra traffic that needs its own reviewed profile.
    return [
        executable,
        "-sT",
        "-Pn",
        "-n",
        "--max-parallelism",
        "1",
        "--max-retries",
        "1",
        "--max-rate",
        f"{max_rate:g}",
        # nmap gives up two seconds early so it can finish its XML inside the approved total.
        "--host-timeout",
        f"{max_seconds - 2}s",
        "-p",
        ",".join(str(port) for port in ports),
        "-oX",
        "-",
        *(["-6"] if parsed.version == 6 else []),
        address,
    ]


def _text(value: str | None) -> str | None:
    # Tool output can carry target-influenced text: keep it short and printable.
    return _UNPRINTABLE.sub("", value)[:200] or None if value else None


def parse_xml(data: bytes, address: str, ports: Sequence[int]) -> tuple[str | None, list[dict]]:
    """Return (nmap version, observations); anything outside the request fails closed."""
    if len(data) > MAX_XML_BYTES:
        raise ValueError("nmap output exceeds the parsing budget.")
    if not data.startswith(_DECLARATIONS):
        raise ValueError("nmap output must begin with its UTF-8 XML declaration.")
    # At most one bare DOCTYPE line; an internal subset or entity never passes.
    rest = data.replace(_DOCTYPE, b"", 1)
    if b"<!DOCTYPE" in rest or b"<!ENTITY" in rest:
        raise ValueError("Document type or entity declarations are not accepted in tool output.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("nmap output is malformed or truncated.") from exc
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
        raise ValueError("nmap did not report a successful run.")
    start = root.get("start", "")
    try:
        captured_at = datetime.fromtimestamp(int(start), UTC).isoformat() if start.isdigit() else None
    except (OverflowError, OSError, ValueError):
        captured_at = None  # an absurd timestamp is dropped, not allowed to crash the parse
    version = _text(root.get("version"))
    observations = []
    seen: set[int] = set()
    for host in root.iter("host"):
        reported = {
            ipaddress.ip_address(item.get("addr", ""))
            for item in host.findall("address")
            if item.get("addrtype") in {"ipv4", "ipv6"}
        }
        if reported != {ipaddress.ip_address(address)}:
            raise ValueError("nmap reported a host other than the requested address.")
        for port in host.iterfind("ports/port"):
            number = int(port.get("portid", ""))
            state = port.find("state")
            if number not in ports or port.get("protocol") != "tcp" or state is None:
                raise ValueError("nmap reported a port outside the request.")
            if number in seen:
                # One observation per requested port: repeats cannot multiply the output.
                raise ValueError("nmap reported a port more than once.")
            seen.add(number)
            service = port.find("service")
            details: dict[str, Any] = {} if service is None else dict(service.attrib)
            confidence = details.get("conf", "")
            observations.append(
                {
                    "kind": "network_service",
                    "category": "network_inventory",
                    "address": address,
                    "port": number,
                    "protocol": "tcp",
                    "state": _text(state.get("state")),
                    "reason": _text(state.get("reason")),
                    # Product/version banners are deliberately not retained.
                    "service": _text(details.get("name")),
                    # "table" means nmap guessed the name from the port number alone.
                    "identification": _text(details.get("method")),
                    "identification_confidence": int(confidence) if confidence.isdigit() else None,
                    "captured_at": captured_at,
                    "tool": "nmap",
                    "tool_version": version,
                }
            )
    return version, observations


def inventory(
    address: str,
    ports: Sequence[int],
    cancelled: Callable[[], bool],
    emit: Callable[[dict], None],
    *,
    executable: str | None = None,
    exec_paths: Sequence[Path | str] = (),
    read_paths: Sequence[Path | str] = (),
    max_seconds: int,
    max_rate: float,
) -> dict:
    """Run the fixed inventory inside the isolated runner; same result shape as safe HTTP's scan().

    executable and paths are server configuration, never operator, target or model input.
    """
    started = time.monotonic()
    result: dict[str, Any] = {
        "adapter": "nmap",
        "version": None,
        "outcome": "failed",
        "observations": [],
        "findings": [],
        "checks": [],
    }

    def check(status: str, detail: str) -> None:
        entry = {"category": "network_inventory", "status": status, "detail": detail}
        result["checks"].append(entry)
        emit({"type": "check", **entry})

    try:
        executable = executable or shutil.which("nmap")
        if not executable:
            check("failed", "nmap is not installed; network inventory did not run.")
            return result
        run = run_isolated(
            build_argv(executable, address, ports, max_seconds, max_rate),
            exec_paths=exec_paths,
            # Data files (nmap-services) are readable, never executable; nmap does not fork.
            read_paths=read_paths or [Path(executable).resolve().parent.parent],
            egress=[(address, port) for port in ports],
            # The runner's deadline is the approved total; nothing runs past it.
            max_seconds=max_seconds,
            max_output_bytes=1048576,
            cancelled=cancelled,
        )
        if run.outcome == "cancelled":
            result["outcome"] = "cancelled"
            check("cancelled", "Operator cancellation requested; nmap and its children were stopped.")
        elif run.outcome == "timeout":
            check("failed", "nmap exceeded its time budget and was stopped.")
        elif not run.scratch_removed:
            check("failed", "The run's scratch directory could not be removed; its output was not used.")
        elif run.outcome != "completed" or run.output_truncated:
            # Tool stderr is target-influenced text and is deliberately not echoed here.
            check("failed", f"nmap exited with status {run.exit_code}; its output was not used.")
        else:
            result["version"], result["observations"] = parse_xml(run.stdout, address, ports)
            for observation in result["observations"]:
                emit({"type": "observation", "kind": observation["kind"], "port": observation["port"]})
            result["outcome"] = "completed"
            check("completed", f"{len(result['observations'])} requested port(s) reported by nmap.")
    except ValueError as exc:
        # Raised only by this adapter and the runner with fixed, target-free messages.
        check("failed", str(exc))
    except OSError:
        check("failed", "The isolated runner could not start nmap.")
    finally:
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


__all__ = ["build_argv", "inventory", "parse_xml"]
