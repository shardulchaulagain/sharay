"""Rootless-container isolation backend (L1): a Linux-container runner, deny-by-default.

This complements the macOS Seatbelt runner with a container boundary (full Linux namespaces,
resource limits, dropped capabilities, read-only root, no-new-privileges). It is the foundation
for enforced non-loopback egress: that allowlist layer is NOT built yet, so this backend FAILS
CLOSED — it runs a tool only with the network fully disabled, refuses any egress request, and
refuses to run at all when no container runtime is present. It never claims isolation it cannot
enforce. Pure request-building and the availability probe are testable without a runtime; actual
execution needs `podman`/`docker` plus a started machine.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path

from services.scanner_worker import IsolatedResult, IsolationError

# Rootful-bridge default subnet inside the podman machine; container egress traverses the VM's
# FORWARD chain, which is the enforcement point an allowlist must sit on (a rootless/pasta setup
# does userspace NAT the VM FORWARD/OUTPUT hooks never see, so it fails open — proven by test).
_VM_SUBNET = "10.88.0.0/16"

# Podman first: rootless by design and its network namespacing is what the future egress allowlist
# will build on. Docker is accepted as a fallback runtime.
_RUNTIMES = ("podman", "docker")
_SEARCH = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$")
MAX_OUTPUT_BYTES = 10 * 1024 * 1024


def container_runtime() -> str | None:
    """Absolute path to a rootless runtime, or None. None means: do not run (fail closed)."""
    for name in _RUNTIMES:
        found = shutil.which(name)
        if found:
            return found
        for directory in _SEARCH:
            candidate = Path(directory, name)
            if candidate.is_file():
                return str(candidate)
    return None


def build_run_argv(
    runtime: str,
    image: str,
    tool_argv: Sequence[str],
    *,
    input_dir: str | Path,
    max_seconds: float = 60,
    memory_mb: int = 512,
    pids_limit: int = 256,
    cpus: float = 1.0,
    destinations: Sequence[tuple[str, int]] = (),
) -> list[str]:
    """Build a locked-down `run` command for a no-network tool, or raise IsolationError.

    `destinations` is accepted for forward compatibility but any non-empty value is REFUSED:
    a per-destination egress allowlist is not enforceable yet, and this backend will not pretend
    to while silently granting full egress.
    """
    if destinations:
        raise IsolationError("Egress allowlist is not enforceable yet; this backend runs no-network only.")
    if not isinstance(runtime, str) or not runtime:
        raise IsolationError("A container runtime path is required.")
    if not isinstance(image, str) or not _IMAGE.match(image):
        raise IsolationError("The image reference is not a valid name or digest.")
    if (
        isinstance(tool_argv, str)
        or not tool_argv
        or not all(isinstance(a, str) and "\0" not in a for a in tool_argv)
    ):
        raise IsolationError("tool_argv must be a non-empty sequence of strings; shell strings are rejected.")
    if type(memory_mb) is not int or not 16 <= memory_mb <= 8192:
        raise IsolationError("memory_mb must be an integer from 16 to 8192.")
    if type(pids_limit) is not int or not 1 <= pids_limit <= 4096:
        raise IsolationError("pids_limit must be an integer from 1 to 4096.")
    if type(cpus) not in (int, float) or not 0 < cpus <= 8:
        raise IsolationError("cpus must be a number in (0, 8].")
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 300:
        raise IsolationError("max_seconds must be a number in (0, 300].")
    source = Path(input_dir).resolve()
    if not source.is_dir():
        raise IsolationError("input_dir must be an existing directory.")
    return [
        runtime,
        "run",
        "--rm",
        "--network=none",  # no egress at all; the enforcement is the runtime's, not the app's
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit",
        str(pids_limit),
        "--memory",
        f"{memory_mb}m",
        "--cpus",
        str(cpus),
        "--mount",
        f"type=bind,src={source},dst=/input,ro",
        "--workdir",
        "/input",
        "--env",
        "HOME=/tmp",
        image,
        *tool_argv,
    ]


def run_contained(
    image: str,
    tool_argv: Sequence[str],
    *,
    input_dir: str | Path,
    max_seconds: float = 60,
    memory_mb: int = 512,
    pids_limit: int = 256,
    cpus: float = 1.0,
    destinations: Sequence[tuple[str, int]] = (),
) -> IsolatedResult:
    """Run a no-network tool inside a rootless container. Raises IsolationError if no runtime is
    available or the request cannot be enforced (fail closed)."""
    runtime = container_runtime()
    if runtime is None:
        raise IsolationError("No container runtime is available; nothing was run.")
    argv = build_run_argv(
        runtime,
        image,
        tool_argv,
        input_dir=input_dir,
        max_seconds=max_seconds,
        memory_mb=memory_mb,
        pids_limit=pids_limit,
        cpus=cpus,
        destinations=destinations,
    )
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=max_seconds,
            check=False,
            env={"PATH": "/opt/homebrew/bin:/usr/bin:/bin", "HOME": str(Path.home())},
        )
    except subprocess.TimeoutExpired:
        return IsolatedResult(
            "timeout", -1, b"", b"", False, True, round((time.monotonic() - started) * 1000), ()
        )
    except OSError as exc:
        raise IsolationError("The container runtime could not be launched.") from exc
    stdout, stderr = proc.stdout[:MAX_OUTPUT_BYTES], proc.stderr[:MAX_OUTPUT_BYTES]
    truncated = len(proc.stdout) > MAX_OUTPUT_BYTES or len(proc.stderr) > MAX_OUTPUT_BYTES
    return IsolatedResult(
        outcome="completed" if proc.returncode == 0 else "failed",
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        output_truncated=truncated,
        scratch_removed=True,  # --rm removes the container filesystem
        duration_ms=round((time.monotonic() - started) * 1000),
        enforced=(
            "no_network",
            "read_only_rootfs",
            "all_capabilities_dropped",
            "no_new_privileges",
            "pid_limit",
            "memory_limit",
        ),
    )


def build_egress_ruleset(
    chain: str, subnet: str, allow_ip: str, allow_port: int
) -> dict[str, list[list[str]]]:
    """Return {'up': [...iptables argv...], 'down': [...]} for a default-drop egress allowlist that
    permits new connections from `subnet` only to `allow_ip`:`allow_port` (replies via conntrack).

    `allow_ip` must be a literal address (resolve the target first): the allowlist admits exactly
    one destination, so DNS and any other host are dropped. Pure; the caller runs these in the VM.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", chain):
        raise IsolationError("Egress chain name must be a short identifier.")
    try:
        ipaddress.ip_network(subnet, strict=False)
        ip = ipaddress.ip_address(allow_ip)  # literal only; a hostname is rejected here
    except ValueError as exc:
        raise IsolationError("Egress subnet and allow_ip must be literal addresses.") from exc
    if ip.version != 4:
        raise IsolationError(
            "The egress backend enforces IPv4 only; an IPv6 destination is not supported yet."
        )
    if type(allow_port) is not int or not 1 <= allow_port <= 65535:
        raise IsolationError("Egress allow_port must be an integer from 1 to 65535.")
    tgt, dport = str(ip), str(allow_port)
    return {
        "up": [
            ["iptables", "-N", chain],
            ["iptables", "-A", chain, "-d", tgt, "-p", "tcp", "--dport", dport, "-j", "ACCEPT"],
            ["iptables", "-A", chain, "-j", "DROP"],  # default-drop every other destination
            [
                "iptables",
                "-I",
                "FORWARD",
                "1",
                "-s",
                subnet,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            ["iptables", "-I", "FORWARD", "2", "-s", subnet, "-j", chain],
        ],
        "down": [
            ["iptables", "-D", "FORWARD", "-s", subnet, "-j", chain],
            [
                "iptables",
                "-D",
                "FORWARD",
                "-s",
                subnet,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            ["iptables", "-F", chain],
            ["iptables", "-X", chain],
        ],
    }


_PODMAN_MACHINE_NAME: str | None = None


def _get_podman_machine_name(runtime: str) -> str:
    global _PODMAN_MACHINE_NAME
    if _PODMAN_MACHINE_NAME is not None:
        return _PODMAN_MACHINE_NAME
    name = "podman-machine-default"
    try:
        proc = subprocess.run(
            [runtime, "machine", "list", "--format", "{{.Name}}\t{{.Running}}\t{{.Default}}"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        for line in proc.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[1].lower() in ("true", "currently running"):
                name = parts[0].rstrip("*")
                break
            if len(parts) >= 3 and parts[2].lower() == "true":
                name = parts[0].rstrip("*")
                break
    except Exception:
        pass
    _PODMAN_MACHINE_NAME = name
    return name


def _machine_ssh(script: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    runtime = container_runtime()
    if runtime is None or Path(runtime).name != "podman":
        raise IsolationError("Egress enforcement needs a running podman machine.")
    machine = _get_podman_machine_name(runtime)
    return subprocess.run(
        [runtime, "machine", "ssh", machine, script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_with_egress(
    image: str,
    tool_argv: Sequence[str],
    *,
    allow_ip: str,
    allow_port: int,
    max_seconds: float = 120,
    memory_mb: int = 512,
    add_host: str | Sequence[str] | None = None,
    mount_volume: str | Sequence[str] | None = None,
    entrypoint: str | None = None,
) -> IsolatedResult:
    """Run a tool rootful on the bridge with egress locked to exactly `allow_ip`:`allow_port`.

    `add_host` ("name:ip") pins a hostname in the container's /etc/hosts so a tool resolves it
    without DNS (the allowlist drops DNS); `mount_volume` ("name:/path:ro") mounts a pre-provisioned
    read-only volume such as a scanner's offline template set.

    FAIL CLOSED: the allowlist is applied before the run and always torn down after (even on
    error); if setup fails the tool never runs. `allow_ip` is a literal address the caller has
    already resolved and authorised through the scope policy. The VM FORWARD chain enforces it.
    """
    runtime = container_runtime()
    if runtime is None or Path(runtime).name != "podman":
        raise IsolationError("No podman machine runtime for enforced egress.")
    # Reuse build_run_argv's validation for image/argv/limits, then swap network=none for the bridge.
    # Validate image/argv/limits (raises on bad input); its output is NOT reused for flag-filtering,
    # because filtering the combined vector would strip a tool argument that happens to equal a setup
    # flag (e.g. '--workdir', '--network=none', 'type=bind...'). Build setup flags separately and
    # append image + tool_argv verbatim so the tool's arguments are preserved exactly.
    build_run_argv(
        runtime, image, tool_argv, input_dir=Path.cwd(), max_seconds=max_seconds, memory_mb=memory_mb
    )
    setup_flags = [
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        f"{memory_mb}m",
        "--cpus",
        "1.0",
        "--env",
        "HOME=/tmp",
        "--tmpfs",
        "/tmp:rw,exec,size=256m",
        "--tmpfs",
        "/zap/wrk:rw,exec,size=256m",
        "--tmpfs",
        "/home/zap:rw,exec,size=256m",
        "--tmpfs",
        "/home/msf:rw,exec,size=256m",
        "--tmpfs",
        "/root/.msf4:rw,exec,size=256m",
        "--tmpfs",
        "/root:rw,exec,size=256m",
    ]
    if entrypoint is not None:
        setup_flags += ["--entrypoint", entrypoint]
    if add_host is not None:
        if isinstance(add_host, str):
            setup_flags += ["--add-host", add_host]
        else:
            for h in add_host:
                setup_flags += ["--add-host", h]
    if mount_volume is not None:
        if isinstance(mount_volume, str):
            setup_flags += ["-v", mount_volume]
        else:
            for v in mount_volume:
                setup_flags += ["-v", v]
    run_flags = [*setup_flags, image, *tool_argv]
    rules = build_egress_ruleset("SHARAY_EGRESS", _VM_SUBNET, allow_ip, allow_port)
    # shlex.quote every token: these strings run in a VM shell via `podman machine ssh`, so a tool
    # argv element like 'x; rm -rf /' must stay one argument to podman, never a second command.
    cleanup = "sudo iptables -F SHARAY_EGRESS 2>/dev/null; sudo iptables -X SHARAY_EGRESS 2>/dev/null; "
    up = cleanup + " && ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in rules["up"])
    down = "; ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in rules["down"])
    # Runs inside the podman machine, so use the VM's podman on PATH, not this host's runtime path.
    inner = "sudo podman run " + " ".join(shlex.quote(a) for a in run_flags)
    started = time.monotonic()
    result = None
    teardown_ok = False
    try:
        # Setup is inside the try so a TimeoutExpired or non-zero result still reaches teardown.
        applied = _machine_ssh(up, timeout=min(15.0, max_seconds))
        if applied.returncode != 0:
            raise IsolationError("Could not apply the egress allowlist; nothing was run.")
        remaining = max_seconds - (time.monotonic() - started)
        # Setup that exhausts the budget runs no tool on a spent clock (result stays None -> timeout).
        if remaining > 0:
            # head -c bounds the bytes buffered across SSH into host RAM; `exit ${PIPESTATUS[0]}` keeps
            # podman's real exit code (a bare pipe reports head's 0 and would mask a failed scan).
            try:
                result = _machine_ssh(
                    f"{inner} 2>&1 | head -c {MAX_OUTPUT_BYTES + 1}; exit ${{PIPESTATUS[0]}}",
                    timeout=remaining,
                )
            except subprocess.TimeoutExpired:
                result = None
    finally:
        # Always remove the allowlist; a failed teardown leaves the sandbox's network state dirty,
        # so it is surfaced rather than swallowed (see scratch_removed below).
        try:
            teardown_ok = _machine_ssh(down, timeout=10.0).returncode == 0
        except Exception:
            teardown_ok = False

    enforced = (
        "egress_allowlist_single_destination",
        "read_only_rootfs",
        "cap_drop_all",
        "no_new_privileges",
    )
    if result is None:
        return IsolatedResult(
            outcome="failed",
            exit_code=124,
            stdout=b"",
            stderr=b"Command timed out before completion",
            output_truncated=False,
            scratch_removed=teardown_ok,
            duration_ms=round((time.monotonic() - started) * 1000),
            enforced=enforced,
        )
    out = result.stdout.encode("utf-8", "replace")[:MAX_OUTPUT_BYTES]
    # scratch_removed=False must never be reported completed (IsolatedResult contract), so a cleanup
    # failure demotes an otherwise-successful run to failed with an explicit reason.
    clean = result.returncode == 0 and teardown_ok
    return IsolatedResult(
        outcome="completed" if clean else "failed",
        exit_code=result.returncode,
        stdout=out,
        stderr=b"" if teardown_ok else b"egress allowlist teardown failed; sandbox network state left dirty",
        output_truncated=len(result.stdout.encode()) > MAX_OUTPUT_BYTES,
        scratch_removed=teardown_ok,
        duration_ms=round((time.monotonic() - started) * 1000),
        enforced=enforced,
    )


def attest() -> dict:
    """Report what this backend can enforce here. Single-destination egress is available only on a
    podman machine (the tested rootful-bridge FORWARD path); any other runtime is no-network only."""
    runtime = container_runtime()
    name = Path(runtime).name if runtime else None
    enforced = ["no_network", "read_only_rootfs", "all_capabilities_dropped", "no_new_privileges"]
    if name == "podman":
        enforced.append("egress_allowlist_single_destination")
    return {
        "backend": "rootless-container",
        "runtime": name,
        "available": runtime is not None,
        "enforced": enforced,
        # A broader CIDR/multi-host allowlist is not built; callers get single-destination only.
        "not_enforced": [] if name == "podman" else ["destination_egress_allowlist"],
    }


__all__ = [
    "attest",
    "build_egress_ruleset",
    "build_run_argv",
    "container_runtime",
    "run_contained",
    "run_with_egress",
    "MAX_OUTPUT_BYTES",
]
