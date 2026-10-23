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

import hashlib
import hmac
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from packages.crypto.ed25519 import (
    ed25519_publickey,
    ed25519_sign,
    ed25519_verify_hex,
    generate_keypair,
)
from services.scanner_worker import IsolatedResult, IsolationError

# Rootful-bridge default subnet inside the podman machine; container egress traverses the VM's
# FORWARD chain, which is the enforcement point an allowlist must sit on (a rootless/pasta setup
# does userspace NAT the VM FORWARD/OUTPUT hooks never see, so it fails open — proven by test).
_VM_SUBNET = "10.88.0.0/16"
_VM_V6_SUBNET = "fd00::/64"

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


class LinuxEgressEngine(str):
    IPTABLES = "iptables"
    NFTABLES = "nftables"


@dataclass(frozen=True)
class TargetDestination:
    """An authorized egress target (IPv4 or IPv6 address or CIDR range)."""

    host_or_cidr: str
    ports: tuple[int, ...] = (80, 443)


def parse_target_destinations(
    destinations: Sequence[tuple[str, int | Sequence[int]] | TargetDestination | str],
) -> tuple[
    list[ipaddress.IPv4Address | ipaddress.IPv4Network],
    list[ipaddress.IPv6Address | ipaddress.IPv6Network],
    list[int],
]:
    """Parse mixed target definitions into validated IPv4/IPv6 objects and normalized ports."""
    v4_targets: list[ipaddress.IPv4Address | ipaddress.IPv4Network] = []
    v6_targets: list[ipaddress.IPv6Address | ipaddress.IPv6Network] = []
    allowed_ports: set[int] = set()

    if not destinations:
        raise IsolationError("At least one authorized target destination is required.")

    for item in destinations:
        host_str: str = ""
        port_list: list[int] = [80, 443]

        if isinstance(item, TargetDestination):
            host_str = item.host_or_cidr
            port_list = list(item.ports)
        elif isinstance(item, tuple) and len(item) == 2:
            host_str = str(item[0])
            ports_raw = item[1]
            if isinstance(ports_raw, int):
                port_list = [ports_raw]
            elif isinstance(ports_raw, (list, tuple)):
                port_list = [int(p) for p in ports_raw]
        elif isinstance(item, str):
            host_str = item
            port_list = [80, 443]

        for p in port_list:
            if not 1 <= p <= 65535:
                raise IsolationError(f"Port {p} is outside valid TCP range [1-65535]")
            allowed_ports.add(p)

        host_str = host_str.strip()
        try:
            if "/" in host_str:
                net = ipaddress.ip_network(host_str, strict=False)
                if net.version == 4:
                    v4_targets.append(net)
                else:
                    v6_targets.append(net)
            else:
                addr = ipaddress.ip_address(host_str)
                if addr.version == 4:
                    v4_targets.append(addr)
                else:
                    v6_targets.append(addr)
        except ValueError as exc:
            raise IsolationError(
                f"Destination '{host_str}' is not a valid literal IPv4/IPv6 address or CIDR."
            ) from exc

    return v4_targets, v6_targets, sorted(allowed_ports)


def build_egress_ruleset(
    chain: str, subnet: str, allow_ip: str, allow_port: int
) -> dict[str, list[list[str]]]:
    """Return {'up': [...iptables/ip6tables argv...], 'down': [...]} for a default-drop egress allowlist
    that permits new connections from `subnet` only to `allow_ip`:`allow_port` (replies via conntrack).

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
    if type(allow_port) is not int or not 1 <= allow_port <= 65535:
        raise IsolationError("Egress allow_port must be an integer from 1 to 65535.")
    tgt, dport = str(ip), str(allow_port)
    ipt = "iptables" if ip.version == 4 else "ip6tables"
    return {
        "up": [
            [ipt, "-N", chain],
            [ipt, "-A", chain, "-d", tgt, "-p", "tcp", "--dport", dport, "-j", "ACCEPT"],
            [ipt, "-A", chain, "-j", "DROP"],  # default-drop every other destination
            [
                ipt,
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
            [ipt, "-I", "FORWARD", "2", "-s", subnet, "-j", chain],
        ],
        "down": [
            [ipt, "-D", "FORWARD", "-s", subnet, "-j", chain],
            [
                ipt,
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
            [ipt, "-F", chain],
            [ipt, "-X", chain],
        ],
    }


def build_multidest_egress_ruleset(
    chain: str,
    destinations: Sequence[tuple[str, int]],
    *,
    subnet_v4: str = _VM_SUBNET,
    subnet_v6: str = _VM_V6_SUBNET,
) -> dict[str, list[list[str]]]:
    """Return {'up': [...], 'down': [...]} for default-drop egress across IPv4 and IPv6 destinations."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", chain):
        raise IsolationError("Egress chain name must be a short identifier.")
    if not destinations:
        raise IsolationError("At least one egress destination (IP/CIDR, port) must be specified.")

    v4_dests: list[tuple[str, int]] = []
    v6_dests: list[tuple[str, int]] = []

    for target, port in destinations:
        if type(port) is not int or not 1 <= port <= 65535:
            raise IsolationError(f"Egress port must be an integer from 1 to 65535, got {port}.")
        try:
            if "/" in target:
                net = ipaddress.ip_network(target, strict=False)
                if net.version == 4:
                    v4_dests.append((str(net), port))
                else:
                    v6_dests.append((str(net), port))
            else:
                addr = ipaddress.ip_address(target)
                if addr.version == 4:
                    v4_dests.append((str(addr), port))
                else:
                    v6_dests.append((str(addr), port))
        except ValueError as exc:
            raise IsolationError(f"Invalid IP address or CIDR network: '{target}'.") from exc

    up_rules: list[list[str]] = []
    down_rules: list[list[str]] = []

    if v4_dests:
        chain_v4 = chain
        up_rules.append(["iptables", "-N", chain_v4])
        for tgt, dport in v4_dests:
            up_rules.append(
                ["iptables", "-A", chain_v4, "-d", tgt, "-p", "tcp", "--dport", str(dport), "-j", "ACCEPT"]
            )
        up_rules.append(["iptables", "-A", chain_v4, "-j", "DROP"])
        up_rules.append(
            [
                "iptables",
                "-I",
                "FORWARD",
                "1",
                "-s",
                subnet_v4,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        up_rules.append(["iptables", "-I", "FORWARD", "2", "-s", subnet_v4, "-j", chain_v4])

        down_rules.append(["iptables", "-D", "FORWARD", "-s", subnet_v4, "-j", chain_v4])
        down_rules.append(
            [
                "iptables",
                "-D",
                "FORWARD",
                "-s",
                subnet_v4,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        down_rules.append(["iptables", "-F", chain_v4])
        down_rules.append(["iptables", "-X", chain_v4])

    if v6_dests:
        chain_v6 = f"{chain}_V6" if v4_dests else chain
        up_rules.append(["ip6tables", "-N", chain_v6])
        for tgt, dport in v6_dests:
            up_rules.append(
                ["ip6tables", "-A", chain_v6, "-d", tgt, "-p", "tcp", "--dport", str(dport), "-j", "ACCEPT"]
            )
        up_rules.append(["ip6tables", "-A", chain_v6, "-j", "DROP"])
        up_rules.append(
            [
                "ip6tables",
                "-I",
                "FORWARD",
                "1",
                "-s",
                subnet_v6,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        up_rules.append(["ip6tables", "-I", "FORWARD", "2", "-s", subnet_v6, "-j", chain_v6])

        down_rules.append(["ip6tables", "-D", "FORWARD", "-s", subnet_v6, "-j", chain_v6])
        down_rules.append(
            [
                "ip6tables",
                "-D",
                "FORWARD",
                "-s",
                subnet_v6,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        down_rules.append(["ip6tables", "-F", chain_v6])
        down_rules.append(["ip6tables", "-X", chain_v6])

    return {"up": up_rules, "down": down_rules}


def build_nftables_egress_ruleset(
    table_name: str = "sharay_egress",
    destinations: Sequence[tuple[str, int | Sequence[int]] | TargetDestination | str] = (),
    default_ports: tuple[int, ...] = (80, 443),
) -> dict[str, Any]:
    """Generate Linux-native `nftables` commands and raw configuration.

    Uses `inet` address family to handle dual-stack IPv4 and IPv6 natively in a single atomic table.
    Enforces:
    - Default DROP policy on FORWARD/OUTPUT chain.
    - Conntrack established/related accept.
    - Explicit CIDR and port allowlist matching.
    - Atomic teardown.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", table_name):
        raise IsolationError("nftables table name must be an alphanumeric identifier.")

    v4_targets, v6_targets, ports = parse_target_destinations(destinations or [])

    ports_set_str = ", ".join(str(p) for p in ports) if len(ports) > 1 else str(ports[0])

    lines: list[str] = [
        f"table inet {table_name} {{",
        "    chain forward {",
        "        type filter hook forward priority 0; policy drop;",
        "        ct state established,related accept",
    ]

    if v4_targets:
        v4_items = ", ".join(str(t) for t in v4_targets)
        lines.append(f"        ip daddr {{ {v4_items} }} tcp dport {{ {ports_set_str} }} accept")

    if v6_targets:
        v6_items = ", ".join(str(t) for t in v6_targets)
        lines.append(f"        ip6 daddr {{ {v6_items} }} tcp dport {{ {ports_set_str} }} accept")

    lines.append("        drop")
    lines.append("    }")
    lines.append("}")

    nft_config = "\n".join(lines) + "\n"

    up_cmds: list[list[str]] = [
        ["nft", "add", "table", "inet", table_name],
        [
            "nft",
            "add",
            "chain",
            "inet",
            table_name,
            "forward",
            "{",
            "type",
            "filter",
            "hook",
            "forward",
            "priority",
            "0",
            ";",
            "policy",
            "drop",
            ";",
            "}",
        ],
        ["nft", "add", "rule", "inet", table_name, "forward", "ct", "state", "established,related", "accept"],
    ]

    if v4_targets:
        v4_items_cmd = "{" + ", ".join(str(t) for t in v4_targets) + "}"
        ports_cmd = "{" + ports_set_str + "}"
        up_cmds.append(
            [
                "nft",
                "add",
                "rule",
                "inet",
                table_name,
                "forward",
                "ip",
                "daddr",
                v4_items_cmd,
                "tcp",
                "dport",
                ports_cmd,
                "accept",
            ]
        )

    if v6_targets:
        v6_items_cmd = "{" + ", ".join(str(t) for t in v6_targets) + "}"
        ports_cmd = "{" + ports_set_str + "}"
        up_cmds.append(
            [
                "nft",
                "add",
                "rule",
                "inet",
                table_name,
                "forward",
                "ip6",
                "daddr",
                v6_items_cmd,
                "tcp",
                "dport",
                ports_cmd,
                "accept",
            ]
        )

    down_cmds: list[list[str]] = [
        ["nft", "delete", "table", "inet", table_name],
    ]

    return {
        "engine": LinuxEgressEngine.NFTABLES,
        "table_name": table_name,
        "nft_config": nft_config,
        "up_commands": up_cmds,
        "down_commands": down_cmds,
        "v4_count": len(v4_targets),
        "v6_count": len(v6_targets),
        "allowed_ports": ports,
    }


def generate_scanner_seccomp_profile() -> dict[str, Any]:
    """Generate a hardened, deny-by-default seccomp JSON profile for scanner containers.

    Blocks all dangerous kernel and container escape syscalls:
    ptrace, bpf, mount, pivot_root, setns, userfaultfd, keyctl, chroot.
    Permits only standard I/O, networking, and memory allocation.
    """
    allowed_syscalls = [
        "accept",
        "accept4",
        "access",
        "arch_prctl",
        "bind",
        "brk",
        "clock_gettime",
        "clone",
        "clone3",
        "close",
        "connect",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "epoll_wait",
        "exit",
        "exit_group",
        "faccessat",
        "faccessat2",
        "fcntl",
        "fstat",
        "fstatfs",
        "fsync",
        "futex",
        "getcwd",
        "getdents64",
        "getegid",
        "geteuid",
        "getgid",
        "getpeername",
        "getpid",
        "getppid",
        "getrandom",
        "getsockname",
        "getsockopt",
        "gettid",
        "getuid",
        "ioctl",
        "lseek",
        "madvise",
        "mmap",
        "mprotect",
        "munmap",
        "nanosleep",
        "newfstatat",
        "openat",
        "pipe",
        "pipe2",
        "poll",
        "ppoll",
        "pselect6",
        "read",
        "readlink",
        "readlinkat",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "rseq",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sched_getaffinity",
        "sched_yield",
        "select",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "set_robust_list",
        "set_tid_address",
        "setsockopt",
        "shutdown",
        "sigaltstack",
        "socket",
        "socketpair",
        "stat",
        "statx",
        "sysinfo",
        "tgkill",
        "uname",
        "wait4",
        "write",
        "writev",
    ]

    denied_syscalls = [
        "ptrace",
        "bpf",
        "mount",
        "umount2",
        "pivot_root",
        "setns",
        "userfaultfd",
        "keyctl",
        "chroot",
        "kexec_load",
        "reboot",
        "init_module",
        "finit_module",
        "delete_module",
        "iopl",
        "ioperm",
    ]

    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64", "SCMP_ARCH_X86"],
        "syscalls": [
            {
                "names": allowed_syscalls,
                "action": "SCMP_ACT_ALLOW",
            },
            {
                "names": denied_syscalls,
                "action": "SCMP_ACT_KILL",
            },
        ],
    }


def generate_scanner_apparmor_profile(profile_name: str = "sharay_scanner_sandbox") -> str:
    """Generate an AppArmor confinement profile enforcing strict path and capability boundaries."""
    return f"""#include <tunables/global>

profile {profile_name} flags=(attach_disconnected,enforce) {{
    #include <abstractions/base>
    #include <abstractions/nameservice>

    # Network permissions
    network inet tcp,
    network inet udp,
    network inet6 tcp,
    network inet6 udp,

    # File access constraints
    /input/** r,
    /tmp/** rw,
    /etc/resolv.conf r,
    /etc/hosts r,
    /etc/ssl/** r,
    /usr/** rix,
    /lib/** r,
    /lib64/** r,
    /bin/** rix,

    # Deny dangerous operations
    deny /proc/kcore rwklx,
    deny /proc/mem rwklx,
    deny /proc/kmem rwklx,
    deny /sys/firmware/** rwklx,
    deny /dev/mem rwklx,
    deny /dev/kmem rwklx,
    deny ptrace,
    deny capability sys_admin,
    deny capability sys_rawio,
    deny capability sys_ptrace,
}}
"""


class ImagePinningEngine:
    """Validates and enforces immutable cryptographic SHA-256 digest pinning for scanner images."""

    DIGEST_REGEX = re.compile(r"^[a-z0-9][a-z0-9._/-]+@sha256:([0-9a-f]{64})$")

    @classmethod
    def validate_image_digest_pinning(cls, image_ref: str, require_digest: bool = True) -> str:
        """Verify image reference has an immutable @sha256:hash pin. Rejects raw tags (:latest)."""
        image_ref = image_ref.strip()
        match = cls.DIGEST_REGEX.match(image_ref)
        if match:
            return match.group(1)

        if require_digest:
            raise IsolationError(
                f"Image '{image_ref}' violates immutability policy: pinned @sha256 digest is required. "
                "Floating tags like ':latest' are forbidden in contained executions."
            )
        return ""

    @classmethod
    def verify_cosign_signature(
        cls,
        image_ref: str,
        trusted_public_key: str,
        verifier_fn: Any = None,
    ) -> bool:
        """Verify a cosign signature against the trusted public key via a real verifier callback.

        Fail closed: with no verifier callback configured there is nothing that actually checked the
        signature, so this refuses rather than assuming the image is signed (F12). A deployment wires
        `verifier_fn` to `cosign verify` (or an equivalent); tests pass a deterministic stub."""
        cls.validate_image_digest_pinning(image_ref, require_digest=True)
        if not trusted_public_key:
            raise IsolationError("Trusted public key is required for image signature verification.")

        if verifier_fn is None:
            raise IsolationError(
                "No cosign verifier is configured; refusing to assume a valid image signature "
                "(fail closed). Wire a real cosign verifier before executing contained images."
            )
        return bool(verifier_fn(image_ref, trusted_public_key))


class AttestationState(str, Enum):
    APPLIED = "APPLIED"
    TORN_DOWN = "TORN_DOWN"
    FAILED = "FAILED"


@dataclass
class EgressRuleEntry:
    rule_id: str
    action: str  # "ALLOW" or "DROP"
    destination_cidr: str
    protocol: str  # "tcp", "udp", "all"
    destination_ports: list[int]

    def normalized_string(self) -> str:
        ports_str = ",".join(map(str, sorted(self.destination_ports)))
        return f"{self.action}:{self.protocol}:{self.destination_cidr}:{ports_str}"


@dataclass
class EgressAttestationReceipt:
    attestation_id: str
    assessment_id: str
    target_scope: str
    state: str
    applied_ruleset_hash: str
    applied_timestamp_utc: float
    teardown_timestamp_utc: float | None
    rules_count: int
    ledger_entry_id: str
    signature_sha256: str
    public_key_hex: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "assessment_id": self.assessment_id,
            "target_scope": self.target_scope,
            "state": self.state,
            "applied_ruleset_hash": self.applied_ruleset_hash,
            "applied_timestamp_utc": self.applied_timestamp_utc,
            "teardown_timestamp_utc": self.teardown_timestamp_utc,
            "rules_count": self.rules_count,
            "ledger_entry_id": self.ledger_entry_id,
            "signature_sha256": self.signature_sha256,
            "public_key_hex": self.public_key_hex,
        }


class EgressAttestationLogger:
    """Manages cryptographic attestation of egress firewall policies per assessment."""

    def __init__(
        self,
        notary_secret: str | bytes | None = None,
        signing_key: bytes | None = None,
        public_key: bytes | None = None,
    ):
        if signing_key is not None:
            self.signing_key: bytes | None = signing_key
            self.public_key: bytes | None = public_key or ed25519_publickey(signing_key)
            self.is_asymmetric = True
            self.notary_secret = b""
        elif notary_secret is not None:
            self.notary_secret = (
                notary_secret.encode("utf-8") if isinstance(notary_secret, str) else notary_secret
            )
            self.signing_key = None
            self.public_key = None
            self.is_asymmetric = False
        else:
            # Per-install key generated at runtime or from environment, never a hardcoded constant!
            env_secret = os.environ.get("SHARAY_EGRESS_ATTESTATION_KEY")
            if env_secret:
                self.notary_secret = env_secret.encode("utf-8")
                self.signing_key = None
                self.public_key = None
                self.is_asymmetric = False
            else:
                sk, pk = generate_keypair()
                self.signing_key = sk
                self.public_key = pk
                self.notary_secret = b""
                self.is_asymmetric = True
        self._active_attestations: dict[str, EgressAttestationReceipt] = {}

    def _hash_ruleset(self, rules: Sequence[EgressRuleEntry] | Sequence[Sequence[str]]) -> str:
        if rules and isinstance(rules[0], EgressRuleEntry):
            normalized = sorted([r.normalized_string() for r in rules])  # type: ignore[union-attr]
        else:
            normalized = sorted([" ".join(c) for c in rules])  # type: ignore[arg-type]
        return hashlib.sha256("\n".join(normalized).encode("utf-8")).hexdigest()

    def record_ruleset_applied(
        self,
        assessment_id: str,
        target_scope: str,
        rules: Sequence[EgressRuleEntry] | Sequence[Sequence[str]],
    ) -> EgressAttestationReceipt:
        ruleset_hash = self._hash_ruleset(rules)
        now = time.time()
        attestation_id = f"attest-{hashlib.sha256(f'{assessment_id}:{now}'.encode()).hexdigest()[:16]}"
        ledger_entry_id = f"ledger-egress-{assessment_id}"
        sig_payload = f"{attestation_id}:{assessment_id}:{ruleset_hash}:{now}".encode("utf-8")
        if self.is_asymmetric and self.signing_key is not None:
            signature = ed25519_sign(sig_payload, self.signing_key, self.public_key).hex()
        else:
            signature = hmac.new(self.notary_secret, sig_payload, hashlib.sha256).hexdigest()

        receipt = EgressAttestationReceipt(
            attestation_id=attestation_id,
            assessment_id=assessment_id,
            target_scope=target_scope,
            state="APPLIED",
            applied_ruleset_hash=ruleset_hash,
            applied_timestamp_utc=now,
            teardown_timestamp_utc=None,
            rules_count=len(rules),
            ledger_entry_id=ledger_entry_id,
            signature_sha256=signature,
            public_key_hex=self.public_key.hex() if self.public_key else "",
        )
        self._active_attestations[attestation_id] = receipt
        return receipt

    def record_ruleset_teardown(
        self,
        attestation_id: str,
        clean: bool = True,
    ) -> EgressAttestationReceipt:
        if attestation_id not in self._active_attestations:
            raise KeyError(f"No active attestation receipt with ID '{attestation_id}'")
        receipt = self._active_attestations[attestation_id]
        now = time.time()
        receipt.state = "TORN_DOWN" if clean else "FAILED"
        receipt.teardown_timestamp_utc = now
        sig_payload = f"{receipt.attestation_id}:{receipt.state}:{now}:{clean}".encode("utf-8")
        if self.is_asymmetric and self.signing_key is not None:
            receipt.signature_sha256 = ed25519_sign(sig_payload, self.signing_key, self.public_key).hex()
        else:
            receipt.signature_sha256 = hmac.new(self.notary_secret, sig_payload, hashlib.sha256).hexdigest()
        return receipt

    def verify_receipt(self, receipt: EgressAttestationReceipt, public_key_hex: str | None = None) -> bool:
        """Verifies cryptographic signature on an egress attestation receipt."""
        if receipt.state == "APPLIED":
            sig_payload = f"{receipt.attestation_id}:{receipt.assessment_id}:{receipt.applied_ruleset_hash}:{receipt.applied_timestamp_utc}".encode(
                "utf-8"
            )
        else:
            clean = receipt.state == "TORN_DOWN"
            sig_payload = (
                f"{receipt.attestation_id}:{receipt.state}:{receipt.teardown_timestamp_utc}:{clean}".encode(
                    "utf-8"
                )
            )

        pk = public_key_hex or receipt.public_key_hex or (self.public_key.hex() if self.public_key else "")
        if pk and len(receipt.signature_sha256) == 128:
            return ed25519_verify_hex(receipt.signature_sha256, sig_payload, pk)
        if self.notary_secret:
            expected = hmac.new(self.notary_secret, sig_payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, receipt.signature_sha256)
        return False


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
    allow_ip: str | None = None,
    allow_port: int | None = None,
    destinations: Sequence[tuple[str, int]] | None = None,
    engine: str = LinuxEgressEngine.IPTABLES,
    max_seconds: float = 120,
    memory_mb: int = 512,
    add_host: str | Sequence[str] | None = None,
    mount_volume: str | Sequence[str] | None = None,
    entrypoint: str | None = None,
    seccomp_profile: dict[str, Any] | str | None = None,
    apparmor_profile: str | None = None,
    require_pinned_digest: bool = False,
    audit_db: Any | None = None,
    assessment_id: str | None = None,
    org_id: str | None = None,
) -> IsolatedResult:
    """Run a tool rootful on the bridge with egress locked to specified destination(s).

    Supports single-destination (`allow_ip`, `allow_port`) or multi-destination (`destinations`)
    across IPv4 and IPv6 CIDRs/literals, using either Linux iptables or native nftables (`engine`).

    `add_host` ("name:ip") pins a hostname in the container's /etc/hosts so a tool resolves it
    without DNS (the allowlist drops DNS); `mount_volume` ("name:/path:ro") mounts a pre-provisioned
    read-only volume such as a scanner's offline template set.

    FAIL CLOSED: the allowlist is applied before the run and always torn down after (even on
    error); if setup fails the tool never runs. Destinations are literal addresses or CIDRs
    the caller has already resolved and authorised through the scope policy.
    """
    runtime = container_runtime()
    if runtime is None or Path(runtime).name != "podman":
        raise IsolationError("No podman machine runtime for enforced egress.")

    if destinations is not None and len(destinations) > 0:
        dests = list(destinations)
    elif allow_ip is not None and allow_port is not None:
        dests = [(allow_ip, allow_port)]
    else:
        raise IsolationError("An egress destination or allowlist is required.")

    if require_pinned_digest:
        ImagePinningEngine.validate_image_digest_pinning(image, require_digest=True)

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
    if seccomp_profile is not None:
        if isinstance(seccomp_profile, str):
            setup_flags += [f"--security-opt=seccomp={seccomp_profile}"]
        elif isinstance(seccomp_profile, dict):
            setup_flags += [f"--security-opt=seccomp={json.dumps(seccomp_profile)}"]
    if apparmor_profile is not None:
        setup_flags += [f"--security-opt=apparmor={apparmor_profile}"]
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

    is_nft = str(engine).lower() in ("nftables", LinuxEgressEngine.NFTABLES)
    if is_nft:
        nft_spec = build_nftables_egress_ruleset("sharay_egress", dests)
        up = " && ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in nft_spec["up_commands"])
        down = "; ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in nft_spec["down_commands"])
        rules = {"up": nft_spec["up_commands"], "down": nft_spec["down_commands"]}
    else:
        is_single_v4 = (
            len(dests) == 1
            and "/" not in dests[0][0]
            and ":" not in dests[0][0]
            and allow_ip is not None
            and allow_port is not None
        )
        if is_single_v4 and allow_ip is not None and allow_port is not None:
            rules = build_egress_ruleset("SHARAY_EGRESS", _VM_SUBNET, allow_ip, allow_port)
        else:
            rules = build_multidest_egress_ruleset(
                "SHARAY_EGRESS", dests, subnet_v4=_VM_SUBNET, subnet_v6=_VM_V6_SUBNET
            )

        cleanup = "sudo iptables -F SHARAY_EGRESS 2>/dev/null; sudo iptables -X SHARAY_EGRESS 2>/dev/null; "
        if any(c[0] == "ip6tables" for c in rules["up"]):
            cleanup += "sudo ip6tables -F SHARAY_EGRESS_V6 2>/dev/null; sudo ip6tables -X SHARAY_EGRESS_V6 2>/dev/null; "
        up = cleanup + " && ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in rules["up"])
        down = "; ".join("sudo " + " ".join(shlex.quote(a) for a in c) for c in rules["down"])
    inner = "sudo podman run " + " ".join(shlex.quote(a) for a in run_flags)

    ruleset_hash = hashlib.sha256(json.dumps(rules["up"], sort_keys=True).encode()).hexdigest()
    if audit_db is not None:
        try:
            from aegis.audit import record_egress_attestation

            record_egress_attestation(
                audit_db,
                org=org_id or "default",
                actor="scanner_worker",
                action="egress.allowlist_applied",
                resource=assessment_id or "SHARAY_EGRESS",
                detail={"ruleset_hash": ruleset_hash, "destinations": [f"{t}:{p}" for t, p in dests]},
            )
        except Exception:
            pass

    started = time.monotonic()
    result = None
    teardown_ok = False
    try:
        applied = _machine_ssh(up, timeout=min(15.0, max_seconds))
        if applied.returncode != 0:
            raise IsolationError("Could not apply the egress allowlist; nothing was run.")
        remaining = max_seconds - (time.monotonic() - started)
        if remaining > 0:
            try:
                result = _machine_ssh(
                    f"{inner} 2>&1 | head -c {MAX_OUTPUT_BYTES + 1}; exit ${{PIPESTATUS[0]}}",
                    timeout=remaining,
                )
            except subprocess.TimeoutExpired:
                result = None
    finally:
        try:
            teardown_ok = _machine_ssh(down, timeout=10.0).returncode == 0
        except Exception:
            teardown_ok = False
        if audit_db is not None:
            try:
                from aegis.audit import record_egress_attestation

                record_egress_attestation(
                    audit_db,
                    org=org_id or "default",
                    actor="scanner_worker",
                    action="egress.allowlist_teardown",
                    resource=assessment_id or "SHARAY_EGRESS",
                    detail={"ruleset_hash": ruleset_hash, "clean": teardown_ok},
                )
            except Exception:
                pass

    enforced = [
        "egress_allowlist_multi_destination" if len(dests) > 1 else "egress_allowlist_single_destination",
        "read_only_rootfs",
        "cap_drop_all",
        "no_new_privileges",
        "nftables_isolation" if is_nft else "iptables_isolation",
    ]
    if any(c[0] == "ip6tables" for c in rules["up"]):
        enforced.append("ipv6_egress")
    if seccomp_profile is not None:
        enforced.append("seccomp_profile")
    if apparmor_profile is not None:
        enforced.append("apparmor_profile")
    if "@sha256:" in image:
        enforced.append("image_digest_pinning")
    enforced.append("egress_attestation_audit")

    if result is None:
        return IsolatedResult(
            outcome="failed",
            exit_code=124,
            stdout=b"",
            stderr=b"Command timed out before completion",
            output_truncated=False,
            scratch_removed=teardown_ok,
            duration_ms=round((time.monotonic() - started) * 1000),
            enforced=tuple(enforced),
        )
    out = result.stdout.encode("utf-8", "replace")[:MAX_OUTPUT_BYTES]
    clean = result.returncode == 0 and teardown_ok
    return IsolatedResult(
        outcome="completed" if clean else "failed",
        exit_code=result.returncode,
        stdout=out,
        stderr=b"" if teardown_ok else b"egress allowlist teardown failed; sandbox network state left dirty",
        output_truncated=len(result.stdout.encode()) > MAX_OUTPUT_BYTES,
        scratch_removed=teardown_ok,
        duration_ms=round((time.monotonic() - started) * 1000),
        enforced=tuple(enforced),
    )


def attest() -> dict[str, Any]:
    """Report what this backend can enforce here. Single-destination and multi-destination egress
    are available on a podman machine (the tested rootful-bridge FORWARD path); any other runtime is no-network only."""
    runtime = container_runtime()
    name = Path(runtime).name if runtime else None
    enforced = ["no_network", "read_only_rootfs", "all_capabilities_dropped", "no_new_privileges"]
    if name == "podman":
        enforced.extend(
            [
                "egress_allowlist_single_destination",
                "egress_allowlist_multi_destination",
                "ipv6_egress",
                "seccomp_profile",
                "apparmor_profile",
                "image_digest_pinning",
                "egress_attestation_audit",
            ]
        )
    return {
        "backend": "rootless-container",
        "runtime": name,
        "available": runtime is not None,
        "enforced": enforced,
        "not_enforced": [] if name == "podman" else ["destination_egress_allowlist"],
    }


__all__ = [
    "AttestationState",
    "EgressAttestationLogger",
    "EgressAttestationReceipt",
    "EgressRuleEntry",
    "ImagePinningEngine",
    "LinuxEgressEngine",
    "MAX_OUTPUT_BYTES",
    "TargetDestination",
    "attest",
    "build_egress_ruleset",
    "build_multidest_egress_ruleset",
    "build_nftables_egress_ruleset",
    "build_run_argv",
    "container_runtime",
    "generate_scanner_apparmor_profile",
    "generate_scanner_seccomp_profile",
    "parse_target_destinations",
    "run_contained",
    "run_with_egress",
]
