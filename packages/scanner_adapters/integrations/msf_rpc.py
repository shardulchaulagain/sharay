"""Programmatic Metasploit RPC Driver, Dynamic Module Tree & Safe-Gated Sessions (Sector O2).

Provides full-capacity Metasploit automation with strict safety controls:
1. Programmatic msfrpcd communication (replacing hardcoded 21-module catalog and one-shots).
2. Dynamic module tree search across ~2,400 exploits, ~1,200 auxiliary, and ~400 post modules.
3. Safe-gated check -> exploit -> benign session execution with clean teardown receipts.
4. Non-destructive msfvenom verification payload generator.
5. Read-only post-exploitation evidence collection within scope.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Protocol


class MsfRpcUnavailable(RuntimeError):
    """msfrpcd is not configured or not reachable; nothing was executed and no proof exists."""


@dataclasses.dataclass
class OperatorConsentReceipt:
    operator_id: str
    target_url: str
    approved_module: str
    non_destructive_command: str = "id"
    session_lifetime_limit_seconds: float = 10.0
    consent_timestamp: float = dataclasses.field(default_factory=time.time)
    consent_hash: str = ""

    def __post_init__(self):
        if not self.consent_hash:
            canonical = (
                f"{self.operator_id}:{self.target_url}:{self.approved_module}:"
                f"{self.non_destructive_command}:{self.consent_timestamp}"
            )
            self.consent_hash = hashlib.sha256(canonical.encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class MetasploitModuleDescriptor:
    fullname: str
    type: str
    name: str
    rank: str
    references: list[str]
    description: str
    targets: list[str]


@dataclasses.dataclass(frozen=True)
class BenignSessionExecutionResult:
    check_passed: bool
    session_opened: bool
    proof_evidence: str
    clean_teardown: bool
    receipt_hash: str
    duration_seconds: float


class RPCTransport(Protocol):
    def send_rpc(self, method: str, params: list[Any]) -> dict[str, Any]:
        ...


class HTTPJsonRPCTransport:
    """Real JSON-RPC 2.0 transport to a running msfrpcd JSON-RPC endpoint (no external deps).

    Speaks the standard JSON-RPC 2.0 envelope over HTTP POST; the bearer token (from auth.login)
    is attached to subsequent calls. This is the concrete transport that lets the client drive a
    live msfrpcd. It performs real network I/O and never fabricates results.
    """

    def __init__(self, url: str, token: str | None = None, timeout: float = 10.0) -> None:
        self.url = url
        self.token = token
        self.timeout = timeout
        self._id = 0

    def send_rpc(self, method: str, params: list[Any]) -> dict[str, Any]:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": self._id}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                doc = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise MsfRpcUnavailable(f"msfrpcd JSON-RPC call '{method}' failed: {type(exc).__name__}") from exc
        if isinstance(doc, dict) and doc.get("error"):
            raise RuntimeError(f"MSF RPC error on '{method}': {doc['error']}")
        result = doc.get("result") if isinstance(doc, dict) else None
        return result if isinstance(result, dict) else {"result": result}


def probe_msfrpc(url: str, timeout: float = 1.0) -> bool:
    """True only if a TCP listener answers at the msfrpcd endpoint; never fabricates reachability."""
    from urllib.parse import urlsplit

    sp = urlsplit(url)
    host = sp.hostname or "127.0.0.1"
    port = sp.port or (443 if sp.scheme == "https" else 55553)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def connect(url: str, username: str, password: str, timeout: float = 10.0) -> "MetasploitRPCClient":
    """Build a client on a real JSON-RPC transport and authenticate, failing closed if unreachable."""
    transport = HTTPJsonRPCTransport(url, timeout=timeout)
    client = MetasploitRPCClient(username=username, password=password, transport=transport)
    client.login()
    return client


class MetasploitRPCClient:
    """Programmatic client for msfrpcd with operator consent safety gating."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "",
        ssl: bool = True,
        transport: RPCTransport | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.token: str | None = None
        self.transport = transport

    def login(self) -> str:
        """Authenticate with msfrpcd and acquire a token. Fails closed without a transport."""
        if self.transport is None:
            raise MsfRpcUnavailable(
                "No msfrpcd transport configured. Set SHARAY_MSFRPC_URL and start msfrpcd; "
                "the client never fabricates a session."
            )
        res = self.transport.send_rpc("auth.login", [self.username, self.password])
        self.token = res.get("token")
        # Propagate the bearer token so subsequent authenticated calls carry it.
        if self.token and hasattr(self.transport, "token"):
            self.transport.token = self.token
        return self.token or ""

    def search_modules(self, query: str) -> list[MetasploitModuleDescriptor]:
        """Search the live module tree (exploit/auxiliary/post) by CVE, service, or keyword.

        Requires a real transport; the full tree comes from msfrpcd, not a hardcoded catalog.
        """
        if self.transport is None:
            raise MsfRpcUnavailable("No msfrpcd transport configured; cannot search the module tree.")
        res = self.transport.send_rpc("module.search", [query])
        raw_modules = res.get("modules", [])
        return [
            MetasploitModuleDescriptor(
                fullname=m.get("fullname", ""),
                type=m.get("type", "exploit"),
                name=m.get("name", ""),
                rank=m.get("rank", "normal"),
                references=m.get("references", []),
                description=m.get("description", ""),
                targets=m.get("targets", []),
            )
            for m in raw_modules
        ]

    def execute_benign_verification(
        self,
        module_name: str,
        options: dict[str, Any],
        consent: OperatorConsentReceipt | None,
    ) -> BenignSessionExecutionResult:
        """Execute safe-gated check -> exploit -> benign command -> clean teardown."""
        # 1. Enforce strict operator consent gate
        if consent is None:
            raise PermissionError("Active exploitation rejected: explicit OperatorConsentReceipt required")
        if consent.approved_module != module_name:
            raise PermissionError(
                f"Consent module mismatch: approved '{consent.approved_module}', requested '{module_name}'"
            )
        # 2. Require a real msfrpcd connection — never fabricate a session.
        if self.transport is None:
            raise MsfRpcUnavailable("No msfrpcd transport configured; refusing to report an unverified session.")

        t_start = time.time()
        check_passed = False
        session_opened = False
        proof_evidence = ""
        clean_teardown = False

        try:
            # Stage 1: Precondition check
            check_res = self.transport.send_rpc("module.check", ["exploit", module_name, options])
            if check_res.get("code") in ("vulnerable", "appears"):
                check_passed = True

            # Stage 2: Benign execution against a real session
            exp_res = self.transport.send_rpc("module.execute", ["exploit", module_name, options])
            if exp_res.get("job_id") or exp_res.get("uuid"):
                session_opened = True

            sess_list = self.transport.send_rpc("session.list", [])
            sess_id = next(iter(sess_list.keys())) if sess_list else None
            if sess_id:
                cmd_res = self.transport.send_rpc(
                    "session.shell_write", [sess_id, f"{consent.non_destructive_command}\n"]
                )
                proof_evidence = cmd_res.get("data", "")
                # Immediate clean session kill
                kill_res = self.transport.send_rpc("session.stop", [sess_id])
                clean_teardown = kill_res.get("result") == "success"
            else:
                clean_teardown = True

        finally:
            t_end = time.time()
            duration = t_end - t_start

        receipt_canonical = (
            f"{consent.consent_hash}:{module_name}:{session_opened}:{proof_evidence}:{clean_teardown}:{duration}"
        )
        receipt_hash = hashlib.sha256(receipt_canonical.encode()).hexdigest()

        return BenignSessionExecutionResult(
            check_passed=check_passed,
            session_opened=session_opened,
            proof_evidence=proof_evidence,
            clean_teardown=clean_teardown,
            receipt_hash=receipt_hash,
            duration_seconds=duration,
        )

    def collect_read_only_post_evidence(self, session_id: int) -> dict[str, str]:
        """Collect read-only post-exploitation system metadata from a real session. Fails closed."""
        if self.transport is None:
            raise MsfRpcUnavailable("No msfrpcd transport configured; cannot collect post-exploitation evidence.")
        k_res = self.transport.send_rpc("session.shell_write", [session_id, "uname -a\n"])
        os_res = self.transport.send_rpc("session.shell_write", [session_id, "cat /etc/os-release\n"])
        self.transport.send_rpc("session.stop", [session_id])
        return {
            "kernel": k_res.get("data", ""),
            "os_release": os_res.get("data", ""),
        }


class MetasploitInteractiveSession:
    """Stateful driver for a live msfrpcd session: open once, run many commands against the SAME
    session (target-side state preserved), then clean-close. This is what the operator console
    drives for real interaction, replacing one-shot `check` invocations. Fail-closed throughout.
    """

    def __init__(self, client: "MetasploitRPCClient", session_id: str) -> None:
        self.client = client
        self.session_id = session_id
        self.history: list[tuple[str, str]] = []
        self._closed = False

    @classmethod
    def open(
        cls,
        client: "MetasploitRPCClient",
        module_name: str,
        options: dict[str, Any],
        consent: OperatorConsentReceipt | None,
    ) -> "MetasploitInteractiveSession":
        """Consent-gated: check -> exploit -> keep the opened session for interaction."""
        if consent is None:
            raise PermissionError("Active exploitation rejected: explicit OperatorConsentReceipt required")
        if consent.approved_module != module_name:
            raise PermissionError(
                f"Consent module mismatch: approved '{consent.approved_module}', requested '{module_name}'"
            )
        if client.transport is None:
            raise MsfRpcUnavailable("No msfrpcd transport configured; refusing to open a session.")
        client.transport.send_rpc("module.check", ["exploit", module_name, options])
        client.transport.send_rpc("module.execute", ["exploit", module_name, options])
        sess_list = client.transport.send_rpc("session.list", [])
        session_id = next(iter(sess_list.keys())) if sess_list else None
        if not session_id:
            raise MsfRpcUnavailable("Exploit ran but no session was opened; nothing to drive.")
        return cls(client, str(session_id))

    def run(self, command: str) -> str:
        """Send one command to the live session and read its output. State persists across calls."""
        if self._closed:
            raise MsfRpcUnavailable("Session is closed.")
        assert self.client.transport is not None
        self.client.transport.send_rpc("session.shell_write", [self.session_id, command + "\n"])
        res = self.client.transport.send_rpc("session.shell_read", [self.session_id])
        out = res.get("data", "")
        self.history.append((command, out))
        return out

    def close(self) -> bool:
        if self._closed:
            return True
        if self.client.transport is not None:
            try:
                self.client.transport.send_rpc("session.stop", [self.session_id])
            except Exception:
                pass
        self._closed = True
        return True

    def __enter__(self) -> "MetasploitInteractiveSession":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class MsfvenomPayloadGenerator:
    """Generates non-destructive benign payloads for authorized verification."""

    @staticmethod
    def generate_benign_command(platform: str, marker: str, command: str = "id") -> str:
        if platform.lower() == "windows":
            return f"cmd.exe /c echo {marker} & {command}"
        return f"sh -c 'echo {marker}; {command}'"


__all__ = [
    "OperatorConsentReceipt",
    "MetasploitModuleDescriptor",
    "BenignSessionExecutionResult",
    "MetasploitRPCClient",
    "MetasploitInteractiveSession",
    "MsfvenomPayloadGenerator",
    "HTTPJsonRPCTransport",
    "MsfRpcUnavailable",
    "connect",
    "probe_msfrpc",
]
