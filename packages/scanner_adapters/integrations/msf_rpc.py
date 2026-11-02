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
    # The exact authorized target address the exploit may use (the pinned RHOST). When set, the
    # module options must target this host or execution is refused; this stops a caller from
    # approving one target and then firing at another.
    approved_rhost: str = ""
    session_lifetime_limit_seconds: float = 10.0
    consent_timestamp: float = dataclasses.field(default_factory=time.time)
    consent_hash: str = ""

    def __post_init__(self):
        if not self.consent_hash:
            canonical = (
                f"{self.operator_id}:{self.target_url}:{self.approved_module}:"
                f"{self.approved_rhost}:{self.non_destructive_command}:{self.consent_timestamp}"
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
    def send_rpc(self, method: str, params: list[Any]) -> dict[str, Any]: ...


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


def _host_only(value: str) -> str:
    """Extract a bare host from a URL or host[:port], lowercased, brackets/port stripped."""
    from urllib.parse import urlsplit

    text = (value or "").strip()
    if "://" in text:
        host = urlsplit(text).hostname or ""
    else:
        host = text.split("/", 1)[0]
        if host.startswith("["):  # bracketed IPv6
            host = host[1 : host.find("]")] if "]" in host else host[1:]
        elif host.count(":") == 1:  # host:port (not IPv6)
            host = host.split(":", 1)[0]
    return host.lower()


def _options_rhost(options: dict[str, Any]) -> str:
    return _host_only(str(options.get("RHOSTS") or options.get("RHOST") or ""))


def _verify_consent_target(options: dict[str, Any], consent: OperatorConsentReceipt) -> None:
    """Refuse when the module options target a host the consent did not approve."""
    expected = (
        _host_only(consent.approved_rhost) if consent.approved_rhost else _host_only(consent.target_url)
    )
    actual = _options_rhost(options)
    if not actual or not expected or actual != expected:
        raise PermissionError(
            f"Consent target mismatch: approved '{expected or '(none)'}', options target '{actual or '(none)'}'"
        )


def _precheck_is_vulnerable(check_res: dict[str, Any]) -> bool:
    return check_res.get("code") in ("vulnerable", "appears")


_SESSION_HOST_FIELDS = ("target_host", "session_host", "tunnel_peer", "host")


def _session_targets_host(info: Any, expected_host: str) -> bool:
    if not isinstance(info, dict):
        return False
    for field in _SESSION_HOST_FIELDS:
        value = _host_only(str(info.get(field) or ""))
        if value and value == expected_host:
            return True
    return False


def _session_has_host_metadata(info: Any) -> bool:
    """True when the session reports any host at all (so an unmatched host is a real contradiction)."""
    if not isinstance(info, dict):
        return False
    return any(str(info.get(field) or "").strip() for field in _SESSION_HOST_FIELDS)


def _select_correlated_session(after: dict[str, Any], before_ids: set[str], expected_host: str) -> str | None:
    """Pick the session created by THIS run (new id) whose target matches the expected host.

    Never falls back to a pre-existing or unrelated session: returns None (fail closed) if no new
    session correlates to the authorized target.
    """
    new_ids = [sid for sid in after if str(sid) not in before_ids]
    for sid in new_ids:
        if _session_targets_host(after.get(sid), expected_host):
            return str(sid)
    # Accept a single new session ONLY when its target is genuinely unknown -- never when its own
    # host metadata names a different host (that is a contradiction, not missing information).
    if len(new_ids) == 1 and not _session_has_host_metadata(after.get(new_ids[0])):
        return str(new_ids[0])
    return None


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
            raise MsfRpcUnavailable(
                "No msfrpcd transport configured; refusing to report an unverified session."
            )
        # 3. The options must target exactly the host the operator approved.
        _verify_consent_target(options, consent)

        t_start = time.time()
        check_passed = False
        session_opened = False
        proof_evidence = ""
        clean_teardown = False
        expected_host = _options_rhost(options)

        try:
            # Stage 1: Precondition check. A non-vulnerable precheck stops here; execution only
            # proceeds when the target actually appears vulnerable.
            check_res = self.transport.send_rpc("module.check", ["exploit", module_name, options])
            check_passed = _precheck_is_vulnerable(check_res)
            if not check_passed:
                clean_teardown = True  # nothing was opened, so nothing to tear down
            else:
                # Stage 2: execute, then bind to the session THIS run created for THIS target.
                before_ids = {str(sid) for sid in (self.transport.send_rpc("session.list", []) or {})}
                self.transport.send_rpc("module.execute", ["exploit", module_name, options])
                after = self.transport.send_rpc("session.list", []) or {}
                sess_id = _select_correlated_session(after, before_ids, expected_host)
                if sess_id:
                    session_opened = True
                    cmd_res = self.transport.send_rpc(
                        "session.shell_write", [sess_id, f"{consent.non_destructive_command}\n"]
                    )
                    proof_evidence = cmd_res.get("data", "")
                    try:
                        kill_res = self.transport.send_rpc("session.stop", [sess_id])
                        clean_teardown = kill_res.get("result") == "success"
                    except Exception:
                        clean_teardown = False  # a failed stop is reported truthfully
                else:
                    clean_teardown = True  # no correlated session opened; nothing to tear down

        finally:
            t_end = time.time()
            duration = t_end - t_start

        receipt_canonical = f"{consent.consent_hash}:{module_name}:{session_opened}:{proof_evidence}:{clean_teardown}:{duration}"
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
            raise MsfRpcUnavailable(
                "No msfrpcd transport configured; cannot collect post-exploitation evidence."
            )
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
        # Options must target the approved host; a non-vulnerable precheck refuses to execute.
        _verify_consent_target(options, consent)
        check_res = client.transport.send_rpc("module.check", ["exploit", module_name, options])
        if not _precheck_is_vulnerable(check_res):
            raise MsfRpcUnavailable(
                "Precheck did not confirm the target is vulnerable; refusing to open a session."
            )
        before_ids = {str(sid) for sid in (client.transport.send_rpc("session.list", []) or {})}
        client.transport.send_rpc("module.execute", ["exploit", module_name, options])
        after = client.transport.send_rpc("session.list", []) or {}
        # Only drive a session THIS run created for THIS target — never a pre-existing/unrelated one.
        session_id = _select_correlated_session(after, before_ids, _options_rhost(options))
        if not session_id:
            raise MsfRpcUnavailable(
                "Exploit ran but no session correlated to the authorized target was opened; nothing to drive."
            )
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
        """Tear the session down and report truthfully whether the stop succeeded."""
        if self._closed:
            return True
        torn_down = False
        if self.client.transport is not None:
            try:
                result = self.client.transport.send_rpc("session.stop", [self.session_id])
                torn_down = result.get("result") == "success" if isinstance(result, dict) else bool(result)
            except Exception:
                torn_down = False
        self._closed = True
        return torn_down

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
