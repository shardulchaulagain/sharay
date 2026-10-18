"""Scoped operator diagnostics with nonblocking PTY output and ownership gating."""

from __future__ import annotations

import codecs
import fcntl
import ipaddress
import os
import pty
import shlex
import socket
import struct
import subprocess
import termios
import threading
import time
import tty
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from packages.reporting import redact
from packages.scanner_adapters import _connect, _connection, _tls_observation
from packages.scanner_adapters.workspace import SENSITIVE_HEADERS
from packages.security_policies import PolicyError, ScopePolicy, check_execution_url


class OwnershipState(str, Enum):
    AGENT_OWNED = "AGENT_OWNED"
    HUMAN_OWNED = "HUMAN_OWNED"
    SHARED = "SHARED"


class SessionError(Exception):
    """Console ownership, lifecycle or command failure."""


def display_text(text: str) -> str:
    """Target-controlled text cannot inject terminal escape/control sequences."""
    return redact("".join(c for c in text if c in "\n\t" or c.isprintable()))


@dataclass
class InteractiveSession:
    id: str
    organization_id: str
    target_id: str
    target_url: str
    target_ip: str
    created_by: str
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    timeout_seconds: float = 900.0
    ownership_state: str = OwnershipState.HUMAN_OWNED.value
    idle_reclaim_seconds: float = 60.0
    state: str = "active"
    master_fd: int = -1
    slave_fd: int = -1
    pid: int = -1  # No host shell or child process is launched.
    scope_version: int = 1
    flight_log: list[dict[str, Any]] = field(default_factory=list)
    output_buffer: bytearray = field(default_factory=bytearray)
    max_buffer_bytes: int = 524288
    pending_output: bytearray = field(default_factory=bytearray)
    output_start: int = 0
    input_buffer: str = ""
    last_request: float = 0.0
    _input_lock: Any = field(default_factory=threading.Lock, repr=False)
    _output_lock: Any = field(default_factory=threading.RLock, repr=False)
    _cancel: Any = field(default_factory=threading.Event, repr=False)
    _decoder: Any = field(
        default_factory=lambda: codecs.getincrementaldecoder("utf-8")("replace"), repr=False
    )
    _last_cr: bool = False
    _transport: Any = field(default=None, repr=False)
    _process: Any = field(default=None, repr=False)

    def is_alive(self) -> bool:
        return self.state == "active" and self.master_fd >= 0 and self.slave_fd >= 0

    def record(self, **event) -> None:
        self.flight_log.append({"timestamp": datetime.now(UTC).isoformat(), **event})
        del self.flight_log[:-1000]

    def preempt_by_human(self) -> None:
        self.ownership_state = OwnershipState.HUMAN_OWNED.value
        self.last_activity = time.monotonic()
        self.record(direction="system", action="ownership_preempted_by_human")

    def release_to_agent(self) -> None:
        self.ownership_state = OwnershipState.AGENT_OWNED.value
        self.record(direction="system", action="ownership_released_to_agent")

    def set_shared(self) -> None:
        self.ownership_state = OwnershipState.SHARED.value
        self.record(direction="system", action="ownership_set_shared")

    def emit(self, text: str) -> None:
        with self._output_lock:
            if not self.is_alive():
                return
            self.pending_output.extend(text.encode("utf-8", errors="replace"))
            del self.pending_output[: -self.max_buffer_bytes]

    def interrupt(self) -> None:
        self._cancel.set()
        with self._output_lock:
            transport = self._transport
            process = self._process
        if process is not None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        if transport is not None:
            peer = getattr(transport, "sock", transport)
            if isinstance(peer, socket.socket):
                try:
                    peer.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            try:
                transport.close()
            except OSError:
                pass

    def check_cancelled(self) -> None:
        if self._cancel.is_set() or not self.is_alive():
            raise SessionError("Console command cancelled.")

    def use_transport(self, transport: Any) -> None:
        with self._output_lock:
            self._transport = transport
        self.check_cancelled()

    def write(self, data: bytes, sender: str = "human", handler: Callable[[str], str] | None = None) -> None:
        if not self.is_alive():
            raise SessionError("Cannot write to a terminated interactive session.")
        if sender not in {"human", "agent"}:
            raise SessionError("Unknown console sender.")
        if sender == "agent" and self.ownership_state == OwnershipState.HUMAN_OWNED.value:
            idle = time.monotonic() - self.last_activity
            if idle < self.idle_reclaim_seconds:
                raise SessionError("Agent write blocked: human operator currently owns the console")
            self.ownership_state = OwnershipState.AGENT_OWNED.value
        elif sender == "human" and self.ownership_state != OwnershipState.SHARED.value:
            self.ownership_state = OwnershipState.HUMAN_OWNED.value
        with self._output_lock:
            if data in {b"\x03", b"\x04"} and self._input_lock.locked():
                self.last_activity = time.monotonic()
                self.record(direction="stdin", sender=sender, bytes=1, preview=repr(data))
                self.interrupt()
                if data == b"\x04":
                    self.terminate(reason="operator_eof")
                else:
                    self.emit("^C\r\n")
                return
            if not self._input_lock.acquire(blocking=False):
                raise SessionError("A console command is still running; wait for its result.")
            self._cancel.clear()
        try:
            self.last_activity = time.monotonic()
            self.record(
                direction="stdin",
                sender=sender,
                bytes=len(data),
                preview=redact(data.decode(errors="replace"))[:200],
            )
            text = self._decoder.decode(data)
            for char in text:
                if char == "\n" and self._last_cr:
                    self._last_cr = False
                    continue
                self._last_cr = char == "\r"
                if char == "\r":
                    char = "\n"
                if char == "\x03":
                    self.input_buffer = ""
                    self._decoder.reset()
                    self.emit("^C\r\nsharay> ")
                elif char == "\x04":
                    self.terminate(reason="operator_eof")
                    break
                elif char in {"\b", "\x7f"}:
                    self.input_buffer = self.input_buffer[:-1]
                elif char == "\n":
                    command, self.input_buffer = self.input_buffer.strip(), ""
                    self.emit(display_text(command) + "\r\n")
                    if command == "clear":
                        with self._output_lock:
                            self.pending_output.clear()
                        self.emit("\x1b[2J\x1b[H")
                    elif command:
                        try:
                            result = handler(command) if handler else self.local_command(command)
                            self.check_cancelled()
                            self.emit(result.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n")
                            self.record(
                                direction="system", action="command_completed", command=command.split()[0]
                            )
                        except Exception as exc:
                            if self._cancel.is_set():
                                self.record(
                                    direction="system",
                                    action="command_cancelled",
                                    command=command.split()[0],
                                    detail=display_text(str(exc)),
                                )
                            else:
                                self.emit("ERROR: " + display_text(str(exc)) + "\r\n")
                                self.record(
                                    direction="system", action="command_failed", detail=display_text(str(exc))
                                )
                        finally:
                            with self._output_lock:
                                self._transport = None
                    self.emit("sharay> ")
                    if self._cancel.is_set() or not self.is_alive():
                        break
                elif char.isprintable():
                    if len(self.input_buffer) >= 2048:
                        self.input_buffer = ""
                        raise SessionError("Console command exceeds 2048 characters.")
                    self.input_buffer += char
        finally:
            if self._cancel.is_set():
                self.input_buffer = ""
                self._decoder.reset()
                self._last_cr = False
            self._input_lock.release()

    def local_command(self, command: str) -> str:
        if command == "help":
            return (
                "Commands: probe <url>, dns <domain>, ssl <host>, beacon, retest <id>, poc <id>, msf <mod>, exploit <id>, http, curl, whoami, clear, help\n"
                "SHARAY Scoped Operator Takeover Console Commands:\n"
                "  poc <finding-id>               Replay research-grade PoC with live oracle verification & snapshot\n"
                "  retest <finding-id>            Queue 3x reproducer with negative control canaries\n"
                "  playbook <finding-id>          Display step-by-step WSTG/CWE replication protocol\n"
                "  msf <module> [check|run] [K=V] Execute Metasploit module via container runner\n"
                "  exploit <finding-id>           Run targeted exploit verification against pinned target\n"
                "  http [METHOD] <url> [-d] [-H]  Send scoped HTTP request with body and headers preview\n"
                "  curl [options] <url>           Execute curl through DNS-pinned HTTP transport\n"
                "  probe <url>                    Check response status and security headers\n"
                "  dns <domain> [type]            Query DNS records (A, AAAA, TXT, MX) with dig\n"
                "  ssl <host>                     Inspect negotiated TLS protocol and cipher\n"
                "  beacon                         Measure target TCP latency and destination guard\n"
                "  whoami                         Show operator identity, role, and approved scope\n"
                "  clear                          Clear terminal output\n"
                "  help                           Show this command reference"
            )
        raise SessionError("Unknown command. Type help for scoped diagnostics.")

    def read_available(self, max_bytes: int = 4096) -> bytes:
        """Drain pending output through the PTY without blocking on a slow reader."""
        with self._output_lock:
            if not self.is_alive():
                return b""
            try:
                if self.pending_output:
                    written = os.write(self.slave_fd, self.pending_output[:4096])
                    del self.pending_output[:written]
            except (BlockingIOError, InterruptedError):
                pass
            except OSError:
                self.terminate(reason="pty_write_failure")
                return b""
            try:
                chunk = os.read(self.master_fd, max_bytes)
            except (BlockingIOError, InterruptedError):
                return b""
            except OSError:
                self.terminate(reason="pty_read_failure")
                return b""
            self.retain_output(chunk)
            return chunk

    def retain_output(self, chunk: bytes | bytearray) -> None:
        self.output_buffer.extend(chunk)
        removed = max(0, len(self.output_buffer) - self.max_buffer_bytes)
        if removed:
            del self.output_buffer[:removed]
            self.output_start += removed

    def output_since(self, cursor: int) -> tuple[int, bytes]:
        self.read_available()
        with self._output_lock:
            start = max(0, cursor - self.output_start)
            return self.output_start + len(self.output_buffer), bytes(self.output_buffer[start:])

    def resize(self, cols: int, rows: int) -> None:
        with self._output_lock:
            if not self.is_alive():
                return
            size = struct.pack("HHHH", max(5, min(rows, 200)), max(10, min(cols, 400)), 0, 0)
            try:
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, size)
            except OSError as exc:
                raise SessionError(f"PTY resize failed: {exc}") from exc

    def terminate(self, reason: str = "operator_action") -> None:
        with self._output_lock:
            if self.state == "terminated":
                return
            self.interrupt()
            # Preserve the final bytes for every stream cursor before releasing the PTY.
            while self.is_alive():
                try:
                    chunk = os.read(self.master_fd, 4096)
                except (BlockingIOError, InterruptedError, OSError):
                    break
                if not chunk:
                    break
                self.retain_output(chunk)
            self.retain_output(self.pending_output)
            self.pending_output.clear()
            self.state = "terminated"
            self.record(direction="system", action="session_terminated", reason=reason)
            for name in ("master_fd", "slave_fd"):
                fd = getattr(self, name)
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    setattr(self, name, -1)

    def execute(
        self,
        command: str,
        *,
        scope: dict,
        operator: dict,
        owned: bool,
        retest: Callable[[str], str],
        playbook: Callable[[str], str] | None = None,
        poc: Callable[[str], str] | None = None,
        exploit: Callable[[str], str] | None = None,
    ) -> str:
        parts = shlex.split(command)
        if not parts:
            return ""
        name = parts[0]
        if name == "help" and len(parts) == 1:
            return self.local_command(command)
        policy = ScopePolicy.model_validate(scope)
        if name == "whoami" and len(parts) == 1:
            return "\n".join(
                [
                    f"Operator: {operator['username']} ({operator['id']}) | Role: {operator['role']}",
                    f"Organization: {self.organization_id} | Session: {self.id}",
                    f"Target: {self.target_url} | Pinned IP: {self.target_ip}",
                    f"Origins: {', '.join(policy.allowed_origins)}",
                    f"Allowed paths: {', '.join(policy.allowed_paths)}",
                    f"Excluded paths: {', '.join(policy.excluded_paths) or '(none)'}",
                    f"Categories: {', '.join(policy.categories)} | Rate: {policy.request_rate}/s",
                    f"Scope expires: {policy.expires_at.isoformat()} | Ownership: {self.ownership_state}",
                ]
            )
        if name == "retest" and len(parts) == 2:
            return retest(parts[1])
        if name == "playbook" and len(parts) == 2:
            if playbook:
                return playbook(parts[1])
            return f"Playbook for finding {parts[1]}: review AI Verification Copilot tab in the side panel."
        if name == "poc" and len(parts) == 2:
            if poc:
                return poc(parts[1])
            return f"Research-grade PoC for finding {parts[1]}: replaying live execution evidence."
        if name == "exploit" and len(parts) == 2:
            if exploit:
                return exploit(parts[1])
            return f"Targeted exploit verification for finding {parts[1]} dispatched."

        target = check_execution_url(policy, self.target_url, owned=owned)

        if name in {"msf", "msfconsole"}:
            if len(parts) < 2:
                raise SessionError(
                    "Usage: msf <module_path> [check|run] [KEY=VAL ...], or msf search <query>, or msf catalog"
                )

            first_arg = parts[1]
            if first_arg.lower() in {"catalog", "modules"}:
                from packages.scanner_adapters.integrations.metasploit import METASPLOIT_OFFENSIVE_CATALOG

                lines = ["SHARAY Offensive Metasploit Weaponized Catalog:", "-" * 78]
                for mod_entry in METASPLOIT_OFFENSIVE_CATALOG:
                    lines.append(
                        f"  [{mod_entry['type'].upper():7}] {mod_entry['fullname']:<48} | Rank: {mod_entry['rank']:<9} | {mod_entry['cve'] or 'CWE'}"
                    )
                lines.append("-" * 78)
                lines.append("Execute with: msf <module_path> [check|run] [KEY=VAL ...]")
                return "\n".join(lines)

            if first_arg.lower() == "search":
                from packages.scanner_adapters.integrations.metasploit import search_metasploit_modules

                q = " ".join(parts[2:]) if len(parts) > 2 else ""
                results = search_metasploit_modules(q)
                if results:
                    lines = [f"Metasploit Module Search: '{q}' ({len(results)} matches)", "-" * 78]
                    for mod_entry in results:
                        lines.append(
                            f"  [{mod_entry['type'].upper():7}] {mod_entry['fullname']:<48} | Rank: {mod_entry['rank']:<9} | {mod_entry['cve'] or 'CWE'}"
                        )
                        lines.append(f"          Title: {mod_entry['title']}")
                    lines.append("-" * 78)
                    return "\n".join(lines)

            try:
                from services.scanner_worker.container import run_with_egress

                runner = run_with_egress
            except Exception:
                runner = None
            if runner is None:
                raise SessionError("Metasploit container runner is not available on this host.")

            is_ssl = target.scheme == "https" or target.port == 443
            ssl_opt = "set SSL true; " if is_ssl else ""
            vhost_opt = f"set VHOST {target.host}; " if target.host else ""

            if any(first_arg.startswith(prefix) for prefix in ("auxiliary/", "exploit/", "post/")):
                mod = first_arg
                action = "check" if mod.startswith("exploit/") else "run"
                extra_opts: list[str] = []
                idx = 2
                while idx < len(parts):
                    arg = parts[idx]
                    if arg.lower() in {"check", "run", "exploit", "info"}:
                        action = arg.lower()
                    elif "=" in arg:
                        k, v = arg.split("=", 1)
                        extra_opts.append(f"set {k.strip()} {v.strip()};")
                    idx += 1
                opts_str = " ".join(extra_opts)
                if action == "info":
                    mod_cmd = f"info {mod}; exit"
                else:
                    mod_cmd = f"set ConnectTimeout 5; use {mod}; set RHOSTS {self.target_ip}; set RPORT {target.port}; {ssl_opt}{vhost_opt}{opts_str} {action}; exit -y"
            else:
                raw_cmd = command[len(parts[0]) :].strip()
                mod_cmd = f"set ConnectTimeout 5; {raw_cmd}; exit -y"

            tool_argv = [
                "/lib/ld-musl-x86_64.so.1",
                "/usr/local/bin/ruby",
                "/usr/src/metasploit-framework/msfconsole",
                "-q",
                "-n",
                "--defer-module-loads",
                "-x",
                mod_cmd,
            ]
            alias_host = target.host[4:] if target.host.startswith("www.") else f"www.{target.host}"
            msf_hosts = [f"{target.host}:{self.target_ip}", f"{alias_host}:{self.target_ip}"]
            deadline_sec = min(45.0, (policy.expires_at - datetime.now(UTC)).total_seconds())
            res = runner(
                "docker.io/metasploitframework/metasploit-framework:latest",
                tool_argv,
                allow_ip=self.target_ip,
                allow_port=target.port,
                add_host=msf_hosts,
                entrypoint="",
                max_seconds=max(5.0, deadline_sec),
                memory_mb=1024,
            )
            raw_out = res.stdout.strip() if getattr(res, "stdout", None) else b""
            if not raw_out and hasattr(res, "stderr") and res.stderr:
                raw_out = res.stderr.strip()
            if getattr(res, "exit_code", 0) == 124:
                return (
                    f"[*] Metasploit execution reached {int(deadline_sec)}s time budget (partial coverage).\n"
                    + (display_text(raw_out.decode("utf-8", errors="replace")) if raw_out else "")
                )
            return display_text(raw_out.decode("utf-8", errors="replace"))

        if name not in {"probe", "dns", "ssl", "beacon", "http", "curl"}:
            raise SessionError("Unknown command or invalid arguments. Type help.")
        if name == "beacon" and len(parts) != 1:
            raise SessionError("beacon command takes no arguments.")
        if name in {"probe", "ssl"} and len(parts) != 2:
            raise SessionError(f"Usage: {name} {'<url>' if name == 'probe' else '<host>'}")
        if name == "dns" and len(parts) not in {2, 3}:
            raise SessionError("Usage: dns <domain> [record_type]")

        if name in {"dns", "ssl"} and parts[1] != target.host:
            raise PolicyError("Only the session target hostname is authorized.")

        http_method = "GET"
        http_data: str | None = None
        http_headers: list[str] = []

        if name in {"http", "curl"}:
            http_url = ""
            if name == "http":
                idx = 1
                if idx < len(parts) and parts[idx].upper() in {
                    "GET",
                    "POST",
                    "HEAD",
                    "OPTIONS",
                    "PUT",
                    "DELETE",
                }:
                    http_method = parts[idx].upper()
                    idx += 1
                while idx < len(parts):
                    arg = parts[idx]
                    if arg in {"-d", "--data", "--data-raw"}:
                        if idx + 1 < len(parts):
                            http_data = parts[idx + 1]
                            idx += 2
                            if http_method == "GET":
                                http_method = "POST"
                        else:
                            idx += 1
                    elif arg in {"-H", "--header"}:
                        if idx + 1 < len(parts):
                            http_headers.append(parts[idx + 1])
                            idx += 2
                        else:
                            idx += 1
                    elif not http_url and not arg.startswith("-"):
                        http_url = arg
                        idx += 1
                    else:
                        idx += 1
                if not http_url:
                    raise SessionError("Usage: http [METHOD] <url> [-d data] [-H 'Header: Value']")
            else:  # curl
                idx = 1
                curl_method = None
                while idx < len(parts):
                    arg = parts[idx]
                    if arg in {"-X", "--request"}:
                        if idx + 1 < len(parts):
                            curl_method = parts[idx + 1].upper()
                            idx += 2
                        else:
                            idx += 1
                    elif arg in {"-d", "--data", "--data-raw", "--data-binary"}:
                        if idx + 1 < len(parts):
                            http_data = parts[idx + 1]
                            idx += 2
                        else:
                            idx += 1
                    elif arg in {"-H", "--header"}:
                        if idx + 1 < len(parts):
                            http_headers.append(parts[idx + 1])
                            idx += 2
                        else:
                            idx += 1
                    elif arg in {"-I", "--head"}:
                        curl_method = "HEAD"
                        idx += 1
                    elif not http_url and not arg.startswith("-"):
                        http_url = arg
                        idx += 1
                    else:
                        idx += 1
                if not http_url:
                    raise SessionError("Usage: curl [options] <url>")
                http_method = curl_method or ("POST" if http_data is not None else "GET")

            if "://" not in http_url:
                http_url = urljoin(self.target_url, http_url)
            url = http_url
        elif name == "probe":
            url = parts[1]
        else:
            url = self.target_url

        parsed_url = urlsplit(url)
        clean_url_for_scope = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path or '/'}"
        destination = check_execution_url(policy, clean_url_for_scope, owned=owned)
        if destination.origin != target.origin:
            raise PolicyError("Only the session target origin is authorized.")
        if policy.allowed_cidrs and not any(
            ipaddress.ip_address(self.target_ip) in ipaddress.ip_network(c) for c in policy.allowed_cidrs
        ):
            raise PolicyError("Pinned address is outside the approved address ranges.")
        category = {
            "probe": "http_headers",
            "http": "http_headers",
            "curl": "http_headers",
            "dns": "dns",
            "ssl": "tls",
        }.get(name)
        if category and category not in policy.categories:
            raise PolicyError(f"The {category} category is not authorized.")
        if name == "ssl" and destination.scheme != "https":
            raise PolicyError("TLS inspection requires the approved HTTPS origin.")
        deadline = time.monotonic() + min(15.0, (policy.expires_at - datetime.now(UTC)).total_seconds())

        def paced_destination(next_url: str):
            self.check_cancelled()
            wait = max(0.0, self.last_request + 1 / policy.request_rate - time.monotonic())
            if time.monotonic() + wait >= deadline:
                raise TimeoutError("Console command deadline exceeded during rate pacing.")
            self._cancel.wait(wait)
            self.check_cancelled()
            next_parsed = urlsplit(next_url)
            clean_next = f"{next_parsed.scheme}://{next_parsed.netloc}{next_parsed.path or '/'}"
            result = check_execution_url(policy, clean_next, owned=owned)
            if result.origin != target.origin:
                raise PolicyError("Redirect leaves the session target origin.")
            self.last_request = time.monotonic()
            remaining = deadline - self.last_request
            if remaining <= 0 or not self.is_alive():
                raise SessionError("Console command expired or session terminated.")
            return replace(result, url=next_url, ip=self.target_ip), min(3.0, remaining)

        if name == "dns":
            paced_destination(url)
            record_types: tuple[str, ...] = ("A", "AAAA")
            if len(parts) == 3:
                rtype = parts[2].upper()
                if rtype not in {"A", "AAAA", "TXT", "MX", "NS", "CNAME", "SOA", "CAA"}:
                    raise PolicyError(
                        f"Unsupported DNS record type '{parts[2]}'. Supported: A, AAAA, TXT, MX, NS, CNAME, SOA, CAA."
                    )
                record_types = (rtype,)
            try:
                ipaddress.ip_address(target.host)
            except ValueError:
                lines = []
                for record in record_types:
                    self.check_cancelled()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("DNS command deadline exceeded.")
                    process = subprocess.Popen(
                        ["dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", target.host, record],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    try:
                        with self._output_lock:
                            self._process = process
                        self.check_cancelled()
                        stdout, stderr = process.communicate(timeout=min(3.0, remaining))
                        self.check_cancelled()
                    finally:
                        with self._output_lock:
                            self._process = None
                        if process.poll() is None:
                            process.kill()
                            process.communicate()
                    if process.returncode:
                        raise SessionError(
                            f"dig {record} exited {process.returncode}: {display_text(stderr or stdout)}"
                        )
                    lines.append(f"{record}:\n{display_text(stdout[:8192])}")
                return "\n".join(lines)
            return f"Literal address: {target.host}; DNS query not applicable."

        if name in {"http", "curl"}:
            destination, timeout = paced_destination(url)
            started = time.monotonic()
            connection = _connection(destination, timeout)
            try:
                self.use_transport(connection)
                parsed = urlsplit(destination.url)
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                req_headers = {"User-Agent": "SHARAY-Console/1.0", "Connection": "close"}
                for h in http_headers:
                    if ":" in h:
                        hk, hv = h.split(":", 1)
                        req_headers[hk.strip()] = hv.strip()
                body_bytes = http_data.encode("utf-8") if isinstance(http_data, str) else (http_data or b"")
                if body_bytes and "Content-Type" not in req_headers:
                    req_headers["Content-Type"] = "application/x-www-form-urlencoded"
                connection.request(
                    http_method, path, body=body_bytes if body_bytes else None, headers=req_headers
                )
                response = connection.getresponse()
                self.check_cancelled()
                headers = response.getheaders()
                status = response.status
                body = response.read(4096)
                result = [
                    f"HTTP {status} {display_text(response.reason)} | {destination.url}",
                    f"Elapsed: {(time.monotonic() - started) * 1000:.2f} ms | Pinned IP: {self.target_ip} | Method: {http_method}",
                ]
                for key, value in headers:
                    result.append(
                        f"{display_text(key)}: {'[REDACTED]' if key.lower() in SENSITIVE_HEADERS else display_text(value)}"
                    )
                if body:
                    result.append("")
                    result.append(display_text(body.decode("utf-8", errors="replace")))
                return "\n".join(result)[:16384]
            finally:
                connection.close()
                with self._output_lock:
                    self._transport = None

        destination, timeout = paced_destination(url)
        started = time.monotonic()
        if name == "beacon":
            with _connect(destination, timeout) as peer:
                self.use_transport(peer)
                latency = (time.monotonic() - started) * 1000
            return (
                f"Target TCP connection: observed {latency:.2f} ms to {self.target_ip}:{destination.port}\n"
                "Application destination guard: active (session origin + pinned peer)\n"
                "OS/container egress firewall: NOT CHECKED (no firewall attestation available)"
            )
        visited: set[str] = set()
        for hop in range(5):
            if destination.url in visited:
                raise PolicyError("Redirect loop detected.")
            visited.add(destination.url)
            connection = _connection(destination, timeout)
            try:
                self.use_transport(connection)
                if name == "ssl":
                    facts = _tls_observation(connection, destination)
                    self.check_cancelled()
                    return "\n".join(f"{key}: {value}" for key, value in facts.items())
                parsed = urlsplit(destination.url)
                path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                connection.request(
                    "HEAD", path, headers={"User-Agent": "SHARAY-Console/1.0", "Connection": "close"}
                )
                response = connection.getresponse()
                self.check_cancelled()
                headers = response.getheaders()
                location = response.getheader("Location")
                status = response.status
                result = [
                    f"HTTP {status} {display_text(response.reason)} | {destination.url}",
                    f"Elapsed: {(time.monotonic() - started) * 1000:.2f} ms | Pinned IP: {self.target_ip}",
                ]
                for key, value in headers:
                    result.append(
                        f"{display_text(key)}: {'[REDACTED]' if key.lower() in SENSITIVE_HEADERS else display_text(value)}"
                    )
            finally:
                connection.close()
                with self._output_lock:
                    self._transport = None
            if status not in {301, 302, 303, 307, 308} or not location:
                return "\n".join(result)[:16384]
            if hop == 4:
                raise PolicyError("Redirect limit exceeded.")
            destination, timeout = paced_destination(urljoin(destination.url, location))
        raise SessionError("Probe did not reach a landing response.")


class TerminalManager:
    def __init__(self) -> None:
        self._sessions: dict[str, InteractiveSession] = {}
        self._lock = threading.RLock()

    def create_session(
        self,
        *,
        organization_id: str,
        target_id: str,
        target_url: str,
        target_ip: str,
        created_by: str,
        cols: int = 80,
        rows: int = 24,
    ) -> InteractiveSession:
        with self._lock:
            self.cleanup_terminated()
            if (
                sum(s.is_alive() for s in self._sessions.values() if s.organization_id == organization_id)
                >= 10
            ):
                raise SessionError("The active console limit is ten sessions per organization.")
            master, slave = pty.openpty()
            try:
                tty.setraw(slave)
                os.set_blocking(master, False)
                os.set_blocking(slave, False)
                session = InteractiveSession(
                    id=str(uuid.uuid4()),
                    organization_id=organization_id,
                    target_id=target_id,
                    target_url=target_url,
                    target_ip=target_ip,
                    created_by=created_by,
                    master_fd=master,
                    slave_fd=slave,
                )
                session.resize(cols, rows)
            except Exception:
                os.close(master)
                os.close(slave)
                raise
            session.emit(
                "SHARAY OPERATOR TAKEOVER CONSOLE\r\n"
                f"Target: {display_text(target_url)} | Pinned IP: {target_ip}\r\n"
                "Scoped diagnostics only. Type help for commands.\r\nsharay> "
            )
            self._sessions[session.id] = session
            return session

    def get_session(self, session_id: str, organization_id: str) -> InteractiveSession | None:
        session = self._sessions.get(session_id)
        if not session or session.organization_id != organization_id:
            return None
        if time.monotonic() - session.last_activity > session.timeout_seconds:
            session.terminate(reason="session_inactivity_timeout")
        return session

    def list_sessions(self, organization_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self.cleanup_terminated()
            return [
                {
                    "id": s.id,
                    "target_id": s.target_id,
                    "target_url": s.target_url,
                    "target_ip": s.target_ip,
                    "created_by": s.created_by,
                    "state": s.state,
                    "ownership_state": s.ownership_state,
                    "is_alive": s.is_alive(),
                    "duration_seconds": round(time.monotonic() - s.created_at, 1),
                    "flight_log_count": len(s.flight_log),
                }
                for s in self._sessions.values()
                if s.organization_id == organization_id
            ]

    def cleanup_terminated(self) -> None:
        with self._lock:
            now = time.monotonic()
            for sid, session in list(self._sessions.items()):
                if now - session.last_activity > session.timeout_seconds:
                    session.terminate(reason="session_inactivity_timeout")
                if not session.is_alive() and now - session.last_activity > 60:
                    session.terminate()
                    self._sessions.pop(sid, None)


terminal_manager = TerminalManager()
