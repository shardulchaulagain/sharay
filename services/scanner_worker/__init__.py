"""OS-isolated execution for scanner tools: macOS Seatbelt, deny by default.

One fixed argv (never a shell) runs able to execute only itself and reviewed
helper paths, read only declared paths, write nothing (or, when granted, only
a private scratch directory) and open TCP connections only to listed ports on exactly 127.0.0.1 or ::1.
Seatbelt cannot allowlist individual non-loopback addresses, so this backend
never grants live-destination egress. Running a tool here is not authorization to assess a
target; callers still pass every scope and policy gate first.
"""

import math
import os
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
# Upper bound a caller may set for captured stdout/stderr. Matches the parsers' own
# MAX_REPORT_BYTES (packages/scanner_adapters/integrations/_parsing.py): a report up to this
# size is captured whole, so a large but valid scan is parsed, not truncated then rejected.
MAX_OUTPUT_BYTES = 10 * 1024 * 1024

# Paths reach the profile as -D parameters, never as interpolated text.
# Data paths ({reads}) are readable but never executable; only {execs} are both.
_PROFILE = """(version 1)
(deny default)
{fork}(allow signal (target same-sandbox))
(allow sysctl-read)
(allow file-read-metadata)
(allow process-exec (literal (param "EXE")){execs})
(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random")
  (subpath "/usr/lib") (subpath "/System/Library") (subpath "/System/Volumes/Preboot/Cryptexes")
  (subpath "/private/var/db/dyld") (literal (param "EXE")) (subpath (param "SCRATCH")){execs}{reads})
(allow file-write* (literal "/dev/null"){writes})
"""

# Sets limits in a fresh single-threaded process, then becomes sandbox-exec; this
# keeps run_isolated safe to call from threaded callers (no preexec_fn after fork).
_LAUNCH = (
    "import os, resource, sys\n"
    "for name, value in zip(('CORE', 'NOFILE', 'CPU', 'FSIZE'), sys.argv[1:5]):\n"
    "    kind = getattr(resource, 'RLIMIT_' + name)\n"
    "    hard = resource.getrlimit(kind)[1]\n"
    # An unprivileged process cannot raise a hard limit inherited from the worker.
    "    value = int(value) if hard == resource.RLIM_INFINITY else min(int(value), hard)\n"
    "    resource.setrlimit(kind, (value, value))\n"
    "os.execv(sys.argv[5], sys.argv[5:])\n"
)

# Runs inside the sandbox and prints only the controls it saw the kernel refuse.
_PROBE = """
import os, socket, sys
def attempt(action):
    try:
        action()
    except PermissionError:
        return "denied"
    except OSError:
        return "error"
    return "ok"
def connect(port):
    with socket.socket() as client:
        client.settimeout(2)
        client.connect(("127.0.0.1", int(port)))
def fork():
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
def connect6(port):
    with socket.socket(socket.AF_INET6) as client:
        client.settimeout(2)
        client.connect(("::1", int(port)))
def datagram(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(b"x", ("127.0.0.1", int(port)))
outside, allowed, blocked = sys.argv[1:4]
seen = []
if attempt(lambda: open(outside).close()) == "denied":
    seen.append("filesystem_read_allowlist")
if attempt(lambda: open(outside, "a").close()) == "denied":
    seen.append("scratch_only_writes")
if attempt(lambda: connect(blocked)) == "denied":
    seen.append("network_denied_by_default")
    if attempt(lambda: connect(allowed)) == "ok":
        seen.append("loopback_port_egress")
        # The grant is TCP to 127.0.0.1 only: not ::1 on that port, and not UDP.
        if attempt(lambda: connect6(allowed)) == "denied" and attempt(lambda: datagram(allowed)) == "denied":
            seen.append("exact_loopback_address")
if attempt(fork) == "denied":
    seen += ["process_escape_containment", "process_count_limit"]
if attempt(lambda: open("scratch-file", "w").close()) == "denied":
    seen.append("aggregate_scratch_quota")
print(" ".join(seen), flush=True)
# Last, because a permitted exec replaces this probe and the control then goes unreported.
if attempt(lambda: os.execv("/usr/bin/true", ["true"])) == "denied":
    print("exec_allowlist")
"""
PROBED = (
    "exec_allowlist",
    "filesystem_read_allowlist",
    "scratch_only_writes",
    "network_denied_by_default",
    "loopback_port_egress",
    "exact_loopback_address",
    "process_escape_containment",
    "process_count_limit",
    "aggregate_scratch_quota",
)
# Each of these needs a namespace/container backend before live execution.
NOT_ENFORCED = (
    "live_destination_egress",
    # macOS rejects RLIMIT_AS/DATA/RSS at usable values; only the deadline bounds memory.
    "memory_limit",
    "file_metadata_privacy",
    # The two opt-ins give up controls for that run; its IsolatedResult.enforced says so.
    "escape_containment_for_forking_tools",
    "scratch_quota_for_writing_tools",
)


_PUBLIC_OPTIONS = frozenset(
    {
        "exec_paths",
        "read_paths",
        "egress",
        "allow_fork",
        "allow_scratch_writes",
        "max_seconds",
        "max_output_bytes",
        "terminate_after_seconds",
        "cancelled",
    }
)


class IsolationError(ValueError):
    """The request cannot run inside the boundary this backend enforces."""


@dataclass(frozen=True)
class IsolatedResult:
    outcome: str  # completed | failed | timeout | cancelled
    exit_code: int
    stdout: bytes
    stderr: bytes
    output_truncated: bool
    # False means the scratch directory survived; such a run is never reported as completed.
    scratch_removed: bool
    duration_ms: int
    # Sandbox controls configured for this run; attest() shows which the host really enforces.
    enforced: tuple[str, ...]


def _stop_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        # macOS reports EPERM when only zombies remain in the group.
        pass


def remove_tree(folder: Path | str) -> bool:
    """Delete a folder a tool may have locked; True when nothing is left.

    Never acts through a link: a symbolic link is unlinked, not followed, and a file with
    another hard link keeps its mode and flags, because those belong to the shared file.
    """
    folder = Path(folder)

    def unlock_folder(path: str) -> None:
        if sys.platform == "darwin":  # file flags are macOS/BSD only; modes are enough elsewhere
            os.chflags(path, 0, follow_symlinks=False)
        os.chmod(path, stat.S_IRWXU, follow_symlinks=False)

    try:
        if folder.is_symlink() or not folder.is_dir():
            folder.unlink(missing_ok=True)
            return True
        unlock_folder(str(folder))
        # Top-down, so each directory is unlocked before the walk needs to list it.
        for parent, folders, files in os.walk(folder):
            for name in folders + files:
                path = os.path.join(parent, name)
                status = os.lstat(path)
                if stat.S_ISDIR(status.st_mode):
                    unlock_folder(path)
                elif (
                    sys.platform == "darwin"
                    and status.st_flags
                    and (stat.S_ISLNK(status.st_mode) or status.st_nlink == 1)
                ):
                    # An immutable flag blocks unlinking; clear it only where no other name shares it.
                    os.chflags(path, 0, follow_symlinks=False)
        shutil.rmtree(folder)
    except OSError:
        return False
    return True


def run_isolated(argv: Sequence[str], **options) -> IsolatedResult:
    """Run one reviewed argv inside the sandbox and always clean up its process group.

    exec_paths hold the tool's own runtime (interpreter, helpers); read_paths hold data
    and stay non-executable. Options: exec_paths, read_paths, egress, allow_fork,
    allow_scratch_writes, max_seconds, max_output_bytes, terminate_after_seconds, cancelled.
    There is deliberately no option here that lets a tool keep files after the run.
    """
    if not _PUBLIC_OPTIONS.issuperset(options):
        raise IsolationError("Unknown or unavailable runner option.")
    return _run_sandboxed(argv, **options)


def _run_sandboxed(
    argv: Sequence[str],
    *,
    exec_paths: Sequence[Path | str] = (),
    read_paths: Sequence[Path | str] = (),
    egress: Sequence[tuple[str, int]] = (),
    allow_fork: bool = False,
    allow_scratch_writes: bool = False,
    max_seconds: float = 60,
    max_output_bytes: int = 65536,
    terminate_after_seconds: float = 3,
    cancelled: Callable[[], bool] = lambda: False,
    output: Path | None = None,
    file_bytes: int = 0,
) -> IsolatedResult:
    """The runner's core. `output` (one folder the tool may write and that survives the run)
    and `file_bytes` (its per-file cap) are reachable only through run_staged_extraction.

    exec_paths hold the tool's own runtime (interpreter, helpers); read_paths hold data
    and stay non-executable. Without allow_fork the tool is a single process that cannot
    leave its group; a forking tool can escape the group kill with setsid(). Without
    allow_scratch_writes the tool can write only its capped stdout/stderr; with it, each
    file is capped but their total is not.
    """
    if sys.platform != "darwin" or not os.access(SANDBOX_EXEC, os.X_OK):
        raise IsolationError("No isolation backend is available on this platform.")
    if os.geteuid() == 0:
        raise IsolationError("Scanner tools never run as root.")
    if isinstance(argv, str) or not argv or not all(isinstance(a, str) and "\0" not in a for a in argv):
        raise IsolationError("argv must be a non-empty sequence of strings; shell strings are rejected.")
    if not os.path.isabs(argv[0]):
        raise IsolationError("The executable must be an absolute path.")
    # Actionable per-field diagnostics (the bounds are unchanged; only the messages are clearer).
    if type(allow_fork) is not bool or type(allow_scratch_writes) is not bool:
        raise IsolationError("allow_fork and allow_scratch_writes must be booleans.")
    if type(max_output_bytes) is not int or not 0 < max_output_bytes <= MAX_OUTPUT_BYTES:
        raise IsolationError(f"max_output_bytes must be an integer in 1..{MAX_OUTPUT_BYTES}.")
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 300:
        raise IsolationError("max_seconds must be a number in (0, 300].")
    if type(terminate_after_seconds) not in (int, float) or not 0 < terminate_after_seconds <= 10:
        raise IsolationError("terminate_after_seconds must be a number in (0, 10].")
    inherited = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
    if inherited != resource.RLIM_INFINITY and inherited <= max_output_bytes:
        # A lower inherited cap would truncate output without the overflow byte that reveals it.
        raise IsolationError("The inherited file-size limit is below the requested output budget.")
    try:
        executable = Path(argv[0]).resolve(strict=True)
        execs = [Path(path).resolve(strict=True) for path in exec_paths]
        reads = [Path(path).resolve(strict=True) for path in read_paths]
        # The tool may read back what it wrote to its staged output, but never execute it.
        reads += [output] if output else []
    except OSError as exc:
        raise IsolationError("The executable and every declared path must exist.") from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise IsolationError("The executable must be an executable regular file.")
    grants = set()
    for host, port in egress:
        # Seatbelt's "localhost" is exactly 127.0.0.1 (tcp4) or ::1 (tcp6), not all of 127/8.
        if host not in ("127.0.0.1", "::1"):
            raise IsolationError("Only literal loopback destinations are enforceable by this backend.")
        if type(port) is not int or not 1 <= port <= 65535:
            raise IsolationError("Egress ports must be integers from 1 to 65535.")
        grants.add(("tcp4" if host == "127.0.0.1" else "tcp6", port))

    profile = _PROFILE.format(
        fork="(allow process-fork)\n" if allow_fork else "",
        writes=(' (subpath (param "SCRATCH"))' if allow_scratch_writes else "")
        + (' (subpath (param "OUTPUT"))' if output else ""),
        execs="".join(f' (subpath (param "EXEC{index}"))' for index in range(len(execs))),
        reads="".join(f' (subpath (param "READ{index}"))' for index in range(len(reads))),
    ) + "".join(
        # tcp4/tcp6 pin the address family and exclude UDP; plain "ip" would admit both families.
        f'(allow network-outbound (remote {family} "localhost:{port}"))\n'
        for family, port in sorted(grants)
    )
    scratch = Path(tempfile.mkdtemp(prefix="sharay-run-")).resolve()
    cpu = math.ceil(max_seconds) + 1
    # One byte over the budget distinguishes "exactly full" from "truncated". The limit is
    # per file, so it bounds total disk use only while scratch writes stay denied.
    command = [
        sys.executable,
        "-I",
        "-S",
        "-c",
        _LAUNCH,
        "0",
        "256",
        str(cpu),
        str(max(max_output_bytes, file_bytes) + 1),
    ]
    command += [SANDBOX_EXEC, "-D", f"EXE={executable}", "-D", f"SCRATCH={scratch}"]
    command += ["-D", f"OUTPUT={output}"] if output else []
    for label, paths in (("EXEC", execs), ("READ", reads)):
        for index, path in enumerate(paths):
            command += ["-D", f"{label}{index}={path}"]
    command += ["-p", profile, str(executable), *argv[1:]]

    started = time.monotonic()
    outcome = ""
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                command,
                cwd=scratch,
                env={"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch), "LANG": "C"},
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                while process.poll() is None and not outcome:
                    if cancelled():
                        outcome = "cancelled"
                    elif time.monotonic() - started >= max_seconds:
                        outcome = "timeout"
                    else:
                        time.sleep(0.02)
                if outcome:
                    _stop_group(process.pid, signal.SIGTERM)
                    try:
                        process.wait(terminate_after_seconds)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                # Also reaps children a finished tool left behind in its group.
                _stop_group(process.pid, signal.SIGKILL)
                process.wait()
            captured = []
            for stream in (stdout, stderr):
                stream.seek(0)
                captured.append(stream.read(max_output_bytes))
            truncated = any(os.fstat(s.fileno()).st_size > max_output_bytes for s in (stdout, stderr))
    finally:
        removed = remove_tree(scratch)
    return IsolatedResult(
        outcome=outcome or ("completed" if process.returncode == 0 and removed else "failed"),
        exit_code=process.returncode,
        stdout=captured[0],
        stderr=captured[1],
        output_truncated=truncated,
        scratch_removed=removed,
        duration_ms=round((time.monotonic() - started) * 1000),
        enforced=(
            "exec_allowlist",
            "filesystem_read_allowlist",
            "scratch_only_writes",
            "network_denied_by_default",
            *(("loopback_port_egress", "exact_loopback_address") if grants else ()),
            *(() if allow_fork else ("process_escape_containment", "process_count_limit")),
            # A staged output folder can receive many capped files: no aggregate quota then.
            *(() if allow_scratch_writes or output else ("aggregate_scratch_quota",)),
        ),
    )


# Runs inside the sandbox. `services` is loaded by location so the child never needs to list
# the project root; extract_archive creates the tree folder itself and removes it on rejection.
_EXTRACT = """
import importlib.util, json, sys
location = sys.argv[1]
spec = importlib.util.spec_from_file_location("services", location + "/__init__.py", submodule_search_locations=[location])
module = importlib.util.module_from_spec(spec)
sys.modules["services"] = module
spec.loader.exec_module(module)
from services.source_analysis_worker import ArchiveError, extract_archive
names = ("max_files", "max_file_bytes", "max_total_bytes", "max_archive_bytes")
try:
    summary = extract_archive(sys.argv[2], sys.argv[3], **dict(zip(names, map(int, sys.argv[4:8]))))
except ArchiveError as exc:
    print(json.dumps({"rejected": str(exc)}))
    sys.exit(3)
summary["skipped"] = len(summary["skipped"])
print(json.dumps(summary))
"""


def run_staged_extraction(
    archive: Path | str,
    output: Path | str,
    *,
    max_files: int = 10000,
    max_file_bytes: int = 20 * 1024 * 1024,
    max_total_bytes: int = 200 * 1024 * 1024,
    max_archive_bytes: int = 100 * 1024 * 1024,
    max_seconds: float = 120,
    cancelled: Callable[[], bool] = lambda: False,
) -> IsolatedResult:
    """Extract one archive into `output`/tree inside the sandbox; the only run that keeps files.

    The child can read the archive and this project's `services` source, write only inside
    `output`, and has no network and no fork. Its stdout is a claim, not a result: the caller
    must validate `output` itself (services.source_analysis_worker.staging) before using it.
    The caller owns `output` and its removal; on this backend total disk use is not capped.
    """
    budgets = (max_files, max_file_bytes, max_total_bytes, max_archive_bytes)
    if any(type(value) is not int or value < 1 for value in budgets) or max_file_bytes > 2 * 1024**3:
        raise IsolationError("Budgets must be positive integers inside the supported bounds.")
    try:
        archive, output = Path(archive), Path(output)
        archive_mode, output_mode = archive.lstat().st_mode, output.lstat().st_mode
        if not stat.S_ISREG(archive_mode) or not stat.S_ISDIR(output_mode) or any(output.iterdir()):
            raise IsolationError("The archive must be a regular file and the output an empty real folder.")
        archive, output = archive.resolve(strict=True), output.resolve(strict=True)
    except OSError as exc:
        raise IsolationError("The archive and the output folder must exist.") from exc
    services = Path(__file__).resolve().parent.parent
    python = os.path.realpath(sys.executable)
    return _run_sandboxed(
        [python, "-I", "-c", _EXTRACT, str(services), str(archive), str(output / "tree"), *map(str, budgets)],
        exec_paths=[sys.base_prefix],
        read_paths=[services, archive],
        max_seconds=max_seconds,
        cancelled=cancelled,
        output=output,
        file_bytes=max_file_bytes,
    )


def attest() -> dict:
    """Probe this host now: a control is listed only if the probe saw the kernel refuse it.

    The probe runs without fork, so process_escape_containment says nothing about a run
    with allow_fork=True; each IsolatedResult.enforced states that run's own configuration.
    Deadline kill and output bounds are parent-side and shown by the test suite instead.
    """
    observed: list[str] = []
    applied = False
    try:
        with socket.socket() as allowed, socket.socket() as blocked:
            for listener in (allowed, blocked):
                listener.bind(("127.0.0.1", 0))
                listener.listen()
            allowed_port, blocked_port = allowed.getsockname()[1], blocked.getsockname()[1]
            python = os.path.realpath(sys.executable)
            run = run_isolated(
                [python, "-I", "-c", _PROBE, __file__, str(allowed_port), str(blocked_port)],
                exec_paths=[sys.base_prefix],
                egress=[("127.0.0.1", allowed_port)],
                max_seconds=10,
            )
        applied = run.outcome == "completed"
        if applied:
            observed = [control for control in run.stdout.decode().split() if control in PROBED]
    except (IsolationError, OSError):
        pass
    return {
        "backend": "macos-seatbelt",
        # Whether the sandbox applies here at all; rely on `enforced` for what it then does.
        "available": applied,
        "enforced": observed,
        "not_enforced": list(NOT_ENFORCED),
    }


__all__ = [
    "MAX_OUTPUT_BYTES",
    "IsolatedResult",
    "IsolationError",
    "attest",
    "remove_tree",
    "run_isolated",
    "run_staged_extraction",
]
