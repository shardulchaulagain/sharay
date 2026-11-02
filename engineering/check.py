#!/usr/bin/env python3
"""Local evidence collection; the collector never installs packages or calls AI.

Explicit gates execute trusted programs with host permissions, including network.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engineering.run_tests import MAX_RESULT_BYTES, RESULT_ENV, validate_metadata

EXCLUDED = {
    ".git",
    ".engineering",
    ".aegis",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "out",
}
MANIFESTS = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "Gemfile",
    "Dockerfile",
    "compose.yaml",
}


def inventory(root, report_path=None):
    files, skipped, errors = [], [], []
    for directory, dirs, names in os.walk(
        root, followlinks=False, onerror=lambda e: errors.append(type(e).__name__)
    ):
        base = Path(directory)
        for name in list(dirs):
            path = base / name
            if name in EXCLUDED or path.is_symlink() or path == report_path:
                skipped.append(path.relative_to(root).as_posix())
                dirs.remove(name)
        for name in sorted(names):
            path = base / name
            try:
                files.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "bytes": path.lstat().st_size,
                        "kind": "symlink" if path.is_symlink() else "file",
                    }
                )
            except OSError as e:
                errors.append(type(e).__name__)
    return {
        "files": sorted(files, key=lambda f: f["path"]),
        "excluded": sorted(skipped),
        "errors": errors,
        "complete_within_scope": not errors,
    }


def validate_gates(data):
    if not isinstance(data, dict) or not isinstance(data.get("gates"), list):
        raise ValueError("gate config must contain a gates array")
    seen = set()
    for gate in data["gates"]:
        if not isinstance(gate, dict):
            raise ValueError("each gate must be an object")
        name = gate.get("name")
        command = gate.get("command")
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError("gate names must be nonempty and unique")
        seen.add(name)
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(a, str) and a and "\x00" not in a for a in command)
        ):
            raise ValueError("commands must be nonempty argument arrays, never shell strings")
        timeout = gate.get("timeout_seconds", 60)
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not 0 < timeout <= 600:
            raise ValueError("timeouts must be between 0 and 600 seconds")
    return data["gates"]


def read_test_diagnostics(path, identity):
    """Read bounded metadata only from the regular file created by this parent."""
    unavailable = {"status": "unavailable"}
    if path is None or not hasattr(os, "O_NOFOLLOW"):
        return unavailable
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != identity
            or info.st_nlink != 1
            or info.st_size > MAX_RESULT_BYTES
        ):
            return unavailable
        chunks, remaining = [], MAX_RESULT_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_RESULT_BYTES:
            return unavailable

        def unique_keys(pairs):
            data = {}
            for key, value in pairs:
                if key in data:
                    raise ValueError("duplicate metadata key")
                data[key] = value
            return data

        data = json.loads(raw, object_pairs_hook=unique_keys)
        return {"status": "available", **data} if validate_metadata(data) else unavailable
    except (OSError, ValueError, UnicodeError, RecursionError):
        return unavailable
    finally:
        if fd is not None:
            os.close(fd)


def cleanup_diagnostics(directory, result):
    """Optional diagnostics cleanup must not replace the observed gate outcome."""
    try:
        try:
            info = os.lstat(directory.name)
        except FileNotFoundError:
            info = None
        if info is not None and not stat.S_ISDIR(info.st_mode):
            # Remove a swapped entry itself, never a symlink's target.
            os.unlink(directory.name)
        directory.cleanup()
    except OSError:
        result["diagnostics_cleanup"] = "unavailable"


def run_gate(gate, root, execute=False):
    """Run only reviewed argv, discard raw output, do not inherit credentials.

    This is NOT an OS sandbox. Use an externally sandboxed runner for untrusted code.
    """
    command = [sys.executable if a == "{python}" else a for a in gate["command"]]
    result = {
        "name": gate["name"],
        "status": "not_run",
        "exit_code": None,
        "duration_seconds": None,
        "test_diagnostics": {"status": "not_run"},
        "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest(),
    }
    if not execute:
        return result
    started = time.perf_counter()
    environment = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TMPDIR") if k in os.environ}
    environment.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"})
    result["test_diagnostics"] = {"status": "unavailable"}
    with ExitStack() as stack:
        path, identity = None, None
        try:
            directory = tempfile.TemporaryDirectory(prefix="sharay-gate-")
            stack.callback(cleanup_diagnostics, directory, result)
            fd, path = tempfile.mkstemp(prefix="tests-", dir=directory.name)
            try:
                info = os.fstat(fd)
                identity = (info.st_dev, info.st_ino)
            finally:
                os.close(fd)
            environment[RESULT_ENV] = path
        except OSError:
            # Diagnostics are optional; their storage cannot block the gate.
            path = None
        try:
            with subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=(os.name == "posix"),
            ) as process:
                try:
                    result["exit_code"] = process.wait(timeout=gate.get("timeout_seconds", 60))
                    result["status"] = "passed" if result["exit_code"] == 0 else "failed"
                except subprocess.TimeoutExpired:
                    result["status"] = "timeout"
                finally:
                    if os.name == "posix":
                        try:
                            # Children may remain even after the group leader exits.
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    elif process.poll() is None:
                        process.kill()
                    process.wait()
        except OSError as e:
            result["status"] = "blocked"
            result["reason"] = type(e).__name__
        result["test_diagnostics"] = read_test_diagnostics(path, identity)
    result["duration_seconds"] = round(time.perf_counter() - started, 6)
    return result


def metrics():
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF)
        return {
            "scope": "collector process only",
            "cpu_seconds": usage.ru_utime + usage.ru_stime,
            "peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
        }
    except ImportError:
        return {"scope": "collector process only", "cpu_seconds": None, "peak_rss_bytes": None}


def render(report, template):
    # A script-data element still ends at </script>. Escape HTML metacharacters.
    payload = (
        json.dumps(report, ensure_ascii=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    return template.replace("__REPORT_JSON__", payload)


def report_directory(output, root):
    """Confine reports to the audited root and reject symlink components.

    Concurrency with a malicious writer requires an external OS sandbox.
    """
    output = Path(os.path.abspath(output))
    relative = output.relative_to(root)
    if not relative.parts:
        raise ValueError("reports require a dedicated subdirectory")
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise ValueError("symlink report path is not allowed")
        current.mkdir(exist_ok=True)
    return output


def write_report(output, name, text):
    target = output / name
    if target.is_symlink():
        raise ValueError("symlink report file is not allowed")
    # Replace directory entries instead of following an existing file/hardlink.
    fd, temp = tempfile.mkstemp(prefix=".report-", dir=output)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--caller",
        choices=("codex", "claude", "gemini", "human"),
        help="supplied attribution, not authentication; separates default report paths",
    )
    parser.add_argument(
        "--run-gates",
        action="store_true",
        help="execute reviewed trusted commands; this is not an OS sandbox",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error("root must be an existing directory")
    output = args.output or root / ".engineering" / "reports"
    if args.output is None and args.caller:
        output = output / args.caller
    config = root / "engineering" / "gates.json"
    try:
        if config.parent.is_symlink() or config.is_symlink():
            raise ValueError("symlink gate configuration is not allowed")
        gates = validate_gates(json.loads(config.read_text())) if config.exists() else []
        if args.run_gates and not gates:
            raise ValueError("execution requires at least one configured gate")
        output = report_directory(output, root)
    except (OSError, ValueError) as e:
        print(f"Invalid gate configuration: {type(e).__name__}", file=sys.stderr)
        return 2
    started = time.perf_counter()
    listing = inventory(root, output)
    checks = [run_gate(g, root, args.run_gates) for g in gates]
    timestamp = dt.datetime.now(dt.timezone.utc)
    report = {
        "schema_version": 1,
        "generated_at": timestamp.isoformat(),
        "root_name": root.name,
        "inventory": listing,
        "manifests": [f["path"] for f in listing["files"] if Path(f["path"]).name in MANIFESTS],
        "gates": checks,
        "collector_metrics": metrics(),
        "collector_wall_seconds": round(time.perf_counter() - started, 6),
        "environment": {"python": platform.python_version(), "platform": platform.system()},
        "unavailable": {
            "application_architecture": "Collector has no architecture adapter; see docs/ARCHITECTURE.md",
            "resolved_dependencies": "No lockfile/SBOM adapter",
            "coverage": "No coverage adapter",
            "build_status": "Collector has no frontend build adapter",
            "application_logs_errors_traces": "Collector does not import product audit/check events",
            "cpu_memory_utilization": "No application process monitor",
            "api_database_network_metrics": "Collector does not import local API/worker metrics",
            "security_findings": "No external scanner executed",
            "codex_tool_calls_commands_modified_files": "No approved session event import",
            "tokens_costs": "No model usage import or pricing snapshot",
        },
    }
    if args.caller:
        report["caller"] = args.caller
        report["caller_attribution"] = "supplied argument, not authentication"
    try:
        template = (Path(__file__).parent / "dashboard.html").read_text()
        encoded = json.dumps(report, indent=2)
        run_id = timestamp.strftime("%Y%m%dT%H%M%S.%fZ")
        write_report(output, f"{run_id}.json", encoded)
        write_report(output, "latest.json", encoded)
        write_report(output, "index.html", render(report, template))
    except (OSError, ValueError) as e:
        print(f"Cannot save report: {type(e).__name__}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "report": str(output / "latest.json"),
                "dashboard": str(output / "index.html"),
                "files": len(listing["files"]),
                "gates": {g["name"]: g["status"] for g in checks},
            }
        )
    )
    return int(bool(listing["errors"]) or any(g["status"] not in ("passed", "not_run") for g in checks))


if __name__ == "__main__":
    sys.exit(main())
