"""CLI and native desktop entry point: python -m sharay."""

import argparse
import getpass
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from sqlalchemy import text

from aegis.auth import consume_recovery, issue_recovery, provision_owner
from aegis.backup import backup_database, restore_database
from aegis.config import ROOT, Settings
from aegis.database import create_database
from aegis.lifecycle import watch_parent_stdin
from packages.scanner_adapters import preflight


def serve(settings: Settings, parent_stdin: bool = False):
    import uvicorn

    from aegis.api import create_app

    os.umask(0o077)
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host="127.0.0.1",
            port=settings.port,
            access_log=False,
            log_level="warning",
            timeout_graceful_shutdown=10,
        )
    )
    with watch_parent_stdin(parent_stdin, lambda: setattr(server, "should_exit", True)):
        server.run()


def ready(settings: Settings) -> bool:
    try:
        with urllib.request.urlopen(settings.origin + "/api/v1/health/ready", timeout=0.5) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException):
        return False


def desktop_assets_available() -> bool:
    return (ROOT / "apps/web/out/index.html").is_file()


def desktop(settings: Settings, browser: bool, smoke_seconds: float):
    if not desktop_assets_available():
        raise ValueError(
            "Frontend build missing. Run: npm --prefix apps/web ci && npm --prefix apps/web run build"
        )
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", settings.port)) == 0:
            raise ValueError("SHARAY_PORT is occupied. Close the existing app or choose another local port")
    environment = {
        key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "TMPDIR", "LANG") if key in os.environ
    }
    environment.update(
        {
            "AEGIS_DATA_DIR": str(settings.data_dir),
            "AEGIS_PORT": str(settings.port),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "aegis", "serve", "--parent-stdin"],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    cleanup_lock = threading.Lock()
    cleaned_up = False

    def stop_api():
        nonlocal cleaned_up
        with cleanup_lock:
            if cleaned_up:
                return
            if process.stdin:
                process.stdin.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cleaned_up = True

    try:
        deadline = time.monotonic() + 15
        while not ready(settings):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("API or worker failed startup; inspect local configuration")
            time.sleep(0.1)
        if smoke_seconds:
            print(
                json.dumps({"api": "ready", "worker": "ready", "ui": "built", "origin": settings.origin}),
                flush=True,
            )
            time.sleep(min(smoke_seconds, 5))
        elif browser:
            import webbrowser

            webbrowser.open(settings.origin)
            print("SHARAY is running locally. Press Ctrl+C to close the API and worker.", flush=True)
            process.wait()
        else:
            try:
                import webview
            except ImportError as exc:
                raise RuntimeError(
                    "Native desktop dependency missing. Install requirements-desktop.txt or explicitly use --browser"
                ) from exc
            window = webview.create_window(
                "SHARAY · Security workspace",
                settings.origin,
                width=1440,
                height=960,
                min_size=(860, 640),
                background_color="#080f14",
            )
            # Cocoa's native Quit can exit before Python's finally block.
            # The closing event runs synchronously before permitting termination.
            if window is None:
                raise RuntimeError("Native window creation failed")
            window.events.closing += stop_api
            webview.start(debug=False, private_mode=True)
    finally:
        stop_api()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--port", type=int)
    sub = parser.add_subparsers(dest="command")
    init = sub.add_parser("init-owner", help="Create the initial owner; no default credentials exist")
    init.add_argument("--username", default=None)
    init.add_argument("--organization", default="Local laboratory")
    recovery = sub.add_parser("issue-recovery", help="Local OS owner creates a ten-minute recovery token")
    recovery.add_argument("username")
    sub.add_parser("reset-password", help="Consume a recovery token once and revoke existing sessions")
    sub.add_parser("preflight", help="Report dependency status without running external scanners")
    sub.add_parser("migrate", help="Apply forward-only Alembic migrations")
    backup = sub.add_parser("backup", help="Create a new private consistent database snapshot")
    backup.add_argument("destination", type=Path)
    restore = sub.add_parser("restore", help="Restore a snapshot into a brand-new --data-dir")
    restore.add_argument("snapshot", type=Path)
    api = sub.add_parser("serve", help="Run loopback API and worker without a window")
    api.add_argument("--parent-stdin", action="store_true", help=argparse.SUPPRESS)
    window = sub.add_parser("desktop", help="Start the native app; this is the default")
    window.add_argument("--browser", action="store_true")
    window.add_argument("--smoke-seconds", type=float, default=0)

    scan_cmd = sub.add_parser("scan", help="Run automated assessment pipeline from command line")
    scan_cmd.add_argument("url", help="Target URL (e.g. https://example.com/)")
    scan_cmd.add_argument(
        "--profile",
        choices=["comprehensive", "safe_http", "approved_templates"],
        default="comprehensive",
        help="Assessment profile (default: comprehensive)",
    )
    scan_cmd.add_argument(
        "--severities", default="medium,high,critical", help="Severities to scan for (nuclei)"
    )
    scan_cmd.add_argument(
        "--mode",
        choices=["passive", "standard", "adaptive", "aggressive"],
        default="adaptive",
        help="Scan mode (default: adaptive, correlates recon to tailor active tests)",
    )
    scan_cmd.add_argument("--tags", default=None, help="Custom Nuclei tags to target (e.g. cve,panel)")
    scan_cmd.add_argument(
        "--rate", type=int, default=150, help="Request rate limit per second (default: 150)"
    )
    scan_cmd.add_argument("--depth", type=int, default=2, help="Crawler max depth (default: 2)")
    scan_cmd.add_argument(
        "--project", default="CLI Assessments", help="Project name to associate findings with"
    )
    scan_cmd.add_argument("--json", action="store_true", help="Output raw JSON results")
    scan_cmd.add_argument(
        "--authorized",
        action="store_true",
        help="Assert verified ownership/authorization of a live (non-loopback) target (required for it)",
    )

    probe_cmd = sub.add_parser("probe", help="Execute an interactive takeover probe against a target")
    probe_cmd.add_argument("url", help="Target URL to probe")
    probe_cmd.add_argument("--method", default="GET", help="HTTP method (GET, POST, etc.)")
    probe_cmd.add_argument(
        "-H", "--header", action="append", default=[], help="HTTP headers (e.g. -H 'Key: Value')"
    )
    probe_cmd.add_argument("-d", "--data", default=None, help="HTTP request body")
    probe_cmd.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds")
    probe_cmd.add_argument("--json", action="store_true", help="Output raw JSON results")
    probe_cmd.add_argument(
        "--authorized",
        action="store_true",
        help="Assert verified ownership/authorization of a live (non-loopback) target (required for it)",
    )

    status_cmd = sub.add_parser("status", help="Show platform status, scanner integrations, and inventory")
    status_cmd.add_argument("--json", action="store_true", help="Output raw JSON metrics")

    find_cmd = sub.add_parser("findings", help="List recorded findings from the SHARAY database")
    find_cmd.add_argument("--severity", default=None, help="Filter by severity (e.g. critical,high)")
    find_cmd.add_argument("--json", action="store_true", help="Output raw JSON findings")
    args = parser.parse_args(argv)
    defaults = Settings.from_env()
    settings = Settings(args.data_dir or defaults.data_dir, args.port or defaults.port)
    if not 1024 <= settings.port <= 65535:
        parser.error("Port must be between 1024 and 65535")
    os.umask(0o077)
    try:
        if args.command == "preflight":
            print(
                json.dumps(
                    {
                        "scanners": preflight(),
                        "ai": "disabled",
                        "mode": "local_desktop",
                        "ui_built": desktop_assets_available(),
                    },
                    indent=2,
                )
            )
        elif args.command == "serve":
            serve(settings, args.parent_stdin)
        elif args.command == "backup":
            print(json.dumps({"backup": "created", **backup_database(settings.data_dir, args.destination)}))
        elif args.command == "restore":
            if args.data_dir is None:
                raise ValueError("Restoration requires an explicit new --data-dir.")
            print(json.dumps({"restore": "created", **restore_database(args.snapshot, settings.data_dir)}))
        elif args.command in {"init-owner", "issue-recovery", "reset-password", "migrate"}:
            engine, sessions = create_database(settings)
            try:
                with sessions() as db:
                    db.execute(text("BEGIN IMMEDIATE"))
                    if args.command == "init-owner":
                        username = args.username or input("Owner username: ").strip()
                        password = getpass.getpass("Owner password (12+ characters): ")
                        if password != getpass.getpass("Confirm password: "):
                            raise ValueError("Passwords do not match")
                        provision_owner(db, username, password, args.organization)
                        print("Owner provisioned. Open SHARAY and sign in with your chosen credentials.")
                    elif args.command == "issue-recovery":
                        # Only the interactive local operator receives this bearer secret.
                        print("Recovery token (expires in ten minutes; use reset-password):")
                        print(issue_recovery(db, args.username))
                    elif args.command == "reset-password":
                        token = getpass.getpass("Recovery token: ")
                        password = getpass.getpass("New password (12+ characters): ")
                        if password != getpass.getpass("Confirm password: "):
                            raise ValueError("Passwords do not match")
                        consume_recovery(db, token, password)
                        print("Password reset and existing sessions revoked.")
                    else:
                        print("Database migrations applied.")
                    db.commit()
            finally:
                engine.dispose()
        elif args.command == "status":
            from aegis.cli import cmd_status

            return cmd_status(settings, as_json=args.json)
        elif args.command == "probe":
            from aegis.cli import cmd_probe

            headers = {}
            for h in args.header:
                k, _, v = h.partition(":")
                headers[k.strip()] = v.strip()
            return cmd_probe(
                args.url,
                method=args.method,
                headers=headers,
                body=args.data,
                timeout=args.timeout,
                as_json=args.json,
                authorized=args.authorized,
            )
        elif args.command == "scan":
            from aegis.cli import cmd_scan

            return cmd_scan(
                settings,
                args.url,
                profile=args.profile,
                severities=args.severities,
                project_name=args.project,
                mode=args.mode,
                tags=args.tags,
                rate=args.rate,
                depth=args.depth,
                as_json=args.json,
                authorized=args.authorized,
            )
        elif args.command == "findings":
            from aegis.cli import cmd_findings

            return cmd_findings(settings, severity=args.severity, as_json=args.json)
        else:
            desktop(settings, getattr(args, "browser", False), getattr(args, "smoke_seconds", 0))
    except (ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
