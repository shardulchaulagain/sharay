"""Synthetic worker jobs preserve origin pacing without real sockets or wall-clock waits."""

import http.client
import json
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import MetaData, Table, event, inspect, select, text
from sqlalchemy.exc import OperationalError

from aegis.config import ROOT, Settings
from aegis.database import create_database
from aegis.models import Assessment, Base, Organization, OriginCooldown, Project, Target, User
from aegis.worker import PersistentRequestStarts, run_one


class Clock:
    def __init__(self):
        self.now = 100.0
        self.utc = datetime.now(UTC)

    def sleep(self, seconds):
        self.now += max(seconds, 1e-9)

    def wall(self, _timezone):
        return self.utc + timedelta(seconds=self.now - 100)


class Response:
    def __init__(self, path):
        self.status = 302 if path == "/redirect" else 200
        self.headers = http.client.HTTPMessage()
        self.headers["Content-Type"] = "text/plain"
        if self.status == 302:
            self.headers["Location"] = "/final"

    def getheaders(self):
        return list(self.headers.items())

    def getheader(self, name):
        return self.headers.get(name)

    def close(self):
        pass


class Connection:
    def __init__(self, clock, destination, requests):
        self.clock, self.destination, self.requests = clock, destination, requests
        self.path = ""

    def request(self, method, path, headers):
        self.path = path
        self.requests.append((self.destination.origin, path, self.clock.now))

    def getresponse(self):
        return Response(self.path)

    def close(self):
        pass


class WorkerPacingTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="worker-pacing-")
        self.addCleanup(folder.cleanup)
        self.data_dir = Path(folder.name)
        engine, self.sessions = create_database(Settings(self.data_dir, start_worker=False))
        self.engine = engine
        self.addCleanup(engine.dispose)
        with self.sessions() as db:
            organization = Organization(name="Synthetic pacing fixture")
            db.add(organization)
            db.flush()
            user = User(
                organization_id=organization.id,
                username="pacing-fixture",
                password_hash="synthetic-unused-hash",
                role="owner",
            )
            db.add(user)
            db.flush()
            project = Project(organization_id=organization.id, owner_id=user.id, name="Synthetic")
            db.add(project)
            db.flush()
            self.org_id, self.user_id, self.project_id = organization.id, user.id, project.id
            db.commit()
        self.clock, self.requests, self.connection_starts, self.counter = Clock(), [], [], 0
        for context in (
            patch("packages.scanner_adapters.time.monotonic", side_effect=lambda: self.clock.now),
            patch("packages.scanner_adapters.time.sleep", side_effect=self.clock.sleep),
            patch(
                "packages.scanner_adapters._connection",
                side_effect=self.connect,
            ),
            patch("socket.socket", side_effect=AssertionError("No real sockets in pacing fixtures")),
            patch("socket.getaddrinfo", side_effect=AssertionError("No DNS in pacing fixtures")),
        ):
            context.start()
            self.addCleanup(context.stop)
        for module in ("packages.scanner_adapters", "packages.security_policies"):
            context = patch(f"{module}.datetime")
            clock_datetime = context.start()
            clock_datetime.now.side_effect = self.clock.wall
            self.addCleanup(context.stop)

    def connect(self, destination, timeout):
        self.connection_starts.append(self.clock.now)
        return Connection(self.clock, destination, self.requests)

    def enqueue(self, path="/", origin="http://127.0.0.1:8766", rate=1.0, lifetime=3600, categories=None):
        self.counter += 1
        scope = {
            "hosts": ["127.0.0.1"],
            "allowed_origins": [origin],
            "allowed_paths": ["/"],
            "excluded_paths": [],
            "allowed_cidrs": ["127.0.0.1/32"],
            "categories": ["http_headers"] if categories is None else categories,
            "request_rate": rate,
            "starts_at": (self.clock.utc - timedelta(seconds=1)).isoformat(),
            "expires_at": (self.clock.utc + timedelta(seconds=lifetime)).isoformat(),
        }
        with self.sessions() as db:
            target = Target(
                organization_id=self.org_id,
                project_id=self.project_id,
                url=origin + path,
                scope=scope,
                verification_status="verified",
                authorized_by=self.user_id,
                approved_at=self.clock.utc.timestamp(),
            )
            db.add(target)
            db.flush()
            job = Assessment(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=target.id,
                created_by=self.user_id,
                idempotency_key=f"synthetic-job-{self.counter}",
                scope_version=1,
                scope_snapshot=scope | {"target_url": target.url},
                created_at=self.counter,
            )
            db.add(job)
            db.flush()
            identifier = job.id
            db.commit()
        return identifier

    def status(self, identifier):
        with self.sessions() as db:
            row = db.get(Assessment, identifier)
            assert row is not None, "Synthetic assessment fixture is missing"
            return row.status

    def restarted_worker_requests(self):
        # A fresh interpreter cannot inherit the first worker's origin map.
        code = """
import contextlib, json, sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from aegis.config import Settings
from aegis.database import create_database
from aegis.worker import run_one
from tests.product.test_worker_pacing import Clock, Connection
engine, sessions = create_database(Settings(Path(sys.argv[1]), start_worker=False), migrate=False)
clock, requests = Clock(), []
clock.utc = datetime.fromisoformat(sys.argv[2])
try:
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch('packages.scanner_adapters.time.monotonic', side_effect=lambda: clock.now))
        stack.enter_context(patch('packages.scanner_adapters.time.sleep', side_effect=clock.sleep))
        stack.enter_context(patch('packages.scanner_adapters._connection', side_effect=lambda destination, timeout: Connection(clock, destination, requests)))
        stack.enter_context(patch('socket.socket', side_effect=AssertionError('No real sockets')))
        stack.enter_context(patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')))
        for module in ('packages.scanner_adapters', 'packages.security_policies'):
            stack.enter_context(patch(module + '.datetime')).now.side_effect = clock.wall
        assert run_one(sessions)
    print(json.dumps(requests))
finally:
    engine.dispose()
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, str(self.data_dir), self.clock.utc.isoformat()],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return json.loads(result.stdout)

    def test_separate_target_ids_and_paths_cannot_reset_same_origin_rate(self):
        jobs = [self.enqueue("/one"), self.enqueue("/two")]
        for job in jobs:
            self.assertTrue(run_one(self.sessions))
            self.assertEqual(self.status(job), "completed")
        self.assertEqual(len(self.requests), 2)
        self.assertGreaterEqual(self.requests[1][2] - self.requests[0][2], 1)

    def test_different_origins_do_not_share_an_unnecessary_delay(self):
        self.enqueue()
        self.enqueue(origin="http://127.0.0.1:8767")
        run_one(self.sessions)
        run_one(self.sessions)
        self.assertEqual([request[2] for request in self.requests], [100, 100])

    def test_faster_job_cannot_shorten_the_previous_jobs_cooldown(self):
        self.enqueue(rate=1)
        self.enqueue(rate=5)
        self.enqueue(rate=5)
        for _ in range(3):
            run_one(self.sessions)
        self.assertGreaterEqual(self.requests[1][2] - self.requests[0][2], 1)
        self.assertGreaterEqual(self.requests[2][2] - self.requests[1][2], 0.2 - 1e-9)

    def test_redirect_then_next_job_preserves_both_intervals(self):
        self.enqueue("/redirect")
        self.enqueue("/later")
        run_one(self.sessions)
        run_one(self.sessions)
        self.assertEqual([request[1] for request in self.requests], ["/redirect", "/final", "/later"])
        for first, second in zip(self.requests, self.requests[1:]):
            self.assertGreaterEqual(second[2] - first[2], 1)

    def test_cancellation_while_waiting_starts_no_second_request(self):
        self.enqueue()
        cancelled = self.enqueue()
        run_one(self.sessions)
        run_one(self.sessions, stopping=lambda: self.clock.now >= 100.1)
        self.assertEqual(self.status(cancelled), "cancelled")
        self.assertEqual(len(self.requests), 1)
        self.assertLessEqual(self.clock.now, 100.2)

    def test_expiry_while_waiting_starts_no_second_request(self):
        self.enqueue()
        expired = self.enqueue(lifetime=0.2)
        run_one(self.sessions)
        run_one(self.sessions)
        self.assertEqual(self.status(expired), "failed")
        self.assertEqual(len(self.requests), 1)

    def test_waiting_consumes_the_existing_execution_budget(self):
        self.enqueue()
        timed_out = self.enqueue(rate=0.01)
        run_one(self.sessions)
        run_one(self.sessions)
        self.assertEqual(self.status(timed_out), "failed")
        self.assertEqual(len(self.requests), 1)
        self.assertLessEqual(self.clock.now, 115.1)

    def test_tls_only_jobs_still_share_connection_pacing(self):
        jobs = [self.enqueue(origin="https://127.0.0.1:8766", categories=["tls"]) for _ in range(2)]
        with patch(
            "packages.scanner_adapters._tls_observation",
            side_effect=lambda connection, destination: {
                "kind": "tls_handshake",
                "url": destination.url,
                "fixture": "Synthetic TLS observation; no real handshake",
            },
        ):
            for job in jobs:
                run_one(self.sessions)
                self.assertEqual(self.status(job), "completed")
        self.assertEqual(self.requests, [])
        self.assertGreaterEqual(self.connection_starts[1] - self.connection_starts[0], 1)

    def test_failed_connection_attempt_still_consumes_its_pacing_slot(self):
        failed, following = self.enqueue(), self.enqueue()

        def connect(destination, timeout):
            connection = self.connect(destination, timeout)
            if len(self.connection_starts) == 1:
                raise OSError("Synthetic connection failure")
            return connection

        with patch("packages.scanner_adapters._connection", side_effect=connect):
            run_one(self.sessions)
            run_one(self.sessions)
        self.assertEqual(self.status(failed), "failed")
        self.assertEqual(self.status(following), "completed")
        self.assertGreaterEqual(self.connection_starts[1] - self.connection_starts[0], 1)

    def test_slow_connect_does_not_let_next_get_skip_the_last_requests_cooldown(self):
        self.enqueue()
        self.enqueue()

        def connect(destination, timeout):
            connection = self.connect(destination, timeout)
            if len(self.connection_starts) == 1:
                self.clock.now += 2
            return connection

        with patch("packages.scanner_adapters._connection", side_effect=connect):
            run_one(self.sessions)
            run_one(self.sessions)
        self.assertEqual(len(self.requests), 2)
        self.assertGreaterEqual(self.requests[1][2] - self.requests[0][2], 1)

    def test_new_worker_process_cannot_reset_the_prior_origins_cooldown(self):
        self.enqueue()
        self.enqueue()
        run_one(self.sessions)
        restarted = self.restarted_worker_requests()
        self.assertEqual(len(restarted), 1)
        self.assertGreaterEqual(restarted[0][2] - self.requests[0][2], 1)

    def test_faster_approval_after_restart_preserves_the_prior_interval(self):
        self.enqueue(rate=1)
        self.enqueue(rate=5)
        run_one(self.sessions)
        restarted = self.restarted_worker_requests()
        self.assertEqual(len(restarted), 1)
        self.assertGreaterEqual(restarted[0][2] - self.requests[0][2], 1)

    def test_failed_attempt_is_still_paced_after_worker_process_loss(self):
        self.enqueue()
        self.enqueue()
        with patch("packages.scanner_adapters._connection", side_effect=OSError("Synthetic failure")):
            run_one(self.sessions)
        restarted = self.restarted_worker_requests()
        self.assertEqual(len(restarted), 1)
        self.assertGreaterEqual(restarted[0][2] - 100, 1)

    def test_warm_worker_does_not_reset_a_cold_fence_after_idle_time(self):
        self.enqueue()
        self.enqueue()
        writes = []

        def record(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith(("INSERT INTO origin_cooldowns", "UPDATE origin_cooldowns")):
                writes.append(statement)

        event.listen(self.engine, "before_cursor_execute", record)
        self.addCleanup(event.remove, self.engine, "before_cursor_execute", record)
        run_one(self.sessions)
        pacing = PersistentRequestStarts(self.sessions)
        run_one(self.sessions, request_starts=pacing)
        self.clock.now += 3
        self.enqueue()
        run_one(self.sessions, request_starts=pacing)
        self.assertEqual(len(self.requests), 3)
        for request, expected in zip(self.requests, (100, 101, 104)):
            self.assertAlmostEqual(request[2], expected, places=7)
        self.assertEqual(len(writes), 1)

    def test_persistence_failure_starts_no_connection_and_does_not_cache_a_slot(self):
        failed = self.enqueue()
        pacing = PersistentRequestStarts(self.sessions)
        with self.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TRIGGER cooldown_failure BEFORE INSERT ON origin_cooldowns "
                "BEGIN SELECT RAISE(ABORT, 'Synthetic fixture write failure'); END"
            )
        run_one(self.sessions, request_starts=pacing)
        self.assertEqual(self.status(failed), "failed")
        self.assertEqual(self.connection_starts, [])
        self.assertEqual(pacing, {})

    def test_high_rate_scope_scans_without_crashing(self):
        # A scope rate above 10 req/s yields a sub-0.1s cooldown; that must pace the scan, not crash
        # it. The persistent store previously rejected the interval, so the safe-HTTP worker failed
        # with a generic "malformed response" error and every UI-launched scan failed at 0s.
        job = self.enqueue(rate=150.0)
        run_one(self.sessions)
        self.assertEqual(self.status(job), "completed")
        self.assertEqual(len(self.connection_starts), 1)

    def test_invalid_stored_interval_fails_before_connection(self):
        # Only a corrupt stored cooldown (non-finite or non-positive) fails closed; a fast-but-valid
        # interval such as 0.05s (20 req/s) is legitimate and must not be treated as corruption.
        for interval in (float("inf"), -1, 0):
            with self.subTest(interval=interval):
                failed = self.enqueue()
                with self.engine.begin() as connection:
                    connection.exec_driver_sql("DELETE FROM origin_cooldowns")
                    connection.exec_driver_sql(
                        "INSERT INTO origin_cooldowns(origin, interval) VALUES (?, ?)",
                        ("http://127.0.0.1:8766", interval),
                    )
                run_one(self.sessions)
                self.assertEqual(self.status(failed), "failed")
        self.assertEqual(self.connection_starts, [])

    def test_ten_rps_approval_has_a_durable_restart_cooldown(self):
        first, second = self.enqueue(rate=10.0), self.enqueue(rate=10.0)
        run_one(self.sessions)
        run_one(self.sessions)
        self.assertEqual(self.status(first), "completed")
        self.assertEqual(self.status(second), "completed")
        self.assertAlmostEqual(self.connection_starts[1] - self.connection_starts[0], 0.1, places=7)
        with self.sessions() as db:
            row = db.get(OriginCooldown, "http://127.0.0.1:8766")
            assert row is not None, "Synthetic cooldown fixture is missing"
            self.assertAlmostEqual(row.interval, 0.1)

    def test_pacing_lock_wait_is_bounded_and_restores_the_connection_timeout(self):
        pacing = PersistentRequestStarts(self.sessions)
        with self.engine.connect() as locked:
            locked.exec_driver_sql("BEGIN IMMEDIATE")
            started = time.perf_counter()
            with self.assertRaises(OperationalError):
                pacing["http://127.0.0.1:8766"] = 100, 1
            self.assertLess(time.perf_counter() - started, 0.5)
            self.assertEqual(pacing, {})
            locked.rollback()
        with self.sessions() as db:
            self.assertEqual(db.scalar(text("PRAGMA busy_timeout")), 10000)

    def test_cancellation_during_reservation_sends_no_request(self):
        cancelled = self.enqueue()
        clock = self.clock

        class DelayedStarts(dict):
            def __setitem__(self, origin, slot):
                super().__setitem__(origin, slot)
                clock.now += 0.2

        run_one(
            self.sessions,
            stopping=lambda: self.clock.now >= 100.1,
            request_starts=DelayedStarts(),
        )
        self.assertEqual(self.status(cancelled), "cancelled")
        self.assertEqual(self.connection_starts, [])

    def test_persistence_time_consumes_the_execution_budget_before_connect(self):
        timed_out = self.enqueue()
        clock = self.clock

        class DelayedStarts(dict):
            def __setitem__(self, origin, slot):
                super().__setitem__(origin, slot)
                clock.now += 16

        run_one(self.sessions, request_starts=DelayedStarts())
        self.assertEqual(self.status(timed_out), "failed")
        self.assertEqual(self.connection_starts, [])

    def test_expiry_during_reservation_starts_no_connection(self):
        expired = self.enqueue(lifetime=0.1)
        clock = self.clock

        class DelayedStarts(dict):
            def __setitem__(self, origin, slot):
                super().__setitem__(origin, slot)
                clock.now += 0.2

        run_one(self.sessions, request_starts=DelayedStarts())
        self.assertEqual(self.status(expired), "failed")
        self.assertEqual(self.connection_starts, [])

    def test_connection_timeout_uses_budget_remaining_after_persistence(self):
        self.enqueue(lifetime=1.5)
        clock = self.clock
        timeouts = []

        class DelayedStarts(dict):
            def __setitem__(self, origin, slot):
                super().__setitem__(origin, slot)
                clock.now += 1

        def connect(destination, timeout):
            timeouts.append(timeout)
            return self.connect(destination, timeout)

        with patch("packages.scanner_adapters._connection", side_effect=connect):
            run_one(self.sessions, request_starts=DelayedStarts())
        self.assertEqual(len(timeouts), 1)
        self.assertLessEqual(timeouts[0], 0.5)

    def test_additive_migration_preserves_old_records_and_is_repeatable(self):
        self.enqueue()
        run_one(self.sessions)
        # origin_cooldowns is populated by the worker; project_members is created and backfilled by a
        # migration (with random ids), so neither represents "old records being preserved" here.
        tables = [
            table
            for table in Base.metadata.sorted_tables
            if table.name not in ("origin_cooldowns", "project_members")
        ]

        def snapshot(connection):
            # Reflect the columns actually present so the comparison is robust to columns added by
            # later migrations (e.g. users.totp_* in 0004) against an older-schema database.
            inspector = inspect(connection)
            result = {}
            for table in tables:
                present = {c["name"] for c in inspector.get_columns(table.name)}
                cols = [table.c[name] for name in table.columns.keys() if name in present]
                result[table.name] = [
                    dict(row)
                    for row in connection.execute(
                        select(*cols).order_by(*table.primary_key.columns)
                    ).mappings()
                ]
            return result

        with tempfile.TemporaryDirectory(prefix="old-pacing-schema-") as folder:
            settings = Settings(Path(folder), start_worker=False)
            old_engine, _ = create_database(settings, migrate=False)
            try:
                config = Config(str(ROOT / "alembic.ini"))
                config.set_main_option("script_location", str(ROOT / "migrations"))
                with self.engine.connect() as source, old_engine.begin() as destination:
                    config.attributes["connection"] = destination
                    command.upgrade(config, "0001_desktop")
                    expected = snapshot(source)
                    present_0001 = {
                        t.name: {c["name"] for c in inspect(destination).get_columns(t.name)}
                        for t in tables
                    }
                    # Insert the old data through reflected (0001-schema) tables so columns added by
                    # later migrations -- even ones with client-side defaults -- are not referenced.
                    for table in tables:
                        rows = [
                            {k: v for k, v in row.items() if k in present_0001[table.name]}
                            for row in expected[table.name]
                        ]
                        if rows:
                            reflected = Table(table.name, MetaData(), autoload_with=destination)
                            destination.execute(reflected.insert(), rows)
                    self.assertNotIn("origin_cooldowns", inspect(destination).get_table_names())
                    expected_0001 = {
                        t.name: [
                            {k: v for k, v in row.items() if k in present_0001[t.name]}
                            for row in expected[t.name]
                        ]
                        for t in tables
                    }
                    self.assertEqual(snapshot(destination), expected_0001)
            finally:
                old_engine.dispose()
            for _ in range(2):
                migrated, _ = create_database(settings)
                try:
                    with migrated.connect() as connection:
                        self.assertIn("origin_cooldowns", inspect(connection).get_table_names())
                        self.assertEqual(snapshot(connection), expected)
                        # Reaches the current Alembic head (robust to new migrations being added).
                        head = ScriptDirectory.from_config(config).get_current_head()
                        self.assertEqual(
                            connection.scalar(text("SELECT version_num FROM alembic_version")), head
                        )
                finally:
                    migrated.dispose()


if __name__ == "__main__":
    unittest.main()
