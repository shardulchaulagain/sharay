"""Synthetic worker jobs preserve origin pacing without real sockets or wall-clock waits."""

import http.client
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from aegis.config import Settings
from aegis.database import create_database
from aegis.models import Assessment, Organization, Project, Target, User
from aegis.worker import run_one


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
        engine, self.sessions = create_database(Settings(Path(folder.name), start_worker=False))
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
            patch("aegis.worker._request_starts", {}, create=True),
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
            return db.get(Assessment, identifier).status

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


if __name__ == "__main__":
    unittest.main()
